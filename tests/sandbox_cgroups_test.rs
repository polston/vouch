use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use vouch::config::{self, SeccompProfile};
use vouch::runtime::{
    CgroupMemoryEvents, CgroupPidsEvents, CgroupV2Manager, LandlockRulesetPlan, LandlockVerdict,
    LoopbackInterfaceSpec, NamespaceSpec, RlimitResource, RlimitRule, RlimitSet,
    SandboxExecutionPlan, SeccompFilterProgram, AUDIT_ARCH_AARCH64, AUDIT_ARCH_X86_64,
    CLONE_NEWNET, CLONE_NEWNS, CLONE_NEWPID, CLONE_NEWUSER, LANDLOCK_ACCESS_FS_EXECUTE,
    LANDLOCK_ACCESS_FS_MAKE_REG, LANDLOCK_ACCESS_FS_READ_FILE, LANDLOCK_ACCESS_FS_REMOVE_FILE,
    LANDLOCK_ACCESS_FS_TRUNCATE, LANDLOCK_ACCESS_FS_WRITE_FILE, SECCOMP_RET_ALLOW,
    SECCOMP_RET_ERRNO_EPERM, SECCOMP_RET_KILL_PROCESS,
};

fn unique_cgroup_root(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "vouch_cgroup_test_{}_{}_{}",
        tag,
        std::process::id(),
        nanos
    ));
    let _ = std::fs::create_dir_all(&dir);
    dir
}

#[test]
fn config_parses_sandbox_cgroups_and_unshare_namespaces() {
    let toml_text = r#"
[sandbox]
unshare_namespaces = true
isolate_network = true
seccomp_profile = "strict"
landlock_enforce = true

[sandbox.cgroups]
max_memory_mb = 2048
high_memory_mb = 1536
"#;
    let cfg = config::load(toml_text).expect("sandbox config parses");
    assert!(cfg.sandbox.unshare_namespaces);
    assert!(cfg.sandbox.isolate_network);
    assert!(cfg.sandbox.landlock_enforce);
    assert_eq!(cfg.sandbox.seccomp_profile, Some(SeccompProfile::Strict));
    assert_eq!(cfg.sandbox.cgroups.max_memory_mb, Some(2048));
    assert_eq!(cfg.sandbox.cgroups.high_memory_mb, Some(1536));
}

#[test]
fn cgroup_v2_manager_provisions_memory_quotas_attaches_pids_and_reads_oom_events() {
    let root = unique_cgroup_root("provision");
    std::fs::write(root.join("cgroup.controllers"), "cpu memory pids\n").unwrap();

    let manager = CgroupV2Manager::new(&root);
    assert!(manager.is_available());

    let toml_text = r#"
[sandbox]
unshare_namespaces = true

[sandbox.cgroups]
max_memory_mb = 2048
high_memory_mb = 1024
"#;
    let cfg = config::load(toml_text).unwrap();
    let (plan, scope_opt) =
        SandboxExecutionPlan::prepare(&manager, "subagent-42", &cfg.sandbox).expect("prepare plan");
    let scope = scope_opt.expect("cgroup scope provisioned");

    // Verify exact byte limits written to memory.max (2048 MiB) and memory.high (1024 MiB)
    let expected_max = 2048u64 * 1024 * 1024;
    let expected_high = 1024u64 * 1024 * 1024;
    assert_eq!(plan.max_memory_bytes, Some(expected_max));
    assert_eq!(plan.high_memory_bytes, Some(expected_high));

    let max_file = std::fs::read_to_string(scope.dir.join("memory.max")).unwrap();
    let high_file = std::fs::read_to_string(scope.dir.join("memory.high")).unwrap();
    assert_eq!(max_file.trim(), expected_max.to_string());
    assert_eq!(high_file.trim(), expected_high.to_string());

    // Attach worker PIDs and verify cgroup.procs
    scope.attach_pid(41001).expect("attach pid 1");
    scope.attach_pid(41002).expect("attach pid 2");
    assert_eq!(scope.attached_pids(), vec![41001, 41002]);

    // Simulate kernel updating memory.current and memory.events
    std::fs::write(scope.dir.join("memory.current"), "536870912\n").unwrap();
    std::fs::write(
        scope.dir.join("memory.events"),
        "low 0\nhigh 3\nmax 1\noom 1\noom_kill 1\noom_group_kill 0\n",
    )
    .unwrap();

    assert_eq!(scope.read_current_memory_bytes(), Some(536_870_912));
    let events: CgroupMemoryEvents = scope.read_memory_events();
    assert_eq!(events.high, 3);
    assert_eq!(events.max, 1);
    assert_eq!(events.oom_kill, 1);
    assert!(events.has_oom_kill());

    // Teardown removes the worker cgroup directory cleanly
    scope.teardown().expect("teardown scope");
    assert!(!scope.dir.exists());

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn namespace_spec_synthesizes_linux_clone_flags_and_rootless_id_maps() {
    let spec = NamespaceSpec::standard_sandbox();
    assert!(spec.is_enabled());
    assert_eq!(
        spec.clone_flags(),
        CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNS
    );
    assert_eq!(NamespaceSpec::format_id_map(0, 1000), "0 1000 1\n");
}

#[test]
fn isolate_network_enables_clone_newnet_and_provisions_loopback_spec() {
    let root = unique_cgroup_root("netns");
    let manager = CgroupV2Manager::new(&root);

    let toml_text = r#"
[sandbox]
isolate_network = true
seccomp_profile = "baseline"
"#;
    let cfg = config::load(toml_text).unwrap();
    let (plan, scope_opt) =
        SandboxExecutionPlan::prepare(&manager, "subagent-net", &cfg.sandbox).expect("prepare");
    assert!(scope_opt.is_none());
    assert!(plan.namespaces.net);
    assert!(plan.namespaces.user);
    assert_eq!(plan.clone_flags, CLONE_NEWUSER | CLONE_NEWNET);
    assert_eq!(
        plan.loopback,
        Some(LoopbackInterfaceSpec {
            ifname: "lo".to_string(),
            ipv4_cidr: "127.0.0.1/8".to_string(),
            ipv6_cidr: "::1/128".to_string(),
            up: true,
        })
    );
    assert!(plan.seccomp_filter.is_some());

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn seccomp_bpf_filter_program_simulates_baseline_and_strict_profiles_across_arches() {
    let args = [0u64; 6];

    // None profile returns None
    assert!(SeccompFilterProgram::for_profile(SeccompProfile::None, AUDIT_ARCH_X86_64).is_none());

    // Baseline on x86_64 blocks ptrace (101), bpf (321), mount (165), kexec_load (246)
    // and allows read (0), write (1), openat (257), unshare (272)
    let baseline_x64 =
        SeccompFilterProgram::for_profile(SeccompProfile::Baseline, AUDIT_ARCH_X86_64)
            .expect("baseline x64 filter");
    assert_eq!(
        baseline_x64.simulate(AUDIT_ARCH_X86_64, 0, &args),
        SECCOMP_RET_ALLOW,
        "read(0) allowed"
    );
    assert_eq!(
        baseline_x64.simulate(AUDIT_ARCH_X86_64, 1, &args),
        SECCOMP_RET_ALLOW,
        "write(1) allowed"
    );
    assert_eq!(
        baseline_x64.simulate(AUDIT_ARCH_X86_64, 257, &args),
        SECCOMP_RET_ALLOW,
        "openat(257) allowed"
    );
    assert_eq!(
        baseline_x64.simulate(AUDIT_ARCH_X86_64, 272, &args),
        SECCOMP_RET_ALLOW,
        "unshare(272) allowed in baseline"
    );
    for &blocked in &[101u32, 321, 165, 246, 298, 169] {
        assert_eq!(
            baseline_x64.simulate(AUDIT_ARCH_X86_64, blocked, &args),
            SECCOMP_RET_ERRNO_EPERM,
            "syscall {blocked} must return EPERM in baseline"
        );
    }
    // Architecture mismatch kills process immediately
    assert_eq!(
        baseline_x64.simulate(AUDIT_ARCH_AARCH64, 0, &args),
        SECCOMP_RET_KILL_PROCESS
    );

    // Strict on x86_64 also blocks unshare (272), setns (308), keyctl (250), userfaultfd (323), io_uring_setup (425)
    let strict_x64 = SeccompFilterProgram::for_profile(SeccompProfile::Strict, AUDIT_ARCH_X86_64)
        .expect("strict x64 filter");
    for &blocked in &[101u32, 321, 272, 308, 250, 323, 425, 426, 427] {
        assert_eq!(
            strict_x64.simulate(AUDIT_ARCH_X86_64, blocked, &args),
            SECCOMP_RET_ERRNO_EPERM,
            "syscall {blocked} must return EPERM in strict"
        );
    }
    assert_eq!(
        strict_x64.simulate(AUDIT_ARCH_X86_64, 59, &args),
        SECCOMP_RET_ALLOW,
        "execve(59) allowed in strict"
    );

    // Strict on aarch64 blocks ptrace (117), bpf (280), unshare (97), keyctl (219), io_uring_setup (425)
    let strict_arm64 =
        SeccompFilterProgram::for_profile(SeccompProfile::Strict, AUDIT_ARCH_AARCH64)
            .expect("strict aarch64 filter");
    for &blocked in &[117u32, 280, 97, 219, 425] {
        assert_eq!(
            strict_arm64.simulate(AUDIT_ARCH_AARCH64, blocked, &args),
            SECCOMP_RET_ERRNO_EPERM
        );
    }
    assert_eq!(
        strict_arm64.simulate(AUDIT_ARCH_AARCH64, 64, &args),
        SECCOMP_RET_ALLOW,
        "write(64) on aarch64 allowed"
    );
}

#[test]
fn landlock_ruleset_compiles_write_policy_and_simulates_hierarchy_access() {
    let root = unique_cgroup_root("landlock");
    let manager = CgroupV2Manager::new(&root);

    let toml_text = r#"
[sandbox]
landlock_enforce = true
"#;
    let cfg = config::load(toml_text).expect("load landlock config");
    let allow_paths = vec![
        "./**".to_string(),
        "/tmp/**".to_string(),
        "/private/tmp/**".to_string(),
    ];
    let cwd = Path::new("/workspace/project");

    let (plan, _) = SandboxExecutionPlan::prepare_with_write_policy(
        &manager,
        "subagent-landlock",
        &cfg.sandbox,
        &allow_paths,
        cwd,
    )
    .expect("prepare with write policy");

    let ruleset: LandlockRulesetPlan = plan
        .landlock_ruleset
        .expect("landlock ruleset must be compiled when landlock_enforce = true");

    // Reads and executions anywhere under `/` are allowed
    assert_eq!(
        ruleset.simulate_access(
            Path::new("/usr/bin/git"),
            LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_EXECUTE
        ),
        LandlockVerdict::Allow
    );
    assert_eq!(
        ruleset.simulate_access(Path::new("/etc/hosts"), LANDLOCK_ACCESS_FS_READ_FILE),
        LandlockVerdict::Allow
    );

    // Writes inside `/workspace/project` (`./**`) and `/tmp` (`/tmp/**`) are allowed
    assert_eq!(
        ruleset.simulate_access(
            Path::new("/workspace/project/src/lib.rs"),
            LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_TRUNCATE
        ),
        LandlockVerdict::Allow
    );
    assert_eq!(
        ruleset.simulate_access(
            Path::new("/tmp/scratch/out.json"),
            LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_WRITE_FILE
        ),
        LandlockVerdict::Allow
    );

    // Writes outside allowed trees (e.g. `/etc/passwd`, `/workspace/other_repo/file.rs`,
    // or lexical traversal `/workspace/project/../other_repo/secret.txt`) are denied with EACCES
    assert_eq!(
        ruleset.simulate_access(Path::new("/etc/passwd"), LANDLOCK_ACCESS_FS_WRITE_FILE),
        LandlockVerdict::DenyEacces
    );
    assert_eq!(
        ruleset.simulate_access(
            Path::new("/workspace/other_repo/file.rs"),
            LANDLOCK_ACCESS_FS_REMOVE_FILE
        ),
        LandlockVerdict::DenyEacces
    );
    assert_eq!(
        ruleset.simulate_access(
            Path::new("/workspace/project/../other_repo/secret.txt"),
            LANDLOCK_ACCESS_FS_WRITE_FILE
        ),
        LandlockVerdict::DenyEacces
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn cgroup_v2_provisions_pids_max_and_monitors_fork_rejection_events() {
    let root = unique_cgroup_root("pids_max");
    std::fs::write(root.join("cgroup.controllers"), "cpu memory pids\n").unwrap();

    let manager = CgroupV2Manager::new(&root);
    let toml_text = r#"
[sandbox]
max_open_files = 1024
max_cpu_seconds = 120

[sandbox.cgroups]
pids_max = 64
"#;
    let cfg = config::load(toml_text).expect("load pids_max config");
    assert_eq!(cfg.sandbox.cgroups.pids_max, Some(64));
    assert_eq!(cfg.sandbox.max_open_files, Some(1024));
    assert_eq!(cfg.sandbox.max_cpu_seconds, Some(120));

    let (plan, scope_opt) =
        SandboxExecutionPlan::prepare(&manager, "worker-pids", &cfg.sandbox).expect("prepare");
    let scope = scope_opt.expect("scope provisioned for pids_max");

    assert_eq!(plan.pids_max, Some(64));
    assert_eq!(scope.pids_max, Some(64));

    let pids_max_file = std::fs::read_to_string(scope.dir.join("pids.max")).unwrap();
    assert_eq!(pids_max_file.trim(), "64");

    // Simulate kernel reporting pids.current and fork rejection in pids.events
    std::fs::write(scope.dir.join("pids.current"), "64\n").unwrap();
    std::fs::write(scope.dir.join("pids.events"), "max 5\n").unwrap();

    assert_eq!(scope.read_current_pids(), Some(64));
    let pids_events: CgroupPidsEvents = scope.read_pids_events();
    assert_eq!(pids_events.max, 5);
    assert!(pids_events.has_fork_rejected());

    // Teardown cleans up pids.* files and removes the cgroup directory
    scope.teardown().expect("teardown scope with pids files");
    assert!(!scope.dir.exists());

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn rlimit_set_compiles_posix_resource_ceilings_and_simulates_enforcement() {
    let root = unique_cgroup_root("rlimits");
    std::fs::write(root.join("cgroup.controllers"), "cpu memory pids\n").unwrap();
    let manager = CgroupV2Manager::new(&root);

    let toml_text = r#"
[sandbox]
max_pids = 128
max_open_files = 512
max_cpu_seconds = 30
"#;
    let cfg = config::load(toml_text).expect("load rlimit config");
    let rlimits = RlimitSet::from_config(&cfg.sandbox);
    assert!(!rlimits.is_empty());
    assert_eq!(
        rlimits.limit_for(RlimitResource::NoFile),
        Some(RlimitRule {
            resource: RlimitResource::NoFile,
            soft: 512,
            hard: 512,
        })
    );
    assert_eq!(
        rlimits.limit_for(RlimitResource::NProc),
        Some(RlimitRule {
            resource: RlimitResource::NProc,
            soft: 128,
            hard: 128,
        })
    );
    assert_eq!(
        rlimits.limit_for(RlimitResource::CpuSeconds),
        Some(RlimitRule {
            resource: RlimitResource::CpuSeconds,
            soft: 30,
            hard: 30,
        })
    );

    assert!(rlimits.simulate_check(RlimitResource::NoFile, 512));
    assert!(!rlimits.simulate_check(RlimitResource::NoFile, 513));
    assert!(rlimits.simulate_check(RlimitResource::NProc, 128));
    assert!(!rlimits.simulate_check(RlimitResource::NProc, 129));
    assert!(rlimits.simulate_check(RlimitResource::CpuSeconds, 30));
    assert!(!rlimits.simulate_check(RlimitResource::CpuSeconds, 31));

    // Top-level `[sandbox].max_pids` also provisions cgroup `pids.max` as fallback
    let (plan, scope_opt) =
        SandboxExecutionPlan::prepare(&manager, "worker-rlimit", &cfg.sandbox).expect("prepare");
    let scope = scope_opt.expect("scope provisioned from max_pids fallback");
    assert_eq!(plan.pids_max, Some(128));
    assert_eq!(plan.rlimits, rlimits);
    assert_eq!(
        std::fs::read_to_string(scope.dir.join("pids.max"))
            .unwrap()
            .trim(),
        "128"
    );

    scope.teardown().expect("teardown");
    let _ = std::fs::remove_dir_all(&root);
}
