use std::path::PathBuf;
use vouch::config::load;
use vouch::runtime::{
    create_verifier, evaluate_trace, EbpfVerifier, FilesystemEvent, NoopVerifier, RuntimeVerifier,
};

fn test_config() -> vouch::config::Config {
    load(
        r#"
version = 1

[write]
allow_paths = ["/tmp/**", "/home/dev/workspace/**"]

[protected]
paths = ["/etc/shadow", "/home/dev/.ssh/**"]

[runtime.linux]
ebpf_tracing = true
ebpf_mode = "audit"
trace_ring_buffer_pages = 64
"#,
    )
    .expect("config parses")
}

#[test]
fn runtime_config_parsing_ebpf_options() {
    let cfg = test_config();
    assert!(cfg.runtime.linux.ebpf_tracing);
    assert_eq!(cfg.runtime.linux.ebpf_mode, "audit");
    assert_eq!(cfg.runtime.linux.trace_ring_buffer_pages, 64);
}

#[test]
fn runtime_policy_allowed_writes_pass() {
    let cfg = test_config();
    let events = vec![
        FilesystemEvent {
            pid: 1234,
            syscall: "openat".into(),
            path: PathBuf::from("/tmp/scratch.txt"),
            is_write: true,
        },
        FilesystemEvent {
            pid: 1234,
            syscall: "openat".into(),
            path: PathBuf::from("/home/dev/workspace/build/out.bin"),
            is_write: true,
        },
    ];

    let trace = evaluate_trace(&events, &cfg);
    assert!(trace.passed);
    assert!(trace.unpermitted_writes.is_empty());
}

#[test]
fn runtime_policy_unpermitted_writes_fail() {
    let cfg = test_config();
    let events = vec![
        FilesystemEvent {
            pid: 1234,
            syscall: "openat".into(),
            path: PathBuf::from("/tmp/scratch.txt"),
            is_write: true,
        },
        FilesystemEvent {
            pid: 1234,
            syscall: "unlinkat".into(),
            path: PathBuf::from("/var/lib/docker/container.pid"),
            is_write: true,
        },
    ];

    let trace = evaluate_trace(&events, &cfg);
    assert!(!trace.passed);
    assert_eq!(trace.unpermitted_writes.len(), 1);
    assert_eq!(trace.unpermitted_writes[0], PathBuf::from("/var/lib/docker/container.pid"));
}

#[test]
fn runtime_policy_protected_paths_fail_even_if_under_allowed() {
    let cfg = load(
        r#"
version = 1
[write]
allow_paths = ["/home/dev/**"]
[protected]
paths = ["/home/dev/.ssh/**"]
"#,
    )
    .expect("config parses");

    let events = vec![FilesystemEvent {
        pid: 1234,
        syscall: "openat".into(),
        path: PathBuf::from("/home/dev/.ssh/id_rsa"),
        is_write: true,
    }];

    let trace = evaluate_trace(&events, &cfg);
    assert!(!trace.passed);
    assert_eq!(trace.unpermitted_writes.len(), 1);
}

#[test]
fn runtime_policy_read_events_are_ignored() {
    let cfg = test_config();
    let events = vec![FilesystemEvent {
        pid: 1234,
        syscall: "openat".into(),
        path: PathBuf::from("/etc/passwd"),
        is_write: false,
    }];

    let trace = evaluate_trace(&events, &cfg);
    assert!(trace.passed);
    assert!(trace.unpermitted_writes.is_empty());
}

#[test]
fn noop_verifier_lifecycle() {
    let noop = NoopVerifier::new("test reason");
    assert!(!noop.is_supported());
    let cfg = test_config();
    let res = noop.monitor_execution(1234, &cfg);
    assert!(res.is_ok());
    let trace = res.unwrap();
    assert!(trace.passed);
}

#[test]
fn ebpf_verifier_mock_execution_monitoring() {
    let cfg = test_config();
    let mock_events = vec![
        FilesystemEvent {
            pid: 4321,
            syscall: "openat".into(),
            path: PathBuf::from("/tmp/allowed.log"),
            is_write: true,
        },
        FilesystemEvent {
            pid: 4321,
            syscall: "openat".into(),
            path: PathBuf::from("/etc/crontab"),
            is_write: true,
        },
    ];

    let verifier = EbpfVerifier::with_mock_events("audit".into(), mock_events);
    assert!(verifier.is_supported());

    let res = verifier.monitor_execution(4321, &cfg);
    assert!(res.is_ok());
    let trace = res.unwrap();
    assert!(!trace.passed);
    assert_eq!(trace.unpermitted_writes.len(), 1);
    assert_eq!(trace.unpermitted_writes[0], PathBuf::from("/etc/crontab"));
}

#[test]
fn create_verifier_factory_returns_active_instance() {
    let cfg = test_config();
    let verifier = create_verifier(&cfg);
    // Factory constructs either EbpfVerifier (on Linux) or NoopVerifier
    let res = verifier.monitor_execution(9999, &cfg);
    assert!(res.is_ok());
}
