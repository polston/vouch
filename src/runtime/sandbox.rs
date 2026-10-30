//! Kernel Namespaces & cgroups v2 Memory Gating for Sandboxed Subagents (M8.2).
//!
//! Provides Linux cgroups v2 memory limits (`memory.max`, `memory.high`, `cgroup.procs`,
//! `memory.events`) and kernel namespace isolation (`CLONE_NEWUSER`, `CLONE_NEWPID`,
//! `CLONE_NEWNS`) for worker processes.
//!
//! Designed with a virtualizable `cgroup_root` so all cgroupfs hierarchy creation,
//! quota enforcement writes, PID registration, and `oom_kill` event parsing are
//! 100% deterministically testable across macOS, Linux, and Windows without root privileges.

use crate::config::{CgroupsConfig, SandboxConfig, SeccompProfile};
use std::fs::{create_dir_all, remove_dir, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

pub const DEFAULT_CGROUP_ROOT: &str = "/sys/fs/cgroup";
pub const VOUCH_CGROUP_SLICE: &str = "vouch.slice";

// Standard Linux clone(2) / unshare(2) namespace bitflags (from <linux/sched.h>)
pub const CLONE_NEWNS: i32 = 0x0002_0000;
pub const CLONE_NEWUTS: i32 = 0x0400_0000;
pub const CLONE_NEWIPC: i32 = 0x0800_0000;
pub const CLONE_NEWUSER: i32 = 0x1000_0000;
pub const CLONE_NEWPID: i32 = 0x2000_0000;
pub const CLONE_NEWNET: i32 = 0x4000_0000;

// Classic BPF opcodes (<linux/filter.h>) and seccomp constants (<linux/seccomp.h>)
pub const BPF_LD_W_ABS: u16 = 0x20;
pub const BPF_JMP_JEQ_K: u16 = 0x15;
pub const BPF_RET_K: u16 = 0x06;

pub const SECCOMP_DATA_NR_OFFSET: u32 = 0;
pub const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;
pub const SECCOMP_DATA_ARGS_OFFSET: u32 = 16;

pub const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
pub const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
pub const SECCOMP_RET_ERRNO_EPERM: u32 = 0x0005_0001;
pub const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

pub const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
pub const AUDIT_ARCH_AARCH64: u32 = 0xc000_00b7;

/// Bitset of Linux namespaces to isolate for a worker process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NamespaceSpec {
    pub user: bool,
    pub pid: bool,
    pub mount: bool,
    pub ipc: bool,
    pub uts: bool,
    pub net: bool,
}

impl NamespaceSpec {
    /// Standard sandbox namespace profile: isolates user, PID, and mount namespaces.
    pub fn standard_sandbox() -> Self {
        Self {
            user: true,
            pid: true,
            mount: true,
            ipc: false,
            uts: false,
            net: false,
        }
    }

    pub fn from_config(cfg: &SandboxConfig) -> Self {
        let mut spec = if cfg.unshare_namespaces {
            Self::standard_sandbox()
        } else {
            Self::default()
        };
        if cfg.isolate_network {
            spec.net = true;
            // Rootless network namespace creation requires CLONE_NEWUSER
            spec.user = true;
        }
        spec
    }

    pub fn is_enabled(&self) -> bool {
        self.user || self.pid || self.mount || self.ipc || self.uts || self.net
    }

    /// Compute the bitwise OR of Linux `CLONE_NEW*` flags.
    pub fn clone_flags(&self) -> i32 {
        let mut flags = 0i32;
        if self.user {
            flags |= CLONE_NEWUSER;
        }
        if self.pid {
            flags |= CLONE_NEWPID;
        }
        if self.mount {
            flags |= CLONE_NEWNS;
        }
        if self.ipc {
            flags |= CLONE_NEWIPC;
        }
        if self.uts {
            flags |= CLONE_NEWUTS;
        }
        if self.net {
            flags |= CLONE_NEWNET;
        }
        flags
    }

    /// Format rootless single-user UID/GID identity map line (`0 <host_id> 1\n`)
    /// for `/proc/self/uid_map` and `/proc/self/gid_map`.
    pub fn format_id_map(container_id: u32, host_id: u32) -> String {
        format!("{container_id} {host_id} 1\n")
    }
}

/// Loopback interface provisioning specification inside an isolated network namespace (`CLONE_NEWNET`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoopbackInterfaceSpec {
    pub ifname: String,
    pub ipv4_cidr: String,
    pub ipv6_cidr: String,
    pub up: bool,
}

impl Default for LoopbackInterfaceSpec {
    fn default() -> Self {
        Self {
            ifname: "lo".to_string(),
            ipv4_cidr: "127.0.0.1/8".to_string(),
            ipv6_cidr: "::1/128".to_string(),
            up: true,
        }
    }
}

/// Classic BPF (`sock_filter`) instruction used by Linux `seccomp(2)`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BpfInstruction {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

impl BpfInstruction {
    pub const fn stmt(code: u16, k: u32) -> Self {
        Self {
            code,
            jt: 0,
            jf: 0,
            k,
        }
    }

    pub const fn jump(code: u16, k: u32, jt: u8, jf: u8) -> Self {
        Self { code, jt, jf, k }
    }
}

/// Compiled Seccomp-BPF filter program and deterministic in-memory simulator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeccompFilterProgram {
    pub profile: SeccompProfile,
    pub target_arch: u32,
    pub blocked_syscalls: Vec<u32>,
    pub instructions: Vec<BpfInstruction>,
}

impl SeccompFilterProgram {
    /// Returns the Linux `AUDIT_ARCH_*` constant for the host architecture (defaults to `AUDIT_ARCH_X86_64`).
    pub fn native_audit_arch() -> u32 {
        #[cfg(target_arch = "aarch64")]
        {
            AUDIT_ARCH_AARCH64
        }
        #[cfg(not(target_arch = "aarch64"))]
        {
            AUDIT_ARCH_X86_64
        }
    }

    /// Returns the list of blocked syscall numbers for a profile on the given `AUDIT_ARCH_*`.
    pub fn blocked_syscalls_for_arch(profile: SeccompProfile, target_arch: u32) -> Vec<u32> {
        if profile == SeccompProfile::None {
            return Vec::new();
        }
        let mut syscalls = match target_arch {
            AUDIT_ARCH_AARCH64 => vec![
                117, // ptrace
                104, // kexec_load
                294, // kexec_file_load
                280, // bpf
                241, // perf_event_open
                105, // init_module
                273, // finit_module
                106, // delete_module
                40,  // mount
                39,  // umount2
                41,  // pivot_root
                224, // swapon
                225, // swapoff
                142, // reboot
            ],
            _ => vec![
                101, // ptrace
                246, // kexec_load
                320, // kexec_file_load
                321, // bpf
                298, // perf_event_open
                175, // init_module
                313, // finit_module
                176, // delete_module
                165, // mount
                166, // umount2
                155, // pivot_root
                167, // swapon
                168, // swapoff
                169, // reboot
            ],
        };

        if profile == SeccompProfile::Strict {
            match target_arch {
                AUDIT_ARCH_AARCH64 => syscalls.extend_from_slice(&[
                    97,  // unshare
                    268, // setns
                    219, // keyctl
                    217, // add_key
                    218, // request_key
                    282, // userfaultfd
                    425, // io_uring_setup
                    426, // io_uring_enter
                    427, // io_uring_register
                ]),
                _ => syscalls.extend_from_slice(&[
                    272, // unshare
                    308, // setns
                    250, // keyctl
                    248, // add_key
                    249, // request_key
                    323, // userfaultfd
                    425, // io_uring_setup
                    426, // io_uring_enter
                    427, // io_uring_register
                ]),
            }
        }

        syscalls
    }

    /// Compile a Seccomp-BPF filter program for `profile` and `target_arch`.
    /// Returns `None` if `profile == SeccompProfile::None`.
    pub fn for_profile(profile: SeccompProfile, target_arch: u32) -> Option<Self> {
        if profile == SeccompProfile::None {
            return None;
        }
        let blocked_syscalls = Self::blocked_syscalls_for_arch(profile, target_arch);
        let n = blocked_syscalls.len();
        let mut instructions = Vec::with_capacity(n + 6);

        // 0: Load seccomp_data.arch
        instructions.push(BpfInstruction::stmt(BPF_LD_W_ABS, SECCOMP_DATA_ARCH_OFFSET));
        // 1: Jump over KILL if arch == target_arch
        instructions.push(BpfInstruction::jump(BPF_JMP_JEQ_K, target_arch, 1, 0));
        // 2: Kill process on unexpected architecture
        instructions.push(BpfInstruction::stmt(BPF_RET_K, SECCOMP_RET_KILL_PROCESS));
        // 3: Load seccomp_data.nr
        instructions.push(BpfInstruction::stmt(BPF_LD_W_ABS, SECCOMP_DATA_NR_OFFSET));

        // 4..4+n: Jump to ERRNO_EPERM (at index 4 + n + 1) if syscall nr matches
        for (i, &sys_nr) in blocked_syscalls.iter().enumerate() {
            let jump_to_deny = (n - i) as u8;
            instructions.push(BpfInstruction::jump(BPF_JMP_JEQ_K, sys_nr, jump_to_deny, 0));
        }

        // 4+n: Default allow
        instructions.push(BpfInstruction::stmt(BPF_RET_K, SECCOMP_RET_ALLOW));
        // 4+n+1: Deny with EPERM
        instructions.push(BpfInstruction::stmt(BPF_RET_K, SECCOMP_RET_ERRNO_EPERM));

        Some(Self {
            profile,
            target_arch,
            blocked_syscalls,
            instructions,
        })
    }

    /// Deterministically simulate the compiled cBPF bytecode against a synthetic `seccomp_data` payload.
    pub fn simulate(&self, arch: u32, syscall_nr: u32, args: &[u64; 6]) -> u32 {
        let mut acc: u32 = 0;
        let mut pc: usize = 0;
        while pc < self.instructions.len() {
            let insn = self.instructions[pc];
            match insn.code {
                BPF_LD_W_ABS => {
                    acc = match insn.k {
                        SECCOMP_DATA_NR_OFFSET => syscall_nr,
                        SECCOMP_DATA_ARCH_OFFSET => arch,
                        offset if offset >= SECCOMP_DATA_ARGS_OFFSET && offset < SECCOMP_DATA_ARGS_OFFSET + 48 => {
                            let rel = (offset - SECCOMP_DATA_ARGS_OFFSET) as usize;
                            let idx = rel / 8;
                            let is_high = (rel % 8) == 4;
                            if is_high {
                                (args[idx] >> 32) as u32
                            } else {
                                (args[idx] & 0xffff_ffff) as u32
                            }
                        }
                        _ => return SECCOMP_RET_KILL_PROCESS,
                    };
                    pc += 1;
                }
                BPF_JMP_JEQ_K => {
                    if acc == insn.k {
                        pc += 1 + (insn.jt as usize);
                    } else {
                        pc += 1 + (insn.jf as usize);
                    }
                }
                BPF_RET_K => {
                    return insn.k;
                }
                _ => return SECCOMP_RET_KILL_PROCESS,
            }
        }
        SECCOMP_RET_KILL_PROCESS
    }
}

/// Parsed statistics from a cgroup v2 `memory.events` control file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CgroupMemoryEvents {
    pub low: u64,
    pub high: u64,
    pub max: u64,
    pub oom: u64,
    pub oom_kill: u64,
    pub oom_group_kill: u64,
}

impl CgroupMemoryEvents {
    pub fn parse(text: &str) -> Self {
        let mut events = Self::default();
        for line in text.lines() {
            let mut parts = line.split_whitespace();
            let Some(key) = parts.next() else { continue };
            let Some(val_str) = parts.next() else { continue };
            let Ok(val) = val_str.parse::<u64>() else { continue };
            match key {
                "low" => events.low = val,
                "high" => events.high = val,
                "max" => events.max = val,
                "oom" => events.oom = val,
                "oom_kill" => events.oom_kill = val,
                "oom_group_kill" => events.oom_group_kill = val,
                _ => {}
            }
        }
        events
    }

    pub fn has_oom_kill(&self) -> bool {
        self.oom_kill > 0 || self.oom_group_kill > 0
    }

    /// Returns true if the kernel OOM-killed the entire cgroup process tree as a group (`oom_group_kill > 0`).
    pub fn has_oom_group_kill(&self) -> bool {
        self.oom_group_kill > 0
    }
}

/// Parsed statistics from a cgroup v2 `pids.events` control file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CgroupPidsEvents {
    pub max: u64,
}

impl CgroupPidsEvents {
    pub fn parse(text: &str) -> Self {
        let mut events = Self::default();
        for line in text.lines() {
            let mut parts = line.split_whitespace();
            let Some(key) = parts.next() else { continue };
            let Some(val_str) = parts.next() else { continue };
            let Ok(val) = val_str.parse::<u64>() else { continue };
            if key == "max" {
                events.max = val;
            }
        }
        events
    }

    /// Returns true if the kernel rejected at least one `fork()`/`clone()` due to hitting `pids.max`.
    pub fn has_fork_rejected(&self) -> bool {
        self.max > 0
    }
}

pub const DEFAULT_CPU_MAX_PERIOD_US: u64 = 100_000;

/// Parsed statistics from a cgroup v2 `cpu.stat` control file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CgroupCpuStat {
    pub usage_usec: u64,
    pub user_usec: u64,
    pub system_usec: u64,
    pub nr_periods: u64,
    pub nr_throttled: u64,
    pub throttled_usec: u64,
}

impl CgroupCpuStat {
    pub fn parse(text: &str) -> Self {
        let mut stat = Self::default();
        for line in text.lines() {
            let mut parts = line.split_whitespace();
            let Some(key) = parts.next() else { continue };
            let Some(val_str) = parts.next() else { continue };
            let Ok(val) = val_str.parse::<u64>() else { continue };
            match key {
                "usage_usec" => stat.usage_usec = val,
                "user_usec" => stat.user_usec = val,
                "system_usec" => stat.system_usec = val,
                "nr_periods" => stat.nr_periods = val,
                "nr_throttled" => stat.nr_throttled = val,
                "throttled_usec" => stat.throttled_usec = val,
                _ => {}
            }
        }
        stat
    }

    /// Returns true if the kernel throttled CPU execution in at least one scheduling period (`cpu.max`).
    pub fn is_throttled(&self) -> bool {
        self.nr_throttled > 0 || self.throttled_usec > 0
    }
}

/// Rolling stall averages (`avg10`, `avg60`, `avg300`) and cumulative stall microseconds (`total_us`)
/// for a single Linux Pressure Stall Information (`some` or `full`) line.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct PsiWindowMetric {
    pub avg10: f64,
    pub avg60: f64,
    pub avg300: f64,
    pub total_us: u64,
}

/// Parsed Linux Pressure Stall Information (`*.pressure`) for a single resource (`cpu`, `memory`, or `io`).
/// Note that Linux kernel `cpu.pressure` emits `some` and may omit `full` on older kernels.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct PsiResourceMetrics {
    pub some: PsiWindowMetric,
    pub full: Option<PsiWindowMetric>,
}

/// Aggregated Pressure Stall Information (`cpu.pressure`, `memory.pressure`, `io.pressure`)
/// read from a cgroup v2 scope.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct CgroupPsiTelemetry {
    pub cpu: PsiResourceMetrics,
    pub memory: PsiResourceMetrics,
    pub io: PsiResourceMetrics,
}

fn parse_psi_window_line(kind: &str, rest: &str) -> Result<PsiWindowMetric, String> {
    let mut avg10 = None;
    let mut avg60 = None;
    let mut avg300 = None;
    let mut total_us = None;

    for tok in rest.split_whitespace() {
        let (k, v) = tok.split_once('=').ok_or_else(|| {
            format!("invalid PSI token '{tok}' on '{kind}' line (expected key=value)")
        })?;
        match k {
            "avg10" => {
                let parsed = v
                    .parse::<f64>()
                    .map_err(|_| format!("invalid PSI avg10 float '{v}'"))?;
                if !parsed.is_finite() || !(0.0..=100.0).contains(&parsed) {
                    return Err(format!("PSI avg10 '{v}' out of range [0.0, 100.0]"));
                }
                avg10 = Some(parsed);
            }
            "avg60" => {
                let parsed = v
                    .parse::<f64>()
                    .map_err(|_| format!("invalid PSI avg60 float '{v}'"))?;
                if !parsed.is_finite() || !(0.0..=100.0).contains(&parsed) {
                    return Err(format!("PSI avg60 '{v}' out of range [0.0, 100.0]"));
                }
                avg60 = Some(parsed);
            }
            "avg300" => {
                let parsed = v
                    .parse::<f64>()
                    .map_err(|_| format!("invalid PSI avg300 float '{v}'"))?;
                if !parsed.is_finite() || !(0.0..=100.0).contains(&parsed) {
                    return Err(format!("PSI avg300 '{v}' out of range [0.0, 100.0]"));
                }
                avg300 = Some(parsed);
            }
            "total" => {
                let parsed = v
                    .parse::<u64>()
                    .map_err(|_| format!("invalid PSI total microseconds '{v}'"))?;
                total_us = Some(parsed);
            }
            other => {
                return Err(format!(
                    "unknown PSI key '{other}' on '{kind}' line (expected avg10, avg60, avg300, or total)"
                ));
            }
        }
    }

    Ok(PsiWindowMetric {
        avg10: avg10.ok_or_else(|| format!("PSI '{kind}' line missing avg10"))?,
        avg60: avg60.ok_or_else(|| format!("PSI '{kind}' line missing avg60"))?,
        avg300: avg300.ok_or_else(|| format!("PSI '{kind}' line missing avg300"))?,
        total_us: total_us.ok_or_else(|| format!("PSI '{kind}' line missing total"))?,
    })
}

/// Parse a Linux cgroups v2 `cpu.pressure`, `memory.pressure`, or `io.pressure` payload
/// (`some avg10=0.00 avg60=0.00 avg300=0.00 total=0\nfull avg10=...`).
pub fn parse_psi_resource(text: &str) -> Result<PsiResourceMetrics, String> {
    let mut some_opt = None;
    let mut full_opt = None;

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("some ") {
            some_opt = Some(parse_psi_window_line("some", rest)?);
        } else if let Some(rest) = line.strip_prefix("full ") {
            full_opt = Some(parse_psi_window_line("full", rest)?);
        } else {
            return Err(format!(
                "invalid PSI line '{line}' (expected 'some ...' or 'full ...')"
            ));
        }
    }

    let some = some_opt.ok_or_else(|| "PSI resource missing required 'some' line".to_string())?;
    Ok(PsiResourceMetrics {
        some,
        full: full_opt,
    })
}

impl CgroupPsiTelemetry {
    /// Evaluate whether any resource (`cpu`, `memory`, or `io`) has an `avg10` stall percentage
    /// (`some.avg10` or `full.avg10`) exceeding `threshold_pct`. Returns a structured diagnostic
    /// string when exceeded.
    pub fn exceeds_stall_warn_pct(&self, threshold_pct: f64) -> Option<String> {
        let mut exceeded = Vec::new();
        for (name, res) in [
            ("cpu", &self.cpu),
            ("memory", &self.memory),
            ("io", &self.io),
        ] {
            if res.some.avg10 > threshold_pct {
                exceeded.push(format!(
                    "{name}.pressure some.avg10={:.2}% > {:.2}% (total={}us)",
                    res.some.avg10, threshold_pct, res.some.total_us
                ));
            }
            if let Some(full) = res.full {
                if full.avg10 > threshold_pct {
                    exceeded.push(format!(
                        "{name}.pressure full.avg10={:.2}% > {:.2}% (total={}us)",
                        full.avg10, threshold_pct, full.total_us
                    ));
                }
            }
        }
        if exceeded.is_empty() {
            None
        } else {
            Some(format!(
                "cgroup v2 PSI stall warning threshold ({threshold_pct:.2}%) exceeded: {}",
                exceeded.join("; ")
            ))
        }
    }
}

/// A single Linux cgroups v2 `io.max` per-device bandwidth and IOPS throttling rule
/// (`"<major>:<minor> rbps=<bytes|max> wbps=<bytes|max> riops=<ops|max> wiops=<ops|max>"`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CgroupIoMaxRule {
    pub major: u32,
    pub minor: u32,
    pub rbps: Option<u64>,
    pub wbps: Option<u64>,
    pub riops: Option<u64>,
    pub wiops: Option<u64>,
}

impl CgroupIoMaxRule {
    /// Parse and validate a cgroup v2 `io.max` line (`"259:0 rbps=104857600 wbps=52428800 wiops=5000"`).
    pub fn parse(line: &str) -> Result<Self, String> {
        let mut tokens = line.split_whitespace();
        let dev_token = tokens
            .next()
            .ok_or_else(|| "io.max rule is empty".to_string())?;
        let (maj_str, min_str) = dev_token.split_once(':').ok_or_else(|| {
            format!("io.max device '{dev_token}' must be in '<major>:<minor>' format")
        })?;
        let major = maj_str
            .parse::<u32>()
            .map_err(|_| format!("invalid device major number '{maj_str}'"))?;
        let minor = min_str
            .parse::<u32>()
            .map_err(|_| format!("invalid device minor number '{min_str}'"))?;

        let mut rbps = None;
        let mut wbps = None;
        let mut riops = None;
        let mut wiops = None;
        let mut count = 0usize;

        for tok in tokens {
            let (key, val_str) = tok.split_once('=').ok_or_else(|| {
                format!("io.max token '{tok}' must be in '<key>=<value>' format")
            })?;
            let parsed_val = if val_str == "max" {
                None
            } else {
                let v = val_str.parse::<u64>().map_err(|_| {
                    format!("io.max key '{key}' has invalid value '{val_str}' (expected positive integer or 'max')")
                })?;
                if v == 0 {
                    return Err(format!("io.max key '{key}' value must be greater than 0"));
                }
                Some(v)
            };
            match key {
                "rbps" => rbps = parsed_val,
                "wbps" => wbps = parsed_val,
                "riops" => riops = parsed_val,
                "wiops" => wiops = parsed_val,
                other => {
                    return Err(format!(
                        "unknown io.max key '{other}' (expected rbps, wbps, riops, or wiops)"
                    ));
                }
            }
            count += 1;
        }

        if count == 0 {
            return Err(
                "io.max rule must specify at least one limit (rbps, wbps, riops, or wiops)"
                    .to_string(),
            );
        }

        Ok(Self {
            major,
            minor,
            rbps,
            wbps,
            riops,
            wiops,
        })
    }

    /// Format this rule as a canonical cgroup v2 `io.max` line.
    pub fn format_line(&self) -> String {
        let mut parts = vec![format!("{}:{}", self.major, self.minor)];
        if let Some(v) = self.rbps {
            parts.push(format!("rbps={v}"));
        }
        if let Some(v) = self.wbps {
            parts.push(format!("wbps={v}"));
        }
        if let Some(v) = self.riops {
            parts.push(format!("riops={v}"));
        }
        if let Some(v) = self.wiops {
            parts.push(format!("wiops={v}"));
        }
        if parts.len() == 1 {
            parts.push("rbps=max wbps=max riops=max wiops=max".to_string());
        }
        parts.join(" ")
    }
}

/// POSIX `setrlimit(2)` resource type enforced for sandboxed worker processes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RlimitResource {
    /// Maximum open file descriptor count (`RLIMIT_NOFILE`).
    NoFile,
    /// Maximum number of processes/threads (`RLIMIT_NPROC`).
    NProc,
    /// Maximum CPU time in seconds (`RLIMIT_CPU`).
    CpuSeconds,
}

/// A single POSIX `setrlimit(2)` soft/hard resource ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RlimitRule {
    pub resource: RlimitResource,
    pub soft: u64,
    pub hard: u64,
}

/// Collection of POSIX `setrlimit(2)` ceilings configured for a sandboxed worker process.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RlimitSet {
    pub rules: Vec<RlimitRule>,
}

impl RlimitSet {
    pub fn from_config(cfg: &SandboxConfig) -> Self {
        let mut rules = Vec::new();
        if let Some(nofile) = cfg.max_open_files.filter(|&v| v > 0) {
            rules.push(RlimitRule {
                resource: RlimitResource::NoFile,
                soft: nofile,
                hard: nofile,
            });
        }
        if let Some(nproc) = cfg.max_pids.or(cfg.cgroups.pids_max).filter(|&v| v > 0) {
            rules.push(RlimitRule {
                resource: RlimitResource::NProc,
                soft: nproc,
                hard: nproc,
            });
        }
        if let Some(cpu_secs) = cfg.max_cpu_seconds.filter(|&v| v > 0) {
            rules.push(RlimitRule {
                resource: RlimitResource::CpuSeconds,
                soft: cpu_secs,
                hard: cpu_secs,
            });
        }
        Self { rules }
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn limit_for(&self, resource: RlimitResource) -> Option<RlimitRule> {
        self.rules.iter().copied().find(|r| r.resource == resource)
    }

    /// Deterministically check whether `requested` units of `resource` are permitted by this `RlimitSet`.
    pub fn simulate_check(&self, resource: RlimitResource, requested: u64) -> bool {
        match self.limit_for(resource) {
            Some(rule) => requested <= rule.hard,
            None => true,
        }
    }

    /// Apply configured `RLIMIT_NOFILE`, `RLIMIT_NPROC`, and `RLIMIT_CPU` ceilings via `libc::setrlimit`.
    #[cfg(target_os = "linux")]
    pub fn apply_in_current_process(&self) -> std::io::Result<()> {
        for rule in &self.rules {
            let resource_id = match rule.resource {
                RlimitResource::NoFile => libc::RLIMIT_NOFILE,
                RlimitResource::NProc => libc::RLIMIT_NPROC,
                RlimitResource::CpuSeconds => libc::RLIMIT_CPU,
            };
            let rlim = libc::rlimit {
                rlim_cur: rule.soft as libc::rlim_t,
                rlim_max: rule.hard as libc::rlim_t,
            };
            let rc = unsafe { libc::setrlimit(resource_id, &rlim as *const libc::rlimit) };
            if rc != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        Ok(())
    }
}

/// Manages a cgroups v2 hierarchy under a configurable root (default `/sys/fs/cgroup`).
#[derive(Debug, Clone)]
pub struct CgroupV2Manager {
    cgroup_root: PathBuf,
    slice_name: String,
}

impl Default for CgroupV2Manager {
    fn default() -> Self {
        Self::new(DEFAULT_CGROUP_ROOT)
    }
}

impl CgroupV2Manager {
    pub fn new(cgroup_root: impl Into<PathBuf>) -> Self {
        Self {
            cgroup_root: cgroup_root.into(),
            slice_name: VOUCH_CGROUP_SLICE.to_string(),
        }
    }

    pub fn with_slice(mut self, slice_name: impl Into<String>) -> Self {
        self.slice_name = slice_name.into();
        self
    }

    pub fn cgroup_root(&self) -> &Path {
        &self.cgroup_root
    }

    pub fn worker_cgroup_dir(&self, scope_id: &str) -> PathBuf {
        let sanitized: String = scope_id
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
            .collect();
        self.cgroup_root
            .join(&self.slice_name)
            .join(format!("vouch-worker-{sanitized}"))
    }

    /// Returns true if the target cgroup v2 unified hierarchy root is present and writable.
    pub fn is_available(&self) -> bool {
        self.cgroup_root.is_dir() && self.cgroup_root.join("cgroup.controllers").exists()
    }

    /// Provision a cgroup v2 directory for `scope_id` and apply configured memory, PID, CPU bandwidth, and block I/O limits.
    pub fn provision_scope(
        &self,
        scope_id: &str,
        cfg: &CgroupsConfig,
    ) -> std::io::Result<CgroupScope> {
        let dir = self.worker_cgroup_dir(scope_id);
        create_dir_all(&dir)?;

        if let Some(max_mb) = cfg.max_memory_mb {
            let max_bytes = max_mb.saturating_mul(1024 * 1024);
            write_control_file(&dir.join("memory.max"), &max_bytes.to_string())?;
        } else {
            write_control_file(&dir.join("memory.max"), "max")?;
        }

        if let Some(high_mb) = cfg.high_memory_mb {
            let high_bytes = high_mb.saturating_mul(1024 * 1024);
            write_control_file(&dir.join("memory.high"), &high_bytes.to_string())?;
        } else {
            write_control_file(&dir.join("memory.high"), "max")?;
        }

        if let Some(swap_bytes) = cfg.memory_swap_max_bytes {
            write_control_file(&dir.join("memory.swap.max"), &swap_bytes.to_string())?;
        } else {
            write_control_file(&dir.join("memory.swap.max"), "max")?;
        }

        if let Some(oom_group) = cfg.memory_oom_group {
            write_control_file(
                &dir.join("memory.oom.group"),
                if oom_group { "1" } else { "0" },
            )?;
        }

        let effective_pids_max = cfg.pids_max.filter(|&v| v > 0);
        if let Some(pids_max) = effective_pids_max {
            write_control_file(&dir.join("pids.max"), &pids_max.to_string())?;
        } else {
            write_control_file(&dir.join("pids.max"), "max")?;
        }

        let effective_cpu_quota = cfg.cpu_max_quota_us.filter(|&v| v > 0);
        let effective_cpu_period = if effective_cpu_quota.is_some() || cfg.cpu_max_period_us.is_some()
        {
            Some(
                cfg.cpu_max_period_us
                    .filter(|&v| v > 0)
                    .unwrap_or(DEFAULT_CPU_MAX_PERIOD_US),
            )
        } else {
            None
        };
        if let Some(period) = effective_cpu_period {
            if let Some(quota) = effective_cpu_quota {
                write_control_file(&dir.join("cpu.max"), &format!("{quota} {period}"))?;
            } else {
                write_control_file(&dir.join("cpu.max"), &format!("max {period}"))?;
            }
        } else {
            write_control_file(&dir.join("cpu.max"), &format!("max {DEFAULT_CPU_MAX_PERIOD_US}"))?;
        }

        let mut io_max_rules = Vec::with_capacity(cfg.io_max.len());
        for raw_rule in &cfg.io_max {
            let rule = CgroupIoMaxRule::parse(raw_rule)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
            io_max_rules.push(rule);
        }
        if !io_max_rules.is_empty() {
            let lines: Vec<String> = io_max_rules
                .iter()
                .map(CgroupIoMaxRule::format_line)
                .collect();
            write_control_file(&dir.join("io.max"), &lines.join("\n"))?;
        }

        Ok(CgroupScope {
            dir,
            max_memory_bytes: cfg.max_memory_mb.map(|mb| mb.saturating_mul(1024 * 1024)),
            high_memory_bytes: cfg.high_memory_mb.map(|mb| mb.saturating_mul(1024 * 1024)),
            memory_swap_max_bytes: cfg.memory_swap_max_bytes,
            memory_oom_group: cfg.memory_oom_group,
            pids_max: effective_pids_max,
            cpu_max_quota_us: effective_cpu_quota,
            cpu_max_period_us: effective_cpu_period,
            io_max_rules,
        })
    }
}

fn write_control_file(path: &Path, value: &str) -> std::io::Result<()> {
    let mut f = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)?;
    f.write_all(value.as_bytes())?;
    f.write_all(b"\n")?;
    f.flush()
}

/// Active cgroup v2 scope for a sandboxed worker process.
#[derive(Debug, Clone)]
pub struct CgroupScope {
    pub dir: PathBuf,
    pub max_memory_bytes: Option<u64>,
    pub high_memory_bytes: Option<u64>,
    pub memory_swap_max_bytes: Option<u64>,
    pub memory_oom_group: Option<bool>,
    pub pids_max: Option<u64>,
    pub cpu_max_quota_us: Option<u64>,
    pub cpu_max_period_us: Option<u64>,
    pub io_max_rules: Vec<CgroupIoMaxRule>,
}

impl CgroupScope {
    /// Attach a process PID to this cgroup by writing to `cgroup.procs`.
    pub fn attach_pid(&self, pid: u32) -> std::io::Result<()> {
        let procs_path = self.dir.join("cgroup.procs");
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(procs_path)?;
        writeln!(f, "{pid}")?;
        f.flush()
    }

    /// Read all attached PIDs currently listed in `cgroup.procs`.
    pub fn attached_pids(&self) -> Vec<u32> {
        let procs_path = self.dir.join("cgroup.procs");
        let Ok(content) = std::fs::read_to_string(procs_path) else {
            return Vec::new();
        };
        content
            .lines()
            .filter_map(|l| l.trim().parse::<u32>().ok())
            .collect()
    }

    /// Read current memory usage in bytes from `memory.current`.
    pub fn read_current_memory_bytes(&self) -> Option<u64> {
        let text = std::fs::read_to_string(self.dir.join("memory.current")).ok()?;
        text.trim().parse::<u64>().ok()
    }

    /// Read current swap memory usage in bytes from `memory.swap.current`.
    pub fn read_current_swap_bytes(&self) -> Option<u64> {
        let text = std::fs::read_to_string(self.dir.join("memory.swap.current")).ok()?;
        text.trim().parse::<u64>().ok()
    }

    /// Read the configured swap ceiling in bytes from `memory.swap.max` (`None` if `"max"` or absent).
    pub fn read_memory_swap_max(&self) -> Option<u64> {
        let text = std::fs::read_to_string(self.dir.join("memory.swap.max")).ok()?;
        let trimmed = text.trim();
        if trimmed == "max" {
            None
        } else {
            trimmed.parse::<u64>().ok()
        }
    }

    /// Read `memory.oom.group` (`Some(true)` for `"1"`, `Some(false)` for `"0"`, `None` otherwise).
    pub fn read_memory_oom_group(&self) -> Option<bool> {
        let text = std::fs::read_to_string(self.dir.join("memory.oom.group")).ok()?;
        match text.trim() {
            "1" => Some(true),
            "0" => Some(false),
            _ => None,
        }
    }

    /// Read and parse `memory.events` (including `oom_kill` counters).
    pub fn read_memory_events(&self) -> CgroupMemoryEvents {
        let Ok(text) = std::fs::read_to_string(self.dir.join("memory.events")) else {
            return CgroupMemoryEvents::default();
        };
        CgroupMemoryEvents::parse(&text)
    }

    /// Read current process/thread count from `pids.current`.
    pub fn read_current_pids(&self) -> Option<u64> {
        let text = std::fs::read_to_string(self.dir.join("pids.current")).ok()?;
        text.trim().parse::<u64>().ok()
    }

    /// Read and parse `pids.events` (including `max` fork-rejection counter).
    pub fn read_pids_events(&self) -> CgroupPidsEvents {
        let Ok(text) = std::fs::read_to_string(self.dir.join("pids.events")) else {
            return CgroupPidsEvents::default();
        };
        CgroupPidsEvents::parse(&text)
    }

    /// Read and parse `cpu.stat` (including `nr_periods`, `nr_throttled`, and `throttled_usec`).
    pub fn read_cpu_stat(&self) -> CgroupCpuStat {
        let Ok(text) = std::fs::read_to_string(self.dir.join("cpu.stat")) else {
            return CgroupCpuStat::default();
        };
        CgroupCpuStat::parse(&text)
    }

    /// Read and parse `io.max` device throttling rules currently written in this scope.
    pub fn read_io_max(&self) -> Vec<CgroupIoMaxRule> {
        let Ok(text) = std::fs::read_to_string(self.dir.join("io.max")) else {
            return Vec::new();
        };
        text.lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .filter_map(|l| CgroupIoMaxRule::parse(l).ok())
            .collect()
    }

    /// Read and parse Pressure Stall Information (`cpu.pressure`, `memory.pressure`, `io.pressure`)
    /// from this cgroup v2 scope directory. Missing pressure files default to zero stall metrics.
    pub fn read_psi_telemetry(&self) -> std::io::Result<CgroupPsiTelemetry> {
        let read_one = |filename: &str| -> std::io::Result<PsiResourceMetrics> {
            let p = self.dir.join(filename);
            if !p.exists() {
                return Ok(PsiResourceMetrics::default());
            }
            let text = std::fs::read_to_string(&p)?;
            parse_psi_resource(&text)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        };
        Ok(CgroupPsiTelemetry {
            cpu: read_one("cpu.pressure")?,
            memory: read_one("memory.pressure")?,
            io: read_one("io.pressure")?,
        })
    }

    /// Remove the worker cgroup directory when no processes remain.
    pub fn teardown(&self) -> std::io::Result<()> {
        if self.dir.exists() {
            for file in [
                "cgroup.procs",
                "memory.max",
                "memory.high",
                "memory.swap.max",
                "memory.swap.current",
                "memory.oom.group",
                "memory.current",
                "memory.events",
                "memory.pressure",
                "pids.max",
                "pids.current",
                "pids.events",
                "cpu.max",
                "cpu.stat",
                "cpu.pressure",
                "io.max",
                "io.stat",
                "io.pressure",
            ] {
                let p = self.dir.join(file);
                if p.is_file() {
                    let _ = std::fs::remove_file(p);
                }
            }
            let _ = remove_dir(&self.dir);
        }
        Ok(())
    }
}

/// Linux Landlock LSM (`<linux/landlock.h>`) filesystem access bitflags (ABI v1–v3).
pub const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
pub const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
pub const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
pub const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
pub const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
pub const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
pub const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
pub const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
pub const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
pub const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
pub const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
pub const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
pub const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;
pub const LANDLOCK_ACCESS_FS_REFER: u64 = 1 << 13;
pub const LANDLOCK_ACCESS_FS_TRUNCATE: u64 = 1 << 14;

pub const LANDLOCK_READ_EXEC_MASK: u64 =
    LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;

pub const LANDLOCK_WRITE_MASK: u64 = LANDLOCK_ACCESS_FS_WRITE_FILE
    | LANDLOCK_ACCESS_FS_REMOVE_DIR
    | LANDLOCK_ACCESS_FS_REMOVE_FILE
    | LANDLOCK_ACCESS_FS_MAKE_CHAR
    | LANDLOCK_ACCESS_FS_MAKE_DIR
    | LANDLOCK_ACCESS_FS_MAKE_REG
    | LANDLOCK_ACCESS_FS_MAKE_SOCK
    | LANDLOCK_ACCESS_FS_MAKE_FIFO
    | LANDLOCK_ACCESS_FS_MAKE_BLOCK
    | LANDLOCK_ACCESS_FS_MAKE_SYM
    | LANDLOCK_ACCESS_FS_REFER
    | LANDLOCK_ACCESS_FS_TRUNCATE;

pub const LANDLOCK_HANDLED_ACCESS_FS_V3: u64 = LANDLOCK_READ_EXEC_MASK | LANDLOCK_WRITE_MASK;

/// A single `landlock_path_beneath_attr` hierarchy rule mapping a directory/file path to allowed access bits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LandlockPathRule {
    pub parent_path: PathBuf,
    pub allowed_access: u64,
}

/// Result of evaluating a filesystem operation against a `LandlockRulesetPlan`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LandlockVerdict {
    Allow,
    DenyEacces,
}

/// Compiled Linux Landlock LSM ruleset plan and deterministic cross-platform hierarchy evaluator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LandlockRulesetPlan {
    pub handled_access_fs: u64,
    pub rules: Vec<LandlockPathRule>,
}

fn normalize_lexical_path(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                let _ = out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    if out.as_os_str().is_empty() {
        PathBuf::from("/")
    } else {
        out
    }
}

fn strip_glob_pattern_to_dir(pattern: &str, cwd: &Path) -> PathBuf {
    let mut s = pattern.trim();
    if let Some(stripped) = s.strip_suffix("/**") {
        s = stripped;
    } else if let Some(stripped) = s.strip_suffix("/*") {
        s = stripped;
    } else if let Some(stripped) = s.strip_suffix('*') {
        s = stripped.trim_end_matches('/');
    }
    if s.is_empty() || s == "." {
        return normalize_lexical_path(cwd);
    }
    if let Some(rest) = s.strip_prefix("./") {
        return normalize_lexical_path(&cwd.join(rest));
    }
    let p = Path::new(s);
    if p.is_absolute() {
        normalize_lexical_path(p)
    } else {
        normalize_lexical_path(&cwd.join(p))
    }
}

impl LandlockRulesetPlan {
    /// Translate Vouch's `[write].allow_paths` and session `cwd` into a Landlock `path_beneath` ruleset.
    /// Grants `LANDLOCK_READ_EXEC_MASK` globally on `/` and `LANDLOCK_READ_EXEC_MASK | LANDLOCK_WRITE_MASK`
    /// beneath each resolved `allow_paths` tree.
    pub fn from_write_policy(allow_paths: &[String], cwd: &Path) -> Self {
        let mut rules = Vec::with_capacity(1 + allow_paths.len());
        rules.push(LandlockPathRule {
            parent_path: PathBuf::from("/"),
            allowed_access: LANDLOCK_READ_EXEC_MASK,
        });

        for pat in allow_paths {
            let resolved = strip_glob_pattern_to_dir(pat, cwd);
            let full_access = LANDLOCK_READ_EXEC_MASK | LANDLOCK_WRITE_MASK;
            if let Some(existing) = rules.iter_mut().find(|r| r.parent_path == resolved) {
                existing.allowed_access |= full_access;
            } else {
                rules.push(LandlockPathRule {
                    parent_path: resolved,
                    allowed_access: full_access,
                });
            }
        }

        Self {
            handled_access_fs: LANDLOCK_HANDLED_ACCESS_FS_V3,
            rules,
        }
    }

    /// Deterministically evaluate whether `requested_access` on `target_path` is permitted by this
    /// Landlock ruleset hierarchy (`Allow` vs `DenyEacces`).
    pub fn simulate_access(&self, target_path: &Path, requested_access: u64) -> LandlockVerdict {
        let needed = requested_access & self.handled_access_fs;
        if needed == 0 {
            return LandlockVerdict::Allow;
        }
        let norm_target = normalize_lexical_path(target_path);
        let mut granted = 0u64;
        for rule in &self.rules {
            let norm_parent = normalize_lexical_path(&rule.parent_path);
            if norm_target == norm_parent || norm_target.starts_with(&norm_parent) {
                granted |= rule.allowed_access;
            }
        }
        if (granted & needed) == needed {
            LandlockVerdict::Allow
        } else {
            LandlockVerdict::DenyEacces
        }
    }
}

/// Summary report of sandbox isolation applied to a worker process.
#[derive(Debug, Clone, PartialEq)]
pub struct SandboxExecutionPlan {
    pub scope_id: String,
    pub cgroup_dir: Option<PathBuf>,
    pub max_memory_bytes: Option<u64>,
    pub high_memory_bytes: Option<u64>,
    pub memory_swap_max_bytes: Option<u64>,
    pub memory_oom_group: Option<bool>,
    pub pids_max: Option<u64>,
    pub cpu_max_quota_us: Option<u64>,
    pub cpu_max_period_us: Option<u64>,
    pub io_max_rules: Vec<CgroupIoMaxRule>,
    pub psi_stall_warn_pct: Option<f64>,
    pub rlimits: RlimitSet,
    pub namespaces: NamespaceSpec,
    pub clone_flags: i32,
    pub loopback: Option<LoopbackInterfaceSpec>,
    pub seccomp_filter: Option<SeccompFilterProgram>,
    pub landlock_ruleset: Option<LandlockRulesetPlan>,
}

impl SandboxExecutionPlan {
    pub fn prepare(
        manager: &CgroupV2Manager,
        scope_id: &str,
        cfg: &SandboxConfig,
    ) -> std::io::Result<(Self, Option<CgroupScope>)> {
        Self::prepare_with_write_policy(
            manager,
            scope_id,
            cfg,
            &["./**".to_string(), "/tmp/**".to_string()],
            Path::new("/workspace"),
        )
    }

    pub fn prepare_with_write_policy(
        manager: &CgroupV2Manager,
        scope_id: &str,
        cfg: &SandboxConfig,
        allow_paths: &[String],
        cwd: &Path,
    ) -> std::io::Result<(Self, Option<CgroupScope>)> {
        let namespaces = NamespaceSpec::from_config(cfg);
        let clone_flags = namespaces.clone_flags();

        let effective_cgroups = CgroupsConfig {
            max_memory_mb: cfg.cgroups.max_memory_mb,
            high_memory_mb: cfg.cgroups.high_memory_mb,
            memory_swap_max_bytes: cfg.cgroups.memory_swap_max_bytes,
            memory_oom_group: cfg.cgroups.memory_oom_group,
            pids_max: cfg.cgroups.pids_max.or(cfg.max_pids),
            cpu_max_quota_us: cfg.cgroups.cpu_max_quota_us,
            cpu_max_period_us: cfg.cgroups.cpu_max_period_us,
            io_max: cfg.cgroups.io_max.clone(),
            psi_stall_warn_pct: cfg.cgroups.psi_stall_warn_pct,
        };
        let has_cgroup_limits = effective_cgroups.max_memory_mb.is_some()
            || effective_cgroups.high_memory_mb.is_some()
            || effective_cgroups.memory_swap_max_bytes.is_some()
            || effective_cgroups.memory_oom_group.is_some()
            || effective_cgroups.pids_max.is_some()
            || effective_cgroups.cpu_max_quota_us.is_some()
            || effective_cgroups.cpu_max_period_us.is_some()
            || !effective_cgroups.io_max.is_empty()
            || effective_cgroups.psi_stall_warn_pct.is_some();

        let scope = if has_cgroup_limits {
            Some(manager.provision_scope(scope_id, &effective_cgroups)?)
        } else {
            None
        };

        let rlimits = RlimitSet::from_config(cfg);

        let loopback = if namespaces.net {
            Some(LoopbackInterfaceSpec::default())
        } else {
            None
        };

        let seccomp_filter = cfg
            .seccomp_profile
            .and_then(|profile| SeccompFilterProgram::for_profile(profile, SeccompFilterProgram::native_audit_arch()));

        let landlock_ruleset = if cfg.landlock_enforce {
            Some(LandlockRulesetPlan::from_write_policy(allow_paths, cwd))
        } else {
            None
        };

        let plan = Self {
            scope_id: scope_id.to_string(),
            cgroup_dir: scope.as_ref().map(|s| s.dir.clone()),
            max_memory_bytes: scope.as_ref().and_then(|s| s.max_memory_bytes),
            high_memory_bytes: scope.as_ref().and_then(|s| s.high_memory_bytes),
            memory_swap_max_bytes: scope.as_ref().and_then(|s| s.memory_swap_max_bytes),
            memory_oom_group: scope.as_ref().and_then(|s| s.memory_oom_group),
            pids_max: scope.as_ref().and_then(|s| s.pids_max),
            cpu_max_quota_us: scope.as_ref().and_then(|s| s.cpu_max_quota_us),
            cpu_max_period_us: scope.as_ref().and_then(|s| s.cpu_max_period_us),
            io_max_rules: scope
                .as_ref()
                .map(|s| s.io_max_rules.clone())
                .unwrap_or_default(),
            psi_stall_warn_pct: effective_cgroups.psi_stall_warn_pct,
            rlimits,
            namespaces,
            clone_flags,
            loopback,
            seccomp_filter,
            landlock_ruleset,
        };

        Ok((plan, scope))
    }

    /// Apply Linux kernel `unshare(2)`, rootless UID/GID mappings, POSIX `setrlimit(2)` ceilings,
    /// Landlock LSM ruleset, and Seccomp-BPF filter inside a child process pre-exec hook.
    #[cfg(target_os = "linux")]
    pub fn apply_in_child_process(&self) -> std::io::Result<()> {
        if self.clone_flags != 0 {
            let uid = unsafe { libc::geteuid() };
            let gid = unsafe { libc::getegid() };
            let rc = unsafe { libc::unshare(self.clone_flags) };
            if rc != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if self.namespaces.user {
                let _ = std::fs::write("/proc/self/setgroups", b"deny\n");
                let _ = std::fs::write(
                    "/proc/self/uid_map",
                    NamespaceSpec::format_id_map(0, uid).as_bytes(),
                );
                let _ = std::fs::write(
                    "/proc/self/gid_map",
                    NamespaceSpec::format_id_map(0, gid).as_bytes(),
                );
            }
        }
        if let Some(ref cg_dir) = self.cgroup_dir {
            let pid = std::process::id();
            let procs_path = cg_dir.join("cgroup.procs");
            if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(procs_path) {
                let _ = writeln!(f, "{pid}");
            }
        }
        self.rlimits.apply_in_current_process()?;
        if let Some(ref ruleset) = self.landlock_ruleset {
            #[repr(C)]
            struct LandlockRulesetAttr {
                handled_access_fs: u64,
            }
            #[repr(C, packed)]
            struct LandlockPathBeneathAttr {
                allowed_access: u64,
                parent_fd: i32,
            }
            const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
            const SYS_LANDLOCK_ADD_RULE: libc::c_long = 445;
            const SYS_LANDLOCK_RESTRICT_SELF: libc::c_long = 446;
            const LANDLOCK_RULE_PATH_BENEATH: libc::c_uint = 1;

            let _ = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
            let attr = LandlockRulesetAttr {
                handled_access_fs: ruleset.handled_access_fs,
            };
            let ruleset_fd = unsafe {
                libc::syscall(
                    SYS_LANDLOCK_CREATE_RULESET,
                    &attr as *const LandlockRulesetAttr,
                    std::mem::size_of::<LandlockRulesetAttr>(),
                    0usize,
                )
            };
            if ruleset_fd >= 0 {
                let fd = ruleset_fd as libc::c_int;
                for rule in &ruleset.rules {
                    if let Ok(c_path) = std::ffi::CString::new(rule.parent_path.to_string_lossy().as_bytes()) {
                        let parent_fd = unsafe {
                            libc::open(c_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC)
                        };
                        if parent_fd >= 0 {
                            let path_attr = LandlockPathBeneathAttr {
                                allowed_access: rule.allowed_access,
                                parent_fd,
                            };
                            let _ = unsafe {
                                libc::syscall(
                                    SYS_LANDLOCK_ADD_RULE,
                                    fd,
                                    LANDLOCK_RULE_PATH_BENEATH,
                                    &path_attr as *const LandlockPathBeneathAttr,
                                    0usize,
                                )
                            };
                            unsafe {
                                libc::close(parent_fd);
                            }
                        }
                    }
                }
                let _ = unsafe { libc::syscall(SYS_LANDLOCK_RESTRICT_SELF, fd, 0usize) };
                unsafe {
                    libc::close(fd);
                }
            }
        }
        if let Some(ref filter) = self.seccomp_filter {
            #[repr(C)]
            struct SockFprog {
                len: libc::c_ushort,
                filter: *const BpfInstruction,
            }
            let rc_no_new_privs = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
            if rc_no_new_privs != 0 {
                return Err(std::io::Error::last_os_error());
            }
            let prog = SockFprog {
                len: filter.instructions.len() as libc::c_ushort,
                filter: filter.instructions.as_ptr(),
            };
            let rc_seccomp = unsafe {
                libc::prctl(
                    libc::PR_SET_SECCOMP,
                    libc::SECCOMP_MODE_FILTER,
                    &prog as *const SockFprog,
                    0,
                    0,
                )
            };
            if rc_seccomp != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        Ok(())
    }
}
