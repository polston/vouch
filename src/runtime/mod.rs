//! eBPF-Assisted Filesystem Write Verification for Linux Environments (M5.3).
//!
//! Provides kernel-level verification of runtime filesystem write mutations
//! using eBPF tracepoints on Linux, detecting unmodeled file writes before disk commit,
//! with safe no-op fallback on macOS/Windows and systems without eBPF capabilities.

pub mod ebpf;
pub mod noop;
pub mod policy;

pub use ebpf::EbpfVerifier;
pub use noop::NoopVerifier;
pub use policy::evaluate_trace;

use std::path::PathBuf;
use crate::config::Config;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesystemEvent {
    pub pid: u32,
    pub syscall: String,
    pub path: PathBuf,
    pub is_write: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExecutionTrace {
    pub events: Vec<FilesystemEvent>,
    pub unpermitted_writes: Vec<PathBuf>,
    pub passed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeError {
    UnsupportedPlatform(String),
    PermissionDenied(String),
    ProbeFailed(String),
}

impl std::fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedPlatform(s) => write!(f, "unsupported platform: {s}"),
            Self::PermissionDenied(s) => write!(f, "permission denied: {s}"),
            Self::ProbeFailed(s) => write!(f, "probe failed: {s}"),
        }
    }
}

impl std::error::Error for RuntimeError {}

/// Trait defining the lifecycle of a runtime write verifier.
pub trait RuntimeVerifier: Send + Sync {
    fn is_supported(&self) -> bool;
    fn monitor_execution(&self, pid: u32, cfg: &Config) -> Result<ExecutionTrace, RuntimeError>;
}

/// Create the appropriate runtime verifier for the current system configuration.
pub fn create_verifier(cfg: &Config) -> Box<dyn RuntimeVerifier> {
    if cfg.runtime.linux.ebpf_tracing {
        #[cfg(target_os = "linux")]
        {
            Box::new(EbpfVerifier::new(cfg.runtime.linux.ebpf_mode.clone()))
        }
        #[cfg(not(target_os = "linux"))]
        {
            Box::new(NoopVerifier::new("eBPF tracing is supported on Linux kernels only"))
        }
    } else {
        Box::new(NoopVerifier::new("eBPF tracing disabled in configuration"))
    }
}
