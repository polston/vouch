//! No-Op Runtime Verifier for Unsupported Platforms and Disabled States.

use crate::config::Config;
use super::{ExecutionTrace, RuntimeError, RuntimeVerifier};

pub struct NoopVerifier {
    reason: String,
}

impl NoopVerifier {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }
}

impl RuntimeVerifier for NoopVerifier {
    fn is_supported(&self) -> bool {
        false
    }

    fn monitor_execution(&self, _pid: u32, _cfg: &Config) -> Result<ExecutionTrace, RuntimeError> {
        Ok(ExecutionTrace {
            events: Vec::new(),
            unpermitted_writes: Vec::new(),
            passed: true,
        })
    }
}
