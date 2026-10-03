//! Session Management & Context Isolation for Multi-Tenant Subagent Sandboxes.
//!
//! Maintains per-connection session contexts so concurrent subagents executing
//! in distinct workspaces cannot contaminate working directories or leak relative
//! path resolutions.

use std::path::PathBuf;
use crate::daemon::protocol::{DecisionOutput, EvaluateRequest};

/// Context isolation boundary for a single client connection or subagent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionContext {
    pub agent_id: String,
    pub session_token: String,
    pub cwd: PathBuf,
    pub state_dir: PathBuf,
}

impl SessionContext {
    pub fn new(agent_id: String, session_token: String, cwd: PathBuf, state_dir: PathBuf) -> Self {
        Self {
            agent_id,
            session_token,
            cwd,
            state_dir,
        }
    }

    pub fn default_for_cwd(cwd: PathBuf) -> Self {
        Self {
            agent_id: "default".into(),
            session_token: "anonymous".into(),
            state_dir: std::env::temp_dir().join("vouch-default-state"),
            cwd,
        }
    }
}

/// Handler interface for evaluating streaming subagent requests within a session scope.
pub trait DaemonSessionHandler: Send + Sync {
    fn handle_evaluate(&self, session: &SessionContext, req: EvaluateRequest) -> DecisionOutput;
}
