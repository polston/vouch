//! Streaming Daemon IPC Protocol for Multi-Tenant Subagent Sandboxes.
//!
//! Provides length-prefixed and newline-delimited JSON streaming frames supporting
//! session handshakes with scoped cwd isolation, concurrent evaluation multiplexing,
//! cancellation tokens, and heartbeat keep-alives.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Streaming frame sent from client (subagent or hook wrapper) to the daemon.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type")]
pub enum ClientFrame {
    /// Initial session handshake establishing agent identity and isolation boundaries.
    Handshake {
        agent_id: String,
        session_token: String,
        cwd: PathBuf,
        state_dir: Option<PathBuf>,
    },
    /// Evaluation query for a hook payload within this session's context.
    Evaluate {
        request_id: u64,
        raw_hook_json: String,
    },
    /// Request cancellation of an in-flight evaluation.
    Cancel {
        request_id: u64,
    },
    /// Liveness heartbeat probe.
    Heartbeat,
}

/// Streaming frame sent from daemon back to the client.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type")]
pub enum DaemonFrame {
    /// Acknowledgement of session handshake.
    HandshakeAck {
        version: String,
        capabilities: Vec<String>,
    },
    /// Evaluation decision outcome for a specific request.
    Decision {
        request_id: u64,
        output: Option<String>,
        verdict: String,
        latency_us: u64,
    },
    /// Error outcome for a request or session failure.
    Error {
        request_id: u64,
        message: String,
    },
    /// Response to heartbeat probe.
    Pong,
}

/// Strongly typed container for an evaluation request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluateRequest {
    pub request_id: u64,
    pub raw_hook_json: String,
}

/// Strongly typed container for an evaluation decision output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionOutput {
    pub request_id: u64,
    pub output: Option<String>,
    pub verdict: String,
    pub latency_us: u64,
}
