//! What actually happened to a tool call.
//!
//! The previous design inferred "the user said no" from the ABSENCE of a
//! PostToolUse event. That was measured to be wrong: PostToolUse fired on 23 of
//! 16,850 completed calls, so absence is the normal state of a SUCCESSFUL call
//! and the inference would have mislabelled thousands of them as refusals.
//!
//! The harness publishes the truth directly. Verified in the binary on
//! 2026-07-25:
//!   PermissionDenied     -> tool_name, tool_input, tool_use_id, reason
//!   PostToolUseFailure   -> tool_name, tool_input, tool_use_id, error, is_interrupt
//!   PostToolUse          -> the call ran
//!
//! Anything with no terminal event stays `Unknown` forever, and `Unknown` is
//! never counted as approval OR refusal. That is the whole point: review
//! evidence must come from a real signal, never from silence.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    /// vouch decided; nothing has come back yet.
    Pending,
    /// The call ran.
    Executed,
    /// The call errored, timed out, or was interrupted.
    Failed,
    /// The user refused it.
    Denied,
    /// No terminal event ever arrived. NEVER evidence of anything.
    Unknown,
}

impl Outcome {
    pub fn from_event(event: &str) -> Option<Outcome> {
        match event {
            "PostToolUse" => Some(Outcome::Executed),
            "PostToolUseFailure" => Some(Outcome::Failed),
            "PermissionDenied" => Some(Outcome::Denied),
            _ => None,
        }
    }

    /// Only an executed call that vouch actually ASKED about is evidence that
    /// the user approved something. Everything else is not.
    pub fn is_approval_evidence(self) -> bool {
        matches!(self, Outcome::Executed)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Pending => "pending",
            Outcome::Executed => "executed",
            Outcome::Failed => "failed",
            Outcome::Denied => "denied",
            Outcome::Unknown => "unknown",
        }
    }
}
