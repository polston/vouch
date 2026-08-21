//! The Claude Code PreToolUse hook protocol.
//!
//! Two rules live here and must not be relaxed:
//!   1. `Decision::Abstain` renders to *nothing at all* — no output, exit 0.
//!      The `defer` verdict is deliberately unsupported: it is ignored by the
//!      interactive app and ends the turn in headless runs.
//!   2. Reason text is passed through verbatim, including newlines. The
//!      self-explaining prompt depends on it arriving whole.

use serde::Deserialize;

#[derive(Debug, Deserialize, Default)]
pub struct ToolInput {
    pub command: Option<String>,
    pub file_path: Option<String>,
    pub url: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Deserialize, Default)]
pub struct HookInput {
    /// Which hook fired. PreToolUse decides; the others report outcomes.
    #[serde(default)]
    pub hook_event_name: String,
    /// Correlates a decision with its outcome. Present on every tool event.
    #[serde(default)]
    pub tool_use_id: String,
    /// PermissionDenied carries why.
    #[serde(default)]
    pub reason: String,
    /// PostToolUseFailure carries these.
    #[serde(default)]
    pub error: String,
    #[serde(default)]
    pub is_interrupt: bool,
    #[serde(default)]
    pub session_id: String,
    #[serde(default)]
    pub cwd: String,
    /// The effective permission mode of THIS call, as the harness reports it
    /// — a per-call fact: an agent definition with a pinned mode overrides
    /// the session's. Empty when the caller did not supply it, which matches
    /// no `[shadow]` mode (fail-closed: vouch stays live).
    #[serde(default)]
    pub permission_mode: String,
    #[serde(default)]
    pub tool_name: String,
    #[serde(default)]
    pub tool_input: ToolInput,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow(String),
    Ask(String),
    Deny(String),
    /// Emit nothing. Used in shadow mode and whenever vouch has no opinion.
    Abstain,
}

pub fn parse_input(raw: &str) -> Result<HookInput, serde_json::Error> {
    serde_json::from_str(raw)
}

/// Renders the hook response. `None` means emit nothing at all.
pub fn render(d: &Decision) -> Option<String> {
    let (verdict, reason) = match d {
        Decision::Abstain => return None,
        Decision::Allow(r) => ("allow", r),
        Decision::Ask(r) => ("ask", r),
        Decision::Deny(r) => ("deny", r),
    };
    let body = serde_json::json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": verdict,
            "permissionDecisionReason": reason,
        }
    });
    Some(body.to_string())
}

/// The emission step of mode-keyed shadow (design 2026-08-16): given the
/// toggle, whether this call's permission mode is listed in `[shadow].modes`,
/// the computed decision, and whether an Ask is a protection ask, say
/// whether the decision is emitted and which journal `mode` word the rows
/// carry. Pure, so the whole table is unit-testable; `main.rs` only wires
/// it. The `--shadow` flag is the caller's business and WINS over this.
pub fn stand_down_emission(
    toggle: crate::config::StandDown,
    mode_listed: bool,
    d: &Decision,
    protection_ask: bool,
) -> (bool, &'static str) {
    use crate::config::StandDown;
    if toggle == StandDown::Off || !mode_listed {
        return (true, "live");
    }
    let keep = toggle == StandDown::KeepDeny;
    match d {
        // An allow never prompts — and in the dontAsk mode a hook allow is
        // one of the three channels that lets a call run at all, so
        // suppressing it would break the work the feature protects. Never
        // suppressed, in any state.
        Decision::Allow(_) => (true, "live"),
        // A live abstain also emits nothing; nothing is being suppressed,
        // so the row must not claim it was.
        Decision::Abstain => (true, "live"),
        Decision::Deny(_) if keep => (true, "live"),
        Decision::Ask(_) if keep && protection_ask => (true, "live"),
        Decision::Ask(_) | Decision::Deny(_) => (false, "stood-down"),
    }
}
