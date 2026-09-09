//! Host hook protocols, normalized into the one input vouch decides.
//!
//! Two rules live here and must not be relaxed:
//!   1. `Decision::Abstain` renders to *nothing at all* — no output, exit 0.
//!      The `defer` verdict is deliberately unsupported: it is ignored by the
//!      interactive app and ends the turn in headless runs.
//!   2. Reason text is passed through verbatim, including newlines. The
//!      self-explaining prompt depends on it arriving whole.

use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Host {
    #[default]
    Claude,
    Codex,
    Agy,
}

impl Host {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "claude" => Ok(Self::Claude),
            "codex" => Ok(Self::Codex),
            "agy" | "antigravity" => Ok(Self::Agy),
            other => Err(format!(
                "vouch: unknown host {other:?}; expected claude, codex, or agy"
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Codex => "codex",
            Self::Agy => "agy",
        }
    }
}

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
    /// Codex scopes a tool call to a turn as well as a session. Claude does
    /// not currently send this field, so the empty default preserves its
    /// protocol exactly.
    #[serde(default)]
    pub turn_id: String,
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AgyToolCall {
    name: String,
    #[serde(default)]
    args: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AgyPayload {
    tool_call: Option<AgyToolCall>,
    step_idx: Option<serde_json::Value>,
    conversation_id: Option<String>,
    workspace_paths: Option<Vec<String>>,
    error: Option<String>,
    reason: Option<String>,
}

pub fn parse_input(raw: &str) -> Result<HookInput, serde_json::Error> {
    if raw.contains("\"toolCall\"")
        || raw.contains("\"workspacePaths\"")
        || raw.contains("\"conversationId\"")
    {
        if let Ok(agy) = serde_json::from_str::<AgyPayload>(raw) {
            if agy.tool_call.is_some()
                || agy.workspace_paths.is_some()
                || agy.conversation_id.is_some()
            {
                let session_id = agy.conversation_id.unwrap_or_default();
                let turn_id = agy
                    .step_idx
                    .map(|v| match v {
                        serde_json::Value::Number(n) => n.to_string(),
                        serde_json::Value::String(s) => s,
                        other => other.to_string(),
                    })
                    .unwrap_or_default();
                let tool_use_id = if !turn_id.is_empty() {
                    if !session_id.is_empty() {
                        format!("{session_id}:{turn_id}")
                    } else {
                        turn_id.clone()
                    }
                } else {
                    session_id.clone()
                };
                let default_cwd = agy
                    .workspace_paths
                    .as_ref()
                    .and_then(|w| w.first().cloned())
                    .unwrap_or_default();

                if let Some(tc) = agy.tool_call {
                    let command = tc
                        .args
                        .get("CommandLine")
                        .or_else(|| tc.args.get("command"))
                        .and_then(|v| v.as_str())
                        .map(String::from);
                    let file_path = tc
                        .args
                        .get("TargetFile")
                        .or_else(|| tc.args.get("file_path"))
                        .and_then(|v| v.as_str())
                        .map(String::from);
                    let url = tc
                        .args
                        .get("Url")
                        .or_else(|| tc.args.get("url"))
                        .and_then(|v| v.as_str())
                        .map(String::from);
                    let cwd = tc
                        .args
                        .get("Cwd")
                        .or_else(|| tc.args.get("cwd"))
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                        .map(String::from)
                        .unwrap_or(default_cwd);

                    let mut extra = tc.args;
                    if let Some(ref cmd) = command {
                        extra.entry("CommandLine".to_string()).or_insert_with(|| serde_json::Value::String(cmd.clone()));
                    }
                    if let Some(ref fp) = file_path {
                        extra.entry("TargetFile".to_string()).or_insert_with(|| serde_json::Value::String(fp.clone()));
                    }
                    return Ok(HookInput {
                        hook_event_name: "PreToolUse".into(),
                        tool_use_id,
                        reason: String::new(),
                        error: String::new(),
                        is_interrupt: false,
                        session_id,
                        turn_id,
                        cwd,
                        permission_mode: String::new(),
                        tool_name: tc.name,
                        tool_input: ToolInput {
                            command,
                            file_path,
                            url,
                            extra,
                        },
                    });
                } else {
                    let error = agy.error.unwrap_or_default();
                    let reason = agy.reason.unwrap_or_default();
                    let hook_event_name = if !error.is_empty() {
                        "PostToolUseFailure".to_string()
                    } else {
                        "PostToolUse".to_string()
                    };
                    return Ok(HookInput {
                        hook_event_name,
                        tool_use_id,
                        reason,
                        error,
                        is_interrupt: false,
                        session_id,
                        turn_id,
                        cwd: default_cwd,
                        permission_mode: String::new(),
                        tool_name: String::new(),
                        tool_input: ToolInput::default(),
                    });
                }
            }
        }
    }
    serde_json::from_str(raw)
}

/// Returns true if a command is a safe local workspace operation that does
/// not require network access or host escape, and can be safely demoted
/// from `BypassSandbox: true` to `BypassSandbox: false`.
pub fn is_local_workspace_command(command: &str) -> bool {
    let trimmed = command.trim();
    if trimmed.is_empty() {
        return false;
    }
    let network_or_remote = [
        "curl", "wget", "ssh", "scp", "sftp", "rsync", "git push", "git fetch", "git pull",
        "git clone", "git remote", "kubectl", "docker", "podman", "nc", "netcat", "telnet",
        "ping", "traceroute", "dig", "nslookup",
    ];
    for bad in network_or_remote {
        if trimmed == bad
            || trimmed.starts_with(&format!("{bad} "))
            || trimmed.contains(&format!(" {bad} "))
            || trimmed.contains(&format!("| {bad}"))
            || trimmed.contains(&format!("; {bad}"))
            || trimmed.contains(&format!("&& {bad}"))
        {
            return false;
        }
    }
    true
}

pub fn should_demote_sandbox(input: &HookInput, d: &Decision) -> bool {
    if !matches!(d, Decision::Allow(_)) {
        return false;
    }
    let wants_bypass = input
        .tool_input
        .extra
        .get("BypassSandbox")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if !wants_bypass {
        return false;
    }
    if let Some(cmd) = &input.tool_input.command {
        is_local_workspace_command(cmd)
    } else {
        true
    }
}

/// Render one normalized decision for Antigravity, including optional sandbox demotion.
pub fn render_for_agy(d: &Decision, demote_sandbox: bool) -> Option<String> {
    let (verdict, reason) = match d {
        Decision::Abstain => return None,
        Decision::Allow(r) => ("allow", r),
        Decision::Ask(r) => ("ask", r),
        Decision::Deny(r) => ("deny", r),
    };
    let mut body = serde_json::json!({
        "decision": verdict,
        "reason": reason,
    });
    if verdict == "allow" && demote_sandbox {
        body["overwrite"] = serde_json::json!({
            "BypassSandbox": false
        });
    }
    Some(body.to_string())
}

/// Renders the hook response. `None` means emit nothing at all.
pub fn render(d: &Decision) -> Option<String> {
    render_for(Host::Claude, d)
}

/// Render one normalized decision for the selected host.
///
/// Codex deliberately receives no output for Allow: its current PreToolUse
/// implementation supports `allow` only together with `updatedInput`, and
/// vouch must not weaken the native sandbox or approval layer. Codex also
/// does not support `ask`, so Ask blocks the first attempt; the caller adds
/// the approval request id that lets the broker authorize one exact retry.
pub fn render_for(host: Host, d: &Decision) -> Option<String> {
    if host == Host::Agy {
        return render_for_agy(d, false);
    }
    if host == Host::Codex && matches!(d, Decision::Allow(_) | Decision::Abstain) {
        return None;
    }
    let (verdict, reason) = match d {
        Decision::Abstain => return None,
        Decision::Allow(r) => ("allow", r),
        Decision::Ask(r) if host == Host::Codex => ("deny", r),
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
