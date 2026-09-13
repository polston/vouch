//! Host hook protocols, normalized into the one input vouch decides.
//!
//! Two rules live here and must not be relaxed:
//!   1. `Decision::Abstain` renders to *nothing at all* — no output, exit 0.
//!      The `defer` verdict is deliberately unsupported: it is ignored by the
//!      interactive app and ends the turn in headless runs.
//!   2. Reason text is passed through verbatim, including newlines. The
//!      self-explaining prompt depends on it arriving whole.

use crate::guards::Knowledge;
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
    /// Absolute paths to active workspace roots, passed by host environments
    /// like Antigravity.
    #[serde(default, alias = "workspacePaths")]
    pub workspace_paths: Vec<String>,
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
    tool_response: Option<serde_json::Value>,
    tool_result: Option<serde_json::Value>,
    response: Option<serde_json::Value>,
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
                let workspace_paths = agy.workspace_paths.clone().unwrap_or_default();
                let default_cwd = workspace_paths.first().cloned().unwrap_or_default();

                let is_terminal = agy.tool_response.is_some()
                    || agy.tool_result.is_some()
                    || agy.response.is_some()
                    || agy.error.is_some()
                    || (agy.tool_call.is_none() && agy.reason.is_some());

                if is_terminal || agy.tool_call.is_none() {
                    let error = agy.error.unwrap_or_default();
                    let reason = agy.reason.unwrap_or_default();
                    let hook_event_name = if !error.is_empty() {
                        "PostToolUseFailure".to_string()
                    } else {
                        "PostToolUse".to_string()
                    };
                    let tool_name = agy
                        .tool_call
                        .as_ref()
                        .map(|tc| tc.name.clone())
                        .unwrap_or_default();
                    return Ok(HookInput {
                        hook_event_name,
                        tool_use_id,
                        reason,
                        error,
                        is_interrupt: false,
                        session_id,
                        turn_id,
                        cwd: default_cwd,
                        workspace_paths,
                        permission_mode: String::new(),
                        tool_name,
                        tool_input: ToolInput::default(),
                    });
                } else if let Some(tc) = agy.tool_call {
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
                        workspace_paths,
                        permission_mode: String::new(),
                        tool_name: tc.name,
                        tool_input: ToolInput {
                            command,
                            file_path,
                            url,
                            extra,
                        },
                    });
                }
            }
        }
    }
    serde_json::from_str(raw)
}

/// Returns true if a command is structurally proven via AST evaluation to
/// require zero network access, zero daemon/host-escape access, and to remain
/// strictly contained within the workspace root.
pub fn is_demote_eligible(kb: &Knowledge, command: &str, cwd: &str) -> bool {
    let trimmed = command.trim();
    if trimmed.is_empty() {
        return false;
    }
    let scan = match crate::shell::parse(trimmed) {
        Ok(s) => s,
        Err(_) => return false,
    };
    if scan.commands.is_empty() {
        return false;
    }
    let all_cmds = crate::guards::expand_wrappers(kb, &scan.commands, "bash");
    if all_cmds.is_empty() {
        return false;
    }
    let root = crate::route::project_root(cwd).unwrap_or_else(|| cwd.replace('\\', "/"));

    for cmd in &all_cmds {
        // Allow-list invariant (§1): Every command node in the AST must be
        // recognized and modeled. Unmodeled or partially modeled commands have
        // unknown capability requirements and must never be demoted.
        if !crate::guards::recognises(kb, cmd, "bash", true) {
            return false;
        }

        // Verify command head path containment: if the binary or executable is an
        // explicit path candidate, it must reside strictly within the workspace root.
        // Running binaries outside the workspace root requires host access.
        if is_external_path_candidate(&cmd.head) {
            if !is_path_contained_in_workspace(&cmd.head, cwd, &root) {
                return false;
            }
        }

        // If the command runs a script file, its internal effects and capability
        // requirements are unmodeled. Commands with unmodeled effects must never be
        // demoted (allow-list invariant §1).
        if crate::guards::runs_file_target(kb, cmd).is_some() {
            return false;
        }
        let (evaluates_input, _, _) =
            crate::guards::evaluates_input_in(kb, cmd, "bash", false, false, false);
        if evaluates_input {
            return false;
        }

        // Host and network capabilities declared in knowledge must not require
        // network, host escape, daemon, or external filesystem access.
        let caps = crate::guards::capabilities_for_cmd(kb, cmd, "bash");
        if caps
            .iter()
            .any(|c| c == "network" || c == "external_paths" || c == "daemon")
        {
            return false;
        }

        // Verify written path containment
        let targets = crate::guards::written_paths_in(kb, cmd, "bash");
        if !targets.unknowable.is_empty() {
            return false;
        }
        for p in &targets.paths {
            if !is_path_contained_in_workspace(p, cwd, &root) {
                return false;
            }
        }

        // Verify argument path containment (reads, configs, and positional targets)
        for arg in &cmd.args {
            let a = arg.trim().trim_matches(|c| c == '\'' || c == '"');
            let candidate = if a.starts_with("--") && a.contains('=') {
                a.split_once('=').map(|(_, v)| v).unwrap_or(a)
            } else {
                a
            };
            if is_external_path_candidate(candidate) {
                if !is_path_contained_in_workspace(candidate, cwd, &root) {
                    return false;
                }
            }
        }
    }

    // Verify redirect targets containment
    for p in &scan.redirect_targets {
        if !is_path_contained_in_workspace(p, cwd, &root) {
            return false;
        }
    }

    true
}

/// Returns true if a token represents an absolute path, home path, or directory traversal candidate.
fn is_external_path_candidate(token: &str) -> bool {
    let t = token.trim().trim_matches(|c| c == '\'' || c == '"');
    if t.is_empty() || t.starts_with('-') {
        return false;
    }
    // Absolute Unix path
    if t.starts_with('/') {
        return true;
    }
    // Home directory path (~ or ~/...)
    if t == "~" || t.starts_with("~/") || t.starts_with("~\\") {
        return true;
    }
    // Windows drive path (e.g. C:\ or C:/)
    if t.len() >= 2 && t.as_bytes()[1] == b':' && (t.starts_with("C:") || t.as_bytes()[0].is_ascii_alphabetic()) {
        return true;
    }
    // Explicit directory traversal component (avoid matching git ranges like master..branch)
    if t == ".."
        || t.starts_with("../")
        || t.starts_with("..\\")
        || t.contains("/../")
        || t.contains("\\..\\")
        || t.ends_with("/..")
        || t.ends_with("\\..")
    {
        return true;
    }
    false
}

/// Backwards-compatible convenience wrapper evaluating against builtin knowledge.
pub fn is_local_workspace_command(command: &str) -> bool {
    is_demote_eligible(crate::guards::in_effect(), command, "")
}

/// True if `path` is contained within the workspace root or names a safe bit-bucket sink (`/dev/null`, `NUL`).
fn is_path_contained_in_workspace(path: &str, cwd: &str, root: &str) -> bool {
    let trimmed = path.trim().trim_matches(|c| c == '\'' || c == '"');
    if trimmed.is_empty() {
        return false;
    }
    let norm_path = crate::paths::normalize(trimmed, "");
    if norm_path == "/dev/null" || norm_path.eq_ignore_ascii_case("NUL") {
        return true;
    }
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_default();
    let norm_root = crate::paths::normalize(root, &home);
    let root_clean = norm_root.trim_end_matches('/');
    if root_clean.is_empty() {
        return false;
    }
    let full = if trimmed == "~" || trimmed.starts_with("~/") || trimmed.starts_with("~\\") {
        if home.is_empty() {
            return false;
        }
        format!(
            "{}/{}",
            home.trim_end_matches('/'),
            trimmed[1..].trim_start_matches(|c| c == '/' || c == '\\')
        )
    } else if trimmed.starts_with('/') || (trimmed.len() >= 2 && trimmed.as_bytes()[1] == b':') {
        trimmed.to_string()
    } else {
        format!("{}/{}", cwd.trim_end_matches('/'), trimmed)
    };
    let norm_full = crate::paths::normalize(&full, &home);
    norm_full == root_clean || norm_full.starts_with(&format!("{root_clean}/"))
}

pub fn should_demote_sandbox(input: &HookInput, d: &Decision, kb: &Knowledge) -> bool {
    if !matches!(d, Decision::Allow(_) | Decision::Ask(_)) {
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
        is_demote_eligible(kb, cmd, &input.cwd)
    } else {
        false
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
    if (verdict == "allow" || verdict == "ask") && demote_sandbox {
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
