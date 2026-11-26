//! `vouch install` & `vouch uninstall` — manage hook registrations across hosts.
//!
//! Generates merged hook configuration for Claude Code (`settings.json`), OpenAI
//! Codex (`hooks.json`), and Google Antigravity (`hooks.json`). Emits merged JSON
//! to standard output for manual review/redirection, or atomically writes to the
//! host's configuration file when `--write` is specified (backed up with rollback).
//! `vouch uninstall` cleanly strips vouch registrations while preserving unrelated
//! hooks and MCP configurations.
//!
//! Live `PreToolUse` registrations wrap the vouch executable so a missing,
//! non-executable, or non-zero-exiting binary blocks execution fail-closed
//! (discarding any partial stdout and emitting the host's structured deny JSON)
//! instead of letting the harness fail open. Passive `--shadow` `PreToolUse`
//! and outcome hooks stay non-disruptive (`exit 0`, `{}` for Antigravity
//! `PostToolUse`). Without `--state-dir`, hooks and CLI commands share the
//! persistent default user state directory (`~/.local/state/vouch` on Unix,
//! `%LOCALAPPDATA%/vouch/state` on Windows).
//!
//! For Claude Code, four events are registered:
//!   PreToolUse         — the decision
//!   PostToolUse        — "it ran"
//!   PostToolUseFailure — "it errored or was interrupted"
//!   PermissionDenied   — "the user refused it"
//!
//! For Codex and Antigravity, `PreToolUse` gates decisions and `PostToolUse`
//! records outcomes. The outcome events exist so `vouch review` is built on real
//! outcomes rather than on the absence of a signal.

use serde_json::{json, Value};

use crate::cli::{validate_state_dir, InstallShell};

const CODEX_STATUS_MESSAGE: &str = "vouch is checking this tool call";

const DEFAULT_STATE_DIR_NOTE: &str =
    "No --state-dir was supplied; hooks use inherited VOUCH_STATE_DIR or the persistent user state directory (~/.local/state/vouch on Unix, %LOCALAPPDATA%/vouch/state on Windows).";

const AGY_CMD_SAFE_DENY_JSON: &str =
    r#"{"decision":"deny","reason":"vouch gate unavailable or failed - blocking fail-closed; reinstall vouch or re-run vouch install"}"#;

pub struct Plan {
    /// The settings.json content to save.
    pub settings: String,
    /// The hooks-only view — display-safe: no MCP/server content, whatever
    /// else the operator's settings.json carries.
    pub hooks_view: String,
    /// What this changes, in plain terms.
    pub notes: Vec<String>,
}

fn bash_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

/// Parse a POSIX single-quoted token produced by [`bash_quote`] at the start of `input`.
fn bash_unquote_prefix(input: &str) -> Option<(String, &str)> {
    let mut rest = input.strip_prefix('\'')?;
    let mut out = String::new();
    while !rest.is_empty() {
        if let Some(after) = rest.strip_prefix("'\"'\"'") {
            out.push('\'');
            rest = after;
        } else if let Some(after) = rest.strip_prefix('\'') {
            return Some((out, after));
        } else {
            let ch = rest.chars().next()?;
            out.push(ch);
            rest = &rest[ch.len_utf8()..];
        }
    }
    None
}

fn powershell_quote(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len() + 2);
    escaped.push('\'');
    for ch in value.chars() {
        match ch {
            '\'' | '\u{2018}' | '\u{2019}' | '\u{201A}' | '\u{201B}' => {
                escaped.push(ch);
                escaped.push(ch);
            }
            _ => escaped.push(ch),
        }
    }
    escaped.push('\'');
    escaped
}

fn cmd_quote(value: &str) -> String {
    let clean = value.replace('"', "");
    // Preserve UNC prefix (`\\server\share`) while converting interior/trailing
    // backslashes to `/` so a trailing `\` cannot escape the closing quote in
    // Win32 `CommandLineToArgvW`.
    let normalized = if let Some(rest) = clean.strip_prefix("\\\\") {
        format!("\\\\{}", rest.replace('\\', "/").trim_end_matches('/'))
    } else {
        clean.replace('\\', "/")
    };
    format!("\"{normalized}\"")
}

fn is_windows_cmd_target(exe: &str) -> bool {
    let b = exe.as_bytes();
    let has_drive = b.len() >= 3
        && b[0].is_ascii_alphabetic()
        && b[1] == b':'
        && matches!(b[2], b'/' | b'\\');
    let is_unc = exe.starts_with("\\\\");
    let is_exe = exe.to_ascii_lowercase().ends_with(".exe");
    let bare_on_windows = cfg!(windows) && !exe.contains('/') && !exe.contains('\\');
    has_drive || is_unc || is_exe || bare_on_windows
}

fn is_vouch_basename(exe: &str) -> bool {
    let base = exe.rsplit(['/', '\\']).next().unwrap_or(exe);
    base.eq_ignore_ascii_case("vouch") || base.eq_ignore_ascii_case("vouch.exe")
}

fn claude_codex_deny_json(exe: &str) -> String {
    serde_json::to_string(&json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": format!(
                "vouch gate unavailable (missing or failed binary: {exe}) - blocking fail-closed; reinstall vouch or re-run vouch install"
            ),
        }
    }))
    .expect("static JSON serialization never fails")
}

fn agy_deny_json(exe: &str) -> String {
    serde_json::to_string(&json!({
        "decision": "deny",
        "reason": format!(
            "vouch gate unavailable (missing or failed binary: {exe}) - blocking fail-closed; reinstall vouch or re-run vouch install"
        ),
    }))
    .expect("static JSON serialization never fails")
}

fn posix_fail_closed_pre(exe: &str, args: &str, deny_json: &str) -> String {
    let q_exe = bash_quote(exe);
    let q_deny = bash_quote(deny_json);
    format!(
        "if command -v {q_exe} >/dev/null 2>&1; then out=$({q_exe} {args}); rc=$?; \
         if [ \"$rc\" -eq 0 ]; then if [ -n \"$out\" ]; then printf '%s\\n' \"$out\"; fi; exit 0; fi; \
         fi; printf '%s\\n' {q_deny}"
    )
}

fn posix_non_disruptive(exe: &str, args: &str, fallback_stdout: Option<&str>) -> String {
    let q_exe = bash_quote(exe);
    match fallback_stdout {
        Some(fb) => {
            let q_fb = bash_quote(fb);
            format!(
                "if command -v {q_exe} >/dev/null 2>&1; then out=$({q_exe} {args}); rc=$?; \
                 if [ \"$rc\" -eq 0 ] && [ -n \"$out\" ]; then printf '%s\\n' \"$out\"; \
                 else printf '%s\\n' {q_fb}; fi; else printf '%s\\n' {q_fb}; fi"
            )
        }
        None => format!(
            "if command -v {q_exe} >/dev/null 2>&1; then {q_exe} {args} || true; fi"
        ),
    }
}

fn claude_args(shadow: bool, state_dir: Option<&str>) -> String {
    let mut args = String::from("--hook");
    if shadow {
        args.push_str(" --shadow");
    }
    if let Some(dir) = state_dir {
        args.push_str(" --state-dir ");
        args.push_str(&bash_quote(dir));
    }
    args
}

fn claude_hook_command(exe: &str, fail_closed_pre: bool, shadow: bool, state_dir: Option<&str>) -> String {
    let args = claude_args(shadow, state_dir);
    if fail_closed_pre && !shadow {
        posix_fail_closed_pre(exe, &args, &claude_codex_deny_json(exe))
    } else {
        posix_non_disruptive(exe, &args, None)
    }
}

fn claude_hook_entry(exe: &str, fail_closed_pre: bool, shadow: bool, state_dir: Option<&str>) -> Value {
    json!({
        "hooks": [{
            "type": "command",
            "command": claude_hook_command(exe, fail_closed_pre, shadow, state_dir)
        }]
    })
}

/// Inspect the argument tail of a Claude vouch invocation (skipping quoted
/// `--state-dir` values so flag-like substrings inside a directory path cannot
/// collide with `--shadow` or `--host`). Returns `Some(is_shadow)` if `--hook`
/// is present and no non-Claude `--host` is named.
fn inspect_claude_args(mut rest: &str) -> Option<bool> {
    let mut saw_hook = false;
    let mut saw_shadow = false;
    loop {
        rest = rest.trim_start();
        if rest.is_empty()
            || rest.starts_with(')')
            || rest.starts_with(';')
            || rest.starts_with("||")
        {
            break;
        }
        let token = if let Some((_, after)) = bash_unquote_prefix(rest) {
            let consumed = rest.len() - after.len();
            let tok = &rest[..consumed];
            rest = after;
            tok
        } else if let Some(after_open) = rest.strip_prefix('"') {
            let close = after_open.find('"')?;
            let tok = &rest[..close + 2];
            rest = &after_open[close + 1..];
            tok
        } else {
            let end = rest
                .find(|c: char| c.is_whitespace() || matches!(c, ')' | ';' | '|'))
                .unwrap_or(rest.len());
            let tok = &rest[..end];
            rest = &rest[end..];
            tok
        };
        match token {
            "--hook" => saw_hook = true,
            "--shadow" => saw_shadow = true,
            "--host" => {
                // Consume the host value; only Claude (or omitted --host) belongs here.
                rest = rest.trim_start();
                let end = rest
                    .find(|c: char| c.is_whitespace() || matches!(c, ')' | ';' | '|'))
                    .unwrap_or(rest.len());
                let host_val = rest[..end].trim_matches(|c| c == '\'' || c == '"');
                if host_val != "claude" {
                    return None;
                }
                rest = &rest[end..];
            }
            "--state-dir" => {
                // Skip the state-dir value completely so paths containing
                // `--shadow` or `--host codex` never confuse flag inspection.
                rest = rest.trim_start();
                if let Some((_, after)) = bash_unquote_prefix(rest) {
                    rest = after;
                } else if let Some(after_open) = rest.strip_prefix('"') {
                    let close = after_open.find('"')?;
                    rest = &after_open[close + 1..];
                } else {
                    let end = rest
                        .find(|c: char| c.is_whitespace() || matches!(c, ')' | ';' | '|'))
                        .unwrap_or(rest.len());
                    rest = &rest[end..];
                }
            }
            _ => {}
        }
    }
    saw_hook.then_some(saw_shadow)
}

/// Parse a Claude hook command generated by vouch (legacy bare or wrapped),
/// returning `(executable_path, was_shadow)`.
/// Rejects lookalike basenames, non-Claude host hooks, and multi-word unrelated
/// commands that merely mention `vouch --hook`.
fn parse_claude_vouch_command(command: &str) -> Option<(String, bool)> {
    // New wrapped registration: `if command -v '<exe>' >/dev/null 2>&1; then ...`
    if let Some(after) = command.strip_prefix("if command -v ") {
        let (exe, rest) = bash_unquote_prefix(after)?;
        let body = rest.strip_prefix(" >/dev/null 2>&1; then ")?;
        if !is_vouch_basename(&exe) {
            return None;
        }
        let q_exe = bash_quote(&exe);
        let invocation = body
            .strip_prefix("out=$(")
            .or_else(|| body.strip_prefix("exec "))
            .unwrap_or(body);
        let args_tail = invocation.strip_prefix(&q_exe)?;
        let was_shadow = inspect_claude_args(args_tail)?;
        return Some((exe, was_shadow));
    }
    // Legacy bare registration: `<exe> --hook [--shadow] [--state-dir ...]`
    let hook_idx = command.find(" --hook")?;
    let head = command[..hook_idx].trim();
    let tail = &command[hook_idx..];
    let exe = if let Some((unquoted, rem)) = bash_unquote_prefix(head) {
        if !rem.is_empty() {
            return None;
        }
        unquoted
    } else if let Some(inner) = head.strip_prefix('"').and_then(|v| v.strip_suffix('"')) {
        if inner.contains('"') {
            return None;
        }
        inner.to_string()
    } else {
        // Unquoted legacy paths never contained whitespace; reject multi-word
        // commands like `python3 tool.py /path/to/vouch --hook`.
        if head.is_empty() || head.chars().any(char::is_whitespace) {
            return None;
        }
        head.to_string()
    };
    if !is_vouch_basename(&exe) {
        return None;
    }
    let was_shadow = inspect_claude_args(tail)?;
    Some((exe, was_shadow))
}

fn vouch_exe_of(command: &str) -> Option<String> {
    parse_claude_vouch_command(command).map(|(exe, _)| exe)
}

#[derive(Default)]
struct Repointed {
    found: bool,
    moved: usize,
    stood_down: usize,
}

/// Repoint generated Claude vouch hooks while retaining unrelated neighbours.
fn repoint(
    entries: &mut [Value],
    exe: &str,
    fail_closed_pre: bool,
    force_shadow: bool,
    state_dir: Option<&str>,
) -> Repointed {
    let mut result = Repointed::default();
    for group in entries {
        let Some(hooks) = group.get_mut("hooks").and_then(Value::as_array_mut) else { continue };
        for hook in hooks {
            let command = hook.get("command").and_then(Value::as_str).unwrap_or_default().to_string();
            let Some((old_exe, was_shadow)) = parse_claude_vouch_command(&command) else { continue };
            result.found = true;
            if old_exe != exe { result.moved += 1; }
            if force_shadow && !was_shadow { result.stood_down += 1; }
            let effective_shadow = if fail_closed_pre { force_shadow } else { force_shadow || was_shadow };
            let wanted = claude_hook_command(exe, fail_closed_pre, effective_shadow, state_dir);
            if wanted != command { hook["command"] = json!(wanted); }
        }
    }
    result
}

fn codex_command(
    exe: &str,
    shell: InstallShell,
    fail_closed_pre: bool,
    shadow: bool,
    state_dir: Option<&str>,
) -> String {
    let shadow_str = if shadow { " --shadow" } else { "" };
    let state_dir_str = state_dir
        .map(|path| match shell {
            InstallShell::Bash => format!(" --state-dir {}", bash_quote(path)),
            InstallShell::PowerShell => format!(" --state-dir {}", powershell_quote(path)),
        })
        .unwrap_or_default();
    let args = format!(
        "--hook --host codex --shell {}{shadow_str}{state_dir_str}",
        shell.as_str()
    );
    match shell {
        InstallShell::Bash => {
            if fail_closed_pre && !shadow {
                posix_fail_closed_pre(exe, &args, &claude_codex_deny_json(exe))
            } else {
                posix_non_disruptive(exe, &args, None)
            }
        }
        InstallShell::PowerShell => {
            let q_exe = powershell_quote(exe);
            if fail_closed_pre && !shadow {
                let q_deny = powershell_quote(&claude_codex_deny_json(exe));
                format!(
                    "if (Get-Command {q_exe} -ErrorAction SilentlyContinue) {{ \
                     try {{ $out = & {q_exe} {args}; \
                     if ($? -and $LASTEXITCODE -eq 0) {{ if ($null -ne $out) {{ $out }}; exit 0 }} \
                     }} catch {{}} }}; Write-Output {q_deny}"
                )
            } else {
                format!(
                    "if (Get-Command {q_exe} -ErrorAction SilentlyContinue) {{ \
                     try {{ & {q_exe} {args} }} catch {{}} }}; exit 0"
                )
            }
        }
    }
}

fn codex_hook_entry(
    exe: &str,
    shell: InstallShell,
    fail_closed_pre: bool,
    shadow: bool,
    state_dir: Option<&str>,
) -> Value {
    json!({
        "matcher": ".*",
        "hooks": [{
            "type": "command",
            "command": codex_command(exe, shell, fail_closed_pre, shadow, state_dir),
            "timeout": 30,
            "statusMessage": CODEX_STATUS_MESSAGE
        }]
    })
}

fn is_codex_vouch_hook(hook: &Value) -> bool {
    hook.get("type").and_then(Value::as_str) == Some("command")
        && hook.get("statusMessage").and_then(Value::as_str) == Some(CODEX_STATUS_MESSAGE)
        && hook
            .get("command")
            .and_then(Value::as_str)
            .is_some_and(|command| command.contains("--hook --host codex"))
}

fn without_codex_vouch(entries: Option<&Value>, event: &str) -> Result<Vec<Value>, String> {
    let Some(entries) = entries else {
        return Ok(Vec::new());
    };
    let entries = entries
        .as_array()
        .ok_or_else(|| format!("hooks.json {event:?} hooks are not an array"))?;
    let mut kept = Vec::new();
    for entry in entries {
        let mut entry = entry.clone();
        let Some(hooks) = entry.get_mut("hooks").and_then(Value::as_array_mut) else {
            kept.push(entry);
            continue;
        };
        hooks.retain(|hook| !is_codex_vouch_hook(hook));
        if !hooks.is_empty() {
            kept.push(entry);
        }
    }
    Ok(kept)
}

/// Build a merged `~/.codex/hooks.json`. Codex owns its native sandbox and
/// approval policy; this file only installs vouch's local PreToolUse decision
/// hook and PostToolUse outcome recorder. Unrelated hooks are never replaced.
pub fn plan_codex(
    existing: &str,
    exe: &str,
    shell: InstallShell,
    shadow: bool,
) -> Result<Plan, String> {
    plan_codex_inner(existing, exe, shell, shadow, None)
}

/// Pin an explicit absolute `--state-dir` onto [`plan_codex`] hooks rather than
/// relying on `VOUCH_STATE_DIR` or the persistent default user state directory.
pub fn plan_codex_with_state(
    existing: &str,
    exe: &str,
    shell: InstallShell,
    shadow: bool,
    state_dir: &str,
) -> Result<Plan, String> {
    validate_state_dir(state_dir)?;
    plan_codex_inner(existing, exe, shell, shadow, Some(state_dir))
}

fn plan_codex_inner(
    existing: &str,
    exe: &str,
    shell: InstallShell,
    shadow: bool,
    state_dir: Option<&str>,
) -> Result<Plan, String> {
    let mut root: Value = if existing.trim().is_empty() {
        json!({})
    } else {
        serde_json::from_str(existing).map_err(|e| format!("hooks.json is not valid JSON: {e}"))?
    };
    if !root.is_object() {
        return Err("hooks.json is not a JSON object".into());
    }
    let hooks = root
        .as_object_mut()
        .unwrap()
        .entry("hooks")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or("hooks.json 'hooks' is not an object")?;

    for (event, fail_closed_pre, event_shadow) in
        [("PreToolUse", !shadow, shadow), ("PostToolUse", false, false)]
    {
        let mut entries = without_codex_vouch(hooks.get(event), event)?;
        entries.push(codex_hook_entry(
            exe,
            shell,
            fail_closed_pre,
            event_shadow,
            state_dir,
        ));
        hooks.insert(event.to_string(), Value::Array(entries));
    }

    let broker_name = if exe.to_ascii_lowercase().ends_with(".exe") {
        "vouch-codex-broker.exe"
    } else {
        "vouch-codex-broker"
    };
    let broker = std::path::Path::new(exe)
        .with_file_name(broker_name)
        .to_string_lossy()
        .replace('\\', "/");
    let broker = if broker.contains(' ') {
        format!("\"{broker}\"")
    } else {
        broker
    };
    let mut notes = vec![
        if shadow {
            "SHADOW: vouch records what it would decide and emits no decision; Codex remains in charge."
        } else {
            "LIVE: vouch blocks Codex tool calls it would ask about or deny (PreToolUse fails closed if the vouch binary is missing or exits non-zero)."
        }
        .into(),
        "Codex PostToolUse records completed calls non-disruptively; unsupported Claude-only outcome events are not installed."
            .into(),
        if state_dir.is_some() {
            "Both Codex hooks use the explicit stable --state-dir."
        } else {
            DEFAULT_STATE_DIR_NOTE
        }
        .into(),
    ];
    if shadow {
        notes.push(
            "Passive shadow needs no vouch approval broker and leaves Codex's approval policy and reviewer unchanged."
                .into(),
        );
    } else {
        notes.push(format!(
            "Register the one-time human approval broker once: codex mcp add vouch_approval -- {broker}"
        ));
        notes.push(
            "Configure Codex for interactive human approval: approval_policy = \"on-request\", approvals_reviewer = \"user\", and under [mcp_servers.vouch_approval] set default_tools_approval_mode = \"prompt\". The native MCP prompt is the broker decision; no nested elicitation is used."
                .into(),
        );
    }
    let hooks_view = serde_json::to_string_pretty(&json!({ "hooks": root["hooks"].clone() }))
        .map_err(|e| e.to_string())?;
    let settings = serde_json::to_string_pretty(&root)
        .map_err(|e| format!("could not render hooks.json: {e}"))?;
    Ok(Plan {
        settings,
        hooks_view,
        notes,
    })
}

fn agy_command(
    exe: &str,
    fail_closed_pre: bool,
    shadow: bool,
    state_dir: Option<&str>,
    is_post: bool,
) -> String {
    if is_windows_cmd_target(exe) {
        let shadow_str = if shadow { " --shadow" } else { "" };
        let state_dir_str = state_dir
            .map(|path| format!(" --state-dir {}", cmd_quote(path)))
            .unwrap_or_default();
        let args = format!("--hook --host agy{shadow_str}{state_dir_str}");
        let has_sep = exe.contains('/') || exe.contains('\\');
        let q_exe = cmd_quote(exe);
        if fail_closed_pre && !shadow {
            if has_sep {
                format!(
                    "if exist {q_exe} ({q_exe} {args} || echo {AGY_CMD_SAFE_DENY_JSON}) else (echo {AGY_CMD_SAFE_DENY_JSON})"
                )
            } else {
                format!(
                    "where /q {q_exe} && ({q_exe} {args} || echo {AGY_CMD_SAFE_DENY_JSON}) || echo {AGY_CMD_SAFE_DENY_JSON}"
                )
            }
        } else if is_post {
            if has_sep {
                format!("if exist {q_exe} ({q_exe} {args} || echo {{}}) else (echo {{}})")
            } else {
                format!("where /q {q_exe} && ({q_exe} {args} || echo {{}}) || echo {{}}")
            }
        } else if has_sep {
            format!("if exist {q_exe} ({q_exe} {args} || exit /b 0)")
        } else {
            format!("where /q {q_exe} && ({q_exe} {args} || exit /b 0) || exit /b 0")
        }
    } else {
        let shadow_str = if shadow { " --shadow" } else { "" };
        let state_dir_str = state_dir
            .map(|path| format!(" --state-dir {}", bash_quote(path)))
            .unwrap_or_default();
        let args = format!("--hook --host agy{shadow_str}{state_dir_str}");
        if fail_closed_pre && !shadow {
            posix_fail_closed_pre(exe, &args, &agy_deny_json(exe))
        } else if is_post {
            posix_non_disruptive(exe, &args, Some("{}"))
        } else {
            posix_non_disruptive(exe, &args, None)
        }
    }
}

fn agy_hook_entry(
    exe: &str,
    fail_closed_pre: bool,
    shadow: bool,
    state_dir: Option<&str>,
    is_post: bool,
) -> Value {
    json!({
        "matcher": "run_command|write_file|edit_file|write_to_file|replace_file_content",
        "hooks": [{
            "type": "command",
            "command": agy_command(exe, fail_closed_pre, shadow, state_dir, is_post)
        }]
    })
}

/// Build a merged Antigravity `hooks.json`.
pub fn plan_agy(
    existing: &str,
    exe: &str,
    shadow: bool,
    state_dir: Option<&str>,
) -> Result<Plan, String> {
    if let Some(path) = state_dir {
        validate_state_dir(path)?;
    }
    let mut root: Value = if existing.trim().is_empty() {
        json!({})
    } else {
        serde_json::from_str(existing).map_err(|e| format!("hooks.json is not valid JSON: {e}"))?
    };
    if !root.is_object() {
        return Err("hooks.json is not a JSON object".into());
    }

    let pre_entry = agy_hook_entry(exe, !shadow, shadow, state_dir, false);
    let post_entry = agy_hook_entry(exe, false, false, state_dir, true);

    let vouch_group = json!({
        "PreToolUse": [pre_entry],
        "PostToolUse": [post_entry]
    });

    root.as_object_mut()
        .unwrap()
        .insert("vouch".to_string(), vouch_group);

    let mut notes = vec![
        if shadow {
            "SHADOW: vouch records what it would decide and emits no decision; Antigravity remains in charge."
        } else {
            "LIVE: vouch gates Antigravity tool calls (run_command, write_file, edit_file, write_to_file, replace_file_content) and fails closed if the vouch binary is missing or exits non-zero."
        }
        .into(),
        "Antigravity PreToolUse evaluates tool calls; PostToolUse records outcomes non-disruptively.".into(),
        "Antigravity PreToolUse automatically allows safe operations without interactive prompts.".into(),
    ];
    if state_dir.is_some() {
        notes.push("Both Antigravity hooks use the explicit stable --state-dir.".into());
    } else {
        notes.push(DEFAULT_STATE_DIR_NOTE.into());
    }

    let hooks_view = serde_json::to_string_pretty(&json!({ "vouch": root["vouch"].clone() }))
        .map_err(|e| e.to_string())?;
    let settings = serde_json::to_string_pretty(&root)
        .map_err(|e| format!("could not render hooks.json: {e}"))?;

    Ok(Plan {
        settings,
        hooks_view,
        notes,
    })
}

/// Builds the merged settings.json. `shadow` keeps the existing gate in place and
/// adds vouch alongside it, recording decisions without being able to affect any.
pub fn plan(existing: &str, exe: &str, shadow: bool) -> Result<Plan, String> {
    plan_with_state(existing, exe, shadow, None)
}

/// Builds the merged Claude Code `settings.json`, optionally pinning an explicit
/// absolute `--state-dir` onto every generated vouch hook command.
pub fn plan_with_state(
    existing: &str,
    exe: &str,
    shadow: bool,
    state_dir: Option<&str>,
) -> Result<Plan, String> {
    if let Some(path) = state_dir {
        validate_state_dir(path)?;
    }
    let mut root: Value = if existing.trim().is_empty() {
        json!({})
    } else {
        serde_json::from_str(existing)
            .map_err(|e| format!("settings.json is not valid JSON: {e}"))?
    };
    let mut notes = Vec::new();

    if !root.is_object() {
        return Err("settings.json is not a JSON object".into());
    }
    let obj = root.as_object_mut().unwrap();
    let hooks = obj
        .entry("hooks")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or("settings.json 'hooks' is not an object")?;

    // What is gating today?
    let existing_pre = hooks.get("PreToolUse").cloned().unwrap_or(json!([]));
    let has_cc_allow_hook = |arr: &[Value]| {
        arr.iter().any(|group| {
            group
                .get("hooks")
                .and_then(Value::as_array)
                .is_some_and(|list| {
                    list.iter().any(|hook| {
                        let cmd = hook.get("command").and_then(Value::as_str).unwrap_or_default();
                        parse_claude_vouch_command(cmd).is_none() && cmd.contains("cc-allow")
                    })
                })
        })
    };
    let vouch_pre = claude_hook_entry(exe, !shadow, shadow, state_dir);

    let mut repointed = 0;
    let mut stood_down = 0;

    if shadow {
        // Keep whatever is there; append vouch. It emits nothing, by construction.
        let mut arr = existing_pre.as_array().cloned().unwrap_or_default();
        let had_cc_allow = has_cc_allow_hook(&arr);
        let result = repoint(&mut arr, exe, false, true, state_dir);
        repointed += result.moved;
        stood_down += result.stood_down;
        if !result.found {
            arr.push(vouch_pre);
        }
        hooks.insert("PreToolUse".into(), Value::Array(arr));
        notes.push(
            "SHADOW: the existing gate still decides everything. vouch is added \
             alongside it and emits nothing — there is a test asserting that. It only \
             records what it would have decided."
                .into(),
        );
        if had_cc_allow {
            notes.push("cc-allow is left wired and still in charge.".into());
        }
    } else {
        // Remove cc-allow from PreToolUse and repoint/upgrade any existing vouch hook,
        // while preserving unrelated non-vouch PreToolUse hooks.
        let mut arr = existing_pre.as_array().cloned().unwrap_or_default();
        let mut removed_cc_allow = false;
        for group in &mut arr {
            if let Some(hook_list) = group.get_mut("hooks").and_then(Value::as_array_mut) {
                let before = hook_list.len();
                hook_list.retain(|hook| {
                    let cmd = hook.get("command").and_then(Value::as_str).unwrap_or_default();
                    parse_claude_vouch_command(cmd).is_some() || !cmd.contains("cc-allow")
                });
                if hook_list.len() < before {
                    removed_cc_allow = true;
                }
            }
        }
        arr.retain(|group| {
            group
                .get("hooks")
                .and_then(Value::as_array)
                .map_or(true, |h| !h.is_empty())
        });
        let result = repoint(&mut arr, exe, true, false, state_dir);
        repointed += result.moved;
        if !result.found {
            arr.push(vouch_pre);
        }
        hooks.insert("PreToolUse".into(), Value::Array(arr));
        notes.push(
            "LIVE: vouch is now the gate for PreToolUse (fails closed if the vouch binary is missing or exits non-zero)."
                .into(),
        );
        if removed_cc_allow {
            notes.push(
                "cc-allow was REMOVED from PreToolUse. Its config file is untouched, \
                 so putting it back is one edit."
                    .into(),
            );
        }
    }

    // Outcome events. Harmless in either mode — they only record and stay non-disruptive if missing.
    let mut added = Vec::new();
    for ev in ["PostToolUse", "PostToolUseFailure", "PermissionDenied"] {
        let mut arr = hooks
            .get(ev)
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let result = repoint(&mut arr, exe, false, false, state_dir);
        repointed += result.moved;
        if !result.found {
            arr.push(claude_hook_entry(exe, false, false, state_dir));
            added.push(ev);
        }
        hooks.insert(ev.to_string(), Value::Array(arr));
    }
    if state_dir.is_some() {
        notes.push("All Claude hooks use the explicit stable --state-dir.".into());
    } else {
        notes.push(DEFAULT_STATE_DIR_NOTE.into());
    }
    if !added.is_empty() {
        notes.push(format!(
            "{} added: these only record what actually happened. Without them \
             `vouch review` would be guessing.",
            added.join(" / ")
        ));
    }
    if repointed > 0 {
        notes.push(format!(
            "{repointed} existing vouch hook(s) named a different executable and were \
             repointed at this one."
        ));
    }
    if stood_down > 0 {
        notes.push(format!(
            "{stood_down} existing vouch hook(s) was deciding and has been stood down to \
             --shadow, because shadow must not promote a new binary into the live gate."
        ));
    }

    let hooks_view = serde_json::to_string_pretty(&json!({ "hooks": root["hooks"].clone() }))
        .map_err(|e| e.to_string())?;

    let settings = serde_json::to_string_pretty(&root)
        .map_err(|e| format!("could not render settings.json: {e}"))?;
    Ok(Plan {
        settings,
        hooks_view,
        notes,
    })
}

/// Remove vouch hooks from Claude Code's settings.json.
pub fn unplan(existing: &str) -> Result<Plan, String> {
    let mut root: Value = if existing.trim().is_empty() {
        json!({})
    } else {
        serde_json::from_str(existing)
            .map_err(|e| format!("settings.json is not valid JSON: {e}"))?
    };
    if !root.is_object() {
        return Err("settings.json is not a JSON object".into());
    }

    let mut removed = 0;
    if let Some(hooks) = root.get_mut("hooks").and_then(Value::as_object_mut) {
        let events = ["PreToolUse", "PostToolUse", "PostToolUseFailure", "PermissionDenied"];
        for ev in events {
            if let Some(groups) = hooks.get_mut(ev).and_then(Value::as_array_mut) {
                for group in groups.iter_mut() {
                    if let Some(hook_list) = group.get_mut("hooks").and_then(Value::as_array_mut) {
                        let before = hook_list.len();
                        hook_list.retain(|hook| {
                            let command = hook.get("command").and_then(Value::as_str).unwrap_or_default();
                            vouch_exe_of(command).is_none()
                        });
                        removed += before - hook_list.len();
                    }
                }
                groups.retain(|group| {
                    group.get("hooks").and_then(Value::as_array).is_some_and(|h| !h.is_empty())
                });
            }
            if hooks.get(ev).and_then(Value::as_array).is_some_and(|g| g.is_empty()) {
                hooks.remove(ev);
            }
        }
        if hooks.is_empty() {
            root.as_object_mut().unwrap().remove("hooks");
        }
    }

    let notes = if removed > 0 {
        vec![format!("{removed} vouch hook(s) removed from Claude settings.json.")]
    } else {
        vec!["No vouch hooks were found in Claude settings.json.".into()]
    };

    let hooks_view = if let Some(hooks) = root.get("hooks") {
        serde_json::to_string_pretty(&json!({ "hooks": hooks.clone() })).map_err(|e| e.to_string())?
    } else {
        "{}".into()
    };
    let settings = serde_json::to_string_pretty(&root)
        .map_err(|e| format!("could not render settings.json: {e}"))?;

    Ok(Plan {
        settings,
        hooks_view,
        notes,
    })
}

/// Remove vouch hooks from Codex's hooks.json.
pub fn unplan_codex(existing: &str) -> Result<Plan, String> {
    let mut root: Value = if existing.trim().is_empty() {
        json!({})
    } else {
        serde_json::from_str(existing)
            .map_err(|e| format!("hooks.json is not valid JSON: {e}"))?
    };
    if !root.is_object() {
        return Err("hooks.json is not a JSON object".into());
    }

    let mut removed = false;
    if let Some(hooks) = root.get_mut("hooks").and_then(Value::as_object_mut) {
        let count_inner = |entries: Option<&Value>| -> usize {
            entries
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .map(|e| {
                            e.get("hooks")
                                .and_then(Value::as_array)
                                .map_or(1, Vec::len)
                        })
                        .sum()
                })
                .unwrap_or(0)
        };
        for event in ["PreToolUse", "PostToolUse"] {
            let before_count = count_inner(hooks.get(event));
            let kept = without_codex_vouch(hooks.get(event), event)?;
            let after_count: usize = kept
                .iter()
                .map(|e| {
                    e.get("hooks")
                        .and_then(Value::as_array)
                        .map_or(1, Vec::len)
                })
                .sum();
            if after_count < before_count {
                removed = true;
            }
            if kept.is_empty() {
                hooks.remove(event);
            } else {
                hooks.insert(event.to_string(), Value::Array(kept));
            }
        }
        if hooks.is_empty() {
            root.as_object_mut().unwrap().remove("hooks");
        }
    }

    let mut notes = Vec::new();
    if removed {
        notes.push("vouch hooks removed from Codex hooks.json.".into());
        notes.push("Note: to remove the vouch_approval MCP broker from Codex, run: codex mcp remove vouch_approval".into());
    } else {
        notes.push("No vouch hooks were found in Codex hooks.json.".into());
    }

    let hooks_view = if let Some(hooks) = root.get("hooks") {
        serde_json::to_string_pretty(&json!({ "hooks": hooks.clone() })).map_err(|e| e.to_string())?
    } else {
        "{}".into()
    };
    let settings = serde_json::to_string_pretty(&root)
        .map_err(|e| format!("could not render hooks.json: {e}"))?;

    Ok(Plan {
        settings,
        hooks_view,
        notes,
    })
}

/// Remove vouch hooks from Antigravity's hooks.json.
pub fn unplan_agy(existing: &str) -> Result<Plan, String> {
    let mut root: Value = if existing.trim().is_empty() {
        json!({})
    } else {
        serde_json::from_str(existing)
            .map_err(|e| format!("hooks.json is not valid JSON: {e}"))?
    };
    if !root.is_object() {
        return Err("hooks.json is not a JSON object".into());
    }

    let removed = root.as_object_mut().unwrap().remove("vouch").is_some();
    let notes = if removed {
        vec!["vouch hook group removed from Antigravity hooks.json.".into()]
    } else {
        vec!["No vouch hook group was found in Antigravity hooks.json.".into()]
    };

    let hooks_view = serde_json::to_string_pretty(&root).map_err(|e| e.to_string())?;
    let settings = serde_json::to_string_pretty(&root)
        .map_err(|e| format!("could not render hooks.json: {e}"))?;

    Ok(Plan {
        settings,
        hooks_view,
        notes,
    })
}

/// Write configuration atomically to `path`, creating any missing parent directories.
pub fn write_file_atomically(path: &std::path::Path, content: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("could not create directory {}: {e}", parent.display()))?;
    }
    let temp_name = format!(
        ".{}.tmp.{}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("config"),
        std::process::id()
    );
    let temp_path = path.with_file_name(temp_name);
    if std::fs::write(&temp_path, content).is_ok() && std::fs::rename(&temp_path, path).is_ok() {
        return Ok(());
    }
    let _ = std::fs::remove_file(&temp_path);
    std::fs::write(path, content)
        .map_err(|e| format!("could not write {}: {e}", path.display()))?;
    Ok(())
}

/// Standard modeled developer tools requiring unsandboxed execution under Antigravity.
pub const DEFAULT_AGY_UNSANDBOXED_TOOLS: &[&str] = &[
    "cargo*",
    "gh*",
    "git*",
    "curl*",
    "ssh*",
    "vouch*",
    "GIT_CONFIG_GLOBAL=*",
    "bash*",
    "sh*",
    "python*",
    "python3*",
    "kubectl*",
    "grep*",
    "file*",
    "find*",
    "cat*",
    "head*",
    "tail*",
    "ls*",
    "node*",
    "npm*",
    "npx*",
    "bun*",
    "pnpm*",
    "docker*",
    "jq*",
    "just*",
    "uv*",
    "stat*",
    "strings*",
    "which*",
];

/// Reconciles Antigravity settings.json permissions to include clean tool entries.
///
/// Antigravity evaluates permissions by tokenizing command strings on whitespace
/// and matching each token as an anchored word (`^(?:pattern)$`). Bare rules without
/// arguments (e.g. `command(git)`) only match zero-argument invocations, while
/// arguments require an explicit second token wildcard (e.g. `command(git *)`).
/// Legacy `unsandboxed(...)` rules are deprecated by Antigravity and ignored,
/// so both modern `command(...)` forms and compatibility `unsandboxed(...)` forms
/// are emitted for both bare and multi-token execution.
pub fn reconcile_agy_permissions(existing: &str, tools: &[&str]) -> Result<String, String> {
    let mut root: Value = if existing.trim().is_empty() {
        json!({})
    } else {
        serde_json::from_str(existing)
            .map_err(|e| format!("settings.json is not valid JSON: {e}"))?
    };
    if !root.is_object() {
        return Err("settings.json is not a JSON object".into());
    }
    let perms = root
        .as_object_mut()
        .unwrap()
        .entry("permissions")
        .or_insert_with(|| json!({}));
    if !perms.is_object() {
        *perms = json!({});
    }
    let allow = perms
        .as_object_mut()
        .unwrap()
        .entry("allow")
        .or_insert_with(|| json!([]));
    if let Some(arr) = allow.as_array_mut() {
        let mut candidates = Vec::new();
        for tool in tools {
            candidates.push((*tool).to_string());
        }

        // Also harvest existing tool rules so legacy unspaced rules (e.g. `command(kubectl*)`)
        // are upgraded with the correct multi-token spaced wildcard entries.
        for item in arr.iter() {
            if let Some(s) = item.as_str() {
                let inner = if let Some(stripped) = s.strip_prefix("command(").and_then(|r| r.strip_suffix(')')) {
                    Some(stripped)
                } else if let Some(stripped) = s.strip_prefix("unsandboxed(").and_then(|r| r.strip_suffix(')')) {
                    Some(stripped)
                } else {
                    None
                };
                if let Some(inner) = inner {
                    if inner.ends_with('*') && !inner.contains(' ') && !inner.contains('/') {
                        candidates.push(inner.to_string());
                    }
                }
            }
        }

        for cand in candidates {
            let is_env = cand.contains('=');
            let base = if is_env {
                cand.as_str()
            } else {
                cand.strip_suffix('*').unwrap_or(&cand)
            };

            let entries = if is_env {
                vec![
                    format!("command({base})"),
                    format!("command({base} *)"),
                    format!("unsandboxed({base})"),
                    format!("unsandboxed({base} *)"),
                ]
            } else {
                vec![
                    format!("command({base})"),
                    format!("command({base} *)"),
                    format!("unsandboxed({base})"),
                    format!("unsandboxed({base} *)"),
                    format!("unsandboxed({base}*)"),
                ]
            };

            for entry in entries {
                let val = Value::String(entry);
                if !arr.contains(&val) {
                    arr.push(val);
                }
            }
        }

        // Standard git subcommands that Antigravity requires explicit prefix rules for
        let git_subcommands = [
            "add", "commit", "status", "diff", "log", "show", "branch", "checkout",
            "switch", "restore", "tag", "stash", "merge", "rebase", "reset",
            "rev-parse", "clean", "rm", "mv", "fetch", "pull", "push", "clone",
            "worktree", "config", "remote",
        ];
        for sub in git_subcommands {
            for pattern in [
                format!("command(git {sub})"),
                format!("command(git {sub}*)"),
                format!("command(git {sub} *)"),
                format!("unsandboxed(git {sub})"),
                format!("unsandboxed(git {sub}*)"),
                format!("unsandboxed(git {sub} *)"),
            ] {
                let val = Value::String(pattern);
                if !arr.contains(&val) {
                    arr.push(val);
                }
            }
        }

        // Standard cargo subcommands
        let cargo_subcommands = [
            "build", "test", "check", "clippy", "run", "clean", "update", "metadata", "install",
        ];
        for sub in cargo_subcommands {
            for pattern in [
                format!("command(cargo {sub})"),
                format!("command(cargo {sub}*)"),
                format!("command(cargo {sub} *)"),
                format!("unsandboxed(cargo {sub})"),
                format!("unsandboxed(cargo {sub}*)"),
                format!("unsandboxed(cargo {sub} *)"),
            ] {
                let val = Value::String(pattern);
                if !arr.contains(&val) {
                    arr.push(val);
                }
            }
        }

        // Standard developer workflow patterns: workspace scripts and scoped multi-argument commands
        let standard_patterns = [
            "command(bash scripts/**)",
            "command(bash scripts/*)",
            "command(sh scripts/**)",
            "command(sh scripts/*)",
            "command(./scripts/**)",
            "command(./scripts/*)",
            "command(bash ./scripts/**)",
            "command(bash ./scripts/*)",
            "command(sh ./scripts/**)",
            "command(sh ./scripts/*)",
            "command(bash ./**)",
            "command(sh ./**)",
            "command(./*)",
            "command(./**)",
            "command(./target/debug/*)",
            "command(./target/debug/* *)",
            "command(target/debug/*)",
            "command(target/debug/* *)",
            "command(./target/release/*)",
            "command(./target/release/* *)",
            "command(target/release/*)",
            "command(target/release/* *)",
            "command(target/debug/vouch)",
            "command(target/debug/vouch *)",
            "command(./target/debug/vouch)",
            "command(./target/debug/vouch *)",
            "command(kubectl -n * exec *)",
            "command(kubectl exec *)",
            "command(kubectl -n * get *)",
            "command(kubectl get *)",
            "command(kubectl -n * describe *)",
            "command(kubectl describe *)",
            "command(kubectl -n * logs *)",
            "command(kubectl logs *)",
            "command(kubectl -n * apply *)",
            "command(kubectl apply *)",
            "command(kubectl -n * delete *)",
            "command(kubectl delete *)",
            "command(kubectl -n * rollout *)",
            "command(kubectl rollout *)",
            "unsandboxed(bash scripts/**)",
            "unsandboxed(bash scripts/*)",
            "unsandboxed(sh scripts/**)",
            "unsandboxed(sh scripts/*)",
            "unsandboxed(./scripts/**)",
            "unsandboxed(./scripts/*)",
            "unsandboxed(./*)",
            "unsandboxed(./**)",
        ];
        for pattern in standard_patterns {
            let val = Value::String(pattern.to_string());
            if !arr.contains(&val) {
                arr.push(val);
            }
        }
    }

    // When vouch is installed as the gate, Antigravity should not prompt with
    // duplicate sandbox bypass modals for tool operations vouch evaluates.
    let obj = root.as_object_mut().unwrap();
    obj.insert("toolPermission".to_string(), json!("always-proceed"));
    obj.insert("enableTerminalSandbox".to_string(), json!(false));

    serde_json::to_string_pretty(&root).map_err(|e| format!("could not render settings.json: {e}"))
}

