//! `vouch install --print` — emit the exact hook registration vouch needs.
//!
//! vouch cannot write `settings.json` itself: Claude Code's own guard refuses to
//! let an agent change which program gates its tool calls. That guard is correct
//! and is not worked around. So this produces the exact JSON, merged with what is
//! already there, for a human to save.
//!
//! Four events are needed, and only the first one decides anything:
//!   PreToolUse         — the decision
//!   PostToolUse        — "it ran"
//!   PostToolUseFailure — "it errored or was interrupted"
//!   PermissionDenied   — "the user refused it"
//!
//! The last three exist so `vouch review` is built on real outcomes rather than
//! on the absence of a signal, which is the mistake that killed the first design.

use serde_json::{json, Value};

use crate::cli::InstallShell;

const CODEX_STATUS_MESSAGE: &str = "vouch is checking this tool call";

pub struct Plan {
    /// The settings.json content to save.
    pub settings: String,
    /// The hooks-only view — display-safe: no MCP/server content, whatever
    /// else the operator's settings.json carries.
    pub hooks_view: String,
    /// What this changes, in plain terms.
    pub notes: Vec<String>,
}

fn hook_entry(exe: &str, extra: &str) -> Value {
    let cmd = if extra.is_empty() {
        format!("{exe} --hook")
    } else {
        format!("{exe} --hook {extra}")
    };
    json!({ "hooks": [ { "type": "command", "command": cmd } ] })
}

fn codex_command(exe: &str, shell: InstallShell, shadow: bool) -> String {
    let quoted = match shell {
        InstallShell::Bash if exe.contains(' ') => format!("'{exe}'"),
        InstallShell::PowerShell if exe.contains(' ') => format!("& '{exe}'"),
        _ => exe.to_string(),
    };
    let shadow = if shadow { " --shadow" } else { "" };
    format!(
        "{quoted} --hook --host codex --shell {}{shadow}",
        shell.as_str()
    )
}

fn codex_hook_entry(exe: &str, shell: InstallShell, shadow: bool) -> Value {
    json!({
        "matcher": ".*",
        "hooks": [{
            "type": "command",
            "command": codex_command(exe, shell, shadow),
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

    for (event, event_shadow) in [("PreToolUse", shadow), ("PostToolUse", false)] {
        let mut entries = without_codex_vouch(hooks.get(event), event)?;
        entries.push(codex_hook_entry(exe, shell, event_shadow));
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
    let notes = vec![
        if shadow {
            "SHADOW: Codex still decides every call; vouch records what it would decide."
        } else {
            "LIVE: vouch blocks Codex tool calls it would ask about or deny."
        }
        .into(),
        "Codex PostToolUse records completed calls; unsupported Claude-only outcome events are not installed."
            .into(),
        format!(
            "Register the one-time human approval broker once: codex mcp add vouch_approval -- {broker}"
        ),
        "Configure Codex for interactive human approval: approval_policy = \"on-request\", approvals_reviewer = \"user\", and under [mcp_servers.vouch_approval] set default_tools_approval_mode = \"prompt\". The native MCP prompt is the broker decision; no nested elicitation is used."
            .into(),
    ];
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

/// Builds the merged settings.json. `shadow` keeps the existing gate in place and
/// adds vouch alongside it, recording decisions without being able to affect any.
pub fn plan(existing: &str, exe: &str, shadow: bool) -> Result<Plan, String> {
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
    let existing_txt = existing_pre.to_string();
    let had_cc_allow = existing_txt.contains("cc-allow");
    let had_vouch = existing_txt.contains("vouch");

    let vouch_pre = hook_entry(exe, if shadow { "--shadow" } else { "" });

    if shadow {
        // Keep whatever is there; append vouch. It emits nothing, by construction.
        let mut arr = existing_pre.as_array().cloned().unwrap_or_default();
        if !had_vouch {
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
        hooks.insert("PreToolUse".into(), json!([vouch_pre]));
        notes.push("LIVE: vouch is now the gate for PreToolUse.".into());
        if had_cc_allow {
            notes.push(
                "cc-allow was REMOVED from PreToolUse. Its config file is untouched, \
                 so putting it back is one edit."
                    .into(),
            );
        }
    }

    // Outcome events. Harmless in either mode — they only record.
    for ev in ["PostToolUse", "PostToolUseFailure", "PermissionDenied"] {
        let mut arr = hooks
            .get(ev)
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        if !arr.iter().any(|e| e.to_string().contains("vouch")) {
            arr.push(hook_entry(exe, ""));
        }
        hooks.insert(ev.to_string(), Value::Array(arr));
    }
    notes.push(
        "PostToolUse / PostToolUseFailure / PermissionDenied added: these only record \
         what actually happened. Without them `vouch review` would be guessing."
            .into(),
    );

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
