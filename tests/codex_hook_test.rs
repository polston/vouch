use std::io::Write;
use std::process::{Command, Stdio};

use vouch::approval::{respond, ApprovalAction};

fn scratch() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("vouch_codex_hook_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn run(dir: &std::path::Path, id: &str, event: &str) -> String {
    let input = serde_json::json!({
        "hook_event_name": event,
        "session_id": "test-session",
        "turn_id": "test-turn",
        "tool_use_id": id,
        "cwd": "C:/Users/dev",
        "tool_name": "Bash",
        "tool_input": {"command": "Remove-Item notes.txt"}
    });
    let mut child = Command::new(env!("CARGO_BIN_EXE_vouch"));
    let mut child = child
        .args(["--hook", "--host", "codex", "--shell", "powershell"])
        .env("VOUCH_CONFIG", dir.join("config.toml"))
        .env("VOUCH_KNOWLEDGE", dir.join("knowledge.toml"))
        .env("VOUCH_MY_KNOWLEDGE", dir.join("my-knowledge.toml"))
        .env("VOUCH_STATE_DIR", dir.join("state"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(input.to_string().as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    String::from_utf8(out.stdout).unwrap()
}

#[test]
fn codex_ask_blocks_then_one_exact_human_approved_retry_runs() {
    let dir = scratch();
    std::fs::write(dir.join("config.toml"), "[tools]\nPowerShell = \"ask\"\n").unwrap();
    std::fs::write(
        dir.join("knowledge.toml"),
        "version = 9\n[[tool]]\nmatch = [\"PowerShell\"]\nsource = \"runs a PowerShell command\"\n",
    )
    .unwrap();
    std::fs::write(dir.join("my-knowledge.toml"), "").unwrap();

    let first = run(&dir, "first", "PreToolUse");
    let response: serde_json::Value = serde_json::from_str(first.trim()).unwrap();
    assert_eq!(response["hookSpecificOutput"]["permissionDecision"], "deny");
    let reason = response["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap();
    let request_id = reason
        .split_whitespace()
        .find(|part| part.starts_with("vouch-"))
        .expect("deny reason carries an approval request id")
        .trim_end_matches(|c: char| !c.is_ascii_alphanumeric() && c != '-')
        .to_string();

    respond(
        &dir.join("state"),
        &request_id,
        ApprovalAction::Accept,
        vouch::journal::now_epoch_secs().parse().unwrap(),
    )
    .unwrap();
    assert_eq!(run(&dir, "retry", "PreToolUse"), "");
    assert_eq!(run(&dir, "retry", "PostToolUse"), "");

    let records = vouch::journal::all(&dir.join("state"));
    assert!(records.iter().any(|record| {
        record.id == "first"
            && record.tool == "PowerShell"
            && record.outcome == vouch::outcome::Outcome::Executed
    }));
    assert!(records.iter().any(|record| {
        record.id == "retry"
            && record.verdict == "allow"
            && record.outcome == vouch::outcome::Outcome::Executed
    }));
}
