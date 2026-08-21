//! With no config file, vouch has been told nothing, so it allows nothing.

use std::io::Write;
use std::process::{Command, Stdio};

const NO_CONFIG: &str = "tests/fixtures/there-is-no-such-config.toml";

fn hook(tool: &str, body: &str, config: &str) -> String {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_vouch"));
    let home = std::env::temp_dir().join("vouch_no_config_home");
    std::fs::create_dir_all(&home).ok();
    cmd.env("VOUCH_STATE_DIR", std::env::temp_dir().join("vouch_no_config_state"));
    cmd.env("VOUCH_CONFIG", config);
    // Pinned so the result does not depend on whose machine this is.
    cmd.env("HOME", &home).env("USERPROFILE", &home);
    cmd.arg("--hook");
    let snippet = format!(
        r#"{{"hook_event_name":"PreToolUse","tool_use_id":"t","session_id":"s","cwd":"C:/claude","tool_name":"{tool}","tool_input":{body}}}"#
    );
    let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
    child.stdin.as_mut().unwrap().write_all(snippet.as_bytes()).unwrap();
    String::from_utf8_lossy(&child.wait_with_output().unwrap().stdout).to_string()
}

#[test]
fn with_no_config_file_even_a_described_program_asks() {
    let out = hook("Bash", r#"{"command":"ls -la"}"#, NO_CONFIG);
    assert!(out.contains("\"permissionDecision\":\"ask\""), "expected ask; got {out}");
}

#[test]
fn with_no_config_file_a_write_is_not_allowed_anywhere() {
    let out = hook("Bash", r#"{"command":"echo hi > C:/work/out.txt"}"#, NO_CONFIG);
    assert!(!out.contains("\"permissionDecision\":\"allow\""), "a write was allowed; got {out}");
}

#[test]
fn with_no_config_file_a_described_TOOL_also_asks() {
    // [review] This was allow. `tool_action` falls back to the descriptions
    // when the config names no tools, and a described tool defaults to allow —
    // so with no config at all, Read, Task, Agent, Skill, WebFetch and
    // EnterWorktree were all allowed while the banner said everything asks.
    for tool in ["Read", "Task", "EnterWorktree"] {
        let out = hook(tool, "{}", NO_CONFIG);
        assert!(
            out.contains("\"permissionDecision\":\"ask\""),
            "{tool} was not asked about with no config; got {out}"
        );
    }
}

#[test]
fn an_ask_with_no_config_still_names_a_setting() {
    // [review] The reason text was the single line "allowed by vouch policy",
    // on an ASK. A prompt naming no setting is a §5 bug.
    let out = hook("Bash", r#"{"command":"ls -la"}"#, NO_CONFIG);
    assert!(!out.contains("allowed by vouch policy"), "an ASK explained itself as an allow: {out}");
    assert!(out.contains("vouch stopped on:"), "the reason does not say what stopped it: {out}");
}

#[test]
fn the_source_does_not_embed_a_config() {
    assert!(
        !include_str!("../src/main.rs").contains("[lang.bash.constructs]"),
        "src/main.rs still carries a config as a string"
    );
}
