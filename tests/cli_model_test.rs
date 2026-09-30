//! Integration tests for `vouch model` CLI command.

use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_vouch")
}

fn temp_dir(prefix: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("{prefix}_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
    let _ = std::fs::create_dir_all(&p);
    p
}

fn vouch_cmd(home: &Path, state_dir: &Path) -> Command {
    let mut cmd = Command::new(bin());
    cmd.env("HOME", home)
        .env("USERPROFILE", home)
        .env("VOUCH_STATE_DIR", state_dir)
        .env_remove("VOUCH_MY_KNOWLEDGE")
        .env_remove("VOUCH_CONFIG");
    cmd
}

#[test]
fn cli_model_program_writes_to_my_knowledge_and_leaves_config_untouched() {
    let home = temp_dir("cli_model_1");
    let state_dir = home.join("state");
    let my_knowledge = home.join(".config/vouch/my-knowledge.toml");
    let config_file = home.join(".config/vouch/config.toml");

    let out = vouch_cmd(&home, &state_dir)
        .args(["model", "program", "mybuilder", "--subcommand", "build", "--value-flag", "-o"])
        .output()
        .expect("command runs");

    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("modeled program `mybuilder`"), "stdout: {stdout}");

    // my-knowledge.toml was created and contains the program
    let content = std::fs::read_to_string(&my_knowledge).expect("my-knowledge.toml exists");
    assert!(content.contains(r#"match = ["mybuilder"]"#));
    assert!(content.contains(r#"subcommands = ["build"]"#));
    assert!(content.contains(r#"value_options = ["-o"]"#));

    // config.toml must be untouched / non-existent
    assert!(!config_file.exists(), "config.toml should not be touched by vouch model");
}

#[test]
fn cli_model_program_duplicate_rejected_without_update() {
    let home = temp_dir("cli_model_2");
    let state_dir = home.join("state");

    let out1 = vouch_cmd(&home, &state_dir)
        .args(["model", "program", "dup_tool", "--subcommand", "run"])
        .output()
        .expect("command runs");
    assert!(out1.status.success(), "stderr: {}", String::from_utf8_lossy(&out1.stderr));

    // Second call without --update fails
    let out2 = vouch_cmd(&home, &state_dir)
        .args(["model", "program", "dup_tool", "--subcommand", "exec"])
        .output()
        .expect("command runs");
    assert!(!out2.status.success());
    let stderr = String::from_utf8_lossy(&out2.stderr);
    assert!(stderr.contains("already modeled"), "stderr: {stderr}");

    // With --update succeeds
    let out3 = vouch_cmd(&home, &state_dir)
        .args(["model", "program", "dup_tool", "--subcommand", "exec", "--update"])
        .output()
        .expect("command runs");
    assert!(out3.status.success(), "stderr: {}", String::from_utf8_lossy(&out3.stderr));
}

#[test]
fn cli_model_tool_writes_structured_rules() {
    let home = temp_dir("cli_model_3");
    let state_dir = home.join("state");
    let my_knowledge = home.join(".config/vouch/my-knowledge.toml");

    let out = vouch_cmd(&home, &state_dir)
        .args([
            "model",
            "tool",
            "mcp__db__query",
            "--snippet",
            "code:python",
            "--cwd-from-call",
            "--rule",
            "query:ask:(?i)drop",
        ])
        .output()
        .expect("command runs");

    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let content = std::fs::read_to_string(&my_knowledge).expect("my-knowledge.toml exists");
    assert!(content.contains(r#"match = ["mcp__db__query"]"#));
    assert!(content.contains(r#"cwd_from_call = true"#));
    assert!(content.contains(r#"action = "ask""#));
    assert!(content.contains(r#"when_pattern = "(?i)drop""#));
}
