//! Integration tests for `vouch trust` policy management command.

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
fn cli_trust_path_writes_to_config_and_leaves_knowledge_untouched() {
    let home = temp_dir("cli_trust_1");
    let state_dir = home.join("state");
    let my_knowledge = home.join(".config/vouch/my-knowledge.toml");
    let config_file = home.join(".config/vouch/config.toml");

    let out = vouch_cmd(&home, &state_dir)
        .args(["trust", "path", "/tmp/safe_scratch"])
        .output()
        .expect("command runs");

    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("trusted path"), "stdout: {stdout}");

    // config.toml exists and contains write.allow_paths
    let content = std::fs::read_to_string(&config_file).expect("config.toml exists");
    assert!(content.contains(r#"/tmp/safe_scratch/**"#));

    // my-knowledge.toml must be untouched / non-existent
    assert!(!my_knowledge.exists(), "my-knowledge.toml should not be touched by vouch trust path");
}

#[test]
fn cli_trust_refuses_protected_path() {
    let home = temp_dir("cli_trust_2");
    let state_dir = home.join("state");
    let config_file = home.join(".config/vouch/config.toml");

    std::fs::create_dir_all(config_file.parent().unwrap()).unwrap();
    std::fs::write(
        &config_file,
        r#"version = 1
[protected]
paths = ["$HOME/.config/vouch/config.toml"]
"#,
    )
    .unwrap();

    let out = vouch_cmd(&home, &state_dir)
        .args(["trust", "path", &format!("{}/.config/vouch/config.toml", home.to_string_lossy().replace('\\', "/"))])
        .output()
        .expect("command runs");

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("protected path"), "stderr: {stderr}");
}

#[test]
fn cli_trust_zone_and_program_location() {
    let home = temp_dir("cli_trust_3");
    let state_dir = home.join("state");
    let config_file = home.join(".config/vouch/config.toml");

    let out1 = vouch_cmd(&home, &state_dir)
        .args(["trust", "zone", "C:/safe_zone"])
        .output()
        .expect("command runs");
    assert!(out1.status.success(), "stderr: {}", String::from_utf8_lossy(&out1.stderr));

    let out2 = vouch_cmd(&home, &state_dir)
        .args(["trust", "program-location", "C:/safe_zone/target", "mycompiler"])
        .output()
        .expect("command runs");
    assert!(out2.status.success(), "stderr: {}", String::from_utf8_lossy(&out2.stderr));

    let content = std::fs::read_to_string(&config_file).expect("config.toml exists");
    assert!(content.contains(r#"trust_all_under = ["C:/safe_zone"]"#));
    assert!(content.contains(r#"under = ["C:/safe_zone/target"]"#));
    assert!(content.contains(r#"name_patterns = ["mycompiler"]"#));
}

#[test]
fn cli_trust_preserves_comments_in_config() {
    let home = temp_dir("cli_trust_4");
    let state_dir = home.join("state");
    let config_file = home.join(".config/vouch/config.toml");

    std::fs::create_dir_all(config_file.parent().unwrap()).unwrap();
    std::fs::write(
        &config_file,
        r#"# Important header comment
version = 1

# Section comment
[write]
default = "ask"
"#,
    )
    .unwrap();

    let out = vouch_cmd(&home, &state_dir)
        .args(["trust", "path", "/tmp/another_scratch"])
        .output()
        .expect("command runs");
    assert!(out.status.success());

    let content = std::fs::read_to_string(&config_file).unwrap();
    assert!(content.contains("# Important header comment"));
    assert!(content.contains("# Section comment"));
    assert!(content.contains("/tmp/another_scratch/**"));
}
