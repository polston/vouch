use std::io::Write;
use std::process::{Command, Stdio};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_vouch")
}

fn pinned_home() -> String {
    let dir = std::env::temp_dir().join(format!("vouch_test_read_home_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    dir.to_string_lossy().replace('\\', "/")
}

fn run_hook(config_toml: &str, raw_input: &str, host: &str) -> (bool, String) {
    let state = std::env::temp_dir().join(format!(
        "vouch_gated_reads_test_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::create_dir_all(&state);
    let cfg_file = state.join("config.toml");
    std::fs::write(&cfg_file, config_toml).unwrap();
    let home = pinned_home();

    let mut cmd = Command::new(bin());
    cmd.arg("--hook")
        .env("VOUCH_CONFIG", &cfg_file)
        .env("VOUCH_STATE_DIR", &state)
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if !host.is_empty() {
        cmd.arg("--host").arg(host);
        if host == "codex" {
            cmd.arg("--shell").arg("bash");
        }
    }

    let mut child = cmd.spawn().unwrap();
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(raw_input.as_bytes());
    }
    let out = child.wait_with_output().unwrap();
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = std::fs::remove_dir_all(&state);
    (out.status.success(), combined)
}

const READ_CONFIG: &str = r#"
[read]
default = "allow"
ask_paths = [
  "$HOME/.ssh/**",
  "$HOME/.aws/**",
  "**/.env",
  "**/.env.*",
  "**/*_rsa",
]
deny_paths = [
  "/secret/**",
]

[lang.bash]
default = "allow"
"#;

#[test]
fn tool_read_on_unlisted_path_allows() {
    let input = serde_json::json!({
        "session_id": "test-s",
        "cwd": "/repo",
        "tool_name": "Read",
        "tool_input": {
            "file_path": "/repo/src/main.rs"
        }
    });
    let (ok, out) = run_hook(READ_CONFIG, &input.to_string(), "claude");
    assert!(ok);
    assert!(
        out.contains("\"permissionDecision\":\"allow\"") || out.contains("\"permissionDecision\": \"allow\""),
        "expected allow on unlisted file, got: {out}"
    );
}

#[test]
fn tool_read_on_protected_path_asks() {
    let home = pinned_home();
    let target = format!("{home}/.ssh/id_rsa");
    let input = serde_json::json!({
        "session_id": "test-s",
        "cwd": "/repo",
        "tool_name": "Read",
        "tool_input": {
            "file_path": target
        }
    });
    let (ok, out) = run_hook(READ_CONFIG, &input.to_string(), "claude");
    assert!(ok);
    assert!(
        out.contains("\"permissionDecision\":\"ask\"") || out.contains("\"permissionDecision\": \"ask\""),
        "expected ask on sensitive file read, got: {out}"
    );
    assert!(out.contains("read of sensitive file"), "reason missing in: {out}");
    assert!(out.contains("read.ask_paths covers this tree"), "diagnostic missing in: {out}");
}

#[test]
fn tool_read_on_denied_path_denies() {
    let input = serde_json::json!({
        "session_id": "test-s",
        "cwd": "/repo",
        "tool_name": "Read",
        "tool_input": {
            "file_path": "/secret/key.pem"
        }
    });
    let (ok, out) = run_hook(READ_CONFIG, &input.to_string(), "claude");
    assert!(ok);
    assert!(
        out.contains("\"permissionDecision\":\"deny\"") || out.contains("\"permissionDecision\": \"deny\""),
        "expected deny on denied path, got: {out}"
    );
    assert!(out.contains("read.deny_paths covers this tree"), "diagnostic missing in: {out}");
}

#[test]
fn view_file_on_protected_path_in_antigravity_asks() {
    let home = pinned_home();
    let target = format!("{home}/.aws/credentials");
    let input = serde_json::json!({
        "session_id": "test-s",
        "cwd": "/repo",
        "tool_name": "view_file",
        "tool_input": {
            "AbsolutePath": target
        }
    });
    let (ok, out) = run_hook(READ_CONFIG, &input.to_string(), "agy");
    assert!(ok);
    assert!(
        out.contains("\"force_ask\""),
        "expected force_ask in antigravity, got: {out}"
    );
    assert!(out.contains("read of sensitive file"));
}

#[test]
fn command_cat_on_protected_path_asks() {
    let home = pinned_home();
    let command = format!("cat {home}/.ssh/id_rsa");
    let input = serde_json::json!({
        "session_id": "test-s",
        "cwd": "/repo",
        "tool_name": "Bash",
        "tool_input": {
            "command": command
        }
    });
    let (ok, out) = run_hook(READ_CONFIG, &input.to_string(), "claude");
    assert!(ok);
    assert!(
        out.contains("\"permissionDecision\":\"ask\"") || out.contains("\"permissionDecision\": \"ask\""),
        "expected ask for cat on sensitive file, got: {out}"
    );
    assert!(out.contains("read of sensitive file"));
}


#[test]
fn command_head_on_env_asks() {
    let input = serde_json::json!({
        "session_id": "test-s",
        "cwd": "/repo",
        "tool_name": "Bash",
        "tool_input": {
            "command": "head -n 20 .env"
        }
    });
    let (ok, out) = run_hook(READ_CONFIG, &input.to_string(), "claude");
    assert!(ok);
    assert!(
        out.contains("\"permissionDecision\":\"ask\"") || out.contains("\"permissionDecision\": \"ask\""),
        "expected ask for head on .env, got: {out}"
    );
    assert!(out.contains("read of sensitive file"), "out was: {out}");
}

#[test]
fn command_cat_on_readme_allows() {
    let input = serde_json::json!({
        "session_id": "test-s",
        "cwd": "/repo",
        "tool_name": "Bash",
        "tool_input": {
            "command": "cat ./README.md"
        }
    });
    let (ok, out) = run_hook(READ_CONFIG, &input.to_string(), "claude");
    assert!(ok);
    assert!(
        out.contains("\"permissionDecision\":\"allow\"") || out.contains("\"permissionDecision\": \"allow\""),
        "expected allow for cat on README.md, got: {out}"
    );
}

#[test]
fn command_cat_on_denied_path_denies() {
    let input = serde_json::json!({
        "session_id": "test-s",
        "cwd": "/repo",
        "tool_name": "Bash",
        "tool_input": {
            "command": "cat /secret/key.pem"
        }
    });
    let (ok, out) = run_hook(READ_CONFIG, &input.to_string(), "claude");
    assert!(ok);
    assert!(
        out.contains("\"permissionDecision\":\"deny\"") || out.contains("\"permissionDecision\": \"deny\""),
        "expected deny for cat on /secret/key.pem, got: {out}"
    );
}

#[test]
fn config_validation_refuses_overlapping_read_paths() {
    let config = r#"
[read]
ask_paths = ["/sensitive/**"]
deny_paths = ["/sensitive/**"]
"#;
    let err = vouch::config::load(config).unwrap_err();
    assert!(
        err.contains("appears in both read.ask_paths and read.deny_paths"),
        "expected error on overlapping paths, got: {err}"
    );
}
