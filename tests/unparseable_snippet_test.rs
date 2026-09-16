use std::io::Write;
use std::process::{Command, Stdio};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_vouch")
}

fn pinned_home() -> String {
    let dir = std::env::temp_dir().join(format!("vouch_test_home_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    dir.to_string_lossy().replace('\\', "/")
}

fn run_hook_with_config(config_toml: &str, raw_input: &str, host: &str) -> (bool, String) {
    let state = std::env::temp_dir().join(format!(
        "vouch_unparseable_test_{}_{}",
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

#[test]
fn unparseable_empty_input_produces_explicit_ask() {
    let (ok, out) = run_hook_with_config("", "", "claude");
    assert!(ok, "exit status should be 0, output: {out}");
    assert!(
        out.contains("unparseable hook payload"),
        "expected unparseable diagnostic, got: {out}"
    );
    assert!(
        out.contains(r#"unparseable_snippet = \"ask\" | \"deny\""#),
        "expected advice naming configuration key, got: {out}"
    );
    assert!(out.contains("\"permissionDecision\":\"ask\""));
}

#[test]
fn unparseable_corrupted_json_produces_explicit_ask() {
    let bad_json = r#"{"tool_name": "Bash", "input": {"#;
    let (ok, out) = run_hook_with_config("", bad_json, "claude");
    assert!(ok);
    assert!(
        out.contains("unparseable hook payload"),
        "expected unparseable diagnostic, got: {out}"
    );
    assert!(out.contains("EOF while parsing"), "expected parse error detail in: {out}");
}

#[test]
fn unparseable_configured_to_deny() {
    let config = "unparseable_snippet = \"deny\"\n";
    let bad_json = "not json at all";
    let (ok, out) = run_hook_with_config(config, bad_json, "claude");
    assert!(ok);
    assert!(
        out.contains("deny"),
        "expected deny decision for configured policy, got: {out}"
    );
    assert!(out.contains("unparseable hook payload"));
}

#[test]
fn unparseable_rendered_for_antigravity() {
    let bad_json = "malformed {";
    let (ok, out) = run_hook_with_config("", bad_json, "agy");
    assert!(ok);
    assert!(
        out.contains("\"permissionDecision\": \"force_ask\"")
            || out.contains("\"permissionDecision\":\"force_ask\"")
            || out.contains("force_ask"),
        "expected antigravity force_ask rendering, got: {out}"
    );
}

#[test]
fn unparseable_rendered_for_codex() {
    let bad_json = "{bad";
    let (ok, out) = run_hook_with_config("", bad_json, "codex");
    assert!(ok);
    assert!(
        out.contains("deny"),
        "expected codex denial of unparseable payload, got: {out}"
    );
}

#[test]
fn config_validation_refuses_unparseable_allow() {
    let err = vouch::config::load("unparseable_snippet = \"allow\"\n").unwrap_err();
    assert!(
        err.contains("unparseable_snippet cannot be 'allow'"),
        "expected refusal of allow, got: {err}"
    );
}
