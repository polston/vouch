//! The real proof that `vouch review` still learns from a prompt made on a
//! fresh install — not just that the recorded reason's first line still
//! starts with "vouch stopped on:" (checked in `missing_files_prompt_test.rs`),
//! but that the full round trip actually produces a candidate: record an
//! ask (with the missing-config banner attached), record its outcome as
//! executed, then run `vouch review` and see the candidate come out.
//!
//! [review] Reproduced with identical evidence to the original defect: config
//! present -> a usable rule candidate; config missing -> "nothing to review
//! yet". This test is the automated version of that repro, run against the
//! actual binary end to end rather than asserted only in prose.

use std::io::Write;
use std::process::{Command, Stdio};

fn vouch(state_dir: &std::path::Path, env: &[(&str, &str)], args: &[&str], stdin_snippet: &str) -> String {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_vouch"));
    cmd.env("VOUCH_STATE_DIR", state_dir);
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.args(args);
    let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
    child.stdin.as_mut().unwrap().write_all(stdin_snippet.as_bytes()).unwrap();
    String::from_utf8_lossy(&child.wait_with_output().unwrap().stdout).to_string()
}

#[test]
fn a_prompt_made_on_a_fresh_install_still_becomes_a_review_candidate() {
    // This test's own state directory — not shared with any other test, since
    // this is the one that actually reads the journal back via `vouch review`.
    let state = std::env::temp_dir().join("vouch_review_survives_missing_files_state");
    let _ = std::fs::remove_dir_all(&state);
    let home = std::env::temp_dir().join("vouch_review_survives_missing_files_home");
    std::fs::create_dir_all(&home).ok();
    let home_s = home.display().to_string();

    let no_config = "tests/fixtures/there-is-no-such-config-for-review-survives.toml";
    let env: Vec<(&str, &str)> = vec![
        ("VOUCH_CONFIG", no_config),
        ("HOME", &home_s),
        ("USERPROFILE", &home_s),
    ];

    let pre = r#"{"hook_event_name":"PreToolUse","tool_use_id":"rv1","session_id":"rv1","cwd":"C:/claude","tool_name":"Bash","tool_input":{"command":"frobnicate x"}}"#;
    let ask = vouch(&state, &env, &["--hook"], pre);
    assert!(ask.contains("\"permissionDecision\":\"ask\""), "expected an ask on a fresh install: {ask}");
    // Confirms the banner really is attached to THIS recorded prompt, so the
    // proof below is about a prompt that actually carries one — not an
    // incidental one that happens to have no gaps.
    assert!(ask.contains("no config file"), "expected the missing-config banner: {ask}");

    let post = r#"{"hook_event_name":"PostToolUse","tool_use_id":"rv1","session_id":"rv1","tool_name":"Bash"}"#;
    vouch(&state, &env, &["--hook"], post);

    let review_out = vouch(&state, &env, &["review"], "");
    assert!(
        !review_out.contains("nothing to review yet"),
        "review could not see the prompt at all — the exact way the original defect surfaced: {review_out}"
    );
    assert!(
        review_out.contains("unmodeled_command"),
        "the prompt made on a fresh install produced no candidate: {review_out}"
    );
}
