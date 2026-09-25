mod common;

use common::realistic_config;
use vouch::engine::decide_command_at;
use vouch::protocol::Decision;

const HOME: &str = "C:/Users/dev";

#[test]
fn safe_awk_print_allows() {
    let cfg = realistic_config();
    let decision = decide_command_at(
        &cfg,
        "bash",
        r#"awk '{print $1, $2}' input.txt"#,
        Some(HOME),
        None,
        Some("C:/scratch"),
    );

    match decision {
        Decision::Allow(reason) => {
            assert!(
                reason.contains("allowed"),
                "expected allow, got: {reason}"
            );
        }
        other => panic!("expected Allow for safe awk print, got: {other:?}"),
    }
}

#[test]
fn safe_awk_math_and_regex_allows() {
    let cfg = realistic_config();
    let decision = decide_command_at(
        &cfg,
        "bash",
        r#"awk '/foo\/bar/ { total += $3; count++ } END { if (count > 0) print total / count }' data.tsv"#,
        Some(HOME),
        None,
        Some("C:/scratch"),
    );

    match decision {
        Decision::Allow(reason) => {
            assert!(
                reason.contains("allowed"),
                "expected allow, got: {reason}"
            );
        }
        other => panic!("expected Allow for safe awk math and regex, got: {other:?}"),
    }
}

#[test]
fn awk_redirect_write_prompts_on_protected_path() {
    let cfg = realistic_config();
    let decision = decide_command_at(
        &cfg,
        "bash",
        r#"awk '{print > "/etc/shadow"}'"#,
        Some(HOME),
        None,
        Some("C:/scratch"),
    );

    match decision {
        Decision::Ask(reason) => {
            assert!(
                reason.contains("/etc/shadow"),
                "expected prompt mentioning target file, got: {reason}"
            );
        }
        other => panic!("expected Ask for redirection to protected file, got: {other:?}"),
    }
}

#[test]
fn awk_system_rm_rf_triggers_delete_recursive_guard() {
    let cfg = realistic_config();
    let decision = decide_command_at(
        &cfg,
        "bash",
        r#"awk 'BEGIN { system("rm -rf /") }'"#,
        Some(HOME),
        None,
        Some("C:/scratch"),
    );

    match decision {
        Decision::Ask(reason) => {
            assert!(
                reason.contains("delete_recursive") || reason.contains("rm -rf /"),
                "expected delete_recursive guard prompt, got: {reason}"
            );
        }
        other => panic!("expected Ask for awk system(rm -rf /), got: {other:?}"),
    }
}

#[test]
fn awk_pipe_to_command_evaluates_nested_command() {
    let cfg = realistic_config();
    let decision = decide_command_at(
        &cfg,
        "bash",
        r#"awk '{ print $1 | "cat" }'"#,
        Some(HOME),
        None,
        Some("C:/scratch"),
    );

    // "cat" is safe read-only tool in bash
    match decision {
        Decision::Allow(reason) => {
            assert!(
                reason.contains("allowed"),
                "expected allow for piping into cat, got: {reason}"
            );
        }
        other => panic!("expected Allow for pipe to cat, got: {other:?}"),
    }
}

#[test]
fn awk_unclosed_brace_fails_gracefully() {
    let cfg = realistic_config();
    let decision = decide_command_at(
        &cfg,
        "bash",
        r#"awk '{ print $1'"#,
        Some(HOME),
        None,
        Some("C:/scratch"),
    );

    match decision {
        Decision::Ask(reason) => {
            assert!(
                reason.contains("parse_failure") || reason.contains("could not read") || reason.contains("syntax") || reason.contains("unclosed"),
                "expected unparseable snippet prompt, got: {reason}"
            );
        }
        other => panic!("expected Ask for unclosed awk snippet, got: {other:?}"),
    }
}
