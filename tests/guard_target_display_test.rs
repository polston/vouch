mod common;

use common::realistic_config;
use vouch::engine::decide_command_at;
use vouch::protocol::Decision;

const HOME: &str = "C:/Users/dev";

#[test]
fn guard_target_display_resolves_same_command_variable_semicolon() {
    let cfg = realistic_config();
    let decision = decide_command_at(
        &cfg,
        "bash",
        r#"DIR="/tmp/test"; rm -rf "$DIR""#,
        Some(HOME),
        None,
        Some("C:/scratch"),
    );

    match decision {
        Decision::Ask(reason) => {
            assert!(
                reason.contains("delete_recursive"),
                "expected delete_recursive guard, got: {reason}"
            );
            assert!(
                reason.contains(r#"command: rm -rf "$DIR""#),
                "expected unexpanded command invocation in: {reason}"
            );
            assert!(
                reason.contains("resolved: rm -rf /tmp/test"),
                "expected resolved target path in: {reason}"
            );
        }
        other => panic!("expected Ask on delete_recursive, got: {other:?}"),
    }
}

#[test]
fn guard_target_display_resolves_same_command_variable_and_chain() {
    let cfg = realistic_config();
    let decision = decide_command_at(
        &cfg,
        "bash",
        r#"CACHE=/tmp/cache && rm -rf "$CACHE""#,
        Some(HOME),
        None,
        Some("C:/scratch"),
    );

    match decision {
        Decision::Ask(reason) => {
            assert!(
                reason.contains("delete_recursive"),
                "expected delete_recursive guard, got: {reason}"
            );
            assert!(
                reason.contains(r#"command: rm -rf "$CACHE""#),
                "expected unexpanded command invocation in: {reason}"
            );
            assert!(
                reason.contains("resolved: rm -rf /tmp/cache"),
                "expected resolved target path in: {reason}"
            );
        }
        other => panic!("expected Ask on delete_recursive, got: {other:?}"),
    }
}

#[test]
fn guard_target_display_reports_unresolvable_variable_notice() {
    let cfg = realistic_config();
    let decision = decide_command_at(
        &cfg,
        "bash",
        r#"rm -rf "$UNSET_DIR""#,
        Some(HOME),
        None,
        Some("C:/scratch"),
    );

    match decision {
        Decision::Ask(reason) => {
            assert!(
                reason.contains("delete_recursive"),
                "expected delete_recursive guard, got: {reason}"
            );
            assert!(
                reason.contains(r#"command: rm -rf "$UNSET_DIR""#),
                "expected command in: {reason}"
            );
            assert!(
                reason.contains("vouch could not work out what $UNSET_DIR is"),
                "expected unresolvable notice in: {reason}"
            );
        }
        other => panic!("expected Ask on delete_recursive, got: {other:?}"),
    }
}
