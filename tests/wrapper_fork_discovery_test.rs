//! Tests for splitting fork enumeration discovery from judgement in wrapper walks (M2.142(a)).

mod common;

use common::realistic_config;
use vouch::protocol::Decision;

#[test]
fn test_fast_path_zero_forks() {
    let cfg = realistic_config();

    // Fast path: no wrappers, zero forks -> exactly one evaluation pass
    let d = vouch::engine::decide_command_at(
        &cfg,
        "bash",
        "ls -la",
        None,
        None,
        Some("C:/Users/dev"),
    );
    assert_eq!(d, Decision::Allow("allowed by vouch policy".to_string()));
}

#[test]
fn test_multi_wrapper_flags_adjudication() {
    let cfg = realistic_config();

    // Multi-wrapper chain with known and undescribed flags:
    // sudo -E -u admin env VAR=val ls -la
    let d = vouch::engine::decide_command_at(
        &cfg,
        "bash",
        "sudo -E -u admin env VAR=val ls -la",
        None,
        None,
        Some("C:/Users/dev"),
    );

    match d {
        Decision::Ask(reason) => {
            assert!(
                reason.contains("privilege_escalation"),
                "expected privilege_escalation guard from sudo, got: {reason}"
            );
        }
        other => panic!("expected Ask on privilege_escalation, got {other:?}"),
    }
}

#[test]
fn test_nested_wrappers_with_environment_variables() {
    let cfg = realistic_config();

    // Nested wrapper chain: env running sh running commands
    let d = vouch::engine::decide_command_at(
        &cfg,
        "bash",
        "env FOO=1 BAR=2 sh -c 'echo test'",
        None,
        None,
        Some("C:/Users/dev"),
    );

    assert_eq!(d, Decision::Allow("allowed by vouch policy".to_string()));
}

#[test]
fn test_wrapper_destructive_guard_preservation() {
    let cfg = realistic_config();

    // Wrapped destructive command must be caught regardless of wrapper fork readings
    let d = vouch::engine::decide_command_at(
        &cfg,
        "bash",
        "env FOO=1 rm -rf /",
        None,
        None,
        Some("C:/Users/dev"),
    );

    match d {
        Decision::Ask(reason) => {
            assert!(
                reason.contains("delete_recursive"),
                "expected delete_recursive guard, got: {reason}"
            );
        }
        other => panic!("expected Ask on delete_recursive, got {other:?}"),
    }
}
