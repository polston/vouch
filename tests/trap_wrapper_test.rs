//! Tests for scanning `trap` command handler argument as a bash snippet (M2.152 Half 2).

mod common;

use common::{realistic_config, realistic_config_with_construct};
use vouch::config::Action;
use vouch::protocol::Decision;

#[test]
fn test_trap_safe_cleanup_handler() {
    let cfg = realistic_config();

    // Standard cleanup handler in C:/tmp is allowed
    let d = vouch::engine::decide_command_at(
        &cfg,
        "bash",
        "trap 'rm -f C:/tmp/test_clean.txt' EXIT",
        None,
        None,
        Some("C:/Users/dev"),
    );

    assert_eq!(d, Decision::Allow("allowed by vouch policy".to_string()));
}

#[test]
fn test_trap_destructive_handler_caught() {
    let cfg = realistic_config();

    // Destructive command inside trap handler is caught by guards
    let d = vouch::engine::decide_command_at(
        &cfg,
        "bash",
        "trap 'rm -rf /' EXIT",
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

#[test]
fn test_trap_unmodeled_handler_caught() {
    let cfg = realistic_config_with_construct("bash", "unmodeled_command", Action::Ask);

    // Unmodeled program inside trap handler prompts on unmodeled_command
    let d = vouch::engine::decide_command_at(
        &cfg,
        "bash",
        "trap 'frobnicate_unmodeled_xyz' EXIT",
        None,
        None,
        Some("C:/Users/dev"),
    );

    match d {
        Decision::Ask(reason) => {
            assert!(
                reason.contains("unmodeled_command"),
                "expected unmodeled_command, got: {reason}"
            );
        }
        other => panic!("expected Ask on unmodeled_command, got {other:?}"),
    }
}

#[test]
fn test_trap_empty_handler_and_reset() {
    let cfg = realistic_config();

    // Empty string handler (ignore signal) wraps nothing, allowed
    let d_empty = vouch::engine::decide_command_at(
        &cfg,
        "bash",
        "trap '' INT TERM",
        None,
        None,
        Some("C:/Users/dev"),
    );
    assert_eq!(d_empty, Decision::Allow("allowed by vouch policy".to_string()));

    // Dash handler (reset signal to default) wraps nothing, allowed
    let d_reset = vouch::engine::decide_command_at(
        &cfg,
        "bash",
        "trap - EXIT",
        None,
        None,
        Some("C:/Users/dev"),
    );
    assert_eq!(d_reset, Decision::Allow("allowed by vouch policy".to_string()));
}

#[test]
fn test_trap_standalone_listing_flags() {
    let cfg = realistic_config();

    // trap -p (print traps) is allowed as standalone flag
    let d_p = vouch::engine::decide_command_at(
        &cfg,
        "bash",
        "trap -p",
        None,
        None,
        Some("C:/Users/dev"),
    );
    assert_eq!(d_p, Decision::Allow("allowed by vouch policy".to_string()));

    // trap -l (list signals) is allowed as standalone flag
    let d_l = vouch::engine::decide_command_at(
        &cfg,
        "bash",
        "trap -l",
        None,
        None,
        Some("C:/Users/dev"),
    );
    assert_eq!(d_l, Decision::Allow("allowed by vouch policy".to_string()));
}
