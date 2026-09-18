mod common;

use common::realistic_config;
use vouch::engine::decide_command_at;
use vouch::protocol::Decision;

const HOME: &str = "C:/Users/dev";

#[test]
fn deno_eval_subcommand_wraps_to_javascript() {
    let cfg = realistic_config();
    let decision = decide_command_at(
        &cfg,
        "bash",
        r#"deno eval "console.log(42)""#,
        Some(HOME),
        None,
        Some("C:/scratch"),
    );
    assert!(matches!(decision, Decision::Allow(_)), "expected Allow, got: {decision:?}");

    let dangerous = decide_command_at(
        &cfg,
        "bash",
        r#"deno eval "child_process.execSync('rm -rf /')""#,
        Some(HOME),
        None,
        Some("C:/scratch"),
    );
    match dangerous {
        Decision::Ask(reason) => {
            assert!(
                reason.contains("delete_recursive"),
                "expected delete_recursive guard, got: {reason}"
            );
        }
        other => panic!("expected Ask on delete_recursive, got: {other:?}"),
    }
}

#[test]
fn node_eval_flag_wraps_to_javascript() {
    let cfg = realistic_config();
    let decision = decide_command_at(
        &cfg,
        "bash",
        r#"node -e "console.log(42)""#,
        Some(HOME),
        None,
        Some("C:/scratch"),
    );
    assert!(matches!(decision, Decision::Allow(_)), "expected Allow, got: {decision:?}");

    let dangerous = decide_command_at(
        &cfg,
        "bash",
        r#"node -e "child_process.execSync('rm -rf /')""#,
        Some(HOME),
        None,
        Some("C:/scratch"),
    );
    match dangerous {
        Decision::Ask(reason) => {
            assert!(
                reason.contains("delete_recursive"),
                "expected delete_recursive guard, got: {reason}"
            );
        }
        other => panic!("expected Ask on delete_recursive, got: {other:?}"),
    }
}
