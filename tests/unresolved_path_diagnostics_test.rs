mod common;

use common::realistic_config;
use vouch::engine::decide_command_at;
use vouch::protocol::Decision;

const HOME: &str = "C:/Users/dev";

#[test]
fn single_command_unresolved_variable_attributes_command_and_sources() {
    let cfg = realistic_config();
    let decision = decide_command_at(
        &cfg,
        "bash",
        r#"cp a "$DEST""#,
        Some(HOME),
        None,
        Some("C:/scratch"),
    );

    match decision {
        Decision::Ask(reason) => {
            assert!(reason.contains("unresolved_path"), "got: {reason}");
            assert!(
                reason.contains("written path for 'cp' contains unresolvable variable '$DEST'"),
                "expected command attribution 'cp' and variable '$DEST', got: {reason}"
            );
            assert!(
                reason.contains("- intra-command assignments: None"),
                "expected intra-command check in: {reason}"
            );
            assert!(
                reason.contains("- intra-line preceding assignments: None"),
                "expected preceding assignments check in: {reason}"
            );
            assert!(
                reason.contains("- environment variables: None"),
                "expected environment check in: {reason}"
            );
        }
        other => panic!("expected Ask on unresolved_path, got: {other:?}"),
    }
}

#[test]
fn multi_command_chain_attributes_specific_acting_command() {
    let cfg = realistic_config();
    // mkdir succeeds (it writes /tmp/d), while cp trips the rule with $DEST
    let decision = decide_command_at(
        &cfg,
        "bash",
        r#"mkdir -p /tmp/d && cp a "$DEST""#,
        Some(HOME),
        None,
        Some("C:/scratch"),
    );

    match decision {
        Decision::Ask(reason) => {
            assert!(reason.contains("unresolved_path"), "got: {reason}");
            assert!(
                reason.contains("written path for 'cp'"),
                "must attribute 'cp', not 'mkdir', got: {reason}"
            );
            assert!(
                !reason.contains("written path for 'mkdir'"),
                "must not attribute 'mkdir', got: {reason}"
            );
        }
        other => panic!("expected Ask on unresolved_path, got: {other:?}"),
    }
}

#[test]
fn redirect_target_attributes_owning_command() {
    let cfg = realistic_config();
    let decision = decide_command_at(
        &cfg,
        "bash",
        r#"echo "data" > "$OUT""#,
        Some(HOME),
        None,
        Some("C:/scratch"),
    );

    match decision {
        Decision::Ask(reason) => {
            assert!(reason.contains("unresolved_path"), "got: {reason}");
            assert!(
                reason.contains("written path for 'echo' contains unresolvable variable '$OUT'"),
                "expected redirect attribution to 'echo', got: {reason}"
            );
            assert!(reason.contains("attempted resolution sources:"), "got: {reason}");
        }
        other => panic!("expected Ask on unresolved_path, got: {other:?}"),
    }
}

#[test]
fn curly_brace_variable_syntax_extracted() {
    let cfg = realistic_config();
    let decision = decide_command_at(
        &cfg,
        "bash",
        r#"touch "${OUTPUT_PATH}/log.txt""#,
        Some(HOME),
        None,
        Some("C:/scratch"),
    );

    match decision {
        Decision::Ask(reason) => {
            assert!(reason.contains("unresolved_path"), "got: {reason}");
            assert!(
                reason.contains("contains unresolvable variable '$OUTPUT_PATH'"),
                "expected '$OUTPUT_PATH' extraction, got: {reason}"
            );
            assert!(
                reason.contains("written path for 'touch'"),
                "expected 'touch' attribution, got: {reason}"
            );
        }
        other => panic!("expected Ask on unresolved_path, got: {other:?}"),
    }
}

#[test]
fn multiple_variables_in_destination_path() {
    let cfg = realistic_config();
    let decision = decide_command_at(
        &cfg,
        "bash",
        r#"cp src "$ROOT/$SUB/file.txt""#,
        Some(HOME),
        None,
        Some("C:/scratch"),
    );

    match decision {
        Decision::Ask(reason) => {
            assert!(reason.contains("unresolved_path"), "got: {reason}");
            assert!(
                reason.contains("contains unresolvable variable '$ROOT, $SUB'"),
                "expected both variables to be reported, got: {reason}"
            );
            assert!(reason.contains("written path for 'cp'"), "got: {reason}");
        }
        other => panic!("expected Ask on unresolved_path, got: {other:?}"),
    }
}
