//! Tests for substitution reader parameter expansion and multi-line heredoc refinement (M2.252).
#[path = "common/mod.rs"]
mod common;

use vouch::engine::decide_command_in;
use vouch::protocol::Decision;
use vouch::shell::substitution_bodies;

fn decide(cmd: &str) -> Decision {
    decide_command_in(&common::realistic_config(), "bash", cmd, Some(common::HOOK_HOME), None)
}

#[test]
fn test_parameter_expansion_pattern_unbalanced_paren() {
    let script = r#"echo $(x=${y%*)}; echo $x)"#;
    let res = substitution_bodies(script);
    assert!(!res.unreadable, "substitution should not be unreadable");
    assert_eq!(res.bodies, vec!["x=${y%*)}; echo $x"]);

    let d = decide(script);
    assert!(
        matches!(d, Decision::Allow(_)),
        "Expected allow for pattern parameter expansion in substitution, got: {:?}",
        d
    );
}

#[test]
fn test_multiline_arithmetic_shift_not_heredoc() {
    // Multi-line arithmetic shift (( 1 << 2 )) must not be treated as heredoc operator
    let script = "echo $(if (( 1 << 2 )); then\necho ok\nfi)";
    let res = substitution_bodies(script);
    assert!(!res.unreadable, "multi-line arithmetic shift should not be unreadable");
    assert_eq!(res.bodies, vec!["if (( 1 << 2 )); then\necho ok\nfi"]);

    let d = decide(script);
    assert!(
        matches!(d, Decision::Allow(_)),
        "Expected allow for multi-line arithmetic shift in substitution, got: {:?}",
        d
    );

    // Single-line arithmetic shift must also evaluate cleanly
    let script_single = "echo $(if (( 1 << 2 )); then echo ok; fi)";
    let res_single = substitution_bodies(script_single);
    assert!(!res_single.unreadable);
    assert_eq!(res_single.bodies, vec!["if (( 1 << 2 )); then echo ok; fi"]);

    let d_single = decide(script_single);
    assert!(
        matches!(d_single, Decision::Allow(_)),
        "Expected allow for single-line arithmetic shift in substitution, got: {:?}",
        d_single
    );
}

#[test]
fn test_genuine_heredoc_in_substitution_preserved() {
    // Genuine heredoc inside command substitution must continue to work
    let script = "echo $(cat <<EOF\nhello world\nEOF\n)";
    let res = substitution_bodies(script);
    assert!(!res.unreadable, "genuine heredoc should not be unreadable");
    assert_eq!(res.bodies, vec!["cat <<EOF\nhello world\nEOF\n"]);

    let d = decide(script);
    assert!(
        matches!(d, Decision::Allow(_)),
        "Expected allow for genuine heredoc in substitution, got: {:?}",
        d
    );
}

#[test]
fn test_non_forking_substitution_parameter_expansion() {
    let script = r#"${ x=${y%*)}; echo $x; }"#;
    let res = substitution_bodies(script);
    assert!(!res.unreadable, "non-forking substitution with parameter expansion should not be unreadable");
    assert_eq!(res.bodies, vec![" x=${y%*)}; echo $x; "]);
}
