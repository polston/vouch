mod common;

use common::{realistic_config, t};
use vouch::engine::decide_command_at;
use vouch::protocol::Decision;

const HOME: &str = "C:/Users/dev";

#[test]
fn literal_for_loop_allows_write_to_allowed_path() {
    let cfg = realistic_config();
    let tmp = t("/tmp");
    let cmd = format!(r#"for f in x y; do cp "src/$f.txt" "{tmp}/$f.txt"; done"#);
    let decision = decide_command_at(
        &cfg,
        "bash",
        &cmd,
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
        other => panic!("expected Allow for literal loop write, got: {other:?}"),
    }
}

#[test]
fn literal_brace_for_loop_allows_write() {
    let cfg = realistic_config();
    let tmp = t("/tmp");
    let cmd = format!(r#"for ext in {{a,b}}; do cp "src/test.$ext" "{tmp}/test.$ext"; done"#);
    let decision = decide_command_at(
        &cfg,
        "bash",
        &cmd,
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
        other => panic!("expected Allow for brace literal loop write, got: {other:?}"),
    }
}

#[test]
fn quoted_literal_for_loop_allows_write() {
    let cfg = realistic_config();
    let tmp = t("/tmp");
    let cmd = format!(r#"for f in "file 1" 'file 2'; do cp "src/$f.txt" "{tmp}/$f.txt"; done"#);
    let decision = decide_command_at(
        &cfg,
        "bash",
        &cmd,
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
        other => panic!("expected Allow for quoted literal loop write, got: {other:?}"),
    }
}

#[test]
fn dynamic_for_loop_asks_on_unresolved_path() {
    let cfg = realistic_config();
    let decision = decide_command_at(
        &cfg,
        "bash",
        r#"for f in $(cat list); do cp "src/$f.txt" "/tmp/$f.txt"; done"#,
        Some(HOME),
        None,
        Some("C:/scratch"),
    );

    match decision {
        Decision::Ask(reason) => {
            assert!(
                reason.contains("unresolved_path"),
                "expected unresolved_path for dynamic loop, got: {reason}"
            );
        }
        other => panic!("expected Ask(unresolved_path) for dynamic loop write, got: {other:?}"),
    }
}

#[test]
fn glob_for_loop_asks_on_unresolved_path() {
    let cfg = realistic_config();
    let decision = decide_command_at(
        &cfg,
        "bash",
        r#"for f in *.txt; do cp "src/$f" "/tmp/$f"; done"#,
        Some(HOME),
        None,
        Some("C:/scratch"),
    );

    match decision {
        Decision::Ask(reason) => {
            assert!(
                reason.contains("unresolved_path"),
                "expected unresolved_path for glob loop, got: {reason}"
            );
        }
        other => panic!("expected Ask(unresolved_path) for glob loop write, got: {other:?}"),
    }
}

#[test]
fn variable_for_loop_asks_on_unresolved_path() {
    let cfg = realistic_config();
    let decision = decide_command_at(
        &cfg,
        "bash",
        r#"for f in $ITEMS; do cp "src/$f.txt" "/tmp/$f.txt"; done"#,
        Some(HOME),
        None,
        Some("C:/scratch"),
    );

    match decision {
        Decision::Ask(reason) => {
            assert!(
                reason.contains("unresolved_path"),
                "expected unresolved_path for variable loop, got: {reason}"
            );
        }
        other => panic!("expected Ask(unresolved_path) for variable loop write, got: {other:?}"),
    }
}

#[test]
fn guard_in_literal_loop_asks_delete_recursive() {
    let cfg = realistic_config();
    let decision = decide_command_at(
        &cfg,
        "bash",
        r#"for x in 1 2; do rm -rf /; done"#,
        Some(HOME),
        None,
        Some("C:/scratch"),
    );

    match decision {
        Decision::Ask(reason) => {
            assert!(
                reason.contains("delete_recursive"),
                "expected delete_recursive guard in literal loop, got: {reason}"
            );
        }
        other => panic!("expected Ask(delete_recursive) in literal loop, got: {other:?}"),
    }
}

#[test]
fn guard_in_dynamic_loop_asks_delete_recursive() {
    let cfg = realistic_config();
    let decision = decide_command_at(
        &cfg,
        "bash",
        r#"for x in $(cat list); do rm -rf /; done"#,
        Some(HOME),
        None,
        Some("C:/scratch"),
    );

    match decision {
        Decision::Ask(reason) => {
            assert!(
                reason.contains("delete_recursive"),
                "expected delete_recursive guard in dynamic loop, got: {reason}"
            );
        }
        other => panic!("expected Ask(delete_recursive) in dynamic loop, got: {other:?}"),
    }
}

#[test]
fn loop_variable_does_not_leak_outside_loop() {
    let cfg = realistic_config();
    // Inside the loop, $f is bound to "x".
    // After the loop, the second cp uses $f which must NOT be resolved to "x".
    let decision = decide_command_at(
        &cfg,
        "bash",
        r#"for f in x; do cp "src/$f.txt" "/tmp/$f.txt"; done; cp "src/$f.txt" "/tmp/$f.txt""#,
        Some(HOME),
        None,
        Some("C:/scratch"),
    );

    match decision {
        Decision::Ask(reason) => {
            assert!(
                reason.contains("unresolved_path"),
                "expected unresolved_path for leaked loop variable, got: {reason}"
            );
        }
        other => panic!("expected Ask(unresolved_path) for leaked loop variable, got: {other:?}"),
    }
}

#[test]
fn bounded_literal_loop_cap_at_32() {
    let cfg = realistic_config();
    // 33 elements exceeds the cap of 32, so it falls back to dynamic (unresolvable $f)
    let words = (1..=33).map(|i| i.to_string()).collect::<Vec<_>>().join(" ");
    let cmd = format!(r#"for f in {words}; do cp "src/$f.txt" "/tmp/$f.txt"; done"#);
    let decision = decide_command_at(
        &cfg,
        "bash",
        &cmd,
        Some(HOME),
        None,
        Some("C:/scratch"),
    );

    match decision {
        Decision::Ask(reason) => {
            assert!(
                reason.contains("unresolved_path"),
                "expected unresolved_path when literal count exceeds cap 32, got: {reason}"
            );
        }
        other => panic!("expected Ask(unresolved_path) for loop exceeding cap 32, got: {other:?}"),
    }
}
