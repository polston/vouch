//! Integration tests for argument-scoped program recognition (`exact_args`).

use vouch::config::{self, Config};
use vouch::engine::decide_command_at_with_knowledge;
use vouch::guards::{self, Knowledge};
use vouch::knowledge;
use vouch::protocol::Decision;

fn parse_cfg(extra_toml: &str) -> Config {
    let base = r#"
[lang.bash]
default = "allow"
[lang.bash.constructs]
unmodeled_command = "ask"
evaluated_input = "ask"

[guards]
delete_recursive = "ask"
in_place_edit = "ask"

[write]
allow_paths = ["/tmp/**"]
"#;
    let combined = format!("{base}\n{extra_toml}");
    config::load(&combined).expect("valid test config")
}

fn load_merged(shipped: &str, own: &str) -> Knowledge {
    knowledge::validate_text(shipped).expect("shipped knowledge validates");
    knowledge::validate_text(own).expect("own knowledge validates");
    let s = guards::load(shipped).expect("shipped parses");
    let o = guards::load(own).expect("own parses");
    knowledge::merge(s, o)
}

#[test]
fn exact_args_recognizes_listed_vectors_and_rejects_unlisted_variants() {
    let shipped = r#"
version = 17
"#;
    let own = r#"
[[program]]
match = ["open"]
value_options = ["-a"]
exact_args = [["-a", "Calendar"], ["-a", "Preview"]]
case_sensitive_flags = true
"#;
    let kb = load_merged(shipped, own);
    let cfg = parse_cfg("");

    // Listed exact vectors allow
    let d1 = decide_command_at_with_knowledge(
        &cfg,
        "bash",
        "open -a Calendar",
        Some("C:/Users/dev"),
        None,
        Some("C:/Users/dev"),
        Some(&kb),
    );
    assert!(matches!(d1, Decision::Allow(_)), "expected Allow, got {d1:?}");

    let d2 = decide_command_at_with_knowledge(
        &cfg,
        "bash",
        "open '-a' \"Preview\"",
        Some("C:/Users/dev"),
        None,
        Some("C:/Users/dev"),
        Some(&kb),
    );
    assert!(matches!(d2, Decision::Allow(_)), "expected Allow on quoted match, got {d2:?}");

    // Unlisted app asks as unmodeled_command
    let d3 = decide_command_at_with_knowledge(
        &cfg,
        "bash",
        "open -a Terminal",
        Some("C:/Users/dev"),
        None,
        Some("C:/Users/dev"),
        Some(&kb),
    );
    match d3 {
        Decision::Ask(reason) => assert!(
            reason.contains("unmodeled_command"),
            "expected unmodeled_command ask, got: {reason}"
        ),
        other => panic!("expected Ask, got {other:?}"),
    }

    // Bare invocation or extra trailing argument asks as unmodeled_command
    for cmd in [
        "open",
        "open https://example.com",
        "open -a Calendar extra",
        "open -A Calendar",
    ] {
        let d = decide_command_at_with_knowledge(
            &cfg,
            "bash",
            cmd,
            Some("C:/Users/dev"),
            None,
            Some("C:/Users/dev"),
            Some(&kb),
        );
        assert!(
            matches!(d, Decision::Ask(_)),
            "expected Ask for `{cmd}`, got {d:?}"
        );
    }
}

#[test]
fn exact_args_fails_closed_on_unreadable_tokens_and_appending_wrappers() {
    let shipped = r#"
version = 17

[[program]]
match = ["xargs"]
wraps = "rest"
args_from_input = true
value_options = ["-n", "-L", "-I"]
no_value_options = ["-0", "-r"]
case_sensitive_flags = true
"#;
    let own = r#"
[[program]]
match = ["open"]
value_options = ["-a"]
exact_args = [["-a", "Calendar"]]
case_sensitive_flags = true
"#;
    let kb = load_merged(shipped, own);
    let cfg = parse_cfg("");

    // Unbound shell variable in argument position fails closed
    let d_var = decide_command_at_with_knowledge(
        &cfg,
        "bash",
        "open -a \"$UNSET_TARGET_APP\"",
        Some("C:/Users/dev"),
        None,
        Some("C:/Users/dev"),
        Some(&kb),
    );
    assert!(
        matches!(d_var, Decision::Ask(_)),
        "expected Ask on unbound variable, got {d_var:?}"
    );

    // Under xargs (args_from_input = true), the recorded args are not complete
    let d_xargs = decide_command_at_with_knowledge(
        &cfg,
        "bash",
        "xargs open -a Calendar",
        Some("C:/Users/dev"),
        None,
        Some("C:/Users/dev"),
        Some(&kb),
    );
    assert!(
        matches!(d_xargs, Decision::Ask(_)),
        "expected Ask under xargs args_from_input wrapper, got {d_xargs:?}"
    );
}

#[test]
fn exact_args_preserves_guards_and_write_checks_and_merges_additively() {
    let shipped = r#"
version = 17

[[program]]
match = ["mytool"]
exact_args = [["--mode", "safe"]]
writes = "named"
write_flags = ["-o"]
value_options = ["--mode", "-o"]
case_sensitive_flags = true

[[program.rule]]
guard = "in_place_edit"
source = "declared: mutates state when --mutate is passed"
any_flag = ["--mutate"]
"#;
    let own = r#"
[[program]]
match = ["mytool"]
exact_args = [["--mode", "mutate", "--mutate"], ["--mode", "write", "-o", "/etc/outside"]]
value_options = ["--mode", "-o"]
no_value_options = ["--mutate"]
case_sensitive_flags = true
"#;
    let kb = load_merged(shipped, own);
    let cfg = parse_cfg("");

    // Shipped exact_args vector still recognized after overlay union
    let d_safe = decide_command_at_with_knowledge(
        &cfg,
        "bash",
        "mytool --mode safe",
        Some("C:/Users/dev"),
        None,
        Some("C:/Users/dev"),
        Some(&kb),
    );
    assert!(matches!(d_safe, Decision::Allow(_)), "got {d_safe:?}");

    // Overlay exact_args vector recognized, and guard still fires!
    let d_guard = decide_command_at_with_knowledge(
        &cfg,
        "bash",
        "mytool --mode mutate --mutate",
        Some("C:/Users/dev"),
        None,
        Some("C:/Users/dev"),
        Some(&kb),
    );
    match d_guard {
        Decision::Ask(reason) => assert!(
            reason.contains("in_place_edit"),
            "expected in_place_edit guard, got: {reason}"
        ),
        other => panic!("expected Ask on guard, got {other:?}"),
    }

    // Write check still fires on write outside allow_paths!
    let d_write = decide_command_at_with_knowledge(
        &cfg,
        "bash",
        "mytool --mode write -o /etc/outside",
        Some("C:/Users/dev"),
        None,
        Some("C:/Users/dev"),
        Some(&kb),
    );
    match d_write {
        Decision::Ask(reason) => assert!(
            reason.contains("write.allow_paths"),
            "expected write.allow_paths ask, got: {reason}"
        ),
        other => panic!("expected Ask on write check, got {other:?}"),
    }
}

#[test]
fn exact_args_schema_validation_rejects_empty_and_python_entries() {
    let empty_outer = r#"
[[program]]
match = ["open"]
exact_args = []
"#;
    assert!(knowledge::validate_text(empty_outer).is_err());

    let empty_inner = r#"
[[program]]
match = ["open"]
exact_args = [[]]
"#;
    assert!(knowledge::validate_text(empty_inner).is_err());

    let empty_token = r#"
[[program]]
match = ["open"]
exact_args = [["-a", ""]]
"#;
    assert!(knowledge::validate_text(empty_token).is_err());

    let python_entry = r#"
[[program]]
match = ["python:os.open"]
exact_args = [["a"]]
"#;
    assert!(knowledge::validate_text(python_entry).is_err());
}
