//! Integration tests for data-driven guard vocabulary declaration in knowledge (M2.64).

mod common;

use common::decision_at;
use vouch::guards::{guard_description, load, Knowledge, KNOWN_GUARDS};

#[test]
fn all_12_known_guards_declared_with_descriptions() {
    let shipped: Knowledge = load(include_str!("../knowledge.toml")).expect("shipped knowledge parses");
    assert!(!shipped.guard.is_empty(), "shipped knowledge must declare guards");

    let declared_names: Vec<&str> = shipped.guard.iter().map(|g| g.name.as_str()).collect();
    for &kg in KNOWN_GUARDS {
        assert!(
            declared_names.contains(&kg),
            "guard {kg:?} must be declared in knowledge.toml"
        );
        let desc = guard_description(kg);
        assert!(
            desc.is_some(),
            "guard {kg:?} must have a registered description"
        );
        let desc_str = desc.unwrap();
        assert!(
            !desc_str.trim().is_empty(),
            "guard {kg:?} description must not be empty"
        );
    }
}

#[test]
fn rule_naming_undeclared_guard_fails_validation() {
    let toml = r#"
version = 17

[[guard]]
name = "delete_recursive"
description = "deletes directories or directory trees recursively"

[[program]]
match = ["badprogram"]
[[program.rule]]
guard = "nonexistent_guard"
always = true
"#;
    let err = vouch::knowledge::validate_text(toml).expect_err("should reject undeclared guard in rule");
    assert!(
        err.contains("names guard \"nonexistent_guard\", which is not declared in [[guard]]"),
        "unexpected error message: {err}"
    );
}

#[test]
fn empty_guard_name_or_description_fails_validation() {
    let empty_name = r#"
version = 17

[[guard]]
name = ""
description = "something"
"#;
    let err = vouch::knowledge::validate_text(empty_name).expect_err("should reject empty name");
    assert!(
        err.contains("[[guard]]: an entry with no `name` describes nothing"),
        "unexpected error: {err}"
    );

    let empty_desc = r#"
version = 17

[[guard]]
name = "some_guard"
description = "   "
"#;
    let err = vouch::knowledge::validate_text(empty_desc).expect_err("should reject empty description");
    assert!(
        err.contains("description must not be empty"),
        "unexpected error: {err}"
    );
}

#[test]
fn config_naming_unknown_guard_fails_validation() {
    let bad_cfg = r#"
version = 1
[guards]
totally_fake_guard = "ask"
"#;
    let err = vouch::config::load(bad_cfg).expect_err("should reject unknown guard in config");
    assert!(
        err.contains("[guards] names 'totally_fake_guard', which is not a known guard"),
        "unexpected error message: {err}"
    );
}

#[test]
fn guard_prompt_explanation_includes_what_that_means() {
    let cfg = vouch::config::load("version = 1\n[lang.bash]\ndefault = \"allow\"\n").unwrap();
    let (verdict, reason) = decision_at(&cfg, "rm -rf /some/path", "/some/path");
    assert_eq!(verdict, "ask");
    assert!(
        reason.contains("vouch stopped on: delete_recursive (guard)"),
        "reason should mention guard: {reason}"
    );
    assert!(
        reason.contains("  what that means: recursively removes files or directory trees"),
        "reason should include declared description: {reason}"
    );
}

#[test]
fn guard_overlay_replaces_or_adds() {
    let base_toml = r#"
version = 17

[[guard]]
name = "delete_recursive"
description = "base description"

[[guard]]
name = "custom_one"
description = "first custom"
"#;
    let mine_toml = r#"
version = 17

[[guard]]
name = "delete_recursive"
description = "overridden description"

[[guard]]
name = "custom_two"
description = "second custom"
"#;
    let base: Knowledge = load(base_toml).expect("base parses");
    let mine: Knowledge = load(mine_toml).expect("mine parses");
    let merged = vouch::knowledge::merge(base, mine);

    let del = merged.guard.iter().find(|g| g.name == "delete_recursive").unwrap();
    assert_eq!(del.description, "overridden description");

    let c1 = merged.guard.iter().find(|g| g.name == "custom_one").unwrap();
    assert_eq!(c1.description, "first custom");

    let c2 = merged.guard.iter().find(|g| g.name == "custom_two").unwrap();
    assert_eq!(c2.description, "second custom");
}
