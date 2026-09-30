//! Tests for structured tool argument and schema-driven gating ([[tool.rule]]).

mod common;

use common::realistic_config;
use vouch::guards::{load, tool_entry};
use vouch::knowledge::{merge, validate_text};
use vouch::protocol::{parse_input, Decision};
use vouch::route::decide;

const HOME: &str = "C:/Users/dev";

#[test]
fn tool_rule_validation_rejects_empty_field() {
    let toml = r#"
version = 1
[[tool]]
match = ["mcp__db__query"]
source = "database queries"
[[tool.rule]]
field = ""
action = "ask"
when_exact = "drop"
"#;
    let err = validate_text(toml).expect_err("should reject empty field");
    assert!(err.contains("rule field is empty"), "got: {err}");
}

#[test]
fn tool_rule_validation_requires_pattern_or_exact() {
    let toml = r#"
version = 1
[[tool]]
match = ["mcp__db__query"]
source = "database queries"
[[tool.rule]]
field = "sql"
action = "ask"
"#;
    let err = validate_text(toml).expect_err("should require pattern or exact");
    assert!(
        err.contains("must specify at least one of when_pattern or when_exact"),
        "got: {err}"
    );
}

#[test]
fn tool_rule_validation_rejects_invalid_regex() {
    let toml = r#"
version = 1
[[tool]]
match = ["mcp__db__query"]
source = "database queries"
[[tool.rule]]
field = "sql"
action = "ask"
when_pattern = "[unclosed_bracket"
"#;
    let err = validate_text(toml).expect_err("should reject invalid regex");
    assert!(err.contains("not a valid regex"), "got: {err}");
}

#[test]
fn tool_rule_validation_rejects_unknown_guard() {
    let toml = r#"
version = 1
[[tool]]
match = ["mcp__db__query"]
source = "database queries"
[[tool.rule]]
field = "sql"
action = "ask"
when_exact = "drop"
guard = "nonexistent_guard_123"
"#;
    let err = validate_text(toml).expect_err("should reject unknown guard");
    assert!(err.contains("not a recognized guard"), "got: {err}");
}

#[test]
fn tool_rule_overlay_layers_additively() {
    let base = load(
        r#"
version = 1
[[tool]]
match = ["mcp__db__query"]
source = "base tool"
[[tool.rule]]
field = "sql"
action = "ask"
when_pattern = "(?i)drop"
"#,
    )
    .expect("base parses");

    let mine = load(
        r#"
[[tool]]
match = ["mcp__db__query"]
source = "operator tool"
[[tool.rule]]
field = "sql"
action = "deny"
when_pattern = "(?i)truncate"
"#,
    )
    .expect("mine parses");

    let merged = merge(base, mine);
    let entry = tool_entry(&merged, "mcp__db__query").expect("entry exists");
    assert_eq!(entry.rule.len(), 2);
    assert_eq!(entry.rule[0].when_pattern.as_deref(), Some("(?i)drop"));
    assert_eq!(entry.rule[1].when_pattern.as_deref(), Some("(?i)truncate"));
}

#[test]
fn tool_rule_exact_match_fires() {
    let kb = load(
        r#"
version = 1
[[tool]]
match = ["mcp__db__admin"]
source = "db admin"
[[tool.rule]]
field = "operation"
action = "ask"
when_exact = "nuke_database"
reason = "destructive database wipe"
"#,
    )
    .expect("parses");

    let cfg = realistic_config();

    let safe_payload = r#"{
        "session_id": "s",
        "cwd": "C:/Users/dev",
        "tool_name": "mcp__db__admin",
        "tool_input": {
            "operation": "get_status"
        }
    }"#;
    let input = parse_input(safe_payload).unwrap();
    let outcome = decide(&cfg, &kb, HOME, &input);
    assert!(
        matches!(outcome.decision, Decision::Allow(_)),
        "safe exact operation should allow, got: {:?}",
        outcome.decision
    );

    let danger_payload = r#"{
        "session_id": "s",
        "cwd": "C:/Users/dev",
        "tool_name": "mcp__db__admin",
        "tool_input": {
            "operation": "nuke_database"
        }
    }"#;
    let input = parse_input(danger_payload).unwrap();
    let outcome = decide(&cfg, &kb, HOME, &input);
    match outcome.decision {
        Decision::Ask(reason) => {
            assert!(
                reason.contains("destructive database wipe"),
                "reason should include configured text: {reason}"
            );
            assert!(
                reason.contains("to allow this tool from now on"),
                "prompt must name setting that turns it off: {reason}"
            );
        }
        other => panic!("expected ask on nuke_database, got: {other:?}"),
    }
}

#[test]
fn tool_rule_regex_pattern_fires_case_insensitively() {
    let kb = load(
        r#"
version = 1
[[tool]]
match = ["mcp__postgres__execute_query"]
source = "postgres runner"
[[tool.rule]]
field = "query"
action = "ask"
when_pattern = "(?i)^\\s*(drop|delete|truncate)\\b"
guard = "delete_recursive"
"#,
    )
    .expect("parses");

    let cfg = realistic_config();

    let read_query = r#"{
        "session_id": "s",
        "cwd": "C:/Users/dev",
        "tool_name": "mcp__postgres__execute_query",
        "tool_input": {
            "query": "SELECT * FROM users WHERE active = true"
        }
    }"#;
    let input = parse_input(read_query).unwrap();
    let outcome = decide(&cfg, &kb, HOME, &input);
    assert!(
        matches!(outcome.decision, Decision::Allow(_)),
        "SELECT query should allow, got: {:?}",
        outcome.decision
    );

    for destructive_sql in [
        "DROP TABLE customers;",
        "  drop database prod;",
        "DELETE FROM sessions WHERE expired = false;",
        "TRUNCATE users CASCADE;",
    ] {
        let payload = format!(
            r#"{{
                "session_id": "s",
                "cwd": "C:/Users/dev",
                "tool_name": "mcp__postgres__execute_query",
                "tool_input": {{
                    "query": {destructive_sql:?}
                }}
            }}"#
        );
        let input = parse_input(&payload).unwrap();
        let outcome = decide(&cfg, &kb, HOME, &input);
        match outcome.decision {
            Decision::Ask(reason) => {
                assert!(
                    reason.contains("tool rule") || reason.contains("delete_recursive"),
                    "must identify tool rule or guard: {reason}"
                );
            }
            other => panic!("expected ask for '{destructive_sql}', got: {other:?}"),
        }
    }
}

#[test]
fn tool_rule_nested_field_matching() {
    let kb = load(
        r#"
version = 1
[[tool]]
match = ["mcp__cloud__action"]
source = "cloud manager"
[[tool.rule]]
field = "params.danger_level"
action = "ask"
when_exact = "critical"
[[tool.rule]]
field = "items.0.action"
action = "deny"
when_exact = "purge"
"#,
    )
    .expect("parses");

    let cfg = realistic_config();

    // Nested object field matches
    let obj_payload = r#"{
        "session_id": "s",
        "cwd": "C:/Users/dev",
        "tool_name": "mcp__cloud__action",
        "tool_input": {
            "params": {
                "danger_level": "critical",
                "target": "prod-cluster"
            }
        }
    }"#;
    let input = parse_input(obj_payload).unwrap();
    let outcome = decide(&cfg, &kb, HOME, &input);
    assert!(matches!(outcome.decision, Decision::Ask(_)), "got: {:?}", outcome.decision);

    // Array index field matches
    let arr_payload = r#"{
        "session_id": "s",
        "cwd": "C:/Users/dev",
        "tool_name": "mcp__cloud__action",
        "tool_input": {
            "items": [
                { "action": "purge" }
            ]
        }
    }"#;
    let input = parse_input(arr_payload).unwrap();
    let outcome = decide(&cfg, &kb, HOME, &input);
    assert!(matches!(outcome.decision, Decision::Deny(_)), "got: {:?}", outcome.decision);
}

#[test]
fn tool_rule_ranking_deny_beats_ask_beats_allow() {
    let kb = load(
        r#"
version = 1
[[tool]]
match = ["mcp__multi__tool"]
source = "multi rule test"
[[tool.rule]]
field = "op"
action = "allow"
when_pattern = ".*"
[[tool.rule]]
field = "op"
action = "ask"
when_pattern = "dangerous"
[[tool.rule]]
field = "op"
action = "deny"
when_pattern = "fatal"
"#,
    )
    .expect("parses");

    let cfg = realistic_config();

    // Matches allow only
    let p1 = r#"{"session_id":"s","cwd":"C:/Users/dev","tool_name":"mcp__multi__tool","tool_input":{"op":"benign"}}"#;
    let out1 = decide(&cfg, &kb, HOME, &parse_input(p1).unwrap());
    assert!(matches!(out1.decision, Decision::Allow(_)));

    // Matches allow and ask -> ask wins
    let p2 = r#"{"session_id":"s","cwd":"C:/Users/dev","tool_name":"mcp__multi__tool","tool_input":{"op":"dangerous_action"}}"#;
    let out2 = decide(&cfg, &kb, HOME, &parse_input(p2).unwrap());
    assert!(matches!(out2.decision, Decision::Ask(_)));

    // Matches allow, ask, and deny -> deny wins
    let p3 = r#"{"session_id":"s","cwd":"C:/Users/dev","tool_name":"mcp__multi__tool","tool_input":{"op":"fatal_dangerous"}}"#;
    let out3 = decide(&cfg, &kb, HOME, &parse_input(p3).unwrap());
    assert!(matches!(out3.decision, Decision::Deny(_)));
}
