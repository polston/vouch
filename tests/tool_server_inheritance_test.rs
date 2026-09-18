mod common;

use common::{kb_with, realistic_config};
use vouch::protocol::{parse_input, Decision};
use vouch::route::decide;

const HOME: &str = "C:/Users/dev";

#[test]
fn bare_exact_tool_inherits_parent_server_snippet_and_halts_on_delete_recursive() {
    // Parent server declares bash snippet field "script".
    // Exact tool mcp__runner__exec declares NO snippet fields of its own.
    let kb = kb_with(
        r#"
[[tool]]
server = "mcp__runner"
source = "runner server tools"

[[tool.snippet]]
field = "script"
language = "bash"

[[tool]]
match = ["mcp__runner__exec"]
source = "operator annotation without own declarations"
"#,
    );
    let cfg = realistic_config();

    let input = parse_input(
        r#"{"session_id":"s","cwd":"C:/Users/dev","tool_name":"mcp__runner__exec","tool_input":{"script":"rm -rf /"}}"#,
    )
    .expect("parses");

    let outcome = decide(&cfg, &kb, HOME, &input);
    match outcome.decision {
        Decision::Ask(reason) => {
            assert!(
                reason.contains("delete_recursive"),
                "bare exact tool must inherit snippet inspection and halt on delete_recursive, got: {reason}"
            );
        }
        other => panic!("expected Ask on delete_recursive, got: {other:?}"),
    }
}

#[test]
fn bare_exact_tool_inherits_parent_server_snippet_and_allows_safe_command() {
    let kb = kb_with(
        r#"
[[tool]]
server = "mcp__runner"
source = "runner server tools"

[[tool.snippet]]
field = "script"
language = "bash"

[[tool]]
match = ["mcp__runner__exec"]
source = "operator annotation"
"#,
    );
    let cfg = realistic_config();

    let input = parse_input(
        r#"{"session_id":"s","cwd":"C:/Users/dev","tool_name":"mcp__runner__exec","tool_input":{"script":"ls -la"}}"#,
    )
    .expect("parses");

    let outcome = decide(&cfg, &kb, HOME, &input);
    assert!(
        matches!(outcome.decision, Decision::Allow(_)),
        "safe command in inherited snippet should allow, got: {:?}",
        outcome.decision
    );
}

#[test]
fn exact_tool_with_own_declarations_overrides_server_declarations() {
    // Server declares snippet on "script", but exact tool declares write_path_field on "dest"
    let kb = kb_with(
        r#"
[[tool]]
server = "mcp__custom"
source = "custom server"

[[tool.snippet]]
field = "script"
language = "bash"

[[tool]]
match = ["mcp__custom__write"]
write_path_field = "dest"
source = "custom writer"
"#,
    );
    let cfg = realistic_config();

    // Passing "script": "rm -rf /" to mcp__custom__write should NOT trigger delete_recursive
    // because mcp__custom__write declares its own write_path_field and overrides server snippet
    let input = parse_input(
        r#"{"session_id":"s","cwd":"C:/Users/dev","tool_name":"mcp__custom__write","tool_input":{"dest":"/tmp/safe.txt","script":"rm -rf /"}}"#,
    )
    .expect("parses");

    let outcome = decide(&cfg, &kb, HOME, &input);
    // Dest is under /tmp (allowed in realistic_config), so write allows and snippet is not parsed
    assert!(
        matches!(outcome.decision, Decision::Allow(_)),
        "exact tool with its own declarations overrides server snippet, got: {:?}",
        outcome.decision
    );
}

#[test]
fn unrelated_server_tool_does_not_inherit() {
    let kb = kb_with(
        r#"
[[tool]]
server = "mcp__runner"
source = "runner server"

[[tool.snippet]]
field = "script"
language = "bash"
"#,
    );
    let cfg = realistic_config();

    // mcp__other__exec belongs to mcp__other, not mcp__runner
    let input = parse_input(
        r#"{"session_id":"s","cwd":"C:/Users/dev","tool_name":"mcp__other__exec","tool_input":{"script":"rm -rf /"}}"#,
    )
    .expect("parses");

    let outcome = decide(&cfg, &kb, HOME, &input);
    // Undeclared tool asks on unrecognised tool, not delete_recursive
    match outcome.decision {
        Decision::Ask(reason) => {
            assert!(
                reason.contains("mcp__other__exec") || reason.contains("unrecognised") || reason.contains("tools.default"),
                "unrelated tool should not inherit snippet inspection, got: {reason}"
            );
            assert!(
                !reason.contains("delete_recursive"),
                "unrelated tool must not trigger delete_recursive"
            );
        }
        other => panic!("expected Ask for unrecognised tool, got: {other:?}"),
    }
}
