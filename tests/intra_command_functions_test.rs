//! Tests for intra-command function definitions (M2.23).
//!
//! Verifies that shell functions defined within the same compound command
//! or script snippet are recognized as non-external programs rather than
//! unmodeled external binaries tripping `unmodeled_command = "ask"`, while
//! strictly evaluating bodies for destructive guards/writes and preventing
//! subshell leakage.

#[path = "common/mod.rs"]
mod common;

use common::hook_bash_at;
use vouch::shell::parse;

const CFG: &str = r#"
[lang.bash]
default = "allow"

[lang.bash.constructs]
function_def = "allow"
subshell = "allow"
"#;

#[test]
fn syntax_identifies_intra_command_functions() {
    let p = parse("f() { ls -la; }; f").expect("parses");
    assert_eq!(p.commands.len(), 2);
    assert_eq!(p.commands[0].head, "ls");
    assert!(!p.commands[0].is_intra_command_function);
    assert_eq!(p.commands[1].head, "f");
    assert!(p.commands[1].is_intra_command_function);
}

#[test]
fn syntax_isolates_subshell_function_definitions() {
    let p = parse("( f() { echo hi; } ); f").expect("parses");
    assert_eq!(p.commands.len(), 2);
    assert_eq!(p.commands[0].head, "echo");
    assert!(!p.commands[0].is_intra_command_function);
    assert_eq!(p.commands[1].head, "f");
    assert!(!p.commands[1].is_intra_command_function);
}

#[test]
fn syntax_subshell_inherits_outer_function_definitions() {
    let p = parse("f() { echo hi; }; ( f )").expect("parses");
    assert_eq!(p.commands.len(), 2);
    assert_eq!(p.commands[0].head, "echo");
    assert_eq!(p.commands[1].head, "f");
    assert!(p.commands[1].is_intra_command_function);
}

#[test]
fn syntax_pipeline_stages_do_not_leak_functions() {
    let p = parse("f() { echo hi; } | f").expect("parses");
    assert_eq!(p.commands.len(), 2);
    assert_eq!(p.commands[0].head, "echo");
    assert_eq!(p.commands[1].head, "f");
    assert!(!p.commands[1].is_intra_command_function);
}

#[test]
fn syntax_substitution_inherits_outer_function() {
    let p = parse("f() { echo hi; }; x=$(f)").expect("parses");
    let f_call = p.commands.iter().find(|c| c.head == "f").expect("f found");
    assert!(f_call.is_intra_command_function);
}

#[test]
fn hook_allows_intra_command_function() {
    let (v, r) = hook_bash_at("icf-allow", "", CFG, "/home", "f() { ls -la; }; f");
    assert_eq!(v, "allow", "expected allow, got reason: {r}");
}

#[test]
fn hook_allows_multi_statement_intra_command_function() {
    let (v, r) = hook_bash_at("icf-multi", "", CFG, "/home", "helper() { git status; echo done; }; helper");
    assert_eq!(v, "allow", "expected allow, got reason: {r}");
}

#[test]
fn hook_allows_intra_command_function_with_args() {
    let (v, r) = hook_bash_at("icf-args", "", CFG, "/home", "f() { echo \"$1\"; }; f \"hello\"");
    assert_eq!(v, "allow", "expected allow, got reason: {r}");
}

#[test]
fn hook_asks_on_destructive_command_inside_function_body() {
    let (v, r) = hook_bash_at("icf-guard", "", CFG, "/home", "f() { rm -rf /; }; f");
    assert_eq!(v, "ask");
    assert!(r.contains("delete_recursive"), "expected delete_recursive guard, got: {r}");
}

#[test]
fn hook_asks_on_unmodeled_command_without_definition() {
    let (v, r) = hook_bash_at("icf-unmodeled", "", CFG, "/home", "unknown_helper");
    assert_eq!(v, "ask");
    assert!(r.contains("unknown_helper"), "expected unmodeled prompt for unknown_helper, got: {r}");
}

#[test]
fn hook_asks_when_function_defined_in_subshell_is_called_outside() {
    let (v, r) = hook_bash_at("icf-subshell-leak", "", CFG, "/home", "( f() { echo hi; } ); f");
    assert_eq!(v, "ask");
    assert!(r.contains("f"), "expected prompt for outer f, got: {r}");
}

#[test]
fn hook_allows_when_outer_function_called_in_subshell() {
    let (v, r) = hook_bash_at("icf-subshell-inherit", "", CFG, "/home", "f() { echo hi; }; ( f )");
    assert_eq!(v, "allow", "expected allow, got reason: {r}");
}
