//! Tests for WSL launcher and `bash.exe` normalization (M2.135).
mod common;

use common::realistic_config;
use vouch::guards::{base_name, in_effect};
use vouch::protocol::Decision;

#[test]
fn test_bash_exe_normalization_to_logical_bash() {
    // Normalization parity per CLAUDE.md §8:
    assert_eq!(base_name("bash.exe"), "bash");
    assert_eq!(base_name("BASH.EXE"), "bash");
    assert_eq!(base_name("C:/Windows/System32/bash.exe"), "bash");
    assert_eq!(base_name("wsl.exe"), "wsl");
    assert_eq!(base_name("WSL.EXE"), "wsl");
    assert_eq!(base_name("C:/Windows/System32/wsl.exe"), "wsl");
}

#[test]
fn test_bash_exe_invocations_adjudication() {
    let cfg = realistic_config();

    // bash.exe -c "ls -la" resolves through bash wrapper and allows safe commands
    let res1 = vouch::engine::decide_command_at(
        &cfg,
        "bash",
        r#"bash.exe -c "ls -la""#,
        None,
        None,
        Some("C:/Users/dev"),
    );
    assert!(
        matches!(res1, Decision::Allow(_)),
        "expected bash.exe to resolve through POSIX shell wrapper, got {res1:?}"
    );

    // bash.exe -c "rm -rf /" evaluates the inner command and catches guards
    let res2 = vouch::engine::decide_command_at(
        &cfg,
        "bash",
        r#"bash.exe -c "rm -rf /""#,
        None,
        None,
        Some("C:/Users/dev"),
    );
    match res2 {
        Decision::Ask(reason) => {
            assert!(
                reason.contains("delete_recursive"),
                "expected delete_recursive guard in bash.exe snippet, got: {reason}"
            );
        }
        other => panic!("expected Ask on delete_recursive, got {other:?}"),
    }
}

#[test]
fn test_wsl_exe_wrapper_adjudication() {
    let cfg = realistic_config();

    // wsl.exe ls -la routes through the wsl rest wrapper
    let res = vouch::engine::decide_command_at(
        &cfg,
        "bash",
        "wsl.exe ls -la",
        None,
        None,
        Some("C:/Users/dev"),
    );
    assert!(
        matches!(res, Decision::Allow(_)),
        "expected wsl.exe to route through wsl rest-wrapper, got {res:?}"
    );
}

#[test]
fn test_knowledge_entry_reachability() {
    let kb = in_effect();

    // Ensure all program match names survive base_name reachability checks
    for prog in &kb.program {
        for name in &prog.match_names {
            let m = name.to_lowercase();
            assert_eq!(
                m,
                base_name(&m),
                "match name {name:?} must match its base_name form"
            );
        }
    }
}
