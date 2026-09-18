//! Tests for colon-attached slash flags and `runas` wrapper modeling (M2.136).
mod common;

use common::realistic_config;
use vouch::flags::{classify, vocab_for, Abbrev, Class};
use vouch::guards::in_effect;
use vouch::protocol::Decision;

#[test]
fn test_slash_flag_colon_classification() {
    let kb = in_effect();
    let prog = kb
        .program
        .iter()
        .find(|p| p.match_names.iter().any(|m| m == "runas"))
        .expect("runas program must be in knowledge");

    let vocab = vocab_for(prog, Abbrev::Refuse);

    // /user:Administrator should classify as Class::Value with attached "Administrator"
    let c1 = classify("/user:Administrator", &vocab);
    assert_eq!(
        c1,
        Class::Value {
            flag: "/user".to_string(),
            attached: Some("Administrator".to_string()),
        }
    );

    // Case-insensitive matching (/USER:dev)
    let c2 = classify("/USER:dev", &vocab);
    assert_eq!(
        c2,
        Class::Value {
            flag: "/user".to_string(),
            attached: Some("dev".to_string()),
        }
    );

    // No-value boolean flags
    let c3 = classify("/noprofile", &vocab);
    assert_eq!(
        c3,
        Class::Bool {
            flag: "/noprofile".to_string(),
        }
    );

    let c4 = classify("/savecred", &vocab);
    assert_eq!(
        c4,
        Class::Bool {
            flag: "/savecred".to_string(),
        }
    );

    // Non-flag arguments
    let c5 = classify("cmd.exe", &vocab);
    assert_eq!(c5, Class::NotFlag);

    // Slash path with directory separator is not a flag
    let c6 = classify("/mnt/c/work", &vocab);
    assert_eq!(c6, Class::NotFlag);
}

#[test]
fn test_runas_wraps_rest_with_colon_flag() {
    let cfg = realistic_config();

    // runas has privilege_escalation guard (Action::Ask)
    // The wrapped command is correctly located as cmd.exe instead of /user:Administrator
    let res = vouch::engine::decide_command_at(
        &cfg,
        "bash",
        r#"runas /user:Administrator cmd.exe"#,
        None,
        None,
        Some("C:/Users/dev"),
    );
    match res {
        Decision::Ask(reason) => {
            assert!(
                reason.contains("privilege_escalation"),
                "expected privilege_escalation for runas, got: {reason}"
            );
        }
        other => panic!("expected Ask(privilege_escalation), got: {other:?}"),
    }
}

#[test]
fn test_runas_evaluates_wrapped_destructive_command() {
    let cfg = realistic_config();

    // runas /noprofile /user:dev rm -rf /
    // Must trigger delete_recursive from wrapped rm -rf /
    let res = vouch::engine::decide_command_at(
        &cfg,
        "bash",
        r#"runas /noprofile /user:dev rm -rf /"#,
        None,
        None,
        Some("C:/Users/dev"),
    );
    match res {
        Decision::Ask(reason) => {
            assert!(
                reason.contains("delete_recursive") || reason.contains("privilege_escalation"),
                "expected delete_recursive or privilege_escalation, got: {reason}"
            );
        }
        other => panic!("expected Ask, got: {other:?}"),
    }
}

#[test]
fn test_runas_wrapped_command_location() {
    let kb = in_effect();

    let cmd = vouch::syntax::Cmd {
        head: "runas".to_string(),
        args: vec![
            "/noprofile".to_string(),
            "/user:Administrator".to_string(),
            "notepad.exe".to_string(),
            "C:/test.txt".to_string(),
        ],
        unread_args: Default::default(),
        keyword_args: Default::default(),
        callable_args: Default::default(),
        expandable_args: Default::default(),
        chain: None,
        prefix_assigns: Default::default(),
        receiver_origin: vouch::syntax::ValueOrigin::Unknown,
        by_reference: false,
        env_assigns: Default::default(),
        is_intra_command_function: false,
    };

    let ex = vouch::guards::expand_wrappers_with_sources(
        kb,
        &[cmd],
        &[],
        &[vouch::syntax::InputSource::Unknown],
        &[true],
        "bash",
        &|_| 4,
    );

    // Occurrences should contain runas AND the unwrapped notepad.exe
    assert_eq!(ex.occurrences.len(), 2, "expected runas and notepad.exe occurrences");
    assert_eq!(ex.occurrences[0].cmd.head, "runas");
    assert_eq!(ex.occurrences[1].cmd.head, "notepad.exe");
    assert_eq!(ex.occurrences[1].cmd.args, vec!["C:/test.txt"]);
}
