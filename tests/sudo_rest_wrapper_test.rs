//! Tests for curated rest wrapper flag vocabularies (`sudo` and `doas`) (M2.137).
mod common;

use common::realistic_config;
use vouch::flags::{classify, vocab_for, Abbrev, Class};
use vouch::guards::in_effect;
use vouch::protocol::Decision;

#[test]
fn test_sudo_and_doas_entries_distinct() {
    let kb = in_effect();
    let sudo_progs: Vec<_> = kb
        .program
        .iter()
        .filter(|p| p.match_names.iter().any(|m| m == "sudo"))
        .collect();
    assert!(!sudo_progs.is_empty(), "sudo entry must be in knowledge");

    let doas_progs: Vec<_> = kb
        .program
        .iter()
        .filter(|p| p.match_names.iter().any(|m| m == "doas"))
        .collect();
    assert!(!doas_progs.is_empty(), "doas entry must be in knowledge");

    // Must be separate match definitions
    for p in &sudo_progs {
        assert!(!p.match_names.iter().any(|m| m == "doas"), "sudo and doas must not share match entries");
    }
}

#[test]
fn test_sudo_flag_vocabulary_classification() {
    let kb = in_effect();
    let prog = kb
        .program
        .iter()
        .find(|p| p.match_names.iter().any(|m| m == "sudo") && !p.value_options.is_empty())
        .expect("sudo program with vocabulary must be in knowledge");

    let vocab = vocab_for(prog, Abbrev::Refuse);

    // Value options
    assert_eq!(
        classify("-u", &vocab),
        Class::Value {
            flag: "-u".to_string(),
            attached: None,
        }
    );
    assert_eq!(
        classify("--user", &vocab),
        Class::Value {
            flag: "--user".to_string(),
            attached: None,
        }
    );
    assert_eq!(
        classify("-D", &vocab),
        Class::Value {
            flag: "-D".to_string(),
            attached: None,
        }
    );
    assert_eq!(
        classify("--chdir", &vocab),
        Class::Value {
            flag: "--chdir".to_string(),
            attached: None,
        }
    );

    // Boolean switches
    assert_eq!(
        classify("-n", &vocab),
        Class::Bool {
            flag: "-n".to_string(),
        }
    );
    assert_eq!(
        classify("-E", &vocab),
        Class::Bool {
            flag: "-E".to_string(),
        }
    );
    assert_eq!(
        classify("-s", &vocab),
        Class::Bool {
            flag: "-s".to_string(),
        }
    );

    // Run directory flags
    assert!(
        prog.run_dir_flags.iter().any(|f| f == "-D"),
        "sudo must declare -D in run_dir_flags"
    );
    assert!(
        prog.run_dir_flags.iter().any(|f| f == "--chdir"),
        "sudo must declare --chdir in run_dir_flags"
    );
}

#[test]
fn test_doas_flag_vocabulary_classification() {
    let kb = in_effect();
    let prog = kb
        .program
        .iter()
        .find(|p| p.match_names.iter().any(|m| m == "doas") && !p.value_options.is_empty())
        .expect("doas program with vocabulary must be in knowledge");

    let vocab = vocab_for(prog, Abbrev::Refuse);

    assert_eq!(
        classify("-u", &vocab),
        Class::Value {
            flag: "-u".to_string(),
            attached: None,
        }
    );
    assert_eq!(
        classify("-s", &vocab),
        Class::Bool {
            flag: "-s".to_string(),
        }
    );
    assert_eq!(
        classify("-n", &vocab),
        Class::Bool {
            flag: "-n".to_string(),
        }
    );
}

#[test]
fn test_sudo_execution_judgment() {
    let cfg = realistic_config();

    // sudo -u admin ls -la prompts on privilege_escalation guard (not ambiguity)
    let d1 = vouch::engine::decide_command_at(
        &cfg,
        "bash",
        "sudo -u admin ls -la",
        None,
        None,
        Some("C:/Users/dev"),
    );
    match d1 {
        Decision::Ask(reason) => {
            assert!(
                reason.contains("privilege_escalation"),
                "expected privilege_escalation guard, got: {reason}"
            );
        }
        other => panic!("expected Ask on privilege_escalation, got {other:?}"),
    }

    // doas ls prompts on privilege_escalation guard
    let d2 = vouch::engine::decide_command_at(
        &cfg,
        "bash",
        "doas ls",
        None,
        None,
        Some("C:/Users/dev"),
    );
    match d2 {
        Decision::Ask(reason) => {
            assert!(
                reason.contains("privilege_escalation"),
                "expected privilege_escalation guard, got: {reason}"
            );
        }
        other => panic!("expected Ask on privilege_escalation, got {other:?}"),
    }
}
