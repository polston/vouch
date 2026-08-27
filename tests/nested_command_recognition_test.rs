//! Exact nested command-path recognition and the four shipped Codex claims
//! (M2.197).

mod common;

use vouch::config::load as load_config;
use vouch::guards::{load, recognises};
use vouch::knowledge::{merge, validate_text};
use vouch::protocol::Decision;

const HOME: &str = "C:/Users/dev";

fn recognise_in(lang: &str, args: &[&str]) -> bool {
    recognises(
        &common::shipped_kb(),
        &common::cmd("codex", args),
        lang,
        true,
    )
}

fn recognise(args: &[&str]) -> bool {
    recognise_in("bash", args)
}

fn config(guards: &str) -> vouch::config::Config {
    load_config(&format!(
        "version = 1\n[lang.bash]\ndefault = \"allow\"\n\
         [lang.bash.constructs]\nunmodeled_command = \"ask\"\n\
         [write]\ndefault = \"allow\"\n{guards}"
    ))
    .expect("config parses")
}

fn decide_in(lang: &str, command: &str, guards: &str) -> Decision {
    vouch::engine::decide_command_in(&config(guards), lang, command, Some(HOME), None)
}

fn decide(command: &str, guards: &str) -> Decision {
    decide_in("bash", command, guards)
}

#[test]
fn shipped_knowledge_recognises_exactly_the_four_named_codex_paths() {
    for lang in ["bash", "powershell"] {
        for args in [
            ["mcp", "get"],
            ["mcp", "remove"],
            ["plugin", "list"],
            ["plugin", "remove"],
        ] {
            assert!(
                recognise_in(lang, &args),
                "codex {} is shipped for {lang}",
                args.join(" ")
            );
        }
    }

    for args in [
        ["mcp", "add"],
        ["mcp", "login"],
        ["plugin", "add"],
        ["plugin", "marketplace"],
    ] {
        assert!(
            !recognise(&args),
            "unlisted sibling codex {} must remain unrecognised",
            args.join(" ")
        );
    }
}

#[test]
fn declared_value_flags_can_precede_or_separate_path_words() {
    assert!(recognise(&[
        "-c", "x=y", "mcp", "--config", "a=b", "get", "fixture"
    ]));
    assert!(recognise(&[
        "--enable=plugins",
        "plugin",
        "--disable",
        "other",
        "list"
    ]));
}

#[test]
fn uncertainty_before_a_complete_path_grants_nothing() {
    assert!(!recognise(&["mcp"]), "an incomplete path grants nothing");
    assert!(!recognise(&["--unknown", "value", "plugin", "list"]));
    assert!(!recognise(&["plugin", "--unknown", "list"]));
    assert!(
        !recognise(&["--Config", "value", "plugin", "list"]),
        "the shipped Unix-style flag vocabulary is case-sensitive"
    );
    assert!(
        !recognise(&["--config"]),
        "a missing value cannot locate a path"
    );

    let kb = common::shipped_kb();
    let mut unread = common::cmd("codex", &["mcp", "get"]);
    unread.unread_args.insert(1);
    assert!(
        !recognises(&kb, &unread, "bash", true),
        "an unread required path word must not recognise"
    );
}

#[test]
fn operands_and_flags_after_a_complete_path_do_not_change_its_identity() {
    assert!(recognise(&["mcp", "get", "fixture", "--json"]));
    assert!(recognise(&["plugin", "list", "--available", "--json"]));
}

#[test]
fn shipped_codex_effects_are_separate_and_default_safe() {
    match decide("codex plugin list", "") {
        Decision::Ask(reason) => assert!(reason.contains("local_state_write"), "{reason}"),
        other => {
            panic!("plugin list initializes local state and must ask by default, got {other:?}")
        }
    }

    match decide("codex mcp get fixture", "") {
        Decision::Ask(reason) => assert!(reason.contains("confidential_output"), "{reason}"),
        other => panic!("mcp get must ask on confidential output, got {other:?}"),
    }
    for command in ["codex mcp remove fixture", "codex plugin remove fixture"] {
        match decide(command, "") {
            Decision::Ask(reason) => assert!(reason.contains("in_place_edit"), "{reason}"),
            other => panic!("{command} must ask on mutation, got {other:?}"),
        }
    }
    match decide("codex plugin add fixture", "") {
        Decision::Ask(reason) => assert!(reason.contains("unmodeled_command"), "{reason}"),
        other => panic!("an unknown sibling must remain unmodeled, got {other:?}"),
    }
}

#[test]
fn shipped_codex_effects_are_equally_safe_in_powershell() {
    for (command, guard) in [
        ("codex plugin list", "local_state_write"),
        ("codex mcp get fixture", "confidential_output"),
        ("codex mcp remove fixture", "in_place_edit"),
        ("codex plugin remove fixture", "in_place_edit"),
    ] {
        match decide_in("powershell", command, "") {
            Decision::Ask(reason) => assert!(reason.contains(guard), "{command}: {reason}"),
            other => panic!("{command} must ask on {guard} in PowerShell, got {other:?}"),
        }
    }
}

#[test]
fn explicit_guard_actions_remain_the_off_switch() {
    let allow = "[guards]\nconfidential_output = \"allow\"\nin_place_edit = \"allow\"\n\
                 local_state_write = \"allow\"\n";
    for command in [
        "codex plugin list",
        "codex mcp get fixture",
        "codex mcp remove fixture",
        "codex plugin remove fixture",
    ] {
        assert!(
            matches!(decide(command, allow), Decision::Allow(_)),
            "{command}"
        );
    }

    match decide(
        "codex mcp get fixture",
        "[guards]\nconfidential_output = \"deny\"\nlocal_state_write = \"allow\"\n",
    ) {
        Decision::Deny(reason) => assert!(reason.contains("confidential_output"), "{reason}"),
        other => panic!("an explicit deny must deny, got {other:?}"),
    }

    match decide(
        "codex plugin list",
        "[guards]\nlocal_state_write = \"deny\"\n",
    ) {
        Decision::Deny(reason) => assert!(reason.contains("local_state_write"), "{reason}"),
        other => panic!("the list operation's own guard must be configurable, got {other:?}"),
    }
}

#[test]
fn path_scope_validation_refuses_empty_paths_and_inert_empty_scopes() {
    for text in [
        "[[program]]\nmatch = [\"tool\"]\nsubcommand_paths = [[]]\n",
        "[[program]]\nmatch = [\"tool\"]\nsubcommand_paths = [[\"group\", \"\"]]\n",
        "[[program]]\nmatch = [\"tool\"]\nsubcommand_paths = []\n",
        "[[program]]\nmatch = [\"tool\"]\nsubcommands = []\nsubcommand_paths = []\n",
    ] {
        assert!(validate_text(text).is_err(), "must refuse: {text}");
    }

    assert!(validate_text(
        "[[program]]\nmatch = [\"tool\"]\nsubcommand_paths = []\n\
         case_sensitive_flags = true\nstandalone_flags = [\"--version\"]\n"
    )
    .is_ok());
}

#[test]
fn overlay_paths_union_and_never_narrow_whole_program_coverage() {
    let base =
        load("[[program]]\nmatch = [\"tool\"]\nsubcommand_paths = [[\"group\", \"list\"]]\n")
            .unwrap();
    let own = load(
        "[[program]]\nmatch = [\"tool\"]\nsubcommands = [\"status\"]\n\
         subcommand_paths = [[\"group\", \"remove\"]]\n",
    )
    .unwrap();
    let merged = merge(base, own);
    for args in [["group", "list"], ["group", "remove"]] {
        assert!(recognises(
            &merged,
            &common::cmd("tool", &args),
            "bash",
            true
        ));
    }
    assert!(recognises(
        &merged,
        &common::cmd("tool", &["status"]),
        "bash",
        true
    ));
    assert!(!recognises(
        &merged,
        &common::cmd("tool", &["group", "other"]),
        "bash",
        true
    ));

    let whole = load("[[program]]\nmatch = [\"wide\"]\n").unwrap();
    let attempted_narrow =
        load("[[program]]\nmatch = [\"wide\"]\nsubcommand_paths = [[\"group\", \"list\"]]\n")
            .unwrap();
    let merged = merge(whole, attempted_narrow);
    assert!(recognises(
        &merged,
        &common::cmd("wide", &["anything", "else"]),
        "bash",
        true
    ));
}

#[test]
fn all_subcommands_explicitly_widens_both_scope_kinds() {
    let base = load(
        "[[program]]\nmatch = [\"tool\"]\nsubcommands = [\"status\"]\n\
         subcommand_paths = [[\"group\", \"list\"]]\n",
    )
    .unwrap();
    let own = load("[[program]]\nmatch = [\"tool\"]\nall_subcommands = true\n").unwrap();
    let merged = merge(base, own);
    let entry = &merged.program[0];
    assert!(entry.subcommands.is_none());
    assert!(entry.subcommand_paths.is_none());
    assert!(recognises(
        &merged,
        &common::cmd("tool", &["anything", "else"]),
        "bash",
        true
    ));
}
