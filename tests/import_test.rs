use vouch::import_cc::import;

const CC: &str = r#"
version = "2.0"
[bash]
default = "allow"
dynamic_commands = "allow"
unresolved_commands = "allow"
[bash.constructs]
background = "allow"
subshells = "allow"
heredocs = "allow"
[bash.allow]
commands = ["timeout", "ffmpeg"]
[write.allow]
paths = ["path:$PROJECT_ROOT/**", "path:C:/work/**", "path:C:/c/work/**"]
[edit.allow]
paths = ["path:C:/work/**"]
[powershell]
default = "ask"
[powershell.allow]
commands = ["ls", "cat"]
[tools]
default = "ask"
allow = ["Agent", "Skill"]
"#;

#[test]
fn the_result_is_a_valid_vouch_config() {
    let r = import(CC).unwrap();
    vouch::config::load(&r.config).expect("imported config must load");
}

#[test]
fn path_allowances_carry_over_and_msys_twins_collapse() {
    let r = import(CC).unwrap();
    let c = vouch::config::load(&r.config).unwrap();
    assert!(c.write.allow_paths.iter().any(|p| p.contains("C:/work/**")));
    assert!(
        !c.write.allow_paths.iter().any(|p| p.to_lowercase().starts_with("c:/c/")),
        "MSYS twin should be dropped: {:?}", c.write.allow_paths
    );
    // the path: prefix is cc-allow syntax and should be stripped
    assert!(!c.write.allow_paths.iter().any(|p| p.starts_with("path:")));
}

#[test]
fn one_dynamic_switch_becomes_two_constructs() {
    let r = import(CC).unwrap();
    let c = vouch::config::load(&r.config).unwrap();
    use vouch::config::Action;
    assert_eq!(c.construct_action("bash", "dynamic_command"), Action::Allow);
    assert_eq!(c.construct_action("bash", "dynamic_redirect"), Action::Allow);
}

#[test]
fn construct_names_are_translated_not_copied() {
    let r = import(CC).unwrap();
    let c = vouch::config::load(&r.config).unwrap();
    use vouch::config::Action;
    // cc-allow said "subshells"/"heredocs"; vouch says "subshell"/"heredoc"
    assert_eq!(c.construct_action("bash", "subshell"), Action::Allow);
    assert_eq!(c.construct_action("bash", "heredoc"), Action::Allow);
}

#[test]
fn command_name_allowlists_are_reported_as_dropped_never_silently_lost() {
    let r = import(CC).unwrap();
    let joined = r.notes.join("\n");
    assert!(joined.contains("2 bash command-name allowances NOT imported"), "{joined}");
    assert!(joined.contains("2 powershell command-name allowances NOT imported"), "{joined}");
    assert!(joined.contains("[tools] section (2 entries) NOT imported"), "{joined}");
}

#[test]
fn vouchs_own_files_are_always_protected_even_if_the_source_had_no_such_rule() {
    let r = import(CC).unwrap();
    let c = vouch::config::load(&r.config).unwrap();
    assert!(c.protected.iter().any(|p| p.contains("settings.json")));
    // [review] This used to look for the substring "vouch.toml", which the
    // moved path ("$HOME/.config/vouch/config.toml") no longer contains —
    // "vouch/config.toml" is not "vouch.toml". An operator onboarding through
    // `vouch import` was getting a config that did not protect vouch's own
    // config file; check the path that is actually read now.
    assert!(c.protected.iter().any(|p| p.contains("vouch/config.toml")));
}

#[test]
fn a_malformed_source_is_an_error_not_an_empty_config() {
    assert!(import("[[[not toml").is_err());
}

#[test]
fn a_powershell_name_allowlist_does_not_become_ask_on_everything() {
    // cc-allow paired powershell.default="ask" with 66 trusted program NAMES.
    // vouch does not gate on names, so importing "ask" literally would prompt on
    // every PowerShell command — the exact behaviour being replaced.
    let r = import(CC).unwrap();
    let c = vouch::config::load(&r.config).unwrap();
    assert_eq!(
        c.lang_default("powershell"),
        vouch::config::Action::Allow,
        "importing 'ask' + a name list literally would prompt on everything"
    );
    assert!(
        r.notes.iter().any(|n| n.contains("prompt on every")),
        "the translation must be stated, not silent: {:?}",
        r.notes
    );
}

#[test]
fn the_constructs_cc_allow_could_not_configure_are_set_by_import() {
    let r = import(CC).unwrap();
    let c = vouch::config::load(&r.config).unwrap();
    use vouch::config::Action;
    // the three that actually interrupted the user
    for name in ["type_literal", "call_operator", "keyword_foreach"] {
        assert_eq!(
            c.construct_action("powershell", name),
            Action::Allow,
            "{name} should be allowed after import"
        );
    }
    // but vouch's own defects stay visible
    assert_eq!(c.construct_action("powershell", "parse_failure"), Action::Ask);
}
