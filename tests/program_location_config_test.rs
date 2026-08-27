use vouch::config;

fn rule(under: &str, names: &str) -> String {
    format!(
        "[[run.trust_program]]\nunder = [{under}]\nname_patterns = [{names}]\n"
    )
}

#[test]
fn a_program_location_rule_loads_and_absence_defaults_to_none() {
    let empty = config::load("version = 1").unwrap();
    assert!(empty.run.trust_program.is_empty());

    let cfg = config::load(&rule(
        r#""$PROJECT_ROOT/target/release/**""#,
        r#""probe", "probe-*""#,
    ))
    .unwrap();
    assert_eq!(cfg.run.trust_program.len(), 1);
    assert_eq!(
        cfg.run.trust_program[0].under,
        vec!["$PROJECT_ROOT/target/release/**"]
    );
    assert_eq!(
        cfg.run.trust_program[0].name_patterns,
        vec!["probe", "probe-*"]
    );
}

#[test]
fn exact_and_terminal_prefix_patterns_match_only_the_written_convention() {
    assert!(config::program_name_pattern_matches("probe", "probe"));
    assert!(!config::program_name_pattern_matches("probe", "probe-a"));
    assert!(config::program_name_pattern_matches("probe-*", "probe-a1"));
    assert!(config::program_name_pattern_matches("probe-*", "probe-"));
    assert!(!config::program_name_pattern_matches("probe-*", "other-probe-a1"));
}

#[test]
fn name_pattern_case_follows_the_platforms_path_equality() {
    let hit = config::program_name_pattern_matches("Probe-*", "probe-a1");
    if cfg!(any(windows, target_os = "macos")) {
        assert!(hit);
    } else {
        assert!(!hit);
    }
}

#[test]
fn the_json_schema_exposes_the_new_table_and_both_required_lists() {
    let schema = serde_json::to_value(config::json_schema()).unwrap();
    let text = serde_json::to_string(&schema).unwrap();
    assert!(text.contains("trust_program"), "{text}");
    assert!(text.contains("ProgramLocationTrust"), "{text}");
    assert!(text.contains("name_patterns"), "{text}");
    let def = &schema["$defs"]["ProgramLocationTrust"];
    let required = def["required"].as_array().unwrap();
    assert!(required.iter().any(|v| v == "under"));
    assert!(required.iter().any(|v| v == "name_patterns"));
}

#[test]
fn empty_lists_and_empty_members_refuse_with_the_entry_and_key() {
    for (text, key) in [
        (rule("", r#""probe-*""#), "under"),
        (rule(r#""C:/build/**""#, ""), "name_patterns"),
        (rule(r#""""#, r#""probe-*""#), "under"),
        (rule(r#""C:/build/**""#, r#""""#), "name_patterns"),
    ] {
        let e = config::load(&text).unwrap_err();
        assert!(e.contains("[[run.trust_program]] #1"), "{e}");
        assert!(e.contains(key), "{e}");
    }
}

#[test]
fn under_accepts_only_exact_paths_or_one_trailing_tree_glob() {
    for good in ["C:/build", "C:/build/**", "$PROJECT_ROOT/target/**", "~/build/**"] {
        config::load(&rule(&format!(r#""{good}""#), r#""probe-*""#)).unwrap();
    }
    for bad in ["C:/bu*ild", "C:/build/*", "C:/build/**/deps", "C:/build?", "C:/[ab]"] {
        let e = config::load(&rule(&format!(r#""{bad}""#), r#""probe-*""#)).unwrap_err();
        assert!(e.contains("under") && e.contains(bad), "{e}");
    }
}

#[test]
fn name_patterns_refuse_every_shape_outside_exact_or_literal_prefix() {
    for bad in [
        "*",
        "pro*be",
        "probe**",
        "probe-*-x",
        "probe?",
        "probe[ab]",
        "dir/probe",
        r"dir\probe",
        "probe name",
        "$PROBE",
        "'probe'",
        "probe.exe",
        "probe.exe*",
    ] {
        let e = config::load(&rule(r#""C:/build/**""#, &format!(r#""{bad}""#))).unwrap_err();
        assert!(e.contains("name_patterns") && e.contains(bad), "{e}");
    }
}

#[test]
fn duplicate_locations_patterns_and_rule_pairs_refuse() {
    let cases = [
        rule(r#""C:/build/**", "C:\\build\\**""#, r#""probe-*""#),
        rule(r#""C:/build/**""#, r#""probe-*", "probe-*""#),
        format!(
            "{}{}",
            rule(r#""C:/build/**""#, r#""probe-*""#),
            rule(r#""C:\\build\\**""#, r#""probe-*""#)
        ),
    ];
    for text in cases {
        let e = config::load(&text).unwrap_err();
        assert!(e.contains("duplicate"), "{e}");
    }
}

#[test]
fn two_rules_with_distinct_pairs_are_allowed() {
    let cfg = config::load(&format!(
        "{}{}",
        rule(r#""C:/build-a/**""#, r#""probe-*""#),
        rule(r#""C:/build-b/**""#, r#""other-*""#)
    ))
    .unwrap();
    assert_eq!(cfg.run.trust_program.len(), 2);
}
