//! Tests for language override validation in test configuration builder (M2.141(1)).

mod common;

use common::{config_text_with, SUPPORTED_TEST_LANGUAGES};

#[test]
fn test_valid_language_overrides_generate_valid_toml() {
    // Overrides for valid languages should succeed and parse cleanly
    let toml = config_text_with(&[
        ("bash", "dynamic_command", "ask"),
        ("python", "evaluated_input", "ask"),
        ("javascript", "unmodeled_command", "ask"),
        ("awk", "parse_failure", "deny"),
    ]);

    // Validate that the generated TOML parses cleanly under vouch's Config schema
    let cfg = vouch::config::load(&toml);
    assert!(cfg.is_ok(), "generated config text must parse cleanly: {:?}", cfg.err());

    let loaded = cfg.unwrap();
    assert_eq!(loaded.construct_action("bash", "dynamic_command"), vouch::config::Action::Ask);
    assert_eq!(loaded.construct_action("python", "evaluated_input"), vouch::config::Action::Ask);
    assert_eq!(loaded.construct_action("javascript", "unmodeled_command"), vouch::config::Action::Ask);
    assert_eq!(loaded.construct_action("awk", "parse_failure"), vouch::config::Action::Deny);
}

#[test]
#[should_panic(expected = "unrecognized or unsupported language override 'javascrip'")]
fn test_typo_language_override_panics() {
    // Typo in language name must panic immediately rather than silently passing
    let _ = config_text_with(&[("javascrip", "parse_failure", "ask")]);
}

#[test]
#[should_panic(expected = "unrecognized or unsupported language override 'unknown_lang'")]
fn test_unknown_language_override_panics() {
    let _ = config_text_with(&[("unknown_lang", "unmodeled_command", "allow")]);
}

#[test]
fn test_supported_languages_list() {
    assert!(SUPPORTED_TEST_LANGUAGES.contains(&"bash"));
    assert!(SUPPORTED_TEST_LANGUAGES.contains(&"powershell"));
    assert!(SUPPORTED_TEST_LANGUAGES.contains(&"python"));
    assert!(SUPPORTED_TEST_LANGUAGES.contains(&"javascript"));
    assert!(SUPPORTED_TEST_LANGUAGES.contains(&"awk"));
}
