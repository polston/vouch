mod common;

use common::realistic_config_with_construct;
use vouch::config::Action;
use vouch::engine::decide_command_at;
use vouch::protocol::Decision;

const HOME: &str = "C:/Users/dev";

fn unmodeled_cfg() -> vouch::config::Config {
    realistic_config_with_construct("bash", "unmodeled_command", Action::Ask)
}

#[test]
fn unmodeled_prompt_single_unknown_contains_divider_and_off_switch() {
    let cfg = unmodeled_cfg();
    let decision = decide_command_at(
        &cfg,
        "bash",
        "totallyunknowncmdxyz123 arg",
        Some(HOME),
        None,
        Some("C:/scratch"),
    );

    match decision {
        Decision::Ask(reason) => {
            assert!(
                reason.contains("vouch stopped on: unmodeled_command"),
                "expected unmodeled_command header, got: {reason}"
            );
            assert!(
                reason.contains("no description of: totallyunknowncmdxyz123"),
                "expected program name in header: {reason}"
            );
            assert!(
                reason.contains("---"),
                "expected divider line separating explanation and remediation: {reason}"
            );
            assert!(
                reason.contains("use the vouch-trust skill"),
                "expected vouch-trust skill guidance: {reason}"
            );
            assert!(
                reason.contains("lang.bash.constructs.unmodeled_command = \"allow\""),
                "expected exact off-switch setting: {reason}"
            );
        }
        other => panic!("expected Ask(unmodeled_command), got: {other:?}"),
    }
}

#[test]
fn unmodeled_prompt_multi_unknown_deduplicates_and_consolidates_trust_template() {
    let cfg = unmodeled_cfg();
    let decision = decide_command_at(
        &cfg,
        "bash",
        "unknownalpha123 | unknownbeta456",
        Some(HOME),
        None,
        Some("C:/scratch"),
    );

    match decision {
        Decision::Ask(reason) => {
            assert!(
                reason.contains("no description of: unknownalpha123, unknownbeta456"),
                "expected both programs listed in header: {reason}"
            );
            // Single consolidated trust template below divider
            let occurrences_of_trust_skill = reason.matches("use the vouch-trust skill").count();
            assert_eq!(
                occurrences_of_trust_skill, 1,
                "expected exactly one consolidated trust guidance block, got {occurrences_of_trust_skill}: {reason}"
            );
            assert!(
                reason.contains("---"),
                "expected divider line: {reason}"
            );
            assert!(
                reason.contains("lang.bash.constructs.unmodeled_command = \"allow\""),
                "expected off-switch setting: {reason}"
            );
        }
        other => panic!("expected Ask(unmodeled_command) for multi-unknown, got: {other:?}"),
    }
}

#[test]
fn unmodeled_prompt_deduplicates_canonical_path_and_bare_heads() {
    let cfg = unmodeled_cfg();
    // Same program referenced as bare name and path-qualified name
    let decision = decide_command_at(
        &cfg,
        "bash",
        "customtoolxyz && /usr/bin/customtoolxyz",
        Some(HOME),
        None,
        Some("C:/scratch"),
    );

    match decision {
        Decision::Ask(reason) => {
            // Deduplicated: should list customtoolxyz only once
            assert!(
                reason.contains("no description of: customtoolxyz"),
                "expected canonical name in header: {reason}"
            );
            assert!(
                !reason.contains("no description of: customtoolxyz, /usr/bin/customtoolxyz"),
                "expected path-qualified alias to be deduplicated: {reason}"
            );
            let occurrences = reason.matches("every operation of `customtoolxyz`").count();
            assert_eq!(
                occurrences, 1,
                "expected only 1 description entry for deduplicated canonical name, got {occurrences}: {reason}"
            );
        }
        other => panic!("expected Ask(unmodeled_command), got: {other:?}"),
    }
}

#[test]
fn unmodeled_prompt_multi_language_cites_all_applicable_language_settings() {
    let mut cfg = unmodeled_cfg();
    cfg.langs
        .get_mut("python")
        .unwrap()
        .constructs
        .insert("unmodeled_command".to_string(), Action::Ask);

    let decision = decide_command_at(
        &cfg,
        "bash",
        r#"unknownbashprog && python3 -c "custom_call()""#,
        Some(HOME),
        None,
        Some("C:/scratch"),
    );

    match decision {
        Decision::Ask(reason) => {
            assert!(
                reason.contains("lang.bash.constructs.unmodeled_command = \"allow\""),
                "expected bash setting: {reason}"
            );
            assert!(
                reason.contains("lang.python.constructs.unmodeled_command = \"allow\""),
                "expected python setting: {reason}"
            );
            assert!(
                reason.contains("---"),
                "expected divider line: {reason}"
            );
        }
        other => panic!("expected Ask(unmodeled_command) for multi-language line, got: {other:?}"),
    }
}
