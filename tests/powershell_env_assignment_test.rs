//! Tests for PowerShell in-snippet environment assignment channel (M2.140).
mod common;

use vouch::protocol::Decision;

fn test_config() -> vouch::config::Config {
    vouch::config::load(r#"
version = 1
[lang.bash]
default = "allow"
[lang.bash.constructs]
unmodeled_command = "allow"
[lang.powershell]
default = "allow"
[lang.powershell.constructs]
unmodeled_command = "allow"
env_assignment = "allow"
[write]
default = "ask"
allow_paths = ["C:/**", "/tmp/**", "/Users/**"]
"#)
    .expect("config parses")
}

#[test]
fn powershell_snippet_path_assignment_rebinds_lookup() {
    let cfg = test_config();
    let res = vouch::engine::decide_command_at(
        &cfg,
        "bash",
        r#"pwsh -Command "$env:PATH = 'C:/x'; git status""#,
        None,
        None,
        Some("C:/Users/dev"),
    );
    match res {
        Decision::Ask(reason) => {
            assert!(
                reason.contains("rebound_name"),
                "expected rebound_name in reason, got: {reason}"
            );
            assert!(
                reason.contains("PATH"),
                "expected PATH mentioned in reason, got: {reason}"
            );
        }
        other => panic!("expected Ask(rebound_name), got: {other:?}"),
    }
}

#[test]
fn powershell_direct_path_assignment_rebinds_lookup() {
    let cfg = test_config();
    let res = vouch::engine::decide_powershell(&cfg, "$env:PATH = 'C:/x'; git status");
    match res {
        Decision::Ask(reason) => {
            assert!(
                reason.contains("rebound_name"),
                "expected rebound_name in reason, got: {reason}"
            );
            assert!(
                reason.contains("PATH"),
                "expected PATH mentioned in reason, got: {reason}"
            );
        }
        other => panic!("expected Ask(rebound_name), got: {other:?}"),
    }
}

#[test]
fn powershell_snippet_psmodulepath_rebinds_lookup() {
    let cfg = test_config();
    let res = vouch::engine::decide_command_at(
        &cfg,
        "bash",
        r#"pwsh -Command "$env:PSModulePath = 'C:/x'; git status""#,
        None,
        None,
        Some("C:/Users/dev"),
    );
    match res {
        Decision::Ask(reason) => {
            assert!(
                reason.contains("rebound_name"),
                "expected rebound_name in reason, got: {reason}"
            );
            assert!(
                reason.contains("PSModulePath"),
                "expected PSModulePath mentioned in reason, got: {reason}"
            );
        }
        other => panic!("expected Ask(rebound_name), got: {other:?}"),
    }

    let res_direct = vouch::engine::decide_powershell(&cfg, "$env:PSModulePath = 'C:/x'; git status");
    match res_direct {
        Decision::Ask(reason) => {
            assert!(
                reason.contains("rebound_name"),
                "expected rebound_name in reason, got: {reason}"
            );
            assert!(
                reason.contains("PSModulePath"),
                "expected PSModulePath mentioned in reason, got: {reason}"
            );
        }
        other => panic!("expected Ask(rebound_name), got: {other:?}"),
    }
}

#[test]
fn powershell_innocuous_env_assignment_allows() {
    let cfg = test_config();
    let res = vouch::engine::decide_command_at(
        &cfg,
        "bash",
        r#"pwsh -Command "$env:FOO = 'bar'; git status""#,
        None,
        None,
        Some("C:/Users/dev"),
    );
    match res {
        Decision::Allow(_) => {}
        other => panic!("expected Allow, got: {other:?}"),
    }

    let res_direct = vouch::engine::decide_powershell(&cfg, "$env:FOO = 'bar'; git status");
    match res_direct {
        Decision::Allow(_) => {}
        other => panic!("expected Allow, got: {other:?}"),
    }
}
