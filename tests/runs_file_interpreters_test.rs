//! Tests for M2.143: Extend `runs_file` script-file ask mechanism to additional
//! interpreters (`node`, `perl`, `ruby`, `bun`).
//!
//! Verifies that non-shell/python interpreters fail closed to Ask on unmodeled
//! script files while preserving existing Allow status for standalone version/help
//! flags and inline code evaluation flags (`-e`).

use vouch::config::load;
use vouch::engine::decide_command_in;
use vouch::protocol::Decision;

fn config_with_unmodeled_allowed() -> vouch::config::Config {
    load(
        r#"
version = 1
[lang.bash]
default = "allow"
[lang.bash.constructs]
unmodeled_command = "allow"
evaluated_input = "ask"
[lang.javascript]
default = "allow"
[lang.javascript.constructs]
evaluated_input = "ask"
[lang.perl]
default = "allow"
[lang.perl.constructs]
evaluated_input = "ask"
unreadable_language = "allow"
[write]
default = "ask"
allow_paths = ["C:/work/**"]
"#,
    )
    .expect("config parses")
}

fn decide(cfg: &vouch::config::Config, cmd: &str) -> Decision {
    decide_command_in(cfg, "bash", cmd, Some("C:/Users/dev"), None)
}

#[test]
fn node_runs_file_asks_on_unmodeled_script() {
    let cfg = config_with_unmodeled_allowed();
    match decide(&cfg, "node app.js") {
        Decision::Ask(reason) => {
            assert!(
                reason.contains("evaluated_input"),
                "expected evaluated_input construct ask, got: {reason}"
            );
        }
        other => panic!("expected Ask on node app.js, got {other:?}"),
    }
}

#[test]
fn node_standalone_flags_allow() {
    let cfg = config_with_unmodeled_allowed();
    assert!(matches!(decide(&cfg, "node --version"), Decision::Allow(_)));
    assert!(matches!(decide(&cfg, "node --help"), Decision::Allow(_)));
}

#[test]
fn node_inline_eval_allows() {
    let cfg = config_with_unmodeled_allowed();
    match decide(&cfg, r#"node -e "console.log(1)""#) {
        Decision::Allow(_) => {}
        other => panic!("expected Allow for node -e, got {other:?}"),
    }
}

#[test]
fn perl_runs_file_asks_on_unmodeled_script() {
    let cfg = config_with_unmodeled_allowed();
    match decide(&cfg, "perl script.pl") {
        Decision::Ask(reason) => {
            assert!(
                reason.contains("evaluated_input"),
                "expected evaluated_input construct ask, got: {reason}"
            );
        }
        other => panic!("expected Ask on perl script.pl, got {other:?}"),
    }
}

#[test]
fn perl_standalone_flags_allow() {
    let cfg = config_with_unmodeled_allowed();
    assert!(matches!(decide(&cfg, "perl --version"), Decision::Allow(_)));
    assert!(matches!(decide(&cfg, "perl --help"), Decision::Allow(_)));
}

#[test]
fn perl_inline_eval_allows() {
    let cfg = config_with_unmodeled_allowed();
    match decide(&cfg, r#"perl -e 'print 1;'"#) {
        Decision::Allow(_) => {}
        other => panic!("expected Allow for perl -e, got {other:?}"),
    }
}

#[test]
fn ruby_runs_file_asks_on_unmodeled_script() {
    let cfg = config_with_unmodeled_allowed();
    match decide(&cfg, "ruby migrate.rb") {
        Decision::Ask(reason) => {
            assert!(
                reason.contains("evaluated_input"),
                "expected evaluated_input construct ask, got: {reason}"
            );
        }
        other => panic!("expected Ask on ruby migrate.rb, got {other:?}"),
    }
}

#[test]
fn ruby_standalone_flags_allow() {
    let cfg = config_with_unmodeled_allowed();
    assert!(matches!(decide(&cfg, "ruby --version"), Decision::Allow(_)));
    assert!(matches!(decide(&cfg, "ruby -v"), Decision::Allow(_)));
}

#[test]
fn bun_runs_file_asks_on_unmodeled_script() {
    let cfg = config_with_unmodeled_allowed();
    match decide(&cfg, "bun server.js") {
        Decision::Ask(reason) => {
            assert!(
                reason.contains("evaluated_input"),
                "expected evaluated_input construct ask, got: {reason}"
            );
        }
        other => panic!("expected Ask on bun server.js, got {other:?}"),
    }
}

#[test]
fn bun_standalone_flags_allow() {
    let cfg = config_with_unmodeled_allowed();
    assert!(matches!(decide(&cfg, "bun --version"), Decision::Allow(_)));
    assert!(matches!(decide(&cfg, "bun -v"), Decision::Allow(_)));
}
