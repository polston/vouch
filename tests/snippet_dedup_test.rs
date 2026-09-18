//! Wrapped snippet scan deduplication (M2.238).
mod common;

use vouch::config::load as load_config;
use vouch::engine::decide_command_in;
use vouch::protocol::Decision;

#[test]
fn wrapped_snippet_redirect_evaluated_from_carried_site() {
    let cfg = load_config(r#"
version = 1
[lang.bash]
default = "allow"
[lang.bash.constructs]
unmodeled_command = "allow"
subshell = "allow"
evaluated_input = "allow"
[write]
default = "ask"
allow_paths = ["C:/allowed/**"]
"#).expect("parses");

    // sh -c with redirect to disallowed path:
    let decision = decide_command_in(&cfg, "bash", "sh -c 'echo hi > C:/disallowed/out.txt'", Some("C:/allowed"), None);
    assert!(
        matches!(decision, Decision::Ask(_)),
        "redirect inside wrapped snippet must be evaluated and gated"
    );
}

#[test]
fn wrapped_snippet_guard_evaluated_from_carried_site() {
    let cfg = load_config(r#"
version = 1
[lang.bash]
default = "allow"
[lang.bash.constructs]
unmodeled_command = "allow"
subshell = "allow"
evaluated_input = "allow"
"#).expect("parses");

    let decision = decide_command_in(&cfg, "bash", "sh -c 'rm -rf C:/allowed/dir'", Some("C:/allowed"), None);
    assert!(
        matches!(decision, Decision::Ask(_)),
        "guard inside wrapped snippet must fire without secondary scan"
    );
}
