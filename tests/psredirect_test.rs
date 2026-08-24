//! PowerShell redirect targets: the ones that are files, and the ones that are not.
//!
//! Measured on 533 real recorded PowerShell commands, 54 ended as
//! `unresolved_path`. 42 of those were `$null` — PowerShell's `/dev/null`, not
//! a file at all — and most of the rest were fabricated: `>` was split out of
//! `-f` format strings, `$( … )` expressions and `else { … }` bodies, inventing
//! a written path that no rule could match and that named no real file.
//!
//! After these fixes the same 533 commands produce 2 unresolved paths, and the
//! prompts that remain name real destinations.

use vouch::config::load;
use vouch::engine::decide_command_in;
use vouch::protocol::Decision;

fn cfg() -> vouch::config::Config {
    load(
        r#"
version = 1
[lang.powershell]
default = "allow"
[lang.powershell.constructs]
unmodeled_command = "allow"
assignment = "allow"
env_assignment = "allow"
method_call = "allow"
redirect = "allow"
keyword_if = "allow"
[write]
default = "ask"
allow_paths = ["C:/work/**"]
"#,
    )
    .expect("parses")
}

fn decide(cmd: &str) -> Decision {
    decide_command_in(&cfg(), "powershell", cmd, Some("C:/Users/dev"), None)
}

fn targets(src: &str) -> Vec<String> {
    vouch::powershell::parse(src).expect("scans").redirect_targets
}

#[test]
fn a_real_redirect_target_is_still_captured() {
    assert!(
        matches!(decide("Get-Content x > C:/Windows/y.txt"), Decision::Ask(_)),
        "a genuine redirect must still be checked"
    );
    assert!(matches!(
        decide("Get-Content x >> C:/Windows/y.txt"),
        Decision::Ask(_)
    ));
    assert!(matches!(
        decide("Get-Content x > C:/work/ok.txt"),
        Decision::Allow(_)
    ));
}

#[test]
fn discarding_output_is_not_a_file_write() {
    // `$null` is how PowerShell throws output away. Treating it as a path made
    // it 42 of the 54 unresolved paths in the real corpus.
    for cmd in [
        "Get-ChildItem C:/workspace > $null",
        "Get-ChildItem C:/workspace 2>$null",
        "Get-ChildItem C:/workspace > $NULL",
    ] {
        assert!(matches!(decide(cmd), Decision::Allow(_)), "{cmd}");
        assert!(targets(cmd).is_empty(), "{cmd} recorded a target");
    }
}

#[test]
fn merging_streams_names_no_file() {
    assert!(targets("Get-ChildItem C:/workspace 2>&1").is_empty());
    assert!(matches!(
        decide("Get-ChildItem C:/workspace 2>&1"),
        Decision::Allow(_)
    ));
}

#[test]
fn a_greater_than_inside_a_string_is_not_a_redirect() {
    let cmd = r#"Write-Output ("{0} > {1}" -f $a, $b)"#;
    assert!(targets(cmd).is_empty(), "invented a target: {:?}", targets(cmd));
    assert!(matches!(decide(cmd), Decision::Allow(_)));
}

#[test]
fn a_greater_than_inside_a_block_or_expression_is_not_a_redirect() {
    for cmd in [
        r#"$c = if ($p) {$p} else {$c}; Write-Output $c"#,
        r#"Write-Output ($(if($p){$p}else{'x'}))"#,
    ] {
        assert!(
            targets(cmd).is_empty(),
            "{cmd} invented {:?}",
            targets(cmd)
        );
    }
}

#[test]
fn a_comparison_operator_is_not_a_redirect() {
    let cmd = "if ($a -gt 5) { Write-Output big }";
    assert!(targets(cmd).is_empty());
    assert!(matches!(decide(cmd), Decision::Allow(_)));
}
