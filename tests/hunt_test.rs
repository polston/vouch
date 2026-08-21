//! Evasion battery, run at the LIBRARY level.
//!
//! Every case here is a way someone might get a gated operation past vouch.
//! Two of these probes were originally written as shell one-liners and produced
//! FALSE vulnerability reports, because the shell rewrote the input before vouch
//! saw it (`/usr/bin/rm` -> `C:/Program Files/Git/usr/bin/rm`, and `\rm` -> CR).
//! Strings go straight to the library here for exactly that reason.

use vouch::protocol::Decision;

fn cfg() -> vouch::config::Config {
    vouch::config::load(
        r#"
version = 1
[lang.bash]
default = "allow"
[lang.powershell]
default = "allow"
[lang.bash.constructs]
unmodeled_command = "allow"
subshell = "allow"
dynamic_redirect = "allow"
heredoc = "allow"
background = "allow"
function_def = "allow"
redirect = "allow"
[lang.powershell.constructs]
unmodeled_command = "allow"
redirect = "allow"
assignment = "allow"
env_assignment = "allow"
method_call = "allow"
type_literal = "allow"
call_operator = "allow"
keyword_foreach = "allow"
[write]
default = "ask"
allow_paths = ["C:/work/**"]
[protected]
paths = ["$HOME/.claude/settings.json"]
"#,
    )
    .expect("parses")
}

fn v(lang: &str, cmd: &str) -> Decision {
    vouch::engine::decide_command_in(&cfg(), lang, cmd, Some("C:/Users/dev"), None)
}

fn gated(lang: &str, cmd: &str) {
    assert!(
        matches!(v(lang, cmd), Decision::Ask(_) | Decision::Deny(_)),
        "LEAK — this got through: {cmd}"
    );
}

fn quiet(lang: &str, cmd: &str) {
    assert!(
        matches!(v(lang, cmd), Decision::Allow(_)),
        "FALSE POSITIVE — this should be silent: {cmd}"
    );
}

#[test]
fn path_spellings_and_quoting_do_not_hide_a_delete() {
    gated("bash", r"rm -rf C:\work\x");
    gated("bash", "rm -rf '/c/work/x'");
    gated("bash", concat!("\u{5c}", "rm -rf /c/work/x"));
}

#[test]
fn every_command_in_a_chain_is_checked() {
    gated("bash", "cd /tmp && rm -rf /c/work/x");
    gated("bash", "ls; rm -rf /c/work/x");
    gated("bash", "ls || rm -rf /c/work/x");
    gated("bash", "( rm -rf /c/work/x )");
}

#[test]
fn compound_statement_bodies_are_checked() {
    gated("bash", "if true; then rm -rf /c/work/x; fi");
    gated("bash", "while true; do rm -rf /c/work/x; done");
    gated("powershell", "if ($true) { Set-Content -Path C:/Windows/y.txt -Value h }");
}

#[test]
fn path_traversal_out_of_an_allowed_area_is_caught() {
    gated("bash", "cp a.txt C:/work/../Windows/x.txt");
    gated("bash", "cp a.txt /c/work/../../Windows/x.txt");
    gated("bash", "cp a.txt ../../Windows/x.txt");
    // ...but traversal that stays inside must NOT prompt
    quiet("bash", "cp a.txt C:/work/sub/../b.txt");
}

#[test]
fn the_protected_file_cannot_be_reached_sideways() {
    gated("bash", "env cp evil.json /c/Users/dev/.claude/settings.json");
    gated("bash", "cp a.txt ~/.claude/settings.json");
    gated("bash", "echo x > /c/Users/dev/.claude/../.claude/settings.json");
}

#[test]
fn every_way_of_writing_a_file_is_checked() {
    gated("bash", "cat > /c/Windows/x.txt <<EOF\nhi\nEOF");
    gated("bash", "tee /c/Windows/x.txt");
    gated("bash", "echo hi &> /c/Windows/x.txt");
    gated("bash", "echo hi >| /c/Windows/x.txt");
    gated("bash", "cd /c/Windows && echo x > relative.txt");
}

#[test]
fn case_and_global_options_do_not_hide_a_git_rewrite() {
    gated("bash", "git --git-dir=/c/repo/.git reset --hard");
    gated("powershell", "set-content -path C:/Windows/x.txt -value hi");
    gated("powershell", "Remove-Item -Recurse -Force C:/work/x");
}

#[test]
fn ordinary_work_stays_silent() {
    quiet("bash", "ls -la");
    quiet("bash", "cp a.txt C:/work/b.txt");
    quiet("bash", "git status && git log --oneline");
    quiet("bash", "echo done > C:/work/out.txt");
    quiet("powershell", "Get-ChildItem C:/work");
    quiet("powershell", "Set-Content -Path C:/work/ok.txt -Value hi");
}
