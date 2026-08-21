//! What `explain` and `why` do with their arguments.
//!
//! `vouch explain bash '<cmd>'` used to explain the one-word command `bash`,
//! print ALLOW, and give no sign it had answered a different question.

use vouch::cli::parse_target;

fn a(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

#[test]
fn a_bare_command_is_bash() {
    let t = parse_target(&a(&["rm -rf /tmp/x"])).expect("parses");
    assert_eq!(t.lang, "bash");
    assert_eq!(t.cmd, "rm -rf /tmp/x");
}

#[test]
fn ps_selects_powershell() {
    let t = parse_target(&a(&["ps", "Get-Item x"])).expect("parses");
    assert_eq!(t.lang, "powershell");
    assert_eq!(t.cmd, "Get-Item x");
}

#[test]
fn powershell_is_accepted_spelled_out() {
    let t = parse_target(&a(&["powershell", "Get-Item x"])).expect("parses");
    assert_eq!(t.lang, "powershell");
    assert_eq!(t.cmd, "Get-Item x");
}

/// The defect this file exists for.
#[test]
fn bash_selects_bash_and_does_not_become_the_command() {
    let t = parse_target(&a(&["bash", "rm -rf /tmp/x"])).expect("parses");
    assert_eq!(t.lang, "bash");
    assert_eq!(t.cmd, "rm -rf /tmp/x", "the selector was treated as the command");
}

#[test]
fn sh_is_accepted_as_a_bash_selector() {
    let t = parse_target(&a(&["sh", "rm -rf /tmp/x"])).expect("parses");
    assert_eq!(t.lang, "bash");
    assert_eq!(t.cmd, "rm -rf /tmp/x");
}

/// `ps` and `bash` are real programs. Asking about them must stay possible.
#[test]
fn a_lone_selector_is_a_command_not_a_selector() {
    let t = parse_target(&a(&["ps"])).expect("parses");
    assert_eq!(t.lang, "bash");
    assert_eq!(t.cmd, "ps");

    let t = parse_target(&a(&["bash"])).expect("parses");
    assert_eq!(t.lang, "bash");
    assert_eq!(t.cmd, "bash");
}

#[test]
fn no_arguments_yields_an_empty_command() {
    let t = parse_target(&[]).expect("parses");
    assert_eq!(t.lang, "bash");
    assert_eq!(t.cmd, "");
}

/// Guessing which argument was meant is what produced the original defect.
#[test]
fn an_unrecognised_extra_argument_is_an_error() {
    let e = parse_target(&a(&["frobnicate", "x y"])).expect_err("must reject");
    assert!(e.contains("one argument"), "the error must say how to fix it, got: {e}");
}

#[test]
fn more_than_two_arguments_is_an_error() {
    let e = parse_target(&a(&["bash", "ls", "extra"])).expect_err("must reject");
    assert!(e.contains("one argument"), "got: {e}");
}

/// An unquoted command is the likeliest way to hit this. The message has to
/// name the fix, because "unexpected argument" alone does not.
#[test]
fn the_error_shows_the_quoted_form() {
    let e = parse_target(&a(&["rm", "-rf", "/tmp/x"])).expect_err("must reject");
    assert!(e.contains("vouch explain"), "got: {e}");
    assert!(e.contains('\''), "the message should show quoting, got: {e}");
}

#[test]
fn no_cwd_flag_leaves_cwd_unset() {
    let t = parse_target(&a(&["git status"])).expect("parses");
    assert_eq!(t.cwd, None);
}

#[test]
fn a_cwd_flag_is_consumed_before_the_positionals() {
    let t = parse_target(&a(&["--cwd", "C:/scratch/j", "git status"])).expect("parses");
    assert_eq!(t.cwd.as_deref(), Some("C:/scratch/j"));
    assert_eq!(t.lang, "bash");
    assert_eq!(t.cmd, "git status");
}

#[test]
fn a_cwd_flag_still_allows_a_language_selector_after_it() {
    let t = parse_target(&a(&["--cwd", "C:/scratch/j", "ps", "Get-Item x"])).expect("parses");
    assert_eq!(t.cwd.as_deref(), Some("C:/scratch/j"));
    assert_eq!(t.lang, "powershell");
    assert_eq!(t.cmd, "Get-Item x");
}

#[test]
fn a_cwd_flag_with_no_command_yields_an_empty_command() {
    let t = parse_target(&a(&["--cwd", "C:/scratch/j"])).expect("parses");
    assert_eq!(t.cwd.as_deref(), Some("C:/scratch/j"));
    assert_eq!(t.cmd, "");
}

/// Carry-forward fix: `--cwd` with nothing after it used to fall through to
/// the ordinary positional match and become the COMMAND `--cwd` — a directory
/// flag silently misread as a one-word command is exactly the kind of
/// guessing this parser exists to refuse.
#[test]
fn a_bare_cwd_flag_with_no_value_is_an_error() {
    let e = parse_target(&a(&["--cwd"])).expect_err("must reject");
    assert!(e.contains("--cwd needs a directory"), "got: {e}");
}
