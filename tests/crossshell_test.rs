//! One shell invoking another must not be a way around every guard.
//!
//! The bash scanner sees `powershell -Command "..."` as a program with one
//! opaque argument, so every guard was blind to whatever was inside it. All of
//! these were ALLOW before 2026-07-25 — the snippet was simply never read.
//!
//! The snippet is in a DIFFERENT language, so it has to be handed to that
//! language's scanner. Bash rules applied to PowerShell text find nothing.

use vouch::config::load;
use vouch::engine::decide_command_in;
use vouch::protocol::Decision;

fn decide(cmd: &str) -> Decision {
    // Everything that is not a guard is allowed here, so an Ask can only mean
    // a guard fired — not that some construct happened to look unfamiliar.
    let cfg = load(
        "version = 1\n[lang.bash]\ndefault = \"allow\"\n[lang.bash.constructs]\n\
         unmodeled_command = \"allow\"\nsubshell = \"allow\"\n",
    )
    .expect("parses");
    decide_command_in(&cfg, "bash", cmd, Some("C:/Users/dev"), None)
}

fn assert_asks(cmd: &str) {
    assert!(matches!(decide(cmd), Decision::Ask(_)), "evaded the guard: {cmd}");
}

fn assert_allows(cmd: &str) {
    assert!(matches!(decide(cmd), Decision::Allow(_)), "false positive: {cmd}");
}

#[test]
fn powershell_snippet_is_read_as_powershell() {
    assert_asks(r#"powershell -Command "Remove-Item -Recurse -Force C:/work/x""#);
    assert_asks(r#"pwsh -Command "Remove-Item -Recurse -Force C:/work/x""#);
    assert_asks(r#"powershell.exe -Command "Remove-Item -Recurse -Force C:/work/x""#);
}

#[test]
fn powershell_short_flag_carries_the_snippet_too() {
    assert_asks(r#"powershell.exe -c "rm -rf /c/work/x""#);
}

#[test]
fn a_write_inside_a_powershell_snippet_still_checks_its_path() {
    // Not a guard — a path rule. It has to survive the language hop as well.
    assert_asks(r#"pwsh -Command "Set-Content -Path C:/Windows/x.txt -Value h""#);
}

#[test]
fn cmd_snippet_is_read_whether_or_not_it_is_quoted() {
    // Quoting is the caller's choice, not the command's: these are the same
    // command arriving as one token and as four.
    assert_asks(r#"cmd /c "del /s /q C:\work\x""#);
    assert_asks(r"cmd.exe /c rd /s /q C:\work\x");
    assert_asks(r"cmd /C del /s /q C:\work\x");
}

#[test]
fn cmd_switches_are_flags_not_paths() {
    // INVERTED (§2.2 item 4, M2.125/§5.2.4): `/s` used to be read as a path
    // and normalize to `S:/`, which made the command ask for an invented
    // reason while the real guard never matched — the flag-vs-path
    // distinction this test used to pin. cmd is now its own unscannable
    // language: the snippet is never read at all, so the reason is
    // `unreadable_language` regardless of what is inside it, and the old
    // false-reason bug is moot for cmd specifically (it can still recur for
    // a language vouch DOES scan, which is a different test's job).
    let d = decide(r#"cmd /c "del /s /q C:\work\x""#);
    match d {
        Decision::Ask(r) => assert!(
            r.contains("unreadable_language"),
            "asked for the wrong reason: {r}"
        ),
        other => panic!("expected Ask, got {other:?}"),
    }
}

#[test]
fn wsl_runs_the_rest_of_the_line() {
    assert_asks("wsl rm -rf /mnt/c/work/x");
    assert_asks("wsl.exe rm -rf /mnt/c/work/x");
}

#[test]
fn reading_through_another_shell_is_still_reading() {
    assert_allows(r#"powershell -Command "Get-ChildItem C:/workspace""#);
    // INVERTED (§2.2 item 5, M2.125/§5.2.4): cmd is its own unscannable
    // language now, so a harmless `dir` inside it asks the same as a
    // destructive one would — vouch cannot tell a read from a write in text
    // it never reads, which is the honest cost of the invariant (§5.2.2),
    // not a regression specific to this shape.
    assert_asks("cmd /c dir");
    assert_allows(r#"pwsh -NoProfile -Command "Get-Content C:/workspace/vouch-dev/knowledge.toml""#);
    assert_allows("wsl ls /mnt/c/work");
}

#[test]
fn a_slash_path_argument_is_not_mistaken_for_a_switch() {
    // The shape test that separates `/s` from `/mnt/c/work` has to hold both
    // ways, or every unix path inside a cmd snippet disappears from the
    // written-path list.
    assert_asks(r"cmd /c del /s /q /mnt/c/work/x");
}

#[test]
fn powershell_aliases_are_the_same_command() {
    // `ri`, `rd`, `del` and `rm` are all aliases for Remove-Item. A guard that
    // only knows the long name is a guard the caller opts out of by typing
    // four fewer characters.
    assert_asks(r#"powershell -Command "ri -Recurse -Force C:/work/x""#);
    assert_asks(r#"powershell -Command "rd -r C:/work/x""#);
    assert_asks(r#"powershell -Command "del -Recurse C:/work/x""#);
}

#[test]
fn an_abbreviated_parameter_is_still_the_parameter() {
    // PowerShell accepts any unambiguous prefix, so a flag list can never be
    // complete by enumeration — the match has to be structural.
    for flag in ["-Recurse", "-Recurs", "-Recu", "-Rec", "-Re"] {
        assert_asks(&format!(
            r#"powershell -Command "Remove-Item {flag} -Force C:/work/x""#
        ));
    }
}

#[test]
fn an_unrelated_parameter_is_not_swallowed_by_prefix_matching() {
    // `-ReadOnly` is not a prefix of `-Recurse`, so it must not match it.
    assert_allows(r#"powershell -Command "Get-ChildItem -ReadOnly C:/workspace""#);
}

#[test]
fn a_redirect_inside_a_snippet_is_checked_like_any_other_write() {
    // Guards looked through the wrapper; redirects did not. A snippet is a
    // whole script, not just a list of program names.
    // (The benign counterpart needs declared allow_paths, so it lives in
    // resolve_test, whose config has them.)
    assert_asks(r#"cmd /c "echo x > C:/Users/dev/.claude/settings.json""#);
    assert_asks(r#"wsl bash -c "echo x > /c/Users/dev/.claude/settings.json""#);
}

#[test]
fn nesting_two_shells_deep_still_resolves() {
    assert_asks(r#"powershell -Command "cmd /c del /s /q C:\work\x""#);
    assert_asks(r#"cmd /c powershell -Command "Remove-Item -Recurse -Force C:/work/x""#);
}

#[test]
fn start_process_is_one_more_shape_of_one_shell_invoking_another() {
    // The program is the first positional argument and its arguments are the
    // -ArgumentList items, so the snippet has to be rebuilt and rescanned.
    assert_asks(
        r#"Start-Process powershell -ArgumentList "-Command","Remove-Item -Recurse C:/work/x""#,
    );
    assert_asks(r#"Start-Process cmd -ArgumentList "/c","del /s /q C:/work/x""#);
}

#[test]
fn start_process_on_something_harmless_stays_quiet() {
    assert_allows(r#"Start-Process notepad"#);
    assert_allows(r#"Start-Process powershell -ArgumentList "-Command","Get-ChildItem C:/workspace""#);
}

#[test]
fn a_run_dir_flag_is_read_the_same_in_both_languages() {
    // `git -C <dir>` is bash syntax, but the engine that resolves run-dir
    // flags is shared by every scanner (syntax.rs). This is the parity check
    // this file exists for: the same line, scanned as bash and as
    // PowerShell, must land on the same resolved write target either way.
    let cfg = load(
        r#"
version = 1
[lang.bash]
default = "allow"
[lang.bash.constructs]
unmodeled_command = "allow"
[lang.powershell]
default = "allow"
[lang.powershell.constructs]
unmodeled_command = "allow"
[write]
default = "ask"
allow_paths = ["C:/work/**", "C:/workspace/**"]
"#,
    )
    .expect("parses");
    for lang in ["bash", "powershell"] {
        match decide_command_in(&cfg, lang, "git -C C:/elsewhere init foo", Some("C:/Users/dev"), None) {
            Decision::Ask(r) => assert!(r.contains("C:/elsewhere/foo"), "[{lang}] {r}"),
            other => panic!("[{lang}] evaded the run-dir resolution, got {other:?}"),
        }
    }
}
