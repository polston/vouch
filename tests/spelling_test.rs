//! One file, many spellings.
//!
//! A protected path is protected because of the file it names, not because of
//! how the caller happened to type it. These pin the spellings that were
//! probed on 2026-07-25: case, drive-letter form, `..` traversal, and the file
//! tools as opposed to bash. Link traversal is covered by protected_test.
//!
//! Every one of these already passed when written. They exist so that a future
//! change to path handling cannot quietly undo them.

use vouch::config::load;
use vouch::engine::{decide_command_in, decide_file};
use vouch::protocol::Decision;

fn cfg() -> vouch::config::Config {
    load(
        r#"
version = 1
[lang.bash]
default = "allow"
[lang.bash.constructs]
unmodeled_command = "allow"
subshell = "allow"
dynamic_redirect = "allow"
[write]
default = "ask"
allow_paths = ["C:/work/**"]
[protected]
paths = ["$HOME/.claude/settings.json"]
"#,
    )
    .expect("parses")
}

const HOME: &str = "C:/Users/dev";

fn stopped(d: &Decision) -> bool {
    matches!(d, Decision::Ask(_) | Decision::Deny(_))
}

#[test]
fn the_protected_file_is_recognised_whatever_the_case() {
    // Windows paths are case-insensitive, so a rule that is not would be
    // opt-out by pressing shift.
    for p in [
        "C:/Users/dev/.claude/settings.json",
        "C:/USERS/DEV/.CLAUDE/SETTINGS.JSON",
        "c:/users/dev/.claude/settings.json",
        r"C:\Users\dev\.claude\settings.json",
    ] {
        assert!(
            stopped(&decide_file(&cfg(), HOME, None, p)),
            "spelling not recognised: {p}"
        );
    }
}

#[test]
fn traversal_does_not_hide_the_destination() {
    let cmd = "echo x > /c/git/vouch/../../Users/dev/.claude/settings.json";
    match decide_command_in(&cfg(), "bash", cmd, Some(HOME), None) {
        Decision::Ask(r) => assert!(r.contains("C:/Users/dev/.claude/settings.json"), "{r}"),
        other => panic!("expected Ask, got {other:?}"),
    }
}

#[test]
fn the_file_tools_are_checked_the_same_way_as_a_command() {
    // A path rule that only applied to Bash would be opt-out by using Write.
    assert!(stopped(&decide_file(
        &cfg(),
        HOME,
        None,
        "C:/Users/dev/.claude/settings.json"
    )));
    assert!(matches!(
        decide_file(&cfg(), HOME, None, "C:/work/ok.txt"),
        Decision::Allow(_)
    ));
}

#[test]
fn a_unc_path_is_not_silently_inside_an_allowed_area() {
    assert!(stopped(&decide_file(&cfg(), HOME, None, "//server/share/x.txt")));
}

#[test]
fn an_allowed_area_still_allows() {
    // The counterpart: none of the above may turn ordinary writes into prompts.
    for p in ["C:/work/a.txt", "C:/work/deep/nested/b.txt", r"C:\work\c.txt"] {
        assert!(
            matches!(decide_file(&cfg(), HOME, None, p), Decision::Allow(_)),
            "false positive: {p}"
        );
    }
}

// --- iteration 20: destinations vouch had no description of ----------------

fn decide_bash(cmd: &str) -> Decision {
    decide_command_in(&cfg(), "bash", cmd, Some(HOME), None)
}

#[test]
fn extraction_writes_to_its_destination_directory() {
    // `-C` / `-d` name a directory every archive member lands in. Without this
    // the whole extraction skipped the path rules.
    assert!(stopped(&decide_bash("tar -xf p.tar -C /c/Windows/System32")));
    assert!(stopped(&decide_bash("unzip -o p.zip -d /c/Windows/System32")));
    assert!(matches!(
        decide_bash("tar -xf p.tar -C /c/work/ok"),
        Decision::Allow(_)
    ));
}

#[test]
fn creating_an_archive_does_not_prompt_about_its_inputs() {
    // `tar -c` means create; the positional arguments are read, not written.
    // Matching `-C` case-insensitively made `-c` record the next token as a
    // written path.
    for cmd in [
        "tar -cf out.tar /c/work/src",
        "tar -c -f out.tar /c/work/src",
        "tar -tf p.tar",
    ] {
        assert!(
            matches!(decide_bash(cmd), Decision::Allow(_)),
            "false positive: {cmd}"
        );
    }
}

#[test]
fn a_link_is_created_at_its_second_argument() {
    // `ln -s target link` CREATES link. The target is only read.
    assert!(stopped(&decide_bash(
        "ln -s /c/work/evil /c/Users/dev/.claude/settings.json"
    )));
    assert!(matches!(
        decide_bash("ln -s /c/work/a /c/work/b"),
        Decision::Allow(_)
    ));
}

// --- iteration 22: destinations that depend on the SUBCOMMAND ---------------

#[test]
fn git_writes_where_its_subcommand_is_pointed() {
    assert!(stopped(&decide_bash(
        "git clone https://example.com/r.git /c/Windows/System32/r"
    )));
    assert!(stopped(&decide_bash("git init /c/Windows/System32/r")));
    assert!(stopped(&decide_bash("git worktree add /c/Windows/System32/wt")));
    assert!(matches!(
        decide_bash("git clone https://example.com/r.git /c/work/r"),
        Decision::Allow(_)
    ));
}

#[test]
fn a_subcommand_that_writes_nothing_is_not_given_a_destination() {
    for cmd in ["git status", "git log --oneline", "git worktree list", "git diff"] {
        assert!(
            matches!(decide_bash(cmd), Decision::Allow(_)),
            "false positive: {cmd}"
        );
    }
}

#[test]
fn git_clone_without_a_directory_now_derives_its_destination() {
    // Until M2.35 this pinned Allow: vouch derived no destination for a bare
    // `git clone <url>`, so nothing was known to be written and the write
    // rules never ran. M2.35 derives one — the URL's last segment with a
    // trailing `.git` stripped (task-10-brief.md) — so the bare form is no
    // longer invisible to them, and the comment claiming vouch "cannot know"
    // it (removed from knowledge.toml at the same change) was never true of
    // the URL's own text, only of vouch's prior refusal to read it.
    //
    // `decide_bash` gives no working directory, so the derived name
    // ("thing") is judged AS WRITTEN — vouch's long-standing behaviour for a
    // relative path with nothing to resolve it against (`CdState::NoDirectory`)
    // — and "thing" is outside `write.allow_paths`, so this asks rather than
    // allows. The URL uses a distinctive leaf ("thing") rather than a single
    // letter: `r.contains('r')` would have been a tautology (every ask names
    // `write.allow_paths`, which itself contains an 'r') and could not have
    // told a real derivation from an identity function that leaked the raw
    // spec text — review finding, 2026-08-06.
    let d = decide_bash("git clone https://example.com/thing.git");
    match d {
        Decision::Ask(r) => assert!(
            r.contains("write.allow_paths") && r.contains("thing"),
            "the derived name must be what the ask is about: {r}"
        ),
        other => panic!("{other:?}"),
    }
}

#[test]
fn worktree_add_takes_its_directory_first() {
    // `git worktree add <dir> [<commit-ish>]`. Taking the LAST argument
    // recorded `HEAD` — a commit, not a directory — as a written path, and
    // that showed up as a prompt on real recorded traffic.
    assert!(
        matches!(decide_bash("git worktree add /c/work/wt HEAD"), Decision::Allow(_)),
        "HEAD was treated as the destination"
    );
    assert!(stopped(&decide_bash(
        "git worktree add /c/Windows/System32/wt HEAD"
    )));
}

#[test]
fn a_relative_file_tool_path_is_resolved_before_any_rule_sees_it() {
    // Left relative, `settings.json` from inside .claude matched no protected
    // path and fell through to an ordinary write rule — one that HAS a setting,
    // when the protected rule deliberately does not.
    //
    // Measured: 0 of 2303 real file-tool calls send a relative path. This
    // closes a gap rather than fixing observed behaviour; the protected rule
    // must not depend on how a path happens to be spelled.
    let abs = "C:/Users/dev/.claude/settings.json";
    match decide_file(&cfg(), HOME, None, abs) {
        Decision::Ask(r) => assert!(r.contains("protected"), "{r}"),
        other => panic!("expected Ask, got {other:?}"),
    }
}

// --- iteration 23 -----------------------------------------------------------

#[test]
fn reading_a_file_is_not_writing_it() {
    // `<` READS. Recording it as a written path made `wc -l < hosts` prompt
    // about writing a file it only reads, and that fired on real traffic.
    for cmd in [
        "wc -l < /c/Windows/System32/drivers/etc/hosts",
        "cat < /c/Windows/y.txt",
        "grep x < /c/Windows/y.txt",
    ] {
        assert!(
            matches!(decide_bash(cmd), Decision::Allow(_)),
            "reading was treated as writing: {cmd}"
        );
    }
}

#[test]
fn every_writing_redirect_is_still_caught() {
    for cmd in [
        "echo x > /c/Windows/y.txt",
        "echo x >> /c/Windows/y.txt",
        "echo x >| /c/Windows/y.txt",
    ] {
        assert!(stopped(&decide_bash(cmd)), "write not caught: {cmd}");
    }
}

#[test]
fn a_command_that_reads_one_file_and_writes_another_names_only_the_write() {
    match decide_bash("sort < /c/Windows/a.txt > /c/Windows/b.txt") {
        Decision::Ask(r) => {
            assert!(r.contains("b.txt"), "{r}");
            assert!(!r.contains("a.txt"), "named the file it only reads: {r}");
        }
        other => panic!("expected Ask, got {other:?}"),
    }
}

#[test]
fn a_destination_on_another_machine_is_not_a_local_path() {
    // `user@host:/path` was treated as RELATIVE and joined to the working
    // directory, so it landed inside whatever area the cwd happened to be in
    // and was allowed for entirely the wrong reason.
    for cmd in [
        "scp /c/work/x user@host:/remote/",
        "rsync -a /c/work/ user@host:/remote/",
        "rsync -a /c/work/ host:/remote/",
    ] {
        assert!(
            matches!(decide_bash(cmd), Decision::Allow(_)),
            "remote destination checked as a local path: {cmd}"
        );
    }
}

#[test]
fn a_local_destination_is_still_checked_even_for_scp() {
    assert!(stopped(&decide_bash(
        "scp user@host:/remote/x /c/Windows/System32/y"
    )));
    assert!(matches!(
        decide_bash("scp /c/work/x /c/work/y"),
        Decision::Allow(_)
    ));
}

#[test]
fn a_windows_drive_is_not_mistaken_for_a_remote_host() {
    // Both are `something:` — a drive is exactly one letter.
    assert!(stopped(&decide_bash("cp /c/work/x C:/Windows/y")));
}

// --- iteration 24 -----------------------------------------------------------

#[test]
fn a_destination_given_as_a_flag_value_is_still_the_destination() {
    // `cp -t <dir> a b c` puts the destination in a flag, so taking the last
    // argument picked a SOURCE and missed the write entirely.
    assert!(stopped(&decide_bash("cp -t /c/Windows/System32 a b c")));
    assert!(stopped(&decide_bash("mv -t /c/Windows/System32 a b c")));
    assert!(matches!(
        decide_bash("cp -t /c/work a b c"),
        Decision::Allow(_)
    ));
}

#[test]
fn the_ordinary_form_still_uses_the_last_argument() {
    assert!(stopped(&decide_bash("cp /c/work/a /c/Windows/y")));
    assert!(stopped(&decide_bash("mv a b c /c/Windows/System32/")));
    assert!(matches!(decide_bash("cp /c/work/a /c/work/b"), Decision::Allow(_)));
}

#[test]
fn an_uppercase_flag_is_not_the_lowercase_one() {
    // `cp -T` is --no-target-directory and takes NO value. Matching `-t`
    // loosely would record the SOURCE as the destination.
    assert!(
        matches!(decide_bash("cp -T /c/work/a /c/work/b"), Decision::Allow(_)),
        "-T was treated as -t"
    );
}

#[test]
fn a_flags_value_is_not_a_path() {
    // `truncate -s 0 <file>` recorded `0`, and `mkdir -m 755 <dir>` recorded
    // `755`, as written paths. Both resolve under the working directory, so
    // they were usually invisible — and wrong whenever it was not allowed.
    for cmd in ["truncate -s 0 /c/Windows/y.txt", "mkdir -m 755 /c/Windows/newdir"] {
        match decide_bash(cmd) {
            Decision::Ask(r) => {
                assert!(!r.contains("/0"), "recorded a flag value as a path: {r}");
                assert!(!r.contains("755"), "recorded a flag value as a path: {r}");
            }
            other => panic!("expected Ask for {cmd}, got {other:?}"),
        }
    }
}

#[test]
fn writing_to_a_file_descriptor_is_not_writing_to_a_file() {
    assert!(matches!(decide_bash("echo err >&2"), Decision::Allow(_)));
}

#[test]
fn a_redirect_with_no_command_still_writes() {
    for cmd in [": > /c/Windows/y.txt", "> /c/Windows/y.txt"] {
        assert!(stopped(&decide_bash(cmd)), "missed: {cmd}");
    }
}

#[test]
fn tee_writes_the_file_it_is_given() {
    assert!(stopped(&decide_bash("echo x | tee /c/Windows/y.txt")));
    assert!(stopped(&decide_bash("echo x | tee -a /c/Windows/y.txt")));
}
