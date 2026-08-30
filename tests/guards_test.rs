//! Guard tests.
//!
//! The guard set is derived from the policy the user's existing tool already
//! declared, not from anyone's opinion about what is dangerous. Each rule in
//! knowledge.toml carries a `source` saying where it came from, and these tests
//! are grouped the same way.

use vouch::config::load;
use vouch::guards::{check_all, in_effect as builtin, KNOWN_GUARDS};
use vouch::protocol::Decision;
use vouch::shell::parse;

fn hits_for(cmd: &str) -> Vec<(String, String)> {
    let p = parse(cmd).expect("parses");
    check_all(builtin(), &p.commands)
        .into_iter()
        .map(|h| (h.guard, h.source))
        .collect()
}

fn guards_for(cmd: &str) -> Vec<String> {
    hits_for(cmd).into_iter().map(|(g, _)| g).collect()
}

fn assert_guard(cmd: &str, want: &str) {
    let got = guards_for(cmd);
    assert!(
        got.iter().any(|g| g == want),
        "expected guard '{want}' for `{cmd}`, got {got:?}"
    );
}

fn assert_no_guard(cmd: &str) {
    let got = guards_for(cmd);
    assert!(got.is_empty(), "expected no guard for `{cmd}`, got {got:?}");
}

// ---------------------------------------------------------------------------
// Rules that came from the user's existing declared policy
// ---------------------------------------------------------------------------

#[test]
fn declared_hard_reset_is_caught_however_it_is_written() {
    for cmd in [
        "git reset --hard origin/main",
        "git reset -q --hard",
        "git -C /c/workspace/vouch reset --hard",
        "git -c user.name=x reset --hard origin/main",
        "cd /tmp && git reset --hard",
    ] {
        assert_guard(cmd, "history_rewrite");
    }
}

#[test]
fn declared_force_push_is_caught_however_it_is_written() {
    for cmd in [
        "git push --force origin main",
        "git push -f origin main",
        "git push --force-with-lease origin wiki",
        "git -C /repo push --force",
    ] {
        assert_guard(cmd, "history_rewrite");
    }
}

#[test]
fn declared_pr_create_and_merge_are_caught() {
    assert_guard("gh pr create --title x --body y", "publish_outward");
    assert_guard("gh pr merge 21 --squash --delete-branch", "publish_outward");
}

#[test]
fn unread_bash_verbs_fire_the_rule_but_use_the_unread_verb_construct() {
    let cfg = load(
        "[lang.bash]\ndefault = \"allow\"\n[guards]\nhistory_rewrite = \"deny\"\n",
    )
    .unwrap();
    assert!(
        matches!(
            vouch::engine::decide_bash(&cfg, "git filter-branch --all"),
            Decision::Deny(_)
        ),
        "the readable twin proves the configured guard action"
    );
    for command in [
        r#"git "filter-branch" --all"#,
        r#"git filter-b"ranch" --all"#,
        "git --exec-path /usr/lib/git-core reset --hard",
    ] {
        match vouch::engine::decide_bash(&cfg, command) {
            Decision::Ask(reason) => {
                assert!(reason.contains("unread_verb"), "{command}: {reason}");
                assert!(!reason.contains("setting: guards.history_rewrite"), "{command}: {reason}");
            }
            other => panic!("unread verb must ask instead of evade or hard-deny ({command}): {other:?}"),
        }
    }
}

#[test]
fn an_unread_hit_does_not_lower_a_sibling_guards_genuine_deny() {
    let cfg = load(
        "[lang.bash]\ndefault = \"allow\"\n[guards]\nhistory_rewrite = \"deny\"\nremote_execution = \"deny\"\n",
    )
    .unwrap();
    match vouch::engine::decide_bash(&cfg, r#"git "filter-branch" --all && ssh host"#) {
        Decision::Deny(reason) => assert!(reason.contains("remote_execution"), "{reason}"),
        other => panic!("the genuine sibling guard must keep its deny: {other:?}"),
    }
}

#[test]
fn sub_arg_0_anchors_on_the_resolved_verb_index_not_equal_text() {
    let cfg = load(
        "[lang.bash]\ndefault = \"allow\"\n[guards]\npublish_outward = \"deny\"\n",
    )
    .unwrap();
    for command in ["gh pr merge 1", "gh -R pr pr merge 1"] {
        match vouch::engine::decide_bash(&cfg, command) {
            Decision::Deny(reason) => assert!(reason.contains("publish_outward"), "{reason}"),
            other => panic!("the merge guard lost its real anchor for {command}: {other:?}"),
        }
    }
    for command in [r#"gh "pr" merge 1"#, "gh --hostname example.test pr merge 1"] {
        match vouch::engine::decide_bash(&cfg, command) {
            Decision::Ask(reason) => assert!(reason.contains("unread_verb"), "{reason}"),
            other => panic!("an unread gh verb must use its construct ({command}): {other:?}"),
        }
    }
}

#[test]
fn verb_readability_is_language_specific() {
    let cfg = load(
        "[lang.powershell]\ndefault = \"allow\"\n[lang.python]\ndefault = \"allow\"\n[guards]\nhistory_rewrite = \"deny\"\n",
    )
    .unwrap();

    // PowerShell's scanner has already decoded syntactic quotes. A quote that
    // was ordinary syntax must not turn a readable guard hit into unread_verb.
    assert!(matches!(
        vouch::engine::decide_powershell(&cfg, r#"git "filter-branch" --all"#),
        Decision::Deny(_)
    ));
    match vouch::engine::decide_powershell(&cfg, "git $Verb --all") {
        Decision::Ask(reason) => assert!(reason.contains("unread_verb"), "{reason}"),
        other => panic!("PowerShell expansion at the verb must be unreadable: {other:?}"),
    }

    // Python literal strings are decoded values. Their punctuation is data,
    // not evidence of an unread token. Python call heads are deliberately
    // namespaced, so exercise the guard primitive with a matching entry.
    let py_kb = vouch::guards::load(
        r#"
[[program]]
match = ["python:git"]
case_sensitive_flags = true
[[program.rule]]
guard = "history_rewrite"
subcommand_in = ["filter-branch"]
"#,
    )
    .unwrap();
    let literal = vouch::python::parse(r#"git("filter-branch", "--all")"#).unwrap();
    let literal_hits = vouch::guards::check_in(&py_kb, &literal.commands[0], "python");
    assert_eq!(literal_hits.len(), 1);
    assert_eq!(literal_hits[0].unread_verb, None);

    let dynamic = vouch::python::parse(r#"git(verb, "--all")"#).unwrap();
    let dynamic_hits = vouch::guards::check_in(&py_kb, &dynamic.commands[0], "python");
    assert_eq!(dynamic_hits.len(), 1);
    assert!(dynamic_hits[0].unread_verb.is_some());
}

#[test]
fn verb_vocabulary_is_language_scoped_and_keeps_the_entry_case_rule() {
    let kb = vouch::guards::load(
        r#"
[[program]]
match = ["widget"]
languages = ["bash"]
value_options = ["-s"]
case_sensitive_flags = false
subcommands = ["x"]

[[program]]
match = ["widget"]
languages = ["powershell"]
value_options = ["-P"]
case_sensitive_flags = false
subcommands = ["x"]
"#,
    )
    .unwrap();

    let bash = cmd("widget", &["-S", "value", "x"]);
    assert_eq!(
        vouch::guards::verb_of_in(&kb, &bash, "bash"),
        vouch::guards::VerbWord::Word("x".into())
    );
    assert!(vouch::guards::recognises(&kb, &bash, "bash", true));
    assert!(matches!(
        vouch::guards::verb_of_in(&kb, &bash, "powershell"),
        vouch::guards::VerbWord::Unknown(_)
    ));

    let powershell = cmd("widget", &["-P", "value", "x"]);
    assert_eq!(
        vouch::guards::verb_of_in(&kb, &powershell, "powershell"),
        vouch::guards::VerbWord::Word("x".into())
    );
    assert!(matches!(
        vouch::guards::verb_of_in(&kb, &powershell, "bash"),
        vouch::guards::VerbWord::Unknown(_)
    ));
}

#[test]
fn then_and_sub_write_share_the_same_name_wide_verb_grammar() {
    let kb = vouch::guards::load(
        r#"
[[program]]
match = ["widget"]
languages = ["bash"]
value_options = ["-s"]
case_sensitive_flags = true

[[program]]
match = ["widget"]
languages = ["bash"]
case_sensitive_flags = true
[[program.sub_write]]
subcommand = "x"
then = "add"
takes = "first"
min_positional = 1
"#,
    )
    .unwrap();
    let command = cmd("widget", &["-s", "value", "x", "add", "C:/work/out"]);
    assert_eq!(
        vouch::guards::verb_of_in(&kb, &command, "bash"),
        vouch::guards::VerbWord::Word("x".into())
    );
    assert_eq!(
        vouch::guards::then_of_in(&kb, &command, "bash"),
        vouch::guards::SecondWord::Word("add".into())
    );
    assert_eq!(
        vouch::guards::written_paths_in(&kb, &command, "bash").paths,
        vec!["C:/work/out".to_string()]
    );

    let post_flag = cmd(
        "widget",
        &["x", "-s", "value", "add", "C:/work/post-flag"],
    );
    assert_eq!(
        vouch::guards::then_of_in(&kb, &post_flag, "bash"),
        vouch::guards::SecondWord::Word("add".into())
    );
    assert_eq!(
        vouch::guards::written_paths_in(&kb, &post_flag, "bash").paths,
        vec!["C:/work/post-flag".to_string()]
    );
}

#[test]
fn overlapping_verb_grammars_refuse_contradictions_but_cross_language_pairs_do_not() {
    let case_error = vouch::knowledge::validate_text(
        r#"
[[program]]
match = ["widget"]
languages = ["bash"]
case_sensitive_flags = true
[[program]]
match = ["widget"]
languages = ["bash"]
case_sensitive_flags = false
"#,
    )
    .unwrap_err();
    assert!(case_error.contains("case_sensitive_flags"), "{case_error}");

    let default_case_error = vouch::knowledge::validate_text(
        r#"
[[program]]
match = ["widget"]
languages = ["bash"]
value_options = ["-x"]
[[program]]
match = ["widget"]
languages = ["bash"]
case_sensitive_flags = true
"#,
    )
    .unwrap_err();
    assert!(default_case_error.contains("unstated value means false"), "{default_case_error}");

    let kind_error = vouch::knowledge::validate_text(
        r#"
[[program]]
match = ["widget"]
languages = ["bash"]
value_options = ["-x"]
case_sensitive_flags = true
[[program]]
match = ["widget"]
languages = ["bash"]
no_value_options = ["-x"]
case_sensitive_flags = true
"#,
    )
    .unwrap_err();
    assert!(kind_error.contains("value-taking"), "{kind_error}");
    assert!(kind_error.contains("no-value"), "{kind_error}");

    vouch::knowledge::validate_text(
        r#"
[[program]]
match = ["widget"]
languages = ["bash"]
value_options = ["-x"]
case_sensitive_flags = true
[[program]]
match = ["widget"]
languages = ["powershell"]
no_value_options = ["-x"]
case_sensitive_flags = false
"#,
    )
    .unwrap();
}

#[test]
fn declared_chmod_execute_is_caught_symbolically_and_numerically() {
    assert_guard("chmod +x script.sh", "grant_execute");
    assert_guard("chmod 755 script.sh", "grant_execute");
    assert_guard("chmod 700 script.sh", "grant_execute");
}

#[test]
fn declared_in_place_sed_is_caught() {
    // "in-place editing not allowed, use Edit tool" — 20+ hits in the corpus,
    // and a rule vouch did not have until it was read out of the real policy.
    assert_guard("sed -i 's/a/b/' file.go", "in_place_edit");
    assert_guard("sed -i.bak 's/a/b/' file.go", "in_place_edit");
    assert_guard("sed -i -e 1007,1037d src/snapshot.rs", "in_place_edit");
}

#[test]
fn a_read_only_sed_is_not_an_in_place_edit() {
    assert_no_guard("sed 's/a/b/' file.go");
    assert_no_guard("cat x | sed -n '1,5p'");
}

#[test]
fn declared_ssh_is_caught() {
    assert_guard("ssh user@host 'ls'", "remote_execution");
}

// ---------------------------------------------------------------------------
// Rules the user asked for directly
// ---------------------------------------------------------------------------

#[test]
fn requested_recursive_delete_is_caught_in_every_spelling() {
    for cmd in [
        "rm -rf /c/work/out",
        "rm -fr /c/work/out",
        "rm -r -f /c/work/out",
        "rm -f -r /c/work/out",
        "rm --recursive --force /c/work/out",
        "cd /tmp && rm -rf build",
        "for d in a b; do rm -rf \"$d\"; done",
    ] {
        assert_guard(cmd, "delete_recursive");
    }
}

#[test]
fn a_plain_rm_of_one_file_is_not_a_recursive_delete() {
    assert_no_guard("rm /tmp/one_file.txt");
}

// ---------------------------------------------------------------------------
// Things the user's policy never prompted on must stay quiet
// ---------------------------------------------------------------------------

#[test]
fn commands_the_existing_policy_allowed_stay_allowed() {
    for cmd in [
        "git push origin main",
        "git status --short",
        "git commit -m 'x'",
        "git rebase main",
        "npm run build",
        "cargo test",
        "ls -la /c/workspace",
        "python script.py",
    ] {
        assert_no_guard(cmd);
    }
}

// ---------------------------------------------------------------------------
// Provenance and configurability
// ---------------------------------------------------------------------------

#[test]
fn every_rule_states_where_it_came_from() {
    for prog in &builtin().program {
        for rule in &prog.rule {
            assert!(
                !rule.source.trim().is_empty(),
                "rule {} for {:?} has no source",
                rule.guard,
                prog.match_names
            );
            let s = &rule.source;
            assert!(
                s.starts_with("declared") || s.starts_with("requested") || s.starts_with("inferred"),
                "rule source must say declared/requested/inferred, got: {s}"
            );
        }
    }
}

#[test]
fn every_guard_the_data_can_emit_is_declared_known() {
    for prog in &builtin().program {
        for rule in &prog.rule {
            assert!(
                KNOWN_GUARDS.contains(&rule.guard.as_str()),
                "guard '{}' is in knowledge.toml but not in KNOWN_GUARDS",
                rule.guard
            );
        }
    }
}

#[test]
fn a_guard_hit_asks_by_default_with_no_configuration() {
    let cfg = load("version = 1\n[lang.bash]\ndefault = \"allow\"\n").expect("parses");
    let d = vouch::engine::decide_bash(&cfg, "rm -rf /c/work/out");
    assert!(matches!(d, Decision::Ask(_)), "got {d:?}");
}

#[test]
fn a_guard_hit_shows_its_source_and_says_it_will_keep_asking() {
    let cfg = load("version = 1\n[lang.bash]\ndefault = \"allow\"\n").expect("parses");
    if let Decision::Ask(reason) = vouch::engine::decide_bash(&cfg, "git reset --hard") {
        assert!(reason.contains("guards.history_rewrite"), "got: {reason}");
        assert!(reason.contains("rule source: declared"), "got: {reason}");
        assert!(reason.contains("does not create a rule"), "got: {reason}");
    } else {
        panic!("expected Ask");
    }
}

#[test]
fn a_guard_can_be_turned_off_by_configuration_like_everything_else() {
    let cfg = load(
        "version = 1\n[lang.bash]\ndefault = \"allow\"\n[guards]\ndelete_recursive = \"allow\"\n",
    )
    .expect("parses");
    let d = vouch::engine::decide_bash(&cfg, "rm -rf /c/work/out");
    assert!(matches!(d, Decision::Allow(_)), "got {d:?}");
}

// ---------------------------------------------------------------------------
// M2.121 — base()'s Windows-rooted shape gate, pinned at the recognition/
// decision layer (guards_test.rs task-8 review round 1): load-validation
// tests exercise base_name for a different purpose and only incidentally
// cover this, so a later refactor of base() could silently break Windows-
// absolute-path recognition with nothing red. These assert the DECISION and
// the deciding reason, not just the folded string, so they cover the path
// recognition actually takes: guards::check by way of the full engine.
// ---------------------------------------------------------------------------

#[test]
fn a_quoted_windows_absolute_head_still_reaches_its_guard() {
    // The backslash fold in `base()` exists for exactly this shape: a
    // drive-letter path, quoted the way a caller writes one with a space
    // in it, has to resolve to the same `rm` entry the bare name does.
    let cfg = load("version = 1\n[lang.bash]\ndefault = \"allow\"\n").expect("parses");
    match vouch::engine::decide_bash(&cfg, r#""C:\bin\rm.exe" -rf d"#) {
        Decision::Ask(reason) => assert!(reason.contains("delete_recursive"), "got: {reason}"),
        other => panic!("a quoted Windows-absolute head evaded the guard: {other:?}"),
    }
}

#[test]
fn a_unc_rooted_head_also_reaches_its_guard() {
    // The other Windows-rooted shape `base()` recognises: a `\\host\share`
    // UNC prefix rather than a drive letter.
    let cfg = load("version = 1\n[lang.bash]\ndefault = \"allow\"\n").expect("parses");
    match vouch::engine::decide_bash(&cfg, r#""\\host\share\rm.exe" -rf d"#) {
        Decision::Ask(reason) => assert!(reason.contains("delete_recursive"), "got: {reason}"),
        other => panic!("a UNC-rooted head evaded the guard: {other:?}"),
    }
}

#[test]
fn a_relative_backslash_head_is_the_accepted_gap_and_still_asks() {
    // The one shape `base()` deliberately does NOT fold: a relative path
    // with a backslash and no drive letter or UNC prefix. It is read as
    // the literal, undescribed name `bin\rm` — never silently misread as
    // the recognised `rm` entry — so the accepted gap is fail-closed: it
    // asks on unmodeled_command rather than producing a wrong allow.
    let cfg = load("version = 1\n[lang.bash]\ndefault = \"allow\"\n").expect("parses");
    match vouch::engine::decide_bash(&cfg, r#""bin\rm.exe" -rf d"#) {
        Decision::Ask(reason) => {
            assert!(reason.contains("unmodeled_command"), "got: {reason}");
            assert!(
                !reason.contains("delete_recursive"),
                "the accepted gap must not be silently read as the recognised `rm` entry: {reason}"
            );
        }
        other => panic!("a relative backslash head produced something other than the unmodeled ask: {other:?}"),
    }
}

#[test]
fn the_knowledge_under_test_is_not_empty() {
    // Without this, every "for prog in &builtin().program" test below passes
    // vacuously the moment the file cannot be found.
    let kb = builtin();
    assert!(
        !kb.program.is_empty(),
        "no programs loaded — these tests would pass over an empty set. \
         Is .cargo/config.toml present and is VOUCH_KNOWLEDGE set?"
    );
}

// ---------------------------------------------------------------------------
// run_dir(): the directory a run-dir flag (`git -C <dir>`) sends a command to
// run in.
// ---------------------------------------------------------------------------

fn kb() -> vouch::guards::Knowledge {
    vouch::guards::load(
        r#"
[[program]]
match = ["git"]
value_options = ["-C", "-c"]
run_dir_flags = ["-C"]
"#,
    )
    .expect("parses")
}
fn cmd(head: &str, args: &[&str]) -> vouch::syntax::Cmd {
    vouch::syntax::Cmd {
        head: head.into(),
        args: args.iter().map(|s| s.to_string()).collect(),
        unread_args: Default::default(),
        keyword_args: Default::default(),
        callable_args: Default::default(),
        chain: None,
        prefix_assigns: vec![],
        receiver_origin: vouch::syntax::ValueOrigin::Unknown,
        by_reference: false,
    }
}

#[test]
fn run_dir_flag_before_the_subcommand_is_extracted() {
    assert!(matches!(
        vouch::guards::run_dir(&kb(), &cmd("git", &["-C", "/x", "init", "foo"])),
        vouch::guards::RunDir::Dir(d) if d == "/x"
    ));
}
#[test]
fn the_same_token_after_the_subcommand_is_not_a_run_dir_flag() {
    // `git commit -C HEAD` reuses a commit message
    assert!(matches!(
        vouch::guards::run_dir(&kb(), &cmd("git", &["commit", "-C", "HEAD"])),
        vouch::guards::RunDir::Absent
    ));
}
#[test]
fn two_run_dir_flags_are_unresolvable() {
    assert!(matches!(
        vouch::guards::run_dir(&kb(), &cmd("git", &["-C", "a", "-C", "b", "init"])),
        vouch::guards::RunDir::Unresolvable(_)
    ));
}
#[test]
fn a_run_dir_flag_with_no_value_is_unresolvable() {
    assert!(matches!(
        vouch::guards::run_dir(&kb(), &cmd("git", &["init", "x"])),
        vouch::guards::RunDir::Absent
    ));
    assert!(matches!(
        vouch::guards::run_dir(&kb(), &cmd("git", &["-C"])),
        vouch::guards::RunDir::Unresolvable(_)
    ));
}
#[test]
fn matching_is_exact_never_case_folded() {
    // -c is a value option (config), not a run-dir flag
    assert!(matches!(
        vouch::guards::run_dir(&kb(), &cmd("git", &["-c", "u.n=x", "init", "y"])),
        vouch::guards::RunDir::Absent
    ));
}

// [task 7, spec §4.1.6] Run-dir matching stays case-sensitive ALWAYS, even
// when the entry itself declares `case_sensitive_flags = false` — the hard
// invariant `matching_is_exact_never_case_folded` above already pins for an
// entry that leaves the field UNSET. This fixture makes the "unconditional"
// half explicit: an entry that actively opts into case-insensitivity must
// still never fold `-c` into `-C`.
fn kb_case_insensitive_entry() -> vouch::guards::Knowledge {
    vouch::guards::load(
        r#"
[[program]]
match = ["git"]
value_options = ["-C", "-c"]
run_dir_flags = ["-C"]
case_sensitive_flags = false
"#,
    )
    .expect("parses")
}

#[test]
fn run_dir_matching_ignores_an_entrys_own_case_insensitive_declaration() {
    // `git -c core.pager=less log` must NOT derive a run dir (it is a config
    // override, not `-C`) ...
    assert!(matches!(
        vouch::guards::run_dir(
            &kb_case_insensitive_entry(),
            &cmd("git", &["-c", "core.pager=less", "log"])
        ),
        vouch::guards::RunDir::Absent
    ));
    // ... while `git -C dir log` still must, on the SAME entry.
    assert!(matches!(
        vouch::guards::run_dir(&kb_case_insensitive_entry(), &cmd("git", &["-C", "dir", "log"])),
        vouch::guards::RunDir::Dir(d) if d == "dir"
    ));
}

#[test]
fn run_dir_reads_a_short_attached_value_with_no_separating_space() {
    // Task 7: before the shared flag primitive, `-C/x` (no space) matched
    // neither `run_dir_flags` nor `value_options` under the old exact-token
    // comparison, so it was silently invisible — not reported as a run dir,
    // not reported as anything else either, just skipped as an
    // unrecognised token. `flags::classify`'s short-attach reading (`-C` is
    // a declared 2-character value-taking flag) now derives it directly,
    // the same shape M2.128 already fixed for `written_paths`.
    let (d, f) = vouch::guards::run_dir_with_flag(&kb(), &cmd("git", &["-C/x", "init", "foo"]));
    assert!(matches!(d, vouch::guards::RunDir::Dir(ref v) if v == "/x"), "{d:?}");
    assert_eq!(f.as_deref(), Some("-C"));
}

// A knowledge fixture with a THIRD value-consuming flag (`-x`), so a run-dir
// flag token can appear as ITS consumed value rather than as a real run-dir
// flag. `-x`'s own value is coincidentally the run-dir flag's own token
// (`-C`), and `-c`'s own value is coincidentally the run-dir flag's raw
// string (`-c` the token, unrelated) — both must be walked past, not read as
// occurrences of `-C`.
fn kb_with_extra_value_flag() -> vouch::guards::Knowledge {
    vouch::guards::load(
        r#"
[[program]]
match = ["git"]
value_options = ["-C", "-c", "-x"]
run_dir_flags = ["-C"]
"#,
    )
    .expect("parses")
}

#[test]
fn a_run_dir_flag_token_consumed_as_another_flags_value_is_not_a_run_dir_flag() {
    // `-x` consumes "-C" as ITS value; the real `-C` never occurs here.
    assert!(matches!(
        vouch::guards::run_dir(
            &kb_with_extra_value_flag(),
            &cmd("git", &["-x", "-C", "-c", "abc", "init"])
        ),
        vouch::guards::RunDir::Absent
    ));
}

#[test]
fn a_real_run_dir_flag_is_still_found_alongside_other_value_consuming_flags() {
    // `-x` consumes "val" as its own value; the LATER `-C` is a genuine
    // run-dir flag and must still be picked up.
    assert!(matches!(
        vouch::guards::run_dir(
            &kb_with_extra_value_flag(),
            &cmd("git", &["-x", "val", "-C", "/y", "init"])
        ),
        vouch::guards::RunDir::Dir(d) if d == "/y"
    ));
}

// run_dir_with_flag(): the same walk, plus the flag token that named the
// directory. The engine puts that token in the prompt, so it has to come out
// of the SAME walk that chose the value — reporting a flag the walk did not
// use would say the verdict came from somewhere it did not.

#[test]
fn the_flag_reported_is_the_one_the_walk_actually_used() {
    let (d, f) =
        vouch::guards::run_dir_with_flag(&kb(), &cmd("git", &["-C", "/x", "init", "foo"]));
    assert!(matches!(d, vouch::guards::RunDir::Dir(ref v) if v == "/x"), "{d:?}");
    assert_eq!(f.as_deref(), Some("-C"));
}

#[test]
fn no_run_dir_flag_reports_no_token() {
    let (d, f) = vouch::guards::run_dir_with_flag(&kb(), &cmd("git", &["init", "foo"]));
    assert!(matches!(d, vouch::guards::RunDir::Absent), "{d:?}");
    assert_eq!(f, None);
}

#[test]
fn an_unresolvable_run_dir_reports_no_token() {
    // There is no single flag to name, and naming one of two would be a
    // claim about which directory won.
    let (d, f) =
        vouch::guards::run_dir_with_flag(&kb(), &cmd("git", &["-C", "a", "-C", "b", "init"]));
    assert!(matches!(d, vouch::guards::RunDir::Unresolvable(_)), "{d:?}");
    assert_eq!(f, None);
}

#[test]
fn run_dir_and_run_dir_with_flag_can_never_disagree() {
    for args in [
        vec!["-C", "/x", "init", "foo"],
        vec!["init", "foo"],
        vec!["-C", "a", "-C", "b", "init"],
        vec!["-C"],
        vec!["commit", "-C", "HEAD"],
    ] {
        let c = cmd("git", &args);
        assert_eq!(
            vouch::guards::run_dir(&kb(), &c),
            vouch::guards::run_dir_with_flag(&kb(), &c).0,
            "disagreed on {args:?}"
        );
    }
}

// subcommand_of(): the verb a prompt has to name when it says which argument
// it could not classify. Working it out with a second rule ("the first
// argument without a dash") picks a value option's VALUE the moment one is
// present, and the prompt then names the wrong thing to look at.

#[test]
fn the_subcommand_is_read_past_a_value_options_value() {
    assert_eq!(
        vouch::guards::subcommand_of(&kb(), &cmd("git", &["-C", "/x", "init", "foo"])),
        Some("init"),
        "a run-dir flag's value was read as the subcommand"
    );
    assert_eq!(
        vouch::guards::subcommand_of(&kb(), &cmd("git", &["init", "foo"])),
        Some("init")
    );
    assert_eq!(vouch::guards::subcommand_of(&kb(), &cmd("git", &["--bare"])), None);
}

// ---------------------------------------------------------------------------
// written_paths(): the hardened destination walk (Task 6).
//
// A knowledge fixture with the consolidated `git` shape: `value_options`
// covers every flag that consumes a following token (including ones that can
// appear after the subcommand, like `--depth` and `-b`), `no_value_options`
// covers the flags that take none, and `init` is declared `takes = "run_dir"`
// so a bare `git init` writes to the run directory itself.
// ---------------------------------------------------------------------------

fn write_kb() -> vouch::guards::Knowledge {
    vouch::guards::load(
        r#"
[[program]]
match = ["git"]
value_options = ["-C", "-c", "--git-dir", "--work-tree", "--namespace", "--depth", "-b"]
no_value_options = ["-q", "--quiet", "--bare", "--detach"]

[[program.sub_write]]
subcommand = "clone"
min_positional = 2

[[program.sub_write]]
subcommand = "init"
takes = "run_dir"

[[program.sub_write]]
subcommand = "worktree"
then = "add"
min_positional = 1
takes = "first"
"#,
    )
    .expect("parses")
}

fn wp(cmd_str: &str) -> vouch::guards::WriteTargets {
    let p = parse(cmd_str).expect("parses");
    let c = p.commands.first().expect("exactly one command");
    vouch::guards::written_paths(&write_kb(), c)
}

#[test]
fn a_flags_value_is_consumed_not_judged_as_the_destination() {
    // Old bug: the sub_write walk kept flag VALUES as positionals, so
    // `--depth 1` left `1` looking like a candidate destination.
    let t = wp("git clone url /x --depth 1");
    assert_eq!(t.paths, vec!["/x".to_string()], "got {t:?}");
}

#[test]
fn a_no_value_options_flag_before_the_destination_is_skipped_not_unknowable() {
    // `-q` is declared in `no_value_options`: it takes nothing, so it must be
    // skipped in place rather than reported as an undescribed flag that
    // withholds the destination. Pins the measured ASK->ALLOW class: before
    // `no_value_options` was consulted here, any flag the walk did not
    // recognise as VALUE-taking made the destination unknowable, so a plain
    // no-value flag like `-q` wrongly asked instead of resolving `/x`.
    let t = wp("git clone -q url /x");
    assert_eq!(t.paths, vec!["/x".to_string()], "got {t:?}");
    assert!(t.unknowable.is_empty(), "got {t:?}");
}

#[test]
fn worktree_add_takes_its_directory_first_by_index() {
    let t = wp("git worktree add -b topic /x/wt");
    assert_eq!(t.paths, vec!["/x/wt".to_string()], "got {t:?}");
}

#[test]
fn an_undescribed_post_subcommand_flag_is_unknowable_and_the_path_is_withheld() {
    // vouch cannot tell whether `--frobnicate` takes a value, so it cannot
    // trust the positional count or order after it — the destination is
    // withheld rather than guessed, and the flag is reported instead.
    let t = wp("git clone url /x --frobnicate");
    assert!(t.paths.is_empty(), "a destination was guessed anyway: {t:?}");
    assert_eq!(t.unknowable, vec!["--frobnicate".to_string()], "got {t:?}");
}

#[test]
fn a_consumed_flag_value_does_not_count_toward_min_positional() {
    // `-c`'s value is `k=v`, consumed post-subcommand; only `url` is left, one
    // short of clone's `min_positional = 2`.
    let t = wp("git clone -c k=v url");
    assert!(t.paths.is_empty(), "got {:?}", t.paths);
    assert!(t.unknowable.is_empty(), "got {:?}", t.unknowable);
}

#[test]
fn the_walk_anchors_on_the_subcommands_index_not_on_string_equality() {
    // Old bug: `skip_while(a != sub)` found the FIRST token equal to "init",
    // which here is `-C`'s value, not the subcommand.
    let t = wp("git -C init init foo");
    assert_eq!(t.paths, vec!["foo".to_string()], "got {t:?}");
}

#[test]
fn bare_init_with_zero_positionals_is_a_run_dir_destination() {
    let t = wp("git init");
    assert!(t.run_dir_dest, "expected run_dir_dest, got {t:?}");
    assert!(t.paths.is_empty(), "got {t:?}");
}

#[test]
fn init_with_a_positional_behaves_as_first_not_run_dir() {
    let t = wp("git init foo");
    assert_eq!(t.paths, vec!["foo".to_string()], "got {t:?}");
    assert!(!t.run_dir_dest, "got {t:?}");
}

#[test]
fn a_then_mismatch_does_not_discard_unknowable_evidence() {
    // [review, task 6 fix] The `then` filter used to `continue` before the
    // `!unk.is_empty()` check ran, so an undescribed value-taking flag
    // between the subcommand and the `then` word discarded the evidence and
    // fell through as if the command wrote nothing. An undescribed flag
    // shifts the positional list, so a `then` mismatch never proves the
    // second word is absent — `--reason` could take a value or not; vouch
    // does not know, so it must not go quiet about `worktree add`.
    let t = wp("git worktree --reason cleanup add /x/wt");
    assert!(!t.unknowable.is_empty(), "the unknowable flag was discarded: {t:?}");
    assert!(t.paths.is_empty(), "a destination was guessed anyway: {t:?}");
}

// --- attached-value form: `--flag=value` as one token ----------------------

#[test]
fn an_attached_value_on_a_described_flag_consumes_nothing_and_is_not_a_positional() {
    // `--depth=1` is one token; `--depth` is in value_options. It must be
    // self-contained: not a positional, not unknowable, and the real
    // destination is still found past it.
    let t = wp("git clone url --depth=1 /x");
    assert_eq!(t.paths, vec!["/x".to_string()], "got {t:?}");
    assert!(t.unknowable.is_empty(), "got {:?}", t.unknowable);
}

#[test]
fn an_attached_value_on_an_undescribed_flag_is_unknowable() {
    let t = wp("git clone url /x --frob=cleanup");
    assert!(t.paths.is_empty(), "a destination was guessed anyway: {t:?}");
    assert_eq!(t.unknowable, vec!["--frob=cleanup".to_string()], "got {t:?}");
}

#[test]
fn a_subcommand_with_no_sub_write_produces_nothing_at_all() {
    // No sub_write entry names "status", so the walk never runs for it — an
    // undescribed flag after a non-destination subcommand must not become an
    // unknowable entry.
    let t = wp("git status");
    assert!(t.paths.is_empty(), "got {t:?}");
    assert!(t.unknowable.is_empty(), "got {t:?}");
    assert!(!t.run_dir_dest, "got {t:?}");
}

// ---------------------------------------------------------------------------
// written_paths(): the write_flags arm reads the shared flag primitive
// (Task 6, M2.128) — a refused abbreviation on a case-sensitive entry must
// be LOUD, not silently matched and not silently dropped.
//
// No shipped `write_flags` entry can trigger this today: every case-
// sensitive one (`cp`/`mv`/…, `curl`, `wget`, `tar`, `unzip`, `sort`)
// declares only <=2-char short flags or `--` GNU long flags, and
// `is_abbrev_candidate_shape` (flags.rs) only ever treats a single-dash
// name LONGER than 2 characters as an abbreviation candidate — so the
// mechanism was proven only in isolation (`flags.rs`'s own unit tests), not
// through `written_paths` itself. This fixture manufactures the shape
// deliberately, the same way `write_kb()` above manufactures git shapes
// that the shipped file's own entry does not need for its OWN tests.
// ---------------------------------------------------------------------------

fn write_flags_kb() -> vouch::guards::Knowledge {
    vouch::guards::load(
        r#"
[[program]]
match = ["frobcopy"]
writes = "flags_only"
write_flags = ["-destination"]
case_sensitive_flags = true
"#,
    )
    .expect("parses")
}

fn write_flags_wp(cmd_str: &str) -> vouch::guards::WriteTargets {
    let p = parse(cmd_str).expect("parses");
    let c = p.commands.first().expect("exactly one command");
    vouch::guards::written_paths(&write_flags_kb(), c)
}

#[test]
fn a_refused_abbreviation_on_a_write_flag_is_unknowable_not_a_silent_match_or_drop() {
    // `-dest` is a proper single-dash prefix of the declared `-destination`
    // — exactly the shape `Abbrev::Refuse` (case_sensitive_flags = true, the
    // derivation policy per spec §4.1.7) reports as `Spell::RefusedAbbrev`
    // rather than folding into an accepted match OR a plain non-match.
    // `writes = "flags_only"` (not "named") so there is no positional
    // fallback to confound the read: an empty `paths` here can only mean the
    // refused candidate was neither matched nor silently ignored.
    let t = write_flags_wp("frobcopy -dest C:/out u");
    assert!(t.paths.is_empty(), "a destination was guessed anyway: {t:?}");
    assert_eq!(t.unknowable, vec!["-dest".to_string()], "the refused abbreviation was not reported: {t:?}");
}

// ---------------------------------------------------------------------------
// written_paths(): the python argument model — keyword folding onto claimed
// positions, the file-mode rule, and the fail-closed floor for absent or
// unreadable positions (Task 7).
// ---------------------------------------------------------------------------

fn open_kb() -> vouch::guards::Knowledge {
    vouch::guards::load(
        r#"
[[program]]
match = ["python:open"]
writes = "arg_0"
writes_only_with_file_mode = true
arg_names = ["file", "mode"]
"#,
    )
    .expect("parses")
}

fn py_cmd(src: &str) -> vouch::shell::Cmd {
    let scan = vouch::python::parse(src).expect("parses");
    scan.commands.into_iter().next().expect("exactly one call")
}

fn py_written(kb: &vouch::guards::Knowledge, src: &str) -> vouch::guards::WriteTargets {
    vouch::guards::written_paths(kb, &py_cmd(src))
}

fn effective_open_args(src: &str) -> vouch::guards::EffectiveArgs {
    let kb = open_kb();
    vouch::guards::effective_args(&kb.program[0], &py_cmd(src))
}

#[test]
fn effective_python_arguments_preserve_keyword_positions_and_readability() {
    let positional = effective_open_args(r#"open("C:/t/x", "w")"#);
    assert_eq!(positional.values, vec!["C:/t/x", "w"]);
    assert!(positional.unread.is_empty());
    assert!(positional.padding.is_empty());

    let equals_literal = effective_open_args(r#"open("file=C:/t/x")"#);
    assert_eq!(equals_literal.values, vec!["file=C:/t/x"]);
    assert!(equals_literal.unread.is_empty());
    assert!(equals_literal.padding.is_empty());

    let keyword = effective_open_args(r#"open(mode="w", file=value)"#);
    assert_eq!(keyword.values, vec!["$value", "w"]);
    assert_eq!(keyword.unread, std::collections::HashSet::from([0]));
    assert!(keyword.padding.is_empty());
}

#[test]
fn effective_python_arguments_distinguish_padding_and_literal_marker_text() {
    let padded = effective_open_args(r#"open(mode="w")"#);
    assert_eq!(padded.padding, std::collections::HashSet::from([0]));
    assert!(padded.unread.is_empty());

    let literal = effective_open_args(r#"open(file="$?", mode="w")"#);
    assert_eq!(literal.values, vec!["$?", "w"]);
    assert!(
        literal.unread.is_empty(),
        "literal marker text is still readable"
    );
    assert!(literal.padding.is_empty());
}

#[test]
fn callback_and_unpack_detection_use_structural_argument_metadata() {
    let kb = vouch::guards::load(
        r#"
[[program]]
match = ["python:open"]
arg_names = ["file", "mode", "buffering", "encoding", "errors", "newline", "closefd", "opener"]
callback_args = ["opener"]
"#,
    )
    .expect("parses");
    assert!(!vouch::guards::callback_argument_used(
        &kb,
        &py_cmd(r#"open("opener=value")"#)
    ));
    assert!(!vouch::guards::callback_argument_used(
        &kb,
        &py_cmd(r#"open("$**")"#)
    ));
    // A subscript is neither a plain literal (so it is `unread`) nor
    // `Name`/`Attribute`/`Lambda` (so `argument_callable`, src/python.rs,
    // never marks it `CallableArg` at all) — the genuine "occupied, unread,
    // not callable" shape rule 1 exists for, unchanged by finding 1.
    assert!(vouch::guards::callback_argument_used(
        &kb,
        &py_cmd(r#"open("x", opener=handlers[0])"#)
    ));
}

/// Finding 1 (task-final-review, spec §5.2 per-slot exclusivity): a bare
/// `Name` reference is ALSO `unread` (it is not literal text vouch can
/// read as a string, same as the subscript above), so before this fix it
/// tripped rule 1 on the strength of occupancy alone — on top of whatever
/// `by_reference_invocations` (M2.89) already said about the same `value`
/// reference. `callable_ref` (src/python.rs:649) resolves a never-rebound
/// bare name straight through to `CallableArg::Named` — the same path
/// `len`, `int`, and `os.path.basename` take — so `value` here is judged
/// specifically (by reference; unevaluable, since no `python:value` entry
/// describes it) rather than generically, and `callback_argument_used`
/// must no longer also fire for this slot.
#[test]
fn a_callable_marked_occupant_is_excluded_here_and_judged_by_reference_instead() {
    let kb = vouch::guards::load(
        r#"
[[program]]
match = ["python:open"]
arg_names = ["file", "mode", "buffering", "encoding", "errors", "newline", "closefd", "opener"]
callback_args = ["opener"]
"#,
    )
    .expect("parses");
    assert!(!vouch::guards::callback_argument_used(
        &kb,
        &py_cmd(r#"open("x", opener=value)"#)
    ));
}

#[test]
fn a_positional_write_mode_applies_the_write_claim() {
    let t = py_written(&open_kb(), r#"open("C:/t/x", "w")"#);
    assert_eq!(t.paths, vec!["C:/t/x".to_string()], "got {t:?}");
}

#[test]
fn no_mode_at_all_is_a_read() {
    // python's documented default for `open` with no mode given is a
    // text read, so no mode at all is a true "reads only" claim.
    let t = py_written(&open_kb(), r#"open("C:/t/x")"#);
    assert!(t.paths.is_empty(), "got {t:?}");
}

#[test]
fn a_read_mode_is_a_read() {
    let t = py_written(&open_kb(), r#"open("C:/t/x", "rb")"#);
    assert!(t.paths.is_empty(), "got {t:?}");
}

#[test]
fn an_encoding_value_containing_w_is_not_a_write_mode() {
    // "encoding" is not in this entry's arg_names, so the keyword never
    // folds onto the claimed mode position — that position stays absent,
    // which reads as python's documented default (a read), regardless of
    // what letters the encoding value itself contains.
    let t = py_written(&open_kb(), r#"open("C:/t/x", encoding="windows-1252")"#);
    assert!(t.paths.is_empty(), "got {t:?}");
}

#[test]
fn an_all_keyword_write_is_judged() {
    let t = py_written(&open_kb(), r#"open(file="C:/t/x", mode="w")"#);
    assert_eq!(t.paths, vec!["C:/t/x".to_string()], "got {t:?}");
}

#[test]
fn an_unresolved_mode_applies_the_write_claim() {
    // `m` is never assigned a literal value in this snippet, so it stays
    // unresolved — a write cannot be ruled out, so the write claim applies.
    let t = py_written(&open_kb(), r#"open("C:/t/x", m)"#);
    assert_eq!(t.paths, vec!["C:/t/x".to_string()], "got {t:?}");
}

#[test]
fn an_unresolvable_receiver_is_an_unresolved_written_path() {
    let kb = vouch::guards::load(
        r#"
[[program]]
match = ["python:.mkdir"]
writes = "arg_0"
"#,
    )
    .expect("parses");
    // `p` is never assigned a literal value, so the receiver — a
    // method-shaped call's own position 0 — stays that name's marker. It
    // flows to the unresolved_path ask downstream (marker-as-target here;
    // one end-to-end ASK test lands in Task 11).
    let t = py_written(&kb, "p.mkdir()");
    assert_eq!(t.paths, vec!["$p".to_string()], "got {t:?}");
}

#[test]
fn a_claimed_position_that_is_absent_fails_closed() {
    // A copy-shape entry: writes = "arg_1", the destination argument.
    let kb = vouch::guards::load(
        r#"
[[program]]
match = ["python:shutil.copy"]
writes = "arg_1"
"#,
    )
    .expect("parses");
    let t = py_written(&kb, "import shutil\nshutil.copy(\"C:/t/a\")");
    assert_eq!(t.paths, vec!["$?".to_string()], "got {t:?}");
}

#[test]
fn an_unfolded_keyword_is_never_a_write_target() {
    // No arg_names on this entry, so a keyword token can never be folded
    // onto any claimed position — the position-0 target must be the marker,
    // never the raw "name=value" token and never just the value.
    let kb = vouch::guards::load(
        r#"
[[program]]
match = ["python:open"]
writes = "arg_0"
"#,
    )
    .expect("parses");
    let t = py_written(&kb, r#"open(file="C:/t/x")"#);
    assert_eq!(t.paths, vec!["$?".to_string()], "got {t:?}");

    let literal = py_written(&kb, r#"open("file=C:/t/x")"#);
    assert_eq!(literal.paths, vec!["file=C:/t/x".to_string()], "got {literal:?}");
}

#[test]
fn a_positional_path_containing_equals_is_not_mistaken_for_a_keyword() {
    // "a=b.txt" is a plain positional literal that happens to contain a
    // literal `=`. The scanner's structural keyword-position set, not the
    // token text or a neighbouring positional, proves which syntax produced
    // it.
    let t = py_written(&open_kb(), r#"open("C:/t/a=b.txt", "w")"#);
    assert_eq!(t.paths, vec!["C:/t/a=b.txt".to_string()], "got {t:?}");
}

#[test]
fn a_swapped_keyword_order_still_resolves_the_path() {
    // python places no ordering requirement on keyword arguments — the
    // fold must land both `mode` and `file` at their claimed positions
    // whichever order the call states them in. Fold-order review, I2.
    let t = py_written(&open_kb(), r#"open(mode="w", file="C:/t/x")"#);
    assert_eq!(t.paths, vec!["C:/t/x".to_string()], "got {t:?}");
}

// ---------------------------------------------------------------------------
// expand_wrappers_with_sources(): the wrap arms — after_flag's shape-aware
// attachment (separate, attached-short, attached-long-with-equals), the
// arg_<N> arm, and the scan_snippet split they now share (Task 8).
// ---------------------------------------------------------------------------

fn wrap_srcs(kb: &vouch::guards::Knowledge, c: &vouch::syntax::Cmd) -> Vec<(String, String)> {
    vouch::guards::expand_wrappers_with_sources(
        kb,
        std::slice::from_ref(c),
        &[],
        &[],
        &[],
        "bash",
        &|_| 4,
    )
    .srcs
}

fn expand_bash_source(src: &str) -> vouch::guards::ExpandedWrappers {
    let scan = vouch::shell::parse(src).expect("bash parses");
    vouch::guards::expand_wrappers_with_sources(
        builtin(),
        &scan.commands,
        &scan.heredocs,
        &scan.input_source,
        &scan.args_complete,
        "bash",
        &|_| 4,
    )
}

#[test]
fn parsed_python_snippets_keep_one_child_scope_and_their_local_order() {
    let expanded = expand_bash_source(r#"python -c "first(); second()""#);
    assert_eq!(expanded.execution_sites.len(), expanded.cmds.len());
    assert_eq!(expanded.scope_parents, vec![0]);

    let first = expanded
        .cmds
        .iter()
        .position(|command| command.head == "python:first")
        .unwrap();
    let second = expanded
        .cmds
        .iter()
        .position(|command| command.head == "python:second")
        .unwrap();
    assert_eq!(expanded.execution_sites[first].scope, 1);
    assert!(expanded.execution_sites[first].scanner_order);
    assert_eq!(
        expanded.execution_sites[first].local_order,
        Some(vouch::syntax::Order::Seq(0))
    );
    assert_eq!(expanded.execution_sites[second].scope, 1);
    assert!(expanded.execution_sites[second].scanner_order);
    assert_eq!(
        expanded.execution_sites[second].local_order,
        Some(vouch::syntax::Order::Seq(1))
    );
}

#[test]
fn nested_and_held_snippets_keep_parent_indices_without_desynchronising() {
    let nested = expand_bash_source(r#"python -c "import os; os.system('echo hi')""#);
    let system = nested
        .cmds
        .iter()
        .position(|command| command.head == "python:os.system")
        .unwrap();
    let echo = nested
        .cmds
        .iter()
        .position(|command| command.head == "echo")
        .unwrap();
    assert_eq!(nested.scope_parents, vec![0, system]);
    assert_eq!(nested.execution_sites[system].scope, 1);
    assert_eq!(nested.execution_sites[echo].scope, 2);

    let held = expand_bash_source("python - <<'PY'\nfirst()\nPY");
    let first = held
        .cmds
        .iter()
        .position(|command| command.head == "python:first")
        .unwrap();
    assert_eq!(held.scope_parents, vec![0]);
    assert_eq!(held.execution_sites[first].scope, 1);
    assert_eq!(
        held.execution_sites[first].local_order,
        Some(vouch::syntax::Order::Seq(0))
    );
}

#[test]
fn synthetic_rest_wrapper_commands_do_not_mint_a_parsed_scope() {
    let kb = vouch::guards::load(
        r#"
[[program]]
match = ["env9"]
wraps = "rest"
"#,
    )
    .unwrap();
    let expanded = expand(&kb, &cmd("env9", &["alpha"]));
    assert!(expanded.scope_parents.is_empty());
    assert_eq!(expanded.execution_sites.len(), expanded.cmds.len());
    assert!(expanded
        .execution_sites
        .iter()
        .all(|site| site.scope == 0 && site.local_order.is_none() && !site.scanner_order));
}

#[test]
fn the_attached_spelling_yields_the_identical_snippet() {
    let kb = vouch::guards::load(
        r#"
[[program]]
match = ["x"]
wraps = "after_flag"
wrap_flags = ["-c"]
wrap_lang = "bash"
"#,
    )
    .expect("parses");
    let attached = wrap_srcs(&kb, &cmd("x", &["-c'true'"]));
    let separate = wrap_srcs(&kb, &cmd("x", &["-c", "'true'"]));
    assert_eq!(attached, separate, "got attached={attached:?} separate={separate:?}");
    assert_eq!(attached, vec![("bash".to_string(), "true".to_string())]);
}

#[test]
fn a_long_flag_attaches_only_with_an_equals_sign() {
    let kb = vouch::guards::load(
        r#"
[[program]]
match = ["x"]
wraps = "after_flag"
wrap_flags = ["--eval"]
wrap_lang = "bash"
"#,
    )
    .expect("parses");
    assert_eq!(
        wrap_srcs(&kb, &cmd("x", &["--eval=true"])),
        vec![("bash".to_string(), "true".to_string())]
    );
    assert_eq!(
        wrap_srcs(&kb, &cmd("x", &["--evaltrue"])),
        Vec::<(String, String)>::new(),
        "a token that merely starts with the flag's text is not the flag"
    );
}

#[test]
fn attachment_respects_the_entry_case_rule() {
    let kb = vouch::guards::load(
        r#"
[[program]]
match = ["xcs"]
wraps = "after_flag"
wrap_flags = ["-c"]
wrap_lang = "bash"
case_sensitive_flags = true

[[program]]
match = ["xci"]
wraps = "after_flag"
wrap_flags = ["-c"]
wrap_lang = "bash"
"#,
    )
    .expect("parses");
    assert_eq!(
        wrap_srcs(&kb, &cmd("xcs", &["-Ctrue"])),
        Vec::<(String, String)>::new(),
        "case_sensitive_flags = true must not read -C as this entry's -c flag"
    );
    assert_eq!(
        wrap_srcs(&kb, &cmd("xci", &["-Ctrue"])),
        vec![("bash".to_string(), "true".to_string())],
        "an entry that never states case sensitivity keeps the existing case-folded match"
    );
}

#[test]
fn a_single_token_entry_does_not_absorb_trailing_argv() {
    // No wrap_join set — python's own shape: -c takes exactly the next
    // token as the snippet, and everything after it is the script's argv.
    let kb = vouch::guards::load(
        r#"
[[program]]
match = ["x"]
wraps = "after_flag"
wrap_flags = ["-c"]
wrap_lang = "bash"
"#,
    )
    .expect("parses");
    assert_eq!(
        wrap_srcs(&kb, &cmd("x", &["-c", "\"true\"", "arg1", "arg2"])),
        vec![("bash".to_string(), "true".to_string())]
    );
}

#[test]
fn a_wrap_join_entry_still_rejoins() {
    // The shipped cmd entry: its snippet genuinely spreads over every token
    // after the flag, so wrap_join = true rejoins them. INVERTED (§2.2 item
    // 7, M2.125/§5.2.4): cmd batch is not bash, so the tag is now cmd's own
    // name — this used to come back tagged "bash", a silent laundering of
    // unread text into a scanned one.
    assert_eq!(
        wrap_srcs(builtin(), &cmd("cmd", &["/c", "echo", "a", "b"])),
        vec![("cmd".to_string(), "echo a b".to_string())]
    );
}

#[test]
fn a_double_dash_ends_option_scanning_so_a_later_dash_c_is_not_the_flag() {
    // INVERTED, Task 9 (spec §2.2 item 9, §4.1.4). The locator used to find
    // `-c` after a bare `--` by raw token text, which the comment here
    // defended as a conservative over-read. It is not conservative — it is a
    // different command: real python treats `--` as end of options, so what
    // follows is a SCRIPT FILENAME and the text after it is that script's
    // argv, not a snippet. Scanning it judged text the interpreter never
    // runs, and the shared flag rule (`ArgWalk`) now stops classifying at
    // `--` for every consumer alike.
    //
    // Nothing is silently dropped by the change: with no wrap flag in scope
    // this is a python invocation with no `-c`, which the entry's own
    // `evaluates_input = "stdin"` claim speaks for.
    assert_eq!(
        wrap_srcs(builtin(), &cmd("python", &["--", "-c", "\"print(1)\""])),
        Vec::<(String, String)>::new()
    );
}

#[test]
fn a_non_ascii_token_never_panics_the_match() {
    let kb = vouch::guards::load(
        r#"
[[program]]
match = ["x"]
wraps = "after_flag"
wrap_flags = ["-c"]
wrap_lang = "bash"
"#,
    )
    .expect("parses");
    // "é" is two bytes in UTF-8, so byte offset 2 falls inside it rather
    // than on a char boundary — the attached-spelling check must skip this
    // token cleanly rather than slice at a fixed byte offset.
    assert_eq!(wrap_srcs(&kb, &cmd("x", &["-éfoo"])), Vec::<(String, String)>::new());
}

#[test]
fn an_arg_position_wrap_reaches_the_declared_language_scanner() {
    let kb = vouch::guards::load(
        r#"
[[program]]
match = ["python:x.y"]
wraps = "arg_0"
wrap_lang = "bash"
"#,
    )
    .expect("parses");
    let ex = vouch::guards::expand_wrappers_with_sources(
        &kb,
        std::slice::from_ref(&cmd("python:x.y", &["echo hi"])),
        &[],
        &[],
        &[],
        "bash",
        &|_| 4,
    );
    let vouch::guards::ExpandedWrappers { cmds, srcs, .. } = ex;
    assert_eq!(srcs, vec![("bash".to_string(), "echo hi".to_string())]);
    assert!(
        cmds.iter().any(|c| c.head == "echo" && c.args == vec!["hi".to_string()]),
        "expected an inner echo command, got {cmds:?}"
    );
    assert_eq!(
        wrap_srcs(&kb, &cmd("python:x.y", &["$?"])),
        Vec::<(String, String)>::new(),
        "the unresolved marker must not be treated as a snippet"
    );
}

// ---------------------------------------------------------------------------
// Task 9 (spec §3.1): every wrap arm answers with a located payload, a
// genuine "wrapped nothing", or a construct — never with an empty scan that
// looks like both.
// ---------------------------------------------------------------------------

fn expand(kb: &vouch::guards::Knowledge, c: &vouch::syntax::Cmd) -> vouch::guards::ExpandedWrappers {
    vouch::guards::expand_wrappers_with_sources(
        kb,
        std::slice::from_ref(c),
        &[],
        &[],
        &[],
        "bash",
        &|_| 4,
    )
}

fn construct_keys(ex: &vouch::guards::ExpandedWrappers) -> Vec<String> {
    ex.constructs.iter().map(|(k, _)| k.clone()).collect()
}

#[test]
fn a_wrap_slot_holding_an_unreadable_value_raises_evaluated_input() {
    // The command string is known to EXIST and known to be unreadable, which
    // is that construct's exact meaning — distinct from a call whose declared
    // position is simply not there.
    let kb = vouch::guards::load(
        r#"
[[program]]
match = ["python:x.y"]
wraps = "arg_0"
wrap_lang = "bash"
"#,
    )
    .expect("parses");
    assert_eq!(construct_keys(&expand(&kb, &cmd("python:x.y", &["$?"]))), vec!["evaluated_input"]);
    assert_eq!(construct_keys(&expand(&kb, &cmd("python:x.y", &["$**"]))), vec!["evaluated_input"]);
    assert!(
        construct_keys(&expand(&kb, &cmd("python:x.y", &[]))).is_empty(),
        "a call with no argument at the declared position wraps nothing and says nothing"
    );
}

#[test]
fn a_clustered_short_flag_still_finds_the_wrapped_snippet() {
    // python's own binding: `-c` consumes its value, so in a cluster the
    // letters BEFORE it are switches and everything after it is the value.
    let kb = vouch::guards::load(
        r#"
[[program]]
match = ["py9"]
wraps = "after_flag"
wrap_flags = ["-c"]
wrap_lang = "bash"
case_sensitive_flags = true
value_options = ["-c"]
no_value_options = ["-S", "-u"]
"#,
    )
    .expect("parses");
    let want = vec![("bash".to_string(), "true".to_string())];
    assert_eq!(wrap_srcs(&kb, &cmd("py9", &["-Sc", "true"])), want, "cluster, wrap letter last");
    assert_eq!(wrap_srcs(&kb, &cmd("py9", &["-Suc", "true"])), want, "two described switches");
    assert_eq!(wrap_srcs(&kb, &cmd("py9", &["-Sctrue"])), want, "value attached inside the cluster");
    let ex = expand(&kb, &cmd("py9", &["-Zc", "true"]));
    assert_eq!(
        ex.srcs,
        Vec::<(String, String)>::new(),
        "an undescribed letter in front of the wrap letter is not read as a cluster"
    );
    assert_eq!(
        construct_keys(&ex),
        vec!["wrap_unlocated"],
        "and refusing to read it is said out loud, not returned as an empty scan"
    );
}

#[test]
fn an_undescribed_letter_beside_the_wrap_letter_is_loud() {
    // The token says the wrap letter is there and vouch cannot parse the rest
    // of it — the backstop `wrap_unlocated` exists for.
    let kb = vouch::guards::load(
        r#"
[[program]]
match = ["sh9"]
wraps = "after_c"
wrap_flags = ["-c"]
wrap_lang = "bash"
case_sensitive_flags = true
no_value_options = ["-c", "-l"]
"#,
    )
    .expect("parses");
    assert_eq!(
        wrap_srcs(&kb, &cmd("sh9", &["-lc", "true"])),
        vec![("bash".to_string(), "true".to_string())],
        "a fully described cluster locates the script"
    );
    assert_eq!(
        construct_keys(&expand(&kb, &cmd("sh9", &["-zc", "true"]))),
        vec!["wrap_unlocated"]
    );
    assert!(
        construct_keys(&expand(&kb, &cmd("sh9", &["script.sh"]))).is_empty(),
        "no wrap flag at all is wrapping nothing, not a miss"
    );
}

#[test]
fn every_exec_occurrence_is_expanded_and_a_missing_terminator_is_loud() {
    let kb = vouch::guards::load(
        r#"
[[program]]
match = ["find9"]
wraps = "after_exec"
wrap_exec_flags = ["-exec", "-ok"]
wrap_exec_terminators = [";", "+"]
case_sensitive_flags = true
"#,
    )
    .expect("parses");
    let ex = expand(&kb, &cmd("find9", &["d", "-exec", "alpha", ";", "-ok", "beta", "x", ";"]));
    let heads: Vec<String> = ex.cmds.iter().map(|c| c.head.clone()).collect();
    assert_eq!(heads, vec!["find9", "alpha", "beta"], "only the first occurrence used to expand");
    assert!(construct_keys(&ex).is_empty(), "both occurrences terminated: {:?}", ex.constructs);

    let ex = expand(&kb, &cmd("find9", &["d", "-exec", "alpha", "x"]));
    assert_eq!(construct_keys(&ex), vec!["wrap_unlocated"]);
    assert_eq!(
        ex.cmds.iter().map(|c| c.head.clone()).collect::<Vec<_>>(),
        vec!["find9"],
        "an unterminated exec yields no command to judge, and says so"
    );
}

#[test]
fn a_wrapper_run_dir_flag_moves_what_it_wraps() {
    let kb = vouch::guards::load(
        r#"
[[program]]
match = ["env9"]
wraps = "rest"
case_sensitive_flags = true
value_options = ["-C"]
run_dir_flags = ["-C"]
"#,
    )
    .expect("parses");
    let ex = expand(&kb, &cmd("env9", &["-C", "C:/tmp", "alpha", "x"]));
    assert_eq!(
        ex.cmds.iter().map(|c| c.head.clone()).collect::<Vec<_>>(),
        vec!["env9", "alpha"]
    );
    assert_eq!(
        ex.inherited_run_dir,
        vec![None, Some("C:/tmp".to_string())],
        "the inner command carries no -C of its own, so the wrapper's has to travel with it"
    );
}

#[test]
fn a_rest_wrapper_records_the_env_words_it_crossed() {
    let kb = vouch::guards::load(
        r#"
[[program]]
match = ["env9"]
wraps = "rest"
case_sensitive_flags = true
"#,
    )
    .expect("parses");
    let ex = expand(&kb, &cmd("env9", &["FOO=1", "BAR=2", "alpha", "x"]));
    let inner = ex.cmds.iter().find(|c| c.head == "alpha").expect("the wrapped command");
    assert_eq!(inner.prefix_assigns, vec!["FOO".to_string(), "BAR".to_string()]);
}

#[test]
fn a_declared_leading_positional_is_crossed_and_an_undeclared_one_is_not() {
    let kb = vouch::guards::load(
        r#"
[[program]]
match = ["one9"]
wraps = "rest"
leading_args = 1
case_sensitive_flags = true

[[program]]
match = ["none9"]
wraps = "rest"
case_sensitive_flags = true
"#,
    )
    .expect("parses");
    let heads = |c: &vouch::syntax::Cmd| {
        expand(&kb, c).cmds.iter().map(|x| x.head.clone()).collect::<Vec<_>>()
    };
    assert_eq!(heads(&cmd("one9", &["5", "alpha"])), vec!["one9", "alpha"]);
    assert_eq!(
        heads(&cmd("none9", &["5", "alpha"])),
        vec!["none9", "5"],
        "a wrapper that declares no leading positional runs whatever comes first"
    );
}

#[test]
fn an_argument_list_that_is_an_array_expression_is_loud() {
    let kb = vouch::guards::load(
        r#"
[[program]]
match = ["sp9"]
wraps = "start_process"
wrap_flags = ["-ArgumentList"]
"#,
    )
    .expect("parses");
    let ex = expand(&kb, &cmd("sp9", &["alpha", "-ArgumentList", "@(\"-Command\",\"beta\")"]));
    assert_eq!(construct_keys(&ex), vec!["wrap_unlocated"]);
}

#[test]
fn a_located_argument_list_with_no_resolvable_program_is_loud() {
    // The backstop the arm has to carry (fix round 1, spec §3.1's preamble):
    // once the declared list parameter is present, "vouch could not tell what
    // is being started" is a MISS, never "this wrapped nothing". The two are
    // indistinguishable to the caller, and that one ambiguity is what let a
    // located payload through unjudged.
    let kb = vouch::guards::load(
        r#"
[[program]]
match = ["sp9"]
wraps = "start_process"
wrap_flags = ["-ArgumentList"]
value_options = ["-ArgumentList", "-Verb"]
"#,
    )
    .expect("parses");
    let ex = expand(&kb, &cmd("sp9", &["-Verb", "runas", "-ArgumentList", "-Command,beta"]));
    assert_eq!(
        construct_keys(&ex),
        vec!["wrap_unlocated"],
        "every token is spoken for by a flag, so no program was resolved"
    );
    // No declared list parameter at all is still the genuine "wraps nothing".
    assert!(construct_keys(&expand(&kb, &cmd("sp9", &["alpha"]))).is_empty());
}

#[test]
fn a_program_named_by_a_declared_head_flag_is_found() {
    let kb = vouch::guards::load(
        r#"
[[program]]
match = ["sp9"]
wraps = "start_process"
wrap_flags = ["-ArgumentList"]
wrap_head_flags = ["-FilePath"]
value_options = ["-ArgumentList", "-FilePath", "-Verb"]
no_value_options = ["-Wait"]
"#,
    )
    .expect("parses");
    for args in [
        vec!["-FilePath", "alpha", "-ArgumentList", "x,y"],
        vec!["-FilePath", "alpha", "-ArgumentList", "x,y", "-Wait"],
        vec!["-Verb", "runas", "-FilePath", "alpha", "-ArgumentList", "x,y"],
        // The positional spelling of the same thing still works.
        vec!["alpha", "-ArgumentList", "x,y"],
    ] {
        let ex = expand(&kb, &cmd("sp9", &args));
        let inner = ex
            .cmds
            .iter()
            .find(|c| c.head == "alpha")
            .unwrap_or_else(|| panic!("no wrapped command for {args:?}: {:?}", ex.cmds));
        assert_eq!(inner.args, vec!["x".to_string(), "y".to_string()], "for {args:?}");
        assert!(construct_keys(&ex).is_empty(), "for {args:?}: {:?}", ex.constructs);
    }
}


// ---------------------------------------------------------------------------
// The wrapper-nesting depth cap (M2.55): reaching it is reported, not a
// silent truncation — the layers past it are exactly the ones nothing
// scanned, so `expand_wrappers_with_sources` names the language whose cap
// was hit instead of just quietly stopping.
// ---------------------------------------------------------------------------

/// Wraps `text` as the argument to one more `sh -c`, producing real,
/// independently re-parseable shell source rather than a hand-typed
/// approximation of nested quoting. Single quotes are used when `text`
/// itself holds none (the common case, and safe regardless of any double
/// quotes inside); once a layer's text already contains a single quote,
/// double quotes are used instead, with `\` and `"` escaped — the same
/// one-layer-at-a-time shape `unquote_snippet`'s own doc comment describes
/// for `python -c "print(\"hi\")"`.
fn wrap_in_sh_c(text: &str) -> String {
    if text.contains('\'') {
        let mut escaped = String::with_capacity(text.len());
        for c in text.chars() {
            match c {
                '\\' => escaped.push_str("\\\\"),
                '"' => escaped.push_str("\\\""),
                other => escaped.push(other),
            }
        }
        format!("sh -c \"{escaped}\"")
    } else {
        format!("sh -c '{text}'")
    }
}

/// `n` layers of `sh -c` wrapped around `inner`.
fn nest_sh_c(inner: &str, n: usize) -> String {
    let mut src = inner.to_string();
    for _ in 0..n {
        src = wrap_in_sh_c(&src);
    }
    src
}

#[test]
fn at_cap_scans_and_one_past_cap_reports() {
    // Five `sh -c` layers around a marker command, using the shipped `sh`
    // entry: the five wrapper commands themselves are pushed at depths
    // 0..=4 (each is entered before its own unwrap is attempted), and the
    // marker they wrap is reached one layer deeper still, at depth 5.
    let src = nest_sh_c("echo done", 5);
    let top = parse(&src).expect("parses").commands;
    let kb = builtin();

    // Cap 4: the marker at depth 5 is exactly one past it — cut, and named.
    let ex = vouch::guards::expand_wrappers_with_sources(kb, &top, &[], &[], &[], "bash", &|_| 4);
    let vouch::guards::ExpandedWrappers { cmds, wrap_depth_exceeded: exceeded, .. } = ex;
    assert_eq!(exceeded, Some("bash".to_string()), "got cmds={cmds:?}");
    assert!(
        !cmds.iter().any(|c| c.head == "echo"),
        "the marker past the cap must not appear in the scanned commands: {cmds:?}"
    );

    // Cap 5: every layer, marker included, is within it.
    let ex = vouch::guards::expand_wrappers_with_sources(kb, &top, &[], &[], &[], "bash", &|_| 5);
    let vouch::guards::ExpandedWrappers { cmds, wrap_depth_exceeded: exceeded, .. } = ex;
    assert_eq!(exceeded, None, "got cmds={cmds:?}");
    assert!(
        cmds.iter()
            .any(|c| c.head == "echo" && c.args == vec!["done".to_string()]),
        "expected the marker command once every layer is scanned: {cmds:?}"
    );
}

#[test]
fn the_cap_is_per_language_of_the_entered_layer() {
    // bash(depth 0, the call's own starting language) -> powershell(depth 1)
    // -> powershell(depth 2) -> powershell(depth 3) -> bash(depth 4, the
    // marker). Caps: bash -> 2, powershell -> 4. The powershell layers sit
    // past bash's cap of 2 but within powershell's own cap of 4, so they
    // must survive; only the final bash layer, checked against bash's cap
    // again on re-entry, is the one that gets cut.
    let top = vec![cmd(
        "powershell",
        &[
            "-Command",
            "powershell",
            "-Command",
            "powershell",
            "-Command",
            "sh",
            "-c",
            "'echo done'",
        ],
    )];
    let kb = builtin();
    let caps = |lang: &str| match lang {
        "bash" => 2,
        "powershell" => 4,
        _ => 4,
    };
    let ex = vouch::guards::expand_wrappers_with_sources(kb, &top, &[], &[], &[], "bash", &caps);
    let vouch::guards::ExpandedWrappers { cmds, wrap_depth_exceeded: exceeded, .. } = ex;
    assert_eq!(exceeded, Some("bash".to_string()), "got cmds={cmds:?}");
    assert!(
        cmds.iter().any(|c| c.head == "sh"),
        "the powershell-hosted layers must survive past bash's own cap: {cmds:?}"
    );
    assert!(
        !cmds.iter().any(|c| c.head == "echo"),
        "the marker one past bash's own cap must not appear: {cmds:?}"
    );
}

// ---------------------------------------------------------------------------
// holds_input: whether vouch has the TEXT of a command's standard input.
//
// Judged through the expansion, which is where the judgement runs. Every pin
// looks the occurrence up BY HEAD, never by array position: a process
// substitution's inner command is pushed before the consumer lands, so index 0
// is frequently the inner command and an index-based helper would let refusal
// pins pass without testing anything.
// ---------------------------------------------------------------------------

fn judged_with(kb: &vouch::guards::Knowledge, src: &str, head: &str) -> bool {
    let scan = vouch::syntax::scanner_for("bash")
        .expect("bash scanner exists")
        .scan(src)
        .unwrap_or_else(|e| panic!("{src:?} does not parse: {e}"));
    let ex = vouch::guards::expand_wrappers_with_sources(
        kb,
        &scan.commands,
        &scan.heredocs,
        &scan.input_source,
        &scan.args_complete,
        "bash",
        &|_| 4,
    );
    let i = ex
        .cmds
        .iter()
        .position(|c| c.head == head)
        .unwrap_or_else(|| panic!("no occurrence {head} in {src:?}: {:?}", ex.cmds));
    ex.holds_input[i]
}

fn judged(src: &str, head: &str) -> bool {
    judged_with(builtin(), src, head)
}

#[test]
fn the_judgement_holds_a_delivered_scanned_body() {
    assert!(judged("python - <<'EOF'\nprint(1)\nEOF\n", "python"), "quoted, bare consumer");
    let shipped = vouch::guards::load(include_str!("../knowledge.toml")).expect("shipped knowledge parses");
    assert!(
        judged_with(
            &shipped,
            "python - C:/work/held.txt <<'EOF'\nprint(1)\nEOF\n",
            "python",
        ),
        "a declared trailing snippet argument does not replace the explicit stdin source"
    );
    assert!(judged("python - <<EOF\nprint(1)\nEOF\n", "python"), "unquoted, expansion-free");
    assert!(judged("bash <<'EOF'\nls -la\nEOF\n", "bash"), "shell consumer");
    assert!(
        judged("python - <<'A' <<'B'\nx\nA\ny\nB\n", "python"),
        "two fd-0 bodies, both verbatim"
    );
    assert!(
        judged("python - <<'A' 3<<'B'\nx\nA\ny\nB\n", "python"),
        "a sibling at another descriptor can never be delivered, so it does not refuse"
    );
    assert!(
        judged("python - <<'EOF' > out.txt\nprint(1)\nEOF\n", "python"),
        "an output redirect is not a competitor for standard input"
    );
    assert!(
        judged("python - <<<'x' <<'EOF'\nprint(1)\nEOF\n", "python"),
        "the here-string comes FIRST, so the here-document is still delivered"
    );
    assert!(
        judged("cat f.txt | python - <<'EOF'\nprint(1)\nEOF\n", "python"),
        "a redirect supersedes the pipe"
    );
}

#[test]
fn the_judgement_refuses_everything_it_cannot_prove() {
    // Rule 2: the delivered body is not what was scanned.
    assert!(!judged("python - <<EOF\nprint('$x')\nEOF\n", "python"), "expansion character");
    assert!(
        !judged("python - <<EOF\nprint('a\\\\nb')\nEOF\n", "python"),
        "an unquoted body's backslashes are processed on delivery"
    );
    // Rule 3: a refused sibling at descriptor 0 can be the delivered body.
    assert!(
        !judged("python - <<'A' <<B\nx\nA\ny $z\nB\n", "python"),
        "the delivered sibling is refused"
    );
    assert!(
        !judged("python - <<B <<'A'\ny $z\nB\nx\nA\n", "python"),
        "a refused earlier sibling at the same descriptor"
    );
    // Rule 5: the argument list must be complete AND name no source.
    assert!(!judged("python -s script.py <<'EOF'\nprint(1)\nEOF\n", "python"), "positional");
    assert!(!judged("python -mjson.tool <<'EOF'\nprint(1)\nEOF\n", "python"), "attached value");
    assert!(
        !judged("python <(cat f.py) <<'EOF'\nprint(1)\nEOF\n", "python"),
        "an argument-position substitution IS the script, and pushes no token"
    );
    // Rule 1: the delivered input source is not the here-document.
    assert!(!judged("python - <<'EOF' < f.txt\nprint(1)\nEOF\n", "python"), "competing file");
    assert!(!judged("python - <<'EOF' <> f.txt\nprint(1)\nEOF\n", "python"), "read-write");
    assert!(!judged("python - <<'EOF' < <(cat f.py)\nprint(1)\nEOF\n", "python"), "substitution");
    assert!(!judged("python - <<'EOF' 0<&3\nprint(1)\nEOF\n", "python"), "duplication");
    assert!(!judged("python - <<'EOF' <<<'x'\nprint(1)\nEOF\n", "python"), "a later here-string");
    assert!(!judged("python - 3<<'EOF'\nprint(1)\nEOF\n", "python"), "the body feeds fd 3");
    // The wrapper shape: the here-document belongs to `sudo`, so the body is
    // never scanned, and the synthesised inner command must not inherit.
    assert!(!judged("sudo python - <<'EOF'\nprint(1)\nEOF\n", "python"), "the unwrapped consumer");
    assert!(!judged("sudo python - <<'EOF'\nprint(1)\nEOF\n", "sudo"), "and the wrapper itself");
}

/// A fixture entry declaring a stdin claim, with `extra` appended.
fn stdin_fixture(extra: &str) -> vouch::guards::Knowledge {
    vouch::guards::load(&format!(
        "version = 5\n[[program]]\nmatch = [\"consume\"]\nevaluates_input = \"stdin\"\n{extra}"
    ))
    .expect("the fixture parses")
}

#[test]
fn the_judgement_needs_a_scanner_backed_in_scope_consuming_entry() {
    // A declared language nothing can read: the body is recorded for the
    // protected-path search and never scanned as code.
    let kb = stdin_fixture("wrap_lang = \"opaque\"\n");
    assert!(!judged_with(&kb, "consume <<'EOF'\nprint(1)\nEOF\n", "consume"), "opaque");
    // INVERTED (§2.2 item 8, M2.125/§5.2.4): a language outside the closed
    // set is a load refusal now, not a silent fallback to the bash scanner —
    // `guards::load` itself refuses this fixture, the same closed-set check
    // real knowledge files get.
    let result = vouch::guards::load(&format!(
        "version = 5\n[[program]]\nmatch = [\"consume\"]\nevaluates_input = \"stdin\"\n\
         wrap_lang = \"klingon\"\n"
    ));
    assert!(result.is_err(), "an unregistered wrap_lang must refuse to load, not fall back silently");
    // No declared language at all — the same fallback under the minimal
    // spelling an operator entry actually uses.
    let kb = stdin_fixture("");
    assert!(!judged_with(&kb, "consume <<'EOF'\nls -la\nEOF\n", "consume"), "empty");
    // Scoped to a different language than the occurrence's own.
    let kb = stdin_fixture("wrap_lang = \"bash\"\nlanguages = [\"powershell\"]\n");
    assert!(!judged_with(&kb, "consume <<'EOF'\nls -la\nEOF\n", "consume"), "out of scope");
    // The same entry in scope: held — so the refusals above are about scope and
    // language, not about the fixture being unusable.
    let kb = stdin_fixture("wrap_lang = \"bash\"\n");
    assert!(judged_with(&kb, "consume <<'EOF'\nls -la\nEOF\n", "consume"), "in scope");
}

#[test]
fn the_judgement_reads_the_entry_that_consumed_the_body() {
    // Two same-name stdin entries. The locator takes the FIRST name match, so
    // that is the entry whose language the body was actually read as — here it
    // is out of scope AND declares a language nothing can read, while a second
    // entry for the same name looks fine. A re-derived lookup would hold this.
    let kb = vouch::guards::load(
        "version = 5\n\
         [[program]]\nmatch = [\"consume\"]\nevaluates_input = \"stdin\"\n\
         wrap_lang = \"opaque\"\nlanguages = [\"powershell\"]\n\
         [[program]]\nmatch = [\"consume\"]\nevaluates_input = \"stdin\"\nwrap_lang = \"bash\"\n",
    )
    .expect("parses");
    assert!(!judged_with(&kb, "consume <<'EOF'\nls -la\nEOF\n", "consume"));
}

#[test]
fn a_wrapper_that_is_also_a_consumer_keeps_its_own_judgement() {
    // The wrapper arm pushes commands between this occurrence's own push and
    // the locator's back-patch, so an append-at-the-locator implementation
    // would land the judgement on the wrong occurrence. No shipped entry is
    // both a wrapper and a stdin consumer, so this needs a fixture.
    let kb = vouch::guards::load(
        "version = 5\n[[program]]\nmatch = [\"both\"]\nevaluates_input = \"stdin\"\n\
         wrap_lang = \"bash\"\nwraps = \"arg_0\"\n",
    )
    .expect("parses");
    assert!(
        judged_with(&kb, "both - <<'EOF'\nls -la\nEOF\n", "both"),
        "the consumer's own judgement, not the position the wrapper arm pushed"
    );
}

// ---------------------------------------------------------------------------
// M2.127 / Task 12 — heredoc selection by identity, not by position.
//
// `judged()` calls `expand_wrappers_with_sources` directly, the same
// calling convention `engine::collect_expanded` uses for a wrapped snippet's
// own nested scan (a fresh `heredocs`/`input_source` pair, not pre-filtered
// to one command the way the top-level engine path pre-filters before
// calling in). Before Task 12, the walk selected a delivered here-document
// by comparing `own_source` (this command's resolved `InputSource::Heredoc`,
// naming a position in whichever list produced it) against `nth` (this
// record's position in `attached`, this command's own FILTERED list). A
// preceding sibling's own heredoc grows the list `own_source` was resolved
// against without growing the filtered one, so the two numbers only ever
// coincided when nothing preceded the consumer — pushing `holds_input` false
// for a body that was genuinely delivered and genuinely scanned. Four shapes
// isolate the two axes that matter: top level vs. inside a wrapped snippet,
// and no preceding sibling vs. one. All four must hold.
// ---------------------------------------------------------------------------

#[test]
fn heredoc_selection_survives_a_preceding_sibling_top_level() {
    assert!(
        judged("python - <<B\nprint(1)\nB\n", "python"),
        "lone top-level consumer, no sibling (control)"
    );
    assert!(
        judged("cat <<A\nsib\nA\npython - <<B\nprint(1)\nB\n", "python"),
        "a preceding top-level sibling's own heredoc must not desync this one"
    );
}

#[test]
fn heredoc_selection_survives_a_preceding_sibling_inside_a_snippet() {
    assert!(
        judged("bash -c 'python - <<B\nprint(1)\nB'", "python"),
        "lone consumer inside a wrapped snippet, no sibling (control)"
    );
    assert!(
        judged(
            "bash -c 'cat <<A\nsib\nA\npython - <<B\nprint(1)\nB'",
            "python"
        ),
        "a preceding sibling INSIDE the same wrapped snippet must not desync this one"
    );
}

// ---------------------------------------------------------------------------
// The veto: `unless_flags` on a guard rule (M2.16, 2026-08-19)
//
// `kill` carries an `always` rule for `process_control`, so every spelling
// trips it except the one the veto names. `kill -0` sends no signal at all —
// it asks the kernel whether a process exists — and it is the most common
// flagged spelling in the corpus (8 of the 9 flag tokens), so a guard without
// the veto would ask on a liveness check nearly every time it fired.
// ---------------------------------------------------------------------------

#[test]
fn signalling_a_process_trips_process_control() {
    assert_guard("kill 1234", "process_control");
    assert_guard("kill -9 1234", "process_control");
    assert_guard("kill -TERM 1234", "process_control");
}

#[test]
fn the_liveness_probe_is_vetoed_and_nothing_else_is() {
    assert_no_guard("kill -0 1234");
    // The veto is ONE flag, not "any flag that looks like a signal number".
    assert_guard("kill -1 1234", "process_control");
}

#[test]
fn the_veto_does_not_read_an_attached_value_as_its_own_flag() {
    // `kill` declares no flag vocabulary, so every short flag looks
    // attachable and `-09` classified as `-0` carrying the value `9`. bash
    // delivers that as SIGKILL — measured, a spawned process ended with wait
    // status 137 — so the veto must require an EXACT spelling.
    assert_guard("kill -09 1234", "process_control");
    assert_guard("kill -0abc 1234", "process_control");
    assert_no_guard("kill -0 1234");
}

#[test]
fn the_veto_reads_only_the_first_argument() {
    // In `kill` only the leading token is a signal specification. A later
    // `-0` is a PID, and a NEGATIVE pid is a process GROUP — so `kill -9 -0`
    // signals the caller's own group, which is broader than the plain kill
    // this guard exists for, not narrower.
    assert_guard("kill -9 -0", "process_control");
    assert_guard("kill -TERM -0", "process_control");
    assert_guard("kill -KILL -0 -1", "process_control");
}

#[test]
fn the_veto_stops_at_the_end_of_options_marker() {
    // After `--` the token is an operand, and a NEGATIVE pid is a process
    // GROUP — broader than a single process, so reading it as the veto would
    // stand the guard down on the most far-reaching spelling there is. The
    // veto goes through the same flag walk as `any_flag` precisely so it
    // cannot.
    assert_guard("kill -- -0", "process_control");
}

#[test]
fn the_veto_is_per_command_not_per_line() {
    let got = guards_for("kill -0 1234; kill -9 5678");
    assert_eq!(
        got.iter().filter(|g| *g == "process_control").count(),
        1,
        "exactly the un-vetoed command should trip the guard, got {got:?}"
    );
}

// ---------------------------------------------------------------------------
// The builtins that stopped being holes in the hand-written list (M2.16)
// ---------------------------------------------------------------------------

#[test]
fn the_newly_described_builtins_carry_no_guard() {
    // Describing them is recognition, not a claim that they are harmless
    // beyond it: vouch stops saying it has never heard of them, and nothing
    // else about them changes.
    assert_no_guard("read -r line");
    assert_no_guard("builtin cd /tmp");
}
