//! Files written BY a command must go through the same path rules as the Write
//! tool. Until 2026-07-25 they did not: `echo x > C:/Windows/y` was allowed
//! outright because [write] only applied to the Write/Edit tools.

use vouch::config::load;
use vouch::engine::decide_command_in;
use vouch::protocol::Decision;

const HOME: &str = "C:/Users/dev";

fn cfg() -> vouch::config::Config {
    load(r#"
version = 1
[lang.bash]
default = "allow"
[lang.bash.constructs]
unmodeled_command = "allow"
dynamic_redirect = "allow"
heredoc = "allow"
subshell = "allow"
redirect = "allow"
[write]
default = "ask"
allow_paths = ["C:/work/**"]
"#).expect("parses")
}

fn decide(cmd: &str) -> Decision {
    decide_command_in(&cfg(), "bash", cmd, Some(HOME), None)
}

#[test]
fn a_redirect_outside_the_allowed_area_asks() {
    for cmd in [
        "echo hi > C:/Windows/evil.txt",
        "echo hi >> C:/Windows/evil.txt",
        r"echo hi > C:\Windows\evil.txt",
        "echo hi > /c/Windows/evil.txt",
    ] {
        assert!(matches!(decide(cmd), Decision::Ask(_)), "not gated: {cmd}");
    }
}

#[test]
fn a_redirect_inside_the_allowed_area_is_allowed() {
    assert!(matches!(decide("echo hi > C:/work/out.txt"), Decision::Allow(_)));
}

#[test]
fn devnull_is_not_treated_as_a_write() {
    assert!(matches!(decide("ls -la > /dev/null"), Decision::Allow(_)));
}

#[test]
fn a_copy_target_outside_the_allowed_area_asks() {
    assert!(matches!(decide("cp a.txt C:/Windows/b.txt"), Decision::Ask(_)));
    assert!(matches!(decide("mv a.txt C:/Windows/b.txt"), Decision::Ask(_)));
}

#[test]
fn a_copy_target_inside_the_allowed_area_is_allowed() {
    assert!(matches!(decide("cp a.txt C:/work/b.txt"), Decision::Allow(_)));
}

#[test]
fn mkdir_targets_are_checked() {
    assert!(matches!(decide("mkdir -p C:/Windows/newdir"), Decision::Ask(_)));
    assert!(matches!(decide("mkdir -p C:/work/newdir"), Decision::Allow(_)));
}

#[test]
fn a_read_only_command_naming_a_path_is_not_a_write() {
    assert!(matches!(decide("ls -la C:/Windows"), Decision::Allow(_)));
    assert!(matches!(decide("cat C:/Windows/win.ini"), Decision::Allow(_)));
}

#[test]
fn the_reason_says_the_write_came_from_the_command() {
    match decide("echo hi > C:/Windows/evil.txt") {
        Decision::Ask(r) => assert!(
            r.contains("written by the command"),
            "reason should distinguish this from a file-tool write: {r}"
        ),
        other => panic!("expected Ask, got {other:?}"),
    }
}

#[test]
fn a_write_inside_a_loop_body_is_still_checked() {
    let d = decide("for f in a b; do cp \"$f\" C:/Windows/out.txt; done");
    assert!(matches!(d, Decision::Ask(_)), "loop body write not gated: {d:?}");
}

// --- PowerShell writes were entirely unchecked until 2026-07-25 -------------

fn ps_cfg() -> vouch::config::Config {
    load(r#"
version = 1
[lang.powershell]
default = "allow"
[lang.powershell.constructs]
unmodeled_command = "allow"
redirect = "allow"
assignment = "allow"
method_call = "allow"
[write]
default = "ask"
allow_paths = ["C:/work/**"]
"#).expect("parses")
}

fn ps(cmd: &str) -> Decision {
    decide_command_in(&ps_cfg(), "powershell", cmd, Some(HOME), None)
}

#[test]
fn powershell_named_parameter_writes_are_checked() {
    assert!(matches!(ps("Set-Content -Path C:/Windows/x.txt -Value hi"), Decision::Ask(_)));
    assert!(matches!(ps("Out-File -FilePath C:/Windows/x.txt"), Decision::Ask(_)));
    assert!(matches!(ps("Set-Content -Path C:/work/ok.txt -Value hi"), Decision::Allow(_)));
}

#[test]
fn powershell_positional_writes_are_checked() {
    assert!(matches!(ps("Copy-Item a.txt C:/Windows/b.txt"), Decision::Ask(_)));
    assert!(matches!(ps("Copy-Item a.txt C:/work/b.txt"), Decision::Allow(_)));
}

#[test]
fn powershell_redirects_are_checked() {
    assert!(matches!(ps("echo hi > C:/Windows/evil.txt"), Decision::Ask(_)));
    assert!(matches!(ps("echo hi > C:/work/fine.txt"), Decision::Allow(_)));
}

#[test]
fn a_powershell_read_is_not_a_write() {
    assert!(matches!(ps("Get-ChildItem C:/Windows"), Decision::Allow(_)));
    assert!(matches!(ps("Get-Content C:/Windows/win.ini"), Decision::Allow(_)));
}

// --- relative write targets ------------------------------------------------
// Found by diffing vouch against cc-allow on live traffic: `rm -f scripts/x.py`
// was asked about, because with no working directory every relative target
// looks like it is outside every scope.

fn at(cmd: &str, cwd: &str) -> Decision {
    vouch::engine::decide_command_at(&cfg(), "bash", cmd, Some(HOME), None, Some(cwd))
}

#[test]
fn a_relative_target_inside_an_allowed_cwd_is_allowed() {
    assert!(matches!(at("rm -f scripts/x.py", "C:/work/proj"), Decision::Allow(_)));
    assert!(matches!(at("echo hi > out.txt", "C:/work/proj"), Decision::Allow(_)));
    assert!(matches!(at("cp a.txt sub/b.txt", "C:/work/proj"), Decision::Allow(_)));
}

#[test]
fn a_relative_target_that_climbs_out_is_caught() {
    assert!(matches!(at("cp a.txt ../../Windows/evil.txt", "C:/work/proj"), Decision::Ask(_)));
}

#[test]
fn a_relative_target_in_a_disallowed_cwd_is_caught() {
    assert!(matches!(at("echo hi > y.txt", "C:/Windows"), Decision::Ask(_)));
}

#[test]
fn with_no_cwd_a_relative_target_is_not_silently_allowed() {
    // Unknown location must not become a pass.
    let d = decide_command_in(&cfg(), "bash", "echo hi > y.txt", Some(HOME), None);
    assert!(matches!(d, Decision::Ask(_)), "got {d:?}");
}

// --- per-command, ordered resolution ---------------------------------------
// Every write is judged in the directory it actually lands in: the run-dir
// flag's directory if the command has one, else the `cd` state at that
// command's own position in the sequence. Each of these was a wrong ALLOW
// probed by the two pre-build reviews.

// -- the headline defect
#[test]
fn a_run_dir_flags_relative_destination_is_judged_there() {
    assert!(matches!(at("git -C C:/elsewhere init foo", "C:/work"), Decision::Ask(_)));
    assert!(matches!(at("git -C C:/work/sub init foo", "C:/elsewhere"), Decision::Allow(_)));
}
#[test]
fn bare_git_init_is_judged_where_it_runs() {
    assert!(matches!(at("git init", "C:/elsewhere"), Decision::Ask(_)));
    assert!(matches!(at("git init", "C:/work"), Decision::Allow(_)));
    assert!(matches!(at("git -C C:/elsewhere init", "C:/work"), Decision::Ask(_)));
}
// -- ordering
#[test]
fn a_write_before_a_cd_resolves_against_the_state_before_the_cd() {
    // Naming the resolved path, not just the verdict: collecting every `cd`
    // in the line into one base answered this with C:/work — the directory
    // the line ENDS in, which is not where f.txt was written. An Ask alone
    // would not tell those two apart.
    match at("echo x > f.txt && cd C:/work", "C:/elsewhere") {
        Decision::Ask(r) => assert!(r.contains("C:/elsewhere/f.txt"), "{r}"),
        d => panic!("expected ask, got {d:?}"),
    }
    assert!(matches!(at("cd C:/work && echo x > f.txt", "C:/elsewhere"), Decision::Allow(_)));
}
#[test]
fn relative_cds_compose() {
    assert!(matches!(at("cd C:/work && cd sub && echo x > f.txt", "C:/elsewhere"), Decision::Allow(_)));
}
#[test]
fn unorderable_cds_fail_closed() {
    for cmd in [
        "(cd C:/work); echo x > f.txt",
        "cd C:/work || echo x > f.txt",
        "pushd C:/work && popd && echo x > f.txt",
        "cd C:/work && cd - && echo x > f.txt",
    ] {
        // The prompt has to say WHY it cannot place the write and name the
        // setting that turns it off (CLAUDE.md §5) — an Ask whose text
        // described some other problem would be the wrong prompt.
        match at(cmd, "C:/elsewhere") {
            Decision::Ask(r) => {
                assert!(r.contains("unresolved_path"), "{cmd}: {r}");
                // Reworded (Task 8, spec §5 rule 5 / M2.37 caution): names no
                // program. Pinned verbatim so a future edit cannot quietly
                // reintroduce one.
                assert!(
                    r.contains(
                        "a directory change vouch cannot order (a subshell, ||, pipeline, \
                         background job, or a directory stack vouch cannot see)"
                    ),
                    "wrong explanation for {cmd}: {r}"
                );
            }
            d => panic!("not asked: {cmd} -> {d:?}"),
        }
    }
}
#[test]
fn cd_with_only_option_shaped_arguments_fails_closed() {
    // `cd -1` is not a flag bash recognises for `cd`; bash errors and stays in
    // cwd. The old code found no directory token in the arguments and fell
    // through to the same branch as bare `cd` (no arguments at all), landing
    // the write in HOME — while the shell never left the disallowed cwd it
    // started in. Option-shaped arguments with no directory token must fail
    // closed, not be read as the bare-`cd`-goes-home case.
    match at("cd -1 && echo x > f.txt", "C:/elsewhere") {
        Decision::Ask(r) => {
            assert!(r.contains("unresolved_path"), "{r}");
            assert!(r.contains("a directory change vouch cannot order"), "{r}");
        }
        d => panic!("expected ask, got {d:?}"),
    }
}

#[test]
fn pushd_with_an_option_never_takes_the_directory_argument() {
    // `pushd -n DIR` pushes DIR onto the stack WITHOUT changing directory —
    // the `-n` suppresses the directory change. The old code only refused the
    // rotate forms (`+1`/`-1`) and otherwise took the first non-flag argument
    // as the new base, so this composed C:/work as the base and ALLOWED a
    // write that really landed in the disallowed cwd it started in.
    match at("pushd -n C:/work && echo x > f.txt", "C:/elsewhere") {
        Decision::Ask(r) => {
            assert!(r.contains("unresolved_path"), "{r}");
            assert!(r.contains("a directory change vouch cannot order"), "{r}");
        }
        d => panic!("expected ask, got {d:?}"),
    }
}

// -- membership deltas the knowledge-driven walk activates (M2.33 / Task 6,
// 2026-07-31, amended after review 2026-08-01)
//
// Reading membership from `dir_change_kind` instead of a hardcoded name list
// does not just change WHERE the answer comes from — for names the old list
// got wrong, it changes the ANSWER. Every one of those deltas is pinned here,
// deliberately, rather than left as an unstated side effect of the swap:
//
//   - `chdir`/`sl`/`set-location` stop being bash movers (they never were —
//     bash has no such builtins; the old list matched by name only, blind to
//     language). Toward-ALLOW, and truthful. On the DEFAULT config
//     (`unmodeled_command = "ask"`) this is invisible: an unrecognised
//     top-level head still asks there regardless of the cd walk. It is
//     visible only once `unmodeled_command` is allowed, and doubly so inside
//     a wrapper snippet (below), because snippet heads are never
//     recognition-checked at all — a pre-existing gap, recorded as M2.46 in
//     `docs/ROADMAP.md`, that this task's swap did not create and does not
//     fix.
//   - `source`/`.` become real (`unstated`) movers. Toward-ASK, and
//     truthful: a sourced script's own `cd` persists in the calling shell.
//     Scheduled as a Task 8 pin; pinned here because Task 5+6 together are
//     what already activated it.
//   - `push-location`/`pop-location` become movers on PowerShell lines.
//     Toward-ASK, not exercised by a bash-only corpus, not separately pinned
//     here — same shape as `source`/`.`, no bash-side name collision to
//     probe.
//
// A wrapped snippet's dir-changer is also looked up under the SNIPPET's own
// language, never the host's (spec §2). `sl` is a dir-changer only in
// PowerShell — on a bash line it is an unrelated external program — so this
// only stays fail-closed if the lookup for a command that came out of a
// `powershell -Command "…"` snippet uses "powershell", not "bash".

fn snippet_lang_cfg() -> vouch::config::Config {
    load(
        r#"
version = 1
[lang.bash]
default = "allow"
[lang.bash.constructs]
unmodeled_command = "allow"
[write]
default = "allow"
"#,
    )
    .expect("parses")
}

#[test]
fn a_snippet_dir_changer_is_looked_up_under_the_snippet_language() {
    // `sl` is a dir-changer only in powershell. Inside a powershell snippet on
    // a bash line it must still poison the timeline (probed ASK today; a
    // host-language lookup would silently flip it to ALLOW — spec §2).
    let cfg = snippet_lang_cfg();
    let d = vouch::engine::decide_command_at(
        &cfg,
        "bash",
        r#"powershell -Command "sl C:/x" && echo hi > probe.txt"#,
        Some(HOME),
        None,
        Some("C:/Users/dev/proj"),
    );
    assert!(
        matches!(d, Decision::Ask(_)),
        "snippet cd must stay fail-closed, got {d:?}"
    );
}

#[test]
fn a_bash_snippet_set_location_cannot_move_the_parent_shell() {
    // `set-location` is a real dir-changer, but only in PowerShell (spec
    // §2). Inside a `bash -c "…"` snippet it is plain bash text — not a
    // builtin there at all — and even if it named a real external program,
    // a CHILD PROCESS cannot change its PARENT shell's cwd. The removed
    // hardcoded list matched "set-location" by name alone, blind to
    // language, and wrongly poisoned this timeline; that old ASK was
    // over-strictness from a false claim, not a real hazard, adjudicated
    // TRUTHFUL in the Task 6 review. What is NOT fixed by this: vouch never
    // recognition-checks a command hiding inside a snippet, so a genuinely
    // unknown program there would allow too — that gap is real, pre-existing
    // (probed identical on master), and tracked separately as M2.46.
    let cfg = snippet_lang_cfg();
    let d = vouch::engine::decide_command_at(
        &cfg,
        "bash",
        r#"bash -c "set-location C:/x" && echo hi > probe.txt"#,
        Some(HOME),
        None,
        Some("C:/Users/dev/proj"),
    );
    assert!(matches!(d, Decision::Allow(_)), "got {d:?}");
}

#[test]
fn a_bash_snippet_chdir_cannot_move_the_parent_shell() {
    // Same grounding as above, and simpler: bash has no `chdir` builtin at
    // all, so even a TOP-LEVEL `chdir /x` never really moved anything — the
    // old list's claim was false there too, not just inside a snippet. The
    // write here sits in the SAME snippet text, so it lands at the
    // wrapper's own base (cwd), not at a directory `chdir` invented.
    let cfg = snippet_lang_cfg();
    let d = vouch::engine::decide_command_at(
        &cfg,
        "bash",
        r#"bash -c "chdir /x; echo hi > f.txt""#,
        Some(HOME),
        None,
        Some("C:/Users/dev/proj"),
    );
    assert!(matches!(d, Decision::Allow(_)), "got {d:?}");
}

#[test]
fn chdir_on_a_bash_line_is_neither_recognised_nor_a_mover() {
    // Same grounding as the snippet case above, at the TOP LEVEL of a bash
    // line rather than inside a wrapper: `chdir` ships nowhere for bash
    // (spec §6 / M2.33) — bash has no such builtin. Two claims held at
    // once: the head still asks because vouch has no description of it
    // (unmodeled_command, left at its default here rather than overridden
    // to allow, so the ask is real and not masked), and the walk must not
    // treat it as a mover — a relative write after it must not resolve
    // against "/tmp", which is what the removed hardcoded cd-name list
    // would have done.
    let cfg = load(
        r#"
version = 1
[lang.bash]
default = "allow"
[write]
default = "ask"
"#,
    )
    .expect("parses");
    let d = vouch::engine::decide_command_at(
        &cfg,
        "bash",
        "chdir /tmp; echo hi > probe.txt",
        Some(HOME),
        None,
        Some("C:/Users/dev/proj"),
    );
    assert!(matches!(d, Decision::Ask(_)), "got {d:?}");
    assert!(
        !format!("{d:?}").contains("/tmp/probe.txt"),
        "the base must not follow a non-mover: {d:?}"
    );
}

#[test]
fn dot_sourcing_still_poisons_the_timeline() {
    // The `source`/`.` entries exist for exactly this (spec §6): a sourced
    // script's own `cd` persists in the calling shell, so vouch cannot say
    // where a later relative write lands. Scheduled as a Task 8 pin; lands
    // here because Task 5's entries plus Task 6's swap are what activate it.
    let cfg = snippet_lang_cfg();
    let d = vouch::engine::decide_command_at(
        &cfg,
        "bash",
        ". ./env.sh; echo hi > probe.txt",
        Some(HOME),
        None,
        Some("C:/Users/dev/proj"),
    );
    match d {
        Decision::Ask(r) => assert!(r.contains("unresolved_path"), "{r}"),
        other => panic!("expected Ask, got {other:?}"),
    }
}

#[test]
fn sourcing_still_poisons_the_timeline() {
    // Same rule, the other spelling.
    let cfg = snippet_lang_cfg();
    let d = vouch::engine::decide_command_at(
        &cfg,
        "bash",
        "source env.sh && echo hi > probe.txt",
        Some(HOME),
        None,
        Some("C:/Users/dev/proj"),
    );
    match d {
        Decision::Ask(r) => assert!(r.contains("unresolved_path"), "{r}"),
        other => panic!("expected Ask, got {other:?}"),
    }
}

// -- the tokens a directory change is classified BY
// The scanner keeps the quotes on an argument, so a `-` or a flag written
// with quotes does not look like one until it has been resolved. Deciding
// what a token IS from the raw text invented directories that do not exist.

#[test]
fn a_quoted_dash_is_the_previous_directory_not_a_directory_named_dash() {
    // `cd "-"` goes to OLDPWD, which is named nowhere in this command line.
    // Read raw, `"-"` is neither `-` nor a flag, so it was taken as a
    // relative directory and composed C:/work/- — inside the allowed area,
    // so this ALLOWED while the write really landed somewhere unnamed.
    match at(r#"cd "-" && echo x > f.txt"#, "C:/work") {
        Decision::Ask(r) => {
            assert!(r.contains("unresolved_path"), "{r}");
            assert!(r.contains("a directory change vouch cannot order"), "{r}");
        }
        d => panic!("expected ask, got {d:?}"),
    }
}

#[test]
fn the_stack_rotate_form_names_no_directory() {
    // `pushd +1` rotates the directory stack. There is no path in the
    // command at all, and `+1` is not a directory called `+1`.
    match at("pushd +1 && echo x > f.txt", "C:/work") {
        Decision::Ask(r) => {
            assert!(r.contains("unresolved_path"), "{r}");
            assert!(r.contains("a directory change vouch cannot order"), "{r}");
        }
        d => panic!("expected ask, got {d:?}"),
    }
}

#[test]
fn a_quoted_directory_still_composes_and_a_quoted_flag_is_still_a_flag() {
    // The control for the two above: resolving before classifying must not
    // stop an ordinary quoted path from being the destination.
    assert!(matches!(
        at(r#"cd "C:/work" && echo x > f.txt"#, "C:/elsewhere"),
        Decision::Allow(_)
    ));
    // Read raw, the quoted flag `"-P"` did not look like a flag at all, so
    // it was skipped as a non-candidate ONLY because resolving turned it
    // into `-P` first — that half stays true. But `-P` is not declared on
    // bash `cd`'s grammar (empty `dest_dir_flags`/`value_options`/
    // `no_value_options`), so spec §4 rule 4 now fails this closed instead
    // of quietly finding "C:/work" as the sole remaining candidate: any
    // undeclared option-shaped token asks, on purpose (Task 7,
    // 2026-07-31 — `an_undeclared_option_fails_closed_for_every_declared_name`
    // pins the unquoted twin of this same shape).
    match at(r#"cd "-P" "C:/work" && echo x > f.txt"#, "C:/elsewhere") {
        Decision::Ask(r) => {
            assert!(r.contains("unresolved_path"), "{r}");
            assert!(r.contains("a directory change vouch cannot order"), "{r}");
        }
        d => panic!("expected ask, got {d:?}"),
    }
}

// -- run-dir edge cases
#[test]
fn two_run_dir_flags_ask_only_when_something_would_be_written() {
    assert!(matches!(at("git -C a -C b init", "C:/work"), Decision::Ask(_)));
    assert!(matches!(at("git -C a -C b status", "C:/work"), Decision::Allow(_)));
}
#[test]
fn a_relative_run_dir_value_resolves_against_the_cd_state() {
    assert!(matches!(at("cd C:/work && git -C sub init foo", "C:/elsewhere"), Decision::Allow(_)));
}
#[test]
fn redirects_never_take_the_run_dir_base() {
    // git's -C points at an allowed dir; the redirect lands in the disallowed
    // cwd. Asserting the PATH, not just the Ask: a redirect that wrongly took
    // the run-dir base would resolve to C:/work/log.txt and this would pass on
    // `foo` alone. The redirect belongs to the shell, not to git (spec §3.5).
    match at("git -C C:/work init foo > log.txt", "C:/elsewhere") {
        Decision::Ask(r) => assert!(r.contains("C:/elsewhere/log.txt"), "{r}"),
        d => panic!("expected ask, got {d:?}"),
    }
}
#[test]
fn an_unknowable_destination_asks_and_names_the_flag() {
    match at("git clone https://x/y.git C:/work/d --frobnicate", "C:/work") {
        Decision::Ask(r) => assert!(r.contains("--frobnicate") && r.contains("unresolved_path"), "{r}"),
        d => panic!("expected ask, got {d:?}"),
    }
}
#[test]
fn the_prompt_names_the_run_dir_provenance() {
    match at("git -C C:/elsewhere init foo", "C:/work") {
        Decision::Ask(r) => assert!(r.contains("git -C C:/elsewhere"), "{r}"),
        d => panic!("expected ask, got {d:?}"),
    }
}

// -- the grammar walk (M2.33 / Task 7, spec 2026-07-31 §4) -------------------
//
// A separate module only because it needs its own `decide` — this file's
// top-level `decide(cmd: &str)` is bash-only and already named. Every pin
// here names the spec rule it checks, verbatim from `docs/specs/2026-07-31-
// changes-dir-knowledge-design.md` §4:
//   1. a dest-dir flag consumes its value AS a destination candidate.
//   2. a value option consumes its value (not a candidate).
//   3. a no-value option is skipped.
//   4. any undeclared option-shaped argument -> unknown. Fail closed.
//   5. remaining non-flag tokens are candidates; exactly one -> destination,
//      zero or more than one -> unknown.
//   6. bare = zero arguments BEFORE any consumption -> home on a bash line,
//      unknown on a powershell line.
//   7. flag comparison is case-insensitive only when the entry says so;
//      prefix abbreviations never match.
mod grammar {
    use vouch::config::load;
    use vouch::engine::decide_command_at;
    use vouch::protocol::Decision;

    fn cfg() -> vouch::config::Config {
        load(
            r#"
version = 1
[lang.bash]
default = "allow"
[lang.bash.constructs]
unmodeled_command = "allow"
dynamic_redirect = "allow"
heredoc = "allow"
subshell = "allow"
redirect = "allow"
[lang.powershell]
default = "allow"
[lang.powershell.constructs]
unmodeled_command = "allow"
redirect = "allow"
assignment = "allow"
env_assignment = "allow"
method_call = "allow"
[write]
default = "ask"
allow_paths = ["C:/work/**"]
"#,
        )
        .expect("parses")
    }

    /// `"ps"` is `vouch explain`'s own selector spelling (`src/cli.rs`); the
    /// scanner registry (`syntax::scanner_for`) only answers to `"powershell"`
    /// literally, so the pins can use the shorter, human spelling and this
    /// helper is the one place that translates it.
    fn decide(lang: &str, src: &str) -> Decision {
        let lang = if lang == "ps" { "powershell" } else { lang };
        let cfg = cfg();
        decide_command_at(&cfg, lang, src, Some("C:/Users/dev"), None, Some("C:/Users/dev/proj"))
    }

    fn assert_asks(lang: &str, src: &str) {
        // Not just "any Ask" — `[write].default = "ask"` alone would rubber-
        // stamp a WRONG resolved base too (the exact defect being fixed:
        // probed 2026-08-01, the pre-Task-7 walk asks about a wrong path for
        // every one of these shapes). The right reason is that the
        // destination itself is unresolved (rule 4/5/6's `unknown`), which
        // always names its own setting, `unresolved_path` (CLAUDE.md §5).
        match decide(lang, src) {
            Decision::Ask(r) => assert!(
                r.contains("unresolved_path"),
                "{src} must ask because the destination is unresolved, got: {r}"
            ),
            d => panic!("{src} must ask, got {d:?}"),
        }
    }

    fn assert_destination(lang: &str, src: &str, want: &str) {
        let d = decide(lang, src);
        let text = format!("{d:?}").replace("<home>", "C:/Users/dev");
        let want = want.replace("<home>", "C:/Users/dev");
        assert!(text.contains(&want), "expected the reason to name {want}, got {text}");
    }

    #[test]
    fn set_location_stackname_no_longer_composes_a_base() {
        // Rule 4: `-StackName` is not declared anywhere on the powershell
        // `set-location` entry (`dest_dir_flags`/`no_value_options` only
        // name `-Path`/`-LiteralPath`/`-PassThru`), so it is an undeclared
        // option-shaped token, not a value option that happens to consume
        // `demo`. Was: the old first-non-dash heuristic took `demo` as the
        // base and judged the write against `<cwd>/demo`.
        assert_asks("ps", r#"Set-Location -StackName demo; "x" > probe.txt"#);
    }

    #[test]
    fn two_argument_cd_is_unknown_not_arg1() {
        // Rule 5: two non-flag tokens are two candidates, not one. Was: the
        // old walk took the first (`/tmp`) as the base even though bash
        // itself rejects a two-argument `cd` and never moves.
        assert_asks("bash", "cd /tmp x; echo hi > probe.txt");
    }

    #[test]
    fn cd_path_resolves_on_a_powershell_line() {
        // Rule 1: `-Path` is a declared dest-dir flag on the powershell
        // `cd`/`set-location` entry, so its value IS the destination.
        assert_destination("ps", "cd -Path C:/elsewhere; \"x\" > probe.txt", "C:/elsewhere/probe.txt");
    }

    #[test]
    fn bare_cd_goes_home_on_bash_and_is_unknown_on_powershell() {
        // Rule 6: bare is zero arguments before any consumption. bash
        // documents and does the home move; PowerShell 5.1 is probed to
        // stay put (a no-op), so a base that depends on which PowerShell
        // runs is not one vouch can state.
        assert_destination("bash", "cd; echo hi > probe.txt", "<home>/probe.txt");
        assert_asks("ps", "cd; \"x\" > probe.txt");
    }

    #[test]
    fn an_undeclared_option_fails_closed_for_the_bash_grammar() {
        // Rule 4 (bash): `-P` is not in bash `cd`'s grammar (empty, by
        // design — spec §6 table). May not be answered by guessing what it
        // means.
        assert_asks("bash", "cd -P /tmp; echo hi > probe.txt");
    }

    #[test]
    fn an_abbreviated_dest_dir_flag_now_resolves_like_the_full_spelling() {
        // [task 7, spec §4.1.7] Before the shared flag primitive, `-pa` (an
        // abbreviation of `-Path`) matched neither declared list under the
        // old exact-string comparison, so it fell to rule 4 and asked —
        // safe, but wrong about WHY: it named the destination "unresolved"
        // when the operator's line named one plainly. Exactly the shape
        // M2.128 fixed for `written_paths`'s own `Set-Content -pa`.
        // `dest_dir_flags` now reads the same case-insensitive-accepts-
        // abbreviation policy: `-pa` resolves to `-Path`, its value IS the
        // destination, and the write rule judges the REAL composed path
        // (here, outside the allowed area) rather than asking about an
        // unresolved one.
        assert_destination("ps", "Set-Location -pa C:/x; \"y\" > probe.txt", "C:/x/probe.txt");
    }

    #[test]
    fn an_undeclared_option_names_itself_and_the_head_in_the_reason() {
        // Task 9 (spec §9.1): `vouch doctor`'s third bucket parses this
        // exact marker back out of the journal, so the format is a tested
        // contract, not just prose. `-P` is the resolved token (§8, M2.38 —
        // not the raw one), `cd` the matched entry's own name (base_name
        // form, already lowercased).
        match decide("bash", "cd -P /tmp; echo hi > probe.txt") {
            Decision::Ask(r) => assert!(
                r.contains("the option '-P' is not described for 'cd'"),
                "marker missing: {r}"
            ),
            d => panic!("expected ask, got {d:?}"),
        }
    }

    // -- rule 1, amended (2026-08-02, spec commit 5de2603) -------------------
    // Review probe: `Set-Location -Path -PassThru` bound `-PassThru` as the
    // dest-dir flag's VALUE and composed a base named literally
    // `<cwd>/-PassThru`, while real PowerShell throws a binding error there
    // and never moves — `-PassThru` binds as its OWN flag, not as `-Path`'s
    // value. A consumed dest-dir value that is itself option-shaped, `-`, or
    // `+` is not a directory the shell was given, so it is the same
    // unresolved unknown as any other rule-4/5 case, never a candidate.

    #[test]
    fn a_dest_dir_flags_option_shaped_value_is_unknown_not_a_composed_base() {
        match decide("ps", r#"Set-Location -Path -PassThru; "x" > probe.txt"#) {
            Decision::Ask(r) => {
                assert!(r.contains("unresolved_path"), "{r}");
                // The defect being fixed: composing `<cwd>/-PassThru` as the
                // base and asking about THAT path instead of failing closed.
                assert!(!r.contains("-PassThru/"), "must not compose a base from the flag's own value: {r}");
            }
            d => panic!("expected ask, got {d:?}"),
        }
    }

    #[test]
    fn a_dest_dir_flags_dash_value_is_unknown_not_a_composed_base() {
        // Same shape, PowerShell 7's history-navigation spelling: `-Path -`
        // binds `-` as `-Path`'s value, which is not a directory either.
        match decide("ps", r#"Set-Location -Path -; "x" > probe.txt"#) {
            Decision::Ask(r) => {
                assert!(r.contains("unresolved_path"), "{r}");
                assert!(!r.contains("/-/"), "must not compose a base from `-`: {r}");
            }
            d => panic!("expected ask, got {d:?}"),
        }
    }

    #[test]
    fn a_dest_dir_flags_ordinary_value_still_resolves() {
        // The positive control: an ordinary directory behind `-Path` is
        // untouched by the amendment above — it still binds and moves.
        assert!(matches!(
            decide("ps", "Set-Location -Path C:/work; \"x\" > probe.txt"),
            Decision::Allow(_)
        ));
    }

    // -- rule 4, disclosed delta (2026-08-02 review) -------------------------
    #[test]
    fn a_bash_end_of_options_marker_is_undeclared_and_asks() {
        // `cd -- C:/x` really moves in bash (`--` is the standard
        // end-of-options marker), but the bash `cd` entry declares no
        // grammar at all (spec §6 table, deliberate), so `--` is an
        // undeclared option-shaped token and rule 4 asks — a real, corpus-
        // silent behaviour change from before this task (Task 1 measured
        // zero `cd --` rows in the real corpus). If this ever asks in
        // practice, the fix is declaring `--` as a `no_value_options` entry
        // on the bash `cd` knowledge, not softening rule 4.
        assert_asks("bash", "cd -- C:/x; echo hi > probe.txt");
    }

    // -- destination-token vocabulary (Task 8, spec 2026-07-31 §5) ----------
    // What stays in code is the VOCABULARY, not program names: token
    // semantics keyed on the kind and the command's own language.

    #[test]
    fn bash_tilde_dash_is_unknown_not_a_literal_directory() {
        // Rule 2: `~-` walks OLDPWD, not a directory literally named `~-`.
        // Before this rule it composed a literal `Known("~-")` base and
        // ALLOWED the write that followed — the probed false-Known.
        assert_asks("bash", "cd ~-; echo hi > probe.txt");
    }

    #[test]
    fn bash_tilde_name_is_unknown_another_users_home() {
        // Rule 2: `~alice/x` names ANOTHER user's home directory — a
        // directory this command line never states and vouch has no way to
        // resolve, not the operator's own home and not a relative path
        // literally spelled `~alice`.
        assert_asks("bash", "cd ~alice/x; echo hi > probe.txt");
    }

    #[test]
    fn bash_plain_home_compose_is_unchanged() {
        // The control for the rule above: plain `~/x` home expansion is
        // untouched — only the NON-plain `~`-forms became unknown.
        assert_destination("bash", "cd ~/x; echo hi > probe.txt", "<home>/x/probe.txt");
    }

    #[test]
    fn powershell_bare_plus_is_unknown() {
        // Rule 3: bare `+` walks the location-history stack forward on 7.x
        // and raises an error on 5.1 — unknown covers both directions.
        assert_asks("ps", r#"cd +; "y" > probe.txt"#);
    }

    #[test]
    fn a_glob_metacharacter_in_the_destination_is_unknown() {
        // Rule 1 (both languages): a glob expands before `cd` runs, so the
        // literal spelling is not the directory `cd` actually lands in.
        assert_asks("bash", "cd 'b*ld'; echo hi > probe.txt");
    }
}
