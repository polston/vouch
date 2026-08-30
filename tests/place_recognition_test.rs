//! Recognition walks the EXPANDED command list, one occurrence at a time
//! (M2.46, spec 2026-08-06 §Recognition).
//!
//! Recognition used to read `scan.commands` — the commands as WRITTEN. Guards
//! have read the expanded list (every command pulled out of a wrapper) since
//! wrappers were first unwrapped, so `env someunknownprogramzz` was guarded on
//! the real program and RECOGNISED on the word `env`: the wrapper is described,
//! so the line was allowed and the program inside it was never checked at all.
//! That is the allow-list going quiet exactly where CLAUDE.md §1 says it must
//! speak up.
//!
//! Each occurrence is judged under ITS OWN language (`all_langs[i]`), because a
//! snippet in another scanner's syntax is not a claim about the host language:
//! a PowerShell snippet's unknown head is settable under
//! `lang.powershell.constructs.unmodeled_command`, not bash's.

mod common;

use vouch::engine::decide_command_at;
use vouch::protocol::Decision;
use vouch::shell::Cmd;

/// Everything allowed except the one check under test, so an Ask can only have
/// come from `unmodeled_command`.
fn ask_cfg() -> vouch::config::Config {
    vouch::config::load(
        "[lang.bash]\ndefault = \"allow\"\n[lang.bash.constructs]\nunmodeled_command = \"ask\"",
    )
    .unwrap()
}

/// M2.46, probed live 2026-08-06: bare unknown asks, env-spelled allowed.
#[test]
fn a_wrapper_spelled_unknown_head_asks_like_the_bare_one() {
    let cfg = ask_cfg();
    let bare = decide_command_at(&cfg, "bash", "someunknownprogramzz x", None, None, None);
    let wrapped = decide_command_at(&cfg, "bash", "env someunknownprogramzz x", None, None, None);
    assert!(matches!(bare, Decision::Ask(_)));
    match wrapped {
        Decision::Ask(r) => assert!(r.contains("someunknownprogramzz"), "{r}"),
        other => panic!("env-spelled unknown must ask: {other:?}"),
    }
}

#[test]
fn a_snippet_spelled_unknown_head_asks_under_its_own_language() {
    let cfg = ask_cfg();
    let d = decide_command_at(&cfg, "bash", "bash -c \"someunknownprogramzz x\"", None, None, None);
    match d {
        // Named, not merely asked: `bash -c` could ask for a construct reason
        // and look identical from the outside.
        Decision::Ask(r) => assert!(r.contains("someunknownprogramzz"), "{r}"),
        other => panic!("a snippet-spelled unknown must ask: {other:?}"),
    }
}

#[test]
fn two_occurrences_of_one_unknown_name_both_reach_the_check() {
    let cfg = ask_cfg();
    let d = decide_command_at(
        &cfg,
        "bash",
        "someunknownprogramzz a && someunknownprogramzz b",
        None,
        None,
        None,
    );
    // One prompt (their place answers agree), naming the program once.
    match d {
        Decision::Ask(r) => assert_eq!(
            r.matches("an entry would recognise every operation of").count(),
            1,
            "one name, one item: {r}"
        ),
        other => panic!("expected one ask: {other:?}"),
    }
}

/// The language ruling, both directions. A PowerShell snippet's unknown head
/// is gated by PowerShell's own setting: bash's says nothing about a command
/// written in another syntax, and a prompt that named bash's setting would name
/// an off-switch that does not turn it off (CLAUDE.md §5).
fn cross_lang_cfg(powershell_unmodeled: &str) -> vouch::config::Config {
    vouch::config::load(&format!(
        "[lang.bash]\ndefault = \"allow\"\n[lang.bash.constructs]\nunmodeled_command = \"allow\"\n\
         [lang.powershell]\ndefault = \"allow\"\n[lang.powershell.constructs]\n\
         unmodeled_command = \"{powershell_unmodeled}\"\n"
    ))
    .unwrap()
}

#[test]
fn a_powershell_snippets_unknown_head_is_gated_by_powershells_own_setting() {
    let d = decide_command_at(
        &cross_lang_cfg("ask"),
        "bash",
        "powershell -Command \"someunknownprogramzz x\"",
        None,
        None,
        None,
    );
    match d {
        Decision::Ask(r) => {
            assert!(r.contains("someunknownprogramzz"), "{r}");
            // §5: the setting named has to be the one that turns THIS prompt
            // off. bash's is already "allow" here, so naming it would be a
            // switch that does nothing.
            assert!(
                r.contains("set lang.powershell.constructs.unmodeled_command = \"allow\""),
                "the off-switch is not powershell's: {r}"
            );
            assert!(!r.contains("lang.bash.constructs"), "bash's setting is not the one: {r}");
            // And the reader is told which syntax the name was read as, since
            // the line they typed was bash.
            assert!(r.contains("(written in powershell)"), "{r}");
        }
        other => panic!("the powershell setting must reach the snippet: {other:?}"),
    }
}

#[test]
fn a_line_unknown_in_two_languages_names_both_off_switches() {
    // A prompt that named one language's setting here would turn off half of
    // what it is complaining about, and the operator would set it, see the
    // prompt again, and conclude vouch lies about its own settings (§5).
    let cfg = vouch::config::load(
        "[lang.bash]\ndefault = \"allow\"\n[lang.bash.constructs]\nunmodeled_command = \"ask\"\n\
         [lang.powershell]\ndefault = \"allow\"\n[lang.powershell.constructs]\n\
         unmodeled_command = \"ask\"\n",
    )
    .unwrap();
    let d = decide_command_at(
        &cfg,
        "bash",
        "someunknownprogramzz a && powershell -Command \"anotherunknownprogramzz b\"",
        None,
        None,
        None,
    );
    match d {
        Decision::Ask(r) => {
            assert!(r.contains("someunknownprogramzz"), "{r}");
            assert!(r.contains("anotherunknownprogramzz"), "{r}");
            assert!(
                r.contains(
                    "set lang.bash.constructs.unmodeled_command = \"allow\" and \
                     lang.powershell.constructs.unmodeled_command = \"allow\" — that allows every \
                     program"
                ),
                "both off-switches must be named, and read as one sentence: {r}"
            );
        }
        other => panic!("expected an ask naming both: {other:?}"),
    }
}

#[test]
fn the_same_snippet_allows_when_powershell_allows_it() {
    // The other half of the ruling, and the reason `common::realistic_config`
    // now mirrors the bash line into `[lang.powershell.constructs]`: without this
    // arm the replay would move rows for a language nobody configured.
    let d = decide_command_at(
        &cross_lang_cfg("allow"),
        "bash",
        "powershell -Command \"someunknownprogramzz x\"",
        None,
        None,
        None,
    );
    assert!(matches!(d, Decision::Allow(_)), "{d:?}");
}

// --- the place-aware recognition primitive ----------------------------------
//
// `recognises_at` is what Task 6's zone checks call with a real run place.
// Here it is exercised directly, because this task deliberately passes
// `run_place: None` from the engine: the seam has to be provably right before
// anything is wired through it.

fn scoped_kb() -> vouch::guards::Knowledge {
    vouch::guards::load(
        "[[program]]\nmatch = [\"probe-tool\"]\nonly_under = [\"C:/scratch/**\"]\n",
    )
    .expect("the fixture's own knowledge parses")
}

fn probe() -> Cmd {
    Cmd {
        head: "probe-tool".into(),
        args: vec!["x".into()],
        unread_args: Default::default(),
        keyword_args: Default::default(),
        callable_args: Default::default(),
        chain: None,
        prefix_assigns: vec![],
        receiver_origin: vouch::syntax::ValueOrigin::Unknown,
        by_reference: false,
    }
}

/// The place a recognition question is asked at, under this file's fixed home
/// and with no project root — what every case here shares but the one that
/// exists to vary the project root.
fn at(dir: Option<&str>) -> vouch::guards::RecognitionPlace<'_> {
    vouch::guards::RecognitionPlace { dir, home: "C:/Users/dev", project_root: None }
}

#[test]
fn a_place_scoped_entry_counts_inside_its_tree() {
    let kb = scoped_kb();
    assert!(vouch::guards::recognises_at(
        &kb,
        &probe(),
        "bash",
        at(Some("C:/scratch/work")),
        // The probe's arguments were built right here, so the record is
        // complete and closed by construction (spec 2026-08-20 §2.4).
        true
    ));
}

#[test]
fn a_place_scoped_entry_does_not_count_outside_its_tree() {
    let kb = scoped_kb();
    assert!(!vouch::guards::recognises_at(&kb, &probe(), "bash", at(Some("C:/elsewhere")), true));
}

#[test]
fn a_place_scoped_entry_does_not_count_when_the_place_is_unknown() {
    // The strict direction on purpose: an entry that says "only under this
    // tree" has made no claim about a command whose tree vouch cannot name,
    // and absence of knowledge is never the permissive case (§1). It is also
    // what keeps `recognises` — which delegates with no place — agreeing with
    // `recognises_at` wherever the engine calls both.
    let kb = scoped_kb();
    assert!(!vouch::guards::recognises_at(&kb, &probe(), "bash", at(None), true));
    assert!(!vouch::guards::recognises(&kb, &probe(), "bash", true));
}

#[test]
fn an_unscoped_entry_counts_wherever_it_runs() {
    let kb = vouch::guards::load("[[program]]\nmatch = [\"probe-tool\"]\n").unwrap();
    for place in [None, Some("C:/scratch/work"), Some("C:/elsewhere")] {
        assert!(vouch::guards::recognises_at(&kb, &probe(), "bash", at(place), true), "{place:?}");
    }
}

#[test]
fn a_place_scope_written_with_a_home_shorthand_expands_before_it_is_compared() {
    let kb = vouch::guards::load(
        "[[program]]\nmatch = [\"probe-tool\"]\nonly_under = [\"~/scratch/**\"]\n",
    )
    .unwrap();
    assert!(vouch::guards::recognises_at(
        &kb,
        &probe(),
        "bash",
        at(Some("C:/Users/dev/scratch/deep")),
        true
    ));
}

#[test]
fn a_project_root_place_scope_cannot_apply_when_there_is_no_project_root() {
    // `expand_pattern` returns None, and a glob that cannot be expanded is a
    // glob that matches nothing — never one that matches everything.
    let kb = vouch::guards::load(
        "[[program]]\nmatch = [\"probe-tool\"]\nonly_under = [\"$PROJECT_ROOT/**\"]\n",
    )
    .unwrap();
    assert!(!vouch::guards::recognises_at(&kb, &probe(), "bash", at(Some("C:/workspace/vouch-dev/src")), true));
    assert!(vouch::guards::recognises_at(
        &kb,
        &probe(),
        "bash",
        vouch::guards::RecognitionPlace {
            dir: Some("C:/workspace/vouch-dev/src"),
            home: "C:/Users/dev",
            project_root: Some("C:/workspace/vouch-dev"),
        },
        true
    ));
}

// --- the shared pattern helpers ---------------------------------------------

#[test]
fn expand_pattern_resolves_home_and_project_root() {
    use vouch::paths::expand_pattern;
    assert_eq!(expand_pattern("~/x", "C:/Users/dev", None).as_deref(), Some("C:/Users/dev/x"));
    assert_eq!(expand_pattern("$PROJECT_ROOT/x", "C:/Users/dev", None), None);
    assert_eq!(
        expand_pattern("$PROJECT_ROOT/x", "C:/Users/dev", Some("C:/workspace/vouch-dev")).as_deref(),
        Some("C:/workspace/vouch-dev/x")
    );
}

#[test]
fn under_any_reads_a_trailing_double_star_as_the_tree_including_its_root() {
    use vouch::paths::under_any;
    let globs = vec!["C:/scratch/**".to_string()];
    assert!(under_any(&globs, "C:/scratch"), "the root of the tree is in it");
    assert!(under_any(&globs, "C:/scratch/a/b"));
    assert!(!under_any(&globs, "C:/scratchpad"), "a name prefix is not a tree prefix");
    assert!(!under_any(&globs, "C:/elsewhere"));
    assert!(!under_any(&[], "C:/scratch"), "no globs, nothing to be under");
    // Without `/**` the glob names one directory and nothing below it.
    assert!(under_any(&["C:/scratch".to_string()], "C:/scratch"));
    assert!(!under_any(&["C:/scratch".to_string()], "C:/scratch/a"));
}

#[test]
fn under_any_follows_the_platforms_own_path_equality() {
    use vouch::paths::under_any;
    let hit = under_any(&["C:/Scratch/**".to_string()], "C:/scratch/a");
    if cfg!(any(windows, target_os = "macos")) {
        assert!(hit, "one tree under two spellings");
    } else {
        assert!(!hit, "linux is exact");
    }
}

// --- trust and distrust zones, decided end to end ---------------------------
//
// The primitive above, wired through the engine: every head — including the
// wrapper-expanded ones — is judged at the place its own occurrence runs in,
// and a grant needs a PROVEN place while a restriction applies unless the
// place is provably outside it (spec 2026-08-06 §The one rule for
// uncertainty).

/// Everything allowed except the unknown-program check, plus whatever `[run]`
/// the test is about — so an Ask can only have come from a place rule or from
/// `unmodeled_command`.
fn zone_cfg(extra: &str) -> vouch::config::Config {
    vouch::config::load(&format!(
        "[lang.bash]\ndefault = \"allow\"\n[lang.bash.constructs]\nunmodeled_command = \"ask\"\n{extra}"
    ))
    .unwrap()
}

#[test]
fn a_trust_zone_recognises_an_unknown_program_inside_it() {
    let cfg = zone_cfg("[run]\ntrust_all_under = [\"C:/scratch/**\"]");
    let d =
        decide_command_at(&cfg, "bash", "someunknownprogramzz x", None, None, Some("C:/scratch/job1"));
    match d {
        Decision::Allow(r) => {
            assert!(r.contains("trust_all_under") && r.contains("C:/scratch/**"), "{r}");
            assert!(r.contains("trusted because you trust commands run from this location"), "{r}");
        }
        other => panic!("in-zone unknown must be recognised: {other:?}"),
    }
}

#[test]
fn the_same_command_outside_the_zone_still_asks() {
    let cfg = zone_cfg("[run]\ntrust_all_under = [\"C:/scratch/**\"]");
    let d = decide_command_at(&cfg, "bash", "someunknownprogramzz x", None, None, Some("C:/work"));
    assert!(matches!(d, Decision::Ask(_)), "{d:?}");
}

#[test]
fn a_cd_prefix_moves_the_command_into_the_zone() {
    let cfg = zone_cfg("[run]\ntrust_all_under = [\"C:/scratch/**\"]");
    let d = decide_command_at(
        &cfg,
        "bash",
        "cd C:/scratch/job1 && someunknownprogramzz x",
        None,
        None,
        Some("C:/work"),
    );
    assert!(matches!(d, Decision::Allow(_)), "{d:?}");
}

#[test]
fn an_unprovable_place_grants_nothing_and_the_prompt_says_a_zone_might_have() {
    let cfg = zone_cfg("[run]\ntrust_all_under = [\"C:/scratch/**\"]");
    let d = decide_command_at(
        &cfg,
        "bash",
        "cd a || cd b; someunknownprogramzz x",
        None,
        None,
        Some("C:/scratch/j"),
    );
    match d {
        Decision::Ask(r) => assert!(r.contains("cannot prove"), "missed-grant line required: {r}"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_distrust_zone_makes_even_a_described_program_ask() {
    let cfg = zone_cfg("[run]\ntrust_nothing_under = [\"D:/inbox/**\"]");
    let d = decide_command_at(&cfg, "bash", "ls -la", None, None, Some("D:/inbox/sub"));
    match d {
        Decision::Ask(r) => {
            assert!(r.contains("trust_nothing_under") && r.contains("D:/inbox/**"), "{r}");
            // Spec prompt table: "described programs ask here too".
            assert!(r.contains("described programs ask here too"), "{r}");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn an_unprovable_place_near_a_distrust_zone_restricts_and_names_the_cause() {
    let cfg = zone_cfg("[run]\ntrust_nothing_under = [\"D:/inbox/**\"]");
    let d = decide_command_at(&cfg, "bash", "cd a || cd b; ls -la", None, None, Some("C:/work"));
    match d {
        Decision::Ask(r) => {
            assert!(r.contains("trust_nothing_under"), "{r}");
            assert!(r.contains("might"), "{r}");
            // The M2.58 standard: WHAT made the place unprovable. The
            // CdState::Unknown cause string is available per occurrence via
            // base_at; NoDirectory's words are the NO_CWD const.
            assert!(
                r.contains("||") || r.contains("cannot order") || r.contains("directory"),
                "cause required: {r}"
            );
        }
        other => panic!("{other:?}"),
    }
}

/// [review] A run-dir flag says where THIS command runs, and the zone pass has
/// to honour it — the write pass already did, so `git -C <tree> <verb>` had its
/// writes judged at the flag's directory while a zone was settled on the
/// SHELL's. That is one command with two run places, and it meant a distrust
/// zone could be stepped around by spelling the directory as a flag rather than
/// a `cd`.
#[test]
fn a_run_dir_flag_carries_a_command_into_a_distrust_zone() {
    let cfg = zone_cfg("[run]\ntrust_nothing_under = [\"C:/scratch/**\"]");
    let inside = decide_command_at(
        &cfg,
        "bash",
        "git -C C:/scratch/j status",
        None,
        None,
        Some("C:/work"),
    );
    match inside {
        Decision::Ask(r) => {
            assert!(r.contains("trust_nothing_under"), "{r}");
            assert!(r.contains("C:/scratch/j"), "the flag's directory is the run place: {r}");
        }
        other => panic!("a run-dir flag into the zone must restrict: {other:?}"),
    }
    // The control: same command, no flag, shell outside the zone — untouched.
    let outside = decide_command_at(&cfg, "bash", "git status", None, None, Some("C:/work"));
    assert!(matches!(outside, Decision::Allow(_)), "{outside:?}");
}

/// The granting direction of the same fix. A trust zone needs the place
/// PROVEN inside its tree, and here the only thing that puts it there is the
/// run-dir flag. `probe-tool` is described with a verb list, so
/// `probe-tool <unknown verb>` is unrecognised and the zone is what decides it
/// — the shipped `git` entry states neither recognition scope, so nothing about it is ever
/// unrecognised and it cannot show this.
#[test]
fn a_run_dir_flag_carries_a_command_into_a_trust_zone() {
    let mine = "[[program]]\nmatch = [\"probe-tool\"]\n\
                value_options = [\"-C\"]\nrun_dir_flags = [\"-C\"]\n\
                subcommands = [\"status\"]\n";
    let cfg = "version = 1\n[lang.bash]\ndefault = \"allow\"\n\
               [lang.bash.constructs]\nunmodeled_command = \"ask\"\n\
               [run]\ntrust_all_under = [\"C:/scratch/**\"]\n";
    let (verdict, reason) = hook_at(
        "rundir_trust_in",
        mine,
        cfg,
        "C:/work",
        "probe-tool -C C:/scratch/j frobnicate",
    );
    assert_eq!(verdict, "allow", "{reason}");
    assert!(reason.contains("trust_all_under"), "the zone decided it: {reason}");

    // Without the flag the same unknown verb runs where the shell is, outside
    // the tree, and the zone grants nothing.
    let (verdict, reason) =
        hook_at("rundir_trust_out", mine, cfg, "C:/work", "probe-tool frobnicate");
    assert_eq!(verdict, "ask", "{reason}");
}

#[test]
fn a_distrust_zone_whose_pattern_cannot_be_resolved_still_restricts() {
    // [review] A pattern that names no directory on this machine used to drop
    // out of the list, which left the zone looking ABSENT — everything
    // allowed, nothing said. That is the uncertainty rule inverted for the one
    // restrict-shaped rule there is: a command cannot be proven OUTSIDE a tree
    // vouch cannot locate, so the restriction applies until it can.
    let cfg = zone_cfg("[run]\ntrust_nothing_under = [\"$PROJECT_ROOT/**\"]");
    let d = decide_command_at(&cfg, "bash", "ls -la", None, None, Some("C:/work"));
    match d {
        Decision::Ask(r) => {
            assert!(r.contains("trust_nothing_under"), "{r}");
            assert!(r.contains("$PROJECT_ROOT/**"), "the unresolvable pattern is unnamed: {r}");
            assert!(r.contains("could not resolve"), "why it applies is unsaid: {r}");
        }
        other => panic!("an unresolvable restrict pattern must not silently lapse: {other:?}"),
    }
}

#[test]
fn a_zone_prompt_with_no_working_directory_says_that_is_the_cause() {
    // [review] The other `unproven_cause` arm. `CdState::NoDirectory` is not a
    // directory change vouch could not order — it is having been handed no
    // directory at all, and the prompt has to say which of the two it is
    // (M2.58: the cause named must be THE cause).
    let cfg = zone_cfg("[run]\ntrust_nothing_under = [\"D:/inbox/**\"]");
    let d = decide_command_at(&cfg, "bash", "ls -la", None, None, None);
    match d {
        Decision::Ask(r) => {
            assert!(r.contains("trust_nothing_under"), "{r}");
            assert!(
                r.contains("no working directory"),
                "the no-directory cause is not the one named: {r}"
            );
            assert!(
                !r.contains("cannot order"),
                "this line has no directory change to blame: {r}"
            );
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_line_allows_by_zone_only_when_every_ungranted_occurrence_is_granted() {
    // The spec's "a line allows via zones only when EVERY otherwise-unknown
    // occurrence is granted", pinned: one command inside the zone, one
    // outside it, and the ask names only the one the zone did not reach.
    let cfg = zone_cfg("[run]\ntrust_all_under = [\"C:/scratch/**\"]");
    let d = decide_command_at(
        &cfg,
        "bash",
        "cd C:/scratch/j && someunknownprogramzz a && cd C:/work && anotherunknownprogramzz b",
        None,
        None,
        Some("C:/start"),
    );
    match d {
        Decision::Ask(r) => {
            assert!(r.contains("anotherunknownprogramzz"), "the ungranted one is unnamed: {r}");
            assert!(
                !r.contains("someunknownprogramzz"),
                "the granted one must not be named in the ask: {r}"
            );
        }
        other => panic!("one ungranted occurrence must hold the line: {other:?}"),
    }
}

#[test]
fn two_occurrences_of_one_name_disagreeing_about_a_zone_still_ask() {
    // The same rule with ONE name in both positions, which the pin above
    // cannot show: there, the granted and ungranted occurrences are different
    // programs, so a per-NAME answer and a per-OCCURRENCE answer look
    // identical. Here the name is asked about once and granted once, and the
    // unknown-program list is deduplicated by name — so a check that settled
    // `someunknownprogramzz` on either occurrence alone would allow the line
    // (first-wins) or ask about it (last-wins) for the wrong reason. The
    // first occurrence runs where the shell starts, outside the zone; the
    // `cd` puts the second inside it.
    let cfg = zone_cfg("[run]\ntrust_all_under = [\"C:/scratch/**\"]");
    let d = decide_command_at(
        &cfg,
        "bash",
        "someunknownprogramzz a && cd C:/scratch && someunknownprogramzz b",
        None,
        None,
        Some("C:/work"),
    );
    match d {
        Decision::Ask(r) => {
            assert!(r.contains("someunknownprogramzz"), "the program is unnamed: {r}");
            assert_eq!(
                r.matches("an entry would recognise every operation of").count(),
                1,
                "one name is one item however many occurrences held the line: {r}"
            );
        }
        other => panic!("an ungranted occurrence of a granted name must hold the line: {other:?}"),
    }
}

#[test]
fn an_allow_that_two_rules_decided_names_both_of_them() {
    // [review] A zone recognised one command and another language's own
    // `unmodeled_command` waved a second one through. Naming only the zone
    // journals one rule as having decided a line that two rules decided —
    // and the operator turning that zone off would still see this line pass.
    let cfg = vouch::config::load(
        "[lang.bash]\ndefault = \"allow\"\n[lang.bash.constructs]\nunmodeled_command = \"ask\"\n\
         [lang.powershell]\ndefault = \"allow\"\n[lang.powershell.constructs]\n\
         unmodeled_command = \"allow\"\n\
         [run]\ntrust_all_under = [\"C:/scratch/**\"]\n",
    )
    .unwrap();
    // The second command runs OUTSIDE the zone on purpose: inside it, the
    // zone recognises both and there is only one decider to name.
    let d = decide_command_at(
        &cfg,
        "bash",
        "someunknownprogramzz a && cd C:/work && powershell -Command \"anotherunknownprogramzz b\"",
        None,
        None,
        Some("C:/scratch/j"),
    );
    match d {
        Decision::Allow(r) => {
            assert!(r.contains("run.trust_all_under"), "the zone is unnamed: {r}");
            assert!(
                r.contains("lang.powershell.constructs.unmodeled_command"),
                "the second decider is unnamed: {r}"
            );
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_guard_still_fires_inside_a_trust_zone() {
    // Trust is recognition only (spec §2 applied to a place): the zone
    // removes unknown-program asks inside the tree and nothing else.
    let cfg = zone_cfg(
        "[run]\ntrust_all_under = [\"C:/scratch/**\"]\n[guards]\ndelete_recursive = \"ask\"",
    );
    let d = decide_command_at(&cfg, "bash", "rm -rf build", None, None, Some("C:/scratch/j"));
    assert!(matches!(d, Decision::Ask(_)), "{d:?}");
}

#[test]
fn one_name_read_under_two_languages_is_annotated_per_language() {
    // [review, Task 5 finding] The `(written in <lang>)` annotation used to be
    // first-seen-wins across a name-only dedupe key: one name occurring under
    // two languages printed ONE line carrying whichever language was seen
    // first, so half the prompt named the wrong syntax. The key carries the
    // language now, so each reading gets its own line and its own annotation.
    let cfg = vouch::config::load(
        "[lang.bash]\ndefault = \"allow\"\n[lang.bash.constructs]\nunmodeled_command = \"ask\"\n\
         [lang.powershell]\ndefault = \"allow\"\n[lang.powershell.constructs]\n\
         unmodeled_command = \"ask\"\n",
    )
    .unwrap();
    let d = decide_command_at(
        &cfg,
        "bash",
        "someunknownprogramzz a && powershell -Command \"someunknownprogramzz b\"",
        None,
        None,
        None,
    );
    match d {
        Decision::Ask(r) => {
            assert!(r.contains("(written in powershell)"), "the powershell reading is unnamed: {r}");
            assert_eq!(
                r.matches("an entry would recognise every operation of").count(),
                2,
                "one name read two ways is two claims, not one: {r}"
            );
        }
        other => panic!("expected an ask: {other:?}"),
    }
}

// --- place-scoped entries, decided end to end -------------------------------
//
// These need a knowledge PAIR the test writes itself, and the engine reads its
// knowledge from the process-global `guards::in_effect()` cache — so a pair
// cannot be handed to `decide_command_at` in-process, and setting the env vars
// here would be a process-wide mutation racing every other test in this binary
// (CLAUDE.md §9). `common::hook_bash_at` spawns a child process, which gets its
// own environment, its own cache, and the real `--hook` path.

/// One `vouch --hook` run, tagged so this binary's temp fixtures never collide
/// with another test binary running the same shared helper in parallel.
fn hook_at(tag: &str, mine: &str, cfg: &str, cwd: &str, command: &str) -> (String, String) {
    common::hook_bash_at(&format!("place_recognition_{tag}"), mine, cfg, cwd, command)
}

/// The operator's own entry, scoped to one tree. `probe-tool` is described by
/// nothing in the shipped file, which is what `only_under` requires (spec
/// §Refused shapes — scoping a shipped name refuses the whole load).
const SCOPED_MINE: &str = "[[program]]\nmatch = [\"probe-tool\"]\nonly_under = [\"C:/scratch/**\"]\n";

/// Unknown programs ask, everything else is out of the way, and no zone is
/// configured — so only the ENTRY's place scope can decide these.
const SCOPED_CFG: &str = "version = 1\n[lang.bash]\ndefault = \"allow\"\n\
                          [lang.bash.constructs]\nunmodeled_command = \"ask\"\n";

#[test]
fn a_place_scoped_entry_recognises_inside_and_the_allow_names_the_entry() {
    let (verdict, reason) =
        hook_at("scoped_inside", SCOPED_MINE, SCOPED_CFG, "C:/scratch/job1", "probe-tool x");
    assert_eq!(verdict, "allow", "{reason}");
    // Spec prompt table, "place-scoped entry allow": the reason names the
    // entry and the matched tree, so the journal says WHY it was allowed.
    assert!(reason.contains("probe-tool"), "the allow does not name the entry: {reason}");
    assert!(reason.contains("C:/scratch/**"), "the allow does not name the tree: {reason}");
}

#[test]
fn a_place_scoped_entry_at_a_proven_place_outside_names_the_entry_it_has() {
    // Spec prompt table, "scoped entry exists, place PROVEN outside its
    // trees" (added 2026-08-06 after the Task 5 review demonstrated it end to
    // end): the ask names the EXISTING entry and its trees, and must NOT
    // print the recognise-it-afresh suggestion — a fresh unscoped entry for a
    // scoped name is refused at load, so following that advice breaks the
    // whole my-knowledge file.
    let (verdict, reason) =
        hook_at("scoped_outside", SCOPED_MINE, SCOPED_CFG, "C:/work", "probe-tool x");
    assert_eq!(verdict, "ask", "{reason}");
    assert!(reason.contains("probe-tool"), "{reason}");
    assert!(reason.contains("C:/scratch/**"), "the entry's trees are unnamed: {reason}");
    assert!(reason.contains("C:/work"), "where it actually runs is unnamed: {reason}");
    assert!(
        !reason.contains("vouch-trust skill"),
        "a fresh entry collides with the scoped one and must not be suggested: {reason}"
    );
    assert!(
        reason.contains("only_under"),
        "the setting that would widen the entry is unnamed: {reason}"
    );
    // The place is PROVEN here, so nothing was missed — the missed-grant line
    // belongs to unprovable places only (decided at the Task 5 review).
    assert!(!reason.contains("cannot prove"), "nothing was unprovable here: {reason}");
}

#[test]
fn a_scoped_name_beside_a_plain_unknown_keeps_the_fresh_entry_advice_off_the_scoped_one() {
    // The suggestion is per NAME, not per prompt. A line carrying both kinds
    // still tells the operator to write an entry — for the program that has
    // none — while the scoped one gets the widen-what-you-have advice, or the
    // two would be one instruction that breaks the file for one of them.
    let (verdict, reason) = hook_at(
        "scoped_and_plain",
        SCOPED_MINE,
        SCOPED_CFG,
        "C:/work",
        "probe-tool x && someunknownprogramzz y",
    );
    assert_eq!(verdict, "ask", "{reason}");
    assert!(reason.contains("no description of: someunknownprogramzz"), "{reason}");
    assert!(
        !reason.contains("no description of: probe-tool"),
        "the scoped name is not undescribed, it is out of reach: {reason}"
    );
    assert!(reason.contains("vouch-trust skill"), "the plain unknown lost its remedy: {reason}");
    assert!(
        !reason.contains("    probe-tool"),
        "the scoped name must not be listed as an entry to write: {reason}"
    );
    assert!(reason.contains("only_under"), "the scoped name lost its remedy: {reason}");
}

#[test]
fn a_place_scoped_entry_at_an_unprovable_place_asks_with_the_missed_grant_line() {
    let (verdict, reason) = hook_at(
        "scoped_unprovable",
        SCOPED_MINE,
        SCOPED_CFG,
        "C:/scratch/job1",
        "cd a || cd b; probe-tool x",
    );
    assert_eq!(verdict, "ask", "{reason}");
    assert!(
        reason.contains("covers a place this command might run in")
            && reason.contains("cannot prove it runs there"),
        "the missed-grant line is missing: {reason}"
    );
    // [review] This shape printed the write-a-fresh-entry advice too, and
    // following it appends an entry the loader then refuses — the same
    // dead-end the proven-outside row exists to close. The entry the operator
    // has is named; a second one is not suggested.
    assert!(reason.contains("probe-tool"), "{reason}");
    assert!(
        !reason.contains("vouch-trust skill"),
        "a second entry for a scoped name refuses the whole file: {reason}"
    );
    assert!(
        reason.contains("a wider `only_under` cannot help"),
        "the remedy must be a placeable command, not a wider tree: {reason}"
    );
}

#[test]
fn a_place_scoped_entry_that_covers_this_place_but_not_this_verb_says_which() {
    // [review] The third shape. Inside the trees and still unrecognised means
    // the entry's own `subcommands` list excluded it — saying "outside them"
    // here, or offering a fresh entry, both name a cause that is not the
    // cause.
    let mine = "[[program]]\nmatch = [\"probe-tool\"]\n\
                only_under = [\"C:/scratch/**\"]\nsubcommands = [\"go\"]\n";
    let (verdict, reason) =
        hook_at("scoped_verb", mine, SCOPED_CFG, "C:/scratch/job1", "probe-tool stop");
    assert_eq!(verdict, "ask", "{reason}");
    assert!(reason.contains("C:/scratch/job1"), "where it runs is unnamed: {reason}");
    assert!(reason.contains("`stop` operation"), "the verb is unnamed: {reason}");
    assert!(reason.contains("`subcommands`"), "the setting that fixes it is unnamed: {reason}");
    assert!(!reason.contains("outside them"), "it is not outside the trees: {reason}");
    assert!(!reason.contains("vouch-trust skill"), "{reason}");
}

#[test]
fn a_place_scoped_entry_whose_tree_cannot_be_resolved_says_so_not_outside_them() {
    // [review] The fourth shape, and the wording finding: an entry scoped to a
    // pattern that names no directory here applies NOWHERE — telling the
    // operator they are "outside" it implies moving would help, and it would
    // not.
    let mine = "[[program]]\nmatch = [\"probe-tool\"]\nonly_under = [\"$PROJECT_ROOT/**\"]\n";
    let (verdict, reason) =
        hook_at("scoped_unlocatable", mine, SCOPED_CFG, "C:/vouch-place-test-nowhere/j", "probe-tool x");
    assert_eq!(verdict, "ask", "{reason}");
    assert!(reason.contains("$PROJECT_ROOT/**"), "the pattern is unnamed: {reason}");
    assert!(
        reason.contains("names no directory on this machine"),
        "the cause is not the one named: {reason}"
    );
    assert!(!reason.contains("outside them"), "nothing was outside anything: {reason}");
    assert!(!reason.contains("vouch-trust skill"), "{reason}");
}

#[test]
fn the_entry_named_in_the_prompt_is_the_program_not_the_shown_verb() {
    // [review] The pin for the restored occurrence index. An item's SHOWN name
    // is `<program> <verb>` whenever an entry for the program exists, so a
    // prompt composed from that name alone says "your entry for `probe-tool
    // x`" — an entry by that name does not exist and never could. The index is
    // what gets back to the command, and `base_name` to the entry's own name.
    let (verdict, reason) =
        hook_at("scoped_named", SCOPED_MINE, SCOPED_CFG, "C:/work", "probe-tool x");
    assert_eq!(verdict, "ask", "{reason}");
    assert!(reason.contains("your entry for `probe-tool`"), "{reason}");
    assert!(
        !reason.contains("your entry for `probe-tool x`"),
        "the prompt names an entry that cannot exist: {reason}"
    );
}

#[test]
fn a_trust_zone_recognises_an_unknown_subcommand_of_a_described_program() {
    // Spec §Precedence step 3, "pinned by test": recognition is per verb
    // (§2), so a described program invoked with a verb its entry does not
    // list is unrecognised at step 2 — and the zone's "whatever it is"
    // includes verbs. Outside the zone the same line asks, or this would
    // prove nothing about the zone. A knowledge pair because no SHIPPED entry
    // carries a `subcommands` list, so nothing in the shipped file can put a
    // command in the verb-miss state this is about.
    let mine = "[[program]]\nmatch = [\"probe-tool\"]\nsubcommands = [\"go\"]\n";
    let cfg = "version = 1\n[lang.bash]\ndefault = \"allow\"\n\
               [lang.bash.constructs]\nunmodeled_command = \"ask\"\n\
               [run]\ntrust_all_under = [\"C:/scratch/**\"]\n";
    let (inside, why_in) = hook_at("zone_verb_in", mine, cfg, "C:/scratch/job1", "probe-tool stop");
    let (outside, why_out) = hook_at("zone_verb_out", mine, cfg, "C:/work", "probe-tool stop");
    assert_eq!(inside, "allow", "in-zone verb: {why_in}");
    assert!(why_in.contains("trust_all_under"), "the allow does not name the zone: {why_in}");
    assert_eq!(outside, "ask", "out-of-zone verb: {why_out}");
}

#[test]
fn a_tilde_spelled_only_under_expands() {
    // Without the expansion the glob is compared as the literal text `~/…`
    // and the entry is silently inert — it would recognise nothing, anywhere,
    // and nothing would say so.
    let mine = "[[program]]\nmatch = [\"probe-tool\"]\nonly_under = [\"~/scratch/**\"]\n";
    let (verdict, reason) =
        hook_at("scoped_tilde", mine, SCOPED_CFG, "C:/Users/dev/scratch/j", "probe-tool x");
    assert_eq!(verdict, "allow", "{reason}");
}

/// A place scope gates RECOGNITION and nothing else (spec §Place-scoped
/// recognition gates recognition, nothing else). The entry's descriptions —
/// here `writes = "named"` plus `write_flags`, the claim that `--out` names a
/// file this program writes — are claims about what the program IS (§3), true
/// in every directory, so they keep being read where the entry does not
/// recognise the program.
///
/// Two runs, both OUTSIDE the entry's tree, and the pair is what makes this
/// mean anything:
///
///   1. aimed into the write wall it DENIES, naming `write.deny_paths` and the
///      destination. Nothing but the entry's own `--out` description can put
///      that path in front of the wall — an unrecognised program with no
///      description read would have produced the unknown-program ask and
///      never mentioned the file at all;
///   2. aimed at an ordinary path it ASKS as unrecognised, so the place scope
///      is demonstrably still gating recognition in the same directory.
///
/// And the control that makes run 1 mean what it claims: the SAME command
/// under an entry carrying no write description at all only asks. Without it,
/// the deny could have come from anywhere and the pin would pass whether or
/// not the description was read.
///
/// A deny is asserted rather than the ask's text because a deny cannot be
/// produced by anything else in this config: it is the strongest observable
/// available, and it fails loudly if descriptions ever start being
/// place-gated along with recognition.
const DESCRIBED_SCOPED_MINE: &str = "[[program]]\nmatch = [\"probe-tool\"]\n\
                                     only_under = [\"C:/scratch/**\"]\n\
                                     value_options = [\"--out\"]\n\
                                     writes = \"named\"\nwrite_flags = [\"--out\"]\n";

const DESCRIBED_SCOPED_CFG: &str = "version = 1\n[lang.bash]\ndefault = \"allow\"\n\
                                    [lang.bash.constructs]\nunmodeled_command = \"ask\"\n\
                                    [write]\ndefault = \"allow\"\n\
                                    deny_paths = [\"D:/wall/**\"]\n";

#[test]
fn a_place_scoped_entrys_descriptions_still_apply_outside_its_trees() {
    let (verdict, reason) = hook_at(
        "scoped_desc_wall",
        DESCRIBED_SCOPED_MINE,
        DESCRIBED_SCOPED_CFG,
        "C:/work",
        "probe-tool --out D:/wall/x.txt",
    );
    assert_eq!(verdict, "deny", "the entry's write description was not read outside its tree: {reason}");
    assert!(reason.contains("write.deny_paths"), "{reason}");
    assert!(
        reason.contains("D:/wall/x.txt"),
        "the destination the `--out` description named is unsaid: {reason}"
    );

    // Same place, same entry: recognition IS still gated there.
    let (verdict, reason) = hook_at(
        "scoped_desc_plain",
        DESCRIBED_SCOPED_MINE,
        DESCRIBED_SCOPED_CFG,
        "C:/work",
        "probe-tool --out C:/work/x.txt",
    );
    assert_eq!(verdict, "ask", "{reason}");
    assert!(
        reason.contains("outside them"),
        "the scope must still be what withholds recognition here: {reason}"
    );

    // The control: strip the write description, keep everything else. The
    // same command at the same place must now only ask — which is what makes
    // the deny above attributable to the description and nothing else.
    let undescribed = DESCRIBED_SCOPED_MINE
        .replace("writes = \"named\"\n", "")
        .replace("write_flags = [\"--out\"]\n", "");
    let (verdict, reason) = hook_at(
        "scoped_desc_control",
        &undescribed,
        DESCRIBED_SCOPED_CFG,
        "C:/work",
        "probe-tool --out D:/wall/x.txt",
    );
    assert_eq!(
        verdict, "ask",
        "with no write declared there is nothing for the wall to catch: {reason}"
    );
}

// --- the boundary: place rules judge commands, tools keep their own path ----

/// Spec §Boundary — commands, not tools. A tool call's cwd is wherever the
/// session is parked, so a trust zone reaching tool recognition would
/// blanket-allow every unknown tool for a whole session parked in it. The
/// session here sits squarely inside the zone and the unknown tool must still
/// ask, naming its own setting.
#[test]
fn an_unknown_tool_called_from_inside_a_trust_zone_still_asks() {
    let kb = common::shipped_kb();
    let cfg = vouch::config::load(
        "version = 1\n[lang.bash]\ndefault = \"allow\"\n\
         [run]\ntrust_all_under = [\"C:/scratch/**\"]\n",
    )
    .expect("config parses");
    let tool = "mcp__probeserverzz__probetoolzz";
    let input = vouch::protocol::parse_input(&format!(
        r#"{{"session_id":"s","cwd":"C:/scratch/j","tool_name":"{tool}","tool_input":{{}}}}"#
    ))
    .expect("the fixture's hook input parses");
    match &vouch::route::decide(&cfg, &kb, common::HOOK_HOME, &input).decision {
        Decision::Ask(r) => {
            assert!(r.contains(&format!("tools.{tool}")), "the tool's own setting is unnamed: {r}");
            assert!(
                !r.contains("trust_all_under"),
                "a zone must not appear in a tool verdict at all: {r}"
            );
        }
        other => panic!("a zone must not reach tool recognition: {other:?}"),
    }
}

// --- a snippet with no directory, against both zone shapes ------------------
//
// A tool snippet carries a run place only via its entry's `cwd_from_call`
// claim (spec §Boundary). Without the claim `route::decide` hands the snippet
// to `decide_command_in_unknown_dir`, so its run place is NoDirectory however
// the session is parked — and the two zone shapes must answer that
// differently, because a grant needs the place PROVEN inside its tree while a
// restriction applies unless the place is provably OUTSIDE it (spec §The one
// rule for uncertainty). Getting this backwards would let any session parked
// in a trust zone launder unknown programs through an undeclared tool.

/// The declared tool both pins use: a snippet field, deliberately no
/// `cwd_from_call` claim.
const NO_CWD_TOOL: &str = "[[tool]]\nmatch = [\"mcp__p_s__sh\"]\n\
                           source = \"runs the `code` field as bash\"\n\
                           [[tool.snippet]]\nfield = \"code\"\nlanguage = \"bash\"\n";

fn sh_snippet_call(code: &str, cwd: &str) -> vouch::protocol::HookInput {
    vouch::protocol::parse_input(&format!(
        r#"{{"session_id":"s","cwd":"{cwd}","tool_name":"mcp__p_s__sh","tool_input":{{"code":"{code}"}}}}"#
    ))
    .expect("the fixture's hook input parses")
}

fn snippet_zone_cfg(zone: &str) -> vouch::config::Config {
    vouch::config::load(&format!(
        "version = 1\n[lang.bash]\ndefault = \"allow\"\n\
         [lang.bash.constructs]\nunmodeled_command = \"ask\"\n\
         [write]\ndefault = \"allow\"\n{zone}"
    ))
    .expect("config parses")
}

#[test]
fn a_snippet_with_no_directory_never_benefits_from_a_trust_zone() {
    let kb = common::kb_with(NO_CWD_TOOL);
    let cfg = snippet_zone_cfg("[run]\ntrust_all_under = [\"C:/scratch/**\"]\n");
    // The SESSION is inside the zone. The snippet is not, because nothing
    // says the tool runs where the session is.
    let input = sh_snippet_call("someunknownprogramzz x", "C:/scratch/j");
    match &vouch::route::decide(&cfg, &kb, common::HOOK_HOME, &input).decision {
        Decision::Ask(r) => {
            assert!(r.contains("someunknownprogramzz"), "the unknown program is unnamed: {r}");
            // The missed-grant line, and the cause it names has to be the
            // missing claim — not a directory change, of which there is none.
            assert!(
                r.contains("cannot prove it runs there"),
                "the near-miss on the zone is unsaid: {r}"
            );
            assert!(r.contains("cwd_from_call"), "the cause named is not the cause: {r}");
        }
        other => panic!("a session's zone must not reach a snippet with no directory: {other:?}"),
    }
}

#[test]
fn a_snippet_with_no_directory_is_still_restricted_by_a_distrust_zone() {
    let kb = common::kb_with(NO_CWD_TOOL);
    let cfg = snippet_zone_cfg("[run]\ntrust_nothing_under = [\"D:/inbox/**\"]\n");
    // A described program, and a session parked nowhere near the zone: the
    // only thing that can stop this is the restriction applying to a place
    // vouch cannot rule out.
    let input = sh_snippet_call("ls -la", "C:/work");
    match &vouch::route::decide(&cfg, &kb, common::HOOK_HOME, &input).decision {
        Decision::Ask(r) => {
            assert!(r.contains("run.trust_nothing_under"), "the zone is unnamed: {r}");
            assert!(r.contains("cwd_from_call"), "the cause named is not the cause: {r}");
            assert!(
                !r.contains("cannot order"),
                "there is no directory change here to blame: {r}"
            );
        }
        other => panic!("a restriction must survive a snippet with no directory: {other:?}"),
    }
}
