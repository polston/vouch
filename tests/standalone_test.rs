//! `standalone_flags` — recognising a flags-only run (spec 2026-08-20 §2).
//!
//! A standalone run is one where the argument walk finds no subcommand, the
//! argument vector is non-empty, every token is a whole-token member of the
//! entry's own `standalone_flags` under its stated case rule, and the record
//! of those arguments is one nothing off the line can add to. The last
//! condition is the `standalone_eligible` parameter every recognition entry
//! point now takes: the engine folds it from the occurrence's own
//! completeness and its not-under-an-appending-wrapper bit, and a caller that
//! BUILT the argument list itself passes `true`, because a hand-assembled
//! record drops nothing.

use vouch::guards::{load, recognises, unmodeled_descriptions, Knowledge};
use vouch::syntax::Cmd;

#[path = "common/mod.rs"]
mod common;

fn kb(text: &str) -> Knowledge {
    load(text).expect("fixture knowledge parses")
}

fn cmd(head: &str, args: &[&str]) -> Cmd {
    Cmd {
        head: head.into(),
        args: args.iter().map(|s| s.to_string()).collect(),
        unread_args: Default::default(),
        chain: None,
        prefix_assigns: vec![],
        receiver_origin: vouch::syntax::ValueOrigin::Unknown,
    }
}

/// The verb-scoped entry the §2 rules are written against: one verb, two
/// listed flags, and a stated case rule (§4 requires the key out loud on any
/// entry declaring `standalone_flags`).
const VERB_SCOPED: &str = "[[program]]\nmatch = [\"mytool\"]\nsubcommands = [\"build\"]\n\
     case_sensitive_flags = true\nstandalone_flags = [\"--version\", \"-V\"]\n";

/// The third `subcommands` state (§3): no verb coverage at all, only
/// standalone runs.
const EMPTY_SCOPED: &str = "[[program]]\nmatch = [\"mytool\"]\nsubcommands = []\n\
     case_sensitive_flags = true\nstandalone_flags = [\"--version\", \"-V\"]\n";

/// The key-absent state: whole-program coverage, which `standalone_flags`
/// neither widens nor narrows.
const WHOLE_PROGRAM: &str = "[[program]]\nmatch = [\"mytool\"]\n\
     case_sensitive_flags = true\nstandalone_flags = [\"--version\", \"-V\"]\n";

// ---------------------------------------------------------------------------
// Membership and the covers arm
// ---------------------------------------------------------------------------

#[test]
fn a_listed_flag_alone_is_recognised() {
    let k = kb(VERB_SCOPED);
    assert!(
        recognises(&k, &cmd("mytool", &["--version"]), "bash", true),
        "a run of one listed flag is a standalone run of the entry that lists it"
    );
}

#[test]
fn two_listed_flags_together_are_recognised() {
    // The claim is per COMBINATION as well as per flag: given only listed
    // flags, the program does the flags' own thing and stops.
    let k = kb(VERB_SCOPED);
    assert!(
        recognises(&k, &cmd("mytool", &["--version", "-V"]), "bash", true),
        "two listed flags together are still a standalone run"
    );
}

#[test]
fn a_quoted_listed_flag_is_recognised_like_the_bare_one() {
    // The scanner keeps the quotes in the token; membership compares the
    // UNQUOTED view, the same view every other flag comparison gets
    // (CLAUDE.md §8).
    let k = kb(VERB_SCOPED);
    assert!(
        recognises(&k, &cmd("mytool", &["\"--version\""]), "bash", true),
        "a quoted spelling of a listed flag must be judged like the bare one"
    );
}

#[test]
fn a_mixed_run_is_not() {
    // Any token the entry does not literally list sends the run down the
    // existing verb path, which for this entry finds no verb.
    let k = kb(VERB_SCOPED);
    assert!(
        !recognises(&k, &cmd("mytool", &["--version", "--other"]), "bash", true),
        "an unlisted token disqualifies the whole run"
    );
}

#[test]
fn a_bare_run_gains_nothing() {
    // Three states, and only the key-absent one covers a bare run — it
    // covered every run before this key existed and is unchanged by it.
    // Asserting false across all three would pin the wrong thing.
    assert!(
        recognises(&kb(WHOLE_PROGRAM), &cmd("mytool", &[]), "bash", true),
        "key-absent `subcommands` still covers the whole program, bare runs included"
    );
    assert!(
        !recognises(&kb(VERB_SCOPED), &cmd("mytool", &[]), "bash", true),
        "a verb-scoped entry gains no bare-run coverage from `standalone_flags`"
    );
    assert!(
        !recognises(&kb(EMPTY_SCOPED), &cmd("mytool", &[]), "bash", true),
        "an explicitly-empty entry gains no bare-run coverage either"
    );
}

#[test]
fn case_matters_when_the_entry_says_so() {
    let sensitive = kb("[[program]]\nmatch = [\"mytool\"]\nsubcommands = [\"build\"]\n\
         case_sensitive_flags = true\nstandalone_flags = [\"-V\"]\n");
    assert!(
        !recognises(&sensitive, &cmd("mytool", &["-v"]), "bash", true),
        "the entry states case-sensitive flags, and `-v` is not `-V`"
    );
    let insensitive = kb("[[program]]\nmatch = [\"mytool\"]\nsubcommands = [\"build\"]\n\
         case_sensitive_flags = false\nstandalone_flags = [\"-V\"]\n");
    assert!(
        recognises(&insensitive, &cmd("mytool", &["-v"]), "bash", true),
        "the entry states case-insensitive flags, so `-v` matches `-V`"
    );
}

#[test]
fn a_cluster_of_two_listed_letters_is_not_a_member() {
    // Membership is exact-token on purpose: the loose reading lets two
    // individually-vouched letters compose into a spelling nobody verified.
    let k = kb("[[program]]\nmatch = [\"mytool\"]\nsubcommands = [\"build\"]\n\
         case_sensitive_flags = true\nstandalone_flags = [\"-h\", \"-V\"]\n");
    assert!(
        !recognises(&k, &cmd("mytool", &["-hV"]), "bash", true),
        "a cluster is not a member even when both letters are listed"
    );
}

#[test]
fn an_abbreviation_is_not_a_member() {
    let k = kb(VERB_SCOPED);
    assert!(
        !recognises(&k, &cmd("mytool", &["--vers"]), "bash", true),
        "an abbreviation of a listed flag is not that flag"
    );
}

#[test]
fn an_attached_value_spelling_is_not_a_member() {
    // A value-carrying spelling would vouch a value-taking flag through the
    // side door.
    let k = kb(VERB_SCOPED);
    assert!(
        !recognises(&k, &cmd("mytool", &["--version=x"]), "bash", true),
        "an attached-value spelling is not the listed flag"
    );
}

#[test]
fn an_incomplete_record_disqualifies() {
    // The same covered shape, with the caller saying the record is not one
    // nothing can add to.
    let k = kb(VERB_SCOPED);
    assert!(
        !recognises(&k, &cmd("mytool", &["--version"]), "bash", false),
        "a record something can append to is never a standalone run"
    );
}

#[test]
fn explicit_empty_subcommands_cover_only_standalone_runs() {
    let k = kb(EMPTY_SCOPED);
    assert!(
        !recognises(&k, &cmd("mytool", &["build"]), "bash", true),
        "an explicitly-empty `subcommands` covers no verb"
    );
    assert!(
        recognises(&k, &cmd("mytool", &["--version"]), "bash", true),
        "an explicitly-empty entry still covers its own standalone runs"
    );
}

#[test]
fn a_verb_still_recognises_beside_the_flags() {
    let k = kb(VERB_SCOPED);
    assert!(
        recognises(&k, &cmd("mytool", &["build"]), "bash", true),
        "the verb arm is untouched by the standalone arm beside it"
    );
}

// ---------------------------------------------------------------------------
// End to end, through the hook path: the completeness fold the engine computes
// ---------------------------------------------------------------------------

/// One `vouch --hook` run with exactly ONE construct forced to ask. The
/// shared harness config reads permissive for these constructs, so without
/// the override a decision could come from a default rather than from the
/// rule under test — and the three suites below differ only in which
/// construct that is, which overlay they lay down, and how they tag their
/// scratch files.
fn hook_asking(
    prefix: &str,
    tag: &str,
    mine: &str,
    construct: &str,
    command: &str,
) -> (String, String) {
    let cfg = common::config_text_with(&[("bash", construct, "ask")]);
    common::hook_bash_at(&format!("{prefix}_{tag}"), mine, &cfg, common::HOOK_HOME, command)
}

/// Exactly one prompt item for `mytool`. The four spaces and the em dash are
/// the item-line shape the unmodeled prompt prints, so a second item would
/// change this count.
fn assert_one_item(reason: &str) {
    assert_eq!(reason.matches("    mytool —").count(), 1, "one item expected: {reason}");
}

/// The knowledge overlay these runs are decided against, and the config.
/// The shared harness default allows unmodeled commands under bash, under
/// which a disqualified run would allow and pin nothing — so every run below
/// uses the ask override.
fn hook(tag: &str, command: &str) -> (String, String) {
    hook_asking("standalone", tag, VERB_SCOPED, "unmodeled_command", command)
}

#[test]
fn a_top_level_standalone_run_allows_end_to_end() {
    let (decision, reason) = hook("top_level", "mytool --version");
    assert_eq!(decision, "allow", "got: {reason}");
}

#[test]
fn a_process_substitution_argument_disqualifies_end_to_end() {
    // The parser pushes no token for `<(…)` while the shell passes the
    // substitution's pathname, so the recorded argument list is not a
    // faithful record and the run is not standalone. The inner command is a
    // shipped read-only one so that the only unrecognised thing on the line
    // is the occurrence under test.
    let (decision, reason) = hook("proc_subst", "mytool --version <(echo hi)");
    assert_eq!(decision, "ask", "got: {reason}");
    assert!(reason.contains("unmodeled_command"), "got: {reason}");
    assert!(reason.contains("mytool"), "got: {reason}");
}

#[test]
fn an_appended_arguments_wrapper_disqualifies_end_to_end() {
    // More arguments arrive from a channel the line never names, so the
    // recorded list being complete is not enough.
    let (decision, reason) = hook("appended", "xargs mytool --version");
    assert_eq!(decision, "ask", "got: {reason}");
    assert!(reason.contains("unmodeled_command"), "got: {reason}");
    assert!(reason.contains("mytool"), "got: {reason}");
}

#[test]
fn a_same_syntax_wrapper_inherits_and_recognises() {
    // A rest-wrapper slices tokens out of the outer command rather than
    // scanning a snippet, so the unwrapped occurrence has no completeness
    // record of its own — it INHERITS the outer one. Reading it as false
    // would silently kill the feature for every wrapper-nested spelling.
    let (decision, reason) = hook("same_syntax", "command mytool --version");
    assert_eq!(decision, "allow", "got: {reason}");
}

// ---------------------------------------------------------------------------
// The stdin claim stands down on a standalone run (Task 6, spec §2 effect 2)
// ---------------------------------------------------------------------------

/// A stdin-evaluating entry shaped like the shipped shell entries: the
/// ordinary `evaluates_input = "stdin"` claim, a scannable `wrap_lang` so a
/// delivered here-document can still be scanned, and a `runs_file` claim so
/// the hint's `no_value_options` pairing (Task 4's membership rule) is
/// exercised rather than assumed.
const STDIN_EVALUATOR: &str = "[[program]]\nmatch = [\"fake-interp\"]\n\
     case_sensitive_flags = true\nno_value_options = [\"--version\"]\n\
     standalone_flags = [\"--version\"]\nevaluates_input = \"stdin\"\n\
     wrap_lang = \"bash\"\nruns_file = \"arg_0\"\n";

/// The same stdin claim split across two same-name entries — the shape the
/// shipped node/perl/ruby-style knowledge actually uses: one block carries
/// the stdin claim and nothing beyond `no_value_options`/`standalone_flags`,
/// a second, unrelated block carries a `wraps` vocabulary of its own.
/// Suppression has to key off the entry that MADE the stdin claim, not get
/// confused by a sibling with different vocabulary.
const SPLIT_ACROSS_ENTRIES: &str = "[[program]]\nmatch = [\"fake-interp\"]\n\
     case_sensitive_flags = true\nno_value_options = [\"--version\"]\n\
     standalone_flags = [\"--version\"]\nevaluates_input = \"stdin\"\n\
     wrap_lang = \"bash\"\n\
     [[program]]\nmatch = [\"fake-interp\"]\nwraps = \"after_flag\"\n\
     wrap_flags = [\"-e\"]\nwrap_lang = \"bash\"\n";

/// The stdin-evaluator suite's own hook wrapper. `evaluated_input` is forced
/// to ask (rather than left to inherit `dynamic_command`'s allow, which the
/// shared harness config sets) so that an allow in these tests can only come
/// from the standalone stand-down actually firing, never from an unrelated
/// setting reading permissive by default.
fn stdin_hook(tag: &str, mine: &str, command: &str) -> (String, String) {
    hook_asking("standalone_stdin", tag, mine, "evaluated_input", command)
}

#[test]
fn a_standalone_run_of_a_stdin_evaluator_does_not_ask() {
    let (decision, reason) = stdin_hook("top_level", STDIN_EVALUATOR, "fake-interp --version");
    assert_eq!(decision, "allow", "got: {reason}");
}

#[test]
fn a_lone_dash_still_asks() {
    // An explicit `-` still names standard input as the source, and it is
    // not a listed `standalone_flags` member — the claim stands.
    let (decision, reason) = stdin_hook("lone_dash", STDIN_EVALUATOR, "fake-interp -");
    assert_eq!(decision, "ask", "got: {reason}");
}

#[test]
fn a_bare_run_still_asks() {
    // An empty argument vector is never a standalone run (`standalone_run`
    // returns false on an empty vector before it even reads the vocabulary).
    let (decision, reason) = stdin_hook("bare", STDIN_EVALUATOR, "fake-interp");
    assert_eq!(decision, "ask", "got: {reason}");
}

#[test]
fn a_process_substitution_keeps_the_ask() {
    // The parser drops the `<(…)` token, so the record is not complete —
    // `standalone_eligible` folds false and the stdin arm still fires.
    let (decision, reason) =
        stdin_hook("proc_subst", STDIN_EVALUATOR, "fake-interp --version <(echo hi)");
    assert_eq!(decision, "ask", "got: {reason}");
    assert!(reason.contains("evaluated_input"), "got: {reason}");
}

#[test]
fn a_heredoc_on_a_standalone_run_is_still_judged() {
    // The top-level ask is suppressed (this is a standalone run), but a
    // heredoc attached to this same command still feeds the entry's own
    // `evaluates_input = "stdin"` claim unconditionally — the locator does
    // not consult `standalone_flags` at all — so its BODY is scanned and
    // judged on its own merits, benign or not.
    let (allow_decision, allow_reason) = stdin_hook(
        "heredoc_benign",
        STDIN_EVALUATOR,
        "fake-interp --version <<'EOF'\necho hi\nEOF",
    );
    assert_eq!(allow_decision, "allow", "got: {allow_reason}");

    let (ask_decision, ask_reason) = stdin_hook(
        "heredoc_risky",
        STDIN_EVALUATOR,
        "fake-interp --version <<'EOF'\nrm -rf /tmp/x\nEOF",
    );
    assert_eq!(ask_decision, "ask", "got: {ask_reason}");
}

#[test]
fn suppression_works_across_same_name_entries() {
    let (decision, reason) =
        stdin_hook("split_entries", SPLIT_ACROSS_ENTRIES, "fake-interp --version");
    assert_eq!(decision, "allow", "got: {reason}");
}

#[test]
fn a_standalone_run_trips_neither_half_of_runs_file() {
    // The entry also declares `runs_file = "arg_0"`. `--version` is a
    // described no-value flag, so the operand walk finds no operand at all —
    // neither the stdin arm nor the runs_file arm should raise
    // `evaluated_input` here, so the whole line allows outright.
    let (decision, reason) =
        stdin_hook("runs_file", STDIN_EVALUATOR, "fake-interp --version");
    assert_eq!(decision, "allow", "got: {reason}");
}

#[test]
fn suppression_survives_a_same_syntax_wrapper() {
    let (decision, reason) =
        stdin_hook("same_syntax", STDIN_EVALUATOR, "command fake-interp --version");
    assert_eq!(decision, "allow", "got: {reason}");
}

#[test]
fn the_flags_only_ask_names_the_narrow_key_and_its_pairing() {
    // Flags-only but `--other` is not a listed member, so the ask stands —
    // and because the entry declares `runs_file`, the sentence that would
    // quiet it has to name BOTH `standalone_flags` and its `no_value_options`
    // pairing (Task 4's membership rule), or the taught edit would not load.
    let (decision, reason) = stdin_hook("narrow_key", STDIN_EVALUATOR, "fake-interp --other");
    assert_eq!(decision, "ask", "got: {reason}");
    assert!(reason.contains("standalone_flags"), "got: {reason}");
    assert!(reason.contains("no_value_options"), "got: {reason}");
}

#[test]
fn the_off_switch_sentence_stays_quiet_for_a_refused_shape() {
    // Flags-only, but `--config=x` fails `member_shape_ok` (an attached-value
    // spelling) — the ask must never teach an edit the loader would refuse.
    let (decision, reason) =
        stdin_hook("refused_shape", STDIN_EVALUATOR, "fake-interp --config=x");
    assert_eq!(decision, "ask", "got: {reason}");
    assert!(!reason.contains("standalone_flags"), "got: {reason}");
}

// ---------------------------------------------------------------------------
// The four prompt sites: `guards::listable_standalone` and the wordings that
// read it (Task 7, spec 2026-08-20 §6). The bare-run sentence used to claim a
// flags-only run "cannot yet be described more narrowly" for every modeled
// program — false the moment `standalone_flags` exists to describe exactly
// that shape.
// ---------------------------------------------------------------------------

/// A modeled entry, no `standalone_flags` of its own yet: a flags-only run of
/// it reaches `unmodeled_descriptions` instead of being recognised outright,
/// which is the population these prompt-site tests are about. `-m` is a
/// declared value option, so a run naming it is genuinely NOT listable.
const PROMPT_ENTRY: &str = "[[program]]\nmatch = [\"mytool\"]\nsubcommands = [\"build\"]\n\
     case_sensitive_flags = true\nvalue_options = [\"-m\"]\n";

/// The same shape with `case_sensitive_flags` left unstated, for the one
/// test that needs the offer to name that key.
const PROMPT_ENTRY_NO_CASE_KEY: &str = "[[program]]\nmatch = [\"caseless\"]\nsubcommands = [\"build\"]\n";

#[test]
fn a_standalone_shaped_run_of_a_scoped_program_offers_the_narrow_entry() {
    let k = kb(PROMPT_ENTRY);
    let items = unmodeled_descriptions(&k, &[cmd("mytool", &["--version"])], "bash", true);
    assert_eq!(items.len(), 1, "{items:?}");
    assert!(
        items[0].1.contains("standalone_flags = [\"--version\"]"),
        "{:?}", items[0]
    );
    assert!(!items[0].1.contains("every operation"), "{:?}", items[0]);
}

#[test]
fn a_non_standalone_flags_only_run_keeps_the_whole_program_description_with_why() {
    // `-m` is a declared value option, so this run's tokens are not all
    // `standalone_flags` candidates — the description must say why, and must
    // not use the retired "cannot yet be described" wording.
    let k = kb(PROMPT_ENTRY);
    let items = unmodeled_descriptions(&k, &[cmd("mytool", &["-m", "x"])], "bash", true);
    assert_eq!(items.len(), 1, "{items:?}");
    assert!(items[0].1.contains("every operation of `mytool`"), "{:?}", items[0]);
    assert!(!items[0].1.contains("cannot yet be described"), "{:?}", items[0]);
}

#[test]
fn a_bare_run_gets_the_bare_sentence() {
    let k = kb(PROMPT_ENTRY);
    let items = unmodeled_descriptions(&k, &[cmd("mytool", &[])], "bash", true);
    assert_eq!(items.len(), 1, "{items:?}");
    assert!(
        items[0].1.contains("a bare run (no arguments) cannot be described more narrowly"),
        "{:?}", items[0]
    );
}

#[test]
fn an_unknown_programs_standalone_run_offers_the_complete_trust_shape() {
    // `nosuchtool` carries no entry at all — the loader demands `subcommands`,
    // `standalone_flags` AND `case_sensitive_flags` on a fresh entry, and an
    // offer missing one teaches an edit the loader would refuse.
    let k = kb(PROMPT_ENTRY);
    let items = unmodeled_descriptions(&k, &[cmd("nosuchtool", &["--version"])], "bash", true);
    assert_eq!(items.len(), 1, "{items:?}");
    assert!(items[0].1.contains("subcommands = []"), "{:?}", items[0]);
    assert!(items[0].1.contains("standalone_flags"), "{:?}", items[0]);
    assert!(items[0].1.contains("case_sensitive_flags"), "{:?}", items[0]);
}

#[test]
fn a_case_silent_modeled_entry_gets_the_case_key_named() {
    let k = kb(PROMPT_ENTRY_NO_CASE_KEY);
    let items = unmodeled_descriptions(&k, &[cmd("caseless", &["--version"])], "bash", true);
    assert_eq!(items.len(), 1, "{items:?}");
    assert!(items[0].1.contains("case_sensitive_flags"), "{:?}", items[0]);
}

#[test]
fn a_prompt_ignores_refused_vocabulary_from_another_language() {
    let k = kb(
        "[[program]]\nmatch = [\"mytool\"]\nlanguages = [\"bash\"]\n\
         subcommands = [\"build\"]\ncase_sensitive_flags = true\n\
         [[program]]\nmatch = [\"mytool\"]\nlanguages = [\"powershell\"]\n\
         subcommands = [\"build\"]\ncase_sensitive_flags = true\n\
         value_options = [\"--version\"]\n",
    );
    let items = unmodeled_descriptions(&k, &[cmd("mytool", &["--version"])], "bash", true);
    assert_eq!(items.len(), 1, "{items:?}");
    assert!(
        items[0].1.contains("standalone_flags = [\"--version\"]"),
        "a PowerShell-only value option must not suppress a truthful Bash offer: {:?}",
        items[0]
    );
}

// --- The engine-level dedup and remedy: end to end -------------------------
//
// `unmodeled_descriptions` itself dedups by name only, one command at a
// time — the mixed-population and union rules live in the engine's own item
// list, so these three need the real `--hook` path.

/// One `vouch --hook` run for the prompt-site suite: a fresh operator
/// overlay (never colliding with a shipped name) and the ask override on
/// bash's `unmodeled_command`, so the description text actually reaches the
/// reason.
fn prompt_hook(tag: &str, mine: &str, command: &str) -> (String, String) {
    hook_asking("standalone_prompt", tag, mine, "unmodeled_command", command)
}

#[test]
fn a_mixed_population_line_shows_the_whole_program_description() {
    // The second run is genuinely NON-listable because the fixture declares
    // `-m` in `value_options` — a bare `-x` would be listable, and this test
    // would then pin the wrong rule (round 2's finding).
    let (decision, reason) =
        prompt_hook("mixed", PROMPT_ENTRY, "mytool --version; mytool -m x");
    assert_eq!(decision, "ask", "{reason}");
    assert_one_item(&reason);
    assert!(
        !reason.contains("an entry could recognise exactly this flags-only shape"),
        "the narrow offer must not survive beside the non-listable sibling: {reason}"
    );
    assert!(
        reason.contains("not every argument here is a flag `standalone_flags` could list"),
        "{reason}"
    );
}

#[test]
fn two_standalone_shapes_with_differing_sets_offer_the_union() {
    let mine = "[[program]]\nmatch = [\"mytool\"]\nsubcommands = [\"build\"]\n\
         case_sensitive_flags = true\n";
    let (decision, reason) = prompt_hook("union", mine, "mytool --version; mytool -x");
    assert_eq!(decision, "ask", "{reason}");
    assert!(
        reason.contains("standalone_flags = [\"--version\", \"-x\"]"),
        "either subset alone would leave the sibling run asking: {reason}"
    );
    assert_one_item(&reason);
}

#[test]
fn two_standalone_shapes_with_equal_sets_collapse_to_one() {
    let mine = "[[program]]\nmatch = [\"mytool\"]\nsubcommands = [\"build\"]\n\
         case_sensitive_flags = true\n";
    let (decision, reason) =
        prompt_hook("collapse", mine, "mytool --version; mytool --version");
    assert_eq!(decision, "ask", "{reason}");
    assert_eq!(
        reason.matches("standalone_flags = [\"--version\"]").count(),
        1,
        "{reason}"
    );
    assert_one_item(&reason);
}

#[test]
fn the_place_scoped_miss_remedy_names_the_key_for_a_standalone_shape() {
    // A place-scoped entry with `subcommands` but no `standalone_flags`: a
    // flags-only run inside its tree is a scoped miss with `verb: None`, and
    // the remedy must teach `standalone_flags`, never "add it to that
    // entry's `subcommands`" — a flags-only shape is not a verb.
    let mine = "[[program]]\nmatch = [\"probe-tool\"]\n\
                only_under = [\"C:/scratch/**\"]\nsubcommands = [\"go\"]\n";
    let cfg = "version = 1\n[lang.bash]\ndefault = \"allow\"\n\
               [lang.bash.constructs]\nunmodeled_command = \"ask\"\n";
    let (decision, reason) = common::hook_bash_at(
        "standalone_scoped_miss",
        mine,
        cfg,
        "C:/scratch/job1",
        "probe-tool --version",
    );
    assert_eq!(decision, "ask", "{reason}");
    assert!(reason.contains("standalone_flags"), "{reason}");
    assert!(
        !reason.contains("add it to that entry's `subcommands`"),
        "{reason}"
    );
}
