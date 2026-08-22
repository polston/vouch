//! Nothing about what programs are is compiled into the binary.
//!
//! The whole of this milestone is that one property. If it regresses, `ls`
//! becomes allowed again by a list the operator cannot open.

use std::path::Path;
use vouch::guards::{HereWrite, Program};
use vouch::knowledge::{load_files, Gap, GapKind, GapSource};
use vouch::syntax::Cmd;

#[path = "common/mod.rs"]
mod common;
use common::v;



const ABSENT: &str = "tests/fixtures/there-is-no-such-file.toml";

#[test]
fn with_no_files_on_disk_vouch_knows_nothing() {
    let loaded = load_files(Path::new(ABSENT), Path::new(ABSENT));
    assert!(
        loaded.kb.program.is_empty(),
        "a program description survived with no file on disk: {:?}",
        loaded.kb.program.first().map(|p| p.match_names.clone())
    );
    assert!(loaded.kb.tool.is_empty(), "a tool description survived");
}

#[test]
fn a_missing_knowledge_file_is_reported_as_a_gap() {
    let loaded = load_files(Path::new(ABSENT), Path::new(ABSENT));
    let named: Vec<&Gap> = loaded.gaps.iter().filter(|g| g.path.contains("there-is-no-such-file")).collect();
    assert_eq!(named.len(), 1, "expected exactly the missing knowledge file; got {:?}", loaded.gaps);
    assert!(named[0].why.contains("not found"), "the gap must say why: {:?}", named[0]);
}

#[test]
fn a_missing_my_knowledge_file_is_not_a_gap() {
    // Not having written your own descriptions is normal, not a problem to
    // announce on every prompt.
    let loaded = load_files(Path::new("knowledge.toml"), Path::new(ABSENT));
    assert!(loaded.gaps.is_empty(), "an absent my-knowledge.toml was announced: {:?}", loaded.gaps);
    assert!(!loaded.kb.program.is_empty(), "the shipped file should load");
}

#[test]
fn a_file_that_does_not_parse_is_a_gap_and_contributes_nothing() {
    let bad = scratch("broken.toml", "this is not [[[ valid toml");
    let loaded = load_files(&bad, Path::new(ABSENT));
    assert!(loaded.kb.program.is_empty(), "a broken file contributed something");
    assert_eq!(loaded.gaps.len(), 1, "a broken file is a gap: {:?}", loaded.gaps);
    assert!(!loaded.gaps[0].why.contains("not found"), "broken is not the same as missing");
}

#[test]
fn a_file_that_parses_to_NOTHING_is_also_a_gap() {
    // [review] An empty or misspelt file parses cleanly, so nothing was
    // reported and no banner appeared. The operator believed they had
    // knowledge and had none — with `unmodeled_command = "allow"`, a total
    // silent disarm. Absence of content is a gap, not a successful load.
    for (name, body) in [
        ("empty.toml", ""),
        ("misspelt.toml", "[[programs]]\nmatch = [\"ls\"]\n"),
    ] {
        let p = scratch(name, body);
        let loaded = load_files(&p, Path::new(ABSENT));
        assert!(
            !loaded.gaps.is_empty(),
            "{name} produced no gap; vouch would run with no knowledge and say nothing"
        );
    }
}

#[test]
fn a_sub_write_with_an_invalid_takes_value_fails_the_whole_file() {
    // `takes` is a closed set: "", "first", "last", "run_dir". Anything else
    // used to silently mean "last" — a typo (`"run-dir"` for `"run_dir"`)
    // would change behaviour on old AND new binaries without a sound. This
    // must fail the same way a misspelt table name does: the whole file is
    // unusable, not just the one entry.
    let bad = scratch(
        "bad_takes.toml",
        "[[program]]\nmatch = [\"git\"]\n[[program.sub_write]]\nsubcommand = \"init\"\ntakes = \"run-dir\"\n",
    );
    let loaded = load_files(&bad, Path::new(ABSENT));
    assert!(
        loaded.kb.program.is_empty(),
        "an invalid takes value still loaded something: {:?}",
        loaded.kb.program
    );
    assert_eq!(loaded.gaps.len(), 1, "an invalid takes value must be a gap: {:?}", loaded.gaps);
    assert!(
        loaded.gaps[0].why.contains("run-dir"),
        "the banner does not name the bad value: {:?}",
        loaded.gaps[0]
    );
}

#[test]
fn a_run_dir_flag_missing_from_value_options_fails_the_whole_file() {
    // `run_dir_flags` must be a subset of `value_options` — a run-dir flag
    // not also listed there would be mistaken for the subcommand.
    //
    // [review, task 6 fix] This entry states its OWN `value_options`
    // (`-c`), so the omission of `-C` is a real claim mismatch, not the
    // "leave value_options unset, inherit the shipped list" pattern —
    // `a_run_dir_flags_only_entry_loads_and_merges_over_the_shipped_value_options`
    // covers that one and must NOT fail.
    let bad = scratch(
        "bad_run_dir_flags.toml",
        "[[program]]\nmatch = [\"git\"]\nvalue_options = [\"-c\"]\nrun_dir_flags = [\"-C\"]\n",
    );
    let loaded = load_files(&bad, Path::new(ABSENT));
    assert!(
        loaded.kb.program.is_empty(),
        "a run_dir_flags/value_options mismatch still loaded something: {:?}",
        loaded.kb.program
    );
    assert_eq!(loaded.gaps.len(), 1, "the mismatch must be a gap: {:?}", loaded.gaps);
    assert!(
        loaded.gaps[0].why.contains("-C"),
        "the banner does not name the offending flag: {:?}",
        loaded.gaps[0]
    );
}

#[test]
fn a_misspelt_changes_dir_value_fails_the_whole_file() {
    // `changes_dir` is a closed set: "no", "stated", "stack", "unstated". A
    // typo must fail the whole file, the same way a misspelt `takes` does —
    // not silently leave the entry un-declared.
    let bad = scratch("bad_changes_dir.toml", "[[program]]\nmatch = [\"zoxide\"]\nchanges_dir = \"statd\"\n");
    let loaded = load_files(&bad, Path::new(ABSENT));
    assert!(
        loaded.kb.program.is_empty(),
        "a misspelt changes_dir value still loaded something: {:?}",
        loaded.kb.program
    );
    assert_eq!(loaded.gaps.len(), 1, "a misspelt changes_dir value must be a gap: {:?}", loaded.gaps);
    assert!(loaded.gaps[0].why.contains("statd"), "the banner does not name the bad value: {:?}", loaded.gaps[0]);
}

#[test]
fn a_language_outside_the_closed_set_fails_the_whole_file() {
    // `languages` values come from the two scanners vouch has: "bash" and
    // "powershell". Anything else is a typo the file must not swallow.
    let bad = scratch(
        "bad_languages.toml",
        "[[program]]\nmatch = [\"cd\"]\nchanges_dir = \"stated\"\nlanguages = [\"fish\"]\n",
    );
    let loaded = load_files(&bad, Path::new(ABSENT));
    assert!(
        loaded.kb.program.is_empty(),
        "a language outside the closed set still loaded something: {:?}",
        loaded.kb.program
    );
    assert_eq!(loaded.gaps.len(), 1, "an invalid language must be a gap: {:?}", loaded.gaps);
    assert!(loaded.gaps[0].why.contains("fish"), "the banner does not name the bad value: {:?}", loaded.gaps[0]);
}

#[test]
fn dest_dir_flags_require_a_stated_or_stack_kind() {
    // A dest-dir flag on a kind that never derives a destination is an
    // incoherent claim: "unstated" means every form is unknown, so a flag
    // saying where the value lands cannot coexist with it.
    let bad = scratch(
        "bad_dest_dir_flags.toml",
        "[[program]]\nmatch = [\"popd\"]\nchanges_dir = \"unstated\"\ndest_dir_flags = [\"-Path\"]\n",
    );
    let loaded = load_files(&bad, Path::new(ABSENT));
    assert!(
        loaded.kb.program.is_empty(),
        "dest_dir_flags on an unstated kind still loaded something: {:?}",
        loaded.kb.program
    );
    assert_eq!(loaded.gaps.len(), 1, "the mismatch must be a gap: {:?}", loaded.gaps);
    assert!(loaded.gaps[0].why.contains("-Path"), "the banner does not name the offending flag: {:?}", loaded.gaps[0]);
}

#[test]
fn wrap_head_flags_must_also_be_value_options() {
    // A flag whose value NAMES the program being started has to be known to
    // consume that value, or the operand walk reads the program name as a
    // positional and the two answers disagree about one token. Same subset
    // rule `run_dir_flags` follows, for the same reason.
    let bad = scratch(
        "bad_wrap_head_flags.toml",
        "[[program]]\nmatch = [\"sp\"]\nwraps = \"start_process\"\n\
         wrap_flags = [\"-ArgumentList\"]\nwrap_head_flags = [\"-FilePath\"]\n\
         value_options = [\"-ArgumentList\"]\n",
    );
    let loaded = load_files(&bad, Path::new(ABSENT));
    assert!(
        loaded.kb.program.is_empty(),
        "a head flag outside value_options still loaded something: {:?}",
        loaded.kb.program
    );
    assert_eq!(loaded.gaps.len(), 1, "the mismatch must be a gap: {:?}", loaded.gaps);
    assert!(
        loaded.gaps[0].why.contains("-FilePath"),
        "the banner does not name the offending flag: {:?}",
        loaded.gaps[0]
    );
}

#[test]
fn wrap_head_flags_need_the_start_process_wrap_kind() {
    // The key belongs to one wrap kind. On any other it is silently inert,
    // which is the shape a knowledge file must never have: it reads to its
    // author as a claim that is being honoured.
    let bad = scratch(
        "bad_wrap_head_kind.toml",
        "[[program]]\nmatch = [\"zz\"]\nwraps = \"rest\"\nwrap_head_flags = [\"-FilePath\"]\n\
         value_options = [\"-FilePath\"]\n",
    );
    let loaded = load_files(&bad, Path::new(ABSENT));
    assert!(
        loaded.kb.program.is_empty(),
        "wrap_head_flags on a rest wrapper still loaded something: {:?}",
        loaded.kb.program
    );
    assert_eq!(loaded.gaps.len(), 1, "the mismatch must be a gap: {:?}", loaded.gaps);
    assert!(
        loaded.gaps[0].why.contains("start_process"),
        "the banner does not name the kind the key needs: {:?}",
        loaded.gaps[0]
    );
}

#[test]
fn an_unreachable_match_name_fails_the_whole_file() {
    // The lookup folds a head to lowercase, drops a path, and trims a
    // trailing `.exe` before any entry is even considered (`guards::base_name`).
    // A match name that does not already equal that folded form can never be
    // reached by a real command line — dead data pretending to be a live
    // claim (M2.121, M2.135). Must fail the same way a misspelt closed-set
    // value does: the whole file, not just the one entry.
    let bad = scratch(
        "unreachable_exe_name.toml",
        "[[program]]\nmatch = [\"vouchtest-fakeprog.exe\"]\nwraps = \"rest\"\n",
    );
    let loaded = load_files(&bad, Path::new(ABSENT));
    assert!(
        loaded.kb.program.is_empty(),
        "an unreachable match name still loaded something: {:?}",
        loaded.kb.program
    );
    assert_eq!(loaded.gaps.len(), 1, "an unreachable match name must be a gap: {:?}", loaded.gaps);
    assert!(
        loaded.gaps[0].why.contains("vouchtest-fakeprog.exe"),
        "the banner does not name the unreachable match name: {:?}",
        loaded.gaps[0]
    );
}

#[test]
fn a_forward_slash_or_windows_rooted_match_name_also_fails_the_whole_file() {
    // Two more shapes the lookup can never reach: a name still carrying a
    // `/` path component (the lookup takes only the last segment,
    // unconditionally, for every language), and a Windows-rooted path
    // (`base` folds `\` to `/` for that one shape — a BARE backslash with
    // no drive letter is left alone, matching what bash's own escape
    // handling already resolved before `head` is ever built, so that shape
    // is deliberately not exercised here as unreachable — see
    // `m2_121_backslash_escape_same_name` in the boundary suite, which pins
    // the opposite: `who\ami` stays a reachable literal name).
    //
    // `needle` is a backslash-free substring of `bad_name` — the banner
    // Debug-formats the offending name, which re-escapes a literal
    // backslash to two characters, so comparing against the raw name would
    // fail on the escaping alone rather than on whether it was named.
    for (file, bad_name, needle) in [
        ("unreachable_forward_slash_name.toml", "some/dir/vouchtestslash", "vouchtestslash"),
        ("unreachable_windows_path_name.toml", "C:\\bin\\vouchtestwin", "vouchtestwin"),
    ] {
        let bad = scratch(file, &format!("[[program]]\nmatch = [{bad_name:?}]\nwraps = \"rest\"\n"));
        let loaded = load_files(&bad, Path::new(ABSENT));
        assert!(
            loaded.kb.program.is_empty(),
            "{bad_name:?} still loaded something: {:?}",
            loaded.kb.program
        );
        assert_eq!(loaded.gaps.len(), 1, "{bad_name:?} must be a gap: {:?}", loaded.gaps);
        assert!(
            loaded.gaps[0].why.contains(needle),
            "the banner does not name {bad_name:?}: {:?}",
            loaded.gaps[0]
        );
    }
}

#[test]
fn a_mixed_case_python_callable_match_name_still_loads() {
    // Round-1 correction (spec §4.4): the reachability check runs on the
    // LOWERCASED name, so a capitalised python callable — which the
    // lookup's own two-sided case fold still reaches — must not be refused
    // for carrying capitals it is allowed to carry.
    let good = scratch(
        "mixed_case_python_name.toml",
        &format!("version = {}\n[[program]]\nmatch = [\"python:PIL.Image.open\"]\nwrites = \"arg_0\"\n", v()),
    );
    let loaded = load_files(&good, Path::new(ABSENT));
    assert!(
        !loaded.kb.program.is_empty(),
        "a reachable mixed-case match name was refused: {:?}",
        loaded.gaps
    );
}

#[test]
fn valid_changes_dir_languages_and_dest_dir_flags_load_and_round_trip() {
    // The closed-set checks above must not reject values that ARE in the set
    // — a validator that fails everything would pass the failing tests too.
    let good = scratch(
        "good_changes_dir.toml",
        &format!("version = {}\n[[program]]\nmatch = [\"set-location\"]\nchanges_dir = \"stated\"\nlanguages = [\"powershell\"]\ndest_dir_flags = [\"-Path\"]\n", v()),
    );
    let loaded = load_files(&good, Path::new(ABSENT));
    assert!(loaded.gaps.is_empty(), "a valid file was rejected: {:?}", loaded.gaps);
    let prog = loaded
        .kb
        .program
        .iter()
        .find(|p| p.match_names.iter().any(|n| n == "set-location"))
        .expect("the entry did not load");
    assert_eq!(prog.changes_dir, Some("stated".to_string()), "changes_dir did not round-trip");
    assert_eq!(prog.languages, vec!["powershell".to_string()], "languages did not round-trip");
    assert_eq!(prog.dest_dir_flags, vec!["-Path".to_string()], "dest_dir_flags did not round-trip");
}

// --- writes_only_with_file_mode / arg_names / wrap_join / arg_<N> (spec
// 2026-08-07 python-snippets, Task 6, knowledge schema v4) ------------------

#[test]
fn writes_only_with_file_mode_arg_names_and_wrap_join_load_and_round_trip() {
    let good = scratch(
        "good_arg_fields.toml",
        &format!("version = {}\n[[program]]\nmatch = [\"python:open\"]\nwrites = \"arg_0\"\n\
         writes_only_with_file_mode = true\narg_names = [\"file\", \"mode\"]\n\
         wraps = \"arg_1\"\nwrap_lang = \"bash\"\nwrap_join = true\n", v()),
    );
    let loaded = load_files(&good, Path::new(ABSENT));
    assert!(loaded.gaps.is_empty(), "a valid file was rejected: {:?}", loaded.gaps);
    let prog = loaded
        .kb
        .program
        .iter()
        .find(|p| p.match_names.iter().any(|n| n == "python:open"))
        .expect("the entry did not load");
    assert_eq!(prog.writes, "arg_0", "writes did not round-trip");
    assert_eq!(prog.writes_only_with_file_mode, Some(true), "writes_only_with_file_mode did not round-trip");
    assert_eq!(prog.arg_names, vec!["file".to_string(), "mode".to_string()], "arg_names did not round-trip");
    assert_eq!(prog.wraps, "arg_1", "wraps did not round-trip");
    assert_eq!(prog.wrap_join, Some(true), "wrap_join did not round-trip");
}

#[test]
fn writes_only_with_file_mode_without_a_mode_name_fails_the_whole_file() {
    let bad = scratch(
        "bad_writes_only_with_file_mode_no_mode.toml",
        "[[program]]\nmatch = [\"python:open\"]\nwrites = \"arg_0\"\n\
         writes_only_with_file_mode = true\narg_names = [\"file\"]\n",
    );
    let loaded = load_files(&bad, Path::new(ABSENT));
    assert!(
        loaded.kb.program.is_empty(),
        "writes_only_with_file_mode without a \"mode\" name still loaded something: {:?}",
        loaded.kb.program
    );
    assert_eq!(loaded.gaps.len(), 1, "the missing mode name must be a gap: {:?}", loaded.gaps);
    assert!(
        loaded.gaps[0].why.contains("writes_only_with_file_mode"),
        "the banner does not name the problem: {:?}",
        loaded.gaps[0]
    );
}

#[test]
fn arg_names_may_name_mode_with_no_writes_only_with_file_mode_at_all() {
    // One-directional by design: a chmod-shaped entry whose mode is an
    // integer names "mode" in `arg_names` without ever setting the flag —
    // spec 2026-08-07 python-snippets.
    let good = scratch(
        "good_mode_name_no_flag.toml",
        &format!("version = {}\n[[program]]\nmatch = [\"python:os.chmod\"]\nwrites = \"arg_0\"\narg_names = [\"path\", \"mode\"]\n", v()),
    );
    let loaded = load_files(&good, Path::new(ABSENT));
    assert!(loaded.gaps.is_empty(), "naming \"mode\" alone was rejected: {:?}", loaded.gaps);
}

// --- writes_via_handle (spec 2026-08-09 python-read-only-builtins, Task 5,
// knowledge schema v5) -------------------------------------------------------

#[test]
fn writes_via_handle_alongside_writes_fails_the_whole_file() {
    let bad = scratch(
        "wvh-alongside-writes.toml",
        &format!("version = {}\n[[program]]\nmatch = [\"python:x\"]\nwrites = \"arg_0\"\nwrites_via_handle = \"arg_1\"\n", v()),
    );
    let loaded = load_files(&bad, Path::new(ABSENT));
    assert!(loaded.kb.program.is_empty(), "a refused file must yield no entries");
    assert!(
        loaded.gaps[0].why.contains("writes_via_handle"),
        "got: {}",
        loaded.gaps[0].why
    );
}

#[test]
fn writes_via_handle_alongside_sub_write_fails_the_whole_file() {
    // Fix round 1: the exclusivity check covered `writes` and
    // `writes_only_with_file_mode` but not `sub_write` — a third way to
    // claim a write target the same entry should not also be allowed to
    // pair with a handle-write claim.
    let bad = scratch(
        "wvh-alongside-subwrite.toml",
        &format!("version = {}\n[[program]]\nmatch = [\"python:x\"]\nwrites_via_handle = \"arg_0\"\n\
         [[program.sub_write]]\nsubcommand = \"y\"\n", v()),
    );
    let loaded = load_files(&bad, Path::new(ABSENT));
    assert!(loaded.kb.program.is_empty(), "a refused file must yield no entries");
    assert!(
        loaded.gaps[0].why.contains("writes_via_handle") && loaded.gaps[0].why.contains("sub_write"),
        "the banner does not name both the field and the conflicting sub_write claim: {}",
        loaded.gaps[0].why
    );
}

#[test]
fn a_writes_via_handle_spelling_outside_the_grammar_fails_the_whole_file() {
    // Fix round 1: pin the SPECIFIC rejection, not any failure that happens
    // to mention the field name — the exclusivity check above also names
    // "writes_via_handle" in its own error, so a loose `contains` here would
    // pass even if this fixture were wrongly routed through that branch
    // instead of the grammar one.
    let bad = scratch(
        "wvh-bad-grammar.toml",
        &format!("version = {}\n[[program]]\nmatch = [\"python:x\"]\nwrites_via_handle = \"arg_zz\"\n", v()),
    );
    let loaded = load_files(&bad, Path::new(ABSENT));
    assert!(loaded.kb.program.is_empty());
    assert!(
        loaded.gaps[0].why.contains("must be \"arg_<N>\" or a keyword parameter name"),
        "the banner does not name the specific grammar rejection: {}",
        loaded.gaps[0].why
    );
    assert!(
        loaded.gaps[0].why.contains("arg_zz"),
        "the banner does not echo the offending value: {}",
        loaded.gaps[0].why
    );
    assert!(
        !loaded.gaps[0].why.contains("cannot appear alongside"),
        "this fixture must be rejected by the GRAMMAR check, not the exclusivity check: {}",
        loaded.gaps[0].why
    );
}

#[test]
fn a_callback_args_entry_that_is_not_an_identifier_fails_the_whole_file() {
    // Grammar only (task 2b, M2.86 fix round): membership in `arg_names` is
    // NOT required, so this cannot check anything beyond "is this a name at
    // all" — a typo would otherwise be a dead declaration, caught instead by
    // the enumeration test that proves every declared slot actually trips.
    let bad = scratch(
        "bad_callback_args_not_identifier.toml",
        "[[program]]\nmatch = [\"python:json.load\"]\ncallback_args = [\"object hook\"]\n",
    );
    let loaded = load_files(&bad, Path::new(ABSENT));
    assert!(loaded.kb.program.is_empty(), "a non-identifier callback_args entry still loaded something: {:?}", loaded.kb.program);
    assert_eq!(loaded.gaps.len(), 1, "the bad identifier must be a gap: {:?}", loaded.gaps);
    assert!(loaded.gaps[0].why.contains("object hook"), "the banner does not name the bad value: {:?}", loaded.gaps[0]);
}

#[test]
fn callback_args_loads_and_round_trips_with_or_without_arg_names() {
    // A keyword-only callback slot (json.load's) has no positional form and
    // is legitimately absent from `arg_names`; a positional one
    // (defaultdict's) names the same slot in both fields.
    let good = scratch(
        "good_callback_args.toml",
        &format!("version = {}\n\
         [[program]]\nmatch = [\"python:json.load\"]\ncallback_args = [\"object_hook\"]\n\n\
         [[program]]\nmatch = [\"python:collections.defaultdict\"]\narg_names = [\"default_factory\"]\ncallback_args = [\"default_factory\"]\n", v()),
    );
    let loaded = load_files(&good, Path::new(ABSENT));
    assert!(loaded.gaps.is_empty(), "a valid callback_args file was rejected: {:?}", loaded.gaps);
    let load_entry = loaded
        .kb
        .program
        .iter()
        .find(|p| p.match_names.iter().any(|n| n == "python:json.load"))
        .expect("the json.load entry did not load");
    assert_eq!(load_entry.callback_args, vec!["object_hook".to_string()], "callback_args did not round-trip");
    assert!(load_entry.arg_names.is_empty(), "json.load's keyword-only slot should not require arg_names");
    let defaultdict_entry = loaded
        .kb
        .program
        .iter()
        .find(|p| p.match_names.iter().any(|n| n == "python:collections.defaultdict"))
        .expect("the defaultdict entry did not load");
    assert_eq!(defaultdict_entry.callback_args, vec!["default_factory".to_string()], "callback_args did not round-trip");
    assert_eq!(defaultdict_entry.arg_names, vec!["default_factory".to_string()], "arg_names did not round-trip");
}

#[test]
fn a_writes_arg_n_value_with_a_non_numeric_suffix_fails_the_whole_file() {
    let bad = scratch("bad_writes_arg_n.toml", "[[program]]\nmatch = [\"python:open\"]\nwrites = \"arg_x\"\n");
    let loaded = load_files(&bad, Path::new(ABSENT));
    assert!(loaded.kb.program.is_empty(), "a non-numeric arg_<N> suffix still loaded something: {:?}", loaded.kb.program);
    assert_eq!(loaded.gaps.len(), 1, "the bad suffix must be a gap: {:?}", loaded.gaps);
    assert!(loaded.gaps[0].why.contains("arg_x"), "the banner does not name the bad value: {:?}", loaded.gaps[0]);
}

#[test]
fn a_wraps_arg_n_value_with_a_non_numeric_suffix_fails_the_whole_file() {
    let bad = scratch("bad_wraps_arg_n.toml", "[[program]]\nmatch = [\"python:os.system\"]\nwraps = \"arg_y\"\n");
    let loaded = load_files(&bad, Path::new(ABSENT));
    assert!(loaded.kb.program.is_empty(), "a non-numeric arg_<N> suffix still loaded something: {:?}", loaded.kb.program);
    assert_eq!(loaded.gaps.len(), 1, "the bad suffix must be a gap: {:?}", loaded.gaps);
    assert!(loaded.gaps[0].why.contains("arg_y"), "the banner does not name the bad value: {:?}", loaded.gaps[0]);
}

#[test]
fn a_writes_arg_n_value_with_a_numeric_suffix_loads_and_round_trips() {
    let good = scratch("good_writes_arg_n.toml", &format!("version = {}\n[[program]]\nmatch = [\"python:open\"]\nwrites = \"arg_2\"\n", v()));
    let loaded = load_files(&good, Path::new(ABSENT));
    assert!(loaded.gaps.is_empty(), "a valid arg_<N> value was rejected: {:?}", loaded.gaps);
    let prog = loaded.kb.program.iter().find(|p| p.match_names.iter().any(|n| n == "python:open")).expect("the entry did not load");
    assert_eq!(prog.writes, "arg_2", "writes did not round-trip");
}

// --- `[[tool]]` schema: snippet, write-path field, cwd claim, server scope -
// (spec 2026-08-05 §Schema). Validated at load; nothing yet consults these
// fields — that is later tasks in this changeset.

#[test]
fn an_empty_tool_snippet_list_fails_the_whole_file() {
    // Spec rule 3: `snippet = []` is a load error, not "no snippets" — the
    // operator's off-switch for snippet inspection is `tools.<name>` in
    // config, never a description that quietly deletes the shipped one.
    let bad = scratch("bad_tool_snippet_empty.toml", "[[tool]]\nmatch = [\"Bash\"]\nsnippet = []\n");
    let loaded = load_files(&bad, Path::new(ABSENT));
    assert!(loaded.kb.tool.is_empty(), "an empty snippet list still loaded something: {:?}", loaded.kb.tool);
    assert_eq!(loaded.gaps.len(), 1, "an empty snippet list must be a gap: {:?}", loaded.gaps);
    assert!(
        loaded.gaps[0].why.contains("snippet = [] is not a thing an entry can say"),
        "the banner does not name the problem: {:?}",
        loaded.gaps[0]
    );
}

#[test]
fn a_server_entry_with_a_non_empty_match_fails_the_whole_file() {
    // Spec rule 2: `server` and `match` in one entry is a load error — a
    // server grant names no individual tool.
    let bad = scratch("bad_tool_server_and_match.toml", "[[tool]]\nmatch = [\"Bash\"]\nserver = \"mcp__x\"\n");
    let loaded = load_files(&bad, Path::new(ABSENT));
    assert!(loaded.kb.tool.is_empty(), "a server+match entry still loaded something: {:?}", loaded.kb.tool);
    assert_eq!(loaded.gaps.len(), 1, "the conflict must be a gap: {:?}", loaded.gaps);
    assert!(
        loaded.gaps[0].why.contains("server") && loaded.gaps[0].why.contains("match"),
        "the banner does not name the conflict: {:?}",
        loaded.gaps[0]
    );
}

#[test]
fn a_tool_entry_naming_neither_match_nor_server_fails_the_whole_file() {
    let bad = scratch("bad_tool_neither.toml", "[[tool]]\nsource = \"x\"\n");
    let loaded = load_files(&bad, Path::new(ABSENT));
    assert!(loaded.kb.tool.is_empty(), "a nameless tool entry still loaded something: {:?}", loaded.kb.tool);
    assert_eq!(loaded.gaps.len(), 1, "a nameless entry must be a gap: {:?}", loaded.gaps);
}

#[test]
fn a_tool_entry_with_an_empty_server_name_fails_the_whole_file() {
    let bad = scratch("bad_tool_empty_server.toml", "[[tool]]\nserver = \"\"\n");
    let loaded = load_files(&bad, Path::new(ABSENT));
    assert!(loaded.kb.tool.is_empty(), "an empty server name still loaded something: {:?}", loaded.kb.tool);
    assert_eq!(loaded.gaps.len(), 1, "an empty server name must be a gap: {:?}", loaded.gaps);
    assert!(loaded.gaps[0].why.contains("server"), "the banner does not name the problem: {:?}", loaded.gaps[0]);
}

#[test]
fn a_snippet_language_outside_the_closed_set_fails_the_whole_file() {
    let bad = scratch(
        "bad_tool_snippet_language.toml",
        "[[tool]]\nmatch = [\"Bash\"]\n\n[[tool.snippet]]\nfield = \"command\"\nlanguage = \"bsah\"\n",
    );
    let loaded = load_files(&bad, Path::new(ABSENT));
    assert!(loaded.kb.tool.is_empty(), "a bad language still loaded something: {:?}", loaded.kb.tool);
    assert_eq!(loaded.gaps.len(), 1, "an invalid language must be a gap: {:?}", loaded.gaps);
    assert!(loaded.gaps[0].why.contains("bsah"), "the banner does not name the bad value: {:?}", loaded.gaps[0]);
}

#[test]
fn a_snippet_language_values_entry_outside_the_closed_set_fails_the_whole_file() {
    let bad = scratch(
        "bad_tool_snippet_language_values.toml",
        "[[tool]]\nmatch = [\"ctx_execute\"]\n\n[[tool.snippet]]\nfield = \"code\"\nlanguage_from = \"language\"\nlanguage_values = { shell = \"bahs\" }\n",
    );
    let loaded = load_files(&bad, Path::new(ABSENT));
    assert!(loaded.kb.tool.is_empty(), "a bad language_values entry still loaded something: {:?}", loaded.kb.tool);
    assert_eq!(loaded.gaps.len(), 1, "an invalid language_values entry must be a gap: {:?}", loaded.gaps);
    assert!(loaded.gaps[0].why.contains("bahs"), "the banner does not name the bad value: {:?}", loaded.gaps[0]);
}

#[test]
fn a_snippet_field_declaring_both_language_and_language_from_fails_the_whole_file() {
    let bad = scratch(
        "bad_tool_snippet_both.toml",
        "[[tool]]\nmatch = [\"Bash\"]\n\n[[tool.snippet]]\nfield = \"command\"\nlanguage = \"bash\"\nlanguage_from = \"language\"\n",
    );
    let loaded = load_files(&bad, Path::new(ABSENT));
    assert!(loaded.kb.tool.is_empty(), "a both-set snippet field still loaded something: {:?}", loaded.kb.tool);
    assert_eq!(loaded.gaps.len(), 1, "declaring both must be a gap: {:?}", loaded.gaps);
}

#[test]
fn a_snippet_field_declaring_neither_language_nor_language_from_fails_the_whole_file() {
    let bad = scratch(
        "bad_tool_snippet_neither_lang.toml",
        "[[tool]]\nmatch = [\"Bash\"]\n\n[[tool.snippet]]\nfield = \"command\"\n",
    );
    let loaded = load_files(&bad, Path::new(ABSENT));
    assert!(loaded.kb.tool.is_empty(), "a neither-set snippet field still loaded something: {:?}", loaded.kb.tool);
    assert_eq!(loaded.gaps.len(), 1, "declaring neither must be a gap: {:?}", loaded.gaps);
}

#[test]
fn a_valid_tool_snippet_write_path_and_server_entry_load_and_round_trip() {
    // The closed-set checks above must not reject values that ARE valid —
    // exercises `snippet`, `write_path_field`, `cwd_from_call` and a
    // standalone `server` entry all loading together.
    let good = scratch(
        "good_tool_schema.toml",
        &format!("version = {}\n\
         [[tool]]\nmatch = [\"mcp__x__ctx_execute\"]\ncwd_from_call = false\n\n\
         [[tool.snippet]]\nfield = \"code\"\nlanguage_from = \"language\"\nlanguage_values = {{ shell = \"bash\", python = \"python\" }}\n\n\
         [[tool]]\nmatch = [\"Write\"]\ncwd_from_call = true\nwrite_path_field = \"file_path\"\n\n\
         [[tool]]\nserver = \"mcp__plugin_x\"\nsource = \"grant\"\n", v()),
    );
    let loaded = load_files(&good, Path::new(ABSENT));
    assert!(loaded.gaps.is_empty(), "a valid tool schema was rejected: {:?}", loaded.gaps);

    let exec = loaded
        .kb
        .tool
        .iter()
        .find(|t| t.match_names.iter().any(|n| n == "mcp__x__ctx_execute"))
        .expect("the snippet entry did not load");
    assert_eq!(exec.cwd_from_call, Some(false), "cwd_from_call did not round-trip");
    let snippet = exec.snippet.as_ref().expect("snippet did not round-trip");
    assert_eq!(snippet.len(), 1);
    assert_eq!(snippet[0].field, "code");
    assert_eq!(snippet[0].language_from.as_deref(), Some("language"));
    assert_eq!(snippet[0].language_values.as_ref().unwrap().get("shell").map(String::as_str), Some("bash"));

    let write = loaded.kb.tool.iter().find(|t| t.match_names.iter().any(|n| n == "Write")).expect("the write-path entry did not load");
    assert_eq!(write.cwd_from_call, Some(true), "cwd_from_call did not round-trip");
    assert_eq!(write.write_path_field.as_deref(), Some("file_path"), "write_path_field did not round-trip");

    let server = loaded.kb.tool.iter().find(|t| t.server.as_deref() == Some("mcp__plugin_x")).expect("the server entry did not load");
    assert!(server.match_names.is_empty(), "a server entry must not also carry a match list");
}

#[test]
fn a_run_dir_flags_only_entry_loads_and_merges_over_the_shipped_value_options() {
    // [review, task 6 fix] Task 5's own documented pattern: the operator
    // sets `run_dir_flags` on a program the shipped file already describes,
    // leaving `value_options` unset so `overlay()` keeps the shipped list.
    // Validating this file in isolation against its OWN empty
    // `value_options` rejected the whole my-knowledge.toml for a shape that
    // becomes valid the moment it is laid over the shipped entry.
    // The version line here is unrelated to what this test is checking (the
    // run_dir_flags/value_options overlay) — it is required so this scratch
    // file, standing in for the SHIPPED knowledge, survives the version gate
    // added for `a_refused_shipped_file_sets_my_knowledge_aside` below.
    let shipped = scratch(
        "shipped_for_run_dir_merge.toml",
        &format!("version = {}\n[[program]]\nmatch = [\"vcs\"]\nvalue_options = [\"-C\", \"-c\"]\n", v()),
    );
    let mine = scratch("mine_run_dir_flags_only.toml", "[[program]]\nmatch = [\"vcs\"]\nrun_dir_flags = [\"-C\"]\n");
    let loaded = load_files(&shipped, &mine);
    assert!(loaded.gaps.is_empty(), "the operator file was rejected: {:?}", loaded.gaps);
    let prog = loaded
        .kb
        .program
        .iter()
        .find(|p| p.match_names.iter().any(|n| n == "vcs"))
        .expect("the merged entry is missing");
    assert_eq!(prog.run_dir_flags, vec!["-C".to_string()], "the operator's run_dir_flags did not survive");
    assert_eq!(
        prog.value_options,
        vec!["-C".to_string(), "-c".to_string()],
        "the shipped value_options should have survived the overlay"
    );

    // Extraction actually works after the merge, not just the field check.
    let cmd = Cmd {
        head: "vcs".into(),
        args: vec!["-C".into(), "/x".into(), "status".into()],
        chain: None,
        prefix_assigns: vec![],
    };
    assert!(
        matches!(
            vouch::guards::run_dir(&loaded.kb, &cmd),
            vouch::guards::RunDir::Dir(d) if d == "/x"
        ),
        "run_dir_flags did not resolve after merge"
    );
}

// --- the retraction-ambiguity check (spec §2.2, amended after Task 4's
// skeptical review — Finding 2, plan commit 4666b8c) -----------------------
//
// The check moved off the MERGED result (provenance-blind: a deliberate
// per-language "no" pair is structurally identical, once merged, to an
// unscoped "no" split by scope) and onto `load_files`, run on the operator's
// OWN entries against the shipped set, before the merge. All four tests below
// go through `load_files` because that is the only place both files are ever
// compared — there is no longer a standalone function to call directly.

#[test]
fn an_unscoped_no_over_a_language_split_shipped_name_is_rejected() {
    // The one INVALID spelling: the operator names no language at all, and
    // the shipped file's own claims for "cd" differ by language. This is the
    // widest possible retraction reading as the default spelling.
    let shipped = scratch(
        "shipped_split_cd.toml",
        &format!("version = {}\n[[program]]\nmatch = [\"cd\"]\nlanguages = [\"bash\"]\nchanges_dir = \"stated\"\n\
         [[program]]\nmatch = [\"cd\"]\nlanguages = [\"powershell\"]\nchanges_dir = \"stated\"\n", v()),
    );
    let mine = scratch("mine_unscoped_no.toml", "[[program]]\nmatch = [\"cd\"]\nchanges_dir = \"no\"\n");
    let loaded = load_files(&shipped, &mine);
    assert!(loaded.kb.program.is_empty(), "an ambiguous retraction must fail the WHOLE load closed: {:?}", loaded.kb.program);
    assert_eq!(loaded.gaps.len(), 1, "the ambiguity must be reported as exactly one gap: {:?}", loaded.gaps);
    assert_eq!(loaded.gaps[0].source, GapSource::MyKnowledge, "it is the OPERATOR's entry that is ambiguous");
    // [review, final review Finding 1] `Unusable` here used to render through
    // the same wildcard arm as a my-knowledge.toml that failed on its OWN —
    // which claims "vouch still recognises everything the shipped knowledge
    // describes". That is false for this gap: `loaded.kb.program` is empty
    // above, not the shipped base. `Ambiguous` gets its own arm instead.
    assert_eq!(loaded.gaps[0].kind, GapKind::Ambiguous);
    assert!(loaded.gaps[0].why.contains("\"cd\""), "the gap must name the offending ENTRY: {:?}", loaded.gaps[0]);
}

#[test]
fn a_per_language_no_pair_validates() {
    // VALID spelling 1: the operator names each language separately, on
    // purpose — even though both entries retract, neither is the "default"
    // unscoped spelling, so this is not the shape the check exists to catch.
    let shipped = scratch(
        "shipped_split_cd2.toml",
        &format!("version = {}\n[[program]]\nmatch = [\"cd\"]\nlanguages = [\"bash\"]\nchanges_dir = \"stated\"\n\
         [[program]]\nmatch = [\"cd\"]\nlanguages = [\"powershell\"]\nchanges_dir = \"stated\"\n", v()),
    );
    let mine = scratch(
        "mine_per_language_no.toml",
        "[[program]]\nmatch = [\"cd\"]\nlanguages = [\"bash\"]\nchanges_dir = \"no\"\n\
         [[program]]\nmatch = [\"cd\"]\nlanguages = [\"powershell\"]\nchanges_dir = \"no\"\n",
    );
    let loaded = load_files(&shipped, &mine);
    assert!(loaded.gaps.is_empty(), "two explicitly-scoped retractions must validate: {:?}", loaded.gaps);
    assert!(!loaded.kb.program.is_empty(), "the load must not be empty: {:?}", loaded.kb.program);
}

#[test]
fn an_explicit_both_languages_no_validates() {
    // VALID spelling 2: `languages = ["bash", "powershell"]` is EQUIVALENT in
    // scope to unscoped, but it is not the SAME spelling — the operator said
    // both languages out loud rather than leaving the key off, which is
    // exactly the distinction spec §2.2 draws (the trigger is empty
    // `languages`, not "covers everything").
    let shipped = scratch(
        "shipped_split_cd3.toml",
        &format!("version = {}\n[[program]]\nmatch = [\"cd\"]\nlanguages = [\"bash\"]\nchanges_dir = \"stated\"\n\
         [[program]]\nmatch = [\"cd\"]\nlanguages = [\"powershell\"]\nchanges_dir = \"stated\"\n", v()),
    );
    let mine = scratch(
        "mine_explicit_both.toml",
        "[[program]]\nmatch = [\"cd\"]\nlanguages = [\"bash\", \"powershell\"]\nchanges_dir = \"no\"\n",
    );
    let loaded = load_files(&shipped, &mine);
    assert!(loaded.gaps.is_empty(), "naming both languages explicitly must validate: {:?}", loaded.gaps);
    assert!(!loaded.kb.program.is_empty(), "the load must not be empty: {:?}", loaded.kb.program);
}

#[test]
fn an_unscoped_no_over_a_single_scope_shipped_name_validates() {
    // VALID spelling 3: the shipped claims for this name do NOT differ by
    // language (there is only one shipped entry for it at all) — the old,
    // post-merge version of this check wrongly rejected this shape, because
    // `overlay_all`'s own remainder logic can produce a second, unrelated
    // entry for the same name after merging, which looked like a "language
    // split" to a check that only ever saw the merged result.
    let shipped = scratch("shipped_single_zoxide.toml", &format!("version = {}\n[[program]]\nmatch = [\"z\"]\nchanges_dir = \"stated\"\n", v()));
    let mine = scratch("mine_unscoped_no_single.toml", "[[program]]\nmatch = [\"z\"]\nchanges_dir = \"no\"\n");
    let loaded = load_files(&shipped, &mine);
    assert!(loaded.gaps.is_empty(), "a name with no shipped language split must validate: {:?}", loaded.gaps);
    let z = loaded.kb.program.iter().find(|p| p.match_names.iter().any(|n| n == "z")).expect("z entry");
    assert_eq!(z.changes_dir.as_deref(), Some("no"), "the retraction itself must still take effect");
}

#[test]
fn the_retraction_check_never_runs_when_my_knowledge_is_absent() {
    // Finding 4: structurally, the check lives inside `load_files`'s
    // `Some(o) =>` arm, so it cannot fire — and cannot name a my-knowledge
    // path that does not exist — when the operator never wrote one at all.
    let shipped = scratch(
        "shipped_split_cd4.toml",
        &format!("version = {}\n[[program]]\nmatch = [\"cd\"]\nlanguages = [\"bash\"]\nchanges_dir = \"stated\"\n\
         [[program]]\nmatch = [\"cd\"]\nlanguages = [\"powershell\"]\nchanges_dir = \"stated\"\n", v()),
    );
    let loaded = load_files(&shipped, Path::new(ABSENT));
    assert!(loaded.gaps.is_empty(), "an absent my-knowledge.toml must never trip the retraction check: {:?}", loaded.gaps);
}

// --- REFUSED is not ABSENT (spec §7, rev 4) --------------------------------

#[test]
fn a_refused_shipped_file_sets_my_knowledge_aside() {
    let dir = std::env::temp_dir().join(format!("vouch-kb-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let shipped = dir.join("knowledge.toml");
    let mine = dir.join("my-knowledge.toml");
    // Stale shipped file: parses cleanly, but predates the schema — no version key.
    std::fs::write(&shipped, "[[program]]\nmatch = [\"cd\"]\n").unwrap();
    std::fs::write(&mine, "[[program]]\nmatch = [\"zoxide\"]\nall_subcommands = true\n").unwrap();
    let loaded = load_files(&shipped, &mine);
    assert!(loaded.kb.program.is_empty(),
        "my-knowledge must not stand in for a refused shipped file");
    assert!(loaded.gaps.iter().any(|g| g.why.contains("version")));
    assert!(loaded.gaps.iter().any(|g| g.why.contains("set aside")));

    // Pinning the WORDING above is not enough: `gap_paragraph` in `src/main.rs`
    // dispatches on `(g.source, g.kind)`, not on `why`'s text, and a wildcard
    // arm exists for `(GapSource::MyKnowledge, _)`. A regression that builds
    // the set-aside gap with `GapKind::Unusable` instead of `SetAside` would
    // still contain similar wording here and pass the two asserts above while
    // silently falling through to the wrong render arm — the one that prints
    // "vouch still recognises everything the shipped knowledge describes"
    // under a refusal, which is the exact defect this task removes. Asserting
    // the discriminators directly is what actually pins the fix.
    let refusal = loaded.gaps.iter().find(|g| g.source == GapSource::Knowledge)
        .expect("no refusal gap for the shipped file");
    assert_eq!(refusal.kind, GapKind::Unusable, "the shipped refusal must render through the Unusable arm: {refusal:?}");
    let set_aside = loaded.gaps.iter().find(|g| g.source == GapSource::MyKnowledge)
        .expect("no set-aside gap for my-knowledge");
    assert_eq!(set_aside.kind, GapKind::SetAside, "the set-aside gap must carry GapKind::SetAside, or it renders through the wrong arm: {set_aside:?}");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn an_absent_shipped_file_keeps_the_documented_behaviour() {
    let dir = std::env::temp_dir().join(format!("vouch-kb-absent-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mine = dir.join("my-knowledge.toml");
    std::fs::write(&mine, "version = 2\n[[program]]\nmatch = [\"mytool\"]\n").unwrap();
    let loaded = load_files(&dir.join("knowledge.toml"), &mine);
    assert_eq!(loaded.kb.program.len(), 1, "absence is not refusal; my-knowledge still applies");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_shipped_file_with_a_version_below_the_schema_refuses() {
    // Distinct from "no version key at all": this file HAS a version, it is
    // just too old. Both must refuse, but they are different sentences (one
    // says "predates the key", the other names the stale number), so this
    // pins the second shape independently.
    let shipped = scratch("stale_version.toml", "version = 1\n[[program]]\nmatch = [\"probe\"]\n");
    let loaded = load_files(&shipped, Path::new(ABSENT));
    assert!(loaded.kb.program.is_empty(), "a stale-versioned shipped file still loaded something");
    assert_eq!(loaded.gaps.len(), 1, "mine is absent, so there is nothing to set aside: {:?}", loaded.gaps);
    assert!(loaded.gaps[0].why.contains("version"), "the gap does not name the version problem: {:?}", loaded.gaps[0]);
    assert!(loaded.gaps[0].why.contains('1'), "the gap does not name the stale value: {:?}", loaded.gaps[0]);
    assert_eq!(loaded.gaps[0].source, GapSource::Knowledge, "the refusal is about the SHIPPED file: {:?}", loaded.gaps[0]);
    assert_eq!(loaded.gaps[0].kind, GapKind::Unusable, "a stale version must render through the same arm as any other refusal: {:?}", loaded.gaps[0]);
}

#[test]
fn a_shipped_file_at_the_previous_schema_version_is_now_refused() {
    // Pins the schema bump itself (Task 6, knowledge schema v4): `version =
    // 3` was CURRENT before this task and loaded cleanly; after the bump it
    // is one behind and must refuse, the same as any other stale number.
    let shipped = scratch("previously_current_version.toml", "version = 3\n[[program]]\nmatch = [\"probe\"]\n");
    let loaded = load_files(&shipped, Path::new(ABSENT));
    assert!(loaded.kb.program.is_empty(), "a version = 3 shipped file still loaded something");
    assert_eq!(loaded.gaps.len(), 1, "the stale version must be a gap: {:?}", loaded.gaps);
    assert!(loaded.gaps[0].why.contains("version"), "the gap does not name the version problem: {:?}", loaded.gaps[0]);
    assert!(loaded.gaps[0].why.contains('3'), "the gap does not name the stale value: {:?}", loaded.gaps[0]);
}

#[test]
fn a_my_knowledge_file_with_no_version_still_loads() {
    // The version gate is the SHIPPED file's alone (spec §7): my-knowledge
    // predates every schema change by design and carries no version key of
    // its own. A shipped file with a current version plus a version-less
    // my-knowledge file must merge exactly as before this task.
    let shipped = scratch("shipped_current.toml", &format!("version = {}\n[[program]]\nmatch = [\"shippedprog\"]\n", v()));
    let mine = scratch("mine_no_version.toml", "[[program]]\nmatch = [\"myextra\"]\n");
    let loaded = load_files(&shipped, &mine);
    assert!(loaded.gaps.is_empty(), "a version-less my-knowledge.toml was rejected: {:?}", loaded.gaps);
    assert!(
        loaded.kb.program.iter().any(|p| p.match_names.iter().any(|n| n == "shippedprog")),
        "the shipped entry did not survive: {:?}", loaded.kb.program
    );
    assert!(
        loaded.kb.program.iter().any(|p| p.match_names.iter().any(|n| n == "myextra")),
        "the version-less my-knowledge entry was not merged: {:?}", loaded.kb.program
    );
}

#[test]
fn the_source_does_not_embed_the_knowledge_file() {
    for (name, src) in [
        ("guards.rs", include_str!("../src/guards.rs")),
        ("knowledge.rs", include_str!("../src/knowledge.rs")),
    ] {
        assert!(!src.contains("include_str!"), "{name} embeds a file at build time");
    }
}

#[test]
fn the_test_run_is_pinned_to_the_repository_files() {
    // Without this, `cargo test` decides against whatever the person running it
    // has in ~/.config, and the same commit passes for one contributor and
    // fails for another.
    for (var, ends_with) in [
        (vouch::knowledge::KNOWLEDGE_ENV, "/knowledge.toml"),
        ("VOUCH_CONFIG", "/vouch.example.toml"),
    ] {
        let v = std::env::var(var)
            .unwrap_or_else(|_| panic!("{var} is not set; .cargo/config.toml is missing"));
        assert!(v.replace('\\', "/").ends_with(ends_with), "{var} points at {v}");
        assert!(std::path::Path::new(&v).exists(), "{var} points at {v}, which does not exist");
    }

    // [review] my-knowledge must NOT point at a tracked file: `cargo run --
    // trust X` writes to it, and the review reproduced a [[program]] block
    // appearing in a committed fixture.
    let mine = std::env::var(vouch::knowledge::MY_KNOWLEDGE_ENV).expect("VOUCH_MY_KNOWLEDGE is not set");
    let mine = mine.replace('\\', "/");
    assert!(mine.contains("/target/"), "must be under target/, which is ignored; got {mine}");
}

#[test]
fn the_knowledge_file_does_not_describe_a_loader_that_does_not_exist() {
    // Its header claimed vouch reads $VOUCH_KNOWLEDGE, "else" the user file,
    // "else this built-in copy". There was never an else. A comment describing
    // machinery that does not exist is checked by nothing and believed by
    // everyone.
    let text = std::fs::read_to_string("knowledge.toml").expect("the repo's own file");
    let head: String = text.lines().take(30).collect::<Vec<_>>().join("\n");
    assert!(!head.contains("built-in copy"), "the header still claims a copy inside the binary");
    assert!(head.contains("my-knowledge.toml"), "the header should name the two files as they are");
}

// --- python: entries are real claims, not accidental shell collisions
// (Task 11, spec 2026-08-07 python-snippets) ---------------------------------

#[test]
fn every_python_prefixed_entry_carries_the_prefix_on_every_match_name() {
    // An entry that mixes a `python:`-prefixed name with a bare one would
    // silently describe a SHELL program too — the prefix is what keeps a
    // python API claim from ever being read as a claim about a shell command
    // of the same spelling.
    let text = std::fs::read_to_string("knowledge.toml").expect("the repo's own file");
    let kb = vouch::guards::load(&text).expect("the shipped file parses");
    for p in &kb.program {
        if !p.match_names.iter().any(|n| n.starts_with("python:")) {
            continue;
        }
        for n in &p.match_names {
            assert!(
                n.starts_with("python:"),
                "entry mixes a python: name with a bare one: {:?}",
                p.match_names
            );
        }
    }
}

/// Python builtins that intentionally share spelling with an existing bare
/// shell entry (M2.86 group A: `set`/`type`/`hash`/`exit`). These are not
/// forgotten prefixes — each is a real, checked python builtin — and
/// matching/merging always compares the full `python:`-prefixed string
/// (`src/guards.rs`, `src/knowledge.rs`), so a python call head can never be
/// mistaken for the bare shell entry of the same spelling at runtime. Only
/// these are exempted; any OTHER bare-name collision still fails below.
///
/// `eval` joined them when the shell builtin was described. Both entries are
/// real and both make the same claim for the same reason — `python:eval` and
/// bash's `eval` each take text and execute it — so this is the reviewed
/// dual-name case the list exists for, not a prefix someone dropped.
const DELIBERATE_DUAL_NAMES: &[&str] = &["set", "type", "hash", "exit", "eval"];

#[test]
fn no_python_api_bare_name_collides_with_an_existing_shell_program() {
    // Stripping the `python:` prefix off each API name must never land on a
    // string some shell (non-prefixed) entry already uses as a match name —
    // that would be the sign of a forgotten prefix on one alias in a
    // multi-name match array. DELIBERATE_DUAL_NAMES above is the one
    // reviewed exception to that heuristic.
    let text = std::fs::read_to_string("knowledge.toml").expect("the repo's own file");
    let kb = vouch::guards::load(&text).expect("the shipped file parses");
    let shell_names: std::collections::HashSet<&str> = kb
        .program
        .iter()
        .flat_map(|p| p.match_names.iter())
        .filter(|n| !n.starts_with("python:"))
        .map(String::as_str)
        .collect();
    let offenders: Vec<&str> = kb
        .program
        .iter()
        .flat_map(|p| p.match_names.iter())
        .filter_map(|n| n.strip_prefix("python:"))
        .filter(|bare| shell_names.contains(bare))
        .filter(|bare| !DELIBERATE_DUAL_NAMES.contains(bare))
        .collect();
    assert!(
        offenders.is_empty(),
        "a python: entry's bare form collides with an existing shell program name: {offenders:?}"
    );
}

#[test]
fn every_writes_only_with_file_mode_entry_names_mode_in_arg_names() {
    // A belt over `knowledge::validate`'s own load-time check (src/knowledge.rs
    // ~343): this walks the actual SHIPPED file's content directly, so it
    // fails independently of whether the loader's own check keeps working.
    let text = std::fs::read_to_string("knowledge.toml").expect("the repo's own file");
    let kb = vouch::guards::load(&text).expect("the shipped file parses");
    let offenders: Vec<&[String]> = kb
        .program
        .iter()
        .filter(|p| p.writes_only_with_file_mode == Some(true))
        .filter(|p| !p.arg_names.iter().any(|n| n == "mode"))
        .map(|p| p.match_names.as_slice())
        .collect();
    assert!(
        offenders.is_empty(),
        "writes_only_with_file_mode = true with no \"mode\" named in arg_names: {offenders:?}"
    );
}

fn scratch(name: &str, body: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join("vouch_knowledge_source_test");
    std::fs::create_dir_all(&dir).expect("mkdir");
    let p = dir.join(name);
    std::fs::write(&p, body).expect("write");
    p
}

#[test]
fn a_version_7_file_is_refused_naming_both_versions() {
    // v7 was current until the standalone_flags changeset; an installed v7
    // file under this binary must refuse with the version message, not a
    // field error.
    let shipped = scratch("v7_now_stale.toml", "version = 7\n[[program]]\nmatch = [\"probe\"]\n");
    let loaded = load_files(&shipped, Path::new(ABSENT));
    assert!(loaded.kb.program.is_empty(), "a version = 7 file still loaded something");
    assert!(loaded.gaps[0].why.contains("version = 7"), "{:?}", loaded.gaps[0]);
    assert!(loaded.gaps[0].why.contains('8'), "{:?}", loaded.gaps[0]);
}

#[test]
fn an_absent_subcommands_key_reads_as_whole_program_and_an_empty_one_does_not() {
    let shipped = scratch(
        "three_state_reading.toml",
        &format!(
            "version = {}\n[[program]]\nmatch = [\"aa\"]\n\n\
             [[program]]\nmatch = [\"bb\"]\nsubcommands = [\"go\"]\n",
            v()
        ),
    );
    let loaded = load_files(&shipped, Path::new(ABSENT));
    let aa = loaded.kb.program.iter().find(|e| e.match_names[0] == "aa").unwrap();
    let bb = loaded.kb.program.iter().find(|e| e.match_names[0] == "bb").unwrap();
    assert_eq!(aa.subcommands, None);
    assert_eq!(bb.subcommands, Some(vec!["go".to_string()]));
}

#[test]
fn member_shape_ok_accepts_a_bare_flag_under_its_prefix() {
    assert!(
        vouch::knowledge::member_shape_ok(&["-"], "--version").is_ok(),
        "a plain long flag under a declared prefix must be accepted"
    );
}

#[test]
fn member_shape_ok_refuses_every_shape_that_is_not_a_bare_flag() {
    // Each of these fails a different one of member_shape_ok's rules — the
    // option terminator, no prefix at all, and a post-prefix character
    // outside the allowlist by way of a glob, a brace expansion, an `=`
    // value, and a variable expansion. Every failure must name a rule, not
    // return an empty string, since the message is what a loader refusal
    // shows the operator.
    for f in ["--", "version", "-?", "-{h,V}", "--config=x", "--$HOME"] {
        let err = vouch::knowledge::member_shape_ok(&["-"], f)
            .expect_err(&format!("{f:?} must be refused"));
        assert!(!err.is_empty(), "the refusal for {f:?} names no rule");
    }
}

#[test]
fn in_refused_vocab_finds_a_token_in_value_options() {
    let prog = Program {
        value_options: vec!["--config".to_string()],
        ..Default::default()
    };
    assert_eq!(
        vouch::knowledge::in_refused_vocab(&prog, "--config"),
        Some("value_options")
    );
}

#[test]
fn in_refused_vocab_finds_a_token_only_in_here_write_when_flags() {
    let prog = Program {
        here_write: vec![HereWrite {
            when_flags: vec!["-x".to_string()],
            unless_flags: vec![],
            subcommand: None,
            operands: None,
        }],
        ..Default::default()
    };
    assert_eq!(
        vouch::knowledge::in_refused_vocab(&prog, "-x"),
        Some("here_write.when_flags")
    );
}

#[test]
fn in_refused_vocab_reports_none_for_an_unclaimed_token() {
    let prog = Program {
        value_options: vec!["--config".to_string()],
        ..Default::default()
    };
    assert_eq!(vouch::knowledge::in_refused_vocab(&prog, "--other"), None);
}

#[test]
fn in_refused_vocab_returns_the_first_vocabulary_in_order_on_a_collision() {
    // "--dup" is claimed by both value_options and wrap_flags — value_options
    // comes first in the checked order, so it must win.
    let prog = Program {
        value_options: vec!["--dup".to_string()],
        wrap_flags: vec!["--dup".to_string()],
        ..Default::default()
    };
    assert_eq!(
        vouch::knowledge::in_refused_vocab(&prog, "--dup"),
        Some("value_options")
    );
}

#[test]
fn an_empty_subcommands_list_without_standalone_flags_is_refused() {
    let shipped = scratch(
        "empty_subcommands_no_standalone.toml",
        &format!(
            "version = {}\n[[program]]\nmatch = [\"probe\"]\ncase_sensitive_flags = true\nsubcommands = []\n",
            v()
        ),
    );
    let loaded = load_files(&shipped, Path::new(ABSENT));
    assert!(
        loaded.kb.program.is_empty(),
        "subcommands = [] with no standalone_flags still loaded: {:?}",
        loaded.kb.program
    );
    assert_eq!(loaded.gaps.len(), 1, "{:?}", loaded.gaps);
    assert!(loaded.gaps[0].why.contains("probe"), "{:?}", loaded.gaps[0]);
    assert!(
        loaded.gaps[0].why.contains("can never recognise anything"),
        "{:?}",
        loaded.gaps[0]
    );
}

#[test]
fn a_standalone_member_that_is_not_flag_shaped_is_refused() {
    let shipped = scratch(
        "standalone_not_flag_shaped.toml",
        &format!(
            "version = {}\n[[program]]\nmatch = [\"probe\"]\ncase_sensitive_flags = true\nstandalone_flags = [\"version\"]\n",
            v()
        ),
    );
    let loaded = load_files(&shipped, Path::new(ABSENT));
    assert!(
        loaded.kb.program.is_empty(),
        "a non-flag-shaped standalone member still loaded: {:?}",
        loaded.kb.program
    );
    assert_eq!(loaded.gaps.len(), 1, "{:?}", loaded.gaps);
    assert!(
        loaded.gaps[0].why.contains("not flag-shaped"),
        "{:?}",
        loaded.gaps[0]
    );
}

#[test]
fn the_end_of_options_token_is_refused_as_a_standalone_member() {
    let shipped = scratch(
        "standalone_end_of_options.toml",
        &format!(
            "version = {}\n[[program]]\nmatch = [\"probe\"]\ncase_sensitive_flags = true\nstandalone_flags = [\"--\"]\n",
            v()
        ),
    );
    let loaded = load_files(&shipped, Path::new(ABSENT));
    assert!(
        loaded.kb.program.is_empty(),
        "\"--\" as a standalone member still loaded: {:?}",
        loaded.kb.program
    );
    assert_eq!(loaded.gaps.len(), 1, "{:?}", loaded.gaps);
    assert!(
        loaded.gaps[0].why.contains("ends option parsing"),
        "{:?}",
        loaded.gaps[0]
    );
}

#[test]
fn a_member_with_characters_outside_the_allowlist_is_refused() {
    // Each spelling defeats the allowlist by a different route — a glob
    // char, a brace-expansion char, an '=' value, and a variable expansion —
    // and each gets its own file+load so a failure names which one broke.
    for (name, flag) in [
        ("standalone_charset_glob.toml", "-?"),
        ("standalone_charset_brace.toml", "-{h,V}"),
        ("standalone_charset_eq.toml", "--config=x"),
        ("standalone_charset_expand.toml", "--$HOME"),
    ] {
        let shipped = scratch(
            name,
            &format!(
                "version = {}\n[[program]]\nmatch = [\"probe\"]\ncase_sensitive_flags = true\nstandalone_flags = [{:?}]\n",
                v(),
                flag
            ),
        );
        let loaded = load_files(&shipped, Path::new(ABSENT));
        assert!(
            loaded.kb.program.is_empty(),
            "{flag:?} should have been refused: {:?}",
            loaded.kb.program
        );
        assert_eq!(loaded.gaps.len(), 1, "{flag:?}: {:?}", loaded.gaps);
        assert!(
            loaded.gaps[0].why.contains("outside the allowed set"),
            "{flag:?}: {:?}",
            loaded.gaps[0]
        );
    }
}

#[test]
fn a_python_prefixed_entry_refuses_the_key() {
    let shipped = scratch(
        "standalone_python_prefixed.toml",
        &format!(
            "version = {}\n[[program]]\nmatch = [\"python:open\"]\ncase_sensitive_flags = true\nstandalone_flags = [\"--version\"]\n",
            v()
        ),
    );
    let loaded = load_files(&shipped, Path::new(ABSENT));
    assert!(
        loaded.kb.program.is_empty(),
        "a python: entry with standalone_flags still loaded: {:?}",
        loaded.kb.program
    );
    assert_eq!(loaded.gaps.len(), 1, "{:?}", loaded.gaps);
    assert!(loaded.gaps[0].why.contains("python:open"), "{:?}", loaded.gaps[0]);
    assert!(
        loaded.gaps[0].why.contains("no flag tokens"),
        "{:?}",
        loaded.gaps[0]
    );
}

#[test]
fn a_member_in_the_entrys_own_value_options_is_refused() {
    let shipped = scratch(
        "standalone_value_options_collision.toml",
        &format!(
            "version = {}\n[[program]]\nmatch = [\"probe\"]\ncase_sensitive_flags = true\nvalue_options = [\"-c\"]\nstandalone_flags = [\"-c\"]\n",
            v()
        ),
    );
    let loaded = load_files(&shipped, Path::new(ABSENT));
    assert!(
        loaded.kb.program.is_empty(),
        "a standalone member also in value_options still loaded: {:?}",
        loaded.kb.program
    );
    assert_eq!(loaded.gaps.len(), 1, "{:?}", loaded.gaps);
    assert!(loaded.gaps[0].why.contains("value_options"), "{:?}", loaded.gaps[0]);
    assert!(loaded.gaps[0].why.contains("-c"), "{:?}", loaded.gaps[0]);
}

// --- the post-merge stage (Task 4, spec 2026-08-20 §4) ---------------------
//
// The standalone_flags checks above run per-file, before either side has
// seen the other. Some of the checks can only be answered once the two
// files are combined — an operator overlay can replace a vocabulary WHOLE,
// so only the merged entry can say whether a standalone member ends up
// orphaned or colliding. A failure here sets the WHOLE my-knowledge overlay
// aside and leaves the shipped knowledge alone in effect (`GapKind::MergedShape`)
// — narrower than the pre-merge refusals above, which throw the whole
// combined load away.

#[test]
fn a_one_key_overlay_onto_a_case_stating_shipped_entry_loads() {
    // THE round-2 trap vector: the operator's own (pre-merge) entry states
    // no case_sensitive_flags at all — that is the whole point of a one-key
    // overlay, leaning on the shipped entry's own case declaration. A check
    // that read the OPERATOR's pre-merge value instead of the MERGED one
    // would refuse this file for a reason that becomes false the moment the
    // merge actually runs.
    let shipped = scratch(
        "shipped_qq.toml",
        &format!(
            "version = {}\n[[program]]\nmatch = [\"qq\"]\nsubcommands = [\"go\"]\ncase_sensitive_flags = true\nno_value_options = [\"--v\"]\n",
            v()
        ),
    );
    let mine = scratch("mine_qq.toml", "[[program]]\nmatch = [\"qq\"]\nstandalone_flags = [\"--v\"]\n");
    let loaded = load_files(&shipped, &mine);
    assert!(loaded.gaps.is_empty(), "the one-key overlay was rejected: {:?}", loaded.gaps);
    let qq = loaded
        .kb
        .program
        .iter()
        .find(|p| p.match_names.iter().any(|n| n == "qq"))
        .expect("the merged entry is missing");
    assert_eq!(
        qq.standalone_flags,
        vec!["--v".to_string()],
        "the operator's standalone_flags did not survive the merge"
    );
}

#[test]
fn a_fresh_standalone_entry_stating_no_case_rule_is_set_aside() {
    let shipped = scratch(
        "shipped_other_for_rr.toml",
        &format!("version = {}\n[[program]]\nmatch = [\"shippedother\"]\n", v()),
    );
    let mine = scratch(
        "mine_rr_no_case.toml",
        "[[program]]\nmatch = [\"rr\"]\nsubcommands = []\nstandalone_flags = [\"--v\"]\n",
    );
    let loaded = load_files(&shipped, &mine);
    assert_eq!(loaded.gaps.len(), 1, "{:?}", loaded.gaps);
    assert_eq!(loaded.gaps[0].kind, GapKind::MergedShape, "{:?}", loaded.gaps[0]);
    assert_eq!(loaded.gaps[0].source, GapSource::MyKnowledge, "{:?}", loaded.gaps[0]);
    assert!(loaded.gaps[0].why.contains("case_sensitive_flags"), "{:?}", loaded.gaps[0]);
    assert!(
        loaded.kb.program.iter().any(|p| p.match_names.iter().any(|n| n == "shippedother")),
        "the shipped knowledge must still be in effect: {:?}",
        loaded.kb.program
    );
    assert!(
        !loaded.kb.program.iter().any(|p| p.match_names.iter().any(|n| n == "rr")),
        "the set-aside entry must not be in effect: {:?}",
        loaded.kb.program
    );
}

#[test]
fn a_replaced_vocabulary_that_orphans_a_member_on_a_runs_file_entry_is_set_aside() {
    let shipped = scratch(
        "shipped_ss_runs_file.toml",
        &format!(
            "version = {}\n[[program]]\nmatch = [\"ss\"]\nruns_file = \"arg_0\"\nno_value_options = [\"--v\"]\nstandalone_flags = [\"--v\"]\ncase_sensitive_flags = true\n",
            v()
        ),
    );
    let mine = scratch(
        "mine_ss_no_value_options.toml",
        "[[program]]\nmatch = [\"ss\"]\nno_value_options = [\"--other\"]\n",
    );
    let loaded = load_files(&shipped, &mine);
    assert_eq!(loaded.gaps.len(), 1, "{:?}", loaded.gaps);
    assert_eq!(loaded.gaps[0].kind, GapKind::MergedShape, "{:?}", loaded.gaps[0]);
    assert!(loaded.gaps[0].why.contains("\"ss\""), "{:?}", loaded.gaps[0]);
    assert!(loaded.gaps[0].why.contains("standalone_flags"), "{:?}", loaded.gaps[0]);
    assert!(loaded.gaps[0].why.contains("no_value_options"), "{:?}", loaded.gaps[0]);
    let ss = loaded
        .kb
        .program
        .iter()
        .find(|p| p.match_names.iter().any(|n| n == "ss"))
        .expect("the shipped ss entry must still be in effect");
    assert_eq!(
        ss.no_value_options,
        vec!["--v".to_string()],
        "the shipped entry, not the merged one, must be in effect"
    );
}

#[test]
fn the_same_orphaning_on_an_entry_without_runs_file_loads() {
    let shipped = scratch(
        "shipped_ss_no_runs_file.toml",
        &format!(
            "version = {}\n[[program]]\nmatch = [\"ss\"]\nno_value_options = [\"--v\"]\nstandalone_flags = [\"--v\"]\ncase_sensitive_flags = true\n",
            v()
        ),
    );
    let mine = scratch(
        "mine_ss_no_value_options2.toml",
        "[[program]]\nmatch = [\"ss\"]\nno_value_options = [\"--other\"]\n",
    );
    let loaded = load_files(&shipped, &mine);
    assert!(loaded.gaps.is_empty(), "the scoping is not real if this refuses: {:?}", loaded.gaps);
    let ss = loaded
        .kb
        .program
        .iter()
        .find(|p| p.match_names.iter().any(|n| n == "ss"))
        .expect("the merged entry is missing");
    assert_eq!(
        ss.no_value_options,
        vec!["--other".to_string()],
        "the operator's no_value_options did not survive the merge"
    );
}

#[test]
fn a_fanned_key_colliding_with_a_siblings_vocabulary_is_set_aside_naming_the_sibling() {
    let shipped = scratch(
        "shipped_tt_two_entries.toml",
        &format!(
            "version = {}\n[[program]]\nmatch = [\"tt\"]\ncase_sensitive_flags = true\n\n\
             [[program]]\nmatch = [\"tt\"]\nwrap_flags = [\"-e\"]\ncase_sensitive_flags = true\n",
            v()
        ),
    );
    let mine = scratch(
        "mine_tt_standalone_e.toml",
        "[[program]]\nmatch = [\"tt\"]\nstandalone_flags = [\"-e\"]\ncase_sensitive_flags = true\n",
    );
    let loaded = load_files(&shipped, &mine);
    assert_eq!(loaded.gaps.len(), 1, "{:?}", loaded.gaps);
    assert_eq!(loaded.gaps[0].kind, GapKind::MergedShape, "{:?}", loaded.gaps[0]);
    assert!(loaded.gaps[0].why.contains("\"tt\""), "{:?}", loaded.gaps[0]);
    assert!(
        loaded.gaps[0].why.contains("wrap_flags"),
        "the gap does not name the colliding sibling's vocabulary: {:?}",
        loaded.gaps[0]
    );
}

#[test]
fn set_aside_leaves_shipped_knowledge_in_effect_not_nothing() {
    let shipped = scratch("shipped_ls_and_rr.toml", &format!("version = {}\n[[program]]\nmatch = [\"ls\"]\n", v()));
    let mine = scratch(
        "mine_rr_no_case_2.toml",
        "[[program]]\nmatch = [\"rr\"]\nsubcommands = []\nstandalone_flags = [\"--v\"]\n",
    );
    let loaded = load_files(&shipped, &mine);
    assert_eq!(loaded.gaps.len(), 1, "{:?}", loaded.gaps);
    assert_eq!(
        loaded.gaps[0].kind,
        GapKind::MergedShape,
        "the set-aside gap must carry the NEW kind, not SetAside: {:?}",
        loaded.gaps[0]
    );
    assert!(
        loaded.kb.program.iter().any(|p| p.match_names.iter().any(|n| n == "ls")),
        "a shipped-only program must still be recognised after the set-aside: {:?}",
        loaded.kb.program
    );
}

#[test]
fn a_fanned_key_onto_a_multi_entry_name_loads_clean() {
    let shipped = scratch(
        "shipped_tt_plain_and_stdin.toml",
        &format!(
            "version = {}\n[[program]]\nmatch = [\"tt\"]\ncase_sensitive_flags = true\n\n\
             [[program]]\nmatch = [\"tt\"]\nevaluates_input = \"stdin\"\ncase_sensitive_flags = true\n",
            v()
        ),
    );
    let mine = scratch(
        "mine_tt_standalone_v.toml",
        "[[program]]\nmatch = [\"tt\"]\nstandalone_flags = [\"--v\"]\ncase_sensitive_flags = true\n",
    );
    let loaded = load_files(&shipped, &mine);
    assert!(loaded.gaps.is_empty(), "the accepted fan was rejected: {:?}", loaded.gaps);
    let tts: Vec<_> = loaded.kb.program.iter().filter(|p| p.match_names.iter().any(|n| n == "tt")).collect();
    assert_eq!(tts.len(), 2, "both shipped siblings should survive the merge: {:?}", tts);
    for p in tts {
        assert_eq!(
            p.standalone_flags,
            vec!["--v".to_string()],
            "the fanned key did not land on every sibling: {:?}",
            p
        );
    }
}

#[test]
fn a_discarded_narrowing_produces_a_note_not_silence() {
    let shipped = scratch(
        "shipped_narrowing.toml",
        &format!(
            "version = {}\n\
             [[program]]\nmatch = [\"aa\"]\n\n\
             [[program]]\nmatch = [\"bb\"]\n\n\
             [[program]]\nmatch = [\"cc\"]\nsubcommands = [\"push\", \"pull\"]\n",
            v()
        ),
    );
    let mine = scratch(
        "mine_narrowing.toml",
        "[[program]]\nmatch = [\"aa\"]\nsubcommands = [\"go\"]\n\n\
         [[program]]\nmatch = [\"bb\"]\nsubcommands = []\nstandalone_flags = [\"--v\"]\ncase_sensitive_flags = true\n\n\
         [[program]]\nmatch = [\"cc\"]\nsubcommands = []\nstandalone_flags = [\"--w\"]\ncase_sensitive_flags = true\n",
    );
    let loaded = load_files(&shipped, &mine);
    assert!(loaded.gaps.is_empty(), "none of these three should fail the load: {:?}", loaded.gaps);
    assert_eq!(loaded.notes.len(), 3, "expected one note per discarded narrowing: {:?}", loaded.notes);
    assert!(
        loaded.notes.iter().any(|n| n.contains("aa") && n.contains("whole-program")),
        "{:?}",
        loaded.notes
    );
    assert!(
        loaded.notes.iter().any(|n| n.contains("bb") && n.contains("whole-program")),
        "{:?}",
        loaded.notes
    );
    assert!(loaded.notes.iter().any(|n| n.contains("cc") && n.contains("verb")), "{:?}", loaded.notes);
}
