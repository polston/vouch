//! When vouch could not read a file, every prompt says so — without destroying
//! the evidence `vouch review` is built on.

use std::io::Write;
use std::process::{Command, Stdio};

#[path = "common/mod.rs"]
mod common;
use common::v;



// [review] All six tests originally shared one `VOUCH_STATE_DIR`. Harmless
// only by accident — none of them read the journal back. A sibling test
// (`review_survives_missing_files_test.rs`) DOES read the journal back via
// `vouch review`, so every test here now gets its own directory, named after
// the test, rather than relying on none of them ever needing to look.
fn run(tag: &str, env: &[(&str, &str)], snippet: &str) -> String {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_vouch"));
    cmd.env("VOUCH_STATE_DIR", std::env::temp_dir().join(format!("vouch_missing_files_state_{tag}")));
    // `.cargo/config.toml` force-sets `VOUCH_KNOWLEDGE` to the repo's real,
    // current `knowledge.toml` for the whole `cargo test` PROCESS, so it is
    // already in THIS test binary's own environment and would otherwise be
    // silently inherited by the child below. Every existing caller already
    // overrides it explicitly in `env`, so removing it first and letting the
    // loop below re-set it changes nothing for them — it only matters for a
    // caller that wants the variable to be genuinely UNSET rather than
    // "whatever cargo pinned it to", which `env` alone cannot express.
    cmd.env_remove("VOUCH_KNOWLEDGE");
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.arg("--hook");
    let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
    child.stdin.as_mut().unwrap().write_all(snippet.as_bytes()).unwrap();
    String::from_utf8_lossy(&child.wait_with_output().unwrap().stdout).to_string()
}

const ABSENT: &str = "tests/fixtures/there-is-no-such-file.toml";
const LS: &str = r#"{"hook_event_name":"PreToolUse","tool_use_id":"t","session_id":"s","cwd":"C:/claude","tool_name":"Bash","tool_input":{"command":"ls -la"}}"#;

fn with_nothing(tag: &str) -> String {
    let home = std::env::temp_dir().join("vouch_missing_files_home");
    std::fs::create_dir_all(&home).ok();
    let home = home.display().to_string();
    run(tag, &[
        ("VOUCH_CONFIG", ABSENT),
        ("VOUCH_KNOWLEDGE", ABSENT),
        ("VOUCH_MY_KNOWLEDGE", ABSENT),
        ("HOME", &home),
        ("USERPROFILE", &home),
    ], LS)
}

#[test]
fn the_prompt_says_there_is_no_knowledge_file() {
    assert!(with_nothing("no_knowledge_file").contains("no knowledge file"), "the prompt does not say what is wrong");
}

#[test]
fn the_prompt_says_where_it_looked() {
    assert!(with_nothing("where_it_looked").contains("there-is-no-such-file.toml"), "the prompt must name the path");
}

#[test]
fn the_prompt_says_it_will_keep_happening() {
    assert!(with_nothing("keep_happening").contains("every command"), "this is not a one-off and must say so");
}

#[test]
fn the_prompt_says_there_is_no_config_file_too() {
    assert!(with_nothing("no_config_file_too").contains("no config file"), "the missing config is not mentioned");
}

#[test]
fn the_reason_still_starts_with_what_stopped_it() {
    // [review] `vouch review` reads the FIRST line. Putting the banner there
    // made every prompt on a fresh install invisible to it.
    let out = with_nothing("reason_starts_with");
    let reason = out.split(r#""permissionDecisionReason":""#).nth(1).expect("a reason");
    assert!(
        reason.starts_with("vouch stopped on:"),
        "the reason no longer starts with the construct: {}",
        &reason[..reason.len().min(120)]
    );
}

// --- a file that is THERE and broken is not a missing file -----------------
//
// [review] The banner branched on WHICH file a gap was about and never on
// whether that file exists. A config with one bad character produced the
// headline "vouch has no config file", a TOML parse error pointing at line 2
// of that same file directly underneath it — a sentence contradicted by its
// own evidence — and then "`vouch.example.toml` ... is the file to copy",
// advice that destroys the configuration the error was about. This is the
// identical defect already fixed once for `my-knowledge.toml` and left in
// place for the other two files.

fn broken_file(name: &str, body: &str) -> String {
    let dir = std::env::temp_dir().join("vouch_missing_files_broken");
    std::fs::create_dir_all(&dir).expect("mkdir");
    let p = dir.join(name);
    std::fs::write(&p, body).expect("write");
    p.display().to_string()
}

fn scratch_home() -> String {
    let home = std::env::temp_dir().join("vouch_missing_files_home");
    std::fs::create_dir_all(&home).ok();
    home.display().to_string()
}

#[test]
fn a_config_that_is_there_and_broken_is_not_called_missing() {
    let bad = broken_file("bad-config.toml", "# my settings\n[lang.bash\ndefault = \"ask\"\n");
    let home = scratch_home();
    let out = run("broken_config", &[
        ("VOUCH_CONFIG", &bad),
        ("VOUCH_KNOWLEDGE", "knowledge.toml"),
        ("VOUCH_MY_KNOWLEDGE", ABSENT),
        ("HOME", &home),
        ("USERPROFILE", &home),
    ], LS);

    assert!(!out.contains("no config file"), "a file that is on disk was called missing: {out}");
    assert!(
        !out.contains("is the file to copy"),
        "offered to copy an example over a file that exists and has content: {out}"
    );
    assert!(out.contains("could not use it"), "the banner does not say what is actually wrong: {out}");
}

#[test]
fn a_knowledge_file_that_is_there_and_broken_is_not_called_missing() {
    let bad = broken_file("bad-knowledge.toml", "this is not [[[ valid toml\n");
    let home = scratch_home();
    let out = run("broken_knowledge", &[
        ("VOUCH_CONFIG", "vouch.example.toml"),
        ("VOUCH_KNOWLEDGE", &bad),
        ("VOUCH_MY_KNOWLEDGE", ABSENT),
        ("HOME", &home),
        ("USERPROFILE", &home),
    ], LS);

    assert!(!out.contains("no knowledge file"), "a file that is on disk was called missing: {out}");
    assert!(
        !out.contains("is the file to copy"),
        "offered to copy the shipped file over one that exists and has content: {out}"
    );
    assert!(out.contains("could not read it"), "the banner does not say what is actually wrong: {out}");
}

/// [review] `VOUCH_KNOWLEDGE` meant THE OPERATOR'S OWN file before this branch
/// and means THE SHIPPED file after it, and nothing said so anywhere the
/// operator would see it. Someone who had it set and upgrades is pointing
/// vouch at their small personal file as though it were the whole shipped set
/// — reproduced with a file holding one `[[program]] match = ["rm"]` entry,
/// which made `rm -rf /` ALLOW while `git push --force`, `sudo rm -rf /` and
/// `chmod +x` fell through to the unmodelled-program prompt. No gap is
/// reported for any of it, because the file is there and it parses.
#[test]
fn a_file_chosen_by_an_environment_variable_says_so() {
    let out = with_nothing("env_redirect");
    assert!(out.contains("VOUCH_KNOWLEDGE"), "the variable in play is not named: {out}");
    assert!(
        out.contains("used to mean YOUR OWN file"),
        "the change of meaning is not stated, so an operator upgrading has no way to learn it: {out}"
    );
    assert!(
        out.contains("unset the variable"),
        "every prompt must name what turns it off: {out}"
    );
}

#[test]
fn a_file_left_at_an_old_path_is_named_and_not_read() {
    let dir = std::env::temp_dir().join("vouch_moved_files_test");
    std::fs::create_dir_all(dir.join(".config")).expect("mkdir");
    std::fs::write(dir.join(".config/vouch-knowledge.toml"), "[[program]]\nmatch = [\"leftbehindprog\"]\n").expect("write");
    let dir = dir.display().to_string();

    let out = run("old_path_not_read", &[
        ("VOUCH_CONFIG", "vouch.example.toml"),
        ("VOUCH_KNOWLEDGE", "knowledge.toml"),
        ("HOME", &dir),
        ("USERPROFILE", &dir),
    ], r#"{"hook_event_name":"PreToolUse","tool_use_id":"t","session_id":"s","cwd":"C:/claude","tool_name":"Bash","tool_input":{"command":"leftbehindprog x"}}"#);

    assert!(out.contains("no longer reads"), "not told the file is at an old path: {out}");
    assert!(out.contains("\"permissionDecision\":\"ask\""), "the old file was loaded: {out}");
}

// --- REFUSED is not ABSENT: the banner must not contradict itself ----------
//
// [review, task 3 finding 1] The `(GapSource::MyKnowledge, GapKind::SetAside)`
// arm in `gap_paragraph` (src/main.rs) was covered only by unit tests that
// pinned `Gap.why`'s wording, never anything exercising the actual render
// path. A regression that built the set-aside gap with `GapKind::Unusable`
// instead of `SetAside` would still contain similar-looking `why` text and
// pass those unit tests, while falling through here to the pre-existing
// `(GapSource::MyKnowledge, _)` wildcard — which prints "vouch still
// recognises everything the shipped knowledge describes" directly under a
// gap saying the shipped file just refused. Both sentences cannot be true at
// once; this is the exact contradiction the task removed, and only a test
// that reads the rendered banner can catch it coming back.
#[test]
fn a_refused_shipped_knowledge_file_does_not_claim_my_knowledge_still_covers_it() {
    let bad = broken_file("stale-knowledge-with-mine.toml", "[[program]]\nmatch = [\"cd\"]\n");
    let mine = broken_file("mine-set-aside.toml", "[[program]]\nmatch = [\"zoxide\"]\nall_subcommands = true\n");
    let home = scratch_home();

    let out = run("refused_shipped_sets_mine_aside", &[
        ("VOUCH_CONFIG", "vouch.example.toml"),
        ("VOUCH_KNOWLEDGE", &bad),
        ("VOUCH_MY_KNOWLEDGE", &mine),
        ("HOME", &home),
        ("USERPROFILE", &home),
    ], LS);

    assert!(
        !out.contains("vouch still recognises everything the shipped knowledge describes"),
        "a refused shipped file must never be followed by a sentence claiming it is still in \
         effect: {out}"
    );
    assert!(
        out.contains("were never applied"),
        "the set-aside wording is missing from the banner: {out}"
    );
    assert!(
        out.contains("recognises NOTHING right now"),
        "the banner must say nothing at all is recognised, my-knowledge included: {out}"
    );
}

// --- a retraction refusal is not the same gap as a broken my-knowledge.toml -
//
// [review, final review Finding 1] An unscoped `changes_dir = "no"` in
// my-knowledge.toml over a shipped name whose language claims differ
// (`validate_retraction`) fails the WHOLE combined load closed — `load_files`
// returns `Knowledge::default()`, not the shipped base. That used to carry
// `GapKind::Unusable`, the SAME kind a my-knowledge.toml that fails on its OWN
// carries, and both rendered through the `(GapSource::MyKnowledge, _)`
// wildcard, which says "vouch still recognises everything the shipped
// knowledge describes" — true for the other case, false for this one. Only a
// test that reads the rendered banner catches that sentence coming back under
// this specific gap.
#[test]
fn a_retraction_refusal_does_not_claim_the_shipped_knowledge_still_stands() {
    let shipped = broken_file(
        "retraction-refusal-shipped.toml",
        &format!("version = {}\n[[program]]\nmatch = [\"cd\"]\nlanguages = [\"bash\"]\nchanges_dir = \"stated\"\n\
         [[program]]\nmatch = [\"cd\"]\nlanguages = [\"powershell\"]\nchanges_dir = \"stated\"\n", v()),
    );
    let mine = broken_file(
        "retraction-refusal-mine.toml",
        "[[program]]\nmatch = [\"cd\"]\nchanges_dir = \"no\"\n",
    );
    let home = scratch_home();

    let out = run("retraction_refusal_banner", &[
        ("VOUCH_CONFIG", "vouch.example.toml"),
        ("VOUCH_KNOWLEDGE", &shipped),
        ("VOUCH_MY_KNOWLEDGE", &mine),
        ("HOME", &home),
        ("USERPROFILE", &home),
    ], LS);

    assert!(
        !out.contains("vouch still recognises everything the shipped knowledge describes"),
        "a retraction refusal must never be followed by a sentence claiming the shipped \
         knowledge is still in effect: {out}"
    );
    assert!(
        out.contains("nothing is in effect right now"),
        "the banner must say nothing at all is recognised, shipped knowledge included: {out}"
    );
}

// --- a place-scope refusal is not a language question ----------------------
//
// [review, final whole-branch review of the place-scoped-rules changeset,
// finding 2] `validate_place_scopes` fails the same way `validate_retraction`
// does — the whole combined load closed, `GapKind` carrying the reason — but
// for a different cause: an `only_under` on a name the shipped knowledge
// already describes, a scoped name split across more than one of the
// operator's own entries, or an empty `only_under` list. None of those is a
// language question, and reusing `Ambiguous`'s banner told the operator to
// add `languages = ["bash"]` or `["powershell"]`, which fixes none of the
// three. `GapKind::PlaceScope` gets its own banner so the remedy comes from
// the `why:` line, which already names the entry and the real cause.
#[test]
fn a_place_scope_refusal_does_not_offer_the_language_remedy() {
    let shipped = broken_file(
        "place-scope-refusal-shipped.toml",
        &format!("version = {}\n[[program]]\nmatch = [\"examplecmd\"]\n", v()),
    );
    let mine = broken_file(
        "place-scope-refusal-mine.toml",
        "[[program]]\nmatch = [\"examplecmd\"]\nonly_under = [\"C:/scratch/**\"]\n",
    );
    let home = scratch_home();

    let out = run("place_scope_refusal_banner", &[
        ("VOUCH_CONFIG", "vouch.example.toml"),
        ("VOUCH_KNOWLEDGE", &shipped),
        ("VOUCH_MY_KNOWLEDGE", &mine),
        ("HOME", &home),
        ("USERPROFILE", &home),
    ], LS);

    assert!(
        !out.contains("languages = [\"bash\"]"),
        "the language remedy must not print for a place-scope refusal, which is not a \
         language question: {out}"
    );
    assert!(
        !out.contains("which language it means"),
        "the Ambiguous banner's opening sentence must not print for this gap either: {out}"
    );
    assert!(
        out.contains("place scope") && out.contains("only_under"),
        "the new banner's own wording is missing: {out}"
    );
    assert!(
        out.contains("examplecmd") && out.contains("shipped"),
        "the refusal's own why: line must still name the entry and the real cause: {out}"
    );
    assert!(
        out.contains("not a language question"),
        "the closing sentence must say this is not a language question: {out}"
    );
}

// --- version_remedy: which fix a refused shipped file's gap names ----------
//
// [review, task 3 finding 2] `version_remedy` (src/knowledge.rs) reads
// `std::env::var(VOUCH_KNOWLEDGE)` directly, at the moment the refusal gap is
// written, to decide whether to name the variable or the installer — the one
// place left that still knows the truth, since `knowledge_path()` already
// resolved the override into a plain path before `load_files` ever saw it.
// Neither branch had a test.

// --- version sniff on an unparsable file: newer schema, not a broken one ---
//
// Spec 2026-08-05 §Schema, version skew point 1: a shipped file written for a
// newer schema than this binary understands fails to PARSE (an unknown key,
// `deny_unknown_fields`) before the ordinary version-below-the-constant check
// in `read_one` ever runs — so without the sniff, the operator saw the
// generic "fix the file... do NOT copy the repository's knowledge.toml over
// it" wording for a file that is not broken; their vouch binary is just old.

#[test]
fn a_shipped_file_newer_than_the_binary_names_the_binary_as_the_problem() {
    let bad = broken_file("newer-than-binary.toml", "version = 99\nunknown_key = true\n");
    let home = scratch_home();

    let out = run("newer_than_binary", &[
        ("VOUCH_CONFIG", "vouch.example.toml"),
        ("VOUCH_KNOWLEDGE", &bad),
        ("VOUCH_MY_KNOWLEDGE", ABSENT),
        ("HOME", &home),
        ("USERPROFILE", &home),
    ], LS);

    assert!(
        out.contains("newer than this vouch binary"),
        "the newer-than-binary sentence is missing: {out}"
    );
    assert!(
        !out.contains("fix the file at that path"),
        "the ordinary fix-the-file wording must not print for this gap: {out}"
    );
}

#[test]
fn a_refused_shipped_file_names_the_environment_variable_when_it_is_set() {
    let bad = broken_file("stale-via-env.toml", "[[program]]\nmatch = [\"cd\"]\n");
    let home = scratch_home();

    let out = run("version_remedy_env_set", &[
        ("VOUCH_CONFIG", "vouch.example.toml"),
        ("VOUCH_KNOWLEDGE", &bad),
        ("VOUCH_MY_KNOWLEDGE", ABSENT),
        ("HOME", &home),
        ("USERPROFILE", &home),
    ], LS);

    assert!(
        out.contains("the VOUCH_KNOWLEDGE environment variable points at this file"),
        "the remedy did not name the variable that is actually in play: {out}"
    );
    assert!(
        !out.contains("install-knowledge.sh"),
        "named the installer even though a variable is what put the file there: {out}"
    );
}

#[test]
fn a_refused_shipped_file_names_the_installer_when_no_variable_is_set() {
    let dir = std::env::temp_dir().join("vouch_missing_files_version_remedy_default");
    std::fs::create_dir_all(dir.join(".config/vouch")).expect("mkdir");
    std::fs::write(dir.join(".config/vouch/knowledge.toml"), "[[program]]\nmatch = [\"cd\"]\n").expect("write");
    let home = dir.display().to_string();

    // `VOUCH_KNOWLEDGE` is deliberately absent from this call's `env` — `run`
    // removes it from the inherited environment first (see its own comment),
    // so vouch falls through to the default `{HOME}/.config/vouch/knowledge.toml`
    // written above, exactly as an operator with no override set would.
    let out = run("version_remedy_env_unset", &[
        ("VOUCH_CONFIG", "vouch.example.toml"),
        ("VOUCH_MY_KNOWLEDGE", ABSENT),
        ("HOME", &home),
        ("USERPROFILE", &home),
    ], LS);

    assert!(
        out.contains("scripts/install-knowledge.sh"),
        "the remedy did not fall back to naming the installer: {out}"
    );
    assert!(
        !out.contains("VOUCH_KNOWLEDGE environment variable points at"),
        "named the variable even though none is set: {out}"
    );
}
