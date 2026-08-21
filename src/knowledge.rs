//! Where the program descriptions come from.
//!
//! Nothing is compiled in. If the files are not on disk, vouch knows nothing
//! and `unmodeled_command` decides what happens.
//!
//! The alternative — an embedded copy used when the file is missing — restores
//! exactly what this module exists to remove: a list of allowed things the
//! operator cannot open, diff, or comment a line out of.
//!
//! Three states, all reported, none fatal: a file that is absent, a file that
//! does not parse, and a file that parses to nothing. The third is the one that
//! was easy to miss — an empty file loads perfectly and leaves vouch knowing
//! nothing while believing it succeeded.

use crate::guards::{load, Knowledge, Program, Rule, SubWrite, Tool};
use crate::guards::ToolSnippet;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

/// Overrides the path to `knowledge.toml`.
///
/// NOTE: this name used to mean the operator's own file. It now means the file
/// that comes with vouch, matching the file names.
pub const KNOWLEDGE_ENV: &str = "VOUCH_KNOWLEDGE";

/// Overrides the path to `my-knowledge.toml`.
pub const MY_KNOWLEDGE_ENV: &str = "VOUCH_MY_KNOWLEDGE";

/// Which file a [`Gap`] is about.
///
/// [review] The banner used to say the same fixed sentence — "vouch has no
/// knowledge file, so it recognises nothing" — for every gap regardless of
/// which file produced it. Reproduced with a VALID `knowledge.toml` and a
/// broken `my-knowledge.toml`: the verdict was `allow` (recognition was
/// working fine) and the banner directly under it claimed vouch recognised
/// nothing and named the operator's OWN path as the place to copy the
/// shipped file over. One sentence for every kind of gap is the exact defect
/// this task exists to remove, reproduced inside the fix for it. The wording
/// now branches on this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GapSource {
    /// The knowledge that ships with vouch. Missing, broken, or empty, vouch
    /// recognises NOTHING — there is no shipped fallback.
    Knowledge,
    /// The operator's own additions. Missing is normal and never a gap (see
    /// `read_one`). Broken means only what THEY added is not in effect — the
    /// shipped knowledge still is.
    MyKnowledge,
    /// `config.toml`. Missing or broken, nothing has been allowed.
    Config,
}

/// What is wrong with the file a [`Gap`] is about — the three states named at
/// the top of this module.
///
/// [review] The banner distinguished WHICH file a gap was about and never
/// WHETHER IT EXISTS, so a config with one bad character produced a headline
/// saying "vouch has no config file" directly above a TOML parse error
/// pointing at line 2 of it — a sentence contradicted by its own evidence —
/// and then told the operator to copy the example over it, destroying the
/// configuration they had. A file that is not there and a file that is there
/// and broken are different sentences and want different advice, so the kind
/// travels with the gap rather than being guessed from the wording of `why`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GapKind {
    /// Not on disk. Copying a starting point over it destroys nothing.
    Missing,
    /// On disk, and vouch could not read or parse it. Never suggest replacing
    /// this one: it exists and it has the operator's content in it.
    Unusable,
    /// Read and parsed perfectly, and says nothing — no `[[program]]` and no
    /// `[[tool]]`.
    ///
    /// Only a file with no entries reaches this. A misspelt table name does NOT:
    /// `Knowledge` carries `deny_unknown_fields`, so `[[programs]]` is a parse
    /// error and lands in `Unusable`. This said otherwise until 2026-07-29, and
    /// the prompt built from it sent the operator to check the one thing that
    /// could not have caused what they were looking at.
    Empty,
    /// Parsed and validated fine ON ITS OWN, but not applied: the shipped base
    /// it would have been laid over refused to load (`GapSource::Knowledge`,
    /// `Unusable`), so there is nothing to overlay it onto. Only ever attached
    /// to `GapSource::MyKnowledge` — the file's OWN disqualifications still go
    /// through `Missing`/`Unusable`/`Empty`; this kind is never about what is
    /// wrong with THIS file. Spec §7, rev 4: a refused shipped file used to
    /// leave the operator's overlay standing in as the whole knowledge, which
    /// is fail-open wearing a banner.
    SetAside,
    /// Parsed and validated fine ON ITS OWN — again never about what is wrong
    /// with THIS file — but one of its OWN entries is ambiguous against the
    /// shipped file (`validate_retraction`: an unscoped `changes_dir = "no"`
    /// whose shipped claims differ by language) and vouch will not guess which
    /// language it meant. Unlike `SetAside`, the shipped base is not the thing
    /// that failed here — it may be perfectly fine on its own — the two files
    /// TOGETHER are what is unusable, so `load_files` throws away BOTH:
    /// nothing is in effect, not even the shipped knowledge alone. Only ever
    /// attached to `GapSource::MyKnowledge` — the ambiguous entry is what
    /// triggered it. Named separately from `Unusable` because the renderer's
    /// wildcard arm for `(GapSource::MyKnowledge, _)` says "vouch still
    /// recognises everything the shipped knowledge describes", which is true
    /// when THIS file alone was rejected (`kb` is then the shipped base, see
    /// `load_files`'s `None => base` arm) and false here — reusing `Unusable`
    /// for this state made that sentence print under a gap it contradicts.
    ///
    /// Renamed from `Refused` 2026-08-03 (CLAUDE.md §0.0): this module's own
    /// word "refused" already names a different state throughout it — the
    /// `refused` bool and doc comments in `load_files` below, meaning the
    /// SHIPPED file failed the version/parse gate — and reusing that word
    /// for THIS state (an operator entry ambiguous against the shipped set)
    /// made a reader work out which meaning was meant every time. This is
    /// what it actually is.
    Ambiguous,
    /// Parsed and validated fine ON ITS OWN — same "both files together are
    /// what is unusable" shape as `Ambiguous`, `kb` becomes
    /// `Knowledge::default()` the same way — but the entry is not a language
    /// question: `validate_place_scopes` refuses an `only_under` on a name
    /// the shipped knowledge already describes, a scoped name split across
    /// more than one of the operator's own entries, or an empty `only_under`
    /// list. Given its own kind rather than folded into `Ambiguous` (final
    /// whole-branch review of the place-scoped-rules changeset, finding 2):
    /// `Ambiguous`'s banner closes with "say which language the retraction
    /// is actually about", which fixes none of these three — none is about
    /// language, and `languages = [...]` changes nothing about a name the
    /// shipped set already owns, a name repeated across entries, or an
    /// empty list. Only ever attached to `GapSource::MyKnowledge`.
    PlaceScope,
    /// The raw text of an unparsable SHIPPED file names a schema version
    /// newer than this binary understands (spec 2026-08-05 §Schema, version
    /// skew point 1: "older vouch + new SHIPPED file"). Only ever
    /// `GapSource::Knowledge` — `read_one`'s stale-version check for a file
    /// that PARSES fine but names too-low a version already covers the other
    /// direction and stays `Unusable`; this kind is for a NEWER file this
    /// binary cannot even parse, where the generic parse-error wording ("fix
    /// the file... do NOT copy the repository's knowledge.toml over it")
    /// would send the operator to edit a file that is not broken — their
    /// vouch binary is just old.
    NewerThanBinary,
    /// Parsed and validated fine ON ITS OWN, and validated fine again against
    /// the shipped set by every OTHER cross-file check in this module — but a
    /// check that can only be answered by the MERGED entry
    /// (`validate_standalone_in_effect`: a `standalone_flags` member the
    /// merge left orphaned or in collision with another vocabulary, or a
    /// merged entry with `standalone_flags` but no stated
    /// `case_sensitive_flags`) failed. Unlike `Ambiguous`/`PlaceScope`, the
    /// shipped base is NOT thrown away here — the thing that failed is the
    /// MERGED entry, and the shipped knowledge alone is still exactly what
    /// it always was, so `load_files` sets the whole my-knowledge overlay
    /// aside and keeps `kb = base` (spec 2026-08-20 §4). Distinct from
    /// `SetAside`, whose banner says the SHIPPED knowledge itself failed to
    /// load — false here: the shipped file loaded and validated fine on its
    /// own, and only the COMBINATION with an operator entry produced a shape
    /// neither file alone was wrong about. Only ever attached to
    /// `GapSource::MyKnowledge`.
    MergedShape,
}

/// A file vouch looked for and could not use. Not an error — something the
/// operator has to be told, on every prompt, until they fix it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gap {
    pub path: String,
    pub why: String,
    pub source: GapSource,
    pub kind: GapKind,
}

/// A path as text for an operator to read or paste. Forward slashes only, on
/// every platform.
///
/// [review] `config_dir` builds a `/`-joined string, but `PathBuf::join`
/// appends the PLATFORM separator — so `config_dir(home).join("knowledge.toml")`
/// printed as `.../vouch\knowledge.toml` on Windows: forward slashes
/// throughout, then one backslash. Not cosmetic — pasted unquoted into bash,
/// the backslash silently eats the next character
/// (`C:/x/vouch\knowledge.toml` becomes `vouchknowledge.toml`). Every path
/// this module turns into text for a human goes through here instead of
/// `.display()` directly, so the fix lives in one place rather than at each
/// print site.
pub fn display_path(p: &Path) -> String {
    p.display().to_string().replace('\\', "/")
}

#[derive(Debug, Default, Clone)]
pub struct Loaded {
    pub kb: Knowledge,
    pub gaps: Vec<Gap>,
    /// One sentence per operator `subcommands` spelling the merge silently
    /// discarded (`narrowing_noops`) — never a gap: nothing failed to load
    /// and nothing goes unrecognised, the operator's file is simply not
    /// doing what one particular line of it might look like it does.
    /// Exposed by `guards::notes()`; printed by `doctor` (Task 8), not by
    /// the per-command prompt path.
    pub notes: Vec<String>,
}

fn from_env_or(var: &str, fallback: PathBuf) -> PathBuf {
    std::env::var(var).map(PathBuf::from).unwrap_or(fallback)
}

/// Everything vouch reads lives here, rather than loose among every other
/// tool's config. `knowledge.toml` is far too generic a name to leave in a
/// shared directory.
pub fn config_dir(home: &str) -> PathBuf {
    PathBuf::from(format!("{}/.config/vouch", home.trim_end_matches('/')))
}

pub fn knowledge_path(home: &str) -> PathBuf {
    from_env_or(KNOWLEDGE_ENV, config_dir(home).join("knowledge.toml"))
}

pub fn my_knowledge_path(home: &str) -> PathBuf {
    from_env_or(MY_KNOWLEDGE_ENV, config_dir(home).join("my-knowledge.toml"))
}

/// Where a file used to live, checked only so the banner can say "it is over
/// there, move it". Never read as a fallback.
pub fn former_path(home: &str, which: &str) -> PathBuf {
    PathBuf::from(format!("{}/.config/{which}", home.trim_end_matches('/')))
}

/// The closed set `sub_write.takes` may hold. Anything else used to silently
/// mean "last" — a typo (`"run-dir"` for `"run_dir"`) would then change
/// behaviour on old AND new binaries with nothing to say so.
const VALID_TAKES: &[&str] = &["", "first", "last", "run_dir", "url_basename"];

/// The closed set `Program::changes_dir` may hold, unset excepted. See the
/// field's doc comment in `guards::Program` for what each value means.
const VALID_CHANGES_DIR: &[&str] = &["no", "stated", "stack", "unstated"];

/// The closed set `Program::named_positional` may hold, unset excepted
/// (unset reads as `"last"`). See the field's doc comment in
/// `guards::Program` for what each value means (M2.128).
const VALID_NAMED_POSITIONAL: &[&str] = &["first", "last"];

/// The closed set `Program::languages` entries may hold. Mirrors the two
/// scanners vouch has (`src/shell.rs`, `src/powershell.rs`) — a value outside
/// this set names a language vouch cannot scan for.
const VALID_LANGUAGES: &[&str] = &["bash", "powershell"];

/// The closed set a `[[tool.snippet]]`'s `language` (or the right-hand side
/// of `language_values`) may hold. Deliberately WIDER than `VALID_LANGUAGES`:
/// `python` and `javascript` are real, useful claims — "this field is a
/// python script" — even though vouch has no scanner for either yet (M1.4).
/// A name outside this set is a typo, not a future scanner, and must fail the
/// load the same way a misspelt `changes_dir` does — never reach the engine's
/// no-scanner abstain arm with an unrecognised name in hand.
pub const SNIPPET_LANGUAGES: &[&str] = &["bash", "powershell", "python", "javascript"];

/// The closed set `Program::wrap_lang` may hold: every `SNIPPET_LANGUAGES`
/// name, plus `"opaque"` (a language vouch has no parser for, period) and
/// `"cmd"` (cmd.exe batch — not bash, so it gets its own name rather than
/// borrowing bash's, spec 2026-08-14 §5.2.4). A name outside this set is a
/// typo and must fail the load, the same reasoning `SNIPPET_LANGUAGES`
/// itself is built on: never let an unrecognised name reach the engine's
/// no-scanner arm in hand, silently read as "no claim at all".
const VALID_WRAP_LANG: &[&str] = &["bash", "powershell", "python", "javascript", "opaque", "cmd"];

/// `Program::wrap_lang`'s two load-time claims: the three TEXT-SCANNING wrap
/// arms (`after_c`, `after_flag`, `arg_<N>` — as opposed to `rest`,
/// `after_exec`, and `start_process`, which build a command from pieces and
/// read no snippet of their own) must say what language that text is in —
/// leaving it unset used to fall back to silently scanning it as bash
/// (M2.125), and a knowledge file is refused now rather than making that
/// claim by omission — and whenever `wrap_lang` is declared at all (on one
/// of those arms, or on an `evaluates_input = "stdin"` entry describing what
/// its own consumed here-document is written in), it has to be a language
/// the engine actually knows the NAME of, scannable or not.
///
/// Extracted from `validate` so `guards::load` — which otherwise skips
/// `validate` entirely, on purpose, for test fixtures that construct shapes
/// the real file-loading path refuses (`[[tool]] snippet = []`, an
/// operator's partial overlay entry) — can still run THIS ONE check on every
/// parse. It is the specific gap the M2.125 pair table names as refused
/// "via `guards::load`" itself, not only through the multi-file
/// `load_files` pipeline; the narrow scope is deliberate; ANY other
/// `validate` rule stays load_files-only, unchanged.
fn validate_wrap_lang_for(prog: &Program) -> Result<(), String> {
    let text_scanning =
        matches!(prog.wraps.as_str(), "after_c" | "after_flag") || prog.wraps.starts_with("arg_");
    if text_scanning && prog.wrap_lang.is_empty() {
        return Err(format!(
            "[[program]] {:?}: wraps = {:?} scans text and must declare wrap_lang \
             (one of {VALID_WRAP_LANG:?}) — an unset wrap_lang used to fall back to \
             scanning the snippet as bash, which is exactly the silent laundering \
             this check exists to refuse",
            prog.match_names, prog.wraps
        ));
    }
    // `VALID_WRAP_LANG` is deliberately wider than `SNIPPET_LANGUAGES`
    // (`"opaque"`, `"cmd"`) for the same reason `SNIPPET_LANGUAGES` is wider
    // than the scanner registry: an unscannable language is still a real,
    // checkable claim, and a name outside even that closed set is a typo,
    // not a future scanner.
    if !prog.wrap_lang.is_empty() && !VALID_WRAP_LANG.contains(&prog.wrap_lang.as_str()) {
        return Err(format!(
            "[[program]] {:?}: wrap_lang = {:?}, which must be one of {VALID_WRAP_LANG:?}",
            prog.match_names, prog.wrap_lang
        ));
    }
    Ok(())
}

/// The narrow slice of `validate` that `guards::load` runs on every parse —
/// see `validate_wrap_lang_for`'s doc comment for why this exists as its own
/// entry point rather than the whole of `validate`.
pub(crate) fn validate_wrap_lang(kb: &Knowledge) -> Result<(), String> {
    for prog in &kb.program {
        validate_wrap_lang_for(prog)?;
    }
    Ok(())
}

/// A program's language scope, EXPANDED: empty `languages` means "every
/// language vouch can scan", which is what the field's absence has always
/// meant (spec 2026-07-31 §2). Expanding it here, once, turns "unscoped" and
/// "explicitly lists every known language" into the SAME value, so the merge
/// never has to special-case emptiness again — the overlap and remainder
/// checks in `overlay_all`, and the scope comparison in `validate_retraction`,
/// all work on plain set operations instead.
fn scope_of(languages: &[String]) -> HashSet<String> {
    if languages.is_empty() {
        VALID_LANGUAGES.iter().map(|s| s.to_string()).collect()
    } else {
        languages.iter().cloned().collect()
    }
}

/// The schema version this binary understands. Bumped whenever a key is
/// added that changes what the shipped file can say — `changes_dir`,
/// `languages` and `dest_dir_flags` took this to 2; `[[tool]]`'s `snippet`,
/// `write_path_field`, `cwd_from_call` and `server` (spec 2026-08-05
/// §Schema) take it to 3; `writes_only_with_file_mode`, `arg_names`,
/// `wrap_join`, and the `arg_<N>` value `writes`/`wraps` can now carry (spec
/// 2026-08-07 python-snippets) take it to 4. Two keys take it to 5, both from
/// spec 2026-08-09 python-read-only-builtins: `callback_args` (Task 2's fix
/// round — added to the struct without this constant moving, in breach of
/// the rule this comment states; caught and closed here rather than left
/// stale) and `writes_via_handle` (Task 5). `named_positional` (M2.128, this
/// task) takes it to 6: which positional a `writes = "named"` fallback picks
/// when no `write_flags` member matched. Enforced in `read_one`, against
/// the SHIPPED file only: `version` absent or below this number refuses the
/// whole load rather than running blind on fields an old file never wrote
/// (spec §7) — a binary older than this constant reading a file that sets
/// either key would run one of two ways depending which key: an unknown
/// `callback_args`/`writes_via_handle`/`named_positional` line is rejected
/// outright by `deny_unknown_fields`, so in practice the whole file already
/// refuses and prints the "vouch recognises NOTHING right now" banner,
/// naming the file — loud, not silent. The version gate exists to make that
/// refusal PRECISE (naming the stale schema number, not a generic parse
/// error) rather than to be the only thing standing between an old binary
/// and silent breakage. `standalone_flags` (spec 2026-08-20 §2/§3) takes it
/// to 8: a new `[[program]]` key, plus `subcommands` moving from an empty
/// list to an ABSENT key for "whole program" — a v7 file's empty
/// `subcommands = []` now means "no verb at all" rather than "every verb",
/// so the version gate is what turns that silent reinterpretation into a
/// loud refusal instead.
pub const KNOWLEDGE_SCHEMA_VERSION: u32 = 8;

/// Semantic checks `deny_unknown_fields` cannot express: a `takes` value
/// outside the closed set, a `run_dir_flags` entry that is not also in
/// `value_options` (it would then be mistaken for the subcommand — see
/// `Program::run_dir_flags`), a `changes_dir` or `languages` value outside its
/// closed set, and `dest_dir_flags` on a `changes_dir` kind that never derives
/// a destination. Each is a per-entry claim a single typo can get wrong, and
/// each fails the file the same way a misspelt table name does — the whole
/// file is unusable, not just the one entry — because a knowledge
/// file that is silently wrong about one entry is exactly the risk this
/// project exists to remove (§1: absence of knowledge is never permissive,
/// and neither is a claim nobody checked).
pub(crate) fn validate(kb: &Knowledge) -> Result<(), String> {
    for prog in &kb.program {
        for sw in &prog.sub_write {
            if !VALID_TAKES.contains(&sw.takes.as_str()) {
                return Err(format!(
                    "[[program]] {:?}: sub_write for subcommand {:?} has takes = {:?}, which must be one of \"\", \"first\", \"last\", \"run_dir\", \"url_basename\"",
                    prog.match_names, sw.subcommand, sw.takes
                ));
            }
        }
        // An entry with `run_dir_flags` set and its OWN `value_options`
        // empty is not broken — it is the documented Task 5 pattern of
        // laying one field over a shipped entry while leaving everything
        // else shipped: `overlay()` treats an empty `value_options` as
        // "keep the shipped list", never as "no value options at all". That
        // entry's real `value_options` only exists after the merge, so
        // checking the subset now, against nothing, would reject an
        // operator file for a shape that becomes valid the moment it is
        // laid over the shipped one. Only an entry that states its OWN
        // `value_options` is checked here.
        if !prog.value_options.is_empty() {
            for f in &prog.run_dir_flags {
                if !prog.value_options.iter().any(|v| v == f) {
                    return Err(format!(
                        "[[program]] {:?}: run_dir_flags contains {:?}, which is not also in value_options {:?}",
                        prog.match_names, f, prog.value_options
                    ));
                }
            }
            // Same subset rule, same reason: a flag that names the program
            // being started has to be known to CONSUME its value, or the
            // operand walk reads that program name as a positional and the
            // two answers disagree about the same token.
            for f in &prog.wrap_head_flags {
                if !prog.value_options.iter().any(|v| v == f) {
                    return Err(format!(
                        "[[program]] {:?}: wrap_head_flags contains {:?}, which is not also in value_options {:?}",
                        prog.match_names, f, prog.value_options
                    ));
                }
            }
        }
        // `standalone_flags` recognises a run whose every argument is one of
        // these — an inert-shape refusal (an empty `subcommands` pairing
        // with nothing that could ever fire), a per-member shape check
        // (`member_shape_ok`, shared with the prompt-side listability test
        // and vouch trust's pre-checks so the three sites cannot drift), the
        // python: refusal (standalone_flags describes command-line flags,
        // and a python callable has none), and the own-vocabulary collision
        // check (`standalone_vocab_collisions`, shared with Task 4's
        // post-merge stage). Runs whether or not the entry states its own
        // `value_options` — unlike the two subset checks above, which only
        // make sense once `value_options` is known.
        let standalone_declared = !prog.standalone_flags.is_empty();
        if prog.subcommands.as_ref().is_some_and(|s| s.is_empty()) && !standalone_declared {
            return Err(format!(
                "[[program]] {:?}: subcommands = [] covers no verb, and without \
                 standalone_flags the entry can never recognise anything — an \
                 installed-looking entry that covers nothing is refused, the same \
                 rule as a veto with no positive condition",
                prog.match_names
            ));
        }
        if standalone_declared {
            if prog.match_names.iter().any(|m| m.starts_with("python:")) {
                return Err(format!(
                    "[[program]] {:?}: standalone_flags describes command-line flags, \
                     and a python callable has no flag tokens",
                    prog.match_names
                ));
            }
            let prefixes = crate::flags::effective_prefixes(&prog.flag_prefix);
            for f in &prog.standalone_flags {
                if let Err(why) = member_shape_ok(&prefixes, f) {
                    return Err(format!(
                        "[[program]] {:?}: standalone_flags: {why}",
                        prog.match_names
                    ));
                }
            }
            standalone_vocab_collisions(prog)?;
        }
        if let Some(cd) = &prog.changes_dir {
            if !VALID_CHANGES_DIR.contains(&cd.as_str()) {
                return Err(format!(
                    "[[program]] {:?}: changes_dir = {:?}, which must be one of \"no\", \"stated\", \"stack\", \"unstated\"",
                    prog.match_names, cd
                ));
            }
        }
        if let Some(np) = &prog.named_positional {
            if !VALID_NAMED_POSITIONAL.contains(&np.as_str()) {
                return Err(format!(
                    "[[program]] {:?}: named_positional = {:?}, which must be one of \"first\", \"last\"",
                    prog.match_names, np
                ));
            }
        }
        for lang in &prog.languages {
            if !VALID_LANGUAGES.contains(&lang.as_str()) {
                return Err(format!(
                    "[[program]] {:?}: languages contains {:?}, which must be one of \"bash\", \"powershell\"",
                    prog.match_names, lang
                ));
            }
        }
        // A dest-dir flag is a flag whose value IS the destination. That only
        // makes sense for a kind that derives a destination at all: "no" and
        // "unstated" never do, so a dest-dir flag on either is an incoherent
        // claim, not a harmless extra.
        if !prog.dest_dir_flags.is_empty() {
            let ok = matches!(prog.changes_dir.as_deref(), Some("stated") | Some("stack"));
            if !ok {
                return Err(format!(
                    "[[program]] {:?}: dest_dir_flags {:?} requires changes_dir = \"stated\" or \"stack\", got {:?}",
                    prog.match_names, prog.dest_dir_flags, prog.changes_dir
                ));
            }
        }
        // `writes = "arg_<N>"` and `wraps = "arg_<N>"` each name a position
        // by number — an `N` that does not parse is a claim vouch can never
        // look up, the same class of typo `takes` and `changes_dir` refuse.
        if let Some(n) = prog.writes.strip_prefix("arg_") {
            if n.parse::<usize>().is_err() {
                return Err(format!(
                    "[[program]] {:?}: writes = {:?}, whose \"arg_\" suffix must be a number",
                    prog.match_names, prog.writes
                ));
            }
        }
        if let Some(n) = prog.wraps.strip_prefix("arg_") {
            if n.parse::<usize>().is_err() {
                return Err(format!(
                    "[[program]] {:?}: wraps = {:?}, whose \"arg_\" suffix must be a number",
                    prog.match_names, prog.wraps
                ));
            }
        }
        // A `[[program.here_write]]` with no condition at all claims the
        // program ALWAYS writes where it stands, which is true of none of
        // the programs this key exists for and could not be checked if it
        // were: every one of them has a shape that writes nothing (`tar
        // -tf`, `unzip -l`) or writes elsewhere (`-C`, `-d`, `-o`). An
        // unconditional entry would quietly claim the run place for those
        // too, so it is refused rather than trusted.
        for hw in &prog.here_write {
            if hw.when_flags.is_empty()
                && hw.unless_flags.is_empty()
                && hw.subcommand.is_none()
                && hw.operands.is_none()
            {
                return Err(format!(
                    "[[program.here_write]] on {:?}: an entry with no when_flags, unless_flags,                      subcommand or operands claims this program writes where it stands in EVERY                      invocation — name the shape it is true of",
                    prog.match_names
                ));
            }
        }
        // A rule that states no POSITIVE condition never fires. `rule_matches`
        // refuses one at match time — an empty list matches nothing, never
        // everything — so it loads clean, sits in the file, and protects
        // nothing: inert protection wearing the look of installed protection,
        // the shape the `here_write` check above refuses for the same reason.
        //
        // The veto is the spelling that makes this easy to write by accident
        // ("fire on everything except this", without `always`), but the check
        // is on the general case rather than on that field — a rule carrying
        // only a guard and a source is just as inert and was just as silent.
        for rule in &prog.rule {
            if !rule.always
                && rule.subcommand_in.is_empty()
                && rule.sub_arg_0_in.is_empty()
                && rule.any_flag.is_empty()
                && rule.any_arg_exact.is_empty()
                && rule.any_arg_prefix.is_empty()
                && !rule.grants_execute
            {
                return Err(format!(
                    "[[program.rule]] for guard {:?} on {:?}: this rule states no condition that \
                     can ever match, so it would load and never fire. Name one of \
                     `subcommand_in`, `sub_arg_0_in`, `any_flag`, `any_arg_exact`, \
                     `any_arg_prefix` or `grants_execute` — or `always = true` if the rule really \
                     is about every invocation ({})",
                    rule.guard,
                    prog.match_names.join(", "),
                    if rule.unless_flags.is_empty() {
                        "an empty list matches nothing, never everything"
                    } else {
                        "`unless_flags` is a veto, not a condition: it can only ever stop a rule \
                         firing, so a rule naming it and nothing else can never fire at all"
                    }
                ));
            }
        }
        // `runs_file` is the same position spelling and gets the same check,
        // plus the one it does not share: `"arg_<N>"` is its ONLY shape. The
        // other position keys have named alternatives (`writes = "named"`,
        // `wraps = "rest"`), so a stray word there lands on a real arm; here
        // any other word would simply never match anything, and an entry that
        // reads to its author as a claim while matching nothing is the failure
        // this file's validation exists to prevent.
        if !prog.runs_file.is_empty() {
            let ok = prog
                .runs_file
                .strip_prefix("arg_")
                .is_some_and(|n| n.parse::<usize>().is_ok());
            if !ok {
                return Err(format!(
                    "[[program]] {:?}: runs_file = {:?}, which must be \"arg_<N>\"",
                    prog.match_names, prog.runs_file
                ));
            }
        }
        // A flag naming code to run has to be a flag this entry describes, or
        // the walk that looks for it never classifies the token as that flag
        // and the claim is inert — the same subset rule `run_dir_flags` and
        // `wrap_head_flags` already carry.
        // Same subset rule as `runs_file_flags`, over BOTH flag lists: a
        // rebinding flag may or may not take a value (`hash -p <path>` does),
        // so what it has to be is described AT ALL — an undescribed one would
        // never classify as this entry's flag and the claim would be inert.
        for f in &prog.rebinds_name_flags {
            let known = prog.value_options.iter().chain(prog.no_value_options.iter());
            if !known.into_iter().any(|v| v == f) {
                return Err(format!(
                    "[[program]] {:?}: rebinds_name_flags names {f:?}, which this entry does not                      describe in value_options or no_value_options",
                    prog.match_names
                ));
            }
        }
        for f in &prog.runs_file_flags {
            if !prog.value_options.iter().any(|v| v == f) {
                return Err(format!(
                    "[[program]] {:?}: runs_file_flags names {f:?}, which is not in value_options — \
                     a flag whose value is code must first be a flag that takes a value",
                    prog.match_names
                ));
            }
        }
        // The three `wraps`-shaped keys each belong to ONE wrap kind, and a
        // key on the wrong kind is silently inert — which is the shape a
        // knowledge file must never be allowed to have, because it reads to
        // its author as a claim that is being honoured. Checked only on an
        // entry that states its own `wraps`: an overlay laying `leading_args`
        // over a shipped `rest` entry legitimately says nothing about the
        // kind, the same reason the `run_dir_flags` subset check above skips
        // an entry with no `value_options` of its own.
        if !prog.wraps.is_empty() {
            if prog.leading_args.is_some() && prog.wraps != "rest" {
                return Err(format!(
                    "[[program]] {:?}: leading_args needs wraps = \"rest\" (the leading data \
                     positionals a rest wrapper crosses before the wrapped head), got wraps = {:?}",
                    prog.match_names, prog.wraps
                ));
            }
            if !prog.wrap_head_flags.is_empty() && prog.wraps != "start_process" {
                return Err(format!(
                    "[[program]] {:?}: wrap_head_flags needs wraps = \"start_process\" (the flags whose value names the program being started), got wraps = {:?}",
                    prog.match_names, prog.wraps
                ));
            }
            let exec_keys = !prog.wrap_exec_flags.is_empty() || !prog.wrap_exec_terminators.is_empty();
            if exec_keys && prog.wraps != "after_exec" {
                return Err(format!(
                    "[[program]] {:?}: wrap_exec_flags/wrap_exec_terminators need wraps = \
                     \"after_exec\", got wraps = {:?}",
                    prog.match_names, prog.wraps
                ));
            }
            // An `after_exec` entry that names no exec flag and no terminator
            // describes a wrapper the walk can never locate: it would find
            // nothing every time and report "wrapped nothing", which is the
            // silent miss this whole arm exists to stop.
            if prog.wraps == "after_exec"
                && (prog.wrap_exec_flags.is_empty() || prog.wrap_exec_terminators.is_empty())
            {
                return Err(format!(
                    "[[program]] {:?}: wraps = \"after_exec\" needs both wrap_exec_flags and \
                     wrap_exec_terminators — without them the walk can never locate the \
                     wrapped command and would report it as wrapping nothing",
                    prog.match_names
                ));
            }
            // Same reasoning for the flag-carried arm, which had no such
            // check: `wraps = "after_flag"` with no `wrap_flags` locates
            // nothing, every time.
            if prog.wraps == "after_flag" && prog.wrap_flags.is_empty() {
                return Err(format!(
                    "[[program]] {:?}: wraps = \"after_flag\" needs wrap_flags — without them \
                     the walk can never locate the wrapped snippet",
                    prog.match_names
                ));
            }
        }
        validate_wrap_lang_for(prog)?;
        // `writes_only_with_file_mode = true` needs a "mode" position to
        // test — this entry's own `arg_names` must name one. One-directional
        // on purpose: an entry may name "mode" in `arg_names` with no
        // `writes_only_with_file_mode` at all (a chmod-shaped entry whose
        // mode is an integer, never a write predicate) — checked ONLY in the
        // direction that would otherwise let the gate point at a position
        // nothing names.
        if prog.writes_only_with_file_mode == Some(true) && !prog.arg_names.iter().any(|n| n == "mode") {
            return Err(format!(
                "[[program]] {:?}: writes_only_with_file_mode = true requires arg_names to contain \"mode\", got {:?}",
                prog.match_names, prog.arg_names
            ));
        }
        // `writes_via_handle` (Task 5, M2.86): the call writes only through an
        // already-opened file object, so it names no path of its own — one
        // write story per entry, never both a target the engine should
        // extract (`writes`, `writes_only_with_file_mode`, or `sub_write` —
        // fix round 1 added `sub_write` to this check: a subcommand-keyed
        // write target is a third way to claim one, and was missed the
        // first time this exclusivity was written) and a target it should
        // not.
        if let Some(h) = &prog.writes_via_handle {
            if !prog.writes.is_empty() || prog.writes_only_with_file_mode.is_some() || !prog.sub_write.is_empty() {
                return Err(format!(
                    "[[program]] {:?}: writes_via_handle cannot appear alongside writes, writes_only_with_file_mode, or sub_write — one write story per entry",
                    prog.match_names
                ));
            }
            let ok = match h.strip_prefix("arg_") {
                Some(n) => n.parse::<usize>().is_ok(),
                None => !h.is_empty() && h.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
            };
            if !ok {
                return Err(format!(
                    "[[program]] {:?}: writes_via_handle = {:?}, which must be \"arg_<N>\" or a keyword parameter name",
                    prog.match_names, h
                ));
            }
        }
        // `callback_args` grammar only (task 2b, M2.86): each entry must be a
        // non-empty identifier. Membership in `arg_names` is NOT required —
        // a keyword-only parameter (most of json.load's callback slots) is
        // legitimately absent from it. A typo here would otherwise be a
        // dead declaration; the enumeration test that proves every declared
        // slot actually trips is what catches that instead.
        for name in &prog.callback_args {
            let is_ident = !name.is_empty()
                && name
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
            if !is_ident {
                return Err(format!(
                    "[[program]] {:?}: callback_args entry {name:?} is not a valid identifier",
                    prog.match_names
                ));
            }
        }
        // A match name the lookup can never reach is not a smaller claim, it
        // is dead data: `guards::base_name` folds a head to lowercase, drops
        // any path, and trims a trailing `.exe` before any entry is even
        // considered, so a name that survives neither step describes
        // something a real command line could never spell (M2.121). Checked
        // on the LOWERCASED name, not the raw one: the lookup folds both
        // sides, so a capitalised python callable (`python:PIL.Image.open`)
        // is reachable and must not be refused for carrying capitals it is
        // allowed to carry (round-1 correction, spec §4.4).
        for n in &prog.match_names {
            let m = n.to_lowercase();
            if m != crate::guards::base_name(&m) {
                return Err(format!(
                    "[[program]] {:?}: match name {n:?} can never be looked up — the lookup \
                     folds a head to {:?} before any entry is even checked, so this name is \
                     dead data, not a reachable claim",
                    prog.match_names,
                    crate::guards::base_name(&m)
                ));
            }
        }
    }
    for tool in &kb.tool {
        validate_tool(tool)?;
    }
    // `[[env_name]]`: a name and a closed-set effect. An unrecognised effect
    // would read to its author as a claim and match no branch that acts on
    // one, which is the inert-claim shape this file's validation exists to
    // refuse.
    for e in &kb.env_name {
        if e.name.is_empty() {
            return Err("[[env_name]]: an entry with no `name` describes nothing".to_string());
        }
        if !matches!(e.effect.as_str(), "lookup" | "startup") {
            return Err(format!(
                "[[env_name]] {:?}: effect = {:?}, which must be \"lookup\" or \"startup\"",
                e.name, e.effect
            ));
        }
    }
    Ok(())
}

/// The member-shape rules for one `standalone_flags` entry, shared by the
/// per-file validator (Task 3), the prompt-side listability test (Task 7),
/// and `vouch trust`'s pre-checks (Task 8) — one definition so the three
/// sites cannot drift. Ok means: flag-shaped under one of `prefixes`, not
/// the option terminator, and every post-prefix character inside the
/// allowlist (letters, digits, '.', '_', '-') — the rule that closes
/// pattern, brace, '=', and expansion rewrites in one shape.
///
/// Its sibling `in_refused_vocab`, defined beside it, is the OTHER shared
/// per-token question — "does some vocabulary of this entry claim this
/// flag does work" — also defined once, for the same reason: three sites
/// consume it (the collision check, the stdin-arm hint, the prompt-side
/// listability test), and a vocabulary key added to the schema tomorrow
/// must be remembered in ONE place, not three:
///
/// ```text
/// pub fn in_refused_vocab(prog: &Program, token: &str) -> Option<&'static str>
/// ```
///
/// returning the name of the vocabulary that claims the token
/// (`value_options`, `wrap_flags`, `write_flags`, `run_dir_flags`,
/// `dest_dir_flags`, `runs_file_flags`, `rebinds_name_flags`,
/// `wrap_head_flags`, `wrap_exec_flags`, or a `here_write`'s
/// `when_flags`), or None. Unit tests beside member_shape_ok's.
pub fn member_shape_ok(prefixes: &[&str], f: &str) -> Result<(), String> {
    if f == "--" {
        return Err(format!(
            "{f:?} ends option parsing rather than doing anything alone — \
             several interpreters read a lone \"--\" as \"read standard input\""
        ));
    }
    let Some(rest) = prefixes.iter().find_map(|p| f.strip_prefix(p)) else {
        return Err(format!(
            "{f:?} is not flag-shaped under the flag prefixes {prefixes:?} — \
             a member that can never fire reads as installed trust"
        ));
    };
    let body = rest.trim_start_matches('-');
    // Two refusals, not one: a body with nothing in it has no characters to
    // be outside any set, and saying it does sends the reader hunting for a
    // bad character that is not there.
    if body.is_empty() {
        return Err(format!(
            "{f:?} is dashes and nothing else — it names no flag, and a member \
             that can never fire reads as installed trust"
        ));
    }
    if !body.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c)) {
        return Err(format!(
            "{f:?} has characters outside the allowed set (the flag prefix, \
             then letters, digits, '.', '_', '-') — a shell can rewrite \
             pattern, brace, '=', or expansion spellings before the program \
             sees them, so vouch would judge a token the program never receives"
        ));
    }
    Ok(())
}

/// Does some vocabulary of THIS entry claim `token` does work — the second
/// shared per-token question beside `member_shape_ok`'s, and for the same
/// reason defined once: three sites consume it (the post-merge collision
/// check, the stdin-arm hint, the prompt-side listability test), so a
/// vocabulary key added to the schema tomorrow is remembered in ONE place,
/// not three.
///
/// Checked in this order, returning the first hit's name: `value_options`,
/// `wrap_flags`, `write_flags`, `run_dir_flags`, `dest_dir_flags`,
/// `runs_file_flags`, `rebinds_name_flags`, `wrap_head_flags`,
/// `wrap_exec_flags` — each matched by whole-token equality — then every
/// `here_write` entry's `when_flags`, reported as `"here_write.when_flags"`.
/// None means no vocabulary on this entry claims the token.
pub fn in_refused_vocab(prog: &Program, token: &str) -> Option<&'static str> {
    let vocabs: [(&'static str, &Vec<String>); 9] = [
        ("value_options", &prog.value_options),
        ("wrap_flags", &prog.wrap_flags),
        ("write_flags", &prog.write_flags),
        ("run_dir_flags", &prog.run_dir_flags),
        ("dest_dir_flags", &prog.dest_dir_flags),
        ("runs_file_flags", &prog.runs_file_flags),
        ("rebinds_name_flags", &prog.rebinds_name_flags),
        ("wrap_head_flags", &prog.wrap_head_flags),
        ("wrap_exec_flags", &prog.wrap_exec_flags),
    ];
    for (name, list) in vocabs {
        if list.iter().any(|v| v == token) {
            return Some(name);
        }
    }
    if prog
        .here_write
        .iter()
        .any(|hw| hw.when_flags.iter().any(|v| v == token))
    {
        return Some("here_write.when_flags");
    }
    None
}

/// Whether any of THIS entry's own `standalone_flags` also appears in one of
/// its own work-doing vocabularies (`in_refused_vocab`'s enumeration) — a
/// flag that takes a value or does work cannot also be vouched for as doing
/// nothing alone. Extracted so the per-file validator (Task 3) and the
/// post-merge stage (Task 4, which must run the same check on a MERGED
/// entry, since either side of an overlay can supply the colliding member)
/// call the identical rule rather than two copies that could drift.
pub fn standalone_vocab_collisions(prog: &Program) -> Result<(), String> {
    for f in &prog.standalone_flags {
        if let Some(vocab) = in_refused_vocab(prog, f) {
            return Err(format!(
                "[[program]] {:?}: {:?} is in standalone_flags AND in {vocab} \
                 — a flag that takes a value or does work cannot also be \
                 vouched for as doing nothing alone",
                prog.match_names, f
            ));
        }
    }
    Ok(())
}

/// The standalone_flags checks that need the entry IN EFFECT — an operator
/// overlay replaces vocabularies whole, so only the merged entry can answer
/// whether a member is orphaned or collides (spec 2026-08-20 §4). Failure
/// sets the whole my-knowledge overlay aside and leaves shipped knowledge
/// alone in effect: the offending entry and key are named, so discarding
/// everything (the pre-merge cross-file refusals' semantics) would punish
/// entries that answered nothing wrong.
fn validate_standalone_in_effect(kb: &Knowledge) -> Result<(), String> {
    for prog in &kb.program {
        if prog.standalone_flags.is_empty() {
            continue;
        }
        if prog.case_sensitive_flags.is_none() {
            return Err(format!(
                "[[program]] {:?}: standalone_flags requires case_sensitive_flags \
                 to be stated — either value, out loud — because flag identity is \
                 load-bearing for this allow and the unset default is \
                 case-insensitive",
                prog.match_names
            ));
        }
        if !prog.runs_file.is_empty() || !prog.runs_file_flags.is_empty() {
            for f in &prog.standalone_flags {
                if !prog.no_value_options.iter().any(|v| v == f) {
                    return Err(format!(
                        "[[program]] {:?}: {:?} is in standalone_flags but not in \
                         this entry's no_value_options — on an entry that runs a \
                         file, an undescribed flag re-raises the very ask \
                         standalone_flags exists to remove",
                        prog.match_names, f
                    ));
                }
            }
        }
        standalone_vocab_collisions(prog)?; // Task 3's extraction, on the merged entry
    }
    Ok(())
}

/// Semantic checks on a `[[tool]]` entry that `deny_unknown_fields` cannot
/// express (spec 2026-08-05 §Schema) — the tool half of `validate` above,
/// same rule: each failure fails the WHOLE file, never just the one entry.
///
/// - `server` and a non-empty `match` in the same entry: a server grant names
///   no individual tool, so the two are mutually exclusive claims.
/// - Neither `server` nor `match`: an entry naming nothing this is about.
/// - `server = ""`: present but empty is not a name.
/// - `snippet = []`: a load error, not "no snippets" — see `Tool::snippet`'s
///   doc comment for why silence has to mean "unset", not this.
/// - Each declared snippet names exactly one of `language` / `language_from`,
///   and every language name — fixed or on the right of `language_values` —
///   is in the closed `SNIPPET_LANGUAGES` set.
fn validate_tool(t: &Tool) -> Result<(), String> {
    let ident = if !t.match_names.is_empty() {
        format!("{:?}", t.match_names)
    } else if let Some(s) = &t.server {
        format!("server = {s:?}")
    } else {
        "(no match, no server)".to_string()
    };

    match &t.server {
        Some(s) if s.is_empty() => {
            return Err(format!("[[tool]] {ident}: server = \"\" is not a thing an entry can say"));
        }
        Some(_) if !t.match_names.is_empty() => {
            return Err(format!(
                "[[tool]] {ident}: server and a non-empty match in the same entry is not a \
                 thing an entry can say — a server grant names no individual tool"
            ));
        }
        None if t.match_names.is_empty() => {
            return Err(format!(
                "[[tool]] {ident}: neither match nor server names anything this entry is about"
            ));
        }
        _ => {}
    }

    if let Some(snippet) = &t.snippet {
        if snippet.is_empty() {
            return Err(format!(
                "[[tool]] {ident}: snippet = [] is not a thing an entry can say — omit the \
                 key to keep what the shipped entry declares, or use `tools.<name>` in your \
                 config to decide this tool without inspection"
            ));
        }
        for p in snippet {
            validate_tool_snippet(&ident, p)?;
        }
    }

    Ok(())
}

/// One `[[tool.snippet]]` entry, checked in isolation — split out of
/// `validate_tool` so each of its two independent claims (which sibling
/// field names the language, and whether that name is in the closed set)
/// reads as one thing apiece.
fn validate_tool_snippet(ident: &str, p: &ToolSnippet) -> Result<(), String> {
    match (&p.language, &p.language_from) {
        (Some(_), Some(_)) => {
            return Err(format!(
                "[[tool]] {ident}: snippet field {:?} sets both language and language_from — \
                 exactly one",
                p.field
            ));
        }
        (None, None) => {
            return Err(format!(
                "[[tool]] {ident}: snippet field {:?} sets neither language nor language_from \
                 — exactly one",
                p.field
            ));
        }
        _ => {}
    }
    if let Some(lang) = &p.language {
        if !SNIPPET_LANGUAGES.contains(&lang.as_str()) {
            return Err(format!(
                "[[tool]] {ident}: snippet field {:?} has language = {:?}, which must be one \
                 of {SNIPPET_LANGUAGES:?}",
                p.field, lang
            ));
        }
    }
    if let Some(values) = &p.language_values {
        for (k, v) in values {
            if !SNIPPET_LANGUAGES.contains(&v.as_str()) {
                return Err(format!(
                    "[[tool]] {ident}: snippet field {:?} has language_values[{k:?}] = {v:?}, \
                     which must be one of {SNIPPET_LANGUAGES:?}",
                    p.field
                ));
            }
        }
    }
    Ok(())
}

/// Where to send an operator whose SHIPPED file just refused on its version:
/// the variable, when `$VOUCH_KNOWLEDGE` is what put that file at this path,
/// else the installer.
///
/// `knowledge_path` resolves the env-var override BEFORE `load_files` ever
/// sees a path, so by the time this gap is written there is no argument left
/// that still says which one happened — the path is just a path. Reading the
/// environment directly, here, at the moment the gap is written, is the one
/// place that still knows the true answer instead of one already flattened
/// by the caller.
fn version_remedy() -> String {
    match std::env::var(KNOWLEDGE_ENV) {
        Ok(v) => format!(
            "the {KNOWLEDGE_ENV} environment variable points at this file ({}); point it at a \
             current knowledge.toml, or unset it and vouch will read the one in ~/.config/vouch",
            v.replace('\\', "/")
        ),
        Err(_) => "reinstall vouch, or in a repository checkout run scripts/install-knowledge.sh, \
                    to replace it with one written against the current schema"
            .to_string(),
    }
}

/// Reads one file. `announce_absence` is false for `my-knowledge.toml`: not
/// having written your own descriptions is normal, and announcing it on every
/// prompt trains the operator to ignore the banner.
///
/// The version gate below applies ONLY when `source == GapSource::Knowledge`.
/// `my-knowledge.toml` parses into the same `Knowledge` struct and so has the
/// same `version` field, but it is never checked here: operator files predate
/// every schema change by design, and their silence on new keys already keeps
/// the shipped values under the field-level merge (spec §7). Refusing them on
/// version would break every existing my-knowledge.toml the moment the shipped
/// schema moves — not vouch's call to make (§4).
fn read_one(path: &Path, announce_absence: bool, source: GapSource, gaps: &mut Vec<Gap>) -> Option<Knowledge> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            // A file that IS there and cannot be opened is not an absence, and
            // is announced for either file: the operator believes something is
            // in effect that is not. Only a genuine absence is governed by
            // `announce_absence`.
            let present = path.exists();
            if announce_absence || present {
                let (why, kind) = if present {
                    (format!("could not be opened ({e})"), GapKind::Unusable)
                } else {
                    (format!("not found ({e})"), GapKind::Missing)
                };
                gaps.push(Gap { path: display_path(path), why, source, kind });
            }
            return None;
        }
    };
    // A file that parses but fails a semantic check (`takes`, `run_dir_flags`)
    // is reported through the exact same channel as one that fails to parse
    // at all — the operator does not need to learn two different kinds of
    // "broken".
    let kb = load(&text).and_then(|kb| validate(&kb).map(|()| kb));
    match kb {
        Ok(kb) => {
            if source == GapSource::Knowledge {
                // Stale in either of two shapes: no `version` key at all (the
                // file predates the key, same as every file before 2026-07-31),
                // or a `version` below what this binary understands. Both fail
                // the whole load exactly like a parse error does (§1) — a
                // binary that kept the old entry for `cd` while the walk that
                // reads it went blind is a state strictly worse than knowing
                // nothing, wearing a banner that says otherwise.
                let stale = match kb.version {
                    Some(v) if v >= KNOWLEDGE_SCHEMA_VERSION => None,
                    Some(v) => Some(format!(
                        "version = {v}, older than the schema this binary understands ({KNOWLEDGE_SCHEMA_VERSION})"
                    )),
                    None => Some(format!(
                        "has no `version` key, so it predates schema {KNOWLEDGE_SCHEMA_VERSION}"
                    )),
                };
                if let Some(cause) = stale {
                    gaps.push(Gap {
                        path: display_path(path),
                        why: format!("{cause}: {}", version_remedy()),
                        source,
                        kind: GapKind::Unusable,
                    });
                    return None;
                }
            }
            Some(kb)
        }
        // Always announced, for either file. A file that is present and broken
        // means the operator believes something is in effect that is not.
        Err(e) => {
            // A file this binary cannot even parse might not be BROKEN — it
            // might be written for a newer schema than this binary
            // understands (spec 2026-08-05 §Schema, version skew point 1).
            // Only checked for the SHIPPED file: `my-knowledge.toml` predates
            // every schema change by design (see this function's own doc
            // comment), so a parse failure there is never this.
            let kind = if source == GapSource::Knowledge && newer_than_binary(&text) {
                GapKind::NewerThanBinary
            } else {
                GapKind::Unusable
            };
            gaps.push(Gap { path: display_path(path), why: format!("could not be read: {e}"), source, kind });
            None
        }
    }
}

/// Does the raw text of a file that just failed to parse contain a `version
/// = N` line naming a schema newer than this binary understands?
///
/// A line-match, not a TOML parse — the file already failed one of those, and
/// this only ever decides which SENTENCE the banner prints (spec 2026-08-05
/// §Schema: "banner hint, not a decision"), never anything the engine acts
/// on. A false negative here still shows the ordinary "could not be read"
/// wording, which was already correct for a merely-broken file; it only
/// leaves the newer-binary sentence unsaid in the rare case a future file
/// puts `version` somewhere this line-match cannot find it.
fn newer_than_binary(text: &str) -> bool {
    for line in text.lines() {
        let Some(rest) = line.trim_start().strip_prefix("version") else { continue };
        let Some(rest) = rest.trim_start().strip_prefix('=') else { continue };
        let num = rest.split('#').next().unwrap_or(rest).trim();
        if let Ok(v) = num.parse::<u32>() {
            if v > KNOWLEDGE_SCHEMA_VERSION {
                return true;
            }
        }
    }
    false
}

/// What a rule matches on, as a comparable key.
///
/// [review] This was the sorted `subcommand_in` list alone, so every rule with
/// no subcommand shared the key "" and one operator rule deleted all of them.
/// Reproduced against the real file: adding an unrelated rule to `rm` removed
/// `delete_recursive`, and the same for chmod, sed, dd, curl and ssh. The key
/// has to be the whole match shape, so a rule replaces only a rule that fires
/// on the same thing.
fn rule_key(r: &Rule) -> String {
    fn sorted(v: &[String]) -> Vec<String> {
        let mut c: Vec<String> = v.to_vec();
        c.sort();
        c
    }
    // `unless_flags` belongs here for the same reason as every other
    // condition: it is part of WHAT the rule fires on. Two rules alike but
    // for their veto fire on different commands, so neither may replace the
    // other — leaving it out would make an operator's `kill` rule with no
    // veto silently displace the shipped one that has it, turning a liveness
    // check back into a prompt with nothing said.
    format!(
        "{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{}|{}",
        sorted(&r.subcommand_in),
        sorted(&r.sub_arg_0_in),
        sorted(&r.any_flag),
        sorted(&r.unless_flags),
        sorted(&r.any_arg_exact),
        sorted(&r.any_arg_prefix),
        r.grants_execute,
        r.always
    )
}

fn sub_write_key(s: &SubWrite) -> String {
    format!("{}\u{1}{}", s.subcommand, s.then)
}

// [review] `shared_names` used to live here and was called only by the program
// half of `merge`. It is gone: the shared-name computation belongs to
// `overlay_all`, which both halves go through, so there is no longer a helper
// that only one kind of entry uses.

/// One entry in the knowledge, of either kind.
///
/// `[[program]]` and `[[tool]]` entries are laid over by the identical
/// algorithm — split a shipped entry by the names the operator actually
/// named, overlay only that part — so it is written once, in `overlay_all`,
/// and each kind supplies only what differs: how its names are compared, and
/// what one entry laid over another means.
///
/// [review] This trait exists because the two halves DID drift. Tool entries
/// were appended rather than overlaid, and the two halves of one file then
/// answered identical silence oppositely. Sharing the algorithm is the only
/// way they cannot drift again.
pub trait Entry: Clone {
    fn names(&self) -> &[String];
    fn set_names(&mut self, names: Vec<String>);
    /// Whether a name the operator wrote is the same name a shipped entry
    /// lists. Each kind uses its OWN lookup rule, so an entry can never
    /// affect a name that the lookup would not then find.
    fn same_name(a: &str, b: &str) -> bool;
    /// A name in the canonical form `same_name` compares by — used ONLY as a
    /// `HashMap` key for coverage tracking, never stored or displayed.
    ///
    /// [review] CRITICAL, found by the skeptical review of this task
    /// (Finding 1). `overlay_all`'s `covered` map was keyed by whichever
    /// spelling happened to be at hand at each site — the SHIPPED entry's
    /// own spelling when recording coverage, the OPERATOR's own spelling
    /// when reading it back — and a plain `HashMap<String, _>` compares keys
    /// by exact bytes, not by `same_name`'s case-insensitive rule. An
    /// operator entry spelled `match = ["Git"]` over a shipped `match =
    /// ["git"]` therefore looked UNCOVERED even though it plainly overlapped,
    /// minted a fresh unscoped `["Git"]` entry with empty (hence
    /// everything-recognising) `subcommands`, and flipped
    /// `recognises("git push")` from false to true — a toward-allow defect
    /// from the exact same "keep is a lie unless the map key is the same
    /// thing the comparison uses" class M2.26 already was. Every `covered`
    /// read and write must go through this, never through a name taken
    /// straight from `names()`.
    fn canonical_name(name: &str) -> String;
    /// Lay `mine` over `self`. Unset means keep, everywhere.
    fn lay(&mut self, mine: &Self);
    /// The tags this entry's claim covers along whatever axis this KIND can
    /// be split on besides name. Programs answer with their (expanded)
    /// `languages` — spec 2026-07-31 §2. Tools carry no such axis in this
    /// changeset: every tool entry answers with the SAME fixed tag, so any
    /// two tool entries always "overlap" and an uncovered name's remainder is
    /// that one tag — unconditionally covered the instant ANY shipped entry
    /// names it, which reproduces `overlay_all`'s pre-existing (name-only)
    /// behaviour for tools rather than changing it.
    fn scope_tags(&self) -> HashSet<String>;
    /// Narrow a fresh clone — one standing in for a remainder no existing
    /// entry covers — to exactly these tags. A no-op for Tool: nothing to
    /// narrow.
    fn set_scope_tags(&mut self, tags: HashSet<String>);
}

/// The one tag every tool entry answers `scope_tags` with — see the trait
/// doc comment above for why a fixed tag reproduces the old name-only
/// behaviour instead of changing it.
const TOOL_SCOPE_TAG: &str = "tool";

impl Entry for Program {
    fn names(&self) -> &[String] {
        &self.match_names
    }
    fn set_names(&mut self, names: Vec<String>) {
        self.match_names = names;
    }
    /// `guards::check`, `is_modeled` and `recognises` all lowercase the
    /// command head before comparing, so program names are matched
    /// case-insensitively here too. ASCII-only (M2.121): a full-Unicode
    /// fold would equate characters the shell and the filesystem keep
    /// distinct, e.g. the Kelvin sign and ASCII `k`.
    fn same_name(a: &str, b: &str) -> bool {
        a.eq_ignore_ascii_case(b)
    }
    fn canonical_name(name: &str) -> String {
        name.to_ascii_lowercase()
    }
    fn lay(&mut self, mine: &Self) {
        overlay(self, mine)
    }
    fn scope_tags(&self) -> HashSet<String> {
        scope_of(&self.languages)
    }
    fn set_scope_tags(&mut self, tags: HashSet<String>) {
        // Canonicalise "the whole universe" back to empty. A remainder that
        // ends up covering every language vouch knows must round-trip to
        // exactly what an unscoped entry means today — an explicit list that
        // happens to spell out both known languages is a different (if
        // equivalent) shape, and keeping the canonical one is what makes
        // `overlay_is_exhaustive_over_every_program_field` (and every test
        // written before `languages` existed) stay meaningful.
        let universe = scope_of(&[]);
        self.languages = if tags == universe {
            Vec::new()
        } else {
            let mut v: Vec<String> = tags.into_iter().collect();
            v.sort();
            v
        };
    }
}

impl Entry for Tool {
    /// A `server` entry has no `match` of its own — its merge identity is
    /// the synthetic name `load`'s normalisation step wrote into
    /// `merge_names` (`server:<server>`). Everything else (a `match` entry,
    /// which is everything before this changeset) reads `match_names`
    /// exactly as it always has.
    fn names(&self) -> &[String] {
        if self.server.is_some() {
            &self.merge_names
        } else {
            &self.match_names
        }
    }
    /// Mirrors `names()`: a server entry writes back through `merge_names`,
    /// never `match_names`. Getting this branch wrong either recognises a
    /// literal tool named `server:x` (writing to `match_names`) or silently
    /// un-splits the M2.26 per-name remainder logic for ordinary tools
    /// (writing every entry through `merge_names`) — see
    /// `tests/tool_action_test.rs`'s
    /// `my_entry_for_one_name_does_not_take_out_the_others_beside_it`.
    fn set_names(&mut self, names: Vec<String>) {
        if self.server.is_some() {
            self.merge_names = names;
        } else {
            self.match_names = names;
        }
    }
    /// `guards::tool_entry` compares tool names EXACTLY, so this does too.
    /// Matching loosely would let `match = ["read"]` change what `Read` does
    /// while the lookup still could not find `read` — the file saying one
    /// thing and the lookup another. Applies equally to the synthetic
    /// `server:<server>` identity: two entries grant the same server only
    /// when the server string matches exactly.
    fn same_name(a: &str, b: &str) -> bool {
        a == b
    }
    fn canonical_name(name: &str) -> String {
        name.to_string()
    }
    fn lay(&mut self, mine: &Self) {
        overlay_tool(self, mine)
    }
    fn scope_tags(&self) -> HashSet<String> {
        std::iter::once(TOOL_SCOPE_TAG.to_string()).collect()
    }
    fn set_scope_tags(&mut self, _tags: HashSet<String>) {}
}

/// Lay the operator's entry over a shipped one. Unset means keep.
///
/// [review] `match_names` is deliberately NOT extended here. It was, and an
/// operator entry naming two programs pushed one shipped entry's description
/// onto the other: `match = ["rm", "cat"]` gave `cat` "writes all its
/// arguments" and a recursive-delete guard, from an entry that claimed nothing.
fn overlay(base: &mut Program, mine: &Program) {
    if !mine.value_options.is_empty() { base.value_options = mine.value_options.clone(); }
    if !mine.run_dir_flags.is_empty() { base.run_dir_flags = mine.run_dir_flags.clone(); }
    if !mine.no_value_options.is_empty() { base.no_value_options = mine.no_value_options.clone(); }
    if !mine.writes.is_empty() { base.writes = mine.writes.clone(); }
    if !mine.wraps.is_empty() { base.wraps = mine.wraps.clone(); }
    if !mine.write_flags.is_empty() { base.write_flags = mine.write_flags.clone(); }
    if !mine.wrap_flags.is_empty() { base.wrap_flags = mine.wrap_flags.clone(); }
    if !mine.wrap_lang.is_empty() { base.wrap_lang = mine.wrap_lang.clone(); }
    if !mine.flag_prefix.is_empty() { base.flag_prefix = mine.flag_prefix.clone(); }
    if !mine.evaluates_input.is_empty() { base.evaluates_input = mine.evaluates_input.clone(); }
    if !mine.runs_file.is_empty() { base.runs_file = mine.runs_file.clone(); }
    if !mine.runs_file_flags.is_empty() { base.runs_file_flags = mine.runs_file_flags.clone(); }
    if !mine.rebinds_name_flags.is_empty() { base.rebinds_name_flags = mine.rebinds_name_flags.clone(); }
    // A bare bool: `true` in an operator entry sets it, and `false` is
    // indistinguishable from unset — the same shape (and the same limit)
    // every other bare bool in this struct has.
    if mine.args_from_input { base.args_from_input = true; }
    if !mine.here_write.is_empty() { base.here_write = mine.here_write.clone(); }
    if mine.remote_dest { base.remote_dest = true; }
    if !mine.arg_names.is_empty() { base.arg_names = mine.arg_names.clone(); }
    if !mine.callback_args.is_empty() { base.callback_args = mine.callback_args.clone(); }
    if mine.case_sensitive_flags.is_some() { base.case_sensitive_flags = mine.case_sensitive_flags; }
    // `changes_dir` follows the `case_sensitive_flags` Option pattern: unset
    // means "the operator did not say", not "no". Without this an operator
    // could never RETRACT a shipped claim with `changes_dir = "no"` — the
    // whole reason that value exists (spec 2026-07-31 §1).
    if mine.changes_dir.is_some() { base.changes_dir = mine.changes_dir.clone(); }
    if !mine.dest_dir_flags.is_empty() { base.dest_dir_flags = mine.dest_dir_flags.clone(); }
    // `only_under` follows the same Option pattern. Unreachable live —
    // `validate_place_scopes` refuses every shape where a scoped name could
    // land on both sides of a merge — but the field must not be silently
    // dropped here if that ever changes.
    if mine.only_under.is_some() { base.only_under = mine.only_under.clone(); }
    // `writes_only_with_file_mode` and `wrap_join` follow the same Option
    // pattern as `case_sensitive_flags`, `changes_dir` and `only_under`
    // above: unset means "the operator did not say", not "false".
    if mine.writes_only_with_file_mode.is_some() {
        base.writes_only_with_file_mode = mine.writes_only_with_file_mode;
    }
    if mine.writes_via_handle.is_some() { base.writes_via_handle = mine.writes_via_handle.clone(); }
    if mine.wrap_join.is_some() { base.wrap_join = mine.wrap_join; }
    // `leading_args` follows the same Option pattern: unset means "the
    // operator did not say", so `leading_args = 0` is how a shipped count is
    // RETRACTED. Without the Option there would be no spelling for that —
    // exactly the hole `changes_dir = "no"` exists to fill.
    if mine.leading_args.is_some() { base.leading_args = mine.leading_args; }
    if !mine.wrap_head_flags.is_empty() { base.wrap_head_flags = mine.wrap_head_flags.clone(); }
    if !mine.wrap_exec_flags.is_empty() { base.wrap_exec_flags = mine.wrap_exec_flags.clone(); }
    if !mine.wrap_exec_terminators.is_empty() {
        base.wrap_exec_terminators = mine.wrap_exec_terminators.clone();
    }
    if mine.named_positional.is_some() { base.named_positional = mine.named_positional.clone(); }
    // `languages` is deliberately NOT field-copied here. Which language scope
    // a split-off piece of an overlay ends up with is computed by
    // `overlay_all` itself (`Entry::set_scope_tags`, called AFTER `lay()`),
    // never by trusting `mine.languages` verbatim — a shipped entry can be
    // BROADER than what the operator's own entry declares (an unscoped
    // shipped claim overlaid by a bash-scoped operator entry), and blindly
    // copying `mine.languages` here would silently erase the shipped claim's
    // powershell coverage instead of splitting it off. See `overlay_all`.

    // Recognition widens, never narrows — the full three-state merge matrix
    // (spec 2026-08-20 §3), pinned cell by cell in
    // tests/knowledge_merge_test.rs (Task 2): a base `None` (whole program)
    // is never narrowed by any `mine` value, list or explicit empty; a base
    // `Some` list left unset by `mine` (key-absent, `None`) is a no-op; two
    // `Some`s union, which makes an empty `mine` list a no-op union (the
    // wider, shipped side stands) and an empty `base` list widen to
    // whatever `mine` states. `all_subcommands = true` in `mine` always
    // clears to the whole-program state (`None`), overriding all of the
    // above.
    if mine.all_subcommands {
        base.subcommands = None;
    } else {
        match (&mut base.subcommands, &mine.subcommands) {
            (None, _) => {}
            (_, None) => {}
            (Some(b), Some(m)) => {
                for s in m {
                    if !b.contains(s) {
                        b.push(s.clone());
                    }
                }
            }
        }
    }
    // `standalone_flags` follows the `value_options` non-empty-replaces
    // pattern, like every other list on this struct.
    if !mine.standalone_flags.is_empty() {
        base.standalone_flags = mine.standalone_flags.clone();
    }

    let replaced: HashSet<String> = mine.rule.iter().map(rule_key).collect();
    base.rule.retain(|r| !replaced.contains(&rule_key(r)));
    base.rule.extend(mine.rule.iter().cloned());

    // Field-level, not whole-entry: a matching key keeps the shipped `takes`
    // and `min_positional` unless the operator's own entry actually sets
    // them. An operator file written before `takes = "run_dir"` shipped for
    // bare `init` names only `subcommand = "init"`, and whole-entry
    // replacement let that silence delete the shipped judgment.
    let mine_keys: HashSet<String> = mine.sub_write.iter().map(sub_write_key).collect();
    let mut laid: Vec<SubWrite> =
        base.sub_write.iter().filter(|s| !mine_keys.contains(&sub_write_key(s))).cloned().collect();
    for m in &mine.sub_write {
        match base.sub_write.iter().find(|s| sub_write_key(s) == sub_write_key(m)) {
            Some(shipped) => {
                let mut sw = shipped.clone();
                if !m.takes.is_empty() { sw.takes = m.takes.clone(); }
                if m.min_positional != 0 { sw.min_positional = m.min_positional; }
                laid.push(sw);
            }
            None => laid.push(m.clone()),
        }
    }
    base.sub_write = laid;
}

/// Lay the operator's tool entry over a shipped one. Unset means keep — the
/// same rule as `overlay`, and the whole reason this function exists.
///
/// [review] CRITICAL. Tool entries used to be APPENDED
/// (`base.tool.extend(mine.tool)`) and `guards::tool_entry` takes the last
/// matching entry WHOLE, so the operator's entry replaced the shipped one
/// outright — including the fields it said nothing about. `action` is an
/// `Option` whose `None` means "kept" everywhere else in this file, but
/// `config::shipped_tool_action` reads an unset action as ALLOW, because on a
/// SHIPPED entry being listed at all is the recognition claim. Put together:
/// silence in the operator's file turned a shipped `action = "ask"` into an
/// allow. Reproduced against the real `knowledge.toml` — a `my-knowledge.toml`
/// containing nothing but
///
/// ```toml
/// [[tool]]
/// match = ["ExitWorktree"]
/// source = "mine"
/// ```
///
/// took that tool from `ask` to `allow`, while the identical silence in a
/// `[[program]]` entry (`match = ["rm"]`) left `rm -rf C:/work/x` asking. Two
/// halves of one file answering the same silence oppositely, and the tool half
/// answering it permissively — §1 of CLAUDE.md, exactly.
fn overlay_tool(base: &mut Tool, mine: &Tool) {
    if !mine.source.trim().is_empty() {
        base.source = mine.source.clone();
    }
    if mine.action.is_some() {
        base.action = mine.action;
    }
    // `snippet` / `write_path_field` / `cwd_from_call` follow the same
    // Option pattern as `action`: `None` means the operator's entry did not
    // say, so the shipped value survives; `Some(_)` replaces it whole. There
    // is no field-level merge WITHIN a snippet list — an operator who sets
    // `snippet` at all is describing the whole set of inspected fields, not
    // patching one entry in the shipped list (spec 2026-08-05 §Schema;
    // `snippet = []` is refused earlier, in `validate_tool`, as exactly the
    // "silently turn off inspection" spelling this Option rule exists to
    // rule out).
    if mine.snippet.is_some() {
        base.snippet = mine.snippet.clone();
    }
    if mine.write_path_field.is_some() {
        base.write_path_field = mine.write_path_field.clone();
    }
    if mine.cwd_from_call.is_some() {
        base.cwd_from_call = mine.cwd_from_call;
    }
    // `server` is identity, not a claim to lay — `overlay_all` only ever
    // calls `lay` on two entries `same_name` already agreed are the SAME
    // server (matched through `merge_names`), so `mine.server` and
    // `base.server` are equal here by construction. Copying it would be a
    // no-op at best; it is left alone so that stays true by inspection
    // rather than by coincidence.
}

/// Lay every one of the operator's entries over the shipped ones.
///
/// [review] EVERY matching entry, not the first. Eight names appear in two
/// `[[program]]` entries each in the shipped file, and overlaying only the
/// first left the shipped twin's rules alive.
///
/// [review] CRITICAL, found after this task first shipped: a shipped entry can
/// name MANY things at once — `knowledge.toml` groups `env`, `xargs`, `nohup`,
/// `nice`, `time` and nine more wrappers into one `[[program]]`. The first
/// version handed the WHOLE shipped entry to the overlay the moment any one
/// name overlapped, so an operator file describing only `time` silently
/// rewrote `env`, `xargs` and the rest of that entry too — recognition widened
/// by omission (the operator never named `env`) and a false claim manufactured
/// for a program they never described. Reproduced: that file disarmed
/// `delete_recursive` for `env rm -rf` and `xargs rm -rf`.
///
/// The fix splits instead of overlaying whole: when the operator's names cover
/// only PART of a shipped entry's names, the shipped entry is cloned, the clone
/// is restricted to the shared names and receives the overlay, and the original
/// keeps the remaining names with its shipped description completely untouched.
///
/// [review] M2.26, generalised along BOTH axes (`docs/ROADMAP.md` — OPEN when
/// this was found, for both `[[program]]` and `[[tool]]`). The previous
/// version tracked a single "did this operator entry match ANYTHING" flag per
/// `m`, set the moment ONE of its names overlapped ONE shipped entry. A
/// second name in the same `match` list that shipped nowhere then had nowhere
/// to go — the flag was already true, so the "entirely new" fallback never
/// ran, and that name's claim silently vanished. Reproduced against the real
/// file for both halves: `match = ["sudo", "mytool"]` beside a shipped `sudo`
/// dropped `mytool` entirely, and the same shape dropped a tool beside a
/// known one. Coverage is now tracked per NAME — and, for programs, per
/// LANGUAGE within that name (spec 2026-07-31 §2) — so the part of `m`'s own
/// claim nothing shipped covers persists as its own entry no matter how much
/// of the REST of `m` found a shipped counterpart. Tools have no language
/// axis (`Entry::scope_tags` answers with one fixed tag for every tool entry),
/// so this reduces to exactly the name-only fix for them; the language split
/// only ever activates for a `Program` whose `languages` (on either side) is
/// non-empty, which no shipped entry in this repository sets yet — the
/// behaviour-preservation invariant this task is held to.
fn overlay_all<E: Entry>(mut base: Vec<E>, mine: &[E]) -> Vec<E> {
    for m in mine {
        let existing = std::mem::take(&mut base);
        let m_scope = m.scope_tags();
        // Per name in `m`, the union of scope tags some shipped entry has
        // already covered. What is LEFT of `m`'s own claim after subtracting
        // this, per name, is the remainder pushed after the loop below.
        let mut covered: HashMap<String, HashSet<String>> = HashMap::new();
        for b in existing {
            let shared: Vec<String> = b
                .names()
                .iter()
                .filter(|n| m.names().iter().any(|o| E::same_name(n, o)))
                .cloned()
                .collect();
            let b_scope = b.scope_tags();
            let overlap_scope: HashSet<String> = b_scope.intersection(&m_scope).cloned().collect();
            if shared.is_empty() || overlap_scope.is_empty() {
                // Either no name in common, or (spec §2) neither scope is
                // unscoped and the two scopes never intersect — a bash-only
                // shipped entry and a powershell-only operator entry sharing
                // a name simply do not interact. `b` is untouched either way.
                base.push(b);
                continue;
            }
            // Keyed by CANONICAL form (Finding 1), not by `b`'s raw spelling:
            // `covered` is read back below using `m`'s own spelling, and a
            // plain `HashMap` key comparison does not know that `same_name`
            // would call `git` and `Git` the same name.
            for n in &shared {
                covered.entry(E::canonical_name(n)).or_default().extend(b_scope.iter().cloned());
            }
            let name_remainder: Vec<String> = b
                .names()
                .iter()
                .filter(|n| !shared.iter().any(|s| E::same_name(s, n)))
                .cloned()
                .collect();
            // The part of `b`'s OWN scope that `m`'s declared scope never
            // addresses, for the names they DO share — an operator override
            // scoped to bash must not silently narrow an unscoped shipped
            // entry's powershell coverage away just because it shares a name.
            // Preserved untouched: `b`'s original values, never laid with
            // `m`, which said nothing about this scope at all. Always empty
            // for `Tool` (both sides answer the same fixed tag), so this
            // never fires for tools.
            let scope_leftover: HashSet<String> = b_scope.difference(&m_scope).cloned().collect();

            if name_remainder.is_empty() && scope_leftover.is_empty() {
                // `m`'s names and scope fully cover `b`: nothing to split
                // off, overlay it in place.
                let mut overlaid = b;
                overlaid.lay(m);
                overlaid.set_scope_tags(overlap_scope);
                base.push(overlaid);
                continue;
            }
            // Partial overlap along one or both axes: split. Only the
            // shared-name / overlap-scope clone is touched; anything left
            // over on `b`'s side is `b`'s original entry, unmodified, just
            // narrowed to the part the operator said nothing about.
            if !name_remainder.is_empty() {
                let mut kept = b.clone();
                kept.set_names(name_remainder);
                base.push(kept);
            }
            if !scope_leftover.is_empty() {
                let mut kept_scope = b.clone();
                kept_scope.set_names(shared.clone());
                kept_scope.set_scope_tags(scope_leftover);
                base.push(kept_scope);
            }
            let mut overlaid = b;
            overlaid.set_names(shared);
            overlaid.lay(m);
            overlaid.set_scope_tags(overlap_scope);
            base.push(overlaid);
        }
        // The M2.26 fix: whatever part of `m`'s own (names x scope) claim no
        // shipped entry actually covered persists as its own entry, carrying
        // `m`'s fields untouched — never silently dropped (a name beside a
        // known one used to vanish), never silently narrowed to only what
        // shipped already said. Names whose leftover scope is IDENTICAL are
        // grouped into one entry rather than one-per-name, so an unscoped
        // `m` naming several brand-new programs still lands as a single
        // entry, exactly as it always has.
        let mut groups: Vec<(Vec<String>, Vec<String>)> = Vec::new();
        for n in m.names() {
            let empty = HashSet::new();
            // Read back through the SAME canonical form it was written
            // under (Finding 1) — `n` here is `m`'s own spelling, which can
            // legitimately differ in case from whatever shipped spelling
            // populated `covered` above while still being the same name.
            let left: HashSet<String> = m_scope
                .difference(covered.get(&E::canonical_name(n)).unwrap_or(&empty))
                .cloned()
                .collect();
            if left.is_empty() {
                continue;
            }
            let mut key: Vec<String> = left.into_iter().collect();
            key.sort();
            match groups.iter_mut().find(|(k, _)| *k == key) {
                Some((_, names)) => names.push(n.clone()),
                None => groups.push((key, vec![n.clone()])),
            }
        }
        for (tags, names) in groups {
            let mut fresh = m.clone();
            fresh.set_names(names);
            fresh.set_scope_tags(tags.into_iter().collect());
            base.push(fresh);
        }
    }
    base
}

/// The operator's descriptions laid over the ones that ship — both halves of
/// the file, by the same algorithm (`overlay_all`).
///
/// [review] The tool half used to be `base.tool.extend(mine.tool)`, a plain
/// append, on the reasoning that `tool_entry` takes the last matching entry so
/// the operator's file "overrides for the names it repeats, and only those".
/// True about which NAMES are affected, false about which FIELDS: taking the
/// last entry takes it WHOLE, so an operator entry with no `action` replaced a
/// shipped `action = "ask"` with silence, and silence on a tool entry means
/// allow. See `overlay_tool` for the reproduction.
pub fn merge(mut base: Knowledge, mine: Knowledge) -> Knowledge {
    base.program = overlay_all(base.program, &mine.program);
    base.tool = overlay_all(base.tool, &mine.tool);
    // `[[env_name]]` carries no `Program`-shaped fields to lay over one at a
    // time, so its merge is the whole entry: an operator entry naming the
    // same variable in the same language scope REPLACES the shipped claim
    // about it, and any other entry is added. Retracting a shipped name is
    // deliberately not expressible — an entry saying a lookup name is inert
    // would be a claim about the SHELL that is false, and the file's rule is
    // that every entry is true (§3).
    for m in mine.env_name {
        match base
            .env_name
            .iter_mut()
            .find(|b| b.name == m.name && b.languages == m.languages)
        {
            Some(b) => *b = m,
            None => base.env_name.push(m),
        }
    }
    base
}

/// Spec 2026-07-31 §2.2, AMENDED after Task 4's skeptical review (Finding
/// 2; see the plan's Task 4 Interfaces, commit 4666b8c). The original
/// signature ran on the MERGED result alone, which is provenance-blind: after
/// the merge, a deliberate per-language `"no"` pair (two entries, each
/// EXPLICITLY scoped, each retracting its own language on purpose) is
/// structurally identical to an unscoped `"no"` that got split across scopes
/// by `overlay_all`'s remainder logic — there is no way to tell them apart
/// from `&Knowledge` alone, so the merged-only check rejected exactly the
/// spellings the spec requires to work. Both halves have to still be
/// separately in scope, so this runs on `mine`'s OWN entries against
/// `shipped`, called from `load_files` BEFORE the merge.
///
/// The trigger, exactly: an entry in `mine` with `changes_dir = Some("no")`
/// AND an EMPTY `languages` (the operator did not name a language at all —
/// an explicit `languages = ["bash", "powershell"]` is a different claim,
/// said out loud, and validates) whose name matches two or more entries in
/// `shipped` whose language scopes are not all the same. That shipped-side
/// difference is exactly the case where the operator's unscoped spelling —
/// the widest possible retraction — reads as "wherever this runs" while the
/// shipped truth for that name is NOT the same everywhere; the almost
/// certain intent was one language, and the unscoped spelling silently
/// retracts both. A name whose shipped claims are all the SAME (including a
/// name shipped only once, or not shipped at all) has nothing to disagree
/// with, so an unscoped `"no"` there validates too.
fn validate_retraction(shipped: &Knowledge, mine: &Knowledge) -> Result<(), String> {
    for m in &mine.program {
        if m.changes_dir.as_deref() != Some("no") || !m.languages.is_empty() {
            continue;
        }
        for n in &m.match_names {
            let shipped_scopes: Vec<HashSet<String>> = shipped
                .program
                .iter()
                .filter(|p| p.match_names.iter().any(|sn| Program::same_name(sn, n)))
                .map(|p| scope_of(&p.languages))
                .collect();
            if shipped_scopes.len() < 2 {
                continue;
            }
            let first = &shipped_scopes[0];
            if shipped_scopes.iter().any(|s| s != first) {
                return Err(format!(
                    "[[program]] {n:?}: changes_dir = \"no\" is unscoped, but the shipped claims \
                     for this name differ by language — name the language this retraction is \
                     actually about (`languages = [\"bash\"]` or [\"powershell\"]), or write one \
                     entry per language if it truly applies to both"
                ));
            }
        }
    }
    Ok(())
}

/// Place-scoped recognition is for the operator's OWN programs. An entry
/// naming a shipped-described program would either patch the shipped entry
/// (one line un-recognises it machine-wide outside the trees) or silently
/// do nothing (the shipped entry still recognises everywhere) — both wrong,
/// so the collision is refused (spec 2026-08-06 §Refused shapes). A scoped
/// name on a second operator entry is refused for the same reason: the
/// overlay would merge them into something nobody wrote.
pub fn validate_place_scopes(shipped: &Knowledge, mine: &Knowledge) -> Result<(), String> {
    // Canonical (lowercased), not the literal spelling: `Program::same_name`
    // matches program names case-insensitively everywhere else in this file
    // (`guards::check`, `is_modeled` and `recognises` all lowercase the
    // command head before comparing), and a `HashSet<&str>` / `HashMap<&str,
    // _>` keyed on the raw spelling would not know that `Examplecmd` is
    // `examplecmd` — the exact "the map key is not the thing the comparison
    // uses" class `Entry::canonical_name`'s own doc comment names as M2.26.
    let shipped_names: HashSet<String> = shipped
        .program
        .iter()
        .flat_map(|e| e.match_names.iter().map(|n| Program::canonical_name(n)))
        .collect();
    let mut seen: HashMap<String, usize> = Default::default();
    for e in &mine.program {
        for n in &e.match_names {
            *seen.entry(Program::canonical_name(n)).or_default() += 1;
        }
    }
    for e in &mine.program {
        let Some(ou) = &e.only_under else { continue };
        if ou.is_empty() {
            return Err(format!(
                "only_under on '{}' is an empty list — a rule that can never apply",
                e.match_names.join(", ")
            ));
        }
        for n in &e.match_names {
            let canon = Program::canonical_name(n);
            if shipped_names.contains(&canon) {
                return Err(format!(
                    "only_under on '{n}': the shipped knowledge already describes {n}; \
                     place-scoped recognition applies to your own programs only"
                ));
            }
            if seen.get(&canon).copied().unwrap_or(0) > 1 {
                return Err(format!(
                    "'{n}' is place-scoped and appears on more than one of your entries — \
                     write one entry whose only_under lists every tree \
                     ('under A or B' is one entry with both globs)"
                ));
            }
        }
    }
    Ok(())
}

/// One sentence per operator entry whose `subcommands` spelling the merge
/// will silently discard — a list or an explicit `[]` laid over a shipped
/// WHOLE-PROGRAM entry (`overlay`'s own comment: "a base `None` is never
/// narrowed by any `mine` value, list or explicit empty"), or an explicit
/// `[]` laid over a shipped VERB list (union with nothing is nothing). A
/// list of real verbs laid over a shipped verb list is NOT here — that
/// unions, a real effect.
///
/// Computed on `base`/`own` BEFORE `merge` runs, called from `load_files`
/// the same way `validate_retraction` is: the merge already erases the
/// distinction between "the operator wrote an explicit empty list" and "the
/// operator wrote nothing at all" — both land on the same post-merge
/// `subcommands` — so only the pre-merge shapes can still tell a discarded
/// overlay apart from a real widen. Not a gap: nothing failed to load and
/// nothing goes unrecognised, so these are returned on `Loaded.notes`
/// rather than pushed onto `gaps`.
fn narrowing_noops(base: &Knowledge, own: &Knowledge) -> Vec<String> {
    let mut notes = Vec::new();
    for m in &own.program {
        let Some(m_sub) = &m.subcommands else { continue };
        for n in &m.match_names {
            for b in base
                .program
                .iter()
                .filter(|p| p.match_names.iter().any(|sn| Program::same_name(sn, n)))
            {
                match &b.subcommands {
                    None => notes.push(format!(
                        "[[program]] {n:?}: your subcommands = {m_sub:?} is discarded by the \
                         merge — the shipped whole-program coverage still stands \
                         (subcommands never narrows below the whole program)"
                    )),
                    Some(b_sub) if m_sub.is_empty() && !b_sub.is_empty() => notes.push(format!(
                        "[[program]] {n:?}: your subcommands = [] is discarded by the merge \
                         — the shipped verb coverage still stands (an empty list unions \
                         with nothing)"
                    )),
                    _ => {}
                }
            }
        }
    }
    notes
}

/// REFUSED is not ABSENT (spec §7, rev 4).
///
/// A shipped file that does not exist leaves `base` empty and my-knowledge
/// still merges over it — today's documented behaviour, unchanged: absence of
/// knowledge is not permissive, but it is also not a claim that anything is
/// wrong with a file the operator never wrote.
///
/// A shipped file that EXISTS but comes back `None` — parse error, failed
/// validation, or the version gate in `read_one` — is a different state, and
/// letting my-knowledge merge over the empty `base` in that case was the
/// defect: the operator's overlay is written against the CURRENT schema and
/// is silent on everything the shipped file would have declared, so it would
/// stand alone as the whole knowledge while looking, from the banner down, like
/// the shipped set was still in effect underneath it. `own` is still read below
/// even when refused, so a my-knowledge.toml that is ALSO broken is still
/// reported — only its content is discarded.
pub fn load_files(knowledge: &Path, mine: &Path) -> Loaded {
    let mut gaps = Vec::new();
    let mut notes = Vec::new();
    let shipped_present = knowledge.exists();
    let shipped = read_one(knowledge, true, GapSource::Knowledge, &mut gaps);
    let refused = shipped_present && shipped.is_none();
    let base = shipped.unwrap_or_default();

    // A file that parses to nothing is a gap. `load("")` succeeds, and so does
    // a file whose tables are all misspelt, so without this vouch runs with no
    // knowledge, reports no gap, and shows no banner. Skipped when `refused` is
    // true: `read_one` already pushed the refusal gap, so `gaps` is non-empty
    // and this block does not fire — `base` being empty there means REFUSED,
    // not the separate "parsed fine, said nothing" state this gap is for.
    if gaps.is_empty() && base.program.is_empty() && base.tool.is_empty() {
        gaps.push(Gap {
            path: display_path(knowledge),
            why: "read, but it describes no programs and no tools".into(),
            source: GapSource::Knowledge,
            kind: GapKind::Empty,
        });
    }

    let own = read_one(mine, false, GapSource::MyKnowledge, &mut gaps);

    if refused {
        if mine.exists() {
            gaps.push(Gap {
                path: display_path(mine),
                why: "set aside: the shipped knowledge base above refused to load, so your \
                      own additions were never merged over it"
                    .into(),
                source: GapSource::MyKnowledge,
                kind: GapKind::SetAside,
            });
        }
        return Loaded { kb: base, gaps, notes };
    }

    let kb = match own {
        Some(o) => {
            // Finding 2/4: the retraction check runs on the OPERATOR's
            // entries against the SHIPPED set, BEFORE the merge — the merge
            // erases exactly the distinction (unscoped-split vs. deliberate
            // per-language pair) the check needs to see — and it structurally
            // only ever runs here, inside `Some(o) =>`, so it cannot fire
            // when no operator file loaded (Finding 4). A failure is the
            // operator's entry being ambiguous, not a per-file parse
            // problem, but the experience is the same as Task 3's refusal:
            // fail closed rather than hand back a half-applied merge. `kb`
            // is discarded entirely, not narrowed to just the shipped base,
            // because by this point the two files are already meant to be
            // combined and there is no way to say which part of that
            // combination is still trustworthy.
            //
            // [review, final review Finding 1] `kind` here used to be
            // `Unusable` — the SAME kind `read_one` uses when THIS file fails
            // on its own, which leaves `kb = base` (shipped only, see the
            // `None => base` arm below). The renderer's `(GapSource::MyKnowledge,
            // _)` wildcard is written for exactly that case and says "vouch
            // still recognises everything the shipped knowledge describes" —
            // true there, false here, where `kb` is about to become
            // `Knowledge::default()`. `Ambiguous` gets this gap its own arm so
            // the banner can say what is actually in effect: nothing.
            if let Err(e) = validate_retraction(&base, &o) {
                gaps.push(Gap {
                    path: display_path(mine),
                    why: e,
                    source: GapSource::MyKnowledge,
                    kind: GapKind::Ambiguous,
                });
                return Loaded { kb: Knowledge::default(), gaps, notes };
            }
            if let Err(e) = validate_place_scopes(&base, &o) {
                gaps.push(Gap {
                    path: display_path(mine),
                    why: e,
                    source: GapSource::MyKnowledge,
                    kind: GapKind::PlaceScope,
                });
                return Loaded { kb: Knowledge::default(), gaps, notes };
            }
            // `narrowing_noops` runs on the PRE-merge shapes — the merge
            // erases exactly the distinction it needs to see (spec §4) — so
            // it has to be computed here, before `merge` consumes `o`.
            // `validate_standalone_in_effect` runs the other way: it needs
            // the MERGED entry, because an operator overlay can replace a
            // vocabulary whole and only the combined shape can answer
            // whether a standalone member is orphaned or collides. A
            // failure there sets the WHOLE my-knowledge overlay aside —
            // `base` (cloned before the merge consumed it) stands in for
            // `kb`, unlike the two refusals above, which discard the
            // combined load entirely: this failure names one merged entry
            // and key, not an ambiguity between the two files at large.
            notes = narrowing_noops(&base, &o);
            let merged = merge(base.clone(), o);
            match validate_standalone_in_effect(&merged) {
                Ok(()) => merged,
                Err(e) => {
                    gaps.push(Gap {
                        path: display_path(mine),
                        why: e,
                        source: GapSource::MyKnowledge,
                        kind: GapKind::MergedShape,
                    });
                    base
                }
            }
        }
        None => base,
    };

    Loaded { kb, gaps, notes }
}
