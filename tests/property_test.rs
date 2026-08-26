//! Invariants that must hold over ANY corpus, real or synthetic.
//!
//! This file is the one that must be green on a fresh clone, so it never
//! requires the gitignored real corpus.

mod common;

#[test]
fn the_synthetic_corpus_is_committed_and_loads() {
    let rows = common::synthetic();
    assert!(
        rows.len() >= 50,
        "synthetic corpus should cover a spread of shapes, got {}",
        rows.len()
    );
    assert!(
        rows.iter().all(|r| !r.cmd.is_empty()),
        "no row may have an empty command"
    );
}

use common::realistic_config;
use vouch::engine::{decide_command_at, decide_command_in};
use vouch::protocol::Decision;

#[test]
fn vouch_never_panics_on_any_command_in_any_corpus() {
    let cfg = realistic_config();
    for (name, rows) in common::all() {
        // Deciding nothing would "not panic" too, so the check that carries
        // the weight is that there was something to decide.
        assert!(!rows.is_empty(), "{name}: corpus is empty, so this proves nothing");
        for row in &rows {
            let _ = decide_command_in(&cfg, "bash", &row.cmd, Some("C:/Users/dev"), None);
        }
        eprintln!("{name}: {} commands decided without panicking", rows.len());
    }
}

/// CLAUDE.md §5, as one predicate: does this reason name something the
/// operator can change to stop seeing it?
///
/// Deliberately no bare `.constructs.` clause. Every emitting site in
/// engine.rs already produces "setting: " or "set lang.bash.constructs."; a
/// looser clause would only ever accept a reason that mentions constructs
/// WITHOUT naming a setting, which is the one thing this file exists to
/// forbid.
///
/// The place-rule names below are the same list, extended for the rules M2.24
/// added — each is the literal text the operator types into their config
/// (`only_under` is the knowledge key, which is where a place-scoped entry's
/// off-switch actually lives). They cost the older net nothing: no
/// `realistic_config` run can emit any of them, because that config turns no
/// place rule on.
///
/// One predicate, used by both nets, so a clause loosened for one of them can
/// never quietly loosen only that one.
fn names_a_setting(reason: &str) -> bool {
    reason.contains("setting: ")
        || reason.contains("set lang.bash.constructs.")
        || reason.contains("set lang.powershell.constructs.")
        || reason.contains("set lang.python.constructs.")
        || reason.contains("write.allow_paths")
        || reason.contains("no setting that allows this")
        || reason.contains("run.trust_all_under")
        || reason.contains("run.trust_nothing_under")
        || reason.contains("run.guards")
        || reason.contains("write.ask_paths")
        || reason.contains("write.deny_paths")
        || reason.contains("write.scope")
        || reason.contains("only_under")
        || reason.contains("tools.")
}

#[test]
fn every_prompt_names_a_setting_that_turns_it_off() {
    let cfg = realistic_config();
    for (name, rows) in common::all() {
        let mut unfixable: Vec<(String, String)> = Vec::new();
        for row in &rows {
            let reason = match decide_command_in(&cfg, "bash", &row.cmd, Some("C:/Users/dev"), None) {
                Decision::Ask(r) | Decision::Deny(r) => r,
                _ => continue,
            };
            if !names_a_setting(&reason) {
                unfixable.push((
                    row.cmd.chars().take(90).collect(),
                    reason.lines().next().unwrap_or("").to_string(),
                ));
            }
        }
        for (cmd, why) in unfixable.iter().take(10) {
            eprintln!("  UNFIXABLE [{name}]: {why}\n      {cmd}");
        }
        assert!(
            unfixable.is_empty(),
            "{name}: {} prompts name nothing that would turn them off",
            unfixable.len()
        );
    }
}

/// The property tests above are worthless if the synthetic corpus never makes
/// vouch prompt - they would pass over a list of `echo` calls. This asserts the
/// fixture actually exercises the paths the properties are about.
#[test]
fn the_synthetic_corpus_actually_exercises_prompting() {
    let cfg = realistic_config();
    let (mut asks, mut guards, mut write_policy) = (0, 0, 0);
    for row in common::synthetic() {
        if let Decision::Ask(r) | Decision::Deny(r) =
            decide_command_in(&cfg, "bash", &row.cmd, Some("C:/Users/dev"), None)
        {
            asks += 1;
            if r.contains("(guard)") {
                guards += 1;
            }
            if r.contains("write.allow_paths") {
                write_policy += 1;
            }
        }
    }
    eprintln!("synthetic: {asks} prompts, {guards} guard hits, {write_policy} write-policy hits");
    assert!(asks >= 8, "synthetic corpus produced only {asks} prompts - too few to prove anything");
    assert!(guards >= 3, "synthetic corpus produced only {guards} guard hits");
    assert!(write_policy >= 1, "synthetic corpus never hit write.allow_paths");
}

/// The basename normalisation `guards::base` applies internally, duplicated
/// here only because it is private. Used to tell "this command's head IS
/// `git`" apart from "some other program that happens to have a subcommand".
fn head_is_git(head: &str) -> bool {
    let h = head.replace('\\', "/");
    let last = h.rsplit('/').next().unwrap_or(&h);
    last.trim_end_matches(".exe").to_lowercase() == "git"
}

/// A git subcommand that only reads: no destination, so a run-dir flag
/// changes WHERE it looks, never what it might write. `branch` only counts
/// bare (no trailing tokens) — `git branch -D` deletes.
fn is_git_read(kb: &vouch::guards::Knowledge, cmd: &vouch::syntax::Cmd) -> bool {
    if !head_is_git(&cmd.head) {
        return false;
    }
    const READS: &[&str] = &["status", "log", "diff", "show", "rev-parse"];
    match vouch::guards::subcommand_of(kb, cmd) {
        Some(sub) if READS.contains(&sub) => true,
        Some("branch") => cmd.args.last().map(String::as_str) == Some("branch"),
        _ => false,
    }
}

/// "reads gain no standing prompt": a git read command, alone in the line
/// with no redirect and nothing else running, must never be asked about
/// because vouch could not resolve some path — it never needed one. Run-dir
/// resolution (`git -C <dir> status`) changing where the read looks must not
/// turn into a prompt about a path vouch could not place.
#[test]
fn a_lone_git_read_never_gets_an_unresolved_path_reason() {
    let cfg = realistic_config();
    let kb = vouch::guards::in_effect();
    for (name, rows) in common::all() {
        let mut checked = 0;
        let mut offenders: Vec<(String, String)> = Vec::new();
        for row in &rows {
            let Ok(scan) = vouch::shell::parse(&row.cmd) else {
                continue;
            };
            if scan.commands.len() != 1 || !scan.redirect_targets.is_empty() {
                continue;
            }
            if !is_git_read(kb, &scan.commands[0]) {
                continue;
            }
            checked += 1;
            let reason = match decide_command_in(&cfg, "bash", &row.cmd, Some("C:/Users/dev"), None) {
                Decision::Ask(r) | Decision::Deny(r) => r,
                _ => continue,
            };
            if reason.contains("unresolved_path") {
                offenders.push((
                    row.cmd.chars().take(90).collect(),
                    reason.lines().next().unwrap_or("").to_string(),
                ));
            }
        }
        eprintln!("{name}: {checked} lone git reads checked");
        for (cmd, why) in offenders.iter().take(10) {
            eprintln!("  OFFENDER [{name}]: {why}\n      {cmd}");
        }
        if name == "synthetic" {
            assert!(checked > 0, "synthetic corpus has no lone git read row - this test proves nothing");
        }
        assert!(
            offenders.is_empty(),
            "{name}: {} lone git reads got an unresolved_path prompt",
            offenders.len()
        );
    }
}

// --- snippet / server well-formedness, over the real in-effect knowledge (Task 13) ---
//
// These are a belt over load-time validation (`knowledge::validate_tool`),
// checked directly against `guards::in_effect()` — the actual merged
// knowledge the gate decides with — so a future loader change that stopped
// calling `validate` would be caught here even though it would not touch
// `knowledge::validate_tool`'s own unit tests at all.

#[test]
fn every_in_effect_snippet_language_is_in_the_closed_set() {
    let kb = vouch::guards::in_effect();
    let mut offenders: Vec<String> = Vec::new();
    for t in &kb.tool {
        let Some(snippets) = &t.snippet else { continue };
        for p in snippets {
            if let Some(lang) = &p.language {
                if !vouch::knowledge::is_snippet_language(lang) {
                    offenders.push(format!(
                        "{:?} field {:?}: language = {lang:?}",
                        t.match_names, p.field
                    ));
                }
            }
            if let Some(values) = &p.language_values {
                for (k, v) in values {
                    if !vouch::knowledge::is_snippet_language(v) {
                        offenders.push(format!(
                            "{:?} field {:?}: language_values[{k:?}] = {v:?}",
                            t.match_names, p.field
                        ));
                    }
                }
            }
        }
    }
    assert!(offenders.is_empty(), "snippet language outside the closed set: {offenders:?}");
}

#[test]
fn no_in_effect_tool_entry_names_both_a_server_and_a_non_empty_match() {
    let kb = vouch::guards::in_effect();
    let offenders: Vec<&[String]> = kb
        .tool
        .iter()
        .filter(|t| t.server.is_some() && !t.match_names.is_empty())
        .map(|t| t.match_names.as_slice())
        .collect();
    assert!(offenders.is_empty(), "entries with both server and a non-empty match: {offenders:?}");
}

#[test]
fn no_in_effect_tool_entry_has_an_empty_snippet_list() {
    let kb = vouch::guards::in_effect();
    let offenders: Vec<&[String]> = kb
        .tool
        .iter()
        .filter(|t| matches!(&t.snippet, Some(p) if p.is_empty()))
        .map(|t| t.match_names.as_slice())
        .collect();
    assert!(offenders.is_empty(), "entries with snippet = Some([]) reached in_effect(): {offenders:?}");
}

// --- the new asks name their setting, driven through route::decide (Task 13) ---
//
// Deliberately NOT an extension of the corpus-row walk above: that walk
// (`decide_command_in`, bash rows only) runs below the routing layer and
// never exercises `[[tool]]` snippet declarations at all. These go through
// `vouch::route::decide` on fixture tool calls instead, the same real
// dispatch `tests/routing_test.rs` pins.

use common::kb_with;

#[test]
fn a_python_snippet_ask_names_the_languages_own_setting_via_route_decide() {
    // Python joined the scanner registry (Task 10): a declared python
    // snippet is decided through the engine exactly like bash and
    // PowerShell, so an ask about it names the LANGUAGE's own setting rather
    // than the tool's blanket grant — until Task 10, python had no scanner
    // and this same fixture asked naming `tools.mcp__p_s__py` instead.
    //
    // Re-decided (Task 11, python-snippets): `realistic_config` now carries
    // a `[lang.python]` block that allows the merely-unknowable, the same as
    // bash and PowerShell already did — the real python entries ship with
    // this task, and an unmodelled head like `print` no longer asks under
    // it. `parse_failure = "ask"` is still explicit there, so an unreadable
    // snippet is what proves the routing now, without depending on
    // `unmodeled_command`'s newly-permissive default.
    let kb = kb_with(
        "[[tool]]\nmatch = [\"mcp__p_s__py\"]\nsource = \"runs the `code` field as python\"\n\
         [[tool.snippet]]\nfield = \"code\"\nlanguage = \"python\"\n",
    );
    let cfg = realistic_config();
    let input = vouch::protocol::parse_input(
        r#"{"session_id":"s","cwd":"C:/Users/dev","tool_name":"mcp__p_s__py","tool_input":{"code":"def broken(:"}}"#,
    )
    .expect("hook input parses");
    let outcome = vouch::route::decide(&cfg, &kb, "C:/Users/dev", &input);
    match &outcome.decision {
        Decision::Ask(reason) => assert!(
            reason.contains("lang.python.constructs.parse_failure"),
            "the ask must name the language's own setting, got: {reason}"
        ),
        other => panic!("expected Ask, got: {other:?}"),
    }
}

#[test]
fn a_missing_snippet_field_ask_names_a_tools_setting_via_route_decide() {
    let kb = kb_with(
        "[[tool]]\nmatch = [\"mcp__p_s__sh\"]\nsource = \"runs the `code` field as bash\"\n\
         cwd_from_call = true\n[[tool.snippet]]\nfield = \"code\"\nlanguage = \"bash\"\n",
    );
    let cfg = realistic_config();
    // No `code` field sent - the declared snippet field is missing entirely.
    let input = vouch::protocol::parse_input(
        r#"{"session_id":"s","cwd":"C:/Users/dev","tool_name":"mcp__p_s__sh","tool_input":{"timeout":5}}"#,
    )
    .expect("hook input parses");
    let outcome = vouch::route::decide(&cfg, &kb, "C:/Users/dev", &input);
    match &outcome.decision {
        Decision::Ask(reason) => {
            assert!(reason.contains("tools."), "the missing-field ask must name a tools. setting, got: {reason}")
        }
        other => panic!("expected Ask, got: {other:?}"),
    }
}

// --- the same net over every place-derived verdict (M2.24, Task 13) ---------
//
// The net above runs under `realistic_config`, which turns no place rule on,
// so not one of the M2.24 ask paths is reachable from it. This walk turns
// EVERY place rule on at once and runs the same predicate over the same
// corpora, plus a fixed probe list carrying at least one line per row of the
// spec's prompt table (2026-08-06 §Every place-derived verdict says so).
//
// Why a probe list beside the corpus: the corpus supplies shape variety —
// 20k real command lines — but it cannot aim a write at a wall or invoke a
// scoped program, so the rarest reasons would never be emitted and the walk
// would report "0 unfixable" for paths it never reached. The probes aim at
// each row deliberately, and `PROMPT_TABLE_COVERAGE` below fails if any of
// them stops being reached, which is what stops this from becoming a test
// that passes because nothing happened.

/// The write wall and the per-program write scope. Appended INSIDE
/// `realistic_config`'s `[write]` table — its `{extra}` sits directly after
/// `allow_paths` — so this walk decides against the same language and write
/// settings every other test uses and only the place rules differ. Two texts
/// that drifted apart would compare fixtures nobody ran.
///
/// `programs` is the spec's own three-item example, verbatim — including the
/// two-word verb `"git worktree add"`, which `validate_scopes` refused until
/// the Task 9 fix round taught scope entries the second verb word the
/// knowledge file already models (`subcommand = "worktree", then = "add"`).
/// Using the documented shape here is deliberate: `main.rs` is the only caller
/// of `validate_scopes`, so an in-process config carrying a refused shape
/// would decide happily while the child-process net rejected the whole file.
const WALLS_AND_SCOPE: &str = r#"
ask_paths = ["$HOME/notes/**"]
deny_paths = ["$HOME/photos/**"]

[[write.scope]]
programs = ["git init", "git clone", "git worktree add"]
only_under = ["C:/scratch/**"]
"#;

const TRUST_ZONE: &str = "trust_all_under = [\"C:/scratch/**\"]\n";
const DISTRUST_ZONE: &str = "trust_nothing_under = [\"D:/inbox/**\"]\n";

/// A stricter override and a looser one, which are two different rules under
/// the uncertainty rule: the stricter applies unless the place is provably
/// outside it, the looser only on a place PROVEN inside.
const GUARD_OVERRIDES: &str = r#"
[[run.guards]]
under = ["C:/workspace/**"]
delete_recursive = "ask"

[[run.guards]]
under = ["C:/scratch/**"]
delete_recursive = "allow"
"#;

/// Every place rule the spec defines, in one config. `distrust` is a
/// parameter for one reason: a distrust zone answers FIRST for any command
/// whose place is not provably outside it, so with it on, the rows that only
/// fire when nothing else has already spoken — the missed grant, the
/// trust-zone allow off an unprovable place — are unreachable. Both settings
/// are walked.
fn place_rules(distrust: bool) -> String {
    format!(
        "{WALLS_AND_SCOPE}\n[run]\n{TRUST_ZONE}{}{GUARD_OVERRIDES}",
        if distrust { DISTRUST_ZONE } else { "" }
    )
}

/// The corpus walk's config: `realistic_config` plus every place rule.
fn place_config(distrust: bool) -> vouch::config::Config {
    common::realistic_config_with(&place_rules(distrust))
}

/// The same place rules with `unmodeled_command = "ask"`. `realistic_config`
/// allows unmodelled programs — deliberately, so that only vouch's own
/// defects prompt over the corpus — which puts every recognition-side place
/// verdict (trust zone, missed grant, place-scoped entry) out of reach. This
/// is the config an operator running the allow-list as an allow-list has, and
/// it cannot be spelled as an addition to `realistic_config` because a TOML
/// key cannot be given twice.
fn asking_place_config(distrust: bool) -> vouch::config::Config {
    vouch::config::load(&format!(
        r#"
version = 1
[lang.bash]
default = "allow"
[lang.bash.constructs]
unmodeled_command = "ask"
parse_failure = "ask"
[write]
default = "ask"
allow_paths = ["C:/work/**", "C:/workspace/**", "$HOME/**"]
{}
"#,
        place_rules(distrust)
    ))
    .expect("the place-rule config parses")
}

/// One line per row of the spec's prompt table, each with the directory it is
/// judged from. Run under every config variant below, so a row masked in one
/// (a distrust zone answering first) is still reached in another.
const PROBES: &[(&str, &str)] = &[
    // distrust zone, place proven / place unprovable
    ("D:/inbox/sub", "ls -la"),
    ("C:/work", "cd a || cd b; ls -la"),
    // guard override, on a proven place and an unprovable one
    ("C:/workspace/vouch-dev", "rm -rf build"),
    ("C:/work", "cd a || cd b; rm -rf build"),
    ("C:/scratch/j", "rm -rf build"),
    // the write wall, both lists
    ("C:/work", "echo x > C:/Users/dev/photos/p.png"),
    ("C:/work", "echo x > C:/Users/dev/notes/n.txt"),
    // per-program write scope: outside its trees, and unprovable
    ("C:/work", "git init C:/work/newrepo"),
    ("C:/work", "git init \"$SOMEWHERE/newrepo\""),
    ("C:/scratch/j", "git init C:/scratch/j/newrepo"),
    // trust zone: the allow, and the missed grant off an unprovable place
    ("C:/scratch/j", "someunknownprogramzz x"),
    ("C:/scratch/j", "cd a || cd b; someunknownprogramzz x"),
    // a redirect beside a scoped program, judged by the wall not the scope
    ("C:/scratch/j", "git init C:/scratch/j/r > C:/Users/dev/notes/log.txt"),
];

/// The sentence each prompt-table row emits, with the row it belongs to. If a
/// needle stops appearing anywhere in the probe walk, the row is no longer
/// being reached and the walk has stopped proving anything about it — which
/// is a failure, not a pass (CLAUDE.md §6: absence in a log is evidence about
/// the log).
const PROMPT_TABLE_COVERAGE: &[(&str, &str)] = &[
    ("distrust zone, place proven", "described programs ask here too"),
    ("distrust zone, place unprovable", "covers a place this command might be running in"),
    ("guard override", "[[run.guards]] entry under ="),
    ("deny_paths", "write.deny_paths covers this tree"),
    ("ask_paths", "write.ask_paths covers this tree"),
    ("write scope, target outside the trees", "this destination is outside them"),
    ("write scope, target unprovable", "cannot prove this write lands inside them"),
    ("missed grant", "cannot prove it runs there"),
    ("trust-zone allow", "allowed by run.trust_all_under"),
];

#[test]
fn every_place_derived_prompt_names_a_setting_that_turns_it_off() {
    // Every place rule on, and two places, both OUTSIDE the distrust zone on
    // purpose: judged from inside it (or from no directory at all) the zone
    // answers first for every row, and 20k copies of one sentence would reach
    // nothing else. Those two arms are what the probe list below and
    // `place_recognition_test.rs` pin instead.
    //
    //   C:/scratch/j  - inside the trust zone and the LOOSER guard override
    //   C:/workspace/vouch-dev  - inside the STRICTER guard override, outside both zones
    let cfg = place_config(true);
    for (name, rows) in common::all() {
        for place in ["C:/scratch/j", "C:/workspace/vouch-dev"] {
            let (mut unfixable, mut place_derived) = (Vec::new(), 0usize);
            for row in &rows {
                let reason = match decide_command_at(
                    &cfg,
                    "bash",
                    &row.cmd,
                    Some("C:/Users/dev"),
                    None,
                    Some(place),
                ) {
                    Decision::Ask(r) | Decision::Deny(r) => r,
                    _ => continue,
                };
                if reason.contains("run.trust")
                    || reason.contains("run.guards")
                    || reason.contains("write.ask_paths")
                    || reason.contains("write.deny_paths")
                    || reason.contains("write.scope")
                {
                    place_derived += 1;
                }
                if !names_a_setting(&reason) {
                    unfixable.push((
                        row.cmd.chars().take(90).collect::<String>(),
                        reason.lines().next().unwrap_or("").to_string(),
                    ));
                }
            }
            eprintln!(
                "{name} @ {place}: {place_derived} place-derived prompts, {} unfixable",
                unfixable.len()
            );
            for (cmd, why) in unfixable.iter().take(10) {
                eprintln!("  UNFIXABLE [{name} @ {place}]: {why}\n      {cmd}");
            }
            assert!(
                unfixable.is_empty(),
                "{name} @ {place}: {} place-rule prompts name nothing that would turn them off",
                unfixable.len()
            );
            // The walk must have exercised the rules it is about, or
            // "0 unfixable" is a statement about the walk and not about
            // vouch (CLAUDE.md §6.3).
            if name == "synthetic" {
                assert!(
                    place_derived > 0,
                    "{name} @ {place}: no place rule spoke at all, so this proves nothing"
                );
            }
        }
    }
}

#[test]
fn every_prompt_table_row_names_a_setting_and_is_still_reached() {
    let mut seen = String::new();
    for cfg in [
        place_config(true),
        place_config(false),
        asking_place_config(true),
        asking_place_config(false),
    ] {
        for (place, cmd) in PROBES {
            let reason = match decide_command_at(
                &cfg,
                "bash",
                cmd,
                Some("C:/Users/dev"),
                None,
                Some(place),
            ) {
                // An allow is not a prompt, so §5 asks nothing of it — but
                // two prompt-table rows ARE allows, and what they must name
                // is checked by `PROMPT_TABLE_COVERAGE` below, which is why
                // the reason is still collected rather than skipped.
                Decision::Allow(r) => {
                    seen.push_str(&r);
                    seen.push('\n');
                    continue;
                }
                Decision::Ask(r) | Decision::Deny(r) => r,
                Decision::Abstain => panic!("{cmd} @ {place}: abstained, so the harness decides alone"),
            };
            assert!(
                names_a_setting(&reason),
                "{cmd} @ {place}: names nothing that would turn it off\n{reason}"
            );
            seen.push_str(&reason);
            seen.push('\n');
        }
    }
    let missed: Vec<&str> = PROMPT_TABLE_COVERAGE
        .iter()
        .filter(|(_, needle)| !seen.contains(needle))
        .map(|(row, _)| *row)
        .collect();
    assert!(
        missed.is_empty(),
        "prompt-table rows no probe reaches any more, so the net says nothing about them: {missed:?}"
    );
}

/// The two rows a config cannot reach on its own: a place-scoped entry lives
/// in my-knowledge, and the engine reads knowledge from the process-global
/// `guards::in_effect()` cache — so these run in a child process through the
/// real `--hook` path (`common::hook_bash_at`), which is also where an
/// operator meets them.
#[test]
fn every_place_scoped_entry_verdict_names_a_setting_that_turns_it_off() {
    const MINE: &str = "[[program]]\nmatch = [\"probe-tool\"]\nonly_under = [\"C:/scratch/**\"]\n";
    let cfg = format!(
        "version = 1\n[lang.bash]\ndefault = \"allow\"\n[lang.bash.constructs]\nunmodeled_command = \"ask\"\n\
         [write]\ndefault = \"ask\"\nallow_paths = [\"$HOME/**\"]\n{}",
        place_rules(false)
    );
    let runs: &[(&str, &str, &str, &str)] = &[
        // (tag, cwd, command, the expected verdict) — inside its tree, proven
        // outside it, and at a place vouch cannot name.
        ("scoped_in", "C:/scratch/j", "probe-tool x", "allow"),
        ("scoped_out", "C:/work", "probe-tool x", "ask"),
        ("scoped_unprovable", "C:/scratch/j", "cd a || cd b; probe-tool x", "ask"),
    ];
    let mut seen = String::new();
    for (tag, cwd, cmd, want) in runs {
        let (verdict, reason) =
            common::hook_bash_at(&format!("property_{tag}"), MINE, &cfg, cwd, cmd);
        assert_eq!(&verdict, want, "[{tag}] {reason}");
        if verdict == "allow" {
            // An allow is not a prompt: there is nothing to turn off, and
            // demanding a setting name here would be demanding the operator
            // be told how to undo their own rule. What the spec's prompt
            // table asks of it is that it name the entry and the tree that
            // decided, so the journal says WHY it passed.
            assert!(reason.contains("probe-tool"), "[{tag}] the entry is unnamed: {reason}");
            assert!(reason.contains("C:/scratch/**"), "[{tag}] the tree is unnamed: {reason}");
        } else {
            assert!(
                names_a_setting(&reason),
                "[{tag}]: names nothing that would turn it off\n{reason}"
            );
        }
        seen.push_str(&reason);
        seen.push('\n');
    }
    // The two prompt-table rows this test exists for, still reached.
    for needle in ["allowed by your entry for", "outside them"] {
        assert!(seen.contains(needle), "no run reached {needle:?} any more:\n{seen}");
    }
}
