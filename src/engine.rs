//! The decision engine — ONE pipeline for every language.
//!
//! Languages differ only in syntax, so the only per-language thing is a
//! `Scanner`. Guards, settings lookup, precedence, and message text are shared.
//! Adding a language is: write a scanner, add it to `syntax::scanner_for`, add a
//! `[lang.<name>]` config key. Nothing here changes.
//!
//! Design rule, enforced by tests: every construct a scanner can name MUST be a
//! settable key and MUST take its verdict from configuration. No code path here
//! returns Ask or Deny from a hard-coded rule.
//!
//! The single deliberate exception is the protected-path check in `decide_file`,
//! which exists so vouch cannot be made to disarm itself.
//!
//! Message rule: a prompt says what the SETTING would allow in general, not just
//! what this one command is — turning a construct on is a standing decision, so
//! its scope has to be stated, along with the fact that guards still apply.

use crate::config::{Action, Config};
use crate::paths::{normalize, resolve_links};
use crate::protocol::Decision;

/// First lines of the protection reasons, pinned because the emission step
/// of mode-keyed shadow classifies protection asks by them — writer and
/// parser side by side so they cannot drift, the same pattern doctor's
/// rule-4 marker uses (see `parse_undeclared_option_line`).
pub const PROTECTED_FILE_LINE: &str = "vouch stopped on: protected file";
pub const WRITE_WALL_LINE: &str = "vouch stopped on: write wall";

/// Whether an ASK is a protection ask — the protected-list ask (either
/// site) or the `ask_paths` wall ask: vouch's deliberate always-fires
/// protections, the class that survives `stand_down = "keep-deny"`. Reads
/// the reason's FIRST line only; the banner, when present, is appended
/// after the reason and cannot reach it. Never called on a deny — the
/// `deny_paths` wall shares the wall first line and survives keep-deny by
/// verdict alone.
pub fn is_protection_ask(reason: &str) -> bool {
    matches!(reason.lines().next(), Some(l) if l == PROTECTED_FILE_LINE || l == WRITE_WALL_LINE)
}

/// Whether a new (action, reason) takes the recorded-reason slot from the
/// held one — a higher rank always does; at EQUAL rank a protection reason
/// takes the slot from a non-protection one, so the recorded first line
/// cannot hide that a protection rule fired beside a guard (probed
/// 2026-08-16: `rm -r` on a protected path recorded the guard line). §5's
/// "checked first and wins" now holds for the REPORT, not only the check.
fn wins_reason_slot(a: Action, reason: &str, held: &Option<(Action, String)>) -> bool {
    match held {
        None => true,
        Some((w, held_r)) => {
            rank(a) > rank(*w)
                || (rank(a) == rank(*w) && is_protection_ask(reason) && !is_protection_ask(held_r))
        }
    }
}

/// Plain-language description of a construct: what allowing it would permit
/// from now on. Help text, not policy.
fn describe(name: &str) -> &'static str {
    match name {
        "dynamic_command" => "the program name comes from a variable, so vouch cannot tell in advance which program runs",
        "dynamic_redirect" => "the output file comes from a variable, so vouch cannot tell in advance which file is written",
        "subshell" => "a nested command runs and its output is used here",
        "background" => "the command is started in the background",
        "heredoc" => "input is supplied inline in the command",
        "function_def" => "a function is defined",
        "parse_failure" => "vouch could not read the command at all",
        "unmodeled_command" => "vouch has no description of what this program does",
        "type_literal" => "a .NET type is referenced, e.g. [System.IO.File]::Delete — vouch cannot follow what the type does",
        "call_operator" => "& is used to invoke something, and vouch may not be able to resolve what",
        "method_call" => "a method is called on an object",
        "redirect" => "output is written to a file",
        "assignment" => "a variable is assigned",
        "env_assignment" => "an environment variable is assigned",
        "keyword_foreach" => "a foreach loop; vouch reads the body but not how many times or over what",
        "keyword_while" => "a while loop; vouch reads the body but not the exit condition",
        "keyword_do" => "a do loop; vouch reads the body but not the exit condition",
        "keyword_switch" => "a switch statement; vouch reads the branches but not which is taken",
        "keyword_trap" => "an error trap",
        "keyword_class" => "a class definition",
        "keyword_try" => "a try/catch block",
        "unbalanced_quotes" => "the quotes do not balance, so vouch cannot split the command reliably",
        "unresolved_path" => "a written path still contains a variable, so vouch cannot tell which file it lands on",
        "evaluated_input" => "this runs text that is fetched or read at the moment it executes, so the thing that actually runs is not in the command vouch was given",
        "splatting" => "the parameters come from a hashtable, so vouch can see which program runs but not which paths or switches it is given",
        "wrap_depth_exceeded" => "this nests one wrapper inside another more times than vouch will follow, so the layers past the limit were never scanned",
        "dynamic_call" => "this calls something whose name vouch could not resolve — a variable, or the result of another expression — so it cannot tell what actually runs",
        "callback_argument" => "this hands a function to a call that will invoke it, and vouch cannot see what that function does",
        "rebound_name" => "this uses a name whose meaning the line itself changed — a snippet rebinding it, or an assignment to a variable the shell reads when it looks a program name up — so vouch will not read it as the name's original meaning",
        "args_from_input" => "this runs a command whose arguments are read from standard input or from a file, so what that command acts on is not stated anywhere on the line",
        "wrap_unlocated" => "this program is described as running another command, and vouch could not find the command it was told to expect — so whatever runs inside the wrapper was never read",
        "wrap_ambiguous" => "a flag on this wrapper is described by nothing vouch knows, so it cannot tell whether the flag takes the next token as its value or whether the next token is the command that runs",
        "unreadable_language" => "this hands off a snippet in a language vouch has no scanner for, so it cannot tell what the snippet does — not even whether it writes anything",
        "brace_expansion" => "the shell rewrites a braced word into several words before the program runs, and this one is a form vouch does not reproduce — so the arguments the program really receives are not the ones on the line",
        _ => "vouch recognises this but cannot follow what it does",
    }
}

fn act(a: Action, reason: String) -> Decision {
    match a {
        Action::Allow => Decision::Allow(reason),
        Action::Ask => Decision::Ask(reason),
        Action::Deny => Decision::Deny(reason),
    }
}

fn rank(a: Action) -> u8 {
    match a {
        Action::Allow => 0,
        Action::Ask => 1,
        Action::Deny => 2,
    }
}

/// A construct added after a config was written has no entry in it. Rather than
/// vouch picking a default, it inherits the one the user already declared for
/// the SAME kind of blindness. `dynamic_command` is that declaration: "vouch
/// cannot tell in advance what this does."
///
/// Returns the construct whose declared value should stand in, if any.
fn inherits_from(name: &str) -> Option<&'static str> {
    match name {
        // The code being run is not in the command at all.
        "evaluated_input" => Some("dynamic_command"),
        // The arguments come from a hashtable the scanner cannot read.
        "splatting" => Some("dynamic_command"),
        // `brace_expansion` is deliberately NOT here, and the absence is the
        // decision (spec 2026-08-20 §9.3): a config that never named it gets
        // the ask, not a value borrowed from `dynamic_command`. Inheritance is
        // how a construct comes to be settled by a key nobody wrote about it,
        // and a rewrite the shell performs on a literal line is not the same
        // blindness as a name that only exists at run time.
        _ => None,
    }
}

/// The action a construct actually got AND the setting that produced it, or
/// None when the config says nothing about it.
///
/// The setting travels with the action because a prompt has to be able to name
/// what decided it (§5), and for an inherited construct that is the DONOR's
/// key, not its own — naming its own would name a setting the operator never
/// wrote and whose value would not change the answer.
fn construct_setting_for(cfg: &Config, lang: &str, name: &str) -> Option<(Action, String)> {
    let (a, key) = deciding_construct_key(cfg, lang, name)?;
    Some((a, format!("lang.{lang}.constructs.{key}")))
}

/// The bare key whose configured value decides a construct's action: its own
/// name when the operator set it, else the donor's on inheritance
/// (`inherits_from`). `None` when neither is configured — the caller then
/// falls back to Ask, still naming `name` itself, since nothing was actually
/// decided.
fn deciding_construct_key<'a>(
    cfg: &Config,
    lang: &str,
    name: &'a str,
) -> Option<(Action, &'a str)> {
    if let Some(a) = cfg.named_construct_action(lang, name) {
        return Some((a, name));
    }
    let donor = inherits_from(name)?;
    let a = cfg.named_construct_action(lang, donor)?;
    Some((a, donor))
}

/// The action for a construct, falling back to an inherited declaration
/// before falling back to Ask — paired with the KEY that decided it (the
/// donor's on inheritance), so a caller can build a reason naming the setting
/// that actually turns the prompt off (CLAUDE.md §5) rather than a key the
/// operator never wrote and whose value would not change the answer.
fn construct_action_for(cfg: &Config, lang: &str, name: &str) -> (Action, String) {
    deciding_construct_key(cfg, lang, name)
        .map(|(a, key)| (a, key.to_string()))
        .unwrap_or_else(|| (Action::Ask, name.to_string()))
}

/// The prompt text for a construct, exposed so a test can assert that EVERY
/// construct names its own setting — the claim criterion 2 actually makes.
pub fn construct_reason_for(lang: &str, name: &str) -> String {
    construct_reason(lang, name)
}

/// `name` is the key the reason should NAME — callers reached through
/// `construct_action_for` pass the deciding key it returned (the donor's on
/// inheritance), not the construct that was actually detected, so the
/// setting this prints is one that genuinely changes the answer.
fn construct_reason(lang: &str, name: &str) -> String {
    format!(
        "vouch stopped on: {name}\n  \
         what that means: {}\n  \
         to allow this permanently, set lang.{lang}.constructs.{name} = \"allow\"\n  \
         that setting applies to EVERY command using this, from now on\n  \
         guards still apply — allowing this does not allow what a command does",
        describe(name)
    )
}

/// The sentence recorded in `grants` when a construct's OWN setting is what
/// allowed a line — the allow-side mirror of `construct_reason`, needed
/// because `worst` drops an Allow reason on the floor (see the guard-override
/// site's identical note): the final match only reads `grants`/`by_setting`
/// for an Allow verdict, so a construct that decided Allow — including one
/// that decided it by INHERITANCE, `key` then naming the donor — has to say
/// so here or the reason silently falls back to "allowed by vouch policy"
/// and the setting that actually decided the line is never named (CLAUDE.md
/// §5's "name the decider", extended to allows).
fn construct_grant(lang: &str, key: &str) -> String {
    format!("allowed by lang.{lang}.constructs.{key} = \"allow\" — {}", describe(key))
}

/// Folds every `(key, detail)` construct the wrapper-EXPANSION walk raised
/// into `worst`, attributed to the HOST language — same shape as the
/// parse-failure and wrap-depth channels just above, kept as its own
/// function so a synthetic entry can drive the routing directly in a test
/// without a real producer (none lands with this change; see the `Expanded`
/// struct doc).
fn fold_expansion_constructs(
    cfg: &Config,
    lang: &str,
    constructs: &[(String, String)],
    worst: &mut Option<(Action, String)>,
    grants: &mut Vec<String>,
) {
    for (key, detail) in constructs {
        let (a, setting_key) = construct_action_for(cfg, lang, key);
        if a == Action::Allow {
            remember(grants, construct_grant(lang, &setting_key));
        }
        let reason = format!("{}\n  {detail}", construct_reason(lang, &setting_key));
        if worst.as_ref().map_or(true, |(w, _)| rank(a) > rank(*w)) {
            *worst = Some((a, reason));
        }
    }
}

/// The action, as the config spells it — the word an operator would type.
fn action_word(a: Action) -> &'static str {
    match a {
        Action::Allow => "allow",
        Action::Ask => "ask",
        Action::Deny => "deny",
    }
}

/// `overrode` is the sentence a place-scoped override wrote about itself, or
/// `None` when the global `[guards]` action decided. It REPLACES the setting
/// line rather than sitting beside it: when an override decided,
/// `guards.<name>` is not the setting that turns this prompt off, and naming it
/// would hand the operator an off-switch that does not switch anything off
/// (CLAUDE.md §5).
fn guard_reason(hit: &crate::guards::Hit, a: Action, overrode: Option<&str>) -> String {
    format!(
        "vouch stopped on: {} (guard)\n  \
         command: {}\n  \
         rule source: {}\n  \
         guards ask every time on purpose — approving this once does not create a rule\n  \
         {}",
        hit.guard,
        hit.detail,
        if hit.source.trim().is_empty() {
            "unspecified"
        } else {
            hit.source.as_str()
        },
        match overrode {
            Some(s) => format!("setting: {s}"),
            None => format!(
                "setting: guards.{} (currently \"{}\")",
                hit.guard,
                action_word(a)
            ),
        }
    )
}

/// The whole decision, for any language.
pub fn decide_command(cfg: &Config, lang: &str, src: &str) -> Decision {
    decide_command_in(cfg, lang, src, None, None)
}

/// Same, with the context needed to check file writes the command performs.
pub fn decide_command_in(
    cfg: &Config,
    lang: &str,
    src: &str,
    home: Option<&str>,
    project_root: Option<&str>,
) -> Decision {
    decide_command_at(cfg, lang, src, home, project_root, None)
}

/// With the working directory, so relative write targets resolve. Without it,
/// `rm -f scripts/x.py` looks like a path outside every scope — a real false
/// positive found by diffing against live traffic.
///
/// `None` here means the CALLER has no directory to offer and is content for
/// a relative target to be judged as written — the pre-cwd behaviour every
/// `decide_command`/`decide_command_in` caller still gets. It does NOT mean
/// "the directory is unknown": for that, which is a hole and must ask, see
/// `decide_command_in_unknown_dir`.
pub fn decide_command_at(
    cfg: &Config,
    lang: &str,
    src: &str,
    home: Option<&str>,
    project_root: Option<&str>,
    cwd: Option<&str>,
) -> Decision {
    decide_command_from(cfg, lang, src, home, project_root, start_state(cwd))
}

/// For a caller that knows the command runs SOMEWHERE it cannot name, and
/// says why. Every relative destination is then unresolvable rather than
/// judged as written, which is the difference between a verdict about the
/// command and a verdict about wherever the vouch process happens to have
/// been started.
///
/// This is what a tool snippet gets when its `[[tool]]` entry makes no
/// `cwd_from_call` claim (spec 2026-08-05 §Schema rule 4). It is deliberately
/// a separate entry point rather than a change to what `cwd: None` means:
/// `decide_command_in` callers — `vouch explain`'s library twin, the corpus
/// replay, the property walk — genuinely have no directory and have judged
/// relative targets as written since before working directories were plumbed
/// through, and turning that into an ask would change what those numbers
/// measure without anyone deciding to.
pub fn decide_command_in_unknown_dir(
    cfg: &Config,
    lang: &str,
    src: &str,
    home: Option<&str>,
    project_root: Option<&str>,
    cause: &str,
) -> Decision {
    decide_command_from(
        cfg,
        lang,
        src,
        home,
        project_root,
        CdState::Unknown(cause.to_string()),
    )
}

/// The directory a command line STARTS in, before any directory change in it.
fn start_state(cwd: Option<&str>) -> CdState {
    match cwd {
        Some(d) if !d.is_empty() => CdState::Known(d.to_string()),
        _ => CdState::NoDirectory,
    }
}

/// How many readings of one line's ambiguous wrappers vouch will judge before
/// it stops enumerating and says so.
///
/// Past this, the line has more undescribed wrapper flags than a verdict can
/// meaningfully be composed from, and enumerating further is guessing at
/// scale rather than at one token: `wrap_unlocated` says the walk could not
/// place the wrapped command, which is exactly what has happened.
const MAX_WRAPPER_READINGS: usize = 8;

/// The decision for one line, over EVERY reading of its ambiguous wrappers.
///
/// An undescribed dash-led token in a wrapper's arguments leaves the wrapped
/// command's head genuinely ambiguous — `command --unknown rm -rf d` either
/// hands `rm` to `--unknown` as a value or runs it. Picking one reading is a
/// guess either way, so vouch judges both and composes:
///
/// - every reading agreed → that verdict, reasoned by the reading the entry's
///   own vocabulary implies (the all-zero one), since the vocabulary never
///   says the undescribed flag takes a value;
/// - the readings disagreed → the most restrictive verdict, never lowered,
///   carrying `wrap_ambiguous` to name the flag that caused the split and the
///   key that would describe it.
///
/// A superseded design removed the wrapped command from judgement altogether
/// when its position was ambiguous; that was found unsound, because the
/// reading it dropped is the one that runs.
fn decide_command_from(
    cfg: &Config,
    lang: &str,
    src: &str,
    home: Option<&str>,
    project_root: Option<&str>,
    start: CdState,
) -> Decision {
    // Enumerated breadth-first over choice PREFIXES: one pass under a prefix
    // reports every fork it met, so a fork beyond the prefix's length is one
    // nobody has chosen yet and splits into its own readings. Every split
    // consumes at least one more argument token, so this terminates on its
    // own; the cap is about how many verdicts are worth composing, not about
    // termination.
    let mut frontier: Vec<Vec<usize>> = vec![Vec::new()];
    let mut done: Vec<(Vec<usize>, Decision)> = Vec::new();
    let mut split: Option<crate::guards::ForkPoint> = None;
    while let Some(prefix) = frontier.pop() {
        let (verdict, points) =
            judge_once(cfg, lang, src, home, project_root, start.clone(), &prefix);
        match points.iter().enumerate().skip(prefix.len()).find(|(_, p)| p.factor > 1) {
            Some((at, point)) => {
                if split.is_none() {
                    split = Some(point.clone());
                }
                for k in 0..point.factor {
                    let mut next = prefix.clone();
                    // Forks between the prefix's end and this one offered no
                    // choice, so reading 0 is the only reading they have.
                    next.resize(at, 0);
                    next.push(k);
                    frontier.push(next);
                }
            }
            None => done.push((prefix, verdict)),
        }
        if done.len() + frontier.len() > MAX_WRAPPER_READINGS {
            let detail = match &split {
                Some(p) => format!(
                    "`{}` and the flags after it leave more readings of `{}`'s arguments than \
                     vouch will judge",
                    p.token, p.program
                ),
                None => "this line has more wrapper readings than vouch will judge".to_string(),
            };
            // Composed with a real judgement, never returned on its own.
            // Returning `act(a, …)` here (fix round 1) meant that with this
            // construct set to "allow" the WHOLE LINE allowed before guards,
            // write rules or protected paths were consulted — while the
            // reason it printed still said "guards still apply". Every
            // sibling channel folds instead: `wrap_depth_exceeded`, the
            // closest one, is a cap on this same walk and leaves the guards
            // to decide. The reading judged here is the one the entries'
            // vocabularies imply, which is the same reading the agreement
            // path speaks with.
            let (base, _) = judge_once(cfg, lang, src, home, project_root, start.clone(), &[]);
            let (a, key) = construct_action_for(cfg, lang, "wrap_unlocated");
            let reason = format!("{}\n  {detail}", construct_reason(lang, &key));
            return match a {
                // The construct itself is allowed, so what the walk DID find
                // decides the line — and where that is an allow, it says
                // which setting let the cap through, the same sentence
                // `construct_grant` records on every other channel.
                Action::Allow => match base {
                    Decision::Allow(_) => {
                        with_extra_reason(base, &construct_grant(lang, &key))
                    }
                    stricter => stricter,
                },
                _ if rank(a) > decision_rank(&base) => act(a, reason),
                _ => with_extra_reason(base, &reason),
            };
        }
    }

    // The all-zero reading always exists: every split pushes a `0` branch, and
    // extending an all-zero prefix with `0` keeps it all-zero. `expect` rather
    // than a fallback, because a missing one would mean the enumeration above
    // stopped reporting its own choices.
    let (_, vocabulary_reading) = done
        .iter()
        .find(|(picks, _)| picks.iter().all(|k| *k == 0))
        .expect("the reading every entry's vocabulary implies is always enumerated");
    let top = done.iter().map(|(_, d)| decision_rank(d)).max().unwrap_or(0);
    let disagreed = done.iter().any(|(_, d)| decision_rank(d) != top);
    if !disagreed {
        return vocabulary_reading.clone();
    }
    // Deterministic across runs: the frontier is a stack, so the order
    // verdicts land in `done` depends on how the splits interleaved. Choosing
    // by the picks vector makes the reason the same every time.
    let mut strictest: Vec<&(Vec<usize>, Decision)> =
        done.iter().filter(|(_, d)| decision_rank(d) == top).collect();
    strictest.sort_by(|a, b| a.0.cmp(&b.0));
    let restrictive = strictest[0].1.clone();
    let Some(point) = split else { return restrictive };
    // The ambiguity note is itself settable (§5): turning it off leaves the
    // restrictive verdict standing and its own reason speaking, and turning it
    // to deny raises the line, which is the only direction a construct is ever
    // allowed to move a verdict it did not cause.
    let (a, key) = construct_action_for(cfg, lang, "wrap_ambiguous");
    let detail = format!(
        "`{}` is described by nothing vouch knows about `{}`, so it cannot tell whether the \
         token after it is that flag's value or the command that runs — both readings were \
         judged and the stricter answer is the one above\n  to remove the ambiguity, describe \
         `{}` in my-knowledge.toml under that program's `value_options` (it takes a value) or \
         `no_value_options` (it does not)",
        point.token, point.program, point.token
    );
    match a {
        // Allowed — and the allow SAYS so. Every other construct channel
        // records the grant that let a line through, so an operator reading
        // an allow can see which setting decided it; this one returned the
        // readings' own verdict silently, which is the same prompt-with-no-
        // named-setting defect in the allow direction (CLAUDE.md §5). Two
        // independent cleanup reviews found it in the same pass.
        Action::Allow => with_extra_reason(restrictive, &construct_grant(lang, &key)),
        _ if rank(a) > decision_rank(&restrictive) => {
            act(a, format!("{}\n  {detail}", construct_reason(lang, &key)))
        }
        _ => with_extra_reason(restrictive, &format!("{}\n  {detail}", construct_reason(lang, &key))),
    }
}

/// The strictness of a whole decision, on the same scale `rank` gives an
/// `Action`. Abstain ranks WITH ask: it is what vouch says when it will not
/// answer, and a reading that will not answer must never be composed as if it
/// had allowed.
fn decision_rank(d: &Decision) -> u8 {
    match d {
        Decision::Allow(_) => rank(Action::Allow),
        Decision::Ask(_) | Decision::Abstain => rank(Action::Ask),
        Decision::Deny(_) => rank(Action::Deny),
    }
}

/// Adds a second paragraph to a decision's reason, keeping the verdict.
/// `Abstain` carries no reason to add one to, so it is returned unchanged.
fn with_extra_reason(d: Decision, extra: &str) -> Decision {
    match d {
        Decision::Allow(r) => Decision::Allow(format!("{r}\n  {extra}")),
        Decision::Ask(r) => Decision::Ask(format!("{r}\n  {extra}")),
        Decision::Deny(r) => Decision::Deny(format!("{r}\n  {extra}")),
        Decision::Abstain => Decision::Abstain,
    }
}

/// The whole decision, under ONE reading of every ambiguous wrapper.
///
/// `picks` selects a reading at each fork the walk meets, in visit order; an
/// empty vector takes the reading each entry's own vocabulary implies. The
/// fork points it met come back alongside the verdict, so the driver above
/// can enumerate the readings it has not tried yet.
fn judge_once(
    cfg: &Config,
    lang: &str,
    src: &str,
    home: Option<&str>,
    project_root: Option<&str>,
    start: CdState,
    picks: &[usize],
) -> (Decision, Vec<crate::guards::ForkPoint>) {
    let mut fork = crate::guards::ForkCursor::new(picks);
    let scanner = match crate::syntax::scanner_for(lang) {
        Some(s) => s,
        // A language with no scanner is not something vouch can judge.
        None => return (Decision::Abstain, Vec::new()),
    };

    let mut scan = match scanner.scan(src) {
        Ok(s) => s,
        Err(e) => {
            let reason = format!(
                "vouch could not read this {lang} command ({e})\n  \
                 either the command is malformed, or vouch's parser has a gap — \
                 this is not a judgement about what the command does\n  \
                 setting: lang.{lang}.constructs.parse_failure"
            );
            return (act(cfg.construct_action(lang, "parse_failure"), reason), Vec::new());
        }
    };

    let mut worst: Option<(Action, String)> = None;

    // Variables assigned in this same text. A later assignment to the same
    // name wins, which is the order the shell would apply — poisoned (`None`)
    // entries included, so a name whose LAST write is poisoned stays poisoned
    // even if an earlier write in the same text was readable.
    let mut assigned: std::collections::HashMap<String, Option<String>> =
        std::collections::HashMap::new();
    for (k, v) in &scan.assignments {
        assigned.insert(k.clone(), v.clone());
    }
    // A name whose last same-line write vouch could not read must resolve to
    // NOTHING — never fall through to the judging process's own environment
    // (M2.122). The two cases a lookup can land in are different questions:
    // the name is ABSENT from this text's own assignments (fall through to
    // the environment, unchanged from before), or it is PRESENT with a
    // poisoned last write (answer `None` outright, and stop — env is not
    // consulted for a name this text itself just tried and failed to set).
    let lookup_assigned = |n: &str| match assigned.get(n) {
        Some(v) => v.clone(),
        None => std::env::var(n).ok(),
    };

    // 0. Resolve the PROGRAM NAME the same way a written path is resolved.
    //
    // `PY="C:/…/python.exe" "$PY" -c "…"` states the program one token earlier,
    // and vouch was reading the head as the literal text `"$PY"` — unknown
    // program, no wrapper, snippet never examined. Written paths have been
    // resolved this way since 2026-07-25; heads were not, so the same command
    // got two different answers depending on which half you looked at.
    for c in scan.commands.iter_mut() {
        let mut h = crate::paths::unquote(&c.head).to_string();
        for _ in 0..4 {
            let next = crate::paths::expand_env_with(&h, &lookup_assigned);
            if next == h {
                break;
            }
            h = next;
        }
        c.head = crate::paths::unquote(&h).to_string();
    }

    // 1. Guards — what the command DOES. Same set for every language.
    //
    // `collect_expanded` (below) walks `scan.commands` one top-level command
    // at a time and expands wrappers, so every command that comes out of a
    // wrapper keeps the ORDER of the command it came out of: a wrapped
    // snippet has no position in the outer sequence of its own, so it takes
    // the wrapper's. Expanding the whole list in one call and then indexing
    // `scan.order` by position in the RESULT would read some other command's
    // order — `scan.order` is parallel to `scan.commands`, never to the
    // expanded list.
    let kb = crate::guards::in_effect();
    // How many layers of wrapper nesting the walk below scans before it stops
    // and reports rather than silently dropping the rest (M2.55): the
    // operator's own `lang.<name>.wrap_depth`, or the built-in default when
    // they have not set one.
    let caps = |l: &str| cfg.lang(l).and_then(|lc| lc.wrap_depth).unwrap_or(4);
    let Expanded {
        cmds: all_cmds,
        orders: all_orders,
        from_snippet,
        langs: all_langs,
        holds_input: all_holds_input,
        args_from_input: all_args_from_input,
        args_complete: all_args_complete,
        snippets,
        wrap_depth_exceeded,
        parse_failures,
        constructs: expansion_constructs,
        inherited_run_dir: all_inherited,
    } = collect_expanded(kb, &scan, lang, &caps, &mut fork);

    // Heredocs captured in THIS text that the locator (inside
    // `collect_expanded` -> `expand_wrappers_with_sources`) did not consume
    // keep today's `heredoc` construct — the same predicate the locator used
    // to decide whether to consume it, applied here to decide whether to
    // mark it. A consumed heredoc's body already went through `scan_snippet`
    // as a normal wrapped snippet (it is in `snippets` above), so it is not
    // touched again here — marking it too would double the ask channel §4
    // forbids. Computed as a plain bool first (rather than calling
    // `scan.note` from inside a loop borrowing `scan.heredocs`) since `note`
    // needs `&mut scan` and this walk needs `&scan` for the whole pass.
    let any_heredoc_unconsumed = scan.heredocs.iter().any(|heredoc| {
        scan.commands
            .get(heredoc.cmd_index)
            .is_some_and(|consumer| crate::guards::heredoc_feeds(kb, consumer, heredoc).is_none())
    });
    if any_heredoc_unconsumed {
        scan.note("heredoc");
    }

    // 1a. Where each of those commands RUNS.
    //
    // Resolve a token the way the shell itself would:
    //   1. drop the quotes the parser kept on the token
    //   2. substitute variables assigned literally in this same command
    //   3. substitute variables set in the environment vouch shares
    // to a fixed point, so `$a = "C:/x"; $b = "$a/y"; > "$b/z"` resolves.
    // Bounded: a self-referential assignment must not spin. What is left
    // after that is genuinely not knowable in advance.
    //
    // (`assigned` is built once above, before heads are resolved, and is the
    // same map used here — one resolution rule for names and paths.)
    let resolve = |raw: &str| -> String {
        let mut t = crate::paths::unquote(raw).to_string();
        for _ in 0..4 {
            let next = crate::paths::expand_env_with(&t, &lookup_assigned);
            if next == t {
                break;
            }
            t = next;
        }
        crate::paths::unquote(&t).to_string()
    };

    // Where a RELATIVE write actually lands.
    //
    // `cd /c/Users/dev/.claude && echo x > settings.json` writes the protected
    // file, but resolving `settings.json` against the hook's own working
    // directory said it landed somewhere harmless, and it was allowed. The
    // destination is stated in plain sight one command earlier, exactly like a
    // literal assignment.
    //
    // Every destination is judged in the directory it actually lands in: the
    // directory a run-dir flag sent that one command to, else the directory
    // state at that command's own position in the sequence.
    //
    // It sits HERE, above the guard, write and recognition passes, because
    // "which directory is this command in" is no longer a question only a
    // write asks: recognition asks it per occurrence too (M2.46), and a place
    // rule will ask it of every command in the line. Building it twice would
    // be two answers to one question. Nothing about the write pass changes:
    // `home` is now handed over as the `Option` it already was, and the write
    // pass still refuses to run without one.
    let timeline = cd_timeline(
        &all_cmds,
        &all_orders,
        &from_snippet,
        &all_langs,
        &resolve,
        home,
        &start,
    );

    // 1b. A wrapped snippet is a whole script, not just a list of program
    // names. Its redirects and its own constructs have to be merged in, or
    // `cmd /c "echo x > <protected>"` writes a file that no rule ever sees —
    // guards looked through the wrapper while redirects did not.
    // Code vouch has no parser for. It cannot say what the code does, but it
    // CAN see a protected path spelled out inside it — and the protected rule
    // is the one rule with no setting behind it, so letting an unreadable
    // snippet name that file and pass would make the guarantee untrue.
    // `python -c "open('…/settings.json','w')"` was ALLOW until 2026-07-25.
    //
    // Runs for EVERY snippet language, not only `"opaque"` — kept
    // permanently, not just until every language has a scanner. For a
    // scanned language this is redundant in the limit (a real parse of the
    // same text sees the same path), but harmless: at worst a false ask on a
    // mention that is not actually a write. What it buys is the window a
    // scanned-but-not-yet-described language would otherwise leave open — a
    // registered scanner with no entries for it yet still has SOMETHING
    // looking at protected names inside its snippets.
    if let Some(home) = home {
        for (_plang, psrc, _) in &snippets {
            if let Some(hit) = mentions_protected(cfg, home, project_root, psrc) {
                let reason = format!(
                    "{PROTECTED_FILE_LINE}\n  {hit}\n  \
                     this file controls vouch itself, so no write.allow_paths entry can \
                     open it — the protected list is checked first and wins\n  \
                     the only way to change that is to take this path out of \
                     [protected] in your own config, deliberately\n  \
                     (named inside code vouch cannot read, so it cannot tell whether \
                     the code writes it)"
                );
                if wins_reason_slot(Action::Ask, &reason, &worst) {
                    worst = Some((Action::Ask, reason));
                }
            }
        }
    }

    // Constructs found INSIDE a wrapped snippet, kept as (language, name)
    // pairs rather than merged into `scan.constructs` — each resolves under
    // its OWN language below (channel 2), never the host's: a python
    // `dynamic_call` nested in a bash line is settable as
    // `lang.python.constructs.dynamic_call`, not bash's (spec's
    // shared-vocabulary paragraph, "on every path").
    let mut snippet_constructs: Vec<(String, String)> = Vec::new();
    for (plang, psrc, porder) in &snippets {
        // A language the registry has no scanner for `continue`s here —
        // recorded divergence from the route path, which asks explicitly
        // instead (`route::decide_snippet`'s `unreadable_language`). This
        // site sees only snippets already reached by wrapper expansion, most
        // of which are `"opaque"` by design (nothing claims a scanner for
        // it), so silently skipping the rest of them is not this task's
        // hole to close — that is ROADMAP M2.73.
        let Some(ps) = crate::syntax::scanner_for(plang) else {
            continue;
        };
        // A scan failure here is the SAME text `scan_snippet` already
        // attempted while expanding wrappers — `snippets` is built from the
        // exact source list `scan_snippet` pushes into — so a failure is the
        // identical failure channel 1 (`parse_failures`, folded below)
        // already turns into an ask naming
        // `lang.<plang>.constructs.parse_failure`. Nothing silently
        // vanishes on `Err`: there is simply no redirect or construct list
        // to read from text that did not parse, and the ask already says so.
        if let Ok(inner) = ps.scan(psrc) {
            // A redirect inside a wrapped snippet writes wherever the WRAPPER
            // command runs — the snippet has no position of its own, so it
            // takes the wrapper's (spec §3.5). Giving these `Unordered`
            // instead would make every wrapped write unresolvable even when
            // the wrapper's own place in the sequence is plain.
            scan.redirect_order
                .extend(std::iter::repeat(porder.clone()).take(inner.redirect_targets.len()));
            scan.redirect_targets.extend(inner.redirect_targets);
            for c in inner.constructs {
                snippet_constructs.push((plang.clone(), c));
            }
            // A heredoc captured INSIDE this snippet's own text, carried up
            // by this same re-scan: the identical unconsumed-marking rule
            // applied at the top level above, but for a heredoc nested one or
            // more snippet boundaries deep. Without this, a heredoc fed to an
            // undeclared consumer inside a wrapped snippet (`sh -c "consumer
            // <<'EOF' ... EOF"`) loses its marker entirely — captured by the
            // scanner, never consumed by the locator (the consumer is
            // undeclared), and never marked (nothing else re-reads it).
            for heredoc in &inner.heredocs {
                if let Some(consumer) = inner.commands.get(heredoc.cmd_index) {
                    if crate::guards::heredoc_feeds(kb, consumer, heredoc).is_none() {
                        snippet_constructs.push((plang.clone(), "heredoc".to_string()));
                    }
                }
            }
        }
    }
    // Guards resolve per HIT, not per guard NAME, because a `[[run.guards]]`
    // override answers per place: `rm -rf a && cd <tree> && rm -rf b` trips one
    // guard from two directories, and collapsing them to one hit before the
    // place is known throws away the difference. `check_each` therefore hands
    // over every hit with the index of the command that tripped it, and the
    // whole set is resolved before anything is said about it.
    let here_home = home.unwrap_or("");
    // What a PLACE recognised, in the words the allow reason uses. Declared
    // here rather than at the recognition pass because a place rule can now let
    // a line through from TWO passes — a guard override that loosens, and a
    // zone or scoped entry — and an allow that names only one of them reads as
    // one rule deciding what two rules decided.
    let mut grants: Vec<String> = Vec::new();
    let mut resolved: Vec<(crate::guards::Hit, Action, Option<String>)> = Vec::new();
    for (i, hit) in crate::guards::check_each(kb, &all_cmds) {
        // Where this one command runs: its position in the line, then its own
        // run-dir flag. Same call the write pass and the recognition pass make
        // — one command, one run place.
        let base = timeline.base_at(
            all_orders.get(i).unwrap_or(&crate::syntax::Order::Unordered),
            all_cmds.get(i).and_then(|c| c.chain.as_ref()),
            &start,
        );
        let (state, _) =
            run_dir_place(kb, &all_cmds[i], &base, inherited_at(&all_inherited, i), &resolve);
        let (a, overrode) = resolve_guard_action(
            cfg,
            &hit.guard,
            &place_of(&state, here_home),
            unproven_cause(&state),
            here_home,
            project_root,
        );
        // An override that LOOSENS is what let this hit through, and `worst`
        // drops an Allow on the floor — so the sentence would be lost with it.
        // It goes in the grant list instead, where the allow reason reads it.
        // `remember` is what dedupes, exactly as it does for a zone.
        if let (Action::Allow, Some(s)) = (a, &overrode) {
            remember(&mut grants, format!("allowed by {s}"));
        }
        resolved.push((hit, a, overrode));
    }
    // The guard pass's own verdict: the strictest action any hit resolved to,
    // reasoned about by the FIRST hit that reached it — which is what the old
    // dedupe-then-`rank(a) > rank(*w)` walk produced, and stays byte-identical
    // when no override is configured.
    if let Some(top) = resolved.iter().map(|(_, a, _)| *a).max_by_key(|a| rank(*a)) {
        let (hit, _, overrode) = resolved.iter().find(|(_, a, _)| *a == top).unwrap();
        let mut reason = guard_reason(hit, top, overrode.as_deref());
        // [review] Every OTHER guard a place rule decided at this same action
        // names itself too. One line can trip two overridden guards, and a
        // prompt that named only the first left the operator turning off a rule
        // that was not the whole answer — the same "name every decider" the
        // zone pass settled for allows. Only OVERRIDDEN guards are added, so a
        // prompt with no place rule in it is untouched.
        let mut named: Vec<&str> = vec![hit.guard.as_str()];
        for (h, a, o) in &resolved {
            let (Some(s), true) = (o, *a == top) else {
                continue;
            };
            if named.contains(&h.guard.as_str()) {
                continue;
            }
            named.push(h.guard.as_str());
            reason.push_str(&format!(
                "\n  this line also trips {} (guard), and a place rule decided that too\n  \
                 setting: {s}",
                h.guard
            ));
        }
        if worst.as_ref().map_or(true, |(w, _)| rank(top) > rank(*w)) {
            worst = Some((top, reason));
        }
    }

    // 1c. File writes performed BY the command — redirect targets and the
    // arguments the knowledge file says a program writes to. Without this,
    // `echo x > C:/Windows/y` and `cp a C:/Windows/b` skip [write] entirely,
    // which they did until 2026-07-25.
    if let (Some(home), true) = (home, !scan.commands.is_empty() || !scan.redirect_targets.is_empty())
    {
        // Every destination, already placed in the directory it lands in,
        // with the run-dir provenance to show when a run-dir flag decided it,
        // and the program that produced it. That last one is what a
        // `[[write.scope]]` rule is matched against, so it has to survive the
        // whole walk — targets used to be stripped to bare paths here, and a
        // scope rule reaching `decide_file` with no program to match would be
        // a rule that could never fire.
        let mut targets: Vec<(String, Option<String>, By)> = Vec::new();
        let mut unplaced: Vec<Unplaced> = Vec::new();

        // Which `[[write.scope]]` rule claims a program's write, if any. One
        // definition, so the two arms that answer for an UNPROVABLE
        // destination and `decide_file_for`, which answers for a provable one,
        // cannot end up disagreeing about which rule governs a command.
        let scope_for = |by: &By| {
            by.as_ref()
                .and_then(|(h, s, t)| cfg.write.scope.iter().find(|sc| sc.names(h, s.as_deref(), t)))
        };

        // Redirects belong to the shell, not to the program: they are never
        // resolved against a run-dir flag's directory (spec §3.5), and for the
        // same reason no write scope judges them — `git init > log.txt` writes
        // that log through the shell, whoever the program is. Their producing
        // program is `None`.
        for (i, t) in scan.redirect_targets.iter().enumerate() {
            let order = scan
                .redirect_order
                .get(i)
                .cloned()
                .unwrap_or(crate::syntax::Order::Unordered);
            // A redirect hangs off a command, and its chain position is that
            // command's. This list is not command-parallel, so the owner is
            // found by the one thing they provably share: their SEQUENCE
            // position. Every stage of one pipeline carries the same chain
            // position, so which stage is found does not matter; a redirect
            // whose position is unprovable finds nothing and folds only an
            // unconditional mover, which is the fail-closed direction.
            let owner_chain = all_orders
                .iter()
                .position(|o| *o == order)
                .and_then(|j| all_cmds.get(j))
                .and_then(|c| c.chain.as_ref());
            match place(&resolve(t), &timeline.base_at(&order, owner_chain, &start)) {
                Placed::At(p) => targets.push((p, None, None)),
                Placed::Nowhere(cause) => unplaced.push(Unplaced {
                    generic: where_it_lands(lang, &cause, Some(t)),
                    cause,
                    what: Some(t.clone()),
                    by: None,
                }),
            }
        }

        for (i, c) in all_cmds.iter().enumerate() {
            let wt = crate::guards::written_paths(kb, c);
            if wt.paths.is_empty() && !wt.run_dir_dest && wt.unknowable.is_empty() {
                continue;
            }
            // Which program produced these destinations, read the SAME way
            // `written_paths` just derived them: `base_name` for the head (the
            // normalisation the knowledge file is matched on), `subcommand_of`
            // for the verb, and `then_of` for the verb's second word — the
            // position `sub_write.then` is matched at, which is what makes a
            // `git worktree add` scope govern exactly the writes the `git
            // worktree add` destination walk found. A scope rule matched on a
            // second, slightly different reading of any of the three would
            // govern a different set of commands than the one whose writes
            // vouch derived.
            let sub = crate::guards::subcommand_of(kb, c);
            let by: By = Some((
                crate::guards::base_name(&c.head),
                sub.map(str::to_string),
                crate::guards::then_of(kb, c),
            ));

            // A token after the subcommand that no entry describes: vouch
            // cannot tell whether it consumes the token after it, so it
            // cannot say which argument is the destination. Naming the token
            // is the whole answer — guessing either way is the wrong ALLOW
            // this changeset exists to remove.
            let mut named: Vec<&String> = Vec::new();
            for tok in &wt.unknowable {
                if named.contains(&tok) {
                    continue;
                }
                named.push(tok);
                unplaced.push(Unplaced {
                    generic: which_token(lang, tok, sub.unwrap_or("")),
                    cause: format!(
                        "'{tok}' after '{}' is not described, so vouch cannot tell which \
                         argument is the destination",
                        sub.unwrap_or("")
                    ),
                    what: None,
                    by: by.clone(),
                });
            }

            let order = all_orders
                .get(i)
                .cloned()
                .unwrap_or(crate::syntax::Order::Unordered);
            let here = timeline.base_at(&order, c.chain.as_ref(), &start);
            let paths: Vec<String> = wt.paths.iter().map(|p| resolve(p)).collect();
            // A run-dir flag only has to resolve when something depends on
            // it. `git -C a -C b status` writes nothing, and a read must
            // never gain a standing prompt.
            let needs_base = wt.run_dir_dest
                || paths.iter().any(|p| is_relative(p) || drive_relative(p).is_some());
            // The run-dir resolution itself is `run_dir_place`, shared with the
            // guard and recognition passes so one command has ONE run place.
            // The `needs_base` gate stays here and only here: it is a WRITE
            // concern (`git -C a -C b status` writes nothing, and a read must
            // never gain a standing prompt), whereas a place rule asks where
            // every command runs whether it writes or not.
            let (base, provenance) = if !needs_base {
                (here.clone(), None)
            } else {
                run_dir_place(kb, c, &here, inherited_at(&all_inherited, i), &resolve)
            };

            if wt.run_dir_dest {
                // The destination IS the directory the command runs in —
                // there is no path in the command to fall back on.
                match &base {
                    CdState::Known(d) => targets.push((d.clone(), provenance.clone(), by.clone())),
                    CdState::Unknown(cause) => unplaced.push(Unplaced {
                        generic: where_it_lands(lang, cause, None),
                        cause: cause.clone(),
                        what: None,
                        by: by.clone(),
                    }),
                    CdState::NoDirectory => unplaced.push(Unplaced {
                        generic: where_it_lands(lang, NO_CWD, None),
                        cause: NO_CWD.to_string(),
                        what: None,
                        by: by.clone(),
                    }),
                }
            }
            // Whether THIS program's destination can be on another machine.
            // Per entry, never a global shape test (M2.131.4): `host:d` is
            // remote for `scp` and is a local file with a colon in its name
            // for `cp` — on NTFS, an alternate data stream of the file before
            // the colon, which is a real write.
            let clang = all_langs.get(i).map(String::as_str).unwrap_or(lang);
            let remote_ok = crate::guards::entry_for(kb, &c.head, clang)
                .is_some_and(|e| e.remote_dest);
            for p in paths {
                if remote_ok && is_remote_spec(&p) {
                    continue;
                }
                match place(&p, &base) {
                    Placed::At(t) => targets.push((
                        t,
                        if is_relative(&p) { provenance.clone() } else { None },
                        by.clone(),
                    )),
                    Placed::Nowhere(cause) => unplaced.push(Unplaced {
                        generic: where_it_lands(lang, &cause, Some(&p)),
                        cause,
                        what: Some(p.clone()),
                        by: by.clone(),
                    }),
                }
            }
        }

        for u in unplaced {
            // The action AND the setting behind it: a scoped destination whose
            // setting is stricter than the scope's ask is decided by that
            // setting, and the prompt has to name it rather than the scope.
            let declared = construct_setting_for(cfg, lang, "unresolved_path");
            let generic = declared.as_ref().map_or(Action::Ask, |(a, _)| *a);
            // A destination vouch cannot place, produced by a program a
            // `[[write.scope]]` rule governs: the scope is why this one
            // matters, so the ask names the rule and keeps the walk's cause
            // instead of the generic text (spec prompt table, "write scope,
            // target unprovable"). Ask is a FLOOR here, not a choice — a rule
            // that restricts applies until vouch can prove the write lands
            // inside its trees, so `lang.<lang>.constructs.unresolved_path`
            // = "allow" must not open a scoped program's unprovable write.
            // A stricter setting still wins.
            let (a, reason) = match scope_for(&u.by) {
                Some(rule) => {
                    let stricter = declared.as_ref().filter(|(a, _)| rank(*a) > rank(Action::Ask));
                    (
                        stricter.map_or(Action::Ask, |(a, _)| *a),
                        scope_unprovable(
                            rule,
                            &u.cause,
                            u.what.as_deref(),
                            stricter.map(|(a, s)| (s.as_str(), *a)),
                        ),
                    )
                }
                None => (generic, u.generic),
            };
            if worst.as_ref().map_or(true, |(w, _)| rank(a) > rank(*w)) {
                worst = Some((a, reason));
            }
        }

        for (t, provenance, by) in targets {
            if t == "/dev/null" || t.eq_ignore_ascii_case("nul") {
                continue;
            }
            // An alternate data stream is a write to the file it hangs off,
            // so that file is what the rules answer about — and it is the
            // path the prompt should name, rather than a spelling with a
            // stream suffix nobody can add to an allow list (M2.131.4).
            let t = stream_base(&t).unwrap_or(t);
            // Still holding a variable after both expansions: assigned earlier
            // in the same command, or command substitution. vouch cannot name
            // where this lands, so it gets its own setting rather than being
            // waved through as if it were a known path.
            let resolved = normalize(&t, home);
            if resolved.contains('$') || resolved.contains('`') || resolved.contains('%') {
                // A path vouch cannot resolve is a path it cannot confirm is
                // allowed, so it takes the action already declared for exactly
                // that case — `[write] default` — rather than a default vouch
                // invents. An explicit constructs entry overrides it.
                // Which setting that action came from, so a scoped prompt can
                // name its real decider — here it is `write.default` whenever
                // the operator named no construct, and that is a different
                // sentence from the construct's own.
                let (declared, setting) = match cfg.named_construct_action(lang, "unresolved_path")
                {
                    Some(a) => (a, format!("lang.{lang}.constructs.unresolved_path")),
                    None => (cfg.write.default, "write.default".to_string()),
                };
                // The second unprovable shape, answered the same way as the
                // unplaceable one above: a scope RESTRICTS, so a destination
                // it cannot be proven to cover asks, and the ask names the
                // scope instead of a setting that would not turn it off —
                // unless that setting is STRICTER than the scope's ask, in
                // which case it is the decider and gets named.
                let (a, reason) = match scope_for(&by) {
                    Some(rule) => {
                        let stricter = rank(declared) > rank(Action::Ask);
                        (
                            if stricter { declared } else { Action::Ask },
                            scope_unprovable(
                                rule,
                                describe("unresolved_path"),
                                Some(&t),
                                stricter.then_some((setting.as_str(), declared)),
                            ),
                        )
                    }
                    None => (
                        declared,
                        format!("{}\n  the path: {t}", construct_reason(lang, "unresolved_path")),
                    ),
                };
                if worst.as_ref().map_or(true, |(w, _)| rank(a) > rank(*w)) {
                    worst = Some((a, reason));
                }
                continue;
            }
            // The action is the one the write rules RETURNED, not
            // `write.default` read a second time. Since the wall and a write
            // scope answer for themselves — deny outright, ask outright — a
            // config with `write.default = "allow"` would otherwise downgrade
            // a walled or out-of-scope destination to an allow, and the rule
            // that refused it would decide nothing. `write.default` still
            // answers when nothing else did: `decide_file_for` returns it
            // through `act` in its own last arm, and that Ask or Deny arrives
            // here as exactly the action it already was.
            let (a, reason) = match decide_file_for(
                cfg,
                home,
                project_root,
                &t,
                by.as_ref().map(|(h, s, t)| (h.as_str(), s.as_deref(), t)),
            ) {
                Decision::Ask(r) => (Action::Ask, r),
                Decision::Deny(r) => (Action::Deny, r),
                Decision::Allow(_) | Decision::Abstain => continue,
            };
            let mut reason = format!("{reason}\n  (written by the command, not by a file tool)");
            if let Some(p) = &provenance {
                reason.push_str(&format!("\n  {p}"));
            }
            if wins_reason_slot(a, &reason, &worst) {
                worst = Some((a, reason));
            }
        }
    }

    // 1d. Commands that run text obtained at execution time. The code is not
    // in what vouch was handed — EXCEPT where it is: an occurrence whose
    // standard input vouch HOLDS (a here-document the locator consumed and
    // scanned, provably that command's input) has nothing left to warn about,
    // and saying otherwise was a false prompt. Every other way of arriving at
    // standard input — a pipe, a file, a stream, an unproven source — still
    // asks, named and settable rather than silently passed.
    //
    // Channel 3: keyed by the CONSUMING entry's own declared snippet
    // language when it named one vouch can actually scan (`wrap_lang`), not
    // the host command's — a python entry that declares `evaluates_input`
    // trips `lang.python.constructs.evaluated_input`, and a host-language
    // allow of the same construct name must not silently cover it (`lang`
    // shadowed here on purpose: the source shape criterion 2's coverage scan
    // looks for).
    for (i, c) in all_cmds.iter().enumerate() {
        // Out of bounds reads as NOT held — the fail-closed direction, so a
        // desynced array keeps today's ask rather than inventing a hold.
        let holds = all_holds_input.get(i).copied().unwrap_or(false);
        // The same fold the recognition loop below reads — one definition, two
        // separate loops over the same parallel vectors.
        let standalone_eligible =
            standalone_eligible_at(&all_args_complete, &all_args_from_input, i);
        let (triggered, wrap_lang, hint) =
            crate::guards::evaluates_input(kb, c, holds, standalone_eligible);
        if !triggered {
            continue;
        }
        let lang = wrap_lang
            .as_deref()
            .filter(|l| crate::syntax::scanner_for(l).is_some())
            .unwrap_or(lang);
        let (a, key) = construct_action_for(cfg, lang, "evaluated_input");
        if a == Action::Allow {
            remember(&mut grants, construct_grant(lang, &key));
        }
        if worst.as_ref().map_or(true, |(w, _)| rank(a) > rank(*w)) {
            let mut reason = construct_reason(lang, &key);
            if let Some(h) = hint {
                let pairing =
                    if h.pair_no_value_options { ", and in `no_value_options`," } else { "" };
                reason.push_str(&format!(
                    "\n  if none of these flags runs anything by itself, listing them in \
                     `standalone_flags`{pairing} on the entry for `{}` removes this ask",
                    crate::guards::base_name(&c.head)
                ));
            }
            worst = Some((a, reason));
        }
    }

    // 1d1. A script FILE handed to an interpreter (M2.118). The code's
    // LOCATION is on the line and its CONTENT is not, which is the same
    // blindness §1d names and therefore the same construct — `bash s.sh` was
    // allowed whole-program while `curl … | bash` already asked, for no
    // reason an operator could have predicted from either.
    //
    // Keyed exactly as §1d keys its own: by the CONSUMING entry's declared
    // snippet language when it named one vouch can scan, else the
    // occurrence's own. `python s.py` and `curl … | python` are one
    // program's one blindness in two spellings, and they must name one
    // off-switch (`lang.python.constructs.evaluated_input`) rather than two.
    for (i, c) in all_cmds.iter().enumerate() {
        let (triggered, wrap_lang) = crate::guards::runs_file_positional(kb, c);
        if !triggered {
            continue;
        }
        let clang = wrap_lang
            .as_deref()
            .filter(|l| crate::syntax::scanner_for(l).is_some())
            .or_else(|| all_langs.get(i).map(String::as_str))
            .unwrap_or(lang);
        let (a, key) = construct_action_for(cfg, clang, "evaluated_input");
        if a == Action::Allow {
            remember(&mut grants, construct_grant(clang, &key));
        }
        if worst.as_ref().map_or(true, |(w, _)| rank(a) > rank(*w)) {
            worst = Some((a, construct_reason(clang, &key)));
        }
    }

    // 1d3. An assignment to a name the SHELL itself consults (M2.120). Two
    // channels, one question: a command's own prefix words (which include an
    // `env`-carried assignment — the operand walk records those as the
    // unwrapped command's prefix), and the same-line assignments the scan
    // recorded, which reach every later command on the line.
    //
    // A `lookup` name says the program that runs may not be the program the
    // knowledge describes, so the description is not evidence about it —
    // `rebound_name`, the same construct python already raises when a snippet
    // rebinds a described name. A `startup` name says the shell runs code
    // named on the line that vouch has not read — `evaluated_input`, the same
    // construct a script file and a pipe-fed interpreter raise.
    //
    // Under the occurrence's own language: an assignment inside a scanned
    // powershell snippet is powershell's, whatever typed the outer line.
    {
        let mut rebinding: Vec<(&str, &str, &str)> = Vec::new();
        for (i, c) in all_cmds.iter().enumerate() {
            let clang = all_langs.get(i).map(String::as_str).unwrap_or(lang);
            if let Some((name, effect)) = crate::guards::env_name_effect(kb, &c.prefix_assigns, clang)
            {
                rebinding.push((name, effect, clang));
            }
            // The program-side spelling of the same thing: a command told to
            // put a path in the shell's own lookup table under some name
            // (M2.113). One construct, because it is one consequence — the
            // name no longer means what the knowledge says it means.
            if let Some(flag) = crate::guards::rebinds_a_name(kb, c, clang) {
                rebinding.push((flag, "flag", clang));
            }
        }
        let same_line: Vec<String> = scan.assignments.iter().map(|(n, _)| n.clone()).collect();
        if let Some((name, effect)) = crate::guards::env_name_effect(kb, &same_line, lang) {
            rebinding.push((name, effect, lang));
        }
        for (label, effect, clang) in rebinding {
            let construct = if effect == "startup" { "evaluated_input" } else { "rebound_name" };
            let (a, key) = construct_action_for(cfg, clang, construct);
            if a == Action::Allow {
                remember(&mut grants, construct_grant(clang, &key));
            }
            if worst.as_ref().map_or(true, |(w, _)| rank(a) > rank(*w)) {
                let detail = match effect {
                    "startup" => format!(
                        "`{label}` names a file the shell runs before the command on this line, \
                         and vouch has not read it"
                    ),
                    "flag" => format!(
                        "`{label}` puts a path of its own into the shell's lookup table, so a \
                         name later on this line runs that path instead of the program vouch \
                         describes"
                    ),
                    _ => format!(
                        "`{label}` is a name the shell itself reads when it looks a program up, \
                         so vouch cannot tell which program will run"
                    ),
                };
                worst = Some((a, format!("{}\n  {detail}", construct_reason(clang, &key))));
            }
        }
    }

    // 1d4. A command whose arguments will be APPENDED from a channel this
    // line never names (M2.116). `echo f.txt | xargs touch` records a `touch`
    // with no arguments at all, and "no destination recorded" is not "no
    // destination" — it is a destination arriving from somewhere vouch cannot
    // read. Every claim an appended token could change therefore fails
    // closed; the ones it could not (`xargs echo`) stay quiet.
    //
    // Placed AFTER the guard and write passes on purpose, and it relies on
    // the recorded-reason rule that a later ask of EQUAL rank does not
    // displace an earlier one: a rule that already matched tokens present ON
    // THE LINE keeps its own, more specific reason, and this ask speaks only
    // where nothing else already did.
    for (i, c) in all_cmds.iter().enumerate() {
        if !all_args_from_input.get(i).copied().unwrap_or(false) {
            continue;
        }
        let clang = all_langs.get(i).map(String::as_str).unwrap_or(lang);
        if !crate::guards::appended_args_could_change_the_answer(kb, c, clang) {
            continue;
        }
        fold_expansion_constructs(
            cfg,
            clang,
            &[(
                "args_from_input".to_string(),
                format!(
                    "`{}` is run with arguments read from standard input or a file, so what it \
                     acts on is not on this line at all",
                    crate::guards::base_name(&c.head)
                ),
            )],
            &mut worst,
            &mut grants,
        );
    }

    // 1d2. A call that occupies a declared `callback_args` slot: the value
    // handed there runs when the described function invokes it, and that
    // never shows up as its own scanned event (task 2b, M2.86 fix round —
    // `json.loads(s, parse_int=g)` hands `g` to `json.loads`, which calls it
    // directly; the scanner has no event for a callable passed by
    // reference). Keyed on the OCCURRENCE's own language (`all_langs[i]`),
    // never the host language — the parse-failure loop below is the pattern
    // this copies; §1d's `evaluated_input` loop above keys on the host
    // language instead, which is a recorded defect (M2.79) this loop must
    // not repeat.
    for (i, c) in all_cmds.iter().enumerate() {
        if !crate::guards::callback_argument_used(kb, c) {
            continue;
        }
        let clang = all_langs.get(i).map(String::as_str).unwrap_or(lang);
        let (a, key) = construct_action_for(cfg, clang, "callback_argument");
        if a == Action::Allow {
            remember(&mut grants, construct_grant(clang, &key));
        }
        if worst.as_ref().map_or(true, |(w, _)| rank(a) > rank(*w)) {
            worst = Some((a, construct_reason(clang, &key)));
        }
    }

    // 1e. The wrapper walk reached its depth cap while unwrapping this line.
    // Everything past the cap is exactly what nothing scanned, so this asks
    // rather than passing on a partial read (M2.55) — named under the
    // language of the layer where the cap was hit (`lang` shadowed here on
    // purpose: the source shape criterion 2's coverage scan looks for).
    if let Some(lang) = &wrap_depth_exceeded {
        let (a, key) = construct_action_for(cfg, lang, "wrap_depth_exceeded");
        if a == Action::Allow {
            remember(&mut grants, construct_grant(lang, &key));
        }
        let reason = format!(
            "{}\n  to scan more layers, set lang.{lang}.wrap_depth = <a larger number>",
            construct_reason(lang, &key)
        );
        if worst.as_ref().is_none_or(|(w, _)| rank(a) > rank(*w)) {
            worst = Some((a, reason));
        }
    }

    // 1e2. Constructs the wrapper-EXPANSION walk itself raised, rather than
    // scanning a command's or a snippet's own text (that is §2/§2b below) —
    // distinct from `wrap_depth_exceeded` above, which is one cap-hit marker
    // per line; this channel carries however many the walk found. Attributed
    // to the HOST language, since the walk operates on the outer text.
    // Two producers push here: `wrap_unlocated`, from every wrap arm that was
    // told a payload exists and could not find it, and the `evaluated_input`
    // an `arg_<N>` slot holding an unreadable value raises. Distinct from the
    // cap path in `decide_command_from`, which raises `wrap_unlocated` about
    // the number of READINGS rather than about one arm's payload.
    fold_expansion_constructs(cfg, lang, &expansion_constructs, &mut worst, &mut grants);

    // 1f. A wrapped snippet the registry has a scanner for, but that did not
    // parse (channel 1). Named under the SNIPPET's own language, never the
    // host's, exactly like every other per-snippet construct (`lang`
    // shadowed here on purpose: the source shape criterion 2's coverage scan
    // looks for) — this is the site that used to discard the error silently
    // (`.unwrap_or_default()` inside `scan_snippet`, and the redundant
    // re-scan just above that only ever said `if let Ok`).
    for (plang, error) in &parse_failures {
        let lang = plang.as_str();
        let (a, key) = construct_action_for(cfg, lang, "parse_failure");
        if a == Action::Allow {
            remember(&mut grants, construct_grant(lang, &key));
        }
        let reason = format!(
            "{}\n  could not read: {error}",
            construct_reason(lang, &key)
        );
        if worst.as_ref().map_or(true, |(w, _)| rank(a) > rank(*w)) {
            worst = Some((a, reason));
        }
    }

    // 2. Constructs — what vouch could not see through.
    for name in &scan.constructs {
        let (a, key) = construct_action_for(cfg, lang, name);
        if a == Action::Allow {
            remember(&mut grants, construct_grant(lang, &key));
        }
        if worst.as_ref().map_or(true, |(w, _)| rank(a) > rank(*w)) {
            worst = Some((a, construct_reason(lang, &key)));
        }
    }
    // 2b. Constructs found INSIDE a wrapped snippet (collected at §1b above)
    // resolve under the snippet's OWN language, never the host's — channel 2
    // (`lang` shadowed here on purpose: the source shape criterion 2's
    // coverage scan looks for).
    for (plang, name) in &snippet_constructs {
        let lang = plang.as_str();
        let (a, key) = construct_action_for(cfg, lang, name);
        if a == Action::Allow {
            remember(&mut grants, construct_grant(lang, &key));
        }
        if worst.as_ref().map_or(true, |(w, _)| rank(a) > rank(*w)) {
            worst = Some((a, construct_reason(lang, &key)));
        }
    }

    // 3. Programs vouch has no description of. The shipped config sets this to
    // "ask" (2026-07-28) — absence of knowledge is not the permissive case,
    // which is the whole polarity claim in CLAUDE.md §1.
    //
    // It shipped as "allow" until then, justified by a measurement that
    // flipping it would prompt on 93.8% of recorded commands. That figure
    // described one machine on one day and was never evidence about anything
    // general; flipping it broke no test. `vouch trust` and doctor are how the
    // list grows from here.
    //
    // Read one OCCURRENCE at a time over the expanded list, never over the
    // commands as WRITTEN. Guards have read the expanded list since wrappers
    // were first unwrapped, so `env someunknownprogram` was guarded on the real
    // program and RECOGNISED on the word `env`: the wrapper is described, so
    // the line was allowed and the program inside it was never checked at all.
    // Every wrapper — `env`, `sudo`, `xargs`, `bash -c`, `powershell -Command`
    // — was a way to spell a name vouch has never heard of and have it pass in
    // silence, which is the allow-list going quiet exactly where §1 says it
    // must speak up.
    //
    // Each occurrence is judged under ITS OWN language (`all_langs[i]`). A
    // snippet written in another scanner's syntax is not a claim about the host
    // language, and the setting that turns its prompt off is that language's
    // own (§5): a PowerShell snippet's unknown head is settable under
    // `lang.powershell.constructs.unmodeled_command`, and naming bash's there would
    // name an off-switch that does not turn it off.
    //
    // The zones, expanded once for the whole line: the globs do not change
    // between occurrences, only the places do. (`here_home` was hoisted to the
    // guard pass, which now asks the same "where does this run" question.)
    let trust = PlaceTrees::of(cfg.run.trust_all_under.as_ref(), here_home, project_root);
    let distrust = PlaceTrees::of(cfg.run.trust_nothing_under.as_ref(), here_home, project_root);

    let mut items: Vec<UnmodeledItem> = Vec::new();
    // The worst action any single occurrence asks for, and every language
    // whose setting is actually holding this prompt open.
    let mut unmodeled_action: Option<Action> = None;
    let mut settings_langs: Vec<String> = Vec::new();
    // (`grants` — what a PLACE recognised, in the words the allow reason uses —
    // is declared at the guard pass, which now contributes to it too.)
    //
    // The other kind of decider on an allowed line: an occurrence whose own
    // language allows unknown programs. Only ever printed beside a place's
    // own sentence — see where it is consumed.
    let mut by_setting: Vec<String> = Vec::new();
    for (i, c) in all_cmds.iter().enumerate() {
        if c.head.is_empty() {
            continue;
        }
        let clang = all_langs.get(i).map(String::as_str).unwrap_or(lang);
        let standalone_eligible =
            standalone_eligible_at(&all_args_complete, &all_args_from_input, i);
        // The place this occurrence runs in: the timeline, hoisted above
        // recognition for exactly this, read at the order of the command this
        // one was expanded from — then moved by the command's own run-dir flag.
        // [review] Without that second step a zone was settled on the SHELL's
        // directory while the same command's writes were judged at the flag's,
        // so `git -C <tree> <verb>` stepped around a zone that a `cd` into the
        // same tree would have entered.
        let base = timeline.base_at(
            all_orders.get(i).unwrap_or(&crate::syntax::Order::Unordered),
            c.chain.as_ref(),
            &start,
        );
        let (state, _) = run_dir_place(kb, c, &base, inherited_at(&all_inherited, i), &resolve);
        let place = place_of(&state, here_home);

        // 3a. The distrust zone, FIRST (spec §Precedence for recognition,
        // step 1). It RESTRICTS, so it applies unless the place is provably
        // outside it, and it applies to described programs too — a zone that
        // spared them would be a no-op, since unknown programs already ask.
        // Its off-switch is the zone itself, never `unmodeled_command`, so it
        // is consulted before that setting is read at all.
        if !distrust.is_empty() {
            let stop = match &place {
                Place::Proven(d) => match distrust.holding(d) {
                    Some(glob) => Some(format!(
                        "vouch stopped on: run.trust_nothing_under\n  \
                         where this command runs: {d}\n  \
                         the tree that covers it: {glob}\n  \
                         what that means: nothing run from under this tree is recognised — \
                         described programs ask here too\n  \
                         to stop asking here, remove {glob} from run.trust_nothing_under"
                    )),
                    // The place is proven and outside every tree vouch could
                    // LOCATE — but a pattern that names no directory here
                    // cannot be proven outside either, and a restriction
                    // applies until it is. [review] Dropping these silently
                    // turned a configured zone into no zone at all.
                    None if !distrust.unresolved.is_empty() => Some(format!(
                        "vouch stopped on: run.trust_nothing_under\n  \
                         where this command runs: {d}\n  \
                         the pattern vouch could not resolve: {}\n  \
                         what that means: this command is outside every tree vouch could \
                         locate, but a pattern that names no directory on this machine cannot \
                         be proven outside, and a rule that restricts applies until it is\n  \
                         to stop asking here, spell that pattern so it resolves ($PROJECT_ROOT \
                         needs a repository) or remove it from run.trust_nothing_under",
                        distrust.unresolved.join(", ")
                    )),
                    None => None,
                },
                // Nothing places this command, so it might be standing in the
                // tree: doubt narrows (spec §The one rule for uncertainty).
                Place::Unproven => Some(format!(
                    "vouch stopped on: run.trust_nothing_under\n  \
                     vouch cannot prove where this command runs: {}\n  \
                     run.trust_nothing_under ({}) covers a place this command might be running \
                     in, and a rule that restricts applies unless vouch can prove the command \
                     runs outside it\n  \
                     to stop asking here, remove that tree from run.trust_nothing_under, or run \
                     the command where vouch can place it",
                    unproven_cause(&state),
                    distrust.written()
                )),
            };
            if let Some(reason) = stop {
                if worst.as_ref().map_or(true, |(w, _)| rank(Action::Ask) > rank(*w)) {
                    worst = Some((Action::Ask, reason));
                }
                continue;
            }
        }

        // 3b. An entry that describes it (spec step 2). A place-scoped entry
        // counts only where the place PROVES the command runs under its trees
        // — a grant, so an unproven place unlocks nothing. One walk answers
        // both questions: whether it was recognised, and by what.
        let run_place = match &place {
            Place::Proven(d) => Some(d.as_str()),
            Place::Unproven => None,
        };
        match crate::guards::recognition_at(
            kb,
            c,
            clang,
            crate::guards::RecognitionPlace {
                dir: run_place,
                home: here_home,
                project_root,
            },
            standalone_eligible,
        ) {
            // The PLACE is what recognised this, so the allow says which entry
            // and which of its trees.
            crate::guards::Recognised::AtPlace(glob) => {
                let at = match &place {
                    Place::Proven(d) => d.as_str(),
                    // Unreachable: a scoped entry never matches without a
                    // place. Named rather than unwrapped, because a panic in
                    // the gate is a worse answer than a sentence.
                    Place::Unproven => "a place vouch cannot name",
                };
                remember(
                    &mut grants,
                    format!(
                        "allowed by your entry for `{}`, which recognises it only under {glob} \
                         — this command runs at {at}",
                        crate::guards::base_name(&c.head)
                    ),
                );
                continue;
            }
            crate::guards::Recognised::Yes => continue,
            crate::guards::Recognised::No => {}
        }

        // 3c. A trust zone (spec step 3), which grants, so it needs a proven
        // place. "Whatever it is" includes an unknown VERB of a described
        // program: 3b left that unrecognised like anything else.
        if let Place::Proven(d) = &place {
            if let Some(glob) = trust.holding(d) {
                remember(
                    &mut grants,
                    format!(
                        "allowed by run.trust_all_under ({glob}) — trusted because you trust \
                         commands run from this location ({d})"
                    ),
                );
                continue;
            }
        }

        let a = cfg.construct_action(clang, "unmodeled_command");
        // An occurrence whose own language already allows unknown programs
        // cannot be what stopped this line, so it is neither described nor
        // named in the prompt — naming it would print a program alongside an
        // off-switch that has nothing to do with it.
        //
        // [review] It is still a DECIDER, though: a line where a zone
        // recognised one command and this setting waved another through was
        // journalled as "allowed by run.trust_all_under", which reads as one
        // rule deciding a line that two rules decided. The sentence is kept
        // aside and only printed beside a place's own — on its own it would
        // rewrite every ordinary allow reason on the machine.
        if a == Action::Allow {
            remember(
                &mut by_setting,
                format!(
                    "allowed by lang.{clang}.constructs.unmodeled_command = \"allow\" — vouch has no \
                     description of `{}` and that setting allows unknown programs",
                    crate::guards::base_name(&c.head)
                ),
            );
            continue;
        }

        // 3d. Nothing recognised it. What the place has to say about that
        // changes the prompt, so it is part of what makes this item distinct.
        let scopes = crate::guards::place_scopes(kb, &c.head, clang);
        let answer = if scopes.is_empty() {
            match &place {
                // Nothing places this command, and a trust zone covers
                // somewhere it might be standing. Without this line an
                // operator standing in their own zone sees vouch apparently
                // ignoring their config. `resolved`, not the whole list: a
                // zone whose patterns name no directory here covers nowhere,
                // so it is not a grant this command missed.
                Place::Unproven if !trust.resolved.is_empty() => {
                    PlaceAnswer::Missed { cause: unproven_cause(&state).to_string() }
                }
                _ => PlaceAnswer::Plain,
            }
        } else {
            // A scoped entry for this very name exists and did not reach this
            // command. WHY decides the wording, and none of the four may end
            // in "write an entry" — that entry exists, and a second one for
            // the same name refuses the whole file.
            let entry_trees = PlaceTrees::of(Some(&scopes), here_home, project_root);
            let why = match &place {
                Place::Proven(d) => match entry_trees.holding(d) {
                    // Inside the trees and still unrecognised: the entry's own
                    // `subcommands` list is what excluded it, never the place.
                    Some(_) => ScopedMiss::Verb {
                        runs_at: d.clone(),
                        verb: crate::guards::subcommand_of(kb, c).map(str::to_string),
                    },
                    // Outside every tree it could LOCATE — and if it could
                    // locate none, "outside them" would be a claim about
                    // trees that are not anywhere.
                    None if entry_trees.resolved.is_empty() => ScopedMiss::Unlocatable,
                    None => ScopedMiss::Outside {
                        runs_at: d.clone(),
                        unlocatable: entry_trees.unresolved.join(", "),
                    },
                },
                Place::Unproven => ScopedMiss::Unproven(unproven_cause(&state).to_string()),
            };
            PlaceAnswer::Scoped { trees: scopes.join(", "), why }
        };
        // One command at a time, so the description is about THIS occurrence
        // and is looked up under THIS occurrence's language.
        // The marker arrives beside the sentence it shaped: `narrow` is what a
        // flags-only run of THIS occurrence could list, the one thing that
        // tells apart the two populations that can collide here (spec
        // 2026-08-20 §6.1) and that the scoped-miss remedy further down reads
        // back.
        for (shown, desc, narrow) in
            crate::guards::unmodeled_descriptions(kb, &all_cmds[i..=i], clang, standalone_eligible)
        {
            if unmodeled_action.map_or(true, |w| rank(a) > rank(w)) {
                unmodeled_action = Some(a);
            }
            if !settings_langs.iter().any(|l| l == clang) {
                settings_langs.push(clang.to_string());
            }
            // Deduplicated by name, LANGUAGE and place answer together: two
            // occurrences that answer the same are one item, two that differ
            // are two. A name-only key printed one line carrying whichever
            // language and whichever place happened to be seen first, so half
            // a mixed-language prompt named the wrong syntax.
            let pos = items
                .iter()
                .position(|it| it.shown == shown && it.lang == clang && it.place == answer);
            match pos {
                None => items.push(UnmodeledItem {
                    occurrence: i,
                    shown,
                    desc,
                    lang: clang.to_string(),
                    place: answer.clone(),
                    narrow,
                }),
                // Today's code was push-if-absent, silently keeping whichever
                // occurrence was seen first. A collision now has to pick a
                // WINNER by the three-case rule, so this is a find-and-
                // REPLACE of the already-pushed item, never a skip.
                Some(idx) => match (items[idx].narrow.take(), narrow) {
                    // Two standalone shapes, equal sets: keep the one
                    // already there — its text already says the same thing.
                    (Some(a), Some(b)) if same_flag_set(&a.flags, &b.flags) => {
                        items[idx].narrow = Some(a);
                    }
                    // Two standalone shapes, DIFFERING sets: the entry could
                    // truthfully list either flag ONLY on the run that named
                    // it, so keeping either subset alone would leave the
                    // sibling run asking. Union them, order-preserving, and
                    // regenerate the description from the union so the
                    // printed text and the stored marker agree.
                    (Some(a), Some(b)) => {
                        let mut union = a.flags.clone();
                        for f in &b.flags {
                            if !union.contains(f) {
                                union.push(f.clone());
                            }
                        }
                        let united = crate::guards::ListableStandalone {
                            flags: union,
                            needs_case_key: a.needs_case_key || b.needs_case_key,
                        };
                        items[idx].desc = narrow_offer_desc(kb, c, clang, &united);
                        items[idx].narrow = Some(united);
                    }
                    // Some beside None: the None item (whole-program
                    // wording) is the safe winner — a narrow offer would
                    // leave the non-standalone sibling asking. Replace the
                    // already-pushed Some with THIS occurrence's None text.
                    (Some(_), None) => {
                        items[idx].desc = desc;
                    }
                    // The existing item was already None (whichever side
                    // supplied it), so it already wins; `.take()` already
                    // left it None.
                    (None, _) => {}
                },
            }
        }
    }
    if let Some(a) = unmodeled_action {
        if worst.as_ref().map_or(true, |(w, _)| rank(a) > rank(*w)) {
            // Names a FRESH entry could recognise, kept apart from names an
            // entry already covers somewhere else: the two get different
            // advice, and giving the second the first's advice writes a
            // colliding entry that refuses the whole my-knowledge file.
            let mut fresh: Vec<&str> = Vec::new();
            for it in &items {
                if !matches!(it.place, PlaceAnswer::Scoped { .. })
                    && !fresh.contains(&it.shown.as_str())
                {
                    fresh.push(&it.shown);
                }
            }
            let lines = items
                .iter()
                .filter(|it| !matches!(it.place, PlaceAnswer::Scoped { .. }))
                .map(|it| {
                    // Only when it differs from the language of the line the
                    // operator typed: otherwise every prompt would carry a
                    // word that says nothing.
                    let where_written = if it.lang == lang {
                        String::new()
                    } else {
                        format!(" (written in {})", it.lang)
                    };
                    format!("    {} — {}{where_written}", it.shown, it.desc)
                })
                .collect::<Vec<_>>()
                .join("\n");
            let them = if fresh.len() == 1 { "it" } else { "them" };
            // Every language actually holding the prompt open gets named, or a
            // mixed-language line would print one off-switch that turns off
            // half of it.
            let settings = settings_langs
                .iter()
                .map(|l| format!("lang.{l}.constructs.unmodeled_command = \"allow\""))
                .collect::<Vec<_>>()
                .join(" and ");

            let mut parts: Vec<String> = vec!["vouch stopped on: unmodeled_command".to_string()];
            if !fresh.is_empty() {
                parts.push(format!("no description of: {}", fresh.join(", ")));
                parts.push(format!("what that means: vouch has no entry that covers {them}"));
                // The old text quoted a stale 93.8% and then steered toward
                // switching the check off, which is the deny-list talking: it
                // made "vouch has never heard of this" sound like a reason to
                // stop asking. It also said to edit knowledge.toml by hand,
                // which was doubly wrong — that file is compiled in, and the
                // user's own file was not being read at all.
                //
                // It then printed `vouch trust {names joined by spaces}` — a
                // command that, four measured ways, did something other than
                // what the prompt was about (M2.12). A printed command cannot
                // say what it will trust; these lines can, and the vouch-trust
                // skill does the checked version: propose, show, write on
                // accept, prove it fired.
                parts.push(format!(
                    "to recognise one, use the vouch-trust skill — it proposes the narrowest \
                     entry, shows exactly what that entry would trust, writes it only on your \
                     accept (it drives `vouch trust`, whose usage `vouch trust` alone prints), \
                     and proves it fires. The narrowest entries here:\n{lines}"
                ));
            }
            // The entry the operator already has, named — never a suggestion
            // to write a new one (spec prompt table, the proven-outside row,
            // and its three siblings found by review). The occurrence index is
            // what makes the name right: the item's SHOWN name can be
            // `<program> <verb>`, and an entry by that name does not exist.
            for it in &items {
                let PlaceAnswer::Scoped { trees, why } = &it.place else { continue };
                let narrow = &it.narrow;
                let bare = crate::guards::base_name(&all_cmds[it.occurrence].head);
                let (what, remedy) = match why {
                    ScopedMiss::Outside { runs_at, unlocatable } => (
                        format!(
                            "recognises it only under {trees}; this command runs at {runs_at}, \
                             outside them{}",
                            if unlocatable.is_empty() {
                                String::new()
                            } else {
                                format!(
                                    " (and {unlocatable} names no directory on this machine, so \
                                     it covers none)"
                                )
                            }
                        ),
                        "to recognise it there too, add that tree to that entry's `only_under`"
                            .to_string(),
                    ),
                    ScopedMiss::Verb { runs_at, verb } => (
                        format!(
                            "recognises it under {trees}, which covers {runs_at} where this \
                             command runs — it is {} that no entry covers",
                            match verb {
                                Some(v) => format!("the `{v}` operation"),
                                None => "this invocation".to_string(),
                            }
                        ),
                        // A flags-only run (`verb: None`) with a narrow
                        // offer teaches `standalone_flags`, not
                        // `subcommands` — "add it to that entry's
                        // `subcommands`" reads as "name this run as a verb",
                        // which is not what a flags-only shape is. Every
                        // other shape — a genuine unknown verb, or a
                        // flags-only run with nothing listable — keeps the
                        // sentence that has always been here.
                        match (verb, narrow) {
                            (None, Some(l)) => format!(
                                "to recognise this flags-only run, add `standalone_flags = [{}]` \
                                 to that entry{}",
                                l.flags.iter().map(|f| format!("{f:?}")).collect::<Vec<_>>().join(", "),
                                if l.needs_case_key {
                                    ", with `case_sensitive_flags` stated on the entry"
                                } else {
                                    ""
                                }
                            ),
                            _ => "to recognise that operation, add it to that entry's \
                                  `subcommands`"
                                .to_string(),
                        },
                    ),
                    ScopedMiss::Unlocatable => (
                        format!(
                            "recognises it only under {trees}, and that names no directory on \
                             this machine — so the entry applies nowhere, wherever this command \
                             runs"
                        ),
                        "to recognise it, spell that tree so it resolves ($PROJECT_ROOT needs a \
                         repository) in that entry's `only_under`"
                            .to_string(),
                    ),
                    ScopedMiss::Unproven(cause) => (
                        format!(
                            "covers a place this command might run in ({trees}), but vouch \
                             cannot prove it runs there ({cause}) — otherwise it would be \
                             recognised"
                        ),
                        "a wider `only_under` cannot help while the place is unknown: what \
                         recognises it is a command vouch can place"
                            .to_string(),
                    ),
                };
                remember(
                    &mut parts,
                    format!(
                        "your entry for `{bare}` {what}\n  \
                         {remedy} — do not write a second entry for `{bare}`: a scoped name on \
                         more than one entry refuses the whole file"
                    ),
                );
            }
            for it in &items {
                if let PlaceAnswer::Missed { cause } = &it.place {
                    remember(
                        &mut parts,
                        format!(
                            "a trust zone or one of your entries covers a place this command \
                             might run in, but vouch cannot prove it runs there ({cause}) — \
                             otherwise it would be recognised"
                        ),
                    );
                }
            }
            parts.push(format!(
                "to stop checking for unknown programs entirely, set {settings} — that allows \
                 every program vouch has never heard of, not just this one"
            ));
            worst = Some((a, parts.join("\n  ")));
        }
    }


    let verdict = match worst {
        Some((a, r)) if a != Action::Allow => act(a, r),
        _ => {
            let a = cfg.lang_default(lang);
            let reason = match a {
                // A place is what recognised this line, so the allow says
                // which rule and which tree. `record_from` copies an Allow's
                // reason into the journal exactly as it does an Ask's, so this
                // is what `vouch why` reads back — without it the operator
                // gets "allowed by vouch policy" for a decision their own zone
                // or their own entry made.
                //
                // [review] EVERY decider, not only the place: one line can be
                // half-recognised by a zone and half waved through by another
                // language's `unmodeled_command`, and naming only the zone
                // reads as one rule deciding what two rules decided.
                Action::Allow if !grants.is_empty() => {
                    grants.iter().chain(by_setting.iter()).cloned().collect::<Vec<_>>().join("\n  ")
                }
                Action::Allow => "allowed by vouch policy".to_string(),
                _ => format!(
                    "vouch stopped on: {lang} default\n  \
                     nothing in this command objected, and `lang.{lang}.default` is \"{}\"\n  \
                     to allow commands that raise no objection, set lang.{lang}.default = \"allow\"",
                    match a { Action::Ask => "ask", _ => "deny" }
                ),
            };
            act(a, reason)
        }
    };
    (verdict, fork.points().to_vec())
}

/// One line's commands after wrapper expansion, in parallel vectors plus the
/// snippets. Parallel and not a vector of structs because that is how the
/// passes downstream read them: `cd_timeline` takes the slices, and every
/// per-command lookup is by the same index into each of them.
struct Expanded {
    cmds: Vec<crate::shell::Cmd>,
    orders: Vec<crate::syntax::Order>,
    /// Marks a command that came out of a wrapper's snippet rather than being
    /// written at the top level — a snippet's internal sequence is not the
    /// outer one, so a directory change inside it cannot be placed.
    from_snippet: Vec<bool>,
    /// The language each expanded command is written in: the host `lang` for a
    /// top-level command or one unwrapped from the SAME syntax (`sudo`, `find
    /// -exec`), or the snippet's own language when the wrap crosses into a
    /// different scanner (`bash -c`, `powershell -Command`). A recognition or
    /// dir-change lookup that used `lang` here instead would be a HOST-language
    /// lookup on a snippet command (spec §2's exact hole).
    langs: Vec<String>,
    /// Whether vouch HOLDS the text of each command's standard input — see
    /// `guards::holds_input`. True only where a here-document the locator
    /// consumed and scanned is provably that command's input; the construct
    /// channel reads it so a scanned body stops the ask that says the code is
    /// not in what vouch was handed.
    holds_input: Vec<bool>,
    /// Whether each command's recorded arguments are a partial record because
    /// a wrapper above it appends more from a channel the line never names
    /// (`xargs`). Read by §1d4, which fails closed for every claim an
    /// appended token could change.
    args_from_input: Vec<bool>,
    /// Whether each command's recorded arguments are a faithful record of
    /// what the shell will pass (`Scan::args_complete`), carried across every
    /// wrapper boundary by the expansion walk rather than being read per
    /// top-level command and dropped. Folded with `args_from_input` above
    /// into the one boolean the standalone arm of recognition needs: a record
    /// is standalone-eligible when it is complete AND nothing off the line
    /// will append to it.
    args_complete: Vec<bool>,
    /// The wrapped snippets themselves — whole scripts vouch has no parser for
    /// at the outer level but can still scan for redirects and protected-path
    /// mentions (§1b in `decide_command_from`).
    snippets: Vec<(String, String, crate::syntax::Order)>,
    /// The language whose wrapper-nesting cap was reached while expanding
    /// THIS line, if any — first hit across every top-level command wins,
    /// since vouch decides once per command (M2.55). `None` means every
    /// layer of every wrapper on this line was scanned.
    wrap_depth_exceeded: Option<String>,
    /// Every `(lang, error)` a wrapped snippet failed to parse with — a
    /// registry scanner exists for `lang`, but the text did not parse
    /// (channel 1). Folded as the `parse_failure` construct under the
    /// SNIPPET's own language, never the host's.
    parse_failures: Vec<(String, String)>,
    /// Every `(key, detail)` construct the wrapper-expansion walk itself
    /// raised — distinct from `scan.constructs`/`snippet_constructs`, which
    /// come from scanning a command's or a snippet's own text. Attributed to
    /// the HOST language: the walk that raises these operates on the outer
    /// text, not on one particular snippet. Two producers: `wrap_unlocated`
    /// and the `evaluated_input` a wrap slot holding an unreadable value
    /// raises.
    constructs: Vec<(String, String)>,
    /// Parallel to `cmds`: the directory a WRAPPER's own run-dir flag sent
    /// this occurrence to, before its own flags are read.
    inherited_run_dir: Vec<Option<String>>,
}

/// Wrapper expansion, one top-level command at a time: for each
/// `scan.commands[i]`, expand wrappers and push every resulting command with
/// the ORIGINAL command's order — a wrapped snippet has no position of its
/// own, so it takes the wrapper's. Expanding the whole list in one call and
/// then indexing `scan.order` by position in the RESULT would read some other
/// command's order, since `scan.order` is parallel to `scan.commands`, never
/// to the expanded list.
fn collect_expanded(
    kb: &crate::guards::Knowledge,
    scan: &crate::syntax::Scan,
    lang: &str,
    caps: &dyn Fn(&str) -> u8,
    fork: &mut crate::guards::ForkCursor,
) -> Expanded {
    let mut out = Expanded {
        cmds: Vec::new(),
        orders: Vec::new(),
        from_snippet: Vec::new(),
        langs: Vec::new(),
        holds_input: Vec::new(),
        args_from_input: Vec::new(),
        args_complete: Vec::new(),
        snippets: Vec::new(),
        wrap_depth_exceeded: None,
        parse_failures: Vec::new(),
        constructs: Vec::new(),
        inherited_run_dir: Vec::new(),
    };
    for (i, c) in scan.commands.iter().enumerate() {
        // A missing order is not a provable one (§1).
        let order = scan
            .order
            .get(i)
            .cloned()
            .unwrap_or(crate::syntax::Order::Unordered);
        // `expand_wrappers_with_sources` is called with a ONE-command slice
        // (`std::slice::from_ref(c)`), so any heredoc attached to `c` has to
        // have its `cmd_index` remapped from its position in the FULL
        // `scan.commands` (`i`) to 0 — the only position that slice has.
        // `InputSource::Heredoc` names a record by its own stable identity
        // (`HeredocId`), not by a position in whichever list holds it, so
        // filtering `scan.heredocs` down to this command's own records needs
        // no matching re-basing pass to keep the reference in sync — the id
        // read from `scan.input_source` below is passed through unchanged
        // and still finds its record in the filtered slice (M2.127).
        let heredocs: Vec<crate::syntax::Heredoc> = scan
            .heredocs
            .iter()
            .filter(|h| h.cmd_index == i)
            .map(|h| crate::syntax::Heredoc { cmd_index: 0, ..h.clone() })
            .collect();
        let source = scan
            .input_source
            .get(i)
            .cloned()
            .unwrap_or(crate::syntax::InputSource::Unknown);
        let args_complete = scan.args_complete.get(i).copied().unwrap_or(false);
        // ONE cursor across every top-level command on the line, so a fork
        // is numbered by its position in the whole line's walk. Numbering per
        // command would make the same choice vector select different readings
        // depending on which command it reached first.
        let ex = crate::guards::expand_wrappers_forking(
            kb,
            std::slice::from_ref(c),
            &heredocs,
            std::slice::from_ref(&source),
            std::slice::from_ref(&args_complete),
            lang,
            caps,
            fork,
        );
        // Zipped rather than indexed, one more strand than before: the walk
        // builds these arrays in lockstep, and a zip that runs short stops
        // early instead of reading a neighbour's answer for the strand that
        // fell behind.
        for (j, (((((ec, elang), eholds), einherited), efrom_input), ecomplete)) in ex
            .cmds
            .into_iter()
            .zip(ex.langs)
            .zip(ex.holds_input)
            .zip(ex.inherited_run_dir)
            .zip(ex.args_from_input)
            .zip(ex.args_complete)
            .enumerate()
        {
            out.cmds.push(ec);
            out.orders.push(order.clone());
            out.from_snippet.push(j > 0);
            out.langs.push(elang);
            out.holds_input.push(eholds);
            out.inherited_run_dir.push(einherited);
            out.args_from_input.push(efrom_input);
            out.args_complete.push(ecomplete);
        }
        for (plang, psrc) in ex.srcs {
            out.snippets.push((plang, psrc, order.clone()));
        }
        out.parse_failures.extend(ex.parse_failures);
        out.constructs.extend(ex.constructs);
        // First hit wins across the whole line (§ struct doc) — a later
        // top-level command reaching its own cap says nothing new once one
        // command already has.
        if out.wrap_depth_exceeded.is_none() {
            out.wrap_depth_exceeded = ex.wrap_depth_exceeded;
        }
    }
    out
}

/// Diagnostic for measurements (spec 2026-08-06 §Measurement plan): how many
/// command positions in this line have an Unknown run place — a directory
/// change the walk cannot order or resolve. Structural: no cwd is supplied,
/// so a bare relative line counts 0 (NoDirectory, not Unknown). NOTE: a
/// single unplaceable directory change marks EVERY position Unknown
/// (`CdTimeline.unplaceable`), so `cd a || cd b; echo x` counts 3 — the
/// count is "positions a restrict-shaped place rule would treat as
/// possibly-inside", which is exactly the noise being sized.
pub fn count_unknown_run_place_commands(lang: &str, src: &str) -> usize {
    let scanner = match crate::syntax::scanner_for(lang) {
        Some(s) => s,
        None => return 0,
    };
    let scan = match scanner.scan(src) {
        Ok(s) => s,
        Err(_) => return 0,
    };
    let kb = crate::guards::in_effect();
    // `snippets` and the depth-cap report go unread here: the diagnostic
    // counts run places over whatever got scanned, using the built-in
    // default depth (this path has no `Config` to read an operator's
    // `wrap_depth` from) — same as `expand_wrappers`'s convenience form.
    let Expanded { cmds: all_cmds, orders: all_orders, from_snippet, langs: all_langs, .. } =
        collect_expanded(kb, &scan, lang, &|_| 4, &mut crate::guards::ForkCursor::new(&[]));
    // Mirror the engine's resolve enough to be honest: same-command literal
    // assignments resolve (scan.assignments), env lookups stay out — an env
    // dependence would make a "structural" count machine-dependent. A
    // poisoned (`None`) last write stays unresolved here exactly as it does
    // in the real resolver — this closure never consulted the environment as
    // a fallback in the first place, so the two converge on the same answer.
    let assigned: std::collections::HashMap<String, Option<String>> =
        scan.assignments.iter().cloned().collect();
    let resolve = |raw: &str| -> String {
        let mut t = crate::paths::unquote(raw).to_string();
        for _ in 0..4 {
            let next = crate::paths::expand_env_with(&t, &|n| assigned.get(n).cloned().flatten());
            if next == t {
                break;
            }
            t = next;
        }
        crate::paths::unquote(&t).to_string()
    };
    let start = CdState::NoDirectory;
    let timeline = cd_timeline(
        &all_cmds,
        &all_orders,
        &from_snippet,
        &all_langs,
        &resolve,
        None,
        &start,
    );
    (0..all_cmds.len())
        .filter(|i| {
            matches!(
                timeline.base_at(
                    all_orders.get(*i).unwrap_or(&crate::syntax::Order::Unordered),
                    all_cmds.get(*i).and_then(|c| c.chain.as_ref()),
                    &start
                ),
                CdState::Unknown(_)
            )
        })
        .count()
}

// --- where a command runs ---------------------------------------------------
//
// A command line is a sequence, and a write lands in whatever directory is in
// effect AT THAT POINT in it. Collecting every `cd` in the line into one base
// answered `echo x > f.txt && cd elsewhere` with the directory the line ENDS
// in, which is not where `f.txt` was written.

/// The plain-language cause a prompt gives when a directory change cannot be
/// placed in the sequence. Its position has to be provable, not merely
/// present: something that may not run, may run concurrently, or may run in a
/// child process leaves every later write unresolvable.
const UNPLACEABLE_CD: &str =
    "a directory change vouch cannot order (a subshell, ||, pipeline, background job, or a directory stack vouch cannot see)";

/// The cause when the caller supplied no working directory at all and the
/// destination is the run directory itself, so there is no path to fall back
/// on. The hook always supplies one; `decide_command_in` does not.
const NO_CWD: &str = "vouch was given no working directory to resolve against";

/// Why a base is unknown when a conditional directory change sits before the
/// command: the change ran only if what preceded it succeeded, and this
/// command running does not say that it did (M2.130).
const CONDITIONAL_CD: &str =
    "a directory change earlier on this line ran only if the command before it succeeded, and this command running does not prove that it did";

/// Why a drive-relative destination could not be placed: it names the current
/// directory ON a named drive, and vouch either does not know where the line
/// stands or knows it stands on a different drive. The drive ROOT is the one
/// answer it is definitely not (M2.131.2).
const DRIVE_RELATIVE: &str =
    "this names a directory on another drive, and vouch cannot tell which one that shell is in";

/// The directory a command at some position in the sequence runs in.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CdState {
    /// Not normalised — `normalize` runs once, on the joined path, exactly
    /// where it always did.
    Known(String),
    /// vouch cannot say. Carries the cause, in the words the prompt uses.
    Unknown(String),
    /// Nothing made this unknowable: the command changes no directory and the
    /// caller gave no working directory. A relative path is then judged as
    /// written, which is what vouch did before working directories were
    /// plumbed through.
    NoDirectory,
}

/// What a PLACE RULE is allowed to know about where one command runs.
///
/// Two answers, not three. `CdState` has to keep `Unknown` and `NoDirectory`
/// apart because they produce different WORDS (`unproven_cause`, below); a
/// place rule may conclude exactly the same thing from both, and collapsing
/// them here is what stops the uncertainty rule being re-derived at every
/// call site: **a place condition that GRANTS applies only when vouch can
/// prove the command runs inside the tree; a place condition that RESTRICTS
/// applies unless vouch can prove it runs outside it** (spec 2026-08-06 §The
/// one rule for uncertainty). Doubt narrows, never widens.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Place {
    /// vouch can name the directory this command runs in, normalised.
    Proven(String),
    /// Nothing places it: a directory change vouch cannot order, an
    /// unresolvable destination, or no working directory at all.
    Unproven,
}

/// What the PLACE had to say about one unrecognised occurrence — part of what
/// makes an item in the unknown-program prompt distinct, because the same name
/// at two places is two different things to say (spec §Recognition point 2).
#[derive(Debug, Clone, PartialEq, Eq)]
enum PlaceAnswer {
    /// The place changes nothing about this prompt.
    Plain,
    /// A place-scoped entry for this very name exists and did not reach this
    /// command. `trees` is that entry's `only_under` as written; `why` is
    /// which of the four ways it missed.
    Scoped { trees: String, why: ScopedMiss },
    /// No entry names this program, the place could not be proven, and a trust
    /// zone covers somewhere it might be standing.
    Missed { cause: String },
}

/// Why a place-scoped entry did not recognise a command it names.
///
/// [review] All four print the entry the operator ALREADY has and none of them
/// suggests writing one: `validate_place_scopes` refuses a second entry for a
/// scoped name, so "use the vouch-trust skill" here is advice that appends a
/// line, fails the load, and has to be rolled back. The first shape was fixed
/// when the spec grew its proven-outside row; these are the other three, and
/// the wording has to say which one it is or the prompt names A cause that is
/// not THE cause (the M2.37/M2.48/M2.58 family).
#[derive(Debug, Clone, PartialEq, Eq)]
enum ScopedMiss {
    /// The place is proven, and provably outside every tree the entry locates.
    /// `unlocatable` is any of its patterns that name no directory here — the
    /// command is not "outside" one of those, it is nowhere near a tree that
    /// does not exist, and the prompt has to say so rather than imply the
    /// operator is standing in the wrong place.
    Outside { runs_at: String, unlocatable: String },
    /// The place is proven and INSIDE the trees, so the entry's own
    /// `subcommands` list is what excluded this command. Carries the verb, or
    /// `None` for a run with no subcommand at all.
    Verb { runs_at: String, verb: Option<String> },
    /// The entry's trees name no directory on this machine, so it applies
    /// nowhere at all — never "you are outside them".
    Unlocatable,
    /// Nothing places the command, so nothing can put it inside the trees.
    Unproven(String),
}

/// Push a line unless it is already there. Two occurrences can produce the
/// very same sentence (one zone, one tree, one program, twice), and a prompt
/// that says it twice reads as two findings.
fn remember(lines: &mut Vec<String>, line: String) {
    if !lines.contains(&line) {
        lines.push(line);
    }
}

/// One line of the unmodeled-command prompt, before it is worded: which
/// occurrence it came from, the name to show, what an entry would trust, the
/// language it was read under, what the PLACE answered, and — when this run's
/// tokens could all be `standalone_flags` members — the narrow shape a fresh
/// or widened entry could list.
///
/// `narrow` is the ONE mechanism behind both the mixed-population dedup and
/// the scoped-miss remedy: the other fields are plain strings, and nothing
/// else marks which population a description came from.
///
/// Named fields rather than a tuple because three of them are `String` in a
/// row: a transposed `shown` and `desc` at a new site would compile and print
/// the sentence where the name goes.
struct UnmodeledItem {
    occurrence: usize,
    shown: String,
    desc: String,
    lang: String,
    place: PlaceAnswer,
    narrow: Option<crate::guards::ListableStandalone>,
}

/// Whether a flags-only run of occurrence `i` could be a standalone run at
/// all: BOTH halves of spec 2026-08-20 §2's condition 4, folded in one place
/// because both are properties of the occurrence rather than of the entry.
/// The record has to be faithful (nothing the parser dropped) AND closed
/// (nothing a wrapper will append). Either half alone is a hole: completeness
/// alone re-opens the appended-arguments wrapper, and both defaulting to
/// false silently kills the feature for every wrapper-nested spelling.
///
/// Fail-closed on a short array in both directions — absent completeness
/// reads false, absent appended-arguments reads true. Two loops over the same
/// parallel vectors read this, and a fold with a fail-closed default in it is
/// exactly the kind of rule that must not have two spellings.
fn standalone_eligible_at(complete: &[bool], from_input: &[bool], i: usize) -> bool {
    complete.get(i).copied().unwrap_or(false) && !from_input.get(i).copied().unwrap_or(true)
}

/// Whether two `standalone_flags` offers name the same SET of flags —
/// order-independent, because two runs that named the same members in a
/// different order are still the equal-sets case (spec 2026-08-20 §6.1),
/// never the union case.
fn same_flag_set(a: &[String], b: &[String]) -> bool {
    let mut sa = a.to_vec();
    let mut sb = b.to_vec();
    sa.sort();
    sb.sort();
    sa == sb
}

/// The narrow-offer sentence for a KEPT item after a mixed-population
/// collision united two DIFFERING `standalone_flags` sets (spec 2026-08-20
/// §6.1): regenerated from the union rather than either run's own text, so
/// the printed shape and the stored marker agree.
///
/// The sentence itself comes from `guards::standalone_offer_text`, the same
/// function the single-run description uses — the union can be kept by either
/// population, and which reading applies is all this decides.
fn narrow_offer_desc(
    kb: &crate::guards::Knowledge,
    c: &crate::shell::Cmd,
    clang: &str,
    l: &crate::guards::ListableStandalone,
) -> String {
    crate::guards::standalone_offer_text(
        &crate::guards::base_name(&c.head),
        l,
        crate::guards::is_modeled(kb, &c.head, clang),
    )
}

/// The place one command runs in, from the state the timeline put it in.
fn place_of(state: &CdState, home: &str) -> Place {
    match state {
        CdState::Known(d) => Place::Proven(normalize(d, home)),
        // Unknown AND NoDirectory: nothing proves a place. Only the cause
        // words differ, and those come from `unproven_cause`.
        _ => Place::Unproven,
    }
}

/// Where ONE command runs: the directory state at its position in the line,
/// moved by that command's own run-dir flag when it has one.
///
/// A run-dir flag says where THIS command runs (`git -C <dir> <verb>`), so it
/// is part of the run PLACE, not a detail of the write pass. It lived only in
/// the write loop, which meant `git -C <tree> <verb>` had its writes judged at
/// the flag's directory while every PLACE rule — zones, place-scoped entries,
/// guard overrides — judged it at the shell's: one command, two answers to the
/// same question, and a zone that the operator could step around by spelling
/// the directory as a flag instead of a `cd`.
///
/// Fail-closed on every uncertainty. A flag vouch cannot resolve makes the
/// place `Unknown` WITH its cause — never the shell's directory, which is a
/// place the command provably might not be running in.
///
/// Returns the provenance line too, because a verdict that silently depended
/// on a flag would repeat the defect being fixed: the write pass prints it, and
/// the place passes discard it (their own sentences already name the tree).
fn run_dir_place<F: Fn(&str) -> String>(
    kb: &crate::guards::Knowledge,
    c: &crate::shell::Cmd,
    here: &CdState,
    inherited: Option<&str>,
    resolve: &F,
) -> (CdState, Option<String>) {
    // A run-dir flag on the WRAPPER moved this command before its own flags
    // are read: `env -C <dir> tar -xf a.tar` runs `tar` in <dir>, and the
    // inner command carries no `-C` token of its own to say so. Applied
    // first, as the directory everything else composes against — exactly
    // where a `cd` one command earlier would sit — so a run-dir flag on the
    // inner command still resolves relative to it.
    let here = &match inherited {
        Some(dir) => {
            let v = resolve(dir);
            if v.contains('$') || v.contains('%') || v.contains('`') {
                CdState::Unknown(format!("the run-dir value '{v}' does not resolve"))
            } else if is_relative(&v) || drive_relative(&v).is_some() {
                match place(&v, here) {
                    Placed::At(p) => CdState::Known(p),
                    Placed::Nowhere(cause) => CdState::Unknown(cause),
                }
            } else {
                CdState::Known(v)
            }
        }
        None => here.clone(),
    };
    match crate::guards::run_dir_with_flag(kb, c) {
        (crate::guards::RunDir::Absent, _) => (here.clone(), None),
        // The causes `run_dir` reports are short internal labels; a prompt has
        // to read as a sentence, so each is given the words the operator sees.
        // The fallback is not dead code — it is what a cause added later reads
        // as until someone words it, which beats a prompt that says nothing.
        (crate::guards::RunDir::Unresolvable(cause), _) => (
            CdState::Unknown(match cause {
                "two run-dir flags" => "the command names two run-dir directories".into(),
                "run-dir flag with no value" => {
                    "the run-dir flag names no directory before the subcommand".into()
                }
                other => other.to_string(),
            }),
            None,
        ),
        (crate::guards::RunDir::Dir(raw), flag) => {
            let v = resolve(&raw);
            let state = if v.contains('$') || v.contains('%') || v.contains('`') {
                CdState::Unknown(format!("the run-dir value '{v}' does not resolve"))
            } else if is_relative(&v) || drive_relative(&v).is_some() {
                // The flag's value is itself relative to wherever the command
                // was already running (§8) — composed by `place`, so a
                // drive-relative value answers the same way it does anywhere
                // else.
                match place(&v, here) {
                    Placed::At(p) => CdState::Known(p),
                    Placed::Nowhere(cause) => CdState::Unknown(cause),
                }
            } else {
                CdState::Known(v)
            };
            let prov = match &state {
                CdState::Known(d) => Some(format!(
                    "resolved against {d} (from {} {} {raw})",
                    c.head,
                    flag.unwrap_or_default()
                )),
                _ => None,
            };
            (state, prov)
        }
    }
}

/// The wrapper-set run directory for one expanded occurrence, read
/// positionally. A short array answers `None` — the same fail-quiet reading
/// every other parallel array here gets, and the honest one: no entry means
/// no wrapper claimed to have moved this command.
fn inherited_at(all: &[Option<String>], i: usize) -> Option<&str> {
    all.get(i).and_then(|o| o.as_deref())
}

/// WHY a place could not be proven, in the words a prompt uses — the M2.58
/// standard: a prompt that says a place is unprovable without saying what made
/// it unprovable leaves the operator no move to make.
fn unproven_cause(state: &CdState) -> &str {
    match state {
        CdState::Unknown(cause) => cause,
        _ => NO_CWD,
    }
}

/// A configured list of place globs, with this machine's directories filled
/// in — and the ones that could not be.
///
/// Both halves are kept because the two DIRECTIONS read a failed expansion
/// opposite ways, and a list that had silently dropped them can only serve one
/// of them:
///
/// - A rule that GRANTS needs a tree it can name. A pattern that expands to
///   nothing names no tree, so it grants nothing — `resolved` is the whole
///   list it may consult.
/// - A rule that RESTRICTS applies unless the command is provably OUTSIDE it,
///   and nothing can be proven outside a tree vouch cannot locate. So
///   `unresolved` is not an empty list to a restriction, it is a reason to
///   apply. [review] `trust_nothing_under = ["$PROJECT_ROOT/**"]` evaluated
///   outside any repository dropped every glob, left the zone looking absent,
///   and allowed silently — the uncertainty rule inverted for the one
///   restrict-shaped rule there is.
struct PlaceTrees {
    /// `(as written, expanded)`. Written, because that is the text the
    /// operator would edit and the prompt has to name it (§5); expanded,
    /// because that is what a directory is compared against.
    resolved: Vec<(String, String)>,
    /// Patterns that name no directory on this machine, as written.
    unresolved: Vec<String>,
}

impl PlaceTrees {
    fn of(globs: Option<&Vec<String>>, home: &str, project_root: Option<&str>) -> PlaceTrees {
        let mut trees = PlaceTrees { resolved: Vec::new(), unresolved: Vec::new() };
        for g in globs.into_iter().flatten() {
            match expand(g, home, project_root) {
                Some(e) => trees.resolved.push((g.clone(), e)),
                None => trees.unresolved.push(g.clone()),
            }
        }
        trees
    }

    /// Nothing was configured at all — as opposed to configured and
    /// unresolvable, which is a rule that is present and cannot be located.
    fn is_empty(&self) -> bool {
        self.resolved.is_empty() && self.unresolved.is_empty()
    }

    /// The first tree that contains `dir`, named as the operator wrote it.
    fn holding(&self, dir: &str) -> Option<&str> {
        self.resolved
            .iter()
            .find(|(_, expanded)| crate::paths::glob_match(expanded, dir))
            .map(|(written, _)| written.as_str())
    }

    /// Every pattern, as written, for a prompt that has to name a whole rule
    /// rather than one matched glob.
    fn written(&self) -> String {
        self.resolved
            .iter()
            .map(|(w, _)| w.as_str())
            .chain(self.unresolved.iter().map(String::as_str))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// What one guard costs at one place, and the sentence saying so when a
/// `[[run.guards]]` override is what decided it.
///
/// The override selection, written out (not clever): collect every override
/// that names this guard AND matches this place under the uncertainty rule — a
/// LOOSER-than-global action is grant-shaped and matches only `Place::Proven(d)`
/// under its trees; a stricter one is restrict-shaped and matches unless the
/// place proves outside every one of its trees. If any matched, the strictest
/// matched action wins (rank: deny > ask > allow); the sentence names
/// `[[run.guards]]`, the winning `under` glob, and the global action it
/// overrode. If none matched, the global `[guards]` action stands with no
/// sentence.
///
/// An override that sets the guard to the action it ALREADY has still MATCHES.
/// [review] Dropping it from the matching set was wrong in the permissive
/// direction: a broad `C:/git/** = ask` under a global `ask`, plus a narrow
/// `C:/git/scratch/** = allow`, left the narrow one unopposed and yielded
/// ALLOW — while the identical shape with a broad entry that merely DIFFERED
/// from the global yielded ask. "The strictest matching action wins" cannot
/// depend on whether a matching entry happens to restate the global. What the
/// same action suppresses is only the CLAIM: when the winning action equals the
/// global, nothing was overridden, and the sentence says the entry agrees with
/// the global rather than that it beat it.
///
/// `cause` is the words for why a place could not be proven (`unproven_cause`),
/// carried in so an unproven restriction can say what made it unprovable rather
/// than only that it was — the M2.58 standard. It is the one addition to the
/// signature the task sketched, and it exists because `Place` deliberately
/// collapses the two unprovable states into one and the WORDS still differ.
fn resolve_guard_action(
    cfg: &Config,
    guard: &str,
    place: &Place,
    cause: &str,
    home: &str,
    project_root: Option<&str>,
) -> (Action, Option<String>) {
    let global = cfg.guard_action(guard);
    // (the action it sets, the trees the prompt must name, why it reached
    // here). The reason travels with the match because the three ways an
    // override can reach one command are three different things to tell the
    // operator, and a single sentence for all of them would say "you are
    // standing in this tree" about a tree vouch could not even locate.
    let mut matched: Option<(Action, String, String)> = None;
    for o in &cfg.run.guard_overrides {
        let Some(&want) = o.actions.get(guard) else {
            continue;
        };
        let trees = PlaceTrees::of(Some(&o.under), home, project_root);
        let reached = if rank(want) < rank(global) {
            // Grant-shaped. A tree vouch cannot locate names no directory, so
            // it cannot put this command inside one: `resolved` is the whole
            // list a grant may consult, and an unproven place unlocks nothing.
            match place {
                Place::Proven(d) => trees
                    .holding(d)
                    .map(|g| (g.to_string(), format!("where this command runs: {d}"))),
                Place::Unproven => None,
            }
        } else {
            // Restrict-shaped. It applies until the place proves the command
            // runs OUTSIDE it — and nothing can be proven outside a tree vouch
            // cannot locate, so an unresolvable pattern is a reason to apply
            // rather than a pattern to drop.
            match place {
                Place::Proven(d) => match trees.holding(d) {
                    Some(g) => Some((g.to_string(), format!("where this command runs: {d}"))),
                    None if !trees.unresolved.is_empty() => Some((
                        trees.unresolved.join(", "),
                        format!(
                            "where this command runs: {d}\n  \
                             that is outside every tree vouch could locate, but a pattern that \
                             names no directory on this machine cannot be proven outside, and a \
                             rule that restricts applies until it is"
                        ),
                    )),
                    None => None,
                },
                Place::Unproven => Some((
                    trees.written(),
                    format!(
                        "vouch cannot prove where this command runs: {cause}\n  \
                         a rule that restricts applies unless vouch can prove the command runs \
                         outside it"
                    ),
                )),
            }
        };
        let Some((named, why)) = reached else {
            continue;
        };
        if matched.as_ref().map_or(true, |(w, _, _)| rank(want) > rank(*w)) {
            matched = Some((want, named, why));
        }
    }
    let Some((won, named, why)) = matched else {
        return (global, None);
    };
    // What the entry DID, which is not always "overrode". When the winning
    // action equals the global, the entry agreed with it — and saying so still
    // matters, because `guards.<name>` on its own is then NOT the off-switch:
    // loosening the global would leave this entry standing over it, and a
    // prompt naming only the global would be naming a switch that does not
    // switch (§5).
    let did = if won == global {
        format!(
            "it sets {guard} = \"{}\" here too, the same action the global \
             guards.{guard} already gives — so changing guards.{guard} alone will not \
             change this",
            action_word(won)
        )
    } else {
        format!(
            "it sets {guard} = \"{}\" here, overriding the global guards.{guard} = \"{}\"",
            action_word(won),
            action_word(global)
        )
    };
    // Deliberately written to take a PREFIX, because this one sentence is
    // read in two voices: `setting: …` when the override held the prompt open,
    // and `allowed by …` when it is what let the line through. An override
    // that grants has to name itself in the journal for the same reason a zone
    // does — otherwise `vouch why` answers "allowed by vouch policy" for a
    // decision the operator's own entry made.
    let sentence = format!(
        "the [[run.guards]] entry under = {named}: {did}\n  \
         {why}\n  \
         to change that, take {guard} out of that [[run.guards]] entry, or narrow its under list"
    );
    (won, Some(sentence))
}

/// The directory changes in one command line, each at its position.
struct CdTimeline {
    /// The state AFTER each ordered directory change, by sequence position,
    /// with the MOVER's own chain position — which is what decides whether a
    /// later command's execution implies the move happened (M2.130) — and
    /// whether that change STANDS ON ITS OWN: an absolute destination
    /// composes against nothing, so it ends any uncertainty an earlier
    /// conditional change left behind.
    events: Vec<(u32, CdState, Option<crate::syntax::ChainPos>, bool)>,
    /// A directory change whose position is not provable. One of these makes
    /// every relative destination in the line unresolvable, wherever it sits:
    /// the change may have run before it, after it, or not at all.
    unplaceable: bool,
}

impl CdTimeline {
    /// The directory a command at this position runs in. `start` is the state
    /// the line began in — the caller's directory, its absence, or its being
    /// unknown — and is what a command before every directory change in the
    /// line inherits.
    fn base_at(
        &self,
        order: &crate::syntax::Order,
        chain: Option<&crate::syntax::ChainPos>,
        start: &CdState,
    ) -> CdState {
        if self.unplaceable {
            return CdState::Unknown(UNPLACEABLE_CD.to_string());
        }
        if self.events.is_empty() {
            return start.clone();
        }
        match order {
            // EVERY change before this command, not just the last one: each
            // recorded state already has the earlier changes composed into
            // it, so one conditional change poisons every state after it —
            // an unconditional `cd sub` two statements later inherits the
            // conditional directory and would otherwise hand it on as
            // certain (found by the task review, reproduced).
            crate::syntax::Order::Seq(n) => {
                let mut before = self.events.iter().filter(|(s, ..)| s < n).peekable();
                if before.peek().is_none() {
                    return start.clone();
                }
                // Uncertainty accumulates and is CLEARED by a later change
                // that stands on its own. A conditional change poisons every
                // state after it, because each state has the earlier ones
                // composed in — but a later ABSOLUTE change composes against
                // nothing, so wherever the shell had got to stops mattering
                // (found by the round-2 verifier: without this, `ls && cd d;
                // cd <absolute>; echo x > f` asked for no reason).
                let mut uncertain = false;
                let mut last = start;
                for (_, st, mover, independent) in before {
                    if !folds_into(mover.as_ref(), chain) {
                        uncertain = true;
                    } else if *independent {
                        uncertain = false;
                    }
                    last = st;
                }
                if uncertain {
                    CdState::Unknown(CONDITIONAL_CD.to_string())
                } else {
                    last.clone()
                }
            }
            // This command's own position is not provable, so which of the
            // directory changes had already run when it wrote is not either.
            crate::syntax::Order::Unordered => CdState::Unknown(UNPLACEABLE_CD.to_string()),
        }
    }
}

/// True for a `pushd`/`push-location` stack-rotate argument: `+2`, `-2`.
///
/// These name a SLOT in the directory stack, not a path. `pushd +1` rotates
/// to whatever was pushed earlier — a directory this command line never
/// states — so it can only be an unknown, never a directory called `+1`.
///
/// Scoped to the `Stack` kind on purpose: `cd +1` has no rotate form, so
/// there `+1` really would be a relative directory of that name, and
/// poisoning it would be vouch inventing a hazard rather than reporting one
/// (§4).
fn is_stack_rotate(arg: &str) -> bool {
    match arg.strip_prefix(['+', '-']) {
        Some(n) => !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()),
        None => false,
    }
}

/// The per-language destination-token vocabulary, spec 2026-07-31 §5. What
/// stays in code here is the VOCABULARY, not program names — nothing below
/// names `cd`, `pushd`, `Set-Location`, or any other head.
///
/// 1. Both languages: a token still holding a variable, backtick, or glob
///    metacharacter is unknown — globs expand before `cd` runs, so the
///    literal spelling is not the directory.
/// 2. bash: any `~`-prefixed token other than plain home (`~` alone, or
///    `~/...`) is unknown — `~-`/`~+`/`~<digit>` walk OLDPWD/PWD/the
///    directory stack, and `~name` names ANOTHER user's home. None of those
///    is derivable from this command line. Plain `~`/`~/x` stay untouched —
///    `paths::normalize` still expands them against `home`. (`-` alone is
///    unreachable here, by `dir_change_candidates`'s own explicit `"-"` rule
///    rather than by accident of a hardcoded `starts_with('-')` — task 7:
///    `flags::flag_shaped` reads a BARE `-` as `NotFlag`, the ordinary
///    "read from stdin" convention everywhere else vouch reads a flag, so
///    the general-purpose primitive cannot be the thing that catches this
///    grammar-specific special case.)
/// 3. PowerShell: `-` and `+` as the WHOLE token are unknown — both walk the
///    location-history stack on 7.x and raise an error on 5.1, so "unknown"
///    is the one answer that covers both. (Bare `-` is likewise unreachable
///    here, for the same `dir_change_candidates` reason as bash above; `+`
///    is not flag-shaped under any prefix this module declares, so it still
///    reaches this function exactly as it always did.)
fn is_unresolvable_token(d: &str, lang: &str) -> bool {
    if d.contains('$') || d.contains('%') || d.contains('`')
        || d.contains('*') || d.contains('?') || d.contains('[')
    {
        return true;
    }
    match lang {
        "bash" => d.starts_with('~') && d != "~" && !d.starts_with("~/"),
        "powershell" => d == "-" || d == "+",
        _ => false,
    }
}

/// A directory token, once resolved, classified into a state: a token the
/// language vocabulary above cannot resolve is unknown, a relative path
/// composes against whatever directory was already in effect, and an
/// absolute path stands on its own. Shared by the `Stated` and `Stack`
/// kinds — both took this same destination once the swap/rotate/
/// option-shaped forms above them had already been ruled out.
fn classify_destination(d: &str, state: &CdState, lang: &str) -> CdState {
    if is_unresolvable_token(d, lang) {
        CdState::Unknown(
            "the command changes directory to somewhere vouch cannot resolve".to_string(),
        )
    } else if is_relative(d) || drive_relative(d).is_some() {
        // A relative change composes against where it already was: `cd a &&
        // cd b` is `a/b`, not `b`. Composed by `place`, the same function
        // every written destination goes through, so a drive-relative
        // spelling gets one answer here and there rather than two.
        match place(d, state) {
            Placed::At(p) => CdState::Known(p),
            Placed::Nowhere(cause) => CdState::Unknown(cause),
        }
    } else {
        CdState::Known(d.to_string())
    }
}

/// The grammar walk, spec 2026-07-31 §4 rules 1-4 (rule 1 amended
/// 2026-08-02, commit 5de2603), over one command's already RESOLVED
/// arguments. `prog` is the entry's own knowledge — `None` for a head that
/// reached this point some other way (it never does today: membership
/// already required `entry_for` to answer, but this function does not
/// assume that, so an absent entry simply declares nothing) — and an entry
/// that declares nothing fails every option-shaped token closed via rule 4,
/// exactly like one that never existed.
///
/// Returns the destination CANDIDATES left after every declared flag is
/// consumed. `Err(Some(flag))` means rule 4 fired on that exact token — an
/// option-shaped token this entry never declared — carried out so the
/// caller can name it in the reason (spec 2026-07-31 §9.1: this is the one
/// instrument `vouch doctor` has for PowerShell noise no bash corpus can
/// predict). `Err(None)` covers every other failure: the amended rule 1 (a
/// dest-dir flag's consumed value was itself option-shaped, `-`, or `+` — a
/// binding error, not a directory) and a declared value-option left with no
/// value to consume. All of these are LOAD-BEARING, not a fallback — never
/// soften any of them by guessing what an undeclared flag or a suspicious
/// value means (§0).
///
/// Reads the shared flag primitive (`crate::flags`), not the old
/// exact-string `flag_matches` (task 7 — the same whole-token comparison
/// that made M2.128 a live wrong ALLOW for `written_paths` backed this walk
/// too): `Set-Location -Path:C:/x` (colon-attach) and `Set-Location -pa
/// C:/x` (abbreviated) used to match nothing in EITHER declared list, fall
/// through to rule 4, and ask — safe, but wrong, the same way an operator's
/// valid `Set-Content -pa` spelling was wrong before `written_paths`
/// migrated (M2.128). `classify`/`spells` read the same attached and
/// abbreviated shapes every other derivation consumer does; abbreviation
/// policy is the derivation policy (spec §4.1.7): accepted for a
/// case-insensitive entry (every shipped `dest_dir_flags` entry today, the
/// PowerShell movers), refused — loudly, routed to rule 4 below, never
/// silently matched or silently dropped — for a case-sensitive one.
///
/// `dest_dir_flags` is folded into the SAME value_options list `classify`
/// searches — it has one "consumes a following or attached value" list, not
/// two — and rule 1 vs rule 2 is decided AFTER classification, by checking
/// which of the two DECLARED lists the canonical flag name actually came
/// from.
///
/// One deliberate non-adoption: `--` does NOT end flag classification here
/// the way `ArgWalk` and every other migrated consumer let it. The bash
/// `cd` entry declares no grammar at all (spec §6 table), so `cd -- x`
/// asking is pinned, on purpose (`bash_writes_test.rs`'s
/// `a_bash_end_of_options_marker_is_undeclared_and_asks`) — softening rule 4
/// for `--` would be exactly the softening §0 forbids. `Class::EndOfOptions`
/// is therefore read as rule 4's undeclared-option case, same as
/// `Undescribed`, not as license to trust whatever follows it.
fn dir_change_candidates(
    args: &[String],
    prog: Option<&crate::guards::Program>,
) -> Result<Vec<String>, Option<String>> {
    let empty: Vec<String> = Vec::new();
    let (dest_dir_flags, value_options, no_value_options, flag_prefix, case_sensitive, colon_attach) =
        match prog {
            Some(p) => (
                &p.dest_dir_flags,
                &p.value_options,
                &p.no_value_options,
                &p.flag_prefix,
                p.case_sensitive_flags.unwrap_or(false),
                p.languages.iter().any(|l| l == "powershell"),
            ),
            None => (&empty, &empty, &empty, &empty, false, false),
        };
    let abbreviation = if case_sensitive {
        crate::flags::Abbrev::Refuse
    } else {
        crate::flags::Abbrev::Accept
    };
    let merged_value_options: Vec<String> =
        dest_dir_flags.iter().cloned().chain(value_options.iter().cloned()).collect();
    let vocab = crate::flags::Vocab {
        value_options: &merged_value_options,
        no_value_options,
        flag_prefix,
        case_sensitive,
        abbreviation,
        colon_attach,
    };
    let mut walk = crate::flags::ArgWalk::new(&vocab);

    let mut candidates = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        // A bare `-` is rule 4's "option-shaped, undeclared" bucket,
        // unconditionally — `flags::flag_shaped` requires more than one
        // character (a lone `-` is the ordinary "read from stdin"
        // convention everywhere else vouch reads a flag), so `classify`
        // would read it as `NotFlag` and let it become a candidate. For a
        // directory-change grammar it never is one: bash's `cd -` and
        // PowerShell's `Set-Location -` both walk history (`$OLDPWD`, the
        // location stack), not a literal directory called `-`
        // (`is_unresolvable_token`'s doc comment explains why the per-
        // language vocabulary does not catch this instead). The
        // pre-primitive code caught this the same way, just as a side
        // effect of its own blanket `starts_with('-')` shape check, which
        // matched a bare `-` too — this keeps that reason text (§9.1's
        // undeclared-option line) unchanged rather than routing it through
        // a different, less specific "unresolved" message.
        if a == "-" {
            return Err(Some(a.clone()));
        }
        match walk.next(a) {
            crate::flags::Class::EndOfOptions => return Err(Some(a.clone())),
            crate::flags::Class::NotFlag => {
                candidates.push(a.clone());
                i += 1;
            }
            crate::flags::Class::Value { flag, attached: Some(v) } => {
                if dest_dir_flags.iter().any(|d| d == &flag) {
                    // Rule 1: an attached value is unambiguous — the token's
                    // own attach syntax (`=`, colon, short-joined) already
                    // bound it to this flag, so there is no PowerShell
                    // parameter-binding ambiguity for the amended rule 1
                    // guard below to worry about (a BARE next token can bind
                    // to a later switch instead; an attached one cannot).
                    candidates.push(v);
                }
                // else: rule 2, consumed as this OTHER flag's value, not a
                // candidate — attached means nothing further to consume.
                i += 1;
            }
            crate::flags::Class::Value { flag, attached: None } => {
                if dest_dir_flags.iter().any(|d| d == &flag) {
                    // Rule 1 (AMENDED 2026-08-02, commit 5de2603): the value
                    // IS a destination candidate — UNLESS the value itself
                    // is option-shaped, `-`, or `+`. `Set-Location -Path
                    // -PassThru` does not move: PowerShell throws a binding
                    // error, because `-PassThru` binds as A FLAG, not as
                    // `-Path`'s value. Taking it as a candidate anyway
                    // composed a base named literally `<cwd>/-PassThru` —
                    // rule 5's own rationale (a binding error moves nothing,
                    // so fail closed) applies to the consumed value exactly
                    // as it applies to candidate counting, so this is the
                    // same unresolved unknown as every other rule-4/5 case,
                    // not a directory.
                    let v = args.get(i + 1).ok_or(None)?;
                    if v.starts_with('-') || v == "+" {
                        return Err(None);
                    }
                    candidates.push(v.clone());
                } else {
                    // Rule 2: the value is consumed, and is NOT a candidate.
                    args.get(i + 1).ok_or(None)?;
                }
                i += 2;
            }
            crate::flags::Class::Bool { .. } => {
                // Rule 3: skipped outright — it takes no value at all.
                i += 1;
            }
            crate::flags::Class::Undescribed { token } => {
                // Rule 4: an option-shaped token this entry never declared.
                // Named, not just failed — doctor's third bucket (spec §9.1)
                // aggregates exactly this token out of the reason it ends up
                // in.
                return Err(Some(token));
            }
            crate::flags::Class::RefusedAbbrev { token, .. } => {
                // Same rule-4 treatment as `Undescribed`, not a plain
                // non-match: a refused abbreviation is unknowable, never
                // silently matched (that would move the shell somewhere the
                // entry's OWN case-sensitive posture just refused to name)
                // and never silently dropped as if it were merely undeclared
                // (that would lose the fact that it prefixes a real declared
                // flag from the reason vouch gives).
                return Err(Some(token));
            }
        }
    }
    Ok(candidates)
}

/// The exact marker line a rule-4 failure appends to `UNPLACEABLE_CD`, in
/// `destination_from_candidates` just below. Kept side by side with
/// `parse_undeclared_option_line`, its inverse, so the two can never drift —
/// `vouch doctor` (`src/main.rs`) scrapes this same line back out of a
/// recorded journal reason for its third bucket (spec 2026-07-31 §9.1): a
/// rule-4 reason is a historical fact rather than something to re-check
/// against current knowledge the way doctor's other two buckets are.
pub fn undeclared_option_line(flag: &str, head: &str) -> String {
    format!("  the option '{flag}' is not described for '{head}'")
}

/// The inverse of `undeclared_option_line`, just above: pulls `(head, flag)`
/// back out of one line of a recorded journal reason. `vouch doctor`
/// (`src/main.rs`) is the only caller.
pub fn parse_undeclared_option_line(line: &str) -> Option<(&str, &str)> {
    let rest = line.trim_start().strip_prefix("the option '")?;
    let (flag, rest) = rest.split_once("' is not described for '")?;
    let head = rest.strip_suffix('\'')?;
    Some((head, flag))
}

/// Rule 5: exactly one candidate is the destination; zero or several is
/// unknown — `cd a b` and `Set-Location C:\x -StackName demo` both fail
/// closed here rather than composing a base from a command that never moved.
///
/// A rule-4 failure carries the undeclared token, and gets one line appended
/// to the reason vouch already gives — `head` is the matched entry name
/// (already `base_name`'d by the caller), `flag` the resolved token rule 4
/// rejected (§8: resolved, never the raw one — M2.38). This is a
/// REASON-TEXT addition only: the decision, the `unresolved_path` construct
/// name, and the setting line `where_it_lands` prints are all untouched.
/// `vouch doctor` parses this exact line back out of the journal (via
/// `parse_undeclared_option_line`, above) to aggregate PowerShell noise no
/// bash corpus could measure in advance (spec 2026-07-31 §9.1).
fn destination_from_candidates(
    cands: &Result<Vec<String>, Option<String>>,
    state: &CdState,
    lang: &str,
    head: &str,
) -> CdState {
    match cands {
        Ok(c) if c.len() == 1 => classify_destination(&c[0], state, lang),
        Err(Some(flag)) => {
            CdState::Unknown(format!("{UNPLACEABLE_CD}\n{}", undeclared_option_line(&flag, head)))
        }
        _ => CdState::Unknown(UNPLACEABLE_CD.to_string()),
    }
}

/// The `Stated` kind's own walk. Rule 6: bare is zero arguments BEFORE any
/// consumption — a command emptied BY consumption (`Set-Location -StackName
/// demo`) is not bare, it is zero candidates, handled by
/// `destination_from_candidates` like any other zero-or-several case. A
/// truly bare command goes home on a bash line — bash documents and does it
/// — and is unknown on a PowerShell line, where 5.1 is probed to stay put
/// (a no-op) and 7.x is doc-claimed to differ: a base that depends on which
/// PowerShell runs is not one vouch can state.
///
/// `home: None` means the caller has no home directory to offer at all — a
/// bare bash `cd` is then Unknown too, naming the cause, rather than a
/// fabricated `Known("")` that would compose relative writes against an
/// empty base and get them wrong silently.
fn stated_destination(
    args: &[String],
    cands: &Result<Vec<String>, Option<String>>,
    state: &CdState,
    lang: &str,
    head: &str,
    home: Option<&str>,
) -> CdState {
    if args.is_empty() {
        return if lang == "bash" {
            match home {
                Some(h) => CdState::Known(h.to_string()),
                None => CdState::Unknown("the home directory is not known".to_string()),
            }
        } else {
            CdState::Unknown(UNPLACEABLE_CD.to_string())
        };
    }
    destination_from_candidates(cands, state, lang, head)
}

/// The `Stack` kind's own walk. Its bare form is the SWAP — `pushd` with no
/// arguments goes to whatever was pushed earlier, a directory this command
/// line never states — unknown in every language, never home; that is a
/// property of the kind, not of which shell is running it, so it is decided
/// here rather than in `destination_from_candidates`'s zero-candidates case
/// (same verdict, different reason it holds). `is_stack_rotate` stays a
/// separate check: `+2`/`-2` name a STACK SLOT, and only the `-`-prefixed
/// half of that is "option-shaped" in the sense rule 4 means — `+2` needs
/// its own recognition or it would read as a relative directory named `+2`.
fn stack_destination(
    args: &[String],
    cands: &Result<Vec<String>, Option<String>>,
    state: &CdState,
    lang: &str,
    head: &str,
) -> CdState {
    if args.iter().any(|a| is_stack_rotate(a)) {
        return CdState::Unknown(UNPLACEABLE_CD.to_string());
    }
    if args.is_empty() {
        return CdState::Unknown(UNPLACEABLE_CD.to_string());
    }
    destination_from_candidates(cands, state, lang, head)
}

/// Every directory change in the line, composed left to right.
///
/// Membership — whether a command is a mover at all — comes from the
/// knowledge file's `changes_dir` claim (`dir_change_kind`), read under THAT
/// command's own language (`langs`, parallel to `cmds`): a snippet command
/// carries the snippet's language, never the host's (spec 2026-07-31 §2), so
/// `sl` inside a `powershell -Command "…"` snippet on a bash line is still
/// found as PowerShell's mover, not silently missed as bash's non-mover.
fn cd_timeline(
    cmds: &[crate::shell::Cmd],
    orders: &[crate::syntax::Order],
    from_snippet: &[bool],
    langs: &[String],
    resolve: &dyn Fn(&str) -> String,
    home: Option<&str>,
    start: &CdState,
) -> CdTimeline {
    let kb = crate::guards::in_effect();
    // The Program entry travels alongside the kind, from here on: the kind
    // says WHETHER this command moves the shell, the entry's own
    // `dest_dir_flags`/`value_options`/`no_value_options`/
    // `case_sensitive_flags` say what its ARGUMENTS mean (spec §4).
    // `dir_change_entry` reads both off the SAME `entry_for` scan — it used
    // to be two separate scans of the same `(head, lang)`, one for the kind
    // and one for the entry.
    let mut ordered: Vec<(u32, &crate::shell::Cmd, crate::guards::DirChangeKind, Option<&crate::guards::Program>, &str, String)> = Vec::new();
    let mut unplaceable = false;
    for (i, c) in cmds.iter().enumerate() {
        // A missing language is not a provable one either — falls back to
        // "bash" only because every vector here is built parallel, index for
        // index, by the one caller in `decide_command_at`; it never actually
        // runs short.
        let lang = langs.get(i).map(String::as_str).unwrap_or("bash");
        let head = crate::guards::base_name(&c.head);
        let (kind, prog) = match crate::guards::dir_change_entry(kb, &head, lang) {
            Some((k, p)) if k != crate::guards::DirChangeKind::No => (k, Some(p)),
            _ => continue,
        };
        match (orders.get(i), from_snippet.get(i)) {
            // A directory change inside a wrapped snippet has no position in
            // the outer sequence — the snippet was handed to another scanner
            // and its statements were never placed against this line's.
            (Some(crate::syntax::Order::Seq(n)), Some(false)) => {
                ordered.push((*n, c, kind, prog, lang, head))
            }
            _ => unplaceable = true,
        }
    }
    ordered.sort_by_key(|(n, ..)| *n);

    let mut state = start.clone();
    let mut events: Vec<(u32, CdState, Option<crate::syntax::ChainPos>, bool)> = Vec::new();
    for (n, c, kind, prog, lang, head) in ordered {
        // Classify the arguments on their RESOLVED text, never the raw
        // token. The scanner keeps the quotes it found, so `cd "-"` arrives
        // as the three characters `"-"`: it is not equal to `-` and it does
        // not start with `-`, so reading it raw made it a relative DIRECTORY
        // named `-`, and `cd "-" && echo x > f.txt` composed a base that does
        // not exist and ALLOWED, while the shell went to OLDPWD — a place
        // named nowhere in the command. The same raw read made a quoted flag
        // (`cd "-P" <dir>`) the destination and never looked at the real path
        // after it. Resolving first is the §8 chain these tokens were missing.
        let args: Vec<String> = c.args.iter().map(|a| resolve(a)).collect();
        // ONE candidate walk per directory change, read by both the
        // destination derivation and the independence test below — it builds a
        // merged option list and classifies every token, so running it twice
        // for one command is work nobody needs.
        let cands = dir_change_candidates(&args, prog);
        state = match kind {
            // Changes directory to somewhere never derivable from the
            // command line — every form is unknown, always.
            crate::guards::DirChangeKind::Unstated => CdState::Unknown(UNPLACEABLE_CD.to_string()),
            crate::guards::DirChangeKind::Stack => stack_destination(&args, &cands, &state, lang, &head),
            crate::guards::DirChangeKind::Stated => stated_destination(&args, &cands, &state, lang, &head, home),
            // Filtered out above: membership requires a kind other than `No`.
            crate::guards::DirChangeKind::No => unreachable!("dir_change_entry filters this out"),
        };
        // Stated absolutely? Read from the same candidate walk the
        // destination itself came from, never from the composed result — a
        // composed path and an absolute one that happens to sit under it are
        // the same text ("C:/git" then "C:/git/vouch-dev"), and only the walk
        // knows which was written.
        let independent = matches!(
            &cands,
            Ok(c) if c.len() == 1
                && !is_relative(&c[0])
                && drive_relative(&c[0]).is_none()
                && !is_unresolvable_token(&c[0], lang)
        );
        events.push((n, state.clone(), c.chain.clone(), independent));
    }
    CdTimeline { events, unplaceable }
}

/// Does the MOVER's effect fold into this command's base? (M2.130, design
/// §6.3.) The question is not "did the mover come first" — the walk already
/// answered that — but "does THIS command running prove the mover ran and
/// succeeded".
///
/// Two ways it does. An UNCONDITIONAL mover always folds: it has no chain, or
/// it is the first member of one, so nothing had to succeed for it to run
/// (`cd d; echo x > f` keeps today's answer, and so does every ordinary
/// sequence). Otherwise both have to be in the same and-or chain, and the
/// mover has to sit inside the run of members whose success this command's
/// own execution certifies: at or after `and_run_from`, and before this
/// command's own index. `and_run_from` is where a `||` link reset the run, so
/// `ls && cd d || echo x > f` fails this test exactly as it should — the
/// write runs when the `cd` FAILED.
///
/// Everything else is an honest Unknown rather than a guess in either
/// direction: a command after a `;` restart does not imply the conditional
/// mover before it ran, and vouch cannot see which way it went.
/// `pub` so the corpus measurement asks THIS function rather than
/// re-deriving the rule: two copies of a fold rule drifting apart is how a
/// measurement ends up describing a judgement nobody makes.
pub fn folds_into(
    mover: Option<&crate::syntax::ChainPos>,
    cmd: Option<&crate::syntax::ChainPos>,
) -> bool {
    let Some(m) = mover else {
        return true;
    };
    if m.idx == 0 {
        return true;
    }
    match cmd {
        Some(c) => c.id == m.id && m.idx >= c.and_run_from && m.idx < c.idx,
        None => false,
    }
}

/// A destination, once vouch has worked out which directory it lands in.
enum Placed {
    At(String),
    /// vouch cannot say where. Carries the cause, in the prompt's words.
    Nowhere(String),
}

/// Put a destination in the directory it lands in. Absolute destinations do
/// not depend on it and are returned as they are.
fn place(t: &str, base: &CdState) -> Placed {
    // `C:name` is drive-RELATIVE: it names the current directory ON drive C,
    // which is this line's own directory only when the line stands on that
    // drive. Answered HERE rather than at one caller, because every consumer
    // of `is_relative` — a redirect, a directory-change destination, a
    // run-dir flag's value, a program's declared write — asks the same
    // question and a rule living at one of them silently folds the others'
    // drive-relative paths into whatever place they happen to have (found by
    // the task review, measured as four corpus rows moving toward allow).
    if let Some((letter, rest)) = drive_relative(t) {
        return match base {
            CdState::Known(d)
                if d.as_bytes().first().map(|b| (*b as char).to_ascii_uppercase())
                    == Some(letter.to_ascii_uppercase()) =>
            {
                Placed::At(join(d, &rest))
            }
            // A proven place on ANOTHER drive says nothing about where this
            // lands, and neither does no place at all. The drive ROOT is the
            // one answer it is definitely not (M2.131.2).
            _ => Placed::Nowhere(DRIVE_RELATIVE.to_string()),
        };
    }
    if !is_relative(t) {
        return Placed::At(t.to_string());
    }
    match base {
        CdState::Known(d) => Placed::At(join(d, t)),
        CdState::Unknown(cause) => Placed::Nowhere(cause.clone()),
        // No directory to resolve against and nothing that made it
        // unknowable: judge the path as written, as vouch always has.
        CdState::NoDirectory => Placed::At(t.to_string()),
    }
}

fn join(dir: &str, rel: &str) -> String {
    format!("{}/{}", dir.trim_end_matches('/').replace('\\', "/"), rel)
}

/// The program whose declared write a destination is — name, verb, and the
/// verb's second word. `None` for a redirect, which belongs to the shell and
/// is never judged by a write scope.
///
/// One alias, because the placed destinations and the unplaceable ones carry
/// exactly the same triple and are matched against the same `[[write.scope]]`
/// rule: two spellings of it could only drift apart.
type By = Option<(String, Option<String>, crate::guards::SecondWord)>;

/// A destination the walk could not place, with everything a prompt about it
/// needs — not just the prompt.
///
/// The generic `unresolved_path` text is still built where the miss is found,
/// but a `[[write.scope]]` rule words this case its own way (spec prompt
/// table, "write scope, target unprovable") and cannot reuse that text: it
/// names `lang.<lang>.constructs.unresolved_path` as the way to stop
/// asking, and that setting does not turn a scoped program's prompt off —
/// a scope RESTRICTS, so it applies until vouch can prove the write lands
/// inside its trees. A prompt naming an off-switch that does not switch it
/// off is the M2.12 defect class, so the ingredients travel and the scoped
/// sentence is built from them.
struct Unplaced {
    /// The `unresolved_path` prompt, used when no scope claims this write.
    generic: String,
    /// Why the walk could not place it, in the words a prompt uses.
    cause: String,
    /// What was being placed, when there is something to name.
    what: Option<String>,
    /// The program whose declared write this is.
    by: By,
}

/// The prompt for a write a `[[write.scope]]` rule governs and vouch could not
/// resolve. It names the rule — the scope is why an unprovable destination
/// matters here — and keeps the walk's own cause, because saying a place is
/// unprovable without saying what made it unprovable leaves the operator no
/// move to make.
///
/// Both unprovable shapes come here: a destination no directory can be found
/// for, and one that still holds a variable after every expansion. They differ
/// only in the cause.
///
/// `decided_by` is the setting whose action OVERTOOK the scope's own ask —
/// `unresolved_path` set to deny, or `write.default` doing the same in the arm
/// that reads it. When one did, it is the decider and the prompt says so: the
/// scope is still why an unprovable destination matters here, but taking the
/// program out of `[[write.scope]]` would not lift a refusal the scope did not
/// make, and offering that as the remedy is a prompt naming an off-switch that
/// does not switch it off (§5, the M2.12 defect class).
fn scope_unprovable(
    rule: &crate::config::WriteScope,
    cause: &str,
    what: Option<&str>,
    decided_by: Option<(&str, Action)>,
) -> String {
    let mut r = format!(
        "vouch stopped on: write scope\n  \
         [[write.scope]] limits {} to {}, and vouch cannot prove this write lands inside \
         them — {cause}\n",
        rule.programs.join(", "),
        rule.only_under.join(", ")
    );
    if let Some(w) = what {
        r.push_str(&format!("  what vouch was placing: {w}\n"));
    }
    match decided_by {
        Some((setting, a)) => r.push_str(&format!(
            "  what decided this: {setting} is \"{}\", which is stricter than the ask the \
             scope alone would give — taking the program out of [[write.scope]] would not \
             change it\n  \
             to change that, set {setting} to a less strict action, or spell the destination \
             so vouch can place it",
            action_word(a)
        )),
        None => r.push_str(
            "  to change that, run the command where vouch can place its destination, spell \
             that destination in full, or take the program out of [[write.scope]]",
        ),
    }
    r
}

/// The prompt for a write whose DIRECTORY vouch cannot name.
fn where_it_lands(lang: &str, cause: &str, path: Option<&str>) -> String {
    let mut r = format!(
        "vouch stopped on: unresolved_path\n  \
         what that means: vouch cannot tell which directory this command's \
         writes land in — {cause}\n"
    );
    if let Some(p) = path {
        r.push_str(&format!("  the relative path: {p}\n"));
    }
    r.push_str(&format!(
        "  to allow this permanently, set lang.{lang}.constructs.unresolved_path = \"allow\"\n  \
         that setting applies to EVERY command using this, from now on\n  \
         guards still apply — allowing this does not allow what a command does"
    ));
    r
}

/// The prompt for a write whose ARGUMENT vouch cannot pick out: a token the
/// knowledge file does not describe sits where the destination is counted
/// from, so the count and the order after it prove nothing.
fn which_token(lang: &str, flag: &str, sub: &str) -> String {
    format!(
        "vouch stopped on: unresolved_path\n  \
         what that means: vouch cannot tell which argument is the destination — \
         '{flag}' after '{sub}' is not described\n  \
         to allow this permanently, set lang.{lang}.constructs.unresolved_path = \"allow\"\n  \
         that setting applies to EVERY command using this, from now on\n  \
         guards still apply — allowing this does not allow what a command does"
    )
}

/// The file a colon-bearing local destination actually writes: on NTFS
/// `notes.txt:hidden` is an alternate data stream ATTACHED to `notes.txt`, so
/// the file the write rules have to answer about is the part before the colon
/// (M2.131.4). `None` when the path carries no such colon — the drive prefix
/// (`C:/…`) is not one, and neither is a path with no colon at all.
///
/// Applied to the COMPOSED destination, after the run place has been folded
/// in, so the drive prefix is always at the front where this can skip it.
fn stream_base(p: &str) -> Option<String> {
    let q = p.replace('\\', "/");
    let start = if drive_absolute(&q) { 2 } else { 0 };
    q[start..].find(':').map(|i| q[..start + i].to_string())
}

/// True when a path has no root and so depends on the working directory.
fn is_relative(p: &str) -> bool {
    let p = p.replace('\\', "/");
    if p.starts_with('/') || p.starts_with('~') || p.starts_with('$') {
        return false;
    }
    // `C:/…` or a bare `C:` — but NOT `C:name`, which is drive-RELATIVE: it
    // names the current directory ON that drive, which is neither the drive
    // root nor necessarily this line's own directory. Reading it as absolute
    // silently rewrote `C:name` to `C:/name` and judged a write to the root
    // of the drive (M2.131.2).
    !drive_absolute(&p)
}

/// `C:/x`, `C:\x` or a bare `C:`: a path anchored at a named drive.
fn drive_absolute(p: &str) -> bool {
    let b = p.as_bytes();
    b.len() >= 2
        && b[0].is_ascii_alphabetic()
        && b[1] == b':'
        && (b.len() == 2 || b[2] == b'/' || b[2] == b'\\')
}

/// The drive letter of a DRIVE-RELATIVE spelling (`C:name`) and the rest of
/// it. `None` for anything else, drive-absolute paths included.
fn drive_relative(p: &str) -> Option<(char, String)> {
    let q = p.replace('\\', "/");
    let b = q.as_bytes();
    if b.len() > 2 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] != b'/' {
        return Some((b[0] as char, q[2..].to_string()));
    }
    None
}

/// True for an scp/rsync destination on another machine: `[user@]host:path`.
///
/// Not a local file, so the local path rules have nothing to say about it.
/// Distinguishing it from `C:/…` matters: a Windows drive is also `letter`
/// followed by a colon, but it is exactly one letter.
fn is_remote_spec(p: &str) -> bool {
    let p = p.replace('\\', "/");
    match p.find(':') {
        // One character before the colon is a drive letter, not a host.
        Some(i) if i > 1 => {
            let host = &p[..i];
            !host.contains('/') && !host.is_empty()
        }
        _ => false,
    }
}

// Both of these moved to `paths` when `only_under` started expanding and
// comparing the same grammar (M2.46) — one expansion and one tree comparison
// for [write], [protected] and a place-scoped entry alike. They stay here as
// the names the file's own path rules already read by, since the two are
// almost always written together (`expand(...).is_some_and(|p| glob_match(…))`).
fn glob_match(pattern: &str, path: &str) -> bool {
    crate::paths::glob_match(pattern, path)
}

fn expand(pattern: &str, home: &str, project_root: Option<&str>) -> Option<String> {
    crate::paths::expand_pattern(pattern, home, project_root)
}

/// A protected path spelled out inside a block of text, or None.
///
/// Compares on the canonical form of the path, so `~/.claude/settings.json`,
/// `$HOME/...`, `C:/Users/...` and backslashes all match the same rule. This is
/// text matching and makes no claim about what the surrounding code does — only
/// that the file vouch protects is named in something vouch cannot read.
fn mentions_protected(
    cfg: &Config,
    home: &str,
    project_root: Option<&str>,
    text: &str,
) -> Option<String> {
    // Normalising the HAYSTACK does not work: `normalize` rewrites a leading
    // `~` or `/c/`, and the path here sits in the middle of a line of code. So
    // the NEEDLE is expanded into the spellings it can appear as, and each is
    // searched for literally.
    let hay = text.to_lowercase();
    let hay_slash = hay.replace('\\', "/");
    for prot in &cfg.protected {
        let Some(p) = expand(prot, home, project_root) else {
            continue;
        };
        let canon = p.to_lowercase();
        let home_l = home.replace('\\', "/").to_lowercase();
        let mut forms = vec![canon.clone()];
        if let Some(rest) = canon.strip_prefix(&home_l) {
            let rest = rest.trim_start_matches('/');
            for prefix in ["~/", "$home/", "${home}/", "$env:userprofile/", "%userprofile%/"] {
                forms.push(format!("{prefix}{rest}"));
            }
        }
        // The MSYS mirror: `C:/x` also appears as `/c/x`.
        if canon.len() > 2 && canon.as_bytes()[1] == b':' {
            forms.push(format!("/{}/{}", &canon[..1], &canon[3..]));
        }
        if forms.iter().any(|f| hay_slash.contains(f)) {
            return Some(p);
        }
    }
    None
}

/// One written path, judged by the write rules.
///
/// The program is unknown here on purpose: a file tool (`Write`, `Edit`) and a
/// shell redirect have no program for a `[[write.scope]]` `programs` list to
/// match, so both go through this and neither meets the scope slot.
pub fn decide_file(cfg: &Config, home: &str, project_root: Option<&str>, target: &str) -> Decision {
    decide_file_for(cfg, home, project_root, target, None)
}

/// The same, told which program produced the write.
///
/// `program` is `(head, subcommand, the subcommand's second word)` —
/// `("git", Some("init"), Absent)`, `("git", Some("worktree"), Word("add"))` —
/// and is `Some` only for a destination the knowledge file says that program
/// writes to. That is the whole of what a `[[write.scope]]` rule governs: the
/// program's DECLARED writes, not every write on the line (spec §Per-program
/// write scope).
pub fn decide_file_for(
    cfg: &Config,
    home: &str,
    project_root: Option<&str>,
    target: &str,
    program: Option<(&str, Option<&str>, &crate::guards::SecondWord)>,
) -> Decision {
    let textual = normalize(target, home);
    let real = normalize(&resolve_links(&textual), home);

    // THE ONE HARD-CODED RULE. Files that control vouch itself are protected by
    // identity, checked before any allow rule, with no setting that opens them.
    for prot in &cfg.protected {
        if let Some(p) = expand(prot, home, project_root) {
            if crate::paths::paths_eq(&p, &textual) || crate::paths::paths_eq(&p, &real) {
                return Decision::Ask(format!(
                    "{PROTECTED_FILE_LINE}\n  {p}\n  \
                     this file controls vouch itself, so no write.allow_paths entry can \
                     open it — the protected list is checked first and wins\n  \
                     the only way to change that is to take this path out of \
                     [protected] in your own config, deliberately"
                ));
            }
        }
    }

    // The write wall: `deny_paths` and `ask_paths` are checked before any
    // allow rule, deny first so an inner deny inside an outer ask still
    // refuses. Neither offers `write.allow_paths` as a way out — the reason
    // says the only fix is to edit the wall itself.
    for (list, name) in [
        (&cfg.write.deny_paths, "write.deny_paths"),
        (&cfg.write.ask_paths, "write.ask_paths"),
    ] {
        for pat in list.iter() {
            if let Some(p) = expand(pat, home, project_root) {
                if glob_match(&p, &real) || glob_match(&p, &textual) {
                    let reason = format!(
                        "{WRITE_WALL_LINE}\n  {real}\n  \
                         {name} covers this tree ({pat}) — no allow rule is consulted for it\n  \
                         the only way to change that is to remove the entry from {name} in your config"
                    );
                    return if name == "write.deny_paths" {
                        Decision::Deny(reason)
                    } else {
                        Decision::Ask(reason)
                    };
                }
            }
        }
    }

    // A `[[write.scope]]` rule for the program that produced this write. It
    // sits after the wall and before `allow_paths` (spec §Precedence step 4),
    // and it answers ALONE: under its `only_under` trees allow, anywhere else
    // ask, with `write.allow_paths` never consulted for this program. That is
    // what makes a scope a narrowing and never a widening — the global allow
    // list cannot reopen what the scope refused, and the scope cannot borrow
    // the global list to allow something its own trees do not cover.
    //
    // The link-target check below belongs to `allow_paths` (it compares the
    // written form against the resolved one in that list), so it is skipped
    // here for the same reason `allow_paths` itself is: the comparison is
    // against `real`, which is the resolved path, so an alias into the trees
    // is judged by where it lands.
    if let Some((head, sub, then)) = program {
        if let Some(rule) = cfg.write.scope.iter().find(|s| s.names(head, sub, then)) {
            for pat in &rule.only_under {
                if let Some(p) = expand(pat, home, project_root) {
                    if glob_match(&p, &real) {
                        return Decision::Allow(format!(
                            "inside the write.scope trees for {head} ({p})"
                        ));
                    }
                }
            }
            return Decision::Ask(format!(
                "vouch stopped on: write scope\n  {real}\n  \
                 [[write.scope]] limits {} to {} — this destination is outside them, and \
                 write.allow_paths is not consulted for a scoped program\n  \
                 to change that, add the tree to that entry's `only_under`, or take the \
                 program out of [[write.scope]]",
                rule.programs.join(", "),
                rule.only_under.join(", ")
            ));
        }
    }

    if real != textual {
        let appeared = cfg
            .write
            .allow_paths
            .iter()
            .any(|pat| expand(pat, home, project_root).is_some_and(|p| glob_match(&p, &textual)));
        let really = cfg
            .write
            .allow_paths
            .iter()
            .any(|pat| expand(pat, home, project_root).is_some_and(|p| glob_match(&p, &real)));
        if appeared && !really {
            let real_parent = real.rsplit_once('/').map(|(d, _)| d).unwrap_or(&real);
            return Decision::Ask(format!(
                "vouch stopped on: link target outside allowed area\n  \
                 written as: {textual}\n  actually:   {real}\n  \
                 to allow this permanently, add to write.allow_paths: \"{real_parent}/**\""
            ));
        }
    }

    for pat in &cfg.write.allow_paths {
        if let Some(p) = expand(pat, home, project_root) {
            if glob_match(&p, &real) {
                return Decision::Allow(format!("inside allowed area {p}"));
            }
        }
    }

    let parent = real.rsplit_once('/').map(|(d, _)| d).unwrap_or(&real);
    act(
        cfg.write.default,
        format!(
            "vouch stopped on: path outside every allowed area\n  {real}\n  \
             to allow this permanently, add to write.allow_paths: \"{parent}/**\""
        ),
    )
}

// --- Back-compat wrappers so existing tests and callers keep working ---------

pub fn decide_bash(cfg: &Config, cmd: &str) -> Decision {
    decide_command(cfg, "bash", cmd)
}

pub fn decide_powershell(cfg: &Config, cmd: &str) -> Decision {
    decide_command(cfg, "powershell", cmd)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `ExpandedWrappers::constructs`/`Expanded::constructs` land empty in
    /// this change — no producer exists yet (T9/T15 add one) — so nothing in
    /// the public `decide_*` surface can drive `fold_expansion_constructs`
    /// today. This pushes a synthetic `(key, detail)` pair through it
    /// directly, proving the routing itself: an unset key asks and names
    /// itself as the setting that would turn the prompt off, carrying the
    /// detail text along.
    #[test]
    fn fold_expansion_constructs_routes_a_synthetic_entry_into_worst() {
        let cfg = crate::config::load("version = 1\n[lang.bash]\ndefault = \"allow\"\n")
            .expect("config parses");
        let mut worst: Option<(Action, String)> = None;
        let mut grants: Vec<String> = Vec::new();
        let constructs = vec![("dynamic_command".to_string(), "sample detail text".to_string())];
        fold_expansion_constructs(&cfg, "bash", &constructs, &mut worst, &mut grants);
        let (a, reason) = worst.expect("a construct with no configured action still asks");
        assert_eq!(a, Action::Ask);
        assert!(reason.contains("dynamic_command"), "reason: {reason}");
        assert!(reason.contains("sample detail text"), "reason: {reason}");
        assert!(grants.is_empty(), "an ask must not also record a grant: {grants:?}");
    }

    /// Same routing, with the key configured to allow — the channel must
    /// read the operator's setting rather than hard-coding Ask, and it has
    /// to record WHY in `grants`: `worst` drops an Allow reason on the floor
    /// (see `construct_grant`'s doc), so an allowed construct that never
    /// reaches `grants` would fall back to the generic "allowed by vouch
    /// policy" and the setting that actually decided the line goes unnamed.
    #[test]
    fn fold_expansion_constructs_respects_a_configured_action() {
        let cfg = crate::config::load(
            "version = 1\n[lang.bash]\ndefault = \"allow\"\n\
             [lang.bash.constructs]\ndynamic_command = \"allow\"\n",
        )
        .expect("config parses");
        let mut worst: Option<(Action, String)> = None;
        let mut grants: Vec<String> = Vec::new();
        let constructs = vec![("dynamic_command".to_string(), "sample detail text".to_string())];
        fold_expansion_constructs(&cfg, "bash", &constructs, &mut worst, &mut grants);
        let (a, _) = worst.expect("routing still records the outcome");
        assert_eq!(a, Action::Allow);
        assert!(
            grants.iter().any(|g| g.contains("dynamic_command")),
            "an allowed construct must record what allowed it: {grants:?}"
        );
    }
}
