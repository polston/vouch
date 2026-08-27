//! The pure-read python vocabulary (M2.86): every shipped read-only
//! `python:` entry is proven to recognise a call synthesized from its own
//! name, unknown siblings still ask, and the excluded higher-order builtins
//! are pinned to ask (spec 2026-08-09, review finding 1 / M2.89).

use vouch::config::load;
use vouch::engine::decide_command_in;
use vouch::protocol::Decision;

mod common;

const HOME: &str = "C:/Users/dev";

fn cfg() -> vouch::config::Config {
    load(
        "version = 1\n[lang.bash]\ndefault = \"allow\"\n[lang.bash.constructs]\nunmodeled_command = \"allow\"\n\
         [lang.python]\ndefault = \"allow\"\n[lang.python.constructs]\nunmodeled_command = \"ask\"\n\
         [write]\ndefault = \"ask\"\nallow_paths = [\"C:/work/**\"]\n",
    )
    .expect("parses")
}

/// `cfg()` with `delete_recursive` turned off (task 2b fix round 4) — needed
/// to check `shutil.rmtree`'s `callback_args` declaration on its own terms.
/// `rmtree` also carries an unconditional (`always = true`) delete_recursive
/// rule, which asks on every call regardless of arguments; with the guard
/// left on, that reason always wins the tie over `callback_argument`
/// (equally valid, but it would mask a dead `callback_args` declaration —
/// exactly the M2.52 hazard this test exists to catch).
fn cfg_with_delete_recursive_off() -> vouch::config::Config {
    load(
        "version = 1\n[lang.bash]\ndefault = \"allow\"\n[lang.bash.constructs]\nunmodeled_command = \"allow\"\n\
         [lang.python]\ndefault = \"allow\"\n[lang.python.constructs]\nunmodeled_command = \"ask\"\n\
         [write]\ndefault = \"ask\"\nallow_paths = [\"C:/work/**\"]\n\
         [guards]\ndelete_recursive = \"allow\"\n",
    )
    .expect("parses")
}

fn decide(cmd: &str) -> Decision {
    decide_command_in(&cfg(), "bash", cmd, Some(HOME), None)
}

fn decide_with(c: &vouch::config::Config, cmd: &str) -> Decision {
    decide_command_in(c, "bash", cmd, Some(HOME), None)
}

/// A read-only entry is one that claims nothing but recognition: no writes,
/// no rules, no wrapping, no evaluates_input, and no writes_via_handle (Task
/// 5: a handle-writer still WRITES, even though the engine extracts no path
/// from the call itself — it must not be swept into the "recognises its own
/// call allows" proof the same way a truly pure entry is).
fn is_read_only(p: &vouch::guards::Program) -> bool {
    p.writes.is_empty()
        && p.rule.is_empty()
        && p.wraps.is_empty()
        && p.evaluates_input.is_empty()
        && p.writes_via_handle.is_none()
        && p.changes_dir.as_deref().unwrap_or("no") == "no"
}

#[test]
fn shipped_os_chdir_is_a_stated_mover_with_one_named_path_argument() {
    let entry = vouch::guards::in_effect()
        .program
        .iter()
        .find(|program| {
            program
                .match_names
                .iter()
                .any(|name| name == "python:os.chdir")
        })
        .expect("python:os.chdir is shipped");
    assert_eq!(entry.changes_dir.as_deref(), Some("stated"));
    assert_eq!(entry.arg_names, vec!["path"]);
    assert!(entry.writes.is_empty());
    assert_eq!(vouch::knowledge::KNOWLEDGE_SCHEMA_VERSION, 10);
}

/// Synthesize a snippet whose one call is `name`, with the import a dotted
/// name needs to be read as a module call. `argless` calls with ZERO
/// arguments instead of one bare probe value — needed for an entry whose
/// only positional slot (position 0) is itself a declared `callback_args`
/// slot (`collections.defaultdict`, `datetime.datetime.now`): passing the
/// generic probe value there would occupy that slot and wrongly trip
/// `callback_argument` on what is meant to be the "no callback used" case.
/// Every entry in the shipped set accepts zero arguments when this applies.
fn snippet_for(p: &vouch::guards::Program, name: &str, argless: bool) -> String {
    let bare = name.strip_prefix("python:").expect("python: prefix");
    let arg = if argless {
        ""
    } else {
        "'k'"
    };
    if let Some(method) = bare.strip_prefix('.') {
        let receiver = match p.receiver_from.as_deref() {
            Some(tags) if tags.iter().any(|tag| tag == "data") => "{}",
            Some(tags) if tags.iter().any(|tag| tag == "file_handle") => "open('C:/work/origin.txt', 'w')",
            _ => "x",
        };
        format!("{receiver}.{method}({arg})")
    } else if let Some((root, _)) = bare.split_once('.') {
        format!("import {root}; {bare}({arg})")
    } else {
        format!("{bare}({arg})")
    }
}

/// Whether `p`'s position-0 argument slot (after any method receiver) is
/// itself a declared callback — see `snippet_for`'s doc comment.
fn position_zero_is_a_callback(p: &vouch::guards::Program) -> bool {
    let base = usize::from(p.match_names.iter().any(|n| n.contains(":.")));
    p.arg_names.get(base).is_some_and(|n| p.callback_args.contains(n))
}

#[test]
fn every_read_only_python_entry_recognises_its_own_call() {
    let kb = vouch::guards::in_effect();
    let mut checked = 0;
    for p in kb.program.iter().filter(|p| is_read_only(p)) {
        let argless = position_zero_is_a_callback(p);
        for name in p.match_names.iter().filter(|n| n.starts_with("python:")) {
            let cmd = format!("python -c \"{}\"", snippet_for(p, name, argless));
            match decide(&cmd) {
                Decision::Allow(_) => checked += 1,
                other => panic!("{name}: expected Allow for {cmd}, got {other:?}"),
            }
        }
    }
    assert!(checked > 0, "no read-only python entries found — the walk is broken or the entries did not ship");
}

#[test]
fn every_declared_callback_slot_trips_the_construct() {
    // The read-side mirror of `guard_rule_enumeration_test.rs` (M2.9's
    // principle): a declared `callback_args` slot that does not actually
    // trip would sit dead and unnoticed, exactly the M2.52 hazard the
    // validation comment warns about. For each shipped entry carrying
    // `callback_args`, occupy EACH declared slot and assert Ask naming
    // `callback_argument` specifically — not just any Ask.
    //
    // Task 2b fix round 4 widened this: earlier it probed with a single
    // bare positional ('k') regardless of the entry, which worked while
    // every callback-bearing entry was pure-read. Once entries that ALSO
    // carry a `writes` claim (`open`, `shutil.copytree`, `shutil.move`,
    // `shutil.rmtree`) gained `callback_args` too, 'k' left their OTHER
    // declared positions unresolved, which the write pass separately (and
    // validly) flagged as "path outside every allowed area" — a DIFFERENT
    // Ask reason that won the tie and masked whether the callback
    // declaration itself was live. Every declared position up to and
    // including the slot under test is now filled with a value that
    // resolves INSIDE `allow_paths`, so the write pass never has anything
    // to object to and `callback_argument` is the only thing that can
    // still be asking.
    let guards_off = cfg_with_delete_recursive_off();
    let kb = vouch::guards::in_effect();
    let mut checked = 0;
    for p in kb.program.iter().filter(|p| !p.callback_args.is_empty()) {
        for name in p.match_names.iter().filter(|n| n.starts_with("python:")) {
            let bare = name.strip_prefix("python:").expect("python: prefix");
            for slot in &p.callback_args {
                // Fill every position up to and including this slot's own
                // (if it has one — a keyword-only slot has none, and one
                // safe positional is still supplied so any write-target
                // position at index 0 resolves cleanly).
                let n_positional = p.arg_names.iter().position(|n| n == slot).map(|i| i + 1).unwrap_or(1);
                let positionals = vec!["'C:/work/x'"; n_positional].join(", ");
                let args_text = format!("{positionals}, {slot}=g");
                let snippet = if let Some((root, _)) = bare.split_once('.') {
                    format!("import {root}; {bare}({args_text})")
                } else {
                    format!("{bare}({args_text})")
                };
                let cmd = format!("python -c \"{snippet}\"");
                match decide_with(&guards_off, &cmd) {
                    Decision::Ask(r) => {
                        assert!(
                            r.contains("callback_argument"),
                            "{name}/{slot}: reason does not name callback_argument: {r}"
                        );
                        assert!(
                            r.contains("lang.python.constructs.callback_argument"),
                            "{name}/{slot}: reason does not name the setting: {r}"
                        );
                        checked += 1;
                    }
                    other => panic!("{name}/{slot}: expected Ask for {cmd}, got {other:?}"),
                }
            }
        }
    }
    assert!(checked > 0, "no callback_args slots found — the declarations did not ship");
}

#[test]
fn a_bare_unpack_alone_trips_every_callback_entry() {
    // Round-2 finding: `fn(**opts)` with NO other argument evaded every
    // round-1 check — the lone marker landed at position 0, inside the
    // "known positions" boundary rule 3 used then, and read as the ordinary
    // unresolvable-data-argument case instead of a possible unpack.
    // `fn(**{"fp": f, "object_hook": g})` is ordinary Python and hands the
    // invoked slot through unseen — the same falsifiability this whole
    // changeset exists to end. `UNPACK_MARKER` (roadmap M2.78's fix,
    // applied here) closes it: the unpack is its own token now, checked
    // directly, with no positional reasoning at all. Driven off the shipped
    // entries by enumeration, per the coordinator's instruction, so an
    // entry added later is covered automatically rather than needing its
    // own hand-written case.
    //
    // Task 2b fix round 4: an entry that ALSO carries a `writes` or guard
    // claim (`open`, `shutil.copytree`, `shutil.move`, `shutil.rmtree`) has
    // NOTHING resolved at all in this bare shape — no other argument is
    // given — so its own write-uncertainty or guard is an equally valid,
    // independently safe reason to ask. The property this proves for those
    // four is the narrower, correct one: it must never Allow. Every entry
    // with neither (every Group A/B pure-read entry from tasks 2/2b) keeps
    // the strict check, since nothing else could legitimately produce an
    // Ask for them.
    let kb = vouch::guards::in_effect();
    let mut checked = 0;
    for p in kb.program.iter().filter(|p| !p.callback_args.is_empty()) {
        let has_competing_claim = !p.writes.is_empty() || !p.rule.is_empty();
        for name in p.match_names.iter().filter(|n| n.starts_with("python:")) {
            let bare = name.strip_prefix("python:").expect("python: prefix");
            let snippet = if let Some(method) = bare.strip_prefix('.') {
                format!("x.{method}(**opts)")
            } else if let Some((root, _)) = bare.split_once('.') {
                format!("import {root}; {bare}(**opts)")
            } else {
                format!("{bare}(**opts)")
            };
            let cmd = format!("python -c \"{snippet}\"");
            match decide(&cmd) {
                Decision::Ask(r) => {
                    if !has_competing_claim {
                        assert!(r.contains("callback_argument"), "{name}: reason does not name callback_argument: {r}");
                    }
                    checked += 1;
                }
                other => panic!("{name}: expected Ask for {cmd}, got {other:?}"),
            }
        }
    }
    assert!(checked > 0, "no callback_args entries found — the declarations did not ship");
}

// --- the excluded higher-order/process-starting builtins stay out (Task 6, M2.89) ---

/// Review finding 1 / M2.89: these builtins invoke a callable the caller
/// supplies — map's own positional argument, sorted's/min's/max's `key=`,
/// filter's own positional argument, iter's two-argument form, list.sort's
/// own `key=`, re.subn's `repl` — and a callable passed by reference is
/// never emitted as its own event, so the caller-supplied function runs
/// unseen. They must NEVER be in the pure-read set. If one of these turns
/// Allow, someone re-added it; see the exclude-list comment on the
/// pure-read vocabulary's group header in knowledge.toml and roadmap item
/// M2.89 before touching this.
///
/// Fix round 1: `.sort` and `re.subn` are documented as excluded for this
/// same reason in two OTHER places in knowledge.toml — `.sort` in group C's
/// "considered and left out" census list (list.sort(key=...) calls key once
/// per element), and `re.subn` beside the shipped `re.sub` entry (it shares
/// re.sub's signature, including the callable-or-string `repl` at position
/// 1, and was never given the same `callback_args` declaration). Neither
/// was pinned before this fix round.
#[test]
fn the_higher_order_builtins_stay_asking() {
    for cmd in [
        // map(fn, iterable) — invokes fn once per element.
        r#"python -c "list(map(os.remove, ['f.txt']))""#,
        // sorted(iterable, key=fn) — invokes fn once per element.
        r#"python -c "import os; sorted(files, key=os.remove)""#,
        // min(iterable, key=fn) — invokes fn once per element.
        r#"python -c "import os; min(files, key=os.system)""#,
        // max(iterable, key=fn) — invokes fn once per element.
        r#"python -c "import os; max(files, key=os.remove)""#,
        // filter(fn, iterable) — invokes fn once per element.
        r#"python -c "filter(f, xs)""#,
        // iter(fn, sentinel) — the two-argument form invokes fn repeatedly.
        r#"python -c "iter(f, None)""#,
        // list.sort(key=fn) — same invoked-parameter shape as sorted's key=,
        // documented separately in knowledge.toml's group C census notes.
        r#"python -c "x.sort(key=os.remove)""#,
        // re.subn(pattern, repl, string) — repl may be a callable, the same
        // shape re.sub already declares via callback_args; re.subn does not.
        r#"python -c "import re; re.subn(p, os.remove, s)""#,
    ] {
        match decide(cmd) {
            Decision::Ask(_) | Decision::Deny(_) => {}
            other => panic!("{cmd}: must never allow, got {other:?}"),
        }
    }
}

/// The same knowledge.toml group header excludes four more names, for
/// reasons OTHER than the callable-reference gap above — pinned here too so
/// the group header's full exclude list is covered, and so the next reader
/// sees why each belongs instead of assuming the group is one reason:
/// - `help` and `breakpoint` can each START something on their own (a
///   pager; a hook-selected callable) — a process/hook-start risk, not a
///   callable handed in BY the caller.
/// - `compile` and `__import__` are left unmodeled on purpose, independent
///   of both reasons above.
#[test]
fn the_process_starting_and_purposely_unmodeled_builtins_stay_asking() {
    for cmd in [
        r#"python -c "help()""#,
        r#"python -c "breakpoint()""#,
        r#"python -c "compile('1', 'f', 'eval')""#,
        r#"python -c "__import__('os')""#,
    ] {
        match decide(cmd) {
            Decision::Ask(_) | Decision::Deny(_) => {}
            other => panic!("{cmd}: must never allow, got {other:?}"),
        }
    }
}

#[test]
fn the_reported_probe_now_asks() {
    // The exact shape the review's probe used: a pre-existing, imported
    // function handed to a callback slot by reference. Before this fix
    // round it reported only `python:json.loads` as unmodeled — `os.remove`
    // never appeared in the emitted calls at all, so the read-only claim on
    // `json.loads` was falsifiable.
    match decide(r#"python -c "import json, os; json.loads(s, parse_int=os.remove)""#) {
        Decision::Ask(r) => assert!(r.contains("callback_argument"), "got: {r}"),
        other => panic!("expected Ask, got {other:?}"),
    }
}

#[test]
fn the_clean_json_load_call_still_allows() {
    // Design point 4.2: no callback slot used → Allow, unaffected by the
    // fix round.
    match decide(r#"python -c "import json; json.load(f)""#) {
        Decision::Allow(_) => {}
        other => panic!("expected Allow, got {other:?}"),
    }
}

#[test]
fn nameless_keyword_unpacking_into_a_callback_entry_fails_closed() {
    // Design point 4.3: `**opts` could be carrying any keyword, including a
    // declared callback slot, and vouch cannot rule that out.
    match decide(r#"python -c "import json; json.load(f, **opts)""#) {
        Decision::Ask(r) => assert!(r.contains("callback_argument"), "got: {r}"),
        other => panic!("expected Ask, got {other:?}"),
    }
}

#[test]
fn defaultdicts_positional_callback_trips_and_the_bare_call_allows() {
    // Design point 4.4: default_factory is positional-only in real Python
    // (verified live: `defaultdict(default_factory=x)` does not set the
    // factory at all, it inserts a literal dict entry named
    // "default_factory" — the callback risk is the POSITIONAL spelling).
    match decide(r#"python -c "import collections; collections.defaultdict(list)""#) {
        Decision::Ask(r) => assert!(r.contains("callback_argument"), "got: {r}"),
        other => panic!("expected Ask, got {other:?}"),
    }
    match decide(r#"python -c "import collections; collections.defaultdict()""#) {
        Decision::Allow(_) => {}
        other => panic!("expected Allow, got {other:?}"),
    }
}

#[test]
fn an_unknown_sibling_name_still_asks() {
    match decide(r#"python -c "zzqx('k')""#) {
        Decision::Ask(r) => assert!(r.contains("unmodeled_command"), "got: {r}"),
        other => panic!("expected Ask, got {other:?}"),
    }
}

#[test]
fn the_typical_read_only_one_liner_allows() {
    // json.load (module read) + len (builtin); print joins in Task 5.
    match decide(r#"python -c "import json, sys; len(json.load(sys.stdin))""#) {
        Decision::Allow(_) => {}
        other => panic!("expected Allow, got {other:?}"),
    }
}

#[test]
fn a_method_call_on_an_unknown_receiver_asks() {
    match decide(r#"python -c "d.get('k')""#) {
        Decision::Ask(r) => assert!(r.contains("unmodeled_command"), "got: {r}"),
        other => panic!("expected Ask, got {other:?}"),
    }
}

#[test]
fn method_shaped_open_remains_unknown_without_a_proven_receiver_model() {
    match decide(r#"python -c "value.open()""#) {
        Decision::Ask(reason) => assert!(reason.contains("unmodeled_command"), "{reason}"),
        other => panic!("unknown .open receiver must Ask, got {other:?}"),
    }
    match decide(
        r#"python -c "from pathlib import Path; Path('C:/work/log.txt').open('w').write('data')""#,
    ) {
        Decision::Ask(reason) => assert!(reason.contains("unmodeled_command"), "{reason}"),
        other => panic!("Path construction and .open stay unmodeled, got {other:?}"),
    }
}

#[test]
fn an_unknown_method_name_still_asks() {
    match decide(r#"python -c "d.zzqx('k')""#) {
        Decision::Ask(r) => assert!(r.contains("unmodeled_command"), "got: {r}"),
        other => panic!("expected Ask, got {other:?}"),
    }
}

// Fix round 1 (widened lens): a name pure on one receiver can be
// filesystem-affecting on another, and group C claims on the name alone —
// so the entry covers every receiver. `.replace` and `.add` were shipped
// then dropped once that collision was found; `.setdefault` and `.update`
// were considered as census-observed additions and never shipped for the
// same reason. All four must still ask, exactly like any other unshipped
// name — this pins that behaviour so a later change cannot silently
// reintroduce any of them.
#[test]
fn replace_is_not_shipped_for_the_path_receiver_collision() {
    match decide(r#"python -c "d.replace('a')""#) {
        Decision::Ask(r) => assert!(r.contains("unmodeled_command"), "got: {r}"),
        other => panic!("expected Ask, got {other:?}"),
    }
}

#[test]
fn add_is_not_shipped_for_the_archive_receiver_collision() {
    match decide(r#"python -c "d.add('a')""#) {
        Decision::Ask(r) => assert!(r.contains("unmodeled_command"), "got: {r}"),
        other => panic!("expected Ask, got {other:?}"),
    }
}

#[test]
fn setdefault_is_not_shipped_for_the_persistent_mapping_receiver_collision() {
    match decide(r#"python -c "d.setdefault('a', 1)""#) {
        Decision::Ask(r) => assert!(r.contains("unmodeled_command"), "got: {r}"),
        other => panic!("expected Ask, got {other:?}"),
    }
}

#[test]
fn update_is_not_shipped_for_the_persistent_mapping_receiver_collision() {
    match decide(r#"python -c "d.update(x)""#) {
        Decision::Ask(r) => assert!(r.contains("unmodeled_command"), "got: {r}"),
        other => panic!("expected Ask, got {other:?}"),
    }
}

// Fix round 1, finding 3: names the widened lens cleared (no invoked
// parameter, no same-name filesystem/dir/process collision found) but that
// were previously left unshipped as "clean but omitted" now ship.
#[test]
fn the_widened_audit_additions_are_now_recognised() {
    for method in ["isdigit", "most_common", "rfind", "ljust", "discard", "astype"] {
        let cmd = format!("python -c \"import json; json.loads('{{}}').{method}('k')\"");
        match decide(&cmd) {
            Decision::Allow(_) => {}
            other => panic!("{method}: expected Allow, got {other:?}"),
        }
    }
}

#[test]
fn a_rebound_builtin_asks_even_when_unmodeled_commands_are_allowed() {
    // rebound_name is its own construct: silencing unmodeled_command must
    // not silence it.
    let c = load(
        "version = 1\n[lang.bash]\ndefault = \"allow\"\n[lang.bash.constructs]\nunmodeled_command = \"allow\"\n\
         [lang.python]\ndefault = \"allow\"\n[lang.python.constructs]\nunmodeled_command = \"allow\"\n\
         [write]\ndefault = \"ask\"\nallow_paths = [\"C:/work/**\"]\n",
    )
    .expect("parses");
    match decide_command_in(&c, "bash", r#"python -c "len = 1; len('C:/work/f.txt')""#, Some(HOME), None) {
        Decision::Ask(r) => {
            assert!(r.contains("rebound_name"), "got: {r}");
            assert!(r.contains("lang.python.constructs.rebound_name"), "no setting named (§5): {r}");
        }
        other => panic!("expected Ask, got {other:?}"),
    }
}

// --- writes_via_handle (Task 5, M2.86, knowledge schema v5) -----------------

#[test]
fn json_dump_into_a_write_mode_open_is_judged_by_the_open() {
    // The handle entry adds nothing; the nested open call carries the path
    // and the write rules judge it (load-bearing fact, spec §writes_via_handle:
    // confirmed against src/python.rs's `Walk::visit_expr` — a `Call` node
    // records its own event AND THEN `walk_expr` descends into its arguments,
    // so the nested `open(...)` is visited as its own call independent of
    // json.dump's).
    match decide(r#"python -c "import json; json.dump(d, open('C:/Windows/x.json', 'w'))""#) {
        Decision::Ask(r) => assert!(r.contains("C:/Windows/x.json"), "got: {r}"),
        other => panic!("expected Ask on the open's path, got {other:?}"),
    }
}

#[test]
fn plain_print_allows_and_print_into_an_opened_file_is_judged_by_the_open() {
    match decide(r#"python -c "print('hi')""#) {
        Decision::Allow(_) => {}
        other => panic!("expected Allow, got {other:?}"),
    }
    match decide(r#"python -c "print('hi', file=open('C:/Windows/log.txt', 'w'))""#) {
        Decision::Ask(r) => assert!(r.contains("C:/Windows/log.txt"), "got: {r}"),
        other => panic!("expected Ask on the open's path, got {other:?}"),
    }
}

#[test]
fn a_write_method_requires_a_known_handle_and_open_still_judges_its_path() {
    // Fix round 1: the two method-spelled group D entries (`.write`,
    // `.writelines`) shipped with no dedicated test at all — this and the
    // sibling below close that, mirroring the json.dump/print treatment.
    match decide(r#"python -c "f.write('data')""#) {
        Decision::Ask(r) => assert!(r.contains("unmodeled_command"), "got: {r}"),
        other => panic!("expected Ask, got {other:?}"),
    }
    match decide(r#"python -c "open('C:/work/log.txt', 'w').write('data')""#) {
        Decision::Allow(_) => {}
        other => panic!("expected Allow for an allowed-path handle, got {other:?}"),
    }
    match decide(r#"python -c "open('C:/Windows/log.txt', 'w').write('data')""#) {
        Decision::Ask(r) => assert!(r.contains("C:/Windows/log.txt"), "got: {r}"),
        other => panic!("expected Ask on the open's path, got {other:?}"),
    }
}

#[test]
fn a_writelines_method_requires_a_known_handle_and_open_still_judges_its_path() {
    match decide(r#"python -c "f.writelines(['a', 'b'])""#) {
        Decision::Ask(r) => assert!(r.contains("unmodeled_command"), "got: {r}"),
        other => panic!("expected Ask, got {other:?}"),
    }
    match decide(r#"python -c "open('C:/work/log.txt', 'w').writelines(['a'])""#) {
        Decision::Allow(_) => {}
        other => panic!("expected Allow for an allowed-path handle, got {other:?}"),
    }
    match decide(r#"python -c "open('C:/Windows/log.txt', 'w').writelines(['a'])""#) {
        Decision::Ask(r) => assert!(r.contains("C:/Windows/log.txt"), "got: {r}"),
        other => panic!("expected Ask on the open's path, got {other:?}"),
    }
}

#[test]
fn known_data_producers_enable_curated_methods() {
    for cmd in [
        r#"python -c "{}.get('name')""#,
        r#"python -c "import json; json.loads('{}').get('name')""#,
        r#"python -c "import yaml; yaml.safe_load('{}').get('name')""#,
        r#"python -c "import sys; sys.stdin.read().strip()""#,
        r#"python -c "import re; re.match('a', 'a').group()""#,
        r#"python -c "import tomllib; tomllib.load(f).get('name')""#,
    ] {
        match decide(cmd) {
            Decision::Allow(_) => {}
            other => panic!("{cmd}: expected Allow, got {other:?}"),
        }
    }
}

#[test]
fn a_callback_customized_producer_withholds_data_provenance() {
    let config = load(
        "version = 1\n[lang.bash]\ndefault = \"allow\"\n[lang.bash.constructs]\nunmodeled_command = \"allow\"\n\
         [lang.python]\ndefault = \"allow\"\n[lang.python.constructs]\nunmodeled_command = \"ask\"\ncallback_argument = \"allow\"\n\
         [write]\ndefault = \"ask\"\nallow_paths = [\"C:/work/**\"]\n",
    )
    .expect("config parses");
    match decide_with(
        &config,
        r#"python -c "import json; json.loads('{}', object_hook=custom).get('name')""#,
    ) {
        Decision::Ask(reason) => assert!(reason.contains("unmodeled_command"), "{reason}"),
        other => panic!("callback-customized result must not mint data, got {other:?}"),
    }
}

#[test]
fn a_with_bound_open_handle_can_read_and_chain_data_methods() {
    match decide(
        r#"python -c "with open('C:/work/input.txt') as handle:
    print(handle.read().strip())""#,
    ) {
        Decision::Allow(_) => {}
        other => panic!("expected Allow for a visibly opened handle, got {other:?}"),
    }
}

#[test]
fn the_element_tree_same_name_write_trap_remains_asking() {
    match decide(r#"python -c "import xml.etree.ElementTree as ET; ET.ElementTree().write('C:/work/out.xml')""#) {
        Decision::Ask(reason) => assert!(reason.contains("unmodeled_command"), "{reason}"),
        other => panic!("unmodeled ElementTree receiver must Ask, got {other:?}"),
    }
}

#[test]
fn every_receiver_gated_entry_has_known_and_unknown_receiver_probes() {
    let knowledge = vouch::guards::in_effect();
    let mut checked = 0;
    for program in
        knowledge.program.iter().filter(|program| program.receiver_from.as_ref().is_some_and(|tags| !tags.is_empty()))
    {
        let argless = position_zero_is_a_callback(program);
        for name in program.match_names.iter().filter(|name| name.starts_with("python:.")) {
            let known = format!("python -c \"{}\"", snippet_for(program, name, argless));
            match decide(&known) {
                Decision::Allow(_) => {}
                other => panic!("{name}: known receiver should Allow for {known}, got {other:?}"),
            }

            let method = name.trim_start_matches("python:.");
            let unknown = format!("python -c \"x.{method}('k')\"");
            match decide(&unknown) {
                Decision::Ask(reason) => {
                    assert!(reason.contains("unmodeled_command"), "{name}: {reason}")
                }
                other => panic!("{name}: unknown receiver should Ask, got {other:?}"),
            }
            checked += 1;
        }
    }
    assert!(checked > 0, "no receiver-gated method entries shipped");
}

#[test]
fn assigned_callable_aliases_keep_open_and_delete_judgments() {
    match decide(r#"python -c "writer = open; writer('C:/Windows/log.txt', 'w').write('data')""#) {
        Decision::Ask(reason) => assert!(reason.contains("C:/Windows/log.txt"), "{reason}"),
        other => panic!("open alias should preserve its path judgment, got {other:?}"),
    }
    match decide(r#"python -c "import shutil; deleter = shutil.rmtree; deleter('C:/work/tree')""#) {
        Decision::Ask(reason) => assert!(reason.contains("delete_recursive"), "{reason}"),
        other => panic!("delete alias should preserve its guard, got {other:?}"),
    }
}

#[test]
fn the_census_one_liner_with_all_three_classes_allows() {
    // json.load (module read) + .get (method) + print (handle-writer): the
    // spec's Problem-section example, whole.
    match decide(r#"python -c "import json, sys; d = json.load(sys.stdin); print(d.get('name'))""#) {
        Decision::Allow(_) => {}
        other => panic!("expected Allow, got {other:?}"),
    }
}

#[test]
fn json_dump_into_an_open_aimed_at_a_protected_path_is_judged_by_the_open() {
    // Spec Testing item 1: the protected-path shape reaches through the
    // nested open, same as `a_protected_file_stays_protected_from_inline_code`
    // (tests/python_snippet_test.rs:87) pins for a bare `open(...)` call — the
    // handle entry adds nothing, so the outcome is identical to that sibling.
    // NOTE: the design spec's prose says this shape "DENIES"; the real,
    // observed decision is an Ask whose reason names the protected file.
    // `Decision::Deny` exists in the enum, but `decide_file_for`
    // (src/engine.rs) deliberately returns `Ask` for every protected-path
    // hit ("THE ONE HARD-CODED RULE", its own comment) — pinned with the
    // sibling test's own words, not the spec's, per this task's instruction
    // to note the difference rather than paper over it.
    let c = load(
        "version = 1\n[lang.bash]\ndefault = \"allow\"\n[lang.bash.constructs]\nunmodeled_command = \"allow\"\n\
         [lang.python]\ndefault = \"allow\"\n[lang.python.constructs]\nunmodeled_command = \"allow\"\n\
         [write]\ndefault = \"ask\"\nallow_paths = [\"C:/work/**\"]\n\
         [protected]\npaths = [\"$HOME/.claude/settings.json\"]\n",
    )
    .expect("parses");
    match decide_command_in(
        &c,
        "bash",
        r#"python -c "import json; json.dump(d, open('C:/Users/dev/.claude/settings.json', 'w'))""#,
        Some(HOME),
        None,
    ) {
        Decision::Ask(r) => assert!(r.contains("protected file"), "got: {r}"),
        other => panic!("expected Ask, got {other:?}"),
    }
}
