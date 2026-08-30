//! The scanner's structural account of a callable passed by reference
//! (M2.89/M2.92, spec §3). These assert the FACT only — no decision depends
//! on it until Task 3.

use vouch::syntax::{CallableArg, Scanner};

fn scan(src: &str) -> vouch::syntax::Scan {
    vouch::python::Python.scan(src).expect("python snippet parses")
}

/// The command whose head ends in `name`, so a test does not depend on the
/// order sibling calls are emitted in.
fn cmd_for<'a>(s: &'a vouch::syntax::Scan, name: &str) -> &'a vouch::syntax::Cmd {
    s.commands.iter().find(|c| c.head == format!("python:{name}")).unwrap_or_else(|| {
        panic!("no command for {name}; heads were {:?}", s.heads)
    })
}

#[test]
fn a_dotted_reference_in_an_argument_is_marked_with_its_head() {
    let s = scan("import os\nmap(os.remove, ['f.txt'])\n");
    let c = cmd_for(&s, "map");
    match c.callable_args.get(&0) {
        Some(CallableArg::Named { head, .. }) => assert_eq!(head, "os.remove"),
        other => panic!("expected a named callable at 0, got {other:?}"),
    }
}

#[test]
fn an_imported_bare_name_resolves_to_the_same_head_as_the_dotted_spelling() {
    let s = scan("from os import remove\nmap(remove, ['f.txt'])\n");
    let c = cmd_for(&s, "map");
    match c.callable_args.get(&0) {
        Some(CallableArg::Named { head, .. }) => assert_eq!(head, "os.remove"),
        other => panic!("expected os.remove at 0, got {other:?}"),
    }
}

#[test]
fn an_assigned_alias_resolves_to_the_callable_it_names() {
    let s = scan("import os\nf = os.remove\nmap(f, ['x'])\n");
    let c = cmd_for(&s, "map");
    match c.callable_args.get(&0) {
        Some(CallableArg::Named { head, .. }) => assert_eq!(head, "os.remove"),
        other => panic!("expected os.remove at 0, got {other:?}"),
    }
}

#[test]
fn a_lambda_argument_is_inline_because_its_body_is_already_scanned() {
    let s = scan("import re\nre.sub('a', lambda m: m, 'x')\n");
    let c = cmd_for(&s, "re.sub");
    assert!(matches!(c.callable_args.get(&1), Some(CallableArg::Inline)));
}

/// M2.92's whole point: a replacement STRING is a value, not a callable.
#[test]
fn a_string_literal_in_a_callback_position_is_not_marked() {
    let s = scan("import re\nre.sub('a', 'b', 'x')\n");
    let c = cmd_for(&s, "re.sub");
    assert!(c.callable_args.is_empty(), "got {:?}", c.callable_args);
}

#[test]
fn a_call_result_and_a_subscript_are_values_not_references() {
    let s = scan("import re\nre.sub('a', g(), 'x')\nre.sub('a', xs[0], 'y')\n");
    for c in s.commands.iter().filter(|c| c.head == "python:re.sub") {
        assert!(c.callable_args.is_empty(), "got {:?}", c.callable_args);
    }
}

/// M2.78's scar, in this seam: a literal that happens to equal an internal
/// marker spelling is still a VALUE. The fact is structural, so no spelling
/// can manufacture it.
#[test]
fn a_literal_equal_to_a_marker_spelling_is_not_a_callable() {
    let s = scan("import re\nre.sub('a', '$?', 'x')\n");
    let c = cmd_for(&s, "re.sub");
    assert!(c.callable_args.is_empty(), "got {:?}", c.callable_args);
}

#[test]
fn a_keyword_reference_is_marked_at_the_position_it_was_pushed_at() {
    let s = scan("import os, json\njson.loads('{}', parse_int=os.remove)\n");
    let c = cmd_for(&s, "json.loads");
    // `'{}'` is the sole positional argument (index 0), so the keyword
    // `parse_int` is pushed at index 1 — look it up by that exact index
    // rather than presuming the map holds exactly one entry.
    assert_eq!(c.keyword_args, std::collections::HashSet::from([1]));
    match c.callable_args.get(&1) {
        Some(CallableArg::Named { head, .. }) => assert_eq!(head, "os.remove"),
        other => panic!("expected os.remove at the keyword position 1, got {other:?}"),
    }
}

#[test]
fn a_rebound_name_is_callable_shaped_but_unresolved() {
    let s = scan("for f in fs:\n    map(f, ['x'])\n");
    let c = cmd_for(&s, "map");
    assert!(matches!(c.callable_args.get(&0), Some(CallableArg::Unresolved)));
}

/// `9acf41c` had exercised only the lambda-LITERAL route (test 4, an
/// `Expr::Lambda` written directly at the call site). A bare NAME bound to a
/// `def` elsewhere in the snippet went through a second, unguarded route —
/// the whole-snippet `defined` fallback in `argument_callable` — that used
/// `Inline` for a body the scanner never actually re-scanned in place. That
/// fallback is gone: `defined` could never distinguish an unambiguous
/// binding from an ambiguous one (every name it held was also, unavoidably,
/// in `poisoned`), so it is `Unresolved` now, the same as any other name
/// `callable_ref` cannot resolve.
#[test]
fn a_def_bound_name_used_as_an_argument_is_unresolved_not_inline() {
    let s = scan("def cb(p):\n    pass\nmap(cb, ['x'])\n");
    let c = cmd_for(&s, "map");
    assert!(matches!(c.callable_args.get(&0), Some(CallableArg::Unresolved)), "got {:?}", c.callable_args.get(&0));
}

/// Same fallback, the lambda-ASSIGNED-name route (`cb = lambda p: p`, as
/// opposed to a lambda literal used directly as the argument) — also never
/// re-scanned in place, also `Unresolved` now.
#[test]
fn a_lambda_assigned_name_used_as_an_argument_is_unresolved_not_inline() {
    let s = scan("cb = lambda p: p\nmap(cb, ['x'])\n");
    let c = cmd_for(&s, "map");
    assert!(matches!(c.callable_args.get(&0), Some(CallableArg::Unresolved)), "got {:?}", c.callable_args.get(&0));
}

/// The isolating pair from the finding: two `def`s in the same snippet, one
/// bound to the parameter name the callback slot uses. The `defined`
/// fallback could not tell "the only binding" from "one of several" — it
/// read the whole-module set, order-blind — so it read this exactly like
/// the single-binding case above and produced `Inline`. It must ask.
#[test]
fn a_shadowed_def_bound_name_used_as_an_argument_is_unresolved() {
    let s = scan("def f(p):\n    pass\ndef run(f):\n    return sorted(xs, key=f)\n");
    let c = cmd_for(&s, "sorted");
    let occupant = c.callable_args.get(&1);
    assert!(matches!(occupant, Some(CallableArg::Unresolved)), "got {occupant:?}");
}

/// A name aliased to a described, undescribed-by-callback destructive entry,
/// then conditionally rebound to a `def` of the same name — the reference
/// must not silently resolve through the alias either, since python does not
/// prove which branch ran. `callable_ref` already refuses this via
/// `poisoned` (the conditional `def` counts as a binding); this test pins
/// that it does NOT fall through to the buggy `Inline` fallback instead.
#[test]
fn a_conditionally_redefined_name_used_as_an_argument_is_unresolved() {
    let s = scan(
        "import shutil\nf = shutil.rmtree\nif cond:\n    def f(p):\n        pass\nsorted(xs, key=f)\n",
    );
    let c = cmd_for(&s, "sorted");
    let occupant = c.callable_args.get(&1);
    assert!(matches!(occupant, Some(CallableArg::Unresolved)), "got {occupant:?}");
}

/// A `for`-loop target shadows a `def`-bound name of the same spelling. The
/// loop target poisons the name (an ordinary assignment target), so the
/// reference after the loop is genuinely ambiguous between the def and
/// whatever the loop bound — `Unresolved`, never `Inline`.
#[test]
fn a_loop_target_shadowing_a_def_bound_name_is_unresolved() {
    let s = scan("def f(p):\n    pass\nfor f in fs:\n    sorted(xs, key=f)\n");
    let c = cmd_for(&s, "sorted");
    let occupant = c.callable_args.get(&1);
    assert!(matches!(occupant, Some(CallableArg::Unresolved)), "got {occupant:?}");
}

/// Finding 1 (fix round 1): `argument_callable` used to check `defined`
/// BEFORE `callable_ref`. `Binder::defined` is order-blind and scope-blind,
/// so a `def` appearing AFTER the reference used to silence a genuine
/// import reference into `Inline` — strictly more permissive than the
/// call-head path, which already refuses this identical shape with
/// `rebound_name`. This must not come back `Inline`.
///
/// Empirically (verified by running this exact snippet through the fixed
/// scanner) it resolves to `Named{head: "os.remove"}`, not `Unresolved`:
/// `callable_ref`'s own Name arm consults `imported` before `poisoned`, so
/// an imported-then-rebound bare name still resolves through the import
/// map. That is a narrower, separate asymmetry against `Walk::target`
/// (which checks `poisoned` first and refuses outright) than the one this
/// finding is about, and is out of scope for this fix: the bar this test
/// pins is the one the finding states — not `Inline`.
#[test]
fn an_imported_name_later_rebound_by_a_def_is_not_silently_inline() {
    let s = scan("from os import remove\nmap(remove, ['x'])\ndef remove(p):\n    pass\n");
    let c = cmd_for(&s, "map");
    assert!(!matches!(c.callable_args.get(&0), Some(CallableArg::Inline)), "got {:?}", c.callable_args.get(&0));
    match c.callable_args.get(&0) {
        Some(CallableArg::Named { head, .. }) => assert_eq!(head, "os.remove"),
        other => panic!("expected the verified current behavior, Named(os.remove), got {other:?}"),
    }
}

/// Finding 3 (fix round 1): a method-shaped call pushes its receiver at
/// index 0, shifting every argument index by one. A later task reads these
/// indices to decide whether a declared `callback_args` slot is occupied,
/// so the shift itself must be pinned.
#[test]
fn a_method_shaped_call_marks_a_callable_argument_at_its_receiver_shifted_index() {
    let s = scan("from os import remove\nx.method(remove)\n");
    let c = cmd_for(&s, ".method");
    assert!(c.callable_args.get(&0).is_none(), "index 0 is the receiver, not an argument: got {:?}", c.callable_args.get(&0));
    match c.callable_args.get(&1) {
        Some(CallableArg::Named { head, .. }) => assert_eq!(head, "os.remove"),
        other => panic!("expected os.remove at the receiver-shifted index 1, got {other:?}"),
    }
}

/// Shared harness for the `m2_92` decision tests below: the whole decide
/// pipeline, wrapping a python snippet inside `python -c "..."` the same way
/// `python_value_flow_test.rs`'s own `decide` helper does. The task-3 brief's
/// illustrative sketch (`vouch::guards::in_effect()`, a 5-argument
/// `decide_command`, a `.action`/`.reason`-bearing return type) does not
/// match this crate's actual API — `decide_command`/`decide_command_in`
/// takes no `kb` parameter (knowledge comes from the internal
/// `guards::in_effect()` cache already) and returns the `Decision` enum, not
/// a struct. This follows the proven shape used elsewhere instead; see
/// task-3-report.md for the full account.
fn common_decide(cmd: &str) -> (vouch::config::Action, String) {
    let config = vouch::config::load(
        "version = 1\n[lang.bash]\ndefault = \"allow\"\n[lang.bash.constructs]\nunmodeled_command = \"allow\"\n\
         [lang.python]\ndefault = \"allow\"\n[lang.python.constructs]\nunmodeled_command = \"ask\"\n\
         [write]\ndefault = \"ask\"\nallow_paths = [\"C:/work/**\"]\n",
    )
    .expect("config parses");
    match vouch::engine::decide_command_in(&config, "bash", cmd, Some("C:/Users/dev"), None) {
        vouch::protocol::Decision::Allow(r) => (vouch::config::Action::Allow, r),
        vouch::protocol::Decision::Ask(r) => (vouch::config::Action::Ask, r),
        vouch::protocol::Decision::Deny(r) => (vouch::config::Action::Deny, r),
        vouch::protocol::Decision::Abstain => panic!("unexpected Abstain for {cmd}"),
    }
}

mod m2_92 {
    use super::*;
    use vouch::config::Action;

    /// The 13-of-16 case: a replacement STRING in a slot declared for a
    /// function. No function anywhere, so no prompt about one.
    #[test]
    fn a_value_in_a_declared_callback_slot_no_longer_asks() {
        let (a, reason) = common_decide(r#"python -c "import re; re.sub('a', 'b', s)""#);
        assert!(!reason.contains("callback_argument"), "reason was: {reason}");
        assert_ne!(a, Action::Ask, "a string replacement must not raise a callback ask");
    }

    /// Finding 1 (review round 1): a subscript occupying a declared slot is
    /// UNREAD, not "read and not callable" — `cbs[0]` can name a function at
    /// runtime exactly as easily as `os.remove` can. Narrowing rule 1 to
    /// `effective.callable` alone silently allowed this; it must still ask.
    #[test]
    fn a_subscript_occupant_in_a_declared_callback_slot_still_asks() {
        let (_, reason) = common_decide(r#"python -c "import re; re.sub('a', cbs[0], s)""#);
        assert!(reason.contains("callback_argument"), "reason was: {reason}");
    }

    /// Finding 1 (review round 1): a call result is likewise UNREAD, not a
    /// value vouch has read and ruled out.
    #[test]
    fn a_call_result_occupant_in_a_declared_callback_slot_still_asks() {
        let (_, reason) = common_decide(r#"python -c "import re; re.sub('a', g(), s)""#);
        assert!(reason.contains("callback_argument"), "reason was: {reason}");
    }

    /// Finding 1 (review round 1): a starred spread has no explicit
    /// `argument_value` arm either, so it lands unread the same way — it must
    /// still ask rather than read as "occupied by a non-callable value."
    #[test]
    fn a_starred_argument_in_a_declared_callback_slot_still_asks() {
        let (_, reason) = common_decide(r#"python -c "import re; re.sub('a', *rest)""#);
        assert!(reason.contains("callback_argument"), "reason was: {reason}");
    }

    /// Finding 1 (task-final-review, spec §5.2 per-slot exclusivity): rule 1
    /// used to trip on `effective.callable` alone, which meant a REAL
    /// callable occupying a positional declared slot asked here on top of
    /// whatever `by_reference_invocations` (M2.89) already said about that
    /// same occupant — two asks for one slot, the exact defect finding 1
    /// fixes. An unresolved reference still legitimately asks post-fix, but
    /// only through the specific construct: `callable_argument`
    /// (`unresolved_callback_argument`), never `callback_argument`.
    #[test]
    fn a_positional_callable_slot_asks_through_the_specific_construct_only() {
        let (a, reason) =
            common_decide(r#"python -c "import re; re.sub('a', undefined_fn, s)""#);
        assert_eq!(a, Action::Ask, "reason was: {reason}");
        assert!(reason.contains("callable_argument"), "reason was: {reason}");
        assert!(!reason.contains("callback_argument"), "reason was: {reason}");
    }

    /// The positive mirror: `len` is in the pure-read set (M2.86) — no
    /// write, no directory change, no process start, in any invocation — so
    /// `by_reference_invocations` judges the reference itself clean
    /// (`unevaluable` is `None`) and rule 1 must not ALSO ask about the same
    /// occupant on the strength of it being callable-shaped. This is the
    /// deliberate loosening finding 1 requires: the allow traces to a real
    /// entry (`python:len`) that genuinely describes the referenced call,
    /// not to something merely no longer being raised.
    #[test]
    fn a_positional_callable_slot_allows_once_fully_judged_clean() {
        let (a, reason) = common_decide(r#"python -c "import re; re.sub('a', len, s)""#);
        assert_ne!(a, Action::Ask, "reason was: {reason}");
        assert!(!reason.contains("callback_argument"), "reason was: {reason}");
    }

    /// Rule 2's mirror of the positional pair above. `parse_int` has no
    /// positional form at all, so this exercises the raw index space rather
    /// than the folded one.
    #[test]
    fn a_keyword_only_callable_slot_asks_through_the_specific_construct_only() {
        let (a, reason) =
            common_decide(r#"python -c "import json; json.loads(s, parse_int=undefined_fn)""#);
        assert_eq!(a, Action::Ask, "reason was: {reason}");
        assert!(reason.contains("callable_argument"), "reason was: {reason}");
        assert!(!reason.contains("callback_argument"), "reason was: {reason}");
    }

    #[test]
    fn a_keyword_only_callable_slot_allows_once_fully_judged_clean() {
        let (a, reason) = common_decide(r#"python -c "import json; json.loads(s, parse_int=len)""#);
        assert_ne!(a, Action::Ask, "reason was: {reason}");
        assert!(!reason.contains("callback_argument"), "reason was: {reason}");
    }

    #[test]
    fn a_value_in_a_keyword_only_callback_slot_does_not_ask() {
        let (_, reason) = common_decide(r#"python -c "import json; json.loads(s, parse_int=3)""#);
        assert!(!reason.contains("callback_argument"), "reason was: {reason}");
    }

    /// Rule 3 is deliberately untouched: an unpack may carry any keyword the
    /// call never names, and narrowing it would infer absence from silence.
    #[test]
    fn a_keyword_unpack_still_trips_on_its_own() {
        let (_, reason) = common_decide(r#"python -c "import json; json.loads(s, **opts)""#);
        assert!(reason.contains("callback_argument"), "reason was: {reason}");
    }
}

mod m2_89 {
    use super::*;
    use vouch::config::Action;

    /// A declared `always` guard is true of every invocation, including one
    /// made by reference. This is applying a declared guard, not inventing
    /// one (CLAUDE.md §4). `shutil.rmtree`'s single `always = true` rule
    /// still needs `map` described (Task 5) before this can go green: today
    /// `map` is unmodeled, so `by_reference_invocations` never sees the
    /// reference inside it at all.
    #[test]
    fn a_referenced_recursive_delete_trips_its_guard() {
        let (_, reason) = common_decide(r#"python -c "import shutil; map(shutil.rmtree, dirs)""#);
        assert!(reason.contains("delete_recursive"), "reason was: {reason}");
    }

    /// The write claim has no argument to resolve. It must become an unnamed
    /// destination, never no write at all. Also blocked on Task 5's `map`.
    #[test]
    fn a_referenced_write_resolves_to_an_unnamed_destination() {
        let (a, reason) = common_decide(r#"python -c "import os; map(os.remove, xs)""#);
        assert_eq!(a, Action::Ask);
        assert!(
            reason.contains("unresolved_path") || reason.contains("callable_argument"),
            "a referenced write must say its destination is unknown; reason was: {reason}"
        );
        assert!(!reason.contains("unmodeled_command"), "map is described by now");
    }

    /// Precision the construct-only design could not buy: a mode-less `open`
    /// reads, so handing it over is not a write.
    ///
    /// Fix round 2, Finding D: the original form (`map(open, paths)`) passed
    /// vacuously — `map` has no entry yet (Task 5), so the reason was always
    /// `unmodeled_command: python:map`, which trivially contains no
    /// `unresolved_path` regardless of what `written_paths_in` does. Rewritten
    /// to use the already-shipped `python:open` entry's own declared `opener`
    /// slot as the reference carrier — the same pattern
    /// `a_referenced_directory_mover_raises_callable_argument_alone` and
    /// `a_referenced_all_args_write_reports_an_unresolved_destination` below
    /// already use — so this no longer depends on Task 5 at all. Empirically
    /// confirmed to exercise the real mode-gate: a by-reference call carries
    /// no arguments, so `mode_says_write` reads the absent mode position as a
    /// read (no unpack in play) and `written_paths_in`'s `arg_0` arm skips the
    /// write target entirely — genuinely different from
    /// `a_referenced_all_args_write_reports_an_unresolved_destination`'s
    /// `os.rename` sibling, whose ungated `"all_args"` grammar pushes
    /// `python::MARKER` (Finding B) and does say `unresolved_path` on the same
    /// empty-argument shape.
    #[test]
    fn a_referenced_mode_gated_write_without_a_mode_is_not_a_write() {
        let (_, reason) = common_decide(r#"python -c "open('f', opener=open)""#);
        assert!(!reason.contains("unresolved_path"), "reason was: {reason}");
    }

    /// The brief's own sketch for this test (`"for f in fs:\n    map(f, xs)"`
    /// with a literal backslash-n) never becomes a real newline inside a bash
    /// double-quoted string, so the snippet fails to parse and the assertion
    /// would pass for the wrong reason. Python allows a `for` loop's body to
    /// be one simple statement on the SAME line as the header
    /// (`for x in y: stmt`), so this keeps the brief's exact intent — `f` is
    /// a loop target, one of `rebound_name`'s own listed rebinding forms —
    /// without a newline at all. An assignment-from-a-call alternative
    /// (`f = get()`) was tried first and rejected: it makes `get` itself an
    /// unmodeled command, which fails this test for an unrelated reason.
    ///
    /// Blocked on Task 5's `map`, empirically confirmed: today `f`'s
    /// reference never reaches `unresolved_callback_argument` because `map`
    /// has no entry to declare a callback slot for it to occupy in the first
    /// place (Ruling A's gate), so the whole command instead asks on
    /// `unmodeled_command: python:map`. Not one of the two tests Ruling C
    /// named, but the same root cause.
    ///
    /// A second, independent cause existed alongside that one and is now
    /// fixed (fix round 2, Finding C): once `map` is described, this
    /// scenario's `callable_argument` reason (from the `Unresolved` arm,
    /// engine.rs's 1d2c loop) ties in configured rank with 1d2's generic
    /// `callback_argument` reason under the default config, and a
    /// tie-deferral introduced in fix round 1 unconditionally deferred to
    /// the generic reason on every such tie — on the theory the two were
    /// equally uninformative. Verified false by direct comparison of their
    /// `describe()` text (`callback_argument` presupposes the function's
    /// identity is known and only its effects are opaque; `callable_argument`
    /// says vouch could not even resolve what was handed over — a materially
    /// more specific claim), so this test would have stayed red on the tie
    /// alone even after Task 5 landed, for a reason its own comment never
    /// named. The deferral is removed; the specific reason now wins ties on
    /// its own merits, proven against a scratch `python:map` overlay (fix
    /// round 2 verification) under five configs: default (tied ask),
    /// `callable_argument = "allow"` (the generic reason correctly takes
    /// over), `callback_argument = "allow"` (the reverse — the specific
    /// reason wins even though it no longer merely runs first), both
    /// `"deny"` (tied deny, specific reason still wins), and probe entries
    /// for Finding A's `args_from_input`/`here_write`/`sub_write`/
    /// `remote_dest`/`rebinds_name_flags` claim kinds (each behaved exactly
    /// as `claim_kind_unevaluable`'s own arm comments in guards.rs document).
    #[test]
    fn an_unresolvable_callable_raises_the_construct() {
        let (a, reason) = common_decide(r#"python -c "for f in fs: map(f, xs)""#);
        assert_eq!(a, Action::Ask);
        assert!(reason.contains("callable_argument"), "reason was: {reason}");
    }

    /// A lambda's body is already emitted, so a second account would prompt
    /// twice for one operation.
    ///
    /// Fix round 2, Finding D: the original form (`map(lambda x: x, xs)`)
    /// passed vacuously for the same reason as the test above — `map` is
    /// unmodeled, so the reason was always `unmodeled_command: python:map`.
    /// Rewritten to occupy the shipped `python:open` entry's own `opener`
    /// slot instead, the same carrier the sibling tests around this one use.
    /// `CallableArg::Inline` is never routed to `by_reference_invocations` or
    /// `unresolved_callback_argument` by design (only `Named` and
    /// `Unresolved` are) — a lambda's own body is already scanned and
    /// emitted as its own `Cmd` where it was written, so it needs no second
    /// judgement here.
    ///
    /// Finding 1 (task-final-review): before the fix this still asked, on
    /// `callback_argument` — the generic rule fired on `effective.callable`
    /// alone, with no narrower check excluding a slot the scanner had
    /// already resolved to a `CallableArg`. `open('f', opener=lambda x: x)`
    /// has an empty, harmless lambda body (no calls at all) and no other
    /// claim of its own (mode-less `open` makes no write claim), so the
    /// double ask was pure noise: nothing in the whole command needed a
    /// prompt. Post-fix this cleanly allows.
    #[test]
    fn an_inline_callable_raises_nothing_of_its_own() {
        let (a, reason) = common_decide(r#"python -c "open('f', opener=lambda x: x)""#);
        assert_ne!(a, Action::Ask, "reason was: {reason}");
        assert!(!reason.contains("callable_argument"), "reason was: {reason}");
        assert!(!reason.contains("callback_argument"), "reason was: {reason}");
    }

    /// Finding 1's own worked example (task-final-review): an Inline
    /// occupant contributing nothing of its own must never be confused with
    /// the WHOLE command being safe — a dangerous call written inside the
    /// lambda's body is scanned and judged as its own event, independent of
    /// the slot it occupies. `os.remove(x)` inside the body asks on its own
    /// write claim (`x` is the lambda's own parameter, an unresolved
    /// destination); the outer `open(...)` call's `opener` slot must
    /// contribute no SECOND, redundant ask — the fix must not trade a
    /// false double-prompt for a false allow.
    #[test]
    fn an_inline_callable_with_a_dangerous_body_asks_through_the_bodys_own_call() {
        let (a, reason) = common_decide(
            r#"python -c "import os; open('f', opener=lambda x: os.remove(x))""#,
        );
        assert_eq!(a, Action::Ask, "reason was: {reason}");
        assert!(reason.contains("unresolved_path"), "reason was: {reason}");
        assert!(!reason.contains("callback_argument"), "reason was: {reason}");
    }

    /// Spec §5.4. The scanner cannot know whether, when, or how often a
    /// referenced mover runs, so it must contribute nothing to the timeline.
    ///
    /// Task 5, ruling 3: split from also asserting `callable_argument`
    /// fires. It never can, alongside this snippet's competing
    /// `open('out.txt', 'w')`: pass 1c's ordinary write-target resolution
    /// runs far earlier in engine.rs than the by-reference judgment and
    /// claims the tied `Action::Ask` slot first, so its reason masks
    /// `callable_argument`'s — a pre-existing, general property of `worst`'s
    /// strict-`>` tie-break (any two unrelated Asks in one command can mask
    /// each other the same way), out of scope to change here (CLAUDE.md,
    /// do not touch `worst`). `a_referenced_directory_mover_raises_
    /// callable_argument_alone` above already isolates that half with no
    /// competing write.
    ///
    /// What remains, and is the actual load-bearing property: a referenced
    /// `os.chdir` must never move the write base. The positive control
    /// alongside it proves the assertion is not vacuous for a scanner that
    /// never resolves anything — a REAL `os.chdir` (not by reference) does
    /// move the base, and the reason names `dirs/out.txt`.
    #[test]
    fn a_referenced_directory_mover_does_not_move_the_write_base() {
        let (_, reason) = common_decide(
            r#"python -c "import os; map(os.chdir, dirs); open('out.txt', 'w')""#,
        );
        assert!(
            !reason.contains("dirs/out.txt") && !reason.contains("dirs\\out.txt"),
            "the base must not have moved on a by-reference chdir; reason was: {reason}"
        );

        let (_, control) = common_decide(
            r#"python -c "import os; os.chdir('dirs'); open('out.txt', 'w')""#,
        );
        assert!(
            control.contains("dirs/out.txt") || control.contains("dirs\\out.txt"),
            "control: a REAL chdir must move the base; reason was: {control}"
        );
    }

    /// Task 4 review C2/C3, isolated from the tie-break masking above: the
    /// broadened `unevaluable` check's `changes_dir` arm, with no competing
    /// write ask in the command to mask it. `open`'s own call is mode-less
    /// (`writes_only_with_file_mode`), so it makes no write claim of its
    /// own — the only thing this command has to say anything about is the
    /// referenced `os.chdir` occupying `open`'s declared `opener` slot.
    #[test]
    fn a_referenced_directory_mover_raises_callable_argument_alone() {
        let (a, reason) = common_decide(r#"python -c "import os; open('f', opener=os.chdir)""#);
        assert_eq!(a, Action::Ask, "reason was: {reason}");
        assert!(reason.contains("callable_argument"), "reason was: {reason}");
        assert!(
            reason.contains("by reference: python:os.chdir"),
            "reason was: {reason}"
        );
        assert!(
            reason.contains("this is not a guard"),
            "os.chdir's changes_dir claim has no guard behind it (I4 point 2); reason was: {reason}"
        );
    }

    /// Task 4 review C4: `written_paths_in`'s `"all_args"` arm used to
    /// silently produce no write target when a by-reference call's argument
    /// list was empty. `os.rename` (`writes = "all_args"`, no rule, no other
    /// unevaluable claim) isolates that arm: the only thing this command can
    /// report is its unresolved destination.
    #[test]
    fn a_referenced_all_args_write_reports_an_unresolved_destination() {
        let (a, reason) = common_decide(r#"python -c "import os; open('f', opener=os.rename)""#);
        assert_eq!(a, Action::Ask, "reason was: {reason}");
        assert!(reason.contains("unresolved_path"), "reason was: {reason}");
        assert!(
            reason.contains(
                "by reference: python:os.rename (no arguments to resolve a destination from)"
            ),
            "reason was: {reason}"
        );
    }

    /// Task 4 review C5: Step 5.2 used to skip straight to the generic
    /// `unresolved_path` sentence, bypassing any `[[write.scope]]` entry
    /// naming the referenced program. A dedicated config (not
    /// `common_decide`'s shared one, so no other test is affected) restricts
    /// `python:os.rename` to a tree its unresolved destination cannot be
    /// proven inside; the reason must be the scope's own wording, not the
    /// generic one bypassing it would have produced.
    #[test]
    fn a_write_scope_still_governs_a_referenced_program() {
        let config = vouch::config::load(
            "version = 1\n[lang.bash]\ndefault = \"allow\"\n[lang.bash.constructs]\nunmodeled_command = \"allow\"\n\
             [lang.python]\ndefault = \"allow\"\n[lang.python.constructs]\nunmodeled_command = \"ask\"\n\
             [write]\ndefault = \"ask\"\nallow_paths = [\"C:/work/**\"]\n\
             [[write.scope]]\nprograms = [\"python:os.rename\"]\nonly_under = [\"C:/scratch/**\"]\n",
        )
        .expect("config parses");
        let decision = vouch::engine::decide_command_in(
            &config,
            "bash",
            r#"python -c "import os; open('f', opener=os.rename)""#,
            Some("C:/Users/dev"),
            None,
        );
        let (a, reason) = match decision {
            vouch::protocol::Decision::Ask(r) => (Action::Ask, r),
            vouch::protocol::Decision::Allow(r) => (Action::Allow, r),
            vouch::protocol::Decision::Deny(r) => (Action::Deny, r),
            vouch::protocol::Decision::Abstain => panic!("unexpected Abstain"),
        };
        assert_eq!(a, Action::Ask, "reason was: {reason}");
        assert!(
            reason.contains("vouch stopped on: write scope"),
            "reason was: {reason}"
        );
        assert!(
            reason.contains("[[write.scope]] limits python:os.rename"),
            "reason was: {reason}"
        );
    }

    /// Task 4 review I1: `Cmd.callable_args` is a `HashMap`, so without
    /// sorting by raw index before judging, which of two tied references
    /// wins the reported reason could vary by hash order rather than by the
    /// command. Both keyword slots are declared `callback_args` on
    /// `json.loads`; `parse_int` is pushed first (one positional ahead of
    /// it), so its reference must be the one that wins the tied
    /// `Action::Ask` rank, every run.
    #[test]
    fn callable_arguments_are_judged_in_a_deterministic_order() {
        for _ in 0..20 {
            let (a, reason) = common_decide(
                r#"python -c "import os, json; json.loads(s, parse_int=os.chdir, parse_float=os.remove)""#,
            );
            assert_eq!(a, Action::Ask, "reason was: {reason}");
            assert!(
                reason.contains("by reference: python:os.chdir"),
                "the lower raw index must win the tie every run; reason was: {reason}"
            );
        }
    }
}

/// Task 5: the vocabulary the by-reference fix unblocks. `sorted`, `min`,
/// `max`, `map`, `filter`, `any`, `all`, and `sum` were left out of the
/// pure-read set (M2.86) only because a callable handed to them was
/// invisible; with the reference recorded and judged (M2.89/M2.92) each can
/// now be described as what it is.
mod vocabulary {
    use super::*;
    use vouch::config::Action;

    #[test]
    fn an_ordinary_sort_no_longer_asks() {
        let (a, _) = common_decide(r#"python -c "print(sorted(xs))""#);
        assert_eq!(a, Action::Allow);
    }

    #[test]
    fn a_sort_key_that_deletes_is_judged_as_a_delete() {
        let (a, reason) = common_decide(
            r#"python -c "import shutil; sorted(xs, key=shutil.rmtree)""#,
        );
        assert_eq!(a, Action::Ask);
        assert!(reason.contains("delete_recursive"), "reason was: {reason}");
    }

    /// `key` is keyword-only in the real signature, so it must NOT be listed
    /// in `arg_names` — doing so would claim a positional slot no spelling
    /// can reach. This pins that it is found through the keyword rule.
    #[test]
    fn the_keyword_only_key_slot_is_found_by_the_keyword_rule() {
        let (_, reason) = common_decide(r#"python -c "sorted(xs, key=f)""#);
        assert!(reason.contains("callable_argument"), "reason was: {reason}");
    }

    /// `map`'s function IS positional-only, so this exercises rule 1.
    #[test]
    fn the_positional_function_slot_is_found_by_the_positional_rule() {
        let (_, reason) = common_decide(r#"python -c "map(f, xs)""#);
        assert!(reason.contains("callable_argument"), "reason was: {reason}");
    }

    #[test]
    fn a_pure_aggregate_allows() {
        for src in [r#"python -c "print(any(xs))""#, r#"python -c "print(sum(xs))""#] {
            assert_eq!(common_decide(src).0, Action::Allow, "{src}");
        }
    }

    /// §3: the claim must be true. `tz` is a tzinfo OBJECT whose methods
    /// `now()` calls; it is never invoked as a function.
    #[test]
    fn datetime_now_no_longer_claims_its_tz_slot_is_invoked() {
        let (a, reason) = common_decide(
            r#"python -c "import datetime; datetime.datetime.now(datetime.timezone.utc)""#,
        );
        assert_eq!(a, Action::Allow);
        assert!(
            !reason.contains("callback_argument") && !reason.contains("callable_argument"),
            "reason was: {reason}"
        );
    }
}
