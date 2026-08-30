//! On-demand measurement: argument-position callable references in the real
//! corpus, and what occupies each shipped `callback_args` slot (spec §7).
//!
//! Fix round 1 replaced this file's first version, which tallied every
//! argument of every call to a program that declares *some* `callback_args`
//! name, regardless of whether the call touched a declared slot at all. This
//! version computes occupancy per DECLARED SLOT NAME: for a name with a
//! positional slot (`arg_names` contains it), occupancy comes straight from
//! vouch's own public `guards::effective_args` — the same fold the engine
//! itself decides with; for a name with none (keyword-only), occupancy comes
//! from a direct scan of raw keyword tokens, mirroring the engine's own rule
//! for that case exactly. Classifying an occupied positional slot as
//! callable or value needs to know which RAW argument filled it, which
//! `effective_args`'s folded output does not carry — `raw_positions` below
//! reconstructs that mapping and every result is cross-checked against the
//! real fold's own text before being trusted; a mismatch is reported as
//! unresolved rather than guessed. `guards::callback_argument_used` (also
//! public) is the reference boolean for "was any declared slot on this call
//! used at all" and serves two jobs: a cross-check this file's own
//! occupancy findings must never contradict (enforced by an assertion, not
//! a count — see `measure_slot_occupancy`), and the only way to attribute
//! the one rule this file cannot see directly (a nameless `**unpack`, which
//! could be carrying any keyword the call never names).
//!
//! Counts only. No corpus text is printed — the classification is by shape
//! and by stdlib entry name, never by the command it came from.
//!
//! Run: `cargo run --release --example count_python_callable_reference_shapes`

#[path = "../tests/common/mod.rs"]
mod common;

use std::collections::BTreeMap;
use vouch::guards::{callback_argument_used, effective_args, EffectiveArgs, Knowledge, Program};
use vouch::syntax::{CallableArg, Cmd};

enum Occupant {
    Callable,
    Value,
}

fn main() {
    let rows = common::rows_for_measurement();
    let kb = common::shipped_kb();
    let python = vouch::syntax::scanner_for("python").expect("python scanner exists");

    // Denominators (spec §6.3: absence in a scan is evidence about the scan,
    // never about the contents — every row examined and both parse-failure
    // classes are reported, never dropped silently). Named to match
    // `count_python_argv_shapes.rs`'s counters exactly.
    let mut parsed_bash_rows = 0usize;
    let mut python_snippets = 0usize; // marks
    let mut parsed_python_snippets = 0usize; // marks
    let mut python_parse_failures = 0usize; // marks

    // Reference-kind tally: marks, one per `CallableArg` entry seen anywhere
    // (a command can carry more than one), separate from the row count below.
    let mut reference_kind_marks: BTreeMap<&str, usize> = BTreeMap::new();
    let mut rows_with_reference = 0usize; // rows: >=1 CallableArg anywhere in the row

    // Declared-slot occupancy: marks, one per occupied declared slot, keyed
    // "stdlib.head:name <- callable|value".
    let mut slot_occupant_marks: BTreeMap<String, usize> = BTreeMap::new();
    // Occupied per the real `effective_args` fold, but this file could not
    // safely recover which raw argument filled the slot (see
    // `classify_positional`) — expected to read empty; a nonzero entry is a
    // concern to report, not a bucket to fold quietly into the others.
    let mut slot_unresolved_marks: BTreeMap<String, usize> = BTreeMap::new();
    // `callback_argument_used` (the real engine) says a slot on this call
    // was used, but this file's own rules found none — attributable only to
    // the nameless `**unpack` rule this file cannot see directly. Keyed by
    // head, marks: one per such call (which declared name it was is not
    // knowable from here).
    let mut slot_unattributed_marks: BTreeMap<String, usize> = BTreeMap::new();
    // A shipped entry matched the head and declares `receiver_from`, whose
    // gate this file cannot evaluate (private). None of the shipped
    // `callback_args`-bearing entries declare it today, so this is expected
    // to stay at zero; kept as an explicit, counted skip rather than a
    // silent assumption in case that ever changes.
    let mut receiver_gated_candidates = 0usize;

    let mut commands_with_higher_order_head = 0usize;

    for row in &rows {
        let Some(snippets) = common::python_snippets(&kb, &row.cmd) else {
            continue;
        };
        parsed_bash_rows += 1;
        let mut row_has_reference = false;
        for src in &snippets {
            python_snippets += 1;
            let Ok(scan) = python.scan(src) else {
                python_parse_failures += 1;
                continue;
            };
            parsed_python_snippets += 1;
            for cmd in &scan.commands {
                let head = vouch::guards::base_name(&cmd.head);

                for arg in cmd.callable_args.values() {
                    *reference_kind_marks
                        .entry(match arg {
                            CallableArg::Named { .. } => "named",
                            CallableArg::Inline => "inline",
                            CallableArg::Unresolved => "unresolved",
                        })
                        .or_default() += 1;
                    row_has_reference = true;
                }

                if head_is_higher_order(&head) {
                    commands_with_higher_order_head += 1;
                }

                measure_slot_occupancy(
                    &kb,
                    cmd,
                    &head,
                    &mut slot_occupant_marks,
                    &mut slot_unresolved_marks,
                    &mut slot_unattributed_marks,
                    &mut receiver_gated_candidates,
                );
            }
        }
        if row_has_reference {
            rows_with_reference += 1;
        }
    }

    println!("corpus_rows={}", rows.len());
    println!("parsed_bash_rows={parsed_bash_rows}");
    println!("python_snippets={python_snippets}  (marks)");
    println!("parsed_python_snippets={parsed_python_snippets}  (marks)");
    println!("python_parse_failures={python_parse_failures}  (marks)");

    println!();
    println!("rows_with_argument_position_callable_reference={rows_with_reference}  (rows)");
    println!("reference_kind (marks, one per CallableArg entry seen):");
    for (k, v) in &reference_kind_marks {
        println!("  {v:>6}  {k}");
    }

    println!();
    println!("declared_callback_slot_occupancy (marks, one per occupied declared slot):");
    for (k, v) in &slot_occupant_marks {
        println!("  {v:>6}  {k}");
    }

    if !slot_unresolved_marks.is_empty() {
        println!();
        println!(
            "declared_callback_slot_unresolved (marks — occupied per the real \
             effective_args fold, but this file could not recover which raw \
             argument filled the slot; expected to be empty):"
        );
        for (k, v) in &slot_unresolved_marks {
            println!("  {v:>6}  {k}");
        }
    }

    if !slot_unattributed_marks.is_empty() {
        println!();
        println!(
            "declared_callback_slot_unattributed (marks, keyed by head — \
             callback_argument_used reports a used slot this file's own rules \
             could not find; attributed to the nameless **unpack rule):"
        );
        for (k, v) in &slot_unattributed_marks {
            println!("  {v:>6}  {k}");
        }
    }

    println!();
    println!("receiver_gated_candidates={receiver_gated_candidates}  (expected 0 — see comment above)");
    println!("commands_with_higher_order_head={commands_with_higher_order_head}  (commands, not rows)");
}

/// The heads Task 5 describes. Named here rather than in `src/` because this
/// is a measurement, and CLAUDE.md §10 keeps program names out of the engine.
fn head_is_higher_order(head: &str) -> bool {
    matches!(
        head,
        "python:sorted"
            | "python:min"
            | "python:max"
            | "python:map"
            | "python:filter"
            | "python:any"
            | "python:all"
            | "python:sum"
    )
}

/// Finds the one shipped entry (if any) declaring a callback slot for `head`,
/// and tallies every declared slot's occupancy for this one call.
///
/// The head-match test below is copied character-for-character from
/// `guards::callback_argument_used`'s own (`prog.match_names.iter().any(|n|
/// n.to_ascii_lowercase() == head)`) rather than written afresh, because the
/// assertion near the end of this function depends on the two searches
/// agreeing on which program a head resolves to.
#[allow(clippy::too_many_arguments)]
fn measure_slot_occupancy(
    kb: &Knowledge,
    cmd: &Cmd,
    head: &str,
    slot_occupant_marks: &mut BTreeMap<String, usize>,
    slot_unresolved_marks: &mut BTreeMap<String, usize>,
    slot_unattributed_marks: &mut BTreeMap<String, usize>,
    receiver_gated_candidates: &mut usize,
) {
    let mut candidate: Option<&Program> = None;
    for prog in &kb.program {
        if prog.callback_args.is_empty() {
            continue;
        }
        if prog.match_names.iter().any(|n| n.to_ascii_lowercase() == head) {
            candidate = Some(prog);
            break;
        }
    }
    let Some(prog) = candidate else {
        return; // no shipped entry declares a callback slot for this head
    };
    if prog.receiver_from.as_ref().is_some_and(|tags| !tags.is_empty()) {
        *receiver_gated_candidates += 1;
        return;
    }

    let effective = effective_args(prog, cmd);
    let mine = raw_positions(prog, cmd);
    let mut mine_found_any = false;

    for name in &prog.callback_args {
        match declared_position(prog, name, effective.base_offset) {
            Some(pos) => {
                if !slot_occupied(&effective, pos) {
                    continue;
                }
                // M2.92: `mine_found_any` mirrors the real engine's rule 1,
                // which now requires a marked callable, not mere occupancy —
                // so it is set only in the `Callable` arm below, not on
                // occupancy alone. `slot_occupant_marks` still tallies both
                // `<- callable` and `<- value` occupancy exactly as before;
                // only the cross-check signal narrowed.
                match classify_positional(cmd, &effective, &mine, pos) {
                    Some(Occupant::Callable) => {
                        mine_found_any = true;
                        *slot_occupant_marks
                            .entry(format!("{head}:{name} <- callable"))
                            .or_default() += 1;
                    }
                    Some(Occupant::Value) => {
                        *slot_occupant_marks
                            .entry(format!("{head}:{name} <- value"))
                            .or_default() += 1;
                    }
                    None => {
                        *slot_unresolved_marks.entry(format!("{head}:{name}")).or_default() += 1;
                    }
                }
            }
            None => {
                // Keyword-only: no positional slot exists to fold onto, so
                // the only way this name is filled is a raw keyword token
                // spelling it directly — mirrors the real engine's rule 2.
                for (i, a) in cmd.args.iter().enumerate() {
                    if !cmd.keyword_args.contains(&i) {
                        continue;
                    }
                    let Some((keyword, _)) = a.split_once('=') else {
                        continue;
                    };
                    if keyword != name {
                        continue;
                    }
                    // M2.92: same narrowing as the positional arm above —
                    // only a marked callable counts toward the cross-check.
                    let occupant = if cmd.callable_args.contains_key(&i) {
                        mine_found_any = true;
                        "callable"
                    } else {
                        "value"
                    };
                    *slot_occupant_marks
                        .entry(format!("{head}:{name} <- {occupant}"))
                        .or_default() += 1;
                }
            }
        }
    }

    let used = callback_argument_used(kb, cmd);
    if used && !mine_found_any {
        *slot_unattributed_marks.entry(head.to_string()).or_default() += 1;
    }
    // `mine_found_any` can only become true through this function's own
    // reimplementations of the real engine's rule 1 (via the real, public
    // `effective_args` fold) and rule 2 (an identical raw-keyword-token
    // scan) for THIS SAME candidate — and, since M2.92, only when the slot
    // that satisfied one of those rules is a MARKED CALLABLE, not merely
    // occupied — so whenever it is true, `callback_argument_used`'s own
    // loop, reaching this same candidate, must find the same marked
    // callable through the same rule and return true. This is provable
    // from the two functions' bodies, not merely expected; a failure here
    // means this file's reimplementation has actually diverged from the
    // engine, which must be fixed rather than papered over with a counter.
    assert!(
        used || !mine_found_any,
        "{head}: found an occupied declared slot that vouch's own \
         callback_argument_used disagrees with — this should be provably \
         impossible; the reimplementation above has diverged from the engine"
    );
}

/// The folded-array position `name` occupies for `prog`, if any — the same
/// one-line lookup as the private `guards::callback_arg_positions`, over the
/// same public `Program` fields (that function itself is not public).
fn declared_position(prog: &Program, name: &str, base_offset: usize) -> Option<usize> {
    prog.arg_names.iter().position(|n| n == name).map(|p| p + base_offset)
}

/// Whether `effective.values[pos]` is a real occupant rather than an
/// unfilled gap — the same check as the private `guards::eff_position_occupied`,
/// over the same public `EffectiveArgs` fields.
fn slot_occupied(effective: &EffectiveArgs, pos: usize) -> bool {
    effective.values.get(pos).is_some() && !effective.padding.contains(&pos)
}

/// Best-effort reconstruction of which RAW `cmd.args` index filled each
/// position in `guards::effective_args`'s folded output, for classifying an
/// already-confirmed-occupied position (see `classify_positional`).
///
/// This is not a second occupancy check — occupancy always comes from the
/// real `effective_args` via `slot_occupied`. It exists only because
/// `EffectiveArgs::values` holds post-fold text, and `cmd.callable_args` is
/// keyed by raw index, so classifying an occupied position needs to know
/// which raw argument produced it.
///
/// One known gap: `effective_args`'s own phase 1 silently drops a raw,
/// non-keyword argument that is python's own nameless-unpack marker
/// (`f(**opts)`) — a value this crate does not expose outside `src/`. This
/// walk cannot reproduce that drop, so from that argument on its positions
/// may not line up with the real fold's. `classify_positional` cross-checks
/// every result against the real fold's own text before trusting it, so
/// this gap surfaces as an explicit "unresolved" count rather than a silent
/// misclassification.
fn raw_positions(prog: &Program, cmd: &Cmd) -> Vec<Option<usize>> {
    let base = usize::from(cmd.head.contains(":."));
    if prog.arg_names.is_empty() {
        return (0..cmd.args.len()).map(Some).collect();
    }
    let mut eff: Vec<Option<usize>> = Vec::new();
    let mut folded: Vec<(usize, usize)> = Vec::new();
    for (i, a) in cmd.args.iter().enumerate() {
        if cmd.keyword_args.contains(&i) {
            if let Some((name, _)) = a.split_once('=') {
                if let Some(p) = prog.arg_names.iter().position(|n| n == name) {
                    folded.push((base + p, i));
                }
            }
            continue;
        }
        eff.push(Some(i));
    }
    folded.sort_by_key(|(pos, _)| *pos);
    for (pos, raw_index) in folded {
        while eff.len() < pos {
            eff.push(None);
        }
        if eff.len() == pos {
            eff.push(Some(raw_index));
        }
    }
    eff
}

/// Classifies an already-confirmed-occupied declared position, or reports
/// that this file could not safely recover which raw argument filled it.
/// Never guesses: a raw index from `raw_positions` is trusted only after its
/// own text agrees with what the real `effective_args` fold reports at that
/// same position.
fn classify_positional(
    cmd: &Cmd,
    effective: &EffectiveArgs,
    mine: &[Option<usize>],
    pos: usize,
) -> Option<Occupant> {
    let raw_index = (*mine.get(pos)?)?;
    let raw_text = cmd.args.get(raw_index)?;
    let expected = if cmd.keyword_args.contains(&raw_index) {
        raw_text.split_once('=').map(|(_, value)| value)
    } else {
        Some(raw_text.as_str())
    };
    if expected != effective.values.get(pos).map(String::as_str) {
        return None; // cross-check failed; report unresolved rather than guess
    }
    Some(if cmd.callable_args.contains_key(&raw_index) {
        Occupant::Callable
    } else {
        Occupant::Value
    })
}
