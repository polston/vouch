//! On-demand measurement: the STDIN-CLAIM FLAGS-ONLY population — the §6.2
//! pre-count `standalone_flags`'s merge decision quotes (spec
//! `2026-08-20-standalone-flags-design.md` §7), re-derived at the tip to
//! prove the count is parser-level and does not move with the changeset.
//!
//! A command is counted when all three hold:
//!   1. some entry for the head declares `evaluates_input = "stdin"` (it is
//!      a program vouch knows can read code from standard input);
//!   2. its `args` are non-empty;
//!   3. `guards::reads_stdin(cmd)` answers true — no positional operand or
//!      `-c` snippet is present, so a script has to arrive on stdin.
//!
//! The total is labelled honestly rather than simply "flags-only": criteria
//! 2+3 also admit a lone `-`/`-s` spelling (`bash -s`, `python -`), which
//! explicitly ASKS to read stdin and is never `standalone_flags`-shaped (a
//! flag that requests standard input is the opposite of one that prints a
//! version and exits). That subset is counted and printed separately so the
//! two stay distinguishable, per `reads_stdin`'s own two branches: naming no
//! source at all (every arg dash-prefixed, none of them `-c`/`-s`/`-`), or
//! naming the source as stdin explicitly (`-s`/`-` present).
//!
//! **CANDIDATE POPULATION (M2.144(a)):** a corpus zero says nothing on its
//! own — it could mean "this shape does not occur" or "no shipped entry
//! could ever produce it". The count of shipped bash-scoped entries
//! declaring `evaluates_input = "stdin"` is printed beside the corpus
//! result so the two zeros stay distinguishable.
//!
//! **`VOUCH_COUNT_HEADS=<comma,separated,names>`** (own switch, not pinned
//! by `.cargo/config.toml`, read by this example alone): for each named
//! head, report a flags-only OCCURRENCE count that is entry-independent —
//! no knowledge lookup at all, because this exists to check heads that
//! carry NO stdin-claiming entry (10b's fixture heads among them). The
//! criterion: `args` non-empty and every token flag-shaped under the
//! default dash prefix (`starts_with('-')`), regardless of what the
//! program's own `flag_prefix` says.
//!
//! Both counts come from one pass: `scan.commands`, the TOP-LEVEL commands
//! only — the same scope `count_recognition_holes.rs` uses, because nothing
//! above a top-level command appends arguments, so its own scanned
//! completeness is the whole fold.
//!
//! Run: cargo run --release --example count_standalone_shapes
//! Run with the per-head report: VOUCH_COUNT_HEADS=foo,bar cargo run --release --example count_standalone_shapes

#[path = "../tests/common/mod.rs"]
mod common;

use std::collections::{BTreeMap, BTreeSet};

/// Per-head counts for the stdin-claim flags-only population.
#[derive(Default)]
struct Tally {
    instances: usize,
    rows: BTreeSet<usize>,
    lone_dash_instances: usize,
    lone_dash_rows: BTreeSet<usize>,
}

/// True when some bash-scoped entry for `head` (already `base_name`d)
/// declares `evaluates_input = "stdin"` — the same name+language filter
/// `guards::entries_for` applies, re-derived here because that helper is
/// private to `guards.rs`.
fn claims_stdin(kb: &vouch::guards::Knowledge, head: &str) -> bool {
    kb.program.iter().any(|p| {
        p.match_names.iter().any(|n| n.to_ascii_lowercase() == head)
            && (p.languages.is_empty() || p.languages.iter().any(|l| l == "bash"))
            && p.evaluates_input == "stdin"
    })
}

/// Whether `reads_stdin(cmd)` (already known true here) fired via the
/// explicit `-`/`-s` spelling rather than via naming no source at all —
/// `reads_stdin`'s own second branch, re-derived here because the branch
/// itself is not exposed.
fn is_lone_dash_spelling(cmd: &vouch::syntax::Cmd) -> bool {
    cmd.args.iter().any(|a| a == "-" || a.eq_ignore_ascii_case("-s"))
}

fn main() {
    let rows = common::rows_for_measurement();
    let kb = vouch::guards::in_effect();
    let scanner = vouch::syntax::scanner_for("bash").expect("bash scanner exists");

    // M2.144(a): the population a corpus zero is measured against.
    let candidate_population = kb
        .program
        .iter()
        .filter(|p| p.languages.is_empty() || p.languages.iter().any(|l| l == "bash"))
        .filter(|p| p.evaluates_input == "stdin")
        .count();

    let heads_wanted: Vec<String> = std::env::var("VOUCH_COUNT_HEADS")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    let mut wanted_counts: BTreeMap<String, usize> =
        heads_wanted.iter().map(|n| (n.clone(), 0)).collect();

    let mut tallies: BTreeMap<String, Tally> = BTreeMap::new();
    let mut scanned = 0usize;

    for (i, row) in rows.iter().enumerate() {
        let Ok(scan) = scanner.scan(&row.cmd) else { continue };
        scanned += 1;
        for cmd in &scan.commands {
            let head = vouch::guards::base_name(&cmd.head);

            // VOUCH_COUNT_HEADS: entry-independent flags-only occurrences.
            if let Some(c) = wanted_counts.get_mut(&head) {
                if !cmd.args.is_empty() && cmd.args.iter().all(|a| a.starts_with('-')) {
                    *c += 1;
                }
            }

            // The stdin-claim flags-only population.
            if cmd.args.is_empty() {
                continue;
            }
            if !claims_stdin(kb, &head) {
                continue;
            }
            if !vouch::guards::reads_stdin(cmd) {
                continue;
            }
            let t = tallies.entry(head).or_default();
            t.instances += 1;
            t.rows.insert(i);
            if is_lone_dash_spelling(cmd) {
                t.lone_dash_instances += 1;
                t.lone_dash_rows.insert(i);
            }
        }
    }

    let total_instances: usize = tallies.values().map(|t| t.instances).sum();
    // A row counts once per head, exactly as count_recognition_holes.rs's
    // "head/row pairs" does — a row with two different stdin-claiming heads
    // is two pairs, so per-head rows can sum past the corpus's own row count.
    let total_rows: usize = tallies.values().map(|t| t.rows.len()).sum();
    let lone_dash_instances: usize = tallies.values().map(|t| t.lone_dash_instances).sum();
    let lone_dash_rows: usize = tallies.values().map(|t| t.lone_dash_rows.len()).sum();

    println!("corpus rows: {} ({scanned} scanned clean)", rows.len());
    println!();
    println!("=== the STDIN-CLAIM FLAGS-ONLY population ===");
    println!(
        "  criteria: some entry for the head claims evaluates_input = \"stdin\"; \
         args non-empty; reads_stdin(cmd) true"
    );
    println!(
        "  CANDIDATE POPULATION (shipped bash-scoped stdin-claiming entries): {candidate_population}"
    );
    println!(
        "  total instances: {total_instances}  (of which lone `-`/`-s` spellings, never \
         standalone-shaped: {lone_dash_instances})"
    );
    println!(
        "  total rows (a row counts once per head): {total_rows}  (of which lone `-`/`-s` \
         rows: {lone_dash_rows})"
    );
    println!();
    println!("  per head:");
    let mut ordered: Vec<_> = tallies.iter().collect();
    ordered.sort_by(|a, b| b.1.instances.cmp(&a.1.instances).then(a.0.cmp(b.0)));
    for (head, t) in ordered {
        println!(
            "    {head:<20} instances {:<6} rows {:<6} lone-dash instances {:<6} lone-dash rows {}",
            t.instances,
            t.rows.len(),
            t.lone_dash_instances,
            t.lone_dash_rows.len()
        );
    }
    if tallies.is_empty() {
        println!("    (none)");
    }

    if !heads_wanted.is_empty() {
        println!();
        println!("=== VOUCH_COUNT_HEADS: flags-only OCCURRENCE count, entry-independent ===");
        println!("  criteria: args non-empty; every token flag-shaped under the default dash prefix ('-')");
        for name in &heads_wanted {
            println!("    {name:<20} flags-only occurrences: {}", wanted_counts[name]);
        }
    }
}
