//! On-demand measurement: what argument SHAPES the corpus shows for one
//! program name, read through vouch's own scanner rather than a regex.
//!
//! Written while deciding what a guard rule for `kill` should trip on (M2.16).
//! A first pass at the same question with a regex counted 81 occurrences and
//! among their "flags" was `--release"`, because the pattern matched the word
//! inside commands that were never a `kill` at all — §6.1, demonstrated on
//! itself. The scanner answers with the head it actually parsed.
//!
//! General rather than kill-specific on purpose: "what does this program get
//! handed in real traffic" is the question every §3 claim needs answered
//! before it is written, so describing the next program starts here too.
//!
//! **Nothing but shapes is printed.** The corpus is real machine history, so a
//! command's text, its operands and any path in them must never reach stdout —
//! this file's output lands in terminals, transcripts and review notes. Flag
//! NAMES are printed with any attached value cut off at the `=`, and operands
//! are reported only as the CLASS of thing they are.
//!
//! Run: cargo run --release --example count_head_shapes -- <name> [<name>…]

#[path = "../tests/common/mod.rs"]
mod common;

use std::collections::BTreeMap;

/// Everything counted for one program name.
///
/// `rows_all_unguarded` is the set a guard on this program must leave alone,
/// so a replay showing one of them moved is the veto failing rather than the
/// guard working; `rows_mixed` holds a guarded and a guard-free occurrence on
/// the same line, which is why a row can move while still containing a
/// vetoed spelling.
#[derive(Default)]
struct Counts {
    occurrences: usize,
    rows_with: usize,
    recognised: usize,
    guarded: usize,
    rows_all_unguarded: usize,
    rows_mixed: usize,
    flags: BTreeMap<String, usize>,
    operands: BTreeMap<&'static str, usize>,
    arity: BTreeMap<usize, usize>,
}

/// What an operand is, without saying what it says.
fn operand_class(tok: &str) -> &'static str {
    if tok.starts_with("$(") || tok.starts_with('`') {
        "a command substitution"
    } else if tok.starts_with('$') || tok.contains("${") {
        "a variable"
    } else if tok.parse::<i64>().is_ok() {
        "a literal number"
    } else if tok.starts_with('-') {
        "a leading-dash token"
    } else {
        "a literal word"
    }
}

/// A flag's name with any attached value removed — an attached spelling
/// prints as its flag alone, so a path can never ride along in the report.
fn flag_name(tok: &str) -> String {
    let cut = tok.split_once('=').map(|(k, _)| k).unwrap_or(tok);
    cut.chars().take(24).collect()
}

fn main() {
    let wanted: Vec<String> = std::env::args()
        .skip(1)
        .map(|a| a.to_ascii_lowercase())
        .collect();
    if wanted.is_empty() {
        eprintln!("usage: cargo run --release --example count_head_shapes -- <name> [<name>…]");
        std::process::exit(1);
    }

    let rows = common::rows_for_measurement();
    let kb = vouch::guards::in_effect();
    let scanner = vouch::syntax::scanner_for("bash").expect("bash scanner exists");

    // One pass over the corpus however many names were asked about. Scanning
    // per name re-parsed all 20,194 rows each time — measured at ~0.39s per
    // extra name — and the scan does not depend on the name at all.
    let mut tally: BTreeMap<&String, Counts> = wanted.iter().map(|n| (n, Counts::default())).collect();
    for row in &rows {
        let Ok(scan) = scanner.scan(&row.cmd) else { continue };
        // Per-row, per-name: how many occurrences and how many were guarded,
        // so a row can be classed as all-clear or mixed once at the end.
        let mut per_row: BTreeMap<&String, (usize, usize)> = BTreeMap::new();
        for (ci, cmd) in scan.commands.iter().enumerate() {
            let eligible = common::top_level_eligible(&scan, ci);
            let head = vouch::guards::base_name(&cmd.head);
            let Some((name, c)) = tally.iter_mut().find(|(n, _)| ***n == head) else {
                continue;
            };
            c.occurrences += 1;
            let entry = per_row.entry(name).or_insert((0, 0));
            entry.0 += 1;
            if !vouch::guards::check(kb, cmd).is_empty() {
                c.guarded += 1;
                entry.1 += 1;
            }
            if vouch::guards::recognises(kb, cmd, "bash", eligible) {
                c.recognised += 1;
            }
            *c.arity.entry(cmd.args.len()).or_default() += 1;
            for a in &cmd.args {
                if a.starts_with('-') && a.len() > 1 {
                    *c.flags.entry(flag_name(a)).or_default() += 1;
                } else {
                    *c.operands.entry(operand_class(a)).or_default() += 1;
                }
            }
        }
        for (name, (in_row, guarded_in_row)) in per_row {
            let c = tally.get_mut(name).expect("seeded above");
            c.rows_with += 1;
            if guarded_in_row == 0 {
                c.rows_all_unguarded += 1;
            } else if guarded_in_row < in_row {
                c.rows_mixed += 1;
            }
        }
    }

    for name in &wanted {
        let Counts {
            occurrences,
            rows_with,
            recognised,
            guarded,
            rows_all_unguarded,
            rows_mixed,
            flags,
            operands,
            arity,
        } = tally.remove(name).expect("seeded above");

        println!("=== {name} ===");
        println!("  occurrences: {occurrences} across {rows_with} rows");
        println!("  of those occurrences, recognised today: {recognised}");
        println!("  of those occurrences, tripping a guard: {guarded}");
        println!("  rows where EVERY occurrence is guard-free: {rows_all_unguarded}");
        println!("  rows mixing a guarded and a guard-free occurrence: {rows_mixed}");
        let mut fs: Vec<_> = flags.iter().collect();
        fs.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        println!("  flag tokens ({} distinct):", fs.len());
        for (f, c) in fs {
            println!("    {c:>5}  {f}");
        }
        let mut os: Vec<_> = operands.iter().collect();
        os.sort_by(|a, b| b.1.cmp(a.1));
        println!("  operand classes:");
        for (o, c) in os {
            println!("    {c:>5}  {o}");
        }
        let mut ar: Vec<_> = arity.iter().collect();
        ar.sort();
        println!("  argument count per occurrence:");
        for (n, c) in ar {
            println!("    {c:>5}  {n} argument(s)");
        }
        println!();
    }
}
