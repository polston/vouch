//! On-demand measurement: which commands the bash parser cannot read, and why.
//!
//! Standard output carries the AGGREGATE only — one `<count>  <kind>` line per
//! parse-failure kind, plus a total. Every single-quoted payload inside a kind's
//! text is elided before it is printed, because three of the parser's error
//! variants interpolate a fragment of the INPUT between single quotes
//! (`failed to parse word '<word>'`, and the parameter and brace-expansion
//! forms). The kind is the useful part; the fragment is corpus text, and it
//! would otherwise reach a terminal and a transcript by way of a line that
//! looks like a category name.
//!
//! The command SAMPLES, and the unelided kind text beside them, go only to the
//! file named by `VOUCH_DUMP_PARSE_SAMPLES`. With that variable unset, one line
//! says they were omitted and how to collect them, and no file is written: the
//! samples are real recorded commands, so printing them unconditionally makes
//! every run of an aggregate a disclosure of the corpus. The path is named by
//! its VARIABLE and never by its value — a resolved value is an absolute path
//! from a real machine, and it also keeps standard output the same whichever
//! destination was chosen.
//!
//! The grouping is ordered, which is the other change from the test this
//! replaces. That one grouped into a `HashMap` and sorted by descending count
//! with a stable sort, so tied kinds came out in hash iteration order — random
//! per process, and two runs of the same corpus could not be diffed. Here the
//! map is a `BTreeMap` and the sort key is `(Reverse(count), kind text)`, so the
//! order is fully determined by the data and two consecutive runs are
//! byte-identical.
//!
//! Not a test: it asserts nothing and no gate runs it. `cargo test` compiles it
//! on every whole-suite run, so it cannot rot unnoticed between the day it is
//! written and the day a number is wanted.
//!
//! Run: `cargo run --release --example dump_parse_failures`
//!
//! With samples: `VOUCH_DUMP_PARSE_SAMPLES=<absolute path> cargo run --release --example dump_parse_failures`
//!
//! Pass an ABSOLUTE destination. A relative one resolves against the invocation
//! directory rather than the package root, and the conventional dump patterns in
//! `.gitignore` only cover `tests/fixtures/`, so a relative path can put
//! corpus-derived output at an untracked-but-unignored place inside the tree.

#[path = "../tests/common/mod.rs"]
mod common;

use std::collections::BTreeMap;

/// The variable naming the file the samples are written to. Unset means the
/// samples are not collected at all.
const SAMPLES_VAR: &str = "VOUCH_DUMP_PARSE_SAMPLES";

/// How many failure kinds are reported, and how many samples each one keeps.
const MAX_KINDS: usize = 15;
const MAX_SAMPLES: usize = 2;

/// A sample is cut to this many characters, so one long command cannot fill the
/// file on its own.
const SAMPLE_CHARS: usize = 200;

/// Replace the contents of every single-quoted span with one ellipsis, so
/// `failed to parse word 'something'` reads `failed to parse word '…'`.
///
/// An UNTERMINATED quote elides to the end of the text rather than passing the
/// remainder through. A payload is the reason this function exists, and the case
/// where the closing quote is missing is exactly the case where the payload
/// itself contained a quote — so the permissive reading is the one that leaks.
fn elide_quoted(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(open) = rest.find('\'') {
        out.push_str(&rest[..open]);
        out.push('\'');
        out.push('…');
        match rest[open + 1..].find('\'') {
            Some(close) => {
                out.push('\'');
                rest = &rest[open + 1 + close + 1..];
            }
            // No closing quote: everything after the opener is payload.
            None => return out,
        }
    }
    out.push_str(rest);
    out
}

fn main() {
    if let Some(dest) = std::env::var_os(SAMPLES_VAR) {
        let p = std::path::PathBuf::from(&dest);
        if !p.is_absolute() {
            eprintln!("{SAMPLES_VAR} must be an absolute path");
            std::process::exit(1);
        }
        let mut probe = p.as_path();
        let canon = loop {
            match probe.canonicalize() {
                Ok(c) => break Some(c),
                Err(_) => match probe.parent() {
                    Some(par) => probe = par,
                    None => break None,
                },
            }
        };
        let mut anc = canon.as_deref();
        while let Some(d) = anc {
            if d.join(".git").exists() {
                eprintln!("{SAMPLES_VAR} must not resolve inside a git worktree");
                std::process::exit(1);
            }
            anc = d.parent();
        }
    }

    let rows = common::rows_for_measurement();

    // A `BTreeMap`, not a `HashMap`: the iteration order is the tie-break the
    // sort below falls through to, and a hashed order is randomised per process.
    let mut by_err: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for r in &rows {
        // `shell::parse` already reduces the parser's error to its first line,
        // so this string IS the grouping key the replaced test used.
        if let Err(e) = vouch::shell::parse(&r.cmd) {
            by_err.entry(e).or_default().push(r.cmd.clone());
        }
    }

    // Descending by count, then by the kind's own text. Two kinds with the same
    // count are ordered by something in the data rather than by where the map
    // happened to put them.
    let mut kinds: Vec<(&String, &Vec<String>)> = by_err.iter().collect();
    kinds.sort_by_key(|(err, cmds)| (std::cmp::Reverse(cmds.len()), *err));

    // Built whether or not it will be written, so the two halves cannot drift:
    // the stdout line and the file line are formatted from the same count in the
    // same pass, differing only in the elision and the samples.
    let mut samples = format!(
        "Real recorded commands from {}. Not for a repository, a terminal or a \
         transcript.\n",
        common::REAL
    );

    println!("=== parse failure kinds ===");
    for (err, cmds) in kinds.iter().take(MAX_KINDS) {
        println!("\n{:>4}  {}", cmds.len(), elide_quoted(err));
        samples.push_str(&format!("\n{:>4}  {}\n", cmds.len(), err));
        for c in cmds.iter().take(MAX_SAMPLES) {
            let one: String = c.chars().take(SAMPLE_CHARS).collect();
            samples.push_str(&format!("      | {}\n", one.replace('\n', "\\n")));
        }
    }
    println!(
        "\ntotal failures: {} of {}",
        by_err.values().map(|v| v.len()).sum::<usize>(),
        rows.len()
    );

    // Written even when nothing failed to parse. An unwritten file would leave
    // the PREVIOUS run's samples in place, and a reader diffing against them
    // would see zero movement no matter what changed — the M2.81 defect.
    match std::env::var_os(SAMPLES_VAR) {
        Some(path) => {
            if let Err(e) = std::fs::write(&path, &samples) {
                // Names the variable, never its value.
                eprintln!("could not write the file named by {SAMPLES_VAR}: {e}");
                std::process::exit(1);
            }
            println!("wrote the samples to the path named by {SAMPLES_VAR}");
        }
        None => println!(
            "samples omitted: they are real recorded commands. Set \
             {SAMPLES_VAR}=<absolute path> to collect them into a file."
        ),
    }
}
