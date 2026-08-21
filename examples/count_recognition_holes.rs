//! On-demand measurement for the two recognition holes at the top of the
//! queue, run BEFORE the change and again AFTER it (§6.2):
//!
//! 1. **The builtin hole (M2.16).** The shipped shell-builtin entry is
//!    hand-written and has holes — `read` is absent, so `… | while read -r f`
//!    asks with "no description of: read". This counts every bash builtin that
//!    appears as a command head in the corpus and that recognition does NOT
//!    cover, so the whole list is measured at once rather than patched a name
//!    at a time as each surfaces.
//!
//! 2. **The flags-only hole (M2.19).** An entry scoped to subcommands can only
//!    match when a verb token was found, so `cargo --version` falls through to
//!    "no description of: cargo". This counts the heads where some bash entry
//!    NAMES the program, recognition says no, and the argument walk found no
//!    verb — the exact shape, not a proxy for it.
//!
//! Both are toward-ALLOW changes, which is why the count comes first: §6.2
//! wants the ceiling before the code exists, and the same run afterwards is
//! the replay.
//!
//! **Two configs, reported separately (§6.6).** The standing replay config
//! sets `unmodeled_command = "allow"` on purpose, so that a replay measures
//! vouch's own defects rather than an unset policy — but that allow hides the
//! entire effect of RECOGNISING something, because an undescribed head already
//! allowed. The operator's live config sets it to `"ask"` (checked, not
//! assumed), so the live-shaped column is the one that says how many prompts a
//! fix removes. Neither is a before/after pair with the other.
//!
//! **Scope, and it bounds the flags-only number hard.** `.cargo/config.toml`
//! pins every measurement to THIS repository's `knowledge.toml`, so the
//! operator's own `my-knowledge.toml` entries are invisible here. The
//! flags-only shape bites hardest on programs an operator described
//! themselves — `cargo` is not in the shipped file at all — so a zero below
//! means "no SHIPPED subcommand-scoped entry is run flags-only in this
//! corpus", never "this shape does not happen". The count of shipped entries
//! that could exhibit it at all is printed beside the result, because a zero
//! out of zero candidates and a zero out of many are different findings.
//!
//! The builtin list is read from the shell at RUN time (`compgen -b`) rather
//! than embedded here. An embedded list is a second claim to keep true, and
//! this measurement exists precisely because the hand-maintained one drifted.
//!
//! Reported per head: the number of corpus ROWS the head appears in, and how
//! those rows are decided TODAY. A row is counted once per head however many
//! times the head occurs in it, because the row is the unit a verdict moves.
//!
//! Run: cargo run --release --example count_recognition_holes

#[path = "../tests/common/mod.rs"]
mod common;

use std::collections::{BTreeMap, BTreeSet};

/// Rows a head appears in, split by how the WHOLE row is decided today.
#[derive(Default)]
struct Tally {
    rows: usize,
    allow: usize,
    ask: usize,
    deny: usize,
}

impl Tally {
    fn add(&mut self, decision: &vouch::protocol::Decision) {
        self.rows += 1;
        match decision {
            vouch::protocol::Decision::Allow(_) => self.allow += 1,
            vouch::protocol::Decision::Ask(_) => self.ask += 1,
            vouch::protocol::Decision::Deny(_) => self.deny += 1,
            vouch::protocol::Decision::Abstain => {}
        }
    }
}

/// The shell's own builtin list, asked of the shell rather than remembered.
///
/// `VOUCH_BASH` names which bash to ask, because a bare `bash` does not mean
/// one thing on Windows: the PATH this process inherits resolves it to the
/// WSL launcher in System32, which exits 1 with no distro installed, while the
/// Git Bash that runs the repo's scripts is somewhere else entirely. Guessing
/// between them would make the measurement's own input depend on who started
/// it, so the failure names the variable instead.
fn builtins() -> BTreeSet<String> {
    let shell = std::env::var("VOUCH_BASH").unwrap_or_else(|_| "bash".to_string());
    let out = std::process::Command::new(&shell)
        .args(["-c", "compgen -b"])
        .output()
        .unwrap_or_else(|e| {
            eprintln!("cannot run `{shell}`: {e}");
            eprintln!("set VOUCH_BASH to the bash that owns this machine's builtin list");
            std::process::exit(1);
        });
    if !out.status.success() {
        eprintln!("`{shell} -c 'compgen -b'` failed: {}", out.status);
        eprintln!("its stderr: {}", String::from_utf8_lossy(&out.stderr).trim());
        eprintln!(
            "on Windows a bare `bash` is usually the WSL launcher, not Git Bash — \
             set VOUCH_BASH to the real one (e.g. C:/Program Files/Git/bin/bash.exe)"
        );
        eprintln!("this measurement is ABOUT that list, so there is no honest fallback");
        std::process::exit(1);
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| l.trim().to_ascii_lowercase())
        .filter(|l| !l.is_empty())
        .collect()
}

/// True when at least one bash entry carries this name — the same predicate
/// `entries_for` uses, so "vouch has never heard of it" and "every entry for
/// it is scoped elsewhere" stay distinguishable.
fn named_by_an_entry(kb: &vouch::guards::Knowledge, head: &str) -> bool {
    let h = vouch::guards::base_name(head);
    kb.program.iter().any(|p| {
        p.match_names.iter().any(|n| n.to_ascii_lowercase() == h)
            && (p.languages.is_empty() || p.languages.iter().any(|l| l == "bash"))
    })
}

fn report(title: &str, note: &str, tallies: &BTreeMap<String, Tally>) {
    let mut ordered: Vec<_> = tallies.iter().collect();
    ordered.sort_by(|a, b| b.1.rows.cmp(&a.1.rows).then(a.0.cmp(b.0)));
    let rows: usize = ordered.iter().map(|(_, t)| t.rows).sum();
    let ask: usize = ordered.iter().map(|(_, t)| t.ask).sum();
    println!("--- {title} ---");
    println!("  {note}");
    println!("  distinct heads: {}", ordered.len());
    println!("  head/row pairs: {rows} (a row counts once per head)");
    println!("  of those pairs, the row asks today: {ask}");
    for (head, t) in ordered {
        println!(
            "    {head:<20} rows {:<6} ALLOW {:<6} ASK {:<6} DENY {}",
            t.rows, t.allow, t.ask, t.deny
        );
    }
}

fn main() {
    let rows = common::rows_for_measurement();
    let kb = vouch::guards::in_effect();
    let scanner = vouch::syntax::scanner_for("bash").expect("bash scanner exists");
    let builtins = builtins();

    // The population the flags-only shape could occur in at all. A zero
    // result against zero candidates says nothing about the shape; a zero
    // against many says the corpus does not run them that way.
    let subcommand_scoped: BTreeSet<String> = kb
        .program
        .iter()
        .filter(|p| p.subcommands.as_ref().is_some_and(|s| !s.is_empty()))
        .filter(|p| p.languages.is_empty() || p.languages.iter().any(|l| l == "bash"))
        .flat_map(|p| p.match_names.iter().map(|n| n.to_ascii_lowercase()))
        .collect();

    // Which rows exhibit each shape is a property of the KNOWLEDGE, not of any
    // config — so the shapes are found once, and only the decisions are taken
    // per config.
    let mut builtin_rows: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    let mut flagsonly_rows: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    let mut scanned = 0usize;

    for (i, row) in rows.iter().enumerate() {
        let Ok(scan) = scanner.scan(&row.cmd) else { continue };
        scanned += 1;
        let mut builtin_heads: BTreeSet<String> = BTreeSet::new();
        let mut flagsonly_heads: BTreeSet<String> = BTreeSet::new();
        for (ci, cmd) in scan.commands.iter().enumerate() {
            let eligible = common::top_level_eligible(&scan, ci);
            if vouch::guards::recognises(kb, cmd, "bash", eligible) {
                continue;
            }
            let head = vouch::guards::base_name(&cmd.head);
            if builtins.contains(&head) {
                builtin_heads.insert(head.clone());
            }
            // Named, unrecognised, and the walk found no verb — M2.19's shape.
            // `subcommand_of` is the real extractor, so a value option's VALUE
            // is not mistaken for the missing verb.
            if named_by_an_entry(kb, &cmd.head) && vouch::guards::subcommand_of(kb, cmd).is_none() {
                flagsonly_heads.insert(head);
            }
        }
        for h in builtin_heads {
            builtin_rows.entry(h).or_default().push(i);
        }
        for h in flagsonly_heads {
            flagsonly_rows.entry(h).or_default().push(i);
        }
    }

    println!("corpus rows: {} ({scanned} scanned clean)", rows.len());
    println!("bash builtins, per the shell: {}", builtins.len());
    println!(
        "shipped bash entries scoped to subcommands, by name: {}",
        subcommand_scoped.len()
    );
    println!();

    for (label, cfg) in [
        ("standing replay (bash unmodeled_command=allow)", common::realistic_config()),
        (
            "live-shaped (bash unmodeled_command=ask)",
            common::realistic_config_with_construct(
                "bash",
                "unmodeled_command",
                vouch::config::Action::Ask,
            ),
        ),
    ] {
        let decide = |idx: &Vec<usize>| {
            let mut t = Tally::default();
            for &i in idx {
                t.add(&vouch::engine::decide_command_in(
                    &cfg,
                    "bash",
                    &rows[i].cmd,
                    Some("C:/Users/dev"),
                    None,
                ));
            }
            t
        };
        println!("=== decided under {label} ===");
        report(
            "the builtin hole (M2.16)",
            "bash builtins appearing as a head that recognition does not cover",
            &builtin_rows.iter().map(|(h, i)| (h.clone(), decide(i))).collect(),
        );
        println!();
        report(
            "the flags-only hole (M2.19)",
            "some SHIPPED bash entry names the head, recognition says no, the walk found no verb",
            &flagsonly_rows.iter().map(|(h, i)| (h.clone(), decide(i))).collect(),
        );
        println!();
    }
}
