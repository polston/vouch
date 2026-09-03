//! How far the restriction clause's stand-down reaches on real traffic
//! (design `2026-09-02-cd-position-and-grants` §3.3a, operator decision
//! 2026-09-03).
//!
//! §4.3 says "a restriction applies if ANY candidate is inside", which also
//! says it does NOT apply when every candidate is proven outside. The standing
//! replay config writes no run-place zone and no `[[run.guards]]` entry, so a
//! replay under it reports zero movement for this clause — a fact about the
//! CONFIG, not about the change. Reporting that zero on its own would be a
//! clean result nobody measured (CLAUDE.md §6.6).
//!
//! So this measures the clause where it can bite: under HYPOTHETICAL configs
//! that DO write a zone and a tightening entry, how many real rows land in the
//! class that newly stands down — every candidate proven, none of them under
//! the tree — versus the classes that still restrict.
//!
//! The two hypothetical configs are labelled as such in the output. Neither
//! describes any machine; they exist so the permissive direction has a number
//! rather than an argument.
//!
//! Every predicate runs through vouch's own scanner, shipped knowledge, and
//! the real decision engine, at one fixed directory (M2.231: a replay with no
//! cwd is blind to every directory-placement rule). No corpus text, path,
//! command, or destination is printed — aggregate counts only (CLAUDE.md §6).
//!
//! Run: `cargo run --release --example count_run_place_restriction_reach`

#[path = "../tests/common/mod.rs"]
mod common;

/// A tree the fixed replay directory is NOT under, so every row's candidates
/// are outside it unless the row's own `cd` walks in. This is the shape that
/// exercises the stand-down.
const ELSEWHERE_TREE: &str = "D:/inbox/**";

/// A tree the fixed replay directory IS under, so every row's candidates are
/// inside it. The control: the restriction must still apply everywhere here.
const COVERING_TREE: &str = "C:/Users/**";

fn zone_cfg(tree: &str) -> vouch::config::Config {
    common::realistic_config_with(&format!("[run]\ntrust_nothing_under = [\"{tree}\"]\n"))
}

fn tightening_cfg(tree: &str) -> vouch::config::Config {
    common::realistic_config_with(&format!(
        "[[run.guards]]\nunder = [\"{tree}\"]\ndelete_recursive = \"deny\"\n"
    ))
}

/// What one config did to every row, and — for the rows it restricted that the
/// bare config did not — WHY, split by the only two reasons a run-place rule
/// can restrict a row whose tree covers nothing it runs under.
#[derive(Default)]
struct Tally {
    allow: usize,
    ask: usize,
    deny: usize,
    /// Restricted here, not under the bare config, and the prompt says vouch
    /// could not place the command. This is the fail-closed residue: an
    /// unprovable candidate might be standing in the tree, so doubt narrows.
    held_unprovable: usize,
    /// Restricted here, not under the bare config, and the prompt does NOT say
    /// the place was unprovable — a restriction reaching a row whose every
    /// candidate is proven and outside. Under §3.3a this must be zero for a
    /// tree the rows are not under; anything else is the clause misapplied.
    held_placed: usize,
}

fn tally(cfg: &vouch::config::Config, rows: &[common::Row], bare: &[String]) -> Tally {
    let mut t = Tally::default();
    for (row, was) in rows.iter().zip(bare) {
        let (verdict, reason) = common::decision_at(cfg, &row.cmd, common::HOOK_HOME);
        match verdict.as_str() {
            "allow" => t.allow += 1,
            "ask" => t.ask += 1,
            "deny" => t.deny += 1,
            _ => {}
        }
        // Stricter here than it was with no run-place entry written.
        let restricted = matches!((was.as_str(), verdict.as_str()), ("allow", "ask" | "deny") | ("ask", "deny"));
        if restricted {
            if reason.contains("cannot prove where this command runs") {
                t.held_unprovable += 1;
            } else {
                t.held_placed += 1;
            }
        }
    }
    t
}

fn report(label: &str, note: &str, t: &Tally) {
    println!("--- HYPOTHETICAL: {label} ---");
    println!("  ({note})");
    println!("  allow {} / ask {} / deny {}", t.allow, t.ask, t.deny);
    println!("  restricted beyond the bare config: {}", t.held_unprovable + t.held_placed);
    println!("    … because a candidate could not be placed: {}", t.held_unprovable);
    println!("    … with every candidate proven and outside: {}", t.held_placed);
    println!();
}

fn main() {
    let rows = common::rows_for_measurement();
    println!("parsed rows: {}", rows.len());
    println!("fixed replay directory: the standard hook home fixture");
    println!();

    // The baseline every hypothetical is read against: no run-place entry at
    // all, which is what the standing config and every live config write.
    let base = common::realistic_config();
    let bare: Vec<String> = rows
        .iter()
        .map(|row| common::decision_at(&base, &row.cmd, common::HOOK_HOME).0)
        .collect();
    let b = tally(&base, &rows, &bare);
    println!("--- no run-place entry (the standing config, and every live one) ---");
    println!("  allow {} / ask {} / deny {}", b.allow, b.ask, b.deny);
    println!();

    // One table, so a fifth case cannot be added to three of four places.
    let cases: [(fn(&str) -> vouch::config::Config, &str, &str, &str); 4] = [
        (
            zone_cfg,
            ELSEWHERE_TREE,
            "a distrust zone over a tree the rows are not under",
            "the stand-down case",
        ),
        (
            zone_cfg,
            COVERING_TREE,
            "a distrust zone over a tree the rows ARE under",
            "the control: a restriction covering every candidate still applies",
        ),
        (
            tightening_cfg,
            ELSEWHERE_TREE,
            "a tightening [[run.guards]] over a tree the rows are not under",
            "the stand-down case, one guard",
        ),
        (
            tightening_cfg,
            COVERING_TREE,
            "the same entry over a tree the rows ARE under",
            "the control",
        ),
    ];
    for (build, tree, label, note) in cases {
        report(label, note, &tally(&build(tree), &rows, &bare));
    }

    println!("How to read this. The number that decides whether §3.3a is");
    println!("implemented correctly is the LAST line of each ELSEWHERE block:");
    println!("rows restricted with every candidate proven and outside. It must");
    println!("be zero — a rule whose tree covers nothing the row runs under has");
    println!("nothing to say about it. The line above it is the fail-closed");
    println!("residue and is expected to be nonzero: a candidate vouch cannot");
    println!("place might be standing in the tree, so the restriction applies");
    println!("exactly as it did before. The COVERING blocks are the controls —");
    println!("a restriction that covers the rows must still reach them.");
}
