//! Measurement for M2.82, run BEFORE the change and again AFTER it (§6.2):
//! heredoc-carrying rows, the fed mark's ceiling (rows meeting the M2.82
//! design's decision-3 conditions), the mark's residue (consumed rows the
//! argument-shape condition refuses — the kept-false-ask cost the spec
//! states), and their decisions — under the standing replay config and the
//! live-shaped variant, reported separately (§6.6: two settings are two
//! measurements, never one before/after pair).
//!
//! SCOPE: walks TOP-LEVEL heredocs only. A nested consumed heredoc (inside
//! a `-c` snippet) can also move and is outside this ceiling; the
//! reconstruction replay catches all movement row-by-row.
//!
//! The setting is mutated on the LOADED config rather than appended as TOML
//! text, exactly as the `dump_decisions_python_asks` example does and for the
//! same duplicate-key reason.
//!
//! Run: cargo run --release --example measure_heredoc_fed_rows_and_their_decisions

#[path = "../tests/common/mod.rs"]
mod common;

fn main() {
    let rows = common::rows_for_measurement();
    let kb = vouch::guards::in_effect();
    let standing = common::realistic_config();
    let live_shaped = common::realistic_config_with_construct(
        "python",
        "evaluated_input",
        vouch::config::Action::Ask,
    );
    let shell_visible = common::realistic_config_with_construct(
        "bash",
        "evaluated_input",
        vouch::config::Action::Ask,
    );

    let scanner = vouch::syntax::scanner_for("bash").expect("bash scanner exists");
    let mut with_heredoc = 0usize;
    let mut any_consumed_rows = 0usize;
    let mut residue_rows = 0usize; // consumed, but the judgement refuses
    let mut fed = Vec::new(); // rows where the judgement HOLDS some occurrence
    for (i, row) in rows.iter().enumerate() {
        let Ok(scan) = scanner.scan(&row.cmd) else { continue };
        if scan.heredocs.is_empty() {
            continue;
        }
        with_heredoc += 1;
        let any_consumed = scan.commands.iter().enumerate().any(|(ci, cmd)| {
            scan.heredocs
                .iter()
                .filter(|h| h.cmd_index == ci)
                .any(|h| vouch::guards::heredoc_feeds(kb, cmd, h).is_some())
        });
        // The REAL judgement, through the real threading — not a re-derived
        // partial predicate. Before the input source existed, the pre-code
        // measurement could only express two of the five rules and was blind to
        // descriptors, competing redirects, argument-position substitutions and
        // the scanner-backed/scope checks; this reads what actually decides.
        let held = vouch::guards::expand_wrappers_with_sources(
            kb,
            &scan.commands,
            &scan.heredocs,
            &scan.input_source,
            &scan.args_complete,
            "bash",
            &|_| 4,
        )
        .holds_input
        .iter()
        .any(|h| *h);
        if any_consumed {
            any_consumed_rows += 1;
        }
        if held {
            fed.push(i);
        } else if any_consumed {
            residue_rows += 1;
        }
    }
    for (name, cfg) in [
        ("standing (python evaluated_input=allow)", &standing),
        ("live-shaped (python evaluated_input=ask)", &live_shaped),
        ("shell-visible (bash evaluated_input=ask)", &shell_visible),
    ] {
        let (mut allow, mut ask, mut deny, mut ask_eval) = (0, 0, 0, 0);
        for &i in &fed {
            match vouch::engine::decide_command_in(cfg, "bash", &rows[i].cmd, Some("C:/Users/dev"), None)
            {
                vouch::protocol::Decision::Allow(_) => allow += 1,
                vouch::protocol::Decision::Ask(r) => {
                    ask += 1;
                    if r.contains("evaluated_input") {
                        ask_eval += 1;
                    }
                }
                vouch::protocol::Decision::Deny(_) => deny += 1,
                vouch::protocol::Decision::Abstain => {}
            }
        }
        println!("--- rows whose input is HELD, decided under {name} ---");
        println!("  rows with a captured heredoc: {with_heredoc}");
        println!("  rows with >=1 consumed heredoc: {any_consumed_rows}");
        println!("  held by the real judgement (all five rules): {}", fed.len());
        println!("  residue (consumed but not held — kept asks): {residue_rows}");
        println!("  ALLOW {allow} / ASK {ask} (reason names evaluated_input: {ask_eval}) / DENY {deny}");
    }
}
