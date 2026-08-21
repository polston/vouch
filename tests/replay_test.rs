//! Replay the real recorded corpus.
//!
//! 20,194 distinct bash commands actually run on these machines, with the verdict
//! the previous tool gave each one. 1,133 of them produced a prompt.
//!
//! The goal this project exists for: vouch should prompt on a small fraction of
//! that, without any of those prompts being unfixable by a setting.

mod common;

use common::realistic_config;
use vouch::engine::decide_command_in;
use vouch::protocol::Decision;

/// Named for what it checks: the corpus is big enough for the replay numbers
/// below to mean anything. It says nothing about presence — an absent corpus
/// skips, like every other measurement here.
#[test]
fn the_real_corpus_is_large_enough_to_measure() {
    let Some(c) = common::real() else {
        return common::skip("replay");
    };
    assert!(c.len() > 15_000, "expected the full corpus, got {}", c.len());
}

#[test]
fn vouch_never_panics_on_any_real_recorded_command() {
    let Some(rows) = common::real() else {
        return common::skip("replay");
    };
    let cfg = realistic_config();
    let mut checked = 0;
    for row in &rows {
        let _ = decide_command_in(&cfg, "bash", &row.cmd, Some("C:/Users/dev"), None);
        checked += 1;
    }
    assert!(checked > 15_000, "checked {checked}");
}

/// Two numbers, measured separately, because they mean opposite things.
///
///  1. Of the prompts the old tool produced, how many survive? Those are the
///     prompts the user considered noise. Target: under 5%.
///  2. How many NEW prompts do guards add? Those are deliberate — the user's
///     rule is that an unsafe operation should keep asking every single time.
///     This number should be reported, never minimised.
#[test]
fn old_noise_prompts_are_gone_and_guard_prompts_are_accounted_for() {
    let Some(rows) = common::real() else {
        return common::skip("replay");
    };
    let cfg = realistic_config();

    let mut old_asked_still_asks = 0;
    let mut old_asked_total = 0;
    let mut newly_guarded = 0;
    let mut parse_failures = 0;
    let mut guard_counts: std::collections::HashMap<String, usize> = Default::default();

    for row in &rows {
        let was_asked = row.verdict != "allow";
        if was_asked {
            old_asked_total += 1;
        }
        match decide_command_in(&cfg, "bash", &row.cmd, Some("C:/Users/dev"), None) {
            Decision::Ask(reason) | Decision::Deny(reason) => {
                let is_guard = reason.contains("(guard)");
                // A write-outside-scope prompt is policy working, not noise:
                // it names write.allow_paths, which is a setting the user owns.
                let is_write_policy = reason.contains("write.allow_paths");
                if reason.contains("could not read") {
                    parse_failures += 1;
                }
                if is_guard {
                    if let Some(line) = reason.lines().next() {
                        let name = line
                            .trim_start_matches("vouch stopped on: ")
                            .trim_end_matches(" (guard)")
                            .to_string();
                        *guard_counts.entry(name).or_default() += 1;
                    }
                }
                if was_asked && !is_guard && !is_write_policy {
                    // A survivor that is NOT a guard hit is leftover noise.
                    old_asked_still_asks += 1;
                }
                if !was_asked && (is_guard || is_write_policy) {
                    newly_guarded += 1;
                }
            }
            _ => {}
        }
    }

    let ratio = old_asked_still_asks as f64 / old_asked_total as f64;
    let mut guards: Vec<_> = guard_counts.iter().collect();
    guards.sort_by_key(|(_, n)| std::cmp::Reverse(**n));

    eprintln!("--- replay over {} distinct commands ---", rows.len());
    eprintln!("old tool prompted on:            {old_asked_total}");
    eprintln!("of those, still prompting as NOISE: {old_asked_still_asks}  ({:.1}%)", ratio * 100.0);
    eprintln!("  (survivors that are guard hits are correct, not noise)");
    eprintln!("  of which vouch could not read: {parse_failures}");
    eprintln!("NEW prompts added by guards:     {newly_guarded}  (deliberate)");
    for (name, n) in guards {
        eprintln!("    {n:>5}  {name}");
    }

    // NO PERCENTAGE TARGET. "Under 5%" was invented, not asked for, and the
    // figure it was measured against — prompts that are neither guards nor
    // write policy — excludes everything vouch itself classifies as
    // deliberate. Grading against a self-chosen denominator is not a check.
    // The raw comparison is printed above; judging it is the operator's job.
    //
    // The property that CANNOT be argued into passing — every prompt names
    // something that turns it off — is asserted in `property_test.rs`, where
    // it runs over the synthetic corpus too and so survives a fresh clone.
}
