//! Pre-build measurements for the place-scoped-rules changeset (spec
//! 2026-08-06 §Measurement plan). Three tests, two of them gated on the real
//! corpus — see `common::skip` — because a measurement over invented commands
//! is a fabricated measurement (CLAUDE.md §6.6).
//!
//! The ungated one is not a measurement: it pins what the counting diagnostic
//! the first measurement calls actually counts, on fixed lines, so a reader of
//! that number cannot take it for a different one.
//!
//! The per-row replay baseline that used to live here is now
//! `examples/dump_per_row_verdicts.rs` — an on-demand measurement, which no gate
//! runs (M2.103).

mod common;

/// What `count_unknown_run_place_commands` COUNTS, pinned on three fixed
/// lines so the number the measurement below reports cannot be read as
/// something it is not. Structural, so no corpus and no skip.
///
/// The counted unit is a command POSITION whose run place is Unknown, never a
/// directory change: a single unplaceable one marks every position in the line
/// Unknown (`CdTimeline.unplaceable`), which is why `cd a || cd b; echo x`
/// counts 3 and not 1 — the count is "positions a restrict-shaped place rule
/// would treat as possibly-inside", which is exactly the noise being sized.
/// Reading it as "lines containing an unplaceable cd" would make the reported
/// figure look ~3x too large and invite a "fix" that measured nothing.
///
/// The two zeroes are the other half of the claim: no cwd is supplied here, so
/// a line with no directory change at all is NoDirectory (0, not Unknown), and
/// a directory change vouch CAN order and resolve leaves nothing unknown
/// either.
#[test]
fn the_unknown_run_place_count_is_per_command_position() {
    use vouch::engine::count_unknown_run_place_commands as count;
    assert_eq!(
        count("bash", "cd a || cd b; echo x"),
        3,
        "one unplaceable directory change marks every position in the line"
    );
    assert_eq!(count("bash", "echo x"), 0, "no directory change is NoDirectory, not Unknown");
    assert_eq!(count("bash", "cd C:/x && echo hi"), 0, "an ordered, resolvable cd is placeable");
}

/// Spec §Measurement plan item 2a: rows with any Unknown run place — the
/// noise floor every restrict-shaped place rule inherits.
#[test]
fn count_rows_with_an_unknown_run_place() {
    let Some(rows) = common::real() else {
        return common::skip("place-measurement");
    };
    let n = rows
        .iter()
        .filter(|r| vouch::engine::count_unknown_run_place_commands("bash", &r.cmd) > 0)
        .count();
    eprintln!("MEASURE unknown-run-place rows: {n} of {}", rows.len());
}

/// Spec §Measurement plan item 2b: wrapper-spelled heads that the M2.46
/// absorption makes newly recognition-checked. Counted with vouch's own
/// parser (§6.1). NOTE (decided at review): this count lives HERE and only
/// here — the corpus REPLAY runs with unmodeled_command = "allow"
/// (common::realistic_config), so wrapper rows do not move there and this
/// number must never be "reconciled" against replay output.
#[test]
fn count_rows_with_wrapper_hidden_unknown_heads() {
    let Some(rows) = common::real() else {
        return common::skip("place-measurement");
    };
    let kb = vouch::guards::in_effect();
    let scanner = vouch::syntax::scanner_for("bash").unwrap();
    let mut newly = 0usize;
    for r in &rows {
        let Ok(scan) = scanner.scan(&r.cmd) else {
            continue;
        };
        // `standalone_eligible = true` for both slices, by the plan's stated
        // decision (spec 2026-08-20 §2.4): this is a MEASUREMENT of how many
        // rows hide an unknown head inside a wrapper, and treating a rare
        // incomplete-record row as standalone-eligible errs toward counting
        // fewer such rows here rather than toward a permissive gate.
        let top = vouch::guards::unmodeled_descriptions(kb, &scan.commands, "bash", true);
        let expanded = vouch::guards::expand_wrappers(kb, &scan.commands, "bash");
        let all = vouch::guards::unmodeled_descriptions(kb, &expanded, "bash", true);
        if all.len() > top.len() {
            newly += 1;
        }
    }
    eprintln!("MEASURE wrapper-hidden unknown-head rows: {newly} of {}", rows.len());
}

