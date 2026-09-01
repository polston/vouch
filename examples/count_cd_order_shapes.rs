//! SCOPE-AWARE since Task 8 of the plan: a `Seq` order is only comparable
//! within its own scope, so movers split three ways — top-level sequenced,
//! sequenced inside a body scope (subshell, brace, branch, loop: shapes the
//! scanner used to flatten to `Unordered`), and order-unprovable records
//! (or-tail members, which the engine places by their chain since part two) — and
//! the later-relative-redirect and writer-position inferences compare only
//! same-scope positions. The ask buckets follow the Task 7 cause split; the
//! old conditional-cd bucket is gone with its sentence, subsumed by the
//! candidate-set union.
//!
//! On-demand measurement for the cd-scope-and-candidate design (M2.2, M2.6,
//! M2.43, M2.44): how often real commands carry a directory change the walk
//! cannot place today, where those movers sit (subshell, `||` tail,
//! conditional `&&` tail, plain sequence), and how many of today's decisions
//! ask for exactly that reason.
//!
//! Every predicate is evaluated over vouch's own bash scanner, shipped
//! knowledge, and the real decision engine. No corpus text, path, command,
//! session value, or destination is printed — aggregate counts only
//! (CLAUDE.md §6).
//!
//! Run: `cargo run --release --example count_cd_order_shapes`

#[path = "../tests/common/mod.rs"]
mod common;

use vouch::syntax::Order;

fn is_relative(path: &str) -> bool {
    let bytes = path.as_bytes();
    let drive_absolute = bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'/' | b'\\');
    !path.starts_with('/') && !drive_absolute
}

/// A chain member reachable only after an earlier `||` break: nothing before
/// it is certified by its own success or failure.
fn is_or_tail(cp: vouch::syntax::ChainPos) -> bool {
    cp.idx > 0 && cp.and_run_from == cp.idx
}

fn main() {
    let rows = common::rows_for_measurement();
    let kb = common::shipped_kb();
    let bash = vouch::syntax::scanner_for("bash").expect("bash scanner exists");
    let cfg = common::realistic_config();

    let mut parsed_rows = 0usize;
    let mut rows_with_mover = 0usize;
    let mut movers_total = 0usize;
    let mut movers_seq = 0usize;
    let mut movers_unordered = 0usize;
    // A mover the walk cannot place makes the WHOLE line unplaceable today.
    let mut rows_with_unordered_mover = 0usize;
    let mut rows_unordered_mover_and_subshell_note = 0usize;
    let mut rows_unordered_mover_and_background_note = 0usize;
    // `cd A || cd B` shapes: a mover that runs only after a `||` break.
    let mut movers_body_seq = 0usize;
    let mut rows_with_body_mover = 0usize;
    let mut or_tail_movers = 0usize;
    let mut rows_with_or_tail_mover = 0usize;
    // `x && cd d` shapes: a mover whose own run is conditional on an earlier
    // member — the CONDITIONAL_CD pool once anything later sits outside the
    // certified run.
    let mut conditional_and_movers = 0usize;
    // M2.44's pool: an unconditional sequenced mover (assumed to succeed
    // today) with a later relative redirect that depends on its base.
    let mut rows_seq_mover_then_later_relative_redirect = 0usize;
    // Sequenced movers per row, for the candidate-set CAP choice: each
    // failable mover can double the candidate count, so the distribution of
    // movers per row bounds how often a CAP would collapse to unknown.
    let mut rows_by_seq_mover_count = [0usize; 5]; // 1, 2, 3, 4, 5+
    // Decision classes under the standing replay config, one fixed directory.
    let mut decided_allow = 0usize;
    let mut decided_ask = 0usize;
    let mut decided_deny = 0usize;
    let mut asks_unplaceable_cd = 0usize;
    let mut asks_candidate_plural = 0usize;
    let mut asks_stack = 0usize;
    let mut asks_unread_dest = 0usize;
    let mut asks_loop_carry = 0usize;
    let mut asks_unplaced_position = 0usize;
    let mut asks_unresolvable_mover_dest = 0usize;
    // The join that sizes the process-boundary win: the row both carries an
    // unplaceable mover and asks for the unplaceable reason today.
    let mut rows_unordered_mover_asking_unplaceable = 0usize;
    // The other side of the same ask pool: every top-level mover is placed,
    // and what sits at an unprovable position is the WRITER — a command or a
    // relative redirect inside a compound body, pipeline, or `||` tail.
    let mut asks_unplaceable_writer_position = 0usize;
    // Remainder: neither an unplaceable top-level mover nor an unordered
    // top-level writer — the cause lives inside a wrapped snippet.
    let mut asks_unplaceable_other = 0usize;

    for row in &rows {
        let Ok(scan) = bash.scan(&row.cmd) else {
            continue;
        };
        parsed_rows += 1;

        let mut row_movers = 0usize;
        let mut row_seq_movers = 0usize;
        let mut row_unordered_mover = false;
        let mut row_body_mover = false;
        let mut row_or_tail_mover = false;
        let mut first_unconditional_seq_mover: Option<u32> = None;
        for (i, cmd) in scan.commands.iter().enumerate() {
            let Some((kind, _)) = vouch::guards::dir_change_entry_for_cmd(&kb, cmd, "bash")
            else {
                continue;
            };
            if kind == vouch::guards::DirChangeKind::No {
                continue;
            }
            row_movers += 1;
            movers_total += 1;
            let scope_known = matches!(scan.cmd_scope.get(i), Some(Some(_)));
            let top_level = matches!(scan.cmd_scope.get(i), Some(Some(0)));
            match scan.order.get(i) {
                Some(Order::Seq(n)) if top_level => {
                    movers_seq += 1;
                    row_seq_movers += 1;
                    match cmd.chain {
                        Some(cp) if is_or_tail(cp) => {
                            or_tail_movers += 1;
                            row_or_tail_mover = true;
                        }
                        Some(cp) if cp.idx > 0 => conditional_and_movers += 1,
                        _ => {
                            if first_unconditional_seq_mover.is_none() {
                                first_unconditional_seq_mover = Some(*n);
                            }
                        }
                    }
                }
                Some(Order::Seq(_)) if scope_known => {
                    // A body-scoped mover: sequenced within its own scope
                    // (subshell, brace, branch, loop), no longer flattened
                    // to Unordered by the scanner since the scope channel.
                    movers_body_seq += 1;
                    row_body_mover = true;
                }
                _ => {
                    movers_unordered += 1;
                    row_unordered_mover = true;
                    if let Some(cp) = cmd.chain {
                        if is_or_tail(cp) {
                            or_tail_movers += 1;
                            row_or_tail_mover = true;
                        }
                    }
                }
            }
        }
        if row_movers > 0 {
            rows_with_mover += 1;
        }
        if row_seq_movers > 0 {
            rows_by_seq_mover_count[row_seq_movers.min(5) - 1] += 1;
        }
        if row_unordered_mover {
            rows_with_unordered_mover += 1;
            if scan.constructs.iter().any(|c| c == "subshell") {
                rows_unordered_mover_and_subshell_note += 1;
            }
            if scan.constructs.iter().any(|c| c == "background") {
                rows_unordered_mover_and_background_note += 1;
            }
        }
        if row_or_tail_mover {
            rows_with_or_tail_mover += 1;
        }
        if row_body_mover {
            rows_with_body_mover += 1;
        }
        if let Some(mover_n) = first_unconditional_seq_mover {
            let later_relative_redirect = scan
                .redirect_targets
                .iter()
                .zip(scan.redirect_order.iter())
                .zip(scan.redirect_scope.iter())
                .any(|((t, o), sc)| {
                    matches!(sc, Some(0))
                        && matches!(o, Order::Seq(m) if *m > mover_n)
                        && is_relative(t)
                });
            if later_relative_redirect {
                rows_seq_mover_then_later_relative_redirect += 1;
            }
        }

        let (verdict, reason) = common::decision_at(&cfg, &row.cmd, common::HOOK_HOME);
        match verdict.as_str() {
            "allow" => decided_allow += 1,
            "ask" => decided_ask += 1,
            "deny" => decided_deny += 1,
            _ => {}
        }
        if verdict == "ask" {
            if reason.contains(vouch::engine::UNPLACEABLE_CD) {
                asks_unplaceable_cd += 1;
                if row_unordered_mover {
                    rows_unordered_mover_asking_unplaceable += 1;
                } else {
                    // A WRITER, not any command: the unordered-position
                    // occupant must itself carry a relative described write
                    // or a relative redirect, or the bucket overstates the
                    // writer-position share and understates the remainder.
                    let unordered_relative_writer =
                        scan.commands.iter().zip(scan.order.iter()).enumerate().any(|(ci, (c, o))| {
                            (matches!(o, Order::Unordered)
                                || !matches!(scan.cmd_scope.get(ci), Some(Some(0))))
                                && vouch::guards::written_paths_in(&kb, c, "bash")
                                    .paths
                                    .iter()
                                    .any(|p| is_relative(p))
                        });
                    let unordered_relative_redirect = scan
                        .redirect_targets
                        .iter()
                        .zip(scan.redirect_order.iter())
                        .zip(scan.redirect_scope.iter())
                        .any(|((t, o), sc)| {
                            (matches!(o, Order::Unordered) || !matches!(sc, Some(0)))
                                && is_relative(t)
                        });
                    if (unordered_relative_writer || unordered_relative_redirect)
                        && !row_body_mover
                    {
                        asks_unplaceable_writer_position += 1;
                    } else {
                        // Either no unordered writer at all, or a body-scoped
                        // mover on the same row makes the cause undecidable
                        // between the mover and the writer position.
                        asks_unplaceable_other += 1;
                    }
                }
            }
            if reason.contains("more than one possible directory")
                || reason.contains(vouch::engine::TOO_MANY_BASES)
            {
                asks_candidate_plural += 1;
            }
            if reason.contains(vouch::engine::STACK_CD) {
                asks_stack += 1;
            }
            if reason.contains(vouch::engine::UNREAD_DEST_CD) {
                asks_unread_dest += 1;
            }
            if reason.contains(vouch::engine::LOOP_CD) {
                asks_loop_carry += 1;
            }
            if reason.contains(vouch::engine::UNPLACED_POS_CD) {
                asks_unplaced_position += 1;
            }
            if reason.contains("changes directory to somewhere vouch cannot resolve") {
                asks_unresolvable_mover_dest += 1;
            }
        }
    }

    println!("rows: {}", rows.len());
    println!("parsed rows: {parsed_rows}");
    println!("rows with a directory-change command: {rows_with_mover}");
    println!("movers total: {movers_total}");
    println!("  sequenced at the top level: {movers_seq}");
    println!("  sequenced inside a body scope: {movers_body_seq}");
    println!("  with an order-unprovable record: {movers_unordered}");
    println!("rows with an order-unprovable mover record (or-tails, placed by their chain since part two): {rows_with_unordered_mover}");
    println!("  … with a subshell noted on the row: {rows_unordered_mover_and_subshell_note}");
    println!("  … with background noted on the row: {rows_unordered_mover_and_background_note}");
    println!("movers running only after a || break: {or_tail_movers} (rows: {rows_with_or_tail_mover})");
    println!("movers conditional on an earlier && member: {conditional_and_movers}");
    println!("rows with a body-scoped mover: {rows_with_body_mover}");
    println!("asks naming several candidates or the cap: {asks_candidate_plural}");
    println!("asks naming the directory stack: {asks_stack}");
    println!("asks naming an unreadable destination: {asks_unread_dest}");
    println!("asks naming loop carry: {asks_loop_carry}");
    println!("asks naming an unplaceable position: {asks_unplaced_position}");
    println!(
        "rows with an unconditional sequenced mover and a later relative redirect: {rows_seq_mover_then_later_relative_redirect}"
    );
    println!(
        "rows by sequenced-mover count (1 / 2 / 3 / 4 / 5+): {} / {} / {} / {} / {}",
        rows_by_seq_mover_count[0],
        rows_by_seq_mover_count[1],
        rows_by_seq_mover_count[2],
        rows_by_seq_mover_count[3],
        rows_by_seq_mover_count[4]
    );
    println!(
        "decisions at one fixed directory under the standing replay config: allow {decided_allow} / ask {decided_ask} / deny {decided_deny}"
    );
    println!("  asks naming the unplaceable-cd cause: {asks_unplaceable_cd}");
    println!("    … whose row carries an unplaceable mover: {rows_unordered_mover_asking_unplaceable}");
    println!("    … whose movers are placed but a writer sits at an unprovable position: {asks_unplaceable_writer_position}");
    println!("    … unattributed residual (a body mover or wrapped snippet leaves the cause undecidable): {asks_unplaceable_other}");
    println!("  asks naming an unresolvable mover destination: {asks_unresolvable_mover_dest}");
}
