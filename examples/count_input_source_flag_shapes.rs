//! On-demand pre-count for the evaluated-input-seam changeset's proposed
//! `input_source_flags` field (design doc
//! `2026-09-05-evaluated-input-seam-design.md` §3). §6.2 requires the count
//! before the rule, and this is that count: the plan's Task 1, run before
//! anything under `input_source_flags` is built, and the answer decides
//! whether it is built at all (§0 — a field that turns out unearned gets
//! left out, not justified after the fact).
//!
//! The field's entire value is one class: an explicit source flag *plus* a
//! here-document supplying the script (`sh -s <<'EOF'`), because M1 already
//! covers every case where the code was located on the line some other way.
//! Two arms, over every top-level command of every real corpus row:
//!
//!   Arm A (the SHAPE): the head resolves to a `[[program]]` entry declaring
//!   `evaluates_input = "stdin"`, the command carries at least one
//!   here-document at descriptor 0 — TOP-LEVEL only, the same scope
//!   `measure_heredoc_fed_rows_and_their_decisions.rs` uses — and the
//!   command's arguments include a spelling `guards::reads_stdin` treats as
//!   an explicit stdin source that is NOT a bare `-`. `reads_stdin`'s own
//!   source spellings are exactly `-s` (case-insensitive) and a bare `-`;
//!   removing the bare `-` leaves `-s`. The bare `-` is excluded on purpose:
//!   `holds_input`'s rule 5 already accepts it today
//!   (`python3 - <<'EOF' … EOF` already ALLOWs — the design's own probe
//!   table), so it is not part of the population this field would move.
//!   `-s` is the one `holds_input` refuses regardless of the heredoc's own
//!   verbatim-ness, which is this field's entire reason to exist.
//!
//!   Arm B (the PROMPT): Arm A, restricted to ROWS whose decision — under
//!   the same `[lang.bash.constructs] evaluated_input = "ask"` override the
//!   design's §4 baseline (269) was measured with — is ASK naming
//!   `evaluated_input`. `realistic_config()` alone is not enough to see
//!   this: bash's `evaluated_input` construct is unset there and inherits
//!   from `dynamic_command = "allow"`, so without the override this whole
//!   class would read as ALLOW and Arm B would be silently zero for a
//!   reason that has nothing to do with the corpus (CLAUDE.md §6.7). Arm A
//!   counts a shape; Arm B counts a prompt actually removed, which is what
//!   the design's §3 gate is decided on.
//!
//! **Known-positive controls run first and gate the report (§6.8).** A zero
//! here is the likely answer — the design's own estimate is that this class
//! sits somewhere inside 1,253 unconsumed heredoc rows, not that it is
//! common — and an inert predicate prints the identical zero to an absent
//! shape. `sh -s <<'EOF' … EOF` (quoted delimiter) must fire both arms;
//! bare `sh <<'EOF' … EOF` (a heredoc with NO source flag at all — already
//! read from stdin implicitly, and already HELD under M1) must fire
//! neither. Both are invented text, tallied separately, never mixed into
//! the corpus counts, and the run exits nonzero if either control
//! disagrees.
//!
//! Every predicate runs over vouch's own bash scanner and the shipped
//! knowledge (`vouch::syntax`, `vouch::guards`) — never a regex over command
//! text (CLAUDE.md §6.1). No corpus text, path, command, or destination is
//! printed — aggregate counts only (CLAUDE.md §6.6).
//!
//! Run:
//!   export VOUCH_STATE_DIR="$(mktemp -d)"
//!   cargo run --release --example count_input_source_flag_shapes

#[path = "../tests/common/mod.rs"]
mod common;

use vouch::syntax::Cmd;

/// True when some entry for `head` (already `base_name`d), scoped to bash,
/// declares `evaluates_input = "stdin"` — the same re-derivation
/// `count_standalone_shapes.rs`'s `claims_stdin` uses, for the same reason:
/// `guards::entries_for_cmd` is private to `guards.rs`.
fn claims_stdin(kb: &vouch::guards::Knowledge, head: &str) -> bool {
    kb.program.iter().any(|p| {
        p.match_names.iter().any(|n| n.to_ascii_lowercase() == head)
            && (p.languages.is_empty() || p.languages.iter().any(|l| l == "bash"))
            && p.evaluates_input == "stdin"
    })
}

/// The one token class this measurement is about: a spelling
/// `guards::reads_stdin` treats as an explicit stdin source, EXCLUDING a
/// bare `-`. `reads_stdin`'s own source spellings are exactly `-s`
/// (case-insensitive) and a bare `-`; removing the bare `-` leaves this.
fn has_non_dash_source_flag(cmd: &Cmd) -> bool {
    cmd.args.iter().any(|a| a.eq_ignore_ascii_case("-s"))
}

#[derive(Default)]
struct Counts {
    /// Per-command occurrences meeting Arm A's shape (a row with two
    /// qualifying commands counts twice here).
    arm_a_instances: usize,
    /// Rows with at least one Arm-A-qualifying command — the population
    /// the design's §3 gate is measured against.
    arm_a_rows: usize,
    /// Arm-A rows whose OVERALL decision — vouch decides a command line
    /// once, not per sub-command — is ASK naming `evaluated_input` under
    /// the override config.
    arm_b_rows: usize,
}

/// One command line through both arms. `cfg` must already carry
/// `[lang.bash.constructs] evaluated_input = "ask"` — see the module doc.
fn tally(
    command: &str,
    kb: &vouch::guards::Knowledge,
    bash: &dyn vouch::syntax::Scanner,
    cfg: &vouch::config::Config,
    c: &mut Counts,
) {
    let Ok(scan) = bash.scan(command) else { return };
    let mut row_in_pool = false;
    for (ci, cmd) in scan.commands.iter().enumerate() {
        let head = vouch::guards::base_name(&cmd.head);
        if !claims_stdin(kb, &head) {
            continue;
        }
        let has_fd0_heredoc = scan.heredocs.iter().any(|h| h.cmd_index == ci && h.fd == 0);
        if !has_fd0_heredoc {
            continue;
        }
        if !has_non_dash_source_flag(cmd) || !vouch::guards::reads_stdin(cmd) {
            continue;
        }
        c.arm_a_instances += 1;
        row_in_pool = true;
    }
    if !row_in_pool {
        return;
    }
    c.arm_a_rows += 1;

    // The REAL judgement: vouch decides a whole command line once, so the
    // prompt this class would remove is a per-ROW fact, not a per-command
    // one (brief's own wording: "restricted to rows").
    let (verdict, reason) = common::decision_at(cfg, command, common::HOOK_HOME);
    if verdict == "ask" && reason.contains("evaluated_input") {
        c.arm_b_rows += 1;
    }
}

/// Invented text, known positives/negatives for the controls below. Not
/// corpus rows and never counted as measurement.
const CONTROL_BOTH_ARMS: &str = "sh -s <<'EOF'\necho hi\nEOF";
const CONTROL_NEITHER_ARM: &str = "sh <<'EOF'\necho hi\nEOF";

fn main() {
    let kb = vouch::guards::in_effect();
    let bash = vouch::syntax::scanner_for("bash").expect("bash scanner exists");
    // The same override the design's §4 baseline (269) was measured under —
    // see the module doc's Arm B paragraph for why the plain standing config
    // cannot see this class at all.
    let cfg = common::realistic_config_with_construct(
        "bash",
        "evaluated_input",
        vouch::config::Action::Ask,
    );

    let mut both = Counts::default();
    tally(CONTROL_BOTH_ARMS, kb, bash.as_ref(), &cfg, &mut both);
    let mut neither = Counts::default();
    tally(CONTROL_NEITHER_ARM, kb, bash.as_ref(), &cfg, &mut neither);

    let checks: [(&str, bool); 4] = [
        ("`sh -s` + quoted-delimiter heredoc fires arm A (the shape)", both.arm_a_rows > 0),
        ("`sh -s` + quoted-delimiter heredoc fires arm B (the prompt)", both.arm_b_rows > 0),
        ("bare `sh` + heredoc, no source flag, does NOT fire arm A", neither.arm_a_rows == 0),
        ("bare `sh` + heredoc, no source flag, does NOT fire arm B", neither.arm_b_rows == 0),
    ];
    let mut inert = false;
    for (what, agrees) in checks {
        if !agrees {
            eprintln!("control disagreed: {what}");
            inert = true;
        }
    }
    if inert {
        eprintln!(
            "This measurement's predicates do not detect the shape they were \
             written for, so a corpus count would be a zero about the \
             detector rather than about the corpus. Fix the predicates \
             before reading any number from this example."
        );
        std::process::exit(1);
    }
    println!("controls: both arms agree on invented text (fire on `sh -s` + heredoc, not on bare `sh` + heredoc)");

    let rows = common::rows_for_measurement();
    let mut c = Counts::default();
    for row in &rows {
        tally(&row.cmd, kb, bash.as_ref(), &cfg, &mut c);
    }

    println!();
    println!("corpus rows: {}", rows.len());
    println!();
    println!("--- Arm A: the shape (stdin-claiming entry + fd0 heredoc + explicit non-dash source flag) ---");
    println!("  instances (a row can hold more than one): {}", c.arm_a_instances);
    println!("  rows (a row counts once): {}", c.arm_a_rows);
    println!();
    println!("--- Arm B: the prompt (Arm A rows currently ASKing, reason naming evaluated_input) ---");
    println!("  rows: {}", c.arm_b_rows);
}
