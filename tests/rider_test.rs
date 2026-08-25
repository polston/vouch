//! Task 9 (Lane D) probes: `standalone_flags` on the SHIPPED `knowledge.toml`
//! — python/python3/py, the shells, and the node/perl/ruby stdin entry. Every
//! candidate flag here was run on the machine that wrote this file before
//! being added (task-9-report.md); these three probes pin the shipped
//! outcome against the actual repository file, the same pattern
//! `schema_docs_test.rs` already uses (`vouch::guards::load` over
//! `CARGO_MANIFEST_DIR/knowledge.toml`), never a synthetic fixture — a
//! fixture could drift from what ships and still pass.

use vouch::guards::{evaluates_input, load, recognises, Knowledge};
use vouch::syntax::Cmd;

fn shipped() -> Knowledge {
    let text = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("knowledge.toml"),
    )
    .expect("the shipped knowledge file is readable");
    load(&text).expect("the shipped knowledge file parses")
}

fn cmd(head: &str, args: &[&str]) -> Cmd {
    Cmd {
        head: head.into(),
        args: args.iter().map(|s| s.to_string()).collect(),
        unread_args: Default::default(),
        chain: None,
        prefix_assigns: vec![],
    }
}

/// `python --version` — a hand-built, complete argument record, so
/// `standalone_eligible = true` (the same reasoning `standalone_test.rs`
/// documents for a fixture-built `Cmd`). Recognised, and the stdin claim
/// stands down rather than firing on a false "this reads its code from
/// standard input" reason.
#[test]
fn shipped_python_version_is_a_standalone_run() {
    let kb = shipped();
    let c = cmd("python", &["--version"]);
    assert!(
        recognises(&kb, &c, "bash", true),
        "python --version should be recognised against the shipped knowledge"
    );
    let (fires, _, _) = evaluates_input(&kb, &c, false, true);
    assert!(
        !fires,
        "python --version must not trip evaluated_input now that --version is a \
         standalone_flags member on the shipped entry"
    );
}

/// `bash --version` — same shape, the shells entry.
#[test]
fn shipped_bash_version_is_a_standalone_run() {
    let kb = shipped();
    let c = cmd("bash", &["--version"]);
    assert!(
        recognises(&kb, &c, "bash", true),
        "bash --version should be recognised against the shipped knowledge"
    );
    let (fires, _, _) = evaluates_input(&kb, &c, false, true);
    assert!(
        !fires,
        "bash --version must not trip evaluated_input now that --version is a \
         standalone_flags member on the shipped shells entry"
    );
}

/// `python -` is the real stdin spelling (a lone `-`), never a member of
/// `standalone_flags` — the standalone stand-down must not blunt this
/// genuinely-true ask, on the shipped file, not just a synthetic one.
#[test]
fn shipped_python_dash_still_asks() {
    let kb = shipped();
    let c = cmd("python", &["-"]);
    let (fires, _, _) = evaluates_input(&kb, &c, false, true);
    assert!(
        fires,
        "python - reads its program from standard input and must still trip \
         evaluated_input — standalone_flags names none of this run's tokens"
    );
}

// ============================================================================
// Task 13 (Lane D) — spec §9.1/§9.2. `source` and `.` claim `runs_file =
// "arg_0"` so the file they run is the same blindness `bash setup.sh`
// already names; `trap` leaves the shell-state builtins entry's match list
// and asks as an unrecognised program.
// ============================================================================

mod common;

use common::assert_verdict;
use vouch::config::Action;

/// Outside every allowed tree in common::realistic_config's write section —
/// mirrors boundary_test.rs's own constant of the same name.
const OUTSIDE: &str = "C:/outside/of/every/allowed/tree";

/// `source setup.sh` and `. setup.sh` run a file vouch never read — the same
/// blindness `bash setup.sh` already names (M2.118), and the spec's point is
/// that all three name ONE off-switch. `evaluated_input` is forced to ask
/// because bash's own construct is UNSET in both the harness default and the
/// unmodeled-ask variant, so it would otherwise inherit `allow` from
/// `dynamic_command` and this test could not fail on a missing edit
/// (boundary_test.rs:259 is the precedent for the same forcing).
#[test]
fn sourcing_a_file_asks_like_running_it() {
    let cfg = common::realistic_config_with_construct("bash", "evaluated_input", Action::Ask);
    for cmd_text in ["source setup.sh", ". setup.sh", "bash setup.sh"] {
        assert_verdict(
            &cfg,
            OUTSIDE,
            cmd_text,
            "ask",
            Some("lang.bash.constructs.evaluated_input"),
        );
    }
}

/// A bare `source` (no operand) has no file to name — `runs_file_positional`
/// requires an occupied operand position, and the real shell errors out on
/// this shape anyway. Must stay quiet rather than asking on a guess.
#[test]
fn a_bare_source_stays_quiet() {
    let cfg = common::realistic_config_with_construct("bash", "evaluated_input", Action::Ask);
    assert_verdict(&cfg, OUTSIDE, "source", "allow", None);
}

/// `trap` left the shell-state builtins entry's match list (spec §9.2) — it
/// is now an unrecognised program and asks like any other, fail-closed with
/// the honest-but-generic reason rather than a false "no effect" claim.
#[test]
fn trap_asks_as_unknown() {
    let cfg = vouch::config::load(&common::config_text_with(&[(
        "bash",
        "unmodeled_command",
        "ask",
    )]))
    .expect("config parses");
    assert_verdict(
        &cfg,
        OUTSIDE,
        r#"trap "echo x" EXIT"#,
        "ask",
        Some("unmodeled_command"),
    );
}
