//! The bash compound walk must visit every position that can hold something
//! judgeable, and a construct vouch cannot read must say so rather than fall
//! through to the language default.
//!
//! Design: `docs/specs/2026-09-04-compound-walk-and-nested-redirects-design.md`.
//!
//! The defect these pin is one empty match arm — `walk_compound`'s
//! `Arithmetic(_) | ArithmeticForClause(_) => {}` — which pushed no command,
//! recorded no redirect and raised no construct, so everything inside an
//! arithmetic construct was invisible to recognition, guards and the write
//! rules alike. Three shapes reached it and bash 5.2 really runs two of them,
//! verified on this machine before these tests were written:
//!
//!   * `for ((i=0;i<3;i++)); do rm -rf d; done`  — deletes, three times
//!   * `( ( echo A > f ) )`                      — writes `f`
//!   * `((echo B > f))`                          — syntax error, writes nothing
//!
//! Every test is written so a wrong answer in EITHER direction fails: the
//! shape vouch must now stop has a sibling that must still pass, so a fix that
//! simply asks about everything is as red as the silence it replaced.
//!
//! Paths are drive-lettered on purpose (M2.230): a rooted, drive-less fixture
//! path resolves against the deciding process's current drive and is green or
//! red by runner geography.

mod common;

use vouch::config::Action;
use vouch::engine::decide_command_in;
use vouch::protocol::Decision;

use common::HOOK_HOME as HOME;

/// Guards ask, an undescribed program does not — the standing replay shape,
/// so a guard is the only thing that can move a row here.
fn decide(cmd: &str) -> Decision {
    decide_command_in(&common::realistic_config(), "bash", cmd, Some(HOME), None)
}

/// The standing config with exactly one allowed write tree, so a derived write
/// destination shows up as a verdict rather than needing the reason text read.
///
/// Built by mutating `realistic_config` rather than by retyping its constructs
/// table: a hand-written copy drifts from the baseline it duplicates, and the
/// first draft of this file had already lost `dynamic_command`, `background`
/// and `function_def` that way — silently harmless only because no fixture
/// here happens to exercise them.
fn walled() -> vouch::config::Config {
    let mut cfg = common::realistic_config();
    cfg.write.allow_paths = vec!["C:/work/**".to_string()];
    cfg
}

fn decide_walled(cmd: &str) -> Decision {
    decide_command_in(&walled(), "bash", cmd, Some(HOME), None)
}

// ---------------------------------------------------------------------------
// M2.224 — an arithmetic for-loop's body is walked
// ---------------------------------------------------------------------------

/// The body's commands reach the guards, exactly as the plain spelling's do.
/// Both spellings are asserted in one test on purpose: the arithmetic form is
/// only correct here because it now matches the form that was always correct,
/// and pinning them apart would let them drift.
#[test]
fn an_arithmetic_for_loop_body_reaches_the_same_guard_as_a_plain_loop() {
    let plain = decide("for i in 1 2 3; do rm -rf C:/Users/dev/scratch; done");
    let arith = decide("for ((i=0;i<3;i++)); do rm -rf C:/Users/dev/scratch; done");
    assert!(
        matches!(plain, Decision::Ask(_)),
        "the plain loop stopped being the reference: {plain:?}"
    );
    assert!(
        matches!(arith, Decision::Ask(_)),
        "an arithmetic for-loop body is still invisible: {arith:?}"
    );
}

/// The other direction: walking the body must not make every arithmetic loop
/// ask. A body holding only a described read is allowed, so the ask above is
/// the guard firing rather than the construct blanketing the shape.
#[test]
fn an_arithmetic_for_loop_over_a_read_still_allows() {
    let d = decide("for ((i=0;i<3;i++)); do ls -la; done");
    assert!(
        matches!(d, Decision::Allow(_)),
        "walking the body turned a harmless loop into a prompt: {d:?}"
    );
}

// ---------------------------------------------------------------------------
// M2.222 — a subshell whose only content is a subshell
// ---------------------------------------------------------------------------

/// bash writes the file. Before this changeset vouch allowed it, because the
/// parser hands a spaced nested subshell over as an arithmetic node and the
/// empty arm dropped the whole construct — the redirect was never lost, the
/// construct was.
#[test]
fn a_doubly_nested_subshell_write_is_judged_like_a_single_one() {
    let single = decide_walled("( echo x > C:/Windows/evil.txt )");
    let double = decide_walled("( ( echo x > C:/Windows/evil.txt ) )");
    assert!(
        matches!(single, Decision::Ask(_)),
        "the single nest stopped being the reference: {single:?}"
    );
    assert!(
        matches!(double, Decision::Ask(_)),
        "a doubly-nested subshell still writes unjudged: {double:?}"
    );
}

/// The sibling and brace spellings were never broken, and must stay that way:
/// they are what proved the trigger was the parser's arithmetic reading rather
/// than nesting depth.
#[test]
fn the_spellings_that_always_worked_still_work() {
    for cmd in [
        "( true; ( echo x > C:/Windows/evil.txt ) )",
        "( { echo x > C:/Windows/evil.txt ; } )",
    ] {
        assert!(
            matches!(decide_walled(cmd), Decision::Ask(_)),
            "a spelling that already worked regressed: {cmd}"
        );
    }
}

/// The other direction: a nested write into the ALLOWED tree still allows, so
/// the fix judges the destination rather than refusing the shape.
#[test]
fn a_doubly_nested_write_inside_the_allowed_tree_still_allows() {
    let d = decide_walled("( ( echo x > C:/work/notes.txt ) )");
    assert!(
        matches!(d, Decision::Allow(_)),
        "the nested write is now refused wherever it points: {d:?}"
    );
}

// ---------------------------------------------------------------------------
// M2.222 / §2.2 — arithmetic text vouch cannot vouch for
// ---------------------------------------------------------------------------

/// Ordinary arithmetic runs no command and writes nothing, so it stays quiet.
/// This is the test that stops §2.2 from becoming "every `((…))` asks", which
/// would be the silent-empty defect swapped for a noisy one.
#[test]
fn ordinary_arithmetic_stays_silent() {
    for cmd in ["(( i=1 ))", "(( i<3 ))", "(( x = (a+b)*c ))", "(( a[i]++ ))"] {
        let d = decide(cmd);
        assert!(
            matches!(d, Decision::Allow(_)),
            "real arithmetic started prompting: {cmd} -> {d:?}"
        );
    }
}

/// Arithmetic carrying a command substitution runs a command bash really runs,
/// and vouch cannot read which one from the arithmetic reading it was handed.
#[test]
fn arithmetic_carrying_a_command_substitution_asks() {
    let d = decide("(( x = $(id -u) ))");
    assert!(
        matches!(d, Decision::Ask(_)),
        "arithmetic that runs a command was allowed unread: {d:?}"
    );
}

// ---------------------------------------------------------------------------
// M2.155 — a for-clause's value words are classified
// ---------------------------------------------------------------------------

/// The words after `in` reached no walker at all, so a brace range there was
/// invisible where the identical token in a head or argument position raised
/// its construct.
#[test]
fn a_brace_range_in_a_for_clause_value_list_raises_its_construct() {
    let cfg = common::realistic_config_with_construct("bash", "brace_expansion", Action::Ask);
    let d = decide_command_in(&cfg, "bash", "for i in {1..3}; do ls; done", Some(HOME), None);
    assert!(
        matches!(d, Decision::Ask(_)),
        "a for-clause value list is still visited by nothing: {d:?}"
    );
}

/// The other direction: a plain literal list is not subject to brace expansion
/// and must stay silent, so the classifier is reading the word rather than the
/// position.
#[test]
fn a_literal_for_clause_value_list_raises_nothing() {
    let cfg = common::realistic_config_with_construct("bash", "brace_expansion", Action::Ask);
    let d = decide_command_in(&cfg, "bash", "for i in alpha beta; do ls; done", Some(HOME), None);
    assert!(
        matches!(d, Decision::Allow(_)),
        "a literal value list started prompting: {d:?}"
    );
}

/// The regression that nearly shipped, and the reason the source spelling
/// decides rather than the token shape.
///
/// A first implementation classified the expression by looking for two
/// operands with no operator between them. `echo x > f` has that pair and was
/// caught; `rm -rf /tmp/x` does not, because `-rf` opens with what arithmetic
/// reads as a unary minus and `/tmp/x` with a division — the whole text is
/// syntactically valid arithmetic (`rm` minus `rf` divided by `tmp` divided by
/// `x`). So the exact shape M2.222 is about kept allowing, while the gate was
/// green and the corpus count was zero.
///
/// Token shape cannot separate these; only the source can, and bash's own rule
/// is the source: `((` opens arithmetic, `( (` opens a nested subshell.
#[test]
fn a_recursive_delete_in_a_doubly_nested_subshell_reaches_its_guard() {
    let d = decide("( ( rm -rf C:/Users/dev/scratch ) )");
    assert!(
        matches!(d, Decision::Ask(_)),
        "a delete inside a doubly-nested subshell is allowed unseen: {d:?}"
    );
    // Not merely "it asks": it must reach the same guard the plain spelling
    // does, or an opaque construct ask would pass this test while telling the
    // operator nothing about what the command does.
    let Decision::Ask(reason) = d else { unreachable!() };
    assert!(
        reason.contains("delete_recursive"),
        "it asks, but not on the guard: {reason}"
    );
}

/// The same source rule read from the other side: a genuine arithmetic
/// evaluation whose text would parse perfectly well as a command must stay
/// silent, or the fix above becomes a blanket ask on real arithmetic.
#[test]
fn arithmetic_whose_text_would_parse_as_a_command_stays_silent() {
    for cmd in ["((ls))", "(( ls ))", "((rm))"] {
        let d = decide(cmd);
        assert!(
            matches!(d, Decision::Allow(_)),
            "real arithmetic read as a command: {cmd} -> {d:?}"
        );
    }
}

/// The span is read by CHARACTER, not by byte, and this is what proves it.
///
/// `SourceSpan` documents its length as a count of characters. Slicing the
/// source by byte would agree with that on ASCII and drift by one byte per
/// multi-byte character before the construct — so a line with an accented word
/// ahead of the parentheses would read the wrong two characters and classify
/// a nested subshell as arithmetic, silently restoring the hole. Five of them
/// makes the drift wide enough that no boundary luck can hide it.
#[test]
fn the_opening_is_read_by_character_so_a_multibyte_prefix_does_not_shift_it() {
    for cmd in [
        "echo é && ( ( rm -rf C:/Users/dev/scratch ) )",
        "echo ééééé && ( ( rm -rf C:/Users/dev/scratch ) )",
    ] {
        let d = decide(cmd);
        assert!(
            matches!(d, Decision::Ask(_)),
            "a multibyte prefix shifted the opening read: {cmd} -> {d:?}"
        );
    }
}

/// Recovery reads the parser's own node, never the raw line, so the same
/// characters inside a quoted argument are an argument and nothing else.
#[test]
fn a_quoted_nested_subshell_is_an_argument_not_a_construct() {
    let d = decide("echo \"( ( rm -rf C:/Users/dev/scratch ) )\"");
    assert!(
        matches!(d, Decision::Allow(_)),
        "quoted text was recovered as a construct: {d:?}"
    );
}
