//! A guard's action can be set per PLACE (spec 2026-08-06 §Place-scoped guard
//! overrides).
//!
//! `[guards]` says what a guard costs everywhere. `[[run.guards]]` says what it
//! costs under one tree. The two directions read uncertainty opposite ways, and
//! that is the whole of this file:
//!
//!   - an override LOOSER than the global action grants, so it needs the place
//!     PROVEN inside one of its trees;
//!   - an override STRICTER than the global action restricts, so it applies
//!     unless the place proves the command runs OUTSIDE every one of them.
//!
//! Resolution is per HIT, not per line: two commands on one line tripping the
//! same guard from two directories are two questions, and the stricter answer
//! is the one the line gets.

mod common;

use vouch::engine::decide_command_at;
use vouch::protocol::Decision;

fn cfg(extra: &str) -> vouch::config::Config {
    vouch::config::load(&format!(
        "[lang.bash]\ndefault = \"allow\"\n[guards]\ndelete_recursive = \"allow\"\n{extra}"
    ))
    .unwrap()
}

#[test]
fn a_stricter_override_applies_on_a_proven_place_and_says_it_overrode() {
    let c = cfg("[[run.guards]]\nunder = [\"C:/workspace/**\"]\ndelete_recursive = \"ask\"");
    let d = decide_command_at(&c, "bash", "rm -rf build", None, None, Some("C:/workspace/vouch-dev"));
    match d {
        Decision::Ask(r) => {
            assert!(r.contains("run.guards") && r.contains("C:/workspace/**"), "{r}");
            // Spec prompt table: "the global action was overridden".
            assert!(r.contains("overrid"), "{r}");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_stricter_override_applies_on_an_unproven_place_and_names_the_cause() {
    let c = cfg("[[run.guards]]\nunder = [\"C:/workspace/**\"]\ndelete_recursive = \"ask\"");
    let d = decide_command_at(&c, "bash", "cd a || cd b; rm -rf build", None, None, Some("C:/tmp"));
    match d {
        Decision::Ask(r) => {
            assert!(
                r.contains("run.guards"),
                "restrict applies unless provably outside, naming itself: {r}"
            );
            // The M2.58 standard: saying a place is unprovable without saying
            // what made it unprovable leaves the operator no move to make.
            assert!(r.contains("cannot order"), "the cause, not just the fact: {r}");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_stricter_override_does_not_apply_provably_outside() {
    let c = cfg("[[run.guards]]\nunder = [\"C:/workspace/**\"]\ndelete_recursive = \"ask\"");
    let d = decide_command_at(&c, "bash", "rm -rf build", None, None, Some("C:/tmp/job"));
    assert!(matches!(d, Decision::Allow(_)), "global allow stands outside: {d:?}");
}

#[test]
fn a_loosening_override_applies_only_on_a_proven_place() {
    let c = vouch::config::load(
        "[lang.bash]\ndefault = \"allow\"\n[guards]\ndelete_recursive = \"ask\"\n\
         [[run.guards]]\nunder = [\"C:/scratch/**\"]\ndelete_recursive = \"allow\"",
    )
    .unwrap();
    let inside = decide_command_at(&c, "bash", "rm -rf build", None, None, Some("C:/scratch/j"));
    match &inside {
        // An allow a place produced says which rule and which tree, or `vouch
        // why` reads back "allowed by vouch policy" for a decision the
        // operator's own entry made (spec §Every place-derived verdict says so).
        Decision::Allow(r) => {
            assert!(r.contains("run.guards") && r.contains("C:/scratch/**"), "{r}")
        }
        other => panic!("{other:?}"),
    }
    let unproven = decide_command_at(
        &c,
        "bash",
        "cd a || cd b; rm -rf build",
        None,
        None,
        Some("C:/scratch/j"),
    );
    assert!(matches!(unproven, Decision::Ask(_)), "loosening needs proof: {unproven:?}");
}

#[test]
fn when_two_overrides_match_the_strictest_wins() {
    // Spec: "when several overrides match the same guard at the same
    // place, the strictest matching action wins."
    let c = vouch::config::load(
        "[lang.bash]\ndefault = \"allow\"\n[guards]\ndelete_recursive = \"allow\"\n\
         [[run.guards]]\nunder = [\"C:/workspace/**\"]\ndelete_recursive = \"ask\"\n\
         [[run.guards]]\nunder = [\"C:/workspace/vouch-dev/**\"]\ndelete_recursive = \"deny\"",
    )
    .unwrap();
    let d = decide_command_at(&c, "bash", "rm -rf build", None, None, Some("C:/workspace/vouch-dev"));
    assert!(matches!(d, Decision::Deny(_)), "{d:?}");
}

/// [review] An override that RESTATES the global action still competes.
///
/// It was being dropped from the matching set as "not an override of
/// anything", which let a narrow loosening entry win unopposed: the broad
/// `C:/workspace/**` entry agreeing with the global `ask` vanished, and
/// `C:/workspace/scratch/** = allow` allowed. The identical shape with a broad entry
/// that merely DIFFERED from the global asked. Whether a matching entry
/// happens to restate the global cannot decide the answer, and it cannot
/// decide it in the permissive direction.
#[test]
fn a_broad_override_restating_the_global_still_blocks_a_narrow_loosening_one() {
    let c = vouch::config::load(
        "[lang.bash]\ndefault = \"allow\"\n[guards]\ndelete_recursive = \"ask\"\n\
         [[run.guards]]\nunder = [\"C:/workspace/**\"]\ndelete_recursive = \"ask\"\n\
         [[run.guards]]\nunder = [\"C:/workspace/scratch/**\"]\ndelete_recursive = \"allow\"",
    )
    .unwrap();
    let d = decide_command_at(&c, "bash", "rm -rf build", None, None, Some("C:/workspace/scratch/j"));
    assert!(matches!(d, Decision::Ask(_)), "the strictest matching action wins: {d:?}");
}

/// The same shape with the broad entry DIFFERING from the global — the control
/// that showed the two were answered differently. Both must ask.
#[test]
fn a_broad_override_differing_from_the_global_blocks_it_the_same_way() {
    let c = vouch::config::load(
        "[lang.bash]\ndefault = \"allow\"\n[guards]\ndelete_recursive = \"allow\"\n\
         [[run.guards]]\nunder = [\"C:/workspace/**\"]\ndelete_recursive = \"ask\"\n\
         [[run.guards]]\nunder = [\"C:/workspace/scratch/**\"]\ndelete_recursive = \"allow\"",
    )
    .unwrap();
    let d = decide_command_at(&c, "bash", "rm -rf build", None, None, Some("C:/workspace/scratch/j"));
    assert!(matches!(d, Decision::Ask(_)), "{d:?}");
}

/// A lone override restating the global claims nothing it did not do: the
/// global action stood, so the prompt must not say it was overridden. It still
/// names the entry, because `guards.<name>` alone is NOT the off-switch here —
/// loosening the global would leave this entry standing over it (§5).
#[test]
fn a_lone_same_action_override_makes_no_false_override_claim() {
    let c = vouch::config::load(
        "[lang.bash]\ndefault = \"allow\"\n[guards]\ndelete_recursive = \"ask\"\n\
         [[run.guards]]\nunder = [\"C:/workspace/**\"]\ndelete_recursive = \"ask\"",
    )
    .unwrap();
    match decide_command_at(&c, "bash", "rm -rf build", None, None, Some("C:/workspace/vouch-dev")) {
        Decision::Ask(r) => {
            assert!(!r.contains("overrid"), "nothing was overridden: {r}");
            assert!(r.contains("guards.delete_recursive"), "{r}");
            assert!(r.contains("the same action"), "{r}");
        }
        other => panic!("{other:?}"),
    }
}

/// [review] One line, two overridden guards: the prompt names both, with a
/// setting line each. Naming only the first left the operator turning off a
/// rule that was not the whole answer.
#[test]
fn a_line_tripping_two_overridden_guards_names_both() {
    let c = vouch::config::load(
        "[lang.bash]\ndefault = \"allow\"\n[guards]\ndelete_recursive = \"allow\"\n\
         history_rewrite = \"allow\"\n\
         [[run.guards]]\nunder = [\"C:/workspace/**\"]\ndelete_recursive = \"ask\"\n\
         history_rewrite = \"ask\"",
    )
    .unwrap();
    match decide_command_at(
        &c,
        "bash",
        "rm -rf build && git reset --hard",
        None,
        None,
        Some("C:/workspace/vouch-dev"),
    ) {
        Decision::Ask(r) => {
            assert!(r.contains("delete_recursive"), "{r}");
            assert!(r.contains("history_rewrite"), "the second overridden guard: {r}");
            // §5 — each named guard carries its own off-switch, not one
            // setting line covering both.
            assert_eq!(r.matches("setting: ").count(), 2, "one setting line each: {r}");
            assert!(
                r.contains("take delete_recursive out of") && r.contains("take history_rewrite out of"),
                "each names its own way off: {r}"
            );
        }
        other => panic!("{other:?}"),
    }
}

/// [review] A run-dir flag says where THIS command runs, so it moves the
/// command's run place for a guard override exactly as a `cd` would. The
/// loosening direction is the sharp one: it GRANTS, so it needs the place
/// proven inside the tree — and the only thing that puts it there is the flag.
#[test]
fn a_run_dir_flag_moves_the_place_a_guard_override_is_matched_against() {
    let c = vouch::config::load(
        "[lang.bash]\ndefault = \"allow\"\n[guards]\nhistory_rewrite = \"ask\"\n\
         [[run.guards]]\nunder = [\"C:/scratch/**\"]\nhistory_rewrite = \"allow\"",
    )
    .unwrap();
    let moved = decide_command_at(
        &c,
        "bash",
        "git -C C:/scratch/j reset --hard",
        None,
        None,
        Some("C:/work"),
    );
    assert!(matches!(moved, Decision::Allow(_)), "the flag put it in the tree: {moved:?}");
    // Without the flag the same command runs where the shell is, and the
    // override grants nothing.
    let unmoved = decide_command_at(&c, "bash", "git reset --hard", None, None, Some("C:/work"));
    assert!(matches!(unmoved, Decision::Ask(_)), "{unmoved:?}");
}

/// Fail-closed: a run-dir value vouch cannot resolve leaves the place
/// UNPROVEN, never the shell's directory — so a grant-shaped override does not
/// apply, and the prompt says what failed to resolve.
#[test]
fn an_unresolvable_run_dir_value_leaves_the_place_unproven() {
    let c = vouch::config::load(
        "[lang.bash]\ndefault = \"allow\"\n[guards]\nhistory_rewrite = \"ask\"\n\
         [[run.guards]]\nunder = [\"C:/scratch/**\"]\nhistory_rewrite = \"allow\"",
    )
    .unwrap();
    let d = decide_command_at(
        &c,
        "bash",
        "git -C \"$NOWHERE_AT_ALL_ZZ/j\" reset --hard",
        None,
        None,
        Some("C:/scratch/j"),
    );
    assert!(matches!(d, Decision::Ask(_)), "an unresolvable place grants nothing: {d:?}");
}

#[test]
fn two_commands_tripping_the_same_guard_from_different_places_get_the_stricter_answer() {
    let c = cfg("[[run.guards]]\nunder = [\"C:/workspace/**\"]\ndelete_recursive = \"ask\"");
    let d = decide_command_at(
        &c,
        "bash",
        "rm -rf outbuild && cd C:/workspace/vouch-dev && rm -rf build",
        None,
        None,
        Some("C:/tmp"),
    );
    assert!(matches!(d, Decision::Ask(_)), "{d:?}");
}

/// The mirror of the one above: the tripped-inside hit comes FIRST and the
/// line LEAVES the tree. Same answer — which order the two places appear in is
/// not something the operator should have to think about.
#[test]
fn the_stricter_answer_does_not_depend_on_which_place_came_first() {
    let c = cfg("[[run.guards]]\nunder = [\"C:/workspace/**\"]\ndelete_recursive = \"ask\"");
    let d = decide_command_at(
        &c,
        "bash",
        "rm -rf build && cd C:/tmp && rm -rf outbuild",
        None,
        None,
        Some("C:/workspace/vouch-dev"),
    );
    assert!(matches!(d, Decision::Ask(_)), "{d:?}");
}

/// A restriction cannot be proven outside a tree that names no directory on
/// this machine, so it applies — the same inversion Task 6's fix round found
/// in the distrust zone, one rule over. `$PROJECT_ROOT` with no repository is
/// the shape that produces it.
#[test]
fn a_stricter_override_whose_trees_cannot_be_located_still_applies() {
    let c = cfg("[[run.guards]]\nunder = [\"$PROJECT_ROOT/**\"]\ndelete_recursive = \"ask\"");
    let d = decide_command_at(&c, "bash", "rm -rf build", None, None, Some("C:/tmp/job"));
    match d {
        Decision::Ask(r) => {
            assert!(r.contains("$PROJECT_ROOT/**"), "{r}");
            // Never "you are outside it" — the tree is nowhere at all, and the
            // prompt has to say which pattern failed to resolve so the operator
            // can spell it differently.
            assert!(r.contains("cannot be proven outside"), "{r}");
        }
        other => panic!("a tree vouch cannot locate cannot be proven outside: {other:?}"),
    }
}

/// The opposite direction of the same uncertainty: a GRANT has no tree to
/// stand in, so it grants nothing and the global action stands.
#[test]
fn a_loosening_override_whose_trees_cannot_be_located_grants_nothing() {
    let c = vouch::config::load(
        "[lang.bash]\ndefault = \"allow\"\n[guards]\ndelete_recursive = \"ask\"\n\
         [[run.guards]]\nunder = [\"$PROJECT_ROOT/**\"]\ndelete_recursive = \"allow\"",
    )
    .unwrap();
    let d = decide_command_at(&c, "bash", "rm -rf build", None, None, Some("C:/tmp/job"));
    assert!(matches!(d, Decision::Ask(_)), "{d:?}");
}

/// An override that names a DIFFERENT guard leaves this one alone — the
/// per-guard lookup, pinned, so a future rewrite cannot make an entry apply to
/// every guard it does not name.
#[test]
fn an_override_for_another_guard_does_not_touch_this_one() {
    let c = cfg("[[run.guards]]\nunder = [\"C:/workspace/**\"]\nhistory_rewrite = \"deny\"");
    let d = decide_command_at(&c, "bash", "rm -rf build", None, None, Some("C:/workspace/vouch-dev"));
    assert!(matches!(d, Decision::Allow(_)), "{d:?}");
}

/// With no `[[run.guards]]` at all, the global action decides and the prompt
/// still names `guards.<name>` as the setting that turns it off (CLAUDE.md §5).
/// This is the row every existing prompt takes, pinned against the override
/// wording replacing it.
#[test]
fn with_no_override_the_prompt_still_names_the_global_setting() {
    let c = vouch::config::load("[lang.bash]\ndefault = \"allow\"\n[guards]\ndelete_recursive = \"ask\"")
        .unwrap();
    match decide_command_at(&c, "bash", "rm -rf build", None, None, Some("C:/workspace/vouch-dev")) {
        Decision::Ask(r) => {
            assert!(r.contains("setting: guards.delete_recursive"), "{r}");
            assert!(!r.contains("run.guards"), "no override decided this: {r}");
        }
        other => panic!("{other:?}"),
    }
}
