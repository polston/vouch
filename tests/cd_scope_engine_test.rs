//! Part-one engine weaving for scanner scopes (Task 3 of the
//! cd-scope-and-candidates plan; design doc §3): a compound body's commands
//! are judged in their own anchored scope instead of poisoning the whole
//! line, a process boundary's movers never reach the parent, a same-process
//! body's movers poison the parent POSITIONALLY from the body's anchor, and
//! a redirect is bound to its owner by (scope, order) rather than by a
//! sequence number that recurs in every scope.
//!
//! The config is the standing realistic one: `/tmp/**` is inside
//! `write.allow_paths`, `/etc` is not, so where a base composes decides the
//! verdict.
//!
//! Paths are drive-qualified on Windows, same reasoning as
//! `cd_candidate_test.rs`: a rooted, drive-less `/tmp/...` resolves against
//! the deciding PROCESS's current drive (`src/paths.rs`'s `resolve_links`,
//! the filesystem half of write-target judging), and on a runner whose
//! workspace lives on `D:` the resolved `D:/tmp/...` sits outside the
//! realistic allow list (`C:/tmp/**` is listed, other drives are not) — the
//! engine then asks correctly and the platform-naive leg fails by runner
//! luck rather than by the shape under test (M2.230).

#[path = "common/mod.rs"]
mod common;

fn cfg() -> vouch::config::Config {
    common::realistic_config()
}

/// Drive-qualify one rooted, drive-less fixture path for Windows — the same
/// helper as `cd_candidate_test.rs`.
fn t(p: &str) -> String {
    if cfg!(windows) { format!("C:{p}") } else { p.to_string() }
}

#[test]
fn a_subshell_cd_no_longer_poisons_the_outer_line() {
    // The subshell is a process boundary: its cd can never move the parent
    // shell, so the outer RELATIVE write composes at the caller's cwd (an
    // absolute target would bypass the base and prove nothing).
    let (v, r) = common::decision_at(
        &cfg(),
        &format!("( cd {} ) ; echo x > f.txt", t("/etc")),
        &t("/tmp/proj"),
    );
    assert_eq!(v, "allow", "{r}");
}

#[test]
fn a_writer_inside_a_subshell_gets_the_anchored_base() {
    // The body starts where its anchor's composed base says the shell was —
    // certified through the && chain — and the write is judged there.
    let (v, r) = common::decision_at(
        &cfg(),
        &format!("cd {} && ( echo x > f.txt )", t("/tmp/proj")),
        &t("/somewhere/else"),
    );
    assert_eq!(v, "allow", "{r}");
    let (v2, _) = common::decision_at(
        &cfg(),
        &format!("cd {} && ( echo x > f.txt )", t("/etc")),
        &t("/tmp/proj"),
    );
    assert_eq!(v2, "ask");
}

#[test]
fn nested_scoped_movers_compose_inside_their_scope() {
    // cd A && ( cd B && write ): the inner write lands at B — the body's own
    // ordered walk runs from the anchored start.
    let (v, r) = common::decision_at(
        &cfg(),
        &format!("cd {} && ( cd {} && echo x > f.txt )", t("/etc"), t("/tmp/proj")),
        &t("/x"),
    );
    assert_eq!(v, "allow", "{r}");
}

#[test]
fn positions_before_a_same_process_body_mover_resolve() {
    // The loop body's cd poisons the parent only from the loop's own anchor
    // onward; the write at an earlier position stays resolved.
    let (v, r) = common::decision_at(
        &cfg(),
        &format!("echo x > f.txt; while true; do cd {}; done", t("/etc")),
        &t("/tmp/proj"),
    );
    assert_eq!(v, "allow", "{r}");
}

#[test]
fn positions_after_a_same_process_body_mover_ask() {
    // The positional half of the rule above: after the brace group's anchor
    // the parent may have been moved, so a later relative write asks while
    // the one before the anchor still resolves.
    let etc = t("/etc");
    let proj = t("/tmp/proj");
    let (v, r) =
        common::decision_at(&cfg(), &format!("{{ cd {etc}; }}; echo y > g.txt"), &proj);
    assert_eq!(v, "ask", "{r}");
    let (v2, r2) = common::decision_at(
        &cfg(),
        &format!("echo x > f.txt; {{ cd {etc}; }}; true"),
        &proj,
    );
    assert_eq!(v2, "allow", "{r2}");
}

#[test]
fn a_condition_list_mover_contaminates_the_body_it_gates() {
    // §3.3's loop trap: `while cd ..; do write; done` moves the directory
    // every pass with zero movers in the body. The condition scope and the
    // body scope share one anchor; a mover in either leaves the body's
    // writers unresolvable.
    let (v, r) = common::decision_at(
        &cfg(),
        &format!("while cd {}; do echo x > rel.txt; done", t("/etc")),
        &t("/tmp/proj"),
    );
    assert_eq!(v, "ask", "{r}");
}

#[test]
fn a_redirect_after_a_subshell_binds_to_its_own_command_not_the_bodys() {
    // Seq(0)/Seq(1) recur in every scope once bodies sequence locally; the
    // outer redirect must be owned by the outer echo through (scope, order),
    // never by a body command whose number happens to match.
    let proj = t("/tmp/proj");
    let (v, r) = common::decision_at(
        &cfg(),
        &format!("( cd {}; echo x > {proj}/inner.txt ); echo y > outer.txt", t("/etc")),
        &proj,
    );
    assert_eq!(v, "allow", "{r}");
}

#[test]
fn a_wrapper_inside_a_body_parents_onto_the_bodys_scope() {
    // The snippet's scope is anchored at the wrapper COMMAND, whose own site
    // sits in the body's scope — so the snippet's write starts from the
    // body's anchored base, not from scope 0.
    let (v, r) = common::decision_at(
        &cfg(),
        &format!("cd {} && ( bash -c 'echo x > f.txt' )", t("/tmp/proj")),
        &t("/x"),
    );
    assert_eq!(v, "allow", "{r}");
}

#[test]
fn an_unowned_redirect_resolves_in_its_own_scope_not_scope_zero() {
    // Task 3 review, F1: a compound's own redirect records an Unordered
    // order, so it finds no owning site — and the fallback used to consult
    // scope 0, whose event-free timeline handed back the caller's cwd while
    // the redirect's OWN scope had provably been moved by its cd. The
    // fallback must answer per scope: moved scope -> unknown -> ask.
    let etc = t("/etc");
    let proj = t("/tmp/proj");
    for cmd in [
        format!("( cd {etc}; {{ echo hi; }} > rel.txt )"),
        format!("( cd {etc}; for f in 1; do echo hi; done > rel.txt )"),
        format!("( cd {etc}; true || echo hi > rel.txt )"),
    ] {
        let (v, r) = common::decision_at(&cfg(), &cmd, &proj);
        assert_eq!(v, "ask", "{cmd}: {r}");
    }
    // The two controls that must keep composing: the same compound redirect
    // at top level with the mover sealed in a process boundary resolves at
    // the caller's cwd, and a mover-free scope's own compound redirect
    // resolves at that scope's anchored start.
    let (v, r) = common::decision_at(
        &cfg(),
        &format!("( cd {etc} ) ; {{ echo hi; }} > rel.txt"),
        &proj,
    );
    assert_eq!(v, "allow", "{r}");
    let (v2, r2) = common::decision_at(&cfg(), "( { echo hi; } > rel.txt )", &proj);
    assert_eq!(v2, "allow", "{r2}");
}

#[test]
fn a_synthesized_wrapper_mover_still_poisons_its_scope() {
    // §3.2 preservation, green before and after this task: a mover whose
    // occurrence was synthesized by wrapper expansion (`scanner_order` is
    // false — find's -exec payload here) has no provable position, so it
    // keeps poisoning its whole scope and the later write keeps asking.
    let (v, r) = common::decision_at(
        &cfg(),
        "find . -exec cd {} \\; ; echo x > f.txt",
        &t("/tmp/proj"),
    );
    assert_eq!(v, "ask", "{r}");
}
