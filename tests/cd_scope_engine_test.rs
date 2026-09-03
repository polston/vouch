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
fn a_compound_redirect_is_judged_from_the_compounds_own_position() {
    // M2.226, and the position half of the 2026-08-30 design §3.3's closing
    // sentence. The redirect is opened at the CONSTRUCT's anchor in the
    // parent's scope, so an ordered mover earlier on the line places it
    // exactly as it places a simple command's redirect. Before the fix the
    // walk recorded `Order::Unordered` here although it had just computed the
    // anchor, so the redirect owned no site, fell back to its scope, found
    // that scope moved, and asked as an unplaceable position.
    // The mover is `&&`-chained, not `;`-sequenced: only an AND-run certifies
    // that it ran (`certifies()`), so a sequenced mover contributes
    // {moved, unmoved} and correctly asks on the unmoved candidate (M2.44).
    // This test is about the redirect's POSITION, so the mover has to be the
    // certified spelling or the control asks for an unrelated reason.
    let proj = t("/tmp/proj");
    let elsewhere = t("/somewhere/else");
    let (simple_v, simple_r) =
        common::decision_at(&cfg(), &format!("cd {proj} && echo x > f.txt"), &elsewhere);
    assert_eq!(simple_v, "allow", "{simple_r}");
    for cmd in [
        format!("cd {proj} && {{ :; }} > f.txt"),
        format!("cd {proj} && for f in 1; do :; done > f.txt"),
    ] {
        let (v, r) = common::decision_at(&cfg(), &cmd, &elsewhere);
        assert_eq!(v, simple_v, "{cmd}: {r}");
    }
}

#[test]
fn a_compound_redirect_after_an_ordered_mover_is_not_judged_at_the_old_cwd() {
    // The permissive direction, probed before the fix and found SAFE — kept
    // as the pin that says so. Written from an allowed cwd into a tree that
    // is not writable, so if the positionless redirect were resolved at the
    // scope's start this would allow a write that lands in /etc. It does not:
    // before the fix it asks naming `unresolved_path`, so M2.226 really is
    // wrong-cause-only and never a wrong allow.
    //
    // What the fix changes is the sentence, not the verdict: anchored at the
    // compound's own position the write target resolves to /etc/f.txt, and
    // the ask names the directory the file actually lands in instead of
    // reporting a position vouch could not place.
    let (v, r) = common::decision_at(
        &cfg(),
        &format!("cd {} ; {{ :; }} > f.txt", t("/etc")),
        &t("/tmp/proj"),
    );
    assert_eq!(v, "ask", "{r}");
    assert!(
        r.contains(&t("/etc")),
        "the ask must name the directory the write actually lands in: {r}"
    );
}

#[test]
fn a_mover_inside_a_compound_never_reaches_that_compounds_redirect() {
    // The other half of the same sentence, and the reason passing the anchor
    // is safe rather than merely convenient: the redirect is anchored at the
    // construct's own position, which PRECEDES the body, so a mover written
    // inside the body cannot decide where the redirect lands. The write is
    // judged at the caller's cwd even though the body walks into a tree that
    // is not writable.
    let (v, r) = common::decision_at(
        &cfg(),
        &format!("{{ cd {} ; }} > f.txt", t("/etc")),
        &t("/tmp/proj"),
    );
    assert_eq!(v, "allow", "{r}");
    // And the mover still reaches everything AFTER the compound, which is
    // what makes the brace group a same-process body rather than a boundary.
    let (v2, r2) = common::decision_at(
        &cfg(),
        &format!("{{ cd {} ; }} > f.txt ; echo x > g.txt", t("/etc")),
        &t("/tmp/proj"),
    );
    assert_eq!(v2, "ask", "{r2}");
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

#[test]
fn a_wrapper_injected_redirect_keeps_the_channels_in_lockstep() {
    // The engine folds a wrapped snippet's own redirects onto the wrapper,
    // and that fold is the one place outside the scanners that appends to the
    // four positional redirect channels. It has shortened one twice:
    // `redirect_scope` (M2.221, IMPORTANT 2) and `redirect_chain` after it,
    // because a channel added later does not inherit the folds the older ones
    // already had. `tests/shell_test.rs`'s lockstep test asserts over ONE
    // scan and cannot see the fold, which is why neither was caught there.
    //
    // A `debug_assert` in the fold is what actually holds the invariant; this
    // drives shapes through it. No verdict differential is asserted, because
    // none was found: with a wrapper-injected redirect the wrapper is itself
    // the owning site, so the chainless fallback is not obviously reachable —
    // the defect is a broken invariant with no demonstrated verdict impact,
    // and saying that plainly beats a differential that passes either way.
    let etc = t("/etc");
    let proj = t("/tmp/proj");
    for cmd in [
        format!("cd {etc} && sh -c 'echo hi > rel.txt'"),
        format!("cd {etc} && true || sh -c 'echo hi > rel.txt' || echo done"),
        format!("sh -c 'echo a > one.txt; echo b > two.txt' > outer.txt"),
        format!("( cd {etc}; sh -c 'echo hi > rel.txt' )"),
        format!("cd {etc} && bash -c 'sh -c \'echo hi > deep.txt\''"),
    ] {
        let (v, r) = common::decision_at(&cfg(), &cmd, &proj);
        assert!(
            v == "allow" || v == "ask" || v == "deny",
            "{cmd} reached a decision without tripping the fold's lockstep \
             assertions: {r}"
        );
    }
}
