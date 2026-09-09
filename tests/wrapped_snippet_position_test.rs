//! A wrapped snippet keeps its own position (M2.225, design
//! `docs/specs/2026-09-05-wrapped-snippet-position-design.md`).
//!
//! Four shapes, one seam. A redirect written inside `bash -c '…'` used to be
//! stamped with the WRAPPER's order and scope, so a `cd` inside the same
//! snippet could never reach it; and the snippet's own compound bodies were
//! flattened into one scope, so a write inside one had no position at all.
//!
//! Every assertion names the CAUSE, never merely that something asked. Both
//! wrong answers this fixes are reachable through a weaker assertion: A and B
//! were ALLOW, and D was an ask for an unrelated reason (`unresolved_path`),
//! which a bare `assert_eq!(v, "ask")` would have called a pass.
//!
//! The config is the standing realistic one: `/tmp/**` is inside
//! `write.allow_paths` and `/etc` is not, so where the base composes decides.
//! Paths are drive-qualified on Windows for the reason `cd_candidate_test.rs`
//! records (M2.230): a rooted, drive-less `/tmp/…` resolves against the
//! deciding process's current drive, and a `D:`-workspace runner would then
//! fail a platform-naive leg by geography rather than by the shape under test.

#[path = "common/mod.rs"]
mod common;

const OUTSIDE: &str = "outside every allowed area";

fn cfg() -> vouch::config::Config {
    common::realistic_config()
}

fn t(p: &str) -> String {
    if cfg!(windows) { format!("C:{p}") } else { p.to_string() }
}

#[test]
fn a_redirect_after_a_snippets_own_cd_resolves_where_the_snippet_moved_to() {
    // Probe A. The `&&` certifies the mover, so the snippet is provably in
    // `/etc` when the redirect runs — one candidate, outside every allowed
    // tree. Stamped with the wrapper's own base this ALLOWED.
    let (v, r) = common::decision_at(
        &cfg(),
        &format!("bash -c 'cd {} && echo x > rel.txt'", t("/etc")),
        &t("/tmp/proj"),
    );
    assert_eq!(v, "ask", "{r}");
    assert!(r.contains(OUTSIDE), "the write wall should name the destination: {r}");
}

#[test]
fn a_redirect_inside_a_body_within_the_snippet_resolves_there_too() {
    // Probe B. Same shape, one scope deeper: the redirect sits inside a
    // subshell the snippet's own scan allocated a scope for, which the
    // expansion used to flatten away.
    let (v, r) = common::decision_at(
        &cfg(),
        &format!("bash -c 'cd {} && (echo x > rel.txt)'", t("/etc")),
        &t("/tmp/proj"),
    );
    assert_eq!(v, "ask", "{r}");
    assert!(r.contains(OUTSIDE), "the write wall should name the destination: {r}");
}

#[test]
fn a_described_write_after_a_snippets_own_cd_is_unchanged() {
    // Probe C, the regression guard. The write-CLAIM channel already composed
    // the inner mover correctly; this changeset must not move it.
    let (v, r) = common::decision_at(
        &cfg(),
        &format!("bash -c 'cd {} && cp a rel.txt'", t("/etc")),
        &t("/tmp/proj"),
    );
    assert_eq!(v, "ask", "{r}");
    assert!(r.contains(OUTSIDE), "the write wall should name the destination: {r}");
}

#[test]
fn a_described_write_inside_a_body_within_the_snippet_names_its_destination() {
    // Probe D. Fail-closed before this changeset and still wrong: it said the
    // position could not be placed, when the position is plain inside the
    // snippet and was discarded on the way out of it. The `unresolved_path`
    // assertion is the point of the test — the verdict alone never moved.
    let (v, r) = common::decision_at(
        &cfg(),
        &format!("bash -c 'cd {} && (cp a rel.txt)'", t("/etc")),
        &t("/tmp/proj"),
    );
    assert_eq!(v, "ask", "{r}");
    assert!(
        !r.contains("unresolved_path"),
        "the position inside the snippet is placeable, so the ask must not claim otherwise: {r}"
    );
    assert!(r.contains(OUTSIDE), "the write wall should name the destination: {r}");
}

#[test]
fn a_snippets_own_cd_into_an_allowed_tree_reaches_its_redirect() {
    // The toward-ALLOW direction, which is what makes this changeset the one
    // that needs its own count: the snippet leaves a disallowed place for an
    // allowed one, and the redirect must follow it there.
    let (v, r) = common::decision_at(
        &cfg(),
        &format!("bash -c 'cd {} && echo x > rel.txt'", t("/tmp/proj")),
        &t("/etc"),
    );
    assert_eq!(v, "allow", "{r}");
}

#[test]
fn a_snippet_with_no_mover_still_writes_where_the_wrapper_runs() {
    // The negative control for the whole change: with nothing moving the
    // shell inside the snippet, the wrapper's own base is the right base, and
    // both directions must still answer from it.
    let (allowed, r) = common::decision_at(
        &cfg(),
        "bash -c 'echo x > rel.txt'",
        &t("/tmp/proj"),
    );
    assert_eq!(allowed, "allow", "{r}");

    let (refused, r2) =
        common::decision_at(&cfg(), "bash -c 'echo x > rel.txt'", &t("/etc"));
    assert_eq!(refused, "ask", "{r2}");
    assert!(refused == "ask" && r2.contains(OUTSIDE), "{r2}");
}

#[test]
fn scanning_one_source_twice_yields_the_same_scope_and_redirect_ids() {
    // The engine re-scans each snippet source that the expansion walk already
    // scanned, and the per-snippet scope table built during the first scan is
    // read against the second scan's ids. That agreement is now load-bearing,
    // so it is pinned rather than assumed (design §2.3).
    let bash = vouch::syntax::scanner_for("bash").expect("bash scanner exists");
    for src in [
        "cd /etc && echo x > rel.txt",
        "cd /etc && (echo x > rel.txt)",
        "if true; then cd /etc; echo x > a.txt; fi; echo y > b.txt",
        "for f in a b; do echo x > $f; done",
        "echo $(cd /etc && echo x > rel.txt)",
        "echo $(echo $(cd /etc))",
        "cat <<EOF\n$(cd /etc)\nEOF\n",
        "for x in $(cd /etc); do :; done",
    ] {
        let first = bash.scan(src).expect("parses");
        let second = bash.scan(src).expect("parses");
        assert_eq!(
            first.scan_scopes.len(),
            second.scan_scopes.len(),
            "scope count differs between two scans of the same text: {src}"
        );
        assert_eq!(first.redirect_scope, second.redirect_scope, "redirect scopes differ: {src}");
        assert_eq!(first.redirect_order, second.redirect_order, "redirect orders differ: {src}");
        assert_eq!(first.cmd_scope, second.cmd_scope, "command scopes differ: {src}");
        assert_eq!(first.constructs, second.constructs, "constructs differ: {src}");
        assert_eq!(first.heads, second.heads, "head sequence differs: {src}");
    }
}

#[test]
fn a_body_nested_inside_another_body_within_the_snippet_still_places() {
    // Two scanner scopes deep inside the snippet. The inner scope's parent is
    // the OUTER inner scope, not the snippet body, so this is the leg that
    // proves the parent chain is rebased rather than flattened onto the body.
    let (v, r) = common::decision_at(
        &cfg(),
        &format!("bash -c 'cd {} && {{ ( echo x > rel.txt ) ; }}'", t("/etc")),
        &t("/tmp/proj"),
    );
    assert_eq!(v, "ask", "{r}");
    assert!(r.contains(OUTSIDE), "the write wall should name the destination: {r}");
}

#[test]
fn a_snippet_inside_a_snippet_carries_its_own_position_too() {
    // The recursion's own case: the inner wrapper allocates its scopes inside
    // the outer wrapper's, so the rebasing has to compose rather than reset.
    let (v, r) = common::decision_at(
        &cfg(),
        &format!("bash -c 'bash -c \"cd {} && echo x > rel.txt\"'", t("/etc")),
        &t("/tmp/proj"),
    );
    assert_eq!(v, "ask", "{r}");
    assert!(r.contains(OUTSIDE), "the write wall should name the destination: {r}");
}
