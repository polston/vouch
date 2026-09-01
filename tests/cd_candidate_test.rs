//! Part-two candidate bases for the chain producers (Task 4 of the
//! cd-scope-and-candidates plan; design doc §4): a sequenced mover the
//! judged command's execution does not certify contributes {target,
//! previous} instead of a false certainty; an or-tail refutes exactly the
//! immediately preceding member of the failed run; sets are bounded,
//! deduplicated, and collapse to Unknown past the cap; and a same-line
//! CDPATH assignment makes a relative destination unknowable.
//!
//! Standing realistic config: `/tmp/**` inside `write.allow_paths`, `/etc`
//! outside.

#[path = "common/mod.rs"]
mod common;

fn cfg() -> vouch::config::Config {
    common::realistic_config()
}

fn assert_absent(path: &str) {
    assert!(
        !std::path::Path::new(path).exists(),
        "precondition: {path} must not exist on the deciding machine"
    );
}

#[test]
fn an_uncertified_mover_contributes_its_failure_branch() {
    // cd A; write — the cd may have failed; the write must be allowed under
    // BOTH the target and the previous directory. The allow half is
    // existence-independent (both candidates sit in the allowed area); the
    // ask half must aim at a target proven ABSENT, or the §4.4 refinement
    // would legitimately discharge the failure branch on a machine where it
    // exists (Task 4 review, IMPORTANT 4).
    let (v, r) = common::decision_at(&cfg(), "cd /tmp/proj/sub; echo x > f.txt", "/tmp/proj");
    assert_eq!(v, "allow", "{r}");
    let absent = "/tmp/vouch-cd-cand-absent-fixture";
    assert_absent(absent);
    let (v2, r2) = common::decision_at(&cfg(), &format!("cd {absent}; echo x > f.txt"), "/etc");
    assert_eq!(v2, "ask", "{r2}");
    assert!(r2.contains("/etc"), "the ask names the escaping candidate: {r2}");
}

#[test]
fn an_or_group_reader_reached_through_and_refutes_nothing() {
    // Task 4 review, CRITICAL 1: in `cd /etc || true && write` the writer's
    // execution proves only that the OR-GROUP succeeded — satisfiable by
    // the cd succeeding — so the cd's moved branch survives and escapes.
    let (v, _) =
        common::decision_at(&cfg(), "cd /etc || true && cp /tmp/s f.txt", "/tmp/proj");
    assert_eq!(v, "ask");
}

#[test]
fn the_or_branch_entry_member_is_never_certified() {
    // Task 4 review, CRITICAL 2: in `a || b && c`, b ran only if a failed;
    // c's execution does not prove b ran, so a's moved branch survives.
    let (v, _) = common::decision_at(
        &cfg(),
        "cd /etc || cd /tmp/vouch-absent-b && cp /tmp/s f.txt",
        "/tmp/proj",
    );
    assert_eq!(v, "ask");
}

#[test]
fn a_conditional_and_member_keeps_run_doubt_whatever_exists() {
    // Task 4 review, CRITICAL 3: the refinement discharges FAILURE doubt
    // only. A second && member may never run — its predecessor here cannot
    // succeed — so however real /tmp is, the caller's own directory
    // survives as a candidate and escapes.
    let (v, _) = common::decision_at(
        &cfg(),
        "cd /etc/vouch-no-such-dir && cd /tmp; cp /tmp/s f.txt",
        "/etc",
    );
    assert_eq!(v, "ask");
}

#[test]
fn a_certified_mover_keeps_its_singleton() {
    // cd A && write: the write running proves the cd succeeded.
    let (v, r) = common::decision_at(&cfg(), "cd /tmp/proj && echo x > f.txt", "/etc");
    assert_eq!(v, "allow", "{r}");
}

#[test]
fn an_or_tail_writer_is_judged_at_the_refuted_state() {
    // cd A || write: the write runs only when the cd failed — the base is
    // the previous directory exactly, never A.
    let (v, r) = common::decision_at(&cfg(), "cd /etc || echo x > f.txt", "/tmp/proj");
    assert_eq!(v, "allow", "{r}");
    let (v2, _) = common::decision_at(&cfg(), "cd /tmp/proj || echo x > f.txt", "/etc");
    assert_eq!(v2, "ask");
}

#[test]
fn only_the_immediate_member_is_refuted() {
    // cd A && cd B || write: the or-tail proves only that the RUN failed at
    // its last reached member — B never survives, A might have run.
    let (v, r) = common::decision_at(
        &cfg(),
        "cd /tmp/proj/a && cd /etc || echo x > f.txt",
        "/tmp/proj",
    );
    assert_eq!(v, "allow", "{r}"); // {/tmp/proj, /tmp/proj/a} both allowed
    let (v2, _) = common::decision_at(
        &cfg(),
        "cd /etc && cd /tmp/proj || echo x > f.txt",
        "/tmp/proj",
    );
    assert_eq!(v2, "ask"); // /etc is a surviving candidate and escapes
}

#[test]
fn or_chain_after_semicolon_unions_every_branch() {
    // cd A || cd B; write — a later command certifies neither and refutes
    // neither: {A, B, previous}.
    let (v, r) = common::decision_at(
        &cfg(),
        "cd /tmp/proj/a || cd /tmp/proj/b; echo x > f.txt",
        "/tmp/proj",
    );
    assert_eq!(v, "allow", "{r}");
    let (v2, _) = common::decision_at(
        &cfg(),
        "cd /tmp/proj/a || cd /etc; echo x > f.txt",
        "/tmp/proj",
    );
    assert_eq!(v2, "ask");
}

#[test]
fn a_negated_mover_is_neither_certified_nor_refuted() {
    // ! cd A && write: the write runs when the cd FAILED — a certified-A
    // singleton would be the wrong-file allow. {A, previous} is honest.
    let (v, _) = common::decision_at(&cfg(), "! cd /etc && echo x > f.txt", "/tmp/proj");
    assert_eq!(v, "ask");
}

#[test]
fn the_cap_collapses_to_unknown_not_to_a_guess() {
    let (v, r) = common::decision_at(
        &cfg(),
        "cd a; cd b; cd c; cd d; echo x > f.txt",
        "/tmp/proj",
    );
    assert_eq!(v, "ask", "{r}");
    assert!(r.contains("unresolved_path"), "{r}");
}

#[test]
fn an_existing_target_discharges_the_failure_branch() {
    // §4.4's refinement, on its own decision rule: a mover that provably
    // runs, is not negated, and names a destination that exists keeps its
    // singleton — cd into an existing directory succeeds — while the same
    // shape aimed at a missing directory keeps both branches. The directory
    // is created by the test so existence is not machine luck.
    // Not env::temp_dir() — a sandboxed TMPDIR can sit outside every
    // allowed tree, and this assertion must read "ask" only from a wrongly
    // surviving /etc branch, never from the target itself. /tmp/** and
    // C:/tmp/** are both in the realistic allow list.
    let root = if cfg!(windows) { "C:/tmp" } else { "/tmp" };
    let existing = format!("{root}/vouch-cd-cand-{}", std::process::id());
    let dir = std::path::PathBuf::from(&existing);
    std::fs::create_dir_all(&dir).expect("create");
    let (v, r) = common::decision_at(&cfg(), &format!("cd {existing}; echo x > f.txt"), "/etc");
    std::fs::remove_dir_all(&dir).ok();
    assert_eq!(v, "allow", "existing target should discharge the /etc branch: {r}");
    let (v2, _) = common::decision_at(
        &cfg(),
        &format!("cd {existing}-missing; echo x > f.txt"),
        "/etc",
    );
    assert_eq!(v2, "ask", "a missing target keeps its failure branch");
}

#[test]
fn a_visible_cdpath_assignment_unresolves_a_relative_destination() {
    // Proven live on v0.16.0 as a wrong-base ALLOW (spec §4.2): the shell
    // lands in /x/sub while vouch composed <cwd>/sub.
    let (v, _) = common::decision_at(&cfg(), "CDPATH=/x cd sub && echo x > f.txt", "/tmp/proj");
    assert_eq!(v, "ask");
}

// --- Task 6: body candidates (design §3.3 / §4.2) --------------------------

#[test]
fn an_if_body_mover_becomes_a_candidate_after_fi() {
    // A branch body may or may not have run: {end, unmoved}. Both inside
    // the allowed tree composes to an allow; an escaping branch end asks.
    let (v, r) = common::decision_at(
        &cfg(),
        "if true; then cd /tmp/proj/sub; fi; echo x > f.txt",
        "/tmp/proj",
    );
    assert_eq!(v, "allow", "{r}");
    let (v2, _) = common::decision_at(
        &cfg(),
        "if true; then cd /etc; fi; echo x > f.txt",
        "/tmp/proj",
    );
    assert_eq!(v2, "ask");
}

#[test]
fn a_then_body_writer_is_certified_at_the_conditions_end_state() {
    // The then-branch running proves the condition list succeeded, so the
    // writer's base is the condition's certified end — a singleton.
    let (v, r) = common::decision_at(&cfg(), "if cd /tmp/proj; then echo x > f.txt; fi", "/etc");
    assert_eq!(v, "allow", "{r}");
}

#[test]
fn a_condition_mover_reaches_past_fi_as_a_candidate() {
    // The condition ran when the if-statement did; its success is unknown
    // to a later chainless reader, so {moved, unmoved} survives past fi.
    let (v, _) = common::decision_at(&cfg(), "if cd /etc; then :; fi; echo x > f.txt", "/tmp/proj");
    assert_eq!(v, "ask");
}

#[test]
fn a_loop_condition_mover_poisons_the_body_and_after() {
    // Iteration carry: the condition's mover runs every pass, so neither
    // the body nor anything after the loop has a knowable base.
    let (v, _) =
        common::decision_at(&cfg(), "while cd ..; do echo x > f.txt; done", "/tmp/proj/deep");
    assert_eq!(v, "ask");
    let (v2, _) =
        common::decision_at(&cfg(), "while cd ..; do :; done; echo x > f.txt", "/tmp/proj/deep");
    assert_eq!(v2, "ask");
}

#[test]
fn a_moverless_loop_body_writer_is_anchored() {
    let (v, r) = common::decision_at(
        &cfg(),
        "cd /tmp/proj && for f in a b; do echo x > f.txt; done",
        "/etc",
    );
    assert_eq!(v, "allow", "{r}");
}

#[test]
fn a_last_pipeline_member_mover_is_a_candidate_not_contained() {
    // zsh runs the last member in the parent (spec §3.3): {moved, unmoved}.
    let (v, _) = common::decision_at(&cfg(), "true | cd /etc; echo x > f.txt", "/tmp/proj");
    assert_eq!(v, "ask");
    let (v2, r2) =
        common::decision_at(&cfg(), "true | cd /tmp/proj/sub; echo x > f.txt", "/tmp/proj");
    assert_eq!(v2, "allow", "{r2}");
}

#[test]
fn an_async_list_member_mover_is_a_candidate() {
    // zsh backgrounds only the last pipeline; the earlier member's cd may
    // move the parent — and when both branches stay inside the allowed
    // tree, the union composes to an allow.
    let (v, _) = common::decision_at(&cfg(), "cd /etc && sleep 1 & echo x > f.txt", "/tmp/proj");
    assert_eq!(v, "ask");
    let (v2, r2) = common::decision_at(
        &cfg(),
        "cd /tmp/proj/sub && sleep 1 & echo x > f.txt",
        "/tmp/proj",
    );
    assert_eq!(v2, "allow", "{r2}");
}

#[test]
fn a_brace_groups_end_composes_with_its_anchors_certainty() {
    // A reached brace group always runs; a chainless later reader still
    // holds {end, unmoved}, and with both inside the allowed tree that is
    // an allow — the Task 3 blanket Unknown asked here.
    let (v, r) =
        common::decision_at(&cfg(), "{ cd /tmp/proj/sub; }; echo x > f.txt", "/tmp/proj");
    assert_eq!(v, "allow", "{r}");
    let (v2, _) = common::decision_at(&cfg(), "{ cd /etc; }; echo x > f.txt", "/tmp/proj");
    assert_eq!(v2, "ask");
}

#[test]
fn a_negated_condition_is_never_certified_by_its_then_branch() {
    // `if ! cd X; then write; fi` — the then-branch running proves the cd
    // FAILED, so the writer's base is the caller's own directory, never X.
    // Certifying X here was the inverted-status wrong-file allow: with X
    // inside the allowed area and the caller outside it, the write went
    // through against a directory the shell provably left alone.
    let absent = "/tmp/vouch-absent-negcond";
    assert_absent(absent);
    let (v, _) = common::decision_at(
        &cfg(),
        &format!("if ! cd {absent}; then echo x > f.txt; fi"),
        "/etc",
    );
    assert_eq!(v, "ask", "the caller's own /etc branch must survive");
}

#[test]
fn an_elif_condition_is_not_certified_by_the_statement_running() {
    // An elif condition runs only when every earlier condition failed, so
    // even a reader that certifies the whole if-statement holds both its
    // branches. With the elif's mover escaping, the union asks.
    let (v, _) = common::decision_at(
        &cfg(),
        "if false; then :; elif cd /etc; then :; fi && echo x > f.txt",
        "/tmp/proj",
    );
    assert_eq!(v, "ask");
}

#[test]
fn a_rescued_condition_mover_keeps_its_failure_branch() {
    // Task 6 review, BLOCKER 1: `if cd X || true; then write` — the list
    // succeeding proves nothing about the cd, which `true` may have
    // rescued; the then-writer's base holds both branches and the caller's
    // own directory escapes.
    let (v, _) = common::decision_at(
        &cfg(),
        "if cd /tmp/proj || true; then echo x > f.txt; fi",
        "/etc",
    );
    assert_eq!(v, "ask");
}

#[test]
fn an_elif_body_is_gated_by_its_own_condition() {
    // Task 6 review, BLOCKER 2: the elif body running proves ITS condition
    // succeeded — `cd /etc` provably happened, so the write asks. Pairing
    // with the first condition made that mover invisible.
    let (v, _) = common::decision_at(
        &cfg(),
        "if false; then :; elif cd /etc; then echo x > f.txt; fi",
        "/tmp/proj",
    );
    assert_eq!(v, "ask");
    let (v2, _) = common::decision_at(
        &cfg(),
        "if false; then :; elif cd /etc && false; then :; else echo x > f.txt; fi",
        "/tmp/proj",
    );
    assert_eq!(v2, "ask", "the else body inherits the elif condition's moved branch");
}

#[test]
fn a_body_anchors_moved_branch_survives_refutation() {
    // Task 6 review's refutation row: the or-tail proves the COMPOUND
    // exited nonzero, which says nothing about the cd inside it — the
    // write runs inside the moved directory.
    let (v, _) = common::decision_at(
        &cfg(),
        "true && { cd /etc; false; } || echo x > f.txt",
        "/tmp/proj",
    );
    assert_eq!(v, "ask");
}

#[test]
fn a_compound_rescuer_still_unions_the_condition_mover() {
    // Task 6 re-review, R1: the rescuing alternative is a brace group — a
    // SCOPE, not a command — so the || boundary is visible only on the
    // body anchor's chain. The list succeeding still proves nothing about
    // the cd.
    let (v, _) = common::decision_at(
        &cfg(),
        "if cd /tmp/proj || { true; }; then echo x > f.txt; fi",
        "/etc",
    );
    assert_eq!(v, "ask");
    let (v2, _) = common::decision_at(
        &cfg(),
        "if cd /tmp/proj || ( true ); then echo x > f.txt; fi",
        "/etc",
    );
    assert_eq!(v2, "ask");
}

#[test]
fn only_the_final_statement_of_a_condition_list_is_certified() {
    // Task 6 re-review, R2: a `;`-separated condition list's exit status is
    // its LAST statement's, so an earlier statement's mover keeps its
    // failure branch — bash lands this write at /etc/ssl/f.txt when the
    // first cd fails and `cd ssl` succeeds from /etc.
    let (v, _) = common::decision_at(
        &cfg(),
        "if cd /tmp/vouch-absent-seq; cd ssl; then echo x > f.txt; fi",
        "/etc",
    );
    assert_eq!(v, "ask");
    let (v2, _) = common::decision_at(
        &cfg(),
        "if cd /tmp/vouch-absent-seq; true; then echo x > f.txt; fi",
        "/etc",
    );
    assert_eq!(v2, "ask");
}

#[test]
fn a_failed_leading_run_never_outranks_the_rescuing_or_tail() {
    // Task 6 re-review round 3: in a mixed chain the final member is the
    // or-tail, whatever Seq positions the leading and-run's members carry —
    // ranking a leading member final certified the mover whose failure is
    // exactly what let the list survive. All six spellings land the write
    // at the caller's own /etc in real bash and zsh.
    for cmd in [
        "if cd /tmp/proj && false || true; then echo x > f.txt; fi",
        "if cd /tmp/proj && ls || true; then echo x > f.txt; fi",
        "if ls && cd /tmp/proj || true; then echo x > f.txt; fi",
        "if ls && cd /tmp/proj || cd /tmp/proj2; then echo x > f.txt; fi",
        "if ls && ls && cd /tmp/proj || true; then echo x > f.txt; fi",
        "if ls && cd /tmp/proj || true && ls; then echo x > f.txt; fi",
    ] {
        let (v, r) = common::decision_at(&cfg(), cmd, "/etc");
        assert_eq!(v, "ask", "{cmd}: {r}");
    }
    // The genuinely-certified trailing mover keeps its singleton: success
    // proves the cd after the rescue ran and succeeded.
    let (v, r) = common::decision_at(
        &cfg(),
        "if cd /tmp/proj || true && cd /private/tmp; then echo x > f.txt; fi",
        "/etc",
    );
    assert_eq!(v, "allow", "{r}");
}

// --- Task 7: cause wording (M2.37, M2.48) ----------------------------------

#[test]
fn a_stack_rotate_names_the_stack_not_a_subshell() {
    let (v, r) = common::decision_at(&cfg(), "pushd +1; echo x > f.txt", "/tmp/proj");
    assert_eq!(v, "ask");
    assert!(r.contains("directory stack"), "{r}");
    assert!(!r.contains("subshell"), "the old catch-all list is gone: {r}");
}

#[test]
fn an_unanchored_writer_names_its_own_position() {
    // M2.37: the WRITE's position is the unprovable thing — no directory
    // change anywhere on the line is at fault, and the wording says so.
    let (v, r) =
        common::decision_at(&cfg(), "cd /tmp/proj; f() { echo x > f.txt; }", "/tmp/proj");
    assert_eq!(v, "ask");
    assert!(r.contains("position"), "{r}");
    assert!(!r.contains("cannot order"), "no cd is the cause here: {r}");
}

#[test]
fn a_loop_mover_names_iteration_carry() {
    let (v, r) =
        common::decision_at(&cfg(), "while cd ..; do echo x > f.txt; done", "/tmp/proj/deep");
    assert_eq!(v, "ask");
    assert!(r.contains("loop"), "{r}");
}

#[test]
fn an_unresolvable_mover_destination_keeps_its_precise_cause() {
    // The pre-existing per-site sentence, untouched by the cause split —
    // the UNREAD_DEST_CD strings are pinned verbatim in bash_writes_test.
    let (v, r) = common::decision_at(&cfg(), "cd \"$D\"; echo x > f.txt", "/tmp/proj");
    assert_eq!(v, "ask");
    assert!(r.contains("somewhere vouch cannot resolve"), "{r}");
}

#[test]
fn the_new_causes_are_pinned_verbatim() {
    // M2.48's standard, applied to the causes this branch minted: pinned
    // as full sentences so a future edit cannot quietly reword one while
    // the census still buckets by the engine's own constants.
    let (v, r) =
        common::decision_at(&cfg(), "while cd ..; do echo x > f.txt; done", "/tmp/proj/deep");
    assert_eq!(v, "ask");
    assert!(r.contains(vouch::engine::LOOP_CD), "{r}");
    let (v2, r2) =
        common::decision_at(&cfg(), "cd /tmp/proj; f() { echo x > f.txt; }", "/tmp/proj");
    assert_eq!(v2, "ask");
    assert!(r2.contains(vouch::engine::UNPLACED_POS_CD), "{r2}");
    let (v3, r3) = common::decision_at(&cfg(), "pushd +1; echo x > f.txt", "/tmp/proj");
    assert_eq!(v3, "ask");
    assert!(r3.contains(vouch::engine::STACK_CD), "{r3}");
}

#[test]
fn a_run_certain_certifiable_anchor_composes_as_an_ordinary_mover() {
    // §3.3's brace row: an unconditionally anchored group's end state
    // composes as an ordinary mover would. The chainless anchor needs no
    // reader — its run-certainty is the movers' own always-runs notion —
    // and its composed `plain_end` keeps every inner failure branch §4.4
    // does not discharge (landing review, finding 1).
    let (v, r) = common::decision_at(&cfg(), "{ cd /tmp; }; cp /tmp/s f.txt", "/etc");
    assert_eq!(v, "allow", "a chainless brace anchor is an ordinary mover: {r}");
    let (v2, r2) = common::decision_at(&cfg(), "if cd /tmp; then :; fi; cp /tmp/s f.txt", "/etc");
    assert_eq!(v2, "allow", "the whole if-statement composes its condition's end: {r2}");
    let (v3, _) = common::decision_at(&cfg(), "false && { cd /tmp; }; cp /tmp/s f.txt", "/etc");
    assert_eq!(v3, "ask", "a later chain member's anchor is not run-certain");
    let (v4, _) = common::decision_at(&cfg(), "! { cd /tmp; }; cp /tmp/s f.txt", "/etc");
    assert_eq!(v4, "ask", "a negated head never composes as certain");
    // The contested position (landing delta review, finding 2): an or-tail
    // reader after the run-certain anchor. The `cp` runs only when the
    // brace FAILED, yet the anchor's replace drops the pre-anchor /etc —
    // licensed by §4.4's existing-target premise, the same accepted
    // residue the plain `cd /tmp && true || write` spelling already ships.
    // This pin makes the coupling loud: narrow §4.4 and this leg goes red.
    let (v5, r5) =
        common::decision_at(&cfg(), "{ cd /tmp; } && true || cp /tmp/s f.txt", "/etc");
    assert_eq!(v5, "allow", "the anchor inherits the walk's §4.4 residue: {r5}");
}

#[test]
fn a_condition_lists_success_end_is_never_broader_than_its_plain_end() {
    // success_end carries the walk's own §4.4 discharge arm: a run-certain,
    // un-negated mover whose target provably exists keeps its singleton
    // under "given the list succeeded" exactly as it does unconditionally.
    // Without the mirror, this shape's then-body started at a STRICT
    // superset of the same scope's plain_end (landing review, finding 2).
    let (v, r) =
        common::decision_at(&cfg(), "if cd /tmp; true; then cp /tmp/s f.txt; fi", "/etc");
    assert_eq!(v, "allow", "{r}");
    // The mirror's reach (landing delta review, finding 2): an or-rescued
    // condition list and an or-rescued anchor both discharge the same way,
    // on §4.4's existing-target premise. Corpus-absent shapes — these legs
    // are the only thing holding them.
    let (v2, r2) = common::decision_at(
        &cfg(),
        "if { cd /tmp; } || true; then cp /tmp/s f.txt; fi",
        "/etc",
    );
    assert_eq!(v2, "allow", "an or-rescued anchor discharges on the §4.4 premise: {r2}");
    let (v3, r3) =
        common::decision_at(&cfg(), "if cd /tmp || true; then echo x > f.txt; fi", "/etc");
    assert_eq!(v3, "allow", "an or-rescued run-certain mover discharges the same way: {r3}");
}

#[test]
fn the_outermost_process_boundary_decides_containment() {
    // §3.3's composition rule: `{ cd A; } | cat` is contained BY the
    // pipeline (first member, a process boundary) brace row notwithstanding,
    // while `cat | { cd A; }` is the last-member case and reaches the parent
    // as a candidate. Both legs in one test so neither can drift alone.
    let (v, _) = common::decision_at(&cfg(), "{ cd /etc; } | cat; cp /tmp/s f.txt", "/tmp/proj");
    assert_eq!(v, "allow", "a boundary-contained mover never reaches the parent");
    let (v2, r2) = common::decision_at(&cfg(), "cat | { cd /etc; }; cp /tmp/s f.txt", "/tmp/proj");
    assert_eq!(v2, "ask", "the last pipeline member may move the parent: {r2}");
}

#[test]
fn a_certified_final_member_survives_an_earlier_or_boundary() {
    // `(cd A || true) && cd B` succeeding proves only the FINAL member ran
    // and succeeded — B replaces, A keeps its failure branch. The
    // and_run_from carry across `&&` after a `||` is what makes this work,
    // and nothing else pins that carry through success_end's virtual reader.
    let (v, r) = common::decision_at(
        &cfg(),
        "if cd /etc || true && cd /tmp; then cp /tmp/s f.txt; fi",
        "/tmp/proj",
    );
    assert_eq!(v, "allow", "the certified final member is the whole answer: {r}");
    let (v2, _) = common::decision_at(
        &cfg(),
        "if cd /tmp && cd /etc || true; then cp /tmp/s f.txt; fi",
        "/tmp/proj",
    );
    assert_eq!(v2, "ask", "an or-tail final member certifies nothing before the entry");
}

#[test]
fn a_condition_inside_a_loop_body_recovers_from_the_poisoned_start() {
    // The loop body starts Unknown (iteration carry), and a certifiable
    // condition list inside it composes an ABSOLUTE mover back to a known
    // base — the Poison start must not be a permanent floor.
    let (v, r) = common::decision_at(
        &cfg(),
        "for i in 1; do if cd /tmp; then cp /tmp/s f.txt; fi; done",
        "/etc",
    );
    assert_eq!(v, "allow", "{r}");
    let (v2, _) = common::decision_at(
        &cfg(),
        "for i in 1; do cp /tmp/s f.txt; cd /tmp; done",
        "/etc",
    );
    assert_eq!(v2, "ask", "a position BEFORE the loop's first mover stays unknown");
}

#[test]
fn sibling_case_branches_are_mutually_exclusive() {
    // Each branch body anchors at the `case` itself, so one branch's mover
    // never enters a sibling branch's base — while both still reach the
    // parent as candidates after `esac`.
    let (v, r) = common::decision_at(
        &cfg(),
        "case x in a) cd /etc;; x) cp /tmp/s f.txt;; esac",
        "/tmp/proj",
    );
    assert_eq!(v, "allow", "a sibling branch's mover is not in this branch's base: {r}");
    let (v2, _) = common::decision_at(
        &cfg(),
        "case x in x) cd /etc;; esac; cp /tmp/s f.txt",
        "/tmp/proj",
    );
    assert_eq!(v2, "ask", "after esac the branch outcome is a candidate");
}
