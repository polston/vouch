//! Set-aware consumers outside the timeline (Task 5 of the
//! cd-scope-and-candidates plan; design doc §4.3): every consumer judges
//! each candidate independently and merges fail-closed — writes push one
//! target per candidate, a grant needs every candidate proven inside, a
//! restriction applies on any candidate inside, run-dir values compose per
//! member, and provenance sentences refuse non-singletons.
//!
//! Ask-expecting shapes whose movers are uncertified aim at targets proven
//! absent, since the §4.4 refinement reads the live filesystem.

#[path = "common/mod.rs"]
mod common;

const ABSENT: &str = "/tmp/vouch-consumers-absent-fixture";

fn assert_absent() {
    assert!(
        !std::path::Path::new(ABSENT).exists(),
        "precondition: {ABSENT} must not exist on the deciding machine"
    );
}

#[test]
fn a_program_write_asks_naming_the_escaping_candidate() {
    // §4.3 write judging for PROGRAM writes (cp's claim, not a redirect):
    // one pushed target per candidate, so the ask names the escaping
    // candidate's own composed path instead of a generic plural collapse.
    assert_absent();
    let (v, r) = common::decision_at(
        &common::realistic_config(),
        &format!("cd {ABSENT}; cp /tmp/s f.txt"),
        "/etc",
    );
    assert_eq!(v, "ask", "{r}");
    assert!(r.contains("etc/f.txt"), "the ask names the escaping candidate's path: {r}");
    // The allow direction: both candidates inside the allowed area.
    let (v2, r2) = common::decision_at(
        &common::realistic_config(),
        &format!("cd {ABSENT}; cp /tmp/s f.txt"),
        "/tmp/proj-elsewhere",
    );
    assert_eq!(v2, "allow", "{r2}");
}

#[test]
fn a_here_write_pushes_every_candidate() {
    // The here_write run-dir destination (`git init` writes into the
    // directory it runs from): the one site a scalar reading would silently
    // take one member.
    assert_absent();
    let (v, r) = common::decision_at(
        &common::realistic_config(),
        &format!("cd {ABSENT}; git init"),
        "/etc",
    );
    assert_eq!(v, "ask", "{r}");
    let (v2, r2) = common::decision_at(
        &common::realistic_config(),
        &format!("cd {ABSENT}; git init"),
        "/tmp/proj-elsewhere",
    );
    assert_eq!(v2, "allow", "{r2}");
}

fn zone_cfg(run_table: &str) -> vouch::config::Config {
    // Built by hand rather than through the realistic config: these tests
    // need `unmodeled_command = "ask"` (so the zone is the only thing that
    // can recognise frobnicate) AND a `[run]` table, and the realistic
    // text already defines the construct table, so appending both would be
    // a duplicate-key parse error.
    vouch::config::load(&format!(
        r#"
version = 1
[lang.bash]
default = "allow"
[lang.bash.constructs]
unmodeled_command = "ask"
[write]
default = "ask"
allow_paths = ["/tmp/**", "/private/tmp/**"]
{run_table}
"#
    ))
    .expect("parses")
}

#[test]
fn a_trust_zone_grant_requires_a_proven_singleton_inside() {
    // §4.3 names the target rule (a grant requires EVERY candidate proven
    // inside); what ships is narrower on the grant side, and this pin
    // spells it: the run-place consumers collapse any non-singleton to
    // Unknown, so only a proven SINGLETON inside the zone grants — even a
    // set whose every member is inside stays refused (M2.228). Every
    // restriction direction is fail-closed under the collapse. frobnicate
    // is unmodeled, so the zone is the only thing that can recognise it.
    let cfg = zone_cfg("[run]\ntrust_all_under = [\"/tmp/zone-proj/**\"]");
    let (v, r) = common::decision_at(&cfg, "cd /tmp/zone-proj/sub && frobnicate", "/etc");
    assert_eq!(v, "allow", "a certified singleton inside the zone is recognised: {r}");
    assert!(
        !std::path::Path::new("/tmp/zone-proj").exists(),
        "precondition: /tmp/zone-proj must not exist, or the refinement would prove the move"
    );
    let (v2, _) = common::decision_at(&cfg, "cd /tmp/zone-proj/sub; frobnicate", "/etc");
    assert_eq!(v2, "ask", "a candidate set grants nothing");
    let (v3, _) =
        common::decision_at(&cfg, "cd /tmp/zone-proj/sub; frobnicate", "/tmp/zone-proj/x");
    assert_eq!(v3, "ask", "every member inside still grants nothing until M2.228");
}

#[test]
fn a_distrust_zone_applies_on_any_candidate() {
    // A restriction applies if ANY candidate is inside: ls is recognised
    // everywhere, but one surviving candidate under the distrust tree
    // strips that recognition.
    // No absent-path precondition: a restriction applies on a proven-inside
    // place AND on an unproven one, so this holds whether or not the zone
    // directory exists.
    let cfg = common::realistic_config_with(
        "[run]\ntrust_nothing_under = [\"/tmp/quarantine-zone/**\"]\n",
    );
    let (v, _) = common::decision_at(
        &cfg,
        "cd /tmp/quarantine-zone/sub; ls",
        "/tmp/proj-elsewhere",
    );
    assert_eq!(v, "ask", "one quarantined candidate is enough to distrust");
}

#[test]
fn a_place_scoped_guard_override_tightens_on_any_candidate() {
    // A stricter override applies if ANY candidate is inside its tree.
    // No absent-path precondition, same reasoning as the distrust test.
    let cfg = common::realistic_config_with(concat!(
        "[guards]\ndelete_recursive = \"allow\"\n",
        "[[run.guards]]\nunder = [\"/tmp/tightened-zone/**\"]\ndelete_recursive = \"ask\"\n",
    ));
    let (v, r) = common::decision_at(
        &cfg,
        "cd /tmp/tightened-zone/sub; rm -rf build",
        "/tmp/proj-elsewhere",
    );
    assert_eq!(v, "ask", "one tightened candidate applies the stricter action: {r}");
}

#[test]
fn an_unplaceable_member_never_skips_a_later_members_target() {
    // Task 5 review, F1: with no working directory, `cd C:/proj` unions
    // {NoDirectory, C:/proj}; the drive-relative target C:x is unplaceable
    // under the first member and composes to C:/proj/x under the second.
    // Every member is judged, so the deny under the composed target must
    // still fire — a break after the first member's Nowhere lost it.
    let cfg = vouch::config::load(
        "[lang.bash]\ndefault = \"allow\"\n[lang.bash.constructs]\nunmodeled_command = \"allow\"\n[write]\ndefault = \"allow\"\ndeny_paths = [\"C:/proj/**\"]",
    )
    .expect("parses");
    let d = vouch::engine::decide_command_in(&cfg, "bash", "cd C:/proj; cp /tmp/s C:x", Some("C:/Users/dev"), None);
    assert!(
        matches!(d, vouch::protocol::Decision::Deny(_)),
        "the later member's composed target must reach the fold: {d:?}"
    );
}

#[test]
fn a_wrapped_snippets_start_carries_every_candidate() {
    // Task 5 review, F2: the snippet scope's start is the wrapper's base
    // per CANDIDATE, so a relative write inside the snippet is judged under
    // each member instead of one flattened plural Unknown.
    assert_absent();
    let (v, r) = common::decision_at(
        &common::realistic_config(),
        &format!("cd {ABSENT}; bash -c 'echo x > f.txt'"),
        "/etc",
    );
    assert_eq!(v, "ask", "{r}");
    assert!(r.contains("etc/f.txt"), "the ask names the escaping candidate's path: {r}");
    let (v2, r2) = common::decision_at(
        &common::realistic_config(),
        &format!("cd {ABSENT}; bash -c 'echo x > f.txt'"),
        "/tmp/proj-elsewhere",
    );
    assert_eq!(v2, "allow", "{r2}");
}

#[test]
fn a_relative_run_dir_flag_composes_per_candidate() {
    // git -C sub moves THIS command; sub composes against both candidates,
    // and the escaping composition asks.
    assert_absent();
    let (v, r) = common::decision_at(
        &common::realistic_config(),
        &format!("cd {ABSENT}; git -C sub init"),
        "/etc",
    );
    assert_eq!(v, "ask", "{r}");
    let (v2, r2) = common::decision_at(
        &common::realistic_config(),
        &format!("cd {ABSENT}; git -C sub init"),
        "/tmp/proj-elsewhere",
    );
    assert_eq!(v2, "allow", "{r2}");
}
