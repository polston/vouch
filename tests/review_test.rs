//! `vouch review` must never turn silence, or a guard, into a rule.

use vouch::journal::Record;
use vouch::outcome::Outcome;
use vouch::review::{apply, candidates, Candidate};

fn rec(id: &str, verdict: &str, reason: &str, outcome: Outcome, mode: &str, session: &str) -> Record {
    Record {
        id: id.into(),
        ts: String::new(),
        session: session.into(),
        tool: "Bash".into(),
        cmd: "some command".into(),
        verdict: verdict.into(),
        reason: reason.into(),
        mode: mode.into(),
        cwd: String::new(),
        outcome,
        lang: String::new(),
        permission_mode: String::new(),
    }
}

const CONSTRUCT_REASON: &str = "vouch stopped on: dynamic_command\n  what that means: ...";
const GUARD_REASON: &str = "vouch stopped on: delete_recursive (guard)\n  command: rm -rf x";

#[test]
fn an_executed_ask_counts_as_approval() {
    let c = candidates(&[rec("1", "ask", CONSTRUCT_REASON, Outcome::Executed, "live", "s1")]);
    assert_eq!(c.len(), 1);
    assert_eq!(c[0].approved, 1);
    assert_eq!(c[0].name, "dynamic_command");
}

#[test]
fn an_unknown_outcome_is_evidence_of_nothing() {
    // Silence is not consent. This is the defect that killed the first design.
    let c = candidates(&[rec("1", "ask", CONSTRUCT_REASON, Outcome::Unknown, "live", "s1")]);
    assert_eq!(c[0].approved, 0, "unknown must not count as approval");
    assert_eq!(c[0].denied, 0, "unknown must not count as denial either");
    assert_eq!(c[0].unknown, 1);
}

#[test]
fn a_failed_call_is_not_an_approval() {
    let c = candidates(&[rec("1", "ask", CONSTRUCT_REASON, Outcome::Failed, "live", "s1")]);
    assert_eq!(c[0].approved, 0);
}

#[test]
fn a_denied_call_is_counted_as_denied() {
    let c = candidates(&[rec("1", "ask", CONSTRUCT_REASON, Outcome::Denied, "live", "s1")]);
    assert_eq!(c[0].denied, 1);
    assert_eq!(c[0].approved, 0);
}

#[test]
fn shadow_records_are_never_evidence() {
    // vouch was not the gate, so the user was never actually asked.
    let c = candidates(&[rec("1", "ask", CONSTRUCT_REASON, Outcome::Executed, "shadow", "s1")]);
    assert!(c.is_empty(), "shadow must produce no candidates, got {c:?}");
}

#[test]
fn stood_down_records_are_never_evidence() {
    // Mode-keyed shadow suppressed the emission; nobody saw a prompt.
    let c = candidates(&[rec("1", "ask", CONSTRUCT_REASON, Outcome::Executed, "stood-down", "s1")]);
    assert!(c.is_empty(), "stood-down must produce no candidates, got {c:?}");
}

#[test]
fn allows_are_not_evidence_because_nothing_was_asked() {
    let c = candidates(&[rec("1", "allow", "allowed by vouch policy", Outcome::Executed, "live", "s1")]);
    assert!(c.is_empty(), "an allow was never a question, got {c:?}");
}

#[test]
fn a_guard_is_listed_but_never_proposable() {
    let c = candidates(&[
        rec("1", "ask", GUARD_REASON, Outcome::Executed, "live", "s1"),
        rec("2", "ask", GUARD_REASON, Outcome::Executed, "live", "s2"),
        rec("3", "ask", GUARD_REASON, Outcome::Executed, "live", "s3"),
    ]);
    assert_eq!(c.len(), 1);
    assert_eq!(c[0].approved, 3, "the evidence is still shown");
    assert!(!c[0].proposable, "a guard must never be proposable");
    assert_eq!(c[0].rule_line(), "", "a guard has no rule line");
}

#[test]
fn applying_a_guard_is_refused_even_when_asked_directly() {
    let guard = Candidate {
        name: "delete_recursive".into(),
        section: "guards".into(),
        approved: 99,
        denied: 0,
        unknown: 0,
        sessions: 9,
        proposable: false,
        blocked: Some("this is a guard. It asks every time on purpose.".into()),
        example: String::new(),
    };
    let err = apply("version = 1\n", &guard).unwrap_err();
    assert!(err.contains("ask every time"), "got: {err}");
}

#[test]
fn applying_a_construct_writes_exactly_one_line() {
    let c = Candidate {
        name: "dynamic_command".into(),
        section: "lang.bash.constructs".into(),
        approved: 5,
        denied: 0,
        unknown: 0,
        sessions: 3,
        proposable: true,
        blocked: None,
        example: String::new(),
    };
    let out = apply("version = 1\n[lang.bash.constructs]\nheredoc = \"allow\"\n", &c).unwrap();
    assert!(out.contains("dynamic_command = \"allow\""));
    assert!(out.contains("heredoc = \"allow\""), "existing rules survive");
    assert_eq!(
        out.matches("dynamic_command").count(),
        1,
        "must not duplicate"
    );
}

#[test]
fn applying_twice_is_idempotent() {
    let c = Candidate {
        name: "subshell".into(),
        section: "lang.bash.constructs".into(),
        approved: 1,
        denied: 0,
        unknown: 0,
        sessions: 1,
        proposable: true,
        blocked: None,
        example: String::new(),
    };
    let once = apply("version = 1\n", &c).unwrap();
    let twice = apply(&once, &c).unwrap();
    assert_eq!(once, twice);
}

#[test]
fn sessions_are_counted_distinctly() {
    let c = candidates(&[
        rec("1", "ask", CONSTRUCT_REASON, Outcome::Executed, "live", "s1"),
        rec("2", "ask", CONSTRUCT_REASON, Outcome::Executed, "live", "s1"),
        rec("3", "ask", CONSTRUCT_REASON, Outcome::Executed, "live", "s2"),
    ]);
    assert_eq!(c[0].approved, 3);
    assert_eq!(c[0].sessions, 2);
}

#[test]
fn a_section_name_inside_a_comment_does_not_misplace_the_rule() {
    // Regression: string-splicing matched "[lang.bash.constructs]" in a COMMENT and
    // inserted the key at top level. It parsed fine and did nothing, so
    // `--accept` reported success while the rule had no effect.
    let cfg = "version = 1\n\n# rules for [lang.bash.constructs] live below\n[lang.bash.constructs]\nheredoc = \"allow\"\n";
    let c = Candidate {
        name: "subshell".into(),
        section: "lang.bash.constructs".into(),
        approved: 1, denied: 0, unknown: 0, sessions: 1,
        proposable: true, blocked: None, example: String::new(),
    };
    let out = apply(cfg, &c).unwrap();
    let loaded = vouch::config::load(&out).expect("still valid");
    let keys: Vec<_> = loaded.lang("bash").unwrap().constructs.keys().cloned().collect();
    assert!(keys.contains(&"subshell".to_string()), "rule landed outside the table: {out}");
    assert!(keys.contains(&"heredoc".to_string()), "existing rule lost: {out}");
}

#[test]
fn accepting_preserves_comments() {
    // Rule provenance lives in comments. Losing them loses the feature.
    let cfg = "version = 1\n[lang.bash.constructs]\n# accepted 2026-07-20 after 9 approvals\nheredoc = \"allow\"\n";
    let c = Candidate {
        name: "subshell".into(),
        section: "lang.bash.constructs".into(),
        approved: 1, denied: 0, unknown: 0, sessions: 1,
        proposable: true, blocked: None, example: String::new(),
    };
    let out = apply(cfg, &c).unwrap();
    assert!(out.contains("# accepted 2026-07-20 after 9 approvals"), "comment lost: {out}");
}

#[test]
fn a_malformed_config_is_refused_not_silently_rewritten() {
    let c = Candidate {
        name: "subshell".into(),
        section: "lang.bash.constructs".into(),
        approved: 1, denied: 0, unknown: 0, sessions: 1,
        proposable: true, blocked: None, example: String::new(),
    };
    assert!(apply("version = = 1\n[[[broken", &c).is_err());
}

// --- iteration 19: what may become a rule at all ---------------------------

fn rec_named(reason: &str, tool: &str, outcome: Outcome) -> Record {
    let mut r = rec("id1", "ask", reason, outcome, "live", "s1");
    r.tool = tool.to_string();
    r
}

#[test]
fn a_prompt_reason_that_is_not_a_settable_key_is_never_proposed() {
    // "path outside every allowed area" is the verdict vouch gave, not a
    // construct. Proposing it produced `[lang.bash.constructs] path outside every
    // allowed area = "allow"` — not a valid key, and no effect if written.
    let recs = vec![rec_named(
        "vouch stopped on: path outside every allowed area",
        "Bash",
        vouch::outcome::Outcome::Executed,
    )];
    let cands = candidates(&recs);
    let c = cands.iter().find(|c| c.name.contains("outside")).expect("listed");
    assert!(!c.proposable, "a prose verdict must not be proposable");
    assert!(c.blocked.is_some(), "must say why");
    assert!(
        apply("version = 1\n", c).is_err(),
        "forcing --accept on it must be refused"
    );
}

#[test]
fn a_real_construct_key_is_still_proposable() {
    let recs = vec![rec_named(
        "vouch stopped on: heredoc",
        "Bash",
        vouch::outcome::Outcome::Executed,
    )];
    let cands = candidates(&recs);
    let c = cands.iter().find(|c| c.name == "heredoc").expect("listed");
    assert!(c.proposable, "a genuine construct must remain proposable");
    assert!(apply("version = 1\n", c).is_ok());
}

#[test]
fn a_snippet_rows_own_lang_drives_the_section_when_the_tool_has_no_knowledge_entry() {
    // Task 9: `records_from_snippets` stamps `lang` onto the row at journal
    // time. `tool` here matches no entry anywhere in the shipped
    // knowledge.toml, so a knowledge-lookup fallback would find nothing —
    // proving the section and settability come from `rec.lang` itself, not
    // from a tool-name lookup.
    let mut r = rec("1", "ask", "vouch stopped on: heredoc", Outcome::Executed, "live", "s1");
    r.tool = "mcp__p_s__batch".to_string();
    r.lang = "bash".to_string();
    let cands = candidates(&[r]);
    let c = cands.iter().find(|c| c.name == "heredoc").expect("listed");
    assert_eq!(c.section, "lang.bash.constructs", "section must come from rec.lang");
    assert!(c.proposable, "a real bash construct named by rec.lang must be settable");
}

#[test]
fn silence_is_not_consent_even_when_accept_is_forced() {
    // Ten prompts, none answered. That is evidence of nothing.
    let recs: Vec<_> = (0..10)
        .map(|_| rec_named("vouch stopped on: heredoc", "Bash", vouch::outcome::Outcome::Unknown))
        .collect();
    let cands = candidates(&recs);
    let c = cands.iter().find(|c| c.name == "heredoc").expect("listed");
    assert_eq!(c.approved, 0);
    let err = apply("version = 1\n", c).expect_err("must refuse");
    assert!(err.contains("not evidence"), "{err}");
}

#[test]
fn the_engines_own_construct_names_are_settable() {
    // Added by the engine rather than a scanner. If they are not on the known
    // list, review refuses to propose the very settings its prompts name.
    for name in ["unresolved_path", "evaluated_input"] {
        let recs = vec![rec_named(
            &format!("vouch stopped on: {name}"),
            "Bash",
            vouch::outcome::Outcome::Executed,
        )];
        let cands = candidates(&recs);
        let c = cands.iter().find(|c| c.name == name).expect("listed");
        assert!(c.proposable, "{name} should be proposable");
    }
}

#[test]
fn stopped_on_is_found_even_when_it_is_not_the_first_line() {
    // [review] "vouch stopped on:" happens to be line 1 in every OTHER
    // reason built in this file (and in every reason `src/main.rs` actually
    // constructs today, since the banner is always appended AFTER it). That
    // means a regression from scanning every line back to
    // `reason.lines().next()` would pass the entire suite without this test
    // — nothing else exercises a marker anywhere but line 1. This reason
    // puts it on the SECOND line, as it would be if anything were ever
    // printed ahead of the reason again — the exact defect this change
    // exists to prevent.
    let reason = "some other line that is not the marker\nvouch stopped on: heredoc\n  detail: x";
    let recs = vec![rec_named(reason, "Bash", vouch::outcome::Outcome::Executed)];
    let cands = candidates(&recs);
    let c = cands
        .iter()
        .find(|c| c.name == "heredoc")
        .expect("the marker on line 2 must still be found by scanning");
    assert!(c.proposable, "a genuine construct found past line 1 must still be proposable");
}

#[test]
fn accepting_creates_a_missing_section_rather_than_failing() {
    // A config that has never named a construct has no `[lang.bash.constructs]`
    // table at all. Accepting must create it, not error and not write the key
    // at top level where it parses cleanly and does nothing.
    let c = Candidate {
        name: "heredoc".into(),
        section: "lang.bash.constructs".into(),
        approved: 3,
        denied: 0,
        unknown: 0,
        sessions: 2,
        proposable: true,
        blocked: None,
        example: String::new(),
    };
    let out = apply("version = 1\n[lang.bash]\ndefault = \"allow\"\n", &c).expect("applies");
    assert!(out.contains("[lang.bash.constructs]"), "section not created: {out}");
    assert!(out.contains("heredoc"), "{out}");

    // And it must actually take effect, not merely appear in the text.
    let cfg = vouch::config::load(&out).expect("result is valid config");
    assert_eq!(
        cfg.construct_action("bash", "heredoc"),
        vouch::config::Action::Allow,
        "the written rule had no effect"
    );
}

#[test]
fn accepting_a_powershell_construct_creates_its_own_section() {
    let c = Candidate {
        name: "keyword_foreach".into(),
        section: "lang.powershell.constructs".into(),
        approved: 2,
        denied: 0,
        unknown: 0,
        sessions: 1,
        proposable: true,
        blocked: None,
        example: String::new(),
    };
    let out = apply("version = 1\n[lang.bash]\ndefault = \"allow\"\n", &c).expect("applies");
    let cfg = vouch::config::load(&out).expect("result is valid config");
    assert_eq!(
        cfg.construct_action("powershell", "keyword_foreach"),
        vouch::config::Action::Allow,
        "{out}"
    );
}
