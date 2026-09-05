//! On-demand measurement: one JSON verdict per corpus row, for diffing one
//! build's decisions against another's — an aggregate cannot see compensating
//! moves.
//!
//! The decide call supplies a STATED working directory (`common::HOOK_HOME`),
//! the way the census (`count_cd_order_shapes`) already does, and prints it
//! with every result.
//!
//! It did not, until 2026-09-04, and that was M2.231: the call was
//! `decide_command_in`, which is `decide_command_at(…, cwd: None)`. With no
//! working directory a relative write has no base to compose against, so the
//! `cd` walk, the candidate set and every run-place consumer were inert and
//! this harness reported a confident 0 for every directory-placement change
//! ever measured through it. A fabricated zero in the direction that looks
//! like success is §6.5's confusion one layer up, and it silently weakened
//! every no-op check taken with it.
//!
//! Two consequences, stated rather than left to be rediscovered. Numbers
//! recorded against this dump BEFORE that date are about a `cwd: None` run and
//! do not transfer. And it no longer mirrors `replay_test`'s row-deciding line,
//! which still passes no cwd: they now answer deliberately different questions
//! — the gated test pins an invariant, this harness measures movement — which
//! is exactly why the judging directory is printed rather than assumed.
//!
//! The corpus row schema carries `cmd` and `verdict` and no directory, so the
//! fixed cwd is a stated convention, not a reconstruction of where each row
//! really ran. Recording a directory per row in the fixture builder is
//! M2.231's larger half and stays open.
//!
//! The destination comes from `VOUCH_DUMP_PER_ROW` rather than a fixed path. That
//! fixed M2.81, and the defect it recorded is worth keeping in view: this used to
//! run during every ordinary `cargo test` and rewrite one committed-looking file,
//! so the "baseline" it was named for was overwritten by the very next test run —
//! and then "diff the dump against the baseline" compared the current code against
//! ITSELF and reported zero movement no matter what changed. A measurement that
//! cannot fail is worse than no measurement.
//!
//! It keeps its own loop rather than using the shared dump body, because its output
//! format differs — one JSON object per row against the other dump's tab-separated
//! verdict and reason. The two reach the verdict through the identical call, so
//! that is a duplication of format only, recorded as M2.106 and deliberately not
//! resolved here.
//!
//! Run: `VOUCH_DUMP_PER_ROW=<absolute path> cargo run --release --example dump_per_row_verdicts`
//! Add `VOUCH_DUMP_COMPARE=<absolute baseline path>` to print a counts-only
//! transition breakdown. The baseline contains only row indices and verdicts;
//! neither comparison output nor the dump includes command text.
//!
//! Pass an ABSOLUTE destination: a relative one resolves against the invocation
//! directory rather than the package root.

#[path = "../tests/common/mod.rs"]
mod common;

fn main() {
    let rows = common::rows_for_measurement();
    let path = std::env::var("VOUCH_DUMP_PER_ROW")
        .expect("set VOUCH_DUMP_PER_ROW to the output path before running this dump");
    // `VOUCH_DUMP_UNMODELED=ask` switches the dump to the LIVE-SHAPED config.
    //
    // The standing replay config sets `unmodeled_command = "allow"` so that a
    // replay measures vouch's own defects rather than an unset policy. That
    // makes it structurally unable to show one whole direction of movement:
    // under it an undescribed program already allowed, so DESCRIBING one can
    // never register as a move toward allow. A changeset whose subject is
    // recognition, reported only under this config, reads as "0 rows became
    // more permissive" while the operator's own config moves dozens (measured
    // on the branch that added this switch: 16 rows toward ask here, 39 toward
    // allow there — the same rows, the same call, one setting apart).
    //
    // `VOUCH_DUMP_EVALUATED=ask` is the standalone-flags measurement's own
    // override (spec `2026-08-20-standalone-flags-design.md` §7): the standing
    // config allows `evaluated_input` for python outright, and bash — unset
    // there — inherits `dynamic_command`'s allow through `inherits_from`, so
    // neither standing dump above can ever show a `standalone_flags` row
    // moving toward allow (the construct that would otherwise ask is already
    // allowed by inheritance or by name). This switch names `evaluated_input`
    // to ask for BOTH languages so that movement becomes visible. A named key
    // beats inheritance, so setting it once per language is sufficient — no
    // separate bash/python variant is needed.
    //
    // Two settings are two measurements, never a before/after pair (§6.6):
    // run this dump twice per end and diff each config against itself.
    let ask_unmodeled = std::env::var("VOUCH_DUMP_UNMODELED").as_deref() == Ok("ask");
    let ask_evaluated = std::env::var("VOUCH_DUMP_EVALUATED").as_deref() == Ok("ask");
    // The config and the name the banner gives it are decided together: two
    // chains over the same two switches could disagree about which measurement
    // just ran, and the banner is the only record of that in the output.
    let (cfg, which) = if ask_evaluated {
        let mut cfg = common::realistic_config_with_construct(
            "bash",
            "evaluated_input",
            vouch::config::Action::Ask,
        );
        cfg.langs
            .get_mut("python")
            .expect("realistic_config writes a [lang.python] section")
            .constructs
            .insert("evaluated_input".to_string(), vouch::config::Action::Ask);
        (
            cfg,
            "evaluated_input override (bash+python evaluated_input=ask)",
        )
    } else if ask_unmodeled {
        (
            common::realistic_config_with_construct(
                "bash",
                "unmodeled_command",
                vouch::config::Action::Ask,
            ),
            "live-shaped (unmodeled_command=ask)",
        )
    } else {
        (
            common::realistic_config(),
            "standing replay (unmodeled_command=allow)",
        )
    };
    let mut out = String::new();
    let mut current = Vec::with_capacity(rows.len());
    for (i, r) in rows.iter().enumerate() {
        // Through the shared helper, not a hand-typed `decide_command_at`.
        // That helper exists for exactly the drift M2.231 turned out to be —
        // its own doc says so — and the census this harness is now aligned
        // with already calls it. Fixing the missing cwd by retyping the call
        // would have left a second copy for the next signature change to miss.
        let (v, reason) = common::decision_at(&cfg, &r.cmd, common::HOOK_HOME);
        let cause = match v.as_str() {
            "allow" => "allow",
            "abstain" => "abstain",
            _ => movement_cause(&reason),
        };
        out.push_str(&format!("{{\"i\":{i},\"verdict\":\"{v}\"}}\n"));
        current.push((v, cause));
    }
    std::fs::write(&path, out).unwrap();
    println!(
        "MEASURE per-row dump written to {path}: {} rows, under {which}, judged at {}",
        rows.len(),
        common::HOOK_HOME
    );

    if let Ok(baseline) = std::env::var("VOUCH_DUMP_COMPARE") {
        let text = std::fs::read_to_string(&baseline).expect("comparison baseline is readable");
        let mut transitions: std::collections::BTreeMap<(&str, &str, &str), usize> =
            Default::default();
        let mut baseline_rows = 0;
        for (i, line) in text.lines().enumerate() {
            let row: serde_json::Value = serde_json::from_str(line).expect("baseline row is JSON");
            assert_eq!(row["i"].as_u64(), Some(i as u64), "baseline row index {i}");
            let old = match row["verdict"].as_str() {
                Some("allow") => "allow",
                Some("ask") => "ask",
                Some("deny") => "deny",
                Some("abstain") => "abstain",
                _ => panic!("baseline row has a known verdict"),
            };
            let (new, cause) = current.get(i).expect("baseline has no extra rows");
            if old != new.as_str() {
                *transitions.entry((old, new.as_str(), *cause)).or_default() += 1;
            }
            baseline_rows += 1;
        }
        assert_eq!(
            baseline_rows,
            current.len(),
            "baseline and tip row counts differ"
        );
        // The judging directory is repeated on the movement line on purpose:
        // a transition count that does not say where it was judged is a number
        // nobody can reproduce, and this line is the one most often quoted on
        // its own (M2.231).
        if transitions.is_empty() {
            println!("MEASURE movement: 0 rows (judged at {})", common::HOOK_HOME);
        }
        for ((old, new, cause), count) in transitions {
            println!(
                "MEASURE movement {old}->{new} via {cause}: {count} rows (judged at {})",
                common::HOOK_HOME
            );
        }
    }
}

fn movement_cause(reason: &str) -> &'static str {
    if reason.contains("unread_verb") {
        "unread_verb"
    } else if reason.contains("write.scope") || reason.contains("scope governs") {
        "write_scope_unprovable"
    } else if reason.contains("unresolved_path") {
        "unresolved_path"
    } else if reason.contains("unmodeled_command") {
        "unmodeled_command"
    } else if reason.contains("(guard)") {
        "guard"
    } else {
        "other"
    }
}
