//! On-demand measurement: one JSON verdict per corpus row, for diffing one
//! build's decisions against another's — an aggregate cannot see compensating
//! moves.
//!
//! The decide call mirrors `replay_test`'s row-deciding line exactly
//! (`decide_command_in` with `home = Some("C:/Users/dev")`, no project root) so
//! this dump measures the same thing the replay measures — NOT `decide_bash`,
//! which passes `home: None` and would silently measure something else.
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
        (cfg, "evaluated_input override (bash+python evaluated_input=ask)")
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
        (common::realistic_config(), "standing replay (unmodeled_command=allow)")
    };
    let mut out = String::new();
    for (i, r) in rows.iter().enumerate() {
        let d = vouch::engine::decide_command_in(&cfg, "bash", &r.cmd, Some("C:/Users/dev"), None);
        let v = match d {
            vouch::protocol::Decision::Allow(_) => "allow",
            vouch::protocol::Decision::Ask(_) => "ask",
            vouch::protocol::Decision::Deny(_) => "deny",
            vouch::protocol::Decision::Abstain => "abstain",
        };
        out.push_str(&format!("{{\"i\":{i},\"verdict\":\"{v}\"}}\n"));
    }
    std::fs::write(&path, out).unwrap();
    println!("MEASURE per-row dump written to {path}: {} rows, under {which}", rows.len());
}
