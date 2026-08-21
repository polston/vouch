//! On-demand measurement: the per-row decision dump under
//! `[lang.python.constructs] unmodeled_command = "ask"`.
//!
//! The standing replay config ALLOWS an unmodeled python call, so a replay
//! measures vouch's own defects rather than an unset policy — but that allow also
//! hides the entire effect of DESCRIBING a python name, because an undescribed
//! call already allowed. Under this setting a described name is the only thing
//! that can allow, so this dump's ask-to-allow rows are the per-snippet effect of
//! the shipped vocabulary.
//!
//! Kept rather than deleted when the eight were sorted (M2.103): the roadmap made
//! its deletion conditional on its numbers no longer being re-derived, and that
//! condition is unmet. M2.87 retires the temporary method-name entries TO ASK,
//! and this is the setting that makes that retirement visible at all — under the
//! standing config an undescribed call already allows, so the retirement would
//! show as nothing.
//!
//! The setting is mutated on the LOADED config rather than appended as TOML text:
//! `[lang.python.constructs]` is already written in `realistic_config`'s source,
//! and a second table with the same path is a duplicate-key parse error.
//!
//! Run: `VOUCH_DUMP_DECISIONS=<absolute path> cargo run --release --example dump_decisions_python_asks`

#[path = "../tests/common/mod.rs"]
mod common;

fn main() {
    let rows = common::rows_for_measurement();
    common::dump_every_row_under(
        common::realistic_config_with_construct(
            "python",
            "unmodeled_command",
            vouch::config::Action::Ask,
        ),
        &rows,
    );
}
