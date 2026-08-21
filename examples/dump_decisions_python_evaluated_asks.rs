//! On-demand measurement: the per-row decision dump under
//! `[lang.python.constructs] evaluated_input = "ask"` — the live-shaped setting.
//!
//! The standing config allows that construct, so python-side input-channel
//! movement is invisible in the plain decision dump; this is the per-row view in
//! which it shows. Mutated on the LOADED config rather than appended as TOML text,
//! because `[lang.python.constructs]` already exists in `realistic_config`'s
//! source and a second table with the same path is a duplicate-key parse error.
//!
//! Run: `VOUCH_DUMP_DECISIONS=<absolute path> cargo run --release --example dump_decisions_python_evaluated_asks`

#[path = "../tests/common/mod.rs"]
mod common;

fn main() {
    let rows = common::rows_for_measurement();
    common::dump_every_row_under(
        common::realistic_config_with_construct(
            "python",
            "evaluated_input",
            vouch::config::Action::Ask,
        ),
        &rows,
    );
}
