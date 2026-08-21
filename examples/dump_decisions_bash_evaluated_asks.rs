//! On-demand measurement: the per-row decision dump under
//! `[lang.bash.constructs] evaluated_input = "ask"` — the SHELL-VISIBLE variant.
//!
//! Neither standing dump can show shell-consumer movement: an unset construct
//! inherits before it defaults, and `realistic_config` sets bash's
//! `dynamic_command = "allow"`, so a shell consumer's input channel already allows
//! there. Naming bash's own key directly overrides that inheritance, which makes
//! this the only view in which a shell-fed row can move at all.
//!
//! Run: `VOUCH_DUMP_DECISIONS=<absolute path> cargo run --release --example dump_decisions_bash_evaluated_asks`

#[path = "../tests/common/mod.rs"]
mod common;

fn main() {
    let rows = common::rows_for_measurement();
    common::dump_every_row_under(
        common::realistic_config_with_construct(
            "bash",
            "evaluated_input",
            vouch::config::Action::Ask,
        ),
        &rows,
    );
}
