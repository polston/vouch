//! On-demand measurement: the per-row decision baseline over the real corpus.
//!
//! For every row, one `<index>\tVERDICT\t<reason first line>` line, written to
//! the path named by `VOUCH_DUMP_DECISIONS`. Diff one build's dump against
//! another's to build a transition matrix — an aggregate cannot see compensating
//! moves, which is the whole reason this exists.
//!
//! Not a test: it asserts nothing and no gate runs it. `cargo test` compiles it on
//! every whole-suite run, so it cannot rot unnoticed between the day it is written
//! and the day a number is wanted.
//!
//! Run: `VOUCH_DUMP_DECISIONS=<absolute path> cargo run --release --example dump_decisions`
//!
//! Pass an ABSOLUTE destination. A relative one resolves against the invocation
//! directory rather than the package root, and the conventional dump patterns in
//! `.gitignore` only cover `tests/fixtures/`, so a relative path can put
//! corpus-derived output at an untracked-but-unignored place inside the tree.
//!
//! `VOUCH_DUMP_CONFIG` selects which config the rows are judged under. Unset
//! (or `"standing"`) dumps `realistic_config()`, the operator's default.
//! `"callback_argument_allow"` dumps the same config with
//! `lang.python.constructs.callback_argument` set to `allow` — the second
//! config a decision-behaviour replay must also cover (task 4 review round
//! 3), since a change that only ever gets exercised under the construct's ask
//! default could hide a compensating move that only shows up once it is
//! allowed. Any other value is refused rather than silently read as the
//! default, so a typo in the variable produces an error, not a wrong dump.

#[path = "../tests/common/mod.rs"]
mod common;

fn main() {
    let rows = common::rows_for_measurement();
    let cfg = match std::env::var("VOUCH_DUMP_CONFIG").ok().as_deref() {
        None | Some("standing") => common::realistic_config(),
        Some("callback_argument_allow") => common::realistic_config_with_construct(
            "python",
            "callback_argument",
            vouch::config::Action::Allow,
        ),
        Some(other) => panic!(
            "VOUCH_DUMP_CONFIG={other:?} is not recognised (expected unset, \
             \"standing\", or \"callback_argument_allow\")"
        ),
    };
    common::dump_every_row_under(cfg, &rows);
}
