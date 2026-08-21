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

#[path = "../tests/common/mod.rs"]
mod common;

fn main() {
    let rows = common::rows_for_measurement();
    common::dump_every_row_under(common::realistic_config(), &rows);
}
