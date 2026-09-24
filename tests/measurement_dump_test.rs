//! Tests for M2.106: Deduplication of on-demand verdict measurement dumps.
//!
//! Verifies that the unified corpus evaluation, formatters, and fast derivation
//! (`decisions_tsv_to_jsonl`) produce consistent, byte-identical or schema-faithful
//! outputs without redundant evaluation passes.

#[path = "common/mod.rs"]
mod common;

#[test]
fn tsv_to_jsonl_derivation_preserves_indices_and_verdicts() {
    let tsv_input = "0\tALLOW\tallowed by policy\n1\tASK\tcould not read command\n2\tDENY\twrote to protected path\n";
    let derived = common::decisions_tsv_to_jsonl(tsv_input);
    let expected = "{\"i\":0,\"verdict\":\"allow\"}\n{\"i\":1,\"verdict\":\"ask\"}\n{\"i\":2,\"verdict\":\"deny\"}\n";
    assert_eq!(derived, expected);
}

#[test]
fn formatters_and_derivation_are_byte_equivalent() {
    let rows = common::synthetic();
    let cfg = common::realistic_config();
    let sample_rows: Vec<common::Row> = rows.into_iter().take(20).collect();

    let decisions = common::evaluate_corpus_rows(&cfg, &sample_rows);
    let tsv = common::format_decisions_tsv(&decisions);
    let jsonl_direct = common::format_per_row_jsonl(&decisions);
    let jsonl_derived = common::decisions_tsv_to_jsonl(&tsv);

    assert_eq!(
        jsonl_derived, jsonl_direct,
        "deriving JSONL from TSV must be byte-identical to direct JSONL formatting"
    );
}

#[test]
fn dual_dump_writes_both_formats_in_single_evaluation() {
    let tag = format!("vouch_test_dump_{}", std::process::id());
    let dir = std::env::temp_dir().join(tag);
    let _ = std::fs::create_dir_all(&dir);
    let tsv_path = dir.join("decisions.tsv");
    let jsonl_path = dir.join("per_row.jsonl");

    let rows = common::synthetic();
    let sample: Vec<common::Row> = rows.into_iter().take(10).collect();
    let cfg = common::realistic_config();

    // Set both environment variables to trigger dual-dump in dump_every_row_under
    std::env::set_var("VOUCH_DUMP_DECISIONS", tsv_path.to_str().unwrap());
    std::env::set_var("VOUCH_DUMP_PER_ROW", jsonl_path.to_str().unwrap());

    common::dump_every_row_under(cfg, &sample);

    std::env::remove_var("VOUCH_DUMP_DECISIONS");
    std::env::remove_var("VOUCH_DUMP_PER_ROW");

    assert!(tsv_path.exists(), "TSV dump file must exist");
    assert!(jsonl_path.exists(), "JSONL dump file must exist");

    let tsv_content = std::fs::read_to_string(&tsv_path).expect("read tsv");
    let jsonl_content = std::fs::read_to_string(&jsonl_path).expect("read jsonl");

    assert_eq!(
        common::decisions_tsv_to_jsonl(&tsv_content),
        jsonl_content,
        "dual-dump outputs must agree"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
