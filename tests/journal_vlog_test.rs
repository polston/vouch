use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use vouch::config::{self, JournalFormat};
use vouch::journal::{self, JournalPolicy, OutcomeRecord, Record};
use vouch::journal_vlog::{
    append_vlog, compact_vlog, compute_bundle_seal_sha256, compute_bundle_seal_sha256_with_extra,
    compute_redacted_field_commitment, encode_record_payload, export_vlog_bundle,
    export_vlog_bundle_since, export_vlog_disclosure, export_vlog_redacted_bundle,
    export_vlog_slice_bundle, merge_vlog_bundles, parse_timestamp_arg, read_disclosed_records,
    read_records_from_vlog_bundle, read_vidx_entries, read_vlog_checkpoints, vchk_path,
    verify_redacted_field_claim, verify_vlog_bundle, verify_vlog_bundle_chain,
    verify_vlog_disclosure, verify_vlog_integrity, vidx_path, write_all_vlog, VlogBundleHeader,
    VlogDisclosureProof, VlogHeader, VlogIndexEntry, VlogReader, VlogSliceFilter, VlogTamperKind,
    VBUNDLE_DELTA_VERSION, VBUNDLE_HEADER_LEN, VBUNDLE_REDACTED_VERSION,
    VBUNDLE_REDACTION_PROOF_LEN, VBUNDLE_SLICE_HEADER_LEN, VBUNDLE_SLICE_VERSION, VBUNDLE_VERSION,
    VCHK_ENTRY_LEN, VDISCLOSURE_HEADER_LEN, VDISCLOSURE_MAGIC, VDISCLOSURE_VERSION,
    VLOG_FRAME_HEADER_LEN, VLOG_HEADER_LEN, VLOG_INDEX_ENTRY_LEN, VLOG_MAGIC,
};
use vouch::journal_wal::crc32;
use vouch::outcome::Outcome;
use vouch::tui::engine::JournalTailReader;

fn vouch_exe() -> PathBuf {
    let mut path = std::env::current_exe().expect("current_exe");
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    let bin = if cfg!(windows) { "vouch.exe" } else { "vouch" };
    path.join(bin)
}

fn unique_test_dir(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "vouch_vlog_test_{}_{}_{}",
        tag,
        std::process::id(),
        nanos
    ));
    let _ = std::fs::create_dir_all(&dir);
    dir
}

fn sample_record(idx: usize, ts: u64, verdict: &str, cmd: &str) -> Record {
    Record {
        id: format!("toolu_{idx:05}"),
        ts: ts.to_string(),
        session: "sess_neutral_01".to_string(),
        tool: "Bash".to_string(),
        cmd: cmd.to_string(),
        verdict: verdict.to_string(),
        reason: format!("reason for {cmd}"),
        mode: "live".to_string(),
        cwd: "C:/Users/dev/workspace".to_string(),
        outcome: Outcome::Pending,
        lang: "bash".to_string(),
        permission_mode: "default".to_string(),
        host: "claude".to_string(),
        count: 1,
        measurement: false,
    }
}

#[test]
fn vlog_header_and_index_entry_roundtrip_and_crc_verification() {
    let header = VlogHeader::new(42, 4096);
    let bytes = header.to_bytes();
    assert_eq!(&bytes[0..4], &VLOG_MAGIC);
    let decoded = VlogHeader::from_bytes(&bytes).expect("valid header decodes");
    assert_eq!(decoded, header);

    // Corrupt a byte in the header and verify CRC32 rejects it
    let mut corrupted = bytes;
    corrupted[10] ^= 0xFF;
    let err = VlogHeader::from_bytes(&corrupted).unwrap_err();
    assert!(err.contains("crc mismatch"), "unexpected error: {err}");

    let rec = sample_record(1, 1_700_000_123, "ask", "rm -rf /tmp/build");
    let entry = VlogIndexEntry::from_record(&rec, 128, 96);
    let entry_bytes = entry.to_bytes();
    assert_eq!(entry_bytes.len(), VLOG_INDEX_ENTRY_LEN);
    let decoded_entry = VlogIndexEntry::from_bytes(&entry_bytes).expect("entry decodes");
    assert_eq!(decoded_entry, entry);
    assert_eq!(decoded_entry.timestamp_secs, 1_700_000_123);
}

#[test]
fn vlog_append_and_mmap_reader_roundtrip() {
    let dir = unique_test_dir("append_roundtrip");
    let r1 = sample_record(1, 1000, "allow", "ls -la");
    let r2 = sample_record(2, 1005, "ask", "rm -rf /tmp/test");
    let r3 = sample_record(3, 1010, "deny", "kill -9 1");

    append_vlog(&dir, &r1).expect("append r1");
    append_vlog(&dir, &r2).expect("append r2");
    append_vlog(&dir, &r3).expect("append r3");

    let vlog_file = dir.join("journal.vlog");
    assert!(vlog_file.exists());

    let reader = VlogReader::open(&vlog_file).expect("open vlog reader");
    assert_eq!(reader.len(), 3);
    #[cfg(unix)]
    assert!(reader.is_mmap(), "Unix VlogReader should use memory-mapped buffer");

    assert_eq!(reader.get_record(0).unwrap().cmd, "ls -la");
    assert_eq!(reader.get_record(1).unwrap().cmd, "rm -rf /tmp/test");
    assert_eq!(reader.get_record(2).unwrap().cmd, "kill -9 1");
    assert_eq!(reader.tail_record().unwrap().cmd, "kill -9 1");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn vlog_binary_search_timestamp_range_and_verdict_filter() {
    let dir = unique_test_dir("seek_range");
    let mut records = Vec::with_capacity(500);
    for i in 0..500 {
        let ts = 1_700_000_000 + (i as u64) * 10;
        let verdict = match i % 3 {
            0 => "allow",
            1 => "ask",
            _ => "deny",
        };
        records.push(sample_record(i, ts, verdict, &format!("echo item_{i}")));
    }

    write_all_vlog(&dir, &records).expect("write 500 records");
    let reader = VlogReader::open(&dir.join("journal.vlog")).expect("open reader");
    assert_eq!(reader.len(), 500);

    // Seek exact timestamp window [1_700_000_500, 1_700_000_550] -> indices 50..=55 (6 records)
    let window = reader.seek_timestamp_range(1_700_000_500, 1_700_000_550);
    assert_eq!(window.len(), 6);
    assert_eq!(window.first().unwrap().cmd, "echo item_50");
    assert_eq!(window.last().unwrap().cmd, "echo item_55");

    // Filter by verdict "deny" using index-level scan
    let denies = reader.filter_by_verdict("deny");
    assert_eq!(denies.len(), 166);
    assert!(denies.iter().all(|r| r.verdict == "deny"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn vlog_self_heals_truncated_or_corrupted_index_footer() {
    let dir = unique_test_dir("self_heal");
    let r1 = sample_record(1, 2000, "allow", "git status");
    let r2 = sample_record(2, 2010, "ask", "git reset --hard");
    write_all_vlog(&dir, &[r1.clone(), r2.clone()]).expect("write initial");

    let path = dir.join("journal.vlog");
    let raw = std::fs::read(&path).unwrap();
    let header = VlogHeader::from_bytes(&raw).unwrap();

    // Simulate an interrupted write that truncated the index table in half
    let truncated_len = (header.index_offset as usize) + VLOG_INDEX_ENTRY_LEN;
    std::fs::write(&path, &raw[..truncated_len]).unwrap();

    // VlogReader should self-heal by scanning CRC32-framed data records
    let reader = VlogReader::open(&path).expect("self-healing open");
    assert_eq!(reader.len(), 2);
    assert_eq!(reader.get_record(0).unwrap().cmd, "git status");
    assert_eq!(reader.get_record(1).unwrap().cmd, "git reset --hard");

    // Appending a 3rd record onto the truncated file should rebuild the index cleanly
    let r3 = sample_record(3, 2020, "allow", "cargo test");
    append_vlog(&dir, &r3).expect("append after self-heal");

    let healed_reader = VlogReader::open(&path).expect("open after heal");
    assert_eq!(healed_reader.len(), 3);
    assert_eq!(healed_reader.tail_record().unwrap().cmd, "cargo test");

    // Verify the healed file header and index offset now match the exact file length
    let healed_bytes = std::fs::read(&path).unwrap();
    let healed_header = VlogHeader::from_bytes(&healed_bytes).unwrap();
    assert_eq!(healed_header.record_count, 3);
    assert_eq!(
        (healed_header.index_offset as usize) + 3 * VLOG_INDEX_ENTRY_LEN,
        healed_bytes.len()
    );
    assert!(healed_header.index_offset >= VLOG_HEADER_LEN as u64);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn config_parses_logging_journal_format_and_wires_journal_persistence() {
    let cfg_toml = r#"
[logging]
journal_format = "binary"
"#;
    let cfg = config::load(cfg_toml).expect("config with [logging] parses");
    assert_eq!(cfg.logging.journal_format, JournalFormat::Binary);

    let dir = unique_test_dir("config_binary_journal");
    let rec = sample_record(10, 3000, "ask", "touch /tmp/x");
    journal::append_with_format(&dir, &rec, cfg.logging.journal_format).expect("append binary");
    journal::append_outcome(
        &dir,
        &OutcomeRecord {
            id: "toolu_00010".to_string(),
            outcome: Outcome::Executed,
            detail: String::new(),
            host: "claude".to_string(),
        },
    )
    .expect("append outcome");

    assert!(dir.join("journal.vlog").exists());
    let loaded = journal::all(&dir);
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].cmd, "touch /tmp/x");
    assert_eq!(loaded[0].outcome, Outcome::Executed);
    assert_eq!(journal::last(&dir).unwrap().outcome, Outcome::Executed);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn vlog_10k_records_indexed_seek_completes_under_submillisecond_budget() {
    let dir = unique_test_dir("bench_10k");
    let mut records = Vec::with_capacity(10_000);
    for i in 0..10_000 {
        let ts = 1_750_000_000 + (i as u64);
        records.push(sample_record(
            i,
            ts,
            if i % 10 == 0 { "ask" } else { "allow" },
            &format!("git diff --stat commit_{i}"),
        ));
    }

    write_all_vlog(&dir, &records).expect("write 10k records");
    let reader = VlogReader::open(&dir.join("journal.vlog")).expect("open 10k vlog");
    assert_eq!(reader.len(), 10_000);

    let start = std::time::Instant::now();
    let found = reader.seek_timestamp_range(1_750_005_000, 1_750_005_009);
    let elapsed = start.elapsed();

    assert_eq!(found.len(), 10);
    assert_eq!(found[0].cmd, "git diff --stat commit_5000");
    assert_eq!(found[9].cmd, "git diff --stat commit_5009");
    assert!(
        elapsed.as_millis() < 25,
        "indexed binary search took too long: {elapsed:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn vlog_vidx_sidecar_and_incremental_tail_reader_streams_only_new_frames() {
    let dir = unique_test_dir("tail_stream_delta");
    let r1 = sample_record(1, 5000, "allow", "git status");
    let r2 = sample_record(2, 5001, "allow", "git diff");
    let r3 = sample_record(3, 5002, "ask", "touch /tmp/a");

    append_vlog(&dir, &r1).expect("append r1");
    append_vlog(&dir, &r2).expect("append r2");
    append_vlog(&dir, &r3).expect("append r3");

    // Verify journal.vidx sidecar was maintained alongside journal.vlog
    let sidecar = vidx_path(&dir);
    assert!(sidecar.exists(), "journal.vidx must exist after append_vlog");
    let (vidx_header, vidx_entries) = read_vidx_entries(&sidecar).expect("read vidx sidecar");
    assert_eq!(vidx_header.record_count, 3);
    assert_eq!(vidx_entries.len(), 3);

    // Attach live tail readers on both journal.vlog and journal.vidx after the first 3 records
    let mut vlog_tail = JournalTailReader::new(dir.join("journal.vlog"));
    let mut vidx_tail = JournalTailReader::new(&sidecar);
    assert_eq!(vlog_tail.last_record_count(), 3);
    assert_eq!(vidx_tail.last_record_count(), 3);
    assert!(vlog_tail.poll_new_records().is_empty());
    assert!(vidx_tail.poll_new_records().is_empty());

    // Append 2 new frames and verify both tail readers stream only the 2 delta records
    let r4 = sample_record(4, 5003, "allow", "cargo check");
    let r5 = sample_record(5, 5004, "deny", "rm -rf /");
    append_vlog(&dir, &r4).expect("append r4");
    append_vlog(&dir, &r5).expect("append r5");

    let delta_vlog = vlog_tail.poll_new_records();
    assert_eq!(delta_vlog.len(), 2);
    assert_eq!(delta_vlog[0].cmd, "cargo check");
    assert_eq!(delta_vlog[1].cmd, "rm -rf /");
    assert_eq!(vlog_tail.last_record_count(), 5);
    assert!(vlog_tail.poll_new_records().is_empty());

    let delta_vidx = vidx_tail.poll_new_records();
    assert_eq!(delta_vidx.len(), 2);
    assert_eq!(delta_vidx[0].cmd, "cargo check");
    assert_eq!(delta_vidx[1].cmd, "rm -rf /");
    assert_eq!(vidx_tail.last_record_count(), 5);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn vlog_pure_binary_compaction_collapses_duplicates_and_preserves_counts() {
    let dir = unique_test_dir("pure_binary_compaction");
    // Write 10 historical duplicate records + 2 recent unique records into journal.vlog ONLY (no journal.jsonl)
    for i in 0..10 {
        let rec = sample_record(i + 1, 6000 + (i as u64), "allow", "git status --short");
        append_vlog(&dir, &rec).expect("append duplicate");
        journal::append_outcome(
            &dir,
            &OutcomeRecord {
                id: rec.id.clone(),
                outcome: Outcome::Executed,
                detail: String::new(),
                host: "claude".to_string(),
            },
        )
        .expect("append outcome");
    }
    let recent1 = sample_record(101, 6100, "ask", "touch /tmp/recent1");
    let recent2 = sample_record(102, 6101, "allow", "ls -la");
    append_vlog(&dir, &recent1).expect("append recent1");
    append_vlog(&dir, &recent2).expect("append recent2");

    assert!(!dir.join("journal.jsonl").exists());
    let size_before = std::fs::metadata(dir.join("journal.vlog")).unwrap().len();

    let policy = JournalPolicy {
        max_records: 100,
        compact_duplicates: true,
        preserve_recent: 2,
    };
    let stats = journal::prune_and_compact(&dir, &policy).expect("prune_and_compact on binary journal");
    assert_eq!(stats.original_count, 12);
    assert_eq!(stats.compacted_count, 3); // 10 historical duplicates collapsed to 1 + 2 recent
    assert_eq!(stats.outcomes_retained, 1);

    let size_after = std::fs::metadata(dir.join("journal.vlog")).unwrap().len();
    assert!(size_after < size_before, "compacted vlog must shrink ({size_after} < {size_before})");

    let reader = VlogReader::open(&dir.join("journal.vlog")).expect("open compacted vlog");
    assert_eq!(reader.len(), 3);
    let collapsed = reader.get_record(0).unwrap();
    assert_eq!(collapsed.cmd, "git status --short");
    assert_eq!(collapsed.count, 10, "collapsed binary record must preserve aggregated count");
    assert_eq!(collapsed.id, "toolu_00010");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn vlog_tail_reader_self_heals_across_compaction_shrink() {
    let dir = unique_test_dir("tail_compaction_heal");
    for i in 0..8 {
        let rec = sample_record(i + 1, 7000 + (i as u64), "allow", "echo duplicate");
        append_vlog(&dir, &rec).expect("append dup");
    }
    let anchor = sample_record(50, 7050, "allow", "echo anchor");
    append_vlog(&dir, &anchor).expect("append anchor");

    let mut tail = JournalTailReader::new(dir.join("journal.vlog"));
    let offset_before = tail.last_offset();
    assert_eq!(tail.last_record_count(), 9);

    // Compact journal.vlog so record count shrinks from 9 -> 2 and index_offset shrinks
    let policy = JournalPolicy {
        max_records: 100,
        compact_duplicates: true,
        preserve_recent: 1,
    };
    compact_vlog(&dir, &policy).expect("compact_vlog");

    // Append a new record after compaction before polling
    let post_compact = sample_record(51, 7051, "ask", "touch /tmp/post_compact");
    append_vlog(&dir, &post_compact).expect("append post_compact");

    // Poll must detect compaction shrink, avoid re-emitting historical records, and return only post_compact
    let polled = tail.poll_new_records();
    assert_eq!(polled.len(), 1);
    assert_eq!(polled[0].cmd, "touch /tmp/post_compact");
    assert_eq!(tail.last_record_count(), 3);
    assert!(tail.last_offset() < offset_before);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn vlog_hash_chain_verification_succeeds_for_appended_and_compacted_logs() {
    let dir = unique_test_dir("hash_chain_valid");
    let r1 = sample_record(1, 8000, "allow", "git status");
    let r2 = sample_record(2, 8001, "allow", "git status");
    let r3 = sample_record(3, 8002, "ask", "rm -rf /tmp/x");

    append_vlog(&dir, &r1).expect("append r1");
    append_vlog(&dir, &r2).expect("append r2");
    append_vlog(&dir, &r3).expect("append r3");

    let vlog_file = dir.join("journal.vlog");
    let report = verify_vlog_integrity(&vlog_file).expect("verify appended vlog");
    assert!(report.valid, "expected valid hash chain, got {report:?}");
    assert_eq!(report.verified_records, 3);
    assert!(report.tamper_finding.is_none());

    // Compact duplicates and verify the re-chained file also passes cryptographic verification
    let policy = JournalPolicy {
        max_records: 100,
        compact_duplicates: true,
        preserve_recent: 1,
    };
    compact_vlog(&dir, &policy).expect("compact vlog");
    let post_compact = verify_vlog_integrity(&vlog_file).expect("verify compacted vlog");
    assert!(
        post_compact.valid,
        "expected valid compacted hash chain, got {post_compact:?}"
    );
    assert_eq!(post_compact.verified_records, 2);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn vlog_hash_chain_detects_middle_frame_deletion_and_reindexing() {
    let dir = unique_test_dir("hash_chain_middle_delete");
    let r0 = sample_record(0, 9000, "allow", "echo zero");
    let r1 = sample_record(1, 9001, "deny", "kill -9 1");
    let r2 = sample_record(2, 9002, "allow", "echo two");
    write_all_vlog(&dir, &[r0.clone(), r1, r2.clone()]).expect("write 3 records");

    let vlog_file = dir.join("journal.vlog");
    let raw = std::fs::read(&vlog_file).unwrap();
    let reader = VlogReader::open(&vlog_file).unwrap();
    let idx = reader.index();
    assert_eq!(idx.len(), 3);

    // Tamper: excise middle frame r1 (idx[1]), splice frame r0 + frame r2 directly together,
    // and rebuild a valid header + footer + sidecar with valid CRC32s so only the hash chain breaks.
    let f0_start = idx[0].record_offset as usize;
    let f0_end = f0_start + (idx[0].record_len as usize);
    let f2_start = idx[2].record_offset as usize;
    let f2_end = f2_start + (idx[2].record_len as usize);

    let frame0 = &raw[f0_start..f0_end];
    let frame2 = &raw[f2_start..f2_end];

    let new_f0_off = VLOG_HEADER_LEN as u64;
    let new_f2_off = new_f0_off + (frame0.len() as u64);
    let new_idx_off = new_f2_off + (frame2.len() as u64);

    let entry0 = VlogIndexEntry::from_record(&r0, new_f0_off, frame0.len() as u32);
    let entry2 = VlogIndexEntry::from_record(&r2, new_f2_off, frame2.len() as u32);
    let forged_header = VlogHeader::new(2, new_idx_off);

    let mut forged = Vec::new();
    forged.extend_from_slice(&forged_header.to_bytes());
    forged.extend_from_slice(frame0);
    forged.extend_from_slice(frame2);
    forged.extend_from_slice(&entry0.to_bytes());
    forged.extend_from_slice(&entry2.to_bytes());
    std::fs::write(&vlog_file, &forged).unwrap();

    let mut forged_vidx = Vec::new();
    forged_vidx.extend_from_slice(&forged_header.to_bytes());
    forged_vidx.extend_from_slice(&entry0.to_bytes());
    forged_vidx.extend_from_slice(&entry2.to_bytes());
    std::fs::write(vidx_path(&dir), &forged_vidx).unwrap();

    let report = verify_vlog_integrity(&vlog_file).expect("verify tampered vlog");
    assert!(!report.valid, "middle frame deletion must fail integrity check");
    assert_eq!(report.verified_records, 1);
    match report.tamper_finding {
        Some(VlogTamperKind::ChainLinkBroken {
            seq_idx, offset, ..
        }) => {
            assert_eq!(seq_idx, 1);
            assert_eq!(offset, new_f2_off);
        }
        other => panic!("expected ChainLinkBroken at seq_idx 1, got {other:?}"),
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn vlog_hash_chain_detects_payload_rewrite_with_recomputed_crc32() {
    let dir = unique_test_dir("hash_chain_payload_rewrite");
    let r0 = sample_record(0, 9100, "allow", "git status");
    let r1 = sample_record(1, 9101, "deny", "rm -rf /tmp/secret");
    write_all_vlog(&dir, &[r0, r1.clone()]).expect("write 2 records");

    let vlog_file = dir.join("journal.vlog");
    let mut raw = std::fs::read(&vlog_file).unwrap();
    let reader = VlogReader::open(&vlog_file).unwrap();
    let f1_off = reader.index()[1].record_offset as usize;

    // Replace r1's payload with a same-length modified command and recompute the frame CRC32,
    // leaving the original chain_tag in place.
    let mut forged_rec = r1;
    forged_rec.cmd = "ls -la /tmp/secret".to_string(); // exact same byte length as "rm -rf /tmp/secret"
    let forged_payload = encode_record_payload(&forged_rec);
    let forged_crc = crc32(&forged_payload);

    let payload_start = f1_off + VLOG_FRAME_HEADER_LEN;
    let payload_end = payload_start + forged_payload.len();
    raw[f1_off + 4..f1_off + 8].copy_from_slice(&forged_crc.to_le_bytes());
    raw[payload_start..payload_end].copy_from_slice(&forged_payload);
    std::fs::write(&vlog_file, &raw).unwrap();

    let report = verify_vlog_integrity(&vlog_file).expect("verify forged payload vlog");
    assert!(!report.valid);
    assert_eq!(report.verified_records, 1);
    assert!(matches!(
        report.tamper_finding,
        Some(VlogTamperKind::ChainLinkBroken { seq_idx: 1, .. })
    ));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn vlog_hash_chain_detects_sidecar_vidx_mismatch() {
    let dir = unique_test_dir("hash_chain_sidecar_mismatch");
    let r0 = sample_record(0, 9200, "allow", "git status");
    let r1 = sample_record(1, 9201, "ask", "touch /tmp/z");
    write_all_vlog(&dir, &[r0.clone(), r1]).expect("write 2 records");

    // Overwrite sidecar journal.vidx so it claims only 1 record
    let sidecar = vidx_path(&dir);
    let (_, entries) = read_vidx_entries(&sidecar).unwrap();
    let stale_header = VlogHeader::new(1, entries[1].record_offset);
    let mut stale_vidx = Vec::new();
    stale_vidx.extend_from_slice(&stale_header.to_bytes());
    stale_vidx.extend_from_slice(&entries[0].to_bytes());
    std::fs::write(&sidecar, &stale_vidx).unwrap();

    let report = verify_vlog_integrity(&dir.join("journal.vlog")).expect("verify sidecar mismatch");
    assert!(!report.valid);
    assert_eq!(report.verified_records, 2);
    assert!(matches!(
        report.tamper_finding,
        Some(VlogTamperKind::SidecarIndexMismatch { .. })
    ));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn vlog_checkpoint_ledger_verifies_multi_generation_compaction_and_post_compact_appends() {
    let dir = unique_test_dir("vchk_multi_gen");
    let vlog_file = dir.join("journal.vlog");
    let vchk_file = vchk_path(&dir);

    // Generation 0: append 6 records (4 duplicates of `git status` + 2 unique)
    for i in 0..4 {
        append_vlog(&dir, &sample_record(i, 10_000 + i as u64, "allow", "git status")).unwrap();
    }
    append_vlog(&dir, &sample_record(10, 10_010, "ask", "touch /tmp/a")).unwrap();
    append_vlog(&dir, &sample_record(11, 10_011, "allow", "cargo test")).unwrap();

    let pre_gen1 = verify_vlog_integrity(&vlog_file).unwrap();
    assert!(pre_gen1.valid);
    assert_eq!(pre_gen1.verified_records, 6);
    assert_eq!(pre_gen1.verified_checkpoints, 0);
    assert!(!vchk_file.exists());

    // Compaction #1: 6 records -> 3 records (4 duplicates collapsed to 1 + 2 recent)
    let policy = JournalPolicy {
        max_records: 100,
        compact_duplicates: true,
        preserve_recent: 2,
    };
    let stats1 = compact_vlog(&dir, &policy).expect("compact #1");
    assert_eq!(stats1.original_count, 6);
    assert_eq!(stats1.compacted_count, 3);
    assert!(vchk_file.exists(), "journal.vchk must be created by compact_vlog");

    let post_gen1 = verify_vlog_integrity(&vlog_file).unwrap();
    assert!(post_gen1.valid, "post_gen1 failed: {post_gen1:?}");
    assert_eq!(post_gen1.verified_records, 3);
    assert_eq!(post_gen1.verified_checkpoints, 1);

    let ckpts1 = read_vlog_checkpoints(&vchk_file).expect("read ckpts #1");
    assert_eq!(ckpts1.len(), 1);
    assert_eq!(ckpts1[0].checkpoint_seq, 0);
    assert_eq!(ckpts1[0].pre_compact_records, 6);
    assert_eq!(ckpts1[0].pre_compact_terminal_tag, pre_gen1.terminal_chain_tag);
    assert_eq!(ckpts1[0].post_compact_records, 3);
    assert_eq!(ckpts1[0].pruned_records, 3);
    assert_eq!(ckpts1[0].post_compact_terminal_tag, post_gen1.terminal_chain_tag);

    // Append 3 new records after Compaction #1 (total 6 records) and verify continuity still holds!
    for i in 0..3 {
        append_vlog(
            &dir,
            &sample_record(20 + i, 10_020 + i as u64, "allow", "git diff"),
        )
        .unwrap();
    }
    let mid_report = verify_vlog_integrity(&vlog_file).unwrap();
    assert!(mid_report.valid, "mid_report after post-compact append failed: {mid_report:?}");
    assert_eq!(mid_report.verified_records, 6);
    assert_eq!(mid_report.verified_checkpoints, 1);

    // Compaction #2: 6 records -> 5 records (`git diff` collapsed in historical prefix with preserve_recent: 1)
    let policy_gen2 = JournalPolicy {
        max_records: 100,
        compact_duplicates: true,
        preserve_recent: 1,
    };
    let stats2 = compact_vlog(&dir, &policy_gen2).expect("compact #2");
    assert_eq!(stats2.original_count, 6);
    assert_eq!(stats2.compacted_count, 5);

    let post_gen2 = verify_vlog_integrity(&vlog_file).unwrap();
    assert!(post_gen2.valid, "post_gen2 failed: {post_gen2:?}");
    assert_eq!(post_gen2.verified_records, 5);
    assert_eq!(post_gen2.verified_checkpoints, 2);

    // Compaction #3 with tighter max_records=3 (5 records -> 3 records)
    let policy_tight = JournalPolicy {
        max_records: 3,
        compact_duplicates: true,
        preserve_recent: 1,
    };
    let stats3 = compact_vlog(&dir, &policy_tight).expect("compact #3");
    assert_eq!(stats3.original_count, 5);
    assert_eq!(stats3.pruned_count, 2);

    let post_gen3 = verify_vlog_integrity(&vlog_file).unwrap();
    assert!(post_gen3.valid, "post_gen3 failed: {post_gen3:?}");
    assert_eq!(post_gen3.verified_records, 3);
    assert_eq!(post_gen3.verified_checkpoints, 3);

    let ckpts3 = read_vlog_checkpoints(&vchk_file).expect("read ckpts #3");
    assert_eq!(ckpts3.len(), 3);
    assert_eq!(ckpts3[1].prev_checkpoint_digest, ckpts3[0].checkpoint_digest);
    assert_eq!(ckpts3[2].prev_checkpoint_digest, ckpts3[1].checkpoint_digest);
    assert_eq!(ckpts3[2].pre_compact_terminal_tag, ckpts3[1].post_compact_terminal_tag);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn vlog_checkpoint_detects_tampered_vchk_and_forged_vlog_replacement() {
    let dir = unique_test_dir("vchk_tamper");
    let vlog_file = dir.join("journal.vlog");
    let vchk_file = vchk_path(&dir);

    for i in 0..4 {
        append_vlog(&dir, &sample_record(i, 11_000 + i as u64, "allow", "echo dup")).unwrap();
    }
    append_vlog(&dir, &sample_record(9, 11_010, "ask", "touch /tmp/z")).unwrap();

    let policy = JournalPolicy {
        max_records: 100,
        compact_duplicates: true,
        preserve_recent: 1,
    };
    compact_vlog(&dir, &policy).expect("compact");
    assert!(verify_vlog_integrity(&vlog_file).unwrap().valid);

    // Case 1: Replace journal.vlog with a freshly written 2-record .vlog whose internal CRC/chain
    // is valid, but whose records do not match the checkpoint's post_compact_terminal_tag.
    let saved_vlog = std::fs::read(&vlog_file).unwrap();
    let saved_vidx = std::fs::read(vidx_path(&dir)).unwrap();

    write_all_vlog(
        &dir,
        &[
            sample_record(100, 11_000, "allow", "echo forged_one"),
            sample_record(101, 11_010, "allow", "echo forged_two"),
        ],
    )
    .unwrap();

    let forged_report = verify_vlog_integrity(&vlog_file).unwrap();
    assert!(!forged_report.valid, "forged vlog replacement must fail checkpoint continuity");
    assert!(matches!(
        forged_report.tamper_finding,
        Some(VlogTamperKind::CheckpointContinuityBroken { checkpoint_seq: 0, .. })
    ));

    // Also verify compact_vlog refuses to compact when checkpoint continuity is broken
    let compact_err = compact_vlog(&dir, &policy).unwrap_err();
    assert_eq!(compact_err.kind(), std::io::ErrorKind::InvalidData);

    // Restore valid vlog/vidx, then tamper with journal.vchk directly
    std::fs::write(&vlog_file, &saved_vlog).unwrap();
    std::fs::write(vidx_path(&dir), &saved_vidx).unwrap();
    assert!(verify_vlog_integrity(&vlog_file).unwrap().valid);

    let mut vchk_bytes = std::fs::read(&vchk_file).unwrap();
    assert_eq!(vchk_bytes.len(), VCHK_ENTRY_LEN);
    // Flip a bit in pre_compact_terminal_tag inside journal.vchk
    vchk_bytes[34] ^= 0x01;
    std::fs::write(&vchk_file, &vchk_bytes).unwrap();

    let tampered_vchk_report = verify_vlog_integrity(&vlog_file).unwrap();
    assert!(!tampered_vchk_report.valid, "corrupted journal.vchk must fail integrity check");
    assert!(matches!(
        tampered_vchk_report.tamper_finding,
        Some(VlogTamperKind::CheckpointContinuityBroken { .. })
    ));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn vbundle_export_and_offline_verification_succeeds_after_state_dir_removal() {
    let state_dir = unique_test_dir("vbundle_state");
    let archive_dir = unique_test_dir("vbundle_archive");
    let bundle_path = archive_dir.join("session.vbundle");

    // Append 5 records (3 duplicates + 2 unique), compact once, then append 1 more record
    for i in 0..3 {
        append_vlog(
            &state_dir,
            &sample_record(i, 12_000 + i as u64, "allow", "git status"),
        )
        .unwrap();
    }
    append_vlog(&state_dir, &sample_record(10, 12_010, "ask", "touch /tmp/x")).unwrap();
    append_vlog(&state_dir, &sample_record(11, 12_011, "allow", "cargo check")).unwrap();

    let policy = JournalPolicy {
        max_records: 100,
        compact_duplicates: true,
        preserve_recent: 2,
    };
    compact_vlog(&state_dir, &policy).expect("compact #1");
    append_vlog(&state_dir, &sample_record(12, 12_012, "allow", "cargo test")).unwrap();

    // Export portable cryptographic bundle
    let export_report = export_vlog_bundle(&state_dir, &bundle_path).expect("export bundle");
    assert!(export_report.valid);
    assert_eq!(export_report.verified_records, 4);
    assert_eq!(export_report.verified_checkpoints, 1);
    assert!(bundle_path.exists());

    //Completely remove the original state_dir to prove offline verification works standalone
    std::fs::remove_dir_all(&state_dir).expect("remove state_dir");
    assert!(!state_dir.exists());

    let offline_report = verify_vlog_bundle(&bundle_path).expect("verify bundle offline");
    assert!(offline_report.valid, "offline verification failed: {offline_report:?}");
    assert_eq!(offline_report.verified_records, 4);
    assert_eq!(offline_report.verified_checkpoints, 1);
    assert_eq!(
        offline_report.terminal_chain_tag,
        export_report.terminal_chain_tag
    );

    let decoded = read_records_from_vlog_bundle(&bundle_path).expect("decode bundle records");
    assert_eq!(decoded.len(), 4);
    assert_eq!(decoded[0].cmd, "git status");
    assert_eq!(decoded[0].count, 3);
    assert_eq!(decoded[3].cmd, "cargo test");

    let _ = std::fs::remove_dir_all(&archive_dir);
}
#[test]
fn vbundle_detects_outer_seal_corruption_and_re_sealed_inner_tampering() {
    let state_dir = unique_test_dir("vbundle_tamper_state");
    let archive_dir = unique_test_dir("vbundle_tamper_archive");
    let bundle_path = archive_dir.join("tamper.vbundle");

    for i in 0..3 {
        append_vlog(
            &state_dir,
            &sample_record(i, 13_000 + i as u64, "allow", "echo dup"),
        )
        .unwrap();
    }
    append_vlog(
        &state_dir,
        &sample_record(9, 13_009, "deny", "rm -rf /tmp/secret"),
    )
    .unwrap();
    let policy = JournalPolicy {
        max_records: 100,
        compact_duplicates: true,
        preserve_recent: 1,
    };
    compact_vlog(&state_dir, &policy).expect("compact");
    export_vlog_bundle(&state_dir, &bundle_path).expect("export bundle");
    let orig_bytes = std::fs::read(&bundle_path).unwrap();

    // Case 1: Flip a byte in the bundle payload without updating the SHA-256 seal
    let mut unsealed_tamper = orig_bytes.clone();
    let mid = VBUNDLE_HEADER_LEN + 40;
    unsealed_tamper[mid] ^= 0xFF;
    std::fs::write(&bundle_path, &unsealed_tamper).unwrap();

    let rep1 = verify_vlog_bundle(&bundle_path).expect("verify unsealed tamper");
    assert!(!rep1.valid);
    assert!(matches!(
        rep1.tamper_finding,
        Some(VlogTamperKind::BundleSealCorrupted { .. })
    ));

    // Case 2: Tamper with embedded vchk checkpoint and recompute outer bundle SHA-256 seal
    let mut resealed_vchk_tamper = orig_bytes.clone();
    let header = VlogBundleHeader::from_bytes(&resealed_vchk_tamper).unwrap();
    let vchk_start = header.vchk_offset as usize;
    resealed_vchk_tamper[vchk_start + 34] ^= 0x01; // flip bit in pre_compact_terminal_tag
    let mut prefix = [0u8; 64];
    prefix.copy_from_slice(&resealed_vchk_tamper[0..64]);
    let vlog_s = &resealed_vchk_tamper[header.vlog_offset as usize..(header.vlog_offset + header.vlog_len) as usize];
    let vidx_s = &resealed_vchk_tamper[header.vidx_offset as usize..(header.vidx_offset + header.vidx_len) as usize];
    let vchk_s = &resealed_vchk_tamper[header.vchk_offset as usize..(header.vchk_offset + header.vchk_len) as usize];
    let forged_seal = compute_bundle_seal_sha256(&prefix, vlog_s, vidx_s, vchk_s);
    resealed_vchk_tamper[64..96].copy_from_slice(&forged_seal);
    std::fs::write(&bundle_path, &resealed_vchk_tamper).unwrap();

    let rep2 = verify_vlog_bundle(&bundle_path).expect("verify resealed vchk tamper");
    assert!(!rep2.valid, "re-sealed inner vchk tamper must fail inner checkpoint check");
    assert!(matches!(
        rep2.tamper_finding,
        Some(VlogTamperKind::CheckpointContinuityBroken { .. })
    ));

    let _ = std::fs::remove_dir_all(&state_dir);
    let _ = std::fs::remove_dir_all(&archive_dir);
}
#[test]
fn cli_vouch_doctor_export_and_verify_bundle_end_to_end() {
    let state_dir = unique_test_dir("cli_bundle_state");
    let archive_dir = unique_test_dir("cli_bundle_archive");
    let bundle_path = archive_dir.join("cli_audit.vbundle");

    append_vlog(&state_dir, &sample_record(1, 14_001, "allow", "ls -la")).unwrap();
    append_vlog(&state_dir, &sample_record(2, 14_002, "allow", "ls -la")).unwrap();
    append_vlog(&state_dir, &sample_record(3, 14_003, "ask", "touch /tmp/cli")).unwrap();
    let policy = JournalPolicy {
        max_records: 100,
        compact_duplicates: true,
        preserve_recent: 1,
    };
    compact_vlog(&state_dir, &policy).unwrap();

    let exe = env!("CARGO_BIN_EXE_vouch");
    let export_out = std::process::Command::new(exe)
        .env("VOUCH_STATE_DIR", &state_dir)
        .args(["doctor", "--export-bundle", bundle_path.to_str().unwrap()])
        .output()
        .expect("run vouch doctor --export-bundle");
    assert!(
        export_out.status.success(),
        "export-bundle failed: stdout={}, stderr={}",
        String::from_utf8_lossy(&export_out.stdout),
        String::from_utf8_lossy(&export_out.stderr)
    );
    let export_stdout = String::from_utf8_lossy(&export_out.stdout);
    assert!(export_stdout.contains("exported cryptographic audit bundle:"));
    assert!(export_stdout.contains("records: 2, compaction generations: 1"));

    // Remove state_dir and run --verify-bundle pointing VOUCH_STATE_DIR to a non-existent directory
    std::fs::remove_dir_all(&state_dir).unwrap();
    let verify_out = std::process::Command::new(exe)
        .env("VOUCH_STATE_DIR", &state_dir)
        .args(["doctor", "--verify-bundle", bundle_path.to_str().unwrap()])
        .output()
        .expect("run vouch doctor --verify-bundle");
    assert!(
        verify_out.status.success(),
        "verify-bundle failed: stdout={}, stderr={}",
        String::from_utf8_lossy(&verify_out.stdout),
        String::from_utf8_lossy(&verify_out.stderr)
    );
    let verify_stdout = String::from_utf8_lossy(&verify_out.stdout);
    assert!(verify_stdout.contains("bundle integrity verified: 2 records, 1 compaction checkpoints, hash chain unbroken"));

    // Corrupt bundle and verify non-zero exit code
    let mut raw = std::fs::read(&bundle_path).unwrap();
    raw[VBUNDLE_HEADER_LEN + 10] ^= 0xAA;
    std::fs::write(&bundle_path, &raw).unwrap();

    let bad_out = std::process::Command::new(exe)
        .env("VOUCH_STATE_DIR", &state_dir)
        .args(["doctor", "--verify-bundle", bundle_path.to_str().unwrap()])
        .output()
        .expect("run vouch doctor --verify-bundle on corrupted bundle");
    assert!(!bad_out.status.success(), "corrupted bundle must exit non-zero");
    let bad_stdout = String::from_utf8_lossy(&bad_out.stdout);
    assert!(bad_stdout.contains("bundle integrity check FAILED"));

    let _ = std::fs::remove_dir_all(&archive_dir);
}

#[test]
fn vbundle_delta_export_and_multi_bundle_chain_verification_succeeds_and_detects_lineage_breaks() {
    let state_dir = unique_test_dir("vbundle_delta_state");
    let archive_dir = unique_test_dir("vbundle_delta_archive");
    let b0_path = archive_dir.join("b0_genesis.vbundle");
    let b1_path = archive_dir.join("b1_delta.vbundle");
    let b2_path = archive_dir.join("b2_delta.vbundle");

    // Step 1: Append 10 records and export genesis bundle B0
    for i in 0..10 {
        append_vlog(
            &state_dir,
            &sample_record(i, 15_000 + i as u64, "allow", &format!("echo step0_{i}")),
        )
        .unwrap();
    }
    let rep_b0 = export_vlog_bundle(&state_dir, &b0_path).expect("export B0");
    assert!(rep_b0.valid);
    assert_eq!(rep_b0.verified_records, 10);

    // Step 2: Append 5 more records and export delta bundle B1 (--since B0)
    for i in 10..15 {
        append_vlog(
            &state_dir,
            &sample_record(i, 15_000 + i as u64, "allow", &format!("echo step1_{i}")),
        )
        .unwrap();
    }
    let rep_b1 =
        export_vlog_bundle_since(&state_dir, &b1_path, Some(&b0_path)).expect("export delta B1");
    assert!(rep_b1.valid);
    assert_eq!(rep_b1.verified_records, 5);

    let b1_bytes = std::fs::read(&b1_path).unwrap();
    let b1_hdr = VlogBundleHeader::from_bytes(&b1_bytes).unwrap();
    assert_eq!(b1_hdr.version, VBUNDLE_DELTA_VERSION);
    let b1_anchor = b1_hdr.parse_delta_anchor(&b1_bytes).unwrap().unwrap();
    assert_eq!(b1_anchor.base_seq_idx, 10);
    assert_eq!(b1_anchor.parent_terminal_chain_tag, rep_b0.terminal_chain_tag);

    // Step 3: Append 3 more records and export delta bundle B2 (--since B1)
    for i in 15..18 {
        append_vlog(
            &state_dir,
            &sample_record(i, 15_000 + i as u64, "ask", &format!("touch /tmp/step2_{i}")),
        )
        .unwrap();
    }
    let rep_b2 =
        export_vlog_bundle_since(&state_dir, &b2_path, Some(&b1_path)).expect("export delta B2");
    assert!(rep_b2.valid);
    assert_eq!(rep_b2.verified_records, 3);

    let live_final = verify_vlog_integrity(&state_dir.join("journal.vlog")).unwrap();
    assert_eq!(live_final.verified_records, 18);
    assert_eq!(rep_b2.terminal_chain_tag, live_final.terminal_chain_tag);

    // Remove state_dir and verify [B0, B1, B2] completely offline
    std::fs::remove_dir_all(&state_dir).unwrap();
    let chain_rep = verify_vlog_bundle_chain(&[b0_path.clone(), b1_path.clone(), b2_path.clone()])
        .expect("verify 3-bundle chain");
    assert!(chain_rep.valid, "3-bundle chain failed: {chain_rep:?}");
    assert_eq!(chain_rep.verified_records, 18);
    assert_eq!(chain_rep.terminal_chain_tag, live_final.terminal_chain_tag);

    // Passing a delta bundle alone to verify_vlog_bundle_chain must report DeltaParentMismatch
    let lone_delta = verify_vlog_bundle_chain(std::slice::from_ref(&b1_path)).unwrap();
    assert!(!lone_delta.valid);
    assert!(matches!(
        lone_delta.tamper_finding,
        Some(VlogTamperKind::DeltaParentMismatch { .. })
    ));

    // Omitting middle bundle B1 ([B0, B2]) must report DeltaParentMismatch
    let skipped_mid = verify_vlog_bundle_chain(&[b0_path.clone(), b2_path.clone()]).unwrap();
    assert!(!skipped_mid.valid);
    assert!(matches!(
        skipped_mid.tamper_finding,
        Some(VlogTamperKind::DeltaParentMismatch { .. })
    ));

    // Reordering ([B1, B0, B2]) must report DeltaParentMismatch
    let reordered =
        verify_vlog_bundle_chain(&[b1_path.clone(), b0_path.clone(), b2_path.clone()]).unwrap();
    assert!(!reordered.valid);
    assert!(matches!(
        reordered.tamper_finding,
        Some(VlogTamperKind::DeltaParentMismatch { .. })
    ));

    // Also verify CLI `vouch doctor --verify-bundle B0 --verify-bundle B1 --verify-bundle B2`
    let exe = vouch_exe();
    let cli_ok = std::process::Command::new(&exe)
        .env("VOUCH_STATE_DIR", &state_dir)
        .args([
            "doctor",
            "--verify-bundle",
            b0_path.to_str().unwrap(),
            "--verify-bundle",
            b1_path.to_str().unwrap(),
            "--verify-bundle",
            b2_path.to_str().unwrap(),
        ])
        .output()
        .expect("run vouch doctor multi-bundle verify");
    assert!(
        cli_ok.status.success(),
        "cli multi-bundle verify failed: stdout={}, stderr={}",
        String::from_utf8_lossy(&cli_ok.stdout),
        String::from_utf8_lossy(&cli_ok.stderr)
    );
    let cli_stdout = String::from_utf8_lossy(&cli_ok.stdout);
    assert!(cli_stdout.contains("bundle integrity verified: 18 records"));

    let _ = std::fs::remove_dir_all(&archive_dir);
}

#[test]
fn vbundle_offline_merge_compacts_genesis_and_delta_chain_into_standalone_bundle_and_serves_as_new_parent() {
    let state_dir = unique_test_dir("vbundle_merge_state");
    let archive_dir = unique_test_dir("vbundle_merge_archive");
    let b0_path = archive_dir.join("b0_genesis.vbundle");
    let b1_path = archive_dir.join("b1_delta.vbundle");
    let b2_path = archive_dir.join("b2_delta.vbundle");
    let merged_path = archive_dir.join("merged_full.vbundle");
    let b3_path = archive_dir.join("b3_delta_after_merge.vbundle");

    // Step 1: Append 6 records (4 duplicates + 2 unique), compact once, and export B0
    for i in 0..4 {
        append_vlog(
            &state_dir,
            &sample_record(i, 16_000 + i as u64, "allow", "git status"),
        )
        .unwrap();
    }
    append_vlog(
        &state_dir,
        &sample_record(4, 16_004, "allow", "echo gen0_a"),
    )
    .unwrap();
    append_vlog(
        &state_dir,
        &sample_record(5, 16_005, "allow", "echo gen0_b"),
    )
    .unwrap();
    let policy = JournalPolicy {
        max_records: 100,
        compact_duplicates: true,
        preserve_recent: 2,
    };
    compact_vlog(&state_dir, &policy).expect("compact before B0");
    let rep_b0 = export_vlog_bundle(&state_dir, &b0_path).expect("export B0");
    assert!(rep_b0.valid);
    assert_eq!(rep_b0.verified_records, 3);
    assert_eq!(rep_b0.verified_checkpoints, 1);

    // Step 2: Append 4 records and export delta B1 (--since B0)
    for i in 6..10 {
        append_vlog(
            &state_dir,
            &sample_record(i, 16_000 + i as u64, "allow", &format!("echo delta1_{i}")),
        )
        .unwrap();
    }
    let rep_b1 =
        export_vlog_bundle_since(&state_dir, &b1_path, Some(&b0_path)).expect("export delta B1");
    assert!(rep_b1.valid);
    assert_eq!(rep_b1.verified_records, 4);

    // Step 3: Append 3 records and export delta B2 (--since B1)
    for i in 10..13 {
        append_vlog(
            &state_dir,
            &sample_record(i, 16_000 + i as u64, "ask", &format!("touch /tmp/delta2_{i}")),
        )
        .unwrap();
    }
    let rep_b2 =
        export_vlog_bundle_since(&state_dir, &b2_path, Some(&b1_path)).expect("export delta B2");
    assert!(rep_b2.valid);
    assert_eq!(rep_b2.verified_records, 3);

    // Step 4: Merge [B0, B1, B2] offline into merged_full.vbundle
    let merge_rep = merge_vlog_bundles(
        &[b0_path.clone(), b1_path.clone(), b2_path.clone()],
        &merged_path,
    )
    .expect("merge [B0, B1, B2]");
    assert!(merge_rep.valid, "merge report invalid: {merge_rep:?}");
    assert_eq!(merge_rep.verified_records, 10);
    assert_eq!(merge_rep.verified_checkpoints, 1);
    assert_eq!(merge_rep.terminal_chain_tag, rep_b2.terminal_chain_tag);
    assert!(merged_path.exists());

    // Verify merged_full.vbundle is a standalone VBUNDLE_VERSION (1) bundle
    let merged_bytes = std::fs::read(&merged_path).unwrap();
    let merged_hdr = VlogBundleHeader::from_bytes(&merged_bytes).unwrap();
    assert_eq!(merged_hdr.version, VBUNDLE_VERSION);
    assert!(merged_hdr.parse_delta_anchor(&merged_bytes).unwrap().is_none());

    // Standalone verify_vlog_bundle and verify_vlog_bundle_chain(&[merged_path]) must pass
    let standalone_rep = verify_vlog_bundle(&merged_path).expect("standalone verify merged");
    assert!(standalone_rep.valid);
    assert_eq!(standalone_rep.verified_records, 10);
    assert_eq!(standalone_rep.verified_checkpoints, 1);
    assert_eq!(standalone_rep.terminal_chain_tag, rep_b2.terminal_chain_tag);

    let single_chain_rep =
        verify_vlog_bundle_chain(std::slice::from_ref(&merged_path)).expect("single chain verify");
    assert!(single_chain_rep.valid);
    assert_eq!(single_chain_rep.verified_records, 10);

    // Decoded records from merged bundle must match the exact 10 records in sequence
    let decoded = read_records_from_vlog_bundle(&merged_path).expect("decode merged records");
    assert_eq!(decoded.len(), 10);
    assert_eq!(decoded[0].cmd, "git status");
    assert_eq!(decoded[0].count, 4);
    assert_eq!(decoded[3].cmd, "echo delta1_6");
    assert_eq!(decoded[9].cmd, "touch /tmp/delta2_12");

    // Step 5: Append 2 more records to live state_dir and export a new delta B3 anchored to merged_full.vbundle!
    for i in 13..15 {
        append_vlog(
            &state_dir,
            &sample_record(i, 16_000 + i as u64, "allow", &format!("echo delta3_{i}")),
        )
        .unwrap();
    }
    let rep_b3 = export_vlog_bundle_since(&state_dir, &b3_path, Some(&merged_path))
        .expect("export delta B3 since merged_full.vbundle");
    assert!(rep_b3.valid);
    assert_eq!(rep_b3.verified_records, 2);

    // Remove state_dir and verify [merged_full.vbundle, B3] offline
    std::fs::remove_dir_all(&state_dir).unwrap();
    let post_merge_chain =
        verify_vlog_bundle_chain(&[merged_path.clone(), b3_path.clone()]).expect("verify post-merge chain");
    assert!(post_merge_chain.valid);
    assert_eq!(post_merge_chain.verified_records, 12);
    assert_eq!(post_merge_chain.verified_checkpoints, 1);
    assert_eq!(post_merge_chain.terminal_chain_tag, rep_b3.terminal_chain_tag);

    // Negative tests: broken chain ([B0, B2] missing B1) must fail and NOT write output file
    let bad_out_path = archive_dir.join("should_not_exist.vbundle");
    let bad_rep =
        merge_vlog_bundles(&[b0_path.clone(), b2_path.clone()], &bad_out_path).expect("merge broken chain");
    assert!(!bad_rep.valid);
    assert!(matches!(
        bad_rep.tamper_finding,
        Some(VlogTamperKind::DeltaParentMismatch { .. })
    ));
    assert!(!bad_out_path.exists(), "failed merge must not create output bundle");

    // Also test CLI `vouch doctor --merge-bundles B0 --merge-bundles B1 --merge-bundles B2 --output cli_merged.vbundle`
    let cli_merged_path = archive_dir.join("cli_merged.vbundle");
    let exe = vouch_exe();
    let cli_merge_out = std::process::Command::new(&exe)
        .env("VOUCH_STATE_DIR", &state_dir)
        .args([
            "doctor",
            "--merge-bundles",
            b0_path.to_str().unwrap(),
            "--merge-bundles",
            b1_path.to_str().unwrap(),
            "--merge-bundles",
            b2_path.to_str().unwrap(),
            "--output",
            cli_merged_path.to_str().unwrap(),
        ])
        .output()
        .expect("run vouch doctor --merge-bundles");
    assert!(
        cli_merge_out.status.success(),
        "cli merge-bundles failed: stdout={}, stderr={}",
        String::from_utf8_lossy(&cli_merge_out.stdout),
        String::from_utf8_lossy(&cli_merge_out.stderr)
    );
    let cli_merge_stdout = String::from_utf8_lossy(&cli_merge_out.stdout);
    assert!(cli_merge_stdout.contains("merged 3 cryptographic audit bundles into"));
    assert!(cli_merge_stdout.contains("10 records, 1 compaction checkpoints"));
    assert!(verify_vlog_bundle(&cli_merged_path).unwrap().valid);

    let _ = std::fs::remove_dir_all(&archive_dir);
}

#[test]
fn vbundle_slice_export_by_session_and_time_window_verifies_offline_and_detects_tampering() {
    let state_dir = unique_test_dir("vbundle_slice_state");
    let archive_dir = unique_test_dir("vbundle_slice_archive");
    let session_slice_path = archive_dir.join("session_b.vbundle");
    let time_slice_path = archive_dir.join("time_window.vbundle");
    let combined_slice_path = archive_dir.join("combined.vbundle");

    // Append interleaved records across 3 sessions ("sess_alpha", "sess_beta", "sess_gamma")
    // using ISO 8601 timestamps and Unix epoch timestamps.
    // 2026-11-04T20:00:00Z = 1793822400
    let base_ts = parse_timestamp_arg("2026-11-04T20:00:00Z").expect("parse base ISO timestamp");
    assert_eq!(base_ts, 1_793_822_400);

    let schedule = [
        (0, "sess_alpha", "2026-11-04T20:00:00Z", "allow", "git status"),
        (1, "sess_beta", "2026-11-04T20:01:00Z", "allow", "cargo check"),
        (2, "sess_alpha", "2026-11-04T20:02:00Z", "ask", "touch /tmp/a"),
        (3, "sess_beta", "2026-11-04T20:03:00Z", "allow", "cargo test"),
        (4, "sess_gamma", "2026-11-04T20:04:00Z", "deny", "rm -rf /tmp/g"),
        (5, "sess_beta", "2026-11-04T20:05:00Z", "ask", "touch /tmp/b"),
        (6, "sess_alpha", "2026-11-04T20:06:00Z", "allow", "git diff"),
    ];

    for (idx, sess, ts_str, verdict, cmd) in schedule {
        let mut r = sample_record(idx, 0, verdict, cmd);
        r.session = sess.to_string();
        r.ts = ts_str.to_string();
        append_vlog(&state_dir, &r).unwrap();
    }

    // 1. Export non-contiguous session slice for "sess_beta" (sequences 1, 3, 5)
    let sess_filter = VlogSliceFilter {
        session: Some("sess_beta".to_string()),
        from_ts_secs: None,
        to_ts_secs: None,
    };
    let sess_rep = export_vlog_slice_bundle(&state_dir, &session_slice_path, &sess_filter)
        .expect("export sess_beta slice");
    assert!(sess_rep.valid);
    assert_eq!(sess_rep.verified_records, 3);

    // Check v3 header and VlogSliceHeader provenance
    let sess_bytes = std::fs::read(&session_slice_path).unwrap();
    let sess_hdr = VlogBundleHeader::from_bytes(&sess_bytes).unwrap();
    assert_eq!(sess_hdr.version, VBUNDLE_SLICE_VERSION);
    let slice_meta = sess_hdr.parse_slice_header(&sess_bytes).unwrap().unwrap();
    assert_eq!(slice_meta.source_record_count, 7);
    assert_eq!(slice_meta.slice_start_seq, 1);
    assert_eq!(slice_meta.slice_end_seq, 5);
    assert_eq!(slice_meta.frame_provenance.len(), 3);
    assert_eq!(slice_meta.frame_provenance[0].0, 1);
    assert_eq!(slice_meta.frame_provenance[1].0, 3);
    assert_eq!(slice_meta.frame_provenance[2].0, 5);

    // 2. Export time-window slice [20:02:00Z .. 20:04:00Z] (sequences 2, 3, 4)
    let time_filter = VlogSliceFilter {
        session: None,
        from_ts_secs: Some(parse_timestamp_arg("2026-11-04T20:02:00Z").unwrap()),
        to_ts_secs: Some(parse_timestamp_arg("2026-11-04T20:04:00Z").unwrap()),
    };
    let time_rep = export_vlog_slice_bundle(&state_dir, &time_slice_path, &time_filter)
        .expect("export time window slice");
    assert!(time_rep.valid);
    assert_eq!(time_rep.verified_records, 3);

    // 3. Export via CLI combining --session sess_beta --from 2026-11-04T20:02:00Z --to 2026-11-04T20:05:00Z (sequences 3, 5)
    let exe = vouch_exe();
    let cli_export = std::process::Command::new(&exe)
        .env("VOUCH_STATE_DIR", &state_dir)
        .args([
            "doctor",
            "--export-bundle",
            combined_slice_path.to_str().unwrap(),
            "--session",
            "sess_beta",
            "--from",
            "2026-11-04T20:02:00Z",
            "--to",
            "2026-11-04T20:05:00Z",
        ])
        .output()
        .expect("cli slice export");
    assert!(
        cli_export.status.success(),
        "cli slice export failed: stdout={}, stderr={}",
        String::from_utf8_lossy(&cli_export.stdout),
        String::from_utf8_lossy(&cli_export.stderr)
    );

    // Remove state_dir and verify all 3 slice bundles completely offline!
    std::fs::remove_dir_all(&state_dir).unwrap();

    let off_sess = verify_vlog_bundle(&session_slice_path).expect("verify session slice offline");
    assert!(off_sess.valid);
    assert_eq!(off_sess.verified_records, 3);
    let sess_recs = read_records_from_vlog_bundle(&session_slice_path).unwrap();
    assert_eq!(sess_recs.len(), 3);
    assert_eq!(sess_recs[0].cmd, "cargo check");
    assert_eq!(sess_recs[1].cmd, "cargo test");
    assert_eq!(sess_recs[2].cmd, "touch /tmp/b");

    let off_time = verify_vlog_bundle(&time_slice_path).expect("verify time slice offline");
    assert!(off_time.valid);
    assert_eq!(off_time.verified_records, 3);

    let cli_verify = std::process::Command::new(&exe)
        .env("VOUCH_STATE_DIR", &state_dir)
        .args([
            "doctor",
            "--verify-bundle",
            combined_slice_path.to_str().unwrap(),
        ])
        .output()
        .expect("cli slice verify");
    assert!(
        cli_verify.status.success(),
        "cli slice verify failed: stdout={}, stderr={}",
        String::from_utf8_lossy(&cli_verify.stdout),
        String::from_utf8_lossy(&cli_verify.stderr)
    );
    let cli_verify_stdout = String::from_utf8_lossy(&cli_verify.stdout);
    assert!(cli_verify_stdout.contains("bundle integrity verified: 2 records"));

    // 4. Tamper test: modify a frame's provenance prev_chain_tag inside VlogSliceHeader and re-seal the outer bundle SHA-256
    let mut tampered = sess_bytes.clone();
    // Flip a bit in frame_provenance[1].prev_chain_tag (offset: VBUNDLE_HEADER_LEN + 128 + 16 + 8)
    let prov_tag_offset = VBUNDLE_HEADER_LEN + 128 + 16 + 8;
    tampered[prov_tag_offset] ^= 0x01;
    let mut prefix = [0u8; 64];
    prefix.copy_from_slice(&tampered[0..64]);
    let vlog_start = sess_hdr.vlog_offset as usize;
    let vlog_end = vlog_start + sess_hdr.vlog_len as usize;
    let vidx_start = sess_hdr.vidx_offset as usize;
    let vidx_end = vidx_start + sess_hdr.vidx_len as usize;
    let forged_seal = compute_bundle_seal_sha256_with_extra(
        &prefix,
        &tampered[VBUNDLE_HEADER_LEN..vlog_start],
        &tampered[vlog_start..vlog_end],
        &tampered[vidx_start..vidx_end],
        &[],
    );
    tampered[64..96].copy_from_slice(&forged_seal);
    let tampered_path = archive_dir.join("tampered_slice.vbundle");
    std::fs::write(&tampered_path, &tampered).unwrap();

    let tampered_rep = verify_vlog_bundle(&tampered_path).expect("verify tampered slice");
    assert!(!tampered_rep.valid, "tampered slice provenance must fail chain link check");
    assert!(matches!(
        tampered_rep.tamper_finding,
        Some(VlogTamperKind::ChainLinkBroken { seq_idx: 3, .. })
    ));

    let _ = std::fs::remove_dir_all(&archive_dir);
}

#[test]
fn vbundle_redacted_export_strips_plaintext_verifies_offline_and_proves_field_commitments() {
    let state_dir = unique_test_dir("vbundle_redacted_state");
    let archive_dir = unique_test_dir("vbundle_redacted_archive");
    let full_redacted_path = archive_dir.join("full_redacted.vbundle");
    let slice_redacted_path = archive_dir.join("slice_redacted.vbundle");

    let sensitive_cmd_0 = "curl -H 'Authorization: Bearer SECRET_MARKER_ALPHA_991' https://internal.example.test/api";
    let sensitive_cmd_1 = "psql --host db.example.test --dbname prod --command 'SELECT SECRET_MARKER_BETA_772'";
    let sensitive_cmd_2 = "aws s3 cp /tmp/SECRET_MARKER_GAMMA_553.pem s3://vault-bucket/";
    let sensitive_cwd = "C:/Users/dev/confidential_workspace_marker_884";

    let records = [
        (0, "sess_red_1", "2026-11-04T21:00:00Z", "ask", sensitive_cmd_0),
        (1, "sess_red_2", "2026-11-04T21:01:00Z", "deny", sensitive_cmd_1),
        (2, "sess_red_1", "2026-11-04T21:02:00Z", "allow", sensitive_cmd_2),
    ];

    for (idx, sess, ts_str, verdict, cmd) in records {
        let mut r = sample_record(idx, 0, verdict, cmd);
        r.session = sess.to_string();
        r.ts = ts_str.to_string();
        r.cwd = sensitive_cwd.to_string();
        r.reason = "vouch stopped on: external command".to_string();
        append_vlog(&state_dir, &r).unwrap();
    }

    // 1. Export full redacted bundle via library
    let empty_filter = VlogSliceFilter::default();
    let rep_full = export_vlog_redacted_bundle(&state_dir, &full_redacted_path, &empty_filter)
        .expect("export full redacted bundle");
    assert!(rep_full.valid);
    assert_eq!(rep_full.verified_records, 3);

    // Inspect raw bytes of full_redacted.vbundle to ensure zero plaintext leakage
    let raw_bytes = std::fs::read(&full_redacted_path).unwrap();
    let raw_lossy = String::from_utf8_lossy(&raw_bytes);
    assert!(
        !raw_lossy.contains("SECRET_MARKER_ALPHA_991")
            && !raw_lossy.contains("SECRET_MARKER_BETA_772")
            && !raw_lossy.contains("SECRET_MARKER_GAMMA_553")
            && !raw_lossy.contains("confidential_workspace_marker_884"),
        "redacted .vbundle must not contain any plaintext command or cwd markers"
    );

    let hdr = VlogBundleHeader::from_bytes(&raw_bytes).unwrap();
    assert_eq!(hdr.version, VBUNDLE_REDACTED_VERSION);
    let red_meta = hdr.parse_redacted_header(&raw_bytes).unwrap().unwrap();
    assert_eq!(red_meta.source_record_count, 3);
    assert_eq!(red_meta.frame_proofs.len(), 3);

    // 2. Export session-filtered redacted bundle via CLI (`--export-bundle ... --session sess_red_1 --redact-fields`)
    let exe = vouch_exe();
    let cli_export = std::process::Command::new(&exe)
        .env("VOUCH_STATE_DIR", &state_dir)
        .args([
            "doctor",
            "--export-bundle",
            slice_redacted_path.to_str().unwrap(),
            "--session",
            "sess_red_1",
            "--redact-fields",
        ])
        .output()
        .expect("cli redacted slice export");
    assert!(
        cli_export.status.success(),
        "cli redacted export failed: stdout={}, stderr={}",
        String::from_utf8_lossy(&cli_export.stdout),
        String::from_utf8_lossy(&cli_export.stderr)
    );

    // Remove state_dir and verify both redacted bundles completely offline!
    std::fs::remove_dir_all(&state_dir).unwrap();

    let off_full = verify_vlog_bundle(&full_redacted_path).expect("verify full redacted offline");
    assert!(off_full.valid);
    assert_eq!(off_full.verified_records, 3);

    let cli_verify = std::process::Command::new(&exe)
        .env("VOUCH_STATE_DIR", &state_dir)
        .args([
            "doctor",
            "--verify-bundle",
            slice_redacted_path.to_str().unwrap(),
        ])
        .output()
        .expect("cli redacted slice verify");
    assert!(
        cli_verify.status.success(),
        "cli redacted verify failed: stdout={}, stderr={}",
        String::from_utf8_lossy(&cli_verify.stdout),
        String::from_utf8_lossy(&cli_verify.stderr)
    );
    let cli_verify_stdout = String::from_utf8_lossy(&cli_verify.stdout);
    assert!(cli_verify_stdout.contains("bundle integrity verified: 2 records"));

    // 3. Decode records from redacted bundle and verify field-level commitment claims
    let decoded_recs = read_records_from_vlog_bundle(&full_redacted_path).unwrap();
    assert_eq!(decoded_recs.len(), 3);
    for (idx, rec) in decoded_recs.iter().enumerate() {
        assert!(rec.cmd.starts_with("sha256:") && rec.cmd.len() == 71);
        assert!(rec.cwd.starts_with("sha256:") && rec.cwd.len() == 71);
        // Structural fields remain intact
        assert_eq!(rec.id, format!("toolu_{idx:05}"));
    }

    let proof_0 = &red_meta.frame_proofs[0];
    assert!(verify_redacted_field_claim(
        proof_0.orig_chain_tag,
        proof_0.orig_seq_idx,
        "cmd",
        sensitive_cmd_0,
        &decoded_recs[0].cmd
    ));
    assert!(!verify_redacted_field_claim(
        proof_0.orig_chain_tag,
        proof_0.orig_seq_idx,
        "cmd",
        "wrong command guess",
        &decoded_recs[0].cmd
    ));
    assert!(verify_redacted_field_claim(
        proof_0.orig_chain_tag,
        proof_0.orig_seq_idx,
        "cwd",
        sensitive_cwd,
        &decoded_recs[0].cwd
    ));
    assert_eq!(
        compute_redacted_field_commitment(proof_0.orig_chain_tag, proof_0.orig_seq_idx, "cmd", sensitive_cmd_0),
        decoded_recs[0].cmd
    );

    // 4. Tamper test: corrupt a proof_tag in VlogRedactedHeader and re-seal the outer bundle SHA-256
    let mut tampered = raw_bytes.clone();
    // Flip a bit in frame_proofs[1].proof_tag (offset: VBUNDLE_HEADER_LEN + VBUNDLE_SLICE_HEADER_LEN + 1 * 96 + 88)
    let proof_tag_offset =
        VBUNDLE_HEADER_LEN + VBUNDLE_SLICE_HEADER_LEN + VBUNDLE_REDACTION_PROOF_LEN + 88;
    tampered[proof_tag_offset] ^= 0x01;
    let mut prefix = [0u8; 64];
    prefix.copy_from_slice(&tampered[0..64]);
    let vlog_start = hdr.vlog_offset as usize;
    let vlog_end = vlog_start + hdr.vlog_len as usize;
    let vidx_start = hdr.vidx_offset as usize;
    let vidx_end = vidx_start + hdr.vidx_len as usize;
    let forged_seal = compute_bundle_seal_sha256_with_extra(
        &prefix,
        &tampered[VBUNDLE_HEADER_LEN..vlog_start],
        &tampered[vlog_start..vlog_end],
        &tampered[vidx_start..vidx_end],
        &[],
    );
    tampered[64..96].copy_from_slice(&forged_seal);
    let tampered_path = archive_dir.join("tampered_redacted.vbundle");
    std::fs::write(&tampered_path, &tampered).unwrap();

    let tampered_rep = verify_vlog_bundle(&tampered_path).expect("verify tampered redacted bundle");
    assert!(
        !tampered_rep.valid,
        "tampered redaction proof tag must fail verification"
    );
    assert!(matches!(
        tampered_rep.tamper_finding,
        Some(VlogTamperKind::ChainLinkBroken { seq_idx: 1, .. })
    ));

    let _ = std::fs::remove_dir_all(&archive_dir);
}

#[test]
fn vbundle_selective_disclosure_export_verify_and_tamper_detection_end_to_end() {
    let state_dir = unique_test_dir("vbundle_disclosure_state");
    let archive_dir = unique_test_dir("vbundle_disclosure_archive");
    let redacted_bundle_path = archive_dir.join("full_redacted.vbundle");
    let disclosure_seq_path = archive_dir.join("selective_seq.vdis");
    let disclosure_cli_path = archive_dir.join("selective_cli.vdis");

    let recs = [
        (0, "sess_dis_1", "2026-11-01T10:00:00Z", "allow", "echo DISCLOSE_CMD_ZERO_111", "/workspace/dis_0"),
        (1, "sess_dis_2", "2026-11-01T10:05:00Z", "ask", "echo DISCLOSE_CMD_ONE_222", "/workspace/dis_1"),
        (2, "sess_dis_1", "2026-11-01T10:10:00Z", "allow", "echo DISCLOSE_CMD_TWO_333", "/workspace/dis_2"),
        (3, "sess_dis_2", "2026-11-01T10:15:00Z", "deny", "echo DISCLOSE_CMD_THREE_444", "/workspace/dis_3"),
    ];
    for (idx, sess, ts_str, verdict, cmd, cwd) in recs {
        let mut r = sample_record(idx, 0, verdict, cmd);
        r.session = sess.to_string();
        r.ts = ts_str.to_string();
        r.cwd = cwd.to_string();
        append_vlog(&state_dir, &r).unwrap();
    }

    // 1. Export full redacted v4 bundle
    let empty_filter = VlogSliceFilter::default();
    let red_rep = export_vlog_redacted_bundle(&state_dir, &redacted_bundle_path, &empty_filter)
        .expect("export redacted v4 bundle");
    assert!(red_rep.valid);
    assert_eq!(red_rep.verified_records, 4);

    // 2. Export selective disclosure proof for only sequence indices [1, 3] via library
    let proof_seq = export_vlog_disclosure(
        &state_dir,
        &disclosure_seq_path,
        &empty_filter,
        &[1, 3],
    )
    .expect("export selective disclosure proof for seq [1, 3]");
    assert_eq!(proof_seq.version, VDISCLOSURE_VERSION);
    assert_eq!(proof_seq.entry_count, 2);
    assert_eq!(proof_seq.source_record_count, 4);

    // Ensure raw bytes of disclosure_seq_path do NOT contain undisguised plaintext from seq 0 or seq 2
    let dis_raw = std::fs::read(&disclosure_seq_path).unwrap();
    assert_eq!(&dis_raw[0..4], &VDISCLOSURE_MAGIC);
    let dis_lossy = String::from_utf8_lossy(&dis_raw);
    assert!(dis_lossy.contains("DISCLOSE_CMD_ONE_222"));
    assert!(dis_lossy.contains("DISCLOSE_CMD_THREE_444"));
    assert!(
        !dis_lossy.contains("DISCLOSE_CMD_ZERO_111") && !dis_lossy.contains("DISCLOSE_CMD_TWO_333"),
        "selective disclosure proof must not leak non-disclosed records"
    );

    // 3. Export selective disclosure proof via CLI (`vouch doctor --export-disclosure ... --session sess_dis_1 --seq 2`)
    let exe = vouch_exe();
    let cli_export = std::process::Command::new(&exe)
        .env("VOUCH_STATE_DIR", &state_dir)
        .args([
            "doctor",
            "--export-disclosure",
            disclosure_cli_path.to_str().unwrap(),
            "--session",
            "sess_dis_1",
            "--seq",
            "2",
        ])
        .output()
        .expect("cli export-disclosure");
    assert!(
        cli_export.status.success(),
        "cli export-disclosure failed: stdout={}, stderr={}",
        String::from_utf8_lossy(&cli_export.stdout),
        String::from_utf8_lossy(&cli_export.stderr)
    );
    let cli_export_stdout = String::from_utf8_lossy(&cli_export.stdout);
    assert!(cli_export_stdout.contains("exported selective disclosure proof:"));
    assert!(cli_export_stdout.contains("disclosed records: 1, source records: 4"));

    // 4. Delete state_dir completely and verify both selective disclosure proofs offline against redacted_bundle_path!
    std::fs::remove_dir_all(&state_dir).unwrap();

    let verify_rep = verify_vlog_disclosure(&redacted_bundle_path, &disclosure_seq_path)
        .expect("offline verify_vlog_disclosure");
    assert!(verify_rep.valid, "selective disclosure verification failed: {verify_rep:?}");
    assert_eq!(verify_rep.verified_records, 2);

    let disclosed_recs = read_disclosed_records(&redacted_bundle_path, &disclosure_seq_path)
        .expect("read_disclosed_records");
    assert_eq!(disclosed_recs.len(), 2);
    assert_eq!(disclosed_recs[0].0, 1);
    assert_eq!(disclosed_recs[0].1.cmd, "echo DISCLOSE_CMD_ONE_222");
    assert_eq!(disclosed_recs[0].1.cwd, "/workspace/dis_1");
    assert_eq!(disclosed_recs[1].0, 3);
    assert_eq!(disclosed_recs[1].1.cmd, "echo DISCLOSE_CMD_THREE_444");
    assert_eq!(disclosed_recs[1].1.cwd, "/workspace/dis_3");

    // Verify CLI `--verify-bundle <redacted.vbundle> --verify-disclosure <selective_cli.vdis>` offline
    let cli_verify = std::process::Command::new(&exe)
        .env("VOUCH_STATE_DIR", &state_dir)
        .args([
            "doctor",
            "--verify-bundle",
            redacted_bundle_path.to_str().unwrap(),
            "--verify-disclosure",
            disclosure_cli_path.to_str().unwrap(),
        ])
        .output()
        .expect("cli verify-disclosure");
    assert!(
        cli_verify.status.success(),
        "cli verify-disclosure failed: stdout={}, stderr={}",
        String::from_utf8_lossy(&cli_verify.stdout),
        String::from_utf8_lossy(&cli_verify.stderr)
    );
    let cli_verify_stdout = String::from_utf8_lossy(&cli_verify.stdout);
    assert!(cli_verify_stdout.contains("selective disclosure verified: 1 disclosed records matched redacted bundle commitments"));
    assert!(cli_verify_stdout.contains("[seq=2] session=sess_dis_1 verdict=allow cwd=/workspace/dis_2 cmd=echo DISCLOSE_CMD_TWO_333"));

    // 5. Tamper test A: Forge a modified command in a VlogDisclosureProof and recompute its outer seal & CRC
    let mut forged_entry = proof_seq.entries[0].clone();
    forged_entry.record.cmd = "echo FORGED_CMD_ONE_999".to_string();
    let forged_proof = VlogDisclosureProof::new(
        proof_seq.exported_at_secs,
        proof_seq.source_record_count,
        proof_seq.source_terminal_chain_tag,
        vec![forged_entry],
    );
    let forged_path = archive_dir.join("forged_cmd.vdis");
    std::fs::write(&forged_path, forged_proof.to_bytes()).unwrap();
    let forged_rep = verify_vlog_disclosure(&redacted_bundle_path, &forged_path)
        .expect("verify forged disclosure proof");
    assert!(!forged_rep.valid, "forged cmd in disclosure proof must be rejected");
    assert!(matches!(
        forged_rep.tamper_finding,
        Some(VlogTamperKind::ChainLinkBroken { seq_idx: 1, .. })
    ));

    // 6. Tamper test B: Corrupt outer seal of disclosure file
    let mut bad_seal_bytes = dis_raw.clone();
    bad_seal_bytes[VDISCLOSURE_HEADER_LEN - 1] ^= 0x55;
    let bad_seal_path = archive_dir.join("bad_seal.vdis");
    std::fs::write(&bad_seal_path, &bad_seal_bytes).unwrap();
    let bad_seal_rep = verify_vlog_disclosure(&redacted_bundle_path, &bad_seal_path).unwrap();
    assert!(!bad_seal_rep.valid);
    assert!(matches!(
        bad_seal_rep.tamper_finding,
        Some(VlogTamperKind::BundleSealCorrupted { .. })
    ));

    let _ = std::fs::remove_dir_all(&archive_dir);
}
