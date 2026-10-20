use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use vouch::config::{self, JournalFormat};
use vouch::journal::{self, JournalPolicy, OutcomeRecord, Record};
use vouch::journal_vlog::{
    append_vlog, compact_vlog, encode_record_payload, read_vidx_entries, read_vlog_checkpoints,
    vchk_path, verify_vlog_integrity, vidx_path, write_all_vlog, VlogHeader, VlogIndexEntry,
    VlogReader, VlogTamperKind, VCHK_ENTRY_LEN, VLOG_FRAME_HEADER_LEN, VLOG_HEADER_LEN,
    VLOG_INDEX_ENTRY_LEN, VLOG_MAGIC,
};
use vouch::journal_wal::crc32;
use vouch::outcome::Outcome;
use vouch::tui::engine::JournalTailReader;

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
