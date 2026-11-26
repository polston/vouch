use std::path::PathBuf;
use vouch::journal_wal::{crc32, decode_frames, encode_frame, recover_and_checkpoint, write_wal_frame};

fn temp_dir(prefix: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "{prefix}_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::create_dir_all(&p);
    p
}

#[test]
fn test_wal_frame_crc32_and_roundtrip() {
    let payload = r#"{"id":"call-1","cmd":"git status","verdict":"allow"}"#;
    let frame = encode_frame(payload.as_bytes());

    assert_eq!(&frame[0..2], b"VJ");
    let len = u32::from_be_bytes([frame[2], frame[3], frame[4], frame[5]]) as usize;
    assert_eq!(len, payload.len());

    let expected_crc = crc32(payload.as_bytes());
    let actual_crc = u32::from_be_bytes([frame[6], frame[7], frame[8], frame[9]]);
    assert_eq!(actual_crc, expected_crc);

    let (records, torn) = decode_frames(&frame);
    assert!(torn.is_none());
    assert_eq!(records.len(), 1);
    assert_eq!(records[0], payload);
}

#[test]
fn test_wal_bit_flip_corruption_detected() {
    let payload = r#"{"id":"call-2","cmd":"ls -la","verdict":"allow"}"#;
    let mut frame = encode_frame(payload.as_bytes());

    // Corrupt one byte of the payload
    frame[12] ^= 0xFF;

    let (records, torn) = decode_frames(&frame);
    assert_eq!(records.len(), 0);
    assert!(torn.is_some());
    assert!(torn.unwrap().reason.contains("checksum mismatch"));
}

#[test]
fn test_wal_torn_write_recovery_and_checkpoint() {
    let dir = temp_dir("wal_recovery");

    // Write two good frames
    let p1 = r#"{"id":"1","cmd":"echo 1"}"#;
    let p2 = r#"{"id":"2","cmd":"echo 2"}"#;
    write_wal_frame(&dir, p1).unwrap();
    write_wal_frame(&dir, p2).unwrap();

    // Now append a torn frame (header with half payload)
    let wal_path = dir.join("journal.wal");
    let p3 = r#"{"id":"3","cmd":"echo 3"}"#;
    let frame3 = encode_frame(p3.as_bytes());
    // Truncate frame 3 to simulate process death mid-write
    let torn_slice = &frame3[..frame3.len() / 2];

    use std::io::Write;
    let mut f = std::fs::OpenOptions::new().append(true).open(&wal_path).unwrap();
    f.write_all(torn_slice).unwrap();
    f.flush().unwrap();
    drop(f);

    // Run crash recovery
    let recovered_count = recover_and_checkpoint(&dir).unwrap();
    assert_eq!(recovered_count, 2);

    // Verify journal.jsonl received exactly the 2 valid records
    let jsonl_content = std::fs::read_to_string(dir.join("journal.jsonl")).unwrap();
    let lines: Vec<&str> = jsonl_content.lines().collect();
    assert_eq!(lines.len(), 2);
    assert!(lines[0].contains("echo 1"));
    assert!(lines[1].contains("echo 2"));

    // Cleanup
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_wal_concurrent_appends() {
    let dir = temp_dir("wal_concurrent");
    let mut handles = Vec::new();

    for t in 0..8 {
        let d = dir.clone();
        handles.push(std::thread::spawn(move || {
            for i in 0..50 {
                let payload = format!(r#"{{"thread":{t},"seq":{i},"cmd":"test"}}"#);
                write_wal_frame(&d, &payload).unwrap();
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    let recovered = recover_and_checkpoint(&dir).unwrap();
    // 8 threads * 50 writes = 400 records
    assert_eq!(recovered, 400);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_wal_stays_bounded_across_500_sequential_journal_appends() {
    use vouch::journal::{append, all, Record};
    use vouch::journal_wal::WAL_CHECKPOINT_THRESHOLD_BYTES;
    use vouch::outcome::Outcome;

    let dir = temp_dir("wal_bounded_500");

    for i in 0..500u64 {
        let rec = Record {
            id: format!("toolu_wal_{i:04}"),
            ts: format!("{}", 1_760_000_000 + i),
            session: "sess_bounded_wal".into(),
            tool: "Bash".into(),
            cmd: format!("echo bounded_wal_record_{i:04}_padding_text_for_checkpoint_threshold"),
            verdict: "allow".into(),
            reason: "allowed by policy".into(),
            mode: "live".into(),
            cwd: "/tmp/work".into(),
            outcome: Outcome::Pending,
            lang: "bash".into(),
            permission_mode: String::new(),
            host: "claude".into(),
            count: 1,
            measurement: false,
        };
        append(&dir, &rec).expect("append record");
    }

    let wal_len = std::fs::metadata(dir.join("journal.wal"))
        .map(|m| m.len())
        .unwrap_or(0);
    assert!(
        wal_len < WAL_CHECKPOINT_THRESHOLD_BYTES * 2,
        "journal.wal grew unbounded to {wal_len} bytes (threshold {WAL_CHECKPOINT_THRESHOLD_BYTES})"
    );

    // Confirm no stray checkpoint temp files remain.
    let ckpt_leftovers: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with("journal.wal.ckpt."))
        .collect();
    assert!(
        ckpt_leftovers.is_empty(),
        "unexpected leftover checkpoint files: {ckpt_leftovers:?}"
    );

    let loaded = all(&dir);
    assert_eq!(loaded.len(), 500);
    assert_eq!(loaded[0].id, "toolu_wal_0000");
    assert_eq!(loaded[499].id, "toolu_wal_0499");

    let _ = std::fs::remove_dir_all(&dir);
}
