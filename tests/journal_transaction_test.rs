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
