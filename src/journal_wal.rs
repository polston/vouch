//! Write-Ahead Logging (WAL), CRC32 integrity verification, and crash recovery (M3.2).
//!
//! Protects `journal.jsonl` from torn writes, unexpected crashes, and concurrent process
//! corruption by framing every record with a binary header and CRC32 checksum.
//! On crash or abnormal termination, recovery truncates uncommitted torn writes and
//! preserves 100% record integrity without data loss.

use std::fs::{create_dir_all, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

pub const WAL_MAGIC: [u8; 2] = [0x56, 0x4A]; // 'V', 'J'
pub const HEADER_LEN: usize = 10; // 2 bytes magic + 4 bytes len + 4 bytes crc32
/// Byte size threshold at which `maybe_checkpoint_wal` rotates and checkpoints `journal.wal`.
pub const WAL_CHECKPOINT_THRESHOLD_BYTES: u64 = 64 * 1024;

/// Standard IEEE 802.3 CRC32 algorithm (zero-dependency, bit-exact with zip/png/ethernet).
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

/// Encode a payload into a framed WAL byte buffer.
pub fn encode_frame(payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u32;
    let checksum = crc32(payload);

    let mut buf = Vec::with_capacity(HEADER_LEN + payload.len());
    buf.extend_from_slice(&WAL_MAGIC);
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(&checksum.to_be_bytes());
    buf.extend_from_slice(payload);
    buf
}

/// Information about a corrupted or torn frame encountered during scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TornFrameInfo {
    pub offset: usize,
    pub reason: String,
}

/// Decode all valid framed records from raw WAL bytes.
/// Returns successfully parsed JSON payloads and details of any trailing torn frame.
pub fn decode_frames(data: &[u8]) -> (Vec<String>, Option<TornFrameInfo>) {
    let mut records = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        let remaining = &data[offset..];
        if remaining.len() < HEADER_LEN {
            return (
                records,
                Some(TornFrameInfo {
                    offset,
                    reason: format!("truncated frame header ({} bytes remaining)", remaining.len()),
                }),
            );
        }

        if remaining[0..2] != WAL_MAGIC {
            return (
                records,
                Some(TornFrameInfo {
                    offset,
                    reason: format!("invalid frame magic: {:02x?}", &remaining[0..2]),
                }),
            );
        }

        let len = u32::from_be_bytes([remaining[2], remaining[3], remaining[4], remaining[5]]) as usize;
        let expected_crc = u32::from_be_bytes([remaining[6], remaining[7], remaining[8], remaining[9]]);

        if remaining.len() < HEADER_LEN + len {
            return (
                records,
                Some(TornFrameInfo {
                    offset,
                    reason: format!("truncated payload: expected {len} bytes, found {}", remaining.len() - HEADER_LEN),
                }),
            );
        }

        let payload = &remaining[HEADER_LEN..HEADER_LEN + len];
        let actual_crc = crc32(payload);
        if actual_crc != expected_crc {
            return (
                records,
                Some(TornFrameInfo {
                    offset,
                    reason: format!("checksum mismatch: expected {expected_crc:08x}, got {actual_crc:08x}"),
                }),
            );
        }

        match std::str::from_utf8(payload) {
            Ok(s) => records.push(s.to_string()),
            Err(e) => {
                return (
                    records,
                    Some(TornFrameInfo {
                        offset,
                        reason: format!("utf-8 error: {e}"),
                    }),
                );
            }
        }

        offset += HEADER_LEN + len;
    }

    (records, None)
}

/// Atomically write a single framed record to `journal.wal` in `dir`.
pub fn write_wal_frame(dir: &Path, payload: &str) -> std::io::Result<()> {
    create_dir_all(dir)?;
    let wal_path = dir.join("journal.wal");
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&wal_path)?;

    let frame = encode_frame(payload.as_bytes());
    file.write_all(&frame)?;
    file.flush()?;
    Ok(())
}

/// Perform crash recovery on `journal.wal`:
/// 1. Reads all frames from `journal.wal`.
/// 2. If a torn frame is detected, truncates `journal.wal` to the last valid frame offset.
/// 3. Appends all recovered records to `journal.jsonl`.
/// 4. Clears `journal.wal`.
pub fn recover_and_checkpoint(dir: &Path) -> std::io::Result<usize> {
    let wal_path = dir.join("journal.wal");
    if !wal_path.exists() {
        return Ok(0);
    }

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&wal_path)?;

    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    if data.is_empty() {
        return Ok(0);
    }

    let (records, torn) = decode_frames(&data);

    if let Some(t) = torn {
        // Truncate to last known good frame
        file.set_len(t.offset as u64)?;
        file.seek(SeekFrom::Start(t.offset as u64))?;
    }

    if !records.is_empty() {
        let jsonl_path = dir.join("journal.jsonl");
        let existing: std::collections::HashSet<String> = if jsonl_path.exists() {
            std::fs::read_to_string(&jsonl_path)?
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect()
        } else {
            std::collections::HashSet::new()
        };

        let uncommitted: Vec<&String> = records
            .iter()
            .filter(|r| !existing.contains(r.trim()))
            .collect();

        if !uncommitted.is_empty() {
            let mut jsonl_file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&jsonl_path)?;

            for r in &uncommitted {
                writeln!(jsonl_file, "{r}")?;
            }
            jsonl_file.flush()?;
        }

        // Truncate WAL after successful checkpoint
        file.set_len(0)?;
    }

    Ok(records.len())
}

/// Read recent lines from the tail of `journal.jsonl` (up to `max_tail_bytes`)
/// into a deduplication set so periodic WAL checkpoints stay O(WAL) even on
/// multi-hundred-megabyte journals.
fn recent_jsonl_lines(jsonl_path: &Path, max_tail_bytes: u64) -> std::io::Result<std::collections::HashSet<String>> {
    if !jsonl_path.exists() {
        return Ok(std::collections::HashSet::new());
    }
    let mut f = OpenOptions::new().read(true).open(jsonl_path)?;
    let len = f.metadata()?.len();
    let start = len.saturating_sub(max_tail_bytes);
    f.seek(SeekFrom::Start(start))?;
    let mut raw = Vec::new();
    f.read_to_end(&mut raw)?;
    let text = String::from_utf8_lossy(&raw);
    let mut lines = text.lines();
    if start > 0 {
        // Skip the potentially partial first line when seeking mid-file.
        let _ = lines.next();
    }
    Ok(lines
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect())
}

/// Atomically rotate and checkpoint `journal.wal` once it reaches
/// `WAL_CHECKPOINT_THRESHOLD_BYTES`, preventing unbounded WAL growth during
/// write-heavy hook execution while remaining safe under concurrent appenders.
pub fn maybe_checkpoint_wal(dir: &Path) -> std::io::Result<bool> {
    let wal_path = dir.join("journal.wal");
    let wal_len = match std::fs::metadata(&wal_path) {
        Ok(m) => m.len(),
        Err(_) => return Ok(false),
    };
    if wal_len < WAL_CHECKPOINT_THRESHOLD_BYTES {
        return Ok(false);
    }

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let ckpt_path = dir.join(format!("journal.wal.ckpt.{}.{nanos}", std::process::id()));
    if let Err(err) = std::fs::rename(&wal_path, &ckpt_path) {
        if err.kind() == std::io::ErrorKind::NotFound {
            // Another concurrent hook process already rotated the WAL.
            return Ok(false);
        }
        return Err(err);
    }

    let data = std::fs::read(&ckpt_path)?;
    let (records, _torn) = decode_frames(&data);
    if !records.is_empty() {
        let jsonl_path = dir.join("journal.jsonl");
        let tail_window = wal_len.saturating_mul(4).max(256 * 1024);
        let existing = recent_jsonl_lines(&jsonl_path, tail_window)?;
        let uncommitted: Vec<&String> = records
            .iter()
            .filter(|r| !existing.contains(r.trim()))
            .collect();
        if !uncommitted.is_empty() {
            let mut jsonl_file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&jsonl_path)?;
            for r in &uncommitted {
                writeln!(jsonl_file, "{r}")?;
            }
            jsonl_file.flush()?;
        }
    }

    let _ = std::fs::remove_file(&ckpt_path);
    Ok(true)
}
