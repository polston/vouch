//! Memory-Mapped Binary Audit Log Persistence & Indexing (`journal.vlog`, M8.1).
//!
//! Provides a zero-copy binary event journal format (`.vlog`) with an offset index
//! footer table and 32-byte header (`VLOG` magic, version, record count, index offset,
//! IEEE 802.3 CRC32) for multi-gigabyte audit trails with sub-millisecond $O(\log N)$
//! timestamp seeking and index-level verdict filtering.
//!
//! Self-heals automatically if an unclean shutdown or torn write leaves the index footer
//! missing or out of sync with the CRC32-framed data region.

use crate::journal::{OutcomeRecord, Record};
use crate::journal_wal::crc32;
use crate::outcome::Outcome;
use sha2::{Digest, Sha256};
use std::fs::{create_dir_all, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

pub const VLOG_MAGIC: [u8; 4] = *b"VLOG";
pub const VLOG_VERSION: u32 = 1;
pub const VLOG_HEADER_LEN: usize = 32;
pub const VLOG_INDEX_ENTRY_LEN: usize = 24;
pub const VLOG_FRAME_HEADER_LEN: usize = 16; // 4 bytes payload_len + 4 bytes payload_crc32 + 8 bytes chain_tag
pub const VLOG_GENESIS_SEED: [u8; 32] = *b"VOUCH_VLOG_GENESIS_SHA256_V00001";
pub const VLOG_GENESIS_TAG: u64 = 0x564f_5543_485f_474e; // "VOUCH_GN"

pub const VCHK_MAGIC: [u8; 4] = *b"VCHK";
pub const VCHK_VERSION: u32 = 1;
pub const VCHK_ENTRY_LEN: usize = 96;
pub const VCHK_GENESIS_SEED: [u8; 32] = *b"VOUCH_VCHK_GENESIS_SHA256_V00001";
pub const VCHK_GENESIS_DIGEST: u64 = 0x564f_5543_485f_434b; // "VOUCH_CK"

pub const VBUNDLE_MAGIC: [u8; 4] = *b"VBND";
pub const VBUNDLE_VERSION: u32 = 1;
pub const VBUNDLE_DELTA_VERSION: u32 = 2;
pub const VBUNDLE_HEADER_LEN: usize = 96;
pub const VBUNDLE_DELTA_ANCHOR_LEN: usize = 48;
pub const VBUNDLE_SEAL_SEED: [u8; 32] = *b"VOUCH_VBUNDLE_SEAL_SHA256_V00001";

/// Compute a 64-bit rolling cryptographic hash chain tag over `(VLOG_GENESIS_SEED, prev_tag, seq_idx, payload)`.
pub fn compute_frame_chain_tag(prev_tag: u64, seq_idx: u64, payload: &[u8]) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(VLOG_GENESIS_SEED);
    hasher.update(prev_tag.to_le_bytes());
    hasher.update(seq_idx.to_le_bytes());
    hasher.update(payload);
    let digest = hasher.finalize();
    u64::from_le_bytes(digest[0..8].try_into().unwrap())
}

/// Compute a 64-bit rolling cryptographic digest over a compaction checkpoint entry.
#[allow(clippy::too_many_arguments)]
pub fn compute_checkpoint_digest(
    prev_checkpoint_digest: u64,
    checkpoint_seq: u64,
    timestamp_secs: u64,
    pre_compact_records: u64,
    pre_compact_terminal_tag: u64,
    pruned_records: u64,
    post_compact_records: u64,
    post_compact_first_tag: u64,
    post_compact_terminal_tag: u64,
) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(VCHK_GENESIS_SEED);
    hasher.update(prev_checkpoint_digest.to_le_bytes());
    hasher.update(checkpoint_seq.to_le_bytes());
    hasher.update(timestamp_secs.to_le_bytes());
    hasher.update(pre_compact_records.to_le_bytes());
    hasher.update(pre_compact_terminal_tag.to_le_bytes());
    hasher.update(pruned_records.to_le_bytes());
    hasher.update(post_compact_records.to_le_bytes());
    hasher.update(post_compact_first_tag.to_le_bytes());
    hasher.update(post_compact_terminal_tag.to_le_bytes());
    let digest = hasher.finalize();
    u64::from_le_bytes(digest[0..8].try_into().unwrap())
}

/// Fixed 96-byte detached compaction checkpoint record stored in `journal.vchk`.
/// Links the pre-compaction `.vlog` hash chain terminal tag to the post-compaction
/// `.vlog` first and terminal tags, forming a verifiable multi-generation lineage chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VlogCheckpointEntry {
    pub version: u32,
    pub checkpoint_seq: u64,
    pub timestamp_secs: u64,
    pub pre_compact_records: u64,
    pub pre_compact_terminal_tag: u64,
    pub pruned_records: u64,
    pub post_compact_records: u64,
    pub post_compact_first_tag: u64,
    pub post_compact_terminal_tag: u64,
    pub prev_checkpoint_digest: u64,
    pub checkpoint_digest: u64,
    pub entry_crc32: u32,
}

impl VlogCheckpointEntry {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        checkpoint_seq: u64,
        timestamp_secs: u64,
        pre_compact_records: u64,
        pre_compact_terminal_tag: u64,
        pruned_records: u64,
        post_compact_records: u64,
        post_compact_first_tag: u64,
        post_compact_terminal_tag: u64,
        prev_checkpoint_digest: u64,
    ) -> Self {
        let checkpoint_digest = compute_checkpoint_digest(
            prev_checkpoint_digest,
            checkpoint_seq,
            timestamp_secs,
            pre_compact_records,
            pre_compact_terminal_tag,
            pruned_records,
            post_compact_records,
            post_compact_first_tag,
            post_compact_terminal_tag,
        );
        let mut entry = Self {
            version: VCHK_VERSION,
            checkpoint_seq,
            timestamp_secs,
            pre_compact_records,
            pre_compact_terminal_tag,
            pruned_records,
            post_compact_records,
            post_compact_first_tag,
            post_compact_terminal_tag,
            prev_checkpoint_digest,
            checkpoint_digest,
            entry_crc32: 0,
        };
        entry.entry_crc32 = entry.compute_crc();
        entry
    }

    pub fn compute_crc(&self) -> u32 {
        let mut buf = [0u8; 88];
        buf[0..4].copy_from_slice(&VCHK_MAGIC);
        buf[4..8].copy_from_slice(&self.version.to_le_bytes());
        buf[8..16].copy_from_slice(&self.checkpoint_seq.to_le_bytes());
        buf[16..24].copy_from_slice(&self.timestamp_secs.to_le_bytes());
        buf[24..32].copy_from_slice(&self.pre_compact_records.to_le_bytes());
        buf[32..40].copy_from_slice(&self.pre_compact_terminal_tag.to_le_bytes());
        buf[40..48].copy_from_slice(&self.pruned_records.to_le_bytes());
        buf[48..56].copy_from_slice(&self.post_compact_records.to_le_bytes());
        buf[56..64].copy_from_slice(&self.post_compact_first_tag.to_le_bytes());
        buf[64..72].copy_from_slice(&self.post_compact_terminal_tag.to_le_bytes());
        buf[72..80].copy_from_slice(&self.prev_checkpoint_digest.to_le_bytes());
        buf[80..88].copy_from_slice(&self.checkpoint_digest.to_le_bytes());
        crc32(&buf)
    }

    pub fn to_bytes(&self) -> [u8; VCHK_ENTRY_LEN] {
        let mut out = [0u8; VCHK_ENTRY_LEN];
        out[0..4].copy_from_slice(&VCHK_MAGIC);
        out[4..8].copy_from_slice(&self.version.to_le_bytes());
        out[8..16].copy_from_slice(&self.checkpoint_seq.to_le_bytes());
        out[16..24].copy_from_slice(&self.timestamp_secs.to_le_bytes());
        out[24..32].copy_from_slice(&self.pre_compact_records.to_le_bytes());
        out[32..40].copy_from_slice(&self.pre_compact_terminal_tag.to_le_bytes());
        out[40..48].copy_from_slice(&self.pruned_records.to_le_bytes());
        out[48..56].copy_from_slice(&self.post_compact_records.to_le_bytes());
        out[56..64].copy_from_slice(&self.post_compact_first_tag.to_le_bytes());
        out[64..72].copy_from_slice(&self.post_compact_terminal_tag.to_le_bytes());
        out[72..80].copy_from_slice(&self.prev_checkpoint_digest.to_le_bytes());
        out[80..88].copy_from_slice(&self.checkpoint_digest.to_le_bytes());
        out[88..92].copy_from_slice(&self.entry_crc32.to_le_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < VCHK_ENTRY_LEN {
            return Err(format!(
                "vchk entry truncated: expected {VCHK_ENTRY_LEN} bytes, got {}",
                bytes.len()
            ));
        }
        if bytes[0..4] != VCHK_MAGIC {
            return Err("invalid vchk magic".to_string());
        }
        let version = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        if version != VCHK_VERSION {
            return Err(format!("unsupported vchk version: {version}"));
        }
        let checkpoint_seq = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        let timestamp_secs = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
        let pre_compact_records = u64::from_le_bytes(bytes[24..32].try_into().unwrap());
        let pre_compact_terminal_tag = u64::from_le_bytes(bytes[32..40].try_into().unwrap());
        let pruned_records = u64::from_le_bytes(bytes[40..48].try_into().unwrap());
        let post_compact_records = u64::from_le_bytes(bytes[48..56].try_into().unwrap());
        let post_compact_first_tag = u64::from_le_bytes(bytes[56..64].try_into().unwrap());
        let post_compact_terminal_tag = u64::from_le_bytes(bytes[64..72].try_into().unwrap());
        let prev_checkpoint_digest = u64::from_le_bytes(bytes[72..80].try_into().unwrap());
        let checkpoint_digest = u64::from_le_bytes(bytes[80..88].try_into().unwrap());
        let entry_crc32 = u32::from_le_bytes(bytes[88..92].try_into().unwrap());

        let entry = Self {
            version,
            checkpoint_seq,
            timestamp_secs,
            pre_compact_records,
            pre_compact_terminal_tag,
            pruned_records,
            post_compact_records,
            post_compact_first_tag,
            post_compact_terminal_tag,
            prev_checkpoint_digest,
            checkpoint_digest,
            entry_crc32,
        };
        let actual_crc = entry.compute_crc();
        if actual_crc != entry_crc32 {
            return Err(format!(
                "vchk entry {checkpoint_seq} crc mismatch: expected {entry_crc32:08x}, got {actual_crc:08x}"
            ));
        }
        let expected_digest = compute_checkpoint_digest(
            prev_checkpoint_digest,
            checkpoint_seq,
            timestamp_secs,
            pre_compact_records,
            pre_compact_terminal_tag,
            pruned_records,
            post_compact_records,
            post_compact_first_tag,
            post_compact_terminal_tag,
        );
        if checkpoint_digest != expected_digest {
            return Err(format!(
                "vchk entry {checkpoint_seq} digest mismatch: expected {expected_digest:016x}, got {checkpoint_digest:016x}"
            ));
        }
        Ok(entry)
    }
}

pub const VERDICT_ALLOW: u8 = 0;
pub const VERDICT_ASK: u8 = 1;
pub const VERDICT_DENY: u8 = 2;
pub const VERDICT_ABSTAIN: u8 = 3;
pub const VERDICT_UNKNOWN: u8 = 255;

pub const OUTCOME_PENDING: u8 = 0;
pub const OUTCOME_EXECUTED: u8 = 1;
pub const OUTCOME_DENIED: u8 = 2;
pub const OUTCOME_UNKNOWN: u8 = 3;
pub const OUTCOME_FAILED: u8 = 4;

pub fn verdict_to_code(verdict: &str) -> u8 {
    match verdict.to_ascii_lowercase().as_str() {
        "allow" => VERDICT_ALLOW,
        "ask" => VERDICT_ASK,
        "deny" => VERDICT_DENY,
        "abstain" => VERDICT_ABSTAIN,
        _ => VERDICT_UNKNOWN,
    }
}

pub fn code_to_verdict(code: u8) -> &'static str {
    match code {
        VERDICT_ALLOW => "allow",
        VERDICT_ASK => "ask",
        VERDICT_DENY => "deny",
        VERDICT_ABSTAIN => "abstain",
        _ => "unknown",
    }
}

pub fn outcome_to_code(outcome: Outcome) -> u8 {
    match outcome {
        Outcome::Pending => OUTCOME_PENDING,
        Outcome::Executed => OUTCOME_EXECUTED,
        Outcome::Denied => OUTCOME_DENIED,
        Outcome::Unknown => OUTCOME_UNKNOWN,
        Outcome::Failed => OUTCOME_FAILED,
    }
}

pub fn code_to_outcome(code: u8) -> Outcome {
    match code {
        OUTCOME_PENDING => Outcome::Pending,
        OUTCOME_EXECUTED => Outcome::Executed,
        OUTCOME_DENIED => Outcome::Denied,
        OUTCOME_FAILED => Outcome::Failed,
        _ => Outcome::Unknown,
    }
}

/// Fixed 32-byte header at offset 0 of `journal.vlog`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VlogHeader {
    pub version: u32,
    pub record_count: u64,
    pub index_offset: u64,
    pub header_crc32: u32,
}

impl VlogHeader {
    pub fn new(record_count: u64, index_offset: u64) -> Self {
        let mut h = Self {
            version: VLOG_VERSION,
            record_count,
            index_offset,
            header_crc32: 0,
        };
        h.header_crc32 = h.compute_crc();
        h
    }

    pub fn empty() -> Self {
        Self::new(0, VLOG_HEADER_LEN as u64)
    }

    pub fn compute_crc(&self) -> u32 {
        let mut buf = [0u8; 24];
        buf[0..4].copy_from_slice(&VLOG_MAGIC);
        buf[4..8].copy_from_slice(&self.version.to_le_bytes());
        buf[8..16].copy_from_slice(&self.record_count.to_le_bytes());
        buf[16..24].copy_from_slice(&self.index_offset.to_le_bytes());
        crc32(&buf)
    }

    pub fn to_bytes(&self) -> [u8; VLOG_HEADER_LEN] {
        let mut out = [0u8; VLOG_HEADER_LEN];
        out[0..4].copy_from_slice(&VLOG_MAGIC);
        out[4..8].copy_from_slice(&self.version.to_le_bytes());
        out[8..16].copy_from_slice(&self.record_count.to_le_bytes());
        out[16..24].copy_from_slice(&self.index_offset.to_le_bytes());
        out[24..28].copy_from_slice(&self.header_crc32.to_le_bytes());
        // bytes 28..32 reserved 0
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < VLOG_HEADER_LEN {
            return Err(format!(
                "vlog header truncated: expected {VLOG_HEADER_LEN} bytes, got {}",
                bytes.len()
            ));
        }
        if bytes[0..4] != VLOG_MAGIC {
            return Err("invalid vlog magic".to_string());
        }
        let version = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        if version != VLOG_VERSION {
            return Err(format!("unsupported vlog version: {version}"));
        }
        let record_count = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        let index_offset = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
        let header_crc32 = u32::from_le_bytes(bytes[24..28].try_into().unwrap());
        let header = Self {
            version,
            record_count,
            index_offset,
            header_crc32,
        };
        let actual_crc = header.compute_crc();
        if actual_crc != header_crc32 {
            return Err(format!(
                "vlog header crc mismatch: expected {header_crc32:08x}, got {actual_crc:08x}"
            ));
        }
        if index_offset < VLOG_HEADER_LEN as u64 {
            return Err(format!("invalid index_offset: {index_offset}"));
        }
        Ok(header)
    }
}

/// Fixed 24-byte index entry stored in the contiguous index table starting at `index_offset`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VlogIndexEntry {
    pub timestamp_secs: u64,
    pub record_offset: u64,
    pub record_len: u32,
    pub verdict_code: u8,
    pub outcome_code: u8,
    pub flags: u16,
}

impl VlogIndexEntry {
    pub const FLAG_MEASUREMENT: u16 = 1 << 0;

    pub fn from_record(rec: &Record, record_offset: u64, record_len: u32) -> Self {
        let timestamp_secs = rec.ts.trim().parse::<u64>().unwrap_or(0);
        let verdict_code = verdict_to_code(&rec.verdict);
        let outcome_code = outcome_to_code(rec.outcome);
        let mut flags = 0u16;
        if rec.measurement {
            flags |= Self::FLAG_MEASUREMENT;
        }
        Self {
            timestamp_secs,
            record_offset,
            record_len,
            verdict_code,
            outcome_code,
            flags,
        }
    }

    pub fn to_bytes(&self) -> [u8; VLOG_INDEX_ENTRY_LEN] {
        let mut out = [0u8; VLOG_INDEX_ENTRY_LEN];
        out[0..8].copy_from_slice(&self.timestamp_secs.to_le_bytes());
        out[8..16].copy_from_slice(&self.record_offset.to_le_bytes());
        out[16..20].copy_from_slice(&self.record_len.to_le_bytes());
        out[20] = self.verdict_code;
        out[21] = self.outcome_code;
        out[22..24].copy_from_slice(&self.flags.to_le_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < VLOG_INDEX_ENTRY_LEN {
            return None;
        }
        let timestamp_secs = u64::from_le_bytes(bytes[0..8].try_into().ok()?);
        let record_offset = u64::from_le_bytes(bytes[8..16].try_into().ok()?);
        let record_len = u32::from_le_bytes(bytes[16..20].try_into().ok()?);
        let verdict_code = bytes[20];
        let outcome_code = bytes[21];
        let flags = u16::from_le_bytes(bytes[22..24].try_into().ok()?);
        Some(Self {
            timestamp_secs,
            record_offset,
            record_len,
            verdict_code,
            outcome_code,
            flags,
        })
    }
}

fn write_str_field(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    let len = bytes.len() as u32;
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(bytes);
}

fn read_str_field<'a>(data: &'a [u8], cursor: &mut usize) -> Result<&'a str, String> {
    if *cursor + 4 > data.len() {
        return Err("truncated string length".to_string());
    }
    let len = u32::from_le_bytes(data[*cursor..*cursor + 4].try_into().unwrap()) as usize;
    *cursor += 4;
    if *cursor + len > data.len() {
        return Err("truncated string bytes".to_string());
    }
    let s = std::str::from_utf8(&data[*cursor..*cursor + len])
        .map_err(|e| format!("invalid utf-8 in vlog record: {e}"))?;
    *cursor += len;
    Ok(s)
}

/// Deterministic binary serialization of a `Record` payload.
pub fn encode_record_payload(rec: &Record) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);
    write_str_field(&mut buf, &rec.id);
    write_str_field(&mut buf, &rec.ts);
    write_str_field(&mut buf, &rec.session);
    write_str_field(&mut buf, &rec.tool);
    write_str_field(&mut buf, &rec.cmd);
    write_str_field(&mut buf, &rec.verdict);
    write_str_field(&mut buf, &rec.reason);
    write_str_field(&mut buf, &rec.mode);
    write_str_field(&mut buf, &rec.cwd);
    buf.push(outcome_to_code(rec.outcome));
    write_str_field(&mut buf, &rec.lang);
    write_str_field(&mut buf, &rec.permission_mode);
    write_str_field(&mut buf, &rec.host);
    buf.extend_from_slice(&(rec.count as u64).to_le_bytes());
    buf.push(u8::from(rec.measurement));
    buf
}

/// Deterministic binary deserialization of a `Record` payload.
pub fn decode_record_payload(data: &[u8]) -> Result<Record, String> {
    let mut cursor = 0;
    let id = read_str_field(data, &mut cursor)?.to_string();
    let ts = read_str_field(data, &mut cursor)?.to_string();
    let session = read_str_field(data, &mut cursor)?.to_string();
    let tool = read_str_field(data, &mut cursor)?.to_string();
    let cmd = read_str_field(data, &mut cursor)?.to_string();
    let verdict = read_str_field(data, &mut cursor)?.to_string();
    let reason = read_str_field(data, &mut cursor)?.to_string();
    let mode = read_str_field(data, &mut cursor)?.to_string();
    let cwd = read_str_field(data, &mut cursor)?.to_string();
    if cursor >= data.len() {
        return Err("truncated outcome byte".to_string());
    }
    let outcome = code_to_outcome(data[cursor]);
    cursor += 1;
    let lang = read_str_field(data, &mut cursor)?.to_string();
    let permission_mode = read_str_field(data, &mut cursor)?.to_string();
    let host = read_str_field(data, &mut cursor)?.to_string();
    if cursor + 9 > data.len() {
        return Err("truncated count/measurement tail".to_string());
    }
    let count = u64::from_le_bytes(data[cursor..cursor + 8].try_into().unwrap()) as usize;
    cursor += 8;
    let measurement = data[cursor] != 0;
    Ok(Record {
        id,
        ts,
        session,
        tool,
        cmd,
        verdict,
        reason,
        mode,
        cwd,
        outcome,
        lang,
        permission_mode,
        host,
        count: count.max(1),
        measurement,
    })
}

/// Encode a `Record` into a chained framed data block (`[len: u32][crc32: u32][chain_tag: u64][payload]`).
/// Returns `(frame_bytes, chain_tag)`.
pub fn encode_record_frame_chained(rec: &Record, prev_tag: u64, seq_idx: u64) -> (Vec<u8>, u64) {
    let payload = encode_record_payload(rec);
    let len = payload.len() as u32;
    let checksum = crc32(&payload);
    let chain_tag = compute_frame_chain_tag(prev_tag, seq_idx, &payload);
    let mut frame = Vec::with_capacity(VLOG_FRAME_HEADER_LEN + payload.len());
    frame.extend_from_slice(&len.to_le_bytes());
    frame.extend_from_slice(&checksum.to_le_bytes());
    frame.extend_from_slice(&chain_tag.to_le_bytes());
    frame.extend_from_slice(&payload);
    (frame, chain_tag)
}

/// Encode a `Record` into a standalone genesis-chained framed data block (`[len: u32][crc32: u32][chain_tag: u64][payload]`).
pub fn encode_record_frame(rec: &Record) -> Vec<u8> {
    encode_record_frame_chained(rec, VLOG_GENESIS_TAG, 0).0
}

/// Decode a single framed record at `offset` within `data`, returning `(Record, frame_total_bytes, chain_tag, payload_slice)`.
pub fn decode_record_frame_at_with_tag(
    data: &[u8],
    offset: usize,
) -> Result<(Record, usize, u64, &[u8]), String> {
    if offset + VLOG_FRAME_HEADER_LEN > data.len() {
        return Err("frame header out of bounds".to_string());
    }
    let len = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
    let expected_crc = u32::from_le_bytes(data[offset + 4..offset + 8].try_into().unwrap());
    let chain_tag = u64::from_le_bytes(data[offset + 8..offset + 16].try_into().unwrap());
    let payload_start = offset + VLOG_FRAME_HEADER_LEN;
    let payload_end = payload_start.saturating_add(len);
    if payload_end > data.len() {
        return Err("frame payload truncated".to_string());
    }
    let payload = &data[payload_start..payload_end];
    let actual_crc = crc32(payload);
    if actual_crc != expected_crc {
        return Err(format!(
            "frame crc mismatch at offset {offset}: expected {expected_crc:08x}, got {actual_crc:08x}"
        ));
    }
    let rec = decode_record_payload(payload)?;
    Ok((rec, VLOG_FRAME_HEADER_LEN + len, chain_tag, payload))
}

/// Decode a single framed record at `offset` within `data`.
/// Returns `(Record, frame_total_bytes)`.
pub fn decode_record_frame_at(data: &[u8], offset: usize) -> Result<(Record, usize), String> {
    let (rec, frame_len, _, _) = decode_record_frame_at_with_tag(data, offset)?;
    Ok((rec, frame_len))
}

/// Scans the data region of a `.vlog` byte buffer from byte 32, recovering all valid
/// CRC32-verified frames and rebuilding the index table up to the last valid frame.
pub fn scan_and_rebuild_index(
    data: &[u8],
    max_data_end: Option<usize>,
) -> (Vec<Record>, Vec<VlogIndexEntry>, usize) {
    let mut records = Vec::new();
    let mut index = Vec::new();
    if data.len() < VLOG_HEADER_LEN {
        return (records, index, VLOG_HEADER_LEN);
    }
    let limit = max_data_end.unwrap_or(data.len()).min(data.len());
    let mut offset = VLOG_HEADER_LEN;
    while offset + VLOG_FRAME_HEADER_LEN <= limit {
        match decode_record_frame_at(data, offset) {
            Ok((rec, frame_len)) => {
                if offset + frame_len > limit {
                    break;
                }
                let entry = VlogIndexEntry::from_record(&rec, offset as u64, frame_len as u32);
                records.push(rec);
                index.push(entry);
                offset += frame_len;
            }
            Err(_) => break,
        }
    }
    (records, index, offset)
}

/// Memory-mapped buffer wrapper with automatic `munmap` on Unix and `Vec<u8>` fallback.
pub struct MappedVlogBuffer {
    #[cfg(unix)]
    ptr: *mut libc::c_void,
    #[cfg(unix)]
    mapped_len: usize,
    fallback: Vec<u8>,
}

// Safety: MappedVlogBuffer maps read-only pages (`PROT_READ`, `MAP_PRIVATE`) and never mutates through `ptr`.
unsafe impl Send for MappedVlogBuffer {}
unsafe impl Sync for MappedVlogBuffer {}

impl MappedVlogBuffer {
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let mut file = File::open(path)?;
        let len = file.metadata()?.len() as usize;
        if len == 0 {
            return Ok(Self {
                #[cfg(unix)]
                ptr: std::ptr::null_mut(),
                #[cfg(unix)]
                mapped_len: 0,
                fallback: Vec::new(),
            });
        }

        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let fd = file.as_raw_fd();
            // SAFETY: `fd` is a valid open file descriptor with non-zero length `len`.
            // `PROT_READ` with `MAP_PRIVATE` creates a private read-only mapping.
            let ptr = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    len,
                    libc::PROT_READ,
                    libc::MAP_PRIVATE,
                    fd,
                    0,
                )
            };
            if ptr != libc::MAP_FAILED && !ptr.is_null() {
                return Ok(Self {
                    ptr,
                    mapped_len: len,
                    fallback: Vec::new(),
                });
            }
        }

        let mut fallback = Vec::with_capacity(len);
        file.read_to_end(&mut fallback)?;
        Ok(Self {
            #[cfg(unix)]
            ptr: std::ptr::null_mut(),
            #[cfg(unix)]
            mapped_len: 0,
            fallback,
        })
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self {
            #[cfg(unix)]
            ptr: std::ptr::null_mut(),
            #[cfg(unix)]
            mapped_len: 0,
            fallback: bytes,
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        #[cfg(unix)]
        {
            if !self.ptr.is_null() && self.mapped_len > 0 {
                // SAFETY: `ptr` was validated against `MAP_FAILED` and non-null with `mapped_len` bytes.
                return unsafe {
                    std::slice::from_raw_parts(self.ptr as *const u8, self.mapped_len)
                };
            }
        }
        &self.fallback
    }

    pub fn is_mmap(&self) -> bool {
        #[cfg(unix)]
        {
            !self.ptr.is_null() && self.mapped_len > 0
        }
        #[cfg(not(unix))]
        {
            false
        }
    }
}

impl Drop for MappedVlogBuffer {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            if !self.ptr.is_null() && self.mapped_len > 0 {
                unsafe {
                    let _ = libc::munmap(self.ptr, self.mapped_len);
                }
            }
        }
    }
}

/// Zero-copy reader for `.vlog` binary journal files.
pub struct VlogReader {
    buffer: MappedVlogBuffer,
    header: VlogHeader,
    index: Vec<VlogIndexEntry>,
}

impl VlogReader {
    pub fn open(path: &Path) -> Result<Self, String> {
        let buffer = MappedVlogBuffer::open(path).map_err(|e| format!("failed to open vlog: {e}"))?;
        Self::from_buffer(buffer)
    }

    pub fn from_buffer(buffer: MappedVlogBuffer) -> Result<Self, String> {
        let slice = buffer.as_slice();
        if slice.is_empty() {
            return Ok(Self {
                buffer,
                header: VlogHeader::empty(),
                index: Vec::new(),
            });
        }

        // Validate header; if header or index table is damaged/truncated, recover by scanning data region
        if let Ok(header) = VlogHeader::from_bytes(slice) {
            let idx_start = header.index_offset as usize;
            let expected_idx_bytes = (header.record_count as usize).saturating_mul(VLOG_INDEX_ENTRY_LEN);
            if idx_start <= slice.len() && idx_start.saturating_add(expected_idx_bytes) == slice.len() {
                let mut index = Vec::with_capacity(header.record_count as usize);
                let mut valid = true;
                for i in 0..(header.record_count as usize) {
                    let entry_offset = idx_start + i * VLOG_INDEX_ENTRY_LEN;
                    if let Some(entry) = VlogIndexEntry::from_bytes(&slice[entry_offset..entry_offset + VLOG_INDEX_ENTRY_LEN]) {
                        let rec_end = (entry.record_offset as usize).saturating_add(entry.record_len as usize);
                        if (entry.record_offset as usize) >= VLOG_HEADER_LEN && rec_end <= idx_start {
                            index.push(entry);
                        } else {
                            valid = false;
                            break;
                        }
                    } else {
                        valid = false;
                        break;
                    }
                }
                if valid {
                    return Ok(Self {
                        buffer,
                        header,
                        index,
                    });
                }
            }
        }

        // Fallback self-healing scan over CRC32-framed data records
        if slice.len() >= 4 && slice[0..4] != VLOG_MAGIC {
            return Err("invalid vlog magic".to_string());
        }
        let max_data = VlogHeader::from_bytes(slice)
            .ok()
            .map(|h| h.index_offset as usize);
        let (_, index, last_offset) = scan_and_rebuild_index(slice, max_data);
        let header = VlogHeader::new(index.len() as u64, last_offset as u64);
        Ok(Self {
            buffer,
            header,
            index,
        })
    }

    pub fn header(&self) -> &VlogHeader {
        &self.header
    }

    pub fn index(&self) -> &[VlogIndexEntry] {
        &self.index
    }

    pub fn len(&self) -> usize {
        self.index.len()
    }

    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    pub fn is_mmap(&self) -> bool {
        self.buffer.is_mmap()
    }

    /// Decode a single record by its 0-based index in $O(1)$ time using the offset table.
    pub fn get_record(&self, idx: usize) -> Result<Record, String> {
        let entry = self
            .index
            .get(idx)
            .ok_or_else(|| format!("record index {idx} out of bounds (len {})", self.index.len()))?;
        let slice = self.buffer.as_slice();
        let (mut rec, _) = decode_record_frame_at(slice, entry.record_offset as usize)?;
        rec.outcome = code_to_outcome(entry.outcome_code);
        Ok(rec)
    }

    /// Return the most recent record in $O(1)$ time without scanning earlier records.
    pub fn tail_record(&self) -> Option<Record> {
        if self.index.is_empty() {
            None
        } else {
            self.get_record(self.index.len() - 1).ok()
        }
    }

    /// Decode all records in the journal.
    pub fn all_records(&self) -> Vec<Record> {
        let mut out = Vec::with_capacity(self.index.len());
        for i in 0..self.index.len() {
            if let Ok(r) = self.get_record(i) {
                out.push(r);
            }
        }
        out
    }

    /// $O(\log N)$ binary search over the index table for records within `[start_ts, end_ts]` inclusive.
    /// Deserializes only the matching records inside the timestamp window.
    pub fn seek_timestamp_range(&self, start_ts: u64, end_ts: u64) -> Vec<Record> {
        if self.index.is_empty() || start_ts > end_ts {
            return Vec::new();
        }

        // Check if timestamps are monotonically non-decreasing (standard append order)
        let is_monotonic = self
            .index
            .windows(2)
            .all(|w| w[0].timestamp_secs <= w[1].timestamp_secs);

        if is_monotonic {
            let start_idx = self.index.partition_point(|e| e.timestamp_secs < start_ts);
            let end_idx = self.index.partition_point(|e| e.timestamp_secs <= end_ts);
            let mut out = Vec::with_capacity(end_idx.saturating_sub(start_idx));
            for idx in start_idx..end_idx {
                if let Ok(rec) = self.get_record(idx) {
                    out.push(rec);
                }
            }
            out
        } else {
            self.index
                .iter()
                .enumerate()
                .filter(|(_, e)| e.timestamp_secs >= start_ts && e.timestamp_secs <= end_ts)
                .filter_map(|(idx, _)| self.get_record(idx).ok())
                .collect()
        }
    }

    /// Index-level filter by verdict (`"allow"`, `"ask"`, `"deny"`, `"abstain"`).
    /// Inspects only the 24-byte `VlogIndexEntry` structs and deserializes only matching records.
    pub fn filter_by_verdict(&self, verdict: &str) -> Vec<Record> {
        let target_code = verdict_to_code(verdict);
        self.index
            .iter()
            .enumerate()
            .filter(|(_, e)| e.verdict_code == target_code)
            .filter_map(|(idx, _)| self.get_record(idx).ok())
            .collect()
    }
}

pub fn vlog_path(dir: &Path) -> PathBuf {
    dir.join("journal.vlog")
}

pub fn vidx_path(dir: &Path) -> PathBuf {
    dir.join("journal.vidx")
}

pub fn vchk_path(dir: &Path) -> PathBuf {
    dir.join("journal.vchk")
}

/// Read and validate all `VlogCheckpointEntry` records from a detached `journal.vchk` ledger.
/// Verifies entry CRC32, SHA-256 checkpoint digest, sequential `checkpoint_seq`, and cross-checkpoint continuity.
pub fn read_vlog_checkpoints(path: &Path) -> Result<Vec<VlogCheckpointEntry>, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("failed to read vchk: {e}"))?;
    parse_vlog_checkpoints_bytes(&bytes)
}

/// Parse and validate all `VlogCheckpointEntry` records from raw `journal.vchk` bytes.
pub fn parse_vlog_checkpoints_bytes(bytes: &[u8]) -> Result<Vec<VlogCheckpointEntry>, String> {
    if bytes.is_empty() {
        return Err("vchk file is empty".to_string());
    }
    if bytes.len() % VCHK_ENTRY_LEN != 0 {
        return Err(format!(
            "vchk file length {} is not a multiple of {VCHK_ENTRY_LEN}",
            bytes.len()
        ));
    }
    let count = bytes.len() / VCHK_ENTRY_LEN;
    let mut entries: Vec<VlogCheckpointEntry> = Vec::with_capacity(count);
    let mut expected_prev_digest = VCHK_GENESIS_DIGEST;

    for idx in 0..count {
        let start = idx * VCHK_ENTRY_LEN;
        let entry = VlogCheckpointEntry::from_bytes(&bytes[start..start + VCHK_ENTRY_LEN])?;
        if entry.checkpoint_seq != idx as u64 {
            return Err(format!(
                "vchk checkpoint_seq mismatch at index {idx}: expected {idx}, got {}",
                entry.checkpoint_seq
            ));
        }
        if entry.prev_checkpoint_digest != expected_prev_digest {
            return Err(format!(
                "vchk chain link broken at checkpoint {idx}: expected prev_checkpoint_digest {expected_prev_digest:016x}, got {:016x}",
                entry.prev_checkpoint_digest
            ));
        }
        if entry.post_compact_records > entry.pre_compact_records {
            return Err(format!(
                "vchk checkpoint {idx} invalid record counts: post_compact_records ({}) > pre_compact_records ({})",
                entry.post_compact_records, entry.pre_compact_records
            ));
        }
        let expected_pruned = entry
            .pre_compact_records
            .saturating_sub(entry.post_compact_records);
        if entry.pruned_records != expected_pruned {
            return Err(format!(
                "vchk checkpoint {idx} pruned_records ({}) != pre - post ({expected_pruned})",
                entry.pruned_records
            ));
        }
        if let Some(prev) = entries.last() {
            if entry.pre_compact_records < prev.post_compact_records {
                return Err(format!(
                    "vchk checkpoint {idx} pre_compact_records ({}) < previous post_compact_records ({})",
                    entry.pre_compact_records, prev.post_compact_records
                ));
            }
            if entry.pre_compact_records == prev.post_compact_records
                && entry.pre_compact_terminal_tag != prev.post_compact_terminal_tag
            {
                return Err(format!(
                    "vchk checkpoint {idx} pre_compact_terminal_tag ({:016x}) != previous post_compact_terminal_tag ({:016x}) with identical record count",
                    entry.pre_compact_terminal_tag, prev.post_compact_terminal_tag
                ));
            }
        }
        expected_prev_digest = entry.checkpoint_digest;
        entries.push(entry);
    }

    Ok(entries)
}

/// Atomically append a new `VlogCheckpointEntry` to `journal.vchk`.
fn append_vlog_checkpoint(
    dir: &Path,
    timestamp_secs: u64,
    pre_compact_records: u64,
    pre_compact_terminal_tag: u64,
    post_compact_records: u64,
    post_compact_first_tag: u64,
    post_compact_terminal_tag: u64,
) -> std::io::Result<VlogCheckpointEntry> {
    let path = vchk_path(dir);
    let existing = if path.exists() {
        read_vlog_checkpoints(&path)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?
    } else {
        Vec::new()
    };

    let checkpoint_seq = existing.len() as u64;
    let prev_checkpoint_digest = existing
        .last()
        .map(|e| e.checkpoint_digest)
        .unwrap_or(VCHK_GENESIS_DIGEST);
    let pruned_records = pre_compact_records.saturating_sub(post_compact_records);

    let entry = VlogCheckpointEntry::new(
        checkpoint_seq,
        timestamp_secs,
        pre_compact_records,
        pre_compact_terminal_tag,
        pruned_records,
        post_compact_records,
        post_compact_first_tag,
        post_compact_terminal_tag,
        prev_checkpoint_digest,
    );

    let tmp_path = dir.join("journal.vchk.tmp");
    {
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp_path)?;
        for prev in &existing {
            f.write_all(&prev.to_bytes())?;
        }
        f.write_all(&entry.to_bytes())?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp_path, &path)?;
    Ok(entry)
}

/// Compute `(first_frame_tag, terminal_frame_tag)` for a slice of records chained from `VLOG_GENESIS_TAG`.
pub fn compute_records_chain_tags(records: &[Record]) -> (u64, u64) {
    if records.is_empty() {
        return (VLOG_GENESIS_TAG, VLOG_GENESIS_TAG);
    }
    let mut prev_tag = VLOG_GENESIS_TAG;
    let mut first_tag = VLOG_GENESIS_TAG;
    for (seq_idx, rec) in records.iter().enumerate() {
        let payload = encode_record_payload(rec);
        let next_tag = compute_frame_chain_tag(prev_tag, seq_idx as u64, &payload);
        if seq_idx == 0 {
            first_tag = next_tag;
        }
        prev_tag = next_tag;
    }
    (first_tag, prev_tag)
}

fn write_all_vidx(dir: &Path, header: &VlogHeader, index_entries: &[VlogIndexEntry]) -> std::io::Result<()> {
    let path = vidx_path(dir);
    let tmp_path = dir.join("journal.vidx.tmp");
    {
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp_path)?;
        f.write_all(&header.to_bytes())?;
        for entry in index_entries {
            f.write_all(&entry.to_bytes())?;
        }
        f.sync_all()?;
    }
    std::fs::rename(&tmp_path, &path)?;
    Ok(())
}

/// Read the header and 24-byte index entries from a sidecar `journal.vidx` file.
pub fn read_vidx_entries(path: &Path) -> Result<(VlogHeader, Vec<VlogIndexEntry>), String> {
    let bytes = std::fs::read(path).map_err(|e| format!("failed to read vidx: {e}"))?;
    parse_vidx_bytes(&bytes)
}

/// Parse the header and 24-byte index entries from raw `journal.vidx` bytes.
pub fn parse_vidx_bytes(bytes: &[u8]) -> Result<(VlogHeader, Vec<VlogIndexEntry>), String> {
    let header = VlogHeader::from_bytes(bytes)?;
    let expected_len = VLOG_HEADER_LEN
        .saturating_add((header.record_count as usize).saturating_mul(VLOG_INDEX_ENTRY_LEN));
    if bytes.len() < expected_len {
        return Err(format!(
            "vidx truncated: expected {expected_len} bytes, got {}",
            bytes.len()
        ));
    }
    let mut entries = Vec::with_capacity(header.record_count as usize);
    for i in 0..(header.record_count as usize) {
        let start = VLOG_HEADER_LEN + i * VLOG_INDEX_ENTRY_LEN;
        let entry = VlogIndexEntry::from_bytes(&bytes[start..start + VLOG_INDEX_ENTRY_LEN])
            .ok_or_else(|| format!("invalid vidx entry at {i}"))?;
        entries.push(entry);
    }
    Ok((header, entries))
}

/// Atomically write a complete list of `Record`s as a clean `.vlog` file with header, index footer,
/// and synchronized `journal.vidx` sidecar index.
pub fn write_all_vlog(dir: &Path, records: &[Record]) -> std::io::Result<()> {
    create_dir_all(dir)?;
    let path = vlog_path(dir);
    let tmp_path = dir.join("journal.vlog.tmp");

    let mut data_frames: Vec<u8> = Vec::new();
    let mut index_entries: Vec<VlogIndexEntry> = Vec::with_capacity(records.len());

    let mut current_offset = VLOG_HEADER_LEN as u64;
    let mut prev_tag = VLOG_GENESIS_TAG;
    for (seq_idx, rec) in records.iter().enumerate() {
        let (frame, next_tag) = encode_record_frame_chained(rec, prev_tag, seq_idx as u64);
        prev_tag = next_tag;
        let frame_len = frame.len() as u32;
        let entry = VlogIndexEntry::from_record(rec, current_offset, frame_len);
        data_frames.extend_from_slice(&frame);
        index_entries.push(entry);
        current_offset += u64::from(frame_len);
    }

    let header = VlogHeader::new(index_entries.len() as u64, current_offset);

    {
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp_path)?;
        f.write_all(&header.to_bytes())?;
        f.write_all(&data_frames)?;
        for entry in &index_entries {
            f.write_all(&entry.to_bytes())?;
        }
        f.sync_all()?;
    }

    std::fs::rename(&tmp_path, &path)?;
    let _ = write_all_vidx(dir, &header, &index_entries);
    Ok(())
}

/// Append a single `Record` to `journal.vlog` and `journal.vidx`, updating the data region,
/// index footer, sidecar index, and 32-byte header.
/// If `journal.vlog` was corrupted or truncated at the tail, self-heals before appending.
pub fn append_vlog(dir: &Path, rec: &Record) -> std::io::Result<()> {
    create_dir_all(dir)?;
    let path = vlog_path(dir);
    if !path.exists() {
        return write_all_vlog(dir, std::slice::from_ref(rec));
    }

    let mut file = OpenOptions::new().read(true).write(true).open(&path)?;
    let file_len = file.metadata()?.len() as usize;
    if file_len < VLOG_HEADER_LEN {
        drop(file);
        return write_all_vlog(dir, std::slice::from_ref(rec));
    }

    let mut header_bytes = [0u8; VLOG_HEADER_LEN];
    file.read_exact(&mut header_bytes)?;

    if let Ok(header) = VlogHeader::from_bytes(&header_bytes) {
        let idx_offset = header.index_offset as usize;
        let expected_idx_len = (header.record_count as usize).saturating_mul(VLOG_INDEX_ENTRY_LEN);
        if idx_offset >= VLOG_HEADER_LEN && idx_offset.saturating_add(expected_idx_len) == file_len {
            // Fast path: read existing index footer, lookup parent chain_tag in O(1), overwrite at idx_offset
            file.seek(SeekFrom::Start(header.index_offset))?;
            let mut idx_bytes = vec![0u8; expected_idx_len];
            file.read_exact(&mut idx_bytes)?;

            let prev_tag_opt = if header.record_count == 0 {
                Some(VLOG_GENESIS_TAG)
            } else {
                let last_idx_start = expected_idx_len - VLOG_INDEX_ENTRY_LEN;
                if let Some(last_entry) = VlogIndexEntry::from_bytes(&idx_bytes[last_idx_start..]) {
                    let tag_offset = last_entry.record_offset.saturating_add(8);
                    if (tag_offset as usize).saturating_add(8) <= idx_offset
                        && file.seek(SeekFrom::Start(tag_offset)).is_ok()
                    {
                        let mut tag_buf = [0u8; 8];
                        if file.read_exact(&mut tag_buf).is_ok() {
                            Some(u64::from_le_bytes(tag_buf))
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            };

            if let Some(prev_tag) = prev_tag_opt {
                let (frame, _) = encode_record_frame_chained(rec, prev_tag, header.record_count);
                let frame_len = frame.len() as u32;

                let new_entry = VlogIndexEntry::from_record(rec, header.index_offset, frame_len);
                let new_entry_bytes = new_entry.to_bytes();
                idx_bytes.extend_from_slice(&new_entry_bytes);

                let new_index_offset = header.index_offset + u64::from(frame_len);
                let new_header = VlogHeader::new(header.record_count + 1, new_index_offset);
                let new_header_bytes = new_header.to_bytes();

                file.seek(SeekFrom::Start(header.index_offset))?;
                file.write_all(&frame)?;
                file.write_all(&idx_bytes)?;
                file.seek(SeekFrom::Start(0))?;
                file.write_all(&new_header_bytes)?;
                file.flush()?;

                // Update or create journal.vidx sidecar in O(1)
                let sidecar_path = vidx_path(dir);
                let expected_vidx_len = VLOG_HEADER_LEN.saturating_add(expected_idx_len);
                let updated_in_place =
                    if let Ok(mut vf) = OpenOptions::new().read(true).write(true).open(&sidecar_path) {
                        if vf.metadata().map(|m| m.len() as usize).unwrap_or(0) == expected_vidx_len {
                            vf.seek(SeekFrom::End(0)).is_ok()
                                && vf.write_all(&new_entry_bytes).is_ok()
                                && vf.seek(SeekFrom::Start(0)).is_ok()
                                && vf.write_all(&new_header_bytes).is_ok()
                                && vf.flush().is_ok()
                        } else {
                            false
                        }
                    } else {
                        false
                    };
                if !updated_in_place {
                    if let Ok(mut vf) = OpenOptions::new()
                        .create(true)
                        .write(true)
                        .truncate(true)
                        .open(&sidecar_path)
                    {
                        let _ = vf.write_all(&new_header_bytes);
                        let _ = vf.write_all(&idx_bytes);
                        let _ = vf.flush();
                    }
                }

                return Ok(());
            }
        }
    }

    // Slow path: self-heal by scanning valid frames and rewriting cleanly
    drop(file);
    let raw = std::fs::read(&path).unwrap_or_default();
    let max_data = VlogHeader::from_bytes(&raw)
        .ok()
        .map(|h| h.index_offset as usize);
    let (mut existing_records, _, _) = scan_and_rebuild_index(&raw, max_data);
    existing_records.push(rec.clone());
    write_all_vlog(dir, &existing_records)
}

/// Read all records from `journal.vlog` and fold in terminal outcomes from `outcomes.jsonl`.
pub fn all_vlog(dir: &Path, outcomes: &[OutcomeRecord]) -> Vec<Record> {
    let path = vlog_path(dir);
    let Ok(reader) = VlogReader::open(&path) else {
        return Vec::new();
    };
    let mut recs = reader.all_records();
    if !outcomes.is_empty() {
        let mut by_id = std::collections::HashMap::new();
        for o in outcomes {
            by_id.insert((o.host.clone(), o.id.clone()), o.outcome);
        }
        for r in &mut recs {
            if let Some(&out) = by_id.get(&(r.host.clone(), r.id.clone())) {
                r.outcome = out;
            }
        }
    }
    recs
}

/// Resolve the `.vlog` path corresponding to either `journal.vlog` or `journal.vidx`.
pub fn resolve_vlog_data_path(path: &Path) -> PathBuf {
    if path.extension().and_then(|e| e.to_str()) == Some("vidx") {
        path.with_extension("vlog")
    } else {
        path.to_path_buf()
    }
}

/// Inspect the current `.vlog` header and tail record watermark for initializing a live tail reader.
pub fn inspect_vlog_watermark(path: &Path) -> (u64, u64, Option<(String, String, String)>) {
    let data_path = resolve_vlog_data_path(path);
    let Ok(reader) = VlogReader::open(&data_path) else {
        return (0, VLOG_HEADER_LEN as u64, None);
    };
    let header = reader.header();
    let last_key = reader
        .tail_record()
        .map(|r| (r.ts, r.id, r.cmd));
    (header.record_count, header.index_offset, last_key)
}

/// Stream only newly appended frames from `.vlog` / `.vidx` in $O(\Delta)$ without re-scanning
/// historical payloads. Automatically self-heals if `compact_vlog` / `prune_and_compact`
/// atomically shrank the file between polls.
pub fn poll_vlog_delta(
    path: &Path,
    last_record_count: &mut u64,
    last_data_offset: &mut u64,
    last_record_key: &mut Option<(String, String, String)>,
) -> Vec<Record> {
    let data_path = resolve_vlog_data_path(path);
    let Ok(mut file) = File::open(&data_path) else {
        return Vec::new();
    };
    let Ok(meta) = file.metadata() else {
        return Vec::new();
    };
    let file_len = meta.len();
    if file_len < VLOG_HEADER_LEN as u64 {
        return Vec::new();
    }

    let mut header_bytes = [0u8; VLOG_HEADER_LEN];
    if file.read_exact(&mut header_bytes).is_err() {
        return Vec::new();
    }
    let Ok(header) = VlogHeader::from_bytes(&header_bytes) else {
        return Vec::new();
    };

    // Detect compaction shrink or truncation
    if header.index_offset < *last_data_offset || header.record_count < *last_record_count {
        drop(file);
        let Ok(reader) = VlogReader::open(&data_path) else {
            *last_record_count = 0;
            *last_data_offset = VLOG_HEADER_LEN as u64;
            return Vec::new();
        };
        let all = reader.all_records();
        let new_recs = if let Some(ref key) = last_record_key {
            if let Some(pos) = all
                .iter()
                .rposition(|r| &(r.ts.clone(), r.id.clone(), r.cmd.clone()) == key)
            {
                all[pos + 1..].to_vec()
            } else {
                Vec::new()
            }
        } else {
            all
        };
        *last_record_count = reader.header().record_count;
        *last_data_offset = reader.header().index_offset;
        if let Some(last) = new_recs.last().cloned().or_else(|| reader.tail_record()) {
            *last_record_key = Some((last.ts, last.id, last.cmd));
        }
        return new_recs;
    }

    if header.record_count == *last_record_count && header.index_offset == *last_data_offset {
        return Vec::new();
    }

    // Fast O(Delta) path: read only the new index entries and decode only the new frame range
    let delta_count = (header.record_count.saturating_sub(*last_record_count)) as usize;
    let start_offset = (*last_data_offset).max(VLOG_HEADER_LEN as u64);
    if header.index_offset < start_offset || header.index_offset > file_len {
        return Vec::new();
    }
    let delta_bytes_len = (header.index_offset - start_offset) as usize;
    if file.seek(SeekFrom::Start(start_offset)).is_err() {
        return Vec::new();
    }
    let mut delta_buf = vec![0u8; delta_bytes_len];
    if file.read_exact(&mut delta_buf).is_err() {
        return Vec::new();
    }

    // Also read corresponding new VlogIndexEntry items to preserve outcome codes if updated
    let idx_read_start = header
        .index_offset
        .saturating_add((*last_record_count).saturating_mul(VLOG_INDEX_ENTRY_LEN as u64));
    let mut new_entries = Vec::with_capacity(delta_count);
    if idx_read_start
        .saturating_add((delta_count * VLOG_INDEX_ENTRY_LEN) as u64)
        <= file_len
        && file.seek(SeekFrom::Start(idx_read_start)).is_ok()
    {
        let mut idx_buf = vec![0u8; delta_count * VLOG_INDEX_ENTRY_LEN];
        if file.read_exact(&mut idx_buf).is_ok() {
            for i in 0..delta_count {
                let s = i * VLOG_INDEX_ENTRY_LEN;
                if let Some(e) = VlogIndexEntry::from_bytes(&idx_buf[s..s + VLOG_INDEX_ENTRY_LEN]) {
                    new_entries.push(e);
                }
            }
        }
    }

    let mut out = Vec::with_capacity(delta_count);
    let mut cursor = 0usize;
    let mut entry_idx = 0usize;
    while cursor + VLOG_FRAME_HEADER_LEN <= delta_buf.len() {
        match decode_record_frame_at(&delta_buf, cursor) {
            Ok((mut rec, frame_len)) => {
                if let Some(entry) = new_entries.get(entry_idx) {
                    rec.outcome = code_to_outcome(entry.outcome_code);
                }
                cursor += frame_len;
                entry_idx += 1;
                out.push(rec);
            }
            Err(_) => break,
        }
    }

    *last_record_count = header.record_count;
    *last_data_offset = header.index_offset;
    if let Some(last) = out.last() {
        *last_record_key = Some((last.ts.clone(), last.id.clone(), last.cmd.clone()));
    }
    out
}

/// Verify the existing `journal.vlog` chain, write the compacted records to `journal.vlog`
/// and `journal.vidx`, and atomically append a `VlogCheckpointEntry` to `journal.vchk`.
pub fn write_compacted_vlog_with_checkpoint(
    dir: &Path,
    compacted_recs: &[Record],
) -> std::io::Result<()> {
    create_dir_all(dir)?;
    let path = vlog_path(dir);
    if !path.exists() {
        return write_all_vlog(dir, compacted_recs);
    }
    let pre_report = verify_vlog_integrity(&path)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    if !pre_report.valid {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "refusing to compact corrupted journal.vlog: {:?}",
                pre_report.tamper_finding
            ),
        ));
    }
    if pre_report.verified_records == 0 {
        return Ok(());
    }

    let (post_first_tag, post_terminal_tag) = compute_records_chain_tags(compacted_recs);
    write_all_vlog(dir, compacted_recs)?;

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    append_vlog_checkpoint(
        dir,
        now_secs,
        pre_report.verified_records,
        pre_report.terminal_chain_tag,
        compacted_recs.len() as u64,
        post_first_tag,
        post_terminal_tag,
    )?;
    Ok(())
}

/// Incrementally compact `journal.vlog` and `journal.vidx` according to `JournalPolicy`,
/// collapsing duplicate historical runs while preserving aggregated execution counts,
/// and recording a cryptographically chained checkpoint entry in `journal.vchk`.
pub fn compact_vlog(
    dir: &Path,
    policy: &crate::journal::JournalPolicy,
) -> std::io::Result<crate::journal::CompactionStats> {
    create_dir_all(dir)?;
    let path = vlog_path(dir);
    if !path.exists() {
        return Ok(crate::journal::CompactionStats::default());
    }
    let reader = VlogReader::open(&path)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let recs = reader.all_records();
    if recs.is_empty() {
        return Ok(crate::journal::CompactionStats::default());
    }
    let (compacted_recs, stats) = crate::journal::compact_records(&recs, policy);
    write_compacted_vlog_with_checkpoint(dir, &compacted_recs)?;
    Ok(stats)
}

/// Classification of tamper or corruption findings detected during `.vlog` cryptographic verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VlogTamperKind {
    HeaderCorrupted {
        detail: String,
    },
    FrameCrcMismatch {
        seq_idx: u64,
        offset: u64,
    },
    ChainLinkBroken {
        seq_idx: u64,
        offset: u64,
        expected_tag: u64,
        actual_tag: u64,
    },
    TruncatedFrame {
        seq_idx: u64,
        offset: u64,
    },
    SidecarIndexMismatch {
        detail: String,
    },
    CheckpointContinuityBroken {
        checkpoint_seq: u64,
        reason: String,
    },
    BundleSealCorrupted {
        detail: String,
    },
    DeltaParentMismatch {
        detail: String,
    },
}

/// Complete audit report returned by `verify_vlog_integrity` and `verify_vlog_bundle`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VlogIntegrityReport {
    pub valid: bool,
    pub verified_records: u64,
    pub verified_checkpoints: u64,
    pub terminal_chain_tag: u64,
    pub tamper_finding: Option<VlogTamperKind>,
}

/// Verify the cryptographic hash chain, CRC32 frame checksums, 32-byte header, index footer,
/// sidecar `journal.vidx` consistency, and detached `journal.vchk` compaction lineage of a `.vlog` binary journal file.
pub fn verify_vlog_integrity(path: &Path) -> Result<VlogIntegrityReport, String> {
    let data_path = resolve_vlog_data_path(path);
    let bytes = std::fs::read(&data_path).map_err(|e| format!("failed to read vlog: {e}"))?;
    let sidecar_path = data_path.with_extension("vidx");
    let vidx_bytes = if sidecar_path.exists() {
        Some(std::fs::read(&sidecar_path).map_err(|e| format!("failed to read vidx: {e}"))?)
    } else {
        None
    };
    let checkpoint_path = data_path.with_extension("vchk");
    let vchk_bytes = if checkpoint_path.exists() {
        Some(std::fs::read(&checkpoint_path).map_err(|e| format!("failed to read vchk: {e}"))?)
    } else {
        None
    };
    verify_vlog_slices(&bytes, vidx_bytes.as_deref(), vchk_bytes.as_deref())
}

/// Verify `.vlog` frames, optional `.vidx` sidecar index, and optional `.vchk` compaction checkpoints
/// entirely in memory from byte slices without requiring active filesystem state directory access.
pub fn verify_vlog_slices(
    bytes: &[u8],
    vidx_bytes: Option<&[u8]>,
    vchk_bytes: Option<&[u8]>,
) -> Result<VlogIntegrityReport, String> {
    verify_vlog_slices_from_anchor(bytes, vidx_bytes, vchk_bytes, 0, VLOG_GENESIS_TAG)
}

/// Verify `.vlog` frames starting from an explicit parent anchor `(base_seq_idx, initial_prev_tag)`.
/// For full genesis journals, `base_seq_idx == 0` and `initial_prev_tag == VLOG_GENESIS_TAG`.
/// For incremental delta slices, frame `i` (`0..record_count`) is verified against
/// `compute_frame_chain_tag(prev_tag, base_seq_idx + i, payload)` without re-encoding frame tags.
pub fn verify_vlog_slices_from_anchor(
    bytes: &[u8],
    vidx_bytes: Option<&[u8]>,
    vchk_bytes: Option<&[u8]>,
    base_seq_idx: u64,
    initial_prev_tag: u64,
) -> Result<VlogIntegrityReport, String> {
    if bytes.is_empty() {
        return Ok(VlogIntegrityReport {
            valid: true,
            verified_records: 0,
            verified_checkpoints: 0,
            terminal_chain_tag: initial_prev_tag,
            tamper_finding: None,
        });
    }

    let header = match VlogHeader::from_bytes(bytes) {
        Ok(h) => h,
        Err(detail) => {
            return Ok(VlogIntegrityReport {
                valid: false,
                verified_records: 0,
                verified_checkpoints: 0,
                terminal_chain_tag: initial_prev_tag,
                tamper_finding: Some(VlogTamperKind::HeaderCorrupted { detail }),
            });
        }
    };

    let idx_offset = header.index_offset as usize;
    let expected_idx_bytes = (header.record_count as usize).saturating_mul(VLOG_INDEX_ENTRY_LEN);

    let mut offset = VLOG_HEADER_LEN;
    let mut prev_tag = initial_prev_tag;
    let mut verified_records = 0u64;
    let mut expected_bounds: Vec<(u64, u32)> = Vec::with_capacity(header.record_count as usize);
    let mut chain_tags_by_seq: Vec<u64> = Vec::with_capacity(header.record_count as usize);

    for rel_idx in 0..header.record_count {
        let seq_idx = base_seq_idx.saturating_add(rel_idx);
        if offset + VLOG_FRAME_HEADER_LEN > bytes.len() || offset + VLOG_FRAME_HEADER_LEN > idx_offset
        {
            return Ok(VlogIntegrityReport {
                valid: false,
                verified_records,
                verified_checkpoints: 0,
                terminal_chain_tag: prev_tag,
                tamper_finding: Some(VlogTamperKind::TruncatedFrame {
                    seq_idx,
                    offset: offset as u64,
                }),
            });
        }

        let len = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        let expected_crc = u32::from_le_bytes(bytes[offset + 4..offset + 8].try_into().unwrap());
        let actual_tag = u64::from_le_bytes(bytes[offset + 8..offset + 16].try_into().unwrap());
        let payload_start = offset + VLOG_FRAME_HEADER_LEN;
        let payload_end = payload_start.saturating_add(len);

        if payload_end > bytes.len() || payload_end > idx_offset {
            return Ok(VlogIntegrityReport {
                valid: false,
                verified_records,
                verified_checkpoints: 0,
                terminal_chain_tag: prev_tag,
                tamper_finding: Some(VlogTamperKind::TruncatedFrame {
                    seq_idx,
                    offset: offset as u64,
                }),
            });
        }

        let payload = &bytes[payload_start..payload_end];
        let actual_crc = crc32(payload);
        if actual_crc != expected_crc {
            return Ok(VlogIntegrityReport {
                valid: false,
                verified_records,
                verified_checkpoints: 0,
                terminal_chain_tag: prev_tag,
                tamper_finding: Some(VlogTamperKind::FrameCrcMismatch {
                    seq_idx,
                    offset: offset as u64,
                }),
            });
        }

        if decode_record_payload(payload).is_err() {
            return Ok(VlogIntegrityReport {
                valid: false,
                verified_records,
                verified_checkpoints: 0,
                terminal_chain_tag: prev_tag,
                tamper_finding: Some(VlogTamperKind::TruncatedFrame {
                    seq_idx,
                    offset: offset as u64,
                }),
            });
        }

        let expected_tag = compute_frame_chain_tag(prev_tag, seq_idx, payload);
        if actual_tag != expected_tag {
            return Ok(VlogIntegrityReport {
                valid: false,
                verified_records,
                verified_checkpoints: 0,
                terminal_chain_tag: prev_tag,
                tamper_finding: Some(VlogTamperKind::ChainLinkBroken {
                    seq_idx,
                    offset: offset as u64,
                    expected_tag,
                    actual_tag,
                }),
            });
        }

        let frame_total_len = (VLOG_FRAME_HEADER_LEN + len) as u32;
        expected_bounds.push((offset as u64, frame_total_len));
        chain_tags_by_seq.push(actual_tag);
        prev_tag = actual_tag;
        verified_records += 1;
        offset = payload_end;
    }

    if offset != idx_offset {
        return Ok(VlogIntegrityReport {
            valid: false,
            verified_records,
            verified_checkpoints: 0,
            terminal_chain_tag: prev_tag,
            tamper_finding: Some(VlogTamperKind::HeaderCorrupted {
                detail: format!(
                    "data frame boundary {offset} does not match header index_offset {idx_offset}"
                ),
            }),
        });
    }

    if idx_offset.saturating_add(expected_idx_bytes) != bytes.len() {
        return Ok(VlogIntegrityReport {
            valid: false,
            verified_records,
            verified_checkpoints: 0,
            terminal_chain_tag: prev_tag,
            tamper_finding: Some(VlogTamperKind::TruncatedFrame {
                seq_idx: header.record_count,
                offset: idx_offset as u64,
            }),
        });
    }

    let mut footer_entries = Vec::with_capacity(header.record_count as usize);
    for (i, &(exp_off, exp_len)) in expected_bounds.iter().enumerate() {
        let entry_start = idx_offset + i * VLOG_INDEX_ENTRY_LEN;
        let Some(entry) =
            VlogIndexEntry::from_bytes(&bytes[entry_start..entry_start + VLOG_INDEX_ENTRY_LEN])
        else {
            return Ok(VlogIntegrityReport {
                valid: false,
                verified_records,
                verified_checkpoints: 0,
                terminal_chain_tag: prev_tag,
                tamper_finding: Some(VlogTamperKind::HeaderCorrupted {
                    detail: format!("invalid footer index entry at {i}"),
                }),
            });
        };
        if entry.record_offset != exp_off || entry.record_len != exp_len {
            return Ok(VlogIntegrityReport {
                valid: false,
                verified_records,
                verified_checkpoints: 0,
                terminal_chain_tag: prev_tag,
                tamper_finding: Some(VlogTamperKind::HeaderCorrupted {
                    detail: format!(
                        "footer index entry {i} offset/len ({}, {}) mismatches frame ({exp_off}, {exp_len})",
                        entry.record_offset, entry.record_len
                    ),
                }),
            });
        }
        footer_entries.push(entry);
    }

    if let Some(vidx_raw) = vidx_bytes {
        match parse_vidx_bytes(vidx_raw) {
            Ok((vidx_header, vidx_entries)) => {
                if vidx_header != header {
                    return Ok(VlogIntegrityReport {
                        valid: false,
                        verified_records,
                        verified_checkpoints: 0,
                        terminal_chain_tag: prev_tag,
                        tamper_finding: Some(VlogTamperKind::SidecarIndexMismatch {
                            detail: format!(
                                "sidecar header (records={}, index_offset={}) != vlog header (records={}, index_offset={})",
                                vidx_header.record_count,
                                vidx_header.index_offset,
                                header.record_count,
                                header.index_offset
                            ),
                        }),
                    });
                }
                if vidx_entries != footer_entries {
                    return Ok(VlogIntegrityReport {
                        valid: false,
                        verified_records,
                        verified_checkpoints: 0,
                        terminal_chain_tag: prev_tag,
                        tamper_finding: Some(VlogTamperKind::SidecarIndexMismatch {
                            detail: "sidecar index entries diverge from vlog footer index"
                                .to_string(),
                        }),
                    });
                }
            }
            Err(detail) => {
                return Ok(VlogIntegrityReport {
                    valid: false,
                    verified_records,
                    verified_checkpoints: 0,
                    terminal_chain_tag: prev_tag,
                    tamper_finding: Some(VlogTamperKind::SidecarIndexMismatch { detail }),
                });
            }
        }
    }

    let mut verified_checkpoints = 0u64;
    if let Some(vchk_raw) = vchk_bytes {
        if !vchk_raw.is_empty() {
            let checkpoints = match parse_vlog_checkpoints_bytes(vchk_raw) {
                Ok(ckpts) => ckpts,
                Err(reason) => {
                    return Ok(VlogIntegrityReport {
                        valid: false,
                        verified_records,
                        verified_checkpoints: 0,
                        terminal_chain_tag: prev_tag,
                        tamper_finding: Some(VlogTamperKind::CheckpointContinuityBroken {
                            checkpoint_seq: 0,
                            reason,
                        }),
                    });
                }
            };

            if let Some(last_ckpt) = checkpoints.last() {
                if verified_records < last_ckpt.post_compact_records {
                    return Ok(VlogIntegrityReport {
                        valid: false,
                        verified_records,
                        verified_checkpoints: checkpoints.len().saturating_sub(1) as u64,
                        terminal_chain_tag: prev_tag,
                        tamper_finding: Some(VlogTamperKind::CheckpointContinuityBroken {
                            checkpoint_seq: last_ckpt.checkpoint_seq,
                            reason: format!(
                                "live vlog record count ({verified_records}) is smaller than checkpoint post_compact_records ({})",
                                last_ckpt.post_compact_records
                            ),
                        }),
                    });
                }
                if last_ckpt.post_compact_records > 0 {
                    let actual_first_tag = chain_tags_by_seq[0];
                    if actual_first_tag != last_ckpt.post_compact_first_tag {
                        return Ok(VlogIntegrityReport {
                            valid: false,
                            verified_records,
                            verified_checkpoints: checkpoints.len().saturating_sub(1) as u64,
                            terminal_chain_tag: prev_tag,
                            tamper_finding: Some(VlogTamperKind::CheckpointContinuityBroken {
                                checkpoint_seq: last_ckpt.checkpoint_seq,
                                reason: format!(
                                    "live vlog first frame tag ({actual_first_tag:016x}) != checkpoint post_compact_first_tag ({:016x})",
                                    last_ckpt.post_compact_first_tag
                                ),
                            }),
                        });
                    }
                    let anchor_idx = (last_ckpt.post_compact_records - 1) as usize;
                    let actual_anchor_tag = chain_tags_by_seq[anchor_idx];
                    if actual_anchor_tag != last_ckpt.post_compact_terminal_tag {
                        return Ok(VlogIntegrityReport {
                            valid: false,
                            verified_records,
                            verified_checkpoints: checkpoints.len().saturating_sub(1) as u64,
                            terminal_chain_tag: prev_tag,
                            tamper_finding: Some(VlogTamperKind::CheckpointContinuityBroken {
                                checkpoint_seq: last_ckpt.checkpoint_seq,
                                reason: format!(
                                    "live vlog anchor frame {anchor_idx} tag ({actual_anchor_tag:016x}) != checkpoint post_compact_terminal_tag ({:016x})",
                                    last_ckpt.post_compact_terminal_tag
                                ),
                            }),
                        });
                    }
                }
            }
            verified_checkpoints = checkpoints.len() as u64;
        }
    }

    Ok(VlogIntegrityReport {
        valid: true,
        verified_records,
        verified_checkpoints,
        terminal_chain_tag: prev_tag,
        tamper_finding: None,
    })
}

/// Fixed 96-byte header at offset 0 of a portable cryptographic audit export bundle (`.vbundle`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VlogBundleHeader {
    pub version: u32,
    pub exported_at_secs: u64,
    pub vlog_offset: u64,
    pub vlog_len: u64,
    pub vidx_offset: u64,
    pub vidx_len: u64,
    pub vchk_offset: u64,
    pub vchk_len: u64,
    pub bundle_sha256: [u8; 32],
}

/// Fixed 48-byte parent lineage anchor stored immediately after the 96-byte `VlogBundleHeader`
/// (`bytes[96..144]`) when `version == VBUNDLE_DELTA_VERSION` (`2`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VlogDeltaAnchor {
    pub base_seq_idx: u64,
    pub parent_terminal_chain_tag: u64,
    pub parent_bundle_sha256: [u8; 32],
}

impl VlogDeltaAnchor {
    pub fn to_bytes(&self) -> [u8; VBUNDLE_DELTA_ANCHOR_LEN] {
        let mut out = [0u8; VBUNDLE_DELTA_ANCHOR_LEN];
        out[0..8].copy_from_slice(&self.base_seq_idx.to_le_bytes());
        out[8..16].copy_from_slice(&self.parent_terminal_chain_tag.to_le_bytes());
        out[16..48].copy_from_slice(&self.parent_bundle_sha256);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < VBUNDLE_DELTA_ANCHOR_LEN {
            return Err(format!(
                "vbundle delta anchor truncated: expected {VBUNDLE_DELTA_ANCHOR_LEN} bytes, got {}",
                bytes.len()
            ));
        }
        let base_seq_idx = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let parent_terminal_chain_tag = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        let mut parent_bundle_sha256 = [0u8; 32];
        parent_bundle_sha256.copy_from_slice(&bytes[16..48]);
        Ok(Self {
            base_seq_idx,
            parent_terminal_chain_tag,
            parent_bundle_sha256,
        })
    }
}

/// Compute the 256-bit SHA-256 cryptographic seal over the 64-byte bundle header prefix and all embedded sections.
pub fn compute_bundle_seal_sha256(
    header_prefix_64: &[u8; 64],
    vlog_bytes: &[u8],
    vidx_bytes: &[u8],
    vchk_bytes: &[u8],
) -> [u8; 32] {
    compute_bundle_seal_sha256_with_anchor(header_prefix_64, None, vlog_bytes, vidx_bytes, vchk_bytes)
}

/// Compute the 256-bit SHA-256 cryptographic seal over the 64-byte bundle header prefix, optional
/// 48-byte delta anchor, and all embedded sections.
pub fn compute_bundle_seal_sha256_with_anchor(
    header_prefix_64: &[u8; 64],
    delta_anchor: Option<&VlogDeltaAnchor>,
    vlog_bytes: &[u8],
    vidx_bytes: &[u8],
    vchk_bytes: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(VBUNDLE_SEAL_SEED);
    hasher.update(header_prefix_64);
    if let Some(anchor) = delta_anchor {
        hasher.update(anchor.to_bytes());
    }
    hasher.update(vlog_bytes);
    hasher.update(vidx_bytes);
    hasher.update(vchk_bytes);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[0..32]);
    out
}

impl VlogBundleHeader {
    pub fn new(
        exported_at_secs: u64,
        vlog_bytes: &[u8],
        vidx_bytes: &[u8],
        vchk_bytes: &[u8],
    ) -> Self {
        Self::new_with_anchor(exported_at_secs, None, vlog_bytes, vidx_bytes, vchk_bytes)
    }

    pub fn new_with_anchor(
        exported_at_secs: u64,
        delta_anchor: Option<&VlogDeltaAnchor>,
        vlog_bytes: &[u8],
        vidx_bytes: &[u8],
        vchk_bytes: &[u8],
    ) -> Self {
        let (version, vlog_offset) = if delta_anchor.is_some() {
            (
                VBUNDLE_DELTA_VERSION,
                (VBUNDLE_HEADER_LEN + VBUNDLE_DELTA_ANCHOR_LEN) as u64,
            )
        } else {
            (VBUNDLE_VERSION, VBUNDLE_HEADER_LEN as u64)
        };
        let vlog_len = vlog_bytes.len() as u64;
        let vidx_offset = vlog_offset.saturating_add(vlog_len);
        let vidx_len = vidx_bytes.len() as u64;
        let vchk_offset = vidx_offset.saturating_add(vidx_len);
        let vchk_len = vchk_bytes.len() as u64;

        let mut h = Self {
            version,
            exported_at_secs,
            vlog_offset,
            vlog_len,
            vidx_offset,
            vidx_len,
            vchk_offset,
            vchk_len,
            bundle_sha256: [0u8; 32],
        };
        let prefix = h.encode_prefix_64();
        h.bundle_sha256 = compute_bundle_seal_sha256_with_anchor(
            &prefix,
            delta_anchor,
            vlog_bytes,
            vidx_bytes,
            vchk_bytes,
        );
        h
    }

    pub fn encode_prefix_64(&self) -> [u8; 64] {
        let mut buf = [0u8; 64];
        buf[0..4].copy_from_slice(&VBUNDLE_MAGIC);
        buf[4..8].copy_from_slice(&self.version.to_le_bytes());
        buf[8..16].copy_from_slice(&self.exported_at_secs.to_le_bytes());
        buf[16..24].copy_from_slice(&self.vlog_offset.to_le_bytes());
        buf[24..32].copy_from_slice(&self.vlog_len.to_le_bytes());
        buf[32..40].copy_from_slice(&self.vidx_offset.to_le_bytes());
        buf[40..48].copy_from_slice(&self.vidx_len.to_le_bytes());
        buf[48..56].copy_from_slice(&self.vchk_offset.to_le_bytes());
        buf[56..64].copy_from_slice(&self.vchk_len.to_le_bytes());
        buf
    }

    pub fn to_bytes(&self) -> [u8; VBUNDLE_HEADER_LEN] {
        let mut out = [0u8; VBUNDLE_HEADER_LEN];
        let prefix = self.encode_prefix_64();
        out[0..64].copy_from_slice(&prefix);
        out[64..96].copy_from_slice(&self.bundle_sha256);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < VBUNDLE_HEADER_LEN {
            return Err(format!(
                "vbundle header truncated: expected at least {VBUNDLE_HEADER_LEN} bytes, got {}",
                bytes.len()
            ));
        }
        if bytes[0..4] != VBUNDLE_MAGIC {
            return Err("invalid vbundle magic".to_string());
        }
        let version = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        if version != VBUNDLE_VERSION && version != VBUNDLE_DELTA_VERSION {
            return Err(format!("unsupported vbundle version: {version}"));
        }
        let exported_at_secs = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        let vlog_offset = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
        let vlog_len = u64::from_le_bytes(bytes[24..32].try_into().unwrap());
        let vidx_offset = u64::from_le_bytes(bytes[32..40].try_into().unwrap());
        let vidx_len = u64::from_le_bytes(bytes[40..48].try_into().unwrap());
        let vchk_offset = u64::from_le_bytes(bytes[48..56].try_into().unwrap());
        let vchk_len = u64::from_le_bytes(bytes[56..64].try_into().unwrap());
        let mut bundle_sha256 = [0u8; 32];
        bundle_sha256.copy_from_slice(&bytes[64..96]);

        let expected_vlog_offset = if version == VBUNDLE_DELTA_VERSION {
            (VBUNDLE_HEADER_LEN + VBUNDLE_DELTA_ANCHOR_LEN) as u64
        } else {
            VBUNDLE_HEADER_LEN as u64
        };
        if vlog_offset != expected_vlog_offset {
            return Err(format!(
                "invalid vbundle vlog_offset: expected {expected_vlog_offset}, got {vlog_offset}"
            ));
        }
        if vidx_offset != vlog_offset.saturating_add(vlog_len) {
            return Err(format!(
                "invalid vbundle vidx_offset: expected {}, got {vidx_offset}",
                vlog_offset.saturating_add(vlog_len)
            ));
        }
        if vchk_offset != vidx_offset.saturating_add(vidx_len) {
            return Err(format!(
                "invalid vbundle vchk_offset: expected {}, got {vchk_offset}",
                vidx_offset.saturating_add(vidx_len)
            ));
        }
        let expected_total = vchk_offset.saturating_add(vchk_len) as usize;
        if bytes.len() != expected_total {
            return Err(format!(
                "vbundle file size mismatch: header expects {expected_total} bytes, got {}",
                bytes.len()
            ));
        }

        Ok(Self {
            version,
            exported_at_secs,
            vlog_offset,
            vlog_len,
            vidx_offset,
            vidx_len,
            vchk_offset,
            vchk_len,
            bundle_sha256,
        })
    }

    pub fn parse_delta_anchor(&self, bytes: &[u8]) -> Result<Option<VlogDeltaAnchor>, String> {
        if self.version != VBUNDLE_DELTA_VERSION {
            return Ok(None);
        }
        let anchor_end = VBUNDLE_HEADER_LEN + VBUNDLE_DELTA_ANCHOR_LEN;
        if bytes.len() < anchor_end {
            return Err("vbundle delta anchor out of bounds".to_string());
        }
        VlogDeltaAnchor::from_bytes(&bytes[VBUNDLE_HEADER_LEN..anchor_end]).map(Some)
    }
}

/// Inspect a `.vbundle` file and return its cumulative chain state `(header, delta_anchor, cumulative_end_seq, report)`.
fn inspect_bundle_chain_state(
    bundle_path: &Path,
) -> Result<(VlogBundleHeader, Option<VlogDeltaAnchor>, u64, VlogIntegrityReport), String> {
    let bytes = std::fs::read(bundle_path).map_err(|e| format!("failed to read vbundle: {e}"))?;
    let header = match VlogBundleHeader::from_bytes(&bytes) {
        Ok(h) => h,
        Err(detail) => {
            return Ok((
                VlogBundleHeader {
                    version: 0,
                    exported_at_secs: 0,
                    vlog_offset: 0,
                    vlog_len: 0,
                    vidx_offset: 0,
                    vidx_len: 0,
                    vchk_offset: 0,
                    vchk_len: 0,
                    bundle_sha256: [0u8; 32],
                },
                None,
                0,
                VlogIntegrityReport {
                    valid: false,
                    verified_records: 0,
                    verified_checkpoints: 0,
                    terminal_chain_tag: VLOG_GENESIS_TAG,
                    tamper_finding: Some(VlogTamperKind::BundleSealCorrupted { detail }),
                },
            ));
        }
    };

    let delta_anchor = match header.parse_delta_anchor(&bytes) {
        Ok(a) => a,
        Err(detail) => {
            return Ok((
                header,
                None,
                0,
                VlogIntegrityReport {
                    valid: false,
                    verified_records: 0,
                    verified_checkpoints: 0,
                    terminal_chain_tag: VLOG_GENESIS_TAG,
                    tamper_finding: Some(VlogTamperKind::BundleSealCorrupted { detail }),
                },
            ));
        }
    };

    let vlog_start = header.vlog_offset as usize;
    let vlog_end = vlog_start + header.vlog_len as usize;
    let vidx_start = header.vidx_offset as usize;
    let vidx_end = vidx_start + header.vidx_len as usize;
    let vchk_start = header.vchk_offset as usize;
    let vchk_end = vchk_start + header.vchk_len as usize;

    let vlog_slice = &bytes[vlog_start..vlog_end];
    let vidx_slice = &bytes[vidx_start..vidx_end];
    let vchk_slice = &bytes[vchk_start..vchk_end];

    let mut prefix = [0u8; 64];
    prefix.copy_from_slice(&bytes[0..64]);
    let expected_seal = compute_bundle_seal_sha256_with_anchor(
        &prefix,
        delta_anchor.as_ref(),
        vlog_slice,
        vidx_slice,
        vchk_slice,
    );
    if expected_seal != header.bundle_sha256 {
        return Ok((
            header,
            delta_anchor,
            0,
            VlogIntegrityReport {
                valid: false,
                verified_records: 0,
                verified_checkpoints: 0,
                terminal_chain_tag: VLOG_GENESIS_TAG,
                tamper_finding: Some(VlogTamperKind::BundleSealCorrupted {
                    detail: "bundle SHA-256 cryptographic seal mismatch".to_string(),
                }),
            },
        ));
    }

    let vidx_opt = if vidx_slice.is_empty() {
        None
    } else {
        Some(vidx_slice)
    };
    let vchk_opt = if vchk_slice.is_empty() {
        None
    } else {
        Some(vchk_slice)
    };
    let (base_seq, init_tag) = match delta_anchor {
        Some(ref a) => (a.base_seq_idx, a.parent_terminal_chain_tag),
        None => (0, VLOG_GENESIS_TAG),
    };
    let report =
        verify_vlog_slices_from_anchor(vlog_slice, vidx_opt, vchk_opt, base_seq, init_tag)?;
    let cumulative_end_seq = base_seq.saturating_add(report.verified_records);
    Ok((header, delta_anchor, cumulative_end_seq, report))
}

/// Package `journal.vlog`, `journal.vidx`, and `journal.vchk` from `dir` into a self-contained,
/// cryptographically sealed `.vbundle` file at `bundle_path`.
///
/// Refuses to export if the live `.vlog` chain fails integrity verification.
pub fn export_vlog_bundle(dir: &Path, bundle_path: &Path) -> Result<VlogIntegrityReport, String> {
    export_vlog_bundle_since(dir, bundle_path, None)
}

/// Package `journal.vlog`, `journal.vidx`, and `journal.vchk` from `dir` into a `.vbundle` file at
/// `bundle_path`. When `since_bundle` is `Some(parent_path)`, exports an incremental delta `.vbundle`
/// (`version == VBUNDLE_DELTA_VERSION`) containing only frames appended after `parent_path` and
/// cryptographically anchored to `parent_path`'s `bundle_sha256` and `terminal_chain_tag`.
pub fn export_vlog_bundle_since(
    dir: &Path,
    bundle_path: &Path,
    since_bundle: Option<&Path>,
) -> Result<VlogIntegrityReport, String> {
    let vlog_file = vlog_path(dir);
    if !vlog_file.exists() {
        return Err(format!(
            "cannot export bundle: {} does not exist",
            vlog_file.display()
        ));
    }
    let full_vlog_bytes =
        std::fs::read(&vlog_file).map_err(|e| format!("failed to read journal.vlog: {e}"))?;
    let vidx_file = vidx_path(dir);
    let full_vidx_bytes = if vidx_file.exists() {
        std::fs::read(&vidx_file).map_err(|e| format!("failed to read journal.vidx: {e}"))?
    } else {
        Vec::new()
    };
    let vchk_file = vchk_path(dir);
    let full_vchk_bytes = if vchk_file.exists() {
        std::fs::read(&vchk_file).map_err(|e| format!("failed to read journal.vchk: {e}"))?
    } else {
        Vec::new()
    };

    let vidx_opt = if full_vidx_bytes.is_empty() {
        None
    } else {
        Some(full_vidx_bytes.as_slice())
    };
    let vchk_opt = if full_vchk_bytes.is_empty() {
        None
    } else {
        Some(full_vchk_bytes.as_slice())
    };
    let live_report = verify_vlog_slices(&full_vlog_bytes, vidx_opt, vchk_opt)?;
    if !live_report.valid {
        return Err(format!(
            "refusing to export corrupted journal.vlog: {:?}",
            live_report.tamper_finding
        ));
    }

    let (delta_anchor, vlog_bytes, vidx_bytes, vchk_bytes, export_report) =
        if let Some(parent_path) = since_bundle {
            let (parent_hdr, _, parent_end_seq, parent_rep) =
                inspect_bundle_chain_state(parent_path)?;
            if !parent_rep.valid {
                return Err(format!(
                    "parent bundle {} failed integrity verification: {:?}",
                    parent_path.display(),
                    parent_rep.tamper_finding
                ));
            }
            if live_report.verified_records < parent_end_seq {
                return Err(format!(
                    "cannot export delta bundle: live journal has {} records, which is fewer than parent bundle cumulative sequence {}",
                    live_report.verified_records, parent_end_seq
                ));
            }

            let full_header = VlogHeader::from_bytes(&full_vlog_bytes)?;
            let idx_offset = full_header.index_offset as usize;
            let total_recs = full_header.record_count as usize;
            let base_idx = parent_end_seq as usize;

            // Verify that the live journal's chain tag at `base_idx - 1` matches `parent_rep.terminal_chain_tag`
            let live_prefix_tag = if base_idx == 0 {
                VLOG_GENESIS_TAG
            } else {
                let entry_start = idx_offset + (base_idx - 1) * VLOG_INDEX_ENTRY_LEN;
                let entry = VlogIndexEntry::from_bytes(
                    &full_vlog_bytes[entry_start..entry_start + VLOG_INDEX_ENTRY_LEN],
                )
                .ok_or_else(|| "failed to read parent anchor index entry".to_string())?;
                let tag_off = (entry.record_offset as usize) + 8;
                u64::from_le_bytes(full_vlog_bytes[tag_off..tag_off + 8].try_into().unwrap())
            };
            if live_prefix_tag != parent_rep.terminal_chain_tag {
                return Err(format!(
                    "cannot export delta bundle: live journal chain tag at sequence {} ({:016x}) does not match parent bundle terminal chain tag ({:016x}) — journal was compacted or diverged since parent bundle",
                    parent_end_seq, live_prefix_tag, parent_rep.terminal_chain_tag
                ));
            }

            let delta_count = (total_recs - base_idx) as u64;
            let first_delta_offset = if base_idx < total_recs {
                let entry_start = idx_offset + base_idx * VLOG_INDEX_ENTRY_LEN;
                let entry = VlogIndexEntry::from_bytes(
                    &full_vlog_bytes[entry_start..entry_start + VLOG_INDEX_ENTRY_LEN],
                )
                .ok_or_else(|| "failed to read first delta index entry".to_string())?;
                entry.record_offset as usize
            } else {
                idx_offset
            };

            let raw_delta_frames = &full_vlog_bytes[first_delta_offset..idx_offset];
            let shift = (first_delta_offset - VLOG_HEADER_LEN) as u64;
            let delta_index_offset = (VLOG_HEADER_LEN + raw_delta_frames.len()) as u64;
            let delta_vlog_hdr = VlogHeader::new(delta_count, delta_index_offset);

            let mut delta_idx_entries = Vec::with_capacity(delta_count as usize);
            for i in base_idx..total_recs {
                let entry_start = idx_offset + i * VLOG_INDEX_ENTRY_LEN;
                let mut entry = VlogIndexEntry::from_bytes(
                    &full_vlog_bytes[entry_start..entry_start + VLOG_INDEX_ENTRY_LEN],
                )
                .ok_or_else(|| "failed to read delta index entry".to_string())?;
                entry.record_offset = entry.record_offset.saturating_sub(shift);
                delta_idx_entries.push(entry);
            }

            let mut d_vlog = Vec::with_capacity(
                VLOG_HEADER_LEN
                    + raw_delta_frames.len()
                    + (delta_count as usize) * VLOG_INDEX_ENTRY_LEN,
            );
            d_vlog.extend_from_slice(&delta_vlog_hdr.to_bytes());
            d_vlog.extend_from_slice(raw_delta_frames);
            for e in &delta_idx_entries {
                d_vlog.extend_from_slice(&e.to_bytes());
            }

            let mut d_vidx = Vec::with_capacity(
                VLOG_HEADER_LEN + (delta_count as usize) * VLOG_INDEX_ENTRY_LEN,
            );
            d_vidx.extend_from_slice(&delta_vlog_hdr.to_bytes());
            for e in &delta_idx_entries {
                d_vidx.extend_from_slice(&e.to_bytes());
            }

            let anchor = VlogDeltaAnchor {
                base_seq_idx: parent_end_seq,
                parent_terminal_chain_tag: parent_rep.terminal_chain_tag,
                parent_bundle_sha256: parent_hdr.bundle_sha256,
            };
            let delta_rep = verify_vlog_slices_from_anchor(
                &d_vlog,
                Some(&d_vidx),
                None,
                anchor.base_seq_idx,
                anchor.parent_terminal_chain_tag,
            )?;
            if !delta_rep.valid {
                return Err(format!(
                    "internal error verifying constructed delta bundle: {:?}",
                    delta_rep.tamper_finding
                ));
            }
            (Some(anchor), d_vlog, d_vidx, Vec::new(), delta_rep)
        } else {
            (
                None,
                full_vlog_bytes,
                full_vidx_bytes,
                full_vchk_bytes,
                live_report,
            )
        };

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let header = VlogBundleHeader::new_with_anchor(
        now_secs,
        delta_anchor.as_ref(),
        &vlog_bytes,
        &vidx_bytes,
        &vchk_bytes,
    );

    if let Some(parent) = bundle_path.parent() {
        if !parent.as_os_str().is_empty() {
            create_dir_all(parent)
                .map_err(|e| format!("failed to create bundle parent directory: {e}"))?;
        }
    }
    let tmp_path = bundle_path.with_extension("vbundle.tmp");
    {
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp_path)
            .map_err(|e| format!("failed to open temporary bundle file: {e}"))?;
        f.write_all(&header.to_bytes())
            .map_err(|e| format!("failed to write bundle header: {e}"))?;
        if let Some(ref anchor) = delta_anchor {
            f.write_all(&anchor.to_bytes())
                .map_err(|e| format!("failed to write bundle delta anchor: {e}"))?;
        }
        f.write_all(&vlog_bytes)
            .map_err(|e| format!("failed to write bundle vlog section: {e}"))?;
        f.write_all(&vidx_bytes)
            .map_err(|e| format!("failed to write bundle vidx section: {e}"))?;
        f.write_all(&vchk_bytes)
            .map_err(|e| format!("failed to write bundle vchk section: {e}"))?;
        f.sync_all()
            .map_err(|e| format!("failed to sync bundle file: {e}"))?;
    }
    std::fs::rename(&tmp_path, bundle_path)
        .map_err(|e| format!("failed to finalize bundle file: {e}"))?;

    Ok(export_report)
}

/// Verify an exported `.vbundle` cryptographic audit bundle completely offline without
/// requiring access to an active state directory.
///
/// Validates the 96-byte `VlogBundleHeader`, the whole-bundle SHA-256 seal (`VBUNDLE_SEAL_SEED`),
/// intra-file `.vlog` frame CRC32s and rolling hash chain (`VLOG_GENESIS_SEED`), `.vidx` index
/// consistency, and `.vchk` cross-compaction continuity lineage (`VCHK_GENESIS_SEED`).
pub fn verify_vlog_bundle(bundle_path: &Path) -> Result<VlogIntegrityReport, String> {
    let (_, _, _, report) = inspect_bundle_chain_state(bundle_path)?;
    Ok(report)
}

/// Verify an ordered sequence of `.vbundle` archives (`[genesis_bundle, delta_1, delta_2, ...]`)
/// completely offline, asserting both intra-bundle cryptographic integrity and cross-bundle
/// parent SHA-256 seal, sequence index, and rolling hash chain continuity.
pub fn verify_vlog_bundle_chain(bundle_paths: &[PathBuf]) -> Result<VlogIntegrityReport, String> {
    if bundle_paths.is_empty() {
        return Err("no bundle paths provided".to_string());
    }
    if bundle_paths.len() == 1 {
        let (_, delta_anchor, _, report) = inspect_bundle_chain_state(&bundle_paths[0])?;
        if !report.valid {
            return Ok(report);
        }
        if let Some(anchor) = delta_anchor {
            return Ok(VlogIntegrityReport {
                valid: false,
                verified_records: report.verified_records,
                verified_checkpoints: report.verified_checkpoints,
                terminal_chain_tag: report.terminal_chain_tag,
                tamper_finding: Some(VlogTamperKind::DeltaParentMismatch {
                    detail: format!(
                        "delta bundle (base_seq_idx={}) requires its parent bundle to verify full chain lineage from genesis",
                        anchor.base_seq_idx
                    ),
                }),
            });
        }
        return Ok(report);
    }

    let mut total_verified_records = 0u64;
    let mut total_verified_checkpoints = 0u64;
    let mut prev_bundle_sha256 = [0u8; 32];
    let mut prev_terminal_tag = VLOG_GENESIS_TAG;
    let mut prev_end_seq = 0u64;

    for (idx, path) in bundle_paths.iter().enumerate() {
        let (hdr, delta_anchor, end_seq, rep) = inspect_bundle_chain_state(path)?;
        if !rep.valid {
            return Ok(VlogIntegrityReport {
                valid: false,
                verified_records: total_verified_records + rep.verified_records,
                verified_checkpoints: total_verified_checkpoints + rep.verified_checkpoints,
                terminal_chain_tag: rep.terminal_chain_tag,
                tamper_finding: rep.tamper_finding,
            });
        }

        if idx == 0 {
            if let Some(anchor) = delta_anchor {
                return Ok(VlogIntegrityReport {
                    valid: false,
                    verified_records: 0,
                    verified_checkpoints: 0,
                    terminal_chain_tag: VLOG_GENESIS_TAG,
                    tamper_finding: Some(VlogTamperKind::DeltaParentMismatch {
                        detail: format!(
                            "first bundle in chain ({}) is a delta bundle (base_seq_idx={}), expected a genesis bundle",
                            path.display(),
                            anchor.base_seq_idx
                        ),
                    }),
                });
            }
        } else {
            let Some(anchor) = delta_anchor else {
                return Ok(VlogIntegrityReport {
                    valid: false,
                    verified_records: total_verified_records,
                    verified_checkpoints: total_verified_checkpoints,
                    terminal_chain_tag: prev_terminal_tag,
                    tamper_finding: Some(VlogTamperKind::DeltaParentMismatch {
                        detail: format!(
                            "bundle #{} ({}) is a standalone genesis bundle, expected a delta bundle anchored to bundle #{}",
                            idx + 1,
                            path.display(),
                            idx
                        ),
                    }),
                });
            };
            if anchor.parent_bundle_sha256 != prev_bundle_sha256 {
                return Ok(VlogIntegrityReport {
                    valid: false,
                    verified_records: total_verified_records,
                    verified_checkpoints: total_verified_checkpoints,
                    terminal_chain_tag: prev_terminal_tag,
                    tamper_finding: Some(VlogTamperKind::DeltaParentMismatch {
                        detail: format!(
                            "bundle #{} ({}) parent_bundle_sha256 does not match bundle #{} seal",
                            idx + 1,
                            path.display(),
                            idx
                        ),
                    }),
                });
            }
            if anchor.base_seq_idx != prev_end_seq {
                return Ok(VlogIntegrityReport {
                    valid: false,
                    verified_records: total_verified_records,
                    verified_checkpoints: total_verified_checkpoints,
                    terminal_chain_tag: prev_terminal_tag,
                    tamper_finding: Some(VlogTamperKind::DeltaParentMismatch {
                        detail: format!(
                            "bundle #{} ({}) base_seq_idx ({}) != parent cumulative record count ({prev_end_seq})",
                            idx + 1,
                            path.display(),
                            anchor.base_seq_idx
                        ),
                    }),
                });
            }
            if anchor.parent_terminal_chain_tag != prev_terminal_tag {
                return Ok(VlogIntegrityReport {
                    valid: false,
                    verified_records: total_verified_records,
                    verified_checkpoints: total_verified_checkpoints,
                    terminal_chain_tag: prev_terminal_tag,
                    tamper_finding: Some(VlogTamperKind::DeltaParentMismatch {
                        detail: format!(
                            "bundle #{} ({}) parent_terminal_chain_tag ({:016x}) != parent terminal tag ({prev_terminal_tag:016x})",
                            idx + 1,
                            path.display(),
                            anchor.parent_terminal_chain_tag
                        ),
                    }),
                });
            }
        }

        total_verified_records += rep.verified_records;
        total_verified_checkpoints += rep.verified_checkpoints;
        prev_bundle_sha256 = hdr.bundle_sha256;
        prev_terminal_tag = rep.terminal_chain_tag;
        prev_end_seq = end_seq;
    }

    Ok(VlogIntegrityReport {
        valid: true,
        verified_records: total_verified_records,
        verified_checkpoints: total_verified_checkpoints,
        terminal_chain_tag: prev_terminal_tag,
        tamper_finding: None,
    })
}

/// Verify a `.vbundle` archive offline and decode all contained `Record` entries.
pub fn read_records_from_vlog_bundle(bundle_path: &Path) -> Result<Vec<Record>, String> {
    let report = verify_vlog_bundle(bundle_path)?;
    if !report.valid {
        return Err(format!(
            "bundle failed integrity verification: {:?}",
            report.tamper_finding
        ));
    }
    let bytes =
        std::fs::read(bundle_path).map_err(|e| format!("failed to read vbundle: {e}"))?;
    let header = VlogBundleHeader::from_bytes(&bytes)?;
    let vlog_start = header.vlog_offset as usize;
    let vlog_end = vlog_start + header.vlog_len as usize;
    let vlog_slice = &bytes[vlog_start..vlog_end];
    if vlog_slice.is_empty() {
        return Ok(Vec::new());
    }
    let vlog_header = VlogHeader::from_bytes(vlog_slice)?;
    let (records, _, _) =
        scan_and_rebuild_index(vlog_slice, Some(vlog_header.index_offset as usize));
    Ok(records)
}
