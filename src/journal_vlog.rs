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
    let header = VlogHeader::from_bytes(&bytes)?;
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

/// Incrementally compact `journal.vlog` and `journal.vidx` according to `JournalPolicy`,
/// collapsing duplicate historical runs while preserving aggregated execution counts.
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
    write_all_vlog(dir, &compacted_recs)?;
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
}

/// Complete audit report returned by `verify_vlog_integrity`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VlogIntegrityReport {
    pub valid: bool,
    pub verified_records: u64,
    pub terminal_chain_tag: u64,
    pub tamper_finding: Option<VlogTamperKind>,
}

/// Verify the cryptographic hash chain, CRC32 frame checksums, 32-byte header, index footer,
/// and sidecar `journal.vidx` consistency of a `.vlog` binary journal file.
pub fn verify_vlog_integrity(path: &Path) -> Result<VlogIntegrityReport, String> {
    let data_path = resolve_vlog_data_path(path);
    let bytes = std::fs::read(&data_path).map_err(|e| format!("failed to read vlog: {e}"))?;
    if bytes.is_empty() {
        return Ok(VlogIntegrityReport {
            valid: true,
            verified_records: 0,
            terminal_chain_tag: VLOG_GENESIS_TAG,
            tamper_finding: None,
        });
    }

    let header = match VlogHeader::from_bytes(&bytes) {
        Ok(h) => h,
        Err(detail) => {
            return Ok(VlogIntegrityReport {
                valid: false,
                verified_records: 0,
                terminal_chain_tag: VLOG_GENESIS_TAG,
                tamper_finding: Some(VlogTamperKind::HeaderCorrupted { detail }),
            });
        }
    };

    let idx_offset = header.index_offset as usize;
    let expected_idx_bytes = (header.record_count as usize).saturating_mul(VLOG_INDEX_ENTRY_LEN);

    let mut offset = VLOG_HEADER_LEN;
    let mut prev_tag = VLOG_GENESIS_TAG;
    let mut verified_records = 0u64;
    let mut expected_bounds: Vec<(u64, u32)> = Vec::with_capacity(header.record_count as usize);

    for seq_idx in 0..header.record_count {
        if offset + VLOG_FRAME_HEADER_LEN > bytes.len() || offset + VLOG_FRAME_HEADER_LEN > idx_offset
        {
            return Ok(VlogIntegrityReport {
                valid: false,
                verified_records,
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
        prev_tag = actual_tag;
        verified_records += 1;
        offset = payload_end;
    }

    if offset != idx_offset {
        return Ok(VlogIntegrityReport {
            valid: false,
            verified_records,
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

    let sidecar_path = data_path.with_extension("vidx");
    if sidecar_path.exists() {
        match read_vidx_entries(&sidecar_path) {
            Ok((vidx_header, vidx_entries)) => {
                if vidx_header != header {
                    return Ok(VlogIntegrityReport {
                        valid: false,
                        verified_records,
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
                    terminal_chain_tag: prev_tag,
                    tamper_finding: Some(VlogTamperKind::SidecarIndexMismatch { detail }),
                });
            }
        }
    }

    Ok(VlogIntegrityReport {
        valid: true,
        verified_records,
        terminal_chain_tag: prev_tag,
        tamper_finding: None,
    })
}
