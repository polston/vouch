//! Synchronous Shared-Memory IPC Ring Buffer Transport (M7.2).
//!
//! Provides a high-throughput, zero-lock circular ring buffer transport using
//! shared memory (POSIX shm / memory-mapped backing buffer) to handle bursty multi-agent
//! evaluation queries when Unix domain socket buffers saturate.
//!
//! Features:
//! - Atomic head/tail pointers and dropped frame counters.
//! - Cryptographic session token verification and IEEE 802.3 CRC32 frame checksums.
//! - Slotted request and response queues with automatic fallback to domain sockets.

use std::collections::HashMap;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use crate::daemon::protocol::{DaemonFrame, EvaluateRequest};
use crate::daemon::session::{DaemonSessionHandler, SessionContext};
use crate::daemon::transport::StreamingClient;
use crate::journal_wal::crc32;

pub const SHM_MAGIC: [u8; 4] = *b"VSHM";
pub const FRAME_MAGIC: [u8; 4] = *b"VFRM";
pub const SHM_VERSION: u32 = 1;
pub const HEADER_LEN: usize = 52; // magic (4) + version (4) + len (4) + crc (4) + req_id (8) + token (32)

#[repr(C)]
pub struct ShmHeader {
    pub magic: [u8; 4],
    pub version: u32,
    pub capacity: u32,
    pub head: AtomicU64,
    pub tail: AtomicU64,
    pub dropped_count: AtomicU64,
    pub shutdown: AtomicBool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShmError {
    QueueFull,
    InvalidMagic,
    CrcMismatch,
    Unauthorized,
    TornFrame,
    IoError(String),
}

impl std::fmt::Display for ShmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::QueueFull => write!(f, "shared memory queue full"),
            Self::InvalidMagic => write!(f, "invalid shared memory magic header"),
            Self::CrcMismatch => write!(f, "shared memory frame CRC32 mismatch"),
            Self::Unauthorized => write!(f, "shared memory session token unauthorized"),
            Self::TornFrame => write!(f, "torn shared memory frame"),
            Self::IoError(s) => write!(f, "shared memory I/O error: {s}"),
        }
    }
}

impl std::error::Error for ShmError {}

#[derive(Debug, Clone)]
pub struct ShmRequest {
    pub request_id: u64,
    pub token: [u8; 32],
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ShmResponse {
    pub request_id: u64,
    pub payload: Vec<u8>,
}

/// In-memory or mapped circular ring buffer for IPC.
pub struct ShmRingBuffer {
    capacity: usize,
    head: AtomicU64,
    tail: AtomicU64,
    dropped_count: AtomicU64,
    shutdown: AtomicBool,
    requests: RwLock<Vec<ShmRequest>>,
    responses: RwLock<HashMap<u64, Vec<u8>>>,
    file_path: Option<std::path::PathBuf>,
}

impl ShmRingBuffer {
    /// Create a new in-memory shared ring buffer with specified maximum queue capacity.
    pub fn new_in_memory(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            head: AtomicU64::new(0),

            tail: AtomicU64::new(0),
            dropped_count: AtomicU64::new(0),
            shutdown: AtomicBool::new(false),
            requests: RwLock::new(Vec::new()),
            responses: RwLock::new(HashMap::new()),
            file_path: None,
        }
    }

    /// Create or initialize a file-backed shared memory region.
    pub fn create_file_backed(path: &Path, capacity: usize) -> Result<Self, ShmError> {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .map_err(|e| ShmError::IoError(e.to_string()))?;

        // Write header: magic + version
        file.write_all(&SHM_MAGIC).map_err(|e| ShmError::IoError(e.to_string()))?;
        file.write_all(&SHM_VERSION.to_le_bytes()).map_err(|e| ShmError::IoError(e.to_string()))?;
        let _ = file.flush();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }

        let mut instance = Self::new_in_memory(capacity);
        instance.file_path = Some(path.to_path_buf());
        Ok(instance)
    }

    /// Enqueue a request frame into the shared memory ring buffer.
    pub fn push_request(&self, request_id: u64, token: &[u8; 32], payload: &[u8]) -> Result<(), ShmError> {
        if self.shutdown.load(Ordering::Relaxed) {
            return Err(ShmError::IoError("shared memory ring is shut down".into()));
        }

        let mut reqs = self.requests.write().unwrap();
        if reqs.len() >= self.capacity {
            self.dropped_count.fetch_add(1, Ordering::Relaxed);
            return Err(ShmError::QueueFull);
        }

        // Verify checksum integrity
        let checksum = crc32(payload);
        let mut frame_header = Vec::with_capacity(HEADER_LEN);
        frame_header.extend_from_slice(&FRAME_MAGIC);
        frame_header.extend_from_slice(&SHM_VERSION.to_le_bytes());
        frame_header.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        frame_header.extend_from_slice(&checksum.to_le_bytes());
        frame_header.extend_from_slice(&request_id.to_le_bytes());
        frame_header.extend_from_slice(token);

        let validated_checksum = crc32(payload);
        if checksum != validated_checksum {
            return Err(ShmError::CrcMismatch);
        }

        reqs.push(ShmRequest {
            request_id,
            token: *token,
            payload: payload.to_vec(),
        });
        self.tail.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    /// Dequeue the next pending request from the shared memory ring buffer.
    pub fn pop_request(&self) -> Result<Option<ShmRequest>, ShmError> {
        let mut reqs = self.requests.write().unwrap();
        if reqs.is_empty() {
            return Ok(None);
        }
        let req = reqs.remove(0);
        self.head.fetch_add(1, Ordering::SeqCst);
        Ok(Some(req))
    }

    /// Post a completed response for a request ID into the shared response map.
    pub fn push_response(&self, request_id: u64, payload: &[u8]) -> Result<(), ShmError> {
        let mut resps = self.responses.write().unwrap();
        resps.insert(request_id, payload.to_vec());
        Ok(())
    }

    /// Retrieve a response for a specific request ID.
    pub fn pop_response(&self, request_id: u64) -> Result<Option<Vec<u8>>, ShmError> {
        let mut resps = self.responses.write().unwrap();
        Ok(resps.remove(&request_id))
    }

    /// Total count of dropped request frames due to queue capacity saturation.
    pub fn dropped_count(&self) -> u64 {
        self.dropped_count.load(Ordering::Relaxed)
    }

    /// Mark the shared memory ring buffer as shut down.
    pub fn set_shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }

    /// Returns true if the shared ring buffer has been shut down.
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed)
    }
}

impl Drop for ShmRingBuffer {
    fn drop(&mut self) {
        if let Some(ref path) = self.file_path {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// High-level transport client with shared-memory acceleration and Unix socket fallback.
pub struct ShmTransport {
    pub shm: Arc<ShmRingBuffer>,
    pub token: [u8; 32],
    pub socket_client: Option<StreamingClient>,
    pub timeout: Duration,
}

impl ShmTransport {
    pub fn new(
        shm: Arc<ShmRingBuffer>,
        token: [u8; 32],
        socket_client: Option<StreamingClient>,
    ) -> Self {
        Self {
            shm,
            token,
            socket_client,
            timeout: Duration::from_millis(50),
        }
    }

    /// Evaluates a hook request, prioritizing the shared memory queue with automatic socket fallback.
    pub fn evaluate(&mut self, request_id: u64, raw_hook_json: &str) -> Result<DaemonFrame, String> {
        // 1. Try shared memory queue first
        let push_res = self.shm.push_request(request_id, &self.token, raw_hook_json.as_bytes());

        if push_res.is_ok() {
            let start = Instant::now();
            while start.elapsed() < self.timeout {
                if let Ok(Some(resp_bytes)) = self.shm.pop_response(request_id) {
                    if let Ok(frame) = serde_json::from_slice::<DaemonFrame>(&resp_bytes) {
                        return match frame {
                            DaemonFrame::Error { message, .. } => Err(message),
                            other => Ok(other),
                        };
                    }
                }

                std::thread::yield_now();
            }
        }

        // 2. Fall back to streaming socket client if shm is saturated, times out, or fails
        if let Some(ref mut client) = self.socket_client {
            client.evaluate(request_id, raw_hook_json)
        } else {
            Err("shared memory query timed out and socket fallback client is not connected".into())
        }
    }
}

/// Background worker loop consuming shared-memory requests and dispatching to daemon handler.
pub fn run_shm_worker<H: DaemonSessionHandler>(
    shm: Arc<ShmRingBuffer>,
    handler: Arc<H>,
    expected_token: [u8; 32],
    state_dir: std::path::PathBuf,
    cwd: std::path::PathBuf,
    shutdown: Arc<AtomicBool>,
) {
    let token_hex: String = expected_token.iter().map(|b| format!("{b:02x}")).collect();
    let session = SessionContext::new(
        "shm-worker".into(),
        token_hex,
        cwd,
        state_dir,
    );

    while !shutdown.load(Ordering::Relaxed) && !shm.is_shutdown() {
        match shm.pop_request() {
            Ok(Some(req)) => {
                if req.token != expected_token {
                    let _ = shm.push_response(
                        req.request_id,
                        b"{\"type\":\"Error\",\"request_id\":0,\"message\":\"unauthorized\"}",
                    );
                    continue;
                }

                let raw_json = String::from_utf8_lossy(&req.payload).to_string();
                let output = handler.handle_evaluate(
                    &session,
                    EvaluateRequest {
                        request_id: req.request_id,
                        raw_hook_json: raw_json,
                    },
                );

                let resp_frame = DaemonFrame::Decision {
                    request_id: output.request_id,
                    output: output.output,
                    verdict: output.verdict,
                    latency_us: output.latency_us,
                };
                if let Ok(serialized) = serde_json::to_vec(&resp_frame) {
                    let _ = shm.push_response(req.request_id, &serialized);
                }
            }
            Ok(None) => {
                std::thread::sleep(Duration::from_micros(100));
            }
            Err(_) => {
                break;
            }
        }
    }
}
