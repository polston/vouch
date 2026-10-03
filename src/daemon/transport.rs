//! Async & Multiplexed Transport for Streaming Daemon IPC.
//!
//! Provides the transport client and server connection loop supporting streaming
//! multiplexed frames, session isolation, heartbeats, and backward compatibility
//! with legacy single-shot requests.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::daemon::protocol::{ClientFrame, DaemonFrame, EvaluateRequest};
use crate::daemon::session::{DaemonSessionHandler, SessionContext};
use crate::daemon::{DaemonRequest, DaemonState};

/// High-level client for streaming daemon sessions.
pub struct StreamingClient {
    #[cfg(unix)]
    reader: BufReader<std::os::unix::net::UnixStream>,
    #[cfg(unix)]
    writer: std::os::unix::net::UnixStream,
    pub session: SessionContext,
}

impl StreamingClient {
    /// Connects to a running daemon and establishes an isolated streaming session.
    pub fn connect(
        socket_path: &Path,
        agent_id: &str,
        session_token: &str,
        cwd: PathBuf,
        state_dir: Option<PathBuf>,
    ) -> Result<Self, String> {
        #[cfg(unix)]
        {
            use std::os::unix::net::UnixStream;

            let stream = UnixStream::connect(socket_path).map_err(|e| format!("connection error: {e}"))?;
            let _ = stream.set_read_timeout(Some(Duration::from_millis(5000)));
            let _ = stream.set_write_timeout(Some(Duration::from_millis(5000)));

            let mut writer = stream.try_clone().map_err(|e| e.to_string())?;
            let mut reader = BufReader::new(stream);

            let session = SessionContext::new(
                agent_id.to_string(),
                session_token.to_string(),
                cwd.clone(),
                state_dir.unwrap_or_else(|| std::env::temp_dir().join("vouch-session")),
            );

            let handshake = ClientFrame::Handshake {
                agent_id: agent_id.to_string(),
                session_token: session_token.to_string(),
                cwd,
                state_dir: Some(session.state_dir.clone()),
            };

            let line = serde_json::to_string(&handshake).map_err(|e| e.to_string())?;
            writeln!(writer, "{line}").map_err(|e| e.to_string())?;
            writer.flush().map_err(|e| e.to_string())?;

            let mut resp_line = String::new();
            reader.read_line(&mut resp_line).map_err(|e| e.to_string())?;

            match serde_json::from_str::<DaemonFrame>(&resp_line) {
                Ok(DaemonFrame::HandshakeAck { .. }) => Ok(Self {
                    reader,
                    writer,
                    session,
                }),
                Ok(other) => Err(format!("unexpected handshake response: {other:?}")),
                Err(e) => Err(format!("handshake deserialization failed: {e}")),
            }
        }
        #[cfg(not(unix))]
        {
            let _ = (socket_path, agent_id, session_token, cwd, state_dir);
            Err("streaming daemon socket IPC not supported on this platform".to_string())
        }
    }

    /// Evaluates a hook payload within this session and waits for the corresponding decision frame.
    pub fn evaluate(&mut self, request_id: u64, raw_hook_json: &str) -> Result<DaemonFrame, String> {
        #[cfg(unix)]
        {
            let req = ClientFrame::Evaluate {
                request_id,
                raw_hook_json: raw_hook_json.to_string(),
            };
            let line = serde_json::to_string(&req).map_err(|e| e.to_string())?;
            writeln!(self.writer, "{line}").map_err(|e| e.to_string())?;
            self.writer.flush().map_err(|e| e.to_string())?;

            let mut resp_line = String::new();
            self.reader.read_line(&mut resp_line).map_err(|e| e.to_string())?;
            serde_json::from_str::<DaemonFrame>(&resp_line).map_err(|e| e.to_string())
        }
        #[cfg(not(unix))]
        {
            let _ = (request_id, raw_hook_json);
            Err("not supported on this platform".to_string())
        }
    }

    /// Sends a heartbeat probe and verifies pong response.
    pub fn heartbeat(&mut self) -> Result<(), String> {
        #[cfg(unix)]
        {
            let frame = ClientFrame::Heartbeat;
            let line = serde_json::to_string(&frame).map_err(|e| e.to_string())?;
            writeln!(self.writer, "{line}").map_err(|e| e.to_string())?;
            self.writer.flush().map_err(|e| e.to_string())?;

            let mut resp_line = String::new();
            self.reader.read_line(&mut resp_line).map_err(|e| e.to_string())?;
            match serde_json::from_str::<DaemonFrame>(&resp_line) {
                Ok(DaemonFrame::Pong) => Ok(()),
                Ok(other) => Err(format!("expected Pong, got {other:?}")),
                Err(e) => Err(format!("failed to deserialize Pong: {e}")),
            }
        }
        #[cfg(not(unix))]
        {
            Err("not supported on this platform".to_string())
        }
    }

    /// Sends a cancellation frame for a given request id.
    pub fn cancel(&mut self, request_id: u64) -> Result<(), String> {
        #[cfg(unix)]
        {
            let frame = ClientFrame::Cancel { request_id };
            let line = serde_json::to_string(&frame).map_err(|e| e.to_string())?;
            writeln!(self.writer, "{line}").map_err(|e| e.to_string())?;
            self.writer.flush().map_err(|e| e.to_string())?;
            Ok(())
        }
        #[cfg(not(unix))]
        {
            let _ = request_id;
            Err("not supported on this platform".to_string())
        }
    }
}

/// Dispatches an incoming client stream to either streaming multi-frame handler
/// or legacy single-line request handler.
#[cfg(unix)]
pub fn handle_client_connection(
    stream: std::os::unix::net::UnixStream,
    handler: Arc<dyn DaemonSessionHandler>,
    state: Arc<std::sync::RwLock<DaemonState>>,
) -> Result<(), String> {
    let mut reader = BufReader::new(stream.try_clone().map_err(|e| e.to_string())?);
    let mut writer = stream;

    let mut line = String::new();
    reader.read_line(&mut line).map_err(|e| e.to_string())?;
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(());
    }

    // 1. Try parsing as ClientFrame
    if let Ok(first_frame) = serde_json::from_str::<ClientFrame>(trimmed) {
        let mut session = match first_frame {
            ClientFrame::Handshake {
                agent_id,
                session_token,
                cwd,
                state_dir,
            } => {
                let sess = SessionContext::new(
                    agent_id,
                    session_token,
                    cwd,
                    state_dir.unwrap_or_else(|| std::env::temp_dir().join("vouch-session")),
                );
                let ack = DaemonFrame::HandshakeAck {
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    capabilities: vec![
                        "streaming".into(),
                        "cwd_isolation".into(),
                        "multiplexing".into(),
                    ],
                };
                let ack_line = serde_json::to_string(&ack).map_err(|e| e.to_string())?;
                writeln!(writer, "{ack_line}").map_err(|e| e.to_string())?;
                writer.flush().map_err(|e| e.to_string())?;
                sess
            }
            ClientFrame::Evaluate {
                request_id,
                raw_hook_json,
            } => {
                let sess = SessionContext::default_for_cwd(PathBuf::from("."));
                let out = handler.handle_evaluate(
                    &sess,
                    EvaluateRequest {
                        request_id,
                        raw_hook_json,
                    },
                );
                let resp_frame = DaemonFrame::Decision {
                    request_id: out.request_id,
                    output: out.output,
                    verdict: out.verdict,
                    latency_us: out.latency_us,
                };
                let resp_line = serde_json::to_string(&resp_frame).map_err(|e| e.to_string())?;
                writeln!(writer, "{resp_line}").map_err(|e| e.to_string())?;
                writer.flush().map_err(|e| e.to_string())?;
                sess
            }
            ClientFrame::Heartbeat => {
                let resp_line = serde_json::to_string(&DaemonFrame::Pong).map_err(|e| e.to_string())?;
                writeln!(writer, "{resp_line}").map_err(|e| e.to_string())?;
                writer.flush().map_err(|e| e.to_string())?;
                SessionContext::default_for_cwd(PathBuf::from("."))
            }
            ClientFrame::Cancel { request_id } => {
                let err_frame = DaemonFrame::Error {
                    request_id,
                    message: "cancelled".into(),
                };
                let resp_line = serde_json::to_string(&err_frame).map_err(|e| e.to_string())?;
                writeln!(writer, "{resp_line}").map_err(|e| e.to_string())?;
                writer.flush().map_err(|e| e.to_string())?;
                return Ok(());
            }
        };

        // Subsequent streaming frames loop
        line.clear();
        while reader.read_line(&mut line).is_ok() && !line.trim().is_empty() {
            if let Ok(frame) = serde_json::from_str::<ClientFrame>(line.trim()) {
                match frame {
                    ClientFrame::Evaluate {
                        request_id,
                        raw_hook_json,
                    } => {
                        let out = handler.handle_evaluate(
                            &session,
                            EvaluateRequest {
                                request_id,
                                raw_hook_json,
                            },
                        );
                        let resp_frame = DaemonFrame::Decision {
                            request_id: out.request_id,
                            output: out.output,
                            verdict: out.verdict,
                            latency_us: out.latency_us,
                        };
                        let resp_line = serde_json::to_string(&resp_frame).map_err(|e| e.to_string())?;
                        writeln!(writer, "{resp_line}").map_err(|e| e.to_string())?;
                        writer.flush().map_err(|e| e.to_string())?;
                    }
                    ClientFrame::Heartbeat => {
                        let resp_line =
                            serde_json::to_string(&DaemonFrame::Pong).map_err(|e| e.to_string())?;
                        writeln!(writer, "{resp_line}").map_err(|e| e.to_string())?;
                        writer.flush().map_err(|e| e.to_string())?;
                    }
                    ClientFrame::Cancel { request_id } => {
                        let err_frame = DaemonFrame::Error {
                            request_id,
                            message: "cancelled".into(),
                        };
                        let resp_line =
                            serde_json::to_string(&err_frame).map_err(|e| e.to_string())?;
                        writeln!(writer, "{resp_line}").map_err(|e| e.to_string())?;
                        writer.flush().map_err(|e| e.to_string())?;
                    }
                    ClientFrame::Handshake {
                        agent_id,
                        session_token,
                        cwd,
                        state_dir,
                    } => {
                        session = SessionContext::new(
                            agent_id,
                            session_token,
                            cwd,
                            state_dir.unwrap_or_else(|| session.state_dir.clone()),
                        );
                        let ack = DaemonFrame::HandshakeAck {
                            version: env!("CARGO_PKG_VERSION").to_string(),
                            capabilities: vec![
                                "streaming".into(),
                                "cwd_isolation".into(),
                                "multiplexing".into(),
                            ],
                        };
                        let ack_line = serde_json::to_string(&ack).map_err(|e| e.to_string())?;
                        writeln!(writer, "{ack_line}").map_err(|e| e.to_string())?;
                        writer.flush().map_err(|e| e.to_string())?;
                    }
                }
            }
            line.clear();
        }
        return Ok(());
    }

    // 2. Fall back to legacy single-line DaemonRequest
    if let Ok(req) = serde_json::from_str::<DaemonRequest>(trimmed) {
        let resp = {
            let s = state.read().map_err(|e| e.to_string())?;
            s.process_request(&req)
        };
        let resp_str = serde_json::to_string(&resp).map_err(|e| e.to_string())?;
        writeln!(writer, "{resp_str}").map_err(|e| e.to_string())?;
        writer.flush().map_err(|e| e.to_string())?;
        return Ok(());
    }

    Err("unrecognized IPC payload".to_string())
}
