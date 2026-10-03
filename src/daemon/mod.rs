//! Persistent Gating Daemon & In-Memory IPC Runtime (M4.5, Goal 5).
//!
//! Provides a resident background daemon maintaining in-memory parsed configuration,
//! compiled knowledge models, and syntax scanners to answer hook queries in <2ms.
//! Communication occurs over a local Unix domain socket (or loopback/named pipe),
//! with non-blocking fail-closed fallback to standalone evaluation if the daemon is unavailable.
//!
//! Submodules:
//! - `protocol`: Streaming length-prefixed and newline JSON frames (`ClientFrame`, `DaemonFrame`).
//! - `session`: Context isolation boundaries (`SessionContext`, `DaemonSessionHandler`).
//! - `transport`: Streaming client & connection multiplexing.

pub mod protocol;
pub mod session;
pub mod transport;

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use serde::{Deserialize, Serialize};

use crate::config::{load, Config};
use crate::protocol::{render_for, Decision, Host};

pub use protocol::{ClientFrame, DaemonFrame, DecisionOutput, EvaluateRequest};
pub use session::{DaemonSessionHandler, SessionContext};
pub use transport::StreamingClient;

/// IPC request payload sent from hook client to daemon.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DaemonRequest {
    pub raw: String,
    pub notice: Option<String>,
    pub host: String,
    pub shadow: bool,
    pub state_dir: String,
    pub home_dir: String,
}

/// IPC response payload sent from daemon to hook client.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DaemonResponse {
    pub output: Option<String>,
    pub from_daemon: bool,
}

/// In-memory daemon state with hot-reloading capability.
pub struct DaemonState {
    pub cfg: Config,
    pub home: String,
    pub config_path: PathBuf,
    pub my_knowledge_path: PathBuf,
    pub config_mtime: Option<SystemTime>,
    pub my_kb_mtime: Option<SystemTime>,
}

impl DaemonState {
    pub fn new(home: &str) -> Self {
        let config_path = crate::knowledge::config_dir(home).join("config.toml");
        let my_knowledge_path = crate::knowledge::my_knowledge_path(home);

        let config_mtime = std::fs::metadata(&config_path).and_then(|m| m.modified()).ok();
        let my_kb_mtime = std::fs::metadata(&my_knowledge_path).and_then(|m| m.modified()).ok();

        let cfg = std::fs::read_to_string(&config_path)
            .ok()
            .and_then(|text| load(&text).ok())
            .unwrap_or_else(Config::nothing_configured);

        Self {
            cfg,
            home: home.to_string(),
            config_path,
            my_knowledge_path,
            config_mtime,
            my_kb_mtime,
        }
    }

    /// Check if configuration or knowledge files on disk have changed since load.
    /// If so, reload in-memory state atomically.
    pub fn check_reload(&mut self) {
        let current_cfg_mtime = std::fs::metadata(&self.config_path).and_then(|m| m.modified()).ok();
        if current_cfg_mtime != self.config_mtime {
            if let Ok(text) = std::fs::read_to_string(&self.config_path) {
                if let Ok(new_cfg) = load(&text) {
                    self.cfg = new_cfg;
                    self.config_mtime = current_cfg_mtime;
                }
            }
        }

        let current_my_kb_mtime = std::fs::metadata(&self.my_knowledge_path).and_then(|m| m.modified()).ok();
        if current_my_kb_mtime != self.my_kb_mtime {
            self.my_kb_mtime = current_my_kb_mtime;
            // Hot-reload process-wide knowledge representation
            let _ = crate::guards::in_effect();
        }
    }

    /// Process one hook evaluation request in-memory.
    pub fn process_request(&self, req: &DaemonRequest) -> DaemonResponse {
        self.process_request_with_cwd(req, None)
    }

    /// Process one hook evaluation request with an optional scoped working directory.
    pub fn process_request_with_cwd(&self, req: &DaemonRequest, scoped_cwd: Option<&Path>) -> DaemonResponse {
        let host = Host::parse(&req.host).unwrap_or(Host::Claude);
        let shadow = req.shadow;

        let mut input = match crate::protocol::parse_input(&req.raw) {
            Ok(input) => input,
            Err(err) => {
                let action = self.cfg.unparseable_snippet.unwrap_or(crate::config::Action::Ask);
                let reason = format!(
                    "vouch stopped on: unparseable hook payload\n  error: {err}\n  to configure this behavior, set unparseable_snippet = \"ask\" | \"deny\" in config.toml"
                );
                let decision = match action {
                    crate::config::Action::Deny => Decision::Deny(reason),
                    _ => Decision::Ask(reason),
                };
                let rec = crate::journal::record_unparseable(host, &req.raw, &decision);
                let _ = crate::journal::append(Path::new(&req.state_dir), &rec);
                if shadow {
                    return DaemonResponse { output: None, from_daemon: true };
                }
                return DaemonResponse {
                    output: render_for(host, &decision),
                    from_daemon: true,
                };
            }
        };

        // If scoped_cwd is provided, override input.cwd if input.cwd was empty
        if let Some(cwd) = scoped_cwd {
            if input.cwd.is_empty() {
                input.cwd = cwd.to_string_lossy().to_string();
            }
        }

        // Terminal events
        if let Some(o) = crate::outcome::Outcome::from_event(&input.hook_event_name) {
            let detail = if !input.reason.is_empty() {
                input.reason.clone()
            } else if input.is_interrupt {
                "interrupted".to_string()
            } else {
                input.error.clone()
            };
            let _ = crate::journal::append_outcome(
                Path::new(&req.state_dir),
                &crate::journal::OutcomeRecord {
                    id: input.tool_use_id.clone(),
                    outcome: o,
                    detail,
                    host: host.as_str().into(),
                },
            );
            return DaemonResponse {
                output: if host == Host::Agy { Some("{}".into()) } else { None },
                from_daemon: true,
            };
        }

        let outcome = crate::route::decide(&self.cfg, crate::guards::in_effect(), &req.home_dir, &input);
        let mut decision = outcome.decision;
        if let Some(notice) = &req.notice {
            decision = match decision {
                Decision::Ask(r) => Decision::Ask(format!("{notice}\n{r}")),
                Decision::Deny(r) => Decision::Deny(format!("{notice}\n{r}")),
                other => other,
            };
        }

        let (emit, mode) = if shadow {
            (false, "shadow")
        } else {
            let protection = matches!(&decision, Decision::Ask(r) if crate::engine::is_protection_ask(r));
            crate::protocol::stand_down_emission(
                self.cfg.stand_down(),
                self.cfg.stands_down_in(&input.permission_mode),
                &decision,
                protection,
            )
        };

        if host == Host::Codex && emit {
            if let Decision::Ask(reason) = &decision {
                let now = crate::journal::now_epoch_secs().parse::<u64>().unwrap_or_default();
                decision = match crate::approval::gate(Path::new(&req.state_dir), &input, reason, now) {
                    Ok(crate::approval::GateResult::Granted) => {
                        Decision::Allow("one-time human approval for this exact retry".into())
                    }
                    Ok(crate::approval::GateResult::Pending { request_id }) => Decision::Ask(format!(
                        "{reason}\n  approval request: {request_id}\n  call mcp__vouch_approval__request_approval with that request_id, then retry this exact tool call once"
                    )),
                    Err(error) => Decision::Deny(format!(
                        "vouch could not create a one-time Codex approval request: {error}"
                    )),
                };
            }
        }

        // Journaling
        if outcome.snippets.is_empty() {
            let rec = crate::journal::record_from_host(host, &input, &decision, mode);
            let _ = crate::journal::append(Path::new(&req.state_dir), &rec);
        } else {
            for rec in crate::journal::records_from_snippets_host(
                host,
                &input,
                &decision,
                mode,
                &outcome.snippets,
            ) {
                let _ = crate::journal::append(Path::new(&req.state_dir), &rec);
            }
        }

        let output = if !emit {
            None
        } else if host == Host::Agy {
            let demote = crate::protocol::should_demote_sandbox(&input, &decision, crate::guards::in_effect());
            crate::protocol::render_for_agy(&decision, demote)
        } else {
            render_for(host, &decision)
        };

        DaemonResponse {
            output,
            from_daemon: true,
        }
    }
}

impl DaemonSessionHandler for DaemonState {
    fn handle_evaluate(&self, session: &SessionContext, req: EvaluateRequest) -> DecisionOutput {
        let start = Instant::now();
        let daemon_req = DaemonRequest {
            raw: req.raw_hook_json,
            notice: None,
            host: "claude".into(),
            shadow: false,
            state_dir: session.state_dir.to_string_lossy().to_string(),
            home_dir: self.home.clone(),
        };

        let resp = self.process_request_with_cwd(&daemon_req, Some(&session.cwd));
        let latency_us = start.elapsed().as_micros() as u64;

        let verdict = if let Some(ref out) = resp.output {
            if out.contains("\"allow\"") || out.contains("\"permissionDecision\":\"allow\"") {
                "allow"
            } else if out.contains("\"deny\"") || out.contains("\"permissionDecision\":\"deny\"") {
                "deny"
            } else {
                "ask"
            }
        } else {
            "abstain"
        };

        DecisionOutput {
            request_id: req.request_id,
            output: resp.output,
            verdict: verdict.to_string(),
            latency_us,
        }
    }
}

/// Resolve the default socket path for the daemon on this machine.
pub fn default_socket_path(home: &str) -> PathBuf {
    if let Ok(sock) = std::env::var("VOUCH_DAEMON_SOCKET") {
        return PathBuf::from(sock);
    }
    crate::knowledge::config_dir(home).join("vouch.sock")
}

/// Client helper: attempt to query daemon via local IPC socket.
/// Returns Err if daemon socket is unavailable, refused, or times out.
pub fn try_query_daemon(
    socket_path: &Path,
    req: &DaemonRequest,
    timeout_ms: u64,
) -> Result<DaemonResponse, String> {
    #[cfg(unix)]
    {
        use std::os::unix::net::UnixStream;

        let stream = UnixStream::connect(socket_path).map_err(|e| e.to_string())?;
        let timeout = Duration::from_millis(timeout_ms);
        let _ = stream.set_read_timeout(Some(timeout));
        let _ = stream.set_write_timeout(Some(timeout));

        let mut writer = stream.try_clone().map_err(|e| e.to_string())?;
        let serialized = serde_json::to_string(req).map_err(|e| e.to_string())?;
        writeln!(writer, "{serialized}").map_err(|e| e.to_string())?;
        writer.flush().map_err(|e| e.to_string())?;

        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).map_err(|e| e.to_string())?;

        let resp: DaemonResponse = serde_json::from_str(&line).map_err(|e| e.to_string())?;
        Ok(resp)
    }
    #[cfg(not(unix))]
    {
        let _ = (socket_path, req, timeout_ms);
        Err("daemon socket IPC not supported on this platform".to_string())
    }
}

/// Server loop: run resident daemon on socket.
pub fn run_daemon_server(
    socket_path: &Path,
    home: &str,
    shutdown_flag: Option<Arc<AtomicBool>>,
) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::net::UnixListener;

        if socket_path.exists() {
            if std::os::unix::net::UnixStream::connect(socket_path).is_ok() {
                return Err(format!(
                    "daemon already running on socket {}",
                    socket_path.display()
                ));
            }
            let _ = std::fs::remove_file(socket_path);
        }

        if let Some(parent) = socket_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let listener = UnixListener::bind(socket_path)
            .map_err(|e| format!("could not bind socket {}: {e}", socket_path.display()))?;
        let _ = std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600));

        let state = Arc::new(std::sync::RwLock::new(DaemonState::new(home)));

        struct StateHandler(Arc<std::sync::RwLock<DaemonState>>);
        impl DaemonSessionHandler for StateHandler {
            fn handle_evaluate(&self, session: &SessionContext, req: EvaluateRequest) -> DecisionOutput {
                let s = self.0.read().unwrap();
                s.handle_evaluate(session, req)
            }
        }
        let handler: Arc<dyn DaemonSessionHandler> = Arc::new(StateHandler(Arc::clone(&state)));

        while shutdown_flag
            .as_ref()
            .map(|f| !f.load(Ordering::Relaxed))
            .unwrap_or(true)
        {
            match listener.accept() {
                Ok((stream, _)) => {
                    if shutdown_flag
                        .as_ref()
                        .map(|f| f.load(Ordering::Relaxed))
                        .unwrap_or(false)
                    {
                        break;
                    }
                    if let Ok(mut s) = state.write() {
                        s.check_reload();
                    }
                    let state_clone = Arc::clone(&state);
                    let handler_clone = Arc::clone(&handler);
                    std::thread::spawn(move || {
                        let _ = transport::handle_client_connection(stream, handler_clone, state_clone);
                    });
                }
                Err(e) => {
                    eprintln!("daemon accept error: {e}");
                }
            }
        }

        let _ = std::fs::remove_file(socket_path);
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (socket_path, home, shutdown_flag);
        Err("daemon server not supported on this platform".to_string())
    }
}
