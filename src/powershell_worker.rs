//! Reference-grade PowerShell AST parser worker client (M4.8).
//!
//! Supervises a persistent .NET/pwsh process hosting Microsoft's official
//! `System.Management.Automation.Language.Parser`, communicating over standard I/O
//! with JSON Lines. Features instant fail-closed fallback to the pure-Rust
//! scanner if the worker is unavailable, uninstalled, or times out.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::syntax::{Cmd, Order, Scan};

#[derive(Serialize)]
struct WorkerRequest<'a> {
    id: &'a str,
    code: &'a str,
}

#[derive(Deserialize, Debug)]
struct WorkerCommand {
    head: String,
    #[serde(default)]
    args: Vec<String>,
}

#[derive(Deserialize, Debug)]
struct WorkerResponse {
    #[allow(dead_code)]
    id: Option<String>,
    #[serde(default)]
    commands: Vec<WorkerCommand>,
    #[serde(default)]
    redirects: Vec<String>,
    #[serde(default)]
    constructs: Vec<String>,
    #[allow(dead_code)]
    #[serde(default)]
    errors: Vec<String>,
}

struct WorkerJob {
    code: String,
    tx: Sender<Result<Scan, String>>,
}

/// Persistent supervisor managing a background PowerShell parser worker process.
pub struct PowerShellWorker {
    job_tx: Sender<WorkerJob>,
}

impl PowerShellWorker {
    pub fn new(binary: Option<&str>, script_path: Option<PathBuf>) -> Result<Self, String> {
        let (job_tx, job_rx) = channel::<WorkerJob>();
        let bin_name = binary.unwrap_or("pwsh").to_string();
        let script = script_path.unwrap_or_else(|| {
            PathBuf::from("scripts/worker/PowerShellAstWorker.ps1")
        });

        std::thread::Builder::new()
            .name("vouch-pwsh-worker".into())
            .spawn(move || {
                run_worker_thread(bin_name, script, job_rx);
            })
            .map_err(|e| format!("could not spawn worker thread: {e}"))?;

        Ok(Self { job_tx })
    }

    /// Query the worker process to parse PowerShell code within a bounded timeout.
    pub fn query(&self, code: &str, timeout_ms: u64) -> Result<Scan, String> {
        let (tx, rx) = channel();
        self.job_tx
            .send(WorkerJob {
                code: code.to_string(),
                tx,
            })
            .map_err(|e| format!("failed to dispatch query to worker: {e}"))?;

        let timeout = Duration::from_millis(timeout_ms.max(1));
        rx.recv_timeout(timeout)
            .map_err(|e| format!("powershell worker timeout ({timeout_ms}ms): {e}"))?
    }
}

fn spawn_child(binary: &str, script: &Path) -> Result<Child, String> {
    Command::new(binary)
        .arg("-NoProfile")
        .arg("-NonInteractive")
        .arg("-File")
        .arg(script)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("failed to spawn {binary} with {script:?}: {e}"))
}

fn run_worker_thread(binary: String, script: PathBuf, rx: Receiver<WorkerJob>) {
    let mut child_opt: Option<Child> = spawn_child(&binary, &script).ok();

    while let Ok(job) = rx.recv() {
        let mut success = false;

        if child_opt.is_none() {
            child_opt = spawn_child(&binary, &script).ok();
        }

        if let Some(child) = &mut child_opt {
            let res = try_parse_on_child(child, &job.code);
            match res {
                Ok(scan) => {
                    let _ = job.tx.send(Ok(scan));
                    success = true;
                }
                Err(err) => {
                    // Child might have died, kill and restart next time
                    let _ = child.kill();
                    child_opt = None;
                    let _ = job.tx.send(Err(err));
                }
            }
        } else {
            let _ = job.tx.send(Err("powershell worker process could not be started".into()));
        }

        if !success && child_opt.is_none() {
            // Attempt to respawn once
            child_opt = spawn_child(&binary, &script).ok();
        }
    }

    if let Some(mut child) = child_opt {
        let _ = child.kill();
    }
}

fn try_parse_on_child(child: &mut Child, code: &str) -> Result<Scan, String> {
    let stdin = child.stdin.as_mut().ok_or("child stdin unavailable")?;
    let stdout = child.stdout.as_mut().ok_or("child stdout unavailable")?;

    let req = WorkerRequest { id: "p1", code };
    let json = serde_json::to_string(&req).map_err(|e| e.to_string())?;

    writeln!(stdin, "{json}").map_err(|e| format!("write to worker failed: {e}"))?;
    stdin.flush().map_err(|e| format!("flush to worker failed: {e}"))?;

    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader.read_line(&mut line).map_err(|e| format!("read from worker failed: {e}"))?;

    if line.trim().is_empty() {
        return Err("worker returned empty response".into());
    }

    let resp: WorkerResponse = serde_json::from_str(&line)
        .map_err(|e| format!("worker invalid json ({e}): {line}"))?;

    let mut scan = Scan::default();

    for construct in &resp.constructs {
        scan.note(construct);
    }

    let mut initial_cmds = Vec::new();
    for cmd in resp.commands {
        initial_cmds.push(Cmd {
            head: cmd.head,
            args: cmd.args,
            ..Default::default()
        });
    }

    let analyzed_cmds = crate::powershell_pipeline::analyze_pipeline_stages(&initial_cmds);
    for (idx, c) in analyzed_cmds.into_iter().enumerate() {
        scan.commands.push(c);
        scan.order.push(Order::Seq(idx as u32));
        scan.args_complete.push(true);
        scan.indexed_values.push(std::collections::HashMap::new());
        scan.cmd_scope.push(None);
        scan.input_source.push(crate::syntax::InputSource::Unknown);
    }

    for redir in resp.redirects {
        scan.redirect_targets.push(redir);
        scan.redirect_scope.push(None);
        scan.redirect_env.push(std::collections::HashMap::new());
        scan.redirect_chain.push(None);
    }

    Ok(scan)
}

/// Global shared worker singleton for daemon/runtime use.
static GLOBAL_WORKER: OnceLock<Arc<Mutex<Option<PowerShellWorker>>>> = OnceLock::new();

fn get_or_init_worker(cfg: &Config) -> Option<Arc<Mutex<Option<PowerShellWorker>>>> {
    let ps_cfg = cfg.lang("powershell")?;
    if ps_cfg.parser_mode.as_deref() != Some("reference") {
        return None;
    }

    let worker_cell = GLOBAL_WORKER.get_or_init(|| {
        let binary = ps_cfg.worker_binary.as_deref();
        let worker = PowerShellWorker::new(binary, None).ok();
        Arc::new(Mutex::new(worker))
    });

    Some(Arc::clone(worker_cell))
}

/// Parse PowerShell code using the reference .NET worker if configured,
/// falling back safely to the pure-Rust scanner if reference mode is disabled,
/// the worker is unavailable, or execution exceeds worker_timeout_ms.
pub fn parse_with_fallback(src: &str, cfg: &Config) -> Result<Scan, String> {
    let ps_cfg = cfg.lang("powershell");
    let mode = ps_cfg.and_then(|l| l.parser_mode.as_deref()).unwrap_or("scanner");

    if mode == "reference" {
        let timeout_ms = ps_cfg.and_then(|l| l.worker_timeout_ms).unwrap_or(50);
        if let Some(worker_lock) = get_or_init_worker(cfg) {
            if let Ok(mut guard) = worker_lock.lock() {
                if let Some(worker) = guard.as_mut() {
                    match worker.query(src, timeout_ms) {
                        Ok(scan) => return Ok(scan),
                        Err(_) => {
                            // Fallback to pure-Rust scanner below
                        }
                    }
                }
            }
        }
    }

    // Fail-closed fallback: pure-Rust scanner
    crate::powershell::parse(src)
}
