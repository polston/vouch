//! Decision Query Engine and Rule Candidate Generator for Vouch TUI.

use crate::journal::Record;
use crate::outcome::Outcome;
use crate::review::{self, Candidate};
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver};
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetFile {
    Config,
    MyKnowledge,
}

#[derive(Debug, Clone)]
pub struct ReviewCandidate {
    pub name: String,
    pub section: String,
    pub target_file: TargetFile,
    pub proposed_toml: String,
    pub approved: usize,
    pub denied: usize,
    pub unknown: usize,
    pub sessions: usize,
    pub proposable: bool,
    pub blocked_reason: Option<String>,
    pub example_cmd: String,
}

#[derive(Debug, Clone)]
pub struct DecisionItem {
    pub timestamp: String,
    pub cmd: String,
    pub verdict: String,
    pub reason: String,
    pub outcome: String,
    pub session: String,
    pub cwd: String,
}

pub struct TuiEngine {
    pub home: String,
    pub decisions: Vec<DecisionItem>,
    pub candidates: Vec<ReviewCandidate>,
    pub tail_reader: Option<JournalTailReader>,
    pub tail_receiver: Option<std::sync::mpsc::Receiver<Record>>,
}

impl TuiEngine {
    pub fn load(home: &str) -> Self {
        let state_dir = crate::journal::state_dir();
        let records = crate::journal::all(&state_dir);
        let vlog_file = state_dir.join("journal.vlog");
        let tail_path = if vlog_file.exists() {
            vlog_file
        } else {
            state_dir.join("journal.jsonl")
        };
        Self::from_records(home, &records).with_tail_reader(JournalTailReader::new(tail_path))
    }

    pub fn from_records(home: &str, records: &[Record]) -> Self {
        let mut decisions = Vec::new();
        // Load recent decisions in reverse chronological order
        for r in records.iter().rev().take(100) {
            decisions.push(DecisionItem {
                timestamp: r.ts.clone(),
                cmd: r.cmd.clone(),
                verdict: r.verdict.clone(),
                reason: r.reason.clone(),
                outcome: format!("{:?}", r.outcome),
                session: r.session.clone(),
                cwd: r.cwd.clone(),
            });
        }

        // Generate construct candidates via existing review module
        let base_cands = review::candidates(records);
        let mut candidates = Vec::new();

        for c in base_cands {
            let proposed_toml = if c.proposable {
                format!("[{}]\n{} = \"allow\"\n", c.section, c.name)
            } else {
                String::new()
            };

            candidates.push(ReviewCandidate {
                name: c.name,
                section: c.section,
                target_file: TargetFile::Config,
                proposed_toml,
                approved: c.approved,
                denied: c.denied,
                unknown: c.unknown,
                sessions: c.sessions,
                proposable: c.proposable,
                blocked_reason: c.blocked,
                example_cmd: c.example,
            });
        }

        // Also identify frequent unpermitted write paths that asked and were executed
        let mut path_counts: std::collections::HashMap<String, (usize, usize, usize)> = std::collections::HashMap::new();
        for r in records {
            if r.verdict == "ask" && r.reason.contains("path outside every allowed area") {
                if let Some(path) = extract_unpermitted_path(&r.reason) {
                    let entry = path_counts.entry(path).or_insert((0, 0, 0));
                    match r.outcome {
                        Outcome::Executed => entry.0 += 1,
                        Outcome::Denied => entry.1 += 1,
                        _ => entry.2 += 1,
                    }
                }
            }
        }

        for (path, (app, den, unk)) in path_counts {
            if app > 0 {
                candidates.push(ReviewCandidate {
                    name: format!("path: {path}"),
                    section: "write.allow_paths".to_string(),
                    target_file: TargetFile::Config,
                    proposed_toml: format!("[write]\nallow_paths = [\"{}\"]\n", path),
                    approved: app,
                    denied: den,
                    unknown: unk,
                    sessions: 1,
                    proposable: true,
                    blocked_reason: None,
                    example_cmd: format!("touch {path}"),
                });
            }
        }

        // Sort candidates: proposable first, then by approved count
        candidates.sort_by(|a, b| {
            b.proposable.cmp(&a.proposable)
                .then_with(|| b.approved.cmp(&a.approved))
        });

        Self {
            home: home.to_string(),
            decisions,
            candidates,
            tail_reader: None,
            tail_receiver: None,
        }
    }

    pub fn with_tail_reader(mut self, reader: JournalTailReader) -> Self {
        self.tail_reader = Some(reader);
        self
    }

    pub fn with_tail_receiver(mut self, rx: Receiver<Record>) -> Self {
        self.tail_receiver = Some(rx);
        self
    }

    pub fn push_record(&mut self, r: &Record) {
        let item = DecisionItem {
            timestamp: r.ts.clone(),
            cmd: r.cmd.clone(),
            verdict: r.verdict.clone(),
            reason: r.reason.clone(),
            outcome: format!("{:?}", r.outcome),
            session: r.session.clone(),
            cwd: r.cwd.clone(),
        };
        self.decisions.insert(0, item);
    }

    pub fn poll_live_events(&mut self) -> usize {
        let mut new_recs = Vec::new();
        if let Some(ref rx) = self.tail_receiver {
            while let Ok(rec) = rx.try_recv() {
                new_recs.push(rec);
            }
        }
        if let Some(ref mut reader) = self.tail_reader {
            let records = reader.poll_new_records();
            new_recs.extend(records);
        }
        let count = new_recs.len();
        for r in &new_recs {
            self.push_record(r);
        }
        count
    }

    pub fn build_cumulative_amended_config_toml(
        &self,
        cands: &[ReviewCandidate],
    ) -> Result<(String, String, bool), String> {
        if cands.is_empty() {
            return Err("No candidate rules provided".to_string());
        }
        let config_path = crate::knowledge::config_dir(&self.home).join("config.toml");
        let mut current_content = std::fs::read_to_string(&config_path).unwrap_or_default();
        let orig_doc: toml_edit::DocumentMut = current_content
            .parse()
            .map_err(|e| format!("Invalid TOML: {e}"))?;
        let has_explicit_bash_default = orig_doc
            .get("lang")
            .and_then(|l| l.get("bash"))
            .and_then(|b| b.get("default"))
            .is_some();

        let mut summaries = Vec::with_capacity(cands.len());
        for cand in cands {
            if !cand.proposable {
                return Err(cand
                    .blocked_reason
                    .clone()
                    .unwrap_or_else(|| "Candidate is not proposable".to_string()));
            }
            if cand.section == "write.allow_paths" {
                let path_to_add = cand.name.strip_prefix("path: ").unwrap_or(&cand.name);
                let mut doc: toml_edit::DocumentMut = current_content
                    .parse()
                    .map_err(|e| format!("Invalid TOML: {e}"))?;
                let write_table = doc
                    .entry("write")
                    .or_insert(toml_edit::Item::Table(toml_edit::Table::new()));
                let write_table = write_table
                    .as_table_like_mut()
                    .ok_or_else(|| "write is not a table")?;

                let allow_paths = write_table.entry("allow_paths").or_insert(
                    toml_edit::Item::Value(toml_edit::Value::Array(toml_edit::Array::new())),
                );
                if let Some(arr) = allow_paths.as_array_mut() {
                    if !arr.iter().any(|v| v.as_str() == Some(path_to_add)) {
                        arr.push(path_to_add);
                    }
                }
                current_content = doc.to_string();
                summaries.push(format!("[write] allow_paths += {:?}", path_to_add));
            } else {
                let c = Candidate {
                    name: cand.name.clone(),
                    section: cand.section.clone(),
                    approved: cand.approved.max(1),
                    denied: cand.denied,
                    unknown: cand.unknown,
                    sessions: cand.sessions.max(1),
                    proposable: true,
                    blocked: None,
                    example: cand.example_cmd.clone(),
                };
                current_content = review::apply(&current_content, &c)?;
                summaries.push(format!("[{}] {} = \"allow\"", cand.section, cand.name));
            }
        }

        Ok((
            current_content,
            summaries.join(" + "),
            has_explicit_bash_default,
        ))
    }

    fn build_amended_config_toml(
        &self,
        cand: &ReviewCandidate,
    ) -> Result<(String, String, bool), String> {
        self.build_cumulative_amended_config_toml(std::slice::from_ref(cand))
    }

    /// Simulates a single candidate policy amendment in-memory against a `DecisionItem` without writing to disk.
    pub fn simulate_candidate(
        &self,
        decision: &DecisionItem,
        cand: &ReviewCandidate,
        target_node_id: usize,
    ) -> Result<super::graph::PolicySimulationResult, String> {
        self.simulate_candidates(decision, std::slice::from_ref(cand), vec![target_node_id])
    }

    /// Simulates one or more staged candidate policy amendments cumulatively in-memory against a `DecisionItem`
    /// and computes session-wide batch impact (`session_flipped_to_allow` / `session_ask_total`).
    pub fn simulate_candidates(
        &self,
        decision: &DecisionItem,
        cands: &[ReviewCandidate],
        staged_node_ids: Vec<usize>,
    ) -> Result<super::graph::PolicySimulationResult, String> {
        let (amended_toml, amendment_summary, has_explicit_bash_default) =
            self.build_cumulative_amended_config_toml(cands)?;
        let mut cfg = crate::config::load(&amended_toml)?;
        if !has_explicit_bash_default && !decision.reason.contains("default") {
            cfg.langs
                .entry("bash".to_string())
                .or_default()
                .default = crate::config::Action::Allow;
        }

        let simulated_decision = crate::engine::decide_command_at(
            &cfg,
            "bash",
            &decision.cmd,
            Some(&self.home),
            Some(&decision.cwd),
            Some(&decision.cwd),
        );
        let (after_verdict, after_reason) = match simulated_decision {
            crate::protocol::Decision::Allow(r) => ("ALLOW".to_string(), r),
            crate::protocol::Decision::Ask(r) => ("ASK".to_string(), r),
            crate::protocol::Decision::Deny(r) => ("DENY".to_string(), r),
            crate::protocol::Decision::Abstain => ("ABSTAIN".to_string(), "abstained".to_string()),
        };

        let mut session_ask_total = 0usize;
        let mut session_flipped_to_allow = 0usize;
        for d in &self.decisions {
            if d.verdict.eq_ignore_ascii_case("ask") {
                session_ask_total += 1;
                let sim_d = crate::engine::decide_command_at(
                    &cfg,
                    "bash",
                    &d.cmd,
                    Some(&self.home),
                    Some(&d.cwd),
                    Some(&d.cwd),
                );
                if matches!(sim_d, crate::protocol::Decision::Allow(_)) {
                    session_flipped_to_allow += 1;
                }
            }
        }

        let target_node_id = staged_node_ids.last().copied().unwrap_or(0);
        Ok(super::graph::PolicySimulationResult {
            target_node_id,
            staged_node_ids,
            amendment_summary,
            before_verdict: decision.verdict.to_uppercase(),
            after_verdict,
            before_reason: decision.reason.clone(),
            after_reason,
            session_ask_total,
            session_flipped_to_allow,
        })
    }

    /// Applies an approved candidate rule to configuration files.
    pub fn apply_candidate(&self, cand: &ReviewCandidate) -> Result<String, String> {
        let (updated_toml, _summary, _) = self.build_amended_config_toml(cand)?;
        let config_path = crate::knowledge::config_dir(&self.home).join("config.toml");
        std::fs::write(&config_path, updated_toml)
            .map_err(|e| format!("Failed to write config: {e}"))?;

        if cand.section == "write.allow_paths" {
            let path_to_add = cand.name.strip_prefix("path: ").unwrap_or(&cand.name);
            Ok(format!("Added {:?} to write.allow_paths in config.toml", path_to_add))
        } else {
            Ok(format!("Added [{}] {} = \"allow\" to config.toml", cand.section, cand.name))
        }
    }

    /// Atomically applies multiple staged candidate rules to `config.toml`.
    pub fn apply_candidates(&self, cands: &[ReviewCandidate]) -> Result<String, String> {
        if cands.len() == 1 {
            return self.apply_candidate(&cands[0]);
        }
        let (updated_toml, summary, _) = self.build_cumulative_amended_config_toml(cands)?;
        let config_path = crate::knowledge::config_dir(&self.home).join("config.toml");
        std::fs::write(&config_path, updated_toml)
            .map_err(|e| format!("Failed to write config: {e}"))?;
        Ok(format!(
            "Applied {} staged amendments ({}) to config.toml",
            cands.len(),
            summary
        ))
    }
}

fn extract_unpermitted_path(reason: &str) -> Option<String> {
    for line in reason.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('/') || (trimmed.len() > 3 && trimmed.chars().nth(1) == Some(':')) {
            return Some(trimmed.to_string());
        }
    }
    None
}

fn is_binary_journal_path(path: & std::path::Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("vlog") | Some("vidx")
    )
}

/// Streaming file follower for `journal.jsonl`, `journal.vlog`, and `journal.vidx`.
pub struct JournalTailReader {
    pub path: PathBuf,
    last_offset: u64,
    last_record_count: u64,
    last_record_key: Option<(String, String, String)>,
}

impl JournalTailReader {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        if is_binary_journal_path(&path) {
            let (last_record_count, last_offset, last_record_key) =
                crate::journal_vlog::inspect_vlog_watermark(&path);
            Self {
                path,
                last_offset,
                last_record_count,
                last_record_key,
            }
        } else {
            let last_offset = if let Ok(meta) = std::fs::metadata(&path) {
                meta.len()
            } else {
                0
            };
            Self {
                path,
                last_offset,
                last_record_count: 0,
                last_record_key: None,
            }
        }
    }

    pub fn from_start(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let initial_offset = if is_binary_journal_path(&path) {
            crate::journal_vlog::VLOG_HEADER_LEN as u64
        } else {
            0
        };
        Self {
            path,
            last_offset: initial_offset,
            last_record_count: 0,
            last_record_key: None,
        }
    }

    pub fn last_offset(&self) -> u64 {
        self.last_offset
    }

    pub fn last_record_count(&self) -> u64 {
        self.last_record_count
    }

    pub fn poll_new_records(&mut self) -> Vec<Record> {
        if is_binary_journal_path(&self.path) {
            return crate::journal_vlog::poll_vlog_delta(
                &self.path,
                &mut self.last_record_count,
                &mut self.last_offset,
                &mut self.last_record_key,
            );
        }

        let Ok(mut file) = File::open(&self.path) else {
            return Vec::new();
        };
        let Ok(meta) = file.metadata() else {
            return Vec::new();
        };
        let current_len = meta.len();
        if current_len <= self.last_offset {
            if current_len < self.last_offset {
                self.last_offset = 0;
            } else {
                return Vec::new();
            }
        }

        if file.seek(SeekFrom::Start(self.last_offset)).is_err() {
            return Vec::new();
        }

        let mut reader = BufReader::new(file);
        let mut new_records = Vec::new();
        let mut line = String::new();

        while let Ok(bytes_read) = reader.read_line(&mut line) {
            if bytes_read == 0 {
                break;
            }
            self.last_offset += bytes_read as u64;
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                if let Ok(rec) = serde_json::from_str::<Record>(trimmed) {
                    self.last_record_count += 1;
                    new_records.push(rec);
                }
            }
            line.clear();
        }

        new_records
    }

    pub fn spawn_channel(
        mut self,
        poll_interval: Duration,
    ) -> (Receiver<Record>, Arc<AtomicBool>) {
        let (tx, rx) = channel();
        let running = Arc::new(AtomicBool::new(true));
        let running_clone = running.clone();

        std::thread::spawn(move || {
            while running_clone.load(Ordering::Relaxed) {
                let records = self.poll_new_records();
                for r in records {
                    if tx.send(r).is_err() {
                        return;
                    }
                }
                std::thread::sleep(poll_interval);
            }
        });

        (rx, running)
    }
}
