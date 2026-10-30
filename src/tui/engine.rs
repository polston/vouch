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

#[derive(Debug, Clone)]
pub struct ConfigUndoSnapshot {
    pub previous_toml: String,
    pub previous_my_knowledge_toml: Option<String>,
    pub description: String,
    pub restored_candidates: Vec<ReviewCandidate>,
}

pub struct TuiEngine {
    pub home: String,
    pub decisions: Vec<DecisionItem>,
    pub candidates: Vec<ReviewCandidate>,
    pub undo_stack: std::cell::RefCell<Vec<ConfigUndoSnapshot>>,
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

        // Synthesize granular exact_args (my-knowledge.toml) and script_constructs (config.toml)
        // candidates from executed ASK records.
        candidates.extend(synthesize_granular_candidates(records));

        // Sort candidates: proposable first, then by approved count
        candidates.sort_by(|a, b| {
            b.proposable.cmp(&a.proposable)
                .then_with(|| b.approved.cmp(&a.approved))
        });

        Self {
            home: home.to_string(),
            decisions,
            candidates,
            undo_stack: std::cell::RefCell::new(Vec::new()),
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
            if cand.target_file != TargetFile::Config {
                continue;
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
            } else if cand.section.ends_with(".script_constructs") {
                let (updated, sum) = apply_script_construct_candidate_to_toml(&current_content, cand)?;
                current_content = updated;
                summaries.push(sum);
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

    pub fn build_cumulative_amended_my_knowledge_toml(
        &self,
        cands: &[ReviewCandidate],
    ) -> Result<(String, String), String> {
        let my_kb_path = crate::knowledge::config_dir(&self.home).join("my-knowledge.toml");
        let mut current_content = std::fs::read_to_string(&my_kb_path).unwrap_or_default();
        let mut summaries = Vec::new();

        for cand in cands {
            if !cand.proposable {
                return Err(cand
                    .blocked_reason
                    .clone()
                    .unwrap_or_else(|| "Candidate is not proposable".to_string()));
            }
            if cand.target_file != TargetFile::MyKnowledge {
                continue;
            }
            let (updated, sum) = apply_exact_args_candidate_to_my_knowledge_toml(&current_content, cand)?;
            current_content = updated;
            summaries.push(sum);
        }

        // Validate against the knowledge schema before returning
        crate::knowledge::validate_text(&current_content)?;

        Ok((current_content, summaries.join(" + ")))
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
        if cands.is_empty() {
            return Err("No candidate rules provided".to_string());
        }
        let has_config_cands = cands.iter().any(|c| c.target_file == TargetFile::Config);
        let has_kb_cands = cands.iter().any(|c| c.target_file == TargetFile::MyKnowledge);

        let (amended_toml, cfg_summary, has_explicit_bash_default) =
            self.build_cumulative_amended_config_toml(cands)?;
        let mut cfg = crate::config::load(&amended_toml)?;
        if !has_explicit_bash_default && !decision.reason.contains("default") {
            cfg.langs
                .entry("bash".to_string())
                .or_default()
                .default = crate::config::Action::Allow;
        }

        let mut summary_parts = Vec::new();
        if has_config_cands && !cfg_summary.is_empty() {
            summary_parts.push(cfg_summary);
        }

        let merged_kb_opt = if has_kb_cands {
            let (amended_my_kb, kb_summary) =
                self.build_cumulative_amended_my_knowledge_toml(cands)?;
            if !kb_summary.is_empty() {
                summary_parts.push(kb_summary);
            }
            let mine_kb = crate::guards::load(&amended_my_kb)?;
            crate::knowledge::validate(&mine_kb)?;
            let base_kb = crate::guards::in_effect().clone();
            Some(crate::knowledge::merge(base_kb, mine_kb))
        } else {
            None
        };

        let amendment_summary = summary_parts.join(" + ");

        let simulated_decision = crate::engine::decide_command_at_with_knowledge(
            &cfg,
            "bash",
            &decision.cmd,
            Some(&self.home),
            Some(&decision.cwd),
            Some(&decision.cwd),
            merged_kb_opt.as_ref(),
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
                let sim_d = crate::engine::decide_command_at_with_knowledge(
                    &cfg,
                    "bash",
                    &d.cmd,
                    Some(&self.home),
                    Some(&d.cwd),
                    Some(&d.cwd),
                    merged_kb_opt.as_ref(),
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

    /// Applies an approved candidate rule to configuration files and pushes a rollback snapshot onto `undo_stack`.
    pub fn apply_candidate(&self, cand: &ReviewCandidate) -> Result<String, String> {
        let config_dir = crate::knowledge::config_dir(&self.home);
        let config_path = config_dir.join("config.toml");
        let my_kb_path = config_dir.join("my-knowledge.toml");
        let previous_toml = std::fs::read_to_string(&config_path).unwrap_or_default();

        if cand.target_file == TargetFile::MyKnowledge {
            let previous_my_kb = std::fs::read_to_string(&my_kb_path).unwrap_or_default();
            let (updated_my_kb, summary) =
                self.build_cumulative_amended_my_knowledge_toml(std::slice::from_ref(cand))?;
            let _ = std::fs::create_dir_all(&config_dir);
            std::fs::write(&my_kb_path, updated_my_kb)
                .map_err(|e| format!("Failed to write my-knowledge.toml: {e}"))?;

            self.undo_stack.borrow_mut().push(ConfigUndoSnapshot {
                previous_toml,
                previous_my_knowledge_toml: Some(previous_my_kb),
                description: summary.clone(),
                restored_candidates: vec![cand.clone()],
            });

            return Ok(format!("Added {summary} to my-knowledge.toml"));
        }

        let (updated_toml, summary, _) = self.build_amended_config_toml(cand)?;
        let _ = std::fs::create_dir_all(&config_dir);
        std::fs::write(&config_path, updated_toml)
            .map_err(|e| format!("Failed to write config: {e}"))?;

        self.undo_stack.borrow_mut().push(ConfigUndoSnapshot {
            previous_toml,
            previous_my_knowledge_toml: None,
            description: summary.clone(),
            restored_candidates: vec![cand.clone()],
        });

        if cand.section == "write.allow_paths" {
            let path_to_add = cand.name.strip_prefix("path: ").unwrap_or(&cand.name);
            Ok(format!("Added {:?} to write.allow_paths in config.toml", path_to_add))
        } else if cand.section.ends_with(".script_constructs") {
            Ok(format!("Added {summary} to config.toml"))
        } else {
            Ok(format!("Added [{}] {} = \"allow\" to config.toml", cand.section, cand.name))
        }
    }

    /// Atomically applies multiple staged candidate rules to `config.toml` and/or `my-knowledge.toml` and pushes a rollback snapshot onto `undo_stack`.
    pub fn apply_candidates(&self, cands: &[ReviewCandidate]) -> Result<String, String> {
        if cands.len() == 1 {
            return self.apply_candidate(&cands[0]);
        }
        let config_dir = crate::knowledge::config_dir(&self.home);
        let config_path = config_dir.join("config.toml");
        let my_kb_path = config_dir.join("my-knowledge.toml");
        let previous_toml = std::fs::read_to_string(&config_path).unwrap_or_default();

        let has_config_cands = cands.iter().any(|c| c.target_file == TargetFile::Config);
        let has_kb_cands = cands.iter().any(|c| c.target_file == TargetFile::MyKnowledge);

        let mut summaries = Vec::new();
        let mut updated_toml_opt = None;
        if has_config_cands {
            let (updated_toml, summary, _) = self.build_cumulative_amended_config_toml(cands)?;
            updated_toml_opt = Some(updated_toml);
            if !summary.is_empty() {
                summaries.push(summary);
            }
        }

        let mut previous_my_kb_opt = None;
        let mut updated_my_kb_opt = None;
        if has_kb_cands {
            let prev = std::fs::read_to_string(&my_kb_path).unwrap_or_default();
            let (updated_my_kb, summary) = self.build_cumulative_amended_my_knowledge_toml(cands)?;
            previous_my_kb_opt = Some(prev);
            updated_my_kb_opt = Some(updated_my_kb);
            if !summary.is_empty() {
                summaries.push(summary);
            }
        }

        let _ = std::fs::create_dir_all(&config_dir);
        if let Some(updated_toml) = updated_toml_opt {
            std::fs::write(&config_path, updated_toml)
                .map_err(|e| format!("Failed to write config: {e}"))?;
        }
        if let Some(updated_my_kb) = updated_my_kb_opt {
            std::fs::write(&my_kb_path, updated_my_kb)
                .map_err(|e| format!("Failed to write my-knowledge.toml: {e}"))?;
        }

        let summary = summaries.join(" + ");
        self.undo_stack.borrow_mut().push(ConfigUndoSnapshot {
            previous_toml,
            previous_my_knowledge_toml: previous_my_kb_opt,
            description: summary.clone(),
            restored_candidates: cands.to_vec(),
        });

        let target_label = match (has_config_cands, has_kb_cands) {
            (true, true) => "config.toml & my-knowledge.toml",
            (false, true) => "my-knowledge.toml",
            _ => "config.toml",
        };

        Ok(format!(
            "Applied {} staged amendments ({}) to {}",
            cands.len(),
            summary,
            target_label
        ))
    }

    /// Reverts the most recent `config.toml` and/or `my-knowledge.toml` amendment from `undo_stack` and restores its candidate entries.
    pub fn undo_last_amendment(&mut self) -> Result<String, String> {
        let Some(snapshot) = self.undo_stack.borrow_mut().pop() else {
            return Err("Undo stack is empty (no applied amendments in this session)".to_string());
        };
        let config_dir = crate::knowledge::config_dir(&self.home);
        let config_path = config_dir.join("config.toml");
        std::fs::write(&config_path, &snapshot.previous_toml)
            .map_err(|e| format!("Failed to write reverted config: {e}"))?;

        if let Some(ref prev_kb) = snapshot.previous_my_knowledge_toml {
            let my_kb_path = config_dir.join("my-knowledge.toml");
            std::fs::write(&my_kb_path, prev_kb)
                .map_err(|e| format!("Failed to write reverted my-knowledge.toml: {e}"))?;
        }

        for cand in snapshot.restored_candidates {
            if !self
                .candidates
                .iter()
                .any(|c| c.section == cand.section && c.name == cand.name)
            {
                self.candidates.push(cand);
            }
        }
        self.candidates.sort_by(|a, b| {
            b.proposable
                .cmp(&a.proposable)
                .then_with(|| b.approved.cmp(&a.approved))
        });

        if snapshot.previous_my_knowledge_toml.is_some() {
            Ok(format!(
                "Reverted policy amendment ({})",
                snapshot.description
            ))
        } else {
            Ok(format!(
                "Reverted config.toml amendment ({})",
                snapshot.description
            ))
        }
    }

    /// Builds a unified diff (`--- a/config.toml` / `+++ b/config.toml` and/or `my-knowledge.toml`)
    /// between the current on-disk files and the cumulative amended files for `cands`.
    pub fn build_unified_diff_for_candidates(
        &self,
        cands: &[ReviewCandidate],
    ) -> Result<String, String> {
        let has_config_cands = cands.iter().any(|c| c.target_file == TargetFile::Config);
        let has_kb_cands = cands.iter().any(|c| c.target_file == TargetFile::MyKnowledge);
        let mut diffs = Vec::new();

        if has_config_cands {
            let config_path = crate::knowledge::config_dir(&self.home).join("config.toml");
            let before = std::fs::read_to_string(&config_path).unwrap_or_default();
            let (after, summary, _) = self.build_cumulative_amended_config_toml(cands)?;
            diffs.push(render_unified_toml_diff_named(
                &before,
                &after,
                &summary,
                "config.toml",
            ));
        }
        if has_kb_cands {
            let my_kb_path = crate::knowledge::config_dir(&self.home).join("my-knowledge.toml");
            let before = std::fs::read_to_string(&my_kb_path).unwrap_or_default();
            let (after, summary) = self.build_cumulative_amended_my_knowledge_toml(cands)?;
            diffs.push(render_unified_toml_diff_named(
                &before,
                &after,
                &summary,
                "my-knowledge.toml",
            ));
        }
        if diffs.is_empty() {
            return Err("No candidate rules provided".to_string());
        }
        Ok(diffs.join("\n"))
    }
}

fn render_unified_toml_diff_named(
    before: &str,
    after: &str,
    summary: &str,
    filename: &str,
) -> String {
    let before_lines: Vec<&str> = before.lines().collect();
    let after_lines: Vec<&str> = after.lines().collect();
    let mut out = String::new();
    out.push_str(&format!("# Amendment Summary: {summary}\n"));
    out.push_str(&format!("--- a/{filename}\n"));
    out.push_str(&format!("+++ b/{filename}\n"));
    out.push_str(&format!(
        "@@ -1,{} +1,{} @@\n",
        before_lines.len(),
        after_lines.len()
    ));

    let mut b_idx = 0usize;
    let mut a_idx = 0usize;
    while b_idx < before_lines.len() || a_idx < after_lines.len() {
        match (before_lines.get(b_idx), after_lines.get(a_idx)) {
            (Some(&b_line), Some(&a_line)) if b_line == a_line => {
                out.push_str(&format!(" {b_line}\n"));
                b_idx += 1;
                a_idx += 1;
            }
            (Some(&b_line), Some(&a_line)) => {
                // Check if b_line appears shortly ahead in after_lines (insertion in `after`)
                if after_lines[a_idx + 1..].contains(&b_line) {
                    out.push_str(&format!("+{a_line}\n"));
                    a_idx += 1;
                } else if before_lines[b_idx + 1..].contains(&a_line) {
                    out.push_str(&format!("-{b_line}\n"));
                    b_idx += 1;
                } else {
                    out.push_str(&format!("-{b_line}\n"));
                    out.push_str(&format!("+{a_line}\n"));
                    b_idx += 1;
                    a_idx += 1;
                }
            }
            (Some(&b_line), None) => {
                out.push_str(&format!("-{b_line}\n"));
                b_idx += 1;
            }
            (None, Some(&a_line)) => {
                out.push_str(&format!("+{a_line}\n"));
                a_idx += 1;
            }
            (None, None) => break,
        }
    }
    out
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

pub(crate) fn extract_unmodeled_exact_args_from_cmd(
    cmd_src: &str,
    reason: &str,
) -> Option<(String, Vec<String>)> {
    if !reason.contains("unmodeled_command") {
        return None;
    }
    let scan = crate::shell::parse(cmd_src).ok()?;
    let kb = crate::guards::in_effect();
    let mut fork = crate::guards::ForkCursor::new(&[]);
    let expanded = crate::guards::expand_wrappers_forking(
        kb,
        &scan.commands,
        &scan.heredocs,
        &scan.input_source,
        &scan.args_complete,
        &[],
        "bash",
        &|_| 4,
        &mut fork,
    );
    for occ in &expanded.occurrences {
        let c = &occ.cmd;
        if c.head.is_empty() || c.args.is_empty() {
            continue;
        }
        let clang = if occ.lang.is_empty() {
            "bash"
        } else {
            occ.lang.as_str()
        };
        let eligible = occ.args_complete && !occ.args_from_input;
        if !eligible || crate::guards::recognises(kb, c, clang, eligible) {
            continue;
        }
        let prog = crate::guards::base(&c.head);
        if prog.starts_with("python:") {
            continue;
        }
        let mut vec = Vec::with_capacity(c.args.len());
        let mut all_readable = true;
        for (idx, raw) in c.args.iter().enumerate() {
            if c.unread_args.contains(&idx) {
                all_readable = false;
                break;
            }
            let unquoted = crate::paths::unquote(raw);
            if unquoted.is_empty()
                || unquoted.contains(['\'', '"'])
                || crate::guards::carries_expansion(raw)
            {
                all_readable = false;
                break;
            }
            vec.push(unquoted.to_string());
        }
        if all_readable && !vec.is_empty() {
            return Some((prog, vec));
        }
    }
    None
}

pub(crate) fn extract_script_construct_from_cmd(
    cmd_src: &str,
    cwd: &str,
    reason: &str,
) -> Option<(String, String, String, String)> {
    let first_line = reason.lines().next()?.trim();
    let rule_name = first_line.strip_prefix("vouch stopped on:")?.trim();
    if rule_name.ends_with("(guard)")
        || rule_name == "unmodeled_command"
        || rule_name.contains("path outside")
    {
        return None;
    }
    let scan = crate::shell::parse(cmd_src).ok()?;
    let kb = crate::guards::in_effect();
    let mut fork = crate::guards::ForkCursor::new(&[]);
    let cwd_opt = if cwd.is_empty() { None } else { Some(cwd) };
    let expanded = crate::guards::expand_wrappers_forking_with_context(
        kb,
        &scan.commands,
        &scan.heredocs,
        &scan.input_source,
        &scan.args_complete,
        &[],
        "bash",
        &|_| 4,
        &mut fork,
        cwd_opt,
        Some(262_144),
    );
    for site in &expanded.srcs {
        if let Some(ref prov) = site.inspected_script {
            if site.constructs.iter().any(|c| c == rule_name) {
                return Some((
                    site.lang.clone(),
                    rule_name.to_string(),
                    prov.canonical_path.clone(),
                    prov.sha256_hex.clone(),
                ));
            }
        }
    }
    None
}

pub(crate) fn format_exact_args_proposed_toml(prog: &str, args: &[String]) -> String {
    let args_formatted = args
        .iter()
        .map(|a| format!("{a:?}"))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "[[program]]\nmatch = [{prog:?}]\ncase_sensitive_flags = true\nexact_args = [[{args_formatted}]]\n"
    )
}

pub(crate) fn format_script_construct_proposed_toml(
    lang: &str,
    construct: &str,
    canonical_path: &str,
    sha256_hex: &str,
) -> String {
    format!(
        "[[lang.{lang}.script_constructs]]\nunder = [{canonical_path:?}]\nsha256 = [{sha256_hex:?}]\n{construct} = \"allow\"\n"
    )
}

fn synthesize_granular_candidates(records: &[Record]) -> Vec<ReviewCandidate> {
    let mut out = Vec::new();
    let mut exact_counts: std::collections::HashMap<
        (String, Vec<String>),
        (usize, usize, usize, std::collections::HashSet<String>, String),
    > = std::collections::HashMap::new();
    let mut script_counts: std::collections::HashMap<
        (String, String, String, String),
        (usize, usize, usize, std::collections::HashSet<String>, String),
    > = std::collections::HashMap::new();

    for r in records {
        if r.verdict != "ask" || r.mode != "live" || r.measurement {
            continue;
        }
        if let Some((prog, args)) = extract_unmodeled_exact_args_from_cmd(&r.cmd, &r.reason) {
            let entry = exact_counts
                .entry((prog, args))
                .or_insert_with(|| (0, 0, 0, std::collections::HashSet::new(), r.cmd.clone()));
            match r.outcome {
                Outcome::Executed => entry.0 += 1,
                Outcome::Denied => entry.1 += 1,
                _ => entry.2 += 1,
            }
            entry.3.insert(r.session.clone());
        }
        if let Some((lang, construct, path, sha)) =
            extract_script_construct_from_cmd(&r.cmd, &r.cwd, &r.reason)
        {
            let entry = script_counts
                .entry((lang, construct, path, sha))
                .or_insert_with(|| (0, 0, 0, std::collections::HashSet::new(), r.cmd.clone()));
            match r.outcome {
                Outcome::Executed => entry.0 += 1,
                Outcome::Denied => entry.1 += 1,
                _ => entry.2 += 1,
            }
            entry.3.insert(r.session.clone());
        }
    }

    for ((prog, args), (app, den, unk, sess, example)) in exact_counts {
        if app > 0 {
            let args_fmt = args
                .iter()
                .map(|a| format!("{a:?}"))
                .collect::<Vec<_>>()
                .join(", ");
            out.push(ReviewCandidate {
                name: format!("exact_args: {prog} [{args_fmt}]"),
                section: "program.exact_args".to_string(),
                target_file: TargetFile::MyKnowledge,
                proposed_toml: format_exact_args_proposed_toml(&prog, &args),
                approved: app,
                denied: den,
                unknown: unk,
                sessions: sess.len().max(1),
                proposable: true,
                blocked_reason: None,
                example_cmd: example,
            });
        }
    }

    for ((lang, construct, path, sha), (app, den, unk, sess, example)) in script_counts {
        if app > 0 {
            let short_sha: String = sha.chars().take(12).collect();
            out.push(ReviewCandidate {
                name: format!("{construct} @ {path} (sha256:{short_sha}...)"),
                section: format!("lang.{lang}.script_constructs"),
                target_file: TargetFile::Config,
                proposed_toml: format_script_construct_proposed_toml(
                    &lang, &construct, &path, &sha,
                ),
                approved: app,
                denied: den,
                unknown: unk,
                sessions: sess.len().max(1),
                proposable: true,
                blocked_reason: None,
                example_cmd: example,
            });
        }
    }

    out
}

fn apply_script_construct_candidate_to_toml(
    current_content: &str,
    cand: &ReviewCandidate,
) -> Result<(String, String), String> {
    let mut doc: toml_edit::DocumentMut = current_content
        .parse()
        .map_err(|e| format!("Invalid TOML: {e}"))?;
    let prop_doc: toml_edit::DocumentMut = cand
        .proposed_toml
        .parse()
        .map_err(|e| format!("Invalid proposed script_constructs TOML: {e}"))?;

    let lang = cand
        .section
        .strip_prefix("lang.")
        .and_then(|s| s.strip_suffix(".script_constructs"))
        .ok_or_else(|| format!("Invalid script_constructs section: {}", cand.section))?;

    let prop_aot = prop_doc
        .get("lang")
        .and_then(|l| l.get(lang))
        .and_then(|lg| lg.get("script_constructs"))
        .and_then(|sc| sc.as_array_of_tables())
        .and_then(|aot| aot.iter().next())
        .ok_or_else(|| "Proposed TOML missing [[lang.<L>.script_constructs]] table".to_string())?;

    let lang_item = doc
        .entry("lang")
        .or_insert(toml_edit::Item::Table(toml_edit::Table::new()));
    let lang_table = lang_item
        .as_table_like_mut()
        .ok_or_else(|| "lang is not a table".to_string())?;
    let sub_item = lang_table
        .entry(lang)
        .or_insert(toml_edit::Item::Table(toml_edit::Table::new()));
    let sub_table = sub_item
        .as_table_like_mut()
        .ok_or_else(|| format!("lang.{lang} is not a table"))?;
    let sc_item = sub_table.entry("script_constructs").or_insert(
        toml_edit::Item::ArrayOfTables(toml_edit::ArrayOfTables::new()),
    );
    let aot = sc_item
        .as_array_of_tables_mut()
        .ok_or_else(|| format!("lang.{lang}.script_constructs is not an array of tables"))?;

    let prop_under = prop_aot
        .get("under")
        .and_then(|u| u.as_array())
        .and_then(|a| a.get(0))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let prop_sha = prop_aot
        .get("sha256")
        .and_then(|u| u.as_array())
        .and_then(|a| a.get(0))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let mut construct_key = String::new();
    for (k, _) in prop_aot.iter() {
        if k != "under" && k != "sha256" {
            construct_key = k.to_string();
            break;
        }
    }

    let mut merged = false;
    for existing in aot.iter_mut() {
        let same_under = existing
            .get("under")
            .and_then(|u| u.as_array())
            .is_some_and(|a| a.iter().any(|v| v.as_str() == Some(prop_under)));
        let same_sha = existing
            .get("sha256")
            .and_then(|u| u.as_array())
            .is_some_and(|a| a.iter().any(|v| v.as_str() == Some(prop_sha)));
        if same_under && same_sha && !construct_key.is_empty() {
            existing.insert(&construct_key, toml_edit::value("allow"));
            merged = true;
            break;
        }
    }
    if !merged {
        aot.push(prop_aot.clone());
    }

    let summary = format!(
        "[[lang.{lang}.script_constructs]] {construct_key} = \"allow\" (under = {prop_under:?})"
    );
    Ok((doc.to_string(), summary))
}

fn apply_exact_args_candidate_to_my_knowledge_toml(
    current_content: &str,
    cand: &ReviewCandidate,
) -> Result<(String, String), String> {
    let mut doc: toml_edit::DocumentMut = current_content
        .parse()
        .map_err(|e| format!("Invalid my-knowledge.toml: {e}"))?;
    let prop_doc: toml_edit::DocumentMut = cand
        .proposed_toml
        .parse()
        .map_err(|e| format!("Invalid proposed exact_args TOML: {e}"))?;

    let prop_table = prop_doc
        .get("program")
        .and_then(|p| p.as_array_of_tables())
        .and_then(|aot| aot.iter().next())
        .ok_or_else(|| "Proposed TOML missing [[program]] table".to_string())?;

    let prog_name = prop_table
        .get("match")
        .and_then(|m| m.as_array())
        .and_then(|a| a.get(0))
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Proposed [[program]] missing match name".to_string())?;

    let new_vec_val = prop_table
        .get("exact_args")
        .and_then(|e| e.as_array())
        .and_then(|a| a.get(0))
        .cloned()
        .ok_or_else(|| "Proposed [[program]] missing exact_args vector".to_string())?;

    let prog_item = doc
        .entry("program")
        .or_insert(toml_edit::Item::ArrayOfTables(toml_edit::ArrayOfTables::new()));
    let aot = prog_item
        .as_array_of_tables_mut()
        .ok_or_else(|| "program in my-knowledge.toml is not an array of tables".to_string())?;

    let mut merged = false;
    for existing in aot.iter_mut() {
        let matches_prog = existing
            .get("match")
            .and_then(|m| m.as_array())
            .is_some_and(|a| {
                a.len() == 1
                    && a.get(0)
                        .and_then(|v| v.as_str())
                        .is_some_and(|s| s.eq_ignore_ascii_case(prog_name))
            });
        if matches_prog {
            let exact_item = existing.entry("exact_args").or_insert(toml_edit::Item::Value(
                toml_edit::Value::Array(toml_edit::Array::new()),
            ));
            if let Some(arr) = exact_item.as_array_mut() {
                let new_str = new_vec_val.to_string();
                if !arr.iter().any(|v| v.to_string().trim() == new_str.trim()) {
                    arr.push_formatted(new_vec_val.clone());
                }
                merged = true;
                break;
            }
        }
    }

    if !merged {
        aot.push(prop_table.clone());
    }

    let summary = format!(
        "[[program]] match = [{prog_name:?}] exact_args += [{}]",
        new_vec_val.to_string().trim()
    );
    Ok((doc.to_string(), summary))
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
