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
            } else if cand.section == "write.scope" {
                let (updated, sum) = apply_write_scope_candidate_to_toml(&current_content, cand)?;
                current_content = updated;
                summaries.push(sum);
            } else if cand.section == "run.guards" {
                let (updated, sum) = apply_place_guard_candidate_to_toml(&current_content, cand)?;
                current_content = updated;
                summaries.push(sum);
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

        let validated_cfg = crate::config::load(&current_content)?;
        crate::config::validate_scopes(&validated_cfg, crate::guards::in_effect())?;

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
            let (updated, sum) = if cand.section == "tool.rule" || cand.section == "tool.action" {
                apply_tool_candidate_to_my_knowledge_toml(&current_content, cand)?
            } else {
                apply_exact_args_candidate_to_my_knowledge_toml(&current_content, cand)?
            };
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

        let simulated_decision =
            self.simulate_single_decision(&cfg, merged_kb_opt.as_ref(), decision);
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
                let sim_d = self.simulate_single_decision(&cfg, merged_kb_opt.as_ref(), d);
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

    fn simulate_single_decision(
        &self,
        cfg: &crate::config::Config,
        kb_opt: Option<&crate::guards::Knowledge>,
        d: &DecisionItem,
    ) -> crate::protocol::Decision {
        if let Some(tool_name) = extract_tool_name_from_reason(&d.reason) {
            let kb = kb_opt.unwrap_or_else(|| crate::guards::in_effect());
            let hook_input = build_hook_input_for_tool_decision(&tool_name, d);
            return crate::route::decide(cfg, kb, &self.home, &hook_input).decision;
        }
        crate::engine::decide_command_at_with_knowledge(
            cfg,
            "bash",
            &d.cmd,
            Some(&self.home),
            Some(&d.cwd),
            Some(&d.cwd),
            kb_opt,
        )
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
        } else if cand.section == "write.scope"
            || cand.section == "run.guards"
            || cand.section.ends_with(".script_constructs")
        {
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

pub(crate) fn extract_tool_name_from_reason(reason: &str) -> Option<String> {
    let first_line = reason.lines().next()?.trim();
    if !first_line.starts_with("vouch stopped on: unmodeled_tool")
        && !first_line.starts_with("vouch stopped on: tool rule")
        && !first_line.starts_with("vouch denied: tool rule")
    {
        return None;
    }
    for line in reason.lines() {
        if let Some(rest) = line.trim().strip_prefix("tool:") {
            let name = rest.trim();
            if !name.is_empty() {
                return Some(name.to_string());
            }
        }
    }
    None
}

pub(crate) fn extract_tool_field_from_reason(reason: &str) -> Option<String> {
    for line in reason.lines() {
        if let Some(rest) = line.trim().strip_prefix("field:") {
            let f = rest.trim();
            if !f.is_empty() {
                return Some(f.to_string());
            }
        }
    }
    None
}

fn extract_json_field_scalar(val: &serde_json::Value, path: &str) -> Option<String> {
    let mut current = val;
    for part in path.split('.') {
        match current {
            serde_json::Value::Object(map) => {
                current = map.get(part)?;
            }
            serde_json::Value::Array(arr) => {
                let idx: usize = part.parse().ok()?;
                current = arr.get(idx)?;
            }
            _ => return None,
        }
    }
    match current {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

pub(crate) fn extract_tool_presets_from_decision(
    cmd: &str,
    reason: &str,
) -> Option<(String, Option<(String, String)>)> {
    let first_line = reason.lines().next()?.trim();
    if first_line.starts_with("vouch stopped on: tool rule (") && first_line.ends_with(')') {
        return None;
    }
    let tool_name = extract_tool_name_from_reason(reason)?;
    let reason_field = extract_tool_field_from_reason(reason);

    let field_val = if let Ok(json_val) = serde_json::from_str::<serde_json::Value>(cmd) {
        if let Some(ref f) = reason_field {
            extract_json_field_scalar(&json_val, f).map(|v| (f.clone(), v))
        } else if let serde_json::Value::Object(map) = &json_val {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            keys.into_iter().find_map(|k| {
                extract_json_field_scalar(&json_val, k)
                    .filter(|v| !v.is_empty())
                    .map(|v| (k.clone(), v))
            })
        } else {
            None
        }
    } else if let Some(f) = reason_field {
        let trimmed = cmd.trim();
        if !trimmed.is_empty() {
            Some((f, trimmed.to_string()))
        } else {
            None
        }
    } else {
        None
    };

    Some((tool_name, field_val))
}

fn insert_dotted_field(
    map: &mut serde_json::Map<String, serde_json::Value>,
    path: &str,
    val: String,
) {
    let parts: Vec<&str> = path.split('.').collect();
    if parts.len() <= 1 {
        map.insert(path.to_string(), serde_json::Value::String(val));
        return;
    }
    let mut root = serde_json::Value::String(val);
    for &part in parts.iter().rev().take(parts.len() - 1) {
        if let Ok(idx) = part.parse::<usize>() {
            let mut arr = vec![serde_json::Value::Null; idx + 1];
            arr[idx] = root;
            root = serde_json::Value::Array(arr);
        } else {
            let mut inner = serde_json::Map::new();
            inner.insert(part.to_string(), root);
            root = serde_json::Value::Object(inner);
        }
    }
    map.insert(parts[0].to_string(), root);
}

fn build_hook_input_for_tool_decision(
    tool_name: &str,
    d: &DecisionItem,
) -> crate::protocol::HookInput {
    let mut tool_input = crate::protocol::ToolInput::default();
    if let Ok(serde_json::Value::Object(map)) = serde_json::from_str::<serde_json::Value>(&d.cmd) {
        if let Some(serde_json::Value::String(c)) = map.get("command") {
            tool_input.command = Some(c.clone());
        }
        if let Some(serde_json::Value::String(fp)) = map.get("file_path") {
            tool_input.file_path = Some(fp.clone());
        }
        if let Some(serde_json::Value::String(u)) = map.get("url") {
            tool_input.url = Some(u.clone());
        }
        tool_input.extra = map;
    } else if let Some(field) = extract_tool_field_from_reason(&d.reason) {
        if !d.cmd.trim().is_empty() {
            let val = d.cmd.trim().to_string();
            match field.as_str() {
                "command" => tool_input.command = Some(val),
                "file_path" => tool_input.file_path = Some(val),
                "url" => tool_input.url = Some(val),
                _ => insert_dotted_field(&mut tool_input.extra, &field, val),
            }
        }
    }
    crate::protocol::HookInput {
        session_id: d.session.clone(),
        cwd: d.cwd.clone(),
        hook_event_name: "PreToolUse".to_string(),
        tool_name: tool_name.to_string(),
        tool_use_id: String::new(),
        tool_input,
        permission_mode: String::new(),
        ..Default::default()
    }
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

pub(crate) fn format_tool_rule_proposed_toml(
    tool_name: &str,
    field: &str,
    when_exact: Option<&str>,
    when_pattern: Option<&str>,
    action: &str,
    reason: &str,
) -> String {
    let mut out = format!(
        "[[tool]]\nmatch = [{tool_name:?}]\nsource = \"TUI interactive rule builder\"\n\n[[tool.rule]]\nfield = {field:?}\n"
    );
    if let Some(exact) = when_exact {
        out.push_str(&format!("when_exact = {exact:?}\n"));
    }
    if let Some(pat) = when_pattern {
        out.push_str(&format!("when_pattern = {pat:?}\n"));
    }
    out.push_str(&format!("action = {action:?}\n"));
    if !reason.trim().is_empty() {
        out.push_str(&format!("reason = {reason:?}\n"));
    }
    out
}

pub(crate) fn format_tool_action_proposed_toml(
    tool_name: &str,
    action: &str,
    source: &str,
) -> String {
    let src = if source.trim().is_empty() {
        "TUI interactive rule builder"
    } else {
        source
    };
    format!("[[tool]]\nmatch = [{tool_name:?}]\nsource = {src:?}\naction = {action:?}\n")
}

pub(crate) fn format_write_scope_proposed_toml(
    programs: &[String],
    only_under: &[String],
) -> String {
    let progs_fmt = programs
        .iter()
        .map(|p| format!("{p:?}"))
        .collect::<Vec<_>>()
        .join(", ");
    let under_fmt = only_under
        .iter()
        .map(|u| format!("{u:?}"))
        .collect::<Vec<_>>()
        .join(", ");
    format!("[[write.scope]]\nprograms = [{progs_fmt}]\nonly_under = [{under_fmt}]\n")
}

pub(crate) fn format_place_guard_proposed_toml(
    under: &[String],
    guard: &str,
    action: &str,
) -> String {
    let under_fmt = under
        .iter()
        .map(|u| format!("{u:?}"))
        .collect::<Vec<_>>()
        .join(", ");
    format!("[[run.guards]]\nunder = [{under_fmt}]\n{guard} = {action:?}\n")
}

pub(crate) fn derive_write_scope_glob(raw_path: &str) -> String {
    let clean = raw_path.trim().replace('\\', "/");
    if clean.ends_with("/**") {
        return clean;
    }
    let trimmed = clean.trim_end_matches('/');
    if let Some((parent, _leaf)) = trimmed.rsplit_once('/') {
        if !parent.is_empty() && parent != "/" && !parent.ends_with(':') {
            return format!("{parent}/**");
        }
    }
    format!("{trimmed}/**")
}

pub(crate) fn extract_write_scope_programs_from_cmd(cmd_src: &str) -> Vec<String> {
    let Ok(scan) = crate::shell::parse(cmd_src) else {
        return Vec::new();
    };
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

    let mut out = Vec::new();
    for occ in &expanded.occurrences {
        let c = &occ.cmd;
        if c.head.is_empty() {
            continue;
        }
        let clang = if occ.lang.is_empty() {
            "bash"
        } else {
            occ.lang.as_str()
        };
        let wt = crate::guards::written_paths_in(kb, c, clang);
        if wt.paths.is_empty() && !wt.run_dir_dest {
            continue;
        }
        let head = crate::guards::base_name(&c.head);
        if head.is_empty() || head.starts_with("python:") {
            continue;
        }
        let has_value_options = kb.program.iter().any(|p| {
            !p.value_options.is_empty()
                && p.match_names.iter().any(|n| n.to_ascii_lowercase() == head)
        });
        if has_value_options {
            if let crate::guards::VerbWord::Word(sub) = crate::guards::verb_of_in(kb, c, clang) {
                let then_word = crate::guards::then_of_in(kb, c, clang);
                let mut matched_three_word = false;
                let mut matched_two_word = false;
                for p in &kb.program {
                    if !p.match_names.iter().any(|n| n.to_ascii_lowercase() == head) {
                        continue;
                    }
                    for sw in &p.sub_write {
                        if sw.subcommand.eq_ignore_ascii_case(&sub) {
                            matched_two_word = true;
                            if !sw.then.is_empty() {
                                if let crate::guards::SecondWord::Word(ref got_then) = then_word {
                                    if sw.then.eq_ignore_ascii_case(got_then) {
                                        let entry3 = format!("{head} {sub} {got_then}");
                                        if !out.contains(&entry3) {
                                            out.push(entry3);
                                        }
                                        matched_three_word = true;
                                    }
                                }
                            }
                        }
                    }
                    if p.subcommands
                        .as_ref()
                        .is_some_and(|subs| subs.iter().any(|s| s.eq_ignore_ascii_case(&sub)))
                        || p.subcommand_options
                            .iter()
                            .any(|so| so.subcommands.iter().any(|s| s.eq_ignore_ascii_case(&sub)))
                    {
                        matched_two_word = true;
                    }
                }
                if (matched_two_word || matched_three_word) && !sub.starts_with('-') && !sub.contains('/') {
                    let entry2 = format!("{head} {sub}");
                    if !out.contains(&entry2) {
                        out.push(entry2);
                    }
                }
            }
        }
        if !out.contains(&head) {
            out.push(head);
        }
    }
    out
}

pub(crate) fn extract_write_scope_presets_from_cmd(
    cmd_src: &str,
    reason: &str,
    path_val: &str,
) -> Vec<super::graph::BuilderPreset> {
    let mut presets = Vec::new();
    let is_scope_stop = reason.contains("vouch stopped on: write scope");
    let scope_glob = derive_write_scope_glob(path_val);
    let prog_entries = extract_write_scope_programs_from_cmd(cmd_src);

    if !is_scope_stop {
        presets.push(super::graph::BuilderPreset::AllowPath {
            path: path_val.to_string(),
        });
    }
    for prog_entry in prog_entries {
        presets.push(super::graph::BuilderPreset::WriteScope {
            programs: vec![prog_entry],
            only_under: vec![scope_glob.clone()],
        });
    }
    if is_scope_stop {
        presets.push(super::graph::BuilderPreset::AllowPath {
            path: path_val.to_string(),
        });
    }
    presets
}

pub(crate) fn extract_place_guard_presets_from_decision(
    cwd: &str,
    reason: &str,
    guard_name: &str,
) -> Vec<super::graph::BuilderPreset> {
    if extract_tool_name_from_reason(reason).is_some()
        || reason.contains("tool rule (")
        || cwd.trim().is_empty()
    {
        return Vec::new();
    }
    let known_list = crate::guards::known_guards();
    let is_known = known_list.iter().any(|k| k == guard_name)
        || crate::guards::KNOWN_GUARDS.contains(&guard_name);
    if !is_known {
        return Vec::new();
    }
    let cwd_clean = cwd.trim().replace('\\', "/");
    let cwd_stem = cwd_clean.trim_end_matches('/');
    if cwd_stem.is_empty() {
        return Vec::new();
    }
    vec![
        super::graph::BuilderPreset::PlaceScopedGuard {
            under: vec![format!("{cwd_stem}/**")],
            guard: guard_name.to_string(),
            action: "allow".to_string(),
        },
        super::graph::BuilderPreset::PlaceScopedGuard {
            under: vec![cwd_stem.to_string()],
            guard: guard_name.to_string(),
            action: "allow".to_string(),
        },
    ]
}

fn synthesize_granular_candidates(records: &[Record]) -> Vec<ReviewCandidate> {
    type SuggestionTally = (usize, usize, usize, std::collections::HashSet<String>, String);
    let mut out = Vec::new();
    let mut exact_counts: std::collections::HashMap<(String, Vec<String>), SuggestionTally> =
        std::collections::HashMap::new();
    let mut script_counts: std::collections::HashMap<
        (String, String, String, String),
        SuggestionTally,
    > = std::collections::HashMap::new();
    let mut tool_rule_counts: std::collections::HashMap<
        (String, String, String),
        SuggestionTally,
    > = std::collections::HashMap::new();
    let mut tool_action_counts: std::collections::HashMap<String, SuggestionTally> =
        std::collections::HashMap::new();
    let mut write_scope_counts: std::collections::HashMap<(String, String), SuggestionTally> =
        std::collections::HashMap::new();
    let mut place_guard_counts: std::collections::HashMap<(String, String), SuggestionTally> =
        std::collections::HashMap::new();

    for r in records {
        if r.verdict != "ask" || r.mode != "live" || r.measurement {
            continue;
        }
        if r.reason.contains("path outside every allowed area")
            || r.reason.contains("vouch stopped on: write scope")
        {
            if let Some(path) = extract_unpermitted_path(&r.reason) {
                let scope_glob = derive_write_scope_glob(&path);
                if let Some(first_prog) = extract_write_scope_programs_from_cmd(&r.cmd).into_iter().next() {
                    let entry = write_scope_counts
                        .entry((first_prog, scope_glob))
                        .or_insert_with(|| (0, 0, 0, std::collections::HashSet::new(), r.cmd.clone()));
                    match r.outcome {
                        Outcome::Executed => entry.0 += 1,
                        Outcome::Denied => entry.1 += 1,
                        _ => entry.2 += 1,
                    }
                    entry.3.insert(r.session.clone());
                }
            }
        }
        if let Some(first_line) = r.reason.lines().next() {
            if let Some(guard_name) = first_line
                .trim()
                .strip_prefix("vouch stopped on:")
                .and_then(|s| s.trim().strip_suffix("(guard)"))
                .map(|s| s.trim())
            {
                let presets = extract_place_guard_presets_from_decision(&r.cwd, &r.reason, guard_name);
                if let Some(super::graph::BuilderPreset::PlaceScopedGuard { under, guard, .. }) =
                    presets.into_iter().next()
                {
                    if let Some(under_glob) = under.into_iter().next() {
                        let entry = place_guard_counts
                            .entry((guard, under_glob))
                            .or_insert_with(|| (0, 0, 0, std::collections::HashSet::new(), r.cmd.clone()));
                        match r.outcome {
                            Outcome::Executed => entry.0 += 1,
                            Outcome::Denied => entry.1 += 1,
                            _ => entry.2 += 1,
                        }
                        entry.3.insert(r.session.clone());
                    }
                }
            }
        }
        if let Some((tool_name, field_val)) = extract_tool_presets_from_decision(&r.cmd, &r.reason) {
            if let Some((field, val)) = field_val {
                let entry = tool_rule_counts
                    .entry((tool_name.clone(), field, val))
                    .or_insert_with(|| (0, 0, 0, std::collections::HashSet::new(), r.cmd.clone()));
                match r.outcome {
                    Outcome::Executed => entry.0 += 1,
                    Outcome::Denied => entry.1 += 1,
                    _ => entry.2 += 1,
                }
                entry.3.insert(r.session.clone());
            }
            let act_entry = tool_action_counts
                .entry(tool_name)
                .or_insert_with(|| (0, 0, 0, std::collections::HashSet::new(), r.cmd.clone()));
            match r.outcome {
                Outcome::Executed => act_entry.0 += 1,
                Outcome::Denied => act_entry.1 += 1,
                _ => act_entry.2 += 1,
            }
            act_entry.3.insert(r.session.clone());
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

    for ((tool_name, field, val), (app, den, unk, sess, example)) in tool_rule_counts {
        if app > 0 {
            out.push(ReviewCandidate {
                name: format!("tool.rule: {tool_name} ({field} == {val:?})"),
                section: "tool.rule".to_string(),
                target_file: TargetFile::MyKnowledge,
                proposed_toml: format_tool_rule_proposed_toml(
                    &tool_name,
                    &field,
                    Some(&val),
                    None,
                    "allow",
                    "TUI interactive rule builder",
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

    for (tool_name, (app, den, unk, sess, example)) in tool_action_counts {
        if app > 0 {
            out.push(ReviewCandidate {
                name: format!("tool: {tool_name} (allow)"),
                section: "tool.action".to_string(),
                target_file: TargetFile::MyKnowledge,
                proposed_toml: format_tool_action_proposed_toml(
                    &tool_name,
                    "allow",
                    "TUI interactive rule builder",
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

    for ((prog_entry, scope_glob), (app, den, unk, sess, example)) in write_scope_counts {
        if app > 0 {
            let programs = vec![prog_entry.clone()];
            let only_under = vec![scope_glob.clone()];
            out.push(ReviewCandidate {
                name: format!("write.scope: {prog_entry} -> {scope_glob}"),
                section: "write.scope".to_string(),
                target_file: TargetFile::Config,
                proposed_toml: format_write_scope_proposed_toml(&programs, &only_under),
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

    for ((guard_name, under_glob), (app, den, unk, sess, example)) in place_guard_counts {
        if app > 0 {
            let under = vec![under_glob.clone()];
            out.push(ReviewCandidate {
                name: format!("run.guards: {guard_name} under {under_glob}"),
                section: "run.guards".to_string(),
                target_file: TargetFile::Config,
                proposed_toml: format_place_guard_proposed_toml(&under, &guard_name, "allow"),
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

fn apply_write_scope_candidate_to_toml(
    current_content: &str,
    cand: &ReviewCandidate,
) -> Result<(String, String), String> {
    let mut doc: toml_edit::DocumentMut = current_content
        .parse()
        .map_err(|e| format!("Invalid TOML: {e}"))?;
    let prop_doc: toml_edit::DocumentMut = cand
        .proposed_toml
        .parse()
        .map_err(|e| format!("Invalid proposed write.scope TOML: {e}"))?;

    let prop_aot = prop_doc
        .get("write")
        .and_then(|w| w.get("scope"))
        .and_then(|s| s.as_array_of_tables())
        .and_then(|aot| aot.iter().next())
        .ok_or_else(|| "Proposed TOML missing [[write.scope]] table".to_string())?;

    let prop_progs: Vec<String> = prop_aot
        .get("programs")
        .and_then(|p| p.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    let prop_under: Vec<String> = prop_aot
        .get("only_under")
        .and_then(|p| p.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    if prop_progs.is_empty() || prop_under.is_empty() {
        return Err("Proposed [[write.scope]] requires non-empty programs and only_under".to_string());
    }

    let write_item = doc
        .entry("write")
        .or_insert(toml_edit::Item::Table(toml_edit::Table::new()));
    let write_table = write_item
        .as_table_like_mut()
        .ok_or_else(|| "write is not a table".to_string())?;
    let scope_item = write_table
        .entry("scope")
        .or_insert(toml_edit::Item::ArrayOfTables(toml_edit::ArrayOfTables::new()));
    let aot = scope_item
        .as_array_of_tables_mut()
        .ok_or_else(|| "write.scope is not an array of tables".to_string())?;

    let fold_prog = |s: &str| {
        s.split_whitespace()
            .map(str::to_lowercase)
            .collect::<Vec<_>>()
            .join(" ")
    };
    let prop_progs_folded: Vec<String> = prop_progs.iter().map(|p| fold_prog(p)).collect();

    let mut merged = false;
    for existing in aot.iter_mut() {
        let existing_progs_folded: Vec<String> = existing
            .get("programs")
            .and_then(|p| p.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(fold_prog))
                    .collect()
            })
            .unwrap_or_default();
        if existing_progs_folded == prop_progs_folded {
            let under_item = existing.entry("only_under").or_insert(toml_edit::Item::Value(
                toml_edit::Value::Array(toml_edit::Array::new()),
            ));
            if let Some(arr) = under_item.as_array_mut() {
                for u in &prop_under {
                    if !arr.iter().any(|v| v.as_str() == Some(u.as_str())) {
                        arr.push(u.as_str());
                    }
                }
                merged = true;
                break;
            }
        }
    }
    if !merged {
        aot.push(prop_aot.clone());
    }

    let summary = format!(
        "[[write.scope]] programs = {prop_progs:?} only_under = {prop_under:?}"
    );
    Ok((doc.to_string(), summary))
}

fn apply_place_guard_candidate_to_toml(
    current_content: &str,
    cand: &ReviewCandidate,
) -> Result<(String, String), String> {
    let mut doc: toml_edit::DocumentMut = current_content
        .parse()
        .map_err(|e| format!("Invalid TOML: {e}"))?;
    let prop_doc: toml_edit::DocumentMut = cand
        .proposed_toml
        .parse()
        .map_err(|e| format!("Invalid proposed run.guards TOML: {e}"))?;

    let prop_aot = prop_doc
        .get("run")
        .and_then(|r| r.get("guards"))
        .and_then(|g| g.as_array_of_tables())
        .and_then(|aot| aot.iter().next())
        .ok_or_else(|| "Proposed TOML missing [[run.guards]] table".to_string())?;

    let prop_under: Vec<String> = prop_aot
        .get("under")
        .and_then(|u| u.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    let mut guard_key = String::new();
    let mut action_val = "allow".to_string();
    for (k, v) in prop_aot.iter() {
        if k != "under" {
            guard_key = k.to_string();
            if let Some(s) = v.as_str() {
                action_val = s.to_string();
            }
            break;
        }
    }
    if prop_under.is_empty() || guard_key.is_empty() {
        return Err("Proposed [[run.guards]] requires non-empty under and guard action".to_string());
    }

    let run_item = doc
        .entry("run")
        .or_insert(toml_edit::Item::Table(toml_edit::Table::new()));
    let run_table = run_item
        .as_table_like_mut()
        .ok_or_else(|| "run is not a table".to_string())?;
    let guards_item = run_table
        .entry("guards")
        .or_insert(toml_edit::Item::ArrayOfTables(toml_edit::ArrayOfTables::new()));
    let aot = guards_item
        .as_array_of_tables_mut()
        .ok_or_else(|| "run.guards is not an array of tables".to_string())?;

    let mut merged = false;
    for existing in aot.iter_mut() {
        let existing_under: Vec<String> = existing
            .get("under")
            .and_then(|u| u.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        if existing_under == prop_under {
            existing.insert(&guard_key, toml_edit::value(action_val.as_str()));
            merged = true;
            break;
        }
    }
    if !merged {
        aot.push(prop_aot.clone());
    }

    let summary = format!(
        "[[run.guards]] under = {prop_under:?} {guard_key} = {action_val:?}"
    );
    Ok((doc.to_string(), summary))
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

fn apply_tool_candidate_to_my_knowledge_toml(
    current_content: &str,
    cand: &ReviewCandidate,
) -> Result<(String, String), String> {
    let mut doc: toml_edit::DocumentMut = current_content
        .parse()
        .map_err(|e| format!("Invalid my-knowledge.toml: {e}"))?;
    let prop_doc: toml_edit::DocumentMut = cand
        .proposed_toml
        .parse()
        .map_err(|e| format!("Invalid proposed tool TOML: {e}"))?;

    let prop_table = prop_doc
        .get("tool")
        .and_then(|p| p.as_array_of_tables())
        .and_then(|aot| aot.iter().next())
        .ok_or_else(|| "Proposed TOML missing [[tool]] table".to_string())?;

    let tool_name = prop_table
        .get("match")
        .and_then(|m| m.as_array())
        .and_then(|a| a.get(0))
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Proposed [[tool]] missing match name".to_string())?;

    let tool_item = doc
        .entry("tool")
        .or_insert(toml_edit::Item::ArrayOfTables(toml_edit::ArrayOfTables::new()));
    let aot = tool_item
        .as_array_of_tables_mut()
        .ok_or_else(|| "tool in my-knowledge.toml is not an array of tables".to_string())?;

    if cand.section == "tool.action" {
        let action_val = prop_table
            .get("action")
            .and_then(|v| v.as_str())
            .unwrap_or("allow");
        let source_val = prop_table
            .get("source")
            .and_then(|v| v.as_str())
            .unwrap_or("TUI interactive rule builder");

        let mut merged = false;
        for existing in aot.iter_mut() {
            let matches_tool = existing
                .get("match")
                .and_then(|m| m.as_array())
                .is_some_and(|a| {
                    a.len() == 1
                        && a.get(0)
                            .and_then(|v| v.as_str())
                            .is_some_and(|s| s == tool_name)
                });
            if matches_tool {
                existing.insert("action", toml_edit::value(action_val));
                if existing.get("source").is_none() {
                    existing.insert("source", toml_edit::value(source_val));
                }
                if action_val == "allow" {
                    if let Some(rule_aot) = existing
                        .get_mut("rule")
                        .and_then(|r| r.as_array_of_tables_mut())
                    {
                        let mut kept = toml_edit::ArrayOfTables::new();
                        for r in rule_aot.iter() {
                            let is_non_guard_ask = r
                                .get("action")
                                .and_then(|a| a.as_str())
                                .is_some_and(|a| a == "ask")
                                && r.get("guard").is_none();
                            if !is_non_guard_ask {
                                kept.push(r.clone());
                            }
                        }
                        if kept.is_empty() {
                            existing.remove("rule");
                        } else {
                            *rule_aot = kept;
                        }
                    }
                }
                merged = true;
                break;
            }
        }
        if !merged {
            aot.push(prop_table.clone());
        }
        let summary = format!("[[tool]] match = [{tool_name:?}] action = {action_val:?}");
        return Ok((doc.to_string(), summary));
    }

    let prop_rule = prop_table
        .get("rule")
        .and_then(|r| r.as_array_of_tables())
        .and_then(|raot| raot.iter().next())
        .ok_or_else(|| "Proposed [[tool]] missing [[tool.rule]] table".to_string())?;

    let field_name = prop_rule
        .get("field")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let when_exact = prop_rule.get("when_exact").and_then(|v| v.as_str());
    let when_pattern = prop_rule.get("when_pattern").and_then(|v| v.as_str());
    let action_val = prop_rule
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or("allow");

    let mut merged = false;
    for existing in aot.iter_mut() {
        let matches_tool = existing
            .get("match")
            .and_then(|m| m.as_array())
            .is_some_and(|a| {
                a.len() == 1
                    && a.get(0)
                        .and_then(|v| v.as_str())
                        .is_some_and(|s| s == tool_name)
            });
        if matches_tool {
            let rule_item = existing
                .entry("rule")
                .or_insert(toml_edit::Item::ArrayOfTables(toml_edit::ArrayOfTables::new()));
            let rule_aot = rule_item
                .as_array_of_tables_mut()
                .ok_or_else(|| "tool.rule in my-knowledge.toml is not an array of tables".to_string())?;

            let mut rule_updated = false;
            for r in rule_aot.iter_mut() {
                let same_field = r.get("field").and_then(|v| v.as_str()) == Some(field_name);
                let same_exact = r.get("when_exact").and_then(|v| v.as_str()) == when_exact;
                let same_pat = r.get("when_pattern").and_then(|v| v.as_str()) == when_pattern;
                if same_field && same_exact && same_pat {
                    r.insert("action", toml_edit::value(action_val));
                    if let Some(reason_v) = prop_rule.get("reason") {
                        r.insert("reason", reason_v.clone());
                    }
                    rule_updated = true;
                    break;
                }
            }
            if !rule_updated {
                rule_aot.push(prop_rule.clone());
            }
            merged = true;
            break;
        }
    }

    if !merged {
        aot.push(prop_table.clone());
    }

    let pred_desc = if let Some(ex) = when_exact {
        format!("{field_name} == {ex:?}")
    } else if let Some(pat) = when_pattern {
        format!("{field_name} ~= {pat:?}")
    } else {
        field_name.to_string()
    };
    let summary = format!(
        "[[tool.rule]] {tool_name} ({pred_desc}) -> {action_val:?}"
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
