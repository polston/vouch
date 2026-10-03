//! Decision Query Engine and Rule Candidate Generator for Vouch TUI.

use crate::journal::Record;
use crate::outcome::Outcome;
use crate::review::{self, Candidate};

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
}

impl TuiEngine {
    pub fn load(home: &str) -> Self {
        let state_dir = crate::journal::state_dir();
        let records = crate::journal::all(&state_dir);
        Self::from_records(home, &records)
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
        }
    }

    /// Applies an approved candidate rule to configuration files.
    pub fn apply_candidate(&self, cand: &ReviewCandidate) -> Result<String, String> {
        if !cand.proposable {
            return Err(cand.blocked_reason.clone().unwrap_or_else(|| "Candidate is not proposable".to_string()));
        }

        let config_path = crate::knowledge::config_dir(&self.home).join("config.toml");
        let content = std::fs::read_to_string(&config_path).unwrap_or_default();

        if cand.section == "write.allow_paths" {
            // Append path to allow_paths list in config.toml
            let path_to_add = cand.name.strip_prefix("path: ").unwrap_or(&cand.name);
            let mut doc: toml_edit::DocumentMut = content.parse().map_err(|e| format!("Invalid TOML: {e}"))?;

            let write_table = doc.entry("write").or_insert(toml_edit::Item::Table(toml_edit::Table::new()));
            let write_table = write_table.as_table_like_mut().ok_or_else(|| "write is not a table")?;

            let allow_paths = write_table.entry("allow_paths").or_insert(toml_edit::Item::Value(toml_edit::Value::Array(toml_edit::Array::new())));
            if let Some(arr) = allow_paths.as_array_mut() {
                if !arr.iter().any(|v| v.as_str() == Some(path_to_add)) {
                    arr.push(path_to_add);
                }
            }
            std::fs::write(&config_path, doc.to_string()).map_err(|e| format!("Failed to write config: {e}"))?;
            Ok(format!("Added {:?} to write.allow_paths in config.toml", path_to_add))
        } else {
            // Construct rule candidate
            let c = Candidate {
                name: cand.name.clone(),
                section: cand.section.clone(),
                approved: cand.approved,
                denied: cand.denied,
                unknown: cand.unknown,
                sessions: cand.sessions,
                proposable: true,
                blocked: None,
                example: cand.example_cmd.clone(),
            };
            let updated = review::apply(&content, &c)?;
            std::fs::write(&config_path, updated).map_err(|e| format!("Failed to write config: {e}"))?;
            Ok(format!("Added [{}] {} = \"allow\" to config.toml", cand.section, cand.name))
        }
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
