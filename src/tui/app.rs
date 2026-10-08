//! Interactive Terminal UI Application State Machine for Vouch.

use super::backend::{KeyCode, TerminalBackend, TerminalEvent};
use super::engine::TuiEngine;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewTab {
    Candidates,
    Decisions,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppStatus {
    Running,
    Exit,
}

pub struct TuiApp {
    pub engine: TuiEngine,
    pub active_tab: ViewTab,
    pub selected_idx: usize,
    pub status_message: String,
    pub show_preview: bool,
    pub search_mode: bool,
    pub search_query: String,
    pub search_filter_active: bool,
}

impl TuiApp {
    pub fn new(engine: TuiEngine) -> Self {
        Self {
            engine,
            active_tab: ViewTab::Candidates,
            selected_idx: 0,
            status_message: "Press [Tab] to switch views, [/] to search, [a] to accept rule, [p] to preview TOML, [q] to quit".to_string(),
            show_preview: false,
            search_mode: false,
            search_query: String::new(),
            search_filter_active: false,
        }
    }

    pub fn matching_decision_indices(&self) -> Vec<usize> {
        if !self.search_filter_active && !self.search_mode {
            return (0..self.engine.decisions.len()).collect();
        }
        if self.search_query.trim().is_empty() {
            return (0..self.engine.decisions.len()).collect();
        }

        let regex_opt = regex::Regex::new(&format!("(?i){}", self.search_query)).ok();
        let query_lower = self.search_query.to_lowercase();

        self.engine
            .decisions
            .iter()
            .enumerate()
            .filter_map(|(idx, d)| {
                let matches = if let Some(ref re) = regex_opt {
                    re.is_match(&d.cmd) || re.is_match(&d.verdict) || re.is_match(&d.reason)
                } else {
                    d.cmd.to_lowercase().contains(&query_lower)
                        || d.verdict.to_lowercase().contains(&query_lower)
                        || d.reason.to_lowercase().contains(&query_lower)
                };
                if matches {
                    Some(idx)
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn handle_event(&mut self, event: TerminalEvent) -> AppStatus {
        if self.search_mode {
            match event {
                TerminalEvent::Key(KeyCode::Escape) => {
                    self.search_mode = false;
                    self.search_filter_active = false;
                    self.search_query.clear();
                    self.selected_idx = 0;
                    self.status_message = "Search cancelled.".to_string();
                }
                TerminalEvent::Key(KeyCode::Enter) => {
                    self.search_mode = false;
                    self.search_filter_active = !self.search_query.is_empty();
                    let count = self.matching_decision_indices().len();
                    self.selected_idx = 0;
                    self.status_message = format!("Filter active: \"{}\" ({} match(es))", self.search_query, count);
                }
                TerminalEvent::Key(KeyCode::Backspace) => {
                    self.search_query.pop();
                    self.selected_idx = 0;
                }
                TerminalEvent::Key(KeyCode::Char(c)) => {
                    self.search_query.push(c);
                    self.selected_idx = 0;
                }
                _ => {}
            }
            return AppStatus::Running;
        }

        match event {
            TerminalEvent::Key(KeyCode::Char('q')) => {
                return AppStatus::Exit;
            }
            TerminalEvent::Key(KeyCode::Escape) => {
                if self.search_filter_active {
                    self.search_filter_active = false;
                    self.search_query.clear();
                    self.selected_idx = 0;
                    self.status_message = "Search filter cleared.".to_string();
                } else {
                    return AppStatus::Exit;
                }
            }
            TerminalEvent::Key(KeyCode::Char('/')) => {
                self.active_tab = ViewTab::Decisions;
                self.search_mode = true;
                self.selected_idx = 0;
                self.status_message = "Search mode: enter regex filter, [Enter] apply, [Esc] cancel".to_string();
            }
            TerminalEvent::Key(KeyCode::Char('n')) if self.search_filter_active => {
                let matches = self.matching_decision_indices();
                if !matches.is_empty() {
                    self.selected_idx = (self.selected_idx + 1) % matches.len();
                }
            }
            TerminalEvent::Key(KeyCode::Char('N')) if self.search_filter_active => {
                let matches = self.matching_decision_indices();
                if !matches.is_empty() {
                    if self.selected_idx == 0 {
                        self.selected_idx = matches.len() - 1;
                    } else {
                        self.selected_idx -= 1;
                    }
                }
            }
            TerminalEvent::Key(KeyCode::Tab) => {
                self.active_tab = match self.active_tab {
                    ViewTab::Candidates => ViewTab::Decisions,
                    ViewTab::Decisions => ViewTab::Candidates,
                };
                self.selected_idx = 0;
                self.show_preview = false;
            }
            TerminalEvent::Key(KeyCode::Char('j')) | TerminalEvent::Key(KeyCode::Down) => {
                let max_len = self.current_list_len();
                if max_len > 0 && self.selected_idx + 1 < max_len {
                    self.selected_idx += 1;
                }
            }
            TerminalEvent::Key(KeyCode::Char('k')) | TerminalEvent::Key(KeyCode::Up) => {
                if self.selected_idx > 0 {
                    self.selected_idx -= 1;
                }
            }
            TerminalEvent::Key(KeyCode::Char('p')) | TerminalEvent::Key(KeyCode::Enter) => {
                if self.active_tab == ViewTab::Candidates {
                    self.show_preview = !self.show_preview;
                }
            }
            TerminalEvent::Key(KeyCode::Char('a')) => {
                if self.active_tab == ViewTab::Candidates {
                    self.apply_current_candidate();
                }
            }
            _ => {}
        }
        AppStatus::Running
    }

    fn current_list_len(&self) -> usize {
        match self.active_tab {
            ViewTab::Candidates => self.engine.candidates.len(),
            ViewTab::Decisions => {
                if self.search_filter_active || self.search_mode {
                    self.matching_decision_indices().len()
                } else {
                    self.engine.decisions.len()
                }
            }
        }
    }

    fn apply_current_candidate(&mut self) {
        if self.engine.candidates.is_empty() {
            self.status_message = "No candidates available to accept.".to_string();
            return;
        }
        let cand = &self.engine.candidates[self.selected_idx];
        match self.engine.apply_candidate(cand) {
            Ok(msg) => {
                self.status_message = format!("✓ {}", msg);
                // Mark candidate as accepted / remove from proposable
                self.engine.candidates.remove(self.selected_idx);
                if self.selected_idx >= self.engine.candidates.len() && self.selected_idx > 0 {
                    self.selected_idx -= 1;
                }
            }
            Err(err) => {
                self.status_message = format!("✗ Refused: {}", err);
            }
        }
    }

    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str("================================================================================\n");
        out.push_str(" vouch interactive review & policy tui\n");
        out.push_str("================================================================================\n");

        let cand_tab = if self.active_tab == ViewTab::Candidates { "[ 1. Rule Candidates * ]" } else { "  1. Rule Candidates  " };
        let dec_tab = if self.active_tab == ViewTab::Decisions { "[ 2. Recent Decisions * ]" } else { "  2. Recent Decisions  " };
        out.push_str(&format!("Tabs: {}  {}\n", cand_tab, dec_tab));
        out.push_str("--------------------------------------------------------------------------------\n");

        match self.active_tab {
            ViewTab::Candidates => {
                if self.engine.candidates.is_empty() {
                    out.push_str("No rule candidates available from recent journal records.\n");
                } else {
                    out.push_str("  #   Status     Approved  Section / Name\n");
                    for (i, c) in self.engine.candidates.iter().take(15).enumerate() {
                        let cursor = if i == self.selected_idx { ">" } else { " " };
                        let status = if c.proposable { "Proposable" } else { "Guarded   " };
                        out.push_str(&format!(
                            "{} {:2}. [{}]   {:4}x   {} :: {}\n",
                            cursor, i + 1, status, c.approved, c.section, c.name
                        ));
                    }

                    if let Some(selected) = self.engine.candidates.get(self.selected_idx) {
                        out.push_str("\n--- Selected Candidate Details ---\n");
                        out.push_str(&format!("Example Command: {}\n", selected.example_cmd));
                        if let Some(ref blocked) = selected.blocked_reason {
                            out.push_str(&format!("Blocked Reason: {}\n", blocked));
                        }
                        if self.show_preview {
                            out.push_str("\n--- Proposed TOML Delta ---\n");
                            out.push_str(&selected.proposed_toml);
                        }
                    }
                }
            }
            ViewTab::Decisions => {
                let match_indices = self.matching_decision_indices();
                if match_indices.is_empty() {
                    if self.search_filter_active || self.search_mode {
                        out.push_str(&format!("No decisions matching filter \"{}\".\n", self.search_query));
                    } else {
                        out.push_str("No recent decisions found in journal.\n");
                    }
                } else {
                    if self.search_filter_active || self.search_mode {
                        out.push_str(&format!(
                            "  [Filter: \"{}\" (match {}/{})]\n",
                            self.search_query,
                            if match_indices.is_empty() { 0 } else { self.selected_idx + 1 },
                            match_indices.len()
                        ));
                    }
                    out.push_str("  #   Verdict  Outcome     Command\n");
                    for (display_idx, &real_idx) in match_indices.iter().take(15).enumerate() {
                        let d = &self.engine.decisions[real_idx];
                        let cursor = if display_idx == self.selected_idx { ">" } else { " " };
                        let short_cmd: String = d.cmd.chars().take(45).collect();
                        out.push_str(&format!(
                            "{} {:2}. {:7}  {:10}  {}\n",
                            cursor, display_idx + 1, d.verdict.to_uppercase(), d.outcome, short_cmd
                        ));
                    }
                    if let Some(&selected_real_idx) = match_indices.get(self.selected_idx) {
                        if let Some(selected) = self.engine.decisions.get(selected_real_idx) {
                            out.push_str("\n--- Decision Detail ---\n");
                            out.push_str(&format!("Full Command: {}\n", selected.cmd));
                            out.push_str(&format!("Verdict: {} ({})\n", selected.verdict, selected.outcome));
                            out.push_str(&format!("Reason:\n  {}\n", selected.reason.replace('\n', "\n  ")));
                        }
                    }
                }
            }
        }

        out.push_str("--------------------------------------------------------------------------------\n");
        if self.search_mode {
            out.push_str(&format!("Search: {}_\n", self.search_query));
            out.push_str("[Enter]: Apply Filter | [Esc]: Cancel Search\n");
        } else if self.search_filter_active {
            out.push_str(&format!("Status: Filtered on \"{}\" ({}/{} matches)\n", self.search_query, self.selected_idx + 1, self.matching_decision_indices().len()));
            out.push_str("[j/k]: Nav | [n/N]: Next/Prev Match | [Esc]: Clear Filter | [Tab]: View | [q]: Quit\n");
        } else {
            out.push_str(&format!("Status: {}\n", self.status_message));
            out.push_str("[j/k]: Nav | [/]: Search | [Tab]: View | [a]: Accept Rule | [p]: Preview TOML | [q]: Quit\n");
        }
        out
    }

    pub fn run_loop<B: TerminalBackend>(&mut self, mut backend: B) -> Result<(), String> {
        backend.enter_raw_mode().map_err(|e| e.to_string())?;

        loop {
            let new_events = self.engine.poll_live_events();
            if new_events > 0 && !self.search_mode && !self.search_filter_active {
                self.status_message = format!("Live stream: ingested {new_events} new decision(s)");
            }

            let frame = self.render();
            let _ = backend.write_str("\x1b[2J\x1b[H"); // clear screen & home
            let _ = backend.write_str(&frame);
            let _ = backend.flush();

            match backend.read_event() {
                Ok(Some(event)) => {
                    if self.handle_event(event) == AppStatus::Exit {
                        break;
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    let _ = backend.exit_raw_mode();
                    return Err(format!("I/O Error: {e}"));
                }
            }
        }

        backend.exit_raw_mode().map_err(|e| e.to_string())?;
        Ok(())
    }
}
