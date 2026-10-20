//! Interactive Terminal UI Application State Machine for Vouch.

use super::backend::{KeyCode, TerminalBackend, TerminalEvent};
use super::engine::TuiEngine;
use super::graph::PolicyGraph;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewTab {
    Candidates,
    Decisions,
    Visualizer,
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
    pub policy_graph: PolicyGraph,
    pub visualizer_decision_idx: usize,
}

impl TuiApp {
    pub fn new(engine: TuiEngine) -> Self {
        let policy_graph = engine
            .decisions
            .first()
            .map(PolicyGraph::from_decision)
            .unwrap_or_else(PolicyGraph::empty);
        Self {
            engine,
            active_tab: ViewTab::Candidates,
            selected_idx: 0,
            status_message: "Press [Tab] to switch views, [v] for Policy Graph, [/] to search, [a] to accept rule, [p] to preview TOML, [q] to quit".to_string(),
            show_preview: false,
            search_mode: false,
            search_query: String::new(),
            search_filter_active: false,
            policy_graph,
            visualizer_decision_idx: 0,
        }
    }

    pub fn refresh_visualizer_graph(&mut self) {
        if let Some(decision) = self.engine.decisions.get(self.visualizer_decision_idx) {
            self.policy_graph = PolicyGraph::from_decision(decision);
        } else {
            self.policy_graph = PolicyGraph::empty();
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
            TerminalEvent::Key(KeyCode::Char('v')) => {
                if self.active_tab == ViewTab::Visualizer {
                    self.active_tab = ViewTab::Candidates;
                } else {
                    if self.active_tab == ViewTab::Decisions {
                        let matches = self.matching_decision_indices();
                        if let Some(&real_idx) = matches.get(self.selected_idx) {
                            self.visualizer_decision_idx = real_idx;
                        }
                    }
                    self.refresh_visualizer_graph();
                    self.active_tab = ViewTab::Visualizer;
                }
                self.selected_idx = 0;
                self.show_preview = false;
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
                    ViewTab::Visualizer => ViewTab::Candidates,
                };
                self.selected_idx = 0;
                self.show_preview = false;
            }
            TerminalEvent::Key(KeyCode::Char('j')) | TerminalEvent::Key(KeyCode::Down) => {
                if self.active_tab == ViewTab::Visualizer {
                    self.policy_graph.move_selection_down();
                    self.selected_idx = self.policy_graph.selected_visible_idx;
                } else {
                    let max_len = self.current_list_len();
                    if max_len > 0 && self.selected_idx + 1 < max_len {
                        self.selected_idx += 1;
                    }
                }
            }
            TerminalEvent::Key(KeyCode::Char('k')) | TerminalEvent::Key(KeyCode::Up) => {
                if self.active_tab == ViewTab::Visualizer {
                    self.policy_graph.move_selection_up();
                    self.selected_idx = self.policy_graph.selected_visible_idx;
                } else if self.selected_idx > 0 {
                    self.selected_idx -= 1;
                }
            }
            TerminalEvent::Key(KeyCode::Char('l')) | TerminalEvent::Key(KeyCode::Right) => {
                if self.active_tab == ViewTab::Visualizer
                    && self.visualizer_decision_idx + 1 < self.engine.decisions.len()
                {
                    self.visualizer_decision_idx += 1;
                    self.refresh_visualizer_graph();
                    self.selected_idx = 0;
                }
            }
            TerminalEvent::Key(KeyCode::Char('h')) | TerminalEvent::Key(KeyCode::Left) => {
                if self.active_tab == ViewTab::Visualizer && self.visualizer_decision_idx > 0 {
                    self.visualizer_decision_idx -= 1;
                    self.refresh_visualizer_graph();
                    self.selected_idx = 0;
                }
            }
            TerminalEvent::Key(KeyCode::Char(' ')) => {
                if self.active_tab == ViewTab::Visualizer {
                    self.policy_graph.toggle_selected_collapse();
                    self.selected_idx = self.policy_graph.selected_visible_idx;
                }
            }
            TerminalEvent::Key(KeyCode::Char('p')) => {
                if self.active_tab == ViewTab::Candidates || self.active_tab == ViewTab::Visualizer {
                    self.show_preview = !self.show_preview;
                }
            }
            TerminalEvent::Key(KeyCode::Enter) => {
                if self.active_tab == ViewTab::Candidates {
                    self.show_preview = !self.show_preview;
                } else if self.active_tab == ViewTab::Visualizer {
                    self.policy_graph.toggle_selected_collapse();
                    self.selected_idx = self.policy_graph.selected_visible_idx;
                }
            }
            TerminalEvent::Key(KeyCode::Char('a')) => {
                if self.active_tab == ViewTab::Candidates {
                    self.apply_current_candidate();
                } else if self.active_tab == ViewTab::Visualizer {
                    self.apply_selected_visualizer_node();
                }
            }
            TerminalEvent::Key(KeyCode::Char('d')) => {
                if self.active_tab == ViewTab::Visualizer {
                    self.simulate_selected_visualizer_node();
                }
            }
            TerminalEvent::Key(KeyCode::Char('D')) => {
                if self.active_tab == ViewTab::Visualizer {
                    self.stage_and_simulate_visualizer_node();
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
            ViewTab::Visualizer => self.policy_graph.visible_entries().len(),
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

    fn simulate_selected_visualizer_node(&mut self) {
        let Some(node) = self.policy_graph.selected_node().cloned() else {
            self.status_message = "No policy graph node selected.".to_string();
            return;
        };
        if node.kind == super::graph::NodeKind::GuardHit {
            self.policy_graph.simulation = None;
            self.status_message = "✗ Refused simulation: Guard rules describe operator effects and cannot be simulated as allow-list amendments.".to_string();
            return;
        }
        if self
            .policy_graph
            .simulation
            .as_ref()
            .is_some_and(|s| s.target_node_id == node.id)
        {
            self.policy_graph.simulation = None;
            self.status_message = "Cleared policy amendment simulation.".to_string();
            return;
        }
        let Some(decision) = self.engine.decisions.get(self.visualizer_decision_idx) else {
            self.status_message = "No decision selected for simulation.".to_string();
            return;
        };
        match node.to_review_candidate(&decision.cmd) {
            Ok(cand) => match self.engine.simulate_candidate(decision, &cand, node.id) {
                Ok(sim) => {
                    self.status_message = format!(
                        "Simulated amendment ({}): {} -> {}",
                        sim.amendment_summary, sim.before_verdict, sim.after_verdict
                    );
                    self.policy_graph.simulation = Some(sim);
                }
                Err(err) => {
                    self.policy_graph.simulation = None;
                    self.status_message = format!("✗ Refused simulation: {err}");
                }
            },
            Err(err) => {
                self.policy_graph.simulation = None;
                self.status_message = format!("✗ Refused simulation: {err}");
            }
        }
    }

    fn stage_and_simulate_visualizer_node(&mut self) {
        match self.policy_graph.toggle_stage_selected() {
            Ok(_newly_staged) => {
                if self.policy_graph.staged_node_ids.is_empty() {
                    self.policy_graph.simulation = None;
                    self.status_message = "Cleared staged policy amendments.".to_string();
                    return;
                }
                let Some(decision) = self.engine.decisions.get(self.visualizer_decision_idx) else {
                    self.status_message = "No decision selected for simulation.".to_string();
                    return;
                };
                let staged_ids = self.policy_graph.staged_node_ids.clone();
                let mut cands = Vec::with_capacity(staged_ids.len());
                for &id in &staged_ids {
                    if let Some(node) = self.policy_graph.nodes.get(id) {
                        if let Ok(cand) = node.to_review_candidate(&decision.cmd) {
                            cands.push(cand);
                        }
                    }
                }
                match self.engine.simulate_candidates(decision, &cands, staged_ids) {
                    Ok(sim) => {
                        self.status_message = format!(
                            "Staged {} node(s) ({}): {} -> {} (session flip: {}/{})",
                            cands.len(),
                            sim.amendment_summary,
                            sim.before_verdict,
                            sim.after_verdict,
                            sim.session_flipped_to_allow,
                            sim.session_ask_total
                        );
                        self.policy_graph.simulation = Some(sim);
                    }
                    Err(err) => {
                        self.policy_graph.simulation = None;
                        self.status_message = format!("✗ Refused simulation: {err}");
                    }
                }
            }
            Err(err) => {
                self.status_message = format!("✗ Refused simulation: {err}");
            }
        }
    }

    fn apply_selected_visualizer_node(&mut self) {
        let example_cmd = self
            .engine
            .decisions
            .get(self.visualizer_decision_idx)
            .map(|d| d.cmd.clone())
            .unwrap_or_default();

        if !self.policy_graph.staged_node_ids.is_empty() {
            let staged_ids = self.policy_graph.staged_node_ids.clone();
            let mut cands = Vec::with_capacity(staged_ids.len());
            for &id in &staged_ids {
                if let Some(node) = self.policy_graph.nodes.get(id) {
                    match node.to_review_candidate(&example_cmd) {
                        Ok(cand) => cands.push(cand),
                        Err(err) => {
                            self.status_message = format!("✗ Refused: {err}");
                            return;
                        }
                    }
                }
            }
            match self.engine.apply_candidates(&cands) {
                Ok(msg) => {
                    self.status_message = format!("✓ {msg}");
                    for cand in &cands {
                        self.engine
                            .candidates
                            .retain(|c| !(c.section == cand.section && c.name == cand.name));
                    }
                    self.policy_graph.staged_node_ids.clear();
                    self.policy_graph.simulation = None;
                }
                Err(err) => {
                    self.status_message = format!("✗ Refused: {err}");
                }
            }
            return;
        }

        let Some(node) = self.policy_graph.selected_node().cloned() else {
            self.status_message = "No policy graph node selected.".to_string();
            return;
        };
        match node.to_review_candidate(&example_cmd) {
            Ok(cand) => match self.engine.apply_candidate(&cand) {
                Ok(msg) => {
                    self.status_message = format!("✓ {}", msg);
                    self.engine
                        .candidates
                        .retain(|c| !(c.section == cand.section && c.name == cand.name));
                }
                Err(err) => {
                    self.status_message = format!("✗ Refused: {}", err);
                }
            },
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
        let vis_tab = if self.active_tab == ViewTab::Visualizer { "[ 3. Policy Visualizer (v) * ]" } else { "  3. Policy Visualizer (v)  " };
        out.push_str(&format!("Tabs: {}  {}  {}\n", cand_tab, dec_tab, vis_tab));
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
            ViewTab::Visualizer => {
                if !self.engine.decisions.is_empty() {
                    out.push_str(&format!(
                        "  [Decision {}/{} — press [h/l] to switch decision, [Space/Enter] to fold node, [p] preview, [a] accept]\n",
                        self.visualizer_decision_idx + 1,
                        self.engine.decisions.len()
                    ));
                }
                out.push_str(&self.policy_graph.render_ascii());
                if self.show_preview {
                    if let Some(sel_node) = self.policy_graph.selected_node() {
                        let example_cmd = self
                            .engine
                            .decisions
                            .get(self.visualizer_decision_idx)
                            .map(|d| d.cmd.as_str())
                            .unwrap_or("");
                        out.push_str("\n--- Proposed TOML Delta ---\n");
                        match sel_node.to_review_candidate(example_cmd) {
                            Ok(cand) => out.push_str(&cand.proposed_toml),
                            Err(err) => out.push_str(&format!("# Not proposable: {err}\n")),
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
            out.push_str("[j/k]: Nav | [n/N]: Next/Prev Match | [Esc]: Clear Filter | [Tab/v]: View | [q]: Quit\n");
        } else {
            out.push_str(&format!("Status: {}\n", self.status_message));
            out.push_str("[j/k]: Nav | [v]: Visualizer | [/]: Search | [Tab]: View | [a]: Accept Rule | [p]: Preview | [q]: Quit\n");
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
