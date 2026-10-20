//! Interactive Policy Evaluation DAG Visualizer (`src/tui/graph.rs`).
//!
//! Constructs and renders a deterministic Directed Acyclic Graph (DAG) for any
//! `DecisionItem`, showing how a command flowed through wrapper expansion,
//! capability inference, construct/path rules, and guards to reach its final verdict.

use super::engine::{DecisionItem, ReviewCandidate, TargetFile};
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    CommandRoot,
    WrapperExpansion,
    ConstructHit,
    CapabilityNode,
    GuardHit,
    PathCheck,
    PolicyVerdict,
}

impl NodeKind {
    pub fn badge(self) -> &'static str {
        match self {
            NodeKind::CommandRoot => "ROOT",
            NodeKind::WrapperExpansion => "WRAP",
            NodeKind::ConstructHit => "RULE",
            NodeKind::CapabilityNode => "CAP",
            NodeKind::GuardHit => "GUARD",
            NodeKind::PathCheck => "PATH",
            NodeKind::PolicyVerdict => "VERDICT",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphNode {
    pub id: usize,
    pub kind: NodeKind,
    pub label: String,
    pub detail: String,
    pub setting_hint: Option<String>,
    pub collapsed: bool,
}

impl GraphNode {
    /// Synthesize an actionable `ReviewCandidate` from a Policy Visualizer DAG node (`[RULE]` or `[PATH]`),
    /// or return an explanatory refusal error (e.g. for `[GUARD]` nodes, which ask on purpose per CLAUDE.md §4).
    pub fn to_review_candidate(&self, example_cmd: &str) -> Result<ReviewCandidate, String> {
        match self.kind {
            NodeKind::GuardHit => Err(
                "this is a guard — guards ask on purpose and cannot be converted into standing allow rules"
                    .to_string(),
            ),
            NodeKind::PathCheck => {
                let path = self
                    .label
                    .strip_prefix("unpermitted write path:")
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| "Could not extract write path from node".to_string())?;
                Ok(ReviewCandidate {
                    name: format!("path: {path}"),
                    section: "write.allow_paths".to_string(),
                    target_file: TargetFile::Config,
                    proposed_toml: format!("[write]\nallow_paths = [\"{path}\"]\n"),
                    approved: 1,
                    denied: 0,
                    unknown: 0,
                    sessions: 1,
                    proposable: true,
                    blocked_reason: None,
                    example_cmd: example_cmd.to_string(),
                })
            }
            NodeKind::ConstructHit => {
                if let Some(ref hint) = self.setting_hint {
                    if let Some((section, key)) = parse_construct_setting_hint(hint) {
                        return Ok(ReviewCandidate {
                            name: key.clone(),
                            section: section.clone(),
                            target_file: TargetFile::Config,
                            proposed_toml: format!("[{section}]\n{key} = \"allow\"\n"),
                            approved: 1,
                            denied: 0,
                            unknown: 0,
                            sessions: 1,
                            proposable: true,
                            blocked_reason: None,
                            example_cmd: example_cmd.to_string(),
                        });
                    }
                }
                if let Some(rule_name) = self.label.strip_prefix("policy gate:") {
                    let key = rule_name.trim();
                    if !key.is_empty() && !key.ends_with("(guard)") {
                        let section = "lang.bash.constructs".to_string();
                        return Ok(ReviewCandidate {
                            name: key.to_string(),
                            section: section.clone(),
                            target_file: TargetFile::Config,
                            proposed_toml: format!("[{section}]\n{key} = \"allow\"\n"),
                            approved: 1,
                            denied: 0,
                            unknown: 0,
                            sessions: 1,
                            proposable: true,
                            blocked_reason: None,
                            example_cmd: example_cmd.to_string(),
                        });
                    }
                }
                Err("Selected rule node is already allowed or has no configurable construct.".to_string())
            }
            other => Err(format!(
                "Select a [RULE] or [PATH] node to amend config.toml (selected: [{}]).",
                other.badge()
            )),
        }
    }
}

fn parse_construct_setting_hint(hint: &str) -> Option<(String, String)> {
    let trimmed = hint.trim();
    if let Some(rest) = trimmed.strip_prefix('[') {
        let (section, after_sec) = rest.split_once(']')?;
        let (key, _val) = after_sec.split_once('=')?;
        let sec_clean = section.trim();
        let key_clean = key.trim();
        if !sec_clean.is_empty() && !key_clean.is_empty() {
            return Some((sec_clean.to_string(), key_clean.to_string()));
        }
    }
    None
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphEdge {
    pub from: usize,
    pub to: usize,
    pub relationship: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicySimulationResult {
    pub target_node_id: usize,
    pub staged_node_ids: Vec<usize>,
    pub amendment_summary: String,
    pub before_verdict: String,
    pub after_verdict: String,
    pub before_reason: String,
    pub after_reason: String,
    pub session_ask_total: usize,
    pub session_flipped_to_allow: usize,
}

#[derive(Debug, Clone)]
pub struct PolicyGraph {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    pub selected_visible_idx: usize,
    pub staged_node_ids: Vec<usize>,
    pub simulation: Option<PolicySimulationResult>,
}

impl PolicyGraph {
    pub fn empty() -> Self {
        Self {
            nodes: Vec::new(),
            edges: Vec::new(),
            selected_visible_idx: 0,
            staged_node_ids: Vec::new(),
            simulation: None,
        }
    }

    /// Construct a deterministic policy evaluation DAG from a `DecisionItem`.
    pub fn from_decision(decision: &DecisionItem) -> Self {
        let mut graph = Self::empty();

        // 0. Root Command Node
        let root_id = graph.add_node(
            NodeKind::CommandRoot,
            decision.cmd.clone(),
            format!("cwd: {} | session: {}", decision.cwd, decision.session),
            None,
        );

        let mut active_parent_id = root_id;

        // 1. Parse shell structure to identify subcommands / wrappers if multiple or wrapped
        if let Ok(scan) = crate::shell::parse(&decision.cmd) {
            for (idx, cmd) in scan.commands.iter().enumerate() {
                let base = crate::guards::base_name(&cmd.head);
                let is_wrapper = matches!(
                    base.as_str(),
                    "bash" | "sh" | "zsh" | "env" | "sudo" | "xargs" | "nohup" | "timeout" | "python" | "python3" | "node" | "pwsh" | "powershell"
                );
                if is_wrapper || scan.commands.len() > 1 {
                    let rendered = if cmd.args.is_empty() {
                        cmd.head.clone()
                    } else {
                        format!("{} {}", cmd.head, cmd.args.join(" "))
                    };
                    let wrap_id = graph.add_node(
                        NodeKind::WrapperExpansion,
                        format!("stage #{}: {}", idx + 1, rendered),
                        format!("head: {} ({} arg(s))", cmd.head, cmd.args.len()),
                        None,
                    );
                    graph.add_edge(active_parent_id, wrap_id, "expands_to");
                    active_parent_id = wrap_id;
                }
            }
        }

        // 2. Static AST capability extraction for inline python/javascript/shell cues
        let mut inferred_caps = Vec::new();
        let py_caps = crate::python::extract_capabilities(&decision.cmd);
        let js_caps = crate::javascript::extract_capabilities(&decision.cmd);
        let mut combined_caps = py_caps;
        combined_caps.union(js_caps);
        if decision.cmd.contains("curl ") || decision.cmd.contains("wget ") || decision.cmd.contains("ssh ") {
            combined_caps.network = true;
        }
        if combined_caps.network {
            inferred_caps.push(("network", "Outbound/inbound socket or HTTP activity"));
        }
        if combined_caps.external_paths {
            inferred_caps.push(("external_paths", "Filesystem mutation or external path access"));
        }
        if combined_caps.daemon {
            inferred_caps.push(("daemon", "Background process / subprocess fork capability"));
        }
        if combined_caps.dynamic_eval {
            inferred_caps.push(("dynamic_eval", "Dynamic code evaluation (eval/exec)"));
        }

        for (cap_name, cap_desc) in inferred_caps {
            let cap_id = graph.add_node(
                NodeKind::CapabilityNode,
                format!("capability: {cap_name}"),
                cap_desc.to_string(),
                Some(format!("[capabilities] {cap_name}")),
            );
            graph.add_edge(active_parent_id, cap_id, "requires_cap");
        }

        // 3. Inspect decision.reason for GuardHit, PathCheck, or ConstructHit
        let setting_hint = extract_setting_hint(&decision.reason);
        let mut evaluation_leaf_ids = Vec::new();

        if let Some(guard_name) = extract_guard_hit(&decision.reason) {
            let guard_id = graph.add_node(
                NodeKind::GuardHit,
                format!("guard: {guard_name}"),
                decision.reason.lines().nth(1).unwrap_or("destructive effect guard").trim().to_string(),
                setting_hint.clone(),
            );
            graph.add_edge(active_parent_id, guard_id, "triggers_guard");
            evaluation_leaf_ids.push(guard_id);
        } else if decision.reason.contains("path outside every allowed area") {
            let path_val = decision
                .reason
                .lines()
                .nth(1)
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|| "<external-path>".to_string());
            let path_id = graph.add_node(
                NodeKind::PathCheck,
                format!("unpermitted write path: {path_val}"),
                "Write target falls outside workspace and write.allow_paths".to_string(),
                setting_hint.clone().or_else(|| Some(format!("write.allow_paths = [\"{path_val}\"]"))),
            );
            graph.add_edge(active_parent_id, path_id, "checks_path");
            evaluation_leaf_ids.push(path_id);
        } else if let Some(rule_name) = extract_stopped_rule(&decision.reason) {
            let rule_id = graph.add_node(
                NodeKind::ConstructHit,
                format!("policy gate: {rule_name}"),
                decision.reason.lines().next().unwrap_or(&decision.reason).trim().to_string(),
                setting_hint.clone(),
            );
            graph.add_edge(active_parent_id, rule_id, "hits_rule");
            evaluation_leaf_ids.push(rule_id);
        } else {
            let rule_id = graph.add_node(
                NodeKind::ConstructHit,
                "policy evaluation: allow-list matched".to_string(),
                decision.reason.clone(),
                None,
            );
            graph.add_edge(active_parent_id, rule_id, "matches_policy");
            evaluation_leaf_ids.push(rule_id);
        }

        // 3b. If decision is ASK without a guard hit, also discover any additional construct gates
        // or unpermitted write paths in the command so multi-gate commands can be staged & simulated together.
        if decision.verdict.eq_ignore_ascii_case("ask")
            && extract_guard_hit(&decision.reason).is_none()
        {
            if let Ok(scan) = crate::shell::parse(&decision.cmd) {
                for construct in &scan.constructs {
                    let expected_label = format!("policy gate: {construct}");
                    if !graph.nodes.iter().any(|n| n.label == expected_label) {
                        let rule_id = graph.add_node(
                            NodeKind::ConstructHit,
                            expected_label,
                            format!("Shell construct gate '{construct}' present in command"),
                            Some(format!("[lang.bash.constructs] {construct} = \"allow\"")),
                        );
                        graph.add_edge(active_parent_id, rule_id, "hits_rule");
                        evaluation_leaf_ids.push(rule_id);
                    }
                }

                let mut extra_write_paths: Vec<String> = Vec::new();
                for target in &scan.redirect_targets {
                    if target.starts_with('/') && !target.starts_with(&decision.cwd) {
                        extra_write_paths.push(target.clone());
                    }
                }
                for cmd in &scan.commands {
                    let base = crate::guards::base_name(&cmd.head);
                    if matches!(
                        base.as_str(),
                        "touch" | "tee" | "mkdir" | "cp" | "mv" | "install"
                    ) {
                        for arg in &cmd.args {
                            if !arg.starts_with('-')
                                && arg.starts_with('/')
                                && !arg.starts_with(&decision.cwd)
                            {
                                extra_write_paths.push(arg.clone());
                            }
                        }
                    }
                }
                for path_val in extra_write_paths {
                    let expected_label = format!("unpermitted write path: {path_val}");
                    if !graph.nodes.iter().any(|n| n.label == expected_label) {
                        let path_id = graph.add_node(
                            NodeKind::PathCheck,
                            expected_label,
                            "Write target falls outside workspace and write.allow_paths".to_string(),
                            Some(format!("write.allow_paths = [\"{path_val}\"]")),
                        );
                        graph.add_edge(active_parent_id, path_id, "checks_path");
                        evaluation_leaf_ids.push(path_id);
                    }
                }
            }
        }

        // 4. Final Verdict Node
        let verdict_id = graph.add_node(
            NodeKind::PolicyVerdict,
            format!("verdict: {} ({})", decision.verdict.to_uppercase(), decision.outcome),
            decision.reason.clone(),
            setting_hint,
        );
        for leaf_id in evaluation_leaf_ids {
            graph.add_edge(leaf_id, verdict_id, "resolves_to");
        }

        graph
    }

    pub fn add_node(
        &mut self,
        kind: NodeKind,
        label: String,
        detail: String,
        setting_hint: Option<String>,
    ) -> usize {
        let id = self.nodes.len();
        self.nodes.push(GraphNode {
            id,
            kind,
            label,
            detail,
            setting_hint,
            collapsed: false,
        });
        id
    }

    pub fn add_edge(&mut self, from: usize, to: usize, relationship: &str) {
        self.edges.push(GraphEdge {
            from,
            to,
            relationship: relationship.to_string(),
        });
    }

    pub fn children_of(&self, node_id: usize) -> Vec<(usize, &str)> {
        self.edges
            .iter()
            .filter(|e| e.from == node_id)
            .map(|e| (e.to, e.relationship.as_str()))
            .collect()
    }

    /// Returns visible `(node_id, depth, incoming_relationship)` in deterministic pre-order traversal.
    pub fn visible_entries(&self) -> Vec<(usize, usize, String)> {
        if self.nodes.is_empty() {
            return Vec::new();
        }
        let mut entries = Vec::new();
        let mut visited = HashSet::new();
        self.collect_visible_dfs(0, 0, "root".to_string(), &mut visited, &mut entries);
        entries
    }

    fn collect_visible_dfs(
        &self,
        node_id: usize,
        depth: usize,
        rel: String,
        visited: &mut HashSet<usize>,
        out: &mut Vec<(usize, usize, String)>,
    ) {
        if !visited.insert(node_id) {
            return;
        }
        out.push((node_id, depth, rel));
        let Some(node) = self.nodes.get(node_id) else {
            return;
        };
        if node.collapsed {
            return;
        }
        for (child_id, edge_rel) in self.children_of(node_id) {
            if self
                .nodes
                .get(child_id)
                .is_some_and(|n| n.kind == NodeKind::PolicyVerdict)
            {
                let all_parents_visited = self
                    .edges
                    .iter()
                    .filter(|e| e.to == child_id)
                    .all(|e| visited.contains(&e.from));
                if !all_parents_visited {
                    continue;
                }
            }
            self.collect_visible_dfs(child_id, depth + 1, edge_rel.to_string(), visited, out);
        }
    }

    pub fn selected_node(&self) -> Option<&GraphNode> {
        let visible = self.visible_entries();
        let (node_id, _, _) = visible.get(self.selected_visible_idx)?;
        self.nodes.get(*node_id)
    }

    pub fn move_selection_down(&mut self) {
        let len = self.visible_entries().len();
        if len > 0 && self.selected_visible_idx + 1 < len {
            self.selected_visible_idx += 1;
        }
    }

    pub fn move_selection_up(&mut self) {
        if self.selected_visible_idx > 0 {
            self.selected_visible_idx -= 1;
        }
    }

    pub fn toggle_selected_collapse(&mut self) {
        let visible = self.visible_entries();
        if let Some(&(node_id, _, _)) = visible.get(self.selected_visible_idx) {
            if !self.children_of(node_id).is_empty() {
                if let Some(node) = self.nodes.get_mut(node_id) {
                    node.collapsed = !node.collapsed;
                }
            }
        }
        let new_len = self.visible_entries().len();
        if new_len > 0 && self.selected_visible_idx >= new_len {
            self.selected_visible_idx = new_len - 1;
        }
    }

    /// Toggle whether the currently selected `[RULE]` or `[PATH]` node is staged for cumulative simulation.
    /// Returns `Ok(true)` if newly staged, `Ok(false)` if unstaged, or `Err(reason)` if the node cannot be staged.
    pub fn toggle_stage_selected(&mut self) -> Result<bool, String> {
        let Some(node) = self.selected_node().cloned() else {
            return Err("No policy graph node selected.".to_string());
        };
        if node.kind == NodeKind::GuardHit {
            return Err(
                "Guard rules describe operator effects and cannot be simulated as allow-list amendments."
                    .to_string(),
            );
        }
        // Validate that the node can produce a proposable ReviewCandidate
        let _ = node.to_review_candidate("")?;

        if let Some(pos) = self.staged_node_ids.iter().position(|&id| id == node.id) {
            self.staged_node_ids.remove(pos);
            Ok(false)
        } else {
            self.staged_node_ids.push(node.id);
            Ok(true)
        }
    }

    /// Render the interactive policy DAG into a deterministic multi-line ASCII/Unicode frame.
    pub fn render_ascii(&self) -> String {
        if self.nodes.is_empty() {
            return "No policy graph available (no decisions recorded).\n".to_string();
        }

        let mut out = String::new();
        let visible = self.visible_entries();

        out.push_str("  Policy Decision Evaluation DAG (press [Space/Enter] to collapse/expand node):\n\n");

        for (vis_idx, (node_id, depth, rel)) in visible.iter().enumerate() {
            let node = &self.nodes[*node_id];
            let cursor = if vis_idx == self.selected_visible_idx {
                ">"
            } else {
                " "
            };
            let has_children = !self.children_of(*node_id).is_empty();
            let fold_marker = if !has_children {
                "[•]"
            } else if node.collapsed {
                "[+]"
            } else {
                "[-]"
            };

            let indent = "    ".repeat(*depth);
            let connector = if *depth == 0 {
                String::new()
            } else {
                format!("└─({rel})─► ")
            };

            let staged_badge = if self.staged_node_ids.contains(node_id) {
                " [STAGED]"
            } else {
                ""
            };

            let sim_badge = match &self.simulation {
                Some(sim)
                    if sim.target_node_id == *node_id
                        || sim.staged_node_ids.contains(node_id)
                        || node.kind == NodeKind::PolicyVerdict =>
                {
                    format!(" [SIMULATED: {} -> {}]", sim.before_verdict, sim.after_verdict)
                }
                _ => String::new(),
            };

            out.push_str(&format!(
                "{} {}{}{} [{}] {}{}{}\n",
                cursor,
                indent,
                connector,
                fold_marker,
                node.kind.badge(),
                node.label,
                staged_badge,
                sim_badge
            ));
        }

        if let Some(sel) = self.selected_node() {
            out.push_str("\n--- Selected Graph Node Inspector ---\n");
            out.push_str(&format!("Node ID: #{} ({})\n", sel.id, sel.kind.badge()));
            out.push_str(&format!("Label:   {}\n", sel.label));
            out.push_str(&format!("Detail:  {}\n", sel.detail.replace('\n', " | ")));
            if let Some(ref hint) = sel.setting_hint {
                out.push_str(&format!("Config:  {}\n", hint));
            }
        }

        if let Some(ref sim) = self.simulation {
            out.push_str("\n--- Side-by-Side Amendment Impact Diff (Simulation) ---\n");
            out.push_str(&format!("Amendment: {}\n", sim.amendment_summary));
            out.push_str(&format!(
                "Before:    [{}] {}\n",
                sim.before_verdict,
                sim.before_reason.lines().next().unwrap_or(&sim.before_reason)
            ));
            out.push_str(&format!(
                "After:     [{}] {}\n",
                sim.after_verdict,
                sim.after_reason.lines().next().unwrap_or(&sim.after_reason)
            ));
            out.push_str(&format!(
                "Session Impact: {}/{} ASK decision(s) would flip to ALLOW\n",
                sim.session_flipped_to_allow, sim.session_ask_total
            ));
        }

        out
    }
}

fn extract_guard_hit(reason: &str) -> Option<String> {
    let first_line = reason.lines().next()?.trim();
    if let Some(rest) = first_line.strip_prefix("vouch stopped on:") {
        let trimmed = rest.trim();
        if let Some(guard_name) = trimmed.strip_suffix("(guard)") {
            return Some(guard_name.trim().to_string());
        }
    }
    None
}

fn extract_stopped_rule(reason: &str) -> Option<String> {
    let first_line = reason.lines().next()?.trim();
    if let Some(rest) = first_line.strip_prefix("vouch stopped on:") {
        return Some(rest.trim().to_string());
    }
    None
}

fn extract_setting_hint(reason: &str) -> Option<String> {
    for line in reason.lines() {
        let trimmed = line.trim();
        if let Some(hint) = trimmed.strip_prefix("to allow this permanently:") {
            return Some(hint.trim().to_string());
        }
    }
    None
}
