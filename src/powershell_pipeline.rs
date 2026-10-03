//! Dynamic Script Block Analysis for Complex PowerShell Pipelines (M5.2).
//!
//! Provides deep inspection of script blocks passed to pipeline cmdlets (`Where-Object`,
//! `ForEach-Object`, `Select-Object`) to track cross-pipeline object mutations, member calls,
//! and synthesize guard-checked commands for destructive pipeline actions.

use crate::syntax::Cmd;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PipelineStageType {
    Source,
    Filter { is_pure: bool },
    Iterator,
    Sink,
}

#[derive(Debug, Clone)]
pub struct PipelineStage {
    pub stage_type: PipelineStageType,
    pub command: Cmd,
    pub synthesized_commands: Vec<Cmd>,
}

/// Inspect a list of parsed PowerShell commands to extract member mutations
/// and classify pipeline stages.
pub fn analyze_pipeline_stages(cmds: &[Cmd]) -> Vec<Cmd> {
    let mut out = Vec::new();

    for cmd in cmds {
        out.push(cmd.clone());

        // Check if command is an iterator or filter cmdlet
        let head_lower = cmd.head.to_lowercase();
        let is_filter = matches!(head_lower.as_str(), "where-object" | "where" | "?");
        let is_iterator = matches!(head_lower.as_str(), "foreach-object" | "foreach" | "%");

        if is_filter || is_iterator {
            for arg in &cmd.args {
                // Check for destructive method calls inside scriptblock text
                let arg_lower = arg.to_lowercase();
                if arg_lower.contains(".kill()") {
                    // Synthesize Stop-Process to trigger process_control guard
                    out.push(Cmd {
                        head: "Stop-Process".to_string(),
                        args: vec!["-Id".to_string(), "$_.Id".to_string()],
                        ..Default::default()
                    });
                }
                if arg_lower.contains(".delete()") {
                    // Synthesize Remove-Item with -Recurse to trigger delete_recursive guard
                    out.push(Cmd {
                        head: "Remove-Item".to_string(),
                        args: vec!["-Recurse".to_string(), "-Path".to_string(), "$_.FullName".to_string()],
                        ..Default::default()
                    });
                }
            }
        }
    }

    out
}

/// Returns true if a scriptblock text represents a pure read-only filter predicate.
pub fn is_pure_predicate_block(script: &str) -> bool {
    let trimmed = script.trim().trim_start_matches('{').trim_end_matches('}').trim();
    if trimmed.is_empty() {
        return true;
    }

    let lower = trimmed.to_lowercase();
    // Known mutating methods or command invocations are not pure predicates
    if lower.contains(".kill(") || lower.contains(".delete(") || lower.contains(".remove(") || lower.contains("remove-") || lower.contains("set-") || lower.contains("stop-") {
        return false;
    }

    // If script contains comparison operators and no nested script statements
    !lower.contains(';')
}
