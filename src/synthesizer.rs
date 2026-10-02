//! Knowledge model synthesis pipeline (M4.6).
//!
//! Analyzes unmodeled programs and callables observed in the journal,
//! extracts flags and subcommands via safe help introspection, and generates
//! schema-validated candidate `[[program]]` TOML blocks for operator review.

use std::process::Command;
use std::time::Duration;

/// Result of synthesizing a candidate knowledge entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SynthesizedCandidate {
    pub name: String,
    pub toml: String,
    pub source: String,
}

/// Synthesize a candidate knowledge entry for a single program or callable name.
pub fn synthesize_candidate(name: &str) -> Option<SynthesizedCandidate> {
    if name.starts_with("python:") {
        return synthesize_python_callable(name);
    }

    synthesize_cli_binary(name)
}

/// Synthesize candidate entries for a slice of unmodeled program names.
pub fn synthesize_candidates(names: &[String]) -> Vec<SynthesizedCandidate> {
    let mut out = Vec::new();
    for name in names {
        if let Some(c) = synthesize_candidate(name) {
            out.push(c);
        }
    }
    out
}

fn synthesize_python_callable(name: &str) -> Option<SynthesizedCandidate> {
    let raw = name.strip_prefix("python:")?;
    let toml = format!(
        "[[program]]\nmatch = [\"python:{raw}\"]\n# Synthesized: Python callable observed in development workflow\n"
    );

    Some(SynthesizedCandidate {
        name: name.to_string(),
        toml,
        source: "python-callable".to_string(),
    })
}

fn synthesize_cli_binary(name: &str) -> Option<SynthesizedCandidate> {
    let bare = crate::guards::base_name(name);
    if bare.is_empty() {
        return None;
    }

    // Try safe --help introspection with a 1-second timeout
    let help_output = run_safe_help(&bare);

    let (subcommands, value_flags) = if let Some(text) = &help_output {
        extract_flags_and_subcommands(text)
    } else {
        (Vec::new(), Vec::new())
    };

    let mut toml = format!("[[program]]\nmatch = [\"{bare}\"]\n");
    if !subcommands.is_empty() {
        let subs = subcommands
            .iter()
            .map(|s| format!("\"{s}\""))
            .collect::<Vec<_>>()
            .join(", ");
        toml.push_str(&format!("subcommands = [{subs}]\n"));
    }
    if !value_flags.is_empty() {
        let vf = value_flags
            .iter()
            .map(|s| format!("\"{s}\""))
            .collect::<Vec<_>>()
            .join(", ");
        toml.push_str(&format!("value_options = [{vf}]\n"));
    }

    Some(SynthesizedCandidate {
        name: bare.to_string(),
        toml,
        source: if help_output.is_some() {
            "help-introspection".to_string()
        } else {
            "archetype-fallback".to_string()
        },
    })
}

fn run_safe_help(binary: &str) -> Option<String> {
    // Only query if the binary actually resolves on PATH
    which(binary)?;

    let child = Command::new(binary)
        .arg("--help")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .ok()?;

    let (tx, rx) = std::sync::mpsc::channel();

    std::thread::spawn(move || {
        let output = child.wait_with_output();
        let _ = tx.send(output);
    });

    match rx.recv_timeout(Duration::from_millis(800)) {
        Ok(Ok(out)) => {
            let mut text = String::from_utf8_lossy(&out.stdout).to_string();
            if text.trim().is_empty() {
                text = String::from_utf8_lossy(&out.stderr).to_string();
            }
            if text.trim().is_empty() {
                None
            } else {
                Some(text)
            }
        }
        _ => {
            // Timed out or failed
            None
        }
    }
}

fn which(binary: &str) -> Option<std::path::PathBuf> {
    if binary.contains('/') || binary.contains('\\') {
        let p = std::path::PathBuf::from(binary);
        if p.exists() {
            return Some(p);
        }
        return None;
    }

    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(binary);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Extract option flags and subcommands from typical CLI help text.
pub fn extract_flags_and_subcommands(help_text: &str) -> (Vec<String>, Vec<String>) {
    let mut subcommands = Vec::new();
    let mut value_flags = Vec::new();

    let mut in_commands_section = false;

    for line in help_text.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with("Commands:") || trimmed.starts_with("Available Commands:") || trimmed.starts_with("SUBCOMMANDS:") {
            in_commands_section = true;
            continue;
        }

        if in_commands_section {
            if trimmed.is_empty() {
                in_commands_section = false;
                continue;
            }
            if trimmed.starts_with("Options:") || trimmed.starts_with("Flags:") {
                in_commands_section = false;
                continue;
            }
            let first_word = trimmed.split_whitespace().next().unwrap_or("");
            if !first_word.is_empty()
                && !first_word.starts_with('-')
                && first_word.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_')
            {
                if !subcommands.contains(&first_word.to_string()) {
                    subcommands.push(first_word.to_string());
                }
            }
        }

        // Look for value-taking flags (e.g. -o, --output <file> or --dir=<path>)
        for part in trimmed.split_whitespace() {
            if part.starts_with("--") {
                let flag_name = part.split('=').next().unwrap_or(part);
                let clean_flag = flag_name
                    .trim_matches(|c: char| !c.is_alphanumeric() && c != '-')
                    .trim_start_matches('-');
                if clean_flag.contains("file")
                    || clean_flag.contains("dir")
                    || clean_flag.contains("path")
                    || clean_flag.contains("output")
                    || clean_flag.contains("input")
                    || clean_flag.contains("config")
                {
                    let flag_formatted = format!("--{clean_flag}");
                    if !value_flags.contains(&flag_formatted) {
                        value_flags.push(flag_formatted);
                    }
                }
            }
        }
    }

    (subcommands, value_flags)
}
