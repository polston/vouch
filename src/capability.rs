//! Automated Cross-Language Capability Propagation.
//!
//! Models host and environment capabilities (`network`, `external_paths`, `daemon`)
//! and computes transitive capability sets across complex multi-language execution
//! trees (e.g. bash scripts invoking python snippets that launch subprocesses or container CLIs).

use serde::{Deserialize, Serialize};

/// Strongly typed bitset representing process capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CapabilitySet {
    pub network: bool,
    pub external_paths: bool,
    pub daemon: bool,
}

impl CapabilitySet {
    pub const EMPTY: Self = Self {
        network: false,
        external_paths: false,
        daemon: false,
    };

    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        !self.network && !self.external_paths && !self.daemon
    }

    pub fn has_any(&self) -> bool {
        self.network || self.external_paths || self.daemon
    }

    pub fn insert(&mut self, cap: &str) {
        match cap {
            "network" => self.network = true,
            "external_paths" => self.external_paths = true,
            "daemon" => self.daemon = true,
            _ => {}
        }
    }

    pub fn contains(&self, cap: &str) -> bool {
        match cap {
            "network" => self.network,
            "external_paths" => self.external_paths,
            "daemon" => self.daemon,
            _ => false,
        }
    }

    pub fn union(&mut self, other: CapabilitySet) {
        self.network |= other.network;
        self.external_paths |= other.external_paths;
        self.daemon |= other.daemon;
    }

    pub fn combined(mut self, other: CapabilitySet) -> Self {
        self.union(other);
        self
    }

    pub fn from_slice(caps: &[impl AsRef<str>]) -> Self {
        let mut set = Self::default();
        for c in caps {
            set.insert(c.as_ref());
        }
        set
    }

    pub fn to_vec(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.network {
            out.push("network".to_string());
        }
        if self.external_paths {
            out.push("external_paths".to_string());
        }
        if self.daemon {
            out.push("daemon".to_string());
        }
        out
    }
}

/// Trait for inspecting script AST bodies to dynamically infer capabilities.
pub trait AstCapabilityExtractor: Send + Sync {
    fn extract_capabilities(&self, script: &str, lang: &str) -> CapabilitySet;
}

/// Default AST capability extractor delegating to language parser visitors.
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultAstCapabilityExtractor;

impl AstCapabilityExtractor for DefaultAstCapabilityExtractor {
    fn extract_capabilities(&self, script: &str, lang: &str) -> CapabilitySet {
        let trimmed = script.trim();
        if trimmed.is_empty() {
            return CapabilitySet::EMPTY;
        }
        match lang {
            "python" | "py" => crate::python::extract_capabilities(trimmed),
            "javascript" | "js" | "node" => crate::javascript::extract_capabilities(trimmed),
            _ => CapabilitySet::EMPTY,
        }
    }
}

/// Extensible capability evaluator for individual commands.
pub trait CapabilityEmitter: Send + Sync {
    fn required_capabilities(
        &self,
        cmd: &crate::syntax::Cmd,
        knowledge: &crate::guards::Knowledge,
        lang: &str,
    ) -> CapabilitySet;
}

/// Default capability emitter delegating to knowledge.toml capability rules and script AST inspection.
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultCapabilityEmitter;

impl CapabilityEmitter for DefaultCapabilityEmitter {
    fn required_capabilities(
        &self,
        cmd: &crate::syntax::Cmd,
        knowledge: &crate::guards::Knowledge,
        lang: &str,
    ) -> CapabilitySet {
        let mut caps = CapabilitySet::from_slice(&crate::guards::capabilities_for_cmd(knowledge, cmd, lang));

        let base_head = crate::guards::base_name(&cmd.head).to_lowercase();
        let is_python = matches!(base_head.as_str(), "python" | "python3" | "py");
        let is_node = matches!(base_head.as_str(), "node" | "nodejs" | "js");

        if is_python || is_node {
            for (idx, arg) in cmd.args.iter().enumerate() {
                let unquoted_arg = crate::paths::unquote(arg);
                if (is_python && (arg == "-c" || unquoted_arg == "-c")) || (is_node && (arg == "-e" || unquoted_arg == "-e")) {
                    if let Some(script) = cmd.args.get(idx + 1) {
                        let unquoted_script = crate::paths::unquote_snippet(script);
                        let script_lang = if is_python { "python" } else { "javascript" };
                        let ast_caps = DefaultAstCapabilityExtractor.extract_capabilities(&unquoted_script, script_lang);
                        caps.union(ast_caps);
                    }
                } else if is_python && unquoted_arg.starts_with("-c") && unquoted_arg.len() > 2 {
                    let script = crate::paths::unquote_snippet(&unquoted_arg[2..]);
                    let ast_caps = DefaultAstCapabilityExtractor.extract_capabilities(&script, "python");
                    caps.union(ast_caps);
                } else if is_node && unquoted_arg.starts_with("-e") && unquoted_arg.len() > 2 {
                    let script = crate::paths::unquote_snippet(&unquoted_arg[2..]);
                    let ast_caps = DefaultAstCapabilityExtractor.extract_capabilities(&script, "javascript");
                    caps.union(ast_caps);
                }
            }
        }

        caps
    }
}

/// Resolves the capability set for a single command occurrence under its source language.
pub fn capabilities_for_cmd(
    kb: &crate::guards::Knowledge,
    cmd: &crate::syntax::Cmd,
    lang: &str,
) -> CapabilitySet {
    DefaultCapabilityEmitter.required_capabilities(cmd, kb, lang)
}

/// Computes the aggregate capabilities required across a collection of expanded command occurrences.
pub fn capabilities_for_occurrences<E: CapabilityEmitter>(
    kb: &crate::guards::Knowledge,
    occurrences: &[crate::guards::Occurrence],
    emitter: &E,
) -> CapabilitySet {
    let mut total_caps = CapabilitySet::default();
    for occ in occurrences {
        let caps = emitter.required_capabilities(&occ.cmd, kb, &occ.lang);
        total_caps.union(caps);
    }
    total_caps
}

/// Computes the transitively propagated capability set required by a command string and all
/// wrapped child/subprocess commands across languages.
pub fn propagate_capabilities(
    kb: &crate::guards::Knowledge,
    command: &str,
    lang: &str,
) -> CapabilitySet {
    propagate_capabilities_with_emitter(kb, command, lang, &DefaultCapabilityEmitter)
}

/// Computes transitively propagated capabilities using a custom emitter.
pub fn propagate_capabilities_with_emitter<E: CapabilityEmitter>(
    kb: &crate::guards::Knowledge,
    command: &str,
    lang: &str,
    emitter: &E,
) -> CapabilitySet {
    let trimmed = command.trim();
    if trimmed.is_empty() {
        return CapabilitySet::default();
    }
    let normalized_lang = match lang {
        "js" | "node" => "javascript",
        "py" => "python",
        "ps" | "ps1" | "pwsh" => "powershell",
        "sh" | "zsh" => "bash",
        other => other,
    };

    let mut total_caps = CapabilitySet::default();

    // If root language is python or javascript, extract direct AST capabilities
    if normalized_lang == "python" || normalized_lang == "javascript" {
        let root_ast = DefaultAstCapabilityExtractor.extract_capabilities(trimmed, normalized_lang);
        total_caps.union(root_ast);
    }

    let scan = if let Some(scanner) = crate::syntax::scanner_for(normalized_lang) {
        match scanner.scan(trimmed) {
            Ok(s) => s,
            Err(_) => return total_caps,
        }
    } else {
        match crate::shell::parse(trimmed) {
            Ok(s) => s,
            Err(_) => return total_caps,
        }
    };

    for cmd in &scan.commands {
        let caps = emitter.required_capabilities(cmd, kb, normalized_lang);
        total_caps.union(caps);
    }

    let expanded = crate::guards::expand_wrappers_with_sources(
        kb,
        &scan.commands,
        &scan.heredocs,
        &scan.input_source,
        &scan.args_complete,
        normalized_lang,
        &|_| 4,
    );
    let occurrences_caps = capabilities_for_occurrences(kb, &expanded.occurrences, emitter);
    total_caps.union(occurrences_caps);
    total_caps
}
