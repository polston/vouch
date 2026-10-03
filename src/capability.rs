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

/// Extensible capability evaluator for individual commands.
pub trait CapabilityEmitter: Send + Sync {
    fn required_capabilities(
        &self,
        cmd: &crate::syntax::Cmd,
        knowledge: &crate::guards::Knowledge,
        lang: &str,
    ) -> CapabilitySet;
}

/// Default capability emitter delegating to knowledge.toml capability rules.
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultCapabilityEmitter;

impl CapabilityEmitter for DefaultCapabilityEmitter {
    fn required_capabilities(
        &self,
        cmd: &crate::syntax::Cmd,
        knowledge: &crate::guards::Knowledge,
        lang: &str,
    ) -> CapabilitySet {
        let caps = crate::guards::capabilities_for_cmd(knowledge, cmd, lang);
        CapabilitySet::from_slice(&caps)
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
    let scan = if let Some(scanner) = crate::syntax::scanner_for(normalized_lang) {
        match scanner.scan(trimmed) {
            Ok(s) => s,
            Err(_) => return CapabilitySet::default(),
        }
    } else {
        match crate::shell::parse(trimmed) {
            Ok(s) => s,
            Err(_) => return CapabilitySet::default(),
        }
    };
    let expanded = crate::guards::expand_wrappers_with_sources(
        kb,
        &scan.commands,
        &scan.heredocs,
        &scan.input_source,
        &scan.args_complete,
        normalized_lang,
        &|_| 4,
    );
    capabilities_for_occurrences(kb, &expanded.occurrences, emitter)
}
