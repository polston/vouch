//! Automated Cross-Language Capability Propagation.
//!
//! Models host and environment capabilities (`network`, `external_paths`, `daemon`)
//! and computes transitive capability sets across complex multi-language execution
//! trees (e.g. bash scripts invoking python snippets that launch subprocesses or container CLIs).

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Strongly typed bitset representing process capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CapabilitySet {
    pub network: bool,
    pub external_paths: bool,
    pub daemon: bool,
    #[serde(default)]
    pub dynamic_eval: bool,
}

impl CapabilitySet {
    pub const EMPTY: Self = Self {
        network: false,
        external_paths: false,
        daemon: false,
        dynamic_eval: false,
    };

    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        !self.network && !self.external_paths && !self.daemon && !self.dynamic_eval
    }

    pub fn has_any(&self) -> bool {
        self.network || self.external_paths || self.daemon || self.dynamic_eval
    }

    pub fn insert(&mut self, cap: &str) {
        match cap {
            "network" => self.network = true,
            "external_paths" => self.external_paths = true,
            "daemon" => self.daemon = true,
            "dynamic_eval" => self.dynamic_eval = true,
            _ => {}
        }
    }

    pub fn contains(&self, cap: &str) -> bool {
        match cap {
            "network" => self.network,
            "external_paths" => self.external_paths,
            "daemon" => self.daemon,
            "dynamic_eval" => self.dynamic_eval,
            _ => false,
        }
    }

    pub fn union(&mut self, other: CapabilitySet) {
        self.network |= other.network;
        self.external_paths |= other.external_paths;
        self.daemon |= other.daemon;
        self.dynamic_eval |= other.dynamic_eval;
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
        if self.dynamic_eval {
            out.push("dynamic_eval".to_string());
        }
        out
    }
}

/// Comprehensive report detailing aggregate capabilities and traversal metadata
/// across a transitively resolved import graph.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CapabilityReport {
    pub capabilities: CapabilitySet,
    pub resolved_files: Vec<PathBuf>,
    pub unresolved_imports: Vec<String>,
    pub cycle_detected: bool,
    pub limit_exceeded: bool,
}

impl CapabilityReport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.capabilities.is_empty() && self.resolved_files.is_empty()
    }

    pub fn has_any(&self) -> bool {
        self.capabilities.has_any()
    }

    pub fn union(&mut self, other: CapabilityReport) {
        self.capabilities.union(other.capabilities);
        for f in other.resolved_files {
            if !self.resolved_files.contains(&f) {
                self.resolved_files.push(f);
            }
        }
        for u in other.unresolved_imports {
            if !self.unresolved_imports.contains(&u) {
                self.unresolved_imports.push(u);
            }
        }
        self.cycle_detected |= other.cycle_detected;
        self.limit_exceeded |= other.limit_exceeded;
    }
}

/// A single TypeScript/JavaScript path alias mapping from `tsconfig.json` / `jsconfig.json`
/// `compilerOptions.paths` (e.g. `"@/*": ["./src/*"]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsPathMapping {
    pub pattern: String,
    pub targets: Vec<PathBuf>,
}

/// Package-scoped Node.js subpath import mappings (`package.json` `"imports": { "#*": ... }`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeSubpathImportScope {
    pub pkg_dir: PathBuf,
    pub mappings: Vec<TsPathMapping>,
}

/// Index of local Python and Node/JavaScript/TypeScript packages discovered from workspace manifests
/// (`pyproject.toml`, `requirements.txt`, `package.json`, `pnpm-lock.yaml`, `tsconfig.json`, `jsconfig.json`).
#[derive(Debug, Clone, Default)]
pub struct WorkspaceManifestIndex {
    /// Maps Python top-level module/package name (normalized and raw) to its package directory.
    pub python_packages: std::collections::HashMap<String, PathBuf>,
    /// Maps Node package name (e.g., `@scope/pkg` or `my-pkg`) to its package root directory.
    pub node_packages: std::collections::HashMap<String, PathBuf>,
    /// Maps Node package name -> subpath key (e.g., `.`, `./net`) -> target path inside package.
    pub node_exports: std::collections::HashMap<String, std::collections::HashMap<String, PathBuf>>,
    /// Package-scoped `#` subpath import mappings from `package.json` `"imports"` fields.
    pub node_subpath_imports: Vec<NodeSubpathImportScope>,
    /// Resolved `compilerOptions.baseUrl` directories from `tsconfig.json` / `jsconfig.json`.
    pub ts_base_urls: Vec<PathBuf>,
    /// Resolved `compilerOptions.paths` alias mappings from `tsconfig.json` / `jsconfig.json`.
    pub ts_path_mappings: Vec<TsPathMapping>,
    /// Resolved TypeScript composite project reference directories (`tsconfig.json` `"references"`).
    pub ts_project_references: Vec<PathBuf>,
}

impl WorkspaceManifestIndex {
    /// Discover workspace manifests under `workspace_root` with bounded recursion.
    pub fn discover(workspace_root: &Path) -> Self {
        let mut index = Self::default();
        if !workspace_root.is_dir() {
            return index;
        }
        let mut visited_dirs = HashSet::new();
        index.scan_dir_bounded(workspace_root, workspace_root, 0, 4, &mut visited_dirs);
        index
    }

    /// Returns true if `specifier` matches any configured `tsconfig.json` / `jsconfig.json` path alias pattern.
    pub fn matches_ts_alias(&self, specifier: &str) -> bool {
        let trimmed = specifier.trim();
        for mapping in &self.ts_path_mappings {
            if let Some((prefix, suffix)) = mapping.pattern.split_once('*') {
                if trimmed.starts_with(prefix)
                    && trimmed.ends_with(suffix)
                    && trimmed.len() >= prefix.len() + suffix.len()
                {
                    return true;
                }
            } else if trimmed == mapping.pattern
                || trimmed.starts_with(&format!("{}/", mapping.pattern))
            {
                return true;
            }
        }
        false
    }

    fn scan_dir_bounded(
        &mut self,
        workspace_root: &Path,
        dir: &Path,
        depth: usize,
        max_depth: usize,
        visited_dirs: &mut HashSet<PathBuf>,
    ) {
        if depth > max_depth || visited_dirs.len() >= 128 {
            return;
        }
        let canonical_dir = dir.canonicalize().unwrap_or_else(|_| dir.to_path_buf());
        if !visited_dirs.insert(canonical_dir) {
            return;
        }

        let pyproject = dir.join("pyproject.toml");
        if pyproject.is_file() {
            self.parse_pyproject_toml(workspace_root, dir, &pyproject);
        }

        let requirements = dir.join("requirements.txt");
        if requirements.is_file() {
            self.parse_requirements_txt(workspace_root, dir, &requirements);
        }

        let package_json = dir.join("package.json");
        if package_json.is_file() {
            self.parse_package_json(workspace_root, dir, &package_json);
        }

        let pnpm_lock = dir.join("pnpm-lock.yaml");
        if pnpm_lock.is_file() {
            self.parse_pnpm_lock(workspace_root, dir, &pnpm_lock);
        }

        for tsconfig_name in &["tsconfig.json", "jsconfig.json"] {
            let tsconfig_path = dir.join(tsconfig_name);
            if tsconfig_path.is_file() {
                self.parse_tsconfig_json(workspace_root, dir, &tsconfig_path, 0);
            }
        }

        // Also check standard src/ layout in workspace root or package dir
        let src_dir = dir.join("src");
        if depth <= 2 && src_dir.is_dir() {
            self.register_python_src_children(&src_dir);
        }

        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if matches!(
                name_str.as_ref(),
                ".git"
                    | "node_modules"
                    | "target"
                    | ".venv"
                    | "venv"
                    | "dist"
                    | "build"
                    | "__pycache__"
                    | ".tox"
                    | ".mypy_cache"
                    | ".pytest_cache"
            ) {
                continue;
            }
            self.scan_dir_bounded(workspace_root, &path, depth + 1, max_depth, visited_dirs);
        }
    }

    fn normalize_py_name(name: &str) -> String {
        name.trim()
            .to_lowercase()
            .replace('-', "_")
            .replace('.', "_")
    }

    fn register_python_package_dir(&mut self, pkg_name: &str, pkg_root: &Path) {
        let norm = Self::normalize_py_name(pkg_name);
        if norm.is_empty() {
            return;
        }

        // Candidate 1: src/<norm>
        let src_pkg = pkg_root.join("src").join(&norm);
        if src_pkg.is_dir() || src_pkg.with_extension("py").is_file() {
            self.python_packages.insert(norm.clone(), src_pkg.clone());
            self.python_packages.insert(pkg_name.to_string(), src_pkg);
            return;
        }

        // Candidate 2: <pkg_root>/<norm>
        let flat_pkg = pkg_root.join(&norm);
        if flat_pkg.is_dir() || flat_pkg.with_extension("py").is_file() {
            self.python_packages.insert(norm.clone(), flat_pkg.clone());
            self.python_packages.insert(pkg_name.to_string(), flat_pkg);
            return;
        }

        // Candidate 3: if pkg_root/src exists, inspect children
        let src_dir = pkg_root.join("src");
        if src_dir.is_dir() {
            self.register_python_src_children(&src_dir);
        }

        // Candidate 4: pkg_root itself if it is a directory (supports __init__.py and PEP 420 namespace packages)
        if pkg_root.is_dir() {
            self.python_packages
                .entry(norm)
                .or_insert_with(|| pkg_root.to_path_buf());
            self.python_packages
                .entry(pkg_name.to_string())
                .or_insert_with(|| pkg_root.to_path_buf());
        }
    }

    fn register_python_src_children(&mut self, src_dir: &Path) {
        let Ok(entries) = std::fs::read_dir(src_dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let file_name = entry.file_name().to_string_lossy().to_string();
            if path.is_dir() && path.join("__init__.py").is_file() {
                let norm = Self::normalize_py_name(&file_name);
                self.python_packages.entry(norm).or_insert_with(|| path.clone());
                self.python_packages.entry(file_name).or_insert(path);
            } else if path.is_file() && file_name.ends_with(".py") && file_name != "__init__.py" {
                let stem = file_name.trim_end_matches(".py");
                self.python_packages
                    .entry(stem.to_string())
                    .or_insert_with(|| src_dir.join(stem));
            }
        }
    }

    fn parse_pyproject_toml(&mut self, _workspace_root: &Path, pkg_dir: &Path, pyproject_path: &Path) {
        let Ok(content) = std::fs::read_to_string(pyproject_path) else {
            return;
        };
        let Ok(val) = toml::from_str::<toml::Value>(&content) else {
            return;
        };

        if let Some(name) = val
            .get("project")
            .and_then(|p| p.get("name"))
            .and_then(|n| n.as_str())
        {
            self.register_python_package_dir(name, pkg_dir);
        }

        if let Some(poetry) = val.get("tool").and_then(|t| t.get("poetry")) {
            if let Some(name) = poetry.get("name").and_then(|n| n.as_str()) {
                self.register_python_package_dir(name, pkg_dir);
            }
            if let Some(packages) = poetry.get("packages").and_then(|p| p.as_array()) {
                for pkg_entry in packages {
                    if let Some(include) = pkg_entry.get("include").and_then(|i| i.as_str()) {
                        let from_dir = pkg_entry
                            .get("from")
                            .and_then(|f| f.as_str())
                            .map(|f| pkg_dir.join(f))
                            .unwrap_or_else(|| pkg_dir.to_path_buf());
                        let target = from_dir.join(include);
                        let norm = Self::normalize_py_name(include);
                        self.python_packages.insert(norm, target.clone());
                        self.python_packages.insert(include.to_string(), target);
                    }
                }
            }
        }
    }

    fn parse_requirements_txt(&mut self, workspace_root: &Path, req_dir: &Path, req_path: &Path) {
        let Ok(content) = std::fs::read_to_string(req_path) else {
            return;
        };
        for raw_line in content.lines() {
            let line = raw_line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let editable_target = if let Some(rest) = line.strip_prefix("-e ") {
                Some(rest.trim())
            } else if let Some(rest) = line.strip_prefix("--editable ") {
                Some(rest.trim())
            } else if let Some(rest) = line.strip_prefix("--editable=") {
                Some(rest.trim())
            } else if line.starts_with("./") || line.starts_with("../") {
                Some(line)
            } else {
                None
            };

            if let Some(rel_target) = editable_target {
                let target_dir = req_dir.join(rel_target);
                let pyproj = target_dir.join("pyproject.toml");
                if pyproj.is_file() {
                    self.parse_pyproject_toml(workspace_root, &target_dir, &pyproj);
                }
                let src_dir = target_dir.join("src");
                if src_dir.is_dir() {
                    self.register_python_src_children(&src_dir);
                }
                if let Some(dir_name) = target_dir.file_name().and_then(|n| n.to_str()) {
                    self.register_python_package_dir(dir_name, &target_dir);
                }
            }
        }
    }

    fn parse_package_json(&mut self, _workspace_root: &Path, pkg_dir: &Path, pkg_json_path: &Path) {
        let Ok(content) = std::fs::read_to_string(pkg_json_path) else {
            return;
        };
        let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) else {
            return;
        };

        if let Some(name) = val.get("name").and_then(|n| n.as_str()) {
            self.node_packages
                .insert(name.to_string(), pkg_dir.to_path_buf());

            if let Some(exports) = val.get("exports") {
                let mut export_map = std::collections::HashMap::new();
                if let Some(s) = exports.as_str() {
                    export_map.insert(".".to_string(), pkg_dir.join(s));
                } else if let Some(obj) = exports.as_object() {
                    for (k, v) in obj {
                        if k.starts_with('.') {
                            if let Some(target_rel) = Self::extract_export_target(v) {
                                export_map.insert(k.clone(), pkg_dir.join(target_rel));
                            }
                        } else if let Some(target_rel) = Self::extract_export_target(exports) {
                            export_map.insert(".".to_string(), pkg_dir.join(target_rel));
                            break;
                        }
                    }
                }
                if !export_map.is_empty() {
                    self.node_exports.insert(name.to_string(), export_map);
                }
            }
        }

        // Parse Node.js subpath imports (`"imports": { "#internal/*": "./src/internal/*", ... }`)
        if let Some(imports_obj) = val.get("imports").and_then(|i| i.as_object()) {
            let mut mappings = Vec::new();
            for (k, v) in imports_obj {
                if k.starts_with('#') {
                    let mut rel_targets = Vec::new();
                    Self::collect_export_targets(v, &mut rel_targets);
                    let targets: Vec<PathBuf> =
                        rel_targets.into_iter().map(|t| pkg_dir.join(t)).collect();
                    if !targets.is_empty() {
                        mappings.push(TsPathMapping {
                            pattern: k.clone(),
                            targets,
                        });
                    }
                }
            }
            if !mappings.is_empty() {
                if let Some(existing) = self
                    .node_subpath_imports
                    .iter_mut()
                    .find(|s| s.pkg_dir == pkg_dir)
                {
                    for m in mappings {
                        if !existing.mappings.contains(&m) {
                            existing.mappings.push(m);
                        }
                    }
                } else {
                    self.node_subpath_imports.push(NodeSubpathImportScope {
                        pkg_dir: pkg_dir.to_path_buf(),
                        mappings,
                    });
                }
            }
        }

        // Check dependencies / devDependencies for file: or link: references
        for dep_section in &["dependencies", "devDependencies", "peerDependencies"] {
            if let Some(deps) = val.get(*dep_section).and_then(|d| d.as_object()) {
                for (dep_name, dep_spec) in deps {
                    if let Some(spec_str) = dep_spec.as_str() {
                        let local_rel = spec_str
                            .strip_prefix("file:")
                            .or_else(|| spec_str.strip_prefix("link:"))
                            .or_else(|| spec_str.strip_prefix("workspace:"));
                        if let Some(rel) = local_rel {
                            let trimmed_rel = rel.trim();
                            if !trimmed_rel.is_empty() && trimmed_rel != "*" && trimmed_rel != "^" && trimmed_rel != "~" {
                                let target_dir = pkg_dir.join(trimmed_rel);
                                self.node_packages.insert(dep_name.clone(), target_dir);
                            }
                        }
                    }
                }
            }
        }
    }

    fn collect_export_targets<'a>(val: &'a serde_json::Value, out: &mut Vec<&'a str>) {
        if let Some(s) = val.as_str() {
            if !out.contains(&s) {
                out.push(s);
            }
        } else if let Some(arr) = val.as_array() {
            for item in arr {
                Self::collect_export_targets(item, out);
            }
        } else if let Some(obj) = val.as_object() {
            for key in &[
                "source",
                "import",
                "module",
                "require",
                "node",
                "default",
                "development",
                "production",
            ] {
                if let Some(inner) = obj.get(*key) {
                    Self::collect_export_targets(inner, out);
                }
            }
            for (_k, v) in obj {
                Self::collect_export_targets(v, out);
            }
        }
    }

    fn extract_export_target(val: &serde_json::Value) -> Option<&str> {
        let mut targets = Vec::new();
        Self::collect_export_targets(val, &mut targets);
        targets.into_iter().next()
    }

    fn parse_pnpm_lock(&mut self, _workspace_root: &Path, lock_dir: &Path, lock_path: &Path) {
        let Ok(content) = std::fs::read_to_string(lock_path) else {
            return;
        };
        let mut current_dep: Option<String> = None;
        for raw_line in content.lines() {
            let trimmed = raw_line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            // Match direct line like `'@acme/pkg': link:packages/pkg` or `my-pkg: link:./packages/my-pkg`
            if let Some((left, right)) = trimmed.split_once(':') {
                let key = left.trim().trim_matches('\'').trim_matches('"');
                let val = right.trim().trim_matches('\'').trim_matches('"');
                if let Some(rel_path) = val.strip_prefix("link:").or_else(|| val.strip_prefix("file:")) {
                    let pkg_name = if key == "version" || key == "specifier" {
                        current_dep.clone()
                    } else {
                        Some(key.to_string())
                    };
                    if let Some(name) = pkg_name {
                        let target_dir = lock_dir.join(rel_path.trim());
                        self.node_packages.entry(name).or_insert(target_dir);
                    }
                } else if val.is_empty() && !key.is_empty() && !matches!(key, "importers" | "dependencies" | "devDependencies" | "packages" | "snapshots") {
                    current_dep = Some(key.to_string());
                }
            }
        }
    }

    fn parse_tsconfig_json(
        &mut self,
        workspace_root: &Path,
        config_dir: &Path,
        config_path: &Path,
        extends_depth: usize,
    ) {
        if extends_depth > 4 {
            return;
        }
        let Ok(raw_content) = std::fs::read_to_string(config_path) else {
            return;
        };
        let clean_json = strip_jsonc_comments_and_trailing_commas(&raw_content);
        let Ok(val) = serde_json::from_str::<serde_json::Value>(&clean_json) else {
            return;
        };

        // 1. Handle `"extends"` (string or array of strings) with bounded recursion
        if let Some(extends_val) = val.get("extends") {
            let mut parent_specs = Vec::new();
            if let Some(s) = extends_val.as_str() {
                parent_specs.push(s);
            } else if let Some(arr) = extends_val.as_array() {
                for item in arr {
                    if let Some(s) = item.as_str() {
                        parent_specs.push(s);
                    }
                }
            }
            for spec in parent_specs {
                let mut cand = config_dir.join(spec);
                if !cand.is_file() {
                    if cand.is_dir() {
                        cand = cand.join("tsconfig.json");
                    } else if cand.extension().is_none() {
                        cand = cand.with_extension("json");
                    }
                }
                if let Ok(canon_parent) = cand.canonicalize() {
                    if canon_parent.starts_with(workspace_root) {
                        if let Some(parent_dir) = canon_parent.parent() {
                            self.parse_tsconfig_json(
                                workspace_root,
                                parent_dir,
                                &canon_parent,
                                extends_depth + 1,
                            );
                        }
                    }
                }
            }
        }

        // 2. Extract `compilerOptions.baseUrl` and `compilerOptions.paths`
        if let Some(compiler_opts) = val.get("compilerOptions").and_then(|c| c.as_object()) {
            let base_dir = if let Some(base_url) = compiler_opts.get("baseUrl").and_then(|b| b.as_str()) {
                let resolved_base = config_dir.join(base_url);
                if !self.ts_base_urls.contains(&resolved_base) {
                    self.ts_base_urls.push(resolved_base.clone());
                }
                resolved_base
            } else {
                config_dir.to_path_buf()
            };

            if let Some(paths_obj) = compiler_opts.get("paths").and_then(|p| p.as_object()) {
                for (pattern, targets_val) in paths_obj {
                    let Some(targets_arr) = targets_val.as_array() else {
                        continue;
                    };
                    let mut targets = Vec::new();
                    for item in targets_arr {
                        if let Some(rel_target) = item.as_str() {
                            targets.push(base_dir.join(rel_target));
                        }
                    }
                    if !targets.is_empty() {
                        let mapping = TsPathMapping {
                            pattern: pattern.clone(),
                            targets,
                        };
                        if !self.ts_path_mappings.contains(&mapping) {
                            self.ts_path_mappings.push(mapping);
                        }
                    }
                }
            }
        }

        // 3. Handle TypeScript composite project `"references"` (`[{ "path": "../pkg-b" }, ...]`)
        if let Some(refs_arr) = val.get("references").and_then(|r| r.as_array()) {
            for ref_item in refs_arr {
                let Some(ref_path_str) = ref_item.get("path").and_then(|p| p.as_str()) else {
                    continue;
                };
                let mut cand = config_dir.join(ref_path_str);
                if cand.is_dir() {
                    cand = cand.join("tsconfig.json");
                } else if !cand.is_file() && cand.extension().is_none() {
                    cand = cand.with_extension("json");
                }
                let Ok(canon_ref) = cand.canonicalize() else {
                    continue;
                };
                // Enforce workspace root boundary on project references
                if !canon_ref.starts_with(workspace_root) {
                    continue;
                }
                let Some(ref_dir) = canon_ref.parent() else {
                    continue;
                };
                if !self.ts_project_references.contains(&ref_dir.to_path_buf()) {
                    self.ts_project_references.push(ref_dir.to_path_buf());
                }
                if let Some(dir_name) = ref_dir.file_name().and_then(|n| n.to_str()) {
                    self.node_packages
                        .entry(dir_name.to_string())
                        .or_insert_with(|| ref_dir.to_path_buf());
                }
                let ref_pkg_json = ref_dir.join("package.json");
                if ref_pkg_json.is_file() {
                    self.parse_package_json(workspace_root, ref_dir, &ref_pkg_json);
                }
                self.parse_tsconfig_json(workspace_root, ref_dir, &canon_ref, extends_depth + 1);
            }
        }
    }
}

/// Strip `//` line comments, `/* ... */` block comments, and trailing commas outside string literals
/// so `tsconfig.json` and `jsconfig.json` (JSONC) files parse cleanly with `serde_json`.
pub fn strip_jsonc_comments_and_trailing_commas(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut no_comments = String::with_capacity(input.len());
    let mut i = 0;
    let mut in_string = false;

    while i < chars.len() {
        let c = chars[i];
        if in_string {
            no_comments.push(c);
            if c == '\\' && i + 1 < chars.len() {
                no_comments.push(chars[i + 1]);
                i += 2;
                continue;
            }
            if c == '"' {
                in_string = false;
            }
            i += 1;
            continue;
        }

        if c == '"' {
            in_string = true;
            no_comments.push(c);
            i += 1;
            continue;
        }

        if c == '/' && i + 1 < chars.len() && chars[i + 1] == '/' {
            i += 2;
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }

        if c == '/' && i + 1 < chars.len() && chars[i + 1] == '*' {
            i += 2;
            while i + 1 < chars.len() && !(chars[i] == '*' && chars[i + 1] == '/') {
                i += 1;
            }
            i = (i + 2).min(chars.len());
            continue;
        }

        no_comments.push(c);
        i += 1;
    }

    let nc_chars: Vec<char> = no_comments.chars().collect();
    let mut out = String::with_capacity(no_comments.len());
    let mut j = 0;
    let mut in_str = false;
    while j < nc_chars.len() {
        let c = nc_chars[j];
        if in_str {
            out.push(c);
            if c == '\\' && j + 1 < nc_chars.len() {
                out.push(nc_chars[j + 1]);
                j += 2;
                continue;
            }
            if c == '"' {
                in_str = false;
            }
            j += 1;
            continue;
        }
        if c == '"' {
            in_str = true;
            out.push(c);
            j += 1;
            continue;
        }
        if c == ',' {
            let mut look = j + 1;
            while look < nc_chars.len() && nc_chars[look].is_whitespace() {
                look += 1;
            }
            if look < nc_chars.len() && matches!(nc_chars[look], '}' | ']') {
                j += 1;
                continue;
            }
        }
        out.push(c);
        j += 1;
    }
    out
}

/// Transitive AST Import Graph Resolver for local Python and Node/JavaScript packages.
#[derive(Debug, Clone)]
pub struct TransitiveImportResolver {
    workspace_root: PathBuf,
    max_depth: usize,
    max_files: usize,
    manifest_index: WorkspaceManifestIndex,
}

impl TransitiveImportResolver {
    pub const DEFAULT_MAX_DEPTH: usize = 8;
    pub const DEFAULT_MAX_FILES: usize = 32;

    pub fn new(workspace_root: impl Into<PathBuf>) -> Self {
        let root = workspace_root.into();
        let canonical = root.canonicalize().unwrap_or(root);
        let manifest_index = WorkspaceManifestIndex::discover(&canonical);
        Self {
            workspace_root: canonical,
            max_depth: Self::DEFAULT_MAX_DEPTH,
            max_files: Self::DEFAULT_MAX_FILES,
            manifest_index,
        }
    }

    pub fn with_limits(mut self, max_depth: usize, max_files: usize) -> Self {
        self.max_depth = max_depth;
        self.max_files = max_files;
        self
    }

    pub fn workspace_root(&self) -> &Path {
        &self.workspace_root
    }

    pub fn manifest_index(&self) -> &WorkspaceManifestIndex {
        &self.manifest_index
    }

    /// Resolve transitive capabilities for a Python snippet or entry file.
    pub fn resolve_python(&self, script: &str, current_file: Option<&Path>) -> CapabilityReport {
        let mut report = CapabilityReport::default();
        let mut visited = HashSet::new();
        self.resolve_python_internal(script, current_file, 0, &mut visited, &mut report);
        report
    }

    /// Resolve transitive capabilities for a JavaScript/TypeScript/Node snippet or entry file.
    pub fn resolve_javascript(&self, script: &str, current_file: Option<&Path>) -> CapabilityReport {
        let mut report = CapabilityReport::default();
        let mut visited = HashSet::new();
        self.resolve_javascript_internal(script, current_file, 0, &mut visited, &mut report);
        report
    }

    /// General entrypoint resolving by language.
    pub fn resolve_script(&self, script: &str, lang: &str, current_file: Option<&Path>) -> CapabilityReport {
        match lang {
            "python" | "py" => self.resolve_python(script, current_file),
            "javascript" | "js" | "node" | "typescript" | "ts" | "tsx" | "jsx" | "mjs" | "cjs" => {
                self.resolve_javascript(script, current_file)
            }
            _ => {
                let caps = DefaultAstCapabilityExtractor.extract_capabilities(script, lang);
                CapabilityReport {
                    capabilities: caps,
                    ..Default::default()
                }
            }
        }
    }

    fn resolve_python_internal(
        &self,
        script: &str,
        current_file: Option<&Path>,
        depth: usize,
        visited: &mut HashSet<PathBuf>,
        report: &mut CapabilityReport,
    ) {
        if depth > self.max_depth || visited.len() >= self.max_files {
            report.limit_exceeded = true;
            return;
        }

        let direct_caps = crate::python::extract_capabilities(script);
        report.capabilities.union(direct_caps);

        let (imports, ast_caps) = match collect_python_imports(script) {
            Ok(res) => res,
            Err(err) => {
                report.unresolved_imports.push(err);
                return;
            }
        };
        report.capabilities.union(ast_caps);

        for spec in imports {
            let candidates = resolve_python_import_candidates(
                &spec,
                current_file,
                &self.workspace_root,
                &self.manifest_index,
            );
            let mut resolved_path = None;
            for cand in candidates {
                if cand.is_file() {
                    resolved_path = Some(cand);
                    break;
                }
            }

            if let Some(cand_file) = resolved_path {
                let canonical = match cand_file.canonicalize() {
                    Ok(c) => c,
                    Err(_) => {
                        report.unresolved_imports.push(cand_file.display().to_string());
                        continue;
                    }
                };

                // Root Invariant: forbid escaping outside the workspace
                if !canonical.starts_with(&self.workspace_root) {
                    report.unresolved_imports.push(format!("escaped: {}", canonical.display()));
                    continue;
                }

                // Cycle detection
                if visited.contains(&canonical) {
                    report.cycle_detected = true;
                    continue;
                }

                visited.insert(canonical.clone());
                report.resolved_files.push(canonical.clone());

                if let Ok(content) = std::fs::read_to_string(&canonical) {
                    self.resolve_python_internal(&content, Some(&canonical), depth + 1, visited, report);
                } else {
                    report.unresolved_imports.push(format!("unreadable: {}", canonical.display()));
                }
            } else if spec.level > 0 {
                // Relative import failed to resolve on disk
                let mod_desc = spec.module.as_deref().unwrap_or("<current>");
                report.unresolved_imports.push(format!("relative_import: level={}, module={}", spec.level, mod_desc));
            }
        }
    }

    fn resolve_javascript_internal(
        &self,
        script: &str,
        current_file: Option<&Path>,
        depth: usize,
        visited: &mut HashSet<PathBuf>,
        report: &mut CapabilityReport,
    ) {
        if depth > self.max_depth || visited.len() >= self.max_files {
            report.limit_exceeded = true;
            return;
        }

        let direct_caps = crate::javascript::extract_capabilities(script);
        report.capabilities.union(direct_caps);

        let imports = match collect_javascript_imports(script) {
            Ok(imps) => imps,
            Err(err) => {
                report.unresolved_imports.push(err);
                return;
            }
        };

        for spec in imports {
            let is_relative_or_local = spec.starts_with("./")
                || spec.starts_with("../")
                || spec.starts_with('/')
                || spec.starts_with('#')
                || self.manifest_index.matches_ts_alias(&spec);
            let candidates = resolve_javascript_import_candidates(
                &spec,
                current_file,
                &self.workspace_root,
                &self.manifest_index,
            );
            let mut resolved_path = None;
            let mut escaped_candidate = None;
            for cand in &candidates {
                let norm = normalize_lexical_path(cand);
                if !norm.starts_with(&self.workspace_root) && escaped_candidate.is_none() {
                    escaped_candidate = Some(norm);
                }
                if cand.is_file() {
                    resolved_path = Some(cand.clone());
                    break;
                }
            }

            if let Some(cand_file) = resolved_path {
                let canonical = match cand_file.canonicalize() {
                    Ok(c) => c,
                    Err(_) => {
                        report.unresolved_imports.push(cand_file.display().to_string());
                        continue;
                    }
                };

                // Root Invariant: forbid escaping outside the workspace
                if !canonical.starts_with(&self.workspace_root) {
                    report.unresolved_imports.push(format!("escaped: {}", canonical.display()));
                    continue;
                }

                // Cycle detection
                if visited.contains(&canonical) {
                    report.cycle_detected = true;
                    continue;
                }

                visited.insert(canonical.clone());
                report.resolved_files.push(canonical.clone());

                if let Ok(content) = std::fs::read_to_string(&canonical) {
                    self.resolve_javascript_internal(&content, Some(&canonical), depth + 1, visited, report);
                } else {
                    report.unresolved_imports.push(format!("unreadable: {}", canonical.display()));
                }
            } else if let Some(escaped) = escaped_candidate {
                report.unresolved_imports.push(format!("escaped: {}", escaped.display()));
            } else if is_relative_or_local {
                report.unresolved_imports.push(format!("local_import: {spec}"));
            }
        }
    }
}

fn normalize_lexical_path(p: &Path) -> PathBuf {
    use std::path::Component;
    let normalized_buf: PathBuf;
    let target: &Path = if std::path::MAIN_SEPARATOR == '\\' {
        let lossy = p.to_string_lossy();
        if lossy.contains('/') {
            normalized_buf = PathBuf::from(lossy.replace('/', "\\"));
            &normalized_buf
        } else {
            p
        }
    } else {
        p
    };
    let mut out = PathBuf::new();
    for comp in target.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn replace_wildcard_in_template(target_tpl: &Path, matched: &str) -> PathBuf {
    let tpl_str = target_tpl.to_string_lossy();
    let raw = if tpl_str.contains('*') {
        PathBuf::from(tpl_str.replace('*', matched))
    } else {
        target_tpl.join(matched)
    };
    normalize_lexical_path(&raw)
}

#[derive(Debug, Clone)]
struct PythonImportSpecifier {
    level: u32,
    module: Option<String>,
    imported_names: Vec<String>,
}

fn collect_python_imports(src: &str) -> Result<(Vec<PythonImportSpecifier>, CapabilitySet), String> {
    use ruff_python_ast as ast;
    use ruff_python_ast::visitor::{self as py_visitor, Visitor as PyVisitor};

    let parsed = match ruff_python_parser::parse_module(src) {
        Ok(parsed) if parsed.has_no_syntax_errors() => parsed.into_syntax(),
        Ok(_) => return Err("syntax_errors".to_string()),
        Err(e) => return Err(format!("parse_error: {e}")),
    };

    struct ImportVisitor {
        imports: Vec<PythonImportSpecifier>,
        caps: CapabilitySet,
    }

    impl<'a> PyVisitor<'a> for ImportVisitor {
        fn visit_stmt(&mut self, stmt: &'a ast::Stmt) {
            match stmt {
                ast::Stmt::Import(import_stmt) => {
                    for alias in &import_stmt.names {
                        self.imports.push(PythonImportSpecifier {
                            level: 0,
                            module: Some(alias.name.to_string()),
                            imported_names: Vec::new(),
                        });
                    }
                }
                ast::Stmt::ImportFrom(from_stmt) => {
                    let level = from_stmt.level;
                    let module = from_stmt.module.as_ref().map(|m| m.to_string());
                    let imported_names = from_stmt.names.iter().map(|a| a.name.to_string()).collect();
                    self.imports.push(PythonImportSpecifier {
                        level,
                        module,
                        imported_names,
                    });
                }
                _ => {}
            }
            py_visitor::walk_stmt(self, stmt);
        }

        fn visit_expr(&mut self, expr: &'a ast::Expr) {
            if let ast::Expr::Call(call) = expr {
                if let ast::Expr::Name(name) = call.func.as_ref() {
                    if matches!(name.id.as_str(), "eval" | "exec" | "compile") {
                        self.caps.dynamic_eval = true;
                    }
                }
            }
            py_visitor::walk_expr(self, expr);
        }
    }

    let mut visitor = ImportVisitor {
        imports: Vec::new(),
        caps: CapabilitySet::EMPTY,
    };
    for stmt in &parsed.body {
        visitor.visit_stmt(stmt);
    }
    Ok((visitor.imports, visitor.caps))
}

fn resolve_python_import_candidates(
    spec: &PythonImportSpecifier,
    current_file: Option<&Path>,
    workspace_root: &Path,
    manifest_index: &WorkspaceManifestIndex,
) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    let current_dir = current_file.and_then(|p| p.parent()).unwrap_or(workspace_root);

    if spec.level > 0 {
        let mut base_dir = current_dir;
        let mut valid = true;
        for _ in 1..spec.level {
            if let Some(parent) = base_dir.parent() {
                base_dir = parent;
            } else {
                valid = false;
                break;
            }
        }
        if valid {
            if let Some(ref mod_name) = spec.module {
                let rel_path = mod_name.replace('.', "/");
                candidates.push(base_dir.join(format!("{}.py", rel_path)));
                candidates.push(base_dir.join(&rel_path).join("__init__.py"));
                for name in &spec.imported_names {
                    candidates.push(base_dir.join(&rel_path).join(format!("{}.py", name)));
                    candidates.push(base_dir.join(&rel_path).join(name).join("__init__.py"));
                }
            } else {
                for name in &spec.imported_names {
                    candidates.push(base_dir.join(format!("{}.py", name)));
                    candidates.push(base_dir.join(name).join("__init__.py"));
                }
            }
        }
    } else if let Some(ref mod_name) = spec.module {
        let rel_path = mod_name.replace('.', "/");
        for base in &[current_dir, workspace_root] {
            candidates.push(base.join(format!("{}.py", rel_path)));
            candidates.push(base.join(&rel_path).join("__init__.py"));
            for name in &spec.imported_names {
                candidates.push(base.join(&rel_path).join(format!("{}.py", name)));
                candidates.push(base.join(&rel_path).join(name).join("__init__.py"));
            }
        }

        // Consult WorkspaceManifestIndex for src-layout / editable / workspace packages
        let (first_seg, rest_opt) = match mod_name.split_once('.') {
            Some((first, rest)) => (first, Some(rest.replace('.', "/"))),
            None => (mod_name.as_str(), None),
        };
        let norm_first = WorkspaceManifestIndex::normalize_py_name(first_seg);
        if let Some(pkg_dir) = manifest_index
            .python_packages
            .get(first_seg)
            .or_else(|| manifest_index.python_packages.get(&norm_first))
        {
            match rest_opt {
                None => {
                    candidates.push(pkg_dir.with_extension("py"));
                    candidates.push(pkg_dir.join("__init__.py"));
                    for name in &spec.imported_names {
                        candidates.push(pkg_dir.join(format!("{}.py", name)));
                        candidates.push(pkg_dir.join(name).join("__init__.py"));
                    }
                }
                Some(rest_rel) => {
                    candidates.push(pkg_dir.join(format!("{}.py", rest_rel)));
                    candidates.push(pkg_dir.join(&rest_rel).join("__init__.py"));
                    for name in &spec.imported_names {
                        candidates.push(pkg_dir.join(&rest_rel).join(format!("{}.py", name)));
                        candidates.push(pkg_dir.join(&rest_rel).join(name).join("__init__.py"));
                    }
                }
            }
        }
    }

    candidates
}

fn collect_javascript_imports(src: &str) -> Result<Vec<String>, String> {
    use oxc_allocator::Allocator;
    use oxc_ast_visit::{walk, Visit};
    use oxc_parser::{ParseOptions, Parser};
    use oxc_span::SourceType;

    let allocator = Allocator::default();
    let source_type = SourceType::mjs().with_typescript(true).with_jsx(true);
    let options = ParseOptions {
        parse_regular_expression: false,
        allow_return_outside_function: true,
        ..ParseOptions::default()
    };

    let ret = Parser::new(&allocator, src, source_type)
        .with_options(options)
        .parse();

    if !ret.diagnostics.is_empty() {
        return Err("syntax_errors".to_string());
    }

    struct JsImportVisitor<'a> {
        imports: Vec<String>,
        _phantom: std::marker::PhantomData<&'a ()>,
    }

    impl<'a> Visit<'a> for JsImportVisitor<'a> {
        fn visit_import_declaration(&mut self, decl: &oxc_ast::ast::ImportDeclaration<'a>) {
            self.imports.push(decl.source.value.to_string());
            walk::walk_import_declaration(self, decl);
        }

        fn visit_export_all_declaration(&mut self, decl: &oxc_ast::ast::ExportAllDeclaration<'a>) {
            self.imports.push(decl.source.value.to_string());
            walk::walk_export_all_declaration(self, decl);
        }

        fn visit_call_expression(&mut self, expr: &oxc_ast::ast::CallExpression<'a>) {
            if let oxc_ast::ast::Expression::Identifier(ident) = &expr.callee {
                if ident.name == "require" {
                    if let Some(arg) = expr.arguments.first() {
                        if let Some(oxc_ast::ast::Expression::StringLiteral(s)) = arg.as_expression() {
                            self.imports.push(s.value.to_string());
                        }
                    }
                }
            }
            walk::walk_call_expression(self, expr);
        }
    }

    let mut visitor = JsImportVisitor {
        imports: Vec::new(),
        _phantom: std::marker::PhantomData,
    };
    visitor.visit_program(&ret.program);
    Ok(visitor.imports)
}

fn push_js_target_candidates(candidates: &mut Vec<PathBuf>, raw_target: &Path) {
    let norm_target = normalize_lexical_path(raw_target);
    let target = norm_target.as_path();

    // 1. Direct path
    candidates.push(target.to_path_buf());

    // TypeScript ESM / composite fallback: if target ends in .js/.mjs/.cjs, also probe .ts/.tsx
    if let Some(ext) = target.extension().and_then(|e| e.to_str()) {
        if matches!(ext, "js" | "mjs" | "cjs") {
            candidates.push(target.with_extension("ts"));
            candidates.push(target.with_extension("tsx"));
        }
    }
    // If target path contains a /dist/ or /build/ segment, also probe the /src/ equivalent
    let target_lossy = target.to_string_lossy();
    for (out_seg, src_seg) in &[
        ("/dist/", "/src/"),
        ("\\dist\\", "\\src\\"),
        ("/build/", "/src/"),
        ("\\build\\", "\\src\\"),
    ] {
        if target_lossy.contains(out_seg) {
            let src_equiv = normalize_lexical_path(Path::new(&target_lossy.replacen(out_seg, src_seg, 1)));
            candidates.push(src_equiv.clone());
            candidates.push(src_equiv.with_extension("ts"));
            candidates.push(src_equiv.with_extension("tsx"));
            candidates.push(src_equiv.with_extension("js"));
        }
    }

    // 2. Common extensions
    for ext in &[".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs", ".json"] {
        let mut with_ext = target.as_os_str().to_os_string();
        with_ext.push(ext);
        candidates.push(PathBuf::from(with_ext));
    }

    // 3. Directory index files
    for idx in &[
        "index.js",
        "index.ts",
        "index.tsx",
        "index.jsx",
        "index.mjs",
        "index.cjs",
        "src/index.js",
        "src/index.ts",
        "src/index.tsx",
        "src/index.jsx",
        "src/index.mjs",
    ] {
        candidates.push(target.join(idx));
    }

    // 4. package.json main / module / exports field
    let pkg_json = target.join("package.json");
    if pkg_json.is_file() {
        if let Ok(content) = std::fs::read_to_string(&pkg_json) {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(exports) = val.get("exports") {
                    if let Some(s) = exports.as_str() {
                        candidates.push(target.join(s));
                    } else if let Some(obj) = exports.as_object() {
                        if let Some(dot_val) = obj.get(".") {
                            if let Some(s) = WorkspaceManifestIndex::extract_export_target(dot_val) {
                                candidates.push(target.join(s));
                            }
                        } else if let Some(s) = WorkspaceManifestIndex::extract_export_target(exports) {
                            candidates.push(target.join(s));
                        }
                    }
                }
                if let Some(main) = val.get("main").and_then(|m| m.as_str()) {
                    let main_path = target.join(main);
                    candidates.push(main_path.clone());
                    for ext in &[".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs"] {
                        let mut with_ext = main_path.clone().into_os_string();
                        with_ext.push(ext);
                        candidates.push(PathBuf::from(with_ext));
                    }
                }
                if let Some(module) = val.get("module").and_then(|m| m.as_str()) {
                    candidates.push(target.join(module));
                }
            }
        }
    }
}

fn split_node_package_specifier(spec: &str) -> (&str, Option<&str>) {
    if spec.starts_with('@') {
        let mut slash_indices = spec.match_indices('/').map(|(i, _)| i);
        let _first_slash = slash_indices.next();
        if let Some(second_slash) = slash_indices.next() {
            (&spec[..second_slash], Some(&spec[second_slash + 1..]))
        } else {
            (spec, None)
        }
    } else if let Some((pkg, sub)) = spec.split_once('/') {
        (pkg, Some(sub))
    } else {
        (spec, None)
    }
}

fn apply_path_mappings_to_candidates(
    trimmed: &str,
    mappings: &[TsPathMapping],
    candidates: &mut Vec<PathBuf>,
) {
    for mapping in mappings {
        if let Some((prefix, suffix)) = mapping.pattern.split_once('*') {
            if trimmed.starts_with(prefix)
                && trimmed.ends_with(suffix)
                && trimmed.len() >= prefix.len() + suffix.len()
            {
                let matched = &trimmed[prefix.len()..trimmed.len() - suffix.len()];
                for target_tpl in &mapping.targets {
                    let resolved = replace_wildcard_in_template(target_tpl, matched);
                    push_js_target_candidates(candidates, &resolved);
                }
            }
        } else if trimmed == mapping.pattern {
            for target_path in &mapping.targets {
                push_js_target_candidates(candidates, target_path);
            }
        } else if let Some(sub) = trimmed.strip_prefix(&format!("{}/", mapping.pattern)) {
            for target_path in &mapping.targets {
                push_js_target_candidates(candidates, &target_path.join(sub));
            }
        }
    }
}

fn resolve_javascript_import_candidates(
    specifier: &str,
    current_file: Option<&Path>,
    workspace_root: &Path,
    manifest_index: &WorkspaceManifestIndex,
) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    let trimmed = specifier.trim();

    if trimmed.starts_with('#') {
        // Node.js package.json `"imports"` subpath imports (`#internal/*`)
        // Prioritize enclosing package scopes (deepest pkg_dir first), then fallback to workspace scopes.
        let mut enclosing_scopes: Vec<&NodeSubpathImportScope> = Vec::new();
        let mut other_scopes: Vec<&NodeSubpathImportScope> = Vec::new();
        for scope in &manifest_index.node_subpath_imports {
            if let Some(cf) = current_file {
                if cf.starts_with(&scope.pkg_dir) {
                    enclosing_scopes.push(scope);
                    continue;
                }
            }
            other_scopes.push(scope);
        }
        enclosing_scopes.sort_by(|a, b| b.pkg_dir.as_os_str().len().cmp(&a.pkg_dir.as_os_str().len()));
        for scope in enclosing_scopes.into_iter().chain(other_scopes.into_iter()) {
            apply_path_mappings_to_candidates(trimmed, &scope.mappings, &mut candidates);
        }
        return candidates;
    }

    let is_relative = trimmed.starts_with("./") || trimmed.starts_with("../") || trimmed.starts_with('/');

    if !is_relative {
        // 1. Consult tsconfig.json / jsconfig.json compilerOptions.paths aliases
        apply_path_mappings_to_candidates(trimmed, &manifest_index.ts_path_mappings, &mut candidates);

        // 2. Consult tsconfig.json / jsconfig.json compilerOptions.baseUrl
        for base_url in &manifest_index.ts_base_urls {
            push_js_target_candidates(&mut candidates, &base_url.join(trimmed));
        }

        // 3. Consult Node workspace packages and package.json exports
        let (pkg_name, subpath_opt) = split_node_package_specifier(trimmed);
        let export_key = match subpath_opt {
            Some(sub) => format!("./{sub}"),
            None => ".".to_string(),
        };

        if let Some(exports_map) = manifest_index.node_exports.get(pkg_name) {
            if let Some(export_target) = exports_map.get(&export_key) {
                push_js_target_candidates(&mut candidates, export_target);
            }
            if let Some(sub) = subpath_opt {
                for (pat_key, pat_target) in exports_map {
                    if let Some(prefix) = pat_key.strip_prefix("./").and_then(|k| k.strip_suffix('*')) {
                        if let Some(matched_wildcard) = sub.strip_prefix(prefix) {
                            let resolved = replace_wildcard_in_template(pat_target, matched_wildcard);
                            push_js_target_candidates(&mut candidates, &resolved);
                        }
                    }
                }
            }
        }

        if let Some(pkg_dir) = manifest_index.node_packages.get(pkg_name) {
            match subpath_opt {
                None => {
                    push_js_target_candidates(&mut candidates, pkg_dir);
                }
                Some(sub) => {
                    push_js_target_candidates(&mut candidates, &pkg_dir.join(sub));
                    push_js_target_candidates(&mut candidates, &pkg_dir.join("src").join(sub));
                }
            }
        }
    }

    let target = if trimmed.starts_with("./") || trimmed.starts_with("../") {
        let base_dir = current_file.and_then(|p| p.parent()).unwrap_or(workspace_root);
        base_dir.join(trimmed)
    } else if trimmed.starts_with('/') {
        workspace_root.join(trimmed.trim_start_matches('/'))
    } else {
        workspace_root.join(trimmed)
    };

    push_js_target_candidates(&mut candidates, &target);

    candidates
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
            "python" | "py" => {
                let mut caps = crate::python::extract_capabilities(trimmed);
                if let Ok((_, ast_caps)) = collect_python_imports(trimmed) {
                    caps.union(ast_caps);
                }
                caps
            }
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
                        let resolver = TransitiveImportResolver::new(".");
                        let report = resolver.resolve_script(&unquoted_script, script_lang, None);
                        caps.union(report.capabilities);
                    }
                } else if is_python && unquoted_arg.starts_with("-c") && unquoted_arg.len() > 2 {
                    let script = crate::paths::unquote_snippet(&unquoted_arg[2..]);
                    let resolver = TransitiveImportResolver::new(".");
                    let report = resolver.resolve_script(&script, "python", None);
                    caps.union(report.capabilities);
                } else if is_node && unquoted_arg.starts_with("-e") && unquoted_arg.len() > 2 {
                    let script = crate::paths::unquote_snippet(&unquoted_arg[2..]);
                    let resolver = TransitiveImportResolver::new(".");
                    let report = resolver.resolve_script(&script, "javascript", None);
                    caps.union(report.capabilities);
                } else if !arg.starts_with('-') {
                    let path = std::path::Path::new(arg);
                    if path.is_file() {
                        let script_lang = if is_python { "python" } else { "javascript" };
                        if let Ok(content) = std::fs::read_to_string(path) {
                            let resolver = TransitiveImportResolver::new(".");
                            let report = resolver.resolve_script(&content, script_lang, Some(path));
                            caps.union(report.capabilities);
                        }
                    }
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
