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

/// Transitive AST Import Graph Resolver for local Python and Node/JavaScript packages.
#[derive(Debug, Clone)]
pub struct TransitiveImportResolver {
    workspace_root: PathBuf,
    max_depth: usize,
    max_files: usize,
}

impl TransitiveImportResolver {
    pub const DEFAULT_MAX_DEPTH: usize = 8;
    pub const DEFAULT_MAX_FILES: usize = 32;

    pub fn new(workspace_root: impl Into<PathBuf>) -> Self {
        let root = workspace_root.into();
        let canonical = root.canonicalize().unwrap_or(root);
        Self {
            workspace_root: canonical,
            max_depth: Self::DEFAULT_MAX_DEPTH,
            max_files: Self::DEFAULT_MAX_FILES,
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
            "javascript" | "js" | "node" | "typescript" | "ts" | "mjs" | "cjs" => {
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
            let candidates = resolve_python_import_candidates(&spec, current_file, &self.workspace_root);
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
            let is_relative_or_local = spec.starts_with("./") || spec.starts_with("../") || spec.starts_with('/');
            let candidates = resolve_javascript_import_candidates(&spec, current_file, &self.workspace_root);
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
                    self.resolve_javascript_internal(&content, Some(&canonical), depth + 1, visited, report);
                } else {
                    report.unresolved_imports.push(format!("unreadable: {}", canonical.display()));
                }
            } else if is_relative_or_local {
                report.unresolved_imports.push(format!("local_import: {spec}"));
            }
        }
    }
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
    }

    candidates
}

fn collect_javascript_imports(src: &str) -> Result<Vec<String>, String> {
    use oxc_allocator::Allocator;
    use oxc_ast_visit::{walk, Visit};
    use oxc_parser::{ParseOptions, Parser};
    use oxc_span::SourceType;

    let allocator = Allocator::default();
    let source_type = SourceType::mjs().with_typescript(true);
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

fn resolve_javascript_import_candidates(
    specifier: &str,
    current_file: Option<&Path>,
    workspace_root: &Path,
) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    let trimmed = specifier.trim();

    let target = if trimmed.starts_with("./") || trimmed.starts_with("../") {
        let base_dir = current_file.and_then(|p| p.parent()).unwrap_or(workspace_root);
        base_dir.join(trimmed)
    } else if trimmed.starts_with('/') {
        workspace_root.join(trimmed.trim_start_matches('/'))
    } else {
        workspace_root.join(trimmed)
    };

    // 1. Direct path
    candidates.push(target.clone());

    // 2. Common extensions
    for ext in &[".js", ".ts", ".mjs", ".cjs", ".json"] {
        let mut with_ext = target.clone().into_os_string();
        with_ext.push(ext);
        candidates.push(PathBuf::from(with_ext));
    }

    // 3. Directory index files
    for idx in &["index.js", "index.ts", "index.mjs", "index.cjs"] {
        candidates.push(target.join(idx));
    }

    // 4. package.json main / module field
    let pkg_json = target.join("package.json");
    if pkg_json.is_file() {
        if let Ok(content) = std::fs::read_to_string(&pkg_json) {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(main) = val.get("main").and_then(|m| m.as_str()) {
                    let main_path = target.join(main);
                    candidates.push(main_path.clone());
                    for ext in &[".js", ".ts", ".mjs", ".cjs"] {
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
