//! Automated Cross-Language Capability Propagation.
//!
//! Models host and environment capabilities (`network`, `external_paths`, `daemon`)
//! and computes transitive capability sets across complex multi-language execution
//! trees (e.g. bash scripts invoking python snippets that launch subprocesses or container CLIs).

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

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

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct PythonImportSpecifier {
    level: u32,
    module: Option<String>,
    imported_names: Vec<String>,
    path_target: Option<String>,
    dynamic_source: Option<String>,
}

/// Extract AST-level Python capabilities including dynamic import and module execution calls.
pub fn extract_python_ast_capabilities(src: &str) -> CapabilitySet {
    match collect_python_imports(src) {
        Ok((imports, mut caps)) => {
            for spec in imports {
                if let Some(ref mod_name) = spec.module {
                    let first_seg = mod_name.split('.').next().unwrap_or(mod_name.as_str());
                    let norm = normalize_py_name(first_seg);
                    caps.union(classify_python_dependency_capabilities(&norm));
                }
            }
            caps
        }
        Err(_) => CapabilitySet::EMPTY,
    }
}

fn check_python_builtin_module_capabilities(
    mod_name: &str,
    imported_names: &[String],
    caps: &mut CapabilitySet,
) {
    let top = mod_name.split('.').next().unwrap_or(mod_name);
    match top {
        "socket" | "http" | "urllib" | "requests" | "httpx" | "aiohttp" | "ftplib" | "asyncio" => {
            caps.network = true;
        }
        "multiprocessing" | "pty" | "daemon" => {
            caps.daemon = true;
        }
        "shutil" | "tempfile" => {
            caps.external_paths = true;
        }
        "ctypes" | "_ctypes" | "cffi" | "_cffi_backend" => {
            caps.external_paths = true;
            caps.daemon = true;
        }
        _ => {}
    }
    let norm = normalize_py_name(top);
    caps.union(classify_python_dependency_capabilities(&norm));
    if mod_name == "os" {
        for name in imported_names {
            if matches!(
                name.as_str(),
                "system" | "popen" | "spawnl" | "spawnlp" | "spawnv" | "spawnvp"
            ) {
                caps.daemon = true;
            }
        }
    } else if mod_name == "subprocess" {
        for name in imported_names {
            if name == "Popen" {
                caps.daemon = true;
            }
        }
    }
}

fn resolve_relative_python_module(level: u32, rest: &str, package: &str) -> Option<String> {
    if level == 0 {
        return Some(rest.to_string());
    }
    let segs: Vec<&str> = package.split('.').filter(|s| !s.is_empty()).collect();
    if segs.len() < level as usize {
        return None;
    }
    let keep = segs.len() - (level as usize - 1);
    let base = segs[..keep].join(".");
    if rest.is_empty() {
        Some(base)
    } else {
        Some(format!("{base}.{rest}"))
    }
}

fn collect_python_imports(src: &str) -> Result<(Vec<PythonImportSpecifier>, CapabilitySet), String> {
    use ruff_python_ast as ast;
    use ruff_python_ast::visitor::{self as py_visitor, Visitor as PyVisitor};

    let parsed = match ruff_python_parser::parse_module(src) {
        Ok(parsed) if parsed.has_no_syntax_errors() => parsed.into_syntax(),
        Ok(_) => return Err("syntax_errors".to_string()),
        Err(e) => return Err(format!("parse_error: {e}")),
    };

    fn eval_static_str(
        expr: &ast::Expr,
        string_vars: &HashMap<String, Option<String>>,
    ) -> Option<String> {
        match expr {
            ast::Expr::StringLiteral(s) => Some(s.value.to_str().to_string()),
            ast::Expr::Name(n) => string_vars.get(n.id.as_str()).and_then(|v| v.clone()),
            ast::Expr::BinOp(bin) if matches!(bin.op, ast::Operator::Add) => {
                let left = eval_static_str(&bin.left, string_vars)?;
                let right = eval_static_str(&bin.right, string_vars)?;
                Some(format!("{left}{right}"))
            }
            ast::Expr::FString(fstr) => {
                let mut out = String::new();
                for part in fstr.value.iter() {
                    match part {
                        ast::FStringPart::Literal(lit) => out.push_str(lit),
                        ast::FStringPart::FString(inner) => {
                            for elem in &inner.elements {
                                match elem {
                                    ast::InterpolatedStringElement::Literal(lit) => {
                                        out.push_str(&lit.value);
                                    }
                                    ast::InterpolatedStringElement::Interpolation(interp) => {
                                        let val = eval_static_str(&interp.expression, string_vars)?;
                                        out.push_str(&val);
                                    }
                                }
                            }
                        }
                    }
                }
                Some(out)
            }
            _ => None,
        }
    }

    fn eval_static_u32(expr: &ast::Expr) -> Option<u32> {
        if let ast::Expr::NumberLiteral(num) = expr {
            if let ast::Number::Int(int_val) = &num.value {
                return int_val.to_string().parse::<u32>().ok();
            }
        }
        None
    }

    fn extract_dotted_expr(expr: &ast::Expr) -> Option<String> {
        match expr {
            ast::Expr::Name(n) => Some(n.id.to_string()),
            ast::Expr::Attribute(attr) => {
                let prefix = extract_dotted_expr(&attr.value)?;
                Some(format!("{prefix}.{}", attr.attr))
            }
            _ => None,
        }
    }

    fn resolve_call_head(
        func: &ast::Expr,
        import_aliases: &HashMap<String, String>,
    ) -> Option<String> {
        let raw = extract_dotted_expr(func)?;
        if let Some((root, rest)) = raw.split_once('.') {
            if let Some(mapped) = import_aliases.get(root) {
                return Some(format!("{mapped}.{rest}"));
            }
            Some(raw)
        } else {
            Some(import_aliases.get(&raw).cloned().unwrap_or(raw))
        }
    }

    fn extract_call_arg<'a>(
        call: &'a ast::ExprCall,
        pos: usize,
        kw_name: &str,
    ) -> Option<&'a ast::Expr> {
        if let Some(arg) = call.arguments.args.get(pos) {
            return Some(arg);
        }
        call.arguments
            .keywords
            .iter()
            .find(|k| k.arg.as_deref() == Some(kw_name))
            .map(|k| &k.value)
    }

    fn is_ctypes_loader_head(head: &str) -> bool {
        matches!(
            head,
            "ctypes.CDLL"
                | "ctypes.PyDLL"
                | "ctypes.WinDLL"
                | "ctypes.OleDLL"
                | "_ctypes.CDLL"
                | "_ctypes.PyDLL"
                | "_ctypes.WinDLL"
                | "_ctypes.OleDLL"
                | "ctypes.cdll.LoadLibrary"
                | "ctypes.pydll.LoadLibrary"
                | "ctypes.windll.LoadLibrary"
                | "ctypes.oledll.LoadLibrary"
                | "ctypes.LibraryLoader.LoadLibrary"
                | "ctypes.util.find_library"
        )
    }

    fn is_ctypes_loader_attr(dotted: &str) -> bool {
        (dotted.starts_with("ctypes.cdll.")
            || dotted.starts_with("ctypes.windll.")
            || dotted.starts_with("ctypes.pydll.")
            || dotted.starts_with("ctypes.oledll."))
            && !dotted.ends_with(".LoadLibrary")
    }

    fn is_cffi_ctor_head(head: &str) -> bool {
        matches!(head, "cffi.FFI" | "_cffi_backend.FFI")
    }

    fn is_native_exec_symbol(sym: &str) -> bool {
        matches!(
            sym,
            "system"
                | "wsystem"
                | "_wsystem"
                | "popen"
                | "_popen"
                | "execve"
                | "execv"
                | "execvp"
                | "execvpe"
                | "execl"
                | "execlp"
                | "execle"
                | "posix_spawn"
                | "posix_spawnp"
                | "ShellExecuteA"
                | "ShellExecuteW"
                | "CreateProcessA"
                | "CreateProcessW"
                | "WinExec"
        )
    }

    fn is_static_ffi_arg(expr: &ast::Expr, vars: &HashMap<String, Option<String>>) -> bool {
        match expr {
            ast::Expr::NumberLiteral(_)
            | ast::Expr::BooleanLiteral(_)
            | ast::Expr::NoneLiteral(_)
            | ast::Expr::BytesLiteral(_)
            | ast::Expr::EllipsisLiteral(_) => true,
            ast::Expr::UnaryOp(u) => is_static_ffi_arg(&u.operand, vars),
            ast::Expr::Tuple(t) => t.elts.iter().all(|e| is_static_ffi_arg(e, vars)),
            ast::Expr::List(l) => l.elts.iter().all(|e| is_static_ffi_arg(e, vars)),
            _ => eval_static_str(expr, vars).is_some(),
        }
    }

    struct ImportVisitor {
        imports: Vec<PythonImportSpecifier>,
        caps: CapabilitySet,
        import_aliases: HashMap<String, String>,
        string_vars: HashMap<String, Option<String>>,
        ffi_instances: HashSet<String>,
        ffi_lib_handles: HashSet<String>,
    }

    impl ImportVisitor {
        fn expr_is_ffi_instance(&self, expr: &ast::Expr) -> bool {
            if let ast::Expr::Call(call) = expr {
                if let Some(head) = resolve_call_head(&call.func, &self.import_aliases) {
                    return is_cffi_ctor_head(&head);
                }
            }
            false
        }

        fn expr_is_ffi_lib_handle(&self, expr: &ast::Expr) -> bool {
            match expr {
                ast::Expr::Call(call) => {
                    if let Some(head) = resolve_call_head(&call.func, &self.import_aliases) {
                        if is_ctypes_loader_head(&head) && head != "ctypes.util.find_library" {
                            return true;
                        }
                        if let Some((recv, method)) = head.rsplit_once('.') {
                            if self.ffi_instances.contains(recv)
                                && matches!(method, "dlopen" | "verify")
                            {
                                return true;
                            }
                        }
                    }
                    if let ast::Expr::Attribute(attr) = call.func.as_ref() {
                        if matches!(attr.attr.as_str(), "dlopen" | "verify")
                            && self.expr_is_ffi_instance(&attr.value)
                        {
                            return true;
                        }
                    }
                    false
                }
                ast::Expr::Attribute(_) => {
                    if let Some(resolved) = resolve_call_head(expr, &self.import_aliases) {
                        return is_ctypes_loader_attr(&resolved);
                    }
                    false
                }
                _ => false,
            }
        }
    }

    impl<'a> PyVisitor<'a> for ImportVisitor {
        fn visit_stmt(&mut self, stmt: &'a ast::Stmt) {
            match stmt {
                ast::Stmt::Import(import_stmt) => {
                    for alias in &import_stmt.names {
                        let bound = alias.asname.as_ref().unwrap_or(&alias.name).to_string();
                        self.import_aliases.insert(bound, alias.name.to_string());
                        check_python_builtin_module_capabilities(
                            alias.name.as_str(),
                            &[],
                            &mut self.caps,
                        );
                        self.imports.push(PythonImportSpecifier {
                            level: 0,
                            module: Some(alias.name.to_string()),
                            imported_names: Vec::new(),
                            path_target: None,
                            dynamic_source: None,
                        });
                    }
                }
                ast::Stmt::ImportFrom(from_stmt) => {
                    let level = from_stmt.level;
                    let module = from_stmt.module.as_ref().map(|m| m.to_string());
                    let imported_names: Vec<String> =
                        from_stmt.names.iter().map(|a| a.name.to_string()).collect();
                    if level == 0 {
                        if let Some(ref mod_name) = module {
                            for alias in &from_stmt.names {
                                let bound =
                                    alias.asname.as_ref().unwrap_or(&alias.name).to_string();
                                self.import_aliases
                                    .insert(bound, format!("{mod_name}.{}", alias.name));
                            }
                            check_python_builtin_module_capabilities(
                                mod_name.as_str(),
                                &imported_names,
                                &mut self.caps,
                            );
                        }
                    }
                    self.imports.push(PythonImportSpecifier {
                        level,
                        module,
                        imported_names,
                        path_target: None,
                        dynamic_source: None,
                    });
                }
                ast::Stmt::Assign(assign) => {
                    self.visit_expr(&assign.value);
                    let val = eval_static_str(&assign.value, &self.string_vars);
                    let is_ffi_inst = self.expr_is_ffi_instance(&assign.value);
                    let is_ffi_lib = self.expr_is_ffi_lib_handle(&assign.value);
                    for target in &assign.targets {
                        if let ast::Expr::Name(name) = target {
                            self.string_vars.insert(name.id.to_string(), val.clone());
                            if is_ffi_inst {
                                self.ffi_instances.insert(name.id.to_string());
                            }
                            if is_ffi_lib {
                                self.ffi_lib_handles.insert(name.id.to_string());
                            }
                        }
                    }
                    return;
                }
                ast::Stmt::AnnAssign(assign) => {
                    if let Some(ref value) = assign.value {
                        self.visit_expr(value);
                        let val = eval_static_str(value, &self.string_vars);
                        let is_ffi_inst = self.expr_is_ffi_instance(value);
                        let is_ffi_lib = self.expr_is_ffi_lib_handle(value);
                        if let ast::Expr::Name(name) = assign.target.as_ref() {
                            self.string_vars.insert(name.id.to_string(), val);
                            if is_ffi_inst {
                                self.ffi_instances.insert(name.id.to_string());
                            }
                            if is_ffi_lib {
                                self.ffi_lib_handles.insert(name.id.to_string());
                            }
                        }
                    } else if let ast::Expr::Name(name) = assign.target.as_ref() {
                        self.string_vars.insert(name.id.to_string(), None);
                    }
                    return;
                }
                ast::Stmt::AugAssign(assign) => {
                    self.visit_expr(&assign.target);
                    self.visit_expr(&assign.value);
                    if let ast::Expr::Name(name) = assign.target.as_ref() {
                        if matches!(assign.op, ast::Operator::Add) {
                            let next = match (
                                self.string_vars.get(name.id.as_str()).and_then(|v| v.clone()),
                                eval_static_str(&assign.value, &self.string_vars),
                            ) {
                                (Some(a), Some(b)) => Some(format!("{a}{b}")),
                                _ => None,
                            };
                            self.string_vars.insert(name.id.to_string(), next);
                        } else {
                            self.string_vars.insert(name.id.to_string(), None);
                        }
                    }
                    return;
                }
                _ => {}
            }
            py_visitor::walk_stmt(self, stmt);
        }

        fn visit_expr(&mut self, expr: &'a ast::Expr) {
            if let ast::Expr::Attribute(_) = expr {
                if let Some(resolved) = resolve_call_head(expr, &self.import_aliases) {
                    if is_ctypes_loader_attr(&resolved) {
                        self.caps.external_paths = true;
                        self.caps.daemon = true;
                    }
                }
            }
            if let ast::Expr::Call(call) = expr {
                if let Some(head) = resolve_call_head(&call.func, &self.import_aliases) {
                    match head.as_str() {
                        "eval" | "exec" | "compile" | "builtins.eval" | "builtins.exec"
                        | "builtins.compile" => {
                            self.caps.dynamic_eval = true;
                        }
                        h if is_ctypes_loader_head(h) => {
                            self.caps.external_paths = true;
                            self.caps.daemon = true;
                            if h != "ctypes.util.find_library" {
                                let name_expr = extract_call_arg(call, 0, "name");
                                if let Some(e) = name_expr {
                                    if !matches!(e, ast::Expr::NoneLiteral(_))
                                        && eval_static_str(e, &self.string_vars).is_none()
                                    {
                                        self.caps.dynamic_eval = true;
                                        self.imports.push(PythonImportSpecifier {
                                            level: 0,
                                            module: None,
                                            imported_names: Vec::new(),
                                            path_target: None,
                                            dynamic_source: Some(h.to_string()),
                                        });
                                    }
                                }
                            }
                        }
                        h if is_cffi_ctor_head(h) => {
                            self.caps.external_paths = true;
                            self.caps.daemon = true;
                        }
                        "importlib.import_module" => {
                            let name_expr = extract_call_arg(call, 0, "name");
                            let pkg_expr = extract_call_arg(call, 1, "package");
                            match name_expr.and_then(|e| eval_static_str(e, &self.string_vars)) {
                                Some(raw_mod) if !raw_mod.is_empty() => {
                                    let dots =
                                        raw_mod.chars().take_while(|&c| c == '.').count() as u32;
                                    let rest = &raw_mod[dots as usize..];
                                    if dots > 0 {
                                        if let Some(p_expr) = pkg_expr {
                                            if let Some(pkg_str) =
                                                eval_static_str(p_expr, &self.string_vars)
                                            {
                                                if let Some(resolved_mod) =
                                                    resolve_relative_python_module(
                                                        dots, rest, &pkg_str,
                                                    )
                                                {
                                                    check_python_builtin_module_capabilities(
                                                        &resolved_mod,
                                                        &[],
                                                        &mut self.caps,
                                                    );
                                                    self.imports.push(PythonImportSpecifier {
                                                        level: 0,
                                                        module: Some(resolved_mod),
                                                        imported_names: Vec::new(),
                                                        path_target: None,
                                                        dynamic_source: None,
                                                    });
                                                } else {
                                                    self.imports.push(PythonImportSpecifier {
                                                        level: dots,
                                                        module: (!rest.is_empty())
                                                            .then(|| rest.to_string()),
                                                        imported_names: Vec::new(),
                                                        path_target: None,
                                                        dynamic_source: None,
                                                    });
                                                }
                                            } else {
                                                self.caps.dynamic_eval = true;
                                                self.imports.push(PythonImportSpecifier {
                                                    level: 0,
                                                    module: None,
                                                    imported_names: Vec::new(),
                                                    path_target: None,
                                                    dynamic_source: Some(
                                                        "importlib.import_module".to_string(),
                                                    ),
                                                });
                                            }
                                        } else {
                                            self.imports.push(PythonImportSpecifier {
                                                level: dots,
                                                module: (!rest.is_empty())
                                                    .then(|| rest.to_string()),
                                                imported_names: Vec::new(),
                                                path_target: None,
                                                dynamic_source: None,
                                            });
                                        }
                                    } else {
                                        check_python_builtin_module_capabilities(
                                            &raw_mod,
                                            &[],
                                            &mut self.caps,
                                        );
                                        self.imports.push(PythonImportSpecifier {
                                            level: 0,
                                            module: Some(raw_mod),
                                            imported_names: Vec::new(),
                                            path_target: None,
                                            dynamic_source: None,
                                        });
                                    }
                                }
                                _ => {
                                    self.caps.dynamic_eval = true;
                                    self.imports.push(PythonImportSpecifier {
                                        level: 0,
                                        module: None,
                                        imported_names: Vec::new(),
                                        path_target: None,
                                        dynamic_source: Some(
                                            "importlib.import_module".to_string(),
                                        ),
                                    });
                                }
                            }
                        }
                        "__import__" | "builtins.__import__" => {
                            let name_expr = extract_call_arg(call, 0, "name");
                            let fromlist_expr = extract_call_arg(call, 3, "fromlist");
                            let level_expr = extract_call_arg(call, 4, "level");
                            let level_opt = match level_expr {
                                Some(e) => eval_static_u32(e),
                                None => Some(0),
                            };
                            let mut imported_names = Vec::new();
                            if let Some(fl) = fromlist_expr {
                                let elts: Option<&[ast::Expr]> = match fl {
                                    ast::Expr::Tuple(t) => Some(&t.elts),
                                    ast::Expr::List(l) => Some(&l.elts),
                                    _ => None,
                                };
                                if let Some(items) = elts {
                                    for item in items {
                                        if let Some(s) = eval_static_str(item, &self.string_vars) {
                                            imported_names.push(s);
                                        }
                                    }
                                }
                            }
                            match (
                                name_expr.and_then(|e| eval_static_str(e, &self.string_vars)),
                                level_opt,
                            ) {
                                (Some(raw_mod), Some(level))
                                    if !raw_mod.is_empty() || level > 0 =>
                                {
                                    let dots =
                                        raw_mod.chars().take_while(|&c| c == '.').count() as u32;
                                    let eff_level = if level > 0 { level } else { dots };
                                    let rest = if dots > 0 {
                                        &raw_mod[dots as usize..]
                                    } else {
                                        raw_mod.as_str()
                                    };
                                    if eff_level == 0 {
                                        check_python_builtin_module_capabilities(
                                            rest,
                                            &imported_names,
                                            &mut self.caps,
                                        );
                                    }
                                    self.imports.push(PythonImportSpecifier {
                                        level: eff_level,
                                        module: (!rest.is_empty()).then(|| rest.to_string()),
                                        imported_names,
                                        path_target: None,
                                        dynamic_source: None,
                                    });
                                }
                                _ => {
                                    self.caps.dynamic_eval = true;
                                    self.imports.push(PythonImportSpecifier {
                                        level: 0,
                                        module: None,
                                        imported_names: Vec::new(),
                                        path_target: None,
                                        dynamic_source: Some("__import__".to_string()),
                                    });
                                }
                            }
                        }
                        "runpy.run_module" => {
                            let mod_expr = extract_call_arg(call, 0, "mod_name");
                            match mod_expr.and_then(|e| eval_static_str(e, &self.string_vars)) {
                                Some(raw_mod) if !raw_mod.is_empty() => {
                                    let dots =
                                        raw_mod.chars().take_while(|&c| c == '.').count() as u32;
                                    let rest = &raw_mod[dots as usize..];
                                    if dots == 0 {
                                        check_python_builtin_module_capabilities(
                                            &raw_mod,
                                            &[],
                                            &mut self.caps,
                                        );
                                    }
                                    self.imports.push(PythonImportSpecifier {
                                        level: dots,
                                        module: (!rest.is_empty()).then(|| rest.to_string()),
                                        imported_names: Vec::new(),
                                        path_target: None,
                                        dynamic_source: None,
                                    });
                                }
                                _ => {
                                    self.caps.dynamic_eval = true;
                                    self.imports.push(PythonImportSpecifier {
                                        level: 0,
                                        module: None,
                                        imported_names: Vec::new(),
                                        path_target: None,
                                        dynamic_source: Some("runpy.run_module".to_string()),
                                    });
                                }
                            }
                        }
                        "runpy.run_path" => {
                            let path_expr = extract_call_arg(call, 0, "path_name");
                            match path_expr.and_then(|e| eval_static_str(e, &self.string_vars)) {
                                Some(raw_path) if !raw_path.is_empty() => {
                                    self.imports.push(PythonImportSpecifier {
                                        level: 0,
                                        module: None,
                                        imported_names: Vec::new(),
                                        path_target: Some(raw_path),
                                        dynamic_source: None,
                                    });
                                }
                                _ => {
                                    self.caps.dynamic_eval = true;
                                    self.imports.push(PythonImportSpecifier {
                                        level: 0,
                                        module: None,
                                        imported_names: Vec::new(),
                                        path_target: None,
                                        dynamic_source: Some("runpy.run_path".to_string()),
                                    });
                                }
                            }
                        }
                        _ => {}
                    }
                }
                if let ast::Expr::Attribute(attr) = call.func.as_ref() {
                    let method = attr.attr.as_str();
                    let is_ffi_recv = match attr.value.as_ref() {
                        ast::Expr::Name(n) => self.ffi_instances.contains(n.id.as_str()),
                        other => self.expr_is_ffi_instance(other),
                    };
                    if is_ffi_recv {
                        match method {
                            "dlopen" => {
                                self.caps.external_paths = true;
                                self.caps.daemon = true;
                                let name_expr = extract_call_arg(call, 0, "name");
                                if let Some(e) = name_expr {
                                    if !matches!(e, ast::Expr::NoneLiteral(_))
                                        && eval_static_str(e, &self.string_vars).is_none()
                                    {
                                        self.caps.dynamic_eval = true;
                                        self.imports.push(PythonImportSpecifier {
                                            level: 0,
                                            module: None,
                                            imported_names: Vec::new(),
                                            path_target: None,
                                            dynamic_source: Some("cffi.FFI.dlopen".to_string()),
                                        });
                                    }
                                }
                            }
                            "cdef" => {
                                self.caps.external_paths = true;
                                self.caps.daemon = true;
                                let csource_expr = extract_call_arg(call, 0, "csource");
                                if let Some(e) = csource_expr {
                                    if eval_static_str(e, &self.string_vars).is_none() {
                                        self.caps.dynamic_eval = true;
                                    }
                                }
                            }
                            "verify" | "set_source" | "compile" => {
                                self.caps.external_paths = true;
                                self.caps.daemon = true;
                                self.caps.dynamic_eval = true;
                            }
                            _ => {}
                        }
                    } else {
                        let is_lib_recv = match attr.value.as_ref() {
                            ast::Expr::Name(n) => self.ffi_lib_handles.contains(n.id.as_str()),
                            other => self.expr_is_ffi_lib_handle(other),
                        };
                        if is_lib_recv {
                            self.caps.external_paths = true;
                            self.caps.daemon = true;
                            let has_dynamic_arg = call
                                .arguments
                                .args
                                .iter()
                                .any(|a| !is_static_ffi_arg(a, &self.string_vars))
                                || call
                                    .arguments
                                    .keywords
                                    .iter()
                                    .any(|kw| !is_static_ffi_arg(&kw.value, &self.string_vars));
                            if is_native_exec_symbol(method) || has_dynamic_arg {
                                self.caps.dynamic_eval = true;
                            }
                        }
                    }
                }
            }
            py_visitor::walk_expr(self, expr);
        }
    }

    let mut visitor = ImportVisitor {
        imports: Vec::new(),
        caps: CapabilitySet::EMPTY,
        import_aliases: HashMap::new(),
        string_vars: HashMap::new(),
        ffi_instances: HashSet::new(),
        ffi_lib_handles: HashSet::new(),
    };
    for stmt in &parsed.body {
        visitor.visit_stmt(stmt);
    }
    Ok((visitor.imports, visitor.caps))
}

fn classify_python_dependency_capabilities(norm_pkg: &str) -> CapabilitySet {
    let mut caps = CapabilitySet::EMPTY;
    if matches!(
        norm_pkg,
        "requests"
            | "httpx"
            | "aiohttp"
            | "urllib3"
            | "websockets"
            | "grpcio"
            | "boto3"
            | "botocore"
            | "paramiko"
            | "fabric"
            | "fastapi"
            | "uvicorn"
            | "starlette"
            | "flask"
            | "django"
            | "tornado"
            | "pycurl"
            | "twine"
    ) {
        caps.network = true;
    }
    if matches!(
        norm_pkg,
        "celery" | "dramatiq" | "rq" | "supervisor" | "python_daemon" | "daemonize"
    ) {
        caps.daemon = true;
    }
    if matches!(
        norm_pkg,
        "psutil" | "pexpect" | "sh" | "plumbum" | "invoke"
    ) {
        caps.external_paths = true;
    }
    if matches!(norm_pkg, "cffi" | "ctypes") {
        caps.external_paths = true;
        caps.daemon = true;
    }
    caps
}


fn normalize_py_name(name: &str) -> String {
    name.trim().to_ascii_lowercase().replace(['-', '.'], "_")
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
            "javascript" | "js" | "node" | "typescript" | "ts" | "tsx" | "jsx" | "mjs" | "cjs" => {
                crate::javascript::extract_capabilities(trimmed)
            }
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

/// Default capability emitter delegating to knowledge.toml capability rules and inline script AST inspection.
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
        let is_python = matches!(base_head.as_str(), "python" | "python3" | "py" | "uv");
        let is_node = matches!(
            base_head.as_str(),
            "node" | "nodejs" | "js" | "deno" | "bun"
        );

        if is_python || is_node {
            let script_lang = if is_python { "python" } else { "javascript" };
            for (idx, arg) in cmd.args.iter().enumerate() {
                let unquoted_arg = crate::paths::unquote(arg);
                if (is_python && (arg == "-c" || unquoted_arg == "-c"))
                    || (is_node && (arg == "-e" || unquoted_arg == "-e"))
                {
                    if let Some(script) = cmd.args.get(idx + 1) {
                        let unquoted_script = crate::paths::unquote_snippet(script);
                        caps.union(
                            DefaultAstCapabilityExtractor
                                .extract_capabilities(&unquoted_script, script_lang),
                        );
                    }
                } else if is_python && unquoted_arg.starts_with("-c") && unquoted_arg.len() > 2 {
                    let script = crate::paths::unquote_snippet(&unquoted_arg[2..]);
                    caps.union(DefaultAstCapabilityExtractor.extract_capabilities(&script, "python"));
                } else if is_node && unquoted_arg.starts_with("-e") && unquoted_arg.len() > 2 {
                    let script = crate::paths::unquote_snippet(&unquoted_arg[2..]);
                    caps.union(
                        DefaultAstCapabilityExtractor.extract_capabilities(&script, "javascript"),
                    );
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

/// Computes the propagated capability set required by a command string and all
/// wrapped child/subprocess commands across languages.
pub fn propagate_capabilities(
    kb: &crate::guards::Knowledge,
    command: &str,
    lang: &str,
) -> CapabilitySet {
    propagate_capabilities_with_emitter(kb, command, lang, &DefaultCapabilityEmitter)
}

/// Computes propagated capabilities using a custom emitter.
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
