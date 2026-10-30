//! JavaScript AST snippet scanner.
//!
//! Powered by `oxc_parser` to provide complete ECMAScript / TypeScript
//! grammar coverage. Extracts calls, file writes, subprocess invocations,
//! module bindings, and dynamic evaluations (`eval`, `new Function`) into
//! vouch's `javascript:` command format without false-positive `parse_failure`
//! prompts on valid modern syntax.

use std::collections::{HashMap, HashSet};

use oxc_allocator::Allocator;
use oxc_ast::ast::*;
use oxc_ast_visit::{walk, Visit};
use oxc_parser::{ParseOptions, Parser};
use oxc_span::SourceType;

pub use crate::syntax::{Cmd, Order, Scan};

pub const KNOWN_CONSTRUCTS: &[&str] = &[
    "parse_failure",
    "unmodeled_command",
    "dynamic_call",
    "unresolved_path",
    "unreadable_language",
];

pub struct JavaScript;

impl crate::syntax::Scanner for JavaScript {
    fn lang(&self) -> &'static str {
        "javascript"
    }

    fn scan(&self, src: &str) -> Result<Scan, String> {
        parse(src)
    }

    fn known_constructs(&self) -> &'static [&'static str] {
        KNOWN_CONSTRUCTS
    }
}

pub fn parse(src: &str) -> Result<Scan, String> {
    let allocator = Allocator::default();
    let source_type = SourceType::mjs().with_typescript(true);
    let options = ParseOptions {
        parse_regular_expression: true,
        allow_return_outside_function: true,
        ..ParseOptions::default()
    };

    let ret = Parser::new(&allocator, src, source_type)
        .with_options(options)
        .parse();

    if !ret.diagnostics.is_empty() {
        let errs: Vec<String> = ret
            .diagnostics
            .iter()
            .map(|d| d.to_string())
            .collect();
        return Err(errs.join("; "));
    }

    let mut visitor = JsVisitor::new();
    visitor.visit_program(&ret.program);
    Ok(visitor.out)
}

struct JsVisitor {
    modules: HashMap<String, String>,
    bindings: HashMap<String, String>,
    require_aliases: HashSet<String>,
    out: Scan,
    seq: u32,
}

fn normalize_js_mod_name(raw: &str) -> String {
    raw.strip_prefix("node:").unwrap_or(raw).to_string()
}

fn extract_static_specifier<'a>(
    expr: &Expression<'a>,
    bindings: &HashMap<String, String>,
) -> Option<String> {
    match expr {
        Expression::StringLiteral(s) => Some(s.value.to_string()),
        Expression::TemplateLiteral(t) => {
            let mut out = String::new();
            let mut quasi_iter = t.quasis.iter();
            let mut expr_iter = t.expressions.iter();
            while let Some(q) = quasi_iter.next() {
                out.push_str(q.value.raw.as_str());
                if let Some(e) = expr_iter.next() {
                    if let Expression::Identifier(id) = e {
                        if let Some(val) = bindings.get(id.name.as_str()) {
                            out.push_str(val);
                        } else {
                            return None;
                        }
                    } else {
                        return None;
                    }
                }
            }
            Some(out)
        }
        Expression::Identifier(id) => bindings.get(id.name.as_str()).cloned(),
        Expression::ParenthesizedExpression(p) => extract_static_specifier(&p.expression, bindings),
        _ => None,
    }
}

fn unwrap_parens<'a, 'b>(mut expr: &'b Expression<'a>) -> &'b Expression<'a> {
    while let Expression::ParenthesizedExpression(p) = expr {
        expr = &p.expression;
    }
    expr
}

impl JsVisitor {
    fn new() -> Self {
        let mut require_aliases = HashSet::new();
        require_aliases.insert("require".to_string());
        Self {
            modules: HashMap::new(),
            bindings: HashMap::new(),
            require_aliases,
            out: Scan::default(),
            seq: 0,
        }
    }

    fn is_create_require_call<'a>(&self, call: &CallExpression<'a>) -> bool {
        let parts = self.extract_callee_parts(&call.callee);
        if parts.is_empty() {
            return false;
        }
        let first = &parts[0];
        let mut canonical = Vec::new();
        if let Some(target) = self.modules.get(first) {
            for seg in target.split('.') {
                canonical.push(seg.to_string());
            }
            canonical.extend(parts[1..].iter().cloned());
        } else {
            canonical = parts;
        }
        let full = canonical.join(".");
        full == "module.createRequire" || full == "createRequire"
    }

    fn is_require_like_callee<'a>(&self, callee: &Expression<'a>) -> bool {
        match unwrap_parens(callee) {
            Expression::Identifier(id) => self.require_aliases.contains(id.name.as_str()),
            Expression::CallExpression(inner_call) => self.is_create_require_call(inner_call),
            _ => false,
        }
    }

    fn bind_module_pattern<'a>(&mut self, pat: &BindingPattern<'a>, base_mod: &str) {
        match pat {
            BindingPattern::BindingIdentifier(ident) => {
                self.modules
                    .insert(ident.name.to_string(), base_mod.to_string());
            }
            BindingPattern::ObjectPattern(obj) => {
                for prop in &obj.properties {
                    if let PropertyKey::StaticIdentifier(key) = &prop.key {
                        let prop_name = key.name.as_str();
                        if let BindingPattern::BindingIdentifier(alias) = &prop.value {
                            let target = if prop_name == "default" {
                                base_mod.to_string()
                            } else {
                                format!("{base_mod}.{prop_name}")
                            };
                            self.modules.insert(alias.name.to_string(), target);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn extract_init_module_specifier<'a>(&self, init: &Expression<'a>) -> Option<String> {
        let unwrapped = unwrap_parens(init);
        match unwrapped {
            Expression::CallExpression(call) => {
                let callee_parts = self.extract_callee_parts(&call.callee);
                if self.is_require_like_callee(&call.callee) {
                    if let Some(arg) = call.arguments.first().and_then(|a| a.as_expression()) {
                        if let Some(raw_spec) = extract_static_specifier(arg, &self.bindings) {
                            return Some(normalize_js_mod_name(&raw_spec));
                        }
                    }
                } else if callee_parts
                    .first()
                    .is_some_and(|first| self.require_aliases.contains(first.as_str()))
                {
                    if let Some(arg) = call.arguments.first().and_then(|a| a.as_expression()) {
                        if let Some(raw_spec) = extract_static_specifier(arg, &self.bindings) {
                            let norm = normalize_js_mod_name(&raw_spec);
                            return Some(if callee_parts.len() > 1 {
                                format!("{norm}.{}", callee_parts[1..].join("."))
                            } else {
                                norm
                            });
                        }
                    }
                }
                None
            }
            Expression::StaticMemberExpression(member) => {
                if let Expression::CallExpression(call) = unwrap_parens(&member.object) {
                    if self.is_require_like_callee(&call.callee) {
                        if let Some(arg) = call.arguments.first().and_then(|a| a.as_expression()) {
                            if let Some(raw_spec) = extract_static_specifier(arg, &self.bindings) {
                                let norm = normalize_js_mod_name(&raw_spec);
                                return Some(format!("{norm}.{}", member.property.name));
                            }
                        }
                    }
                }
                None
            }
            Expression::AwaitExpression(aw) => {
                if let Expression::ImportExpression(imp) = unwrap_parens(&aw.argument) {
                    if let Some(raw_spec) = extract_static_specifier(&imp.source, &self.bindings) {
                        return Some(normalize_js_mod_name(&raw_spec));
                    }
                }
                None
            }
            Expression::ImportExpression(imp) => {
                if let Some(raw_spec) = extract_static_specifier(&imp.source, &self.bindings) {
                    return Some(normalize_js_mod_name(&raw_spec));
                }
                None
            }
            _ => None,
        }
    }

    fn extract_callee_parts<'a>(&self, expr: &Expression<'a>) -> Vec<String> {
        match expr {
            Expression::Identifier(id) => vec![id.name.to_string()],
            Expression::StaticMemberExpression(m) => {
                let mut parts = self.extract_callee_parts(&m.object);
                parts.push(m.property.name.to_string());
                parts
            }
            Expression::ComputedMemberExpression(_) => vec!["$computed".to_string()],
            Expression::CallExpression(c) => {
                // Handle require('child_process').execSync or customReq('child_process').execSync chaining
                if self.is_require_like_callee(&c.callee) {
                    if let Some(arg) = c.arguments.first().and_then(|a| a.as_expression()) {
                        if let Some(raw_spec) = extract_static_specifier(arg, &self.bindings) {
                            return vec![normalize_js_mod_name(&raw_spec)];
                        }
                    }
                }
                vec!["$call_result".to_string()]
            }
            Expression::AwaitExpression(aw) => {
                if let Expression::ImportExpression(imp) = unwrap_parens(&aw.argument) {
                    if let Some(raw_spec) = extract_static_specifier(&imp.source, &self.bindings) {
                        return vec![normalize_js_mod_name(&raw_spec)];
                    }
                }
                vec!["$await".to_string()]
            }
            Expression::ParenthesizedExpression(p) => self.extract_callee_parts(&p.expression),
            _ => vec!["$expr".to_string()],
        }
    }

    fn extract_expr_value<'a>(&self, expr: &Expression<'a>) -> String {
        match expr {
            Expression::StringLiteral(s) => s.value.to_string(),
            Expression::NumericLiteral(n) => n.value.to_string(),
            Expression::BooleanLiteral(b) => b.value.to_string(),
            Expression::Identifier(id) => {
                if let Some(val) = self.bindings.get(id.name.as_str()) {
                    val.clone()
                } else {
                    format!("${}", id.name)
                }
            }
            Expression::TemplateLiteral(t) => {
                let mut result = String::new();
                let mut quasi_iter = t.quasis.iter();
                let mut expr_iter = t.expressions.iter();

                while let Some(q) = quasi_iter.next() {
                    result.push_str(q.value.raw.as_str());
                    if let Some(e) = expr_iter.next() {
                        if let Expression::Identifier(id) = e {
                            if let Some(val) = self.bindings.get(id.name.as_str()) {
                                result.push_str(val);
                            } else {
                                result.push('$');
                                result.push_str(id.name.as_str());
                            }
                        } else {
                            result.push_str("$?");
                        }
                    }
                }
                result
            }
            Expression::BinaryExpression(b) => {
                if b.operator == BinaryOperator::Addition {
                    let left = self.extract_expr_value(&b.left);
                    let right = self.extract_expr_value(&b.right);
                    format!("{left}{right}")
                } else {
                    "$?".to_string()
                }
            }
            Expression::ArrayExpression(arr) => {
                let mut elements = Vec::new();
                for el in &arr.elements {
                    match el {
                        ArrayExpressionElement::SpreadElement(_) => elements.push("$**".to_string()),
                        _ => {
                            if let Some(e) = el.as_expression() {
                                elements.push(self.extract_expr_value(e));
                            }
                        }
                    }
                }
                serde_json::to_string(&elements).unwrap_or_else(|_| "$array".to_string())
            }
            Expression::ObjectExpression(_) => "$object".to_string(),
            Expression::ParenthesizedExpression(p) => self.extract_expr_value(&p.expression),
            _ => "$?".to_string(),
        }
    }

    fn extract_args<'a>(&self, args: &[Argument<'a>]) -> Vec<String> {
        args.iter()
            .map(|arg| match arg {
                Argument::SpreadElement(_) => "$**".to_string(),
                _ => {
                    if let Some(expr) = arg.as_expression() {
                        self.extract_expr_value(expr)
                    } else {
                        "$?".to_string()
                    }
                }
            })
            .collect()
    }
}

impl<'a> Visit<'a> for JsVisitor {
    fn visit_variable_declaration(&mut self, decl: &VariableDeclaration<'a>) {
        for declarator in &decl.declarations {
            if let Some(init) = &declarator.init {
                if let Expression::CallExpression(call) = unwrap_parens(init) {
                    if self.is_create_require_call(call) {
                        if let BindingPattern::BindingIdentifier(ident) = &declarator.id {
                            self.require_aliases.insert(ident.name.to_string());
                        }
                    }
                }
                if let Some(base_mod) = self.extract_init_module_specifier(init) {
                    if base_mod == "module.createRequire" {
                        if let BindingPattern::BindingIdentifier(ident) = &declarator.id {
                            self.modules
                                .insert(ident.name.to_string(), base_mod.clone());
                        }
                    } else {
                        self.bind_module_pattern(&declarator.id, &base_mod);
                    }
                } else if let Some(lit) = extract_static_specifier(init, &self.bindings) {
                    if let BindingPattern::BindingIdentifier(ident) = &declarator.id {
                        self.bindings.insert(ident.name.to_string(), lit);
                    }
                }
            }
        }
        walk::walk_variable_declaration(self, decl);
    }

    fn visit_import_declaration(&mut self, decl: &ImportDeclaration<'a>) {
        let mod_name = normalize_js_mod_name(decl.source.value.as_str());
        if let Some(specifiers) = &decl.specifiers {
            for spec in specifiers {
                match spec {
                    ImportDeclarationSpecifier::ImportDefaultSpecifier(s) => {
                        self.modules.insert(s.local.name.to_string(), mod_name.clone());
                    }
                    ImportDeclarationSpecifier::ImportSpecifier(s) => {
                        let imported = s.imported.name();
                        self.modules.insert(
                            s.local.name.to_string(),
                            format!("{mod_name}.{imported}"),
                        );
                    }
                    ImportDeclarationSpecifier::ImportNamespaceSpecifier(s) => {
                        self.modules.insert(s.local.name.to_string(), mod_name.clone());
                    }
                }
            }
        }
        walk::walk_import_declaration(self, decl);
    }

    fn visit_import_expression(&mut self, expr: &ImportExpression<'a>) {
        if extract_static_specifier(&expr.source, &self.bindings).is_none() {
            self.out.note("dynamic_call");
            let arg = self.extract_expr_value(&expr.source);
            self.out.push_cmd(
                "javascript:import".to_string(),
                vec![arg],
                Order::Seq(self.seq),
                crate::syntax::InputSource::Unknown,
                true,
                None,
                vec![],
                None,
                HashMap::new(),
                false,
            );
            self.seq += 1;
        }
        walk::walk_import_expression(self, expr);
    }

    fn visit_new_expression(&mut self, expr: &NewExpression<'a>) {
        if let Expression::Identifier(id) = &expr.callee {
            if id.name == "Function" {
                self.out.note("dynamic_call");
                let args = self.extract_args(&expr.arguments);
                self.out.push_cmd(
                    "javascript:Function".to_string(),
                    args,
                    Order::Seq(self.seq),
                    crate::syntax::InputSource::Unknown,
                    true,
                    None,
                    vec![],
                    None,
                    HashMap::new(),
                    false,
                );
                self.seq += 1;
            }
        }
        walk::walk_new_expression(self, expr);
    }

    fn visit_call_expression(&mut self, expr: &CallExpression<'a>) {
        // Handle `import('mod').then((m) => ...)` and `import('mod').then(({ execSync }) => ...)`
        if let Expression::StaticMemberExpression(member) = unwrap_parens(&expr.callee) {
            if member.property.name == "then" {
                if let Expression::ImportExpression(imp) = unwrap_parens(&member.object) {
                    if let Some(raw_spec) = extract_static_specifier(&imp.source, &self.bindings) {
                        let base_mod = normalize_js_mod_name(&raw_spec);
                        if let Some(first_arg) =
                            expr.arguments.first().and_then(|a| a.as_expression())
                        {
                            match unwrap_parens(first_arg) {
                                Expression::ArrowFunctionExpression(arrow) => {
                                    if let Some(param) = arrow.params.items.first() {
                                        self.bind_module_pattern(&param.pattern, &base_mod);
                                    }
                                }
                                Expression::FunctionExpression(func) => {
                                    if let Some(param) = func.params.items.first() {
                                        self.bind_module_pattern(&param.pattern, &base_mod);
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
        }

        if self.is_require_like_callee(&expr.callee) {
            let is_static = expr
                .arguments
                .first()
                .and_then(|a| a.as_expression())
                .and_then(|arg| extract_static_specifier(arg, &self.bindings))
                .is_some();
            if !is_static {
                self.out.note("dynamic_call");
                let args = self.extract_args(&expr.arguments);
                self.out.push_cmd(
                    "javascript:require".to_string(),
                    args,
                    Order::Seq(self.seq),
                    crate::syntax::InputSource::Unknown,
                    true,
                    None,
                    vec![],
                    None,
                    HashMap::new(),
                    false,
                );
                self.seq += 1;
            }
            walk::walk_call_expression(self, expr);
            return;
        }

        if self.is_create_require_call(expr) {
            walk::walk_call_expression(self, expr);
            return;
        }

        let callee_parts = self.extract_callee_parts(&expr.callee);
        if !callee_parts.is_empty() {
            let first = &callee_parts[0];
            let mut canonical_parts = Vec::new();
            if let Some(target) = self.modules.get(first) {
                for seg in target.split('.') {
                    canonical_parts.push(seg.to_string());
                }
                canonical_parts.extend(callee_parts[1..].iter().cloned());
            } else {
                canonical_parts = callee_parts.clone();
            }

            let full_name = canonical_parts.join(".");

            if full_name == "require" || full_name == "module.createRequire" {
                // Bare require / createRequire does not produce a command
            } else if full_name == "eval" {
                self.out.note("dynamic_call");
                let args = self.extract_args(&expr.arguments);
                self.out.push_cmd(
                    "javascript:eval".to_string(),
                    args,
                    Order::Seq(self.seq),
                    crate::syntax::InputSource::Unknown,
                    true,
                    None,
                    vec![],
                    None,
                    HashMap::new(),
                    false,
                );
                self.seq += 1;
            } else if matches!(
                full_name.as_str(),
                "child_process.spawn"
                    | "child_process.spawnSync"
                    | "spawn"
                    | "spawnSync"
                    | "child_process.execFile"
                    | "child_process.execFileSync"
                    | "execFile"
                    | "execFileSync"
            ) {
                let args = self.extract_args(&expr.arguments);
                let prog = args.first().cloned().unwrap_or_default();
                let mut argv = vec![prog];
                if let Some(arg1) = args.get(1) {
                    if let Ok(extra_args) = serde_json::from_str::<Vec<String>>(arg1) {
                        argv.extend(extra_args);
                    } else if !arg1.is_empty() && arg1 != "$?" {
                        argv.push(arg1.clone());
                    }
                }
                let argv_json = serde_json::to_string(&argv).unwrap_or_default();
                let head = format!("javascript:{full_name}");
                self.out.push_cmd(
                    head,
                    vec![argv_json],
                    Order::Seq(self.seq),
                    crate::syntax::InputSource::Unknown,
                    true,
                    None,
                    vec![],
                    None,
                    HashMap::new(),
                    false,
                );
                self.seq += 1;
            } else if !full_name.is_empty() && !full_name.starts_with('$') {
                let args = self.extract_args(&expr.arguments);
                let head = format!("javascript:{full_name}");
                self.out.push_cmd(
                    head,
                    args,
                    Order::Seq(self.seq),
                    crate::syntax::InputSource::Unknown,
                    true,
                    None,
                    vec![],
                    None,
                    HashMap::new(),
                    false,
                );
                self.seq += 1;
            }
        }
        walk::walk_call_expression(self, expr);
    }
}

/// Extract dynamically inferred capabilities from a JavaScript/Node.js script AST.
pub fn extract_capabilities(src: &str) -> crate::capability::CapabilitySet {
    use crate::capability::CapabilitySet;

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

    let mut caps = CapabilitySet::EMPTY;

    fn check_js_mod(spec: &str, caps: &mut CapabilitySet) {
        let normalized = spec.strip_prefix("node:").unwrap_or(spec);
        match normalized {
            "net" | "http" | "https" | "dgram" | "undici" | "axios" | "tls" | "dns" | "http2" => {
                caps.network = true;
            }
            "child_process" | "cluster" | "worker_threads" => {
                caps.daemon = true;
            }
            "fs" | "fs/promises" => {
                caps.external_paths = true;
            }
            "vm" => {
                caps.dynamic_eval = true;
            }
            _ => {}
        }
    }

    struct JsCapVisitor<'a> {
        caps: &'a mut CapabilitySet,
        modules: HashMap<String, String>,
        bindings: HashMap<String, String>,
        require_aliases: HashSet<String>,
        _phantom: std::marker::PhantomData<&'a ()>,
    }

    impl<'a> JsCapVisitor<'a> {
        fn is_create_require_call(&self, call: &CallExpression<'a>) -> bool {
            match unwrap_parens(&call.callee) {
                Expression::Identifier(id) => {
                    id.name == "createRequire"
                        || self
                            .modules
                            .get(id.name.as_str())
                            .is_some_and(|m| m == "module.createRequire")
                }
                Expression::StaticMemberExpression(m) => {
                    if m.property.name != "createRequire" {
                        return false;
                    }
                    match unwrap_parens(&m.object) {
                        Expression::Identifier(id) => self
                            .modules
                            .get(id.name.as_str())
                            .is_some_and(|mod_name| mod_name == "module"),
                        Expression::CallExpression(inner) => {
                            if let Expression::Identifier(id) = unwrap_parens(&inner.callee) {
                                if self.require_aliases.contains(id.name.as_str()) {
                                    if let Some(arg) =
                                        inner.arguments.first().and_then(|a| a.as_expression())
                                    {
                                        if let Some(spec) =
                                            extract_static_specifier(arg, &self.bindings)
                                        {
                                            return normalize_js_mod_name(&spec) == "module";
                                        }
                                    }
                                }
                            }
                            false
                        }
                        _ => false,
                    }
                }
                _ => false,
            }
        }

        fn is_require_like_callee(&self, callee: &Expression<'a>) -> bool {
            match unwrap_parens(callee) {
                Expression::Identifier(id) => self.require_aliases.contains(id.name.as_str()),
                Expression::CallExpression(inner) => self.is_create_require_call(inner),
                _ => false,
            }
        }
    }

    impl<'a> Visit<'a> for JsCapVisitor<'a> {
        fn visit_import_declaration(&mut self, decl: &ImportDeclaration<'a>) {
            let mod_str = decl.source.value.as_str();
            check_js_mod(mod_str, self.caps);
            let norm_mod = normalize_js_mod_name(mod_str);
            if let Some(specifiers) = &decl.specifiers {
                for spec in specifiers {
                    match spec {
                        ImportDeclarationSpecifier::ImportDefaultSpecifier(s) => {
                            self.modules
                                .insert(s.local.name.to_string(), norm_mod.clone());
                        }
                        ImportDeclarationSpecifier::ImportNamespaceSpecifier(s) => {
                            self.modules
                                .insert(s.local.name.to_string(), norm_mod.clone());
                        }
                        ImportDeclarationSpecifier::ImportSpecifier(s) => {
                            let imported = s.imported.name();
                            self.modules.insert(
                                s.local.name.to_string(),
                                format!("{norm_mod}.{imported}"),
                            );
                        }
                    }
                }
            }
            walk::walk_import_declaration(self, decl);
        }

        fn visit_variable_declaration(&mut self, decl: &VariableDeclaration<'a>) {
            for declarator in &decl.declarations {
                if let Some(init) = &declarator.init {
                    let unwrapped = unwrap_parens(init);
                    if let Expression::CallExpression(call) = unwrapped {
                        if self.is_create_require_call(call) {
                            if let BindingPattern::BindingIdentifier(ident) = &declarator.id {
                                self.require_aliases.insert(ident.name.to_string());
                            }
                        } else if self.is_require_like_callee(&call.callee) {
                            if let Some(arg) =
                                call.arguments.first().and_then(|a| a.as_expression())
                            {
                                if let Some(spec) = extract_static_specifier(arg, &self.bindings) {
                                    let norm_mod = normalize_js_mod_name(&spec);
                                    match &declarator.id {
                                        BindingPattern::BindingIdentifier(ident) => {
                                            self.modules.insert(ident.name.to_string(), norm_mod);
                                        }
                                        BindingPattern::ObjectPattern(obj) => {
                                            for prop in &obj.properties {
                                                if let PropertyKey::StaticIdentifier(key) =
                                                    &prop.key
                                                {
                                                    if let BindingPattern::BindingIdentifier(
                                                        alias,
                                                    ) = &prop.value
                                                    {
                                                        self.modules.insert(
                                                            alias.name.to_string(),
                                                            format!(
                                                                "{norm_mod}.{}",
                                                                key.name.as_str()
                                                            ),
                                                        );
                                                    }
                                                }
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }
                    } else if let Some(lit) = extract_static_specifier(unwrapped, &self.bindings) {
                        if let BindingPattern::BindingIdentifier(ident) = &declarator.id {
                            self.bindings.insert(ident.name.to_string(), lit);
                        }
                    }
                }
            }
            walk::walk_variable_declaration(self, decl);
        }

        fn visit_import_expression(&mut self, expr: &ImportExpression<'a>) {
            match extract_static_specifier(&expr.source, &self.bindings) {
                Some(spec) => check_js_mod(&spec, self.caps),
                None => self.caps.dynamic_eval = true,
            }
            walk::walk_import_expression(self, expr);
        }

        fn visit_call_expression(&mut self, expr: &CallExpression<'a>) {
            if self.is_require_like_callee(&expr.callee) {
                match expr
                    .arguments
                    .first()
                    .and_then(|a| a.as_expression())
                    .and_then(|arg| extract_static_specifier(arg, &self.bindings))
                {
                    Some(spec) => check_js_mod(&spec, self.caps),
                    None => self.caps.dynamic_eval = true,
                }
            } else if let Expression::Identifier(ident) = &expr.callee {
                if ident.name == "eval" {
                    self.caps.dynamic_eval = true;
                }
            }
            walk::walk_call_expression(self, expr);
        }

        fn visit_new_expression(&mut self, expr: &NewExpression<'a>) {
            if let Expression::Identifier(ident) = &expr.callee {
                if ident.name == "Function" {
                    self.caps.dynamic_eval = true;
                }
            }
            walk::walk_new_expression(self, expr);
        }
    }

    let mut require_aliases = HashSet::new();
    require_aliases.insert("require".to_string());
    let mut visitor = JsCapVisitor {
        caps: &mut caps,
        modules: HashMap::new(),
        bindings: HashMap::new(),
        require_aliases,
        _phantom: std::marker::PhantomData,
    };
    visitor.visit_program(&ret.program);

    caps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_pure_math_and_console_log() {
        let scan = parse("const x = 1 + 2; console.log(x);").unwrap();
        assert_eq!(scan.commands.len(), 1);
        assert_eq!(scan.commands[0].head, "javascript:console.log");
        assert_eq!(scan.commands[0].args, vec!["$x"]);
    }

    #[test]
    fn parses_subprocess_exec_sync() {
        let scan = parse("require('child_process').execSync('rm -rf /');").unwrap();
        assert_eq!(scan.commands.len(), 1);
        assert_eq!(scan.commands[0].head, "javascript:child_process.execSync");
        assert_eq!(scan.commands[0].args, vec!["rm -rf /"]);
    }

    #[test]
    fn parses_destructured_exec_sync() {
        let scan = parse("const { execSync } = require('child_process'); execSync('echo hi');").unwrap();
        assert_eq!(scan.commands.len(), 1);
        assert_eq!(scan.commands[0].head, "javascript:child_process.execSync");
        assert_eq!(scan.commands[0].args, vec!["echo hi"]);
    }

    #[test]
    fn parses_dynamic_eval() {
        let scan = parse("eval('foo()');").unwrap();
        assert!(scan.constructs.contains(&"dynamic_call".to_string()));
        assert_eq!(scan.commands.len(), 1);
        assert_eq!(scan.commands[0].head, "javascript:eval");
        assert_eq!(scan.commands[0].args, vec!["foo()"]);
    }

    #[test]
    fn parses_new_function() {
        let scan = parse("const f = new Function('a', 'return a');").unwrap();
        assert!(scan.constructs.contains(&"dynamic_call".to_string()));
        assert_eq!(scan.commands.len(), 1);
        assert_eq!(scan.commands[0].head, "javascript:Function");
    }

    #[test]
    fn parses_modern_regex_and_optional_chaining() {
        let scan = parse(
            r#"
            const re = /pattern\d+/gi;
            const obj = { nested: { val: 42 } };
            if (re.test("pattern123")) {
                console.log(obj?.nested?.val);
            }
            "#,
        )
        .unwrap();
        assert!(scan.commands.iter().any(|c| c.head == "javascript:re.test"));
        assert!(scan.commands.iter().any(|c| c.head == "javascript:console.log"));
    }

    #[test]
    fn parses_classes_and_arrow_functions() {
        let scan = parse(
            r#"
            class Worker {
                #secret = "private";
                run = (task) => {
                    console.log(task);
                };
            }
            const w = new Worker();
            w.run("build");
            "#,
        )
        .unwrap();
        assert!(scan.commands.iter().any(|c| c.head == "javascript:w.run"));
    }

    #[test]
    fn fails_closed_on_syntax_error() {
        let res = parse("const x = ;");
        assert!(res.is_err(), "expected parse failure on invalid syntax");
    }

    #[test]
    fn parses_dynamic_import_and_create_require_bindings_and_tainted_specifiers() {
        // 1. Static `await import('node:child_process')` and `.then(...)` resolve module bindings cleanly
        let scan_static = parse(
            r#"
            const cp = await import('node:child_process');
            cp.execSync('echo ok');
            import('child_process').then(({ spawnSync }) => {
                spawnSync('git', ['status']);
            });
            "#,
        )
        .unwrap();
        assert!(
            !scan_static.constructs.contains(&"dynamic_call".to_string()),
            "static literal import() must not emit dynamic_call: {:?}",
            scan_static.constructs
        );
        assert!(
            scan_static
                .commands
                .iter()
                .any(|c| c.head == "javascript:child_process.execSync" && c.args == vec!["echo ok"])
        );
        assert!(
            scan_static
                .commands
                .iter()
                .any(|c| c.head == "javascript:child_process.spawnSync")
        );

        // 2. `createRequire` from 'node:module' binds custom require function and resolves calls
        let scan_req = parse(
            r#"
            import { createRequire } from 'node:module';
            const customReq = createRequire(import.meta.url);
            const { writeFileSync } = customReq('node:fs');
            writeFileSync('/tmp/out.txt', 'hello');
            "#,
        )
        .unwrap();
        assert!(
            !scan_req.constructs.contains(&"dynamic_call".to_string()),
            "static literal customReq() must not emit dynamic_call: {:?}",
            scan_req.constructs
        );
        assert_eq!(scan_req.commands.len(), 1);
        assert_eq!(scan_req.commands[0].head, "javascript:fs.writeFileSync");

        // 3. Non-literal / tainted `import(userSpec)` and `customReq(userSpec)` emit `dynamic_call`
        let scan_tainted_import = parse("const mod = await import(process.env.PLUGIN_PATH);").unwrap();
        assert!(
            scan_tainted_import
                .constructs
                .contains(&"dynamic_call".to_string()),
            "non-literal import() must emit dynamic_call"
        );
        assert!(
            scan_tainted_import
                .commands
                .iter()
                .any(|c| c.head == "javascript:import")
        );

        let scan_tainted_req = parse(
            r#"
            import { createRequire } from 'module';
            const req = createRequire(import.meta.url);
            req(`./plugins/${dynamicName}`);
            "#,
        )
        .unwrap();
        assert!(
            scan_tainted_req
                .constructs
                .contains(&"dynamic_call".to_string()),
            "non-literal createRequire alias call must emit dynamic_call"
        );
        assert!(
            scan_tainted_req
                .commands
                .iter()
                .any(|c| c.head == "javascript:require")
        );
    }
}
