//! JavaScript AST snippet scanner.
//!
//! Powered by `oxc_parser` to provide complete ECMAScript / TypeScript
//! grammar coverage. Extracts calls, file writes, subprocess invocations,
//! module bindings, and dynamic evaluations (`eval`, `new Function`) into
//! vouch's `javascript:` command format without false-positive `parse_failure`
//! prompts on valid modern syntax.

use std::collections::HashMap;

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
    out: Scan,
    seq: u32,
}

impl JsVisitor {
    fn new() -> Self {
        Self {
            modules: HashMap::new(),
            bindings: HashMap::new(),
            out: Scan::default(),
            seq: 0,
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
                // Handle require('child_process').execSync chaining
                if let Expression::Identifier(id) = &c.callee {
                    if id.name == "require" {
                        if let Some(arg) = c.arguments.first() {
                            if let Some(Expression::StringLiteral(s)) = arg.as_expression() {
                                return vec![s.value.to_string()];
                            }
                        }
                    }
                }
                vec!["$call_result".to_string()]
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
                // Check if init is a require('mod') or require('mod').sub call
                if let Expression::CallExpression(call) = init {
                    let callee_parts = self.extract_callee_parts(&call.callee);
                    if callee_parts.first().map(|s| s.as_str()) == Some("require") {
                        if let Some(arg) = call.arguments.first() {
                            if let Some(Expression::StringLiteral(s)) = arg.as_expression() {
                                let base_mod = if callee_parts.len() > 1 {
                                    format!("{}.{}", s.value, callee_parts[1..].join("."))
                                } else {
                                    s.value.to_string()
                                };

                                match &declarator.id {
                                    BindingPattern::BindingIdentifier(ident) => {
                                        self.modules.insert(ident.name.to_string(), base_mod);
                                    }
                                    BindingPattern::ObjectPattern(obj) => {
                                        for prop in &obj.properties {
                                            if let PropertyKey::StaticIdentifier(key) = &prop.key {
                                                let prop_name = key.name.as_str();
                                                if let BindingPattern::BindingIdentifier(alias) = &prop.value {
                                                    self.modules.insert(
                                                        alias.name.to_string(),
                                                        format!("{base_mod}.{prop_name}"),
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
                } else if let Expression::StringLiteral(s) = init {
                    if let BindingPattern::BindingIdentifier(ident) = &declarator.id {
                        self.bindings.insert(ident.name.to_string(), s.value.to_string());
                    }
                }
            }
        }
        walk::walk_variable_declaration(self, decl);
    }

    fn visit_import_declaration(&mut self, decl: &ImportDeclaration<'a>) {
        let mod_name = decl.source.value.as_str();
        if let Some(specifiers) = &decl.specifiers {
            for spec in specifiers {
                match spec {
                    ImportDeclarationSpecifier::ImportDefaultSpecifier(s) => {
                        self.modules.insert(s.local.name.to_string(), mod_name.to_string());
                    }
                    ImportDeclarationSpecifier::ImportSpecifier(s) => {
                        let imported = s.imported.name();
                        self.modules.insert(
                            s.local.name.to_string(),
                            format!("{mod_name}.{imported}"),
                        );
                    }
                    ImportDeclarationSpecifier::ImportNamespaceSpecifier(s) => {
                        self.modules.insert(s.local.name.to_string(), mod_name.to_string());
                    }
                }
            }
        }
        walk::walk_import_declaration(self, decl);
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

            if full_name == "require" {
                // Bare require does not produce a command
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
}
