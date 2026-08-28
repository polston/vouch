//! On-demand measurement for M2.107: how often scanned Python snippets read
//! `sys.argv` by subscript, grouped by the index shape vouch would need to
//! connect to the enclosing interpreter command.
//!
//! The corpus rows and snippet boundaries come from vouch's own Bash scanner
//! and wrapper expansion. Python expressions are counted with the same pinned
//! Ruff parser and normalization used by vouch's Python scanner. No corpus
//! text, path, command, session value, or callable name is printed — aggregate
//! counts only (CLAUDE.md §6).
//!
//! Run: `cargo run --release --example count_python_argv_shapes`

#[path = "../tests/common/mod.rs"]
mod common;

use ruff_python_ast as ast;
use ruff_python_ast::visitor::{self, Visitor};
use std::collections::HashSet;

#[derive(Default)]
struct ArgvCounts {
    subscripts: usize,
    zero_indices: usize,
    positive_indices: usize,
    negative_indices: usize,
    dynamic_indices: usize,
    oversized_positive_indices: usize,
    maximum_positive_index: usize,
}

impl ArgvCounts {
    fn found_any(&self) -> bool {
        self.subscripts > 0
    }

    fn add(&mut self, other: &Self) {
        self.subscripts += other.subscripts;
        self.zero_indices += other.zero_indices;
        self.positive_indices += other.positive_indices;
        self.negative_indices += other.negative_indices;
        self.dynamic_indices += other.dynamic_indices;
        self.oversized_positive_indices += other.oversized_positive_indices;
        self.maximum_positive_index = self
            .maximum_positive_index
            .max(other.maximum_positive_index);
    }
}

fn is_sys_argv(expr: &ast::Expr) -> bool {
    let ast::Expr::Attribute(attribute) = expr else {
        return false;
    };
    let ast::Expr::Name(name) = attribute.value.as_ref() else {
        return false;
    };
    name.id.as_str() == "sys" && attribute.attr.as_str() == "argv"
}

fn integer_literal(expr: &ast::Expr) -> Option<(bool, String)> {
    match expr {
        ast::Expr::NumberLiteral(number) => match &number.value {
            ast::Number::Int(value) => Some((false, value.to_string())),
            _ => None,
        },
        ast::Expr::UnaryOp(unary)
            if matches!(unary.op, ast::UnaryOp::UAdd | ast::UnaryOp::USub) =>
        {
            let ast::Expr::NumberLiteral(number) = unary.operand.as_ref() else {
                return None;
            };
            let ast::Number::Int(value) = &number.value else {
                return None;
            };
            Some((matches!(unary.op, ast::UnaryOp::USub), value.to_string()))
        }
        _ => None,
    }
}

impl<'a> Visitor<'a> for ArgvCounts {
    fn visit_expr(&mut self, expr: &'a ast::Expr) {
        if let ast::Expr::Subscript(subscript) = expr {
            if is_sys_argv(&subscript.value) {
                self.subscripts += 1;
                match integer_literal(&subscript.slice) {
                    Some((true, _)) => self.negative_indices += 1,
                    Some((false, value)) if value == "0" => self.zero_indices += 1,
                    Some((false, value)) => {
                        self.positive_indices += 1;
                        match value.parse::<usize>() {
                            Ok(index) => {
                                self.maximum_positive_index = self.maximum_positive_index.max(index)
                            }
                            Err(_) => self.oversized_positive_indices += 1,
                        }
                    }
                    None => self.dynamic_indices += 1,
                }
            }
        }
        visitor::walk_expr(self, expr);
    }
}

fn dedent(src: &str) -> String {
    let lines: Vec<&str> = src.lines().collect();
    let indent = lines
        .iter()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            line.chars()
                .take_while(|character| character.is_whitespace())
                .count()
        })
        .min()
        .unwrap_or(0);
    if indent == 0 {
        return src.to_string();
    }
    lines
        .iter()
        .map(|line| {
            if line.chars().count() >= indent {
                line.chars().skip(indent).collect::<String>()
            } else {
                line.trim_start().to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn count_source(source: &str) -> Result<ArgvCounts, String> {
    let source = dedent(&vouch::paths::normalize_newlines(source));
    let parsed = ruff_python_parser::parse_module(&source).map_err(|error| error.to_string())?;
    if !parsed.has_no_syntax_errors() {
        return Err("unsupported syntax recovery".to_string());
    }
    let module = parsed.into_syntax();
    let mut counts = ArgvCounts::default();
    for statement in &module.body {
        counts.visit_stmt(statement);
    }
    Ok(counts)
}

/// Reads one private decision dump without ever printing its path or rows.
/// `None` means the caller did not request a comparison.
fn decision_dump(var: &str) -> Option<Vec<(String, String)>> {
    let path = std::env::var(var).ok()?;
    let body = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("{var} was set but its decision dump could not be read: {error}"));
    let mut records = Vec::new();
    for (line_number, line) in body.lines().enumerate() {
        let mut fields = line.splitn(3, '\t');
        let index = fields
            .next()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or_else(|| panic!("{var} line {} has no numeric row index", line_number + 1));
        let verdict = fields
            .next()
            .unwrap_or_else(|| panic!("{var} line {} has no verdict", line_number + 1));
        let reason = fields
            .next()
            .unwrap_or_else(|| panic!("{var} line {} has no reason summary", line_number + 1));
        assert_eq!(
            index,
            records.len(),
            "{var} line {} is out of row order",
            line_number + 1
        );
        records.push((verdict.to_string(), reason.to_string()));
    }
    Some(records)
}

fn main() {
    let rows = common::rows_for_measurement();
    let kb = common::shipped_kb();
    let bash = vouch::syntax::scanner_for("bash").expect("bash scanner exists");

    let mut parsed_bash_rows = 0usize;
    let mut python_snippets = 0usize;
    let mut parsed_python_snippets = 0usize;
    let mut python_parse_failures = 0usize;
    let mut snippets_with_sys_argv = 0usize;
    let mut rows_with_sys_argv = 0usize;
    let mut rows_with_mappable_static_index = HashSet::new();
    let mut rows_with_unmapped_index = HashSet::new();
    let mut totals = ArgvCounts::default();

    for (row_index, row) in rows.iter().enumerate() {
        let Ok(scan) = bash.scan(&row.cmd) else {
            continue;
        };
        parsed_bash_rows += 1;
        let expanded = vouch::guards::expand_wrappers_with_sources(
            &kb,
            &scan.commands,
            &scan.heredocs,
            &scan.input_source,
            &scan.args_complete,
            "bash",
            &|_| 4,
        );
        let mut row_found = false;
        for (language, source) in expanded.srcs {
            if language != "python" {
                continue;
            }
            python_snippets += 1;
            match count_source(&source) {
                Ok(counts) => {
                    parsed_python_snippets += 1;
                    if counts.found_any() {
                        snippets_with_sys_argv += 1;
                        row_found = true;
                    }
                    if counts.zero_indices > 0
                        || counts.positive_indices > counts.oversized_positive_indices
                    {
                        rows_with_mappable_static_index.insert(row_index);
                    }
                    if counts.dynamic_indices > 0
                        || counts.negative_indices > 0
                        || counts.oversized_positive_indices > 0
                    {
                        rows_with_unmapped_index.insert(row_index);
                    }
                    totals.add(&counts);
                }
                Err(_) => python_parse_failures += 1,
            }
        }
        rows_with_sys_argv += usize::from(row_found);
    }

    println!("corpus_rows={}", rows.len());
    println!("parsed_bash_rows={parsed_bash_rows}");
    println!("python_snippets={python_snippets}");
    println!("parsed_python_snippets={parsed_python_snippets}");
    println!("python_parse_failures={python_parse_failures}");
    println!("rows_with_sys_argv={rows_with_sys_argv}");
    println!("snippets_with_sys_argv={snippets_with_sys_argv}");
    println!("sys_argv_subscripts={}", totals.subscripts);
    println!("zero_indices={}", totals.zero_indices);
    println!("positive_indices={}", totals.positive_indices);
    println!("negative_indices={}", totals.negative_indices);
    println!("dynamic_indices={}", totals.dynamic_indices);
    println!(
        "oversized_positive_indices={}",
        totals.oversized_positive_indices
    );
    println!("maximum_positive_index={}", totals.maximum_positive_index);

    let before = decision_dump("VOUCH_DUMP_BEFORE");
    let after = decision_dump("VOUCH_DUMP_AFTER");
    assert_eq!(
        before.is_some(),
        after.is_some(),
        "VOUCH_DUMP_BEFORE and VOUCH_DUMP_AFTER must be set together"
    );
    if let (Some(before), Some(after)) = (before, after) {
        assert_eq!(before.len(), rows.len(), "VOUCH_DUMP_BEFORE row count differs from the corpus");
        assert_eq!(after.len(), rows.len(), "VOUCH_DUMP_AFTER row count differs from the corpus");
        let retracted = decision_dump("VOUCH_DUMP_RETRACTED");
        if let Some(records) = &retracted {
            assert_eq!(
                records.len(),
                rows.len(),
                "VOUCH_DUMP_RETRACTED row count differs from the corpus"
            );
        }

        let mut record_changes = 0usize;
        let mut verdict_changes = 0usize;
        let mut asks_to_allow = 0usize;
        let mut asks_to_allow_with_mappable_static = 0usize;
        let mut asks_to_allow_with_unmapped = 0usize;
        let mut unmapped_rows_with_record_changes = 0usize;
        let mut unmapped_rows_with_verdict_changes = 0usize;
        let mut changes_exactly_reverted = 0usize;
        let mut changes_not_exactly_reverted = 0usize;

        for index in 0..rows.len() {
            let record_changed = before[index] != after[index];
            let verdict_changed = before[index].0 != after[index].0;
            if record_changed {
                record_changes += 1;
                if let Some(records) = &retracted {
                    if records[index] == before[index] {
                        changes_exactly_reverted += 1;
                    } else {
                        changes_not_exactly_reverted += 1;
                    }
                }
            }
            if verdict_changed {
                verdict_changes += 1;
            }
            if before[index].0 == "ASK" && after[index].0 == "ALLOW" {
                asks_to_allow += 1;
                asks_to_allow_with_mappable_static +=
                    usize::from(rows_with_mappable_static_index.contains(&index));
                asks_to_allow_with_unmapped += usize::from(rows_with_unmapped_index.contains(&index));
            }
            if rows_with_unmapped_index.contains(&index) {
                unmapped_rows_with_record_changes += usize::from(record_changed);
                unmapped_rows_with_verdict_changes += usize::from(verdict_changed);
            }
        }

        println!("decision_record_changes={record_changes}");
        println!("decision_verdict_changes={verdict_changes}");
        println!("decision_ask_to_allow={asks_to_allow}");
        println!(
            "decision_ask_to_allow_with_mappable_static={asks_to_allow_with_mappable_static}"
        );
        println!("decision_ask_to_allow_with_unmapped={asks_to_allow_with_unmapped}");
        println!("unmapped_index_rows_with_record_changes={unmapped_rows_with_record_changes}");
        println!("unmapped_index_rows_with_verdict_changes={unmapped_rows_with_verdict_changes}");
        if retracted.is_some() {
            println!("decision_changes_exactly_reverted={changes_exactly_reverted}");
            println!("decision_changes_not_exactly_reverted={changes_not_exactly_reverted}");
        }
    }
}
