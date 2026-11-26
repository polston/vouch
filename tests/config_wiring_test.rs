//! Regression gate ensuring every top-level field of `Config` in `src/config.rs`
//! has at least one live runtime consumer outside `src/config.rs`.
//!
//! Previously, entire config tables (`[sandbox]`, `[sandbox.cgroups]`,
//! `[runtime]`, `[runtime.linux]`, `[runtime.ebpf]`, `[daemon].shared_memory`)
//! were deserialized, documented, and validated in `src/config.rs` without any
//! runtime consumer in `src/` ever reading them. This gate catches any future
//! top-level `Config` field that is parsed into `Config` but left unwired.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

fn manifest_dir() -> PathBuf {
    std::env::var_os("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .expect("CARGO_MANIFEST_DIR is unset: run this test through cargo")
}

/// Strip `//` line comments so commented-out references never count as live consumers.
fn strip_line_comments(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    for line in source.lines() {
        let code = match line.find("//") {
            Some(idx) => &line[..idx],
            None => line,
        };
        out.push_str(code);
        out.push('\n');
    }
    out
}

/// Returns true if `needle` appears in `haystack` as a whole identifier token
/// (not immediately preceded or followed by an ASCII alphanumeric or `_`).
fn contains_ident_token(haystack: &str, needle: &str) -> bool {
    haystack.match_indices(needle).any(|(start, _)| {
        let before = haystack[..start].chars().next_back();
        let after = haystack[start + needle.len()..].chars().next();
        before.is_none_or(|c| !c.is_ascii_alphanumeric() && c != '_')
            && after.is_none_or(|c| !c.is_ascii_alphanumeric() && c != '_')
    })
}

/// Returns true if `.field` appears in `haystack` as a Rust field access
/// (not `..field` and not a prefix of a longer identifier like `.field_extra`).
fn contains_field_access(haystack: &str, field: &str) -> bool {
    let needle = format!(".{field}");
    haystack.match_indices(&needle).any(|(start, _)| {
        let before = haystack[..start].chars().next_back();
        let after = haystack[start + needle.len()..].chars().next();
        before != Some('.')
            && after.is_none_or(|c| !c.is_ascii_alphanumeric() && c != '_')
    })
}

/// Extract brace-balanced block starting at the first `{` at or after `start`.
fn extract_brace_block(source: &str, start: usize) -> Option<&str> {
    let open = source[start..].find('{')? + start;
    let mut depth = 0usize;
    for (offset, ch) in source[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&source[open + 1..open + offset]);
                }
            }
            _ => {}
        }
    }
    None
}

/// Extract every `pub <field>:` name from `pub struct Config { ... }`.
fn parse_config_fields(config_src: &str) -> Vec<String> {
    let stripped = strip_line_comments(config_src);
    let marker = stripped
        .find("pub struct Config")
        .expect("src/config.rs defines `pub struct Config`");
    let body = extract_brace_block(&stripped, marker)
        .expect("`pub struct Config` has a brace-delimited body");

    let mut fields = Vec::new();
    for line in body.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("pub ") {
            if let Some((name, _)) = rest.split_once(':') {
                let name = name.trim();
                if !name.is_empty()
                    && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                {
                    fields.push(name.to_string());
                }
            }
        }
    }
    fields
}

/// Map each `pub fn <method>(&self, ...)` in `impl Config { ... }` to the set
/// of `Config` field names it reads via `self.<field>`.
fn parse_config_method_field_reads(
    config_src: &str,
    fields: &[String],
) -> BTreeMap<String, BTreeSet<String>> {
    let stripped = strip_line_comments(config_src);
    let mut method_reads: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    let mut search_from = 0;
    while let Some(rel) = stripped[search_from..].find("impl Config") {
        let pos = search_from + rel;
        let after_header = &stripped[pos + "impl Config".len()..];
        let trimmed_after = after_header.trim_start();
        if !trimmed_after.starts_with('{') {
            search_from = pos + "impl Config".len();
            continue;
        }
        let Some(impl_body) = extract_brace_block(&stripped, pos) else {
            break;
        };

        let mut fn_from = 0;
        while let Some(fn_rel) = impl_body[fn_from..].find("pub fn ") {
            let fn_pos = fn_from + fn_rel;
            let after_pub_fn = &impl_body[fn_pos + "pub fn ".len()..];
            let Some(paren_idx) = after_pub_fn.find('(') else {
                break;
            };
            let method_name = after_pub_fn[..paren_idx].trim();
            let Some(fn_body) = extract_brace_block(impl_body, fn_pos) else {
                break;
            };

            let mut touched = BTreeSet::new();
            for field in fields {
                let needle = format!("self.{field}");
                if contains_ident_token(fn_body, &needle) {
                    touched.insert(field.clone());
                }
            }
            if !method_name.is_empty() && !touched.is_empty() {
                method_reads
                    .entry(method_name.to_string())
                    .or_default()
                    .extend(touched);
            }
            fn_from = fn_pos + "pub fn ".len();
        }

        search_from = pos + "impl Config".len() + impl_body.len();
    }

    method_reads
}

fn find_unwired_config_fields(config_src: &str, other_sources: &[String]) -> Vec<String> {
    let fields = parse_config_fields(config_src);
    let method_reads = parse_config_method_field_reads(config_src, &fields);

    let cleaned_others: Vec<String> = other_sources
        .iter()
        .map(|s| strip_line_comments(s))
        .collect();

    let mut wired_fields: BTreeSet<String> = BTreeSet::new();

    // 1. Direct `.field` references outside `src/config.rs`.
    for field in &fields {
        if cleaned_others
            .iter()
            .any(|src| contains_field_access(src, field))
        {
            wired_fields.insert(field.clone());
        }
    }

    // 2. Indirect references via a `pub fn` on `impl Config` called outside `src/config.rs`.
    for (method, touched_fields) in &method_reads {
        let call = format!(".{method}(");
        if cleaned_others.iter().any(|src| src.contains(&call)) {
            wired_fields.extend(touched_fields.iter().cloned());
        }
    }

    fields
        .into_iter()
        .filter(|field| !wired_fields.contains(field))
        .collect()
}

fn collect_rust_sources(dir: &Path, exclude: &Path) -> Vec<String> {
    let mut pending = vec![dir.to_path_buf()];
    let mut sources = Vec::new();
    while let Some(current) = pending.pop() {
        for entry in std::fs::read_dir(&current).expect("src directory reads") {
            let entry = entry.expect("src entry reads");
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().and_then(|e| e.to_str()) == Some("rs") && path != exclude {
                sources.push(std::fs::read_to_string(&path).expect("Rust source file reads"));
            }
        }
    }
    sources
}

#[test]
fn every_top_level_config_field_has_a_live_runtime_consumer() {
    let root = manifest_dir();
    let src_dir = root.join("src");
    let config_path = src_dir.join("config.rs");
    let config_src = std::fs::read_to_string(&config_path).expect("src/config.rs reads");
    let other_sources = collect_rust_sources(&src_dir, &config_path);

    let fields = parse_config_fields(&config_src);
    assert!(
        !fields.is_empty(),
        "parser found no fields in `pub struct Config`"
    );

    let unwired = find_unwired_config_fields(&config_src, &other_sources);
    assert!(
        unwired.is_empty(),
        "top-level Config fields have no live runtime consumer outside src/config.rs: {unwired:?}\n\
         Wire the field into the runtime decision/daemon/journal pipeline or remove the inert config table."
    );
}

#[test]
fn config_wiring_gate_catches_unwired_fields_and_uncalled_accessors() {
    let fake_config = r#"
pub struct Config {
    pub wired_direct: bool,
    pub wired_via_method: bool,
    pub inert_sandbox: bool,
    pub inert_with_unused_getter: bool,
    pub commented_only: bool,
}

impl Config {
    pub fn check_method(&self) -> bool {
        self.wired_via_method
    }

    pub fn unused_getter(&self) -> bool {
        self.inert_with_unused_getter
    }
}
"#;

    let fake_runtime = vec![r#"
fn run(cfg: &Config) {
    let _ = cfg.wired_direct;
    let _ = cfg.check_method();
    // let _ = cfg.commented_only;
}
"#
    .to_string()];

    let unwired = find_unwired_config_fields(fake_config, &fake_runtime);
    assert_eq!(
        unwired,
        vec![
            "inert_sandbox".to_string(),
            "inert_with_unused_getter".to_string(),
            "commented_only".to_string(),
        ]
    );
}
