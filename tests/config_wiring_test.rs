//! Regression gates ensuring:
//!   1. Every top-level field of `Config` in `src/config.rs` has a live runtime
//!      consumer outside `src/config.rs`.
//!   2. Every nested property key in the generated `config.toml` JSON Schema has
//!      a live runtime consumer outside `src/config.rs` (closing the loophole
//!      where an inert leaf field like `[daemon].fail_closed` or
//!      `[daemon].shared_memory` hid inside an otherwise-wired parent table).
//!   3. Every module declared in `src/lib.rs` is transitively reachable from at
//!      least one shipped binary (`src/main.rs` or `src/bin/*.rs`), closing the
//!      loophole where a `pub mod` (like `container_runtime` or `runtime`) was
//!      called only by integration tests and never executed by any binary.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
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

/// Strip `#[cfg(test)]` inline modules so unit tests inside a production module
/// do not falsely mark another module or field as runtime-reachable.
fn strip_cfg_test_blocks(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    let mut cursor = 0;
    while let Some(rel) = source[cursor..].find("#[cfg(test)]") {
        let pos = cursor + rel;
        out.push_str(&source[cursor..pos]);
        // Find the brace block belonging to the #[cfg(test)] item (if any).
        if let Some(open_rel) = source[pos..].find('{') {
            let open = pos + open_rel;
            let mut depth = 0usize;
            let mut end = source.len();
            for (offset, ch) in source[open..].char_indices() {
                match ch {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            end = open + offset + 1;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            cursor = end;
        } else {
            // Standalone #[cfg(test)] line without braces — skip to newline.
            cursor = source[pos..]
                .find('\n')
                .map(|n| pos + n + 1)
                .unwrap_or(source.len());
        }
    }
    out.push_str(&source[cursor..]);
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

/// Map each `pub fn <method>(...)` across every `impl ... { ... }` block in
/// `src/config.rs` to the set of candidate field/key names accessed via `.key`
/// inside that method body.
fn parse_impl_method_field_reads(
    config_src: &str,
    candidates: &[String],
) -> BTreeMap<String, BTreeSet<String>> {
    let stripped = strip_cfg_test_blocks(&strip_line_comments(config_src));
    let mut method_reads: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    let mut search_from = 0;
    while let Some(rel) = stripped[search_from..].find("impl ") {
        let pos = search_from + rel;
        // Skip `impl Trait for Type` blocks only if needed? No — inherent impls
        // carry `pub fn` methods, and trait impls do not use `pub fn`.
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
            for field in candidates {
                if contains_field_access(fn_body, field) {
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

        search_from = pos + "impl ".len() + impl_body.len();
    }

    method_reads
}

fn find_unwired_fields(
    candidates: &[String],
    config_src: &str,
    other_sources: &[String],
) -> Vec<String> {
    let method_reads = parse_impl_method_field_reads(config_src, candidates);

    let cleaned_others: Vec<String> = other_sources
        .iter()
        .map(|s| strip_cfg_test_blocks(&strip_line_comments(s)))
        .collect();

    let mut wired: BTreeSet<String> = BTreeSet::new();

    // 1. Direct `.field` references outside `src/config.rs`.
    for field in candidates {
        if cleaned_others
            .iter()
            .any(|src| contains_field_access(src, field))
        {
            wired.insert(field.clone());
        }
    }

    // 2. Indirect references via a `pub fn` in `src/config.rs` called outside `src/config.rs`.
    for (method, touched_fields) in &method_reads {
        let dot_call = format!(".{method}(");
        let path_call = format!("::{method}(");
        if cleaned_others
            .iter()
            .any(|src| src.contains(&dot_call) || src.contains(&path_call))
        {
            wired.extend(touched_fields.iter().cloned());
        }
    }

    candidates
        .iter()
        .filter(|field| !wired.contains(*field))
        .cloned()
        .collect()
}

fn find_unwired_config_fields(config_src: &str, other_sources: &[String]) -> Vec<String> {
    let fields = parse_config_fields(config_src);
    find_unwired_fields(&fields, config_src, other_sources)
}

fn collect_schema_property_names(schema: &serde_json::Value, out: &mut BTreeSet<String>) {
    match schema {
        serde_json::Value::Object(object) => {
            if let Some(properties) = object
                .get("properties")
                .and_then(serde_json::Value::as_object)
            {
                out.extend(properties.keys().cloned());
            }
            for value in object.values() {
                collect_schema_property_names(value, out);
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                collect_schema_property_names(value, out);
            }
        }
        _ => {}
    }
}

/// Find every property key in a JSON Schema for `config.toml` that has no live
/// consumer outside `src/config.rs`, accounting for explicit schema-to-Rust
/// field renames (which themselves must still be wired) and the single reserved
/// top-level `version` key.
fn find_unwired_schema_keys(
    schema_json: &str,
    config_src: &str,
    other_sources: &[String],
    renames: &[(&str, &str)],
    reserved_keys: &[&str],
) -> Vec<String> {
    let schema: serde_json::Value =
        serde_json::from_str(schema_json).expect("config schema JSON parses");
    let mut keys = BTreeSet::new();
    collect_schema_property_names(&schema, &mut keys);

    let rename_map: BTreeMap<&str, &str> = renames.iter().copied().collect();
    let reserved_set: BTreeSet<&str> = reserved_keys.iter().copied().collect();

    // Translate schema keys through the rename map into the Rust field names we
    // require to be live-consumed outside `src/config.rs`.
    let mut rust_candidates = Vec::new();
    let mut schema_to_rust: Vec<(String, String)> = Vec::new();
    for key in keys {
        if reserved_set.contains(key.as_str()) {
            continue;
        }
        let rust_name = rename_map
            .get(key.as_str())
            .copied()
            .unwrap_or(key.as_str())
            .to_string();
        rust_candidates.push(rust_name.clone());
        schema_to_rust.push((key, rust_name));
    }

    let unwired_rust: BTreeSet<String> =
        find_unwired_fields(&rust_candidates, config_src, other_sources)
            .into_iter()
            .collect();

    schema_to_rust
        .into_iter()
        .filter(|(_, rust_name)| unwired_rust.contains(rust_name))
        .map(|(schema_key, _)| schema_key)
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

/// Parse every top-level `mod <name>;` / `pub mod <name>;` from `src/lib.rs`.
fn parse_lib_modules(lib_rs: &str) -> Vec<String> {
    let stripped = strip_cfg_test_blocks(&strip_line_comments(lib_rs));
    let mut mods = Vec::new();
    for line in stripped.lines() {
        let trimmed = line.trim();
        let rest = trimmed
            .strip_prefix("pub mod ")
            .or_else(|| trimmed.strip_prefix("mod "));
        if let Some(rest) = rest {
            if let Some(name) = rest.strip_suffix(';') {
                let name = name.trim();
                if !name.is_empty()
                    && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                {
                    mods.push(name.to_string());
                }
            }
        }
    }
    mods
}

/// Returns true if `source` references module `module_name` via `<prefix>::<module_name>`
/// or inside a brace-grouped `use <prefix>::{..., <module_name>, ...}` import.
fn source_references_module(source: &str, prefix: &str, module_name: &str) -> bool {
    let direct = format!("{prefix}::{module_name}");
    if contains_ident_token(source, &direct) {
        return true;
    }
    let group_marker = format!("{prefix}::{{");
    let mut cursor = 0;
    while let Some(rel) = source[cursor..].find(&group_marker) {
        let pos = cursor + rel;
        if let Some(body) = extract_brace_block(source, pos) {
            if contains_ident_token(body, module_name) {
                return true;
            }
            cursor = pos + group_marker.len() + body.len();
        } else {
            break;
        }
    }
    false
}

/// Compute all modules declared in `modules` that are NOT transitively reachable
/// from any shipped binary entry-point source (`entry_sources`).
fn find_unreachable_modules(
    modules: &[String],
    entry_sources: &[String],
    module_sources: &BTreeMap<String, String>,
) -> Vec<String> {
    let cleaned_entries: Vec<String> = entry_sources
        .iter()
        .map(|s| strip_cfg_test_blocks(&strip_line_comments(s)))
        .collect();
    let cleaned_modules: BTreeMap<String, String> = module_sources
        .iter()
        .map(|(k, v)| (k.clone(), strip_cfg_test_blocks(&strip_line_comments(v))))
        .collect();

    let mut reachable: BTreeSet<String> = BTreeSet::new();
    let mut queue: VecDeque<String> = VecDeque::new();

    for m in modules {
        let hit = cleaned_entries.iter().any(|src| {
            source_references_module(src, "vouch", m) || source_references_module(src, "crate", m)
        });
        if hit && reachable.insert(m.clone()) {
            queue.push_back(m.clone());
        }
    }

    while let Some(current) = queue.pop_front() {
        let Some(src) = cleaned_modules.get(&current) else {
            continue;
        };
        for m in modules {
            if reachable.contains(m) {
                continue;
            }
            if source_references_module(src, "crate", m)
                || source_references_module(src, "super", m)
            {
                reachable.insert(m.clone());
                queue.push_back(m.clone());
            }
        }
    }

    modules
        .iter()
        .filter(|m| !reachable.contains(*m))
        .cloned()
        .collect()
}

fn read_module_tree_source(src_dir: &Path, module_name: &str) -> String {
    let file_path = src_dir.join(format!("{module_name}.rs"));
    if file_path.is_file() {
        return std::fs::read_to_string(&file_path).expect("module .rs file reads");
    }
    let dir_path = src_dir.join(module_name);
    if dir_path.is_dir() {
        let mut combined = String::new();
        let mut pending = vec![dir_path];
        while let Some(dir) = pending.pop() {
            for entry in std::fs::read_dir(&dir).expect("module dir reads") {
                let entry = entry.expect("module dir entry reads");
                let path = entry.path();
                if path.is_dir() {
                    pending.push(path);
                } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                    combined.push_str(&std::fs::read_to_string(&path).expect("module file reads"));
                    combined.push('\n');
                }
            }
        }
        return combined;
    }
    panic!("could not find source file or directory for module `{module_name}` in src/");
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
fn every_nested_config_schema_key_has_a_live_runtime_consumer() {
    let root = manifest_dir();
    let src_dir = root.join("src");
    let config_path = src_dir.join("config.rs");
    let config_src = std::fs::read_to_string(&config_path).expect("src/config.rs reads");
    let other_sources = collect_rust_sources(&src_dir, &config_path);

    let docs = vouch::cli::generate_schema_docs();
    // Explicit schema-to-Rust field renames in `src/config.rs`:
    //   - `[lang.<L>]` -> `Config.langs`
    //   - `[protected].paths` -> unwrapped into `Config.protected`
    // And `version` is the single reserved top-level config-format version key.
    let renames = [("lang", "langs"), ("paths", "protected")];
    let reserved = ["version"];

    let unwired =
        find_unwired_schema_keys(&docs.config_json, &config_src, &other_sources, &renames, &reserved);
    assert!(
        unwired.is_empty(),
        "config.toml schema keys have no live runtime consumer outside src/config.rs: {unwired:?}\n\
         Wire the setting into the runtime decision/daemon/journal pipeline or remove the inert key."
    );
}

#[test]
fn every_src_lib_module_is_reachable_from_a_shipped_binary() {
    let root = manifest_dir();
    let src_dir = root.join("src");
    let lib_rs = std::fs::read_to_string(src_dir.join("lib.rs")).expect("src/lib.rs reads");
    let modules = parse_lib_modules(&lib_rs);
    assert!(!modules.is_empty(), "parser found no modules in src/lib.rs");

    let mut entry_sources = vec![
        std::fs::read_to_string(src_dir.join("main.rs")).expect("src/main.rs reads"),
    ];
    let bin_dir = src_dir.join("bin");
    if bin_dir.is_dir() {
        for entry in std::fs::read_dir(&bin_dir).expect("src/bin reads") {
            let path = entry.expect("src/bin entry reads").path();
            if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                entry_sources.push(std::fs::read_to_string(&path).expect("src/bin file reads"));
            }
        }
    }

    let mut module_sources = BTreeMap::new();
    for m in &modules {
        module_sources.insert(m.clone(), read_module_tree_source(&src_dir, m));
    }

    let unreachable = find_unreachable_modules(&modules, &entry_sources, &module_sources);
    assert!(
        unreachable.is_empty(),
        "src/lib.rs modules are not reachable from src/main.rs or src/bin/*.rs: {unreachable:?}\n\
         Wire the module into a shipped binary entry point or remove the test-only dead subsystem."
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

#[test]
fn nested_config_schema_wiring_gate_catches_unwired_leaf_key() {
    let fake_schema = r#"{
        "type": "object",
        "properties": {
            "version": { "type": "integer" },
            "daemon": {
                "type": "object",
                "properties": {
                    "socket_path": { "type": "string" },
                    "timeout_ms": { "type": "integer" },
                    "inert_fail_closed": { "type": "boolean" }
                }
            },
            "shadow": {
                "type": "object",
                "properties": {
                    "modes": { "type": "array" }
                }
            }
        }
    }"#;

    let fake_config = r#"
impl Config {
    pub fn stands_down_in(&self, mode: &str) -> bool {
        self.shadow.as_ref().is_some_and(|s| s.modes.contains(mode))
    }
}
"#;

    let fake_runtime = vec![r#"
fn run(cfg: &Config) {
    let _ = (&cfg.daemon.socket_path, cfg.daemon.timeout_ms);
    let _ = cfg.stands_down_in("auto");
    // cfg.daemon.inert_fail_closed is commented out
}
"#
    .to_string()];

    let unwired = find_unwired_schema_keys(
        fake_schema,
        fake_config,
        &fake_runtime,
        &[],
        &["version"],
    );
    assert_eq!(unwired, vec!["inert_fail_closed".to_string()]);
}

#[test]
fn binary_reachability_gate_catches_test_only_orphan_module() {
    let modules = vec![
        "wired_direct".to_string(),
        "wired_transitive".to_string(),
        "orphan_test_only".to_string(),
        "commented_only".to_string(),
    ];

    let entry_sources = vec![r#"
use vouch::{wired_direct};
// use vouch::commented_only;
fn main() {
    wired_direct::go();
}
#[cfg(test)]
mod tests {
    use vouch::orphan_test_only;
}
"#
    .to_string()];

    let mut module_sources = BTreeMap::new();
    module_sources.insert(
        "wired_direct".to_string(),
        "pub fn go() { crate::wired_transitive::step(); }".to_string(),
    );
    module_sources.insert("wired_transitive".to_string(), "pub fn step() {}".to_string());
    module_sources.insert("orphan_test_only".to_string(), "pub fn dead() {}".to_string());
    module_sources.insert("commented_only".to_string(), "pub fn dead2() {}".to_string());

    let unreachable = find_unreachable_modules(&modules, &entry_sources, &module_sources);
    assert_eq!(
        unreachable,
        vec![
            "orphan_test_only".to_string(),
            "commented_only".to_string(),
        ]
    );
}
