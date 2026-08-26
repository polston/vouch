//! Documents asserted against code. `docs/reference/config-schema.json`,
//! `docs/reference/knowledge-schema.json` and `docs/reference/reference.md`
//! are committed artifacts generated from the same structs the config and
//! knowledge loaders actually read (`vouch::cli::generate_schema_docs`), and
//! two more tests hold the release-flow invariants to the same standard.
//!
//! Seven independent gates:
//!   1. the committed files must match what the structs generate RIGHT NOW —
//!      otherwise the reference page is describing a shape the loader no
//!      longer accepts, or has stopped accepting a shape it still does.
//!   2. `vouch.example.toml` must name every construct any scanner can
//!      trip — an omission there is exactly how `evaluated_input` went
//!      undocumented long enough for an inheritance surprise to hide behind
//!      it (CLAUDE.md, this task's own reason for existing).
//!   3. the five version fields release-please drives from one commit —
//!      `Cargo.toml`, this package's `Cargo.lock` entry,
//!      both plugin manifests, and Claude's versioned marketplace entry —
//!      agree with each other. Codex's marketplace entry has no version field.
//!   4. the tracked `CHANGELOG.md` carries no forge remnant (a link or a
//!      commit id) that would name this private repository or point at a
//!      commit the public mirror does not have.
//!   5. in the development repository, every accepted schema key and every
//!      settable construct has one exact vocabulary row in private
//!      `CLAUDE.md` §0.0; the public mirror deliberately omits that file.
//!   6. the example config advertises exactly the registered constructs, with
//!      neither omissions nor dead settings.
//!   7. current operational documentation present in either repository does
//!      not claim a registered scanner is absent.

/// `core.autocrlf` on a Windows checkout rewrites a committed LF file to
/// CRLF on disk; the generator always emits LF. Normalizing before compare
/// keeps this test about CONTENT, not about which machine last checked the
/// repository out — a real content edit still differs after normalizing,
/// only the line-ending convention is ignored.
fn normalize(s: &str) -> String {
    s.replace("\r\n", "\n")
}

/// Resolve the checkout at run time. Compiling `CARGO_MANIFEST_DIR` into this
/// binary makes a cached test artifact point at the checkout that built it;
/// after that checkout is removed, otherwise-current tests fail on files that
/// are present in the checkout running them. `cargo test` supplies the same
/// variable to the test process, without making the artifact location-bound.
fn manifest_dir() -> std::path::PathBuf {
    std::env::var_os("CARGO_MANIFEST_DIR")
        .map(std::path::PathBuf::from)
        .expect("CARGO_MANIFEST_DIR is unset: run this test through cargo")
}

/// Resolve a development-only document without making the public mirror's
/// deliberately smaller manifest fail its own test suite.
///
/// Absence is allowed only when the private release configuration is absent
/// too. That distinguishes the public product mirror from an accidentally
/// damaged development checkout: deleting `CLAUDE.md` here must still fail
/// loudly instead of turning its glossary ratchet off.
fn development_only_document(
    root: &std::path::Path,
    relative: &str,
) -> Option<std::path::PathBuf> {
    let path = root.join(relative);
    match development_document_presence(
        path.is_file(),
        root.join("release-please-config.json").is_file(),
    ) {
        Ok(true) => Some(path),
        Ok(false) => None,
        Err(()) => panic!(
            "development-only document {relative} is missing from the development repository"
        ),
    }
}

fn development_document_presence(
    document_exists: bool,
    development_repository: bool,
) -> Result<bool, ()> {
    match (document_exists, development_repository) {
        (true, _) => Ok(true),
        (false, false) => Ok(false),
        (false, true) => Err(()),
    }
}

#[test]
fn development_only_documents_may_be_absent_only_from_the_public_tree() {
    assert_eq!(development_document_presence(false, false), Ok(false));
    assert_eq!(development_document_presence(false, true), Err(()));
    assert_eq!(development_document_presence(true, false), Ok(true));
    assert_eq!(development_document_presence(true, true), Ok(true));
}

#[test]
fn rust_test_artifacts_do_not_embed_a_checkout_path() {
    let root = manifest_dir();
    let forbidden = ["env", "!(\"CARGO_MANIFEST_DIR\")"].concat();
    let mut pending = vec![
        std::path::PathBuf::from("tests"),
        std::path::PathBuf::from("examples"),
    ];
    let mut offenders = Vec::new();

    while let Some(relative_dir) = pending.pop() {
        for entry in
            std::fs::read_dir(root.join(&relative_dir)).expect("Rust source directory reads")
        {
            let entry = entry.expect("Rust source directory entry reads");
            let relative = relative_dir.join(entry.file_name());
            let path = entry.path();
            if path.is_dir() {
                pending.push(relative);
            } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
                let source = std::fs::read_to_string(&path).expect("Rust source file reads");
                if source.contains(&forbidden) {
                    offenders.push(relative);
                }
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "these Rust sources compile a checkout path into their artifacts: {offenders:?}"
    );
}

#[test]
fn the_shipped_knowledge_declares_the_schema_this_binary_understands() {
    // A new `[[program]]` or `[[program.rule]]` field is only half a change:
    // the shipped file has to DECLARE the version that carries it, or an
    // operator running an older binary against it gets "TOML parse error at
    // line N" — the whole file refused, everything asking, and the reason
    // pointing at a line number instead of at an out-of-date binary. The
    // version key is what turns that into the precise "this knowledge file is
    // newer than this vouch binary" refusal, and nothing else checks it.
    // Read the PARSED value, not a line scan. A scan here would be the
    // fourth spelling of "find the version line" and the loosest of them —
    // `strip_prefix("version")` accepts any key merely starting with that
    // word, and nothing would strip a trailing comment. The loader already
    // holds the answer, and §6.1 is about exactly this.
    let shipped = std::fs::read_to_string(manifest_dir().join("knowledge.toml"))
        .expect("the shipped knowledge file is readable");
    let declared: u32 = vouch::guards::load(&shipped)
        .expect("the shipped knowledge file parses")
        .version
        .expect("knowledge.toml declares a top-level `version`");
    assert_eq!(
        declared,
        vouch::knowledge::KNOWLEDGE_SCHEMA_VERSION,
        "knowledge.toml says version = {declared} but this binary understands \
         {}. A new knowledge field bumps BOTH.",
        vouch::knowledge::KNOWLEDGE_SCHEMA_VERSION
    );
}

#[test]
fn the_committed_schemas_match_the_structs() {
    let docs = vouch::cli::generate_schema_docs();
    let checks: [(&str, &str); 3] = [
        ("docs/reference/config-schema.json", &docs.config_json),
        ("docs/reference/knowledge-schema.json", &docs.knowledge_json),
        ("docs/reference/reference.md", &docs.reference_md),
    ];
    let mut stale = Vec::new();
    for (path, generated) in checks {
        match std::fs::read_to_string(path) {
            Ok(committed) => {
                if normalize(&committed) != normalize(generated) {
                    stale.push(path);
                }
            }
            Err(e) => panic!("could not read committed {path}: {e}"),
        }
    }
    assert!(
        stale.is_empty(),
        "these committed schema docs no longer match the structs: {stale:?}\n\
         regenerate with `vouch schema config --write` and `vouch schema knowledge \
         --write`, then review the diff"
    );
}

fn construct_documentation_gaps(example: &str) -> (Vec<String>, Vec<String>, Vec<String>) {
    let parsed: toml::Value = toml::from_str(example).expect("vouch.example.toml parses as TOML");
    let language_tables = parsed
        .get("lang")
        .and_then(toml::Value::as_table)
        .expect("vouch.example.toml has a [lang] table");
    let mut missing_languages = Vec::new();
    let mut missing = Vec::new();
    let mut extra = Vec::new();

    for lang in vouch::syntax::scanner_languages() {
        let Some(language) = language_tables.get(lang).and_then(toml::Value::as_table) else {
            missing_languages.push(lang.to_string());
            continue;
        };
        let documented: std::collections::BTreeSet<_> = language
            .get("constructs")
            .and_then(toml::Value::as_table)
            .into_iter()
            .flat_map(|table| table.keys().map(String::as_str))
            .collect();
        let scanner = vouch::syntax::scanner_for(lang).expect("registered scanner exists");
        let known: std::collections::BTreeSet<_> =
            scanner.known_constructs().iter().copied().collect();

        missing.extend(
            known
                .difference(&documented)
                .map(|name| format!("{lang}/{name}")),
        );
        extra.extend(
            documented
                .difference(&known)
                .map(|name| format!("{lang}/{name}")),
        );
    }
    (missing_languages, missing, extra)
}

#[test]
fn the_example_config_documents_exactly_every_known_construct() {
    let example = std::fs::read_to_string("vouch.example.toml").expect("vouch.example.toml reads");
    let (missing_languages, missing, extra) = construct_documentation_gaps(&example);
    assert!(
        missing_languages.is_empty() && missing.is_empty() && extra.is_empty(),
        "vouch.example.toml construct mismatch: missing languages {missing_languages:?}; \
         missing constructs {missing:?}; extra constructs {extra:?}"
    );
}

#[test]
fn the_example_config_check_detects_an_omission_and_a_dead_setting() {
    let example = std::fs::read_to_string("vouch.example.toml").expect("vouch.example.toml reads");
    let changed = example.replacen("dynamic_command = \"allow\"", "dead_construct = \"ask\"", 1);
    let (_, missing, extra) = construct_documentation_gaps(&changed);
    assert!(missing.iter().any(|name| name == "bash/dynamic_command"));
    assert!(extra.iter().any(|name| name == "bash/dead_construct"));
}

fn collect_schema_property_names(
    schema: &serde_json::Value,
    out: &mut std::collections::BTreeSet<String>,
) {
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

fn exact_glossary_names(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| {
            let rest = line.strip_prefix("| **`")?;
            let (name, _) = rest.split_once("`** |")?;
            (!name.is_empty() && !name.contains('`')).then(|| name.to_string())
        })
        .collect()
}

#[test]
fn every_schema_key_and_construct_has_one_exact_glossary_row() {
    let root = manifest_dir();
    let Some(claude_path) = development_only_document(&root, "CLAUDE.md") else {
        return;
    };
    let generated = vouch::cli::generate_schema_docs();
    let mut schema_keys = std::collections::BTreeSet::new();
    for json in [&generated.config_json, &generated.knowledge_json] {
        let schema: serde_json::Value =
            serde_json::from_str(json).expect("generated schema parses");
        collect_schema_property_names(&schema, &mut schema_keys);
    }

    let mut constructs = std::collections::BTreeSet::new();
    for lang in vouch::syntax::scanner_languages() {
        constructs.extend(
            vouch::syntax::scanner_for(lang)
                .expect("registered scanner exists")
                .known_constructs()
                .iter()
                .map(|name| name.to_string()),
        );
    }

    let claude = std::fs::read_to_string(claude_path).expect("CLAUDE.md reads");
    let rows = exact_glossary_names(&claude);
    let glossary: std::collections::BTreeSet<_> = rows.iter().cloned().collect();
    let duplicates: Vec<_> = glossary
        .iter()
        .filter(|name| rows.iter().filter(|row| *row == *name).count() > 1)
        .cloned()
        .collect();
    let missing_schema: Vec<_> = schema_keys.difference(&glossary).cloned().collect();
    let missing_constructs: Vec<_> = constructs.difference(&glossary).cloned().collect();

    assert!(
        duplicates.is_empty() && missing_schema.is_empty() && missing_constructs.is_empty(),
        "CLAUDE.md §0.0 exact glossary mismatch: duplicate rows {duplicates:?}; \
         missing schema keys {missing_schema:?}; missing constructs {missing_constructs:?}"
    );
}

fn word_present(paragraph: &str, word: &str) -> bool {
    paragraph.match_indices(word).any(|(start, _)| {
        let before = paragraph[..start].chars().next_back();
        let after = paragraph[start + word.len()..].chars().next();
        before.is_none_or(|c| !c.is_ascii_alphanumeric() && c != '_')
            && after.is_none_or(|c| !c.is_ascii_alphanumeric() && c != '_')
    })
}

fn false_scanner_claims<'a>(paragraphs: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    let mut claims = Vec::new();
    for paragraph in paragraphs {
        let normalized = paragraph.to_ascii_lowercase();
        if normalized.contains("no scanner") {
            for lang in vouch::syntax::scanner_languages() {
                if word_present(&normalized, lang) {
                    claims.push(lang.to_string());
                }
            }
        }
    }
    claims.sort();
    claims.dedup();
    claims
}

fn markdown_paragraphs(text: &str) -> Vec<String> {
    let mut paragraphs = Vec::new();
    let mut current = Vec::new();
    let flush = |current: &mut Vec<&str>, paragraphs: &mut Vec<String>| {
        if !current.is_empty() {
            paragraphs.push(current.join(" "));
            current.clear();
        }
    };

    for line in text.lines() {
        let trimmed = line.trim();
        let numbered = trimmed
            .split_once(". ")
            .is_some_and(|(number, _)| number.chars().all(|c| c.is_ascii_digit()));
        let starts_block = trimmed.starts_with("| ")
            || trimmed.starts_with("- ")
            || trimmed.starts_with("* ")
            || trimmed.starts_with('#')
            || numbered;
        if trimmed.is_empty() || starts_block {
            flush(&mut current, &mut paragraphs);
        }
        if !trimmed.is_empty() {
            current.push(trimmed);
        }
        if trimmed.starts_with("| ") {
            flush(&mut current, &mut paragraphs);
        }
    }
    flush(&mut current, &mut paragraphs);
    paragraphs
}

fn toml_comment_paragraphs(text: &str) -> Vec<String> {
    let mut paragraphs = Vec::new();
    let mut current = Vec::new();
    for line in text.lines() {
        let comment = line.trim_start().strip_prefix('#').map(str::trim);
        match comment {
            Some("") | None => {
                if !current.is_empty() {
                    paragraphs.push(current.join(" "));
                    current.clear();
                }
            }
            Some(line) => current.push(line),
        }
    }
    if !current.is_empty() {
        paragraphs.push(current.join(" "));
    }
    paragraphs
}

fn rust_doc_paragraphs(text: &str) -> Vec<String> {
    let mut paragraphs = Vec::new();
    let mut current = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim_start();
        let doc = trimmed
            .strip_prefix("///")
            .or_else(|| trimmed.strip_prefix("//!"));
        match doc.map(str::trim) {
            Some("") | None => {
                if !current.is_empty() {
                    paragraphs.push(current.join(" "));
                    current.clear();
                }
            }
            Some(line) => current.push(line),
        }
    }
    if !current.is_empty() {
        paragraphs.push(current.join(" "));
    }
    paragraphs
}

fn files_with_extension(root: &std::path::Path, extension: &str) -> Vec<std::path::PathBuf> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(dir).expect("documentation directory reads") {
            let entry = entry.expect("documentation entry reads");
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().and_then(|value| value.to_str()) == Some(extension) {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

#[test]
fn current_documentation_does_not_deny_a_registered_scanner() {
    let root = manifest_dir();
    let mut markdown = ["README.md"]
        .into_iter()
        .map(|path| root.join(path))
        .collect::<Vec<_>>();
    markdown.extend(development_only_document(&root, "CLAUDE.md"));
    markdown.extend(files_with_extension(&root.join("plugin"), "md"));
    markdown.extend(files_with_extension(&root.join("docs/reference"), "md"));

    let mut offenders = Vec::new();
    for path in markdown {
        let text = std::fs::read_to_string(&path).expect("current documentation reads");
        let paragraphs = markdown_paragraphs(&text);
        for lang in false_scanner_claims(paragraphs.iter().map(String::as_str)) {
            offenders.push(format!(
                "{}: {lang}",
                path.strip_prefix(&root).unwrap().display()
            ));
        }
    }
    for path in [root.join("knowledge.toml"), root.join("vouch.example.toml")] {
        let text = std::fs::read_to_string(&path).expect("current TOML documentation reads");
        let paragraphs = toml_comment_paragraphs(&text);
        for lang in false_scanner_claims(paragraphs.iter().map(String::as_str)) {
            offenders.push(format!(
                "{}: {lang}",
                path.strip_prefix(&root).unwrap().display()
            ));
        }
    }
    for path in files_with_extension(&root.join("src"), "rs") {
        let text = std::fs::read_to_string(&path).expect("Rust source reads");
        let paragraphs = rust_doc_paragraphs(&text);
        for lang in false_scanner_claims(paragraphs.iter().map(String::as_str)) {
            offenders.push(format!(
                "{}: {lang}",
                path.strip_prefix(&root).unwrap().display()
            ));
        }
    }

    assert!(
        offenders.is_empty(),
        "current operational documentation says a registered language has no scanner: {offenders:?}"
    );
}

#[test]
fn the_current_document_claim_check_distinguishes_registered_languages() {
    assert_eq!(
        false_scanner_claims(["Python has no scanner."]),
        vec!["python"]
    );
    assert!(false_scanner_claims(["JavaScript has no scanner."]).is_empty());
}

/// The version lives in five published fields. release-please writes all five in
/// one commit, so they cannot drift while that holds — this fails loudly if it
/// stops holding, or if someone edits one by hand.
///
/// It asserts AGREEMENT, never a particular value, which is what makes it true
/// in the public mirror as well: `tests/` publishes wholesale.
#[test]
fn the_five_version_fields_agree() {
    let root = manifest_dir();

    let cargo: toml::Value =
        toml::from_str(&std::fs::read_to_string(root.join("Cargo.toml")).unwrap()).unwrap();
    let from_cargo = cargo["package"]["version"].as_str().unwrap().to_string();

    let lock: toml::Value =
        toml::from_str(&std::fs::read_to_string(root.join("Cargo.lock")).unwrap()).unwrap();
    let from_lock = lock["package"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"].as_str() == Some("vouch"))
        .expect("Cargo.lock has no entry named vouch")["version"]
        .as_str()
        .unwrap()
        .to_string();

    let plugin: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(root.join("plugin/.claude-plugin/plugin.json")).unwrap(),
    )
    .unwrap();
    let from_plugin = plugin["version"].as_str().unwrap().to_string();

    let market: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(root.join(".claude-plugin/marketplace.json")).unwrap(),
    )
    .unwrap();
    let from_market = market["plugins"][0]["version"].as_str().unwrap().to_string();

    let codex_plugin: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(root.join("plugin/.codex-plugin/plugin.json")).unwrap(),
    )
    .unwrap();
    let from_codex_plugin = codex_plugin["version"].as_str().unwrap().to_string();

    assert_eq!(
        from_cargo, from_lock,
        "Cargo.toml says {from_cargo}, Cargo.lock's vouch entry says {from_lock}"
    );
    assert_eq!(
        from_cargo, from_plugin,
        "Cargo.toml says {from_cargo}, plugin.json says {from_plugin}"
    );
    assert_eq!(
        from_cargo, from_market,
        "Cargo.toml says {from_cargo}, marketplace.json says {from_market}"
    );
    assert_eq!(
        from_cargo, from_codex_plugin,
        "Cargo.toml says {from_cargo}, the Codex plugin says {from_codex_plugin}"
    );
}

/// A tracked changelog must read as plain prose: no URL, no markdown link, no
/// parenthesised commit-id or PR-number remnant. This file is published, and a
/// remnant is a repository identifier wearing plain text. It is generated
/// upstream of every local hook; the pre-write plugin and release-branch shell
/// harness watch the candidate, while this test independently watches the final
/// tree.
#[test]
fn a_tracked_changelog_carries_no_forge_remnant() {
    let path = manifest_dir().join("CHANGELOG.md");
    let Ok(text) = std::fs::read_to_string(&path) else {
        return; // no changelog yet; nothing to check
    };
    for (i, line) in text.lines().enumerate() {
        let n = i + 1;
        assert!(!line.contains("http"), "CHANGELOG.md line {n} carries a URL");
        assert!(!line.contains("]("), "CHANGELOG.md line {n} carries a markdown link");
        // A parenthesised token of 7-40 hex chars, or (#123), is a commit or
        // PR identifier the strip step failed to remove. The hex candidate must
        // mix digits and letters — a real commit id does; an all-digit date or
        // an all-letter word that happens to live in a-f does not, and both are
        // reachable in ordinary changelog prose.
        let mut rest = line;
        while let Some(open) = rest.find('(') {
            let inner = &rest[open + 1..];
            let close = inner.find(')').unwrap_or(inner.len());
            let raw = inner[..close].trim();
            let tok = raw.trim_start_matches('#');
            let hexish = (7..=40).contains(&tok.len())
                && !tok.is_empty()
                && tok.chars().all(|c| c.is_ascii_hexdigit())
                && tok.chars().any(|c| c.is_ascii_digit())
                && tok.chars().any(|c| c.is_ascii_alphabetic());
            let prnum = raw.starts_with('#') && !tok.is_empty()
                && tok.chars().all(|c| c.is_ascii_digit());
            assert!(
                !hexish && !prnum,
                "CHANGELOG.md line {n} carries a commit-id or PR-number remnant"
            );
            rest = &inner[(close + 1).min(inner.len())..];
        }
    }
}
