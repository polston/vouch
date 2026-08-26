//! Documents asserted against code. `docs/reference/config-schema.json`,
//! `docs/reference/knowledge-schema.json` and `docs/reference/reference.md`
//! are committed artifacts generated from the same structs the config and
//! knowledge loaders actually read (`vouch::cli::generate_schema_docs`), and
//! two more tests hold the release-flow invariants to the same standard.
//!
//! Four independent gates:
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

/// True when some line of `text`, trimmed, is a TOML key assignment for
/// exactly `name` — `name = ...`, not merely `name` appearing somewhere in
/// the file. A bare substring check would pass `redirect` for free off of
/// `dynamic_redirect = "allow"`, a DIFFERENT settable key that happens to
/// contain the shorter name as characters — exactly the loose-match trap
/// CLAUDE.md §6.1 warns against ("counting curl -o three ways gave 349,
/// 289, and a true 240").
fn sets_key(text: &str, name: &str) -> bool {
    text.lines().any(|line| {
        let line = line.trim_start();
        line.strip_prefix(name)
            .and_then(|rest| rest.trim_start().strip_prefix('='))
            .is_some()
    })
}

#[test]
fn every_known_construct_is_documented_in_the_example_config() {
    let example = std::fs::read_to_string("vouch.example.toml").expect("vouch.example.toml reads");
    let mut missing = Vec::new();
    for lang in ["bash", "powershell", "python"] {
        let scanner = vouch::syntax::scanner_for(lang).expect("scanner exists");
        for name in scanner.known_constructs() {
            if !sets_key(&example, name) {
                missing.push(format!("{lang}/{name}"));
            }
        }
    }
    assert!(
        missing.is_empty(),
        "vouch.example.toml does not set these constructs as their own key: {missing:?}"
    );
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
