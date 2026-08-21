//! Generated schema docs: `docs/reference/config-schema.json`,
//! `docs/reference/knowledge-schema.json` and `docs/reference/reference.md`
//! are committed artifacts generated from the same structs the config and
//! knowledge loaders actually read (`vouch::cli::generate_schema_docs`).
//!
//! Two independent gates:
//!   1. the committed files must match what the structs generate RIGHT NOW —
//!      otherwise the reference page is describing a shape the loader no
//!      longer accepts, or has stopped accepting a shape it still does.
//!   2. `vouch.example.toml` must name every construct any scanner can
//!      trip — an omission there is exactly how `evaluated_input` went
//!      undocumented long enough for an inheritance surprise to hide behind
//!      it (CLAUDE.md, this task's own reason for existing).

/// `core.autocrlf` on a Windows checkout rewrites a committed LF file to
/// CRLF on disk; the generator always emits LF. Normalizing before compare
/// keeps this test about CONTENT, not about which machine last checked the
/// repository out — a real content edit still differs after normalizing,
/// only the line-ending convention is ignored.
fn normalize(s: &str) -> String {
    s.replace("\r\n", "\n")
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
    let shipped = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("knowledge.toml"),
    )
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
