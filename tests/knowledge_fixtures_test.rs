use std::path::Path;
use vouch::knowledge::{load_files, KNOWLEDGE_SCHEMA_VERSION};

const ABSENT: &str = "tests/fixtures/there-is-no-such-file.toml";

#[test]
fn evaluated_scope_knowledge_fixture_matches_active_schema_version() {
    let fixture_path = "tests/fixtures/evaluated_scope_knowledge.toml";
    let text = std::fs::read_to_string(fixture_path)
        .unwrap_or_else(|e| panic!("failed to read fixture {fixture_path}: {e}"));

    // Verify raw version in fixture matches current binary schema version
    let declared_version: u32 = text
        .lines()
        .find_map(|line| {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("version") {
                let rest = rest.trim_start().strip_prefix('=').map(str::trim)?;
                rest.parse::<u32>().ok()
            } else {
                None
            }
        })
        .unwrap_or_else(|| panic!("fixture {fixture_path} missing 'version = <N>' header"));

    assert_eq!(
        declared_version, KNOWLEDGE_SCHEMA_VERSION,
        "fixture {fixture_path} declared version {declared_version} drifts from KNOWLEDGE_SCHEMA_VERSION {KNOWLEDGE_SCHEMA_VERSION}"
    );

    // Verify loading yields a non-empty knowledge base without shipped knowledge gap
    let out = load_files(Path::new(fixture_path), Path::new(ABSENT));
    let knowledge_gaps: Vec<_> = out
        .gaps
        .iter()
        .filter(|g| matches!(g.source, vouch::knowledge::GapSource::Knowledge))
        .collect();
    assert!(
        knowledge_gaps.is_empty(),
        "fixture {fixture_path} failed to load as shipped knowledge: {knowledge_gaps:?}"
    );
    assert!(
        !out.kb.program.is_empty() || !out.kb.tool.is_empty(),
        "fixture {fixture_path} yielded an empty knowledge base under schema {KNOWLEDGE_SCHEMA_VERSION}"
    );
    assert_eq!(
        out.kb.program.len(),
        3,
        "fixture {fixture_path} expected 3 programs (widgetrunner, sprocketreader, gadgetconsole)"
    );
}
