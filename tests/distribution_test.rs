use serde_json::Value;

fn json(path: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn claude_and_codex_plugin_catalogs_track_the_crate_version() {
    let version = env!("CARGO_PKG_VERSION");
    assert_eq!(
        json("plugin/.claude-plugin/plugin.json")["version"],
        version
    );
    assert_eq!(
        json(".claude-plugin/marketplace.json")["plugins"][0]["version"],
        version
    );
    assert_eq!(json("plugin/.codex-plugin/plugin.json")["version"], version);
    let marketplace = json(".agents/plugins/marketplace.json");
    assert_eq!(marketplace["plugins"][0]["name"], "vouch");
    assert_eq!(marketplace["plugins"][0]["source"]["path"], "./plugin");
}

#[test]
fn every_release_archive_contains_the_hook_and_broker_binaries() {
    let workflow = std::fs::read_to_string(".github/workflows/release.yml").unwrap();
    assert!(workflow.contains("broker: vouch-codex-broker.exe"));
    assert!(workflow.matches("broker: vouch-codex-broker").count() >= 3);
    assert!(workflow.contains("${{ matrix.broker }}"));
}

#[test]
fn vouch_trust_teaches_structured_write_path_declarations() {
    let skill = std::fs::read_to_string("plugin/skills/vouch-trust/SKILL.md").unwrap();

    assert!(skill.contains("[[tool.write_path]]"));
    assert!(skill.contains("format = \"scalar\""));
    assert!(skill.contains("format = \"apply_patch\""));
}
