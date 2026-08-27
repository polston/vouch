//! Contract tests for the counts-only program-location measurement.
//!
//! The real-corpus example may see private commands, working directories, and
//! executable paths. Its reusable renderer therefore accepts only the
//! engine's path-free aggregate, and this test pins the complete output shape:
//! stable keys followed by decimal counts, with no sample channel.

#[path = "../examples/count_program_location_shapes.rs"]
#[allow(dead_code)]
mod example;

use std::path::Path;

struct Scratch(std::path::PathBuf);

impl Scratch {
    fn new() -> Self {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "vouch-program-location-measurement-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn slash(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

#[test]
fn output_is_counts_only_and_classifies_neutral_shapes() {
    let temp = Scratch::new();
    let trusted = temp.path().join("trusted");
    let outside = temp.path().join("outside");
    std::fs::create_dir_all(&trusted).unwrap();
    std::fs::create_dir_all(&outside).unwrap();

    let matching = trusted.join("probe-alpha");
    let sibling_name = trusted.join("helper-alpha");
    let outside_match = outside.join("probe-beta");
    for path in [&matching, &sibling_name, &outside_match] {
        std::fs::write(path, "invented fixture\n").unwrap();
    }

    let cfg = vouch::config::load(&format!(
        "version = 1\n[[run.trust_program]]\nunder = [{:?}]\nname_patterns = [\"probe-*\"]\n",
        format!("{}/**", slash(&trusted))
    ))
    .unwrap();
    let commands = vec![
        slash(&matching),
        "probe-alpha".to_string(),
        format!("{}/missing-probe", slash(&trusted)),
        slash(&outside_match),
        slash(&sibling_name),
    ];

    let output = example::render_counts(&cfg, &commands, "C:/Users/dev", None, None);
    assert_eq!(
        output,
        concat!(
            "rows_total=5\n",
            "rows_scanned=5\n",
            "eligible_path_spelled_occurrences=4\n",
            "proven_existing_files=3\n",
            "matching_both_clauses=1\n",
            "unproven_unresolved_head=0\n",
            "unproven_unknown_run_place=0\n",
            "unproven_no_run_directory=0\n",
            "unproven_missing_file=1\n",
            "unproven_not_regular_file=0\n",
            "unproven_canonicalization_failed=0\n",
            "unresolved_residual=0\n",
        )
    );

    for line in output.lines() {
        let (key, count) = line
            .split_once('=')
            .expect("one stable key/value separator");
        assert!(
            key.chars().all(|c| c == '_' || c.is_ascii_lowercase()),
            "unstable output key: {key:?}"
        );
        assert!(
            count.chars().all(|c| c.is_ascii_digit()),
            "non-count output: {line:?}"
        );
    }
    assert!(
        !output.contains(&slash(temp.path())),
        "a local path reached output"
    );
    assert!(!output.contains("probe"), "a program name reached output");
}

#[test]
fn parse_failures_are_residual_rows_without_payloads() {
    let cfg = vouch::config::load("version = 1\n").unwrap();
    let output = example::render_counts(
        &cfg,
        &["echo 'invented unterminated".to_string()],
        "C:/Users/dev",
        None,
        None,
    );
    assert!(output.contains("rows_scanned=0\n"), "{output}");
    assert!(output.contains("unresolved_residual=1\n"), "{output}");
    assert!(!output.contains("invented"), "source text reached output");
}

#[test]
fn neutral_scratch_rule_moves_only_the_matching_direct_program() {
    use vouch::protocol::Decision;

    let temp = Scratch::new();
    let trusted = temp.path().join("trusted");
    let outside = temp.path().join("outside");
    std::fs::create_dir_all(&trusted).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    let matching = trusted.join("probe-alpha");
    let sibling_name = trusted.join("helper-alpha");
    let outside_match = outside.join("probe-beta");
    for path in [&matching, &sibling_name, &outside_match] {
        std::fs::write(path, "invented fixture\n").unwrap();
    }

    let base_text = concat!(
        "version = 1\n",
        "[lang.bash]\n",
        "default = \"allow\"\n",
        "[lang.bash.constructs]\n",
        "unmodeled_command = \"ask\"\n",
    );
    let base = vouch::config::load(base_text).unwrap();
    let candidate = vouch::config::load(&format!(
        "{base_text}[[run.trust_program]]\nunder = [{:?}]\nname_patterns = [\"probe-*\"]\n",
        format!("{}/**", slash(&trusted))
    ))
    .unwrap();

    let decide = |cfg: &vouch::config::Config, command: &str| {
        vouch::engine::decide_command_at(cfg, "bash", command, Some("C:/Users/dev"), None, None)
    };
    assert!(matches!(decide(&base, &slash(&matching)), Decision::Ask(_)));
    assert!(matches!(
        decide(&candidate, &slash(&matching)),
        Decision::Allow(_)
    ));

    for unchanged in [
        "probe-alpha".to_string(),
        format!("{}/missing-probe", slash(&trusted)),
        slash(&outside_match),
        slash(&sibling_name),
    ] {
        assert!(
            matches!(decide(&candidate, &unchanged), Decision::Ask(_)),
            "a nonmatching neutral shape moved"
        );
    }
}
