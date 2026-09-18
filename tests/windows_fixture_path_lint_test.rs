//! Mechanical lint test for Windows rooted drive-less path fixtures (M2.230).
//!
//! On Windows, a rooted path without a drive letter like `/tmp/...` resolves
//! against the current drive of the executing process (e.g. `D:/tmp/...` if
//! the CI runner workspace is on drive `D:`). Because the standard realistic allow_paths
//! configuration specifies `C:/tmp/**`, allow-expecting tests that hardcode `/tmp/...`
//! without drive qualification fail on Windows secondary drives.
//!
//! This lint mechanically scans test source files to ensure allow-expecting test
//! cases use drive-qualified paths or the shared `common::t()` helper.
mod common;

use common::t;
use std::fs;
use std::path::Path;

/// Detects if a snippet contains an un-drive-qualified `/tmp/...` literal
/// in a test that expects `Allow`.
fn find_unqualified_tmp_hazard(source: &str) -> Vec<String> {
    let mut violations = Vec::new();
    // Scan test functions
    let functions = source.split("#[test]");
    for func in functions.skip(1) {
        let fn_name = func
            .lines()
            .find(|l| l.contains("fn "))
            .and_then(|l| l.split("fn ").nth(1))
            .and_then(|l| l.split('(').next())
            .unwrap_or("unknown")
            .trim();

        // Must be an engine test
        let is_engine_test = func.contains("decide_command")
            || func.contains("assert_verdict")
            || func.contains("assert_pair")
            || func.contains("decide_powershell");

        if !is_engine_test {
            continue;
        }

        // Check if this test asserts an Allow decision
        let expects_allow = func.contains("Decision::Allow")
            || func.contains(r#"assert_eq!(d, "allow")"#)
            || func.contains(r#"assert_eq!(verdict, "allow")"#)
            || func.contains(r#", "allow""#);

        if expects_allow {
            for (line_idx, line) in func.lines().enumerate() {
                let trimmed = line.trim();
                if trimmed.starts_with("//") || trimmed.starts_with('*') {
                    continue;
                }
                // Skip configuration patterns, assertion comparisons, destructive guards, or mount normalizations
                if trimmed.contains("/tmp/**")
                    || trimmed.contains(".contains(")
                    || trimmed.starts_with("assert")
                    || trimmed.contains("scan-allow")
                    || trimmed.contains("normalize_with_mounts")
                    || trimmed.contains("rm -rf")
                    || trimmed.contains("rm -r")
                {
                    continue;
                }
                // Match literal /tmp/ without C: or t("/tmp/ or common::t( or cfg!(windows)
                if trimmed.contains("/tmp/")
                    && !trimmed.contains("C:/tmp/")
                    && !trimmed.contains("t(\"/tmp/")
                    && !trimmed.contains("common::t(")
                    && !trimmed.contains("cfg!(windows)")
                {
                    violations.push(format!(
                        "fn {fn_name} (line ~{line_idx}): un-drive-qualified /tmp literal: {trimmed}"
                    ));
                }
            }
        }
    }
    violations
}

#[test]
fn test_t_helper_drive_qualifies_path() {
    let raw = "/tmp/scratch/test.txt";
    let qualified = t(raw);
    if cfg!(windows) {
        assert_eq!(qualified, "C:/tmp/scratch/test.txt");
    } else {
        assert_eq!(qualified, "/tmp/scratch/test.txt");
    }
}

#[test]
fn test_lint_detects_unqualified_hazard() {
    let hazardous_snippet = r#"
#[test]
fn sample_hazard_test() {
    let cfg = realistic_config();
    let d = decide_command_at(&cfg, "bash", "echo hi > /tmp/out.txt", None, None, None);
    assert_eq!(d, "allow");
}
"#;
    let findings = find_unqualified_tmp_hazard(hazardous_snippet);
    assert!(
        !findings.is_empty(),
        "lint must flag un-drive-qualified /tmp path in allow test"
    );

    let clean_snippet = r#"
#[test]
fn sample_clean_test() {
    let cfg = realistic_config();
    let tmp = t("/tmp/out.txt");
    let d = decide_command_at(&cfg, "bash", &format!("echo hi > {tmp}"), None, None, None);
    assert_eq!(d, "allow");
}
"#;
    let clean_findings = find_unqualified_tmp_hazard(clean_snippet);
    assert!(
        clean_findings.is_empty(),
        "lint must pass t()-wrapped /tmp path: {clean_findings:?}"
    );
}

#[test]
fn test_all_integration_tests_avoid_drive_less_allow_fixtures() {
    let manifest_dir = std::env::var_os("CARGO_MANIFEST_DIR")
        .map(std::path::PathBuf::from)
        .expect("CARGO_MANIFEST_DIR is unset: run this test through cargo");
    let tests_dir = manifest_dir.join("tests");

    let entries = fs::read_dir(&tests_dir).expect("tests directory must exist");
    let mut all_violations = Vec::new();

    for entry in entries {
        let entry = entry.expect("valid entry");
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("rs") {
            let filename = path.file_name().unwrap().to_str().unwrap();
            // Skip the lint test itself
            if filename == "windows_fixture_path_lint_test.rs" {
                continue;
            }
            let content = fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
            let violations = find_unqualified_tmp_hazard(&content);
            for v in violations {
                all_violations.push(format!("{filename}: {v}"));
            }
        }
    }

    assert!(
        all_violations.is_empty(),
        "Found platform-naive un-drive-qualified /tmp fixtures in allow tests:\n{}",
        all_violations.join("\n")
    );
}
