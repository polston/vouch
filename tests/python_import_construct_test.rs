//! Tests for Python top-level import statement execution modeling and construct emission (M2.93).

use vouch::config::load;
use vouch::engine::decide_command_in;
use vouch::protocol::Decision;
use vouch::python::{is_known_inert_module, parse};

#[test]
fn inert_standard_library_modules_are_recognized() {
    assert!(is_known_inert_module("sys"));
    assert!(is_known_inert_module("math"));
    assert!(is_known_inert_module("json"));
    assert!(is_known_inert_module("os"));
    assert!(is_known_inert_module("pathlib"));
    assert!(is_known_inert_module("__future__"));

    assert!(!is_known_inert_module("requests"));
    assert!(!is_known_inert_module("numpy"));
    assert!(!is_known_inert_module("dangerous_package"));
}

#[test]
fn inert_top_level_imports_emit_no_unmodeled_import_construct() {
    let scan = parse("import sys, math, json\nfrom os.path import join\nfrom pathlib import Path").unwrap();
    assert!(
        !scan.constructs.iter().any(|c| c == "unmodeled_import"),
        "inert imports should not emit unmodeled_import; got: {:?}",
        scan.constructs
    );
}

#[test]
fn unmodeled_top_level_import_emits_construct_with_detail() {
    let scan = parse("import dangerous_pkg").unwrap();
    assert!(
        scan.constructs.iter().any(|c| c == "unmodeled_import"),
        "unmodeled import must emit unmodeled_import construct"
    );
    assert!(
        scan.construct_details
            .iter()
            .any(|(name, detail)| name == "unmodeled_import" && detail == "dangerous_pkg"),
        "construct detail must name the unmodeled module; got: {:?}",
        scan.construct_details
    );
}

#[test]
fn unmodeled_from_import_emits_construct_with_root_module() {
    let scan = parse("from custom_library.submodule import worker").unwrap();
    assert!(
        scan.constructs.iter().any(|c| c == "unmodeled_import"),
        "unmodeled from-import must emit unmodeled_import construct"
    );
    assert!(
        scan.construct_details
            .iter()
            .any(|(name, detail)| name == "unmodeled_import" && detail == "custom_library"),
        "construct detail must name the root module; got: {:?}",
        scan.construct_details
    );
}

#[test]
fn deferred_import_inside_function_does_not_trip_top_level_construct() {
    let scan = parse("def helper():\n    import requests\n").unwrap();
    assert!(
        !scan.constructs.iter().any(|c| c == "unmodeled_import"),
        "deferred import inside function body should not emit top-level unmodeled_import"
    );
}

#[test]
fn engine_decides_python_imports_fail_closed_with_actionable_off_switch() {
    let cfg = load(
        "version = 1\n[lang.bash]\ndefault = \"allow\"\n[lang.python]\ndefault = \"allow\"\n",
    )
    .unwrap();

    // Inert import allows cleanly
    let allow_dec = decide_command_in(&cfg, "bash", "python -c \"import json\"", None, None);
    assert!(matches!(allow_dec, Decision::Allow(_)), "expected Allow for inert import; got: {:?}", allow_dec);

    // Unmodeled import asks by default, naming the off-switch and the unread module
    let ask_dec = decide_command_in(&cfg, "bash", "python -c \"import evil_pkg\"", None, None);
    match ask_dec {
        Decision::Ask(reason) => {
            assert!(
                reason.contains("lang.python.constructs.unmodeled_import"),
                "prompt must name actionable off-switch; got: {reason}"
            );
            assert!(
                reason.contains("evil_pkg"),
                "prompt detail must name the offending module; got: {reason}"
            );
        }
        other => panic!("expected Ask for unmodeled import; got: {:?}", other),
    }

    // Setting unmodeled_import to allow permits the command
    let allow_cfg = load(
        "version = 1\n[lang.bash]\ndefault = \"allow\"\n[lang.python]\ndefault = \"allow\"\n[lang.python.constructs]\nunmodeled_import = \"allow\"\n",
    )
    .unwrap();
    let permitted = decide_command_in(&allow_cfg, "bash", "python -c \"import evil_pkg\"", None, None);
    assert!(
        matches!(permitted, Decision::Allow(_)),
        "expected Allow when unmodeled_import is allowed; got: {:?}",
        permitted
    );
}
