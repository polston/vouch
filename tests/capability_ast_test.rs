use vouch::capability::{propagate_capabilities, AstCapabilityExtractor, DefaultAstCapabilityExtractor};
use vouch::guards::in_effect;

#[test]
fn python_ast_import_network_capabilities() {
    let extractor = DefaultAstCapabilityExtractor;

    let caps1 = extractor.extract_capabilities("import socket", "python");
    assert!(caps1.network);
    assert!(!caps1.daemon);

    let caps2 = extractor.extract_capabilities("import urllib.request as ureq", "python");
    assert!(caps2.network);

    let caps3 = extractor.extract_capabilities("from httpx import Client", "python");
    assert!(caps3.network);
}

#[test]
fn python_ast_import_daemon_and_subprocess_capabilities() {
    let extractor = DefaultAstCapabilityExtractor;

    let caps1 = extractor.extract_capabilities("from subprocess import Popen", "python");
    assert!(caps1.daemon);

    // Bare import subprocess delegates child capability extraction to wrapper propagation
    let caps_bare = extractor.extract_capabilities("import subprocess", "python");
    assert!(!caps_bare.daemon);

    let caps2 = extractor.extract_capabilities("from os import system, popen", "python");
    assert!(caps2.daemon);

    let caps3 = extractor.extract_capabilities("import multiprocessing as mp", "python");
    assert!(caps3.daemon);
}

#[test]
fn python_ast_string_literal_immunity() {
    let extractor = DefaultAstCapabilityExtractor;

    // String literals must not trigger capability flags
    let caps = extractor.extract_capabilities(r#"print("import socket; import subprocess")"#, "python");
    assert!(caps.is_empty(), "string literal containing import must not trigger capabilities");
}

#[test]
fn javascript_ast_require_and_import_capabilities() {
    let extractor = DefaultAstCapabilityExtractor;

    let caps1 = extractor.extract_capabilities("const net = require('node:net');", "javascript");
    assert!(caps1.network);
    assert!(!caps1.daemon);

    let caps2 = extractor.extract_capabilities("const cp = require('child_process');", "javascript");
    assert!(caps2.daemon);

    let caps3 = extractor.extract_capabilities("import https from 'https';", "javascript");
    assert!(caps3.network);

    let caps4 = extractor.extract_capabilities("const fs = require('fs');", "javascript");
    assert!(caps4.external_paths);
}

#[test]
fn javascript_ast_string_literal_immunity() {
    let extractor = DefaultAstCapabilityExtractor;

    let caps = extractor.extract_capabilities(r#"console.log("require('net'); require('child_process');");"#, "javascript");
    assert!(caps.is_empty(), "string literal in JS must not trigger capabilities");
}

#[test]
fn propagate_capabilities_inline_python_and_node_cli() {
    let kb = in_effect();

    let cmd_py = r#"python -c "import socket; s = socket.socket(); s.connect(('1.1.1.1', 80))""#;
    let caps_py = propagate_capabilities(kb, cmd_py, "bash");
    assert!(caps_py.network, "inline python script importing socket must propagate network capability");

    let cmd_node = r#"node -e "const cp = require('child_process'); cp.spawn('ls');""#;
    let caps_node = propagate_capabilities(kb, cmd_node, "bash");
    assert!(caps_node.daemon, "inline node script requiring child_process must propagate daemon capability");

    let cmd_clean = r#"python -c "print('hello from clean script')""#;
    let caps_clean = propagate_capabilities(kb, cmd_clean, "bash");
    assert!(caps_clean.is_empty(), "clean python script must require zero capabilities");
}
