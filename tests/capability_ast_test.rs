use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use vouch::capability::TransitiveImportResolver;

struct TestWorkspace {
    root: PathBuf,
}

impl TestWorkspace {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "vouch_ast_test_{}_{}_{}",
            name,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        Self { root }
    }

    fn write_file(&self, rel_path: &str, content: &str) -> PathBuf {
        let full_path = self.root.join(rel_path);
        if let Some(parent) = full_path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let mut file = File::create(&full_path).unwrap();
        file.write_all(content.as_bytes()).unwrap();
        full_path
    }

    fn path(&self) -> &Path {
        &self.root
    }
}

impl Drop for TestWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn python_transitive_relative_imports_and_capability_aggregation() {
    let ws = TestWorkspace::new("py_relative");

    // ws/pkg/sub/worker.py -> imports from ..net.client -> imports requests
    ws.write_file("pkg/__init__.py", "");
    ws.write_file("pkg/net/__init__.py", "");
    ws.write_file(
        "pkg/net/client.py",
        "import requests\n\ndef fetch():\n    return requests.get('https://example.com')\n",
    );
    ws.write_file("pkg/sub/__init__.py", "");
    let worker_file = ws.write_file(
        "pkg/sub/worker.py",
        "from ..net.client import fetch\n\ndef run():\n    fetch()\n",
    );

    let resolver = TransitiveImportResolver::new(ws.path());
    let script = fs::read_to_string(&worker_file).unwrap();
    let report = resolver.resolve_python(&script, Some(&worker_file));

    assert!(report.capabilities.network, "Transitively imported requests must grant network capability");
    assert!(!report.capabilities.daemon);
    assert!(!report.capabilities.external_paths);
    assert!(!report.cycle_detected);
    assert!(!report.limit_exceeded);
    assert!(report.resolved_files.len() >= 1);
}

#[test]
fn python_intra_workspace_absolute_imports() {
    let ws = TestWorkspace::new("py_absolute");

    ws.write_file("core/__init__.py", "");
    ws.write_file(
        "core/fs_util.py",
        "import shutil\n\ndef clean():\n    shutil.rmtree('/tmp/trash')\n",
    );
    let main_file = ws.write_file(
        "main.py",
        "from core.fs_util import clean\n\nclean()\n",
    );

    let resolver = TransitiveImportResolver::new(ws.path());
    let script = fs::read_to_string(&main_file).unwrap();
    let report = resolver.resolve_python(&script, Some(&main_file));

    assert!(report.capabilities.external_paths, "Intra-workspace import of shutil must grant external_paths");
    assert!(!report.capabilities.network);
    assert!(!report.capabilities.daemon);
}

#[test]
fn python_circular_dependency_terminates_with_cycle_flag() {
    let ws = TestWorkspace::new("py_cycle");

    let a_file = ws.write_file("a.py", "from b import helper_b\ndef helper_a(): return 1\n");
    let _b_file = ws.write_file("b.py", "import socket\nfrom a import helper_a\ndef helper_b(): return 2\n");

    let resolver = TransitiveImportResolver::new(ws.path());
    let script = fs::read_to_string(&a_file).unwrap();
    let report = resolver.resolve_python(&script, Some(&a_file));

    assert!(report.capabilities.network, "Must aggregate network capability from b.py in cycle");
    assert!(report.cycle_detected, "Cycle between a.py and b.py must be detected");
    assert!(!report.limit_exceeded);
}

#[test]
fn javascript_transitive_require_and_dynamic_eval() {
    let ws = TestWorkspace::new("js_require");

    ws.write_file("lib/math.js", "function compute(code) { return eval(code); }\nmodule.exports = { compute };\n");
    ws.write_file("lib/api.js", "const math = require('./math');\nconst http = require('http');\nmodule.exports = { math, http };\n");
    let entry_file = ws.write_file("entry.js", "const api = require('./lib/api');\nconsole.log(api);\n");

    let resolver = TransitiveImportResolver::new(ws.path());
    let script = fs::read_to_string(&entry_file).unwrap();
    let report = resolver.resolve_javascript(&script, Some(&entry_file));

    assert!(report.capabilities.network, "Transitively required http must grant network capability");
    assert!(report.capabilities.dynamic_eval, "Transitively required eval must grant dynamic_eval capability");
    assert!(!report.capabilities.daemon);
    assert!(!report.cycle_detected);
    assert!(!report.limit_exceeded);
}

#[test]
fn javascript_es_module_relative_import_and_daemon() {
    let ws = TestWorkspace::new("js_esm");

    ws.write_file("services/cluster.js", "import child_process from 'child_process';\nexport function spawnWorker() { return child_process.fork('w.js'); }\n");
    let app_file = ws.write_file("app.js", "import { spawnWorker } from './services/cluster.js';\nspawnWorker();\n");

    let resolver = TransitiveImportResolver::new(ws.path());
    let script = fs::read_to_string(&app_file).unwrap();
    let report = resolver.resolve_javascript(&script, Some(&app_file));

    assert!(report.capabilities.daemon, "child_process import must grant daemon capability");
    assert!(!report.capabilities.network);
    assert!(!report.capabilities.external_paths);
}

#[test]
fn javascript_package_json_main_resolution() {
    let ws = TestWorkspace::new("js_pkg_json");

    ws.write_file("components/auth/package.json", "{\"main\": \"src/auth_service.js\"}");
    ws.write_file("components/auth/src/auth_service.js", "const net = require('net');\nmodule.exports = { net };\n");
    let main_file = ws.write_file("index.js", "const auth = require('./components/auth');\n");

    let resolver = TransitiveImportResolver::new(ws.path());
    let script = fs::read_to_string(&main_file).unwrap();
    let report = resolver.resolve_javascript(&script, Some(&main_file));

    assert!(report.capabilities.network, "package.json main resolution must follow into auth_service.js and find net");
}

#[test]
fn bounded_traversal_limits_depth_and_files() {
    let ws = TestWorkspace::new("limits");

    // Chain: 0 -> 1 -> 2 -> 3 -> 4
    for i in 0..5 {
        let next = i + 1;
        ws.write_file(&format!("step{i}.py"), &format!("import step{next}\n"));
    }
    ws.write_file("step5.py", "import socket\n");

    let entry = ws.root.join("step0.py");
    let script = fs::read_to_string(&entry).unwrap();

    // Resolver with max_depth = 2
    let resolver = TransitiveImportResolver::new(ws.path()).with_limits(2, 32);
    let report = resolver.resolve_python(&script, Some(&entry));

    assert!(report.limit_exceeded, "Chain exceeding max_depth must set limit_exceeded");
    assert!(!report.capabilities.network, "step5.py is at depth 5 so its socket import must not be reached");

    // Resolver with max_files = 2
    let resolver_files = TransitiveImportResolver::new(ws.path()).with_limits(8, 2);
    let report_files = resolver_files.resolve_python(&script, Some(&entry));
    assert!(report_files.limit_exceeded, "Graph exceeding max_files must set limit_exceeded");
}

#[test]
fn sandboxing_forbids_escaping_workspace_root() {
    let ws = TestWorkspace::new("sandbox");

    // Create outside file
    let outside_dir = ws.root.parent().unwrap();
    let outside_file = outside_dir.join("outside_evil.py");
    let _ = fs::write(&outside_file, "import socket\n");

    let entry = ws.write_file(
        "entry.py",
        "from ..outside_evil import pwn\n",
    );

    let resolver = TransitiveImportResolver::new(ws.path());
    let script = fs::read_to_string(&entry).unwrap();
    let report = resolver.resolve_python(&script, Some(&entry));

    assert!(!report.capabilities.network, "Escaped import outside workspace root must NOT be traversed");
    assert!(
        report.unresolved_imports.iter().any(|u| u.contains("relative_import") || u.contains("escaped")),
        "Escaped or invalid relative import must be recorded in unresolved_imports"
    );

    let _ = fs::remove_file(outside_file);
}

#[test]
fn string_literal_immunity_in_python_and_javascript() {
    let ws = TestWorkspace::new("immunity");

    ws.write_file("evil.py", "import socket\n");
    ws.write_file("evil.js", "const net = require('net');\n");

    let py_script = "msg = 'from .evil import hack'\nprint(msg)\n";
    let resolver = TransitiveImportResolver::new(ws.path());
    let py_report = resolver.resolve_python(py_script, None);
    assert!(!py_report.capabilities.network, "Python string literals must have zero capability resolution");
    assert_eq!(py_report.resolved_files.len(), 0);

    let js_script = "const str = \"require('./evil.js')\";\nconsole.log(str);\n";
    let js_report = resolver.resolve_javascript(js_script, None);
    assert!(!js_report.capabilities.network, "JS string literals must have zero capability resolution");
    assert_eq!(js_report.resolved_files.len(), 0);
}
