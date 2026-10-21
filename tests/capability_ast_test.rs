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

#[test]
fn python_pyproject_src_layout_and_pep503_hyphen_normalization() {
    let ws = TestWorkspace::new("py_pyproject_src");

    ws.write_file(
        "pyproject.toml",
        r#"[project]
name = "acme-core"
version = "0.1.0"
"#,
    );
    ws.write_file("src/acme_core/__init__.py", "");
    ws.write_file(
        "src/acme_core/http_worker.py",
        "import urllib.request\n\ndef fetch_data():\n    return urllib.request.urlopen('https://example.com')\n",
    );
    let runner = ws.write_file(
        "scripts/runner.py",
        "from acme_core.http_worker import fetch_data\n\nfetch_data()\n",
    );

    let resolver = TransitiveImportResolver::new(ws.path());
    let script = fs::read_to_string(&runner).unwrap();
    let report = resolver.resolve_python(&script, Some(&runner));

    assert!(
        report.capabilities.network,
        "pyproject.toml src/ layout with PEP 503 hyphen normalization must resolve acme_core.http_worker and detect network"
    );
    assert!(!report.unresolved_imports.iter().any(|u| u.contains("escaped")));
}

#[test]
fn python_requirements_txt_editable_local_packages() {
    let ws = TestWorkspace::new("py_req_editable");

    ws.write_file(
        "requirements.txt",
        "# Local editable packages\n-e ./packages/telemetry\n",
    );
    ws.write_file(
        "packages/telemetry/pyproject.toml",
        r#"[tool.poetry]
name = "vouch-telemetry"
version = "0.1.0"
"#,
    );
    ws.write_file("packages/telemetry/src/vouch_telemetry/__init__.py", "");
    ws.write_file(
        "packages/telemetry/src/vouch_telemetry/sender.py",
        "import socket\n\ndef send_metric():\n    return socket.socket()\n",
    );
    let app = ws.write_file(
        "app.py",
        "import vouch_telemetry.sender\n\nvouch_telemetry.sender.send_metric()\n",
    );

    let resolver = TransitiveImportResolver::new(ws.path());
    let script = fs::read_to_string(&app).unwrap();
    let report = resolver.resolve_python(&script, Some(&app));

    assert!(
        report.capabilities.network,
        "Editable package in requirements.txt must resolve vouch_telemetry.sender and detect socket network capability"
    );
}

#[test]
fn javascript_monorepo_workspaces_and_subpath_exports() {
    let ws = TestWorkspace::new("js_monorepo_exports");

    ws.write_file(
        "package.json",
        r#"{
  "name": "acme-monorepo",
  "private": true,
  "workspaces": ["packages/*"]
}"#,
    );
    ws.write_file(
        "packages/net-utils/package.json",
        r#"{
  "name": "@acme/net-utils",
  "version": "1.0.0",
  "exports": {
    ".": {
      "import": "./src/index.ts",
      "default": "./dist/index.js"
    },
    "./client": {
      "source": "./src/client.ts",
      "default": "./dist/client.js"
    }
  }
}"#,
    );
    ws.write_file(
        "packages/net-utils/src/index.ts",
        "export const VERSION = '1.0.0';\n",
    );
    ws.write_file(
        "packages/net-utils/src/client.ts",
        "import https from 'https';\nexport function connect() { return https.get('https://example.com'); }\n",
    );
    let main_ts = ws.write_file(
        "apps/web/main.ts",
        "import { connect } from '@acme/net-utils/client';\nconnect();\n",
    );

    let resolver = TransitiveImportResolver::new(ws.path());
    let script = fs::read_to_string(&main_ts).unwrap();
    let report = resolver.resolve_javascript(&script, Some(&main_ts));

    assert!(
        report.capabilities.network,
        "Workspace package @acme/net-utils/client subpath export must resolve to src/client.ts and detect https network capability"
    );
}

#[test]
fn javascript_pnpm_lock_and_file_link_resolution() {
    let ws = TestWorkspace::new("js_pnpm_lock");

    ws.write_file(
        "pnpm-lock.yaml",
        r#"lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      '@acme/daemon-runner':
        specifier: workspace:*
        version: link:packages/daemon-runner
"#,
    );
    ws.write_file(
        "packages/daemon-runner/src/index.js",
        "const cp = require('child_process');\nmodule.exports = { spawn: () => cp.fork('worker.js') };\n",
    );
    let entry = ws.write_file(
        "index.js",
        "const runner = require('@acme/daemon-runner');\nrunner.spawn();\n",
    );

    let resolver = TransitiveImportResolver::new(ws.path());
    let script = fs::read_to_string(&entry).unwrap();
    let report = resolver.resolve_javascript(&script, Some(&entry));

    assert!(
        report.capabilities.daemon,
        "pnpm-lock.yaml link: target must resolve @acme/daemon-runner to packages/daemon-runner/src/index.js and detect daemon capability"
    );
}

#[test]
fn workspace_manifest_escape_outside_root_is_blocked() {
    let ws = TestWorkspace::new("manifest_escape");
    let outside_py_dir = ws.root.parent().unwrap().join(format!(
        "vouch_escaped_py_{}",
        std::process::id()
    ));
    let outside_js_dir = ws.root.parent().unwrap().join(format!(
        "vouch_escaped_js_{}",
        std::process::id()
    ));
    let _ = fs::create_dir_all(&outside_py_dir);
    let _ = fs::create_dir_all(&outside_js_dir);
    let _ = fs::write(outside_py_dir.join("__init__.py"), "import socket\n");
    let _ = fs::write(outside_js_dir.join("index.js"), "const net = require('net');\n");

    let py_rel = format!("../{}", outside_py_dir.file_name().unwrap().to_string_lossy());
    let js_rel = format!("file:../{}", outside_js_dir.file_name().unwrap().to_string_lossy());

    ws.write_file("requirements.txt", &format!("-e {py_rel}\n"));
    ws.write_file(
        "package.json",
        &format!(
            r#"{{
  "name": "escape-test",
  "dependencies": {{
    "@evil/escaped": "{js_rel}"
  }}
}}"#
        ),
    );

    let py_pkg_name = outside_py_dir
        .file_name()
        .unwrap()
        .to_string_lossy()
        .replace('-', "_");
    let py_entry = ws.write_file("main.py", &format!("import {py_pkg_name}\n"));
    let js_entry = ws.write_file("main.js", "const evil = require('@evil/escaped');\n");

    let resolver = TransitiveImportResolver::new(ws.path());

    let py_report = resolver.resolve_python(&fs::read_to_string(&py_entry).unwrap(), Some(&py_entry));
    assert!(
        !py_report.capabilities.network,
        "Escaped Python editable package must NOT grant capabilities outside workspace"
    );
    assert!(
        py_report.unresolved_imports.iter().any(|u| u.starts_with("escaped:")),
        "Escaped Python editable package must record escaped entry in unresolved_imports: {:?}",
        py_report.unresolved_imports
    );

    let js_report = resolver.resolve_javascript(&fs::read_to_string(&js_entry).unwrap(), Some(&js_entry));
    assert!(
        !js_report.capabilities.network,
        "Escaped Node file: dependency must NOT grant capabilities outside workspace"
    );
    assert!(
        js_report.unresolved_imports.iter().any(|u| u.starts_with("escaped:")),
        "Escaped Node file: dependency must record escaped entry in unresolved_imports: {:?}",
        js_report.unresolved_imports
    );

    let _ = fs::remove_dir_all(&outside_py_dir);
    let _ = fs::remove_dir_all(&outside_js_dir);
}

#[test]
fn typescript_tsconfig_jsonc_paths_and_baseurl_resolution() {
    let ws = TestWorkspace::new("ts_paths_jsonc");

    // JSONC tsconfig.json with line comments, block comments, and trailing commas
    ws.write_file(
        "tsconfig.json",
        r#"{
  // Root TypeScript configuration with JSONC comments
  "compilerOptions": {
    "baseUrl": ".", /* resolve bare imports relative to root */
    "paths": {
      "@/*": ["./src/*"],
      "@net": ["./src/services/net_client.ts"],
    },
  },
}"#,
    );
    ws.write_file(
        "src/services/net_client.ts",
        "import https from 'https';\nexport function request() { return https.get('https://example.com'); }\n",
    );
    ws.write_file(
        "src/utils/ping.ts",
        "import { request } from '@net';\nexport function ping() { return request(); }\n",
    );
    ws.write_file(
        "src/components/Widget.tsx",
        "import { ping } from '@/utils/ping';\nexport const Widget = () => { ping(); return <div />; };\n",
    );
    let entry = ws.write_file(
        "main.ts",
        "import { Widget } from 'src/components/Widget';\nWidget();\n",
    );

    let resolver = TransitiveImportResolver::new(ws.path());
    let script = fs::read_to_string(&entry).unwrap();
    let report = resolver.resolve_javascript(&script, Some(&entry));

    assert!(
        report.capabilities.network,
        "Transitive resolution through baseUrl -> .tsx -> @/* -> @net must detect https network capability"
    );
    assert!(
        report.unresolved_imports.is_empty(),
        "Expected zero unresolved imports, got {:?}",
        report.unresolved_imports
    );
}

#[test]
fn typescript_tsconfig_extends_inheritance_across_monorepo() {
    let ws = TestWorkspace::new("ts_extends");

    ws.write_file(
        "tsconfig.base.json",
        r#"{
  "compilerOptions": {
    "baseUrl": ".",
    "paths": {
      "@shared/*": ["packages/shared/src/*"]
    }
  }
}"#,
    );
    ws.write_file(
        "apps/api/tsconfig.json",
        r#"{
  "extends": "../../tsconfig.base.json",
  "compilerOptions": {
    "paths": {
      "@local/*": ["./src/*"]
    }
  }
}"#,
    );
    ws.write_file(
        "packages/shared/src/spawner.ts",
        "import cp from 'child_process';\nexport function forkWorker() { return cp.fork('w.js'); }\n",
    );
    ws.write_file(
        "apps/api/src/helper.ts",
        "import { forkWorker } from '@shared/spawner';\nexport function start() { return forkWorker(); }\n",
    );
    let server = ws.write_file(
        "apps/api/src/server.ts",
        "import { start } from '@local/helper';\nstart();\n",
    );

    let resolver = TransitiveImportResolver::new(ws.path());
    let script = fs::read_to_string(&server).unwrap();
    let report = resolver.resolve_javascript(&script, Some(&server));

    assert!(
        report.capabilities.daemon,
        "Inherited @shared/* and child @local/* tsconfig paths must resolve spawner.ts and detect daemon capability"
    );
}

#[test]
fn typescript_tsconfig_path_alias_escape_outside_workspace_is_blocked() {
    let ws = TestWorkspace::new("ts_alias_escape");
    let outside_ts_dir = ws.root.parent().unwrap().join(format!(
        "vouch_escaped_ts_{}",
        std::process::id()
    ));
    let _ = fs::create_dir_all(&outside_ts_dir);
    let _ = fs::write(
        outside_ts_dir.join("pwn.ts"),
        "import net from 'net';\nexport const s = net.connect(80);\n",
    );

    let rel_escape = format!(
        "../{}/*",
        outside_ts_dir.file_name().unwrap().to_string_lossy()
    );
    ws.write_file(
        "tsconfig.json",
        &format!(
            r#"{{
  "compilerOptions": {{
    "baseUrl": ".",
    "paths": {{
      "@escaped/*": ["{rel_escape}"]
    }}
  }}
}}"#
        ),
    );
    let entry = ws.write_file("main.ts", "import { s } from '@escaped/pwn';\nconsole.log(s);\n");

    let resolver = TransitiveImportResolver::new(ws.path());
    let report = resolver.resolve_javascript(&fs::read_to_string(&entry).unwrap(), Some(&entry));

    assert!(
        !report.capabilities.network,
        "Escaped tsconfig path alias outside workspace root must NOT grant capabilities"
    );
    assert!(
        report.unresolved_imports.iter().any(|u| u.starts_with("escaped:")),
        "Escaped tsconfig path alias must record escaped entry in unresolved_imports: {:?}",
        report.unresolved_imports
    );

    let _ = fs::remove_dir_all(&outside_ts_dir);
}

#[test]
fn node_package_json_subpath_imports_resolve_wildcard_and_conditional_targets() {
    let ws = TestWorkspace::new("node_subpath_imports");

    ws.write_file(
        "packages/app/package.json",
        r##"{
  "name": "@acme/app",
  "imports": {
    "#internal/*": "./src/internal/*.ts",
    "#net": {
      "import": "./src/net/esm_client.ts",
      "require": "./src/net/cjs_client.js",
      "default": "./src/net/cjs_client.js"
    }
  }
}"##,
    );
    ws.write_file(
        "packages/app/src/internal/workers/spawner.ts",
        "import cp from 'child_process';\nexport function runDaemon() { return cp.fork('worker.js'); }\n",
    );
    ws.write_file(
        "packages/app/src/net/esm_client.ts",
        "import https from 'https';\nexport function getUrl(u: string) { return https.get(u); }\n",
    );
    let entry = ws.write_file(
        "packages/app/src/index.ts",
        "import { runDaemon } from '#internal/workers/spawner';\nimport { getUrl } from '#net';\nrunDaemon();\ngetUrl('https://example.com');\n",
    );

    let resolver = TransitiveImportResolver::new(ws.path());
    let script = fs::read_to_string(&entry).unwrap();
    let report = resolver.resolve_javascript(&script, Some(&entry));

    assert!(
        report.capabilities.daemon,
        "Subpath import #internal/spawner must resolve to spawner.ts and detect daemon capability"
    );
    assert!(
        report.capabilities.network,
        "Conditional subpath import #net must resolve to esm_client.ts and detect network capability"
    );
    assert!(
        report.unresolved_imports.is_empty(),
        "Expected zero unresolved imports, got {:?}",
        report.unresolved_imports
    );
}

#[test]
fn typescript_project_references_propagate_capabilities_across_composite_packages() {
    let ws = TestWorkspace::new("ts_project_references");

    // Solution-style root tsconfig with references to composite packages (no root workspaces array in package.json)
    ws.write_file(
        "tsconfig.json",
        r#"{
  "files": [],
  "references": [
    { "path": "./packages/core" },
    { "path": "./packages/cli" }
  ]
}"#,
    );
    ws.write_file(
        "packages/core/tsconfig.json",
        r#"{
  "compilerOptions": {
    "composite": true,
    "rootDir": "./src",
    "outDir": "./dist",
    "baseUrl": ".",
    "paths": {
      "@core-internal/*": ["./src/internal/*"]
    }
  }
}"#,
    );
    ws.write_file(
        "packages/core/package.json",
        r#"{
  "name": "@acme/core",
  "main": "./dist/index.js",
  "exports": {
    ".": {
      "types": "./dist/index.d.ts",
      "import": "./dist/index.js"
    }
  }
}"#,
    );
    ws.write_file(
        "packages/core/src/internal/http.ts",
        "import net from 'net';\nexport function connectSocket() { return net.connect(443); }\n",
    );
    ws.write_file(
        "packages/core/src/index.ts",
        "import { connectSocket } from '@core-internal/http';\nexport { connectSocket };\n",
    );

    ws.write_file(
        "packages/cli/tsconfig.json",
        r#"{
  "compilerOptions": {
    "composite": true
  },
  "references": [
    { "path": "../core/tsconfig.json" }
  ]
}"#,
    );
    let cli_entry = ws.write_file(
        "packages/cli/src/main.ts",
        "import { connectSocket } from '@acme/core';\nconnectSocket();\n",
    );

    let resolver = TransitiveImportResolver::new(ws.path());
    let script = fs::read_to_string(&cli_entry).unwrap();
    let report = resolver.resolve_javascript(&script, Some(&cli_entry));

    assert!(
        report.capabilities.network,
        "TypeScript project references must index @acme/core (including dist->src fallback and @core-internal/* paths) and propagate network capability"
    );
    assert!(
        report.unresolved_imports.is_empty(),
        "Expected zero unresolved imports across TS project references, got {:?}",
        report.unresolved_imports
    );
}

#[test]
fn node_subpath_imports_escape_outside_workspace_is_blocked() {
    let ws = TestWorkspace::new("node_subpath_escape");

    ws.write_file(
        "package.json",
        r##"{
  "name": "@acme/escape-pkg",
  "imports": {
    "#outside/*": "../../outside/*"
  }
}"##,
    );
    let entry = ws.write_file(
        "src/index.js",
        "import { secret } from '#outside/secret.js';\nconsole.log(secret);\n",
    );

    let resolver = TransitiveImportResolver::new(ws.path());
    let script = fs::read_to_string(&entry).unwrap();
    let report = resolver.resolve_javascript(&script, Some(&entry));

    assert!(
        report.unresolved_imports.iter().any(|u| u.starts_with("escaped:")),
        "Subpath import escaping workspace root must record escaped entry in unresolved_imports: {:?}",
        report.unresolved_imports
    );
}

#[test]
fn deno_jsonc_and_import_map_resolve_local_prefixes_scopes_and_external_specifiers() {
    let ws = TestWorkspace::new("deno_import_map");

    // 1. External `import_map.json` referenced from `deno.jsonc` with comments & trailing commas
    ws.write_file(
        "deno.jsonc",
        r#"{
  // Deno config with external import map and local overrides
  "importMap": "./import_map.json",
  "imports": {
    "@local/": "./src/local/",
  },
  "scopes": {
    "./packages/special/": {
      "@scoped/helper": "./packages/special/scoped_exec.ts",
    },
  },
}"#,
    );

    ws.write_file(
        "import_map.json",
        r#"{
  "imports": {
    "http-client": "npm:axios@^1.6.0",
    "std-http/": "jsr:@std/http/",
    "remote-mod": "https://deno.land/std@0.220.0/http/server.ts"
  }
}"#,
    );

    ws.write_file(
        "src/local/runner.ts",
        "import fs from 'node:fs';\nexport function runCmd() { return fs.readFileSync('id'); }\n",
    );
    ws.write_file(
        "packages/special/scoped_exec.ts",
        "export function evaluateDynamic(code: string) { return eval(code); }\n",
    );

    let entry = ws.write_file(
        "packages/special/main.ts",
        r#"
import { runCmd } from "@local/runner.ts";
import { evaluateDynamic } from "@scoped/helper";
import axios from "http-client";
runCmd();
evaluateDynamic("1+1");
console.log(axios);
"#,
    );

    let resolver = TransitiveImportResolver::new(ws.path());
    let script = fs::read_to_string(&entry).unwrap();
    let report = resolver.resolve_javascript(&script, Some(&entry));

    assert!(
        report.capabilities.network,
        "import map alias 'http-client' -> 'npm:axios@^1.6.0' must propagate network capability"
    );
    assert!(
        report.capabilities.external_paths,
        "import map prefix '@local/' -> './src/local/runner.ts' importing 'node:child_process' must propagate external_paths"
    );
    assert!(
        report.capabilities.dynamic_eval,
        "scoped import map '@scoped/helper' -> './packages/special/scoped_exec.ts' must propagate dynamic_eval"
    );
    assert!(
        report.unresolved_imports.is_empty(),
        "expected no unresolved local imports, got {:?}",
        report.unresolved_imports
    );
}

#[test]
fn python_pep723_inline_script_metadata_resolves_dependencies_and_uv_local_sources() {
    let ws = TestWorkspace::new("python_pep723_metadata");

    // Local package referenced via [tool.uv.sources]
    ws.write_file(
        "pkgs/internal_runner/src/internal_runner/__init__.py",
        "import shutil\ndef run_task():\n    shutil.rmtree('/tmp/work')\n",
    );

    let script_path = ws.write_file(
        "scripts/fetch_and_run.py",
        r#"# /// script
# requires-python = ">=3.12"
# dependencies = [
#   "httpx[http2]>=0.27.0",
#   "celery~=5.3",
#   "internal-runner",
# ]
#
# [tool.uv.sources]
# internal-runner = { path = "../pkgs/internal_runner" }
# ///

import internal_runner

def main():
    internal_runner.run_task()
"#,
    );

    let resolver = TransitiveImportResolver::new(ws.path());
    let script = fs::read_to_string(&script_path).unwrap();
    let report = resolver.resolve_python(&script, Some(&script_path));

    assert!(
        report.capabilities.network,
        "PEP 723 dependency 'httpx[http2]>=0.27.0' must propagate network capability"
    );
    assert!(
        report.capabilities.daemon,
        "PEP 723 dependency 'celery~=5.3' must propagate daemon capability"
    );
    assert!(
        report.capabilities.external_paths,
        "PEP 723 [tool.uv.sources] local path '../pkgs/internal_runner' importing subprocess must propagate external_paths"
    );
    assert_eq!(
        report.resolved_files.len(),
        1,
        "expected internal_runner/__init__.py to be resolved on disk"
    );
}

#[test]
fn deno_import_map_and_pep723_escape_outside_workspace_are_blocked() {
    let ws = TestWorkspace::new("import_map_pep723_escape");

    ws.write_file(
        "deno.json",
        r#"{
  "imports": {
    "@escaped/": "../../outside_workspace/"
  }
}"#,
    );
    let js_entry = ws.write_file(
        "main.ts",
        "import { x } from '@escaped/secret.ts';\nconsole.log(x);\n",
    );

    let py_entry = ws.write_file(
        "run.py",
        r#"# /// script
# dependencies = ["escaped-pkg"]
# [tool.uv.sources]
# escaped-pkg = { path = "../../outside_py_pkg" }
# ///
import escaped_pkg
"#,
    );

    let resolver = TransitiveImportResolver::new(ws.path());

    let js_report = resolver.resolve_javascript(
        &fs::read_to_string(&js_entry).unwrap(),
        Some(&js_entry),
    );
    assert!(
        js_report
            .unresolved_imports
            .iter()
            .any(|u| u.starts_with("escaped:")),
        "deno.json import map target escaping workspace must record escaped entry: {:?}",
        js_report.unresolved_imports
    );

    let py_report = resolver.resolve_python(
        &fs::read_to_string(&py_entry).unwrap(),
        Some(&py_entry),
    );
    assert!(
        py_report
            .unresolved_imports
            .iter()
            .any(|u| u.starts_with("escaped:")),
        "PEP 723 [tool.uv.sources] path escaping workspace must record escaped entry: {:?}",
        py_report.unresolved_imports
    );
}

#[test]
fn python_uv_lock_and_poetry_lock_resolve_local_editable_and_directory_packages() {
    let ws = TestWorkspace::new("uv_and_poetry_lock_local");

    // 1. uv.lock editable package in `packages/uv-net-client`
    ws.write_file(
        "uv.lock",
        r#"version = 1
requires-python = ">=3.12"

[[package]]
name = "uv-net-client"
version = "0.1.0"
source = { editable = "packages/uv-net-client" }
"#,
    );
    ws.write_file(
        "packages/uv-net-client/src/uv_net_client/__init__.py",
        "import socket\ndef connect_remote():\n    return socket.create_connection(('example.com', 443))\n",
    );

    // 2. poetry.lock directory package in `packages/poetry-cleaner`
    ws.write_file(
        "poetry.lock",
        r#"[[package]]
name = "poetry-cleaner"
version = "0.2.0"
description = "Local cleaner"
optional = false
python-versions = ">=3.11"

[package.source]
type = "directory"
url = "packages/poetry-cleaner"
"#,
    );
    ws.write_file(
        "packages/poetry-cleaner/poetry_cleaner/__init__.py",
        "import shutil\ndef wipe_dir():\n    shutil.rmtree('/tmp/cache')\n",
    );

    let entry = ws.write_file(
        "app.py",
        "import uv_net_client\nimport poetry_cleaner\nuv_net_client.connect_remote()\npoetry_cleaner.wipe_dir()\n",
    );

    let resolver = TransitiveImportResolver::new(ws.path());
    let report = resolver.resolve_python(&fs::read_to_string(&entry).unwrap(), Some(&entry));

    assert!(
        report.capabilities.network,
        "uv.lock editable package importing socket must propagate network capability"
    );
    assert!(
        report.capabilities.external_paths,
        "poetry.lock directory package calling shutil.rmtree('/tmp/cache') must propagate external_paths"
    );
    assert_eq!(report.resolved_files.len(), 2);
}
#[test]
fn bun_and_pnpm_workspace_catalogs_resolve_local_links_and_external_capabilities() {
    let ws = TestWorkspace::new("bun_pnpm_catalogs");

    // 1. `pnpm-workspace.yaml` with `catalog:` and `catalogs:`
    ws.write_file(
        "pnpm-workspace.yaml",
        r#"packages:
  - 'packages/*'

catalog:
  '@acme/shared-fs': link:packages/shared-fs
  axios: ^1.7.2

catalogs:
  daemon_tools:
    '@acme/worker-pool': file:packages/worker-pool
"#,
    );

    ws.write_file(
        "packages/shared-fs/package.json",
        r#"{ "name": "@acme/shared-fs", "main": "index.ts" }"#,
    );
    ws.write_file(
        "packages/shared-fs/index.ts",
        "import fs from 'node:fs';\nexport function readSecret() { return fs.readFileSync('/etc/hosts'); }\n",
    );

    ws.write_file(
        "packages/worker-pool/package.json",
        r#"{ "name": "@acme/worker-pool", "main": "index.ts" }"#,
    );
    ws.write_file(
        "packages/worker-pool/index.ts",
        "import cp from 'node:child_process';\nexport function spawnWorker() { return cp.fork('worker.js'); }\n",
    );

    ws.write_file(
        "packages/app/package.json",
        r#"{
  "name": "@acme/app",
  "dependencies": {
    "@acme/shared-fs": "catalog:",
    "@acme/worker-pool": "catalog:daemon_tools",
    "axios": "catalog:"
  }
}"#,
    );

    let entry = ws.write_file(
        "packages/app/main.ts",
        r#"
import { readSecret } from "@acme/shared-fs";
import { spawnWorker } from "@acme/worker-pool";
import axios from "axios";
readSecret();
spawnWorker();
console.log(axios);
"#,
    );

    let resolver = TransitiveImportResolver::new(ws.path());
    let report = resolver.resolve_javascript(&fs::read_to_string(&entry).unwrap(), Some(&entry));

    assert!(
        report.capabilities.external_paths,
        "catalog: local package '@acme/shared-fs' importing node:fs must propagate external_paths"
    );
    assert!(
        report.capabilities.daemon,
        "catalog:daemon_tools local package '@acme/worker-pool' importing node:child_process must propagate daemon"
    );
    assert!(
        report.capabilities.network,
        "catalog: external package 'axios' must propagate network capability"
    );
    assert_eq!(report.resolved_files.len(), 2);
}
