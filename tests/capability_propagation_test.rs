use vouch::capability::{
    capabilities_for_cmd, capabilities_for_occurrences, propagate_capabilities,
    CapabilityEmitter, CapabilitySet,
};
use vouch::guards::{in_effect, Knowledge, Occurrence, SourceProvenance};
use vouch::syntax::Cmd;
use vouch::protocol::is_demote_eligible;

#[test]
fn capability_set_basic_operations_and_helpers() {
    let mut set = CapabilitySet::new();
    assert!(set.is_empty());
    assert!(!set.has_any());
    assert!(!set.contains("network"));

    set.insert("network");
    assert!(!set.is_empty());
    assert!(set.has_any());
    assert!(set.contains("network"));
    assert_eq!(set.to_vec(), vec!["network"]);

    let mut other = CapabilitySet::default();
    other.insert("external_paths");
    other.insert("daemon");
    assert!(other.contains("external_paths"));
    assert!(other.contains("daemon"));

    set.union(other);
    assert!(set.network);
    assert!(set.external_paths);
    assert!(set.daemon);
    assert_eq!(set.to_vec(), vec!["network", "external_paths", "daemon"]);

    let from_slice = CapabilitySet::from_slice(&["network", "daemon"]);
    assert!(from_slice.network);
    assert!(!from_slice.external_paths);
    assert!(from_slice.daemon);

    // Serialization & Deserialization
    let serialized = serde_json::to_string(&set).unwrap();
    let deserialized: CapabilitySet = serde_json::from_str(&serialized).unwrap();
    assert_eq!(set, deserialized);
}

#[test]
fn python_subprocess_curl_propagates_network_capability() {
    let kb = in_effect();
    let cmd = r#"python -c "import subprocess; subprocess.run(['curl', 'https://example.com'])""#;
    let caps = propagate_capabilities(kb, cmd, "bash");
    assert!(caps.network, "curl child command must propagate network capability to parent python snippet");
    assert!(!caps.daemon, "curl does not require daemon capability");
}

#[test]
fn python_subprocess_docker_propagates_external_paths_and_daemon() {
    let kb = in_effect();
    let cmd = r#"python -c "import subprocess; subprocess.run(['docker', 'run', 'img'])""#;
    let caps = propagate_capabilities(kb, cmd, "bash");
    assert!(
        caps.external_paths,
        "docker child command must propagate external_paths capability to parent python snippet"
    );
    assert!(
        caps.daemon,
        "docker child command must propagate daemon capability to parent python snippet"
    );
}

#[test]
fn python_subprocess_offline_git_status_has_zero_capabilities() {
    let kb = in_effect();
    let cmd = r#"python -c "import subprocess; subprocess.run(['git', 'status'])""#;
    let caps = propagate_capabilities(kb, cmd, "bash");
    assert!(
        !caps.has_any(),
        "git status in subprocess requires zero capabilities, expected clean capability set but got {caps:?}"
    );
}

#[test]
fn node_exec_sync_curl_propagates_network_capability() {
    let kb = in_effect();
    let cmd = r#"node -e "require('child_process').execSync('curl https://example.com');""#;
    let caps = propagate_capabilities(kb, cmd, "bash");
    assert!(
        caps.network,
        "execSync curl inside node snippet must propagate network capability"
    );
}

#[test]
fn multi_hop_nested_wrappers_propagate_network_capability() {
    let kb = in_effect();
    let nested = r#"bash -c "python -c \"import subprocess; subprocess.run(['curl', 'https://example.com'])\"""#;
    let caps = propagate_capabilities(kb, nested, "bash");
    assert!(
        caps.network,
        "bash -> python -> subprocess -> curl multi-hop chain must transitively propagate network capability"
    );
}

#[test]
fn multi_hop_nested_wrappers_offline_remain_zero_capabilities() {
    let kb = in_effect();
    let nested = r#"bash -c "python -c \"import subprocess; subprocess.run(['git', 'status'])\"""#;
    let caps = propagate_capabilities(kb, nested, "bash");
    assert!(
        !caps.has_any(),
        "bash -> python -> subprocess -> git status multi-hop chain must maintain zero capabilities"
    );
}

#[test]
fn extensible_custom_capability_emitter() {
    struct CustomEmitter;
    impl CapabilityEmitter for CustomEmitter {
        fn required_capabilities(
            &self,
            cmd: &Cmd,
            _kb: &Knowledge,
            _lang: &str,
        ) -> CapabilitySet {
            let mut set = CapabilitySet::default();
            if cmd.head == "custom-agent-sync" {
                set.network = true;
                set.daemon = true;
            }
            set
        }
    }

    let kb = in_effect();
    let cmd = Cmd {
        head: "custom-agent-sync".to_string(),
        args: vec![],
        unread_args: Default::default(),
        keyword_args: Default::default(),
        callable_args: Default::default(),
        expandable_args: Default::default(),
        chain: None,
        prefix_assigns: vec![],
        receiver_origin: vouch::syntax::ValueOrigin::Unknown,
        by_reference: false,
        env_assigns: Default::default(),
        is_intra_command_function: false,
    };
    let occ = Occurrence {
        cmd,
        execution_site: vouch::guards::ExecutionSite {
            scope: 0,
            local_order: None,
            scanner_order: false,
        },
        lang: "bash".to_string(),
        provenance: SourceProvenance::Direct,
        args_from_input: false,
        args_complete: true,
        inherited_run_dir: None,
        assignments: vec![],
    };

    let caps = capabilities_for_occurrences(kb, &[occ], &CustomEmitter);
    assert!(caps.network);
    assert!(caps.daemon);
    assert!(!caps.external_paths);

    let curl_cmd = Cmd {
        head: "curl".to_string(),
        args: vec!["https://example.com".to_string()],
        unread_args: Default::default(),
        keyword_args: Default::default(),
        callable_args: Default::default(),
        expandable_args: Default::default(),
        chain: None,
        prefix_assigns: vec![],
        receiver_origin: vouch::syntax::ValueOrigin::Unknown,
        by_reference: false,
        env_assigns: Default::default(),
        is_intra_command_function: false,
    };
    let curl_caps = capabilities_for_cmd(kb, &curl_cmd, "bash");
    assert!(curl_caps.network);
}

#[test]
fn protocol_demotion_rejects_subprocesses_with_capabilities() {
    let kb = in_effect();
    let temp = std::env::temp_dir();
    let cwd = temp.to_string_lossy().to_string();

    // Python invoking curl (network) -> must NOT demote (BypassSandbox must remain true)
    let net_cmd = r#"python -c "import subprocess; subprocess.run(['curl', 'https://example.com'])""#;
    assert!(
        !is_demote_eligible(kb, net_cmd, &cwd),
        "command with child network capability must not be eligible for sandbox demotion"
    );

    // Python invoking docker (external_paths & daemon) -> must NOT demote
    let docker_cmd = r#"python -c "import subprocess; subprocess.run(['docker', 'run', 'img'])""#;
    assert!(
        !is_demote_eligible(kb, docker_cmd, &cwd),
        "command with child external_paths/daemon capability must not be eligible for sandbox demotion"
    );
}

#[test]
fn protocol_demotion_permits_safe_offline_subprocesses() {
    let kb = in_effect();
    let temp = std::env::temp_dir();
    let cwd = temp.to_string_lossy().to_string();

    // Offline git status inside python subprocess -> eligible for demotion when in workspace
    let offline_cmd = r#"python -c "import subprocess; subprocess.run(['git', 'status'])""#;
    assert!(
        is_demote_eligible(kb, offline_cmd, &cwd),
        "offline child command with zero capabilities in safe workspace should be eligible for demotion"
    );
}

#[test]
fn transitive_import_resolver_follows_worker_thread_files_and_vm_capabilities() {
    use vouch::capability::TransitiveImportResolver;

    let tmp_dir = std::env::temp_dir().join(format!("vouch_worker_cap_test_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp_dir);
    std::fs::create_dir_all(&tmp_dir).expect("create_dir_all");
    let worker_net = tmp_dir.join("worker_net.mjs");
    let worker_fs = tmp_dir.join("worker_fs.mjs");
    let entry_file = tmp_dir.join("index.mjs");

    std::fs::write(&worker_net, "import https from 'node:https';\nhttps.get('https://example.com');\n")
        .expect("write worker_net");
    std::fs::write(&worker_fs, "import fs from 'node:fs';\nfs.writeFileSync('/tmp/out', '1');\n")
        .expect("write worker_fs");
    let entry_src = r#"
        import { Worker } from 'node:worker_threads';
        const w1 = new Worker('./worker_net.mjs');
        const w2 = new Worker(new URL('./worker_fs.mjs', import.meta.url));
    "#;
    std::fs::write(&entry_file, entry_src).expect("write entry");

    let resolver = TransitiveImportResolver::new(&tmp_dir);
    let report = resolver.resolve_javascript(entry_src, Some(&entry_file));
    let _ = std::fs::remove_dir_all(&tmp_dir);

    assert!(
        report.capabilities.daemon,
        "Worker instantiation must set daemon capability"
    );
    assert!(
        report.capabilities.network,
        "TransitiveImportResolver must follow ./worker_net.mjs and union network capability: {:?}",
        report
    );
    assert!(
        report.capabilities.external_paths,
        "TransitiveImportResolver must follow new URL('./worker_fs.mjs', import.meta.url) and union external_paths capability: {:?}",
        report
    );
    assert_eq!(report.resolved_files.len(), 2);
    assert!(report.unresolved_imports.is_empty());
}

#[test]
fn python_importlib_and_dunder_import_resolve_static_and_relative_modules() {
    use vouch::capability::TransitiveImportResolver;

    let tmp_dir = std::env::temp_dir().join(format!("vouch_py_dyn_import_test_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp_dir);
    std::fs::create_dir_all(tmp_dir.join("pkg")).expect("create pkg dir");
    std::fs::create_dir_all(tmp_dir.join("scripts")).expect("create scripts dir");

    std::fs::write(tmp_dir.join("pkg/__init__.py"), "").expect("write init");
    std::fs::write(
        tmp_dir.join("pkg/net.py"),
        "import socket\ndef connect():\n    return socket.socket()\n",
    )
    .expect("write pkg/net.py");
    std::fs::write(
        tmp_dir.join("pkg/sub.py"),
        "import shutil\ndef clean():\n    shutil.rmtree('/tmp/work')\n",
    )
    .expect("write pkg/sub.py");
    std::fs::write(
        tmp_dir.join("pkg/worker.py"),
        "import multiprocessing\n",
    )
    .expect("write pkg/worker.py");
    std::fs::write(
        tmp_dir.join("scripts/task.py"),
        "import urllib.request\n",
    )
    .expect("write scripts/task.py");

    let resolver = TransitiveImportResolver::new(&tmp_dir);

    // 1. Static importlib.import_module("pkg.net") and __import__("pkg.net")
    let r_importlib = resolver.resolve_python(
        "import importlib\nm = importlib.import_module('pkg.net')\n",
        None,
    );
    assert!(
        r_importlib.capabilities.network,
        "importlib.import_module('pkg.net') must resolve pkg/net.py and propagate network=true: {:?}",
        r_importlib
    );
    assert!(!r_importlib.capabilities.dynamic_eval);
    assert_eq!(r_importlib.resolved_files.len(), 1);

    let r_dunder = resolver.resolve_python(
        "m = __import__('pkg.net')\n",
        None,
    );
    assert!(
        r_dunder.capabilities.network,
        "__import__('pkg.net') must resolve pkg/net.py and propagate network=true: {:?}",
        r_dunder
    );
    assert!(!r_dunder.capabilities.dynamic_eval);

    // 2. Relative importlib.import_module(".sub", package="pkg")
    let r_rel = resolver.resolve_python(
        "from importlib import import_module\nmod = import_module('.sub', package='pkg')\n",
        None,
    );
    assert!(
        r_rel.capabilities.external_paths,
        "import_module('.sub', package='pkg') must resolve pkg/sub.py and propagate external_paths=true: {:?}",
        r_rel
    );
    assert!(!r_rel.capabilities.dynamic_eval);
    assert_eq!(r_rel.resolved_files.len(), 1);

    // 3. runpy.run_module("pkg.worker") and runpy.run_path("./scripts/task.py")
    let r_run_mod = resolver.resolve_python(
        "import runpy\nrunpy.run_module('pkg.worker')\n",
        None,
    );
    assert!(
        r_run_mod.capabilities.daemon,
        "runpy.run_module('pkg.worker') must resolve pkg/worker.py and propagate daemon=true: {:?}",
        r_run_mod
    );
    assert!(!r_run_mod.capabilities.dynamic_eval);

    let r_run_path = resolver.resolve_python(
        "from runpy import run_path\nrun_path('./scripts/task.py')\n",
        None,
    );
    assert!(
        r_run_path.capabilities.network,
        "run_path('./scripts/task.py') must resolve scripts/task.py and propagate network=true: {:?}",
        r_run_path
    );
    assert!(!r_run_path.capabilities.dynamic_eval);

    // 4. Dynamic / computed arguments set dynamic_eval = true, record unresolved_imports, and emit unmodeled_import in python::parse
    let dyn_importlib_src = "import importlib, sys\nuser_mod = sys.argv[1]\nimportlib.import_module(user_mod)\n";
    let r_dyn_importlib = resolver.resolve_python(dyn_importlib_src, None);
    assert!(
        r_dyn_importlib.capabilities.dynamic_eval,
        "Dynamic importlib.import_module(user_mod) must set dynamic_eval=true: {:?}",
        r_dyn_importlib
    );
    assert!(
        r_dyn_importlib
            .unresolved_imports
            .iter()
            .any(|u| u == "dynamic_import: importlib.import_module"),
        "Dynamic importlib.import_module must record unresolved dynamic_import: {:?}",
        r_dyn_importlib.unresolved_imports
    );
    let scan_dyn_importlib = vouch::python::parse(dyn_importlib_src).expect("parse dyn_importlib");
    assert!(
        scan_dyn_importlib
            .constructs
            .iter()
            .any(|c| c == "unmodeled_import"),
        "python::parse must emit unmodeled_import for dynamic importlib.import_module: {:?}",
        scan_dyn_importlib.constructs
    );

    let dyn_run_path_src = "import runpy, os\ndynamic_path = os.getenv('TASK_SCRIPT')\nrunpy.run_path(dynamic_path)\n";
    let r_dyn_run_path = resolver.resolve_python(dyn_run_path_src, None);
    assert!(
        r_dyn_run_path.capabilities.dynamic_eval,
        "Dynamic runpy.run_path(dynamic_path) must set dynamic_eval=true: {:?}",
        r_dyn_run_path
    );
    assert!(
        r_dyn_run_path
            .unresolved_imports
            .iter()
            .any(|u| u == "dynamic_import: runpy.run_path"),
        "Dynamic runpy.run_path must record unresolved dynamic_import: {:?}",
        r_dyn_run_path.unresolved_imports
    );
    let scan_dyn_run_path = vouch::python::parse(dyn_run_path_src).expect("parse dyn_run_path");
    assert!(
        scan_dyn_run_path
            .constructs
            .iter()
            .any(|c| c == "unmodeled_import"),
        "python::parse must emit unmodeled_import for dynamic runpy.run_path: {:?}",
        scan_dyn_run_path.constructs
    );

    let _ = std::fs::remove_dir_all(&tmp_dir);
}

#[test]
fn python_ctypes_and_cffi_native_ffi_capability_propagation() {
    use vouch::capability::TransitiveImportResolver;

    let tmp_dir = std::env::temp_dir().join(format!(
        "vouch_cap_py_ffi_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let pkg_dir = tmp_dir.join("native_pkg");
    std::fs::create_dir_all(&pkg_dir).unwrap();
    std::fs::write(pkg_dir.join("__init__.py"), "").unwrap();
    std::fs::write(
        pkg_dir.join("bridge.py"),
        "import ctypes\nlibc = ctypes.CDLL('libc.so.6')\nlibc.getpid()\n",
    )
    .unwrap();
    std::fs::write(
        pkg_dir.join("cffi_compile.py"),
        "from cffi import FFI\nffi = FFI()\nffi.cdef('int system(const char *);')\nlib = ffi.verify('#include <stdlib.h>')\n",
    )
    .unwrap();

    let resolver = TransitiveImportResolver::new(&tmp_dir);

    // 1. Static ctypes.CDLL('libc.so.6') sets external_paths=true, daemon=true, dynamic_eval=false
    let r_static_cdll = resolver.resolve_python(
        "import ctypes\nlibc = ctypes.CDLL('libc.so.6')\nlibc.puts(b'hello')\n",
        None,
    );
    assert!(r_static_cdll.capabilities.external_paths);
    assert!(r_static_cdll.capabilities.daemon);
    assert!(
        !r_static_cdll.capabilities.dynamic_eval,
        "Static ctypes.CDLL with constant args should not set dynamic_eval: {:?}",
        r_static_cdll
    );

    // 2. Transitive import of native_pkg.bridge propagates external_paths=true and daemon=true
    let r_transitive = resolver.resolve_python("import native_pkg.bridge\n", None);
    assert!(r_transitive.capabilities.external_paths);
    assert!(r_transitive.capabilities.daemon);
    assert!(!r_transitive.capabilities.dynamic_eval);

    // 3. ctypes.cdll.libc.system(...) or dynamic argument to native function sets dynamic_eval=true
    let r_cdll_system = resolver.resolve_python(
        "import ctypes\nctypes.cdll.libc.system(b'id')\n",
        None,
    );
    assert!(r_cdll_system.capabilities.external_paths);
    assert!(r_cdll_system.capabilities.daemon);
    assert!(
        r_cdll_system.capabilities.dynamic_eval,
        "ctypes.cdll.libc.system must set dynamic_eval=true: {:?}",
        r_cdll_system
    );

    let r_cdll_dyn_arg = resolver.resolve_python(
        "import ctypes, sys\nlib = ctypes.WinDLL('kernel32.dll')\nlib.WinExec(sys.argv[1], 1)\n",
        None,
    );
    assert!(r_cdll_dyn_arg.capabilities.external_paths);
    assert!(r_cdll_dyn_arg.capabilities.daemon);
    assert!(r_cdll_dyn_arg.capabilities.dynamic_eval);

    // 4. Dynamic library path in ctypes.CDLL(user_so) sets dynamic_eval=true and emits unmodeled_import
    let dyn_cdll_src = "from ctypes import CDLL\nimport os\nso_path = os.getenv('PLUGIN_SO')\nCDLL(so_path)\n";
    let r_dyn_cdll = resolver.resolve_python(dyn_cdll_src, None);
    assert!(r_dyn_cdll.capabilities.external_paths);
    assert!(r_dyn_cdll.capabilities.daemon);
    assert!(r_dyn_cdll.capabilities.dynamic_eval);
    assert!(
        r_dyn_cdll
            .unresolved_imports
            .iter()
            .any(|u| u == "dynamic_import: ctypes.CDLL"),
        "Dynamic ctypes.CDLL must record unresolved dynamic_import: {:?}",
        r_dyn_cdll.unresolved_imports
    );
    let scan_dyn_cdll = vouch::python::parse(dyn_cdll_src).expect("parse dyn_cdll_src");
    assert!(
        scan_dyn_cdll
            .constructs
            .iter()
            .any(|c| c == "unmodeled_import"),
        "python::parse must emit unmodeled_import for dynamic ctypes.CDLL: {:?}",
        scan_dyn_cdll.constructs
    );

    // 5. cffi.FFI().dlopen static vs dynamic and ffi.verify / ffi.set_source inline C compilation
    let r_cffi_static = resolver.resolve_python(
        "import cffi\nffi = cffi.FFI()\nffi.cdef('int getpid(void);')\nC = ffi.dlopen(None)\nC.getpid()\n",
        None,
    );
    assert!(r_cffi_static.capabilities.external_paths);
    assert!(r_cffi_static.capabilities.daemon);
    assert!(!r_cffi_static.capabilities.dynamic_eval);

    let r_cffi_dyn_dlopen = resolver.resolve_python(
        "from cffi import FFI\nimport sys\nffi = FFI()\nlib = ffi.dlopen(sys.argv[1])\n",
        None,
    );
    assert!(r_cffi_dyn_dlopen.capabilities.external_paths);
    assert!(r_cffi_dyn_dlopen.capabilities.daemon);
    assert!(r_cffi_dyn_dlopen.capabilities.dynamic_eval);
    assert!(
        r_cffi_dyn_dlopen
            .unresolved_imports
            .iter()
            .any(|u| u == "dynamic_import: cffi.FFI.dlopen"),
        "Dynamic ffi.dlopen must record unresolved dynamic_import: {:?}",
        r_cffi_dyn_dlopen.unresolved_imports
    );

    let r_cffi_verify = resolver.resolve_python("import native_pkg.cffi_compile\n", None);
    assert!(r_cffi_verify.capabilities.external_paths);
    assert!(r_cffi_verify.capabilities.daemon);
    assert!(
        r_cffi_verify.capabilities.dynamic_eval,
        "Transitive import of module calling ffi.verify must propagate dynamic_eval=true: {:?}",
        r_cffi_verify
    );

    // 6. PEP 723 inline script metadata with cffi dependency
    let pep723_cffi = "# /// script\n# dependencies = [\"cffi>=1.16\"]\n# ///\nprint('ok')\n";
    let r_pep723 = resolver.resolve_python(pep723_cffi, None);
    assert!(r_pep723.capabilities.external_paths);
    assert!(r_pep723.capabilities.daemon);

    let _ = std::fs::remove_dir_all(&tmp_dir);
}
