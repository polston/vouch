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
