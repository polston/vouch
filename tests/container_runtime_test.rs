use std::path::PathBuf;
use vouch::config::load;
use vouch::container_runtime::{detect_active_runtime, normalize_mount_source, ContainerEngine};

fn temp_dir(prefix: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "{prefix}_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::create_dir_all(&p);
    p
}

#[test]
fn test_container_runtime_socket_detection() {
    let tmp = temp_dir("container_rt");
    let home = tmp.to_str().unwrap();

    // No sockets exist yet
    let none_found = detect_active_runtime(home);
    // Might find system /var/run/docker.sock if present on host, or None
    if !std::path::Path::new("/var/run/docker.sock").exists() {
        assert!(none_found.is_none());
    }

    // Create mock Colima socket
    let colima_dir = tmp.join(".colima/default");
    std::fs::create_dir_all(&colima_dir).unwrap();
    let sock = colima_dir.join("docker.sock");
    std::fs::write(&sock, b"").unwrap();

    let rt = detect_active_runtime(home).expect("should detect colima socket");
    assert_eq!(rt.engine, ContainerEngine::Colima);
    assert_eq!(rt.socket_path, sock);
    assert!(rt.is_vm_backed);

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn test_normalize_mount_source() {
    let home = "/Users/dev";
    let normalized = normalize_mount_source("~/project/data", home);
    assert_eq!(normalized, "/Users/dev/project/data");

    let raw = normalize_mount_source("/var/log", home);
    assert_eq!(raw, "/var/log");
}

#[test]
fn test_nerdctl_and_finch_volume_evaluation() {
    let cfg_text = r#"
[lang.bash]
default = "allow"
[write]
default = "ask"
allow_paths = [
  "C:/workspace/**",
  "/Users/dev/scratch/**",
]
ask_paths = [
  "/etc/**",
  "/private/etc/**",
]
"#;
    let cfg = load(cfg_text).expect("valid config");
    let kb = vouch::guards::in_effect();

    let home = Some("/Users/dev");

    // nerdctl run with allowed volume mount
    let dec_allow = vouch::engine::decide_command_in_with_knowledge(
        &cfg,
        "bash",
        "nerdctl run -v /Users/dev/scratch/data:/data alpine ls",
        home,
        None,
        Some(kb),
    );
    assert!(matches!(dec_allow, vouch::protocol::Decision::Allow(_)));

    // finch run with unallowed volume mount outside allow_paths
    let dec_ask = vouch::engine::decide_command_in_with_knowledge(
        &cfg,
        "bash",
        "finch run -v /var/secret:/data alpine ls",
        home,
        None,
        Some(kb),
    );
    assert!(matches!(dec_ask, vouch::protocol::Decision::Ask(_)));

    // colima nerdctl run with protected path
    let dec_colima = vouch::engine::decide_command_in_with_knowledge(
        &cfg,
        "bash",
        "colima nerdctl run -v /etc/shadow:/data alpine ls",
        home,
        None,
        Some(kb),
    );
    assert!(matches!(dec_colima, vouch::protocol::Decision::Ask(_)));
}
