use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use vouch::daemon::lifecycle::{generate_session_token, is_pid_alive, PidLockGuard};
use vouch::daemon::{run_daemon_server, try_query_daemon, DaemonRequest};

fn make_temp_dir(prefix: &str) -> PathBuf {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let p = std::env::temp_dir().join(format!("{prefix}_{}_{now}", std::process::id()));
    std::fs::create_dir_all(&p).unwrap();
    p
}

#[test]
fn daemon_session_token_generation_and_uniqueness() {
    let token1 = generate_session_token();
    let token2 = generate_session_token();
    assert_eq!(token1.len(), 64);
    assert_eq!(token2.len(), 64);
    assert_ne!(token1, token2);
}

#[test]
fn daemon_pid_liveness_check() {
    let current_pid = std::process::id();
    assert!(is_pid_alive(current_pid));
    // Non-existent large PID should not be alive
    assert!(!is_pid_alive(4_000_000));
}

#[test]
fn daemon_pid_lock_lifecycle_and_duplicate_rejection() {
    let tmp = make_temp_dir("daemon_pid_test");
    let pid_file = tmp.join("test_daemon.pid");

    // First acquisition succeeds
    let mut lock1 = PidLockGuard::acquire(&pid_file).expect("lock1 acquires");
    assert!(pid_file.exists());
    let content = std::fs::read_to_string(&pid_file).unwrap();
    assert_eq!(content.trim(), std::process::id().to_string());

    // Second acquisition on the same path fails because current process is alive
    let lock2_res = PidLockGuard::acquire(&pid_file);
    assert!(lock2_res.is_err());
    let err_msg = lock2_res.err().unwrap();
    assert!(err_msg.contains("already running"));

    // Releasing lock1 allows subsequent acquisition
    lock1.release();
    assert!(!pid_file.exists());

    let lock3 = PidLockGuard::acquire(&pid_file).expect("lock3 acquires after release");
    drop(lock3);
    assert!(!pid_file.exists());

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn daemon_server_runs_and_shuts_down_cleanly() {
    let tmp = make_temp_dir("daemon_srv_test");
    let pid = std::process::id();
    let socket_path = PathBuf::from(format!("/tmp/vdl-{pid}.sock"));
    let home = tmp.to_string_lossy().to_string();

    let shutdown_flag = Arc::new(AtomicBool::new(false));
    let shutdown_clone = Arc::clone(&shutdown_flag);
    let sock_clone = socket_path.clone();
    let home_clone = home.clone();

    let server_handle = std::thread::spawn(move || {
        let _ = run_daemon_server(&sock_clone, &home_clone, Some(shutdown_clone));
    });

    // Wait briefly for server to bind
    for _ in 0..50 {
        if socket_path.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(socket_path.exists());

    // Query daemon
    let req = DaemonRequest {
        raw: r#"{"type":"pre_tool_use","tool_name":"bash","tool_args":{"command":"echo test"}}"#.into(),
        notice: None,
        host: "claude".into(),
        shadow: false,
        state_dir: tmp.join("state").to_string_lossy().to_string(),
        home_dir: home.clone(),
    };
    let resp = try_query_daemon(&socket_path, &req, 500);
    assert!(resp.is_ok());

    // Trigger graceful shutdown
    shutdown_flag.store(true, Ordering::SeqCst);
    server_handle.join().unwrap();

    // Socket file must be cleanly unlinked
    assert!(!socket_path.exists());

    let _ = std::fs::remove_dir_all(&tmp);
}
