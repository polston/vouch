//! Tests for persistent gating daemon & in-memory IPC runtime (M4.5).

#[cfg(unix)]
mod daemon_tests {
    use std::fs;
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};

    use vouch::daemon::{run_daemon_server, try_query_daemon, DaemonRequest, DaemonState};

    struct TestEnv {
        root: PathBuf,
        socket_path: PathBuf,
        home: PathBuf,
        state_dir: PathBuf,
        shutdown: Arc<AtomicBool>,
        server_handle: Option<thread::JoinHandle<Result<(), String>>>,
    }

    impl TestEnv {
        fn new(_name: &str) -> Self {
            let pid = std::process::id();
            let nonce = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let root = std::env::temp_dir().join(format!("vouch-dt-{pid}-{nonce}"));
            let home = root.join("home");
            let socket_path = PathBuf::from(format!("/tmp/vd-{pid}-{}.sock", nonce % 1000000));
            let state_dir = root.join("state");

            fs::create_dir_all(&home.join(".config/vouch")).unwrap();
            fs::create_dir_all(&state_dir).unwrap();

            Self {
                root,
                socket_path,
                home,
                state_dir,
                shutdown: Arc::new(AtomicBool::new(false)),
                server_handle: None,
            }
        }

        fn start_server(&mut self) {
            let socket_path = self.socket_path.clone();
            let home_str = self.home.to_str().unwrap().to_string();
            let shutdown = Arc::clone(&self.shutdown);

            let handle = thread::spawn(move || {
                run_daemon_server(&socket_path, &home_str, Some(shutdown))
            });
            self.server_handle = Some(handle);

            // Wait for socket to become available
            let deadline = Instant::now() + Duration::from_millis(2000);
            while Instant::now() < deadline {
                if let Some(ref handle) = self.server_handle {
                    if handle.is_finished() {
                        panic!("Daemon server thread terminated unexpectedly");
                    }
                }
                if self.socket_path.exists() {
                    if UnixStream::connect(&self.socket_path).is_ok() {
                        return;
                    }
                }
                thread::sleep(Duration::from_millis(10));
            }
            panic!("Daemon server failed to bind socket in time: {}", self.socket_path.display());
        }

        fn stop(mut self) {
            self.shutdown.store(true, Ordering::Relaxed);
            let _ = UnixStream::connect(&self.socket_path);
            if let Some(handle) = self.server_handle.take() {
                let _ = handle.join();
            }
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    impl Drop for TestEnv {
        fn drop(&mut self) {
            self.shutdown.store(true, Ordering::Relaxed);
            let _ = UnixStream::connect(&self.socket_path);
            if let Some(handle) = self.server_handle.take() {
                let _ = handle.join();
            }
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn daemon_fallback_when_socket_missing() {
        let req = DaemonRequest {
            raw: r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}"#.into(),
            notice: None,
            host: "claude".into(),
            shadow: false,
            state_dir: "/tmp".into(),
            home_dir: "C:/Users/dev".into(),
        };

        let missing = PathBuf::from("/tmp/nonexistent-vouch-daemon-socket.sock");
        let res = try_query_daemon(&missing, &req, 20);
        assert!(res.is_err(), "querying nonexistent socket must return error");
    }

    #[test]
    fn daemon_query_parity_with_direct_eval() {
        let mut env = TestEnv::new("parity");
        let config_toml = r#"
version = 1
[tools]
Bash = "allow"
"#;
        fs::write(env.home.join(".config/vouch/config.toml"), config_toml).unwrap();
        env.start_server();

        let req = DaemonRequest {
            raw: r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git status"}}"#.into(),
            notice: None,
            host: "claude".into(),
            shadow: false,
            state_dir: env.state_dir.to_str().unwrap().into(),
            home_dir: env.home.to_str().unwrap().into(),
        };

        let daemon_resp = try_query_daemon(&env.socket_path, &req, 500).expect("daemon query should succeed");
        assert!(daemon_resp.from_daemon);

        let direct_state = DaemonState::new(env.home.to_str().unwrap());
        let direct_resp = direct_state.process_request(&req);

        assert_eq!(daemon_resp.output, direct_resp.output);
        env.stop();
    }

    #[test]
    fn daemon_hot_reloads_config_changes() {
        let mut env = TestEnv::new("hotreload");
        let initial_config = r#"
version = 1
[tools]
Bash = "ask"
"#;
        let config_file = env.home.join(".config/vouch/config.toml");
        fs::write(&config_file, initial_config).unwrap();
        env.start_server();

        let req = DaemonRequest {
            raw: r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo hello"}}"#.into(),
            notice: None,
            host: "claude".into(),
            shadow: false,
            state_dir: env.state_dir.to_str().unwrap().into(),
            home_dir: env.home.to_str().unwrap().into(),
        };

        let initial_resp = try_query_daemon(&env.socket_path, &req, 500).unwrap();
        assert!(initial_resp.output.is_some(), "Bash=ask should emit a prompt response");

        // Now modify config to allow
        thread::sleep(Duration::from_millis(50));
        let updated_config = r#"
version = 1
[tools]
Bash = "allow"
"#;
        fs::write(&config_file, updated_config).unwrap();
        thread::sleep(Duration::from_millis(50));

        let updated_resp = try_query_daemon(&env.socket_path, &req, 500).unwrap();
        let output = updated_resp.output.expect("updated Bash=allow should emit allow decision");
        assert!(output.contains("\"permissionDecision\":\"allow\""), "got: {output}");

        env.stop();
    }

    #[test]
    fn daemon_latency_benchmark() {
        let mut env = TestEnv::new("latency");
        let config_toml = r#"
version = 1
[tools]
Bash = "allow"
"#;
        fs::write(env.home.join(".config/vouch/config.toml"), config_toml).unwrap();
        env.start_server();

        let req = DaemonRequest {
            raw: r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git status"}}"#.into(),
            notice: None,
            host: "claude".into(),
            shadow: false,
            state_dir: env.state_dir.to_str().unwrap().into(),
            home_dir: env.home.to_str().unwrap().into(),
        };

        // Warmup
        let _ = try_query_daemon(&env.socket_path, &req, 500).unwrap();

        let iterations = 20;
        let start = Instant::now();
        for _ in 0..iterations {
            let res = try_query_daemon(&env.socket_path, &req, 500).unwrap();
            assert!(res.from_daemon);
        }
        let total = start.elapsed();
        let avg_us = total.as_micros() / iterations;
        assert!(
            avg_us < 2000,
            "Daemon average query latency ({avg_us}µs) exceeded 2ms (2000µs) target"
        );

        env.stop();
    }
}
