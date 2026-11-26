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

    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

    impl TestEnv {
        fn new(_name: &str) -> Self {
            let pid = std::process::id();
            let c = COUNTER.fetch_add(1, Ordering::SeqCst);
            let root = std::env::temp_dir().join(format!("vouch-dt-{pid}-{c}"));
            let home = root.join("home");
            let socket_path = PathBuf::from(format!("/tmp/vd-{pid}-{c}.sock"));
            let state_dir = root.join("state");

            let _ = std::fs::remove_file(&socket_path);
            let _ = std::fs::remove_dir_all(&root);
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

    #[test]
    fn daemon_socket_path_config_is_honored_and_env_overrides() {
        use std::io::{BufRead, BufReader, Write};
        use std::os::unix::net::UnixListener;

        // 1. Removed inert `daemon.fail_closed` must be rejected by config loader.
        let legacy_cfg = "[daemon]\nfail_closed = true\n";
        assert!(
            vouch::config::load(legacy_cfg).is_err(),
            "removed inert daemon.fail_closed key must be rejected"
        );

        // 2. Tilde expansion in resolve_socket_path.
        let expanded = vouch::daemon::resolve_socket_path("~/custom/v.sock", "/tmp/home-a");
        assert_eq!(expanded, PathBuf::from("/tmp/home-a/custom/v.sock"));

        let env = TestEnv::new("cfg_sock");
        let config_file = env.home.join(".config/vouch/config.toml");

        // Helper: bind a stub UnixListener that waits up to 2s for a single client
        // so a routing regression fails fast instead of blocking forever.
        fn spawn_stub_daemon(
            sock: &PathBuf,
            marker: &'static str,
        ) -> thread::JoinHandle<bool> {
            let _ = fs::remove_file(sock);
            let listener = UnixListener::bind(sock).expect("bind stub daemon socket");
            listener
                .set_nonblocking(true)
                .expect("set stub listener nonblocking");
            thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(2);
                while Instant::now() < deadline {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            let _ = stream.set_nonblocking(false);
                            let mut reader = BufReader::new(stream.try_clone().unwrap());
                            let mut line = String::new();
                            let _ = reader.read_line(&mut line);
                            let resp = format!(
                                r#"{{"output":"{{\"daemon_marker\":\"{marker}\"}}","from_daemon":true}}"#
                            );
                            writeln!(stream, "{resp}").unwrap();
                            let _ = stream.flush();
                            return true;
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => return false,
                    }
                }
                false
            })
        }

        // 3. Spin up a stub UnixListener at a custom socket path returning a unique marker
        //    that local direct evaluation could never produce, proving `vouch --hook`
        //    actually routes to `[daemon].socket_path` when VOUCH_DAEMON_SOCKET is unset.
        let custom_sock = env.socket_path.clone();
        let server = spawn_stub_daemon(&custom_sock, "from-configured-socket");

        let config_toml = format!(
            "version = 1\n[tools]\nBash = \"allow\"\n[daemon]\nsocket_path = {:?}\ntimeout_ms = 500\n",
            custom_sock.to_string_lossy()
        );
        fs::write(&config_file, &config_toml).unwrap();

        let hook_payload = r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}"#;
        let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_vouch"))
            .arg("--hook")
            .env("HOME", &env.home)
            .env("VOUCH_CONFIG", &config_file)
            .env("VOUCH_STATE_DIR", &env.state_dir)
            .env_remove("VOUCH_DAEMON_SOCKET")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn vouch --hook");
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(hook_payload.as_bytes())
            .unwrap();
        let output = child.wait_with_output().expect("wait vouch --hook");
        let accepted = server.join().expect("stub daemon server joined");
        assert!(accepted, "stub daemon at [daemon].socket_path received no connection");
        assert!(
            output.status.success(),
            "vouch --hook failed: stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("from-configured-socket"),
            "vouch --hook did not query configured [daemon].socket_path; got: {stdout}"
        );

        // 4. Verify VOUCH_DAEMON_SOCKET takes precedence over `[daemon].socket_path`.
        let env_sock = PathBuf::from(format!("/tmp/vd-env-{}.sock", std::process::id()));
        let server2 = spawn_stub_daemon(&env_sock, "from-env-override");

        let bad_cfg = "version = 1\n[tools]\nBash = \"allow\"\n[daemon]\nsocket_path = \"/tmp/definitely-missing-vouch.sock\"\ntimeout_ms = 500\n";
        fs::write(&config_file, bad_cfg).unwrap();
        let mut child2 = std::process::Command::new(env!("CARGO_BIN_EXE_vouch"))
            .arg("--hook")
            .env("HOME", &env.home)
            .env("VOUCH_CONFIG", &config_file)
            .env("VOUCH_STATE_DIR", &env.state_dir)
            .env("VOUCH_DAEMON_SOCKET", &env_sock)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn vouch --hook with VOUCH_DAEMON_SOCKET");
        child2
            .stdin
            .as_mut()
            .unwrap()
            .write_all(hook_payload.as_bytes())
            .unwrap();
        let output2 = child2.wait_with_output().expect("wait vouch --hook env override");
        let accepted2 = server2.join().expect("stub env override server joined");
        let _ = fs::remove_file(&env_sock);
        assert!(accepted2, "stub daemon at VOUCH_DAEMON_SOCKET received no connection");
        assert!(output2.status.success());
        let stdout2 = String::from_utf8_lossy(&output2.stdout);
        assert!(
            stdout2.contains("from-env-override"),
            "VOUCH_DAEMON_SOCKET did not override [daemon].socket_path; got: {stdout2}"
        );

        let _ = fs::remove_file(&custom_sock);
        env.stop();
    }
}
