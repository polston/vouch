//! Concurrency & Multi-Tenant Isolation Tests for Daemon Streaming IPC (Goal 5).

#[cfg(unix)]
mod concurrency_tests {
    use std::fs;
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};

    use vouch::daemon::protocol::DaemonFrame;
    use vouch::daemon::{
        run_daemon_server, try_query_daemon, DaemonRequest, StreamingClient,
    };

    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

    struct TestEnv {
        root: PathBuf,
        socket_path: PathBuf,
        home: PathBuf,
        shutdown: Arc<AtomicBool>,
        server_handle: Option<thread::JoinHandle<Result<(), String>>>,
    }

    impl TestEnv {
        fn new(_name: &str) -> Self {
            let pid = std::process::id();
            let c = COUNTER.fetch_add(1, Ordering::Relaxed);
            let nonce = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let root = std::env::temp_dir().join(format!("vouch-conc-{pid}-{c}-{nonce}"));
            let home = root.join("home");
            let socket_path = PathBuf::from(format!("/tmp/vcd-{pid}-{c}.sock"));

            fs::create_dir_all(&home.join(".config/vouch")).unwrap();

            let config_toml = r#"
version = 1
[tools]
Bash = "allow"
"#;
            fs::write(home.join(".config/vouch/config.toml"), config_toml).unwrap();

            Self {
                root,
                socket_path,
                home,
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

            // Wait for socket to bind
            let deadline = Instant::now() + Duration::from_millis(2500);
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
    fn streaming_handshake_and_ack() {
        let mut env = TestEnv::new("handshake");
        env.start_server();

        let client = StreamingClient::connect(
            &env.socket_path,
            "subagent-1",
            "tok-123",
            PathBuf::from("/workspace/a"),
            None,
        );
        assert!(client.is_ok(), "streaming client handshake must succeed: {:?}", client.err());
        let c = client.unwrap();
        assert_eq!(c.session.agent_id, "subagent-1");
        assert_eq!(c.session.session_token, "tok-123");
        assert_eq!(c.session.cwd, PathBuf::from("/workspace/a"));

        env.stop();
    }

    #[test]
    fn streaming_heartbeat_and_pong() {
        let mut env = TestEnv::new("heartbeat");
        env.start_server();

        let mut client = StreamingClient::connect(
            &env.socket_path,
            "subagent-probe",
            "tok-probe",
            PathBuf::from("/workspace/probe"),
            None,
        )
        .unwrap();

        assert!(client.heartbeat().is_ok(), "heartbeat probe must return Ok(Pong)");
        env.stop();
    }

    #[test]
    fn streaming_evaluation_and_decision() {
        let mut env = TestEnv::new("eval");
        env.start_server();

        let mut client = StreamingClient::connect(
            &env.socket_path,
            "subagent-eval",
            "tok-eval",
            PathBuf::from("/workspace/eval"),
            None,
        )
        .unwrap();

        let raw_hook = r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git status"}}"#;
        let resp = client.evaluate(42, raw_hook).expect("evaluation must succeed");

        match resp {
            DaemonFrame::Decision {
                request_id,
                verdict,
                latency_us,
                output,
            } => {
                assert_eq!(request_id, 42);
                assert_eq!(verdict, "allow");
                assert!(output.is_some());
                assert!(latency_us > 0, "latency must be recorded");
            }
            other => panic!("expected DaemonFrame::Decision, got {other:?}"),
        }

        env.stop();
    }

    #[test]
    fn streaming_cancellation_request() {
        let mut env = TestEnv::new("cancel");
        env.start_server();

        let mut client = StreamingClient::connect(
            &env.socket_path,
            "subagent-cancel",
            "tok-cancel",
            PathBuf::from("/workspace/cancel"),
            None,
        )
        .unwrap();

        assert!(client.cancel(99).is_ok());
        env.stop();
    }

    #[test]
    fn streaming_session_cwd_isolation() {
        let mut env = TestEnv::new("isolation");
        env.start_server();

        let ws_a = env.root.join("ws-a");
        let ws_b = env.root.join("ws-b");
        fs::create_dir_all(&ws_a).unwrap();
        fs::create_dir_all(&ws_b).unwrap();

        let mut client_a = StreamingClient::connect(
            &env.socket_path,
            "agent-alpha",
            "tok-alpha",
            ws_a.clone(),
            None,
        )
        .unwrap();

        let mut client_b = StreamingClient::connect(
            &env.socket_path,
            "agent-beta",
            "tok-beta",
            ws_b.clone(),
            None,
        )
        .unwrap();

        assert_eq!(client_a.session.cwd, ws_a);
        assert_eq!(client_b.session.cwd, ws_b);

        // Verify independent evaluations
        let raw = r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git status"}}"#;
        let resp_a = client_a.evaluate(1, raw).unwrap();
        let resp_b = client_b.evaluate(2, raw).unwrap();

        match (resp_a, resp_b) {
            (DaemonFrame::Decision { request_id: id_a, .. }, DaemonFrame::Decision { request_id: id_b, .. }) => {
                assert_eq!(id_a, 1);
                assert_eq!(id_b, 2);
            }
            other => panic!("unexpected frames: {other:?}"),
        }

        env.stop();
    }

    #[test]
    fn streaming_multi_client_concurrent_load() {
        let mut env = TestEnv::new("concurrency");
        env.start_server();

        let client_count = 25;
        let mut handles = Vec::new();

        let start = Instant::now();

        for i in 0..client_count {
            let socket_path = env.socket_path.clone();
            let handle = thread::spawn(move || {
                let ws = PathBuf::from(format!("/workspace/subagent-{}", i));
                let mut client = StreamingClient::connect(
                    &socket_path,
                    &format!("agent-{}", i),
                    &format!("tok-{}", i),
                    ws,
                    None,
                )
                .expect("client must connect successfully");

                for req_id in 0..5 {
                    let raw = format!(
                        r#"{{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{{"command":"echo test-{}-{}"}}}}"#,
                        i, req_id
                    );
                    let resp = client.evaluate(req_id as u64, &raw).expect("evaluate must succeed");
                    match resp {
                        DaemonFrame::Decision { request_id, .. } => {
                            assert_eq!(request_id, req_id as u64);
                        }
                        other => panic!("thread {i} got unexpected response: {other:?}"),
                    }
                }
            });
            handles.push(handle);
        }

        for h in handles {
            h.join().expect("client worker thread must succeed without panic");
        }

        let elapsed = start.elapsed();
        println!(
            "Executed {} concurrent subagent sessions (125 evaluations total) in {:?}",
            client_count, elapsed
        );

        env.stop();
    }

    #[test]
    fn streaming_mixed_legacy_and_streaming_clients() {
        let mut env = TestEnv::new("mixed");
        env.start_server();

        // 1. Streaming client
        let mut stream_client = StreamingClient::connect(
            &env.socket_path,
            "streaming-agent",
            "tok-stream",
            PathBuf::from("/workspace/stream"),
            None,
        )
        .unwrap();

        // 2. Legacy client single-shot query
        let legacy_req = DaemonRequest {
            raw: r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git status"}}"#.into(),
            notice: None,
            host: "claude".into(),
            shadow: false,
            state_dir: env.root.join("state").to_str().unwrap().into(),
            home_dir: env.home.to_str().unwrap().into(),
        };

        let legacy_resp = try_query_daemon(&env.socket_path, &legacy_req, 500)
            .expect("legacy query on mixed daemon must succeed");
        assert!(legacy_resp.from_daemon);

        // 3. Streaming query on active session
        let raw = r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git status"}}"#;
        let stream_resp = stream_client.evaluate(101, raw).unwrap();
        match stream_resp {
            DaemonFrame::Decision { request_id, verdict, .. } => {
                assert_eq!(request_id, 101);
                assert_eq!(verdict, "allow");
            }
            other => panic!("expected Decision, got {other:?}"),
        }

        env.stop();
    }
}
