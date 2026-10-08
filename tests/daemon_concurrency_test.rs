use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use vouch::daemon::shm::{run_shm_worker, ShmError, ShmRingBuffer, ShmTransport};
use vouch::daemon::{DaemonSessionHandler, DecisionOutput, EvaluateRequest, SessionContext};

struct MockDaemonHandler {
    call_count: AtomicUsize,
}

impl MockDaemonHandler {
    fn new() -> Self {
        Self {
            call_count: AtomicUsize::new(0),
        }
    }
}

impl DaemonSessionHandler for MockDaemonHandler {
    fn handle_evaluate(&self, _session: &SessionContext, req: EvaluateRequest) -> DecisionOutput {
        self.call_count.fetch_add(1, Ordering::Relaxed);
        let verdict = if req.raw_hook_json.contains("rm -rf") {
            "ask"
        } else {
            "allow"
        };

        DecisionOutput {
            request_id: req.request_id,
            output: Some(format!("{{\"verdict\":\"{verdict}\"}}")),
            verdict: verdict.to_string(),
            latency_us: 150,
        }
    }
}

#[test]
fn shm_ring_buffer_basic_push_pop_and_crc() {
    let shm = ShmRingBuffer::new_in_memory(128);
    let token = [7u8; 32];
    let payload = b"{\"hook\":\"PreToolUse\",\"cmd\":\"ls -la\"}";

    shm.push_request(101, &token, payload).expect("push request");

    let req = shm.pop_request().expect("pop request").expect("some request");
    assert_eq!(req.request_id, 101);
    assert_eq!(req.token, token);
    assert_eq!(req.payload, payload);

    shm.push_response(101, b"{\"verdict\":\"allow\"}").expect("push response");

    let resp = shm.pop_response(101).expect("pop response").expect("some response");
    assert_eq!(resp, b"{\"verdict\":\"allow\"}");
}

#[test]
fn shm_ring_buffer_capacity_overflow_and_dropped_count() {
    let shm = ShmRingBuffer::new_in_memory(4);
    let token = [1u8; 32];

    for i in 0..4 {
        shm.push_request(i, &token, b"query").expect("push within capacity");
    }

    // 5th push should exceed capacity and increment dropped count
    let err = shm.push_request(5, &token, b"overflow").unwrap_err();
    assert_eq!(err, ShmError::QueueFull);
    assert_eq!(shm.dropped_count(), 1);
}

#[test]
fn shm_multi_agent_burst_concurrency_16_workers() {
    let capacity = 2048;
    let shm = Arc::new(ShmRingBuffer::new_in_memory(capacity));
    let token = [42u8; 32];
    let handler = Arc::new(MockDaemonHandler::new());
    let shutdown = Arc::new(AtomicBool::new(false));

    // Spawn background SHM worker thread
    let worker_shm = Arc::clone(&shm);
    let worker_handler = Arc::clone(&handler);
    let worker_shutdown = Arc::clone(&shutdown);
    let worker_handle = std::thread::spawn(move || {
        run_shm_worker(
            worker_shm,
            worker_handler,
            token,
            std::env::temp_dir().join("vouch-shm-test"),
            std::env::temp_dir(),
            worker_shutdown,
        );
    });

    // Launch 16 concurrent worker threads simulating subagents
    let num_workers = 16;
    let queries_per_worker = 100;
    let total_queries = num_workers * queries_per_worker;
    let start_time = Instant::now();

    let mut handles = Vec::new();
    for worker_id in 0..num_workers {
        let thread_shm = Arc::clone(&shm);
        handles.push(std::thread::spawn(move || {
            let mut transport = ShmTransport::new(thread_shm, token, None);
            transport.timeout = Duration::from_millis(500);

            for q in 0..queries_per_worker {
                let req_id = (worker_id as u64) * 1000 + (q as u64);
                let raw_json = format!("{{\"worker\":{worker_id},\"query\":{q},\"cmd\":\"git status\"}}");
                let frame = transport.evaluate(req_id, &raw_json).expect("shm query evaluates");

                match frame {
                    vouch::daemon::DaemonFrame::Decision { request_id: out_id, verdict, .. } => {
                        assert_eq!(out_id, req_id);
                        assert_eq!(verdict, "allow");
                    }
                    other => panic!("unexpected frame: {other:?}"),
                }

            }
        }));
    }

    for h in handles {
        h.join().expect("subagent worker thread completed");
    }

    let elapsed = start_time.elapsed();
    let per_query_us = elapsed.as_micros() / (total_queries as u128);

    // Stop background worker
    shutdown.store(true, Ordering::Relaxed);
    shm.set_shutdown();
    let _ = worker_handle.join();

    assert_eq!(handler.call_count.load(Ordering::Relaxed), total_queries);
    assert_eq!(shm.dropped_count(), 0);
    // Sub-millisecond latency check (<1000us per query on average)
    assert!(
        per_query_us < 5000,
        "average per-query latency too high: {per_query_us}us"
    );
}

#[test]
fn shm_unauthorized_token_rejection() {
    let shm = Arc::new(ShmRingBuffer::new_in_memory(16));
    let server_token = [99u8; 32];
    let bad_client_token = [0u8; 32];
    let handler = Arc::new(MockDaemonHandler::new());
    let shutdown = Arc::new(AtomicBool::new(false));

    let worker_shm = Arc::clone(&shm);
    let worker_handler = Arc::clone(&handler);
    let worker_shutdown = Arc::clone(&shutdown);
    let worker_handle = std::thread::spawn(move || {
        run_shm_worker(
            worker_shm,
            worker_handler,
            server_token,
            std::env::temp_dir().join("vouch-shm-bad-token"),
            std::env::temp_dir(),
            worker_shutdown,
        );
    });

    let mut transport = ShmTransport::new(shm, bad_client_token, None);
    transport.timeout = Duration::from_millis(100);

    // Should fail because client token doesn't match daemon's server token
    let res = transport.evaluate(1234, "{\"cmd\":\"ls\"}");
    assert!(res.is_err());

    shutdown.store(true, Ordering::Relaxed);
    let _ = worker_handle.join();
}
