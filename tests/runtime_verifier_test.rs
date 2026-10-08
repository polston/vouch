use std::path::PathBuf;
use vouch::config::load;
use vouch::runtime::{
    create_verifier, evaluate_trace, EbpfVerifier, FilesystemEvent, NoopVerifier, RuntimeVerifier,
};

fn test_config() -> vouch::config::Config {
    load(
        r#"
version = 1

[write]
allow_paths = ["/tmp/**", "/home/dev/workspace/**"]

[protected]
paths = ["/etc/shadow", "/home/dev/.ssh/**"]

[runtime.linux]
ebpf_tracing = true
ebpf_mode = "audit"
trace_ring_buffer_pages = 64
"#,
    )
    .expect("config parses")
}

#[test]
fn runtime_config_parsing_ebpf_options() {
    let cfg = test_config();
    assert!(cfg.runtime.linux.ebpf_tracing);
    assert_eq!(cfg.runtime.linux.ebpf_mode, "audit");
    assert_eq!(cfg.runtime.linux.trace_ring_buffer_pages, 64);
}

#[test]
fn runtime_policy_allowed_writes_pass() {
    let cfg = test_config();
    let events = vec![
        FilesystemEvent {
            pid: 1234,
            syscall: "openat".into(),
            path: PathBuf::from("/tmp/scratch.txt"),
            is_write: true,
        },
        FilesystemEvent {
            pid: 1234,
            syscall: "openat".into(),
            path: PathBuf::from("/home/dev/workspace/build/out.bin"),
            is_write: true,
        },
    ];

    let trace = evaluate_trace(&events, &cfg);
    assert!(trace.passed);
    assert!(trace.unpermitted_writes.is_empty());
}

#[test]
fn runtime_policy_unpermitted_writes_fail() {
    let cfg = test_config();
    let events = vec![
        FilesystemEvent {
            pid: 1234,
            syscall: "openat".into(),
            path: PathBuf::from("/tmp/scratch.txt"),
            is_write: true,
        },
        FilesystemEvent {
            pid: 1234,
            syscall: "unlinkat".into(),
            path: PathBuf::from("/var/lib/docker/container.pid"),
            is_write: true,
        },
    ];

    let trace = evaluate_trace(&events, &cfg);
    assert!(!trace.passed);
    assert_eq!(trace.unpermitted_writes.len(), 1);
    assert_eq!(trace.unpermitted_writes[0], PathBuf::from("/var/lib/docker/container.pid"));
}

#[test]
fn runtime_policy_protected_paths_fail_even_if_under_allowed() {
    let cfg = load(
        r#"
version = 1
[write]
allow_paths = ["/home/dev/**"]
[protected]
paths = ["/home/dev/.ssh/**"]
"#,
    )
    .expect("config parses");

    let events = vec![FilesystemEvent {
        pid: 1234,
        syscall: "openat".into(),
        path: PathBuf::from("/home/dev/.ssh/id_rsa"),
        is_write: true,
    }];

    let trace = evaluate_trace(&events, &cfg);
    assert!(!trace.passed);
    assert_eq!(trace.unpermitted_writes.len(), 1);
}

#[test]
fn runtime_policy_read_events_are_ignored() {
    let cfg = test_config();
    let events = vec![FilesystemEvent {
        pid: 1234,
        syscall: "openat".into(),
        path: PathBuf::from("/etc/passwd"),
        is_write: false,
    }];

    let trace = evaluate_trace(&events, &cfg);
    assert!(trace.passed);
    assert!(trace.unpermitted_writes.is_empty());
}

#[test]
fn noop_verifier_lifecycle() {
    let noop = NoopVerifier::new("test reason");
    assert!(!noop.is_supported());
    let cfg = test_config();
    let res = noop.monitor_execution(1234, &cfg);
    assert!(res.is_ok());
    let trace = res.unwrap();
    assert!(trace.passed);
}

#[test]
fn ebpf_verifier_mock_execution_monitoring() {
    let cfg = test_config();
    let mock_events = vec![
        FilesystemEvent {
            pid: 4321,
            syscall: "openat".into(),
            path: PathBuf::from("/tmp/allowed.log"),
            is_write: true,
        },
        FilesystemEvent {
            pid: 4321,
            syscall: "openat".into(),
            path: PathBuf::from("/etc/crontab"),
            is_write: true,
        },
    ];

    let verifier = EbpfVerifier::with_mock_events("audit".into(), mock_events);
    assert!(verifier.is_supported());

    let res = verifier.monitor_execution(4321, &cfg);
    assert!(res.is_ok());
    let trace = res.unwrap();
    assert!(!trace.passed);
    assert_eq!(trace.unpermitted_writes.len(), 1);
    assert_eq!(trace.unpermitted_writes[0], PathBuf::from("/etc/crontab"));
}

#[test]
fn create_verifier_factory_returns_active_instance() {
    let cfg = test_config();
    let verifier = create_verifier(&cfg);
    // Factory constructs either EbpfVerifier (on Linux) or NoopVerifier
    let res = verifier.monitor_execution(9999, &cfg);
    assert!(res.is_ok());
}

#[test]
fn tracepoint_decoder_handles_openat_unlinkat_renameat() {
    use vouch::runtime::{RawTraceEvent, TracepointEventDecoder};

    let raw_openat_read = RawTraceEvent {
        pid: 100,
        syscall_nr: 257,
        filename: "/etc/hosts".into(),
        flags: 0o0, // O_RDONLY
        is_write: false,
    };
    let event = TracepointEventDecoder::decode(&raw_openat_read);
    assert_eq!(event.syscall, "openat");
    assert!(!event.is_write);
    assert_eq!(event.path, PathBuf::from("/etc/hosts"));

    let raw_openat_write = RawTraceEvent {
        pid: 100,
        syscall_nr: 257,
        filename: "/tmp/out.txt".into(),
        flags: 0o101, // O_CREAT | O_WRONLY
        is_write: false,
    };
    let event = TracepointEventDecoder::decode(&raw_openat_write);
    assert_eq!(event.syscall, "openat");
    assert!(event.is_write);
    assert_eq!(event.path, PathBuf::from("/tmp/out.txt"));

    let raw_unlinkat = RawTraceEvent {
        pid: 101,
        syscall_nr: 263,
        filename: "/tmp/stale.lock".into(),
        flags: 0,
        is_write: false,
    };
    let event = TracepointEventDecoder::decode(&raw_unlinkat);
    assert_eq!(event.syscall, "unlinkat");
    assert!(event.is_write);

    let raw_renameat = RawTraceEvent {
        pid: 102,
        syscall_nr: 264,
        filename: "/tmp/new.txt".into(),
        flags: 0,
        is_write: false,
    };
    let event = TracepointEventDecoder::decode(&raw_renameat);
    assert_eq!(event.syscall, "renameat");
    assert!(event.is_write);
}

#[test]
fn ebpf_verifier_with_mock_ring_buffer_reader() {
    use vouch::runtime::{MockRingBufferReader, RawTraceEvent, RingBufferReader};

    let cfg = test_config();
    let mut reader = MockRingBufferReader::new();
    reader.add_event(RawTraceEvent {
        pid: 5555,
        syscall_nr: 257,
        filename: "/tmp/allowed.log".into(),
        flags: 0o1,
        is_write: true,
    });
    reader.add_event(RawTraceEvent {
        pid: 5555,
        syscall_nr: 263,
        filename: "/var/log/system.log".into(),
        flags: 0,
        is_write: true,
    });
    reader.simulate_dropped(3);
    assert_eq!(reader.dropped_events(), 3);

    let verifier = EbpfVerifier::with_reader("audit".into(), Box::new(reader));
    assert!(verifier.is_supported());

    let res = verifier.monitor_execution(5555, &cfg);
    assert!(res.is_ok());
    let trace = res.unwrap();
    assert!(!trace.passed);
    assert_eq!(trace.unpermitted_writes.len(), 1);
    assert_eq!(trace.unpermitted_writes[0], PathBuf::from("/var/log/system.log"));
}

#[test]
fn zero_copy_ebpf_config_parsing() {
    let cfg = load(
        r#"
version = 1
[runtime.linux]
ebpf_tracing = true
zero_copy = true
[runtime.ebpf]
zero_copy = true
buffer_page_count = 128
"#,
    )
    .expect("config parses");

    assert!(cfg.runtime.linux.zero_copy);
    assert!(cfg.runtime.ebpf.zero_copy);
    assert_eq!(cfg.runtime.ebpf.buffer_page_count, 128);
}

#[test]
fn zero_copy_trace_decoder_handles_slices() {
    use vouch::runtime::ZeroCopyTraceDecoder;

    let mut buf = Vec::new();
    ZeroCopyTraceDecoder::encode_record(1001, 257, 0o1, false, "/tmp/zero_copy.txt", &mut buf);
    ZeroCopyTraceDecoder::encode_record(1002, 263, 0, false, "/etc/unpermitted.conf", &mut buf);

    let (ev1, consumed1) = ZeroCopyTraceDecoder::decode_slice(&buf).expect("ev1 decodes");
    assert_eq!(ev1.pid, 1001);
    assert_eq!(ev1.syscall_nr, 257);
    assert_eq!(ev1.filename, "/tmp/zero_copy.txt");
    assert!(ev1.is_write);
    assert_eq!(consumed1, 17 + "/tmp/zero_copy.txt".len() + 1);

    let (ev2, consumed2) = ZeroCopyTraceDecoder::decode_slice(&buf[consumed1..]).expect("ev2 decodes");
    assert_eq!(ev2.pid, 1002);
    assert_eq!(ev2.syscall_nr, 263);
    assert_eq!(ev2.filename, "/etc/unpermitted.conf");
    assert!(ev2.is_write);
    assert_eq!(consumed2, 17 + "/etc/unpermitted.conf".len() + 1);
}

#[test]
fn zero_copy_trace_decoder_fails_closed_on_corrupt_slices() {
    use vouch::runtime::ZeroCopyTraceDecoder;

    let short_slice = [0u8; 10]; // Less than MIN_RECORD_LEN (17)
    let res = ZeroCopyTraceDecoder::decode_slice(&short_slice);
    assert!(res.is_err());

    let invalid_utf8_slice = [
        1, 0, 0, 0, // pid: 1
        1, 1, 0, 0, 0, 0, 0, 0, // syscall: 257
        1, 0, 0, 0, // flags: 1
        1,    // explicit_write: 1
        0xff, 0xff, 0, // invalid utf8 followed by NUL
    ];
    let res = ZeroCopyTraceDecoder::decode_slice(&invalid_utf8_slice);
    assert!(res.is_err());
}

#[test]
fn ebpf_verifier_with_mock_zero_copy_reader() {
    use vouch::runtime::{MockZeroCopyReader, ZeroCopyRingBufferReader};

    let cfg = test_config();
    let mut reader = MockZeroCopyReader::new();
    reader.add_record(7777, 257, 0o1, true, "/tmp/allowed_zero_copy.txt");
    reader.add_record(7777, 263, 0, true, "/etc/shadow");
    reader.simulate_dropped(5);
    assert_eq!(reader.dropped_events(), 5);

    let verifier = EbpfVerifier::with_zero_copy_reader("audit".into(), Box::new(reader));
    assert!(verifier.is_supported());

    let res = verifier.monitor_execution(7777, &cfg);
    assert!(res.is_ok());
    let trace = res.unwrap();
    assert!(!trace.passed);
    assert_eq!(trace.unpermitted_writes.len(), 1);
    assert_eq!(trace.unpermitted_writes[0], PathBuf::from("/etc/shadow"));
}

#[test]
fn zero_copy_batch_simulation_and_policy_evaluation() {
    use vouch::runtime::{evaluate_trace_zero_copy, MockZeroCopyReader, ZeroCopyRingBufferReader};

    let cfg = test_config();
    let mut reader = MockZeroCopyReader::new();

    for i in 0..100 {
        reader.add_record(9000, 257, 0o1, true, &format!("/tmp/file_{i}.tmp"));
    }
    // Add one unpermitted write
    reader.add_record(9000, 257, 0o1, true, "/var/run/unpermitted.pid");

    let mut unpermitted_count = 0;
    let mut unpermitted_paths = Vec::new();
    let count = reader
        .consume_events(&mut |ev| {
            if !vouch::runtime::evaluate_event_borrowed(&ev, &cfg) {
                unpermitted_count += 1;
                unpermitted_paths.push(PathBuf::from(ev.filename));
            }
            Ok(())
        })
        .expect("events consumed");

    assert_eq!(count, 101);
    assert_eq!(unpermitted_count, 1);
    assert_eq!(unpermitted_paths, vec![PathBuf::from("/var/run/unpermitted.pid")]);

    // Also test evaluate_trace_zero_copy over slice-decoded events
    let mut raw_buf = Vec::new();
    vouch::runtime::ZeroCopyTraceDecoder::encode_record(9001, 257, 0o1, true, "/tmp/allowed.log", &mut raw_buf);
    vouch::runtime::ZeroCopyTraceDecoder::encode_record(9001, 257, 0o1, true, "/etc/shadow", &mut raw_buf);

    let (ev1, c1) = vouch::runtime::ZeroCopyTraceDecoder::decode_slice(&raw_buf).unwrap();
    let (ev2, _) = vouch::runtime::ZeroCopyTraceDecoder::decode_slice(&raw_buf[c1..]).unwrap();
    let trace = evaluate_trace_zero_copy(vec![ev1, ev2], &cfg);
    assert!(!trace.passed);
    assert_eq!(trace.unpermitted_writes.len(), 1);
    assert_eq!(trace.unpermitted_writes[0], PathBuf::from("/etc/shadow"));
}
