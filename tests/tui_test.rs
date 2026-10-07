use vouch::journal::Record;
use vouch::outcome::Outcome;
use vouch::tui::backend::{KeyCode, MockTerminalBackend, TerminalEvent};
use vouch::tui::{AppStatus, TuiApp, TuiEngine};

fn sample_records() -> Vec<Record> {
    vec![
        Record {
            id: "1".into(),
            ts: "2026-10-02T12:00:00Z".into(),
            cmd: "touch /tmp/test.txt".into(),
            verdict: "allow".into(),
            reason: "allowed by vouch policy".into(),
            mode: "live".into(),
            outcome: Outcome::Executed,
            session: "sess-1".into(),
            lang: "bash".into(),
            cwd: "/home/dev".into(),
            tool: "bash".into(),
            permission_mode: "".into(),
            measurement: false,
            host: "claude".into(),
            count: 1,
        },
        Record {
            id: "2".into(),
            ts: "2026-10-02T12:01:00Z".into(),
            cmd: "eval 'echo hello'".into(),
            verdict: "ask".into(),
            reason: "vouch stopped on: evaluated_input\n  to allow this permanently: [lang.bash.constructs] evaluated_input = \"allow\"".into(),
            mode: "live".into(),
            outcome: Outcome::Executed,
            session: "sess-1".into(),
            lang: "bash".into(),
            cwd: "/home/dev".into(),
            tool: "bash".into(),
            permission_mode: "".into(),
            measurement: false,
            host: "claude".into(),
            count: 1,
        },
        Record {
            id: "3".into(),
            ts: "2026-10-02T12:02:00Z".into(),
            cmd: "rm -rf /".into(),
            verdict: "ask".into(),
            reason: "vouch stopped on: delete_recursive (guard)\n  what that means: recursively deletes directory trees".into(),
            mode: "live".into(),
            outcome: Outcome::Denied,
            session: "sess-2".into(),
            lang: "bash".into(),
            cwd: "/home/dev".into(),
            tool: "bash".into(),
            permission_mode: "".into(),
            measurement: false,
            host: "claude".into(),
            count: 1,
        },
        Record {
            id: "4".into(),
            ts: "2026-10-02T12:03:00Z".into(),
            cmd: "touch /var/log/custom.log".into(),
            verdict: "ask".into(),
            reason: "vouch stopped on: path outside every allowed area\n  /var/log/custom.log\n  to allow this permanently: write.allow_paths = [\"/var/log/custom.log\"]".into(),
            mode: "live".into(),
            outcome: Outcome::Executed,
            session: "sess-3".into(),
            lang: "bash".into(),
            cwd: "/home/dev".into(),
            tool: "bash".into(),
            permission_mode: "".into(),
            measurement: false,
            host: "claude".into(),
            count: 1,
        },
    ]
}

#[test]
fn tui_engine_extracts_decisions_and_candidates() {
    let records = sample_records();
    let engine = TuiEngine::from_records("/tmp", &records);

    // Should index 4 decisions
    assert_eq!(engine.decisions.len(), 4);
    assert_eq!(engine.decisions[0].cmd, "touch /var/log/custom.log"); // most recent first

    // Candidates should include evaluated_input, path candidate, and delete_recursive (guarded)
    assert!(engine.candidates.iter().any(|c| c.name == "evaluated_input" && c.proposable));
    assert!(engine.candidates.iter().any(|c| c.name == "path: /var/log/custom.log" && c.proposable));

    // Guard must be non-proposable
    let guard_cand = engine.candidates.iter().find(|c| c.name == "delete_recursive").expect("guard exists");
    assert!(!guard_cand.proposable);
    assert!(guard_cand.blocked_reason.is_some());
}

#[test]
fn tui_app_tab_switching_and_navigation() {
    let records = sample_records();
    let engine = TuiEngine::from_records("/tmp", &records);
    let mut app = TuiApp::new(engine);

    assert_eq!(app.active_tab, vouch::tui::app::ViewTab::Candidates);
    assert_eq!(app.selected_idx, 0);

    // Down navigation
    let status = app.handle_event(TerminalEvent::Key(KeyCode::Down));
    assert_eq!(status, AppStatus::Running);
    assert_eq!(app.selected_idx, 1);

    // Up navigation
    let status = app.handle_event(TerminalEvent::Key(KeyCode::Up));
    assert_eq!(status, AppStatus::Running);
    assert_eq!(app.selected_idx, 0);

    // Switch to Decisions tab via Tab
    let status = app.handle_event(TerminalEvent::Key(KeyCode::Tab));
    assert_eq!(status, AppStatus::Running);
    assert_eq!(app.active_tab, vouch::tui::app::ViewTab::Decisions);
    assert_eq!(app.selected_idx, 0);

    // Tab back to Candidates
    app.handle_event(TerminalEvent::Key(KeyCode::Tab));
    assert_eq!(app.active_tab, vouch::tui::app::ViewTab::Candidates);
}

#[test]
fn tui_preview_toggle() {
    let records = sample_records();
    let engine = TuiEngine::from_records("/tmp", &records);
    let mut app = TuiApp::new(engine);

    assert!(!app.show_preview);
    app.handle_event(TerminalEvent::Key(KeyCode::Char('p')));
    assert!(app.show_preview);

    let frame = app.render();
    assert!(frame.contains("--- Proposed TOML Delta ---"));

    app.handle_event(TerminalEvent::Key(KeyCode::Char('p')));
    assert!(!app.show_preview);
}

#[test]
fn tui_guard_refuses_standing_rule_approval() {
    let records = sample_records();
    let engine = TuiEngine::from_records("/tmp", &records);
    let mut app = TuiApp::new(engine);

    // Select the guard candidate
    let guard_pos = app.engine.candidates.iter().position(|c| c.name == "delete_recursive").expect("guard present");
    app.selected_idx = guard_pos;

    // Attempt to accept with 'a'
    app.handle_event(TerminalEvent::Key(KeyCode::Char('a')));
    assert!(app.status_message.contains("Refused: this is a guard"));
}

#[test]
fn tui_headless_event_loop_execution() {
    let records = sample_records();
    let engine = TuiEngine::from_records("/tmp", &records);
    let mut app = TuiApp::new(engine);

    let events = vec![
        TerminalEvent::Key(KeyCode::Down),
        TerminalEvent::Key(KeyCode::Char('p')),
        TerminalEvent::Key(KeyCode::Tab),
        TerminalEvent::Key(KeyCode::Char('q')),
    ];

    let backend = MockTerminalBackend::new(80, 24, events);
    let res = app.run_loop(backend);
    assert!(res.is_ok());
}

#[test]
fn tui_empty_records_handling() {
    let engine = TuiEngine::from_records("/tmp", &[]);
    assert_eq!(engine.decisions.len(), 0);
    assert_eq!(engine.candidates.len(), 0);

    let app = TuiApp::new(engine);
    let frame = app.render();
    assert!(frame.contains("No rule candidates available"));
}

#[test]
fn tui_apply_candidate_to_config() {
    let tag = format!("tui_test_{}_{}", std::process::id(), line!());
    let tmp_path = std::env::temp_dir().join(tag);
    let _ = std::fs::remove_dir_all(&tmp_path);
    let home = tmp_path.to_str().unwrap();
    let config_dir = tmp_path.join(".config").join("vouch");
    std::fs::create_dir_all(&config_dir).unwrap();
    let config_file = config_dir.join("config.toml");
    std::fs::write(&config_file, "[lang.bash.constructs]\n").unwrap();

    let records = sample_records();
    let engine = TuiEngine::from_records(home, &records);

    let cand = engine.candidates.iter().find(|c| c.name == "evaluated_input").unwrap();
    let res = engine.apply_candidate(cand);
    assert!(res.is_ok());

    let updated_text = std::fs::read_to_string(&config_file).unwrap();
    assert!(updated_text.contains("evaluated_input = \"allow\""));
}

#[test]
fn tui_apply_allow_path_candidate_to_config() {
    let tag = format!("tui_test_{}_{}", std::process::id(), line!());
    let tmp_path = std::env::temp_dir().join(tag);
    let _ = std::fs::remove_dir_all(&tmp_path);
    let home = tmp_path.to_str().unwrap();
    let config_dir = tmp_path.join(".config").join("vouch");
    std::fs::create_dir_all(&config_dir).unwrap();
    let config_file = config_dir.join("config.toml");
    std::fs::write(&config_file, "[write]\nallow_paths = [\"/tmp/**\"]\n").unwrap();

    let records = sample_records();
    let engine = TuiEngine::from_records(home, &records);

    let cand = engine.candidates.iter().find(|c| c.name == "path: /var/log/custom.log").unwrap();
    let res = engine.apply_candidate(cand);
    assert!(res.is_ok());

    let updated_text = std::fs::read_to_string(&config_file).unwrap();
    assert!(updated_text.contains("/var/log/custom.log"));
    assert!(updated_text.contains("/tmp/**")); // existing path preserved
}

#[test]
fn tui_app_apply_current_candidate_removes_from_list() {
    let tag = format!("tui_test_{}_{}", std::process::id(), line!());
    let tmp_path = std::env::temp_dir().join(tag);
    let _ = std::fs::remove_dir_all(&tmp_path);
    let home = tmp_path.to_str().unwrap();
    let config_dir = tmp_path.join(".config").join("vouch");
    std::fs::create_dir_all(&config_dir).unwrap();
    let config_file = config_dir.join("config.toml");
    std::fs::write(&config_file, "version = 1\n").unwrap();

    let records = sample_records();
    let engine = TuiEngine::from_records(home, &records);
    let mut app = TuiApp::new(engine);

    let initial_count = app.engine.candidates.len();
    assert!(initial_count > 0);

    // Ensure selected is a proposable candidate
    let prop_idx = app.engine.candidates.iter().position(|c| c.proposable).unwrap();
    app.selected_idx = prop_idx;

    app.handle_event(TerminalEvent::Key(KeyCode::Char('a')));
    assert!(app.status_message.starts_with("✓"));
    assert_eq!(app.engine.candidates.len(), initial_count - 1);
}

#[test]
fn tui_backend_decode_key_bytes_sequences() {
    use vouch::tui::backend::decode_key_bytes;

    // Single ASCII char
    let (ev, len) = decode_key_bytes(b"q").expect("decodes q");
    assert_eq!(ev, TerminalEvent::Key(KeyCode::Char('q')));
    assert_eq!(len, 1);

    // Enter
    let (ev, len) = decode_key_bytes(b"\r").expect("decodes CR");
    assert_eq!(ev, TerminalEvent::Key(KeyCode::Enter));
    assert_eq!(len, 1);

    let (ev, len) = decode_key_bytes(b"\n").expect("decodes LF");
    assert_eq!(ev, TerminalEvent::Key(KeyCode::Enter));
    assert_eq!(len, 1);

    // Tab and Backspace
    let (ev, len) = decode_key_bytes(b"\t").expect("decodes tab");
    assert_eq!(ev, TerminalEvent::Key(KeyCode::Tab));
    assert_eq!(len, 1);

    let (ev, len) = decode_key_bytes(&[0x7f]).expect("decodes backspace");
    assert_eq!(ev, TerminalEvent::Key(KeyCode::Backspace));
    assert_eq!(len, 1);

    // Arrows
    let (ev, len) = decode_key_bytes(b"\x1b[A").expect("decodes Up");
    assert_eq!(ev, TerminalEvent::Key(KeyCode::Up));
    assert_eq!(len, 3);

    let (ev, len) = decode_key_bytes(b"\x1b[B").expect("decodes Down");
    assert_eq!(ev, TerminalEvent::Key(KeyCode::Down));
    assert_eq!(len, 3);

    let (ev, len) = decode_key_bytes(b"\x1b[C").expect("decodes Right");
    assert_eq!(ev, TerminalEvent::Key(KeyCode::Right));
    assert_eq!(len, 3);

    let (ev, len) = decode_key_bytes(b"\x1b[D").expect("decodes Left");
    assert_eq!(ev, TerminalEvent::Key(KeyCode::Left));
    assert_eq!(len, 3);

    // Standalone Escape
    let (ev, len) = decode_key_bytes(b"\x1b").expect("decodes Escape");
    assert_eq!(ev, TerminalEvent::Key(KeyCode::Escape));
    assert_eq!(len, 1);

    // Empty input returns None
    assert!(decode_key_bytes(b"").is_none());
}

#[test]
fn tui_backend_raw_mode_guard_lifecycle() {
    use vouch::tui::backend::RawModeGuard;

    // Acquire guard (safe even in test runner without TTY)
    let mut guard = RawModeGuard::acquire().expect("acquire raw mode guard succeeds");
    guard.restore();
    // Double restore should be safe and idempotent
    guard.restore();
}
