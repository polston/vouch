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

#[test]
fn tui_journal_tail_reader_streaming() {
    use std::io::Write;
    use vouch::tui::JournalTailReader;

    let tmp_dir = std::env::temp_dir().join(format!("vouch_tui_test_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&tmp_dir);
    let log_file = tmp_dir.join("journal.jsonl");

    let r1 = Record {
        id: "101".into(),
        ts: "2026-10-08T12:00:00Z".into(),
        cmd: "ls -la".into(),
        verdict: "allow".into(),
        reason: "safe".into(),
        mode: "live".into(),
        outcome: Outcome::Executed,
        session: "s1".into(),
        lang: "bash".into(),
        cwd: "/home/dev".into(),
        tool: "bash".into(),
        permission_mode: "".into(),
        measurement: false,
        host: "claude".into(),
        count: 1,
    };

    let mut f = std::fs::File::create(&log_file).unwrap();
    writeln!(f, "{}", serde_json::to_string(&r1).unwrap()).unwrap();
    drop(f);

    let mut reader = JournalTailReader::from_start(&log_file);
    let recs = reader.poll_new_records();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].cmd, "ls -la");

    // Second poll with no new data
    let recs2 = reader.poll_new_records();
    assert_eq!(recs2.len(), 0);

    // Append second record
    let r2 = Record {
        id: "102".into(),
        ts: "2026-10-08T12:01:00Z".into(),
        cmd: "cargo build".into(),
        verdict: "allow".into(),
        reason: "safe build".into(),
        mode: "live".into(),
        outcome: Outcome::Executed,
        session: "s1".into(),
        lang: "bash".into(),
        cwd: "/home/dev".into(),
        tool: "bash".into(),
        permission_mode: "".into(),
        measurement: false,
        host: "claude".into(),
        count: 1,
    };
    let mut f2 = std::fs::OpenOptions::new().append(true).open(&log_file).unwrap();
    writeln!(f2, "{}", serde_json::to_string(&r2).unwrap()).unwrap();
    drop(f2);

    let recs3 = reader.poll_new_records();
    assert_eq!(recs3.len(), 1);
    assert_eq!(recs3[0].cmd, "cargo build");

    let _ = std::fs::remove_dir_all(&tmp_dir);
}

#[test]
fn tui_engine_live_stream_poll_events() {
    use std::io::Write;
    use vouch::tui::JournalTailReader;

    let tmp_dir = std::env::temp_dir().join(format!("vouch_tui_engine_test_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&tmp_dir);
    let log_file = tmp_dir.join("journal.jsonl");

    let _ = std::fs::File::create(&log_file).unwrap();

    let mut engine = TuiEngine::from_records("/tmp", &[]);
    assert_eq!(engine.decisions.len(), 0);

    let reader = JournalTailReader::from_start(&log_file);
    engine = engine.with_tail_reader(reader);

    let rec = Record {
        id: "201".into(),
        ts: "2026-10-08T12:00:00Z".into(),
        cmd: "git status".into(),
        verdict: "allow".into(),
        reason: "clean".into(),
        mode: "live".into(),
        outcome: Outcome::Executed,
        session: "s2".into(),
        lang: "bash".into(),
        cwd: "/home/dev".into(),
        tool: "bash".into(),
        permission_mode: "".into(),
        measurement: false,
        host: "claude".into(),
        count: 1,
    };

    let mut f = std::fs::OpenOptions::new().append(true).open(&log_file).unwrap();
    writeln!(f, "{}", serde_json::to_string(&rec).unwrap()).unwrap();
    drop(f);

    let ingested = engine.poll_live_events();
    assert_eq!(ingested, 1);
    assert_eq!(engine.decisions.len(), 1);
    assert_eq!(engine.decisions[0].cmd, "git status");

    let _ = std::fs::remove_dir_all(&tmp_dir);
}

#[test]
fn tui_search_mode_interactive_filtering() {
    let records = sample_records();
    let engine = TuiEngine::from_records("/tmp", &records);
    let mut app = TuiApp::new(engine);

    // Switch to Decisions tab and enter search mode via '/'
    app.handle_event(TerminalEvent::Key(KeyCode::Char('/')));
    assert!(app.search_mode);
    assert_eq!(app.active_tab, vouch::tui::ViewTab::Decisions);

    // Type 'e', 'v', 'a', 'l'
    app.handle_event(TerminalEvent::Key(KeyCode::Char('e')));
    app.handle_event(TerminalEvent::Key(KeyCode::Char('v')));
    app.handle_event(TerminalEvent::Key(KeyCode::Char('a')));
    app.handle_event(TerminalEvent::Key(KeyCode::Char('l')));
    assert_eq!(app.search_query, "eval");

    let frame = app.render();
    assert!(frame.contains("Search: eval_"));
    assert!(frame.contains("[Filter: \"eval\" (match 1/1)]"));

    // Press Enter to commit search filter
    app.handle_event(TerminalEvent::Key(KeyCode::Enter));
    assert!(!app.search_mode);
    assert!(app.search_filter_active);

    let committed_frame = app.render();
    assert!(committed_frame.contains("eval 'echo hello'"));
    assert!(!committed_frame.contains("touch /tmp/test.txt")); // filtered out

    // Escape clears filter
    app.handle_event(TerminalEvent::Key(KeyCode::Escape));
    assert!(!app.search_filter_active);
    assert!(app.render().contains("touch /tmp/test.txt")); // restored
}

#[test]
fn tui_search_regex_and_match_cycling() {
    let records = sample_records();
    let engine = TuiEngine::from_records("/tmp", &records);
    let mut app = TuiApp::new(engine);

    // Search for 'touch' (matches 2 records: touch /tmp/test.txt and touch /var/log/custom.log)
    app.handle_event(TerminalEvent::Key(KeyCode::Char('/')));
    for c in "touch".chars() {
        app.handle_event(TerminalEvent::Key(KeyCode::Char(c)));
    }
    app.handle_event(TerminalEvent::Key(KeyCode::Enter));

    assert!(app.search_filter_active);
    let matches = app.matching_decision_indices();
    assert_eq!(matches.len(), 2);
    assert_eq!(app.selected_idx, 0);

    // 'n' cycles to next match
    app.handle_event(TerminalEvent::Key(KeyCode::Char('n')));
    assert_eq!(app.selected_idx, 1);

    // 'n' wraps around to first match
    app.handle_event(TerminalEvent::Key(KeyCode::Char('n')));
    assert_eq!(app.selected_idx, 0);

    // 'N' cycles backward to last match
    app.handle_event(TerminalEvent::Key(KeyCode::Char('N')));
    assert_eq!(app.selected_idx, 1);
}

#[test]
fn tui_policy_graph_construction_from_decisions() {
    use vouch::tui::{DecisionItem, NodeKind, PolicyGraph};

    let guard_decision = DecisionItem {
        timestamp: "2026-10-13T12:00:00Z".into(),
        cmd: "bash -c 'curl https://example.com && rm -rf /'".into(),
        verdict: "ask".into(),
        reason: "vouch stopped on: delete_recursive (guard)\n  what that means: recursively deletes directory trees".into(),
        outcome: "Denied".into(),
        session: "sess-g".into(),
        cwd: "/home/dev".into(),
    };

    let graph = PolicyGraph::from_decision(&guard_decision);
    assert!(graph.nodes.iter().any(|n| n.kind == NodeKind::CommandRoot));
    assert!(graph.nodes.iter().any(|n| n.kind == NodeKind::WrapperExpansion));
    assert!(graph.nodes.iter().any(|n| n.kind == NodeKind::CapabilityNode && n.label.contains("network")));
    assert!(graph.nodes.iter().any(|n| n.kind == NodeKind::GuardHit && n.label.contains("delete_recursive")));
    assert!(graph.nodes.iter().any(|n| n.kind == NodeKind::PolicyVerdict && n.label.contains("ASK")));

    let rendered = graph.render_ascii();
    assert!(rendered.contains("[ROOT]"));
    assert!(rendered.contains("[WRAP]"));
    assert!(rendered.contains("[CAP] capability: network"));
    assert!(rendered.contains("[GUARD] guard: delete_recursive"));
    assert!(rendered.contains("[VERDICT] verdict: ASK (Denied)"));
}

#[test]
fn tui_visualizer_tab_navigation_and_node_collapse_expand() {
    let records = sample_records();
    let engine = TuiEngine::from_records("/tmp", &records);
    let mut app = TuiApp::new(engine);

    // Press 'v' to switch to Policy Visualizer tab
    app.handle_event(TerminalEvent::Key(KeyCode::Char('v')));
    assert_eq!(app.active_tab, vouch::tui::ViewTab::Visualizer);
    assert_eq!(app.visualizer_decision_idx, 0);

    let initial_visible = app.policy_graph.visible_entries().len();
    assert!(initial_visible >= 3, "Root decision graph should have at least 3 visible nodes");

    let frame_expanded = app.render();
    assert!(frame_expanded.contains("[ 3. Policy Visualizer (v) * ]"));
    assert!(frame_expanded.contains("[-] [ROOT] touch /var/log/custom.log"));
    assert!(frame_expanded.contains("[PATH] unpermitted write path: /var/log/custom.log"));

    // Navigate down to child node with 'j' and back up to root with 'k'
    app.handle_event(TerminalEvent::Key(KeyCode::Char('j')));
    assert_eq!(app.selected_idx, 1);
    app.handle_event(TerminalEvent::Key(KeyCode::Char('k')));
    assert_eq!(app.selected_idx, 0);

    // Collapse root node using Space
    app.handle_event(TerminalEvent::Key(KeyCode::Char(' ')));
    assert_eq!(app.policy_graph.visible_entries().len(), 1);
    let frame_collapsed = app.render();
    assert!(frame_collapsed.contains("[+] [ROOT] touch /var/log/custom.log"));
    assert!(!frame_collapsed.contains("[VERDICT]"));

    // Expand root node again using Enter
    app.handle_event(TerminalEvent::Key(KeyCode::Enter));
    assert_eq!(app.policy_graph.visible_entries().len(), initial_visible);

    // Switch to next decision in visualizer using 'l' (Right)
    app.handle_event(TerminalEvent::Key(KeyCode::Char('l')));
    assert_eq!(app.visualizer_decision_idx, 1);
    let frame_second = app.render();
    assert!(frame_second.contains("[ROOT] rm -rf /"));
    assert!(frame_second.contains("[GUARD] guard: delete_recursive"));
}

#[test]
fn tui_visualizer_direct_path_and_construct_amendment_and_guard_refusal() {
    let tag = format!("tui_test_vis_amend_{}_{}", std::process::id(), line!());
    let tmp_path = std::env::temp_dir().join(tag);
    let _ = std::fs::remove_dir_all(&tmp_path);
    let home = tmp_path.to_str().unwrap();
    let config_dir = tmp_path.join(".config").join("vouch");
    std::fs::create_dir_all(&config_dir).unwrap();
    let config_file = config_dir.join("config.toml");
    std::fs::write(&config_file, "version = 1\n[write]\nallow_paths = [\"/tmp/**\"]\n").unwrap();

    let records = sample_records();
    let engine = TuiEngine::from_records(home, &records);
    let mut app = TuiApp::new(engine);

    // Switch to Policy Visualizer tab
    app.handle_event(TerminalEvent::Key(KeyCode::Char('v')));
    assert_eq!(app.active_tab, vouch::tui::ViewTab::Visualizer);
    // Decision 0 is "touch /var/log/custom.log" with child node [PATH] unpermitted write path: /var/log/custom.log
    assert_eq!(app.visualizer_decision_idx, 0);

    // Navigate down to child [PATH] node
    app.handle_event(TerminalEvent::Key(KeyCode::Char('j')));
    assert_eq!(app.selected_idx, 1);

    // Press 'p' to preview TOML delta on the [PATH] node
    app.handle_event(TerminalEvent::Key(KeyCode::Char('p')));
    let preview_frame = app.render();
    assert!(preview_frame.contains("--- Proposed TOML Delta ---"));
    assert!(preview_frame.contains("/var/log/custom.log"));

    // Press 'a' to apply the [PATH] node directly to config.toml
    app.handle_event(TerminalEvent::Key(KeyCode::Char('a')));
    assert!(
        app.status_message.contains("Added \"/var/log/custom.log\" to write.allow_paths in config.toml"),
        "Unexpected status: {}",
        app.status_message
    );
    let updated_cfg = std::fs::read_to_string(&config_file).unwrap();
    assert!(updated_cfg.contains("/var/log/custom.log"));
    assert!(updated_cfg.contains("/tmp/**"));
    // Matching candidate should also be removed from engine.candidates
    assert!(!app.engine.candidates.iter().any(|c| c.name == "path: /var/log/custom.log"));

    // Switch to Decision 1 ("rm -rf /" with [GUARD] guard: delete_recursive)
    app.handle_event(TerminalEvent::Key(KeyCode::Char('l')));
    assert_eq!(app.visualizer_decision_idx, 1);
    app.handle_event(TerminalEvent::Key(KeyCode::Char('j'))); // Select [GUARD] node
    app.handle_event(TerminalEvent::Key(KeyCode::Char('a')));
    assert!(
        app.status_message.contains("Refused: this is a guard"),
        "Guard node must refuse direct amendment, got: {}",
        app.status_message
    );

    // Switch to Decision 2 ("eval 'echo hello'" with [RULE] construct: evaluated_input)
    app.handle_event(TerminalEvent::Key(KeyCode::Char('l')));
    assert_eq!(app.visualizer_decision_idx, 2);
    app.handle_event(TerminalEvent::Key(KeyCode::Char('j'))); // Select [RULE] node
    app.handle_event(TerminalEvent::Key(KeyCode::Char('a')));
    assert!(
        app.status_message.contains("Added [lang.bash.constructs] evaluated_input = \"allow\" to config.toml"),
        "Construct node should apply amendment, got: {}",
        app.status_message
    );
    let final_cfg = std::fs::read_to_string(&config_file).unwrap();
    assert!(final_cfg.contains("evaluated_input = \"allow\""));
    assert!(!app.engine.candidates.iter().any(|c| c.name == "evaluated_input"));

    let _ = std::fs::remove_dir_all(&tmp_path);
}

#[test]
fn tui_visualizer_interactive_simulation_and_impact_diff_without_disk_mutation() {
    let tag = format!("tui_test_vis_sim_{}_{}", std::process::id(), line!());
    let tmp_path = std::env::temp_dir().join(tag);
    let _ = std::fs::remove_dir_all(&tmp_path);
    let home = tmp_path.to_str().unwrap();
    let config_dir = tmp_path.join(".config").join("vouch");
    std::fs::create_dir_all(&config_dir).unwrap();
    let config_file = config_dir.join("config.toml");
    let initial_toml = "version = 1\n[write]\nallow_paths = [\"/tmp/**\"]\n";
    std::fs::write(&config_file, initial_toml).unwrap();

    let records = sample_records();
    let engine = TuiEngine::from_records(home, &records);
    let mut app = TuiApp::new(engine);

    // Switch to Policy Visualizer tab
    app.handle_event(TerminalEvent::Key(KeyCode::Char('v')));
    assert_eq!(app.active_tab, vouch::tui::ViewTab::Visualizer);
    assert_eq!(app.visualizer_decision_idx, 0);

    // Select child [PATH] node ("unpermitted write path: /var/log/custom.log")
    app.handle_event(TerminalEvent::Key(KeyCode::Char('j')));
    assert_eq!(app.selected_idx, 1);

    // Press 'd' to simulate amendment in memory
    app.handle_event(TerminalEvent::Key(KeyCode::Char('d')));
    assert!(
        app.status_message.contains("ASK -> ALLOW"),
        "Expected ASK -> ALLOW simulation status, got: {}",
        app.status_message
    );
    let sim_frame = app.render();
    assert!(sim_frame.contains("[SIMULATED: ASK -> ALLOW]"));
    assert!(sim_frame.contains("--- Side-by-Side Amendment Impact Diff (Simulation) ---"));
    assert!(sim_frame.contains("Amendment: [write] allow_paths += \"/var/log/custom.log\""));
    assert!(sim_frame.contains("Before:    [ASK]"));
    assert!(sim_frame.contains("After:     [ALLOW]"));

    // Verify config.toml on disk was NOT mutated during simulation
    let disk_after_sim = std::fs::read_to_string(&config_file).unwrap();
    assert_eq!(disk_after_sim, initial_toml, "Simulation must never mutate config.toml on disk");

    // Pressing 'd' again toggles simulation off
    app.handle_event(TerminalEvent::Key(KeyCode::Char('d')));
    assert!(app.policy_graph.simulation.is_none());
    assert!(!app.render().contains("[SIMULATED:"));

    // Switch to Decision 1 ("rm -rf /" with [GUARD] delete_recursive)
    app.handle_event(TerminalEvent::Key(KeyCode::Char('l')));
    app.handle_event(TerminalEvent::Key(KeyCode::Char('j'))); // Select [GUARD] node
    app.handle_event(TerminalEvent::Key(KeyCode::Char('d')));
    assert!(
        app.status_message.contains("Guard rules describe operator effects and cannot be simulated as allow-list amendments."),
        "Guard simulation must be refused with explanatory message, got: {}",
        app.status_message
    );
    assert!(app.policy_graph.simulation.is_none());

    // Switch to Decision 2 ("eval 'echo hello'" with [RULE] evaluated_input)
    app.handle_event(TerminalEvent::Key(KeyCode::Char('l')));
    app.handle_event(TerminalEvent::Key(KeyCode::Char('j'))); // Select [RULE] node
    app.handle_event(TerminalEvent::Key(KeyCode::Char('d')));
    assert!(
        app.status_message.contains("ASK -> ALLOW"),
        "Construct simulation must transition ASK -> ALLOW, got: {}",
        app.status_message
    );
    let rule_sim_frame = app.render();
    assert!(rule_sim_frame.contains("Amendment: [lang.bash.constructs] evaluated_input = \"allow\""));
    assert_eq!(std::fs::read_to_string(&config_file).unwrap(), initial_toml);

    let _ = std::fs::remove_dir_all(&tmp_path);
}
