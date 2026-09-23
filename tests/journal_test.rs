use std::fs;
use vouch::journal::{append, record_from, records_from_snippets, Record};
use vouch::outcome::Outcome;
use vouch::protocol::{parse_input, Decision};

#[test]
fn appends_one_json_line_per_record() {
    let dir = std::env::temp_dir().join("vouch_journal_test_1");
    let _ = fs::remove_dir_all(&dir);
    let rec = Record {
        id: "tid".into(),
        outcome: Outcome::Pending,
        ts: "2026-07-25T00:00:00Z".into(),
        session: "s1".into(),
        tool: "Bash".into(),
        cmd: "ls".into(),
        verdict: "abstain".into(),
        reason: "shadow".into(),
        mode: "shadow".into(),
        cwd: String::new(),
        lang: String::new(),
        permission_mode: String::new(),
        host: "claude".into(),
        count: 1,
        measurement: false,
    };
    append(&dir, &rec).unwrap();
    append(&dir, &rec).unwrap();

    let body = fs::read_to_string(dir.join("journal.jsonl")).unwrap();
    let lines: Vec<&str> = body.lines().collect();
    assert_eq!(lines.len(), 2);
    let parsed: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(parsed["tool"], "Bash");
    assert_eq!(parsed["mode"], "shadow");
}

#[test]
fn record_from_extracts_the_command() {
    let raw = r#"{"session_id":"s9","tool_name":"Bash","tool_input":{"command":"git status"}}"#;
    let input = parse_input(raw).unwrap();
    let rec = record_from(&input, &Decision::Abstain, "shadow");
    assert_eq!(rec.session, "s9");
    assert_eq!(rec.cmd, "git status");
    assert_eq!(rec.verdict, "abstain");
}

#[test]
fn record_from_falls_back_to_the_file_path() {
    let raw = r#"{"session_id":"s","tool_name":"Write","tool_input":{"file_path":"C:/work/x.txt"}}"#;
    let input = parse_input(raw).unwrap();
    let rec = record_from(&input, &Decision::Allow("ok".into()), "live");
    assert_eq!(rec.cmd, "C:/work/x.txt");
    assert_eq!(rec.verdict, "allow");
    assert_eq!(rec.mode, "live");
}

#[test]
fn record_from_never_claims_a_language() {
    // The known contract (Task 9): `record_from` is only reached when
    // `route::decide`'s `RouteOutcome.snippets` came back empty — a
    // config-named allow short-circuits before extraction. The snippet was
    // never looked at, so the single fallback record must not claim one.
    let raw = r#"{"session_id":"s","tool_name":"Bash","tool_input":{"command":"ls -la"}}"#;
    let input = parse_input(raw).unwrap();
    let rec = record_from(&input, &Decision::Allow("tools.Bash = \"allow\"".into()), "live");
    assert_eq!(rec.lang, "", "a fallback record must not claim a language it never read");
}

#[test]
fn records_from_snippets_journals_one_record_per_snippet_sharing_the_tool_use_id() {
    // The batch shape: a two-command call must become two rows, not one
    // joined record, each carrying the extracted text as `cmd` and the
    // language it was decided in, and all sharing the call's `tool_use_id`.
    let raw = r#"{"session_id":"s","tool_use_id":"batch1","tool_name":"mcp__p_s__batch","tool_input":{}}"#;
    let input = parse_input(raw).unwrap();
    let snippets = vec![("ls -la".to_string(), "bash".to_string()), ("pwd".to_string(), "bash".to_string())];
    let recs = records_from_snippets(&input, &Decision::Ask("vouch stopped on: heredoc".into()), "live", &snippets);

    assert_eq!(recs.len(), 2, "one record per snippet, got: {recs:?}");
    assert_eq!(recs[0].id, "batch1");
    assert_eq!(recs[1].id, "batch1");
    assert_eq!(recs[0].cmd, "ls -la");
    assert_eq!(recs[1].cmd, "pwd");
    assert_eq!(recs[0].lang, "bash");
    assert_eq!(recs[1].lang, "bash");
    assert_eq!(recs[0].verdict, "ask");
    assert_eq!(recs[1].verdict, "ask");
    assert!(recs[0].reason.contains("heredoc"));
}

#[test]
fn shadow_records_are_never_recorded_as_an_approval() {
    // A shadow record must never be usable as evidence that a human approved anything.
    let raw = r#"{"session_id":"s","tool_name":"Bash","tool_input":{"command":"rm -rf /"}}"#;
    let input = parse_input(raw).unwrap();
    let rec = record_from(&input, &Decision::Abstain, "shadow");
    assert_eq!(rec.mode, "shadow");
    assert_ne!(rec.verdict, "allow");
}

#[test]
fn a_missing_directory_is_created_rather_than_failing() {
    let dir = std::env::temp_dir().join("vouch_journal_test_2/nested/deeper");
    let _ = fs::remove_dir_all(std::env::temp_dir().join("vouch_journal_test_2"));
    let rec = Record {
        id: "tid".into(),
        outcome: Outcome::Pending,
        ts: "t".into(),
        session: "s".into(),
        tool: "Bash".into(),
        cmd: "ls".into(),
        verdict: "abstain".into(),
        reason: String::new(),
        mode: "shadow".into(),
        cwd: String::new(),
        lang: String::new(),
        permission_mode: String::new(),
        host: "claude".into(),
        count: 1,
        measurement: false,
    };
    append(&dir, &rec).unwrap();
    assert!(dir.join("journal.jsonl").exists());
}

#[test]
fn record_from_carries_the_permission_mode() {
    let raw = r#"{"session_id":"s","tool_name":"Bash","permission_mode":"auto","tool_input":{"command":"ls"}}"#;
    let input = parse_input(raw).unwrap();
    let rec = record_from(&input, &Decision::Allow("ok".into()), "live");
    assert_eq!(rec.permission_mode, "auto");
}

#[test]
fn an_old_journal_row_without_the_field_still_parses() {
    // A row written before this field existed. Empty means "old row OR the
    // caller supplied no mode" — the two are not distinguishable, by design.
    let line = r#"{"id":"x","ts":"1","session":"s","tool":"Bash","cmd":"ls","verdict":"allow","reason":"","mode":"live"}"#;
    let rec: Record = serde_json::from_str(line).unwrap();
    assert_eq!(rec.permission_mode, "");
    assert_eq!(rec.host, "");
}

#[test]
fn outcomes_correlate_by_host_as_well_as_tool_use_id() {
    let dir = std::env::temp_dir().join("vouch_journal_host_correlation");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("journal.jsonl"),
        concat!(
            "{\"id\":\"same\",\"ts\":\"1\",\"session\":\"s\",\"tool\":\"Bash\",\"cmd\":\"a\",\"verdict\":\"allow\",\"reason\":\"\",\"mode\":\"live\",\"host\":\"claude\"}\n",
            "{\"id\":\"same\",\"ts\":\"2\",\"session\":\"s\",\"tool\":\"Bash\",\"cmd\":\"b\",\"verdict\":\"ask\",\"reason\":\"\",\"mode\":\"shadow\",\"host\":\"codex\"}\n",
        ),
    )
    .unwrap();
    fs::write(
        dir.join("outcomes.jsonl"),
        "{\"id\":\"same\",\"host\":\"codex\",\"outcome\":\"executed\",\"detail\":\"\"}\n",
    )
    .unwrap();

    let recs = vouch::journal::all(&dir);
    assert_eq!(recs[0].host, "claude");
    assert_eq!(recs[0].outcome, Outcome::Unknown);
    assert_eq!(recs[1].host, "codex");
    assert_eq!(recs[1].outcome, Outcome::Executed);
}

#[test]
fn legacy_hostless_rows_still_correlate_only_with_legacy_outcomes() {
    let dir = std::env::temp_dir().join("vouch_journal_legacy_host_correlation");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("journal.jsonl"),
        "{\"id\":\"old\",\"ts\":\"1\",\"session\":\"s\",\"tool\":\"Bash\",\"cmd\":\"a\",\"verdict\":\"allow\",\"reason\":\"\",\"mode\":\"live\"}\n",
    )
    .unwrap();
    fs::write(
        dir.join("outcomes.jsonl"),
        "{\"id\":\"old\",\"outcome\":\"executed\",\"detail\":\"\"}\n",
    )
    .unwrap();

    let recs = vouch::journal::all(&dir);
    assert_eq!(recs[0].host, "");
    assert_eq!(recs[0].outcome, Outcome::Executed);
}

#[test]
fn compact_records_preserves_recent_window_and_deduplicates_history() {
    use vouch::journal::{compact_records, JournalPolicy};

    let make_rec = |id: &str, cmd: &str, ts: &str| Record {
        id: id.into(),
        outcome: Outcome::Pending,
        ts: ts.into(),
        session: "s".into(),
        tool: "Bash".into(),
        cmd: cmd.into(),
        verdict: "allow".into(),
        reason: "ok".into(),
        mode: "live".into(),
        cwd: String::new(),
        lang: "bash".into(),
        permission_mode: String::new(),
        host: "claude".into(),
        count: 1,
        measurement: false,
    };

    let records = vec![
        make_rec("1", "git status", "100"),
        make_rec("2", "ls -la", "101"),
        make_rec("3", "git status", "102"),
        make_rec("4", "git status", "103"),
        // Recent window (last 2 records)
        make_rec("5", "git status", "104"),
        make_rec("6", "pwd", "105"),
    ];

    let policy = JournalPolicy {
        max_records: 10,
        compact_duplicates: true,
        preserve_recent: 2,
    };

    let (compacted, stats) = compact_records(&records, &policy);
    assert_eq!(stats.original_count, 6);
    // Historical had 4 records: 3 git status, 1 ls -la -> collapses to 2 records (git status with count 3, ls -la with count 1)
    // Recent had 2 records: untouched (ids "5", "6")
    assert_eq!(compacted.len(), 4);
    assert_eq!(compacted[0].cmd, "git status");
    assert_eq!(compacted[0].count, 3);
    assert_eq!(compacted[0].ts, "103"); // latest historical timestamp
    assert_eq!(compacted[1].cmd, "ls -la");
    assert_eq!(compacted[1].count, 1);
    assert_eq!(compacted[2].id, "5");
    assert_eq!(compacted[2].count, 1);
    assert_eq!(compacted[3].id, "6");
    assert_eq!(compacted[3].count, 1);
}

#[test]
fn prune_enforces_hard_record_cap() {
    use vouch::journal::{compact_records, JournalPolicy};

    let make_rec = |id: &str| Record {
        id: id.into(),
        outcome: Outcome::Pending,
        ts: id.into(),
        session: "s".into(),
        tool: "Bash".into(),
        cmd: format!("cmd_{id}"),
        verdict: "allow".into(),
        reason: "ok".into(),
        mode: "live".into(),
        cwd: String::new(),
        lang: "bash".into(),
        permission_mode: String::new(),
        host: "claude".into(),
        count: 1,
        measurement: false,
    };

    let records: Vec<Record> = (0..20).map(|i| make_rec(&i.to_string())).collect();
    let policy = JournalPolicy {
        max_records: 5,
        compact_duplicates: false,
        preserve_recent: 2,
    };

    let (compacted, stats) = compact_records(&records, &policy);
    assert_eq!(compacted.len(), 5);
    assert_eq!(stats.pruned_count, 15);
    // The retained 5 records are the latest records (15..20)
    assert_eq!(compacted[0].id, "15");
    assert_eq!(compacted[4].id, "19");
}

#[test]
fn tail_record_reads_last_entry_without_parsing_whole_file() {
    use vouch::journal::{append, append_outcome, last, tail_record, OutcomeRecord};

    let dir = std::env::temp_dir().join("vouch_journal_tail_test");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();

    assert!(last(&dir).is_none());
    assert!(tail_record(&dir).is_none());

    for i in 0..10 {
        let rec = Record {
            id: format!("id_{i}"),
            outcome: Outcome::Pending,
            ts: i.to_string(),
            session: "s".into(),
            tool: "Bash".into(),
            cmd: format!("echo {i}"),
            verdict: "allow".into(),
            reason: "ok".into(),
            mode: "live".into(),
            cwd: String::new(),
            lang: "bash".into(),
            permission_mode: String::new(),
            host: "claude".into(),
            count: 1,
            measurement: false,
        };
        append(&dir, &rec).unwrap();
    }

    append_outcome(
        &dir,
        &OutcomeRecord {
            id: "id_9".into(),
            outcome: Outcome::Executed,
            detail: String::new(),
            host: "claude".into(),
        },
    )
    .unwrap();

    let tail = tail_record(&dir).expect("should find tail record");
    assert_eq!(tail.id, "id_9");
    assert_eq!(tail.cmd, "echo 9");
    assert_eq!(tail.outcome, Outcome::Executed);

    let l = last(&dir).expect("should find last record");
    assert_eq!(l.id, "id_9");
    assert_eq!(l.outcome, Outcome::Executed);
}

#[test]
fn atomic_compaction_retains_outcome_pairing() {
    use vouch::journal::{append, append_outcome, prune_and_compact, JournalPolicy, OutcomeRecord};

    let dir = std::env::temp_dir().join("vouch_journal_atomic_test");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();

    // Write duplicate commands
    for i in 0..10 {
        let rec = Record {
            id: format!("id_{i}"),
            outcome: Outcome::Pending,
            ts: i.to_string(),
            session: "s".into(),
            tool: "Bash".into(),
            cmd: if i < 6 { "git status".into() } else { format!("cmd_{i}") },
            verdict: "allow".into(),
            reason: "ok".into(),
            mode: "live".into(),
            cwd: String::new(),
            lang: "bash".into(),
            permission_mode: String::new(),
            host: "claude".into(),
            count: 1,
            measurement: false,
        };
        append(&dir, &rec).unwrap();
        append_outcome(
            &dir,
            &OutcomeRecord {
                id: format!("id_{i}"),
                outcome: Outcome::Executed,
                detail: String::new(),
                host: "claude".into(),
            },
        )
        .unwrap();
    }

    let policy = JournalPolicy {
        max_records: 6,
        compact_duplicates: true,
        preserve_recent: 2, // ids 8 and 9 are preserved
    };

    let stats = prune_and_compact(&dir, &policy).unwrap();
    assert!(stats.original_count == 10);

    let recs = vouch::journal::all(&dir);
    assert!(recs.len() <= 6);
    // Verified that all outcomes for retained records are properly folded
    for r in &recs {
        assert_eq!(r.outcome, Outcome::Executed, "record {} outcome should be Executed", r.id);
    }
}

#[test]
fn measurement_record_serialization_and_legacy_compatibility() {
    let rec_prod = Record {
        id: "p1".into(),
        ts: "100".into(),
        session: "s".into(),
        tool: "Bash".into(),
        cmd: "ls".into(),
        verdict: "allow".into(),
        reason: "ok".into(),
        mode: "live".into(),
        cwd: String::new(),
        outcome: Outcome::Pending,
        lang: "bash".into(),
        permission_mode: String::new(),
        host: "claude".into(),
        count: 1,
        measurement: false,
    };
    let json_prod = serde_json::to_string(&rec_prod).unwrap();
    assert!(!json_prod.contains("measurement"), "false measurement should be omitted: {json_prod}");

    let mut rec_meas = rec_prod.clone();
    rec_meas.measurement = true;
    let json_meas = serde_json::to_string(&rec_meas).unwrap();
    assert!(json_meas.contains("\"measurement\":true"), "true measurement should be present: {json_meas}");

    // Legacy row without measurement field
    let legacy_json = r#"{"id":"leg","ts":"100","session":"s","tool":"Bash","cmd":"ls","verdict":"allow","reason":"ok","mode":"live"}"#;
    let decoded: Record = serde_json::from_str(legacy_json).unwrap();
    assert!(!decoded.measurement, "legacy row must default to measurement: false");
}

#[test]
fn compact_records_isolates_measurement_from_production() {
    use vouch::journal::{compact_records, JournalPolicy};

    let make_rec = |id: &str, cmd: &str, meas: bool| Record {
        id: id.into(),
        outcome: Outcome::Pending,
        ts: "100".into(),
        session: "s".into(),
        tool: "Bash".into(),
        cmd: cmd.into(),
        verdict: "allow".into(),
        reason: "ok".into(),
        mode: "live".into(),
        cwd: String::new(),
        lang: "bash".into(),
        permission_mode: String::new(),
        host: "claude".into(),
        count: 1,
        measurement: meas,
    };

    let records = vec![
        make_rec("1", "git status", false),
        make_rec("2", "git status", false),
        make_rec("3", "git status", true),
        make_rec("4", "git status", true),
    ];

    let policy = JournalPolicy {
        max_records: 10,
        compact_duplicates: true,
        preserve_recent: 0, // all in historical
    };

    let (compacted, stats) = compact_records(&records, &policy);
    assert_eq!(stats.original_count, 4);
    // Should collapse into 2 records: one production (count 2) and one measurement (count 2)
    assert_eq!(compacted.len(), 2);
    let prod = compacted.iter().find(|r| !r.measurement).expect("production record");
    assert_eq!(prod.count, 2);
    let meas = compacted.iter().find(|r| r.measurement).expect("measurement record");
    assert_eq!(meas.count, 2);
}
