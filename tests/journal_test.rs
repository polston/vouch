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
}
