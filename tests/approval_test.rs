use std::fs;

use vouch::approval::{
    gate, request_summary, respond, take_outcome_alias, ApprovalAction, GateResult,
};
use vouch::protocol::parse_input;

fn scratch(tag: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("vouch_approval_{tag}_{}", std::process::id()));
    let _ = fs::remove_dir_all(&p);
    p
}

fn call(id: &str, command: &str) -> vouch::protocol::HookInput {
    parse_input(&format!(
        r#"{{"session_id":"session-a","turn_id":"turn-a","tool_use_id":"{id}","cwd":"C:/Users/dev","tool_name":"Bash","tool_input":{{"command":{}}}}}"#,
        serde_json::to_string(command).unwrap()
    ))
    .unwrap()
}

#[test]
fn accepted_approval_is_one_use_and_exact_input_only() {
    let dir = scratch("one_use");
    let first = call("first", "remove-item notes.txt");
    let request_id = match gate(&dir, &first, "vouch stopped on: write", 100).unwrap() {
        GateResult::Pending { request_id } => request_id,
        other => panic!("first attempt must be pending, got {other:?}"),
    };
    respond(&dir, &request_id, ApprovalAction::Accept, 101).unwrap();

    let retry = call("retry", "remove-item notes.txt");
    assert!(matches!(
        gate(&dir, &retry, "vouch stopped on: write", 102).unwrap(),
        GateResult::Granted
    ));
    assert_eq!(
        take_outcome_alias(&dir, "retry").unwrap().as_deref(),
        Some("first")
    );

    let replay = call("replay", "remove-item notes.txt");
    assert!(matches!(
        gate(&dir, &replay, "vouch stopped on: write", 103).unwrap(),
        GateResult::Pending { .. }
    ));
}

#[test]
fn changed_retry_cannot_consume_the_grant() {
    let dir = scratch("changed");
    let request_id = match gate(&dir, &call("first", "remove-item a.txt"), "ask", 100).unwrap() {
        GateResult::Pending { request_id } => request_id,
        other => panic!("got {other:?}"),
    };
    respond(&dir, &request_id, ApprovalAction::Accept, 101).unwrap();
    let changed = gate(&dir, &call("changed", "remove-item b.txt"), "ask", 102).unwrap();
    assert!(matches!(changed, GateResult::Pending { .. }));
}

#[test]
fn expired_grant_is_not_consumed() {
    let dir = scratch("expired");
    let request_id = match gate(&dir, &call("first", "remove-item a.txt"), "ask", 100).unwrap() {
        GateResult::Pending { request_id } => request_id,
        other => panic!("got {other:?}"),
    };
    respond(&dir, &request_id, ApprovalAction::Accept, 101).unwrap();
    let retry = gate(&dir, &call("retry", "remove-item a.txt"), "ask", 1000).unwrap();
    assert!(matches!(retry, GateResult::Pending { .. }));
}

#[test]
fn a_grant_from_the_future_is_not_treated_as_fresh() {
    let dir = scratch("future_grant");
    let request_id = match gate(&dir, &call("first", "remove-item a.txt"), "ask", 100).unwrap() {
        GateResult::Pending { request_id } => request_id,
        other => panic!("got {other:?}"),
    };
    respond(&dir, &request_id, ApprovalAction::Accept, 200).unwrap();
    let retry = gate(&dir, &call("retry", "remove-item a.txt"), "ask", 150).unwrap();
    assert!(matches!(retry, GateResult::Pending { .. }));
}

#[test]
fn exact_retry_grants_require_both_codex_session_and_turn_scope() {
    let dir = scratch("missing_scope");
    let mut missing_session = call("first", "remove-item a.txt");
    missing_session.session_id.clear();
    let error = gate(&dir, &missing_session, "ask", 100).unwrap_err();
    assert!(error.contains("session_id"), "{error}");

    let mut missing_turn = call("second", "remove-item a.txt");
    missing_turn.turn_id.clear();
    let error = gate(&dir, &missing_turn, "ask", 100).unwrap_err();
    assert!(error.contains("turn_id"), "{error}");
}

#[test]
fn pending_state_never_contains_the_raw_command_or_session_id() {
    let dir = scratch("redacted");
    let marker = "private-command-marker";
    let session_marker = "session-a";
    let _ = gate(
        &dir,
        &call("first", marker),
        "vouch stopped on: evaluated_input",
        100,
    )
    .unwrap();
    let combined = fs::read_dir(dir.join("approvals"))
        .unwrap()
        .filter_map(Result::ok)
        .filter_map(|e| fs::read_to_string(e.path()).ok())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !combined.contains(marker),
        "raw tool input persisted: {combined}"
    );
    assert!(
        !combined.contains(session_marker),
        "session id persisted: {combined}"
    );
}

#[test]
fn broker_rejects_malformed_request_ids_before_building_a_path() {
    let dir = scratch("bad_request_id");
    let summary_error = request_summary(&dir, "../outside").unwrap_err();
    assert!(
        summary_error.contains("invalid request id"),
        "{summary_error}"
    );

    let respond_error = respond(&dir, "vouch-not-hex", ApprovalAction::Cancel, 100).unwrap_err();
    assert!(
        respond_error.contains("invalid request id"),
        "{respond_error}"
    );
}
