use vouch::protocol::{parse_input, render, render_for, Decision, Host};

#[test]
fn parses_a_real_bash_snippet() {
    let raw = r#"{"session_id":"abc","cwd":"C:/claude","hook_event_name":"PreToolUse",
        "tool_name":"Bash","tool_input":{"command":"ls -la /c/workspace"}}"#;
    let input = parse_input(raw).expect("should parse");
    assert_eq!(input.tool_name, "Bash");
    assert_eq!(input.tool_input.command.as_deref(), Some("ls -la /c/workspace"));
}

#[test]
fn abstain_renders_nothing() {
    assert_eq!(render(&Decision::Abstain), None);
}

#[test]
fn ask_renders_the_reason_verbatim() {
    let out = render(&Decision::Ask("because reasons".into())).expect("some output");
    assert!(out.contains(r#""permissionDecision":"ask""#));
    assert!(out.contains("because reasons"));
}

#[test]
fn never_emits_defer() {
    for d in [
        Decision::Allow("a".into()),
        Decision::Ask("b".into()),
        Decision::Deny("c".into()),
    ] {
        let out = render(&d).unwrap_or_default();
        assert!(!out.contains("defer"), "defer must never appear: {out}");
    }
}

#[test]
fn a_multiline_reason_survives_intact() {
    // The self-explaining prompt depends on multi-line reasons arriving whole.
    let reason = "vouch stopped on: dynamic_command\n  set lang.bash.constructs.dynamic_command = \"allow\"";
    let out = render(&Decision::Ask(reason.into())).expect("some output");
    let parsed: serde_json::Value = serde_json::from_str(&out).expect("valid json");
    assert_eq!(
        parsed["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap(),
        reason
    );
}

#[test]
fn tool_input_keeps_unknown_named_fields() {
    let raw = r#"{"hook_event_name":"PreToolUse","tool_name":"mcp__p_s__ctx_execute",
        "tool_input":{"code":"ls -la","language":"shell","timeout":5}}"#;
    let input = parse_input(raw).unwrap();
    assert_eq!(input.tool_input.extra.get("code").and_then(|v| v.as_str()), Some("ls -la"));
    assert!(input.tool_input.extra.get("command").is_none()); // typed keys are consumed, not duplicated
}

#[test]
fn typed_fields_still_deserialize() {
    let raw = r#"{"tool_name":"Bash","tool_input":{"command":"ls"}}"#;
    let input = parse_input(raw).unwrap();
    assert_eq!(input.tool_input.command.as_deref(), Some("ls"));
    assert!(input.tool_input.extra.is_empty());
}

#[test]
fn codex_allow_emits_nothing_and_never_weakens_its_native_gate() {
    assert_eq!(render_for(Host::Codex, &Decision::Allow("known read".into())), None);
}

#[test]
fn codex_ask_is_a_block_not_the_unsupported_ask_shape() {
    let out = render_for(Host::Codex, &Decision::Ask("request approval id: abc".into()))
        .expect("Codex Ask must block the first attempt");
    let body: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(body["hookSpecificOutput"]["permissionDecision"], "deny");
    assert_eq!(
        body["hookSpecificOutput"]["permissionDecisionReason"],
        "request approval id: abc"
    );
    assert!(!out.contains(r#""permissionDecision":"ask""#));
}

#[test]
fn codex_deny_uses_the_supported_block_shape() {
    let out = render_for(Host::Codex, &Decision::Deny("blocked".into())).unwrap();
    assert!(out.contains(r#""permissionDecision":"deny""#));
}

#[test]
fn codex_turn_id_is_preserved_for_exact_retry_scoping() {
    let input = parse_input(
        r#"{"session_id":"s","turn_id":"t","tool_name":"Bash","tool_input":{"command":"ls"}}"#,
    )
    .unwrap();
    assert_eq!(input.turn_id, "t");
}

#[test]
fn parses_agy_run_command_payload() {
    let raw = r#"{
        "toolCall": {
            "name": "run_command",
            "args": {
                "CommandLine": "cargo test --release",
                "Cwd": "C:/workspace/project",
                "BypassSandbox": true
            }
        },
        "stepIdx": 42,
        "conversationId": "conv-123",
        "workspacePaths": ["C:/workspace/project"]
    }"#;
    let input = parse_input(raw).expect("should parse AGY run_command");
    assert_eq!(input.hook_event_name, "PreToolUse");
    assert_eq!(input.tool_name, "run_command");
    assert_eq!(input.session_id, "conv-123");
    assert_eq!(input.turn_id, "42");
    assert_eq!(input.cwd, "C:/workspace/project");
    assert_eq!(input.tool_input.command.as_deref(), Some("cargo test --release"));
    assert_eq!(
        input.tool_input.extra.get("BypassSandbox"),
        Some(&serde_json::Value::Bool(true))
    );
}

#[test]
fn parses_agy_file_tools_payload() {
    let raw = r#"{
        "toolCall": {
            "name": "write_to_file",
            "args": {
                "TargetFile": "C:/workspace/project/src/main.rs",
                "CodeContent": "fn main() {}"
            }
        },
        "stepIdx": 5,
        "conversationId": "conv-456",
        "workspacePaths": ["C:/workspace/project"]
    }"#;
    let input = parse_input(raw).expect("should parse AGY write_to_file");
    assert_eq!(input.tool_name, "write_to_file");
    assert_eq!(
        input.tool_input.file_path.as_deref(),
        Some("C:/workspace/project/src/main.rs")
    );
}

#[test]
fn parses_agy_post_tool_payloads() {
    let success = r#"{
        "stepIdx": 10,
        "conversationId": "conv-789",
        "workspacePaths": ["C:/workspace/project"]
    }"#;
    let post_ok = parse_input(success).unwrap();
    assert_eq!(post_ok.hook_event_name, "PostToolUse");
    assert_eq!(post_ok.session_id, "conv-789");

    let failure = r#"{
        "stepIdx": 11,
        "error": "command failed with status 1",
        "conversationId": "conv-789",
        "workspacePaths": ["C:/workspace/project"]
    }"#;
    let post_fail = parse_input(failure).unwrap();
    assert_eq!(post_fail.hook_event_name, "PostToolUseFailure");
    assert_eq!(post_fail.error, "command failed with status 1");
}

#[test]
fn renders_agy_allow_ask_deny_and_abstain() {
    assert_eq!(render_for(Host::Agy, &Decision::Abstain), None);

    let allow_out = render_for(Host::Agy, &Decision::Allow("known read".into())).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&allow_out).unwrap();
    assert_eq!(parsed["decision"], "allow");
    assert_eq!(parsed["reason"], "known read");
    assert!(parsed.get("overwrite").is_none());

    let ask_out = render_for(Host::Agy, &Decision::Ask("unmodeled command".into())).unwrap();
    let parsed_ask: serde_json::Value = serde_json::from_str(&ask_out).unwrap();
    assert_eq!(parsed_ask["decision"], "ask");
    assert_eq!(parsed_ask["reason"], "unmodeled command");

    let deny_out = render_for(Host::Agy, &Decision::Deny("protected path".into())).unwrap();
    let parsed_deny: serde_json::Value = serde_json::from_str(&deny_out).unwrap();
    assert_eq!(parsed_deny["decision"], "deny");
    assert_eq!(parsed_deny["reason"], "protected path");
}

#[test]
fn demotes_safe_local_commands_in_agy() {
    use vouch::protocol::{render_for_agy, should_demote_sandbox};

    let raw = r#"{
        "toolCall": {
            "name": "run_command",
            "args": {
                "CommandLine": "git status",
                "BypassSandbox": true
            }
        },
        "conversationId": "c",
        "stepIdx": 1
    }"#;
    let input = parse_input(raw).unwrap();
    let decision = Decision::Allow("known local read".into());
    assert!(should_demote_sandbox(&input, &decision));

    let rendered = render_for_agy(&decision, true).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&rendered).unwrap();
    assert_eq!(parsed["decision"], "allow");
    assert_eq!(parsed["overwrite"]["BypassSandbox"], false);
}

#[test]
fn preserves_unsandboxed_for_network_commands_in_agy() {
    use vouch::protocol::should_demote_sandbox;

    let raw = r#"{
        "toolCall": {
            "name": "run_command",
            "args": {
                "CommandLine": "git fetch origin",
                "BypassSandbox": true
            }
        },
        "conversationId": "c",
        "stepIdx": 2
    }"#;
    let input = parse_input(raw).unwrap();
    let decision = Decision::Allow("fetch allowed".into());
    assert!(!should_demote_sandbox(&input, &decision));
}
