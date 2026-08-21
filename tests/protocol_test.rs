use vouch::protocol::{parse_input, render, Decision};

#[test]
fn parses_a_real_bash_snippet() {
    let raw = r#"{"session_id":"abc","cwd":"C:/claude","hook_event_name":"PreToolUse",
        "tool_name":"Bash","tool_input":{"command":"ls -la /c/git"}}"#;
    let input = parse_input(raw).expect("should parse");
    assert_eq!(input.tool_name, "Bash");
    assert_eq!(input.tool_input.command.as_deref(), Some("ls -la /c/git"));
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
