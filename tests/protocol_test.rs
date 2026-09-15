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

    let success_with_tool_call = r#"{
        "stepIdx": 10,
        "toolCall": {
            "name": "run_command",
            "args": { "CommandLine": "cargo test" }
        },
        "toolResponse": { "output": "ok" },
        "conversationId": "conv-789",
        "workspacePaths": ["C:/workspace/project"]
    }"#;
    let post_tc_ok = parse_input(success_with_tool_call).unwrap();
    assert_eq!(post_tc_ok.hook_event_name, "PostToolUse");
    assert_eq!(post_tc_ok.tool_name, "run_command");

    let failure = r#"{
        "stepIdx": 11,
        "error": "command failed with status 1",
        "conversationId": "conv-789",
        "workspacePaths": ["C:/workspace/project"]
    }"#;
    let post_fail = parse_input(failure).unwrap();
    assert_eq!(post_fail.hook_event_name, "PostToolUseFailure");
    assert_eq!(post_fail.error, "command failed with status 1");

    let failure_with_tool_call = r#"{
        "stepIdx": 11,
        "toolCall": {
            "name": "run_command",
            "args": { "CommandLine": "cargo test" }
        },
        "error": "command failed with status 1",
        "conversationId": "conv-789",
        "workspacePaths": ["C:/workspace/project"]
    }"#;
    let post_tc_fail = parse_input(failure_with_tool_call).unwrap();
    assert_eq!(post_tc_fail.hook_event_name, "PostToolUseFailure");
    assert_eq!(post_tc_fail.error, "command failed with status 1");
    assert_eq!(post_tc_fail.tool_name, "run_command");
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
    assert_eq!(parsed_ask["decision"], "force_ask");
    assert_eq!(parsed_ask["reason"], "unmodeled command");

    let deny_out = render_for(Host::Agy, &Decision::Deny("protected path".into())).unwrap();
    let parsed_deny: serde_json::Value = serde_json::from_str(&deny_out).unwrap();
    assert_eq!(parsed_deny["decision"], "deny");
    assert_eq!(parsed_deny["reason"], "protected path");
}

#[test]
fn demotes_safe_local_commands_in_agy() {
    use vouch::protocol::{render_for_agy, should_demote_sandbox};
    let kb = vouch::guards::in_effect();

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
    assert!(should_demote_sandbox(&input, &decision, kb));

    let rendered = render_for_agy(&decision, true).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&rendered).unwrap();
    assert_eq!(parsed["decision"], "allow");
    assert_eq!(parsed["overwrite"]["BypassSandbox"], false);
}

#[test]
fn preserves_unsandboxed_for_network_commands_in_agy() {
    use vouch::protocol::should_demote_sandbox;
    let kb = vouch::guards::in_effect();

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
    assert!(!should_demote_sandbox(&input, &decision, kb));
}

#[test]
fn demotes_safe_local_commands_on_ask_in_agy() {
    use vouch::protocol::{render_for_agy, should_demote_sandbox};
    let kb = vouch::guards::in_effect();

    // Modeled safe local command on Ask demotes to avoid dual-prompt friction (M2.259)
    let raw = r#"{
        "toolCall": {
            "name": "run_command",
            "args": {
                "CommandLine": "git status",
                "BypassSandbox": true
            }
        },
        "conversationId": "c",
        "stepIdx": 3
    }"#;
    let input = parse_input(raw).unwrap();
    let decision = Decision::Ask("operator confirmation needed".into());
    assert!(should_demote_sandbox(&input, &decision, kb));

    let rendered = render_for_agy(&decision, true).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&rendered).unwrap();
    assert_eq!(parsed["decision"], "force_ask");
    assert_eq!(
        parsed["reason"],
        "operator confirmation needed"
    );
    assert_eq!(parsed["overwrite"]["BypassSandbox"], false);

    // Network command on Ask does NOT demote
    let network_raw = r#"{
        "toolCall": {
            "name": "run_command",
            "args": {
                "CommandLine": "git push origin master",
                "BypassSandbox": true
            }
        },
        "conversationId": "c",
        "stepIdx": 4
    }"#;
    let network_input = parse_input(network_raw).unwrap();
    assert!(!should_demote_sandbox(&network_input, &decision, kb));
}

#[test]
fn preserves_unsandboxed_for_unmodeled_commands_allow_list_invariant() {
    use vouch::protocol::should_demote_sandbox;
    let kb = vouch::guards::in_effect();

    // Allow-list invariant (§1): unmodeled commands have unknown capability requirements
    // and must NEVER be demoted if the caller requested a sandbox bypass.
    let raw = r#"{
        "toolCall": {
            "name": "run_command",
            "args": {
                "CommandLine": "./scripts/validate-local-code-harness.sh --static",
                "BypassSandbox": true
            }
        },
        "conversationId": "c",
        "stepIdx": 5
    }"#;
    let input = parse_input(raw).unwrap();
    let decision = Decision::Ask("unmodeled_command: ./scripts/validate-local-code-harness.sh".into());
    assert!(!should_demote_sandbox(&input, &decision, kb));

    let unmodeled_bin_raw = r#"{
        "toolCall": {
            "name": "run_command",
            "args": {
                "CommandLine": "my_custom_tool --foo",
                "BypassSandbox": true
            }
        },
        "conversationId": "c",
        "stepIdx": 6
    }"#;
    let unmodeled_input = parse_input(unmodeled_bin_raw).unwrap();
    assert!(!should_demote_sandbox(&unmodeled_input, &decision, kb));

    // A shell executing an external script file runs unmodeled internal code
    // and must NEVER be demoted (runs_file)
    let script_raw = r#"{
        "toolCall": {
            "name": "run_command",
            "args": {
                "CommandLine": "bash scripts/verify.sh",
                "BypassSandbox": true
            }
        },
        "conversationId": "c",
        "stepIdx": 7
    }"#;
    let script_input = parse_input(script_raw).unwrap();
    let allow_decision = Decision::Allow("lang.bash.default = allow".into());
    assert!(!should_demote_sandbox(&script_input, &allow_decision, kb));
}

#[test]
fn ast_capability_demotion_git_log_and_curl_probes() {
    use vouch::protocol::should_demote_sandbox;
    let kb = vouch::guards::in_effect();
    let decision = Decision::Allow("allowed".into());

    let make_input = |cmd: &str| {
        let raw = format!(
            r#"{{
                "toolCall": {{
                    "name": "run_command",
                    "args": {{
                        "CommandLine": {cmd:?},
                        "BypassSandbox": true
                    }}
                }},
                "conversationId": "c",
                "stepIdx": 10
            }}"#
        );
        parse_input(&raw).unwrap()
    };

    // 1. git log with --grep="curl" contains the string "curl" in its args,
    // but AST evaluation proves the command is git log (no network capability) -> demotes!
    let input = make_input("git log --grep=\"curl\"");
    assert!(should_demote_sandbox(&input, &decision, kb));

    // 2. git log | curl ... has curl in the AST pipeline -> preserves bypass!
    let input = make_input("git log | curl -s https://example.com");
    assert!(!should_demote_sandbox(&input, &decision, kb));

    // 3. echo $(curl ...) has curl in a command substitution -> preserves bypass!
    let input = make_input("echo $(curl -s https://example.com)");
    assert!(!should_demote_sandbox(&input, &decision, kb));

    // 4. git push requires network capability -> preserves bypass!
    let input = make_input("git push origin master");
    assert!(!should_demote_sandbox(&input, &decision, kb));

    // 5. git commit modifies refs/locks (external_paths capability) -> preserves bypass!
    let input = make_input("git commit -m 'test'");
    assert!(!should_demote_sandbox(&input, &decision, kb));

    // 6. git checkout modifies worktree/index/refs -> preserves bypass!
    let input = make_input("git checkout master");
    assert!(!should_demote_sandbox(&input, &decision, kb));

    // 7. git diff is a local read-only command -> demotes!
    let input = make_input("git diff");
    assert!(should_demote_sandbox(&input, &decision, kb));
}

#[test]
fn does_not_demote_on_deny() {
    use vouch::protocol::{render_for_agy, should_demote_sandbox};
    let kb = vouch::guards::in_effect();

    let raw = r#"{
        "toolCall": {
            "name": "run_command",
            "args": {
                "CommandLine": "git status",
                "BypassSandbox": true
            }
        },
        "conversationId": "c",
        "stepIdx": 20
    }"#;
    let input = parse_input(raw).unwrap();
    let decision = Decision::Deny("protected path".into());
    assert!(!should_demote_sandbox(&input, &decision, kb));

    let rendered = render_for_agy(&decision, false).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&rendered).unwrap();
    assert_eq!(parsed["decision"], "deny");
    assert!(parsed.get("overwrite").is_none());
}

#[test]
fn subcommand_capability_and_standalone_flags_demotion() {
    use vouch::protocol::should_demote_sandbox;
    let kb = vouch::guards::in_effect();
    let decision = Decision::Allow("allowed".into());

    let make_input = |cmd: &str| {
        let raw = format!(
            r#"{{
                "toolCall": {{
                    "name": "run_command",
                    "args": {{
                        "CommandLine": {cmd:?},
                        "BypassSandbox": true
                    }}
                }},
                "conversationId": "c",
                "stepIdx": 10
            }}"#
        );
        parse_input(&raw).unwrap()
    };

    // 1. gh --help is a standalone flags run -> demotes to sandbox!
    let input = make_input("gh --help");
    assert!(should_demote_sandbox(&input, &decision, kb));

    // 2. gh --version is a standalone flags run -> demotes to sandbox!
    let input = make_input("gh --version");
    assert!(should_demote_sandbox(&input, &decision, kb));

    // 3. gh completion is an offline subcommand -> demotes to sandbox!
    let input = make_input("gh completion -s bash");
    assert!(should_demote_sandbox(&input, &decision, kb));

    // 4. gh pr view requires network -> preserves BypassSandbox: true!
    let input = make_input("gh pr view 42");
    assert!(!should_demote_sandbox(&input, &decision, kb));

    // 5. gh run view requires network -> preserves BypassSandbox: true!
    let input = make_input("gh run view 12345");
    assert!(!should_demote_sandbox(&input, &decision, kb));

    // 6. curl --help is a standalone flags run -> demotes to sandbox!
    let input = make_input("curl --help");
    assert!(should_demote_sandbox(&input, &decision, kb));

    // 7. curl to a URL requires network -> preserves BypassSandbox: true!
    let input = make_input("curl https://example.com");
    assert!(!should_demote_sandbox(&input, &decision, kb));
}

#[test]
fn m2_264_read_path_and_external_argument_scoping() {
    use vouch::protocol::should_demote_sandbox;
    let kb = vouch::guards::in_effect();
    let decision = Decision::Allow("allowed".into());

    let make_input = |cmd: &str| {
        let raw = format!(
            r#"{{
                "toolCall": {{
                    "name": "run_command",
                    "args": {{
                        "CommandLine": {cmd:?},
                        "BypassSandbox": true
                    }}
                }},
                "conversationId": "c-m2-264",
                "stepIdx": 1,
                "cwd": "/workspace/project",
                "workspacePaths": ["/workspace/project"]
            }}"#
        );
        parse_input(&raw).unwrap()
    };

    // 1. Reading home files (e.g. ~/.gemini/settings.json) must NOT demote (preserves BypassSandbox: true)
    let input = make_input("cat ~/.gemini/settings.json");
    assert!(!should_demote_sandbox(&input, &decision, kb));

    // 2. Reading workspace-internal files demotes cleanly to sandbox
    let input = make_input("cat ./README.md");
    assert!(should_demote_sandbox(&input, &decision, kb));

    let input = make_input("cat src/main.rs");
    assert!(should_demote_sandbox(&input, &decision, kb));

    // 3. Absolute path outside workspace (e.g. /tmp or /etc/hosts) must NOT demote
    let input = make_input("ls /tmp");
    assert!(!should_demote_sandbox(&input, &decision, kb));

    let input = make_input("grep 'pattern' /etc/hosts");
    assert!(!should_demote_sandbox(&input, &decision, kb));

    // 4. Directory traversal escaping workspace must NOT demote
    let input = make_input("head -n 10 ../sibling/file");
    assert!(!should_demote_sandbox(&input, &decision, kb));

    // 5. Normal workspace directory listing demotes cleanly
    let input = make_input("ls target/debug");
    assert!(should_demote_sandbox(&input, &decision, kb));

    // 6. Safe bit-bucket sink /dev/null demotes cleanly
    let input = make_input("cat /dev/null");
    assert!(should_demote_sandbox(&input, &decision, kb));

    // 7. Non-path arguments containing slashes or dots must not be falsely classified as external paths
    let input = make_input("echo 'hello/world'");
    assert!(should_demote_sandbox(&input, &decision, kb));

    let input = make_input("git log origin/master..master");
    assert!(should_demote_sandbox(&input, &decision, kb));

    // 8. Flag with external path value (e.g. --config=~/.config/vouch/config.toml) must NOT demote
    let input = make_input("cat --config=~/.config/vouch/config.toml");
    assert!(!should_demote_sandbox(&input, &decision, kb));

    // 9. Script files cannot be demoted because their internal effects are unmodeled (§1)
    let input = make_input("bash ./scripts/test.sh");
    assert!(!should_demote_sandbox(&input, &decision, kb));

    let input = make_input("bash scripts/githooks/test-hooks.sh && bash scripts/test-uninstall.sh");
    assert!(!should_demote_sandbox(&input, &decision, kb));

    // 10. Script files targeting external paths must NOT demote (preserves BypassSandbox: true)
    let input = make_input("bash /tmp/test.sh");
    assert!(!should_demote_sandbox(&input, &decision, kb));

    let input = make_input("bash ~/.config/evil.sh");
    assert!(!should_demote_sandbox(&input, &decision, kb));

    // 11. Script file with unknowable target (undescribed options) must NOT demote
    let input = make_input("bash --unknown-option test.sh");
    assert!(!should_demote_sandbox(&input, &decision, kb));

    // 12. Command head targeting external path must NOT demote (preserves BypassSandbox: true)
    let input = make_input("~/.config/vouch/bin/vouch --version");
    assert!(!should_demote_sandbox(&input, &decision, kb));

    let input = make_input("/opt/bin/tool --help");
    assert!(!should_demote_sandbox(&input, &decision, kb));

    let input = make_input("../sibling/bin/tool --version");
    assert!(!should_demote_sandbox(&input, &decision, kb));

    // 13. Command head targeting workspace-contained path demotes cleanly
    let input = make_input("/workspace/project/bin/git --version");
    assert!(should_demote_sandbox(&input, &decision, kb));
}

#[test]
fn m2_265_workspace_write_containment_and_robust_sandbox_execution() {
    use vouch::protocol::should_demote_sandbox;
    let kb = vouch::guards::in_effect();
    let decision = Decision::Allow("allowed".into());

    let make_input = |cmd: &str| {
        let raw = format!(
            r#"{{
                "toolCall": {{
                    "name": "run_command",
                    "args": {{
                        "CommandLine": {cmd:?},
                        "BypassSandbox": true
                    }}
                }},
                "conversationId": "c-m2-265",
                "stepIdx": 1,
                "cwd": "/workspace/project",
                "workspacePaths": ["/workspace/project"]
            }}"#
        );
        parse_input(&raw).unwrap()
    };

    // 1. git add modifies index and creates lock file -> preserves BypassSandbox: true
    let input = make_input("git add .");
    assert!(!should_demote_sandbox(&input, &decision, kb));

    let input = make_input("git add src/main.rs");
    assert!(!should_demote_sandbox(&input, &decision, kb));

    // 2. git rm and git clean modify worktree/index -> preserves BypassSandbox: true
    let input = make_input("git rm file.rs");
    assert!(!should_demote_sandbox(&input, &decision, kb));

    let input = make_input("git clean -fd");
    assert!(!should_demote_sandbox(&input, &decision, kb));

    // 3. Shell redirection write targets -> preserves BypassSandbox: true
    let input = make_input("echo 'hello' > output.txt");
    assert!(!should_demote_sandbox(&input, &decision, kb));

    let input = make_input("cargo check > build.log");
    assert!(!should_demote_sandbox(&input, &decision, kb));

    // 4. File-mutating commands (touch, rm) -> preserves BypassSandbox: true
    let input = make_input("touch src/new_file.rs");
    assert!(!should_demote_sandbox(&input, &decision, kb));

    let input = make_input("rm src/temp.rs");
    assert!(!should_demote_sandbox(&input, &decision, kb));

    // 5. Pure read-only commands continue to demote to sandbox cleanly
    let input = make_input("git status");
    assert!(should_demote_sandbox(&input, &decision, kb));

    let input = make_input("git diff");
    assert!(should_demote_sandbox(&input, &decision, kb));

    let input = make_input("git log -n 5");
    assert!(should_demote_sandbox(&input, &decision, kb));
}



