//! The hook registration vouch needs, and the safety of the shadow variant.

use vouch::cli::{
    parse_hook_options, parse_install_args, parse_install_options, parse_uninstall_options,
    InstallHost, InstallShell,
};
use vouch::install::{
    plan, plan_agy, plan_codex, plan_codex_with_state, plan_with_state, unplan, unplan_agy,
    unplan_codex, write_file_atomically,
};

const EXISTING: &str = r#"{
  "model": "opus",
  "hooks": {
    "PreToolUse": [
      { "hooks": [ { "type": "command", "command": "C:/workspace/cc-allow/cc-allow.exe --hook" } ] }
    ]
  }
}"#;

#[test]
fn shadow_leaves_the_existing_gate_in_charge() {
    let p = plan(EXISTING, "C:/workspace/vouch-dev/vouch.exe", true).unwrap();
    assert!(
        p.settings.contains("cc-allow.exe --hook"),
        "existing gate removed: {}",
        p.settings
    );
    assert!(p.settings.contains("'C:/workspace/vouch-dev/vouch.exe' --hook --shadow"));
}

#[test]
fn live_replaces_the_existing_gate() {
    let p = plan(EXISTING, "C:/workspace/vouch-dev/vouch.exe", false).unwrap();
    let root: serde_json::Value = serde_json::from_str(&p.settings).unwrap();
    let pre = root["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        .as_str()
        .unwrap();
    assert!(
        !pre.contains("cc-allow"),
        "cc-allow still in PreToolUse: {pre}"
    );
    assert!(pre.contains("'C:/workspace/vouch-dev/vouch.exe' --hook"));
    assert!(
        pre.contains("permissionDecision") && pre.contains("deny"),
        "live PreToolUse must fail closed when binary is missing: {pre}"
    );
    assert!(!pre.contains("--shadow"), "live mode must not be shadow");
}

#[test]
fn the_three_outcome_events_are_always_registered() {
    for shadow in [true, false] {
        let p = plan(EXISTING, "C:/vouch.exe", shadow).unwrap();
        for ev in ["PostToolUse", "PostToolUseFailure", "PermissionDenied"] {
            assert!(p.settings.contains(ev), "{ev} missing (shadow={shadow})");
        }
    }
}

#[test]
fn other_settings_are_preserved() {
    let p = plan(EXISTING, "C:/vouch.exe", true).unwrap();
    assert!(p.settings.contains("\"model\""), "unrelated settings lost");
}

#[test]
fn running_it_twice_does_not_duplicate_entries() {
    let once = plan(EXISTING, "C:/vouch.exe", true).unwrap().settings;
    let twice = plan(&once, "C:/vouch.exe", true).unwrap().settings;
    assert_eq!(twice.matches("--shadow").count(), 1, "duplicated: {twice}");
    assert_eq!(
        twice.matches("PostToolUseFailure").count(),
        1,
        "duplicated event: {twice}"
    );
}

#[test]
fn an_empty_settings_file_is_handled() {
    let p = plan("", "C:/vouch.exe", false).unwrap();
    assert!(p.settings.contains("PreToolUse"));
}

#[test]
fn malformed_settings_are_refused_not_overwritten() {
    assert!(plan("{not json", "C:/vouch.exe", false).is_err());
}

#[test]
fn the_notes_say_plainly_what_changes() {
    let p = plan(EXISTING, "C:/vouch.exe", false).unwrap();
    let joined = p.notes.join(" ");
    assert!(joined.contains("cc-allow was REMOVED"), "got: {joined}");
    let s = plan(EXISTING, "C:/vouch.exe", true).unwrap();
    assert!(
        s.notes.join(" ").contains("emits nothing"),
        "got: {:?}",
        s.notes
    );
}

const EXISTING_WITH_SERVER: &str = r#"{
  "model": "opus",
  "mcpServers": { "example": { "url": "https://example.invalid", "headers": { "x-sample": "placeholder" } } },
  "hooks": {
    "PreToolUse": [
      { "hooks": [ { "type": "command", "command": "C:/workspace/cc-allow/cc-allow.exe --hook" } ] }
    ]
  }
}"#;

#[test]
fn the_hooks_only_view_carries_no_server_content() {
    let p = plan(EXISTING_WITH_SERVER, "C:/vouch.exe", false).unwrap();
    assert!(
        !p.hooks_view.contains("mcpServers"),
        "server block leaked: {}",
        p.hooks_view
    );
    assert!(!p.hooks_view.contains("x-sample"));
    assert!(!p.hooks_view.contains("model"));
    for ev in [
        "PreToolUse",
        "PostToolUse",
        "PostToolUseFailure",
        "PermissionDenied",
    ] {
        assert!(
            p.hooks_view.contains(ev),
            "{ev} missing from the hooks view"
        );
    }
}

#[test]
fn the_full_document_still_carries_everything() {
    let p = plan(EXISTING_WITH_SERVER, "C:/vouch.exe", false).unwrap();
    assert!(
        p.settings.contains("mcpServers"),
        "full form must keep the document whole"
    );
}

// `vouch install` argument parsing. main.rs calls `parse_install_args` before
// reading `settings.json` or printing anything, so an unrecognised argument
// is refused here rather than silently falling through to the bare-install
// form — the incident this guards against: an out-of-scope `install --help`
// probe fell through and printed the full merged document instead of a usage
// line.

#[test]
fn bare_install_takes_neither_flag() {
    let (shadow, hooks_only) = parse_install_args(&[]).unwrap();
    assert!(!shadow);
    assert!(!hooks_only);
}

#[test]
fn shadow_flag_is_recognised() {
    let args = vec!["--shadow".to_string()];
    let (shadow, hooks_only) = parse_install_args(&args).unwrap();
    assert!(shadow);
    assert!(!hooks_only);
}

#[test]
fn print_flag_is_recognised() {
    let args = vec!["--print".to_string()];
    let (shadow, hooks_only) = parse_install_args(&args).unwrap();
    assert!(!shadow);
    assert!(hooks_only);
}

#[test]
fn both_recognised_flags_together_are_accepted_in_either_order() {
    let args = vec!["--print".to_string(), "--shadow".to_string()];
    let (shadow, hooks_only) = parse_install_args(&args).unwrap();
    assert!(shadow);
    assert!(hooks_only);
}

#[test]
fn an_unrecognised_flag_is_refused() {
    let args = vec!["--help".to_string()];
    let err = parse_install_args(&args).unwrap_err();
    assert!(
        err.contains("--help"),
        "error does not name the bad flag: {err}"
    );
    assert!(
        err.contains("usage: vouch install"),
        "error carries no usage line: {err}"
    );
}

#[test]
fn a_stray_positional_argument_is_refused() {
    let args = vec!["shadow".to_string()];
    assert!(
        parse_install_args(&args).is_err(),
        "a bare word with no dashes must not be silently accepted"
    );
}

#[test]
fn a_recognised_flag_beside_an_unrecognised_one_is_still_refused() {
    let args = vec!["--shadow".to_string(), "--bogus".to_string()];
    let err = parse_install_args(&args).unwrap_err();
    assert!(
        err.contains("--bogus"),
        "error does not name the bad flag: {err}"
    );
}

const MOVED_CLAUDE_HOOKS: &str = r#"{
  "hooks": {
    "PreToolUse": [
      { "hooks": [ { "type": "command", "command": "C:/old/vouch.exe --hook" } ] }
    ],
    "PostToolUse": [
      { "hooks": [ { "type": "command", "command": "C:/other/tool.exe observe" } ] },
      { "hooks": [ { "type": "command", "command": "C:/old/vouch.exe --hook" } ] }
    ],
    "PostToolUseFailure": [
      { "hooks": [ { "type": "command", "command": "C:/old/vouch.exe --hook" } ] }
    ],
    "PermissionDenied": [
      { "hooks": [ { "type": "command", "command": "C:/old/vouch.exe --hook" } ] }
    ]
  }
}"#;

#[test]
fn claude_repoints_a_moved_binary_on_every_event() {
    let p = plan(MOVED_CLAUDE_HOOKS, "C:/new/vouch.exe", false).unwrap();
    assert!(!p.settings.contains("C:/old/vouch.exe"));
    assert_eq!(p.settings.matches("'C:/new/vouch.exe' --hook").count(), 4);
    assert!(p.settings.contains("C:/other/tool.exe observe"));
    assert!(p.notes.join(" ").contains("4 existing vouch hook(s)"));
}

#[test]
fn claude_shadow_stands_a_repointed_live_gate_down() {
    let p = plan(MOVED_CLAUDE_HOOKS, "C:/new/vouch.exe", true).unwrap();
    let root: serde_json::Value = serde_json::from_str(&p.settings).unwrap();
    let pre = root["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        .as_str()
        .unwrap();
    assert!(pre.contains("'C:/new/vouch.exe' --hook --shadow"));
    assert!(!pre.contains("permissionDecision"), "shadow PreToolUse must stay non-disruptive: {pre}");
    assert!(p.notes.join(" ").contains("stood down"));
}

#[test]
fn claude_quotes_an_executable_path_with_spaces() {
    let p = plan("{}", "C:/Program Files/vouch/bin/vouch.exe", false).unwrap();
    assert!(p.settings.contains("'C:/Program Files/vouch/bin/vouch.exe' --hook"));
}

#[test]
fn claude_recognises_a_quoted_registration_without_duplication() {
    let existing = r#"{
      "hooks": {
        "PostToolUse": [
          { "hooks": [ { "type": "command", "command": "\"C:/My Tools/vouch.exe\" --hook" } ] }
        ]
      }
    }"#;
    let p = plan(existing, "C:/new/vouch.exe", false).unwrap();
    assert!(!p.settings.contains("My Tools"));
    let root: serde_json::Value = serde_json::from_str(&p.settings).unwrap();
    let post = root["hooks"]["PostToolUse"].as_array().unwrap();
    assert_eq!(post.len(), 1);
    assert!(post[0]["hooks"][0]["command"]
        .as_str()
        .unwrap()
        .contains("'C:/new/vouch.exe' --hook"));
}

#[test]
fn claude_does_not_claim_a_lookalike_hook() {
    let existing = r#"{
      "hooks": {
        "PostToolUse": [
          { "hooks": [ { "type": "command", "command": "C:/bin/notvouch.exe --hook" } ] }
        ]
      }
    }"#;
    let p = plan(existing, "C:/new/vouch.exe", false).unwrap();
    assert!(p.settings.contains("C:/bin/notvouch.exe --hook"));
    assert!(p.settings.contains("'C:/new/vouch.exe' --hook"));
}

#[test]
fn codex_install_flags_are_explicit_and_order_independent() {
    let args = vec![
        "--shell".to_string(),
        "powershell".to_string(),
        "--host".to_string(),
        "codex".to_string(),
        "--print".to_string(),
    ];
    let got = parse_install_options(&args).unwrap();
    assert_eq!(got.host, InstallHost::Codex);
    assert_eq!(got.shell, Some(InstallShell::PowerShell));
    assert!(got.hooks_only);
    assert!(!got.shadow);
}

#[test]
fn codex_install_requires_an_explicit_shell() {
    let args = vec!["--host".to_string(), "codex".to_string()];
    let err = parse_install_options(&args).unwrap_err();
    assert!(err.contains("--shell"), "got: {err}");
}

#[test]
fn codex_hook_requires_the_same_explicit_shell_adapter() {
    let missing = vec![
        "--hook".to_string(),
        "--host".to_string(),
        "codex".to_string(),
    ];
    assert!(parse_hook_options(&missing).is_err());
    let complete = vec![
        "--hook".to_string(),
        "--host".to_string(),
        "codex".to_string(),
        "--shell".to_string(),
        "powershell".to_string(),
    ];
    let got = parse_hook_options(&complete).unwrap();
    assert_eq!(got.host, InstallHost::Codex);
    assert_eq!(got.shell, Some(InstallShell::PowerShell));
}

#[test]
fn hook_batch_is_explicit_and_mutually_exclusive_with_the_native_hook() {
    let batch = vec!["--hook-batch".to_string()];
    assert!(parse_hook_options(&batch).unwrap().batch);

    let both = vec!["--hook".to_string(), "--hook-batch".to_string()];
    assert!(parse_hook_options(&both).is_err());

    let neither = Vec::new();
    assert!(parse_hook_options(&neither).is_err());
}

#[test]
fn codex_state_dir_is_absolute_and_reaches_both_parsers() {
    let install = vec![
        "--host".to_string(),
        "codex".to_string(),
        "--shell".to_string(),
        "bash".to_string(),
        "--state-dir".to_string(),
        "/tmp/vouch-codex".to_string(),
    ];
    let got = parse_install_options(&install).unwrap();
    assert_eq!(got.state_dir.as_deref(), Some("/tmp/vouch-codex"));

    let hook = vec!["--hook".to_string()]
        .into_iter()
        .chain(install)
        .collect::<Vec<_>>();
    let got = parse_hook_options(&hook).unwrap();
    assert_eq!(got.state_dir.as_deref(), Some("/tmp/vouch-codex"));

    for bad in ["relative/state", "state"] {
        let args = vec![
            "--host".to_string(),
            "codex".to_string(),
            "--shell".to_string(),
            "bash".to_string(),
            "--state-dir".to_string(),
            bad.to_string(),
        ];
        assert!(parse_install_options(&args).is_err(), "accepted {bad:?}");
    }
    // Claude now also accepts an explicit absolute --state-dir symmetrically with Codex and Agy.
    let claude_state = parse_install_options(&["--state-dir".into(), "/tmp/vouch".into()]).unwrap();
    assert_eq!(claude_state.host, InstallHost::Claude);
    assert_eq!(claude_state.state_dir.as_deref(), Some("/tmp/vouch"));
    let claude_hook_state =
        parse_hook_options(&["--hook".into(), "--state-dir".into(), "/tmp/vouch".into()]).unwrap();
    assert_eq!(claude_hook_state.host, InstallHost::Claude);
    assert_eq!(claude_hook_state.state_dir.as_deref(), Some("/tmp/vouch"));
}

#[test]
fn claude_install_rejects_a_shell_override() {
    let args = vec!["--shell".to_string(), "bash".to_string()];
    assert!(parse_install_options(&args).is_err());
}

#[test]
fn codex_live_install_preserves_unrelated_hooks_and_replaces_only_vouch() {
    let existing = r#"{
      "hooks": {
        "PreToolUse": [
          {"matcher":".*","hooks":[{"type":"command","command":"other-gate"}]},
          {"matcher":".*","hooks":[{"type":"command","command":"other-gate --host codex"}]},
          {"matcher":".*","hooks":[{"type":"command","command":"other-gate --hook --host codex","statusMessage":"another hook"}]},
          {"matcher":".*","hooks":[{"type":"command","command":"old-vouch --hook --host codex","statusMessage":"vouch is checking this tool call"}]}
        ],
        "PostToolUse": []
      }
    }"#;
    let p = plan_codex(
        existing,
        "C:/Vouch Bin/vouch.exe",
        InstallShell::PowerShell,
        false,
    )
    .unwrap();
    assert!(
        p.settings.contains("other-gate"),
        "unrelated hook lost: {}",
        p.settings
    );
    assert!(
        p.settings.contains("other-gate --host codex"),
        "an unrelated command using the same generic flags was removed: {}",
        p.settings
    );
    assert!(
        p.settings.contains("other-gate --hook --host codex"),
        "an unrelated hook using the same generic flags was removed: {}",
        p.settings
    );
    assert!(
        !p.settings.contains("old-vouch"),
        "old vouch hook survived: {}",
        p.settings
    );
    assert!(p.settings.contains("--host codex --shell powershell"));
    assert!(p.settings.contains("PostToolUse"));
    assert!(!p.settings.contains("PostToolUseFailure"));
    assert!(!p.settings.contains("PermissionDenied"));
    assert!(
        p.notes
            .iter()
            .any(|note| note.contains("codex mcp add vouch_approval")
                && note.contains("vouch-codex-broker.exe")),
        "broker registration missing: {:?}",
        p.notes
    );
    assert!(
        p.notes.iter().any(|note| {
            note.contains("approvals_reviewer = \"user\"")
                && note.contains("default_tools_approval_mode = \"prompt\"")
                && note.contains("native MCP prompt")
        }),
        "broker approval configuration missing: {:?}",
        p.notes
    );
}

#[test]
fn codex_shadow_is_idempotent() {
    let once = plan_codex("", "C:/vouch.exe", InstallShell::Bash, true)
        .unwrap()
        .settings;
    let twice = plan_codex(&once, "C:/vouch.exe", InstallShell::Bash, true)
        .unwrap()
        .settings;
    assert_eq!(
        twice.matches("--host codex").count(),
        2,
        "one Pre and one Post hook: {twice}"
    );
    assert_eq!(
        twice.matches("--shadow").count(),
        1,
        "shadow Pre duplicated: {twice}"
    );
}

#[test]
fn codex_passive_shadow_has_one_stable_host_attributed_journal_and_no_broker_notes() {
    let state = "/tmp/vouch codex journal";
    let once = plan_codex_with_state("", "/opt/Vouch Bin/vouch", InstallShell::Bash, true, state)
        .unwrap();
    let twice = plan_codex_with_state(
        &once.settings,
        "/opt/Vouch Bin/vouch",
        InstallShell::Bash,
        true,
        state,
    )
    .unwrap();
    let root: serde_json::Value = serde_json::from_str(&twice.settings).unwrap();
    let command = |event: &str| {
        root["hooks"][event][0]["hooks"][0]["command"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let pre = command("PreToolUse");
    let post = command("PostToolUse");
    assert!(pre.contains("--shadow"));
    assert!(!post.contains("--shadow"));
    for cmd in [&pre, &post] {
        assert!(cmd.contains("--state-dir"), "missing state dir: {cmd}");
        assert!(cmd.contains(state), "wrong state dir: {cmd}");
    }
    assert_eq!(twice.settings.matches("--host codex").count(), 2);
    let notes = twice.notes.join("\n");
    assert!(!notes.contains("vouch_approval"), "shadow cannot need a broker: {notes}");
    assert!(!notes.contains("approvals_reviewer = \"user\""), "shadow cannot disable auto-review: {notes}");
    assert!(notes.contains("emits no decision"), "passive behavior unstated: {notes}");
}

#[test]
fn agy_install_options_and_hook_options_parsing() {
    let args = vec![
        "--host".into(),
        "agy".into(),
        "--shadow".into(),
        "--state-dir".into(),
        "/tmp/vouch-agy".into(),
        "--print".into(),
    ];
    let got = parse_install_options(&args).unwrap();
    assert_eq!(got.host, InstallHost::Agy);
    assert!(got.shadow);
    assert!(got.hooks_only);
    assert_eq!(got.state_dir.as_deref(), Some("/tmp/vouch-agy"));
    assert!(got.shell.is_none());

    let hook_args = vec![
        "--hook".into(),
        "--host".into(),
        "agy".into(),
        "--state-dir".into(),
        "/tmp/vouch-agy".into(),
    ];
    let got_hook = parse_hook_options(&hook_args).unwrap();
    assert_eq!(got_hook.host, InstallHost::Agy);
    assert_eq!(got_hook.state_dir.as_deref(), Some("/tmp/vouch-agy"));

    // Reject shell with agy
    let bad_args = vec![
        "--host".into(),
        "agy".into(),
        "--shell".into(),
        "bash".into(),
    ];
    assert!(parse_install_options(&bad_args).is_err());
    let bad_hook = vec![
        "--hook".into(),
        "--host".into(),
        "agy".into(),
        "--shell".into(),
        "bash".into(),
    ];
    assert!(parse_hook_options(&bad_hook).is_err());
}

#[test]
fn agy_plan_generation_and_idempotency() {
    let existing = r#"{
      "other_plugin": {
        "PreToolUse": [{"matcher": ".*", "hooks": [{"type": "command", "command": "other-gate"}]}]
      }
    }"#;
    let exe = "/opt/Vouch Bin/vouch";
    let state = "/tmp/vouch agy state";
    let p = plan_agy(existing, exe, true, Some(state)).unwrap();

    let root: serde_json::Value = serde_json::from_str(&p.settings).unwrap();
    assert!(root.get("other_plugin").is_some(), "other_plugin lost");
    let vouch_group = root.get("vouch").expect("vouch group missing");
    let pre_matcher = vouch_group["PreToolUse"][0]["matcher"].as_str().unwrap();
    let post_matcher = vouch_group["PostToolUse"][0]["matcher"].as_str().unwrap();
    for expected_tool in [
        "run_command",
        "write_file",
        "edit_file",
        "write_to_file",
        "replace_file_content",
    ] {
        assert!(
            pre_matcher.split('|').any(|t| t == expected_tool),
            "PreToolUse matcher missing {expected_tool}: {pre_matcher}"
        );
        assert!(
            post_matcher.split('|').any(|t| t == expected_tool),
            "PostToolUse matcher missing {expected_tool}: {post_matcher}"
        );
    }
    let pre_cmd = vouch_group["PreToolUse"][0]["hooks"][0]["command"]
        .as_str()
        .unwrap();
    let post_cmd = vouch_group["PostToolUse"][0]["hooks"][0]["command"]
        .as_str()
        .unwrap();

    assert!(
        pre_cmd.contains("'/opt/Vouch Bin/vouch' --hook --host agy --shadow --state-dir '/tmp/vouch agy state'"),
        "unexpected shadow pre_cmd: {pre_cmd}"
    );
    assert!(
        !pre_cmd.contains("\"decision\":\"deny\""),
        "shadow PreToolUse must stay non-disruptive: {pre_cmd}"
    );
    assert!(
        post_cmd.contains("'/opt/Vouch Bin/vouch' --hook --host agy --state-dir '/tmp/vouch agy state'")
            && post_cmd.contains("printf '%s\\n' '{}'"),
        "unexpected post_cmd: {post_cmd}"
    );
    assert!(!post_cmd.contains("--shadow"));

    // Idempotent: running again produces identical vouch config
    let p2 = plan_agy(&p.settings, exe, true, Some(state)).unwrap();
    let root2: serde_json::Value = serde_json::from_str(&p2.settings).unwrap();
    assert_eq!(root, root2);

    // Live mode with an explicit Unix path (deterministic across Unix and Windows CI)
    let p_live = plan_agy("", "/usr/local/bin/vouch", false, None).unwrap();
    let root_live: serde_json::Value = serde_json::from_str(&p_live.settings).unwrap();
    let live_pre = root_live["vouch"]["PreToolUse"][0]["hooks"][0]["command"]
        .as_str()
        .unwrap();
    assert!(
        live_pre.contains("'/usr/local/bin/vouch' --hook --host agy")
            && live_pre.contains("\"decision\":\"deny\""),
        "live Agy PreToolUse must fail closed: {live_pre}"
    );
    let live_post = root_live["vouch"]["PostToolUse"][0]["hooks"][0]["command"]
        .as_str()
        .unwrap();
    assert!(
        live_post.contains("'/usr/local/bin/vouch' --hook --host agy")
            && live_post.contains("printf '%s\\n' '{}'"),
        "live Agy PostToolUse must stay non-disruptive: {live_post}"
    );
}

#[test]
fn install_write_flag_parsed_correctly() {
    let args = vec!["--write".to_string()];
    let got = parse_install_options(&args).unwrap();
    assert!(got.write);
    assert!(!got.hooks_only);

    let conflict = vec!["--print".to_string(), "--write".to_string()];
    let err = parse_install_options(&conflict).unwrap_err();
    assert!(err.contains("--print and --write cannot be used together"), "got: {err}");
}

#[test]
fn uninstall_options_parsing() {
    let bare = parse_uninstall_options(&[]).unwrap();
    assert_eq!(bare.host, InstallHost::Claude);
    assert!(!bare.write);

    let with_write = parse_uninstall_options(&["--write".into()]).unwrap();
    assert_eq!(with_write.host, InstallHost::Claude);
    assert!(with_write.write);

    let agy = parse_uninstall_options(&["--host".into(), "agy".into(), "--write".into()]).unwrap();
    assert_eq!(agy.host, InstallHost::Agy);
    assert!(agy.write);

    let codex = parse_uninstall_options(&["--host".into(), "codex".into()]).unwrap();
    assert_eq!(codex.host, InstallHost::Codex);
    assert!(!codex.write);

    let missing_val = parse_uninstall_options(&["--host".into()]);
    assert!(missing_val.is_err());
    assert!(missing_val.unwrap_err().contains("needs a value"));

    let unknown = parse_uninstall_options(&["--bogus".into()]);
    assert!(unknown.is_err());
    assert!(unknown.unwrap_err().contains("usage: vouch uninstall"));
}

#[test]
fn claude_unplan_removes_vouch_and_preserves_others() {
    let planned = plan(EXISTING_WITH_SERVER, "C:/workspace/vouch.exe", false).unwrap();
    assert!(planned.settings.contains("'C:/workspace/vouch.exe' --hook"));
    assert!(planned.settings.contains("mcpServers"));

    let unp = unplan(&planned.settings).unwrap();
    assert!(!unp.settings.contains("vouch"));
    assert!(unp.settings.contains("mcpServers"));
    assert!(unp.settings.contains("opus"));
    assert!(unp.notes.iter().any(|n| n.contains("removed from Claude settings.json")));

    // When only vouch hooks were installed in a blank config, hooks object is pruned
    let planned_blank = plan("{}", "C:/workspace/vouch.exe", false).unwrap();
    let unp_blank = unplan(&planned_blank.settings).unwrap();
    let root: serde_json::Value = serde_json::from_str(&unp_blank.settings).unwrap();
    assert!(root.get("hooks").is_none(), "empty hooks object should be cleaned up: {}", unp_blank.settings);
}

#[test]
fn codex_unplan_removes_vouch_and_preserves_others() {
    let existing = r#"{
      "hooks": {
        "PreToolUse": [
          {"matcher":".*","hooks":[{"type":"command","command":"other-gate"}]},
          {"matcher":".*","hooks":[{"type":"command","command":"C:/vouch.exe --hook --host codex --shell bash","statusMessage":"vouch is checking this tool call"}]}
        ],
        "PostToolUse": [
          {"matcher":".*","hooks":[{"type":"command","command":"C:/vouch.exe --hook --host codex --shell bash","statusMessage":"vouch is checking this tool call"}]}
        ]
      }
    }"#;

    let unp = unplan_codex(existing).unwrap();
    assert!(!unp.settings.contains("vouch.exe"));
    assert!(unp.settings.contains("other-gate"));
    let root: serde_json::Value = serde_json::from_str(&unp.settings).unwrap();
    assert!(root["hooks"]["PreToolUse"].as_array().unwrap().len() == 1);
    assert!(root["hooks"].get("PostToolUse").is_none());
}

#[test]
fn agy_unplan_removes_vouch_group_and_preserves_others() {
    let existing = r#"{
      "other_plugin": {
        "PreToolUse": [{"matcher": ".*", "hooks": [{"type": "command", "command": "other-gate"}]}]
      }
    }"#;
    let planned = plan_agy(existing, "/opt/vouch", false, None).unwrap();
    assert!(planned.settings.contains("\"vouch\""));
    assert!(planned.settings.contains("other-gate"));

    let unp = unplan_agy(&planned.settings).unwrap();
    assert!(!unp.settings.contains("\"vouch\""));
    assert!(unp.settings.contains("other-gate"));
    assert!(unp.notes.iter().any(|n| n.contains("vouch hook group removed")));
}

#[test]
fn write_file_atomically_creates_parent_dirs_and_writes() {
    let dir = std::env::temp_dir().join(format!("vouch_test_atomic_{}", std::process::id()));
    let target = dir.join("sub/dir/config.json");
    let content = "{\"test\": true}";

    write_file_atomically(&target, content).unwrap();
    let read_back = std::fs::read_to_string(&target).unwrap();
    assert_eq!(read_back, content);

    // Overwrite atomically
    let updated = "{\"test\": false}";
    write_file_atomically(&target, updated).unwrap();
    let read_back2 = std::fs::read_to_string(&target).unwrap();
    assert_eq!(read_back2, updated);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn reconciles_agy_permissions_cleanly() {
    use vouch::install::{reconcile_agy_permissions, DEFAULT_AGY_UNSANDBOXED_TOOLS};

    let existing = r#"{
      "permissions": {
        "allow": ["command(bash*)", "unsandboxed(git*)"]
      }
    }"#;

    let reconciled = reconcile_agy_permissions(existing, DEFAULT_AGY_UNSANDBOXED_TOOLS).unwrap();
    let root: serde_json::Value = serde_json::from_str(&reconciled).unwrap();
    let allow = root["permissions"]["allow"].as_array().unwrap();

    // Preserved existing
    assert!(allow.contains(&serde_json::Value::String("command(bash*)".into())));
    assert!(allow.contains(&serde_json::Value::String("unsandboxed(git*)".into())));

    // Added new modeled tools
    assert!(allow.contains(&serde_json::Value::String("unsandboxed(cargo*)".into())));
    assert!(allow.contains(&serde_json::Value::String("unsandboxed(gh*)".into())));
    assert!(allow.contains(&serde_json::Value::String("unsandboxed(vouch*)".into())));
    assert!(allow.contains(&serde_json::Value::String("unsandboxed(GIT_CONFIG_GLOBAL=*)".into())));
    assert!(allow.contains(&serde_json::Value::String("unsandboxed(bash*)".into())));

    // Added spaced token rules for bare and multi-token execution under Antigravity
    assert!(allow.contains(&serde_json::Value::String("command(cargo)".into())));
    assert!(allow.contains(&serde_json::Value::String("command(cargo *)".into())));
    assert!(allow.contains(&serde_json::Value::String("command(git)".into())));
    assert!(allow.contains(&serde_json::Value::String("command(git *)".into())));
    assert!(allow.contains(&serde_json::Value::String("command(kubectl)".into())));
    assert!(allow.contains(&serde_json::Value::String("command(kubectl *)".into())));
    assert!(allow.contains(&serde_json::Value::String("command(grep)".into())));
    assert!(allow.contains(&serde_json::Value::String("command(grep *)".into())));
    assert!(allow.contains(&serde_json::Value::String("command(file)".into())));
    assert!(allow.contains(&serde_json::Value::String("command(file *)".into())));
    assert!(allow.contains(&serde_json::Value::String("command(vouch)".into())));
    assert!(allow.contains(&serde_json::Value::String("command(vouch *)".into())));
    assert!(allow.contains(&serde_json::Value::String("command(bash)".into())));
    assert!(allow.contains(&serde_json::Value::String("command(bash *)".into())));
    assert!(allow.contains(&serde_json::Value::String("command(GIT_CONFIG_GLOBAL=*)".into())));
    assert!(allow.contains(&serde_json::Value::String("command(GIT_CONFIG_GLOBAL=* *)".into())));

    // Sets toolPermission to always-proceed and disables the duplicate terminal sandbox so vouch remains the sole gate
    assert_eq!(root["toolPermission"], "always-proceed");
    assert_eq!(root["enableTerminalSandbox"], false);

    // Added workspace script and kubectl execution patterns
    assert!(allow.contains(&serde_json::Value::String("command(bash scripts/**)".into())));
    assert!(allow.contains(&serde_json::Value::String("command(./scripts/**)".into())));
    assert!(allow.contains(&serde_json::Value::String("command(target/debug/*)".into())));
    assert!(allow.contains(&serde_json::Value::String("command(target/debug/vouch)".into())));
    // Added git and cargo subcommands
    assert!(allow.contains(&serde_json::Value::String("command(git add*)".into())));
    assert!(allow.contains(&serde_json::Value::String("command(git commit*)".into())));
    assert!(allow.contains(&serde_json::Value::String("command(cargo build*)".into())));
    assert!(allow.contains(&serde_json::Value::String("command(cargo test*)".into())));

    // Idempotent: running again produces identical output
    let reconciled2 = reconcile_agy_permissions(&reconciled, DEFAULT_AGY_UNSANDBOXED_TOOLS).unwrap();
    assert_eq!(reconciled, reconciled2);
}

#[test]
fn claude_live_preserves_unrelated_pre_hooks_repoints_wrapped_and_supports_state_dir() {
    let existing = r#"{
      "hooks": {
        "PreToolUse": [
          { "hooks": [ { "type": "command", "command": "C:/workspace/cc-allow/cc-allow.exe --hook" } ] },
          { "hooks": [ { "type": "command", "command": "/usr/local/bin/other-guard check" } ] }
        ]
      }
    }"#;
    let first = plan_with_state(existing, "/opt/old/vouch", false, Some("/tmp/vouch state")).unwrap();
    let root1: serde_json::Value = serde_json::from_str(&first.settings).unwrap();
    let pre1 = root1["hooks"]["PreToolUse"].as_array().unwrap();
    assert_eq!(pre1.len(), 2, "must retain unrelated guard and add vouch: {pre1:?}");
    assert!(first.settings.contains("/usr/local/bin/other-guard check"));
    assert!(!first.settings.contains("cc-allow"));
    assert!(first.settings.contains("--state-dir '/tmp/vouch state'"));
    assert!(first.notes.join(" ").contains("cc-allow was REMOVED"));

    // Repoint wrapped hooks to a new path containing spaces and single quotes
    let moved = plan_with_state(
        &first.settings,
        "/opt/it's my/vouch",
        false,
        Some("/tmp/vouch state"),
    )
    .unwrap();
    assert!(!moved.settings.contains("/opt/old/vouch"));
    assert!(moved.settings.contains("/usr/local/bin/other-guard check"));
    assert!(moved.notes.join(" ").contains("4 existing vouch hook(s)"));

    // Idempotent second run produces zero repoint notes and identical hooks
    let again = plan_with_state(
        &moved.settings,
        "/opt/it's my/vouch",
        false,
        Some("/tmp/vouch state"),
    )
    .unwrap();
    assert_eq!(moved.settings, again.settings);
    assert!(!again.notes.join(" ").contains("repointed"));

    // Standing down wrapped live PreToolUse to shadow
    let stood_down = plan_with_state(
        &moved.settings,
        "/opt/it's my/vouch",
        true,
        Some("/tmp/vouch state"),
    )
    .unwrap();
    assert!(stood_down.notes.join(" ").contains("stood down"));
    let root_sd: serde_json::Value = serde_json::from_str(&stood_down.settings).unwrap();
    let pre_sd = root_sd["hooks"]["PreToolUse"][1]["hooks"][0]["command"]
        .as_str()
        .unwrap();
    assert!(pre_sd.contains("--shadow") && !pre_sd.contains("permissionDecision"));

    // Unplan cleanly strips all 4 wrapped hooks while keeping the unrelated PreToolUse guard
    let removed = unplan(&moved.settings).unwrap();
    assert!(!removed.settings.contains("vouch"));
    assert!(removed.settings.contains("/usr/local/bin/other-guard check"));
    assert!(removed.notes.join(" ").contains("4 vouch hook(s) removed"));
}

#[test]
fn install_notes_name_persistent_default_state_dir_across_all_hosts() {
    let claude = plan("", "/opt/vouch", false).unwrap();
    let codex = plan_codex("", "/opt/vouch", InstallShell::Bash, false).unwrap();
    let agy = plan_agy("", "/opt/vouch", false, None).unwrap();

    for (host, notes) in [
        ("claude", claude.notes.join("\n")),
        ("codex", codex.notes.join("\n")),
        ("agy", agy.notes.join("\n")),
    ] {
        assert!(
            notes.contains("~/.local/state/vouch") && notes.contains("%LOCALAPPDATA%/vouch/state"),
            "{host} notes missing persistent state dir default: {notes}"
        );
        assert!(
            !notes.contains("OS temp fallback"),
            "{host} notes still mention OS temp fallback: {notes}"
        );
        assert!(
            notes.contains("fails closed"),
            "{host} live notes must state fail-closed behavior: {notes}"
        );
    }
}

#[test]
fn codex_powershell_and_agy_windows_cmd_wrappers_are_well_formed() {
    let codex_ps = plan_codex(
        "",
        "C:/Program Files/O'Brien/vouch.exe",
        InstallShell::PowerShell,
        false,
    )
    .unwrap();
    let root_ps: serde_json::Value = serde_json::from_str(&codex_ps.settings).unwrap();
    let ps_pre = root_ps["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        .as_str()
        .unwrap();
    let ps_post = root_ps["hooks"]["PostToolUse"][0]["hooks"][0]["command"]
        .as_str()
        .unwrap();
    assert!(ps_pre.contains("Get-Command 'C:/Program Files/O''Brien/vouch.exe'"));
    assert!(ps_pre.contains("try {") && ps_pre.contains("catch {}"));
    assert!(ps_pre.contains("$? -and $LASTEXITCODE -eq 0"));
    assert!(ps_pre.contains("Write-Output"));
    assert!(ps_pre.contains("permissionDecision"));
    assert!(ps_post.contains("Get-Command 'C:/Program Files/O''Brien/vouch.exe'"));
    assert!(ps_post.contains("try {") && ps_post.contains("catch {}"));
    assert!(!ps_post.contains("Write-Output"));

    // PowerShell also doubles Unicode single-quote delimiters
    let codex_ps_unicode = plan_codex(
        "",
        "C:/Program Files/O\u{2019}Brien/vouch.exe",
        InstallShell::PowerShell,
        false,
    )
    .unwrap();
    assert!(codex_ps_unicode.settings.contains("O\u{2019}\u{2019}Brien"));

    // Windows Antigravity path-bearing cmd wrapper uses `if exist ... (...) else (...)`
    // and normalizes trailing backslashes in --state-dir so Win32 quoting cannot break.
    let agy_win = plan_agy(
        "",
        "C:/Program Files (x86)/vouch/vouch.exe",
        false,
        Some(r"C:\Users\dev\AppData\Local\vouch\state\"),
    )
    .unwrap();
    let root_win: serde_json::Value = serde_json::from_str(&agy_win.settings).unwrap();
    let win_pre = root_win["vouch"]["PreToolUse"][0]["hooks"][0]["command"]
        .as_str()
        .unwrap();
    let win_post = root_win["vouch"]["PostToolUse"][0]["hooks"][0]["command"]
        .as_str()
        .unwrap();
    assert!(win_pre.starts_with(r#"if exist "C:/Program Files (x86)/vouch/vouch.exe" ("#));
    assert!(win_pre.contains(r#") else (echo {"decision":"deny""#));
    assert!(win_pre.contains(r#"--state-dir "C:/Users/dev/AppData/Local/vouch/state/""#));
    assert!(win_post.contains("|| echo {}) else (echo {})"));

    // Windows Antigravity bare .exe wrapper quotes the executable and exits 0 in shadow mode
    let agy_bare_live = plan_agy("", "vouch.exe", false, None).unwrap();
    let bare_live_root: serde_json::Value = serde_json::from_str(&agy_bare_live.settings).unwrap();
    let bare_live_pre = bare_live_root["vouch"]["PreToolUse"][0]["hooks"][0]["command"]
        .as_str()
        .unwrap();
    let bare_live_post = bare_live_root["vouch"]["PostToolUse"][0]["hooks"][0]["command"]
        .as_str()
        .unwrap();
    assert!(bare_live_pre.starts_with(r#"where /q "vouch.exe" && ("vouch.exe" --hook --host agy || echo "#));
    assert!(bare_live_post.starts_with(r#"where /q "vouch.exe" && ("vouch.exe" --hook --host agy || echo {}) || echo {}"#));

    let agy_bare_shadow = plan_agy("", "vouch.exe", true, None).unwrap();
    let bare_shadow_root: serde_json::Value =
        serde_json::from_str(&agy_bare_shadow.settings).unwrap();
    let bare_shadow_pre = bare_shadow_root["vouch"]["PreToolUse"][0]["hooks"][0]["command"]
        .as_str()
        .unwrap();
    assert!(bare_shadow_pre.ends_with("|| exit /b 0"));
}

#[test]
fn claude_parser_handles_same_exe_upgrade_tricky_state_dir_and_rejects_lookalikes() {
    // 1. Legacy bare hook with the SAME executable upgrades to fail-closed wrapper with 0 repointed
    let legacy = r#"{
      "hooks": {
        "PreToolUse": [ { "hooks": [ { "type": "command", "command": "/opt/vouch --hook" } ] } ],
        "PostToolUse": [ { "hooks": [ { "type": "command", "command": "/opt/vouch --hook" } ] } ],
        "PostToolUseFailure": [ { "hooks": [ { "type": "command", "command": "/opt/vouch --hook" } ] } ],
        "PermissionDenied": [ { "hooks": [ { "type": "command", "command": "/opt/vouch --hook" } ] } ]
      }
    }"#;
    let upgraded = plan(legacy, "/opt/vouch", false).unwrap();
    assert!(!upgraded.notes.join(" ").contains("repointed"));
    let root: serde_json::Value = serde_json::from_str(&upgraded.settings).unwrap();
    let pre = root["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        .as_str()
        .unwrap();
    assert!(pre.contains("permissionDecision") && pre.contains("deny"));

    // 2. State-dir paths containing `--shadow` or `--host codex` must not confuse flag/host parsing
    let tricky_state = "/tmp/my --shadow --host codex dir";
    let once = plan_with_state("", "/opt/vouch", false, Some(tricky_state)).unwrap();
    let twice = plan_with_state(&once.settings, "/opt/vouch", false, Some(tricky_state)).unwrap();
    assert_eq!(once.settings, twice.settings, "idempotency broke on tricky --state-dir");
    let root2: serde_json::Value = serde_json::from_str(&twice.settings).unwrap();
    let post = root2["hooks"]["PostToolUse"][0]["hooks"][0]["command"]
        .as_str()
        .unwrap();
    assert!(
        post.contains("--hook --state-dir '/tmp/my --shadow --host codex dir'"),
        "PostToolUse must not gain spurious --shadow: {post}"
    );
    let cleaned = unplan(&twice.settings).unwrap();
    assert!(!cleaned.settings.contains("vouch"));

    // 3. Lookalike wrapped hooks and multi-word unrelated commands ending in `.../vouch --hook` are preserved
    let lookalikes = r#"{
      "hooks": {
        "PostToolUse": [
          { "hooks": [ { "type": "command", "command": "if command -v '/opt/notvouch' >/dev/null 2>&1; then '/opt/notvouch' --hook || true; fi" } ] },
          { "hooks": [ { "type": "command", "command": "python3 /usr/local/bin/tool.py /path/to/vouch --hook" } ] }
        ]
      }
    }"#;
    let p = plan(lookalikes, "/opt/vouch", false).unwrap();
    assert!(p.settings.contains("/opt/notvouch"));
    assert!(p.settings.contains("python3 /usr/local/bin/tool.py /path/to/vouch --hook"));
    let unp = unplan(&p.settings).unwrap();
    assert!(unp.settings.contains("/opt/notvouch"));
    assert!(unp.settings.contains("python3 /usr/local/bin/tool.py /path/to/vouch --hook"));
}

#[test]
fn codex_unplan_removes_wrapped_bash_and_powershell_hooks_including_shared_groups() {
    for shell in [InstallShell::Bash, InstallShell::PowerShell] {
        let planned = plan_codex("", "/opt/vouch", shell, false).unwrap();
        let unp = unplan_codex(&planned.settings).unwrap();
        assert!(!unp.settings.contains("vouch"));
        assert!(unp.notes.join(" ").contains("vouch hooks removed"));
    }

    // Shared matcher group containing both an unrelated hook and a vouch hook
    let shared = r#"{
      "hooks": {
        "PreToolUse": [{
          "matcher": ".*",
          "hooks": [
            {"type": "command", "command": "other-gate"},
            {"type": "command", "command": "if command -v '/opt/vouch' >/dev/null 2>&1; then '/opt/vouch' --hook --host codex --shell bash; fi", "statusMessage": "vouch is checking this tool call"}
          ]
        }]
      }
    }"#;
    let unp = unplan_codex(shared).unwrap();
    assert!(unp.settings.contains("other-gate"));
    assert!(!unp.settings.contains("/opt/vouch"));
    assert!(unp.notes.join(" ").contains("vouch hooks removed"));
}

#[cfg(unix)]
#[test]
fn unix_sh_wrappers_fail_closed_on_missing_nonexec_and_crash_and_stay_silent_on_outcomes() {
    use std::os::unix::fs::PermissionsExt;
    use std::process::{Command, Stdio};

    let tmp = std::env::temp_dir().join(format!("vouch_install_sh_probe_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let tricky = tmp.join("dir with 'quote' and space");
    std::fs::create_dir_all(&tricky).unwrap();

    let ok_allow = tricky.join("vouch");
    std::fs::write(
        &ok_allow,
        "#!/bin/sh\ncat >/dev/null\nprintf '%s\\n' '{\"decision\":\"allow\",\"reason\":\"ok\"}'\nexit 0\n",
    )
    .unwrap();
    std::fs::set_permissions(&ok_allow, std::fs::Permissions::from_mode(0o755)).unwrap();

    let ok_empty = tricky.join("vouch_empty");
    std::fs::write(&ok_empty, "#!/bin/sh\ncat >/dev/null\nexit 0\n").unwrap();
    std::fs::set_permissions(&ok_empty, std::fs::Permissions::from_mode(0o755)).unwrap();

    let crash_partial = tricky.join("vouch_crash");
    std::fs::write(
        &crash_partial,
        "#!/bin/sh\nprintf '{\"partial\": '\nexit 134\n",
    )
    .unwrap();
    std::fs::set_permissions(&crash_partial, std::fs::Permissions::from_mode(0o755)).unwrap();

    let nonexec = tricky.join("vouch_nonexec");
    std::fs::write(&nonexec, "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&nonexec, std::fs::Permissions::from_mode(0o644)).unwrap();

    let missing = tricky.join("vouch_missing");

    let run_sh = |cmd: &str| -> (i32, String, String) {
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg(cmd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn /bin/sh");
        {
            use std::io::Write;
            let mut stdin = child.stdin.take().unwrap();
            let _ = stdin.write_all(b"{\"hook_event_name\":\"PreToolUse\"}");
        }
        let out = child.wait_with_output().unwrap();
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).to_string(),
            String::from_utf8_lossy(&out.stderr).to_string(),
        )
    };

    // 1. Claude, Codex (bash), and Antigravity live PreToolUse on missing, nonexec, and crash-with-partial-stdout
    for exe in [&missing, &nonexec, &crash_partial] {
        let exe_str = exe.to_string_lossy();

        // Claude
        let claude_plan = plan("", &exe_str, false).unwrap();
        let claude_root: serde_json::Value = serde_json::from_str(&claude_plan.settings).unwrap();
        let claude_pre = claude_root["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
            .as_str()
            .unwrap();
        let (rc, stdout, _) = run_sh(claude_pre);
        assert_eq!(rc, 0, "Claude PreToolUse must emit structured deny JSON with exit 0");
        let parsed: serde_json::Value = serde_json::from_str(stdout.trim())
            .unwrap_or_else(|e| panic!("Claude output must be valid JSON ({e}): {stdout:?}"));
        assert_eq!(parsed["hookSpecificOutput"]["permissionDecision"], "deny");

        // Codex (bash)
        let codex_plan = plan_codex("", &exe_str, InstallShell::Bash, false).unwrap();
        let codex_root: serde_json::Value = serde_json::from_str(&codex_plan.settings).unwrap();
        let codex_pre = codex_root["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
            .as_str()
            .unwrap();
        let (rc, stdout, _) = run_sh(codex_pre);
        assert_eq!(rc, 0);
        let parsed: serde_json::Value = serde_json::from_str(stdout.trim())
            .unwrap_or_else(|e| panic!("Codex output must be valid JSON ({e}): {stdout:?}"));
        assert_eq!(parsed["hookSpecificOutput"]["permissionDecision"], "deny");

        // Antigravity
        let agy_plan = plan_agy("", &exe_str, false, None).unwrap();
        let agy_root: serde_json::Value = serde_json::from_str(&agy_plan.settings).unwrap();
        let agy_pre = agy_root["vouch"]["PreToolUse"][0]["hooks"][0]["command"]
            .as_str()
            .unwrap();
        let (rc, stdout, _) = run_sh(agy_pre);
        assert_eq!(rc, 0);
        let parsed: serde_json::Value = serde_json::from_str(stdout.trim())
            .unwrap_or_else(|e| panic!("Agy output must be valid JSON ({e}): {stdout:?}"));
        assert_eq!(parsed["decision"], "deny");
    }

    // 2. Working binary passes stdout through verbatim; empty stdout (Codex Allow / Abstain) stays empty
    let ok_plan = plan_agy("", &ok_allow.to_string_lossy(), false, None).unwrap();
    let ok_root: serde_json::Value = serde_json::from_str(&ok_plan.settings).unwrap();
    let ok_pre = ok_root["vouch"]["PreToolUse"][0]["hooks"][0]["command"]
        .as_str()
        .unwrap();
    let (rc, stdout, _) = run_sh(ok_pre);
    assert_eq!(rc, 0);
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(parsed["decision"], "allow");

    let empty_plan =
        plan_codex("", &ok_empty.to_string_lossy(), InstallShell::Bash, false).unwrap();
    let empty_root: serde_json::Value = serde_json::from_str(&empty_plan.settings).unwrap();
    let empty_pre = empty_root["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        .as_str()
        .unwrap();
    let (rc, stdout, _) = run_sh(empty_pre);
    assert_eq!(rc, 0);
    assert_eq!(stdout, "", "empty stdout on Allow/Abstain must remain 0 bytes");

    // 3. Outcome hooks & shadow PreToolUse stay silently non-disruptive when binary is missing
    let miss_str = missing.to_string_lossy();
    let claude_shadow = plan("", &miss_str, true).unwrap();
    let cs_root: serde_json::Value = serde_json::from_str(&claude_shadow.settings).unwrap();
    for ev in ["PreToolUse", "PostToolUse", "PostToolUseFailure", "PermissionDenied"] {
        let cmd = cs_root["hooks"][ev][0]["hooks"][0]["command"].as_str().unwrap();
        let (rc, stdout, stderr) = run_sh(cmd);
        assert_eq!(rc, 0, "Claude {ev} shadow/outcome must exit 0 when missing");
        assert_eq!(stdout, "", "Claude {ev} must stay silent");
        assert_eq!(stderr, "", "Claude {ev} must emit no stderr");
    }

    let codex_shadow = plan_codex("", &miss_str, InstallShell::Bash, true).unwrap();
    let cx_root: serde_json::Value = serde_json::from_str(&codex_shadow.settings).unwrap();
    for ev in ["PreToolUse", "PostToolUse"] {
        let cmd = cx_root["hooks"][ev][0]["hooks"][0]["command"].as_str().unwrap();
        let (rc, stdout, stderr) = run_sh(cmd);
        assert_eq!(rc, 0, "Codex {ev} shadow/outcome must exit 0 when missing");
        assert_eq!(stdout, "");
        assert_eq!(stderr, "");
    }

    let agy_shadow = plan_agy("", &miss_str, true, None).unwrap();
    let ag_root: serde_json::Value = serde_json::from_str(&agy_shadow.settings).unwrap();
    let ag_pre = ag_root["vouch"]["PreToolUse"][0]["hooks"][0]["command"].as_str().unwrap();
    let (rc, stdout, stderr) = run_sh(ag_pre);
    assert_eq!(rc, 0);
    assert_eq!(stdout, "");
    assert_eq!(stderr, "");

    let ag_post = ag_root["vouch"]["PostToolUse"][0]["hooks"][0]["command"].as_str().unwrap();
    let (rc, stdout, stderr) = run_sh(ag_post);
    assert_eq!(rc, 0);
    assert_eq!(stdout.trim(), "{}");
    assert_eq!(stderr, "");

    let _ = std::fs::remove_dir_all(&tmp);
}


