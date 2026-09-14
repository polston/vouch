//! The hook registration vouch needs, and the safety of the shadow variant.

use vouch::cli::{
    parse_hook_options, parse_install_args, parse_install_options, parse_uninstall_options,
    InstallHost, InstallShell,
};
use vouch::install::{
    plan, plan_agy, plan_codex, plan_codex_with_state, unplan, unplan_agy, unplan_codex,
    write_file_atomically,
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
    assert!(p.settings.contains("vouch.exe --hook --shadow"));
}

#[test]
fn live_replaces_the_existing_gate() {
    let p = plan(EXISTING, "C:/workspace/vouch-dev/vouch.exe", false).unwrap();
    let pre = p.settings.split("\"PreToolUse\"").nth(1).unwrap_or("");
    let pre = pre.split(']').next().unwrap_or("");
    assert!(
        !pre.contains("cc-allow"),
        "cc-allow still in PreToolUse: {pre}"
    );
    assert!(pre.contains("vouch.exe --hook"));
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
    assert_eq!(p.settings.matches("C:/new/vouch.exe --hook").count(), 4);
    assert!(p.settings.contains("C:/other/tool.exe observe"));
    assert!(p.notes.join(" ").contains("repointed"));
}

#[test]
fn claude_shadow_stands_a_repointed_live_gate_down() {
    let p = plan(MOVED_CLAUDE_HOOKS, "C:/new/vouch.exe", true).unwrap();
    let pre = p.settings.split("\"PreToolUse\"").nth(1).unwrap_or("");
    let pre = pre.split(']').next().unwrap_or("");
    assert!(pre.contains("C:/new/vouch.exe --hook --shadow"));
    assert!(!pre.contains("C:/new/vouch.exe --hook\""));
    assert!(p.notes.join(" ").contains("stood down"));
}

#[test]
fn claude_quotes_an_executable_path_with_spaces() {
    let p = plan("{}", "C:/Program Files/vouch/bin/vouch.exe", false).unwrap();
    assert!(p.settings.contains("\\\"C:/Program Files/vouch/bin/vouch.exe\\\" --hook"));
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
    let post = p.settings.split("\"PostToolUse\"").nth(1).unwrap_or("");
    let post = post.split(']').next().unwrap_or("");
    assert_eq!(post.matches("--hook").count(), 1);
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
    assert!(p.settings.contains("C:/new/vouch.exe --hook"));
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
    assert!(parse_install_options(&["--state-dir".into(), "/tmp/vouch".into()]).is_err());
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
    let pre_cmd = vouch_group["PreToolUse"][0]["hooks"][0]["command"]
        .as_str()
        .unwrap();
    let post_cmd = vouch_group["PostToolUse"][0]["hooks"][0]["command"]
        .as_str()
        .unwrap();

    assert!(pre_cmd.starts_with(
        "\"/opt/Vouch Bin/vouch\" --hook --host agy --shadow --state-dir \"/tmp/vouch agy state\""
    ));
    assert!(post_cmd.starts_with(
        "\"/opt/Vouch Bin/vouch\" --hook --host agy --state-dir \"/tmp/vouch agy state\""
    ));
    assert!(!post_cmd.contains("--shadow"));

    // Idempotent: running again produces identical vouch config
    let p2 = plan_agy(&p.settings, exe, true, Some(state)).unwrap();
    let root2: serde_json::Value = serde_json::from_str(&p2.settings).unwrap();
    assert_eq!(root, root2);

    // Live mode (shadow = false, state_dir = None)
    let p_live = plan_agy("", "vouch", false, None).unwrap();
    let root_live: serde_json::Value = serde_json::from_str(&p_live.settings).unwrap();
    let live_pre = root_live["vouch"]["PreToolUse"][0]["hooks"][0]["command"]
        .as_str()
        .unwrap();
    assert_eq!(live_pre, "vouch --hook --host agy");
    let live_post = root_live["vouch"]["PostToolUse"][0]["hooks"][0]["command"]
        .as_str()
        .unwrap();
    assert_eq!(live_post, "vouch --hook --host agy");
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
    assert!(planned.settings.contains("vouch.exe --hook"));
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


