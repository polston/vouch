//! The hook registration vouch needs, and the safety of the shadow variant.

use vouch::cli::parse_install_args;
use vouch::install::plan;

const EXISTING: &str = r#"{
  "model": "opus",
  "hooks": {
    "PreToolUse": [
      { "hooks": [ { "type": "command", "command": "C:/git/cc-allow/cc-allow.exe --hook" } ] }
    ]
  }
}"#;

#[test]
fn shadow_leaves_the_existing_gate_in_charge() {
    let p = plan(EXISTING, "C:/git/vouch/vouch.exe", true).unwrap();
    assert!(p.settings.contains("cc-allow.exe --hook"), "existing gate removed: {}", p.settings);
    assert!(p.settings.contains("vouch.exe --hook --shadow"));
}

#[test]
fn live_replaces_the_existing_gate() {
    let p = plan(EXISTING, "C:/git/vouch/vouch.exe", false).unwrap();
    let pre = p.settings.split("\"PreToolUse\"").nth(1).unwrap_or("");
    let pre = pre.split(']').next().unwrap_or("");
    assert!(!pre.contains("cc-allow"), "cc-allow still in PreToolUse: {pre}");
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
    assert!(s.notes.join(" ").contains("emits nothing"), "got: {:?}", s.notes);
}

const EXISTING_WITH_SERVER: &str = r#"{
  "model": "opus",
  "mcpServers": { "example": { "url": "https://example.invalid", "headers": { "x-sample": "placeholder" } } },
  "hooks": {
    "PreToolUse": [
      { "hooks": [ { "type": "command", "command": "C:/git/cc-allow/cc-allow.exe --hook" } ] }
    ]
  }
}"#;

#[test]
fn the_hooks_only_view_carries_no_server_content() {
    let p = plan(EXISTING_WITH_SERVER, "C:/vouch.exe", false).unwrap();
    assert!(!p.hooks_view.contains("mcpServers"), "server block leaked: {}", p.hooks_view);
    assert!(!p.hooks_view.contains("x-sample"));
    assert!(!p.hooks_view.contains("model"));
    for ev in ["PreToolUse", "PostToolUse", "PostToolUseFailure", "PermissionDenied"] {
        assert!(p.hooks_view.contains(ev), "{ev} missing from the hooks view");
    }
}

#[test]
fn the_full_document_still_carries_everything() {
    let p = plan(EXISTING_WITH_SERVER, "C:/vouch.exe", false).unwrap();
    assert!(p.settings.contains("mcpServers"), "full form must keep the document whole");
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
    assert!(err.contains("--help"), "error does not name the bad flag: {err}");
    assert!(err.contains("usage: vouch install"), "error carries no usage line: {err}");
}

#[test]
fn a_stray_positional_argument_is_refused() {
    let args = vec!["shadow".to_string()];
    assert!(parse_install_args(&args).is_err(), "a bare word with no dashes must not be silently accepted");
}

#[test]
fn a_recognised_flag_beside_an_unrecognised_one_is_still_refused() {
    let args = vec!["--shadow".to_string(), "--bogus".to_string()];
    let err = parse_install_args(&args).unwrap_err();
    assert!(err.contains("--bogus"), "error does not name the bad flag: {err}");
}
