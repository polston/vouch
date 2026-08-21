//! Mode-keyed shadow (docs/specs/2026-08-16-mode-keyed-shadow-design.md):
//! the protocol field, the emission table, and — from Task 7 on — the
//! end-to-end hook cases.

mod common;

use common::hook_bash_run;
use vouch::protocol::parse_input;

#[test]
fn permission_mode_is_parsed_from_hook_input() {
    let raw = r#"{"session_id":"s","tool_name":"Bash","permission_mode":"auto","tool_input":{"command":"ls"}}"#;
    assert_eq!(parse_input(raw).unwrap().permission_mode, "auto");
}

#[test]
fn permission_mode_absent_parses_to_empty() {
    let raw = r#"{"session_id":"s","tool_name":"Bash","tool_input":{"command":"ls"}}"#;
    assert_eq!(parse_input(raw).unwrap().permission_mode, "");
}

#[test]
fn the_protection_first_lines_are_what_the_engine_writes() {
    use vouch::engine::{is_protection_ask, PROTECTED_FILE_LINE, WRITE_WALL_LINE};
    use vouch::protocol::Decision;
    let cfg = vouch::config::load(
        "version = 1\n[lang.bash]\ndefault = \"allow\"\n[write]\ndefault = \"allow\"\n\
         allow_paths = [\"C:/**\"]\nask_paths = [\"C:/walled/**\"]\n\
         [protected]\npaths = [\"C:/protccfg/settings.json\"]\n",
    )
    .unwrap();
    // The protected-list write rule (the ONE HARD-CODED RULE) asks, and its
    // first line is the pinned constant.
    let d = vouch::engine::decide_command_at(
        &cfg, "bash", "echo x > C:/protccfg/settings.json", Some("C:/Users/dev"), None, Some("C:/work"),
    );
    match &d {
        Decision::Ask(r) => {
            assert_eq!(r.lines().next().unwrap(), PROTECTED_FILE_LINE);
            assert!(is_protection_ask(r));
        }
        other => panic!("protected write must ask, got {other:?}"),
    }
    // The ask_paths wall asks with the wall first line.
    let d = vouch::engine::decide_command_at(
        &cfg, "bash", "echo x > C:/walled/f.txt", Some("C:/Users/dev"), None, Some("C:/work"),
    );
    match &d {
        Decision::Ask(r) => {
            assert_eq!(r.lines().next().unwrap(), WRITE_WALL_LINE);
            assert!(is_protection_ask(r));
        }
        other => panic!("walled write must ask, got {other:?}"),
    }
    // An ordinary ask is NOT a protection ask.
    assert!(!is_protection_ask("vouch stopped on: unmodeled_command\n  x"));
    // The banner is appended AFTER the reason and cannot reach the first line.
    assert!(is_protection_ask(&format!("{PROTECTED_FILE_LINE}\n  p\n\nsome banner text")));
}

#[test]
fn a_mixed_guard_and_protected_call_records_the_protection_first_line() {
    // `rm -r <protected>` fires the delete guard AND the protected rule (rm
    // declares writes = "all_args"). Probed 2026-08-16: without the
    // reason-slot rule the guard's reason wins the recorded slot on the
    // equal-rank tie, so keep-deny would stand vouch's self-protection down
    // on exactly this call. The protection reason must win the slot.
    use vouch::engine::{is_protection_ask, PROTECTED_FILE_LINE};
    use vouch::protocol::Decision;
    let cfg = vouch::config::load(
        "version = 1\n[lang.bash]\ndefault = \"allow\"\n[write]\ndefault = \"allow\"\n\
         allow_paths = [\"C:/**\"]\n\
         [protected]\npaths = [\"C:/protccfg/settings.json\"]\n",
    )
    .unwrap();
    let d = vouch::engine::decide_command_at(
        &cfg, "bash", "rm -r C:/protccfg/settings.json", Some("C:/Users/dev"), None, Some("C:/work"),
    );
    match &d {
        Decision::Ask(r) => {
            assert_eq!(r.lines().next().unwrap(), PROTECTED_FILE_LINE, "full reason:\n{r}");
            assert!(is_protection_ask(r));
        }
        other => panic!("mixed guard+protected must ask, got {other:?}"),
    }
}

#[test]
fn the_emission_table_row_by_row() {
    use vouch::config::StandDown::{Full, KeepDeny, Off};
    use vouch::protocol::{stand_down_emission, Decision};
    let d = |name: &str| -> Decision {
        match name {
            "allow" => Decision::Allow("r".into()),
            "ask" => Decision::Ask("r".into()),
            "deny" => Decision::Deny("r".into()),
            _ => Decision::Abstain,
        }
    };
    // (toggle, mode listed, decision, protection ask) -> (emit, mode word).
    // This IS the spec's table (design §Emission policy); keep them in sync.
    let cases = [
        (Off, true, "ask", false, true, "live"),
        (KeepDeny, false, "ask", false, true, "live"),
        (Full, false, "deny", false, true, "live"),
        (KeepDeny, true, "allow", false, true, "live"),
        (KeepDeny, true, "abstain", false, true, "live"),
        (KeepDeny, true, "ask", false, false, "stood-down"),
        (KeepDeny, true, "ask", true, true, "live"),
        (KeepDeny, true, "deny", false, true, "live"),
        (Full, true, "allow", false, true, "live"),
        (Full, true, "abstain", false, true, "live"),
        (Full, true, "ask", false, false, "stood-down"),
        (Full, true, "ask", true, false, "stood-down"),
        (Full, true, "deny", false, false, "stood-down"),
    ];
    for (toggle, listed, name, prot, want_emit, want_mode) in cases {
        let (emit, mode) = stand_down_emission(toggle, listed, &d(name), prot);
        assert_eq!(
            (emit, mode),
            (want_emit, want_mode),
            "toggle {toggle:?}, listed {listed}, decision {name}, protection {prot}"
        );
    }
    // The unarmed half of the cross product: toggle off (any listing), or
    // mode unlisted (any toggle), is always as-today/live. With the rows
    // above this covers all 3 x 2 x 4 x 2 combinations.
    for toggle in [Off, KeepDeny, Full] {
        for name in ["allow", "ask", "deny", "abstain"] {
            for prot in [false, true] {
                assert_eq!(stand_down_emission(toggle, false, &d(name), prot), (true, "live"));
                if toggle == Off {
                    assert_eq!(stand_down_emission(toggle, true, &d(name), prot), (true, "live"));
                }
            }
        }
    }
    // The protection flag is meaningful only for asks; for every other
    // decision it must change nothing, armed or not.
    for toggle in [KeepDeny, Full] {
        for name in ["allow", "abstain", "deny"] {
            assert_eq!(
                stand_down_emission(toggle, true, &d(name), true),
                stand_down_emission(toggle, true, &d(name), false),
                "protection flag must be inert for {name} under {toggle:?}"
            );
        }
    }
}

const STAND_DOWN_CFG: &str = r#"
version = 1
[lang.bash]
default = "allow"
[lang.bash.constructs]
unmodeled_command = "ask"
[shadow]
stand_down = "keep-deny"
modes = ["auto", "dontAsk", "bypassPermissions"]
[write]
default = "ask"
allow_paths = ["C:/work/**"]
ask_paths = ["C:/walled/**"]
deny_paths = ["C:/forbidden/**"]
[protected]
paths = ["C:/protccfg/settings.json"]
"#;

/// The same config with the toggle at "full".
fn full_cfg() -> String {
    STAND_DOWN_CFG.replace("keep-deny", "full")
}

/// The same config with no [shadow] section at all.
fn no_shadow_cfg() -> String {
    let mut s = String::new();
    let mut skipping = false;
    for line in STAND_DOWN_CFG.lines() {
        if line.trim() == "[shadow]" {
            skipping = true;
            continue;
        }
        if skipping {
            if line.trim().starts_with('[') {
                skipping = false;
            } else {
                continue;
            }
        }
        s.push_str(line);
        s.push('\n');
    }
    s
}

#[test]
fn a_default_mode_call_is_live_and_journals_its_mode() {
    let r = hook_bash_run("sd_live", "", STAND_DOWN_CFG, "C:/work", "someunknownprogramzz", "default");
    assert_eq!(r.emitted.as_ref().map(|(v, _)| v.as_str()), Some("ask"));
    assert_eq!(r.rows[0]["mode"], "live");
    assert_eq!(r.rows[0]["permission_mode"], "default");
}

#[test]
fn an_auto_mode_ordinary_ask_is_stood_down_and_still_journaled() {
    let r = hook_bash_run("sd_ask", "", STAND_DOWN_CFG, "C:/work", "someunknownprogramzz", "auto");
    assert!(r.emitted.is_none(), "nothing may be emitted, got {:?}", r.emitted);
    assert_eq!(r.rows.len(), 1, "the row is what proves the binary ran");
    assert_eq!(r.rows[0]["verdict"], "ask");
    assert_eq!(r.rows[0]["mode"], "stood-down");
    assert_eq!(r.rows[0]["permission_mode"], "auto");
}

#[test]
fn an_allow_is_still_emitted_while_stood_down_in_dont_ask_mode() {
    // The dontAsk regression pin: a hook allow is one of the three channels
    // that lets a call run in that mode — suppressing it breaks work.
    let r = hook_bash_run("sd_allow", "", STAND_DOWN_CFG, "C:/work", "ls -la", "dontAsk");
    assert_eq!(r.emitted.as_ref().map(|(v, _)| v.as_str()), Some("allow"));
    assert_eq!(r.rows[0]["mode"], "live");
    assert_eq!(r.rows[0]["permission_mode"], "dontAsk");
}

#[test]
fn keep_deny_keeps_the_protected_list_ask_in_auto_mode() {
    let r = hook_bash_run("sd_prot", "", STAND_DOWN_CFG, "C:/work", "echo x > C:/protccfg/settings.json", "auto");
    let (v, reason) = r.emitted.as_ref().expect("the protection ask must still be emitted");
    assert_eq!(v, "ask");
    assert!(reason.starts_with("vouch stopped on: protected file"), "{reason}");
    assert_eq!(r.rows[0]["mode"], "live");
}

#[test]
fn keep_deny_keeps_the_wall_ask_and_the_deny_in_auto_mode() {
    let r = hook_bash_run("sd_wall", "", STAND_DOWN_CFG, "C:/work", "echo x > C:/walled/f.txt", "auto");
    assert_eq!(r.emitted.as_ref().map(|(v, _)| v.as_str()), Some("ask"));
    let r = hook_bash_run("sd_deny", "", STAND_DOWN_CFG, "C:/work", "echo x > C:/forbidden/f.txt", "auto");
    assert_eq!(r.emitted.as_ref().map(|(v, _)| v.as_str()), Some("deny"));
    assert_eq!(r.rows[0]["mode"], "live");
}

#[test]
fn full_stands_down_everything_but_allows() {
    let cfg = full_cfg();
    for (tag, cmd) in [
        ("sd_f_prot", "echo x > C:/protccfg/settings.json"),
        ("sd_f_wall", "echo x > C:/walled/f.txt"),
        ("sd_f_deny", "echo x > C:/forbidden/f.txt"),
        ("sd_f_ask", "someunknownprogramzz"),
    ] {
        let r = hook_bash_run(tag, "", &cfg, "C:/work", cmd, "auto");
        assert!(r.emitted.is_none(), "{tag}: nothing may be emitted");
        assert_eq!(r.rows[0]["mode"], "stood-down", "{tag}");
    }
    let r = hook_bash_run("sd_f_allow", "", &cfg, "C:/work", "ls -la", "auto");
    assert_eq!(r.emitted.as_ref().map(|(v, _)| v.as_str()), Some("allow"));
}

#[test]
fn an_unlisted_mode_and_a_missing_mode_stay_live() {
    let r = hook_bash_run("sd_plan", "", STAND_DOWN_CFG, "C:/work", "someunknownprogramzz", "plan");
    assert_eq!(r.emitted.as_ref().map(|(v, _)| v.as_str()), Some("ask"));
    let r = hook_bash_run("sd_none", "", STAND_DOWN_CFG, "C:/work", "someunknownprogramzz", "");
    assert_eq!(r.emitted.as_ref().map(|(v, _)| v.as_str()), Some("ask"));
    assert_eq!(r.rows[0]["permission_mode"], "");
    // full + unmatched mode is also live — the toggle alone arms nothing.
    let cfg = full_cfg();
    let r = hook_bash_run("sd_f_plan", "", &cfg, "C:/work", "someunknownprogramzz", "plan");
    assert_eq!(r.emitted.as_ref().map(|(v, _)| v.as_str()), Some("ask"));
    assert_eq!(r.rows[0]["mode"], "live");
}

#[test]
fn the_parked_state_stays_live_in_a_listed_mode() {
    // stand_down = "off" with modes written: legal (the parked state), and
    // it stands nothing down even when the call's mode is in the list.
    let cfg = STAND_DOWN_CFG.replace("keep-deny", "off");
    let r = hook_bash_run("sd_off", "", &cfg, "C:/work", "someunknownprogramzz", "auto");
    assert_eq!(r.emitted.as_ref().map(|(v, _)| v.as_str()), Some("ask"));
    assert_eq!(r.rows[0]["mode"], "live");
}

#[test]
fn a_mixed_guard_and_protected_call_survives_keep_deny_and_stands_down_under_full() {
    // The reason-slot rule, end to end: `rm -r <protected>` trips the delete
    // guard AND the protected rule; the protection first line must win the
    // recorded reason, so keep-deny still emits the ask in auto mode.
    let r = hook_bash_run("sd_mixed", "", STAND_DOWN_CFG, "C:/work", "rm -r C:/protccfg/settings.json", "auto");
    let (v, reason) = r.emitted.as_ref().expect("keep-deny must keep the mixed-cause protection ask");
    assert_eq!(v, "ask");
    assert!(reason.starts_with("vouch stopped on: protected file"), "{reason}");
    assert_eq!(r.rows[0]["mode"], "live");
    // Under full, the same call is stood down — journaled, nothing emitted.
    let cfg = full_cfg();
    let r = hook_bash_run("sd_f_mixed", "", &cfg, "C:/work", "rm -r C:/protccfg/settings.json", "auto");
    assert!(r.emitted.is_none());
    assert_eq!(r.rows[0]["verdict"], "ask");
    assert_eq!(r.rows[0]["mode"], "stood-down");
}

#[test]
fn the_journal_row_shape_is_preserved_plus_the_one_new_field() {
    // The "same or better" assertion: on input with no [shadow] in play,
    // every field today's code writes is written unchanged, plus
    // permission_mode.
    let r = hook_bash_run("sd_shape", "", &no_shadow_cfg(), "C:/work", "ls -la", "default");
    let row = r.rows[0].as_object().unwrap();
    let mut keys: Vec<&str> = row.keys().map(|k| k.as_str()).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec!["cmd", "cwd", "id", "lang", "mode", "outcome", "permission_mode", "reason", "session", "tool", "ts", "verdict"]
    );
}
