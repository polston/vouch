// tests/write_prompt_narrowing_test.rs
//
// M2.27: Narrow suggested write prompt rules.
// Verifies that prompts for rejected file writes suggest the specific file
// rather than blanket whole-filesystem or whole-drive wildcard rules.

use vouch::config::Config;
use vouch::engine::{decide_file, suggest_write_advice};
use vouch::protocol::Decision;

#[test]
fn test_suggest_write_advice_root_posix() {
    let advice = suggest_write_advice("/probe.txt");
    assert!(advice.contains("to allow this permanently, add to write.allow_paths: \"/probe.txt\""));
    assert!(advice.contains("allowing the containing directory would open the entire filesystem or drive to writes"));
    assert!(!advice.contains("\"/**\""));
}

#[test]
fn test_suggest_write_advice_root_windows() {
    let advice = suggest_write_advice("C:/probe.txt");
    assert!(advice.contains("to allow this permanently, add to write.allow_paths: \"C:/probe.txt\""));
    assert!(advice.contains("allowing the containing directory would open the entire filesystem or drive to writes"));
    assert!(!advice.contains("\"C:/**\""));
}

#[test]
fn test_suggest_write_advice_nested_posix() {
    let advice = suggest_write_advice("/var/log/app/output.log");
    assert!(advice.contains("to allow this permanently, add to write.allow_paths: \"/var/log/app/output.log\""));
    assert!(advice.contains("or to allow this directory: \"/var/log/app/**\""));
}

#[test]
fn test_suggest_write_advice_nested_windows() {
    let advice = suggest_write_advice("C:/Users/dev/project/data.txt");
    assert!(advice.contains("to allow this permanently, add to write.allow_paths: \"C:/Users/dev/project/data.txt\""));
    assert!(advice.contains("or to allow this directory: \"C:/Users/dev/project/**\""));
}

#[test]
fn test_decide_file_prompts_narrow_rules() {
    let mut cfg = Config::nothing_configured();
    cfg.write.default = vouch::config::Action::Ask;

    let (root_target, nested_target) = if cfg!(windows) {
        ("C:/root_file.txt", "C:/nested/path/file.txt")
    } else {
        ("/root_file.txt", "/nested/path/file.txt")
    };

    let res = decide_file(&cfg, "C:/Users/dev", Some("C:/Users/dev/project"), root_target);
    match res {
        Decision::Ask(msg) => {
            assert!(msg.contains(&format!("to allow this permanently, add to write.allow_paths: \"{root_target}\"")), "got: {msg}");
            assert!(!msg.contains("\"/**\"") && !msg.contains("\"C:/**\""), "must not suggest /**: {msg}");
            assert!(msg.contains("(note: allowing the containing directory would open the entire filesystem or drive to writes)"), "got: {msg}");
        }
        other => panic!("expected Ask, got {other:?}"),
    }

    let res2 = decide_file(&cfg, "C:/Users/dev", Some("C:/Users/dev/project"), nested_target);
    match res2 {
        Decision::Ask(msg) => {
            assert!(msg.contains(&format!("to allow this permanently, add to write.allow_paths: \"{nested_target}\"")), "got: {msg}");
            let dir_rule = if cfg!(windows) { "C:/nested/path/**" } else { "/nested/path/**" };
            assert!(msg.contains(&format!("or to allow this directory: \"{dir_rule}\"")), "got: {msg}");
        }
        other => panic!("expected Ask, got {other:?}"),
    }
}
