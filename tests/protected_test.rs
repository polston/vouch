use vouch::config::{load, Config};
use vouch::engine::decide_file;
use vouch::protocol::Decision;

const HOME: &str = "C:/Users/dev";

fn cfg() -> Config {
    load(
        r#"
version = 1
[write]
default = "ask"
allow_paths = ["$PROJECT_ROOT/**", "C:/work/**", "$HOME/.claude/**"]
[protected]
paths = ["$HOME/.claude/settings.json", "$HOME/.config/vouch.toml"]
"#,
    )
    .expect("parses")
}

#[test]
fn allows_a_path_inside_an_allowed_area() {
    let d = decide_file(&cfg(), HOME, None, "C:/work/out/x.png");
    assert!(matches!(d, Decision::Allow(_)), "got {d:?}");
}

#[test]
fn prompts_for_a_path_outside_every_allowed_area() {
    let d = decide_file(&cfg(), HOME, None, "C:/Windows/System32/drivers/etc/hosts");
    assert!(matches!(d, Decision::Ask(_)), "got {d:?}");
}

#[test]
fn protected_paths_win_even_though_a_broad_rule_covers_them() {
    // $HOME/.claude/** is allowed, but settings.json is protected by identity.
    let d = decide_file(&cfg(), HOME, None, "C:/Users/dev/.claude/settings.json");
    assert!(
        matches!(d, Decision::Ask(_)),
        "a protected file must never be silently writable: {d:?}"
    );
}

#[test]
fn protected_paths_survive_every_spelling_of_the_path() {
    for spelling in [
        r"C:\Users\dev\.claude\settings.json",
        "/c/Users/dev/.claude/settings.json",
        "C:/c/Users/dev/.claude/settings.json",
        "~/.claude/settings.json",
        "C:/Users/dev/.claude/../.claude/settings.json",
    ] {
        let d = decide_file(&cfg(), HOME, None, spelling);
        assert!(matches!(d, Decision::Ask(_)), "{spelling} slipped through: {d:?}");
    }
}

#[test]
fn vouchs_own_config_is_protected() {
    let d = decide_file(&cfg(), HOME, None, "C:/Users/dev/.config/vouch.toml");
    assert!(matches!(d, Decision::Ask(_)), "got {d:?}");
}

#[test]
fn the_project_root_is_resolved_per_run() {
    let d = decide_file(
        &cfg(),
        HOME,
        Some("C:/git/somenewproject"),
        "C:/git/somenewproject/src/a.rs",
    );
    assert!(
        matches!(d, Decision::Allow(_)),
        "a new project must not cost a prompt: {d:?}"
    );
}

#[test]
fn a_project_root_pattern_is_skipped_when_there_is_no_project() {
    // Must not accidentally match everything when the root is unknown.
    let d = decide_file(&cfg(), HOME, None, "C:/somewhere/else/a.rs");
    assert!(matches!(d, Decision::Ask(_)), "got {d:?}");
}

#[test]
fn the_reason_names_the_setting_for_an_ordinary_path() {
    if let Decision::Ask(reason) = decide_file(&cfg(), HOME, None, "C:/nowhere/x.txt") {
        assert!(reason.contains("write.allow_paths"), "got: {reason}");
    } else {
        panic!("expected Ask");
    }
}
