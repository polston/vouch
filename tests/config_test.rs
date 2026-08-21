use vouch::config::{load, Action};

const SAMPLE: &str = r#"
version = 1

[lang.bash]
default = "allow"

[lang.bash.constructs]
dynamic_command = "allow"
parse_failure = "ask"

[write]
default = "ask"
allow_paths = ["$PROJECT_ROOT/**", "C:/work/**"]

[protected]
paths = ["$HOME/.claude/settings.json"]
"#;

#[test]
fn loads_defaults_and_constructs() {
    let c = load(SAMPLE).expect("parses");
    assert_eq!(c.lang_default("bash"), Action::Allow);
    assert_eq!(c.construct_action("bash", "dynamic_command"), Action::Allow);
    assert_eq!(c.construct_action("bash", "parse_failure"), Action::Ask);
}

#[test]
fn unknown_construct_falls_back_to_ask_not_allow() {
    let c = load(SAMPLE).expect("parses");
    // Absence of knowledge is never the permissive case.
    assert_eq!(c.construct_action("bash", "something_new"), Action::Ask);
}

#[test]
fn rejects_an_invalid_action_word() {
    let bad = "version = 1\n[lang.bash]\ndefault = \"maybe\"\n";
    assert!(load(bad).is_err());
}

#[test]
fn protected_paths_are_loaded() {
    let c = load(SAMPLE).expect("parses");
    assert!(c.protected.iter().any(|p| p.contains("settings.json")));
}

#[test]
fn an_empty_config_is_valid_and_conservative() {
    let c = load("version = 1\n").expect("parses");
    assert_eq!(c.lang_default("bash"), Action::Ask);
    assert_eq!(c.write.default, Action::Ask);
    assert_eq!(c.construct_action("bash", "dynamic_command"), Action::Ask);
}

#[test]
fn the_shipped_example_config_is_valid() {
    let text = std::fs::read_to_string("vouch.example.toml").expect("example config exists");
    load(&text).expect("example config must parse");
}

/// Rot guard for the my-knowledge example at the bottom of `vouch.example.toml`
/// (final whole-branch review of the place-scoped-rules changeset, finding 1,
/// Task 14 ledger line): that block is shown commented out, because it
/// belongs to a DIFFERENT schema than the rest of the file (`my-knowledge.toml`,
/// not `config.toml`), so `the_shipped_example_config_is_valid` above never
/// reads it — comments are just comments to `config::load`. The block refused
/// to load for real once (an extra `source =` line `[[program]]` has no field
/// for), and nothing caught it until an operator would have. This strips the
/// `# ` comment markers back off and loads the result through the real
/// knowledge parser, the same one `knowledge::read_one` calls, so the example
/// stays honest the way the config half already is pinned to be.
#[test]
fn the_shipped_my_knowledge_example_loads() {
    let text = std::fs::read_to_string("vouch.example.toml").expect("example config exists");
    // `str::lines` strips a trailing `\r` regardless of whether the file uses
    // LF or CRLF, so the file's own line endings (this one is CRLF) never
    // enter the comparison below. Anchored on the LINE being exactly
    // "# [[program]]", not a substring search: the prose two paragraphs above
    // ("...my-knowledge.toml, on a\n# [[program]] entry. Shown here...")
    // contains that same text mid-sentence, on a line that is NOT exactly it.
    let lines: Vec<&str> = text.lines().collect();
    let start = lines
        .iter()
        .position(|l| *l == "# [[program]]")
        .expect("the my-knowledge example block is no longer where this test looks for it");
    let block: Vec<&str> = lines[start..]
        .iter()
        // The block is a run of comment lines; the first one that is JUST
        // "#" (no trailing space, nothing after) is the blank separator
        // before the prose paragraph that follows the block, not part of it.
        .take_while(|l| l.starts_with('#') && l.trim() != "#")
        .copied()
        .collect();
    assert!(!block.is_empty(), "found the marker but no lines followed it");
    let uncommented = block
        .iter()
        .map(|l| l.strip_prefix("# ").or_else(|| l.strip_prefix('#')).unwrap_or(l))
        .collect::<Vec<_>>()
        .join("\n");
    let kb = vouch::guards::load(&uncommented)
        .expect("the shipped my-knowledge example must parse — copying it verbatim must not refuse an operator's file");
    assert_eq!(kb.program.len(), 1, "{uncommented}");
    assert_eq!(kb.program[0].match_names, vec!["probe-tool".to_string()]);
    assert!(kb.program[0].only_under.is_some(), "the example exists to show only_under; {uncommented}");
}

// --- [lang.*] becomes the only spelling (Task 5) ---------------------------

#[test]
fn the_old_top_level_spelling_refuses_the_load_with_a_pointer() {
    let e = load("version = 1\n[bash]\ndefault = \"allow\"\n").unwrap_err();
    assert!(e.contains("[lang.bash]"), "the refusal must point at the new spelling: {e}");
}

#[test]
fn lang_bash_is_read_and_not_clobbered() {
    // Before this task `load` inserted the top-level sections OVER the lang
    // map (config.rs's old `langs.insert("bash".into(), raw.bash)`), so a
    // `[lang.bash]` section was silently replaced by the absent `[bash]`'s
    // default. This pins the fix.
    let c = load("version = 1\n[lang.bash]\ndefault = \"ask\"\n").unwrap();
    assert_eq!(c.lang_default("bash"), Action::Ask);
}

#[test]
fn wrap_depth_parses_and_is_optional() {
    let c = load("version = 1\n[lang.python]\nwrap_depth = 2\n").unwrap();
    assert_eq!(c.lang("python").unwrap().wrap_depth, Some(2));
    let c = load("version = 1\n[lang.python]\ndefault = \"allow\"\n").unwrap();
    assert_eq!(c.lang("python").unwrap().wrap_depth, None);
}

#[test]
fn an_absent_lang_section_defaults_to_ask() {
    let c = load("version = 1\n").unwrap();
    assert_eq!(c.lang_default("python"), Action::Ask);
}

#[test]
fn a_construct_prompt_names_the_new_spelling_exactly() {
    // Tighten one existing pin from a contains("bash.constructs") substring
    // (true for both spellings, since "lang.bash.constructs" contains
    // "bash.constructs" too) to the full "lang.bash.constructs." string, so
    // the prompt and the spelling the config actually accepts cannot drift
    // apart again silently.
    let reason = vouch::engine::construct_reason_for("bash", "heredoc");
    assert!(
        reason.contains("lang.bash.constructs."),
        "the prompt does not name the exact accepted spelling: {reason}"
    );
}

#[test]
fn a_shadow_section_loads_and_answers_the_accessors() {
    let cfg = load("version = 1\n[shadow]\nstand_down = \"keep-deny\"\nmodes = [\"auto\", \"dontAsk\"]\n").unwrap();
    assert_eq!(cfg.stand_down(), vouch::config::StandDown::KeepDeny);
    assert!(cfg.stands_down_in("auto"));
    assert!(!cfg.stands_down_in("default"));
    assert!(!cfg.stands_down_in(""), "an empty mode must never match");
}

#[test]
fn no_shadow_section_means_off() {
    let cfg = load("version = 1\n").unwrap();
    assert_eq!(cfg.stand_down(), vouch::config::StandDown::Off);
    assert!(!cfg.stands_down_in("auto"));
}

#[test]
fn a_shadow_section_without_stand_down_refuses() {
    let e = load("version = 1\n[shadow]\nmodes = [\"auto\"]\n").unwrap_err();
    assert!(e.contains("keep-deny") && e.contains("full") && e.contains("off"), "{e}");
}

#[test]
fn an_unknown_stand_down_value_refuses() {
    assert!(load("version = 1\n[shadow]\nstand_down = \"maybe\"\nmodes = [\"auto\"]\n").is_err());
}

#[test]
fn an_unknown_mode_spelling_refuses() {
    let e = load("version = 1\n[shadow]\nstand_down = \"full\"\nmodes = [\"Auto\"]\n").unwrap_err();
    assert!(e.contains("Auto"), "the refusal names the bad spelling: {e}");
}

#[test]
fn a_written_empty_modes_list_refuses_in_every_state() {
    for t in ["keep-deny", "full", "off"] {
        let text = format!("version = 1\n[shadow]\nstand_down = \"{t}\"\nmodes = []\n");
        assert!(load(&text).is_err(), "empty list must refuse under {t}");
    }
}

#[test]
fn an_armed_toggle_with_absent_modes_refuses_but_off_parks() {
    assert!(load("version = 1\n[shadow]\nstand_down = \"keep-deny\"\n").is_err());
    assert!(load("version = 1\n[shadow]\nstand_down = \"off\"\n").is_ok(), "off with no modes is the parked state");
}
