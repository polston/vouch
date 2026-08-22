use std::io::Write;
use std::process::{Command, Stdio};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_vouch")
}

/// A directory to hand the child process as `HOME`/`USERPROFILE`.
///
/// [review] Neither is pinned by cargo. The config-path fallback reads them
/// today, and a later task wires up the banner and the moved-file list to
/// read them too (both exist in `src/` already — `guards::gaps()` and
/// `knowledge::former_path()` — but nothing calls them yet). This pin is
/// precautionary ahead of that: on a machine with the pre-move layout (a real
/// `~/.config/vouch.toml` or `~/.config/knowledge.toml` left over from before
/// everything moved under `~/.config/vouch/`), a spawned decision could pick
/// up a stray config now, or moved-file paragraphs once that task lands —
/// home-dependent output either way. A fresh, empty scratch directory has
/// none of that.
fn pinned_home() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join("vouch_cli_test_home");
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn run_hook(snippet: &str, extra: &[&str]) -> (bool, String) {
    run_hook_with_envs(snippet, extra, &[])
}

/// The same hook invocation, with `envs` laid over the pinned defaults. An
/// entry naming a variable the defaults already set wins, because it is applied
/// second — that is how a caller points the state directory or the knowledge
/// files at files of its own.
fn run_hook_with_envs(
    snippet: &str,
    extra: &[&str],
    envs: &[(&str, &std::path::Path)],
) -> (bool, String) {
    let mut cmd = Command::new(bin());
    // Tests must not write to the REAL journal. Without this, every CLI test
    // appended a decision to it: 915 of 1,328 records in a real journal carried
    // this file's session id. `review` builds its evidence from that journal,
    // so test data sat in the same pile as the user's actual answers. It never
    // became approval evidence only because tests fire no terminal events —
    // luck, not isolation.
    cmd.env(
        "VOUCH_STATE_DIR",
        std::env::temp_dir().join("vouch_cli_test_scratch"),
    );
    let home = pinned_home();
    cmd.env("HOME", &home).env("USERPROFILE", &home);
    for (name, value) in envs {
        cmd.env(name, value);
    }
    cmd.arg("--hook");
    for e in extra {
        cmd.arg(e);
    }
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(snippet.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).to_string(),
    )
}

#[test]
fn shadow_mode_emits_absolutely_nothing() {
    let (ok, out) = run_hook(
        r#"{"session_id":"s","cwd":"C:/claude","tool_name":"Bash","tool_input":{"command":"rm -rf /"}}"#,
        &["--shadow"],
    );
    assert!(ok);
    assert!(
        out.trim().is_empty(),
        "shadow mode must never emit a decision, got: {out}"
    );
}

#[test]
fn a_broken_snippet_never_breaks_the_session() {
    let (ok, _) = run_hook("not json at all", &[]);
    assert!(ok, "must exit 0 even on unreadable input");
}

#[test]
fn empty_input_never_breaks_the_session() {
    let (ok, _) = run_hook("", &[]);
    assert!(ok);
}

#[test]
fn every_tool_gets_a_decision() {
    // This test used to assert the opposite — that vouch stays silent on tools
    // it has no scanner for. That silence was the same "unknown means allowed"
    // inversion as unmodelled programs, one level up: 46.5% of recorded tool
    // calls got no decision, so the harness decided alone.
    //
    // A recognised tool is allowed and says why.
    let (ok, out) = run_hook(
        r#"{"session_id":"s","cwd":"C:/claude","tool_name":"WebSearch","tool_input":{}}"#,
        &[],
    );
    assert!(ok);
    assert!(
        out.contains("\"allow\""),
        "a recognised tool should be allowed, got: {out}"
    );
}

#[test]
fn an_unrecognised_tool_asks_and_names_its_setting() {
    let (ok, out) = run_hook(
        r#"{"session_id":"s","cwd":"C:/claude","tool_name":"SomeToolNobodyDescribed","tool_input":{}}"#,
        &[],
    );
    assert!(ok);
    assert!(out.contains("\"ask\""), "an unknown tool must ask, got: {out}");
    assert!(
        out.contains("tools.SomeToolNobodyDescribed"),
        "the prompt must name the setting that turns it off, got: {out}"
    );
}

// --- reason wording: a tool can ask for three different reasons, and the ---
// --- prompt must never claim knowledge.toml said something it did not.  ---
//
// [review] `src/main.rs`'s tool-prompt used to compute "is this described"
// and "what do I do about it" as two independent facts and pick wording from
// whether the FIRST was true. That is wrong the moment the SECOND has more
// than one possible cause. Each test below asserts the actual sentence, not
// just the verdict, because a right verdict with a false explanation is
// exactly the defect this task exists to remove (§5 of CLAUDE.md: every
// prompt must name the real setting, truthfully).

fn run_hook_with_config(snippet: &str, config: &str) -> (bool, String) {
    let home = pinned_home();
    let mut cmd = Command::new(bin());
    cmd.env(
        "VOUCH_STATE_DIR",
        std::env::temp_dir().join("vouch_cli_test_scratch"),
    )
    .env("HOME", &home)
    .env("USERPROFILE", &home)
    .env("VOUCH_CONFIG", config)
    .arg("--hook");
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(snippet.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).to_string(),
    )
}

/// State 1: vouch has no `[[tool]]` entry for this tool at all.
#[test]
fn an_undescribed_tool_says_it_has_no_description() {
    let (ok, out) = run_hook(
        r#"{"session_id":"s","cwd":"C:/claude","tool_name":"SomeToolNobodyDescribed","tool_input":{}}"#,
        &[],
    );
    assert!(ok);
    assert!(out.contains("\"ask\""), "got: {out}");
    assert!(
        out.contains("vouch has no scanner for this tool"),
        "must say vouch does not recognise it, got: {out}"
    );
    assert!(
        !out.contains("described in knowledge.toml"),
        "must not claim a description that does not exist, got: {out}"
    );
}

/// State 2: an entry names this tool, and its own `action` decided — no
/// `[tools]` section in play at all.
#[test]
fn a_described_tool_set_to_ask_says_knowledge_toml_set_it() {
    let (ok, out) = run_hook(
        r#"{"session_id":"s","cwd":"C:/claude","tool_name":"ExitWorktree","tool_input":{}}"#,
        &[],
    );
    assert!(ok);
    assert!(out.contains("\"ask\""), "got: {out}");
    assert!(
        out.contains("described in knowledge.toml and set to ask there"),
        "must credit knowledge.toml's own action, got: {out}"
    );
    assert!(
        !out.contains("[tools] section"),
        "no config names any tool here, so this sentence must not appear, got: {out}"
    );
}

/// State 3: THE bug. `Read` ships with no `action` (so Allow on its own), but
/// a config naming some OTHER tool makes the `[tools]` section govern every
/// tool, including this unnamed one. Reproduced by the reviewer: verdict
/// flips from Allow to Ask, and the old text still said knowledge.toml set it
/// to ask — which it never did.
#[test]
fn a_config_that_governs_other_tools_does_not_blame_knowledge_toml() {
    let (ok, out) = run_hook_with_config(
        r#"{"session_id":"s","cwd":"C:/claude","tool_name":"Read","tool_input":{}}"#,
        "tests/fixtures/tools_names_other.toml",
    );
    assert!(ok);
    assert!(
        out.contains("\"ask\""),
        "naming any tool must make an unnamed one ask, got: {out}"
    );
    assert!(
        out.contains("[tools] section names at least one OTHER tool"),
        "must say the config's [tools] section is why, got: {out}"
    );
    assert!(
        !out.contains("and set to ask there"),
        "must not claim knowledge.toml set this to ask — it never did, got: {out}"
    );
}

/// Same class of bug, one step over: the operator's OWN config names this
/// exact tool. That decided it, not knowledge.toml's `action` field — even
/// though knowledge.toml also describes this tool.
#[test]
fn a_tool_named_directly_in_config_is_not_credited_to_knowledge_toml() {
    let (ok, out) = run_hook_with_config(
        r#"{"session_id":"s","cwd":"C:/claude","tool_name":"ExitWorktree","tool_input":{}}"#,
        "tests/fixtures/tools_named_exact.toml",
    );
    assert!(ok);
    assert!(out.contains("\"ask\""), "got: {out}");
    assert!(
        out.contains("your OWN config names it directly"),
        "must credit the operator's own [tools] entry, got: {out}"
    );
    assert!(
        !out.contains("and set to ask there"),
        "must not claim knowledge.toml's action decided this, got: {out}"
    );
}

/// The same defect end to end, against the real shipped `knowledge.toml`
/// rather than a synthetic pair: an operator file that names `ExitWorktree`
/// and says nothing else must leave the shipped `action = "ask"` in force.
/// Before the fix this came back `allow`, and the whole prompt with it.
#[test]
fn my_tool_entry_that_says_nothing_does_not_turn_a_shipped_ask_into_an_allow() {
    let home = pinned_home();
    let mut cmd = Command::new(bin());
    cmd.env(
        "VOUCH_STATE_DIR",
        std::env::temp_dir().join("vouch_cli_test_scratch"),
    )
    .env("HOME", &home)
    .env("USERPROFILE", &home)
    .env("VOUCH_MY_KNOWLEDGE", "tests/fixtures/my_knowledge_silent_tool.toml")
    .arg("--hook");
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(
            br#"{"session_id":"s","cwd":"C:/claude","tool_name":"ExitWorktree","tool_input":{}}"#,
        )
        .unwrap();
    let out = child.wait_with_output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("\"permissionDecision\":\"ask\""),
        "an operator entry that said nothing turned a shipped ask into an allow: {text}"
    );
}

/// [review] `knowledge::config_dir` builds a `/`-joined string and
/// `PathBuf::join` appends the PLATFORM separator, so this printed
/// `.../.config/vouch\my-knowledge.toml` — forward slashes throughout, then
/// one backslash, which a shell pasting the path unquoted silently eats.
/// `vouch trust` is the one command whose entire output is "here is the file I
/// wrote", and it was the one place not using `knowledge::display_path`.
///
/// `--` with no program name only prints the usage; nothing is written.
#[test]
fn trust_prints_a_path_with_one_kind_of_separator() {
    let home = pinned_home();
    let out = Command::new(bin())
        .arg("trust")
        // Pinned by `.cargo/config.toml` to a relative path under target/,
        // which has no separator in it at all. Removing it is what makes this
        // test look at the path vouch BUILDS from the home directory.
        .env_remove("VOUCH_MY_KNOWLEDGE")
        .env(
            "VOUCH_STATE_DIR",
            std::env::temp_dir().join("vouch_cli_test_scratch"),
        )
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    let line = err
        .lines()
        .find(|l| l.contains("writes to"))
        .unwrap_or_else(|| panic!("the usage must name the file it writes: {err}"));
    assert!(
        !line.contains('\\'),
        "a path meant for pasting mixes separators: {line}"
    );
}

/// [review] `vouch doctor` said "add any of these to knowledge.toml". That is
/// the file that SHIPS, and `scripts/install-knowledge.sh --force` replaces it
/// wholesale — so a description added where doctor pointed is thrown away on
/// the next install. `my-knowledge.toml` is the operator's own file and
/// nothing overwrites it.
#[test]
fn doctor_points_at_the_file_that_nothing_overwrites() {
    let home = pinned_home();
    let state = std::env::temp_dir().join("vouch_cli_test_doctor_state");
    let _ = std::fs::remove_dir_all(&state);

    // doctor reports nothing at all until a decision has been recorded, so
    // make one about a program vouch has no description of.
    let mut rec = Command::new(bin());
    rec.env("VOUCH_STATE_DIR", &state)
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .arg("--hook");
    let mut child = rec
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(
            br#"{"hook_event_name":"PreToolUse","tool_use_id":"d1","session_id":"d1","cwd":"C:/claude","tool_name":"Bash","tool_input":{"command":"totallymadeupprog x"}}"#,
        )
        .unwrap();
    child.wait_with_output().unwrap();

    let out = Command::new(bin())
        .arg("doctor")
        .env("VOUCH_STATE_DIR", &state)
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("add any of these to my-knowledge.toml"),
        "doctor must point at the operator's own file: {text}"
    );
    assert!(
        !text.contains("add any of these to knowledge.toml"),
        "doctor still points at the file `install-knowledge.sh --force` overwrites: {text}"
    );
}

/// Builds a journal record whose `reason` carries the exact marker
/// `engine::destination_from_candidates` appends on a rule-4 ask: `  the
/// option '<flag>' is not described for '<head>'`. Written straight through
/// the journal's own API — this bucket is a historical-fact readout, not a
/// re-scan, so there is no need to route it through a hook invocation at all.
fn undeclared_option_record(id: &str, head: &str, flag: &str) -> vouch::journal::Record {
    vouch::journal::Record {
        id: id.into(),
        ts: vouch::journal::now_epoch_secs(),
        session: "s1".into(),
        tool: "PowerShell".into(),
        cmd: format!("{head} x"),
        verdict: "ask".into(),
        reason: format!(
            "vouch stopped on: unresolved_path\n  the option '{flag}' is not described for '{head}'\n"
        ),
        mode: "live".into(),
        cwd: String::new(),
        outcome: vouch::outcome::Outcome::Pending,
        lang: String::new(),
        permission_mode: String::new(),
    }
}

#[test]
fn doctor_aggregates_undeclared_dir_change_options_by_spelling() {
    // spec 2026-07-31 §9.1's third bucket: this is the one instrument that
    // can measure PowerShell noise, since no bash corpus bounds it. Two
    // spellings of the same head plus one other head, at three DIFFERENT
    // counts, so the ordering assertion below cannot pass by accident of
    // HashMap iteration order.
    let home = pinned_home();
    let state = std::env::temp_dir().join("vouch_cli_test_doctor_undeclared");
    let _ = std::fs::remove_dir_all(&state);

    let mut n = 0;
    for (head, flag, count) in [
        ("set-location", "-erroraction", 3),
        ("other-mover", "-someflag", 2),
        ("set-location", "-ea", 1),
    ] {
        for _ in 0..count {
            n += 1;
            vouch::journal::append(&state, &undeclared_option_record(&format!("id{n}"), head, flag))
                .unwrap();
        }
    }

    let out = Command::new(bin())
        .arg("doctor")
        .env("VOUCH_STATE_DIR", &state)
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("undeclared options on dir-changers, by spelling"),
        "section missing: {text}"
    );
    assert!(
        text.contains("3  set-location -erroraction"),
        "wrong count for set-location -erroraction: {text}"
    );
    assert!(
        text.contains("2  other-mover -someflag"),
        "wrong count for other-mover -someflag: {text}"
    );
    assert!(
        text.contains("1  set-location -ea"),
        "wrong count for set-location -ea: {text}"
    );
    // Sorted by count descending: 3, then 2, then 1.
    let i3 = text.find("set-location -erroraction").expect("listed");
    let i2 = text.find("other-mover -someflag").expect("listed");
    let i1 = text.find("set-location -ea").expect("listed");
    assert!(i3 < i2 && i2 < i1, "not sorted by count descending: {text}");
}

#[test]
fn doctor_omits_the_undeclared_options_section_when_nothing_carries_the_marker() {
    let home = pinned_home();
    let state = std::env::temp_dir().join("vouch_cli_test_doctor_undeclared_empty");
    let _ = std::fs::remove_dir_all(&state);

    let rec = vouch::journal::Record {
        id: "id1".into(),
        ts: vouch::journal::now_epoch_secs(),
        session: "s1".into(),
        tool: "Bash".into(),
        cmd: "echo hi".into(),
        verdict: "ask".into(),
        reason: "vouch stopped on: heredoc\n  what that means: ...".into(),
        mode: "live".into(),
        cwd: String::new(),
        outcome: vouch::outcome::Outcome::Pending,
        lang: String::new(),
        permission_mode: String::new(),
    };
    vouch::journal::append(&state, &rec).unwrap();

    let out = Command::new(bin())
        .arg("doctor")
        .env("VOUCH_STATE_DIR", &state)
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        !text.contains("undeclared options on dir-changers"),
        "section must be absent when no record carries the marker: {text}"
    );
}

/// Task 9: a call routed through a tool whose entry declares an ARRAY snippet
/// (`commands[].command`, the batch shape) must journal one record per
/// extracted command, all sharing the call's `tool_use_id`, and each carrying
/// the language it was decided in — not one record with the commands joined.
#[test]
fn a_batch_shaped_call_journals_one_record_per_command_sharing_the_tool_use_id() {
    let home = pinned_home();
    let state = std::env::temp_dir().join("vouch_cli_test_batch_journal");
    let _ = std::fs::remove_dir_all(&state);

    let (ok, _) = {
        let mut cmd = Command::new(bin());
        cmd.env("VOUCH_STATE_DIR", &state)
            .env("HOME", &home)
            .env("USERPROFILE", &home)
            .env("VOUCH_MY_KNOWLEDGE", "tests/fixtures/my_knowledge_batch_tool.toml")
            .arg("--hook");
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(
                br#"{"session_id":"s","cwd":"C:/Users/dev","tool_use_id":"batch1","tool_name":"mcp__p_s__batch","tool_input":{"commands":[{"command":"ls -la"},{"command":"pwd"}]}}"#,
            )
            .unwrap();
        let out = child.wait_with_output().unwrap();
        (out.status.success(), String::from_utf8_lossy(&out.stdout).to_string())
    };
    assert!(ok);

    let recs = vouch::journal::all(&state);
    assert_eq!(recs.len(), 2, "one record per extracted command, got: {recs:?}");
    assert!(recs.iter().all(|r| r.id == "batch1"), "must share the tool_use_id: {recs:?}");
    assert!(recs.iter().all(|r| r.lang == "bash"), "must carry the decided language: {recs:?}");
    assert_eq!(recs[0].cmd, "ls -la");
    assert_eq!(recs[1].cmd, "pwd");
}

/// Task 9: doctor must read a journal row's own `lang` to pick a scanner,
/// not a tool-name table. `tool` here matches no entry in the shipped
/// knowledge.toml at all — the old `syntax::lang_for_tool` table would have
/// skipped it outright, and so would a knowledge-lookup fallback, so only
/// `rec.lang` can make this row re-scannable.
#[test]
fn doctor_rescans_a_snippet_row_using_its_own_recorded_language() {
    let home = pinned_home();
    let state = std::env::temp_dir().join("vouch_cli_test_doctor_snippet_lang");
    let _ = std::fs::remove_dir_all(&state);

    let rec = vouch::journal::Record {
        id: "id1".into(),
        ts: vouch::journal::now_epoch_secs(),
        session: "s1".into(),
        tool: "mcp__p_s__batch".into(),
        cmd: "totallyunmodeledprogram123 --flag".into(),
        verdict: "allow".into(),
        reason: String::new(),
        mode: "live".into(),
        cwd: String::new(),
        outcome: vouch::outcome::Outcome::Pending,
        lang: "bash".into(),
        permission_mode: String::new(),
    };
    vouch::journal::append(&state, &rec).unwrap();

    let out = Command::new(bin())
        .arg("doctor")
        .env("VOUCH_STATE_DIR", &state)
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("totallyunmodeledprogram123"),
        "doctor must re-scan a snippet row by its own recorded lang: {text}"
    );
}

#[test]
fn explain_names_the_setting() {
    let home = pinned_home();
    let out = Command::new(bin())
        .arg("explain")
        .arg(r#"P=x; "$P" y"#)
        .env("VOUCH_CONFIG", "tests/fixtures/ask_dynamic.toml")
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("dynamic_command"), "got: {text}");
    assert!(text.contains("lang.bash.constructs"), "got: {text}");
}

/// Task 12: `explain` now always announces where it judged from, so the
/// verdict itself no longer leads the output — it follows that line.
#[test]
fn explain_reports_allow_for_an_ordinary_command() {
    let home = pinned_home();
    let out = Command::new(bin())
        .arg("explain")
        .arg("git status")
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.starts_with("judged from:"), "got: {text}");
    assert!(text.contains("ALLOW"), "got: {text}");
}

#[test]
fn a_live_run_emits_a_decision_for_a_gated_tool() {
    let (ok, out) = run_hook(
        r#"{"session_id":"s","cwd":"C:/claude","tool_name":"Write","tool_input":{"file_path":"C:/nowhere/at/all/x.txt"}}"#,
        &[],
    );
    assert!(ok);
    assert!(
        out.contains("permissionDecision"),
        "expected a decision, got: {out}"
    );
    assert!(!out.contains("defer"), "must never emit defer: {out}");
}

/// `explain bash '<cmd>'` used to explain the one-word command `bash` and
/// print ALLOW. The binary must now explain the command it was handed.
#[test]
fn explain_bash_explains_the_command_not_the_selector() {
    let home = pinned_home();
    let out = Command::new(bin())
        .arg("explain")
        .arg("bash")
        .arg(r#"P=x; "$P" y"#)
        .env("VOUCH_CONFIG", "tests/fixtures/ask_dynamic.toml")
        .env("VOUCH_STATE_DIR", std::env::temp_dir().join("vouch_cli_test_scratch"))
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("dynamic_command"),
        "explained the selector instead of the command, got: {text}"
    );
}

#[test]
fn explain_rejects_an_unrecognised_extra_argument() {
    let home = pinned_home();
    let out = Command::new(bin())
        .arg("explain")
        .arg("frobnicate")
        .arg("ls -la")
        .env("VOUCH_CONFIG", "tests/fixtures/ask_dynamic.toml")
        .env("VOUCH_STATE_DIR", std::env::temp_dir().join("vouch_cli_test_scratch"))
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "a rejected invocation must not exit 0");
    assert!(err.contains("one argument"), "got: {err}");
}

/// `why` had the identical defect and must get the identical fix.
#[test]
fn why_bash_explains_the_command_not_the_selector() {
    let home = pinned_home();
    let out = Command::new(bin())
        .arg("why")
        .arg("bash")
        .arg(r#"P=x; "$P" y"#)
        .env("VOUCH_CONFIG", "tests/fixtures/ask_dynamic.toml")
        .env("VOUCH_STATE_DIR", std::env::temp_dir().join("vouch_cli_test_scratch"))
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("dynamic_command"),
        "explained the selector instead of the command, got: {text}"
    );
}

/// Task 12: `--cwd` lets the operator ask what vouch would say from a
/// directory they are not actually standing in. The zone config makes an
/// otherwise-unrecognised program ask everywhere except under
/// `C:/scratch/**`, so an ALLOW here can only have come from `--cwd` having
/// been read and honoured.
#[test]
fn explain_with_cwd_judges_from_the_given_directory_and_allows_via_the_zone() {
    let home = pinned_home();
    let state = std::env::temp_dir().join("vouch_cli_test_explain_cwd_zone");
    let cfg_path = std::env::temp_dir().join("vouch_cli_test_explain_cwd_zone.toml");
    std::fs::write(
        &cfg_path,
        "[lang.bash]\ndefault = \"allow\"\n[lang.bash.constructs]\nunmodeled_command = \"ask\"\n\
         [run]\ntrust_all_under = [\"C:/scratch/**\"]\n",
    )
    .unwrap();
    let out = Command::new(bin())
        .arg("explain")
        .arg("--cwd")
        .arg("C:/scratch/j")
        .arg("someunknownprogramzz x")
        .env("VOUCH_CONFIG", &cfg_path)
        .env("VOUCH_STATE_DIR", &state)
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.starts_with("judged from: C:/scratch/j"),
        "must say the given directory, before the verdict: {text}"
    );
    assert!(text.contains("ALLOW"), "the zone should have allowed it: {text}");
    assert!(
        text.contains("trust_all_under"),
        "the zone should be named as the reason: {text}"
    );
}

/// The other half: no `--cwd` at all falls back to the process's own
/// directory, and the fallback is still announced.
#[test]
fn explain_without_cwd_flag_judges_from_the_process_directory() {
    let home = pinned_home();
    let dir = std::env::temp_dir().join("vouch_cli_test_explain_no_cwd_flag");
    std::fs::create_dir_all(&dir).unwrap();
    let out = Command::new(bin())
        .arg("explain")
        .arg("git status")
        .current_dir(&dir)
        .env("VOUCH_STATE_DIR", std::env::temp_dir().join("vouch_cli_test_scratch"))
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    let expected = dir.to_string_lossy().replace('\\', "/");
    assert!(
        text.contains(&format!("judged from: {expected}")),
        "must judge from the process's own directory when no --cwd is given: {text}"
    );
}

/// Task 12: `vouch why`'s journal-row arm used to only print what was
/// recorded. It now also re-decides the same command under the CURRENT
/// config, from the directory the journal recorded — proven the same way as
/// the `explain` test above: only the zone can turn this unrecognised
/// program's re-decision into an allow.
#[test]
fn why_rescans_a_journalled_rows_own_cwd_and_names_the_zone_that_allowed_it() {
    let home = pinned_home();
    let state = std::env::temp_dir().join("vouch_cli_test_why_redecide_zone");
    let _ = std::fs::remove_dir_all(&state);
    let cfg_path = std::env::temp_dir().join("vouch_cli_test_why_redecide_zone.toml");
    std::fs::write(
        &cfg_path,
        "[lang.bash]\ndefault = \"allow\"\n[lang.bash.constructs]\nunmodeled_command = \"ask\"\n\
         [run]\ntrust_all_under = [\"C:/scratch/**\"]\n",
    )
    .unwrap();

    let rec = vouch::journal::Record {
        id: "id1".into(),
        ts: vouch::journal::now_epoch_secs(),
        session: "s1".into(),
        tool: "Bash".into(),
        cmd: "someunknownprogramzz x".into(),
        verdict: "ask".into(),
        reason: "some earlier reason, since superseded".into(),
        mode: "live".into(),
        cwd: "C:/scratch/j".into(),
        outcome: vouch::outcome::Outcome::Pending,
        lang: String::new(),
        permission_mode: String::new(),
    };
    vouch::journal::append(&state, &rec).unwrap();

    let out = Command::new(bin())
        .arg("why")
        .env("VOUCH_CONFIG", &cfg_path)
        .env("VOUCH_STATE_DIR", &state)
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("re-decided now, from"),
        "must re-decide from the recorded cwd: {text}"
    );
    assert!(text.contains("C:/scratch/j"), "must name the recorded directory: {text}");
    assert!(
        text.contains("trust_all_under"),
        "the zone should be named as the current allow's reason: {text}"
    );
}

/// Carry-forward fix: `why <command>`'s explicit-command arm parsed `--cwd`
/// (via the shared `parse_target`) but never read it — the flag was accepted
/// and silently ignored. It must honour `--cwd` exactly as `explain` does:
/// decide from the given directory and announce it.
#[test]
fn why_with_a_command_honours_cwd_and_judges_from_the_given_directory() {
    let home = pinned_home();
    let cfg_path = std::env::temp_dir().join("vouch_cli_test_why_cmd_cwd_zone.toml");
    std::fs::write(
        &cfg_path,
        "[lang.bash]\ndefault = \"allow\"\n[lang.bash.constructs]\nunmodeled_command = \"ask\"\n\
         [run]\ntrust_all_under = [\"C:/scratch/**\"]\n",
    )
    .unwrap();
    let out = Command::new(bin())
        .arg("why")
        .arg("--cwd")
        .arg("C:/scratch/j")
        .arg("someunknownprogramzz x")
        .env("VOUCH_CONFIG", &cfg_path)
        .env("VOUCH_STATE_DIR", std::env::temp_dir().join("vouch_cli_test_why_cmd_cwd_state"))
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("judged from: C:/scratch/j"),
        "must say the given directory: {text}"
    );
    assert!(text.contains("ALLOW"), "the zone should have allowed it: {text}");
    assert!(
        text.contains("trust_all_under"),
        "the zone should be named as the reason: {text}"
    );
}

/// [review, final review Finding 2] `vouch trust` writes a comment into both
/// the whole-program and the scoped entry templates saying the entry is ALSO
/// read as a claim that the program does not change the shell's working
/// directory — the flip side of `changes_dir`: an entry with no `changes_dir`
/// key means "stays put", not "unknown". Nothing pinned that sentence, so a
/// future edit to either template could drop it silently.
#[test]
fn trust_templates_claim_the_program_does_not_change_the_working_directory() {
    let home = pinned_home();
    let scratch = |name: &str| {
        let p = std::env::temp_dir().join(name);
        let _ = std::fs::remove_file(&p);
        p
    };

    // Whole-program template: `vouch trust <program>`, no subcommands.
    let whole = scratch("vouch_cli_test_trust_template_whole.toml");
    let out = Command::new(bin())
        .arg("trust")
        .arg("totallymadeuptrustwhole")
        .env("VOUCH_MY_KNOWLEDGE", &whole)
        .env("VOUCH_STATE_DIR", std::env::temp_dir().join("vouch_cli_test_scratch"))
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "whole-program trust did not succeed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let written = std::fs::read_to_string(&whole).expect("trust must have written the file");
    assert!(
        written.contains("does not change the shell's working directory"),
        "the whole-program template dropped the changes_dir claim: {written}"
    );
    assert!(
        written.contains("add `changes_dir` to this entry"),
        "the whole-program template dropped the remedy: {written}"
    );

    // Scoped template: `vouch trust <program> <subcommand>`.
    let scoped = scratch("vouch_cli_test_trust_template_scoped.toml");
    let out = Command::new(bin())
        .arg("trust")
        .arg("totallymadeuptrustscoped")
        .arg("dosomething")
        .env("VOUCH_MY_KNOWLEDGE", &scoped)
        .env("VOUCH_STATE_DIR", std::env::temp_dir().join("vouch_cli_test_scratch"))
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "scoped trust did not succeed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let written = std::fs::read_to_string(&scoped).expect("trust must have written the file");
    assert!(
        written.contains("does not change the shell's working directory"),
        "the scoped template dropped the changes_dir claim: {written}"
    );
    assert!(
        written.contains("add `changes_dir` to this entry"),
        "the scoped template dropped the remedy: {written}"
    );
}

/// [M2.12 defect 1] `vouch trust <path>` used to write `match = ["<path>"]`,
/// which recognition — bare-name comparison — can never match. Trust must
/// write the name it will be compared by, and say it did.
#[test]
fn trust_normalises_a_path_spelled_program_to_the_bare_name() {
    let home = pinned_home();
    let file = std::env::temp_dir().join("vouch_cli_test_trust_path_norm.toml");
    let _ = std::fs::remove_file(&file);
    let out = Command::new(bin())
        .arg("trust")
        .arg("/c/tools/totallymadeuppathprog.exe")
        .env("VOUCH_MY_KNOWLEDGE", &file)
        .env("VOUCH_STATE_DIR", std::env::temp_dir().join("vouch_cli_test_scratch"))
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let written = std::fs::read_to_string(&file).unwrap();
    assert!(
        written.contains("match = [\"totallymadeuppathprog\"]"),
        "entry must carry the bare name recognition compares: {written}"
    );
    assert!(
        !written.contains("/c/tools/"),
        "the path must not be written into the entry: {written}"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("spelled with a directory or extension"),
        "no normalisation note: {stdout}"
    );
    assert!(stdout.contains("`totallymadeuppathprog`"), "{stdout}");
}

/// [M2.14 core] trust used to append an entry and stop — never re-reading the
/// file, never checking the entry fires. Now it reloads what vouch reads and
/// verifies the entry as WRITTEN covers the shape it was asked to cover
/// (`recognises`, not a name-level check — a name-level check is already true
/// before the write whenever the program was known), out loud.
#[test]
fn trust_verifies_the_written_entry_is_recognised() {
    let home = pinned_home();
    let file = std::env::temp_dir().join("vouch_cli_test_trust_verify.toml");
    let _ = std::fs::remove_file(&file);
    let out = Command::new(bin())
        .arg("trust")
        .arg("totallymadeupverifyprog")
        .env("VOUCH_MY_KNOWLEDGE", &file)
        .env("VOUCH_STATE_DIR", std::env::temp_dir().join("vouch_cli_test_scratch"))
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("verified: an entry now recognises `totallymadeupverifyprog`"),
        "no verification line: {stdout}"
    );
}

/// Task 11: an MCP-shaped name (`mcp__server__tool`) must write a `[[tool]]`
/// entry, never a `[[program]]` one — recognition for tools is exact and
/// case-sensitive (guards::tool_entry), so the name must survive untouched,
/// unlike a program's bare_name lowercasing.
#[test]
fn trust_of_an_mcp_tool_writes_a_tool_entry_with_case_preserved() {
    let home = pinned_home();
    let file = std::env::temp_dir().join("vouch_cli_test_trust_mcp_tool.toml");
    let _ = std::fs::remove_file(&file);
    let name = "mcp__TotallyMadeUpServer__DoSomething";
    let out = Command::new(bin())
        .arg("trust")
        .arg(name)
        .env("VOUCH_MY_KNOWLEDGE", &file)
        .env("VOUCH_STATE_DIR", std::env::temp_dir().join("vouch_cli_test_scratch"))
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains(&format!("verified: an entry now recognises `{name}`")),
        "no verification line: {stdout}"
    );
    let written = std::fs::read_to_string(&file).expect("trust must have written the file");
    assert!(
        written.contains("[[tool]]"),
        "an MCP tool name must write a [[tool]] entry: {written}"
    );
    assert!(
        !written.contains("[[program]]"),
        "an MCP tool name must never write a [[program]] entry: {written}"
    );
    assert!(
        written.contains(&format!("match = [{name:?}]")),
        "entry must carry the exact tool name, case preserved: {written}"
    );
}

/// Task 11, spec 2026-08-05 §Server entry rule 5: the whole-server grant has
/// to be said out loud, the same way `--all-subcommands` is for programs.
#[test]
fn trust_of_a_whole_server_writes_a_server_entry() {
    let home = pinned_home();
    let file = std::env::temp_dir().join("vouch_cli_test_trust_mcp_server.toml");
    let _ = std::fs::remove_file(&file);
    let server = "mcp__totallymadeupwholeserver";
    let out = Command::new(bin())
        .arg("trust")
        .arg("--whole-server")
        .arg(server)
        .env("VOUCH_MY_KNOWLEDGE", &file)
        .env("VOUCH_STATE_DIR", std::env::temp_dir().join("vouch_cli_test_scratch"))
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let written = std::fs::read_to_string(&file).expect("trust must have written the file");
    assert!(
        written.contains(&format!("server = {server:?}")),
        "a --whole-server trust must write a server entry: {written}"
    );
    assert!(
        !written.contains("match ="),
        "a server entry names no individual tool: {written}"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("verified"), "no verification line: {stdout}");
}

/// Task 11, spec 2026-08-05 §Server entry: a name shaped like just the server
/// half (`mcp__<server>`, no `__<tail>`) can never fire as a `[[tool]] match`
/// entry — nothing would ever call it by that spelling — so without
/// `--whole-server` it must be refused, naming the flag that does mean it,
/// rather than silently writing a `[[tool]]` entry that can never recognise
/// anything real.
#[test]
fn trust_refuses_a_bare_server_shape_without_the_whole_server_flag() {
    let home = pinned_home();
    let file = std::env::temp_dir().join("vouch_cli_test_trust_mcp_bare_refused.toml");
    let _ = std::fs::remove_file(&file);
    let name = "mcp__totallymadeupbareserver";
    let out = Command::new(bin())
        .arg("trust")
        .arg(name)
        .env("VOUCH_MY_KNOWLEDGE", &file)
        .env("VOUCH_STATE_DIR", std::env::temp_dir().join("vouch_cli_test_scratch"))
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "a bare-server shape without --whole-server must be refused, got: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--whole-server"),
        "the refusal must name the flag that does mean this: {stderr}"
    );
    assert!(
        !file.exists(),
        "a refused trust must not write anything: {}",
        file.display()
    );
}

/// `--whole-server` is a claim about an MCP SERVER: it recognises every tool
/// that server exposes. A name that is not spelled `mcp__<server>` names no
/// server, so there is nothing for the flag to mean. It used to fall through
/// to the program path and write a `[[program]]` entry with the flag silently
/// dropped — the operator asked for one thing and got a different one, with
/// no line saying so. It is refused instead, naming the flag.
#[test]
fn trust_refuses_whole_server_for_a_name_that_is_not_a_server() {
    let home = pinned_home();
    let file = std::env::temp_dir().join("vouch_cli_test_trust_whole_server_nonmcp.toml");
    let _ = std::fs::remove_file(&file);
    let out = Command::new(bin())
        .arg("trust")
        .arg("--whole-server")
        .arg("totallymadeupprogram")
        .env("VOUCH_MY_KNOWLEDGE", &file)
        .env("VOUCH_STATE_DIR", std::env::temp_dir().join("vouch_cli_test_scratch"))
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "--whole-server on a name that is not a server must be refused, got: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--whole-server"),
        "the refusal must name the flag it is about: {stderr}"
    );
    assert!(
        !file.exists(),
        "a refused trust must not write anything: {}",
        file.display()
    );
}

/// [M2.54(3) — do NOT inherit for the tool path] The program path's restore
/// writes the prior content back unconditionally, which mints an empty file
/// when none existed before. The tool path must not: when verification fails
/// and no my-knowledge existed before this run, the freshly written file must
/// be removed entirely, not left behind as a zero-byte artifact. Forced by
/// pointing VOUCH_KNOWLEDGE at a shipped file that fails to parse, so the
/// merge that would have picked up the fresh entry never happens
/// (`knowledge::load_files`: a refused shipped file discards `my`).
#[test]
fn trust_of_an_mcp_tool_removes_a_freshly_written_file_when_verification_fails() {
    let home = pinned_home();
    let file = std::env::temp_dir().join("vouch_cli_test_trust_mcp_verify_fail.toml");
    let _ = std::fs::remove_file(&file);
    let bad_knowledge = std::env::temp_dir().join("vouch_cli_test_trust_mcp_bad_knowledge.toml");
    std::fs::write(&bad_knowledge, "this is not [[[ valid toml").unwrap();
    let out = Command::new(bin())
        .arg("trust")
        .arg("mcp__totallymadeupfailserver__dosomething")
        .env("VOUCH_MY_KNOWLEDGE", &file)
        .env("VOUCH_KNOWLEDGE", &bad_knowledge)
        .env("VOUCH_STATE_DIR", std::env::temp_dir().join("vouch_cli_test_scratch"))
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "a verification failure must be a non-zero exit, got: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        !file.exists(),
        "no my-knowledge existed before this run — a failed verification must remove the \
         freshly written file, not leave a zero-byte one: {}",
        file.display()
    );
}

/// The other half of the same rule: when my-knowledge DID exist before this
/// run, a failed verification must restore its exact prior bytes, not mint an
/// empty file and not leave the (non-firing) entry appended.
#[test]
fn trust_of_an_mcp_tool_restores_prior_content_when_verification_fails() {
    let home = pinned_home();
    let file = std::env::temp_dir().join("vouch_cli_test_trust_mcp_verify_fail_restore.toml");
    let prior = "# a prior comment nobody wrote a description of\n";
    std::fs::write(&file, prior).unwrap();
    let bad_knowledge =
        std::env::temp_dir().join("vouch_cli_test_trust_mcp_bad_knowledge_restore.toml");
    std::fs::write(&bad_knowledge, "this is not [[[ valid toml").unwrap();
    let out = Command::new(bin())
        .arg("trust")
        .arg("mcp__totallymadeuprestoreserver__dosomething")
        .env("VOUCH_MY_KNOWLEDGE", &file)
        .env("VOUCH_KNOWLEDGE", &bad_knowledge)
        .env("VOUCH_STATE_DIR", std::env::temp_dir().join("vouch_cli_test_scratch"))
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .output()
        .unwrap();
    assert!(!out.status.success(), "{}", String::from_utf8_lossy(&out.stdout));
    let after = std::fs::read_to_string(&file).unwrap();
    assert_eq!(
        after, prior,
        "a my-knowledge file that existed before this run must be restored exactly, not left \
         with the failed entry or emptied"
    );
}

/// [M2.12 defect 2] With an empty [tools] section, following the prompt's
/// `set tools.<Name> = "allow"` instruction flips the whole section into
/// governing every tool — the shipped-described tools start prompting. The
/// prompt must say so BEFORE the operator follows it. (Config here is the
/// pinned vouch.example.toml, which names no tools.)
#[test]
fn an_unmodeled_tool_prompt_warns_that_the_first_named_tool_governs_all() {
    let (ok, out) = run_hook(
        r#"{"session_id":"s","cwd":"C:/claude","tool_name":"SomeToolNobodyDescribed","tool_input":{}}"#,
        &[],
    );
    assert!(ok);
    assert!(out.contains("\"ask\""), "an unknown tool must ask, got: {out}");
    assert!(
        out.contains("tools.SomeToolNobodyDescribed"),
        "the prompt must name the setting that turns it off, got: {out}"
    );
    assert!(
        out.contains("careful: your config names no tools yet"),
        "must warn that the config names no tools yet, got: {out}"
    );
    assert!(
        out.contains("govern EVERY tool"),
        "must warn that naming the first tool makes [tools] govern every tool, got: {out}"
    );
}

/// Regression pin, not TDD: this passes before the change too — it pins the
/// gate so the warning can never appear when [tools] already names a tool
/// (where it would be false: the section already governs).
#[test]
fn the_first_tool_warning_disappears_once_a_tool_is_named() {
    let (ok, out) = run_hook_with_config(
        r#"{"session_id":"s","cwd":"C:/claude","tool_name":"SomeToolNobodyDescribed","tool_input":{}}"#,
        "tests/fixtures/tools_names_other.toml",
    );
    assert!(ok);
    assert!(out.contains("\"ask\""), "an unknown tool must ask, got: {out}");
    assert!(
        out.contains("tools.SomeToolNobodyDescribed"),
        "the prompt must name the setting that turns it off, got: {out}"
    );
    assert!(
        !out.contains("careful: your config names no tools yet"),
        "the section already governs — the warning must not appear, got: {out}"
    );
}

/// Task 8: a flag typed after the program name routes into `standalone_flags`
/// instead of being stripped (the old `!a.starts_with("--")` filter) or minted
/// as a bogus subcommand. No `runs_file` on this entry, so the scoped rule
/// asks nothing of `no_value_options` — pinned so nobody "helpfully" adds it.
#[test]
fn trust_with_a_flag_writes_the_narrow_entry_and_it_loads() {
    let home = pinned_home();
    let file = std::env::temp_dir().join("vouch_cli_test_trust_flag_only.toml");
    let _ = std::fs::remove_file(&file);
    let out = Command::new(bin())
        .arg("trust")
        .arg("totallymadeupflagonly")
        .arg("--version")
        .env("VOUCH_MY_KNOWLEDGE", &file)
        .env("VOUCH_STATE_DIR", std::env::temp_dir().join("vouch_cli_test_scratch"))
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("verified"), "no verification line: {stdout}");
    let written = std::fs::read_to_string(&file).unwrap();
    assert!(
        written.contains("subcommands = []"),
        "a flags-only mint must write the narrow subcommands key: {written}"
    );
    assert!(
        written.contains(r#"standalone_flags = ["--version"]"#),
        "the flag must be routed into standalone_flags: {written}"
    );
    assert!(
        written.contains("case_sensitive_flags = true"),
        "a standalone_flags entry must state the case rule: {written}"
    );
    assert!(
        !written.contains("no_value_options"),
        "an entry with no runs_file must not gain no_value_options: {written}"
    );
}

/// A program name plus a verb plus a flag writes the middle state: the named
/// subcommand stays, and the two flags-carrying keys are added beside it.
#[test]
fn trust_with_verb_and_flag_writes_the_middle_state() {
    let home = pinned_home();
    let file = std::env::temp_dir().join("vouch_cli_test_trust_verb_and_flag.toml");
    let _ = std::fs::remove_file(&file);
    let out = Command::new(bin())
        .arg("trust")
        .arg("totallymadeupverbflag")
        .arg("build")
        .arg("--version")
        .env("VOUCH_MY_KNOWLEDGE", &file)
        .env("VOUCH_STATE_DIR", std::env::temp_dir().join("vouch_cli_test_scratch"))
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("verified"),
        "both the verb probe and the flag probe must verify: {stdout}"
    );
    let written = std::fs::read_to_string(&file).unwrap();
    assert!(
        written.contains(r#"subcommands = ["build"]"#),
        "the named subcommand must survive: {written}"
    );
    assert!(
        written.contains(r#"standalone_flags = ["--version"]"#),
        "the flag must be routed into standalone_flags: {written}"
    );
    assert!(
        written.contains("case_sensitive_flags = true"),
        "the case rule must be stated: {written}"
    );
}

/// [M2.54] A single-dash flag used to fall through the old `!a.starts_with("--")`
/// filter and land in `words`, getting minted as a bogus subcommand. It must
/// route the same way a double-dash flag does.
#[test]
fn a_single_dash_flag_is_routed_not_written_as_a_verb() {
    let home = pinned_home();
    let file = std::env::temp_dir().join("vouch_cli_test_trust_single_dash.toml");
    let _ = std::fs::remove_file(&file);
    let out = Command::new(bin())
        .arg("trust")
        .arg("totallymadeupsingledash")
        .arg("-V")
        .env("VOUCH_MY_KNOWLEDGE", &file)
        .env("VOUCH_STATE_DIR", std::env::temp_dir().join("vouch_cli_test_scratch"))
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let written = std::fs::read_to_string(&file).unwrap();
    assert!(
        written.contains(r#"standalone_flags = ["-V"]"#),
        "a single-dash flag must route into standalone_flags: {written}"
    );
    assert!(
        written.contains("subcommands = []"),
        "no subcommand must be written when only a flag was typed: {written}"
    );
    assert!(
        !written.contains(r#"subcommands = ["-V"]"#),
        "the flag must never be minted as a bogus subcommand: {written}"
    );
}

/// A refusal at trust time is total: a nonzero exit, nothing written to the
/// my-knowledge file, and a stderr naming every spelling in `must_contain`, so
/// the operator reads what was refused rather than that something was. `tag`
/// names the file the run is pointed at and so must be unique across callers.
fn assert_trust_refuses(tag: &str, args: &[&str], must_contain: &[&str]) {
    let home = pinned_home();
    let file = std::env::temp_dir().join(format!("vouch_cli_test_trust_refuse_{tag}.toml"));
    let _ = std::fs::remove_file(&file);
    let mut cmd = Command::new(bin());
    cmd.arg("trust");
    for a in args {
        cmd.arg(a);
    }
    let out = cmd
        .env("VOUCH_MY_KNOWLEDGE", &file)
        .env("VOUCH_STATE_DIR", std::env::temp_dir().join("vouch_cli_test_scratch"))
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "`trust {}` must refuse at trust time, got: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        !file.exists(),
        "a refused trust must write nothing: {}",
        file.display()
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    for want in must_contain {
        assert!(
            stderr.contains(want),
            "the refusal must name `{want}`: {stderr}"
        );
    }
}

/// A member that can never fire (the option terminator, a shell-rewrite shape,
/// an attached-value spelling) refuses at trust time — before anything is
/// written — rather than surfacing as a failed verify-and-undo.
#[test]
fn a_bad_member_refuses_at_trust_time_writing_nothing() {
    for (tag, prog, bad_flag) in [
        ("bad_member_dashdash", "totallymadeupbadmember1", "--"),
        ("bad_member_brace", "totallymadeupbadmember2", "-{a,b}"),
        ("bad_member_attached", "totallymadeupbadmember3", "--config=x"),
    ] {
        assert_trust_refuses(tag, &[prog, bad_flag], &[bad_flag]);
    }
}

/// Both control flags — not just one — contradict a named flag: one asks for
/// everything, the other for the narrow flags-only entry. The refusal names the
/// control flag AND the flag it contradicts.
#[test]
fn the_control_flag_combinations_refuse() {
    for (tag, ctrl_flag) in [
        ("control_combo_all", "--all-subcommands"),
        ("control_combo_whole", "--whole-server"),
    ] {
        assert_trust_refuses(
            tag,
            &["totallymadeupcombo", "--version", ctrl_flag],
            &[ctrl_flag, "--version"],
        );
    }
}

/// The M2.54 slash half stays on its own row: a `/`-spelled token is not
/// flag-shaped under the routing loop's `starts_with('-')` test, so it still
/// lands in `words` and is written as a subcommand exactly as before.
#[test]
fn a_slash_token_still_lands_in_words() {
    let home = pinned_home();
    let file = std::env::temp_dir().join("vouch_cli_test_trust_slash_token.toml");
    let _ = std::fs::remove_file(&file);
    let out = Command::new(bin())
        .arg("trust")
        .arg("totallymadeupslashtoken")
        .arg("/s")
        .env("VOUCH_MY_KNOWLEDGE", &file)
        .env("VOUCH_STATE_DIR", std::env::temp_dir().join("vouch_cli_test_scratch"))
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let written = std::fs::read_to_string(&file).unwrap();
    assert!(
        written.contains(r#"subcommands = ["/s"]"#),
        "a slash token must still land in words as a subcommand: {written}"
    );
}

/// Task 8: `doctor` prints `guards::notes()` in the config-only section —
/// beside the inert place rules and ahead of the empty-journal early exit —
/// so a fresh state directory with zero recorded decisions still shows a
/// `subcommands` spelling the merge silently discarded.
#[test]
fn doctor_prints_the_narrowing_notes() {
    let home = pinned_home();
    let state = std::env::temp_dir().join("vouch_cli_test_doctor_notes_state");
    let _ = std::fs::remove_dir_all(&state);
    let knowledge = std::env::temp_dir().join("vouch_cli_test_doctor_notes_knowledge.toml");
    let my_knowledge = std::env::temp_dir().join("vouch_cli_test_doctor_notes_my.toml");
    std::fs::write(
        &knowledge,
        format!(
            "version = {}\n[[program]]\nmatch = [\"totallymadeupnotesprog\"]\n",
            vouch::knowledge::KNOWLEDGE_SCHEMA_VERSION
        ),
    )
    .unwrap();
    std::fs::write(
        &my_knowledge,
        "[[program]]\nmatch = [\"totallymadeupnotesprog\"]\nsubcommands = [\"build\"]\n",
    )
    .unwrap();

    let out = Command::new(bin())
        .arg("doctor")
        .env("VOUCH_KNOWLEDGE", &knowledge)
        .env("VOUCH_MY_KNOWLEDGE", &my_knowledge)
        .env("VOUCH_STATE_DIR", &state)
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    let notes_pos = text
        .find("still stands")
        .unwrap_or_else(|| panic!("doctor must print the narrowing note: {text}"));
    let exit_pos = text
        .find("no decisions recorded yet")
        .unwrap_or_else(|| panic!("the empty-journal exit line must still print: {text}"));
    assert!(
        notes_pos < exit_pos,
        "the note is config-only and must print before the empty-journal exit: {text}"
    );
}

/// [round-2 catch] The `MergedShape` renderer arm has to sit ABOVE the
/// `(GapSource::MyKnowledge, _)` wildcard, or the wildcard's near-enough text
/// swallows it with no red anywhere — exhaustiveness alone cannot catch that,
/// because it only fires on never-constructed source/kind rows. Provoked
/// through the binary: a shipped entry declares `runs_file` + `no_value_options`
/// + `standalone_flags` + a stated case rule; the operator's own file replaces
/// `no_value_options` without the standalone member, which only the MERGED
/// entry can be wrong about (`validate_standalone_in_effect`).
#[test]
fn a_merged_shape_set_aside_prints_the_true_banner() {
    let state = std::env::temp_dir().join("vouch_cli_test_merged_shape_banner_state");
    let _ = std::fs::remove_dir_all(&state);
    let knowledge = std::env::temp_dir().join("vouch_cli_test_merged_shape_banner_knowledge.toml");
    let my_knowledge = std::env::temp_dir().join("vouch_cli_test_merged_shape_banner_my.toml");
    std::fs::write(
        &knowledge,
        format!("version = {}\n\
         [[program]]\n\
         match = [\"totallymadeupmergedshapeprog\"]\n\
         runs_file = \"arg_0\"\n\
         no_value_options = [\"--version\"]\n\
         standalone_flags = [\"--version\"]\n\
         case_sensitive_flags = true\n", vouch::knowledge::KNOWLEDGE_SCHEMA_VERSION),
    )
    .unwrap();
    std::fs::write(
        &my_knowledge,
        "[[program]]\n\
         match = [\"totallymadeupmergedshapeprog\"]\n\
         no_value_options = [\"--other\"]\n",
    )
    .unwrap();

    let (_, text) = run_hook_with_envs(
        r#"{"session_id":"s","cwd":"C:/claude","tool_name":"Bash","tool_input":{"command":"totallymadeupmergedshapeprog --version"}}"#,
        &[],
        &[
            ("VOUCH_KNOWLEDGE", knowledge.as_path()),
            ("VOUCH_MY_KNOWLEDGE", my_knowledge.as_path()),
            ("VOUCH_STATE_DIR", state.as_path()),
        ],
    );
    assert!(
        text.contains("were set aside because a merged entry's shape is refused"),
        "must say my-knowledge was set aside for a merged entry's shape: {text}"
    );
    assert!(
        text.contains("vouch still recognises everything the shipped knowledge describes"),
        "must say the shipped knowledge still applies: {text}"
    );
}
