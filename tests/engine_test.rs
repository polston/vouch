use vouch::config::{load, Action, Config};
use vouch::engine::{decide_bash, decide_command_in};
use vouch::syntax::Scanner;
use vouch::protocol::Decision;

mod common;

fn cfg_with(constructs: &str) -> Config {
    // These tests are about specific constructs, so unknown programs are allowed
    // unless the caller says otherwise — otherwise every case would trip
    // `unmodeled_command` instead of the thing under test.
    let base = if constructs.contains("unmodeled_command") {
        String::new()
    } else {
        "unmodeled_command = \"allow\"\n".to_string()
    };
    load(&format!(
        "version = 1\n[lang.bash]\ndefault = \"allow\"\n[lang.bash.constructs]\n{base}{constructs}"
    ))
    .expect("parses")
}

#[test]
fn every_known_construct_can_be_turned_off_by_configuration() {
    // THE hard rule. If this fails, vouch has become the tool it replaces.
    for name in vouch::shell::Bash.known_constructs() {
        let c = cfg_with(&format!("{name} = \"allow\"\n"));
        assert_eq!(
            c.construct_action("bash", name),
            Action::Allow,
            "construct {name} has no working configuration path"
        );
    }
}

#[test]
fn every_construct_the_parser_can_emit_is_declared_known() {
    // Detecting something the user cannot configure is the defect we exist to avoid.
    let samples = [
        r#"P=x; "$P" y"#,
        r#"O=/tmp/a; echo hi > "$O""#,
        "(cd /tmp && ls)",
        "sleep 1 &",
        "cat <<'EOF'\nx\nEOF\n",
        "f() { echo hi; }",
    ];
    for s in samples {
        let parsed = vouch::shell::parse(s).expect("sample parses");
        for c in &parsed.constructs {
            assert!(
                vouch::shell::Bash.known_constructs().contains(&c.as_str()),
                "parser emitted '{c}' which is not in the scanner's known_constructs (sample: {s})"
            );
        }
    }
}

#[test]
fn a_dynamic_command_is_allowed_when_configured_allow() {
    // The sample's resolved program is python and its argument is a script
    // file, which since M2.118 is its own construct in python's own table.
    // Left in the sample rather than swapped out: the thing under test is
    // that a RESOLVED head stops being a dynamic command, and the resolution
    // is what puts the second construct on the line at all.
    let c = cfg_with(
        "dynamic_command = \"allow\"\n\
         [lang.python.constructs]\nevaluated_input = \"allow\"\n",
    );
    let d = decide_bash(&c, r#"PY="/usr/bin/python"; "$PY" x.py"#);
    assert!(matches!(d, Decision::Allow(_)), "got {d:?}");
}

#[test]
fn a_dynamic_command_prompts_when_configured_ask() {
    let c = cfg_with("dynamic_command = \"ask\"\n");
    let d = decide_bash(&c, r#"PY="/usr/bin/python"; "$PY" x.py"#);
    assert!(matches!(d, Decision::Ask(_)), "got {d:?}");
}

#[test]
fn a_parse_failure_is_reported_as_our_defect_not_a_hazard() {
    let c = cfg_with("parse_failure = \"ask\"\n");
    let d = decide_bash(&c, "for x in ; do");
    match d {
        Decision::Ask(reason) => assert!(
            reason.contains("could not read"),
            "reason must name our own defect, got: {reason}"
        ),
        other => panic!("expected Ask, got {other:?}"),
    }
}

#[test]
fn the_reason_text_names_the_setting_that_would_allow_it() {
    let c = cfg_with("dynamic_command = \"ask\"\n");
    if let Decision::Ask(reason) = decide_bash(&c, r#"P=x; "$P" y"#) {
        assert!(
            reason.contains("lang.bash.constructs.dynamic_command"),
            "got: {reason}"
        );
    } else {
        panic!("expected Ask");
    }
}

#[test]
fn deny_beats_ask_when_two_constructs_disagree() {
    let c = cfg_with("dynamic_command = \"ask\"\nsubshell = \"deny\"\n");
    let d = decide_bash(&c, r#"P=$(ls); "$P" y"#);
    assert!(matches!(d, Decision::Deny(_)), "got {d:?}");
}

#[test]
fn a_plain_command_is_allowed_under_an_allow_default() {
    let c = cfg_with("");
    let d = decide_bash(&c, "git status --short");
    assert!(matches!(d, Decision::Allow(_)), "got {d:?}");
}

/// The prompt an unrecognised command produces, with `unmodeled_command` set
/// to ask. Every test below asks for one and then reads it, so the getting of
/// it lives here once instead of three times over.
fn unmodeled_prompt(command: &str) -> String {
    let c = cfg_with("unmodeled_command = \"ask\"\n");
    match decide_bash(&c, command) {
        Decision::Ask(reason) => reason,
        other => panic!("expected Ask, got {other:?}"),
    }
}

#[test]
fn the_unmodeled_prompt_prints_no_joined_trust_command() {
    // M2.12 defects 3 and 4: `vouch trust alpha beta` means "program alpha,
    // subcommand beta". The prompt must never print a pasteable trust
    // command again — `vouch trust ` with a trailing space is what an
    // instruction-with-arguments contains; prose mentions are
    // backtick-delimited and never match.
    let reason = unmodeled_prompt("totallymadeupalpha x && totallymadeupbeta y");
    assert!(
        !reason.contains("vouch trust "),
        "a pasteable trust command is back: {reason}"
    );
    assert!(
        reason.contains("every operation of `totallymadeupalpha`"),
        "no per-item description for alpha: {reason}"
    );
    assert!(
        reason.contains("every operation of `totallymadeupbeta`"),
        "no per-item description for beta: {reason}"
    );
    assert!(reason.contains("vouch-trust"), "the skill is not named: {reason}");
    // §5: the prompt must still name the setting that turns it off.
    assert!(
        reason.contains("set lang.bash.constructs.unmodeled_command = \"allow\""),
        "the off-switch went missing: {reason}"
    );
}

#[test]
fn a_single_unknown_program_also_gets_no_pasteable_command() {
    // The most common shape — one bare unknown name. Without this test, an
    // implementation could keep printing `vouch trust <name>` whenever there
    // is exactly one item and every other test would still pass.
    let reason = unmodeled_prompt("totallymadeupsolo x");
    assert!(!reason.contains("vouch trust "), "{reason}");
    assert!(
        reason.contains("every operation of `totallymadeupsolo`"),
        "{reason}"
    );
}

#[test]
fn the_unmodeled_prompt_describes_a_path_head_by_its_bare_name() {
    // M2.12 defect 1: the old prompt said `vouch trust <path>`, and running
    // exactly that wrote a rule that could never fire.
    let reason = unmodeled_prompt("/c/tools/totallymadeupfrob.exe --go");
    assert!(reason.contains("`totallymadeupfrob`"), "bare name absent: {reason}");
    assert!(!reason.contains("vouch trust "), "{reason}");
}

// --- python joins the scanner registry (Task 10) ----------------------------
//
// `scan_snippet` now asks `syntax::scanner_for` instead of hand-matching
// language names, so a wrapped snippet in any registered language is
// actually scanned, and three engine judgment channels every scanned
// snippet needs land with it: parse-failure reporting, per-language
// construct keying, and stdin-claim keying.

#[test]
fn an_opaque_snippet_still_gets_search_only() {
    // INVERTED (§2.2 item 1, M2.125/§5.2): `node -e` stays opaque — Task 10
    // does not touch that entry, only how `scan_snippet` looks languages up
    // — but opaque no longer means "allow clean text". EVERY inline opaque
    // program asks now, including this harmless one: vouch cannot tell a
    // printing `console.log(1)` from a writing one without a scanner, so
    // treating clean text as safe was exactly the laundering `M2.125` names.
    // The protected-path search still applies underneath the ask (both
    // still recognise the tool and find the snippet; what changed is that
    // NEITHER case is silently trusted any more) — pinned by both reasons
    // naming `unreadable_language`, not by one asking and one allowing.
    let cfg = load(
        r#"
version = 1
[lang.bash]
default = "allow"
[lang.bash.constructs]
unmodeled_command = "allow"
[protected]
paths = ["$HOME/.claude/settings.json"]
"#,
    )
    .expect("parses");
    let clean =
        decide_command_in(&cfg, "bash", r#"node -e "console.log(1)""#, Some("C:/Users/dev"), None);
    match clean {
        Decision::Ask(r) => assert!(r.contains("unreadable_language"), "got: {r}"),
        other => panic!("got {other:?}"),
    }

    let mentioning = decide_command_in(
        &cfg,
        "bash",
        r#"node -e "require('fs').readFileSync('C:/Users/dev/.claude/settings.json')""#,
        Some("C:/Users/dev"),
        None,
    );
    assert!(matches!(mentioning, Decision::Ask(_)), "got {mentioning:?}");
}

// The remaining two tests need a knowledge entry the test writes itself (a
// wrap declaration naming `wrap_lang = "python"`) and the engine reads its
// knowledge from the process-global `guards::in_effect()` cache — so a
// custom entry cannot be handed to `decide_command_at` in-process, and
// setting the env vars that select one would be a process-wide mutation
// racing every other test in this binary (CLAUDE.md §9). `common::hook_bash_at`
// spawns a child process, which gets its own environment, its own cache, and
// the real `--hook` path — where an operator meets this anyway.

/// A program named `pyrun`, distinct from the shipped `python` entry (which
/// now carries this exact `wrap_lang = "python"` shape itself, since Task
/// 11), kept separate here so these tests exercise the general mechanism
/// rather than depending on the shipped entry's own content.
const PYRUN_ENTRY: &str = "[[program]]\nmatch = [\"pyrun\"]\nwraps = \"after_flag\"\n\
     wrap_flags = [\"-c\"]\nwrap_lang = \"python\"\ncase_sensitive_flags = true\n";

fn hook_at(tag: &str, mine: &str, cfg: &str, command: &str) -> (String, String) {
    common::hook_bash_at(&format!("engine_snippets_{tag}"), mine, cfg, "C:/Users/dev", command)
}

#[test]
fn a_python_snippet_parse_failure_asks_naming_the_python_setting() {
    // Channel 1. `def broken(:` is the same string `python_scanner_test.rs`
    // pins as a parse failure at the scanner level; here it runs the whole
    // way through the engine, wrapped inside a bash line.
    let cfg = "version = 1\n[lang.bash]\ndefault = \"allow\"\n[lang.bash.constructs]\n\
        unmodeled_command = \"allow\"\n[lang.python.constructs]\nparse_failure = \"ask\"\n";
    let (decision, reason) =
        hook_at("parse_failure", PYRUN_ENTRY, cfg, r#"pyrun -c "def broken(:""#);
    assert_eq!(decision, "ask", "got: {reason}");
    assert!(
        reason.contains("lang.python.constructs.parse_failure"),
        "got: {reason}"
    );
}

#[test]
fn a_snippet_construct_resolves_under_its_own_language() {
    // Channel 2. `d['k']()` is a computed callee — python's own
    // `dynamic_call` construct, tripped inside a bash line.
    //
    // Allowed under python's own table, nothing said under bash: the line
    // allows.
    let allow_under_python = "version = 1\n[lang.bash]\ndefault = \"allow\"\n\
        [lang.bash.constructs]\nunmodeled_command = \"allow\"\n\
        [lang.python.constructs]\ndynamic_call = \"allow\"\n";
    let (decision, reason) = hook_at(
        "construct_allow",
        PYRUN_ENTRY,
        allow_under_python,
        r#"pyrun -c "d['k']()""#,
    );
    assert_eq!(decision, "allow", "got: {reason}");

    // The SAME allow, written under bash's own table instead: it must not
    // transfer — the construct is python's, so it still asks.
    let allow_under_bash = "version = 1\n[lang.bash]\ndefault = \"allow\"\n\
        [lang.bash.constructs]\nunmodeled_command = \"allow\"\ndynamic_call = \"allow\"\n";
    let (decision, reason) = hook_at(
        "construct_ask",
        PYRUN_ENTRY,
        allow_under_bash,
        r#"pyrun -c "d['k']()""#,
    );
    assert_eq!(decision, "ask", "got: {reason}");
    assert!(
        reason.contains("lang.python.constructs.dynamic_call"),
        "got: {reason}"
    );
}
