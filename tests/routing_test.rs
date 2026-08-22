//! Pins routing behaviour through the real dispatch, `vouch::route::decide`.
//!
//! These are the equivalence gate for the Task 8 conversion that moved the
//! hardcoded Bash/PowerShell/Write/Edit/NotebookEdit routing into knowledge
//! data (`[[tool]]` entries in `knowledge.toml`, read through the same
//! declared-snippet/write-path flow every other tool goes through): the
//! corpus replay measures rows below the routing layer and cannot see any
//! of this. Three pins used to record behaviour that was DELIBERATELY wrong
//! before that move — an `Abstain` where the tool's own declared snippet or
//! write path now asks or decides instead — and now pin the corrected
//! verdict. A pin failing here means today's behaviour differs from what
//! this file expected; the fix is to record what it actually is and pin
//! THAT, not to change `src/`.
//!
//! Knowledge for every pin is the repo's own shipped `knowledge.toml`,
//! loaded fresh with `guards::load` — never `guards::in_effect()`'s
//! process-global cache, and never the `target/test-my-knowledge.toml`
//! fixture other tests (`vouch trust`) write to concurrently. `home` is a
//! fixed, never-real path, per CLAUDE.md's "no real account name" rule.

mod common;

use common::{kb_with, shipped_kb};
use vouch::protocol::{parse_input, Decision};
use vouch::route::decide;

const HOME: &str = "C:/Users/dev";

fn hook(json: &str) -> vouch::protocol::HookInput {
    parse_input(json).expect("the fixture's hook input parses")
}

fn ask_reason(d: &Decision) -> &str {
    match d {
        Decision::Ask(r) => r,
        other => panic!("expected Ask, got: {other:?}"),
    }
}

#[test]
fn bash_ls_la_allows() {
    let kb = shipped_kb();
    let cfg = common::realistic_config();
    let input = parse_input(
        r#"{"session_id":"s","cwd":"C:/Users/dev","tool_name":"Bash","tool_input":{"command":"ls -la"}}"#,
    )
    .expect("parses");
    let outcome = decide(&cfg, &kb, HOME, &input);
    assert!(matches!(outcome.decision, Decision::Allow(_)), "got: {:?}", outcome.decision);
}

#[test]
fn powershell_get_childitem_pin() {
    // No prediction here — run it and pin whatever `route::decide` actually
    // returns today. Measured: with `realistic_config()` (no `[lang.powershell]`
    // section, so its language default is Ask) this asks, naming the
    // setting `lang.powershell.default` and `lang.bash.default` copy in the
    // reason text does not apply — see the assertion below for the exact text
    // observed.
    let kb = shipped_kb();
    let cfg = common::realistic_config();
    let input = parse_input(
        r#"{"session_id":"s","cwd":"C:/Users/dev","tool_name":"PowerShell","tool_input":{"command":"Get-ChildItem"}}"#,
    )
    .expect("parses");
    let outcome = decide(&cfg, &kb, HOME, &input);
    match &outcome.decision {
        Decision::Ask(reason) => {
            assert!(reason.contains("lang.powershell.default"), "got: {reason}");
        }
        other => panic!("expected Ask (no [lang.powershell] section in realistic_config, so its \
                          language default is Ask), got: {other:?}"),
    }
}

#[test]
fn write_absolute_path_under_home_gets_the_file_decision() {
    let kb = shipped_kb();
    let cfg = common::realistic_config();
    let input = parse_input(
        r#"{"session_id":"s","cwd":"C:/Users/dev","tool_name":"Write","tool_input":{"file_path":"C:/Users/dev/notes/probe.txt"}}"#,
    )
    .expect("parses");
    let outcome = decide(&cfg, &kb, HOME, &input);
    // realistic_config's write.default is "ask", but `$HOME/**` is in
    // allow_paths and the path is under HOME — the file decision allows it.
    assert!(matches!(outcome.decision, Decision::Allow(_)), "got: {:?}", outcome.decision);
}

#[test]
fn write_relative_path_resolves_against_cwd_today() {
    let kb = shipped_kb();
    let cfg = common::realistic_config();
    let input = parse_input(
        r#"{"session_id":"s","cwd":"C:/Users/dev","tool_name":"Write","tool_input":{"file_path":"notes/probe.txt"}}"#,
    )
    .expect("parses");
    let outcome = decide(&cfg, &kb, HOME, &input);
    // `route::decide` resolves a relative `file_path` against `input.cwd`
    // before deciding — "C:/Users/dev" + "notes/probe.txt" lands under
    // `$HOME/**`, same as the absolute pin above. Task 8's knowledge entry
    // declares `cwd_from_call = true` for Write/Edit precisely so this stays
    // true once the hardcode moves to data.
    assert!(matches!(outcome.decision, Decision::Allow(_)), "got: {:?}", outcome.decision);
}

#[test]
fn bash_with_no_command_asks() {
    // Flipped by Task 8: `Bash` is now a `[[tool]]` entry declaring `command`
    // as its bash snippet field, decided through the same declared-snippet
    // flow every tool goes through. An empty `tool_input` has no `command`
    // to extract, and extraction fails closed — Ask, naming the missing
    // field and `tools.Bash`, the blanket-grant setting. Before Task 8 this
    // rendered no output at all (`Decision::Abstain` -> the harness decided
    // alone); this pin records the corrected verdict.
    let kb = shipped_kb();
    let cfg = common::realistic_config();
    let input = parse_input(
        r#"{"session_id":"s","cwd":"C:/Users/dev","tool_name":"Bash","tool_input":{}}"#,
    )
    .expect("parses");
    let outcome = decide(&cfg, &kb, HOME, &input);
    let reason = ask_reason(&outcome.decision);
    assert!(reason.contains("command"), "the prompt must name the missing field, got: {reason}");
    assert!(reason.contains("tools.Bash"), "got: {reason}");
}

#[test]
fn write_with_no_file_path_asks() {
    // Flipped by Task 8, same shape as the Bash pin above: `Write`/`Edit`
    // are now a `[[tool]]` entry declaring `file_path` as the write-path
    // field. An empty `tool_input` sends no such field, and the write-path
    // decision fails closed — Ask, naming the missing field and
    // `tools.Write`. Was `Decision::Abstain` before Task 8.
    let kb = shipped_kb();
    let cfg = common::realistic_config();
    let input = parse_input(
        r#"{"session_id":"s","cwd":"C:/Users/dev","tool_name":"Write","tool_input":{}}"#,
    )
    .expect("parses");
    let outcome = decide(&cfg, &kb, HOME, &input);
    let reason = ask_reason(&outcome.decision);
    assert!(reason.contains("file_path"), "the prompt must name the missing field, got: {reason}");
    assert!(reason.contains("tools.Write"), "got: {reason}");
}

#[test]
fn notebookedit_gets_the_file_decision_on_notebook_path() {
    // Flipped by Task 8: `NotebookEdit` is now its own `[[tool]]` entry
    // declaring `notebook_path` as its write-path field, read for real
    // instead of the old hardcode's `tool_input.file_path` (a field
    // `NotebookEdit` calls never send, so it always fell into `extra` and
    // the old match saw `file_path: None`). Same verdict shape as the Write
    // absolute pin above: under `$HOME/**`, the file decision allows it.
    // Was `Decision::Abstain` before Task 8.
    let kb = shipped_kb();
    let cfg = common::realistic_config();
    let input = parse_input(
        r#"{"session_id":"s","cwd":"C:/Users/dev","tool_name":"NotebookEdit","tool_input":{"notebook_path":"C:/Users/dev/notes/probe.ipynb"}}"#,
    )
    .expect("parses");
    let outcome = decide(&cfg, &kb, HOME, &input);
    assert!(matches!(outcome.decision, Decision::Allow(_)), "got: {:?}", outcome.decision);
}

// ---------------------------------------------------------------------------
// The new decision flow (M2.5 task 7): config first, then the tool's declared
// snippets and write path, fail closed at every hole. Every entry below is
// injected as the operator layer — none of this ships.
// ---------------------------------------------------------------------------

/// One tool that runs its `code` field as bash, in the calling session's own
/// directory. The shape Task 8 gives `Bash` itself.
const SH_ENTRY: &str = r#"
[[tool]]
match = ["mcp__p_s__sh"]
source = "runs the `code` field as bash"
cwd_from_call = true
[[tool.snippet]]
field = "code"
language = "bash"
"#;

fn sh_call(code: &str) -> vouch::protocol::HookInput {
    hook(&format!(
        r#"{{"session_id":"s","cwd":"C:/Users/dev","tool_name":"mcp__p_s__sh","tool_input":{{"code":{}}}}}"#,
        serde_json::Value::String(code.to_string())
    ))
}

#[test]
fn a_declared_bash_snippet_is_decided_on_its_text() {
    let kb = kb_with(SH_ENTRY);
    let cfg = common::realistic_config();
    let outcome = decide(&cfg, &kb, HOME, &sh_call("ls -la"));
    assert!(matches!(outcome.decision, Decision::Allow(_)), "got: {:?}", outcome.decision);
    assert_eq!(outcome.snippets, vec![("ls -la".to_string(), "bash".to_string())]);
}

#[test]
fn an_entry_set_to_ask_caps_a_snippet_that_would_allow() {
    let kb = kb_with(&SH_ENTRY.replace(
        "cwd_from_call = true",
        "cwd_from_call = true\naction = \"ask\"",
    ));
    let cfg = common::realistic_config();
    let outcome = decide(&cfg, &kb, HOME, &sh_call("ls -la"));
    let reason = ask_reason(&outcome.decision);
    assert!(reason.contains("tools.mcp__p_s__sh"), "got: {reason}");
    // The extracted snippet still leaves through the outcome, whatever the
    // verdict — Task 9 journals one record per text.
    assert_eq!(outcome.snippets, vec![("ls -la".to_string(), "bash".to_string())]);
}

#[test]
fn an_entry_set_to_deny_caps_a_snippet_that_would_allow() {
    let kb = kb_with(&SH_ENTRY.replace(
        "cwd_from_call = true",
        "cwd_from_call = true\naction = \"deny\"",
    ));
    let cfg = common::realistic_config();
    let outcome = decide(&cfg, &kb, HOME, &sh_call("ls -la"));
    match &outcome.decision {
        Decision::Deny(reason) => assert!(reason.contains("tools.mcp__p_s__sh"), "got: {reason}"),
        other => panic!("an entry set to deny must deny, got: {other:?}"),
    }
}

#[test]
fn an_entry_set_to_allow_does_not_lower_a_snippet_ask_to_allow() {
    // `cap`'s doc comment (src/route.rs): "An action never LOWERS a verdict:
    // action unset (or allow) is a recognition claim about the tool, never
    // permission for whatever its snippet turned out to contain." Unpinned
    // hold from the Task 7 review — nothing exercised `action = "allow"`
    // against a declaration that asks on its own. `Action::Allow` ranks 0 in
    // `cap`'s ordering, so `rank(&decision) >= rank_of(action)` holds for
    // every non-allow verdict and the cap is a no-op — this pins that in
    // practice, not just by reading the rank table.
    //
    // Re-decided (Task 11, python-snippets): `realistic_config` now allows
    // an unmodelled python head, so `print(1)` no longer asks on its own —
    // an unreadable snippet still does, which is what this needs.
    let kb = kb_with(
        r#"
[[tool]]
match = ["mcp__p_s__py"]
source = "runs the `code` field as python"
action = "allow"
[[tool.snippet]]
field = "code"
language = "python"
"#,
    );
    let cfg = common::realistic_config();
    let input = hook(
        r#"{"session_id":"s","cwd":"C:/Users/dev","tool_name":"mcp__p_s__py","tool_input":{"code":"def broken(:"}}"#,
    );
    let reason = ask_reason(&decide(&cfg, &kb, HOME, &input).decision).to_string();
    assert!(reason.contains("python"), "an entry's action = \"allow\" must not silently swallow the snippet ask, got: {reason}");
}

#[test]
fn the_config_naming_the_tool_allows_a_snippet_vouch_cannot_read() {
    // Config is the decisions layer and it is consulted FIRST: naming the
    // tool is the operator's off-switch for snippet inspection, and the only
    // honest answer to "what setting turns the python-snippet ask off".
    let kb = kb_with(
        r#"
[[tool]]
match = ["mcp__p_s__py"]
source = "runs the `code` field as python"
[[tool.snippet]]
field = "code"
language = "python"
"#,
    );
    let cfg = common::realistic_config_with("[tools]\n\"mcp__p_s__py\" = \"allow\"");
    let input = hook(
        r#"{"session_id":"s","cwd":"C:/Users/dev","tool_name":"mcp__p_s__py","tool_input":{"code":"print(1)"}}"#,
    );
    let outcome = decide(&cfg, &kb, HOME, &input);
    assert!(matches!(outcome.decision, Decision::Allow(_)), "got: {:?}", outcome.decision);
}

#[test]
fn the_config_naming_the_tool_denies_a_snippet_that_would_allow() {
    let kb = kb_with(SH_ENTRY);
    let cfg = common::realistic_config_with("[tools]\n\"mcp__p_s__sh\" = \"deny\"");
    let outcome = decide(&cfg, &kb, HOME, &sh_call("ls -la"));
    assert!(matches!(outcome.decision, Decision::Deny(_)), "got: {:?}", outcome.decision);
}

#[test]
fn a_tools_line_governs_a_tool_whose_entry_runs_a_command_field() {
    // The entry is shaped exactly like the one Task 8 writes for `Bash`
    // (snippet field `command`, fixed bash, cwd claimed), under a name the
    // surviving hardcode does not intercept. Once Bash itself is data, an
    // explicit `tools.Bash` line governs it the same way — today such a line
    // is silently dead because `lang_for_tool` short-circuits first.
    let kb = kb_with(
        r#"
[[tool]]
match = ["BashLike"]
source = "runs the `command` field as bash in the calling session's directory"
cwd_from_call = true
[[tool.snippet]]
field = "command"
language = "bash"
"#,
    );
    let input = hook(
        r#"{"session_id":"s","cwd":"C:/Users/dev","tool_name":"BashLike","tool_input":{"command":"ls -la"}}"#,
    );

    let allowed = decide(&common::realistic_config(), &kb, HOME, &input);
    assert!(matches!(allowed.decision, Decision::Allow(_)), "got: {:?}", allowed.decision);
    // `command` is a TYPED `ToolInput` field, so serde's flatten never puts
    // it in `extra`: without the re-insert the declaration cannot match and
    // this would ask.
    assert_eq!(allowed.snippets, vec![("ls -la".to_string(), "bash".to_string())]);

    let cfg = common::realistic_config_with("[tools]\nBashLike = \"ask\"");
    let outcome = decide(&cfg, &kb, HOME, &input);
    assert!(matches!(outcome.decision, Decision::Ask(_)), "got: {:?}", outcome.decision);
}

#[test]
fn a_config_naming_another_tool_does_not_govern_a_declared_entry() {
    // Naming any tool makes [tools] govern every OTHER tool — except ones
    // whose entry declares what to inspect, which are governed by their
    // snippet decision instead. Without that exemption, naming one MCP tool
    // would flip every bash command on the machine to ask.
    let kb = kb_with(SH_ENTRY);
    let cfg = common::realistic_config_with("[tools]\nRead = \"allow\"");
    let outcome = decide(&cfg, &kb, HOME, &sh_call("ls -la"));
    assert!(matches!(outcome.decision, Decision::Allow(_)), "got: {:?}", outcome.decision);
}

#[test]
fn a_restrictive_server_entry_caps_an_exact_entry_of_that_server() {
    let kb = kb_with(&format!(
        r#"{SH_ENTRY}
[[tool]]
server = "mcp__p_s"
source = "operator grant: every tool this server exposes"
action = "ask"
"#
    ));
    let cfg = common::realistic_config();
    let outcome = decide(&cfg, &kb, HOME, &sh_call("ls -la"));
    let reason = ask_reason(&outcome.decision);
    assert!(
        reason.contains("the whole server mcp__p_s is set to ask"),
        "the prompt must say which SERVER stopped it, not blame the tool's own entry, got: {reason}"
    );
}

/// An entry that declares nothing to inspect, set to deny. Its `action` is
/// what `Config::tool_decision` already consults through `shipped_tool_action`
/// — and only in the branch where the shipped description is in play at all.
const UNDECLARED_DENY: &str = r#"
[[tool]]
match = ["mcp__p_s__wipe"]
source = "an entry the operator set to deny, declaring nothing to inspect"
action = "deny"
"#;

fn wipe_call() -> vouch::protocol::HookInput {
    hook(r#"{"session_id":"s","cwd":"C:/Users/dev","tool_name":"mcp__p_s__wipe","tool_input":{}}"#)
}

#[test]
fn an_undeclared_entrys_action_does_not_override_the_config_governing_others() {
    // Naming any tool puts the shipped description out of play entirely: this
    // tool asks because the config does not name it, NOT because the entry
    // says deny. Turning that into a deny would answer with a verdict
    // knowledge.toml was not being asked for, and the prompt — which explains
    // that the config is what decided — would contradict it.
    let kb = kb_with(UNDECLARED_DENY);
    let cfg = common::realistic_config_with("[tools]\nRead = \"allow\"");
    let reason = ask_reason(&decide(&cfg, &kb, HOME, &wipe_call()).decision).to_string();
    assert!(
        reason.contains("names at least one OTHER tool"),
        "the pre-existing ConfigGovernsOthers wording must survive, got: {reason}"
    );
}

#[test]
fn an_undeclared_entrys_action_does_not_override_the_no_config_ask() {
    // With no config file nothing has been allowed and nothing has been
    // forbidden either — the shipped description is not what decided, and a
    // prompt telling the operator to set `tools.X = "allow"` in a file that
    // does not exist is advice they cannot follow.
    let kb = kb_with(UNDECLARED_DENY);
    let cfg = vouch::config::Config::nothing_configured();
    let reason = ask_reason(&decide(&cfg, &kb, HOME, &wipe_call()).decision).to_string();
    assert!(
        reason.contains("there is no vouch config file at all"),
        "the pre-existing NoConfig wording must survive, got: {reason}"
    );
}

#[test]
fn an_undeclared_entrys_own_action_still_decides_when_the_description_is_in_play() {
    // The other side of the two pins above: with a config that names no tools,
    // the shipped description IS what decides, and this entry says deny.
    let kb = kb_with(UNDECLARED_DENY);
    let cfg = common::realistic_config();
    let outcome = decide(&cfg, &kb, HOME, &wipe_call());
    assert!(matches!(outcome.decision, Decision::Deny(_)), "got: {:?}", outcome.decision);
}

#[test]
fn a_whole_server_deny_covers_an_exact_entry_that_declares_nothing() {
    // Spec §Server entry rule 4: a whole-server stop means the whole server,
    // and a more specific entry must not silently override it. The exact entry
    // here claims recognition and nothing else, which on its own allows.
    let kb = kb_with(
        r#"
[[tool]]
match = ["mcp__p_s__wipe"]
source = "recognised, and nothing more is claimed"

[[tool]]
server = "mcp__p_s"
source = "operator grant: every tool this server exposes"
action = "deny"
"#,
    );
    let cfg = common::realistic_config();
    let outcome = decide(&cfg, &kb, HOME, &wipe_call());
    match &outcome.decision {
        Decision::Deny(reason) => assert!(
            reason.contains("the whole server mcp__p_s is set to deny"),
            "got: {reason}"
        ),
        other => panic!("a whole-server deny must cover this tool, got: {other:?}"),
    }
}

#[test]
fn a_restrictive_server_entry_says_so_when_it_is_the_only_entry() {
    let kb = kb_with(
        r#"
[[tool]]
server = "mcp__p_s"
source = "operator grant: every tool this server exposes"
action = "ask"
"#,
    );
    let cfg = common::realistic_config();
    let input = hook(
        r#"{"session_id":"s","cwd":"C:/Users/dev","tool_name":"mcp__p_s__anything","tool_input":{}}"#,
    );
    let reason = ask_reason(&decide(&cfg, &kb, HOME, &input).decision).to_string();
    assert!(
        reason.contains("the entry for the whole server mcp__p_s)"),
        "the prompt must not read as though this tool had been described one by one, got: {reason}"
    );
    assert!(reason.contains("tools.mcp__p_s__anything"), "got: {reason}");
}

#[test]
fn an_exact_entry_beats_a_server_entry_for_recognition() {
    // The server entry declares a snippet vouch cannot read; the exact entry
    // declares a bash one. Exact wins whatever the file order, so the call is
    // decided on its bash text rather than asked about.
    let kb = kb_with(&format!(
        r#"
[[tool]]
server = "mcp__p_s"
source = "operator grant: every tool this server exposes, code in `code`"
[[tool.snippet]]
field = "code"
language = "python"
{SH_ENTRY}"#
    ));
    let cfg = common::realistic_config();
    let outcome = decide(&cfg, &kb, HOME, &sh_call("ls -la"));
    assert!(matches!(outcome.decision, Decision::Allow(_)), "got: {:?}", outcome.decision);
    assert_eq!(outcome.snippets, vec![("ls -la".to_string(), "bash".to_string())]);
}

#[test]
fn a_server_entry_recognises_a_tool_with_no_entry_of_its_own() {
    let kb = kb_with(
        r#"
[[tool]]
server = "mcp__p_s"
source = "operator grant: every tool this server exposes"
"#,
    );
    let cfg = common::realistic_config();
    let input = hook(
        r#"{"session_id":"s","cwd":"C:/Users/dev","tool_name":"mcp__p_s__anything","tool_input":{}}"#,
    );
    let outcome = decide(&cfg, &kb, HOME, &input);
    assert!(matches!(outcome.decision, Decision::Allow(_)), "got: {:?}", outcome.decision);
}

#[test]
fn a_server_of_mcp_alone_matches_nothing() {
    // Every real tool name's remainder after `mcp__` contains a `__` of its
    // own, so the every-server glob is inexpressible: this entry covers
    // nothing and the call falls through to the unmodeled-tool ask.
    let kb = kb_with(
        r#"
[[tool]]
server = "mcp"
source = "operator grant: every tool this server exposes"
"#,
    );
    let cfg = common::realistic_config();
    let input = hook(
        r#"{"session_id":"s","cwd":"C:/Users/dev","tool_name":"mcp__p_s__anything","tool_input":{}}"#,
    );
    let outcome = decide(&cfg, &kb, HOME, &input);
    let reason = ask_reason(&outcome.decision);
    assert!(reason.contains("tools.mcp__p_s__anything"), "got: {reason}");
}

// --- server-matching tail edges (unpinned holds from the Task 7 review) ----
//
// `guards::server_entry_for`'s doc comment says a server entry matches
// `<server>__<tail>` where `<tail>` is non-empty and contains no further
// `__`. Nothing exercised the three boundary shapes that constraint exists
// for. Each of these is a tool name a `server = "mcp__p_s"` grant must NOT
// cover, so the call falls all the way through to the unmodeled-tool ask.

#[test]
fn a_server_entry_does_not_match_the_server_name_with_an_empty_tail() {
    let kb = kb_with(
        r#"
[[tool]]
server = "mcp__p_s"
source = "operator grant: every tool this server exposes"
"#,
    );
    let cfg = common::realistic_config();
    let input = hook(
        r#"{"session_id":"s","cwd":"C:/Users/dev","tool_name":"mcp__p_s__","tool_input":{}}"#,
    );
    let reason = ask_reason(&decide(&cfg, &kb, HOME, &input).decision).to_string();
    assert!(reason.contains("tools.mcp__p_s__"), "an empty tail must not be covered by the server grant, got: {reason}");
}

#[test]
fn a_server_entry_does_not_match_a_deeper_tail() {
    let kb = kb_with(
        r#"
[[tool]]
server = "mcp__p_s"
source = "operator grant: every tool this server exposes"
"#,
    );
    let cfg = common::realistic_config();
    let input = hook(
        r#"{"session_id":"s","cwd":"C:/Users/dev","tool_name":"mcp__p_s__a__b","tool_input":{}}"#,
    );
    let reason = ask_reason(&decide(&cfg, &kb, HOME, &input).decision).to_string();
    assert!(
        reason.contains("tools.mcp__p_s__a__b"),
        "a tail containing a further __ must not be covered by the server grant, got: {reason}"
    );
}

#[test]
fn a_server_entry_does_not_match_a_tool_name_equal_to_the_server_string() {
    let kb = kb_with(
        r#"
[[tool]]
server = "mcp__p_s"
source = "operator grant: every tool this server exposes"
"#,
    );
    let cfg = common::realistic_config();
    let input = hook(r#"{"session_id":"s","cwd":"C:/Users/dev","tool_name":"mcp__p_s","tool_input":{}}"#);
    let reason = ask_reason(&decide(&cfg, &kb, HOME, &input).decision).to_string();
    assert!(
        reason.contains("tools.mcp__p_s"),
        "a tool name equal to the server string itself must not be covered by the server grant, got: {reason}"
    );
}

#[test]
fn a_language_value_with_no_mapping_asks_naming_the_setting() {
    let kb = kb_with(
        r#"
[[tool]]
match = ["mcp__p_s__exec"]
source = "runs `code` in the language named by `language`"
[[tool.snippet]]
field = "code"
language_from = "language"
language_values = { shell = "bash" }
"#,
    );
    let cfg = common::realistic_config();
    let input = hook(
        r#"{"session_id":"s","cwd":"C:/Users/dev","tool_name":"mcp__p_s__exec","tool_input":{"code":"puts 1","language":"ruby"}}"#,
    );
    let reason = ask_reason(&decide(&cfg, &kb, HOME, &input).decision).to_string();
    assert!(reason.contains("language_values"), "the prompt must say what was unreadable, got: {reason}");
    assert!(reason.contains("tools.mcp__p_s__exec"), "got: {reason}");
}

#[test]
fn a_missing_snippet_field_asks_naming_it() {
    let kb = kb_with(SH_ENTRY);
    let cfg = common::realistic_config();
    let input = hook(
        r#"{"session_id":"s","cwd":"C:/Users/dev","tool_name":"mcp__p_s__sh","tool_input":{"timeout":5}}"#,
    );
    let outcome = decide(&cfg, &kb, HOME, &input);
    let reason = ask_reason(&outcome.decision);
    assert!(reason.contains("code"), "got: {reason}");
    assert!(reason.contains("tools.mcp__p_s__sh"), "got: {reason}");
    assert!(outcome.snippets.is_empty(), "nothing was extracted, so nothing is journaled");
}

#[test]
fn an_empty_array_snippet_asks() {
    let kb = kb_with(
        r#"
[[tool]]
match = ["mcp__p_s__batch"]
source = "runs every `command` in `commands` as bash"
cwd_from_call = true
[[tool.snippet]]
field = "commands[].command"
language = "bash"
"#,
    );
    let cfg = common::realistic_config();
    let input = hook(
        r#"{"session_id":"s","cwd":"C:/Users/dev","tool_name":"mcp__p_s__batch","tool_input":{"commands":[]}}"#,
    );
    let reason = ask_reason(&decide(&cfg, &kb, HOME, &input).decision).to_string();
    assert!(reason.contains("empty array"), "got: {reason}");
}

#[test]
fn an_empty_string_snippet_asks() {
    let kb = kb_with(SH_ENTRY);
    let cfg = common::realistic_config();
    let reason = ask_reason(&decide(&cfg, &kb, HOME, &sh_call("   ")).decision).to_string();
    assert!(reason.contains("empty"), "got: {reason}");
    assert!(reason.contains("tools.mcp__p_s__sh"), "got: {reason}");
}

#[test]
fn a_snippet_and_a_write_path_compose_and_the_worst_wins() {
    let kb = kb_with(
        r#"
[[tool]]
match = ["mcp__p_s__render"]
source = "runs `code` as bash and writes the file named by `out`"
cwd_from_call = true
write_path_field = "out"
[[tool.snippet]]
field = "code"
language = "bash"
"#,
    );
    let cfg = common::realistic_config();
    // The snippet allows; the write target is outside every allow path, so
    // the write's ask governs.
    let input = hook(
        r#"{"session_id":"s","cwd":"C:/Users/dev","tool_name":"mcp__p_s__render","tool_input":{"code":"ls -la","out":"D:/elsewhere/x.txt"}}"#,
    );
    let outcome = decide(&cfg, &kb, HOME, &input);
    assert!(matches!(outcome.decision, Decision::Ask(_)), "got: {:?}", outcome.decision);
    assert_eq!(outcome.snippets, vec![("ls -la".to_string(), "bash".to_string())]);

    // Both inside the allow paths: nothing is worse than allow.
    let allowed = hook(
        r#"{"session_id":"s","cwd":"C:/Users/dev","tool_name":"mcp__p_s__render","tool_input":{"code":"ls -la","out":"C:/Users/dev/x.txt"}}"#,
    );
    let outcome = decide(&cfg, &kb, HOME, &allowed);
    assert!(matches!(outcome.decision, Decision::Allow(_)), "got: {:?}", outcome.decision);
}

#[test]
fn a_javascript_snippet_asks_end_to_end() {
    let kb = kb_with(
        r#"
[[tool]]
match = ["mcp__p_s__js"]
source = "runs the `code` field as javascript"
[[tool.snippet]]
field = "code"
language = "javascript"
"#,
    );
    let cfg = common::realistic_config();
    let input = hook(
        r#"{"session_id":"s","cwd":"C:/Users/dev","tool_name":"mcp__p_s__js","tool_input":{"code":"console.log(1)"}}"#,
    );
    let outcome = decide(&cfg, &kb, HOME, &input);
    let reason = ask_reason(&outcome.decision);
    assert!(reason.contains("javascript"), "the prompt must name the language, got: {reason}");
    assert!(reason.contains("tools.mcp__p_s__js"), "got: {reason}");
    assert_eq!(
        outcome.snippets,
        vec![("console.log(1)".to_string(), "javascript".to_string())]
    );
}

#[test]
fn a_scanned_python_snippets_ask_names_the_languages_own_setting() {
    // Python joined the scanner registry (Task 10), so a declared python
    // snippet is decided through the engine exactly like bash and
    // PowerShell, and its ask names lang.python.constructs, not the tool's
    // blanket tools. grant.
    //
    // Re-decided (Task 11, python-snippets): the real python entries ship
    // with this task, and `realistic_config` now carries a `[lang.python]`
    // block that allows the merely-unknowable — `print(1)` is still an
    // unmodelled head (`print` is not described), but that no longer asks.
    // An unreadable snippet still does (`parse_failure = "ask"` stays
    // explicit there), so this uses that shape to keep proving the routing.
    let kb = kb_with(
        r#"
[[tool]]
match = ["mcp__p_s__py"]
source = "runs the `code` field as python"
[[tool.snippet]]
field = "code"
language = "python"
"#,
    );
    let cfg = common::realistic_config();
    let input = hook(
        r#"{"session_id":"s","cwd":"C:/Users/dev","tool_name":"mcp__p_s__py","tool_input":{"code":"def broken(:"}}"#,
    );
    let reason = ask_reason(&decide(&cfg, &kb, HOME, &input).decision).to_string();
    assert!(
        reason.contains("lang.python.constructs.parse_failure"),
        "the prompt must name the language's own setting, got: {reason}"
    );
}

#[test]
fn a_snippet_language_with_no_scanner_never_reaches_the_engine() {
    // `engine::decide_command_at`'s no-scanner arm returns Abstain, which
    // renders as no output at all — the harness would then decide alone. A
    // snippet language the registry has no scanner for must never get
    // there, so the language mapped here to javascript has to arrive as an
    // Ask, from routing. (Python moved off this test in Task 10, once it
    // joined the registry — javascript is the language `SNIPPET_LANGUAGES`
    // still closes over that stays scanner-less; the brief named "ruby",
    // which is not a member of that set and would refuse to load.)
    let kb = kb_with(
        r#"
[[tool]]
match = ["mcp__p_s__exec"]
source = "runs `code` in the language named by `language`"
[[tool.snippet]]
field = "code"
language_from = "language"
language_values = { shell = "bash", js = "javascript" }
"#,
    );
    let cfg = common::realistic_config();
    let input = hook(
        r#"{"session_id":"s","cwd":"C:/Users/dev","tool_name":"mcp__p_s__exec","tool_input":{"code":"console.log(1)","language":"js"}}"#,
    );
    let outcome = decide(&cfg, &kb, HOME, &input);
    assert_ne!(outcome.decision, Decision::Abstain, "the engine's no-scanner arm was reached");
    let reason = ask_reason(&outcome.decision);
    assert!(reason.contains("javascript"), "got: {reason}");
}

/// The same entry twice, once claiming the tool runs in the calling session's
/// directory and once not. Everything else about the two calls is identical.
const WRITER: &str = r#"
[[tool]]
match = ["mcp__p_s__put"]
source = "writes the file named by `path`"
write_path_field = "path"
"#;

#[test]
fn a_relative_write_path_asks_when_the_tool_does_not_claim_the_calls_directory() {
    let kb = kb_with(WRITER);
    let cfg = common::realistic_config();
    let input = hook(
        r#"{"session_id":"s","cwd":"C:/Users/dev","tool_name":"mcp__p_s__put","tool_input":{"path":"notes/probe.txt"}}"#,
    );
    let reason = ask_reason(&decide(&cfg, &kb, HOME, &input).decision).to_string();
    assert!(reason.contains("cwd_from_call"), "the prompt must name what is missing, got: {reason}");
}

#[test]
fn a_relative_write_path_is_decided_when_the_tool_claims_the_calls_directory() {
    let kb = kb_with(&WRITER.replace(
        "write_path_field = \"path\"",
        "write_path_field = \"path\"\ncwd_from_call = true",
    ));
    let cfg = common::realistic_config();
    let input = hook(
        r#"{"session_id":"s","cwd":"C:/Users/dev","tool_name":"mcp__p_s__put","tool_input":{"path":"notes/probe.txt"}}"#,
    );
    // Resolved against the call's directory it lands under `$HOME/**`, which
    // realistic_config allows — the same verdict the Write pin above records.
    let outcome = decide(&cfg, &kb, HOME, &input);
    assert!(matches!(outcome.decision, Decision::Allow(_)), "got: {:?}", outcome.decision);
}

#[test]
fn an_absolute_write_path_is_decided_without_the_cwd_claim() {
    let kb = kb_with(WRITER);
    let cfg = common::realistic_config();
    let input = hook(
        r#"{"session_id":"s","cwd":"C:/Users/dev","tool_name":"mcp__p_s__put","tool_input":{"path":"C:/Users/dev/notes/probe.txt"}}"#,
    );
    let outcome = decide(&cfg, &kb, HOME, &input);
    assert!(matches!(outcome.decision, Decision::Allow(_)), "got: {:?}", outcome.decision);
}

#[test]
fn a_missing_write_path_field_asks_naming_the_field() {
    let kb = kb_with(WRITER);
    let cfg = common::realistic_config();
    let input = hook(
        r#"{"session_id":"s","cwd":"C:/Users/dev","tool_name":"mcp__p_s__put","tool_input":{"content":"hello"}}"#,
    );
    let reason = ask_reason(&decide(&cfg, &kb, HOME, &input).decision).to_string();
    assert!(reason.contains("path"), "got: {reason}");
    assert!(reason.contains("tools.mcp__p_s__put"), "got: {reason}");
}

#[test]
fn a_relative_write_inside_a_snippet_asks_as_unresolvable_without_the_cwd_claim() {
    // Same gate one level down: the call's directory reaches the snippet
    // decision only when the entry claims the tool runs there, so a relative
    // redirect is unresolvable and asks for THAT reason.
    //
    // This used to assert `Ask(_)` and nothing more, and it passed for the
    // wrong reason: the target was placed as written and then judged against
    // `write.allow_paths`, which asked only because `notes/probe.txt` is not
    // a path any allow rule covers. Which verdict that produced depended on
    // the directory the test binary happened to run in — see the sibling
    // test below. Asserting the unresolvable reason is what makes the pin
    // mean "vouch cannot tell which directory this lands in".
    let kb = kb_with(&SH_ENTRY.replace("cwd_from_call = true\n", ""));
    let cfg = common::realistic_config();
    let outcome = decide(&cfg, &kb, HOME, &sh_call("echo hi > notes/probe.txt"));
    let reason = ask_reason(&outcome.decision);
    assert!(reason.contains("unresolved_path"), "got: {reason}");
    assert!(reason.contains("cwd_from_call"), "the prompt must name what is missing, got: {reason}");
    assert!(
        !reason.contains("outside every allowed area"),
        "this must not be judged as a path at all — it has no directory to be judged in: {reason}"
    );
}

#[test]
fn a_relative_write_inside_a_snippet_does_not_take_the_vouch_processs_own_directory() {
    // The whole point of the rule above, in the shape that used to ALLOW.
    //
    // `Cargo.toml` exists in the directory `cargo test` runs the binary in
    // (the crate root). Placed as written, `decide_file` canonicalises it —
    // `std::fs::canonicalize` resolves a relative path against the PROCESS's
    // current directory — so the target became this checkout's own
    // `Cargo.toml`, an absolute path inside whatever area the checkout sits
    // in. On a machine whose checkout is under an allowed area that is an
    // ALLOW, and the same call decided somewhere else is not: a verdict
    // depending on where the vouch binary was started from.
    //
    // The assertion holds wherever this runs: the entry makes no claim about
    // the tool's directory, so there is no directory, so it asks.
    let kb = kb_with(&SH_ENTRY.replace("cwd_from_call = true\n", ""));
    let cfg = common::realistic_config();
    let outcome = decide(&cfg, &kb, HOME, &sh_call("echo x > Cargo.toml"));
    let reason = ask_reason(&outcome.decision);
    assert!(reason.contains("unresolved_path"), "got: {reason}");
}

#[test]
fn an_absolute_write_inside_a_snippet_is_still_decided_without_the_cwd_claim() {
    // The scope of the rule above: a target that says where it starts needs
    // no working directory, so the missing claim costs it nothing. Without
    // this pin, "no cwd claim → unresolvable" could quietly grow into "no
    // cwd claim → nothing in the snippet can be decided", which would be a
    // different tool.
    let kb = kb_with(&SH_ENTRY.replace("cwd_from_call = true\n", ""));
    let cfg = common::realistic_config();
    let outcome = decide(&cfg, &kb, HOME, &sh_call("echo hi > C:/Users/dev/notes/probe.txt"));
    assert!(matches!(outcome.decision, Decision::Allow(_)), "got: {:?}", outcome.decision);
}

#[test]
fn a_snippet_with_no_writes_at_all_is_decided_without_the_cwd_claim() {
    // Same scope, from the other side: a snippet that writes nothing has
    // nothing to place, so the missing claim is not a hole in it.
    let kb = kb_with(&SH_ENTRY.replace("cwd_from_call = true\n", ""));
    let cfg = common::realistic_config();
    let outcome = decide(&cfg, &kb, HOME, &sh_call("ls -la"));
    assert!(matches!(outcome.decision, Decision::Allow(_)), "got: {:?}", outcome.decision);
}

#[test]
fn a_relative_write_inside_a_snippet_is_decided_with_the_cwd_claim() {
    let kb = kb_with(SH_ENTRY);
    let cfg = common::realistic_config();
    let outcome = decide(&cfg, &kb, HOME, &sh_call("echo hi > notes/probe.txt"));
    assert!(matches!(outcome.decision, Decision::Allow(_)), "got: {:?}", outcome.decision);
}

#[test]
fn unknown_tool_asks_naming_the_setting() {
    // Mirrors the existing wording pins at `tests/cli_test.rs:726-767`,
    // driven through `route::decide` directly rather than the CLI binary.
    let kb = shipped_kb();
    let cfg = common::realistic_config();
    let input = parse_input(
        r#"{"session_id":"s","cwd":"C:/Users/dev","tool_name":"SomeToolNobodyDescribed2","tool_input":{}}"#,
    )
    .expect("parses");
    let outcome = decide(&cfg, &kb, HOME, &input);
    match &outcome.decision {
        Decision::Ask(reason) => {
            assert!(
                reason.contains("tools.SomeToolNobodyDescribed2"),
                "the prompt must name the setting that turns it off, got: {reason}"
            );
        }
        other => panic!("an unknown tool must ask, got: {other:?}"),
    }
}

/// [M2.5 task 10] An MCP-shaped name (`mcp__<server>__<tail>`) with no entry
/// at all must recommend the scoped per-tool entry — via the vouch-trust
/// skill — BEFORE any mention of `tools.<name>`, must mention the server
/// entry as the deliberate whole-server form, and the `tools.<name>`
/// mention, when it finally comes, must carry the blanket warning. Spec
/// 2026-08-05 §Decision flow rule 4: "it must not recommend `tools.<name> =
/// "allow"` as the first resort".
#[test]
fn an_mcp_shaped_unknown_tool_recommends_the_scoped_entry_before_the_blanket_setting() {
    let kb = shipped_kb();
    let cfg = common::realistic_config();
    let tool = "mcp__totallymadeupserver__totallymadeuptool";
    let input = parse_input(&format!(
        r#"{{"session_id":"s","cwd":"C:/Users/dev","tool_name":"{tool}","tool_input":{{}}}}"#
    ))
    .expect("parses");
    let reason = ask_reason(&decide(&cfg, &kb, HOME, &input).decision).to_string();

    let trust_pos = reason
        .find("vouch-trust skill")
        .unwrap_or_else(|| panic!("no vouch-trust-skill recommendation at all: {reason}"));
    let tools_pos = reason
        .find("tools.mcp__totallymadeupserver__totallymadeuptool")
        .unwrap_or_else(|| panic!("no tools.<name> mention at all: {reason}"));
    assert!(
        trust_pos < tools_pos,
        "the scoped-entry recommendation must come before any tools.<name> mention, got: {reason}"
    );

    let server_pos = reason
        .find("server = \"totallymadeupserver\"")
        .unwrap_or_else(|| panic!("no server-entry mention at all: {reason}"));
    assert!(
        server_pos < tools_pos,
        "the server entry must be mentioned before tools.<name>, got: {reason}"
    );
    assert!(
        reason.contains("whole-server"),
        "must say the server entry is the deliberate whole-server form, got: {reason}"
    );

    assert!(
        reason.contains("blanket grant"),
        "the tools.<name> mention must carry the blanket warning, got: {reason}"
    );
}

/// The non-MCP counterpart: the wording `undeclared`'s `(None, _)` arm
/// produced before this task must not have changed for a name that is not
/// MCP-shaped. Pinned as a full-string equality against the literal text in
/// `src/route.rs`, not just `contains`, so a change leaking out of the new
/// MCP-shaped branch into the shared one would fail here even if every
/// individual substring happened to still be present.
#[test]
fn a_non_mcp_unknown_tool_keeps_todays_wording_unchanged() {
    let kb = shipped_kb();
    let cfg = common::realistic_config();
    let tool = "SomeToolNobodyDescribed3";
    let input = parse_input(&format!(
        r#"{{"session_id":"s","cwd":"C:/Users/dev","tool_name":"{tool}","tool_input":{{}}}}"#
    ))
    .expect("parses");
    let reason = ask_reason(&decide(&cfg, &kb, HOME, &input).decision).to_string();

    // realistic_config() names no tools, so the first-tool warning fires —
    // copied verbatim from `undeclared` in `src/route.rs`.
    let first_tool_warning = "\n  careful: your config names no tools yet — the first tools.<Name> line makes \
         [tools] govern EVERY tool, so each tool it does not name will start asking. The \
         tools vouch currently recognises are the [[tool]] entries in knowledge.toml and \
         my-knowledge.toml — name each one you rely on in the same edit";
    let expected = format!(
        "vouch stopped on: unmodeled_tool\n  \
         tool: {tool}\n  \
         what that means: vouch has no scanner for this tool, so it cannot say \
         what the call does\n  \
         to allow this tool from now on, set tools.{tool} = \"allow\"\n  \
         that setting applies to EVERY use of this tool{first_tool_warning}"
    );
    assert_eq!(reason, expected, "non-MCP unknown-tool wording changed");
}

// --- snippet = [] constructed directly, skipping validate_tool (Task 13 property 4) ---
//
// `snippet = []` is refused by `knowledge::validate_tool` at real load time
// (`[[tool]] ...: snippet = [] is not a thing an entry can say`) - it cannot
// reach the engine through a knowledge FILE loaded the normal way
// (`knowledge::load_files`). `kb_with` here uses `guards::load` directly,
// which skips `validate` entirely, so this shape is constructible as a
// test-only fixture. Task 7's review flagged it as an unpinned hold: an
// entry that nominally declares a snippet alongside a write_path_field that
// independently resolves and allows must not let the write decide alone, as
// though the (unreadable) snippet declaration were not there at all.
//
// [Task 13 finding, since fixed] This pin used to record an ALLOW.
// `decide_declared` (src/route.rs) filtered the snippet with
// `.filter(|p| !p.is_empty())` before deciding on it, so an empty list
// contributed nothing to `worst` - the same as if no snippet were declared
// at all - and the write-path decision alone governed. In this fixture the
// write path resolves under `$HOME/**` and allows, so the call allowed with
// the declared (if empty) snippet silently unread. The filter is the same
// one `Extracted::Refused`/missing-field handling relies on to fail closed
// for every OTHER hole in step 2, and this was the one shape that slipped
// through it silently instead of asking, against the module doc's claim
// that every hole asks. A present-but-empty list is now a hole like the
// rest: it asks, naming the tool.
#[test]
fn a_snippet_of_empty_list_alongside_a_passing_write_path_field_asks() {
    let kb = kb_with(
        r#"
[[tool]]
match = ["mcp__p_s__emptysnippet"]
source = "declares a snippet list that is empty, and a write path"
snippet = []
write_path_field = "path"
"#,
    );
    let cfg = common::realistic_config();
    let input = hook(
        r#"{"session_id":"s","cwd":"C:/Users/dev","tool_name":"mcp__p_s__emptysnippet","tool_input":{"path":"C:/Users/dev/x.txt"}}"#,
    );
    let outcome = decide(&cfg, &kb, HOME, &input);
    let reason = ask_reason(&outcome.decision);
    assert!(
        reason.contains("tools.mcp__p_s__emptysnippet"),
        "the prompt must name the setting that turns it off, got: {reason}"
    );
}


#[test]
fn apply_patch_add_update_delete_and_move_paths_are_all_decided() {
    let kb = kb_with(
        r#"
[[tool]]
match = ["apply_patch"]
source = "applies every path named by the patch command"
cwd_from_call = true
[[tool.write_path]]
field = "command"
format = "apply_patch"
"#,
    );
    let cfg = common::realistic_config();
    let input = hook(
        r#"{"session_id":"s","cwd":"C:/Users/dev","tool_name":"apply_patch","tool_input":{"command":"*** Begin Patch\n*** Add File: notes/new.txt\n+x\n*** Update File: notes/old.txt\n@@\n-x\n+y\n*** Move to: notes/moved.txt\n*** Delete File: notes/gone.txt\n*** End Patch"}}"#,
    );
    let outcome = decide(&cfg, &kb, HOME, &input);
    assert!(matches!(outcome.decision, Decision::Allow(_)), "got: {:?}", outcome.decision);
}

#[test]
fn apply_patch_uses_the_worst_path_in_a_multi_file_patch() {
    let kb = kb_with(
        r#"
[[tool]]
match = ["apply_patch"]
source = "applies every path named by the patch command"
cwd_from_call = true
[[tool.write_path]]
field = "command"
format = "apply_patch"
"#,
    );
    let cfg = common::realistic_config();
    let input = hook(
        r#"{"session_id":"s","cwd":"C:/Users/dev","tool_name":"apply_patch","tool_input":{"command":"*** Begin Patch\n*** Add File: notes/safe.txt\n+x\n*** Add File: D:/elsewhere/unsafe.txt\n+x\n*** End Patch"}}"#,
    );
    assert!(matches!(decide(&cfg, &kb, HOME, &input).decision, Decision::Ask(_)));
}

#[test]
fn malformed_apply_patch_asks_instead_of_losing_the_write() {
    let kb = kb_with(
        r#"
[[tool]]
match = ["apply_patch"]
source = "applies every path named by the patch command"
cwd_from_call = true
[[tool.write_path]]
field = "command"
format = "apply_patch"
"#,
    );
    let cfg = common::realistic_config();
    let input = hook(
        r#"{"session_id":"s","cwd":"C:/Users/dev","tool_name":"apply_patch","tool_input":{"command":"not a patch"}}"#,
    );
    let reason = ask_reason(&decide(&cfg, &kb, HOME, &input).decision).to_string();
    assert!(reason.contains("apply_patch"), "got: {reason}");
    assert!(reason.contains("could not"), "got: {reason}");
}

#[test]
fn an_unknown_apply_patch_directive_cannot_hide_beside_a_valid_path() {
    let kb = kb_with(
        r#"
[[tool]]
match = ["apply_patch"]
source = "applies every path named by the patch command"
cwd_from_call = true
[[tool.write_path]]
field = "command"
format = "apply_patch"
"#,
    );
    let cfg = common::realistic_config();
    let input = hook(
        r#"{"session_id":"s","cwd":"C:/Users/dev","tool_name":"apply_patch","tool_input":{"command":"*** Begin Patch\n*** Add File: notes/safe.txt\n+x\n*** Copy File: D:/elsewhere/hidden.txt\n*** End Patch"}}"#,
    );
    let reason = ask_reason(&decide(&cfg, &kb, HOME, &input).decision).to_string();
    assert!(reason.contains("directive"), "got: {reason}");
}

#[test]
fn shipped_knowledge_inspects_codex_apply_patch_paths() {
    let kb = shipped_kb();
    let cfg = common::realistic_config();
    let safe = hook(
        r#"{"session_id":"s","cwd":"C:/Users/dev","tool_name":"apply_patch","tool_input":{"command":"*** Begin Patch\n*** Add File: notes/safe.txt\n+x\n*** End Patch"}}"#,
    );
    assert!(matches!(
        decide(&cfg, &kb, HOME, &safe).decision,
        Decision::Allow(_)
    ));

    let outside = hook(
        r#"{"session_id":"s","cwd":"C:/Users/dev","tool_name":"apply_patch","tool_input":{"command":"*** Begin Patch\n*** Add File: D:/elsewhere/unsafe.txt\n+x\n*** End Patch"}}"#,
    );
    assert!(matches!(
        decide(&cfg, &kb, HOME, &outside).decision,
        Decision::Ask(_)
    ));
}

#[test]
fn old_and_new_write_path_declarations_cannot_both_be_set() {
    let err = vouch::knowledge::validate_text(
        r#"
version = 9
[[tool]]
match = ["bad"]
source = "bad"
write_path_field = "path"
[[tool.write_path]]
field = "command"
format = "apply_patch"
"#,
    )
    .unwrap_err();
    assert!(err.contains("write_path_field"), "got: {err}");
    assert!(err.contains("write_path"), "got: {err}");
}
