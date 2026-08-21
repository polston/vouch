//! End to end: `python -c` snippets are scanned and judged by the shipped
//! `python:`-prefixed knowledge entries (Task 11, spec 2026-08-07
//! python-snippets).
//!
//! Every test decides through `vouch::engine::decide_command_in` against the
//! repo's own shipped `knowledge.toml` (pinned by `.cargo/config.toml`, read
//! through the process-global `guards::in_effect()` cache) — no custom
//! `[[program]]` fixture is needed, because the entries under test are the
//! real shipped ones. That also means no child process and no
//! `VOUCH_STATE_DIR` are needed: `decide_command_in` is a pure decision
//! function with no journal side effect, the same entry point
//! `wrapper_test.rs` and `evaluated_test.rs` already use.
//!
//! Every written path a test names is absolute, per CLAUDE.md's rule that a
//! relative target would canonicalise against the test process's own
//! directory rather than the one under test.

use vouch::config::load;
use vouch::engine::decide_command_in;
use vouch::protocol::Decision;

const HOME: &str = "C:/Users/dev";

/// The config most tests build from: bash recognises `python` on its own (it
/// is a described program), so `lang.bash.constructs.unmodeled_command` never
/// has to matter — set anyway so an unrelated head never derails a test. The
/// python side is explicit per the brief's own rule: an allow assertion needs
/// BOTH `[lang.python] default = "allow"` AND
/// `[lang.python.constructs] unmodeled_command = "allow"` — the lang default
/// alone never answers for an unmodelled head (`Config::construct_action`
/// only ever falls back to Ask, never to the language default).
fn cfg(python_constructs: &str) -> vouch::config::Config {
    load(&format!(
        "version = 1\n[lang.bash]\ndefault = \"allow\"\n[lang.bash.constructs]\nunmodeled_command = \"allow\"\n\
         [lang.python]\ndefault = \"allow\"\n[lang.python.constructs]\n{python_constructs}\n\
         [write]\ndefault = \"ask\"\nallow_paths = [\"C:/work/**\"]\n"
    ))
    .expect("parses")
}

/// A config with python as the ONLY declared language — used where the test
/// hands python straight to the engine as the HOST language, not nested
/// inside a bash `-c` line (see `subprocess_and_eval_trip_evaluated_input...`
/// below for why).
fn cfg_python_only(python_constructs: &str) -> vouch::config::Config {
    load(&format!(
        "version = 1\n[lang.python]\ndefault = \"allow\"\n[lang.python.constructs]\n{python_constructs}\n\
         [write]\ndefault = \"ask\"\nallow_paths = [\"C:/work/**\"]\n"
    ))
    .expect("parses")
}

fn decide(c: &vouch::config::Config, cmd: &str) -> Decision {
    decide_command_in(c, "bash", cmd, Some(HOME), None)
}

// 1. The python spelling of a recursive delete reaches the same guard as the
// shell spelling.
#[test]
fn the_python_spelling_of_a_recursive_delete_reaches_the_same_guard_as_the_shell_spelling() {
    let c = cfg("unmodeled_command = \"allow\"");
    match decide(&c, r#"python -c "import shutil; shutil.rmtree('C:/work/x')""#) {
        Decision::Ask(r) => assert!(r.contains("delete_recursive"), "got: {r}"),
        other => panic!("expected Ask, got {other:?}"),
    }
    match decide(&c, "rm -rf C:/work/x") {
        Decision::Ask(r) => assert!(r.contains("delete_recursive"), "got: {r}"),
        other => panic!("expected Ask, got {other:?}"),
    }
}

// 2. A snippet write outside allowed areas asks naming the (absolute) path.
#[test]
fn a_snippet_write_outside_allowed_areas_asks_naming_the_absolute_path() {
    let c = cfg("unmodeled_command = \"allow\"");
    match decide(&c, r#"python -c "open('C:/Windows/x.txt', 'w')""#) {
        Decision::Ask(r) => {
            assert!(r.contains("path outside every allowed area"), "got: {r}");
            assert!(r.contains("C:/Windows/x.txt"), "the absolute path is not named: {r}");
        }
        other => panic!("expected Ask, got {other:?}"),
    }
}

// 3. A protected file stays protected from inline code.
#[test]
fn a_protected_file_stays_protected_from_inline_code() {
    let c = load(
        "version = 1\n[lang.bash]\ndefault = \"allow\"\n[lang.bash.constructs]\nunmodeled_command = \"allow\"\n\
         [lang.python]\ndefault = \"allow\"\n[lang.python.constructs]\nunmodeled_command = \"allow\"\n\
         [write]\ndefault = \"ask\"\nallow_paths = [\"C:/work/**\"]\n\
         [protected]\npaths = [\"$HOME/.claude/settings.json\"]\n",
    )
    .expect("parses");
    match decide(&c, r#"python -c "open('C:/Users/dev/.claude/settings.json', 'w')""#) {
        Decision::Ask(r) => assert!(r.contains("protected file"), "got: {r}"),
        other => panic!("expected Ask, got {other:?}"),
    }
}

// 4. Reads are not writes: a snippet calling `open` on an absolute path with
// no mode ALLOWS under the permissive-constructs config.
#[test]
fn a_read_only_open_call_allows_under_the_permissive_constructs_config() {
    let c = cfg("unmodeled_command = \"allow\"");
    // Deliberately OUTSIDE allow_paths — if this were misjudged as a write it
    // would ask "path outside every allowed area", so the allow here is
    // proof it was read as a read, not a coincidence of where the path sits.
    match decide(&c, r#"python -c "open('C:/Windows/x.txt')""#) {
        Decision::Allow(_) => {}
        other => panic!("expected Allow, got {other:?}"),
    }
}

// 5. `windows-1252` is not a write mode.
#[test]
fn windows_1252_named_as_encoding_is_not_read_as_a_write_mode() {
    // "encoding" is not in python:open's arg_names, so the keyword never
    // folds onto the claimed mode position — the position stays absent,
    // which is the documented read default, regardless of what letters
    // "windows-1252" itself contains (it does contain a 'w').
    let c = cfg("unmodeled_command = \"allow\"");
    match decide(&c, r#"python -c "open('C:/Windows/x.txt', encoding='windows-1252')""#) {
        Decision::Allow(_) => {}
        other => panic!("expected Allow, got {other:?}"),
    }
}

// 6. Alias and variable resolution reach the guard.
#[test]
fn alias_and_variable_resolution_reach_the_guard() {
    let c = cfg("unmodeled_command = \"allow\"");
    match decide(&c, r#"python -c "import shutil as sh; sh.rmtree('C:/work/x')""#) {
        Decision::Ask(r) => assert!(r.contains("delete_recursive"), "got: {r}"),
        other => panic!("expected Ask, got {other:?}"),
    }
}

// 7. An unreadable snippet asks naming lang.python.constructs.parse_failure.
#[test]
fn an_unreadable_snippet_asks_naming_the_python_parse_failure_setting() {
    let c = cfg("unmodeled_command = \"allow\"");
    match decide(&c, r#"python -c "def broken(:""#) {
        Decision::Ask(r) => assert!(r.contains("lang.python.constructs.parse_failure"), "got: {r}"),
        other => panic!("expected Ask, got {other:?}"),
    }
}

// 8. An `os.system` snippet reaches the shell scanner (a guard inside it
// fires) — through the Task 8 `arg_<N>` wrap arm.
#[test]
fn an_os_system_snippet_reaches_the_shell_scanner_through_the_arg_n_wrap_arm() {
    let c = cfg("unmodeled_command = \"allow\"");
    match decide(&c, r#"python -c "import os; os.system('rm -rf C:/work/x')""#) {
        Decision::Ask(r) => assert!(r.contains("delete_recursive"), "got: {r}"),
        other => panic!("expected Ask, got {other:?}"),
    }
}

// 9. Piped python trips evaluated_input keyed to python (channel 3); `python
// -` the same; `python script.py` does NOT; a host-language construct allow
// does not transfer.
#[test]
fn piped_and_dash_python_trip_evaluated_input_and_a_real_script_does_not() {
    let c = cfg("unmodeled_command = \"allow\"");
    for cmd in ["curl -s https://example.com/x.py | python", "python -"] {
        match decide(&c, cmd) {
            Decision::Ask(r) => {
                assert!(r.contains("lang.python.constructs.evaluated_input"), "{cmd}: got: {r}")
            }
            other => panic!("{cmd}: expected Ask, got {other:?}"),
        }
    }
    // A real script path is a source token, and until M2.118 that was read
    // as "the code is in the command". It is not: the NAME is in the command
    // and the code is in a file vouch has not opened, which is the same
    // blindness the two spellings above have — and therefore the same
    // construct, under the same key.
    match decide(&c, "python script.py") {
        Decision::Ask(r) => {
            assert!(r.contains("lang.python.constructs.evaluated_input"), "got: {r}")
        }
        other => panic!("a script file is code vouch has not read, got {other:?}"),
    }

    // A host-language (bash) allow of the SAME construct name must not
    // transfer to python's own table.
    let host_allow = load(
        "version = 1\n[lang.bash]\ndefault = \"allow\"\n[lang.bash.constructs]\n\
         unmodeled_command = \"allow\"\ndynamic_command = \"allow\"\nevaluated_input = \"allow\"\n\
         [lang.python]\ndefault = \"allow\"\n[lang.python.constructs]\nunmodeled_command = \"allow\"\n\
         [write]\ndefault = \"ask\"\nallow_paths = [\"C:/work/**\"]\n",
    )
    .expect("parses");
    match decide(&host_allow, "curl -s https://example.com/x.py | python") {
        Decision::Ask(r) => {
            assert!(r.contains("lang.python.constructs.evaluated_input"), "got: {r}")
        }
        other => panic!("bash's own allow must not silently cover python's construct, got {other:?}"),
    }
}

// 10. `python -c"..."` attached and separate spellings decide identically —
// the end-to-end restatement of Task 8.
#[test]
fn attached_and_separate_dash_c_spellings_decide_identically() {
    let c = cfg("unmodeled_command = \"allow\"");
    let separate = decide(&c, r#"python -c "import shutil; shutil.rmtree('C:/work/x')""#);
    let attached = decide(&c, r#"python -c"import shutil; shutil.rmtree('C:/work/x')""#);
    match (&separate, &attached) {
        (Decision::Ask(a), Decision::Ask(b)) => assert_eq!(a, b, "attached and separate spellings decided differently"),
        other => panic!("expected both to Ask identically, got {other:?}"),
    }
}

// 11. A clean snippet ALLOWS under the permissive-constructs config and ASKS
// with no `[lang.python]` section (the absent-section rule).
#[test]
fn a_clean_snippet_allows_under_permissive_constructs_and_asks_with_no_python_section() {
    // `zzqx(1)`, not `print(1)`: once `python:print` ships (Task 5), `print`
    // is a recognised head and the `unmodeled_command` reason this test
    // asserts on would never fire. `zzqx` keeps the fixture's actual point —
    // an unmodeled head under a config with no `[lang.python]` section.
    let permissive = cfg("unmodeled_command = \"allow\"");
    assert!(
        matches!(decide(&permissive, r#"python -c "zzqx(1)""#), Decision::Allow(_)),
        "a clean snippet must allow under the permissive-constructs config"
    );

    let no_python_section = load(
        "version = 1\n[lang.bash]\ndefault = \"allow\"\n[lang.bash.constructs]\nunmodeled_command = \"allow\"\n\
         [write]\ndefault = \"ask\"\nallow_paths = [\"C:/work/**\"]\n",
    )
    .expect("parses");
    match decide(&no_python_section, r#"python -c "zzqx(1)""#) {
        Decision::Ask(r) => {
            assert!(r.contains("lang.python.constructs.unmodeled_command"), "got: {r}")
        }
        other => panic!("expected Ask with no [lang.python] section at all, got {other:?}"),
    }
}

// 12. `subprocess.run(['a','b'])` and `eval("…")` trip evaluated_input, and
// `[lang.python.constructs] evaluated_input = "allow"` stops that prompt.
//
// Decided with python as the DIRECT host language — the shape an MCP tool's
// `[[tool.snippet]] language = "python"` declaration produces — rather than
// nested inside a bash `-c` wrapper. ROADMAP M2.79 (found while writing this
// test): the same calls nested inside a bash-wrapped `python -c` line key
// this ask to the OUTER (bash) language today, because these entries declare
// no `wrap_lang` of their own (they wrap no further text to name a language
// for) and the engine's channel-3 loop falls back to the host language
// rather than the occurrence's own recorded language in that case. That is a
// separate, already-recorded gap; this test exercises the shape that is
// unaffected by it.
#[test]
fn subprocess_and_eval_trip_evaluated_input_settable_via_pythons_own_construct() {
    let asking = cfg_python_only("unmodeled_command = \"allow\"");
    for src in [r#"import subprocess; subprocess.run(['a', 'b'])"#, r#"eval("1 + 1")"#] {
        match decide_command_in(&asking, "python", src, Some(HOME), None) {
            Decision::Ask(r) => {
                assert!(r.contains("lang.python.constructs.evaluated_input"), "{src}: got {r}")
            }
            other => panic!("{src}: expected Ask, got {other:?}"),
        }
    }

    let allowing = cfg_python_only("unmodeled_command = \"allow\"\nevaluated_input = \"allow\"");
    for src in [r#"import subprocess; subprocess.run(['a', 'b'])"#, r#"eval("1 + 1")"#] {
        assert!(
            matches!(decide_command_in(&allowing, "python", src, Some(HOME), None), Decision::Allow(_)),
            "{src}: evaluated_input = \"allow\" did not stop the prompt"
        );
    }
}

// ---------------------------------------------------------------------------
// Heredoc-fed snippets (Task 12): the scanner captures a heredoc's body and
// ties it to the command reading it; the locator inside
// `expand_wrappers_with_sources` hands that body to a scanner exactly when
// the consuming entry declares `evaluates_input = "stdin"`, the command
// itself reads stdin (no script positional; a lone `-` counts), and the body
// reaches the consumer unmodified (a quoted delimiter, or an unquoted one
// with no `$`/backtick). Every case below decides through the same
// `decide_command_in` entry point as the tests above — no custom knowledge
// fixture, the shipped `python`/shell entries are what is under test.
// ---------------------------------------------------------------------------

// 13. A quoted-delimiter heredoc fed to python is scanned: the aliased
// recursive delete reaches the same guard `-c` reaches.
#[test]
fn a_quoted_delimiter_heredoc_fed_to_python_is_scanned() {
    let c = cfg("unmodeled_command = \"allow\"");
    let src = "python - <<'EOF'\nimport shutil\nshutil.rmtree('C:/work/x')\nEOF\n";
    match decide(&c, src) {
        Decision::Ask(r) => assert!(r.contains("delete_recursive"), "got: {r}"),
        other => panic!("expected Ask, got {other:?}"),
    }
}

// 14. An unquoted delimiter whose body contains `$` is NOT scanned — the
// shell would expand it first, so the raw captured text is not what the
// consumer actually sees. The heredoc construct governs, exactly as before
// capture existed.
#[test]
fn an_unquoted_expansion_bearing_body_keeps_todays_behaviour() {
    // This test KEEPS its `evaluated_input = "allow"`, and the reason is now
    // precise: the heredoc here is NOT consumed, so vouch does not hold this
    // command's input and channel 3 legitimately still fires beside the heredoc
    // marker. (The general "trips regardless of the heredoc" reading stopped
    // being true when a consumed body began satisfying the claim — but for this
    // test's own unconsumed shape it still trips, and the allow keeps the
    // assertion below about the HEREDOC construct specifically.)
    let c = cfg("unmodeled_command = \"allow\"\nevaluated_input = \"allow\"");
    let src = "python - <<EOF\nimport shutil\nshutil.rmtree('C:/work/$x')\nEOF\n";
    match decide(&c, src) {
        Decision::Ask(r) => assert!(r.contains("lang.bash.constructs.heredoc"), "got: {r}"),
        other => panic!("expected Ask, got {other:?}"),
    }
}

// 15. An unquoted delimiter whose body holds no `$` or backtick IS scanned —
// nothing shell expansion would act on, so the raw text is exactly what the
// consumer sees.
#[test]
fn an_unquoted_expansion_free_body_is_scanned() {
    let c = cfg("unmodeled_command = \"allow\"");
    let src = "python - <<EOF\nimport shutil\nshutil.rmtree('C:/work/x')\nEOF\n";
    match decide(&c, src) {
        Decision::Ask(r) => assert!(r.contains("delete_recursive"), "got: {r}"),
        other => panic!("expected Ask, got {other:?}"),
    }
}

// 16. A consumed body does not ALSO trip the `heredoc` construct — a
// construct says vouch could not see through something, and here it did.
// `heredoc` is explicitly set to "ask" so a stray double-trip would surface
// as an unexpected Ask rather than being masked by some other default.
#[test]
fn a_scanned_body_does_not_double_trip_the_marker() {
    // This is also the HEADLINE case for the input-source changeset, which is
    // why the `evaluated_input = "allow"` workaround this test used to carry is
    // gone: a consumed body IS this command's proven standard input, so that
    // channel now silences itself and the ask it used to raise was false.
    //
    // Neither `evaluated_input` NOR `dynamic_command` is set for python here,
    // deliberately: an unset construct INHERITS before it defaults, so a
    // `dynamic_command = "allow"` in this config would silence the channel by
    // inheritance and this test would pass with no judgement at all.
    let c = load(
        "version = 1\n[lang.bash]\ndefault = \"allow\"\n[lang.bash.constructs]\n\
         unmodeled_command = \"allow\"\nheredoc = \"ask\"\n\
         [lang.python]\ndefault = \"allow\"\n[lang.python.constructs]\n\
         unmodeled_command = \"allow\"\n\
         [write]\ndefault = \"ask\"\nallow_paths = [\"C:/work/**\"]\n",
    )
    .expect("parses");
    let src = "python - <<'EOF'\nprint(1)\nEOF\n";
    match decide(&c, src) {
        Decision::Allow(_) => {}
        other => panic!("expected Allow (clean body, marker not double-tripped), got {other:?}"),
    }
}

// 17. A heredoc fed to a program with no `evaluates_input = "stdin"`
// declaration (a plain file-reading program) keeps the construct marker,
// exactly today.
#[test]
fn a_heredoc_fed_to_an_undeclared_program_keeps_the_marker() {
    let c = cfg("unmodeled_command = \"allow\"");
    let src = "cat <<'EOF'\nhello\nEOF\n";
    match decide(&c, src) {
        Decision::Ask(r) => assert!(r.contains("lang.bash.constructs.heredoc"), "got: {r}"),
        other => panic!("expected Ask, got {other:?}"),
    }
}

// 18. A heredoc nested inside a wrapped snippet keeps its marker too — the
// capture must not vanish at the snippet boundary. `frobnicate` is an
// undeclared program (unmodeled_command is allowed so THAT never decides),
// so the inner heredoc is neither consumed by the locator nor silently
// dropped: the engine's own re-scan of the wrapped snippet text carries the
// capture up and marks it.
#[test]
fn a_nested_heredoc_keeps_its_marker() {
    let c = cfg("unmodeled_command = \"allow\"");
    let src = "sh -c \"frobnicate <<EOF\nhello\nEOF\n\"\n";
    match decide(&c, src) {
        Decision::Ask(r) => assert!(r.contains("lang.bash.constructs.heredoc"), "got: {r}"),
        other => panic!("expected Ask, got {other:?}"),
    }
}

// 19. A heredoc reaching a program through a PIPE, not a direct attachment
// (`cat <<'EOF' | python`), is the piped case, not the heredoc-locator case:
// the locator never fires (the heredoc feeds `cat`, which is undeclared),
// and `python` — reading from what the pipe feeds it, with no source token
// of its own — trips its own `evaluated_input` claim instead.
#[test]
fn a_pipe_fed_consumer_is_the_piped_case() {
    let c = cfg("unmodeled_command = \"allow\"");
    let src = "cat <<'EOF' | python\nprint(1)\nEOF\n";
    match decide(&c, src) {
        Decision::Ask(r) => assert!(
            r.contains("lang.python.constructs.evaluated_input"),
            "got: {r}"
        ),
        other => panic!("expected Ask, got {other:?}"),
    }
}

// 20. A heredoc feeding a SHELL is scanned too, closing the 44-occurrence
// heredoc-fed-shell shape the corpus measurement has called a gap since
// July — this requires the shells' knowledge entry to carry `wrap_lang =
// "bash"` (Task 12's completing knowledge line), or the locator has no
// language to scan the body as.
#[test]
fn heredoc_fed_shells_are_scanned_too() {
    let c = cfg("unmodeled_command = \"allow\"");
    let src = "bash <<'EOF'\nrm -rf C:/work/x\nEOF\n";
    match decide(&c, src) {
        Decision::Ask(r) => assert!(r.contains("delete_recursive"), "got: {r}"),
        other => panic!("expected Ask, got {other:?}"),
    }
}

/// Wraps `text` as the argument to one more `sh -c`, producing real,
/// independently re-parseable shell source (mirrors the identically-named
/// helper in `guards_test.rs`, duplicated here since integration test
/// binaries share no code except `mod common`): single-quoted when `text`
/// holds no single quote, double-quoted with `\`/`"` escaped otherwise.
fn wrap_in_sh_c(text: &str) -> String {
    if text.contains('\'') {
        let mut escaped = String::with_capacity(text.len());
        for c in text.chars() {
            match c {
                '\\' => escaped.push_str("\\\\"),
                '"' => escaped.push_str("\\\""),
                other => escaped.push(other),
            }
        }
        format!("sh -c \"{escaped}\"")
    } else {
        format!("sh -c '{text}'")
    }
}

/// `n` layers of `sh -c` wrapped around `inner`.
fn nest_sh_c(inner: &str, n: usize) -> String {
    let mut src = inner.to_string();
    for _ in 0..n {
        src = wrap_in_sh_c(&src);
    }
    src
}

// 21. The heredoc body sits under the SAME depth counter as every other
// snippet kind: a heredoc-fed body that itself nests wrappers one layer past
// the cap asks naming `wrap_depth_exceeded`, the same as a flag-carried
// snippet would. The heredoc consumption itself is the first hop (bash's own
// occurrence at depth 0 -> the body's own top-level command at depth 1), so
// four more `sh -c` layers inside the body reach depth 5 — one past the
// built-in cap of 4.
#[test]
fn a_past_cap_nest_through_a_heredoc_asks() {
    // The `evaluated_input = "allow"` this test used to carry is gone: the
    // body IS consumed here (quoted delimiter), so that channel silences
    // itself. The suppression is load-bearing for this assertion rather than
    // incidental — the wrap-depth fold sits AFTER channel 3 and equal-rank
    // folds keep the earliest reason, so without it the depth-cap reason would
    // lose the tie and never be the one reported.
    let c = load(
        "version = 1\n[lang.bash]\ndefault = \"allow\"\n[lang.bash.constructs]\n\
         unmodeled_command = \"allow\"\n\
         [lang.python]\ndefault = \"allow\"\n[lang.python.constructs]\nunmodeled_command = \"allow\"\n\
         [write]\ndefault = \"ask\"\nallow_paths = [\"C:/work/**\"]\n",
    )
    .expect("parses");
    let body = nest_sh_c("echo done", 4);
    let src = format!("bash <<'EOF'\n{body}\nEOF\n");
    match decide(&c, &src) {
        Decision::Ask(r) => assert!(r.contains("wrap_depth_exceeded"), "got: {r}"),
        other => panic!("expected Ask, got {other:?}"),
    }
}

// 22. The shipped chmod entry matches both a module-shaped head
// (`python:os.chmod`) and a method-shaped head (`python:.chmod`) in the SAME
// entry. The keyword-fold offset that places `arg_names` positions has to be
// read from each call's own head, not from the whole entry's match-name set
// — otherwise every occurrence of a mixed entry is treated as method-shaped,
// and a keyword-spelled module call's "path" keyword folds one slot too far,
// leaving position 0 an unresolved hole instead of the named path.
#[test]
fn a_keyword_spelled_module_chmod_call_resolves_its_path_argument() {
    let c = cfg("unmodeled_command = \"allow\"");
    match decide(&c, r#"python -c "import os; os.chmod(path='C:/work/target', mode=0o755)""#) {
        Decision::Allow(_) => {}
        other => panic!(
            "expected Allow (path resolves to C:/work/target, inside allow_paths), got {other:?}"
        ),
    }
}

// 23. The method-spelled form of that same mixed entry already puts its
// receiver at position 0 without any keyword folding needed for it, so it
// has to keep resolving correctly after the fix above too — a keyword-spelled
// "mode" here must not disturb the receiver already sitting at position 0.
#[test]
fn the_method_spelled_chmod_call_still_resolves_its_receiver_path() {
    let c = cfg("unmodeled_command = \"allow\"");
    match decide(&c, r#"python -c "p = 'C:/work/target'; p.chmod(mode=0o644)""#) {
        Decision::Allow(_) => {}
        other => panic!("expected Allow (receiver resolves to C:/work/target), got {other:?}"),
    }
}

// 24. A nameless `**` keyword-unpack could be supplying `open`'s "mode"
// invisibly (`open(**{"file": "x", "mode": "w"}) `is ordinary Python), and
// `mode_says_write`'s "absent position means the documented read default"
// reading does not hold when the absence is caused by an unpack rather than
// a genuinely omitted argument. Found live (task 2b fix round 2, the
// `UNPACK_MARKER` sweep): before the fix, both calls below ALLOWED
// unconditionally — a write through `open` could be smuggled past the mode
// gate by any keyword-unpack, whatever the unseen mode actually was.
//
// No `file=` was ever given here, so there is genuinely nothing to resolve
// the write target to — the prompt shows the ordinary unresolved-value
// marker (`$?`), never the unpack's own sentinel (`$**`): confirming that
// even in the one shape where NEITHER marker could possibly be replaced by
// a real value, the internal unpack token still never leaks into
// operator-facing text.
#[test]
fn a_bare_unpack_into_open_can_no_longer_hide_a_write_mode() {
    let c = cfg("unmodeled_command = \"allow\"");
    match decide(&c, r#"python -c "open(**opts)""#) {
        Decision::Ask(r) => {
            assert!(r.contains("unresolved_path"), "got: {r}");
            assert!(!r.contains("$**"), "the unpack sentinel leaked into the prompt: {r}");
        }
        other => panic!("expected Ask, got {other:?}"),
    }
}

// 25. A keyword-spelled path alongside a trailing unpack must resolve to the
// REAL path, not the unpack's own token — found by the round-3 re-review:
// `fold_kwargs` was pushing the unpack sentinel into the folded array as if
// it were a genuine positional occupant, so it landed in the prompt (or,
// worse, silently in the write-judgment machinery) instead of the file the
// operator actually named. Two shapes pin this: a path OUTSIDE the allowed
// area still asks, but now names the real path, never the sentinel; a path
// INSIDE the allowed area now resolves correctly and allows, where round 2
// could only ask (misreading the destination as unresolved).
#[test]
fn an_unpack_alongside_an_out_of_bounds_file_keyword_names_the_real_path_not_a_sentinel() {
    let c = cfg("unmodeled_command = \"allow\"");
    match decide(&c, r#"python -c "open(file='C:/elsewhere/x.txt', **opts)""#) {
        Decision::Ask(r) => {
            assert!(r.contains("path outside every allowed area"), "got: {r}");
            assert!(r.contains("C:/elsewhere/x.txt"), "the real path is not named: {r}");
            assert!(!r.contains("$**"), "the unpack sentinel leaked into the prompt: {r}");
            assert!(!r.contains("$?"), "the ordinary marker leaked in place of a resolvable path: {r}");
        }
        other => panic!("expected Ask, got {other:?}"),
    }
}

// Task 2b fix round 4 retargeted this one, and the two below it, from
// `open` to `codecs.open`: once `open`'s own `opener` parameter was
// audited and declared as a `callback_args` slot (`opener` is CALLED by
// `open` itself), any `**opts` on `open` correctly asks regardless of what
// the file/mode resolve to — `opts` could always be supplying `opener`.
// That is the CORRECT, more complete behaviour (proven by
// `open_calling_a_reference_through_opener_via_unpack_asks` above), but it
// means `open` can no longer demonstrate THIS test's actual point — the
// `fold_kwargs` positional fix letting a real keyword-spelled value resolve
// — in isolation. `codecs.open` shares the identical mode-gate shape
// (`writes_only_with_file_mode`, `arg_names`) with no callback parameter of
// its own, so it still can.
#[test]
fn an_unpack_alongside_an_in_bounds_file_keyword_now_resolves_and_allows() {
    let c = cfg("unmodeled_command = \"allow\"");
    match decide(&c, r#"python -c "import codecs; codecs.open(filename='C:/work/x.txt', **opts)""#) {
        Decision::Allow(_) => {}
        other => panic!(
            "expected Allow (the path resolves to C:/work/x.txt, inside allow_paths, and the \
             unpack no longer displaces it in the folded array), got {other:?}"
        ),
    }
}

// 26. The fix must not become a blanket "any unpack anywhere asks" — an
// EXPLICIT, readable mode alongside an unpack is still read correctly; only
// an ABSENT mode position becomes untrustworthy once an unpack is present.
// Retargeted to `codecs.open` for the reason given above.
#[test]
fn an_explicit_readable_mode_alongside_an_unpack_still_allows() {
    let c = cfg("unmodeled_command = \"allow\"");
    match decide(&c, r#"python -c "import codecs; codecs.open(mode='r', **opts)""#) {
        Decision::Allow(_) => {}
        other => panic!("expected Allow (mode is explicit and read-only), got {other:?}"),
    }
}

// `open` itself now correctly asks on ANY unpack, mode notwithstanding —
// pinned directly here so the divergence from `codecs.open`'s behaviour
// above is a documented, deliberate fact rather than something a future
// reader has to re-derive from two separately-passing tests.
#[test]
fn opens_own_explicit_readable_mode_does_not_suppress_the_opener_ask() {
    let c = cfg("unmodeled_command = \"allow\"");
    match decide(&c, r#"python -c "open(mode='r', **opts)""#) {
        Decision::Ask(r) => assert!(r.contains("callback_argument"), "got: {r}"),
        other => panic!("expected Ask (opener could still be supplied through opts), got {other:?}"),
    }
}

// 27. Position-shift behaviour for the ORDINARY unresolved marker must be
// completely unaffected by round 3's change — only the unpack's own
// sentinel stops occupying a slot; a plain unresolvable argument (no name
// to attach, not from an unpack) still must occupy its position or the
// argument after it would shift into the wrong slot. `os.rename` carries no
// `arg_names` (its `writes = "all_args"` needs none), so this is the
// scanner's own marker-holds-its-place behaviour reaching the engine
// end-to-end, independent of round 3's `fold_kwargs` change entirely.
#[test]
fn an_unresolvable_first_argument_does_not_shift_the_real_destination() {
    let c = cfg("unmodeled_command = \"allow\"");
    match decide(&c, r#"python -c "import os; os.rename(compute(), 'C:/work/x.txt')""#) {
        Decision::Ask(r) => {
            // The unresolvable first argument is what's reported — proof
            // the SECOND argument was read as its own position (the real
            // destination), not folded into position 0's place.
            assert!(r.contains("unresolved_path"), "got: {r}");
        }
        other => panic!("expected Ask (the first argument is unresolvable), got {other:?}"),
    }
}

// A companion to 27 that exercises `fold_kwargs` itself (unlike
// `os.rename`, `open`/`codecs.open` DO declare `arg_names`) and combines
// every piece round 3 touches in one call: an unresolvable KEYWORD value
// (`mode`, no name to attach a value to, but still a real argument) sitting
// BEFORE a real resolvable one in call order, plus a trailing unpack. The
// unresolvable marker must still occupy its own claimed slot; the unpack
// must occupy none at all; `file`/`filename` must resolve to its real value
// regardless of source order or the unpack sitting after it. Retargeted to
// `codecs.open` for the reason given at test 25's retargeted companion
// above (`open`'s own `opener` parameter now correctly asks regardless).
#[test]
fn an_unresolvable_keyword_value_still_occupies_its_slot_alongside_a_trailing_unpack() {
    let c = cfg("unmodeled_command = \"allow\"");
    match decide(&c, r#"python -c "import codecs; codecs.open(mode=compute(), filename='C:/work/x.txt', **opts)""#) {
        Decision::Allow(_) => {}
        other => panic!(
            "expected Allow (filename resolves to C:/work/x.txt regardless of where mode's \
             unresolvable value sits or the trailing unpack), got {other:?}"
        ),
    }
}

// 28. Task 2b fix round 4: the invoked-parameter class was never audited on
// the WRITE-side python entries from the earlier changeset. Three named
// probes, each a function reference handed to a parameter the callee
// invokes itself: shutil.copytree calls `ignore` and `copy_function`,
// shutil.move calls `copy_function`, open calls `opener`. Before this
// round all three allowed unconditionally.
#[test]
fn shutil_copytree_calling_a_reference_through_ignore_asks() {
    let c = cfg("unmodeled_command = \"allow\"");
    match decide(&c, r#"python -c "import shutil, os; shutil.copytree('C:/work/a', 'C:/work/b', ignore=os.remove)""#) {
        Decision::Ask(r) => assert!(r.contains("callback_argument"), "got: {r}"),
        other => panic!("expected Ask, got {other:?}"),
    }
}

#[test]
fn shutil_move_calling_a_reference_through_copy_function_asks() {
    let c = cfg("unmodeled_command = \"allow\"");
    match decide(&c, r#"python -c "import shutil, os; shutil.move('C:/work/a', 'C:/work/b', copy_function=os.system)""#) {
        Decision::Ask(r) => assert!(r.contains("callback_argument"), "got: {r}"),
        other => panic!("expected Ask, got {other:?}"),
    }
}

#[test]
fn open_calling_a_reference_through_opener_via_unpack_asks() {
    let c = cfg("unmodeled_command = \"allow\"");
    match decide(&c, r#"python -c "open(file='C:/work/x.txt', **opts)""#) {
        Decision::Ask(r) => assert!(r.contains("callback_argument"), "got: {r}"),
        other => panic!("expected Ask, got {other:?}"),
    }
}

// 29. No over-ask: the same four shapes with NOTHING invoked keep whatever
// their verdict already was before this round — recorded here, not just
// asserted, so a future change that quietly narrows the write claim itself
// shows up as a changed comment, not a silent behaviour change nobody reads.
//   shutil.copytree('C:/work/a', 'C:/work/b')  -> Allow, before and after
//   shutil.move('C:/work/a', 'C:/work/b')      -> Allow, before and after
//   open('C:/work/f.txt', 'w')                 -> Allow (write detected, target inside allow_paths), before and after
//   open('C:/work/f.txt')                      -> Allow (read, no mode given), before and after
#[test]
fn a_clean_copytree_call_still_allows() {
    let c = cfg("unmodeled_command = \"allow\"");
    match decide(&c, r#"python -c "import shutil; shutil.copytree('C:/work/a', 'C:/work/b')""#) {
        Decision::Allow(_) => {}
        other => panic!("expected Allow, got {other:?}"),
    }
}

#[test]
fn a_clean_move_call_still_allows() {
    let c = cfg("unmodeled_command = \"allow\"");
    match decide(&c, r#"python -c "import shutil; shutil.move('C:/work/a', 'C:/work/b')""#) {
        Decision::Allow(_) => {}
        other => panic!("expected Allow, got {other:?}"),
    }
}

#[test]
fn a_clean_write_mode_open_call_still_allows() {
    let c = cfg("unmodeled_command = \"allow\"");
    match decide(&c, r#"python -c "open('C:/work/f.txt', 'w')""#) {
        Decision::Allow(_) => {}
        other => panic!("expected Allow, got {other:?}"),
    }
}

#[test]
fn a_clean_read_open_call_still_allows() {
    let c = cfg("unmodeled_command = \"allow\"");
    match decide(&c, r#"python -c "open('C:/work/f.txt')""#) {
        Decision::Allow(_) => {}
        other => panic!("expected Allow, got {other:?}"),
    }
}

// 30. shutil.rmtree's onerror/onexc are declared even though the
// unconditional delete_recursive rule already asks on every call
// (coordinator's point 3) — this pins that the rule still fires (unaffected
// by the new fields) and, separately, that the callback declaration itself
// is live rather than dead (proven in isolation from the guard in
// `tests/python_read_entries_test.rs`'s
// `every_declared_callback_slot_trips_the_construct`, which turns the guard
// off for exactly this reason).
#[test]
fn shutil_rmtree_still_asks_via_its_guard_regardless_of_onerror() {
    let c = cfg("unmodeled_command = \"allow\"");
    match decide(&c, r#"python -c "import shutil; shutil.rmtree('C:/work/a', onerror=g)""#) {
        Decision::Ask(r) => assert!(r.contains("delete_recursive"), "got: {r}"),
        other => panic!("expected Ask, got {other:?}"),
    }
}

// 31. Task 2b fix round 5, the remaining two properties `PADDING_MARKER`
// needed the same coverage the other two sentinels already had.

// `open(mode="w", encoding="utf-8")` never addresses `file` (position 0) at
// all — only `mode` and `encoding`, both by keyword — so folding `encoding`
// onto its own position pads straight through position 0. The write
// proceeds (mode says so) and the target read must show the ORDINARY
// unresolved marker there, never the padding sentinel's own text.
#[test]
fn the_padding_sentinel_never_appears_in_a_prompt() {
    let c = cfg("unmodeled_command = \"allow\"");
    match decide(&c, r#"python -c "open(mode='w', encoding='utf-8')""#) {
        Decision::Ask(r) => {
            assert!(r.contains("unresolved_path"), "got: {r}");
            assert!(!r.contains("$,"), "the padding sentinel leaked into the prompt: {r}");
        }
        other => panic!("expected Ask, got {other:?}"),
    }
}

// A literal, if unusual, mode value that happens to equal `PADDING_MARKER`'s
// own text must be read as exactly that — a real, given argument — not as
// "this position was never addressed at all". Before occupancy was tracked
// by INDEX rather than by comparing a position's text (this round's
// structural fix), this read as genuinely absent and ALLOWED regardless of
// the destination; the destination here is deliberately OUTSIDE the allowed
// area, so a silent allow would be visible immediately.
#[test]
fn a_literal_argument_matching_the_padding_sentinels_text_is_not_read_as_padding() {
    let c = cfg("unmodeled_command = \"allow\"");
    match decide(&c, r#"python -c "open('C:/elsewhere/f.txt', '$,')""#) {
        Decision::Ask(r) => {
            assert!(r.contains("path outside every allowed area"), "got: {r}");
            assert!(r.contains("C:/elsewhere/f.txt"), "the real path is not named: {r}");
        }
        other => panic!("expected Ask, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// The input-source changeset, end to end. `cfg()` leaves both
// `evaluated_input` and its inheritance donor `dynamic_command` unset for
// python, so the channel really is the thing under test in every pin below.
// Every competing redirect is spelled on the consumer's OWN line, before the
// body — one written after the terminator belongs to a different command.
// ---------------------------------------------------------------------------

/// Asserts the line still asks, and that the reason is the input channel.
fn asks_on_input(src: &str) {
    let c = cfg("unmodeled_command = \"allow\"");
    match decide(&c, src) {
        Decision::Ask(r) => assert!(
            r.contains("constructs.evaluated_input"),
            "expected the input channel to ask for {src:?}, got: {r}"
        ),
        other => panic!("expected Ask for {src:?}, got {other:?}"),
    }
}

/// Asserts the line allows — vouch holds this command's input.
fn allows(src: &str) {
    let c = cfg("unmodeled_command = \"allow\"");
    match decide(&c, src) {
        Decision::Allow(_) => {}
        other => panic!("expected Allow for {src:?}, got {other:?}"),
    }
}

#[test]
fn a_held_input_allows_end_to_end() {
    allows("python - <<'EOF'\nprint(1)\nEOF\n");
    allows("bash <<'EOF'\nls -la\nEOF\n");
    allows("python - <<'EOF' > C:/work/out.txt\nprint(1)\nEOF\n");
    allows("cat f.txt | python - <<'EOF'\nprint(1)\nEOF\n");
    allows("sh -c \"python - <<'EOF'\nprint(1)\nEOF\n\"");
    allows("while read x; do python - <<'EOF'\nprint(1)\nEOF\n done < C:/work/list.txt");
    allows("python - <<'EOF'\nEOF\n");
    // The competitor comes FIRST, so the here-document is still the last
    // descriptor-0 redirect and still the delivered source. Its twin — the
    // competitor written last — is in the refusal set below.
    allows("python - < f.txt <<'EOF'\nprint(1)\nEOF\n");
}

#[test]
fn an_unheld_input_still_asks_end_to_end() {
    asks_on_input("python - <<EOF\nprint('$x')\nEOF\n");
    asks_on_input("python -s script.py <<'EOF'\nprint(1)\nEOF\n");
    asks_on_input("python -mjson.tool <<'EOF'\nprint(1)\nEOF\n");
    asks_on_input("python <(cat f.py) <<'EOF'\nprint(1)\nEOF\n");
    asks_on_input("python - <<'EOF' < f.txt\nprint(1)\nEOF\n");
    asks_on_input("python - <<'EOF' <> C:/work/f.txt\nprint(1)\nEOF\n");
    asks_on_input("python - <<'EOF' < <(cat f.py)\nprint(1)\nEOF\n");
    asks_on_input("python - <<'EOF' 0<&3\nprint(1)\nEOF\n");
    asks_on_input("python - <<'EOF' <<<'x'\nprint(1)\nEOF\n");
    asks_on_input("python - 3<<'EOF'\nprint(1)\nEOF\n");
    // A wrapper prefix: the here-document belongs to the WRAPPER, so the body
    // is never scanned and the unwrapped consumer must not inherit an answer
    // about it. `env` rather than `sudo` — sudo trips a privilege guard, which
    // folds ahead of this channel and would mask what is under test.
    asks_on_input("env python - <<'EOF'\nprint(1)\nEOF\n");
    asks_on_input("cat f.py | python");
}

// The same wrapper shape under `sudo`, which asks for its own guard reason
// first — asserted separately so the pin above can be specific about the input
// channel while this one records that the shape still asks at all.
#[test]
fn a_wrapper_fronted_consumer_asks_whatever_reason_wins() {
    let c = cfg("unmodeled_command = \"allow\"");
    match decide(&c, "sudo python - <<'EOF'\nprint(1)\nEOF\n") {
        Decision::Ask(_) => {}
        other => panic!("expected Ask, got {other:?}"),
    }
}

// A consumed body that does not parse hands the reason to channel 1, which
// names the body's own language — the code WAS in the command, it just could
// not be read, and saying "not in what vouch was handed" would be the false
// sentence this changeset removes. Suppression is what lets that channel
// speak: it folds after the input channel and would otherwise lose the tie.
#[test]
fn a_consumed_but_unparseable_body_asks_as_a_parse_failure() {
    let c = cfg("unmodeled_command = \"allow\"");
    match decide(&c, "python - <<'EOF'\ndef def def(\nEOF\n") {
        Decision::Ask(r) => {
            assert!(r.contains("parse_failure"), "got: {r}");
            assert!(!r.contains("evaluated_input"), "the input channel must stay silent: {r}");
        }
        other => panic!("expected Ask, got {other:?}"),
    }
}

// Two consumers on one line — the only shape that crosses the engine's
// per-command re-basing of the here-document list, and therefore the only
// witness that a named record's index is re-based along with it.
//
// BOTH bodies are clean and quoted, so both must be held and the line must
// allow. That is what discriminates: the second consumer's record sits at
// position 1 of the whole-line list and position 0 of its own filtered one, so
// an omitted or off-by-one re-base leaves its index out of bounds, the
// judgement refuses, and the input channel asks. Asserting an Ask on a
// deliberately-unheld shape would instead pass under every wrong
// implementation, including the ones that never re-base at all.
#[test]
fn two_consumers_on_one_line_are_judged_independently() {
    let c = cfg("unmodeled_command = \"allow\"");
    let src = "python - <<'A'\nprint(1)\nA\npython - <<'B'\nprint(2)\nB\n";
    match decide(&c, src) {
        Decision::Allow(_) => {}
        other => panic!("both consumers hold their own body, so: {other:?}"),
    }
}

// The adversarial twin of the pin above: the FIRST consumer's body carries an
// expansion character, so it is never consumed and its own input is genuinely
// unknown — the channel must still ask for it even though the second consumer
// on the same line is held.
#[test]
fn one_unheld_consumer_still_asks_beside_a_held_one() {
    let c = cfg("unmodeled_command = \"allow\"");
    let src = "python - <<A\nprint('$x')\nA\npython - <<'B'\nprint(2)\nB\n";
    match decide(&c, src) {
        Decision::Ask(r) => assert!(r.contains("constructs.evaluated_input"), "got: {r}"),
        other => panic!("expected the unheld consumer to ask, got {other:?}"),
    }
}
