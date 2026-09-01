//! Resolving a written path to the file it actually lands on.
//!
//! Agent tooling constantly writes `f="C:/…/x.output"` and then
//! `> "$f"`. Before 2026-07-25 vouch kept the quotes the parser attached, so
//! the target read as the relative path `"$f"`, got the working directory
//! prepended, and became `C:/claude/"$f"` — a file that does not exist. That
//! produced prompts naming a fabricated path AND let real writes through.
//!
//! Resolution happens in the order the shell itself would: unquote, then
//! variables assigned literally in the same text, then the environment. What
//! survives all three is genuinely unknowable and is reported as such.

use vouch::config::load;
use vouch::engine::decide_command_in;
use vouch::paths::{expand_env_with, normalize_newlines, unquote, unquote_snippet};
use vouch::protocol::Decision;

fn cfg() -> vouch::config::Config {
    load(
        r#"
version = 1
[lang.bash]
default = "allow"
[lang.bash.constructs]
unmodeled_command = "allow"
subshell = "allow"
dynamic_redirect = "allow"
[lang.powershell]
default = "allow"
[lang.powershell.constructs]
unmodeled_command = "allow"
assignment = "allow"
env_assignment = "allow"
method_call = "allow"
redirect = "allow"
[write]
default = "ask"
allow_paths = ["C:/work/**", "C:/workspace/**"]
[protected]
paths = ["$HOME/.claude/settings.json"]
"#,
    )
    .expect("parses")
}

fn decide(cmd: &str) -> Decision {
    decide_command_in(&cfg(), "bash", cmd, Some("C:/Users/dev"), None)
}

#[test]
fn quotes_are_stripped_from_a_redirect_target() {
    assert_eq!(unquote(r#""$f""#), "$f");
    assert_eq!(unquote("'$f'"), "$f");
    assert_eq!(unquote("plain"), "plain");
    // Only ONE layer, and only when they match.
    assert_eq!(unquote(r#""unbalanced"#), r#""unbalanced"#);
}

#[test]
fn unquote_snippet_strips_one_layer_of_double_quotes_and_unescapes() {
    assert_eq!(unquote_snippet(r#""print(\"hi\")""#), r#"print("hi")"#);
    assert_eq!(unquote_snippet(r#""a\\b""#), r"a\b");
}

#[test]
fn unquote_snippet_single_quotes_are_verbatim() {
    assert_eq!(unquote_snippet(r#"'print("hi")'"#), r#"print("hi")"#);
    assert_eq!(unquote_snippet(r"'a\\b'"), r"a\\b");
}

#[test]
fn unquote_snippet_unquoted_text_drops_backslashes() {
    assert_eq!(unquote_snippet(r"a\ b"), "a b");
}

#[test]
fn unquote_snippet_leaves_unbalanced_quotes_alone() {
    assert_eq!(unquote_snippet(r#""half"#), r#""half"#);
}

#[test]
fn unquote_snippet_an_escaped_final_quote_is_not_a_closing_quote() {
    // The trailing `\"` escapes that quote rather than closing the string,
    // so this is unbalanced, not a well-formed double-quoted snippet — and
    // an unbalanced extraction is returned exactly as written.
    assert_eq!(unquote_snippet(r#""print(1)\""#), r#""print(1)\""#);
}

#[test]
fn unquote_snippet_empty_string_is_empty() {
    assert_eq!(unquote_snippet(""), "");
}

#[test]
fn unquote_snippet_a_single_character_is_itself() {
    assert_eq!(unquote_snippet("x"), "x");
    // A lone quote character opens a quote it cannot possibly close.
    assert_eq!(unquote_snippet("\""), "\"");
    assert_eq!(unquote_snippet("'"), "'");
}

#[test]
fn unquote_snippet_a_lone_trailing_backslash_is_dropped_when_unquoted() {
    assert_eq!(unquote_snippet(r"a\"), "a");
}

#[test]
fn unquote_snippet_a_trailing_escaped_backslash_survives_inside_double_quotes() {
    // `\\` right before the closing quote is an EVEN run (one escaped
    // pair), so the quote still closes; the pair unescapes to one literal
    // trailing backslash in the output.
    assert_eq!(unquote_snippet(r#""a\\""#), r"a\");
}

#[test]
fn unquote_snippet_an_unbalanced_quote_containing_a_backslash_stays_verbatim() {
    // Opens a double quote, has a backslash inside, never closes at all —
    // unbalanced, so no backslash processing happens either.
    assert_eq!(unquote_snippet(r#""a\b"#), r#""a\b"#);
}

#[test]
fn normalize_newlines_converts_crlf_only() {
    assert_eq!(normalize_newlines("a\r\nb\nc"), "a\nb\nc");
}

#[test]
fn a_variable_assigned_in_the_same_command_resolves() {
    // The write lands on a protected file. Naming it is the whole point.
    match decide(r#"f="C:/Users/dev/.claude/settings.json" echo x > "$f""#) {
        Decision::Ask(r) => {
            assert!(r.contains("C:/Users/dev/.claude/settings.json"), "{r}");
            assert!(!r.contains("$f"), "reported an unresolved path: {r}");
        }
        other => panic!("expected Ask, got {other:?}"),
    }
}

#[test]
fn resolving_can_also_clear_a_write() {
    // This used to become `C:/claude/"$f"` and prompt about a path that does
    // not exist. Resolving it correctly means it is plainly inside C:/work.
    assert!(
        matches!(decide(r#"f="C:/work/ok.txt" echo x > "$f""#), Decision::Allow(_)),
        "a resolvable write into an allowed area should not prompt"
    );
}

#[test]
fn a_variable_used_as_a_prefix_resolves() {
    match decide(r#"D="C:/work/sub" echo y > "$D/out.txt""#) {
        Decision::Allow(_) => {}
        other => panic!("expected Allow, got {other:?}"),
    }
}

#[test]
fn the_last_assignment_wins() {
    match decide(r#"f="C:/work/a.txt" f="C:/Users/dev/.claude/settings.json" echo x > "$f""#) {
        Decision::Ask(r) => assert!(r.contains("settings.json"), "{r}"),
        other => panic!("expected Ask, got {other:?}"),
    }
}

#[test]
fn a_value_built_by_command_substitution_is_not_treated_as_known() {
    // `T=$(mktemp -d)` is genuinely unknowable at gate time. Claiming to know
    // it would be worse than saying so.
    match decide(r#"T=$(mktemp -d) echo x > "$T/out.txt""#) {
        Decision::Ask(r) | Decision::Deny(r) => {
            assert!(r.contains("unresolved_path"), "{r}")
        }
        other => panic!("expected a prompt naming unresolved_path, got {other:?}"),
    }
}

#[test]
fn an_unset_variable_stays_unresolved_and_names_its_setting() {
    match decide(r#"echo x > "$nothing_defines_this/out.txt""#) {
        Decision::Ask(r) => {
            assert!(r.contains("unresolved_path"), "{r}");
            assert!(r.contains("constructs.unresolved_path"), "no setting named: {r}");
        }
        other => panic!("expected Ask, got {other:?}"),
    }
}

#[test]
fn environment_variables_are_substituted_in_every_spelling() {
    let look = |n: &str| match n {
        "USERPROFILE" => Some("C:/Users/dev".to_string()),
        "TEMP" => Some("C:/tmp".to_string()),
        _ => None,
    };
    assert_eq!(expand_env_with("%USERPROFILE%/x", &look), "C:/Users/dev/x");
    assert_eq!(expand_env_with("$env:USERPROFILE/x", &look), "C:/Users/dev/x");
    assert_eq!(expand_env_with("$TEMP/x", &look), "C:/tmp/x");
    assert_eq!(expand_env_with("${TEMP}/x", &look), "C:/tmp/x");
    // Unset names are left exactly as written — that is the honest answer.
    assert_eq!(expand_env_with("$NOPE/x", &look), "$NOPE/x");
    assert_eq!(expand_env_with("%NOPE%/x", &look), "%NOPE%/x");
}

#[test]
fn none_of_vouchs_own_python_sentinels_are_legal_environment_variable_references() {
    // `src/python.rs`'s `MARKER` ("$?") and `UNPACK_MARKER` ("$**"), and
    // `src/guards.rs`'s `PADDING_MARKER` ("$,") — task 2b fix round 5,
    // proven structurally rather than by inspection. `PADDING_MARKER`'s
    // first spelling, "$_", passed this resolver's `$NAME` grammar
    // (`[A-Za-z0-9_]`), so a padded write-target position expanded against
    // the REAL process environment before the "still contains `$`"
    // fail-closed check downstream ever ran — verified live by the
    // reviewer, with a genuine environment variable, before this fix.
    //
    // An ALWAYS-succeeding lookup proves the grammar itself rejects each
    // sentinel, never a real environment variable's absence: if the parser
    // ever recognised a name inside any of these three, this lookup would
    // supply a value and the text would change. It never does. This repo's
    // own rule against process-wide env vars in tests (CLAUDE.md §9) is why
    // the property is proven this way — through the injectable lookup
    // `expand_env_with` already takes — rather than by setting one.
    let always_succeeds = |_: &str| Some("SHOULD_NOT_APPEAR".to_string());
    for sentinel in ["$?", "$**", "$,"] {
        assert_eq!(
            expand_env_with(sentinel, &always_succeeds),
            sentinel,
            "{sentinel} was accepted as a $NAME reference"
        );
    }
}

#[test]
fn expansion_never_evaluates_anything() {
    let look = |_: &str| Some("SHOULD_NOT_APPEAR".to_string());
    // A command substitution is not a variable reference; it must survive
    // untouched rather than being handed to the lookup.
    let out = expand_env_with("$(rm -rf /)", &look);
    assert!(out.starts_with("$(") || out.contains("rm -rf"), "{out}");
}

#[test]
fn the_home_spellings_all_name_the_same_directory() {
    // A rule written with one spelling has to match a command written with
    // another, or the rule only works when the caller happens to agree.
    for form in [
        "~/.claude/settings.json",
        "$HOME/.claude/settings.json",
        "${HOME}/.claude/settings.json",
        "$env:USERPROFILE/.claude/settings.json",
    ] {
        let cmd = format!("echo x > {form}");
        assert!(
            matches!(decide(&cmd), Decision::Ask(_) | Decision::Deny(_)),
            "spelling not recognised as the protected file: {form}"
        );
    }
}

#[test]
fn a_benign_redirect_inside_a_wrapped_snippet_stays_quiet() {
    // INVERTED (§2.2 item 6, M2.125/§5.2.4): this used to be the counterpart
    // to the protected-file case in crossshell_test, proving that reading a
    // snippet does not turn every wrapped write into a prompt. cmd is its
    // own unscannable language now, so its redirect is never read at all —
    // "quiet" would mean trusting a write inside text vouch never looked at,
    // which is exactly the silent laundering M2.125 closes. It now asks,
    // honestly, via unreadable_language.
    match decide(r#"cmd /c "echo x > C:/work/ok.txt""#) {
        Decision::Ask(r) => assert!(r.contains("unreadable_language"), "got: {r}"),
        other => panic!("expected Ask, got {other:?}"),
    }
}

// --- PowerShell side -------------------------------------------------------
// The same pattern, the other language. Implementing this for bash only left
// `$sp = "C:/…"` unresolvable in PowerShell even though it is a plain literal.

fn decide_ps(cmd: &str) -> Decision {
    decide_command_in(&cfg(), "powershell", cmd, Some("C:/Users/dev"), None)
}

#[test]
fn a_set_location_dash_path_target_still_resolves() {
    // [task-6/7 review] Until Task 7 (spec 2026-07-31 §4), the cd-family walk
    // took the FIRST token after the head that did not start with `-` — it
    // did not know `-Path` was the parameter naming the value, it only
    // happened to land on the value because `-Path` itself starts with `-`
    // and got skipped over. Task 7 taught it PowerShell's named-parameter
    // grammar for real: `-Path`/`-LiteralPath` are declared `dest_dir_flags`
    // on the powershell `set-location` entry (knowledge.toml), so rule 1 now
    // consumes `-Path`'s value AS the destination candidate on purpose,
    // rather than by the old heuristic's coincidence. The answer is
    // unchanged — pinning here so `Set-Location -Path C:/x` keeps resolving
    // exactly like `Set-Location C:/x` rather than silently regressing to
    // "unresolved".
    // && per design 2026-08-30 §4.2 — named-parameter grammar is the
    // subject, so the mover is certified.
    match decide_ps(r#"Set-Location -Path C:/x && Set-Content -Path y.txt -Value h"#) {
        Decision::Ask(r) => assert!(r.contains("C:/x/y.txt"), "{r}"),
        other => panic!("expected Ask, got {other:?}"),
    }
}

#[test]
fn a_powershell_literal_assignment_resolves() {
    match decide_ps(r#"$sp = "C:/Users/dev/.claude"; Set-Content -Path "$sp/settings.json" -Value x"#) {
        Decision::Ask(r) => {
            assert!(r.contains("C:/Users/dev/.claude/settings.json"), "{r}");
            assert!(!r.contains("$sp"), "reported an unresolved path: {r}");
        }
        other => panic!("expected Ask, got {other:?}"),
    }
}

#[test]
fn a_powershell_assignment_can_also_clear_a_write() {
    assert!(
        matches!(
            decide_ps(r#"$sp = "C:/work/out"; Set-Content -Path "$sp/f.txt" -Value x"#),
            Decision::Allow(_)
        ),
        "a resolvable write into an allowed area should not prompt"
    );
}

#[test]
fn chained_assignments_resolve_to_a_fixed_point() {
    // `$a` -> `$b` -> target. One substitution pass would leave `$a` behind.
    assert!(
        matches!(
            decide_ps(r#"$a = "C:/work"; $b = "$a/deep"; Set-Content -Path "$b/f.txt" -Value x"#),
            Decision::Allow(_)
        ),
        "chained assignment did not resolve"
    );
}

#[test]
fn a_computed_powershell_value_is_not_treated_as_known() {
    // `Join-Path` is a call, not a literal. Claiming to know the result would
    // be worse than saying it is unknown.
    match decide_ps(r#"$link = Join-Path $sp "sub"; Set-Content -Path $link -Value x"#) {
        Decision::Ask(r) | Decision::Deny(r) => {
            assert!(r.contains("unresolved_path"), "{r}")
        }
        other => panic!("expected a prompt naming unresolved_path, got {other:?}"),
    }
}

#[test]
fn a_self_referential_assignment_cannot_spin() {
    // Resolution runs to a fixed point, so it must be bounded.
    let _ = decide_ps(r#"$a = "$a/x"; Set-Content -Path "$a/f.txt" -Value y"#);
    let _ = decide(r#"a="$a/x" echo z > "$a/f.txt""#);
}

// --- iteration 21: where a RELATIVE write actually lands --------------------
//
// `cd /c/Users/dev/.claude && echo x > settings.json` writes the protected
// file. Resolving `settings.json` against the hook's own working directory said
// it landed somewhere harmless, and it was ALLOWED. The destination is stated
// in plain sight one command earlier, exactly like a literal assignment.

#[test]
fn a_relative_write_lands_in_the_directory_the_command_changed_to() {
    match decide(r#"cd /c/Users/dev/.claude && echo x > settings.json"#) {
        Decision::Ask(r) => {
            assert!(r.contains("C:/Users/dev/.claude/settings.json"), "{r}")
        }
        other => panic!("the protected file was written, got {other:?}"),
    }
}

#[test]
fn the_cd_target_decides_whether_a_relative_write_is_allowed() {
    // Same relative filename, two destinations, two different answers.
    assert!(matches!(
        decide("cd /c/work && echo x > y.txt"),
        Decision::Allow(_)
    ));
    match decide("cd /c/Windows/System32 && echo x > y.txt") {
        Decision::Ask(r) => assert!(r.contains("C:/Windows/System32/y.txt"), "{r}"),
        other => panic!("expected Ask, got {other:?}"),
    }
}

#[test]
fn a_program_that_writes_by_flag_uses_the_cd_target_too() {
    // The fix belongs to path resolution, not to redirects specifically.
    // && per design 2026-08-30 §4.2 — flag-value composition is the subject,
    // so the mover is certified.
    match decide("cd /c/Windows/System32 && curl -o y.dll https://example.com/a") {
        Decision::Ask(r) => assert!(r.contains("C:/Windows/System32/y.dll"), "{r}"),
        other => panic!("expected Ask, got {other:?}"),
    }
}

#[test]
fn several_directory_changes_compose_in_the_order_they_run() {
    // This asked, with "the command changes directory more than once", until
    // per-command ordered resolution landed on 2026-07-30. That was true of a
    // SET of directory changes and false of a SEQUENCE: `&&` and `;`
    // guarantee the order, so the state at the write is everything before it
    // composed left to right, and a second absolute change is simply the one
    // in effect. Nothing is guessed — the shapes where the order is NOT
    // provable still ask, which is `unorderable_cds_fail_closed`.
    assert!(matches!(
        decide("cd /c/work && cd /c/workspace && echo x > y.txt"),
        Decision::Allow(_)
    ));
    // And the write is judged in the LAST one, not the first.
    match decide("cd /c/work && cd /c/Windows/System32 && echo x > y.txt") {
        Decision::Ask(r) => assert!(r.contains("C:/Windows/System32/y.txt"), "{r}"),
        other => panic!("expected Ask, got {other:?}"),
    }
    // A relative change composes against the directory before it.
    match decide("cd /c/work && cd ../Windows && echo x > y.txt") {
        Decision::Ask(r) => assert!(r.contains("C:/Windows/y.txt"), "{r}"),
        other => panic!("expected Ask, got {other:?}"),
    }
}

#[test]
fn changing_to_a_directory_vouch_cannot_resolve_is_also_unknown() {
    match decide(r#"cd "$SOMEWHERE" && echo x > y.txt"#) {
        Decision::Ask(r) => assert!(r.contains("unresolved_path"), "{r}"),
        other => panic!("expected Ask, got {other:?}"),
    }
}

#[test]
fn a_download_destination_is_checked_like_any_other_write() {
    assert!(matches!(
        decide("curl -o /c/work/ok.bin https://example.com/a"),
        Decision::Allow(_)
    ));
    assert!(matches!(
        decide("curl -o /c/Windows/System32/x.dll https://example.com/a"),
        Decision::Ask(_)
    ));
    // The URL is a positional argument, not a path — it must not be reported.
    assert!(matches!(
        decide("curl -s https://example.com/a"),
        Decision::Allow(_)
    ));
}
