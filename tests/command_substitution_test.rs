//! The command-substitution reader and walk (M2.250, M2.155's other half).
//! Design: docs/specs/2026-09-07-command-substitution-bodies-design.md.
mod common;

use vouch::config::Action;
use vouch::engine::decide_command_in;
use vouch::protocol::Decision;
use vouch::shell::{heredoc_substitution_bodies, strip_line_continuations, substitution_bodies, Bash};
use vouch::syntax::{Order, Scanner};

fn bodies(raw: &str) -> Vec<String> {
    substitution_bodies(raw).bodies
}

#[test]
fn a_plain_substitution_yields_its_body() {
    assert_eq!(bodies("$(rm -rf d)"), vec!["rm -rf d"]);
    assert_eq!(bodies("`rm -rf d`"), vec!["rm -rf d"]);
    assert_eq!(bodies("pre$(a)mid`b`post"), vec!["a", "b"]);
}

#[test]
fn quoting_decides_what_is_a_body() {
    assert_eq!(bodies("\"$(a)\""), vec!["a"], "double quotes expand");
    assert_eq!(bodies("$\"$(a)\""), vec!["a"], "gettext double quotes expand (probed)");
    assert!(bodies("'$(a)'").is_empty(), "single quotes are literal");
    assert!(bodies("\"\\$(a)\"").is_empty(), "an escaped dollar inside double quotes is literal");
    assert!(bodies("\\`a\\`").is_empty(), "an escaped backtick pair is literal");
    assert!(!substitution_bodies("'$(a)'").unreadable);
}

#[test]
fn a_nested_body_is_reported_once_at_its_outer_level() {
    // The inner `$(b)` belongs to the walk over "echo $(b)", not to this word.
    assert_eq!(bodies("$(echo $(b))"), vec!["echo $(b)"]);
    assert_eq!(bodies("`echo \\`b\\``"), vec!["echo `b`"], "the escape before a nested backtick is collapsed, as bash collapses it");
}

#[test]
fn parameter_expansion_strings_are_read() {
    assert_eq!(bodies("${x:-$(a)}"), vec!["a"]);
    assert_eq!(bodies("${x:=$(a)}"), vec!["a"]);
    assert_eq!(bodies("${x:?$(a)}"), vec!["a"]);
    assert_eq!(bodies("${x:+$(a)}"), vec!["a"]);
    assert_eq!(bodies("${x#$(a)}"), vec!["a"]);
    assert_eq!(bodies("${x/$(a)/$(b)}"), vec!["a", "b"]);
    assert_eq!(bodies("${arr[$(a)]}"), vec!["a"], "an array subscript is evaluated (probed)");
    assert_eq!(bodies("${v:$(a):$(b)}"), vec!["a", "b"], "substring offset and length are evaluated (probed)");
}

#[test]
fn arithmetic_expansion_is_told_from_a_substitution_by_balance() {
    assert!(bodies("$((1+2))").is_empty(), "arithmetic runs no command");
    assert!(bodies("$((touch M))").is_empty(), "balanced text is arithmetic, and a runtime syntax error runs nothing (probed)");
    assert_eq!(bodies("$(( $(id -u) + 1 ))"), vec!["id -u"], "a substitution inside arithmetic runs first");
    assert_eq!(bodies("$((echo a); (touch M))"), vec!["(echo a); (touch M)"], "unbalanced text is a substitution holding a subshell (probed)");
    assert_eq!(bodies("$((touch M) )"), vec!["(touch M) "], "the spaced spelling is a plain substitution");
}

#[test]
fn a_line_continuation_is_removed_before_reading() {
    assert_eq!(strip_line_continuations("a\\\nb").as_ref(), "ab");
    assert_eq!(bodies("$\\\n(a)"), vec!["a"], "a split opener still runs (probed in a here-document body)");
}

#[test]
fn text_vouch_cannot_delimit_is_flagged_rather_than_dropped() {
    let b = substitution_bodies("$(foo");
    assert!(b.bodies.is_empty());
    assert!(b.unreadable, "an unterminated opener is unreadable, not literal");
    assert!(!substitution_bodies("$((1+2))").unreadable);
    assert!(!substitution_bodies("plain").unreadable);
}

#[test]
fn an_empty_substitution_is_an_empty_body() {
    assert_eq!(bodies("$()"), vec![""]);
}

#[test]
fn a_heredoc_body_is_read_through_the_heredoc_parser() {
    assert_eq!(heredoc_substitution_bodies("$(id)").bodies, vec!["id"]);
    assert!(heredoc_substitution_bodies("$(foo").unreadable);
    assert_eq!(
        heredoc_substitution_bodies("$\\\n(id)").bodies,
        vec!["id"],
        "a split opener still runs (design §2.1)"
    );
}

#[test]
fn a_here_document_inside_a_substitution_is_data_to_the_delimiter() {
    let two_words = "$(cat <<'EOF'\nalpha (beta it's gamma) don't delta\nuse `--alpha` and `--beta`\nEOF\n)";
    assert_eq!(bodies(two_words), vec!["cat <<'EOF'\nalpha (beta it's gamma) don't delta\nuse `--alpha` and `--beta`\nEOF\n"]);
    assert!(!substitution_bodies(two_words).unreadable);
    let one_side = "$(cat <<'EOF'\nit's (alpha don't beta) gamma\nuse `--zeta` here\nEOF\n)";
    assert_eq!(bodies(one_side), vec!["cat <<'EOF'\nit's (alpha don't beta) gamma\nuse `--zeta` here\nEOF\n"]);
    let numbered = "$(cat <<'EOF'\n1) use `--alpha`\nEOF\n)";
    assert_eq!(bodies(numbered), vec!["cat <<'EOF'\n1) use `--alpha`\nEOF\n"]);
    let balanced = "$(cat <<'EOF'\nsee (foo) here\nEOF\n)";
    assert_eq!(bodies(balanced), vec!["cat <<'EOF'\nsee (foo) here\nEOF\n"]);
    let unquoted = "$(cat <<EOF\nit's (x\nEOF\n)";
    assert_eq!(bodies(unquoted), vec!["cat <<EOF\nit's (x\nEOF\n"]);
    let dashed = "$(cat <<-EOF\n\tit's (x\n\tEOF\n)";
    assert_eq!(bodies(dashed), vec!["cat <<-EOF\n\tit's (x\n\tEOF\n"]);
    let two_docs = "$(cat <<A <<B\nit's (\nA\ndon't )\nB\n)";
    assert_eq!(bodies(two_docs), vec!["cat <<A <<B\nit's (\nA\ndon't )\nB\n"]);
    let unterminated_doc = "$(cat <<'EOF'\nnever closed\n)";
    assert!(substitution_bodies(unterminated_doc).unreadable);
}

#[test]
fn a_here_string_and_an_arithmetic_shift_are_not_here_documents() {
    assert_eq!(bodies("$(cat <<< \"it's\")"), vec!["cat <<< \"it's\""]);
    assert!(bodies("$(( x << 2 ))").is_empty());
    assert!(!substitution_bodies("$(( x << 2 ))").unreadable);
    // An arithmetic shift followed by a real here-document on the same line:
    // the arithmetic reading never looks for a delimiter, so the `<<` inside
    // the parentheses is a shift and the outer text is read whole.
    assert!(bodies("$(( x << 2 )); cat <<EOF\nfoo\nEOF\n").is_empty());
    assert!(!substitution_bodies("$(( x << 2 )); cat <<EOF\nfoo\nEOF\n").unreadable);
}

#[test]
fn a_bodys_content_keeps_its_own_quoting() {
    assert_eq!(bodies("$(echo 'a)b')"), vec!["echo 'a)b'"]);
    assert_eq!(bodies("$(echo \"a)b\")"), vec!["echo \"a)b\""]);
    assert_eq!(bodies("$(echo \\))"), vec!["echo \\)"]);
    assert!(substitution_bodies("\"$(echo hi\"").unreadable);
}

#[test]
fn here_document_mode_reads_quotes_as_text_and_escapes_as_bash_does() {
    assert_eq!(heredoc_substitution_bodies("it's $(id) done").bodies, vec!["id"]);
    assert_eq!(heredoc_substitution_bodies("say \"$(id)\"").bodies, vec!["id"]);
    assert!(heredoc_substitution_bodies("cost \\$(id)").bodies.is_empty());
    assert_eq!(heredoc_substitution_bodies("$(echo 'a)b')").bodies, vec!["echo 'a)b'"], "inside the body the content is shell again");
    assert_eq!(heredoc_substitution_bodies("`id`").bodies, vec!["id"]);
    assert!(heredoc_substitution_bodies("a \\` b").bodies.is_empty());
}

#[test]
fn a_comment_inside_a_substitution_does_not_close_it() {
    let commented = "$(echo a # not a closer )\nrm -rf C:/Users/dev/scratch\n)";
    assert_eq!(bodies(commented), vec!["echo a # not a closer )\nrm -rf C:/Users/dev/scratch\n"]);
    assert!(!substitution_bodies(commented).unreadable);
    assert_eq!(bodies("$(# leading comment )\necho hi\n)"), vec!["# leading comment )\necho hi\n"]);
    assert_eq!(bodies("$(echo 'a # b')"), vec!["echo 'a # b'"]);
    assert_eq!(bodies("$(echo \"a # b\")"), vec!["echo \"a # b\""]);
    assert_eq!(bodies("$(echo a#b)"), vec!["echo a#b"]);
    assert!(substitution_bodies("$(echo a # never closed").unreadable);
    // Backticks close character-first, as bash reads them.
    assert_eq!(bodies("`echo a # x`"), vec!["echo a # x"]);
}

#[test]
fn a_comment_after_a_close_parenthesis_inside_a_substitution_does_not_close_it() {
    // A `)` ends a word, so a `#` written straight after one begins a comment
    // and the comment swallows the parenthesis a reader would close on. zsh 5.9
    // reads this as ONE substitution printing both lines.
    let after_paren = "$( (echo a)#x )\necho B\n)";
    assert_eq!(bodies(after_paren), vec![" (echo a)#x )\necho B\n"]);
    assert!(!substitution_bodies(after_paren).unreadable);
}

#[test]
fn a_nested_substitution_is_read_to_its_own_closer() {
    // A `"` inside a nested substitution belongs to that substitution, not to
    // the double-quoted string the nest sits in, so it must not flip the outer
    // walk's quote parity. Both shells give the whole body here.
    assert_eq!(bodies("$(echo \"$(echo \"a)\")\")"), vec!["echo \"$(echo \"a)\")\""]);
    assert_eq!(
        bodies("$(printf \"%s\" \"$(sed \"s/)//\" f)\")"),
        vec!["printf \"%s\" \"$(sed \"s/)//\" f)\""]
    );
    assert_eq!(bodies("$(echo \"$(echo ')')\")"), vec!["echo \"$(echo ')')\""]);
    // The nested arithmetic is decided on its own no-skip walk, so its `<<` is
    // a shift and never arms the outer walk's here-document skip.
    let shift = "$(echo $((1 << 2))\necho hi)";
    assert_eq!(bodies(shift), vec!["echo $((1 << 2))\necho hi"]);
    assert!(!substitution_bodies(shift).unreadable);
}

#[test]
fn a_comment_marker_right_after_a_nested_closer_is_text() {
    // A `)` that ends a SUBSHELL is an operator: it ends the word before it,
    // so a `#` written after it begins a comment (pinned above). The `)` that
    // closes a nested substitution is INSIDE a word, so the `#` after that one
    // is ordinary text — zsh 5.9 prints "a#x" and "3#x" for these two.
    let nested = "$(echo $(echo a)#x)";
    assert_eq!(bodies(nested), vec!["echo $(echo a)#x"]);
    assert!(!substitution_bodies(nested).unreadable);
    let arithmetic = "$(echo $((1+2))#x)";
    assert_eq!(bodies(arithmetic), vec!["echo $((1+2))#x"]);
    assert!(!substitution_bodies(arithmetic).unreadable);
}

#[test]
fn a_nest_deeper_than_the_cap_is_refused_rather_than_walked() {
    let nest = |n: usize| (0..n).fold("echo a".to_string(), |s, _| format!("$((echo a); {s})"));
    let three = nest(3);
    let read = substitution_bodies(&three);
    assert!(!read.unreadable, "three levels are inside the cap");
    assert_eq!(read.bodies.len(), 1);
    // COMPLETING is the assertion. Each `$((`-shaped level costs up to two
    // whole extent walks, so resolving a nested opener once per enclosing walk
    // is exponential: forty levels is 2^41 walks and this line would not
    // return for hours. The cap refuses the ninth level and the per-scan memo
    // keeps every level that IS resolved to one walk.
    let forty = nest(40);
    let read = substitution_bodies(&forty);
    assert!(read.unreadable, "past the cap the extent is refused, never guessed");
    assert!(read.bodies.is_empty());
}

#[test]
fn a_case_statements_pattern_parentheses_do_not_close_a_substitution() {
    assert_eq!(bodies("$(case $x in a) echo;; esac)"), vec!["case $x in a) echo;; esac"]);
    assert_eq!(bodies("$(case $x in (a) echo;; esac)"), vec!["case $x in (a) echo;; esac"]);
    // `case` in argument position is a word, not a keyword.
    assert_eq!(bodies("$(grep case file)"), vec!["grep case file"]);
    // The inner `esac` must not end the outer statement, or the outer `c)`
    // pattern below would be read as this substitution's closer.
    let nested = "$(case $x in a)\ncase $y in b) echo;; esac\n;;\nc) echo;;\nesac)";
    assert_eq!(bodies(nested), vec!["case $x in a)\ncase $y in b) echo;; esac\n;;\nc) echo;;\nesac"]);
}

// ---------------------------------------------------------------------------
// The visitor: every body is walked from the simple-command positions —
// head, prefix assignment, suffix argument (design §2.1–§2.2's first three
// rows, Task 2).
// ---------------------------------------------------------------------------

const RM: &str = "rm -rf C:/Users/dev/scratch";

/// The standing replay configuration: guards ask, an undescribed program
/// does not — so under it the inner guard is the only thing that can ask
/// (design §4).
fn decide(cmd: &str) -> Decision {
    decide_command_in(&common::realistic_config(), "bash", cmd, Some(common::HOOK_HOME), None)
}

fn reason(d: &Decision) -> String {
    match d {
        Decision::Ask(r) | Decision::Allow(r) | Decision::Deny(r) => r.clone(),
        Decision::Abstain => String::new(),
    }
}

/// Every construct the scan raised.
fn constructs(src: &str) -> Vec<String> {
    Bash.scan(src).expect("scans").constructs
}

fn asks_on_the_guard(cmd: &str) {
    let d = decide(cmd);
    assert!(matches!(d, Decision::Ask(_)), "{cmd}: {d:?}");
    assert!(reason(&d).contains("delete_recursive"), "{cmd}: {}", reason(&d));
}

#[test]
fn a_guard_inside_a_substitution_fires_from_the_simple_command_positions() {
    asks_on_the_guard(&format!("$({RM}) --version"));
    asks_on_the_guard(&format!("X=$({RM}) ls"));
    asks_on_the_guard(&format!("echo $({RM})"));
    asks_on_the_guard(&format!("echo k=$({RM})"));
    asks_on_the_guard(&format!("arr=($({RM}))"));
    asks_on_the_guard(&format!("echo \"$({RM})\""));
    asks_on_the_guard(&format!("echo $\"$({RM})\""));
    asks_on_the_guard(&format!("echo ${{x:-$({RM})}}"));
    asks_on_the_guard(&format!("echo ${{a[$({RM})]}}"));
    asks_on_the_guard(&format!("echo ${{v:$({RM}):1}}"));
    asks_on_the_guard(&format!("echo `{RM}`"));
    asks_on_the_guard(&format!("echo $(echo $({RM}))"));
    asks_on_the_guard(&format!("echo $(( $({RM}) + 1 ))"));
    asks_on_the_guard(&format!("echo $((echo a); ({RM}))"));
    asks_on_the_guard(&format!("echo $(({RM}) )"));
}

#[test]
fn a_guard_after_a_comment_inside_a_substitution_still_fires() {
    asks_on_the_guard("echo $(echo a # note )\nrm -rf C:/Users/dev/scratch\n)");
}

/// The reachable half of the same defect. brush's own COMMAND parser strips a
/// comment out of a `$( … )` before the visitor ever sees the word, so the
/// test above passes on brush's reading whether or not vouch has one of its
/// own. An unquoted here-document body is raw text nothing pre-processes, and
/// bash expands a substitution written in it — so this spelling ran the
/// delete while vouch allowed the row (probed at bb170c8: Allow).
#[test]
fn a_guard_after_a_comment_inside_a_substitution_in_a_here_document_still_fires() {
    asks_on_the_guard(
        "cat <<EOF\n$(echo a # note )\nrm -rf C:/Users/dev/scratch\n)\nEOF\n",
    );
    // The same reachable path with the comment beginning straight after a `)`,
    // which ends a word exactly as a space does.
    asks_on_the_guard(
        "cat <<EOF\n$( (echo a)#note )\nrm -rf C:/Users/dev/scratch\n)\nEOF\n",
    );
}

#[test]
fn what_is_inside_decides_recognition() {
    let ask_unknown = vouch::config::load(&common::config_text_with(&[(
        "bash",
        "unmodeled_command",
        "ask",
    )]))
    .unwrap();
    let (v, r) = common::decision_at(&ask_unknown, "echo $(unknownprogzz)", common::HOOK_HOME);
    assert_eq!(v, "ask", "{r}");
    assert!(
        r.contains("unknownprogzz") && r.contains("lang.bash.constructs.unmodeled_command"),
        "{r}"
    );
    let (v, r) = common::decision_at(&ask_unknown, "echo $(ls -la)", common::HOOK_HOME);
    assert_eq!(v, "allow", "{r}");
    assert_eq!(constructs("echo $(ls -la)"), vec!["subshell".to_string()]);
}

#[test]
fn a_false_note_is_no_longer_raised() {
    for src in ["echo $((1+2))", "echo '$(x)'", "echo \"\\$(x)\"", "echo \\`x\\`"] {
        assert!(constructs(src).is_empty(), "{src} noted {:?}", constructs(src));
    }
}

#[test]
fn unreadable_substitution_text_asks_on_parse_failure() {
    // The outer line parses; only the body does not.
    assert!(Bash.scan("echo $(for)").is_ok());
    assert!(constructs("echo $(for)").contains(&"parse_failure".to_string()));
    let d = decide("echo $(for)");
    assert!(reason(&d).contains("parse_failure"), "{}", reason(&d));
}

#[test]
fn the_nesting_cap_fails_closed() {
    let eight = (0..8).fold(RM.to_string(), |s, _| format!("echo $({s})"));
    asks_on_the_guard(&eight);
    let nine = format!("echo $({eight})");
    let d = decide(&nine);
    assert!(reason(&d).contains("parse_failure"), "{}", reason(&d));
}

/// `the_nesting_cap_fails_closed` above puts nine `$(` openers in ONE word,
/// so the READER's own per-word cap (`read_substitution`'s `depth`
/// parameter, reset to 0 on every fresh call) refuses the ninth opener
/// before the walk's own depth (`WalkState::depth`, read by
/// `walk_substitution_body`) ever gets near its own cap. This spreads the
/// same nine levels across nine separate heredoc-wrapped bodies instead, so
/// every individual `bodies_via` call sees at most one `$(` opener of its own
/// — the reader's local depth never leaves 0 — and only the WALK's depth,
/// which persists across the whole recursive walk rather than resetting per
/// word, can be the thing that trips.
#[test]
fn the_walks_own_cap_is_reached_without_the_readers_cap_firing() {
    fn nested(level: usize, total: usize) -> String {
        if level > total {
            RM.to_string()
        } else {
            format!("cat <<EOF{level}\n$({})\nEOF{level}\n", nested(level + 1, total))
        }
    }
    let eight = nested(1, 8);
    asks_on_the_guard(&eight);
    let nine = nested(1, 9);
    let d = decide(&nine);
    assert!(reason(&d).contains("parse_failure"), "{}", reason(&d));
}

#[test]
fn the_outer_command_is_unchanged_by_the_walk_inside() {
    let s = Bash.scan(&format!("$({RM}) --version")).unwrap();
    assert!(s.constructs.contains(&"dynamic_command".to_string()));
    assert!(s.args_complete.iter().all(|c| *c));
    // Both facts hold — the target still resolves to nothing and asks on
    // `unresolved_path`, AND the guard inside now fires — but they cannot
    // both show up as substrings of the SAME reported reason under one
    // config, so each is pinned at the ENGINE layer under the config that
    // lets it surface.
    //
    // Under the default config the guard-hit pass runs first (`src/engine.rs`
    // around line 1065: `worst` is `None`, so it is set unconditionally the
    // first time) and the later write-target pass's own `unresolved_path`
    // ask is the same Ask rank, so the strict `rank(a) > rank(*w)` test
    // around line 1493 does not displace it — the reported reason is
    // `delete_recursive` alone.
    let target_cmd = format!("echo x > $({RM})");
    let d = decide(&target_cmd);
    assert!(reason(&d).contains("delete_recursive"), "{}", reason(&d));
    // Allow the guard globally and the SAME two lines of engine.rs now work
    // the other way: the guard-hit pass still sets `worst` first (line
    // 1065's check is unconditional the first time, an Allow included, rank
    // 0), but the write-target pass's Ask (rank 1) then strictly outranks
    // it at line 1493 and displaces it — so `unresolved_path` reaches the
    // reported reason at the engine layer, proving the target is still
    // judged as unresolved there rather than merely kept as raw scanner
    // text.
    let allow_guard = common::realistic_config_with("[guards]\ndelete_recursive = \"allow\"\n");
    let d2 = decide_command_in(&allow_guard, "bash", &target_cmd, Some(common::HOOK_HOME), None);
    assert!(reason(&d2).contains("unresolved_path"), "{}", reason(&d2));
    let s = Bash.scan(&format!("X=$({RM}); rm \"$X\"")).unwrap();
    assert!(s.assignments.iter().any(|(n, v)| n == "X" && v.is_none()), "X is poisoned");
}

// ---------------------------------------------------------------------------
// Task 3: redirect targets, here-strings, here-document bodies, and a
// function definition's own redirect list (design §2.2's remaining rows).
// ---------------------------------------------------------------------------

#[test]
fn a_guard_inside_a_substitution_fires_from_the_redirect_positions() {
    let allow_unresolved = common::realistic_config_with_construct("bash", "unresolved_path", Action::Allow);
    for cmd in [format!("echo x > $({RM})"), format!("echo x >&$({RM})"), format!("echo x &> $({RM})")] {
        let (v, r) = common::decision_at(&allow_unresolved, &cmd, common::HOOK_HOME);
        assert_eq!(v, "ask", "{cmd}: {r}");
        assert!(r.contains("delete_recursive"), "{cmd}: {r}");
    }
    asks_on_the_guard(&format!("cat <<< \"$({RM})\""));
}

#[test]
fn an_unquoted_here_document_body_is_walked_and_a_quoted_one_is_not() {
    asks_on_the_guard(&format!("cat <<EOF\n$({RM})\nEOF\n"));
    asks_on_the_guard(&format!("{{ :; }} <<EOF\n$({RM})\nEOF\n"));
    asks_on_the_guard(&format!("cat <<EOF\n$\\\n({RM})\nEOF\n"));
    let d = decide(&format!("cat <<'EOF'\n$({RM})\nEOF\n"));
    assert!(matches!(d, Decision::Allow(_)), "{d:?}");
}

#[test]
fn an_unterminated_opener_in_a_here_document_body_asks_on_parse_failure() {
    let src = "cat <<EOF\n$(foo\nEOF\n";
    assert!(vouch::shell::Bash.scan(src).is_ok());
    assert!(constructs(src).contains(&"parse_failure".to_string()));
    let d = decide(src);
    assert!(matches!(d, Decision::Ask(_)), "{d:?}");
    assert!(reason(&d).contains("parse_failure"), "{}", reason(&d));
}

#[test]
fn a_here_document_with_a_declared_consumer_is_judged_by_both_paths() {
    let d = decide(&format!("python - <<EOF\n$({RM})\nEOF\n"));
    let r = reason(&d);
    assert!(r.contains("delete_recursive"), "{r}");
    // `realistic_config()` sets `lang.python.constructs.evaluated_input =
    // "allow"`, so the held-input path's own refusal of an expanding body
    // never turns into a competing ASK here — only the guard's does. What
    // this second assertion pins is the underlying FACT the held-input path
    // acts on: the heredoc is unquoted (`quoted_delimiter` is false), so
    // `delivers_verbatim` refuses it and neither path silently stands the
    // other's judgement down.
    let s = vouch::shell::Bash.scan(&format!("python - <<EOF\n$({RM})\nEOF\n")).unwrap();
    assert!(s.heredocs.iter().any(|h| !h.quoted_delimiter));
}

#[test]
fn a_function_definitions_own_redirect_list_is_walked() {
    asks_on_the_guard(&format!("f() {{ :; }} > $({RM})"));
    let d = decide("f() { :; } > C:/Windows/x");
    assert!(matches!(d, Decision::Ask(_)) || matches!(d, Decision::Deny(_)), "{d:?}");
    assert!(reason(&d).contains("C:/Windows/x"), "{}", reason(&d));
}

// ---------------------------------------------------------------------------
// Task 4: the for-clause value list, the case subject and patterns, the
// extended-test operands, and the two arithmetic arms (design §2.2's
// remaining rows).
// ---------------------------------------------------------------------------

#[test]
fn a_guard_inside_a_substitution_fires_from_the_compound_positions() {
    asks_on_the_guard(&format!("for x in $({RM}); do :; done"));
    asks_on_the_guard(&format!("case $({RM}) in a) echo;; esac"));
    asks_on_the_guard(&format!("case x in $({RM})) echo;; esac"));
    asks_on_the_guard(&format!("[[ $({RM}) ]] && echo hi"));
    asks_on_the_guard(&format!("[[ ! $({RM}) ]]"));
    asks_on_the_guard(&format!("[[ a || $({RM}) ]]"));
    asks_on_the_guard(&format!("[[ ( $({RM}) ) ]]"));
    asks_on_the_guard(&format!("f() for x in $({RM}); do :; done"));
}

#[test]
fn arithmetic_walks_its_substitution_instead_of_refusing_it() {
    for cmd in [format!("(( x = $({RM}) ))"), format!("for ((i=$({RM}); i<1; i++)); do :; done")] {
        let d = decide(&cmd);
        assert!(reason(&d).contains("delete_recursive"), "{cmd}: {}", reason(&d));
        assert!(!reason(&d).contains("parse_failure"), "{cmd}: {}", reason(&d));
    }
    assert!(matches!(decide("(( i=1 ))"), Decision::Allow(_)));
    assert!(reason(&decide("(( ))")).contains("parse_failure"));
}

#[test]
fn select_is_covered_by_whole_line_parse_failure_today() {
    // brush 0.4.0 reserves the word and parses no clause for it, so the
    // WHOLE LINE fails to parse — `Bash.scan` returns `Err`, not an
    // `Ok(Parsed)` carrying a noted construct — and it is the engine's own
    // scanner-error channel (`src/engine.rs`'s `Err(e)` arm) that turns that
    // into an ask naming `lang.bash.constructs.parse_failure`, the same
    // channel `tests/shell_test.rs`'s
    // `a_parse_failure_is_an_error_not_a_silent_empty_result` pins for an
    // unterminated `for`. `constructs()` cannot observe this case — it
    // unwraps the `Ok` a whole-line failure never produces — so this is
    // proved at the `decide` layer instead. Pinned so a future brush that
    // parses `select` cannot open its value list silently.
    assert!(Bash.scan("select x in a; do :; done").is_err());
    let d = decide("select x in a; do :; done");
    assert!(matches!(d, Decision::Ask(_)), "{d:?}");
    assert!(reason(&d).contains("parse_failure"));
}

#[test]
fn the_extended_test_mints_one_anchor() {
    let s = vouch::shell::Bash.scan(&format!("[[ $({RM}) ]] > a.txt > b.txt")).unwrap();
    // `scan_scopes.len() == 1` alone would hold whether or not the fix
    // landed — there is only one substitution in this line to allocate a
    // scope for, whatever position it gets minted at. The real claim is that
    // BOTH redirects and the operand's own substitution body share the
    // identical `Order`, which is what a single, unconditionally-minted
    // anchor means: moving `own_order` back inside the redirect loop mints
    // `Seq(n)` and `Seq(n+1)` instead of `Seq(n)` twice, and that is what
    // this pins.
    assert_eq!(s.redirect_order.len(), 2, "two redirect targets");
    let n = match s.redirect_order[0] {
        Order::Seq(n) => n,
        Order::Unordered => panic!("a redirect on a top-level [[ ]] must be provable: {:?}", s.redirect_order),
    };
    assert_eq!(s.redirect_order, vec![Order::Seq(n), Order::Seq(n)], "both redirects share one position");
    assert_eq!(s.scan_scopes.len(), 1, "exactly one substitution body");
    assert_eq!(s.scan_scopes[0].anchor_order, Order::Seq(n), "the operand's body anchors at the same position");
}

#[test]
fn ansi_c_quoting_keeps_its_escaped_quote_inside_the_quote() {
    let raw = "$(foo $'\\''$(bar)$'\\'')";
    let read = substitution_bodies(raw);
    assert!(!read.unreadable, "{read:?}");
    assert_eq!(read.bodies, vec!["foo $'\\''$(bar)$'\\''"]);
    // Plain single quotes still take no escape: the backslash is literal and
    // the quote closes at the next quote character.
    assert_eq!(bodies("$(echo '\\')"), vec!["echo '\\'"]);
    // An ANSI-C quoted close paren does not close the substitution.
    assert_eq!(bodies("$(echo $')' ; echo TAIL)"), vec!["echo $')' ; echo TAIL"]);
    // Inside a body, a substitution written inside ANSI-C quotes is literal.
    assert!(bodies("$'$(x)'").is_empty());
}
