//! Brace expansion in the bash scanner (spec 2026-08-20 §9.3).
//!
//! The defect these pin: bash rewrites `rm -{r,f} d` into `rm -r -f d` before
//! `rm` runs, and the scanner recorded the token as it was written — so a guard
//! rule looking for `-r` saw nothing and the row allowed clean, while the plain
//! spelling asked. Reading the token is therefore not optional; the only
//! question is whether vouch can reproduce the rewrite exactly.
//!
//! Every classification asserted here was checked against bash 5.2 first, and
//! the tests are written so a wrong answer in EITHER direction fails: a shape
//! vouch reproduces must produce the shell's own words, and a shape it does
//! not reproduce must say so out loud rather than record a literal token.

mod common;

use vouch::engine::decide_command_in;
use vouch::protocol::Decision;
use vouch::shell::{expand_braces, Braces};
use vouch::syntax::Scanner;

const HOME: &str = "C:/Users/dev";

/// The standing replay configuration: guards ask, an undescribed program does
/// not. A construct nobody configured — `brace_expansion` among them — asks.
fn decide(cmd: &str) -> Decision {
    decide_command_in(&common::realistic_config(), "bash", cmd, Some(HOME), None)
}

/// The same, with an undescribed program asking — the operator's own shape,
/// and the only one under which recognising a head can be seen to move a row.
fn decide_unmodeled_asks(cmd: &str) -> Decision {
    let cfg = vouch::config::load(&common::config_text_with(&[(
        "bash",
        "unmodeled_command",
        "ask",
    )]))
    .expect("the shared config text parses");
    decide_command_in(&cfg, "bash", cmd, Some(HOME), None)
}

/// The head and arguments the scanner recorded for the first command.
fn first(src: &str) -> (String, Vec<String>) {
    let s = vouch::shell::Bash.scan(src).expect("scans");
    let c = s.commands.first().expect("one command").clone();
    (c.head, c.args)
}

/// Every construct the scan raised.
fn constructs(src: &str) -> Vec<String> {
    vouch::shell::Bash.scan(src).expect("scans").constructs
}

fn reason(d: &Decision) -> String {
    match d {
        Decision::Ask(r) | Decision::Allow(r) | Decision::Deny(r) => r.clone(),
        Decision::Abstain => String::new(),
    }
}

// ---------------------------------------------------------------------------
// The defect itself
// ---------------------------------------------------------------------------

#[test]
fn a_brace_spelled_delete_trips_the_guard() {
    // The probe pair from the roadmap row: the two spellings are the same
    // command to the shell, so they must be the same verdict to vouch. The
    // target sits inside the allowed write area on purpose — otherwise the
    // path rule asks for both spellings and hides which one the GUARD saw.
    let plain = decide("rm -r -f C:/work/d");
    let braced = decide("rm -{r,f} C:/work/d");
    assert!(matches!(plain, Decision::Ask(_)), "the plain spelling stopped asking: {plain:?}");
    assert!(
        reason(&plain).contains("delete_recursive"),
        "the plain spelling asked for some other reason: {}",
        reason(&plain)
    );
    assert!(
        matches!(braced, Decision::Ask(_)),
        "the brace spelling did not ask: {braced:?}"
    );
    assert!(
        reason(&braced).contains("delete_recursive"),
        "the brace spelling asked for some other reason: {}",
        reason(&braced)
    );
}

// ---------------------------------------------------------------------------
// What expands, and into exactly what
// ---------------------------------------------------------------------------

#[test]
fn expansion_distributes_prefix_and_suffix() {
    // bash: a{b,c}d -> abd acd
    let (head, args) = first("echo a{b,c}d");
    assert_eq!(head, "echo");
    assert_eq!(args, vec!["abd".to_string(), "acd".to_string()]);
    assert!(!constructs("echo a{b,c}d").iter().any(|c| c == "brace_expansion"));
}

#[test]
fn an_empty_alternative_expands_with_surviving_affix() {
    // bash: x{a,} -> xa x. The empty alternative leaves a real word because
    // the prefix survives.
    let (_, args) = first("echo x{a,}");
    assert_eq!(args, vec!["xa".to_string(), "x".to_string()]);
    // bash: {a,}b -> ab b. The suffix serves the same purpose.
    let (_, args) = first("echo {a,}b");
    assert_eq!(args, vec!["ab".to_string(), "b".to_string()]);
    // Bare {a,} leaves an empty word, which bash then drops — a word count
    // vouch would get wrong, so it refuses to guess and says so.
    assert!(
        constructs("echo {a,}").iter().any(|c| c == "brace_expansion"),
        "a bare empty alternative was reproduced rather than reported"
    );
}

#[test]
fn a_brace_head_expands_or_asks_never_slips() {
    // bash: {echo,hi} runs `echo hi`. The head is a word like any other, so a
    // simple list there becomes real words rather than a literal head nobody
    // can recognise.
    let (head, args) = first("{echo,hi}");
    assert_eq!(head, "echo", "the head was left as a literal brace token");
    assert_eq!(args, vec!["hi".to_string()]);
    // A head-position group vouch does NOT reproduce must still be reported:
    // a cross product in head position names two programs, neither of them
    // the literal token.
    assert!(
        constructs("{echo,ls}{1,2}").iter().any(|c| c == "brace_expansion"),
        "an unreproducible head group was recorded silently"
    );
    // A range in head position is the same case.
    assert!(
        constructs("prog{1..3}").iter().any(|c| c == "brace_expansion"),
        "a range in head position was recorded silently"
    );
}

#[test]
fn head_expansion_puts_its_extra_words_before_the_rest() {
    // The words a head group produces are earlier on the line than anything in
    // the suffix, and the recorded order has to say so — an argument walk reads
    // positions.
    let (head, args) = first("{echo,one} two");
    assert_eq!(head, "echo");
    assert_eq!(args, vec!["one".to_string(), "two".to_string()]);
    // A prefix assignment sits between the head and the arguments in the
    // walk, and contributes no argument of its own — so the order holds.
    let (head, args) = first("FOO=1 {echo,one} two");
    assert_eq!(head, "echo");
    assert_eq!(args, vec!["one".to_string(), "two".to_string()]);
}

#[test]
fn a_suffix_assignment_shaped_word_expands() {
    // bash: `of={a,b}` after a command name is an ARGUMENT, and it expands.
    let (head, args) = first("dd of={a,b}");
    assert_eq!(head, "dd");
    assert_eq!(args, vec!["of=a".to_string(), "of=b".to_string()]);
}

// ---------------------------------------------------------------------------
// What stays quiet
// ---------------------------------------------------------------------------

#[test]
fn commaless_and_parameter_braces_stay_quiet() {
    for src in ["echo {a}", "echo {}", "echo {a-b}", "find . -exec echo {} \\;", "echo ${X}/y"] {
        assert!(
            !constructs(src).iter().any(|c| c == "brace_expansion"),
            "a literal brace raised the construct: {src}"
        );
    }
    // The placeholder really is passed through untouched, not just unreported.
    let (_, args) = first("echo {}");
    assert_eq!(args, vec!["{}".to_string()]);
    let d = decide("find . -exec echo {} \\;");
    assert!(matches!(d, Decision::Allow(_)), "the placeholder shape stopped allowing: {d:?}");
}

#[test]
fn quoted_braces_are_literal_and_quiet() {
    // bash passes `-{r,f}` through as one literal token when it is quoted, so
    // there is nothing hidden and nothing to ask about — and no guard fires,
    // because no `-r` reaches rm.
    for src in [r#"rm "-{r,f}" d"#, "rm '-{r,f}' d"] {
        assert!(
            !constructs(src).iter().any(|c| c == "brace_expansion"),
            "a quoted brace raised the construct: {src}"
        );
        let (_, args) = first(src);
        assert_eq!(args.len(), 2, "a quoted brace was split: {src}");
    }
}

#[test]
fn a_prefix_assignment_value_is_never_expanded() {
    // bash does not brace-expand a prefix assignment's value (probed:
    // FOO={a,b} leaves FOO set to the literal `{a,b}`), so vouch must not
    // either — the recorded value is what later resolution reads.
    let s = vouch::shell::Bash.scan("FOO={a,b} echo hi").expect("scans");
    assert_eq!(
        s.assignments,
        vec![("FOO".to_string(), Some("{a,b}".to_string()))],
        "a prefix assignment's value was rewritten"
    );
    assert!(
        !s.constructs.iter().any(|c| c == "brace_expansion"),
        "a prefix assignment raised the construct, though bash expands nothing there"
    );
}

#[test]
fn a_redirect_target_is_never_expanded_but_is_never_silent() {
    // A multi-word redirect IS a shell error, so the target is never expanded
    // — the recorded token stays exactly as written.
    let s = vouch::shell::Bash.scan("echo x > f{1,2}.txt").expect("scans");
    assert_eq!(s.redirect_targets, vec!["f{1,2}.txt".to_string()]);
    assert!(
        s.constructs.iter().any(|c| c == "brace_expansion"),
        "a braced redirect target was recorded silently"
    );
}

#[test]
fn a_single_word_collapse_redirect_target_asks() {
    // The case that disproved the first draft's "nothing can hide here"
    // rationale: a group collapsing to ONE word redirects fine. Probed —
    // `echo x > f{7..7}.txt` wrote `f7.txt`, and `echo y > {a,}` wrote `a`.
    // The recorded target is therefore not the path written, and that path
    // feeds the write rules.
    //
    // Only the first source below collapses to one word. The other two expand
    // to several, and they belong here for the SAME reason rather than that
    // one: whatever the group does, the word vouch recorded is not the path
    // bash writes, so the construct has to fire on all three.
    //
    // Targets sit inside the allowed write area on purpose: otherwise the path
    // rule holds the one recorded reason slot and hides which stop is under
    // test.
    for src in
        ["echo x > C:/work/f{7..7}.txt", "echo y > C:/work/{a,}", "echo z > C:/work/d{1..3}/o.txt"]
    {
        let s = vouch::shell::Bash.scan(src).expect("scans");
        assert!(
            s.constructs.iter().any(|c| c == "brace_expansion"),
            "a braced redirect target was recorded silently: {src}"
        );
        assert_eq!(s.redirect_targets.len(), 1, "a redirect target was expanded: {src}");
        let d = decide(src);
        assert!(matches!(d, Decision::Ask(_)), "a braced target did not ask: {src} → {d:?}");
        assert!(
            reason(&d).contains("brace_expansion"),
            "the prompt did not name the construct: {}",
            reason(&d)
        );
    }
}

#[test]
fn a_plain_redirect_target_stays_quiet() {
    for src in ["echo x > C:/work/plain.txt", "echo x >> C:/work/plain.txt", "wc -l < C:/work/f"] {
        assert!(
            !vouch::shell::Bash
                .scan(src)
                .expect("scans")
                .constructs
                .iter()
                .any(|c| c == "brace_expansion"),
            "a plain redirect target raised the construct: {src}"
        );
    }
    let d = decide("echo x > C:/work/plain.txt");
    assert!(matches!(d, Decision::Allow(_)), "a plain redirect stopped allowing: {d:?}");
}

#[test]
fn a_group_inside_a_command_substitution_belongs_to_the_inner_command() {
    // Probed: bash hands `x$(echo {a,b})` to the program as the two words `xa`
    // and `b` — the group expands inside the command the substitution RUNS,
    // and its output is then word-split. Expanding it as a group of the OUTER
    // word would record `x$(echo a)` and `x$(echo b)`, which the shell never
    // passes, and record them silently.
    for src in ["echo x$(echo {a,b})", "echo x`echo {a,b}`"] {
        let s = vouch::shell::Bash.scan(src).expect("scans");
        assert_eq!(s.commands[0].args.len(), 1, "an inner group was expanded outward: {src}");
        assert!(
            !s.constructs.iter().any(|c| c == "brace_expansion"),
            "an inner group raised the outer word's construct: {src}"
        );
    }
    // The classifier's own view of the same two shapes.
    assert_eq!(expand_braces("x$(echo {a,b})"), Braces::Literal);
    assert_eq!(expand_braces("x`echo {a,b}`"), Braces::Literal);
}

#[test]
fn a_group_outside_a_command_substitution_still_classifies() {
    // The adjacent case, and it must NOT be swallowed by the fix above:
    // probed, `$(echo z){a,b}` really is a two-word expansion (`za zb`), and
    // the expansion is textual, so the recorded words carry the substitution
    // through unchanged.
    let words = |v: &[&str]| Braces::Words(v.iter().map(|s| s.to_string()).collect());
    assert_eq!(expand_braces("$(echo z){a,b}"), words(&["$(echo z)a", "$(echo z)b"]));
    assert_eq!(expand_braces("`echo z`{a,b}"), words(&["`echo z`a", "`echo z`b"]));
    let (_, args) = first("echo $(echo z){a,b}");
    assert_eq!(args, vec!["$(echo z)a".to_string(), "$(echo z)b".to_string()]);
    // A group outside the substitution that vouch does NOT reproduce still
    // raises, rather than being lost with the skipped span.
    assert!(
        constructs("echo $(echo z){1..3}").iter().any(|c| c == "brace_expansion"),
        "a range outside a substitution was recorded silently"
    );
}

// ---------------------------------------------------------------------------
// What asks, and names its own setting
// ---------------------------------------------------------------------------

#[test]
fn a_range_asks_naming_the_construct() {
    // A range carries no comma and bash rewrites it anyway. Leaving it literal
    // is the exact blindness this closes. The target sits inside the allowed
    // write area so that the path rule does not hold the one recorded reason
    // slot and hide the two stops under test.
    let guarded = "rm -r C:/work/d{1..3}";
    let d = decide(guarded);
    assert!(matches!(d, Decision::Ask(_)), "a range did not ask: {d:?}");
    let r = reason(&d);
    assert!(
        constructs(guarded).iter().any(|c| c == "brace_expansion"),
        "a range raised no construct"
    );
    // Criterion 2: a prompt names the setting that turns it off.
    let quiet = decide("echo {1..3}");
    let qr = reason(&quiet);
    assert!(matches!(quiet, Decision::Ask(_)), "a range on a quiet head did not ask: {quiet:?}");
    assert!(
        qr.contains("brace_expansion") && qr.contains("lang.bash.constructs.brace_expansion"),
        "the prompt did not name the construct and its setting: {qr}"
    );
    // The guarded row stops on BOTH, and each has to be provable. The engine
    // records ONE reason first-line, and at equal rank the guard holds the
    // slot — so the guarded row's prompt names `delete_recursive`, and the
    // construct is proved by taking the guard out of the way rather than by
    // expecting two reasons in one line.
    assert!(
        r.contains("delete_recursive"),
        "the guarded row's prompt did not name the guard: {r}"
    );
    let mut relaxed = common::realistic_config();
    relaxed.guards.insert("delete_recursive".to_string(), vouch::config::Action::Allow);
    let without_the_guard = decide_command_in(&relaxed, "bash", guarded, Some(HOME), None);
    let wr = reason(&without_the_guard);
    assert!(
        matches!(without_the_guard, Decision::Ask(_)),
        "with the guard allowed the range stopped asking: {without_the_guard:?}"
    );
    assert!(
        wr.contains("brace_expansion") && wr.contains("lang.bash.constructs.brace_expansion"),
        "the same row's remaining stop is not the construct and its setting: {wr}"
    );
}

#[test]
fn a_nested_group_asks() {
    assert!(
        constructs("rm -{r,{f,x}} d").iter().any(|c| c == "brace_expansion"),
        "a nested group was reproduced rather than reported"
    );
}

#[test]
fn quote_or_escape_carrying_alternatives_ask() {
    // bash splits quote- and escape-aware: {a,"b,c"} is two alternatives and
    // {a\,b,c} is two as well. vouch does not reimplement that, so it says so.
    for src in [r#"echo {a,"b,c"}"#, r"echo {a\,b,c}", "echo {a,'b,c'}"] {
        assert!(
            constructs(src).iter().any(|c| c == "brace_expansion"),
            "a quote- or escape-carrying group was reproduced: {src}"
        );
    }
}

#[test]
fn multiple_groups_in_one_token_ask() {
    // The cross product is not attempted.
    assert!(
        constructs("echo {a,b}{c,d}").iter().any(|c| c == "brace_expansion"),
        "a cross product was reproduced rather than reported"
    );
}

#[test]
fn a_dollar_carrying_group_asks() {
    assert!(
        constructs("echo {$X,b}").iter().any(|c| c == "brace_expansion"),
        "an expansion-carrying alternative was reproduced"
    );
    assert!(
        constructs("echo {`id`,b}").iter().any(|c| c == "brace_expansion"),
        "a backquote-carrying alternative was reproduced"
    );
}

// ---------------------------------------------------------------------------
// The other direction: expansion can make a row RECOGNISED
// ---------------------------------------------------------------------------

#[test]
fn a_brace_spelled_head_becomes_a_recognised_command() {
    // Under the operator's own shape, an undescribed program asks. A head left
    // as the literal token `{echo,hi}` is undescribed by construction; expanded,
    // it is a program vouch knows.
    let d = decide_unmodeled_asks("{echo,hi}");
    assert!(
        matches!(d, Decision::Allow(_)),
        "a brace-spelled head stayed unrecognised: {d:?}"
    );
}

// ---------------------------------------------------------------------------
// The classifier on its own, where a scanner-level test cannot reach
// ---------------------------------------------------------------------------

#[test]
fn the_classifier_answers_the_shell_word_for_word() {
    // Each case is what bash 5.2 printed for the same text.
    let words = |v: &[&str]| Braces::Words(v.iter().map(|s| s.to_string()).collect());
    assert_eq!(expand_braces("a{b,c}d"), words(&["abd", "acd"]));
    assert_eq!(expand_braces("-{r,f}"), words(&["-r", "-f"]));
    assert_eq!(expand_braces("pre{a,b}suf"), words(&["preasuf", "prebsuf"]));
    assert_eq!(expand_braces("x{a,}"), words(&["xa", "x"]));
    // A literal group in the affix distributes as ordinary text, which is what
    // bash does too — one SUBJECT group is the rule, not one brace.
    assert_eq!(expand_braces("a{b,c}{}"), words(&["ab{}", "ac{}"]));
    // An escaped `$` is a literal dollar, not a parameter expansion, and bash
    // brace-expands the group after it (probed).
    assert_eq!(expand_braces(r"\${a,b}"), words(&[r"\$a", r"\$b"]));

    for literal in ["{a}", "{}", "{a-b}", "${X}/y", r#""-{r,f}""#, "'{a,b}'", "{a\\,b}", "plain"] {
        assert_eq!(expand_braces(literal), Braces::Literal, "not literal: {literal}");
    }
    for rewritten in ["{a..c}", "{1..10..2}", "{a,{b,c}}", "{a,b}{c,d}", "{a,}", "{,a}", "{a,b,}"] {
        assert_eq!(expand_braces(rewritten), Braces::Rewritten, "not reported: {rewritten}");
    }
    // An unterminated brace is ordinary text to the shell.
    assert_eq!(expand_braces("{a,b"), Braces::Literal);
}
