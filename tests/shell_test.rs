use vouch::shell::parse;
use vouch::syntax::{Order, Scanner};

fn orders(src: &str) -> (Vec<Order>, Vec<Order>) {
    let s = vouch::shell::Bash.scan(src).expect("scans");
    (s.order, s.redirect_order)
}

#[test]
fn top_level_sequencing_is_provable() {
    // `a && b ; c` — three commands, positions 0,1,2
    let (o, _) = orders("cd /x && echo hi ; ls");
    assert_eq!(o, vec![Order::Seq(0), Order::Seq(1), Order::Seq(2)]);
}

#[test]
fn an_or_branch_is_unordered_from_the_or_on() {
    let (o, _) = orders("cd /x || echo hi");
    assert_eq!(o[0], Order::Seq(0));
    assert_eq!(o[1], Order::Unordered);
}

#[test]
fn subshell_pipeline_background_and_compound_bodies_are_locally_sequenced() {
    // Renamed and re-pinned for the cd-scope-and-candidates plan's Task 2
    // (docs/specs/2026-08-30-cd-scope-and-candidate-design.md §3.1/§3.3): a
    // construct's own body now gets its own `ScanScope` and sequences
    // internally with a FRESH LOCAL `Order::Seq` counter, rather than being
    // pinned `Order::Unordered` as before this task. `cd` is still the
    // first (and only) command in each of these bodies, so it reads
    // `Seq(0)` — locally provable, just no longer comparable to positions
    // outside its own scope. `engine::collect_expanded` bridges that: it
    // still presents `Unordered` for any command whose `cmd_scope` isn't
    // `Some(0)`, so today's DECISION behavior is unchanged (see
    // `unorderable_cds_fail_closed` in bash_writes_test.rs) until Task 3
    // teaches the engine to read the scope table for real and removes the
    // bridge.
    for src in [
        "(cd /x); echo hi",
        "cd /x | cat",
        "cd /x & echo hi",
        "if true; then cd /x; fi; echo hi",
        "for i in 1; do cd /x; done; echo hi",
    ] {
        let (o, _) = orders(src);
        let cd = o
            .iter()
            .zip(vouch::shell::Bash.scan(src).unwrap().commands)
            .find(|(_, c)| c.head == "cd")
            .map(|(o, _)| o.clone());
        assert_eq!(cd, Some(Order::Seq(0)), "cd not locally sequenced in: {src}");
    }
}

#[test]
fn redirects_carry_their_commands_order() {
    let (_, ro) = orders("echo x > f.txt && cd /y");
    assert_eq!(ro, vec![Order::Seq(0)]);
    // Re-pinned for the cd-scope-and-candidates plan's Task 2: a subshell
    // body now sequences internally with a fresh LOCAL `Order::Seq` rather
    // than being pinned `Order::Unordered` — the redirect still carries its
    // own command's order, which is now the local one.
    let (_, ro) = orders("(echo x > f.txt)");
    assert_eq!(ro, vec![Order::Seq(0)]);
    // Review finding IMPORTANT 2, M2.221: the redirect's scope must
    // be carried alongside its order, or a value-only order comparison at the
    // engine boundary cannot tell this LOCAL `Seq(0)` apart from a top-level
    // `Seq(0)` on the same line. Scope 0 is the top level; the subshell body
    // is the first allocated child scope, so its own redirect reads scope 1.
    let s = vouch::shell::Bash.scan("(echo x > f.txt)").expect("scans");
    assert_eq!(s.redirect_scope, vec![Some(1)]);
}

#[test]
fn the_four_redirect_channels_stay_in_lockstep() {
    // M2.229/M2.221. `redirect_targets`, `redirect_order`, `redirect_scope`
    // and `redirect_chain` are read positionally against each other, so a
    // push site that extends three of them and not the fourth silently
    // shortens a channel — which is how the wrapper-injected redirect gap
    // (M2.221, IMPORTANT 2) reached a review instead of a test. Asserted over
    // every shape this file exercises rather than over one, because the four
    // pushes are spread across three arms of `walk_redirect` plus PowerShell.
    for src in [
        "echo x > f.txt",
        "echo x >> f.txt",
        "echo x >& both.txt",
        "echo x > a.txt 2> b.txt",
        "(echo x > f.txt)",
        "{ :; } > f.txt",
        "cd /x && for f in 1; do :; done > rel.txt",
        "cd /x || echo hi > f.txt",
        "[[ -f a ]] > f.txt",
        "bash -c 'echo x > inner.txt' > outer.txt",
        "wc -l < in.txt > out.txt",
    ] {
        let s = vouch::shell::Bash.scan(src).expect("scans");
        let n = s.redirect_targets.len();
        assert_eq!(s.redirect_order.len(), n, "order channel short for {src:?}");
        assert_eq!(s.redirect_scope.len(), n, "scope channel short for {src:?}");
        assert_eq!(s.redirect_chain.len(), n, "chain channel short for {src:?}");
    }
    let s = vouch::powershell::PowerShell
        .scan("Set-Location C:/x; Write-Output hi > f.txt")
        .expect("scans");
    let n = s.redirect_targets.len();
    assert_eq!(s.redirect_order.len(), n);
    assert_eq!(s.redirect_scope.len(), n);
    assert_eq!(s.redirect_chain.len(), n);
}

#[test]
fn an_or_tail_redirect_carries_its_own_chain() {
    // M2.229. The chain is what lets the engine place a redirect whose owner
    // it cannot find — without it an `&&`-proven mover is never certified for
    // that position. Pinned at the scanner so the channel cannot quietly
    // start recording `None` for every redirect and still pass the engine
    // tests by falling back to the same answer for a different reason.
    let s = vouch::shell::Bash
        .scan("cd /etc || true && echo x > f.txt")
        .expect("scans");
    assert_eq!(s.redirect_targets.len(), 1);
    assert!(
        s.redirect_chain[0].is_some(),
        "a chained redirect records its chain: {:?}",
        s.redirect_chain
    );
    // A lone statement is not a chain member, and says so.
    let s = vouch::shell::Bash.scan("echo x > f.txt").expect("scans");
    assert_eq!(s.redirect_chain, vec![None]);
}

#[test]
fn a_compound_redirect_carries_the_compounds_own_anchor_order() {
    // M2.226. The 2026-08-30 design §3.3 says a redirection attached to a
    // compound is "opened once, at the compound's anchor, in the parent's
    // scope". The scope half shipped; the position half was recorded
    // `Order::Unordered` although the walk had just computed the anchor.
    //
    // The construct is the first (and only) statement, so its own position in
    // the parent scope is `Seq(0)`, and the parent scope is 0 — the body's
    // fresh scope is 1 and the redirect must not be in it.
    let s = vouch::shell::Bash.scan("{ :; } > f.txt").expect("scans");
    assert_eq!(s.redirect_order, vec![Order::Seq(0)]);
    assert_eq!(s.redirect_scope, vec![Some(0)]);

    // A loop is the same shape and the design's own example spelling.
    let s = vouch::shell::Bash
        .scan("cd /x ; for f in 1; do :; done > rel.txt")
        .expect("scans");
    assert_eq!(s.redirect_order, vec![Order::Seq(1)]);
    assert_eq!(s.redirect_scope, vec![Some(0)]);

    // The extended-test arm of the same walk already passed a real order;
    // pinned here so the two compound-shaped arms cannot drift apart again.
    let s = vouch::shell::Bash.scan("[[ -f a ]] > f.txt").expect("scans");
    assert_eq!(s.redirect_order, vec![Order::Seq(0)]);
}

#[test]
fn finds_command_heads() {
    let p = parse("ls -la /c/workspace && git status").unwrap();
    assert!(p.heads.contains(&"ls".to_string()), "heads: {:?}", p.heads);
    assert!(p.heads.contains(&"git".to_string()), "heads: {:?}", p.heads);
}

#[test]
fn finds_redirect_targets() {
    let p = parse("echo hi > /tmp/out.txt").unwrap();
    assert!(
        p.redirect_targets.iter().any(|t| t.contains("out.txt")),
        "targets: {:?}",
        p.redirect_targets
    );
}

#[test]
fn names_a_dynamic_command_construct() {
    let p = parse(r#"PY="/usr/bin/python"; "$PY" script.py"#).unwrap();
    assert!(
        p.constructs.contains(&"dynamic_command".to_string()),
        "constructs: {:?}",
        p.constructs
    );
}

#[test]
fn names_a_dynamic_redirect_construct() {
    let p = parse(r#"OUT=/tmp/x; echo hi > "$OUT""#).unwrap();
    assert!(
        p.constructs.contains(&"dynamic_redirect".to_string()),
        "constructs: {:?}",
        p.constructs
    );
}

#[test]
fn a_plain_command_reports_no_constructs() {
    let p = parse("git status --short").unwrap();
    assert!(p.constructs.is_empty(), "constructs: {:?}", p.constructs);
}

#[test]
fn a_parse_failure_is_an_error_not_a_silent_empty_result() {
    let r = parse("for x in ; do");
    assert!(
        r.is_err(),
        "unterminated input must be an error, not an empty Parsed"
    );
}

#[test]
fn finds_heads_inside_a_pipeline() {
    let p = parse("cat x.txt | grep foo | wc -l").unwrap();
    for want in ["cat", "grep", "wc"] {
        assert!(p.heads.contains(&want.to_string()), "heads: {:?}", p.heads);
    }
}

#[test]
fn finds_heads_inside_a_for_loop_body() {
    // Loops were an explicit requirement: the body must be inspected, not skipped.
    let p = parse("for f in a b c; do rm -rf \"$f\"; done").unwrap();
    assert!(p.heads.contains(&"rm".to_string()), "heads: {:?}", p.heads);
}

#[test]
fn detects_a_function_definition() {
    let p = parse("check() { echo hi; }").unwrap();
    assert!(
        p.constructs.contains(&"function_def".to_string()),
        "constructs: {:?}",
        p.constructs
    );
}

#[test]
fn detects_a_heredoc() {
    // Re-decided: a heredoc attached to a landing command (`cat` here) is
    // now CAPTURED rather than merely noted — the construct note is reserved
    // for a heredoc with no consuming command to tie the capture to.
    let p = parse("cat > /tmp/f <<'EOF'\nhello\nEOF\n").unwrap();
    assert_eq!(p.heredocs.len(), 1, "heredocs: {:?}", p.heredocs);
    assert_eq!(p.commands[p.heredocs[0].cmd_index].head, "cat");
    assert!(
        !p.constructs.contains(&"heredoc".to_string()),
        "constructs: {:?}",
        p.constructs
    );
}

#[test]
fn a_heredoc_body_and_its_consumer_are_captured() {
    let p = parse("python - <<'EOF'\nimport os\nEOF\n").unwrap();
    assert_eq!(p.heredocs.len(), 1);
    assert!(p.heredocs[0].quoted_delimiter);
    assert_eq!(p.heredocs[0].body.trim(), "import os");
    assert_eq!(p.commands[p.heredocs[0].cmd_index].head, "python");
}

#[test]
fn an_unquoted_delimiter_is_recorded_as_such() {
    let p = parse("python - <<EOF\nimport os\nEOF\n").unwrap();
    assert!(!p.heredocs[0].quoted_delimiter);
}

/// The index of the command whose head is `head` — one lookup, and one panic
/// message, for every test here that needs a specific occurrence.
fn index_of(p: &vouch::syntax::Scan, head: &str) -> usize {
    p.commands
        .iter()
        .position(|c| c.head == head)
        .unwrap_or_else(|| panic!("no command {head} among {:?}", p.heads))
}

/// The resolved input source of the command whose head is `head`.
fn source_of(src: &str, head: &str) -> vouch::syntax::InputSource {
    let p = parse(src).unwrap_or_else(|e| panic!("{src:?} does not parse: {e}"));
    p.input_source[index_of(&p, head)].clone()
}

// What supplies standard input, per command. Every competing redirect is
// spelled on the consumer's own line, before the body: a redirect written after
// the terminator line belongs to a different command entirely.
#[test]
fn the_input_source_names_what_supplies_standard_input() {
    use vouch::syntax::HeredocId;
    use vouch::syntax::InputSource::*;
    // A consumed here-document, by the record's own identity — `HeredocId(0)`
    // because this is the first (and only) id this fresh scan allocated.
    let p = parse("python - <<'EOF'\nprint(1)\nEOF\n").unwrap();
    assert_eq!(p.input_source[0], Heredoc(HeredocId(0)));
    assert_eq!(p.heredocs[0].fd, 0, "the record carries its resolved descriptor");
    // Filename redirects, decided by RESOLVED descriptor, not by read/write shape.
    assert_eq!(source_of("python - < f.txt", "python"), File);
    assert_eq!(source_of("python - 0< f.txt", "python"), File);
    assert_eq!(source_of("python - <> f.txt", "python"), File);
    assert_eq!(source_of("python - 0> f.txt", "python"), File, "fd 0 by digit, write-shaped");
    // Redirects that do not touch descriptor 0 leave the value alone.
    assert_eq!(source_of("python - > out.txt", "python"), Nothing);
    assert_eq!(source_of("python - 2> err.txt", "python"), Nothing);
    assert_eq!(source_of("python - > >(cat)", "python"), Nothing);
    // Streams.
    assert_eq!(source_of("python - < <(cat f.txt)", "python"), Stream);
    assert_eq!(source_of("python - 0<&3", "python"), Stream);
    assert_eq!(source_of("python - 0<&-", "python"), Stream);
    assert_eq!(source_of("python - <<< word", "python"), Stream, "a here-string has no record");
    // The last redirect resolving to descriptor 0 decides, in both orders.
    assert_eq!(source_of("python - <<'EOF' < f.txt\nx\nEOF\n", "python"), File);
    assert_eq!(
        source_of("python - < f.txt <<'EOF'\nx\nEOF\n", "python"),
        Heredoc(HeredocId(0))
    );
    // Spellings aimed elsewhere supply no input.
    let p = parse("python - 3<<'EOF'\nx\nEOF\n").unwrap();
    assert_ne!(p.input_source[0], Heredoc(HeredocId(0)), "fd 3 does not feed standard input");
    assert_eq!(p.heredocs[0].fd, 3, "but the record exists and carries its descriptor");
    assert_eq!(source_of("python - 3<<< word", "python"), Nothing);
    // Pipelines: both members named.
    assert_eq!(source_of("cat f.txt | python -", "cat"), Nothing);
    assert_eq!(source_of("cat f.txt | python -", "python"), Pipe);
}

// An argument-position process substitution pushes no token, so the recorded
// argument list is not a faithful record of what the shell will pass.
#[test]
fn an_argument_position_substitution_marks_the_argument_list_incomplete() {
    let p = parse("python <(cat f.py) <<'EOF'\nx\nEOF\n").unwrap();
    let i = index_of(&p, "python");
    assert!(p.commands[i].args.is_empty(), "the substitution pushed no token");
    assert!(!p.args_complete[i], "so the command is marked incomplete");
    // A plain argument leaves it complete.
    let p = parse("python script.py").unwrap();
    assert!(p.args_complete[0]);
}

// Input arriving from an enclosing construct is Unknown, never Nothing — a
// value the design calls factual must not be asserted where nothing looked.
#[test]
fn input_inherited_from_an_enclosing_construct_is_unknown() {
    use vouch::syntax::InputSource::*;
    assert_eq!(source_of("{ python -; } < f.txt", "python"), Unknown);
    assert_eq!(source_of("cat f.txt | { python -; }", "python"), Unknown);
    assert_eq!(source_of("while read x; do python -; done < list.txt", "python"), Unknown);
    assert_eq!(source_of("f() { python -; }", "python"), Unknown);
    assert_eq!(source_of("coproc { python -; }", "python"), Unknown);
    // But an inner command's OWN source wins over the enclosing one.
    let p = parse("while read x; do python - <<'EOF'\nprint(1)\nEOF\n done < list.txt").unwrap();
    let i = index_of(&p, "python");
    assert!(matches!(p.input_source[i], Heredoc(_)), "got {:?}", p.input_source[i]);
    // …including inside a function definition.
    let p = parse("f() { python - <<'EOF'\nprint(1)\nEOF\n }").unwrap();
    let i = index_of(&p, "python");
    assert!(matches!(p.input_source[i], Heredoc(_)), "got {:?}", p.input_source[i]);
    // …and a pipeline member inside a redirected compound keeps its pipe.
    assert_eq!(
        source_of("while read x; do cat a | python -; done < list.txt", "python"),
        Pipe
    );
}

// The per-command arrays stay parallel to `commands` for every shape the bash
// scanner walks — a short array would attribute one command's input source to
// another, so the invariant is asserted rather than assumed.
#[test]
fn the_per_command_arrays_stay_parallel_to_commands() {
    for src in [
        "ls -la",
        "cat a.txt | grep x | wc -l",
        "cd /x && echo hi ; ls",
        "for f in a b; do rm \"$f\"; done",
        "python - <<'EOF'\nprint(1)\nEOF\n",
        "f() { python -; }",
        "{ python -; } < f.txt",
        "cat <(sh -c 'echo hi') > out.txt",
    ] {
        let p = parse(src).unwrap();
        assert_eq!(
            p.input_source.len(),
            p.commands.len(),
            "input_source not parallel to commands for: {src}"
        );
        assert_eq!(
            p.args_complete.len(),
            p.commands.len(),
            "args_complete not parallel to commands for: {src}"
        );
    }
}

/// The head of the command a heredoc record points at, found by a distinctive
/// fragment of its body — the only way to tell two records apart without
/// depending on capture order.
fn consumer_of(p: &vouch::syntax::Scan, body_fragment: &str) -> String {
    let h = p
        .heredocs
        .iter()
        .find(|h| h.body.contains(body_fragment))
        .unwrap_or_else(|| panic!("no record whose body holds {body_fragment:?}"));
    p.commands[h.cmd_index].head.clone()
}

// A process substitution on the same simple command pushes its inner
// command(s) into the list DURING the prefix/suffix walk, while the real
// command lands after it — an index captured before that walk therefore points
// at the substitution's inner command.
#[test]
fn a_heredoc_beside_a_process_substitution_points_at_its_real_consumer() {
    let p = parse("cat x.txt > >(sh) <<'EOF'\nhello\nEOF\n").unwrap();
    assert_eq!(p.heredocs.len(), 1, "one heredoc captured: {:?}", p.heredocs);
    assert_eq!(
        p.commands[p.heredocs[0].cmd_index].head, "cat",
        "the record must point at the consumer, not the substitution's inner command"
    );
}

// The aliasing trap: a heredoc INSIDE an argument-position substitution is
// pushed by the substitution's own walk, correctly stamped, and its index can
// EQUAL the outer command's prospective value — so a fix-up matching by index
// value clobbers it. Both records must keep their own consumers.
#[test]
fn an_inner_and_an_outer_heredoc_keep_their_own_consumers() {
    let p = parse("cat <(sh <<'A'\ninner\nA\n) <<'B'\nouter\nB\n").unwrap();
    assert_eq!(p.heredocs.len(), 2, "two heredocs captured: {:?}", p.heredocs);
    assert_eq!(consumer_of(&p, "inner"), "sh");
    assert_eq!(consumer_of(&p, "outer"), "cat");
}

// The redirect-target twin: here the inner command is pushed by a redirect
// walk, so per-redirect-call length tracking would claim its record as the
// outer command's. The bodies follow OPERATOR order, not layout — the
// tokenizer queues here-tags first in, first out — so `B` takes the first body
// and `A` the second, and the substitution closes on the consumer's own line.
#[test]
fn a_redirect_target_substitutions_heredoc_keeps_its_own_consumer() {
    let p = parse("cat <<'B' > >(sh <<'A')\nouter\nB\ninner\nA\n").unwrap();
    assert_eq!(p.heredocs.len(), 2, "two heredocs captured: {:?}", p.heredocs);
    assert_eq!(consumer_of(&p, "inner"), "sh");
    assert_eq!(consumer_of(&p, "outer"), "cat");
}

// ============================================================================
// ChainPos — a command's position in an `&&`/`||` and-or chain.
// ============================================================================

/// The exact three-member mixed chain the design pins: `a && b || c`.
/// `idx` runs 0,1,2; `and_run_from` stays at the chain's start across the
/// `&&` link and resets to the member's own `idx` at the `||`.
#[test]
fn a_mixed_and_or_chain_gets_the_pinned_chain_positions() {
    let p = parse("a && b || c").unwrap();
    let a = p.commands[index_of(&p, "a")].chain.expect("a is chained");
    let b = p.commands[index_of(&p, "b")].chain.expect("b is chained");
    let c = p.commands[index_of(&p, "c")].chain.expect("c is chained");
    assert_eq!((a.idx, a.and_run_from), (0, 0), "a");
    assert_eq!((b.idx, b.and_run_from), (1, 0), "b");
    assert_eq!((c.idx, c.and_run_from), (2, 2), "c");
    // All three belong to the SAME chain.
    assert_eq!(a.id, b.id);
    assert_eq!(b.id, c.id);
}

/// A longer chain: `&&` keeps carrying the same `and_run_from` forward across
/// more than one link, and a SECOND `||` resets it again from its own new
/// baseline rather than the very first member.
#[test]
fn and_run_from_carries_across_multiple_and_links_and_resets_on_each_or() {
    let p = parse("a && b && c || d && e").unwrap();
    let pos = |head: &str| p.commands[index_of(&p, head)].chain.expect("chained");
    let (a, b, c, d, e) = (pos("a"), pos("b"), pos("c"), pos("d"), pos("e"));
    assert_eq!((a.idx, a.and_run_from), (0, 0));
    assert_eq!((b.idx, b.and_run_from), (1, 0));
    assert_eq!((c.idx, c.and_run_from), (2, 0));
    assert_eq!((d.idx, d.and_run_from), (3, 3), "the || resets to d's own idx");
    assert_eq!((e.idx, e.and_run_from), (4, 3), "reachable from d via && only");
}

/// A plain `;`-separated statement is not part of any and-or chain —
/// `Cmd.chain` reads `None`, per its own doc.
#[test]
fn a_semicolon_separated_command_has_no_chain() {
    let p = parse("a; b").unwrap();
    assert_eq!(p.commands[index_of(&p, "a")].chain, None);
    assert_eq!(p.commands[index_of(&p, "b")].chain, None);
}

/// A bare pipeline with no `&&`/`||` link at all is not a chain either, even
/// though it has more than one member syntactically.
#[test]
fn a_bare_pipeline_with_no_and_or_link_has_no_chain() {
    let p = parse("a | b").unwrap();
    assert_eq!(p.commands[index_of(&p, "a")].chain, None);
    assert_eq!(p.commands[index_of(&p, "b")].chain, None);
}

/// Every piped stage of ONE and-or chain member shares that member's single
/// `ChainPos` — `idx` counts chain members, not `Cmd`s, so a two-stage pipe
/// on one side of an `&&` does not inflate the index the far side sees.
#[test]
fn every_piped_stage_of_one_member_shares_its_chain_position() {
    let p = parse("a | b && c").unwrap();
    let a = p.commands[index_of(&p, "a")].chain.expect("a is chained");
    let b = p.commands[index_of(&p, "b")].chain.expect("b is chained");
    let c = p.commands[index_of(&p, "c")].chain.expect("c is chained");
    assert_eq!(a, b, "both pipe stages are the SAME chain member");
    assert_eq!(a.idx, 0);
    assert_eq!((c.idx, c.and_run_from), (1, 0));
}

/// A chain nested inside a compound body gets its own `id`, distinct from an
/// unrelated chain elsewhere in the same line — so a later reader comparing
/// `id`s never mistakes two independent chains for the same one.
#[test]
fn nested_and_outer_chains_get_different_ids() {
    let p = parse("if x && y; then z && w; fi").unwrap();
    let outer = p.commands[index_of(&p, "x")].chain.expect("x is chained");
    let inner = p.commands[index_of(&p, "z")].chain.expect("z is chained");
    assert_ne!(outer.id, inner.id, "nested chain must not collide with the outer one");
}

// ============================================================================
// prefix_assigns — names assigned in a command's own PREFIX words.
// ============================================================================

#[test]
fn a_prefix_assignment_name_is_captured() {
    let p = parse("FOO=bar cmd args").unwrap();
    let cmd = &p.commands[index_of(&p, "cmd")];
    assert_eq!(cmd.prefix_assigns, vec!["FOO".to_string()]);
}

#[test]
fn multiple_prefix_assignments_are_all_captured_in_order() {
    let p = parse("A=1 B=2 cmd").unwrap();
    let cmd = &p.commands[index_of(&p, "cmd")];
    assert_eq!(cmd.prefix_assigns, vec!["A".to_string(), "B".to_string()]);
}

/// `dd if=x of=y` — assignment-SHAPED words in the SUFFIX are arguments, not
/// environment assignments; they must not be recorded as prefix assigns.
#[test]
fn a_suffix_assignment_shaped_word_is_not_a_prefix_assign() {
    let p = parse("dd if=x of=y").unwrap();
    let cmd = &p.commands[index_of(&p, "dd")];
    assert!(cmd.prefix_assigns.is_empty(), "got {:?}", cmd.prefix_assigns);
}

/// A prefix assignment's NAME is captured even when its value is poisoned —
/// this one invocation still ran with the name set, whatever it was set to.
#[test]
fn a_poisoned_prefix_assignment_still_records_its_name() {
    let p = parse("FOO=$(true) cmd").unwrap();
    let cmd = &p.commands[index_of(&p, "cmd")];
    assert_eq!(cmd.prefix_assigns, vec!["FOO".to_string()]);
}

// ============================================================================
// Poisoned assignments (M2.122) — a value built by command substitution is
// recorded, not skipped, so a later resolution never silently falls through.
// ============================================================================

#[test]
fn a_command_substitution_assignment_is_recorded_as_poisoned() {
    let p = parse("F=$(mktemp) echo x").unwrap();
    assert_eq!(
        p.assignments.iter().find(|(n, _)| n == "F").map(|(_, v)| v.clone()),
        Some(None),
        "assignments: {:?}",
        p.assignments
    );
}

#[test]
fn a_literal_assignment_is_still_recorded_readable() {
    let p = parse(r#"F="C:/work" echo x"#).unwrap();
    assert_eq!(
        p.assignments.iter().find(|(n, _)| n == "F").map(|(_, v)| v.clone()),
        Some(Some("C:/work".to_string())),
        "assignments: {:?}",
        p.assignments
    );
}

/// Last-write-wins, poisoned included: a later poisoned write shadows an
/// earlier readable one for the SAME name.
#[test]
fn a_later_poisoned_write_shadows_an_earlier_readable_one() {
    let p = parse(r#"F="C:/work"; F=$(mktemp); echo x"#).unwrap();
    let last = p.assignments.iter().filter(|(n, _)| n == "F").last().map(|(_, v)| v.clone());
    assert_eq!(last, Some(None), "assignments: {:?}", p.assignments);
}

// ============================================================================
// Unquoted-region backslash escapes (M2.121) — `\X` -> `X` outside quotes.
// ============================================================================

#[test]
fn an_unquoted_backslash_escape_is_resolved_in_the_head() {
    let p = parse(r"who\ami").unwrap();
    assert_eq!(p.commands[0].head, "whoami");
}

#[test]
fn an_unquoted_backslash_escape_is_resolved_in_an_argument() {
    let p = parse(r"echo foo\ bar").unwrap();
    assert_eq!(p.commands[0].args, vec!["foo bar".to_string()]);
}

/// Inside single quotes, backslash is ordinary text — no escaping happens.
#[test]
fn a_backslash_inside_single_quotes_is_left_alone() {
    let p = parse(r#"echo 'a\b'"#).unwrap();
    assert_eq!(p.commands[0].args, vec![r"'a\b'".to_string()]);
}

/// Inside double quotes, this scanner does not process the escape (that is
/// `paths::unquote_snippet`'s job downstream) — but it must still track the
/// quote boundary correctly so an escaped `\"` does not end the region early.
#[test]
fn a_backslash_inside_double_quotes_is_left_alone_but_the_boundary_tracks() {
    let p = parse(r#"echo "a\"b" tail"#).unwrap();
    assert_eq!(p.commands[0].args, vec![r#""a\"b""#.to_string(), "tail".to_string()]);
}
