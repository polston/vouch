//! PowerShell tests.
//!
//! The three constructs in here that are named after real events are the ones
//! that interrupted the user repeatedly on 2026-07-25 with a message telling
//! them to change a setting that did not exist:
//!   [Type]::Member   ·   foreach   ·   & "path"
//! Each must be nameable AND settable. That is the whole point.

use vouch::config::load;
use vouch::powershell::parse;
use vouch::protocol::Decision;
use vouch::syntax::Order;

fn constructs(cmd: &str) -> Vec<String> {
    parse(cmd).expect("scans").constructs
}

/// The index of the command whose head is `head` — mirrors shell_test.rs's
/// own helper of the same name.
fn index_of(p: &vouch::syntax::Scan, head: &str) -> usize {
    p.commands
        .iter()
        .position(|c| c.head == head)
        .unwrap_or_else(|| panic!("no command {head} among {:?}", p.heads))
}

fn assert_construct(cmd: &str, want: &str) {
    let got = constructs(cmd);
    assert!(
        got.iter().any(|c| c == want),
        "expected construct '{want}' for `{cmd}`, got {got:?}"
    );
}

// --- the three that actually interrupted the user --------------------------

#[test]
fn type_literal_is_named() {
    for cmd in [
        r#"[System.IO.Compression.ZipFile]::ExtractToDirectory($a, $b)"#,
        r#"$t = [System.Diagnostics.Stopwatch]::StartNew()"#,
        r#"[math]::Round($x, 1)"#,
        r#"[PSCustomObject]@{ Name = "x" }"#,
    ] {
        assert_construct(cmd, "type_literal");
    }
}

#[test]
fn call_operator_is_named() {
    for cmd in [
        r#"& "C:\Users\dev\python.exe" script.py"#,
        r#"& $py script.py"#,
        r#"$out = & $tool --version"#,
    ] {
        assert_construct(cmd, "call_operator");
    }
}

#[test]
fn unsupported_keywords_are_named() {
    assert_construct("foreach ($x in $list) { Write-Output $x }", "keyword_foreach");
    assert_construct("while ($true) { Start-Sleep 1 }", "keyword_while");
    assert_construct("switch ($x) { 1 { 'one' } }", "keyword_switch");
}

// --- the parser defect that made vouch's predecessor unusable --------------

#[test]
fn an_unquoted_assignment_value_is_not_a_command() {
    // cc-allow read `$env:PYTHONUTF8=1` as a command named "1" and prompted.
    let p = parse(r#"$env:PYTHONUTF8=1; python foo.py"#).expect("scans");
    assert!(
        !p.heads.iter().any(|h| h == "1"),
        "an assignment value must never be read as a command: {:?}",
        p.heads
    );
    assert!(p.heads.iter().any(|h| h == "python"), "heads: {:?}", p.heads);
}

#[test]
fn a_bare_numeric_assignment_is_not_a_command() {
    let p = parse("$n = 5; Get-ChildItem").expect("scans");
    assert!(
        !p.heads.iter().any(|h| h == "5"),
        "got heads {:?}",
        p.heads
    );
    assert!(p.heads.iter().any(|h| h == "Get-ChildItem"));
}

#[test]
fn a_quoted_assignment_value_is_not_a_command() {
    let p = parse(r#"$s = "utf-8"; python foo.py"#).expect("scans");
    assert!(!p.heads.iter().any(|h| h == "utf-8"), "heads: {:?}", p.heads);
}

#[test]
fn an_assignment_from_a_command_still_finds_the_command() {
    let p = parse("$d = Get-Date").expect("scans");
    assert!(p.heads.iter().any(|h| h == "Get-Date"), "heads: {:?}", p.heads);
}

// --- ordinary things must stay quiet ---------------------------------------

#[test]
fn a_plain_pipeline_reports_no_constructs() {
    let got = constructs("Get-ChildItem C:/workspace | Select-Object -First 5");
    assert!(got.is_empty(), "got {got:?}");
}

#[test]
fn heads_are_found_across_separators_and_pipes() {
    let p = parse("cd C:/workspace; Get-ChildItem | Where-Object { $_.Length -gt 10 }").expect("scans");
    for want in ["cd", "Get-ChildItem", "Where-Object"] {
        assert!(p.heads.iter().any(|h| h == want), "missing {want} in {:?}", p.heads);
    }
}

// --- order attribution: a multi-line pipeline is still one pipeline --------
//
// `cmd |\n  next` is the idiomatic way to write a multi-line PowerShell
// pipeline. The splitter used to drop the `|` when it was followed
// immediately by a newline (nothing but whitespace between them), so the
// statement after it looked newline-joined instead of pipe-joined, and a
// provably-unordered pipeline member came out as a provable `Seq` position.

#[test]
fn a_pipeline_broken_before_the_newline_is_still_a_pipeline() {
    let p = parse("gci |\nsort").expect("scans");
    assert_eq!(
        p.order,
        vec![Order::Unordered, Order::Unordered],
        "order: {:?}",
        p.order
    );
}

#[test]
fn a_multiline_pipeline_with_a_scriptblock_member_is_still_a_pipeline() {
    let p = parse("Get-ChildItem |\n  Where-Object { $_.Length -gt 10 } |\n  Select-Object Name")
        .expect("scans");
    assert_eq!(
        p.order,
        vec![Order::Unordered, Order::Unordered, Order::Unordered],
        "order: {:?}",
        p.order
    );
}

#[test]
fn a_pipeline_that_breaks_only_before_its_last_member_is_still_one_pipeline() {
    let p = parse("gci | sort |\nselect -First 3").expect("scans");
    assert_eq!(
        p.order,
        vec![Order::Unordered, Order::Unordered, Order::Unordered],
        "order: {:?}",
        p.order
    );
}

// --- order attribution: top-level statements, pipelines, script blocks -----
//
// Task 2 gave the scanner provisional wiring for this (a counter over
// `;`/newline-joined statements, `Unordered` for any pipeline with more than
// one member). These pin the exact vectors so that wiring cannot regress
// silently.

#[test]
fn semicolon_joined_statements_are_sequenced() {
    let p = parse("Set-Location C:/x; git init").expect("scans");
    assert_eq!(
        p.order,
        vec![Order::Seq(0), Order::Seq(1)],
        "order: {:?}",
        p.order
    );
}

#[test]
fn a_pipeline_member_command_is_unordered() {
    // A pipeline with more than one member runs concurrently, so no member's
    // position relative to the others is provable — including the first one,
    // which is easy to mistake for "runs first, so it's Seq(0)".
    let p = parse("Set-Location C:/x | Out-Null").expect("scans");
    let idx = p
        .heads
        .iter()
        .position(|h| h == "Set-Location")
        .unwrap_or_else(|| panic!("Set-Location not found in heads: {:?}", p.heads));
    assert_eq!(p.order[idx], Order::Unordered, "order: {:?}", p.order);
}

#[test]
fn a_script_block_snippet_is_absorbed_as_unordered() {
    // Same input shape as `unsupported_keywords_are_named` above: a script
    // block is a wrapper snippet the outer scan hands off and cannot vouch
    // for the timing of, whatever order it was provable at inside its own
    // nested text.
    let p = parse("foreach ($x in $list) { Write-Output $x }").expect("scans");
    let idx = p
        .heads
        .iter()
        .position(|h| h == "Write-Output")
        .unwrap_or_else(|| panic!("Write-Output not found in heads: {:?}", p.heads));
    assert_eq!(p.order[idx], Order::Unordered, "order: {:?}", p.order);
}

// The per-command arrays stay parallel to `commands` across an ABSORBED inner
// block — the one path that extends every array by hand rather than through
// `push_cmd`, and therefore the one where a hand-written extension can desync.
// This scanner does not populate the input source (PowerShell has no
// input-redirection operator), so every value is `Unknown`; the invariant under
// test is the length, not the content.
#[test]
fn the_per_command_arrays_survive_an_absorbed_block() {
    for src in [
        "foreach ($x in $list) { Write-Output $x }",
        "Get-Item foo",
        "$(Get-Item foo)",
    ] {
        let p = parse(src).expect("scans");
        assert_eq!(p.input_source.len(), p.commands.len(), "input_source: {src}");
        assert_eq!(p.args_complete.len(), p.commands.len(), "args_complete: {src}");
    }
}

// --- everything must be settable -------------------------------------------

#[test]
fn every_construct_the_scanner_emits_is_settable() {
    let samples = [
        r#"[math]::Round($x)"#,
        r#"& "C:\x\y.exe" a"#,
        "foreach ($x in $l) { }",
        "while ($true) { }",
        "switch ($x) { }",
        "function f { }",
        "$o.Method()",
        "Get-Thing > out.txt",
        "$env:X = \"1\"",
        "$(Get-Date)",
    ];
    for s in samples {
        for c in constructs(s) {
            assert!(
                vouch::powershell::KNOWN_CONSTRUCTS.contains(&c.as_str()),
                "scanner emitted '{c}' which is not in KNOWN_CONSTRUCTS (sample: {s})"
            );
        }
    }
}

#[test]
fn type_literal_can_be_allowed_by_configuration() {
    // The exact thing that could not be turned off in the previous tool.
    let cfg = load(
        "version = 1\n[lang.powershell]\ndefault = \"allow\"\n\
         [lang.powershell.constructs]\ntype_literal = \"allow\"\n",
    )
    .expect("parses");
    let d = vouch::engine::decide_powershell(&cfg, r#"[math]::Round(1.5)"#);
    assert!(matches!(d, Decision::Allow(_)), "got {d:?}");
}

#[test]
fn call_operator_can_be_allowed_by_configuration() {
    // Two constructs, two switches, and they sit in different language
    // tables. The line invokes a program through the call operator (this
    // test's subject, a PowerShell construct), and since M2.118 it also
    // hands python a script file vouch has not read — python's blindness,
    // keyed to python because that is the language of the code that runs.
    // Allowing one construct has never covered another, so both are said.
    let cfg = load(
        "version = 1\n[lang.powershell]\ndefault = \"allow\"\n\
         [lang.powershell.constructs]\nunmodeled_command = \"allow\"\ncall_operator = \"allow\"\n\
         [lang.python.constructs]\nevaluated_input = \"allow\"\n",
    )
    .expect("parses");
    let d = vouch::engine::decide_powershell(&cfg, r#"& "C:\x\python.exe" a.py"#);
    assert!(matches!(d, Decision::Allow(_)), "got {d:?}");
}

#[test]
fn foreach_can_be_allowed_by_configuration() {
    let cfg = load(
        "version = 1\n[lang.powershell]\ndefault = \"allow\"\n\
         [lang.powershell.constructs]\nunmodeled_command = \"allow\"\nkeyword_foreach = \"allow\"\n",
    )
    .expect("parses");
    let d = vouch::engine::decide_powershell(&cfg, "foreach ($x in $l) { Write-Output $x }");
    assert!(matches!(d, Decision::Allow(_)), "got {d:?}");
}

#[test]
fn an_unset_construct_asks_and_names_its_setting() {
    let cfg = load("version = 1\n[lang.powershell]\ndefault = \"allow\"\n").expect("parses");
    match vouch::engine::decide_powershell(&cfg, r#"[math]::Round(1.5)"#) {
        Decision::Ask(reason) => {
            assert!(
                reason.contains("lang.powershell.constructs.type_literal"),
                "got: {reason}"
            );
        }
        other => panic!("expected Ask, got {other:?}"),
    }
}

#[test]
fn guards_apply_to_powershell_too() {
    let cfg = load("version = 1\n[lang.powershell]\ndefault = \"allow\"\n").expect("parses");
    let d = vouch::engine::decide_powershell(&cfg, "git reset --hard origin/main");
    match d {
        Decision::Ask(reason) => assert!(reason.contains("history_rewrite"), "got: {reason}"),
        other => panic!("expected Ask, got {other:?}"),
    }
}

// ============================================================================
// M2.126 — `split_statements_with_sep` learns `&&`/`||` as two-character
// separators, and the split members carry the same `ChainPos` vocabulary
// bash's own and-or walk produces (shell_test.rs's own suite of the same
// name).
// ============================================================================

#[test]
fn semicolon_split_gives_two_commands_with_no_chain() {
    let p = parse("Get-Date; Remove-Item x").expect("scans");
    assert_eq!(p.heads, vec!["Get-Date", "Remove-Item"]);
    assert_eq!(p.commands[index_of(&p, "Get-Date")].chain, None);
    assert_eq!(p.commands[index_of(&p, "Remove-Item")].chain, None);
    assert_eq!(p.order, vec![Order::Seq(0), Order::Seq(1)], "order: {:?}", p.order);
}

#[test]
fn and_link_splits_into_two_chained_commands_both_ordered() {
    let p = parse("Get-Date && Remove-Item x").expect("scans");
    assert_eq!(p.heads, vec!["Get-Date", "Remove-Item"]);
    let a = p.commands[index_of(&p, "Get-Date")].chain.expect("Get-Date is chained");
    let b = p.commands[index_of(&p, "Remove-Item")].chain.expect("Remove-Item is chained");
    assert_eq!(a.id, b.id, "same chain");
    assert_eq!((a.idx, a.and_run_from), (0, 0), "Get-Date");
    assert_eq!((b.idx, b.and_run_from), (1, 0), "Remove-Item");
    // Nothing but `&&` links this chain — both members stay provably
    // ordered, same as bash's `cd d && echo x > f` (shell.rs's own rule).
    assert_eq!(p.order, vec![Order::Seq(0), Order::Seq(1)], "order: {:?}", p.order);
}

#[test]
fn or_link_splits_into_two_chained_commands_second_unordered() {
    let p = parse("Get-Date || Remove-Item x").expect("scans");
    assert_eq!(p.heads, vec!["Get-Date", "Remove-Item"]);
    let a = p.commands[index_of(&p, "Get-Date")].chain.expect("Get-Date is chained");
    let b = p.commands[index_of(&p, "Remove-Item")].chain.expect("Remove-Item is chained");
    assert_eq!(a.id, b.id, "same chain");
    assert_eq!((a.idx, a.and_run_from), (0, 0), "Get-Date");
    // `||` means the second member only runs when the first FAILED — its
    // own `and_run_from` resets to its own idx, and its execution is no
    // longer certain.
    assert_eq!((b.idx, b.and_run_from), (1, 1), "Remove-Item");
    assert_eq!(
        p.order,
        vec![Order::Seq(0), Order::Unordered],
        "order: {:?}",
        p.order
    );
}

/// The exact three-member mixed chain shell_test.rs pins for bash:
/// `a && b || c` — `idx` runs 0,1,2; `and_run_from` stays at the chain's
/// start across the `&&` link and resets to the member's own `idx` at the
/// `||`. PowerShell's splitter must produce the identical vocabulary.
#[test]
fn mixed_chain_matches_bashs_pinned_positions() {
    let p = parse("a && b || c").expect("scans");
    let a = p.commands[index_of(&p, "a")].chain.expect("a is chained");
    let b = p.commands[index_of(&p, "b")].chain.expect("b is chained");
    let c = p.commands[index_of(&p, "c")].chain.expect("c is chained");
    assert_eq!((a.idx, a.and_run_from), (0, 0), "a");
    assert_eq!((b.idx, b.and_run_from), (1, 0), "b");
    assert_eq!((c.idx, c.and_run_from), (2, 2), "c");
    assert_eq!(a.id, b.id);
    assert_eq!(b.id, c.id);
    assert_eq!(
        p.order,
        vec![Order::Seq(0), Order::Seq(1), Order::Unordered],
        "order: {:?}",
        p.order
    );
}

/// A lone statement with no `&&`/`||` neighbour is not a chain at all, even
/// once it sits next to `;`-joined siblings — matches shell_test.rs's own
/// `a_semicolon_separated_command_has_no_chain`.
#[test]
fn a_semicolon_separated_command_has_no_chain() {
    let p = parse("a; b; c").expect("scans");
    assert_eq!(p.commands[index_of(&p, "a")].chain, None);
    assert_eq!(p.commands[index_of(&p, "b")].chain, None);
    assert_eq!(p.commands[index_of(&p, "c")].chain, None);
}

/// A single `&` — the call operator prefix, or PowerShell 7's background
/// suffix — must never be read as half of `&&`. The splitter only consumes
/// a second character when one is actually there.
#[test]
fn a_single_ampersand_is_not_treated_as_a_separator() {
    let p = parse("Get-Process &").expect("scans");
    // One statement, not two: the trailing `&` stays literal text and does
    // not create a phantom second (empty) command.
    assert_eq!(p.heads, vec!["Get-Process"]);
}

/// The call operator on BOTH sides of a real `&&` link: the leading `&` of
/// each statement must not be consumed by the two-character lookahead
/// (there is exactly one `&` at each of those positions, not two), while the
/// `&&` between them still splits and still carries chain identity.
#[test]
fn call_operator_statements_joined_by_and_still_chain() {
    let p = parse(r#"& $tool -v && & $other -w"#).expect("scans");
    assert_eq!(p.heads, vec!["$tool", "$other"]);
    let a = p.commands[index_of(&p, "$tool")].chain.expect("chained");
    let b = p.commands[index_of(&p, "$other")].chain.expect("chained");
    assert_eq!(a.id, b.id);
    assert_eq!((a.idx, b.idx), (0, 1));
}

/// Every piped stage of one and-or chain member shares that member's single
/// `ChainPos` — a `|`-joined run is one member, exactly as shell_test.rs's
/// `every_piped_stage_of_one_member_shares_its_chain_position` pins for
/// bash.
#[test]
fn every_piped_stage_of_one_member_shares_its_chain_position() {
    let p = parse("a | b && c").expect("scans");
    let a = p.commands[index_of(&p, "a")].chain.expect("a is chained");
    let b = p.commands[index_of(&p, "b")].chain.expect("b is chained");
    let c = p.commands[index_of(&p, "c")].chain.expect("c is chained");
    assert_eq!(a, b, "both pipe stages are the SAME chain member");
    assert_eq!(a.idx, 0);
    assert_eq!((c.idx, c.and_run_from), (1, 0));
}

/// A nested script block re-parses its own text as a fresh, independent
/// `parse()` call with its own `chain_counter` starting at 0 (powershell.rs
/// has no cross-call state to thread the way shell.rs threads
/// `chain_counter` through nested compounds within ONE parse). Left
/// unremapped, an absorbed chain's `id` would collide with an unrelated
/// chain already present in the outer scan — `Scan::absorb` (syntax.rs)
/// offsets every absorbed `ChainPos.id` past whatever the outer scan
/// already uses, so two genuinely unrelated chains never compare equal.
#[test]
fn nested_block_chain_ids_do_not_collide_with_the_outer_chain() {
    let p = parse("a && b; if ($true) { c && d }").expect("scans");
    let outer = p.commands[index_of(&p, "a")].chain.expect("a is chained");
    let inner = p.commands[index_of(&p, "c")].chain.expect("c is chained");
    assert_ne!(
        outer.id, inner.id,
        "the absorbed nested chain must not collide with the outer one's id"
    );
    // Each chain is still internally consistent after the remap.
    let b = p.commands[index_of(&p, "b")].chain.expect("b is chained");
    let d = p.commands[index_of(&p, "d")].chain.expect("d is chained");
    assert_eq!(outer.id, b.id, "a and b share the outer chain");
    assert_eq!(inner.id, d.id, "c and d share the (remapped) inner chain");
}
