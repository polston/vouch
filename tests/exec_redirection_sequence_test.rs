//! Verification tests for M2.101: `exec`-family redirection sequence modeling
//! across subsequent pipeline commands in the same execution scope.

use vouch::shell::parse;
use vouch::syntax::InputSource::*;
use vouch::syntax::Scan;

fn find_indices(p: &Scan, head: &str) -> Vec<usize> {
    p.commands
        .iter()
        .enumerate()
        .filter(|(_, c)| c.head == head)
        .map(|(i, _)| i)
        .collect()
}

#[test]
fn sequential_propagation_in_same_scope() {
    let p = parse("exec < f.txt; cat").expect("parses");
    assert_eq!(p.commands.len(), 2);
    assert_eq!(p.input_source[0], File, "exec has File input");
    assert_eq!(p.input_source[1], File, "cat inherits File input from exec");
}

#[test]
fn multiple_sequential_commands_inherit_until_overridden() {
    let p = parse("exec < f.txt; head -n 1; grep pattern; exec < g.txt; tail -n 5").expect("parses");
    assert_eq!(p.input_source[0], File); // exec < f.txt
    assert_eq!(p.input_source[1], File); // head
    assert_eq!(p.input_source[2], File); // grep
    assert_eq!(p.input_source[3], File); // exec < g.txt
    assert_eq!(p.input_source[4], File); // tail
}

#[test]
fn explicit_redirect_overrides_inherited_source() {
    let p = parse("exec < f.txt; cat < g.txt").expect("parses");
    assert_eq!(p.input_source[0], File);
    assert_eq!(p.input_source[1], File); // cat keeps explicit redirect
}

#[test]
fn pipeline_stage_overrides_inherited_source() {
    let p = parse("exec < f.txt; echo hi | cat").expect("parses");
    assert_eq!(p.input_source[0], File); // exec
    assert_eq!(p.input_source[1], File); // echo (first pipeline member inherits)
    assert_eq!(p.input_source[2], Pipe); // cat (subsequent pipeline stage reads pipe)
}

#[test]
fn subshell_isolates_exec_from_outer_scope() {
    let p = parse("(exec < f.txt; cat); cat").expect("parses");
    let cats = find_indices(&p, "cat");
    assert_eq!(cats.len(), 2);
    let inner_cat = cats[0];
    let outer_cat = cats[1];

    assert_eq!(p.input_source[inner_cat], File, "inner cat in subshell sees exec");
    assert_eq!(
        p.input_source[outer_cat],
        Nothing,
        "outer cat outside subshell does not inherit inner subshell exec"
    );
}

#[test]
fn subshell_inherits_from_parent_and_modifications_stay_local() {
    let p = parse("exec < f.txt; (exec < g.txt; cat); cat").expect("parses");
    let cats = find_indices(&p, "cat");
    assert_eq!(cats.len(), 2);
    let inner_cat = cats[0];
    let outer_cat = cats[1];

    assert_eq!(p.input_source[inner_cat], File, "inner cat sees inner exec");
    assert_eq!(
        p.input_source[outer_cat],
        File,
        "outer cat sees outer exec unaffected by inner subshell"
    );
}

#[test]
fn subshell_inherits_parent_exec_redirection() {
    let p = parse("exec < f.txt; (cat)").expect("parses");
    let cats = find_indices(&p, "cat");
    assert_eq!(cats.len(), 1);
    assert_eq!(p.input_source[cats[0]], File, "subshell cat inherits parent exec");
}

#[test]
fn non_bare_exec_does_not_mutate_sequence_stdin() {
    let p = parse("exec ls -la; cat").expect("parses");
    assert_eq!(p.input_source[0], Nothing); // exec ls -la
    assert_eq!(p.input_source[1], Nothing); // cat does not inherit
}

#[test]
fn wrapped_exec_does_not_mutate_sequence_stdin() {
    let p = parse("exec -a myname ls; cat").expect("parses");
    assert_eq!(p.input_source[0], Nothing);
    assert_eq!(p.input_source[1], Nothing);
}

#[test]
fn bare_exec_with_double_dash_is_recognized() {
    let p = parse("exec -- < f.txt; cat").expect("parses");
    assert_eq!(p.input_source[0], File);
    assert_eq!(p.input_source[1], File);
}

#[test]
fn stream_descriptor_close_propagates() {
    let p = parse("exec <&-; cat").expect("parses");
    assert_eq!(p.input_source[0], Stream);
    assert_eq!(p.input_source[1], Stream);
}

#[test]
fn compound_redirect_blanks_inherited_stdin() {
    let p = parse("exec < f.txt; { cat; } < g.txt").expect("parses");
    let cats = find_indices(&p, "cat");
    assert_eq!(cats.len(), 1);
    assert_eq!(
        p.input_source[cats[0]],
        Unknown,
        "compound redirect overrides inherited stdin for inner command"
    );
}

#[test]
fn unordered_exec_resolves_subsequent_to_unknown() {
    let p = parse("false || exec < f.txt; cat").expect("parses");
    let cats = find_indices(&p, "cat");
    assert_eq!(cats.len(), 1);
    assert_eq!(
        p.input_source[cats[0]],
        Unknown,
        "conditionally executed exec leaves subsequent command with Unknown source"
    );
}

#[test]
fn backgrounded_exec_is_isolated_to_subshell() {
    let p = parse("exec < f.txt & cat").expect("parses");
    let cats = find_indices(&p, "cat");
    assert_eq!(cats.len(), 1);
    assert_eq!(
        p.input_source[cats[0]],
        Nothing,
        "backgrounded exec runs in child process scope, so outer cat remains Nothing"
    );
}

#[test]
fn input_source_parallelism_preserved() {
    for src in [
        "exec < f.txt; cat",
        "exec < f.txt; cat < g.txt",
        "exec < f.txt; echo hi | cat",
        "(exec < f.txt; cat); cat",
        "exec < f.txt; { cat; } < g.txt",
        "exec < f.txt & cat",
    ] {
        let p = parse(src).expect("parses");
        assert_eq!(
            p.input_source.len(),
            p.commands.len(),
            "input_source length matches commands length for {src}"
        );
    }
}
