use vouch::syntax::{Order, ScopeKind};

fn bash_scan(src: &str) -> vouch::syntax::Scan {
    vouch::syntax::scanner_for("bash").unwrap().scan(src).unwrap()
}

#[test]
fn a_flat_line_has_no_scopes_and_every_command_in_scope_zero() {
    let s = bash_scan("cd /a && echo hi");
    assert!(s.scan_scopes.is_empty());
    assert_eq!(s.cmd_scope, vec![Some(0), Some(0)]);
}

#[test]
fn the_channels_stay_parallel_to_commands_and_redirects() {
    let s = bash_scan("echo hi > f.txt; ls");
    assert_eq!(s.cmd_scope.len(), s.commands.len());
    assert_eq!(s.redirect_scope.len(), s.redirect_targets.len());
}

#[test]
fn absorb_restamps_scope_ids_past_the_absorbing_scans_own() {
    // Build two scans with scopes via the bash walk once Task 2 lands; at
    // this task's stage, drive absorb directly with hand-built scans.
    let mut outer = bash_scan("echo hi");
    let mut inner = vouch::syntax::Scan::default();
    inner.scan_scopes.push(vouch::syntax::ScanScope {
        class: None,
        parent: 0,
        kind: ScopeKind::ProcessBoundary,
        anchor_order: Order::Unordered,
        anchor_chain: None,
    });
    inner.push_cmd("pwd".into(), vec![], Order::Unordered,
        vouch::syntax::InputSource::Unknown, true, None, vec![], Some(1));
    let outer_scopes = outer.scan_scopes.len();
    outer.absorb(inner);
    // The absorbed command's scope id is offset past the outer scan's own
    // scope table, and the absorbed scope's parent is re-stamped too.
    assert_eq!(outer.scan_scopes.len(), outer_scopes + 1);
    let absorbed = outer.cmd_scope.last().unwrap().unwrap();
    assert_eq!(absorbed, outer_scopes + 1);
}

#[test]
fn a_subshell_is_a_process_boundary_scope_sequenced_internally() {
    let s = bash_scan("cd /a && ( cd /b; touch x ) && echo done");
    let sub = s.cmd_scope[1].unwrap();
    assert_ne!(sub, 0);
    assert_eq!(s.cmd_scope[2].unwrap(), sub);
    assert_eq!(s.cmd_scope[3], Some(0));
    let scope = &s.scan_scopes[sub - 1];
    assert_eq!(scope.kind, ScopeKind::ProcessBoundary);
    assert_eq!(scope.parent, 0);
    assert!(matches!(scope.anchor_order, Order::Seq(_)));
    assert!(scope.anchor_chain.is_some());
    assert_eq!(s.order[1], Order::Seq(0));
    assert_eq!(s.order[2], Order::Seq(1));
}

#[test]
fn a_one_member_pipeline_allocates_no_scope() {
    let s = bash_scan("cd /a; touch x");
    assert!(s.scan_scopes.is_empty());
}

#[test]
fn pipeline_members_get_scopes_only_the_last_same_process() {
    let s = bash_scan("cd /a | cat");
    let first = s.cmd_scope[0].unwrap();
    let last = s.cmd_scope[1].unwrap();
    assert_ne!(first, 0);
    assert_ne!(last, 0);
    assert_ne!(first, last);
    assert_eq!(s.scan_scopes[first - 1].kind, ScopeKind::ProcessBoundary);
    assert_eq!(s.scan_scopes[last - 1].kind, ScopeKind::SameProcess);
}

#[test]
fn an_async_list_backgrounds_only_its_last_pipeline() {
    // zsh runs `cd /a` in the PARENT here (spec §3.3): it must NOT be a
    // process boundary. Only `true` — the last pipeline — is backgrounded.
    let s = bash_scan("cd /a && true & echo hi");
    let cd = s.cmd_scope[0].unwrap();
    let bg = s.cmd_scope[1].unwrap();
    assert_eq!(s.scan_scopes[cd - 1].kind, ScopeKind::SameProcess);
    assert_eq!(s.scan_scopes[bg - 1].kind, ScopeKind::ProcessBoundary);
    assert_eq!(s.cmd_scope[2], Some(0));
}

#[test]
fn grouped_background_is_fully_contained() {
    let s = bash_scan("( cd /a && true ) & echo hi");
    let cd = s.cmd_scope[0].unwrap();
    assert_eq!(s.scan_scopes[cd - 1].kind, ScopeKind::ProcessBoundary);
}

#[test]
fn if_condition_and_branch_get_distinct_same_process_scopes() {
    let s = bash_scan("if cd /a; then touch x; fi; echo hi");
    let cond = s.cmd_scope[0].unwrap();
    let body = s.cmd_scope[1].unwrap();
    assert_ne!(cond, body);
    assert_eq!(s.scan_scopes[cond - 1].kind, ScopeKind::SameProcess);
    assert_eq!(s.scan_scopes[body - 1].kind, ScopeKind::SameProcess);
    assert_eq!(s.cmd_scope[2], Some(0));
}

#[test]
fn a_negated_member_carries_the_negation_bit() {
    let s = bash_scan("! cd /a && touch x");
    assert!(s.commands[0].chain.unwrap().negated);
    assert!(!s.commands[1].chain.unwrap().negated);
}

#[test]
fn process_substitution_anchors_at_its_enclosing_command() {
    let s = bash_scan("cd /a; diff <(cd /b; pwd) f.txt");
    // The procsub's inner commands sit in a ProcessBoundary scope anchored
    // at the diff's own (pre-captured) order.
    let inner = s.cmd_scope.iter().flatten().find(|sc| **sc != 0).copied()
        .expect("procsub allocates a scope");
    let scope = &s.scan_scopes[inner - 1];
    assert_eq!(scope.kind, ScopeKind::ProcessBoundary);
    assert!(matches!(scope.anchor_order, Order::Seq(_)));
}

#[test]
fn nested_bodies_parent_onto_the_enclosing_scope() {
    let s = bash_scan("( cd /a; ( cd /b ) )");
    let outer = s.cmd_scope[0].unwrap();
    let inner = s.cmd_scope[1].unwrap();
    assert_eq!(s.scan_scopes[inner - 1].parent, outer);
}

#[test]
fn compound_own_redirect_stays_in_the_parent_scope() {
    let s = bash_scan("for f in 1; do cd /a; done > rel.txt");
    // The loop body's cd is scoped; the compound's own redirect belongs to
    // the PARENT scope at the compound's anchor (spec §3.3).
    assert_eq!(s.redirect_scope[0], Some(0));
}

#[test]
fn powershell_and_python_scans_emit_no_scopes() {
    let ps = vouch::syntax::scanner_for("powershell").unwrap()
        .scan("Get-ChildItem").unwrap();
    assert!(ps.scan_scopes.is_empty());
    assert!(ps.cmd_scope.iter().all(|s| *s == Some(0)));
    let py = vouch::syntax::scanner_for("python").unwrap()
        .scan("print(1)").unwrap();
    assert!(py.scan_scopes.is_empty());
    assert!(py.cmd_scope.iter().all(|s| *s == Some(0)));
}

// Deferred from Task 1's review: the test above only exercises
// `scope_offset == 0` (an outer scan with no scopes of its own absorbing
// one that has some). This one drives a nonzero offset: an outer scan that
// ALREADY has a scope table absorbs another scan with its own scope table,
// so the absorbed scope ids and parents must land past the outer's own.
#[test]
fn absorb_restamps_scope_ids_past_a_nonzero_existing_offset() {
    let mut outer = vouch::syntax::Scan::default();
    outer.scan_scopes.push(vouch::syntax::ScanScope {
        class: None,
        parent: 0,
        kind: ScopeKind::SameProcess,
        anchor_order: Order::Unordered,
        anchor_chain: None,
    });
    outer.push_cmd("echo".into(), vec!["hi".into()], Order::Unordered,
        vouch::syntax::InputSource::Unknown, true, None, vec![], Some(1));

    let mut inner = vouch::syntax::Scan::default();
    inner.scan_scopes.push(vouch::syntax::ScanScope {
        class: None,
        parent: 0,
        kind: ScopeKind::ProcessBoundary,
        anchor_order: Order::Unordered,
        anchor_chain: None,
    });
    inner.push_cmd("pwd".into(), vec![], Order::Unordered,
        vouch::syntax::InputSource::Unknown, true, None, vec![], Some(1));

    let outer_scopes = outer.scan_scopes.len();
    outer.absorb(inner);
    assert_eq!(outer.scan_scopes.len(), outer_scopes + 1);
    // The absorbed command's scope id sits past the outer's own existing
    // scope table, not just past zero.
    let absorbed = outer.cmd_scope.last().unwrap().unwrap();
    assert_eq!(absorbed, outer_scopes + 1);
    // The absorbed scope's own parent (originally 0, meaning "the absorbed
    // scan's own top level") is re-stamped to the outer's top level (still
    // 0 — top level is shared, never offset), not left pointing at a scope
    // id that only made sense inside the absorbed scan's own table.
    assert_eq!(outer.scan_scopes[absorbed - 1].parent, 0);
}
