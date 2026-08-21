//! Every guard rule in the knowledge in effect is a live claim (CLAUDE.md §3).
//!
//! `tests/guards_test.rs` pins specific commands to specific guards, written
//! one at a time for the rules someone remembered — which is how 13 of the
//! then-23 rules ended up with no test at all (M2.9). These tests instead
//! enumerate the rules from the loaded knowledge itself, the way
//! `criterion2_test.rs` enumerates constructs from the scanners: a rule added
//! tomorrow is covered the moment it exists, or the suite goes red.
//!
//! Per rule, two claims:
//!   1. it FIRES on a command built from its own match criteria — a rule that
//!      cannot be made to fire from its own definition is dead, and a dead
//!      rule is silent non-enforcement (§1);
//!   2. it does NOT fire on the bare program name without those criteria
//!      (`always` rules excepted — firing on the bare name is their claim).
//!
//! The other per-rule claims — a guard name `KNOWN_GUARDS` recognises, a
//! provenance the prompt can show — are already enumerated over the same walk
//! by `every_guard_the_data_can_emit_is_declared_known` and
//! `every_rule_states_where_it_came_from` in `guards_test.rs`.

use vouch::guards::{base_name, check, in_effect, rule_matches, Program, Rule};
use vouch::shell::Cmd;

/// A command built from nothing but the rule's own match criteria.
///
/// Field by field, first value of each: the subcommand, the sub-arg-0, one
/// flag verbatim, one exact argument, one argument extending a prefix, and a
/// `+x` when the rule wants the execute-bit predicate. A rule this builder
/// cannot make fire has criteria that cannot all hold at once — which is the
/// finding, not a builder gap.
fn firing_cmd(head: &str, rule: &Rule) -> Cmd {
    let mut args = Vec::new();
    if let Some(s) = rule.subcommand_in.first() {
        args.push(s.clone());
    }
    if let Some(s) = rule.sub_arg_0_in.first() {
        args.push(s.clone());
    }
    if let Some(f) = rule.any_flag.first() {
        args.push(f.clone());
    }
    if let Some(a) = rule.any_arg_exact.first() {
        args.push(a.clone());
    }
    if let Some(p) = rule.any_arg_prefix.first() {
        args.push(format!("{p}x"));
    }
    if rule.grants_execute {
        args.push("+x".to_string());
    }
    Cmd {
        head: head.to_string(),
        args,
        chain: None,
        prefix_assigns: vec![],
    }
}

fn bare(head: &str) -> Cmd {
    Cmd {
        head: head.to_string(),
        args: Vec::new(),
        chain: None,
        prefix_assigns: vec![],
    }
}

/// The walk everything below iterates. Asserting non-emptiness here, once,
/// keeps every other loop honest: each of these tests passes vacuously if no
/// knowledge loaded, which the M0 work hit twice.
fn rule_bearing_entries() -> Vec<(&'static Program, &'static Rule)> {
    let kb = in_effect();
    let pairs: Vec<_> = kb
        .program
        .iter()
        .flat_map(|p| p.rule.iter().map(move |r| (p, r)))
        .collect();
    assert!(
        !pairs.is_empty(),
        "the knowledge in effect carries no guard rules at all — \
         either nothing loaded (vacuous walk) or every rule was removed"
    );
    pairs
}

#[test]
fn every_rule_fires_on_a_command_built_from_its_own_criteria() {
    let kb = in_effect();
    for (prog, rule) in rule_bearing_entries() {
        for name in &prog.match_names {
            let cmd = firing_cmd(name, rule);
            assert!(
                rule_matches(rule, &cmd, prog),
                "rule ({guard} / {source}) on `{name}` is DEAD: it does not \
                 fire on a command built from its own criteria: `{name} {args}`",
                guard = rule.guard,
                source = rule.source,
                args = cmd.args.join(" ")
            );
            // And end to end: the entry is reachable by name lookup, so the
            // rule fires through `check()`, not only in isolation. A match
            // name spelled with a path or `.exe` would pass `rule_matches`
            // and fail here — that is M2.52's dead-entry class. (Keyed by
            // (guard, source), which is not unique per rule, so a same-named
            // entry carrying a pair-identical rule could mask an unreachable
            // one — no shipped pair collides today. Precise rule identity in
            // a Hit is M2.17's accounting work; tighten this when it lands.)
            let hits = check(kb, &cmd);
            assert!(
                hits.iter()
                    .any(|h| h.guard == rule.guard && h.source == rule.source),
                "rule ({} / {}) fires in isolation but `check()` never reaches \
                 it for head `{name}` — the entry itself is unreachable",
                rule.guard,
                rule.source
            );
        }
    }
}

#[test]
fn no_rule_fires_on_the_bare_program_name_without_its_criteria() {
    for (prog, rule) in rule_bearing_entries() {
        if rule.always {
            continue; // firing on the bare name IS an `always` rule's claim
        }
        for name in &prog.match_names {
            assert!(
                !rule_matches(rule, &bare(name), prog),
                "rule ({} / {}) on `{}` fires on the bare program name — its \
                 criteria constrain nothing",
                rule.guard,
                rule.source,
                name
            );
        }
    }
}

#[test]
fn the_bare_name_trips_exactly_the_always_rules_and_nothing_else() {
    // The per-rule negative above is precise but rule-local; this is the
    // end-to-end statement. Several entries can share one name (the shipped
    // file has same-name pairs — M2.53), so expectations are gathered across
    // every rule-bearing entry carrying the name — compared via `base_name`,
    // the module's own normalisation, not a second locally-invented rule.
    let kb = in_effect();
    let pairs = rule_bearing_entries();
    let mut names: Vec<String> = pairs
        .iter()
        .flat_map(|(p, _)| p.match_names.iter())
        .map(|n| base_name(n))
        .collect();
    names.sort();
    names.dedup();
    for name in &names {
        let mut want: Vec<(String, String)> = pairs
            .iter()
            .filter(|(p, r)| r.always && p.match_names.iter().any(|n| &base_name(n) == name))
            .map(|(_, r)| (r.guard.clone(), r.source.clone()))
            .collect();
        let mut got: Vec<(String, String)> = check(kb, &bare(name))
            .into_iter()
            .map(|h| (h.guard, h.source))
            .collect();
        want.sort();
        got.sort();
        assert_eq!(
            got, want,
            "bare `{name}` should trip exactly its `always` rules"
        );
    }
}
