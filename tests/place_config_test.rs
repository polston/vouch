use vouch::config;
use vouch::guards::{load, Knowledge};
use vouch::knowledge::validate_place_scopes;

#[path = "common/mod.rs"]
mod common;
use common::v;



#[test]
fn the_new_sections_parse() {
    let cfg = config::load(r#"
version = 1
[run]
trust_all_under = ["C:/scratch/**"]
trust_nothing_under = ["D:/inbox/**"]
[[run.guards]]
under = ["C:/workspace/**"]
delete_recursive = "ask"
[write]
allow_paths = ["C:/work/**"]
ask_paths = ["~/notes/**"]
deny_paths = ["~/photos/**"]
[[write.scope]]
programs = ["git init"]
only_under = ["C:/scratch/**"]
"#).unwrap();
    assert_eq!(cfg.run.trust_all_under.as_deref(), Some(&["C:/scratch/**".to_string()][..]));
    assert_eq!(cfg.run.guard_overrides.len(), 1);
    assert_eq!(cfg.write.ask_paths, vec!["~/notes/**"]);
    assert_eq!(cfg.write.scope[0].programs, vec!["git init"]);
}

#[test]
fn a_misspelt_key_refuses_the_load() {
    // Today this parses silently (Raw has no unknown-key refusal). After
    // this task it is an Err naming the key.
    let e = config::load("[write]\ndeny_pathes = [\"~/x/**\"]").unwrap_err();
    assert!(e.contains("deny_pathes"), "error must name the key: {e}");
}

#[test]
fn version_is_a_real_key_now() {
    assert!(config::load("version = 1").is_ok());
}

#[test]
fn an_unknown_guard_name_refuses_in_both_homes() {
    let e = config::load("[guards]\ndelete_recursiv = \"ask\"").unwrap_err();
    assert!(e.contains("delete_recursiv"));
    let e2 = config::load("[[run.guards]]\nunder = [\"C:/x/**\"]\ndelete_recursiv = \"ask\"").unwrap_err();
    assert!(e2.contains("delete_recursiv"));
}

#[test]
fn a_guard_named_under_in_the_global_map_refuses() {
    // `under` is a structural word in [[run.guards]]; a guard by that name
    // could never be overridden there. The global map refuses it by the
    // same KNOWN_GUARDS check as any other unknown name — this pin exists
    // so that stays true.
    let e = config::load("[guards]\nunder = \"ask\"").unwrap_err();
    assert!(e.contains("under"));
}

#[test]
fn an_empty_grant_list_refuses() {
    let e = config::load("[run]\ntrust_all_under = []").unwrap_err();
    assert!(e.contains("trust_all_under"));
    let e2 = config::load("[[write.scope]]\nprograms = [\"probe-tool\"]\nonly_under = []").unwrap_err();
    assert!(e2.contains("only_under"));
}

#[test]
fn the_same_tree_in_opposing_lists_refuses() {
    let e = config::load(
        "[run]\ntrust_all_under = [\"C:/x/**\"]\ntrust_nothing_under = [\"C:/X/**\"]",
    ).unwrap_err();
    assert!(e.contains("trust_all_under") && e.contains("trust_nothing_under"));
    let e2 = config::load(
        "[write]\nallow_paths = [\"C:/y/**\"]\ndeny_paths = [\"C:/y/**\"]",
    ).unwrap_err();
    assert!(e2.contains("allow_paths") && e2.contains("deny_paths"));
}

#[test]
fn absent_sections_still_default_cleanly() {
    let cfg = config::load("[lang.bash]\ndefault = \"allow\"").unwrap();
    assert!(cfg.run.trust_all_under.is_none());
    assert!(cfg.write.deny_paths.is_empty());
}

#[test]
fn a_custom_language_section_still_parses_under_strict_raw() {
    // The `[lang.foo]` table is a catch-all for new languages: Raw has a named
    // `lang` field (HashMap<String, LangConfig>), so [lang.foo] deserializes
    // into that map, not as an unknown field. This pin ensures strict
    // deny_unknown_fields on Raw does not break the extensibility pattern.
    let cfg = config::load(r#"
version = 1
[lang.zsh]
default = "ask"
[lang.zsh.constructs]
heredoc = "allow"
"#).unwrap();
    assert!(cfg.langs.contains_key("zsh"));
    assert_eq!(cfg.langs["zsh"].default, config::Action::Ask);
}

#[test]
fn allow_paths_contradicts_ask_paths() {
    // Third of three opposing pairs: allow vs ask (allow already tested against
    // deny). Same normalization and contradiction detection as the other two.
    let e = config::load(
        "[write]\nallow_paths = [\"C:/safe/**\"]\nask_paths = [\"c:/SAFE/**\"]",
    ).unwrap_err();
    assert!(e.contains("allow_paths") && e.contains("ask_paths"));
}

// --- `only_under` on a `[[program]]` entry (spec 2026-08-06 §Schema,
// §Refused shapes) ------------------------------------------------------
//
// A knowledge.toml/my-knowledge.toml concern, not a vouch.toml one — these
// four go through `vouch::guards::load` (TOML text -> `Knowledge`, the same
// helper `tests/knowledge_merge_test.rs` uses to build fixtures) and
// `vouch::knowledge::validate_place_scopes` directly, since both are `pub`
// and neither needs `load_files`'s version gating or its temp files on disk.

fn kb(text: &str) -> Knowledge {
    load(text).expect("fixture parses")
}

#[test]
fn only_under_parses_on_an_operator_entry() {
    // Today this is an unknown-key parse error (`deny_unknown_fields` on
    // `guards::Program`, which has no `only_under` field yet); after this
    // task it loads and the value round-trips.
    let mine = load("[[program]]\nmatch = [\"probe-tool\"]\nonly_under = [\"C:/scratch/**\"]\n")
        .expect("only_under must parse on an operator entry");
    let p = mine
        .program
        .iter()
        .find(|p| p.match_names.iter().any(|n| n == "probe-tool"))
        .expect("the entry itself is missing");
    assert_eq!(p.only_under.as_deref(), Some(&["C:/scratch/**".to_string()][..]));
}

#[test]
fn only_under_on_a_shipped_described_name_refuses() {
    // Scoping a name the shipped knowledge already describes would either
    // silently patch the shipped entry, or silently do nothing (the shipped
    // entry keeps recognising it everywhere) — both wrong, so it refuses.
    let shipped = kb("[[program]]\nmatch = [\"examplecmd\"]\n");
    let mine = kb("[[program]]\nmatch = [\"examplecmd\"]\nonly_under = [\"C:/scratch/**\"]\n");
    let e = validate_place_scopes(&shipped, &mine).unwrap_err();
    assert!(e.contains("examplecmd"), "the error does not name the program: {e}");
    assert!(e.contains("shipped"), "the error does not say why: {e}");
    assert!(e.contains("only_under"), "the error does not name the setting: {e}");
}

#[test]
fn a_scoped_name_on_any_second_entry_refuses() {
    // Two of the operator's OWN entries for the same name, at least one
    // scoped: the overlay would otherwise merge them into a shape nobody
    // wrote. Covers both scoped+scoped and scoped+unscoped — this one is
    // scoped+unscoped; the shipped knowledge says nothing about this name at
    // all, isolating this refusal from the shipped-collision one above.
    let shipped = Knowledge::default();
    let mine = kb(
        "[[program]]\nmatch = [\"probe-tool\"]\nonly_under = [\"C:/scratch/**\"]\n\
         [[program]]\nmatch = [\"probe-tool\"]\nwrites = \"last_arg\"\n",
    );
    let e = validate_place_scopes(&shipped, &mine).unwrap_err();
    assert!(e.contains("probe-tool"), "the error does not name the program: {e}");
    assert!(
        e.contains("one entry") && e.contains("only_under"),
        "the error does not give the one-entry-with-both-globs remedy: {e}"
    );
}

#[test]
fn a_case_varied_shipped_name_collision_still_refuses() {
    // Program names are matched case-insensitively everywhere else in the
    // codebase (`Program::same_name`, `guards::check`, `is_modeled`,
    // `recognises` all lowercase the command head before comparing) — a
    // case-varied spelling of a shipped name must not slip past the
    // shipped-collision refusal `only_under_on_a_shipped_described_name_refuses`
    // pins, the M2.26 bug class (`Entry::canonical_name`'s own doc comment).
    let shipped = kb("[[program]]\nmatch = [\"examplecmd\"]\n");
    let mine = kb("[[program]]\nmatch = [\"Examplecmd\"]\nonly_under = [\"C:/scratch/**\"]\n");
    let e = validate_place_scopes(&shipped, &mine).unwrap_err();
    assert!(e.contains("shipped"), "the error does not say why: {e}");
    assert!(e.contains("only_under"), "the error does not name the setting: {e}");
}

#[test]
fn a_case_varied_duplicate_pair_still_refuses() {
    // Same shape as `a_scoped_name_on_any_second_entry_refuses`, but the
    // second entry spells the name in a different case — the two must still
    // be recognised as ONE name, or the overlay would merge them into a
    // shape nobody wrote, silently, because a case-varied spelling looked
    // uncovered.
    let shipped = Knowledge::default();
    let mine = kb(
        "[[program]]\nmatch = [\"probe-tool\"]\nonly_under = [\"C:/scratch/**\"]\n\
         [[program]]\nmatch = [\"Probe-Tool\"]\nwrites = \"last_arg\"\n",
    );
    let e = validate_place_scopes(&shipped, &mine).unwrap_err();
    assert!(
        e.contains("one entry") && e.contains("only_under"),
        "the error does not give the one-entry-with-both-globs remedy: {e}"
    );
}

#[test]
fn an_empty_only_under_refuses() {
    // An empty list is a rule that can never apply — the same "refuse, don't
    // silently accept a no-op" rule `trust_all_under = []` follows in
    // `vouch.toml` (`an_empty_grant_list_refuses`, above).
    let shipped = Knowledge::default();
    let mine = kb("[[program]]\nmatch = [\"probe-tool\"]\nonly_under = []\n");
    let e = validate_place_scopes(&shipped, &mine).unwrap_err();
    assert!(e.contains("only_under"), "the error does not name the setting: {e}");
}

// --- `config::inert_place_rules` (Task 11, spec §Overlaps tier 2): place
// rules that can never fire because a wider or opposing rule already
// answers first. None of these six shapes refuses at load — each line is a
// legal rule on its own, and it takes a second rule in the SAME config,
// expanded against a real home and project root, to make it unreachable.

#[test]
fn a_trust_zone_inside_a_distrust_zone_is_reported_inert() {
    let cfg = config::load("[run]\ntrust_all_under = [\"D:/inbox/vetted/**\"]\ntrust_nothing_under = [\"D:/inbox/**\"]").unwrap();
    let findings = vouch::config::inert_place_rules(&cfg, "C:/Users/dev", None);
    assert_eq!(findings.len(), 1);
    assert!(findings[0].contains("trust_all_under") && findings[0].contains("can never grant"), "{}", findings[0]);
    assert!(findings[0].contains("vouch-reconcile"), "{}", findings[0]);
}

#[test]
fn an_allow_entry_entirely_inside_a_wall_is_reported_inert() {
    let cfg = config::load("[write]\nallow_paths = [\"C:/x/sub/**\"]\ndeny_paths = [\"C:/x/**\"]").unwrap();
    let findings = vouch::config::inert_place_rules(&cfg, "C:/Users/dev", None);
    assert!(findings.iter().any(|f| f.contains("allow_paths") && f.contains("deny_paths")));
}

#[test]
fn a_loosening_override_inside_a_distrust_zone_is_reported_inert() {
    let cfg = config::load(
        "[guards]\ndelete_recursive = \"ask\"\n[run]\ntrust_nothing_under = [\"D:/inbox/**\"]\n\
         [[run.guards]]\nunder = [\"D:/inbox/**\"]\ndelete_recursive = \"allow\"",
    ).unwrap();
    let findings = vouch::config::inert_place_rules(&cfg, "C:/Users/dev", None);
    assert!(findings.iter().any(|f| f.contains("run.guards")));
}

#[test]
fn disjoint_rules_report_nothing() {
    let cfg = config::load("[run]\ntrust_all_under = [\"C:/scratch/**\"]\ntrust_nothing_under = [\"D:/inbox/**\"]").unwrap();
    assert!(vouch::config::inert_place_rules(&cfg, "C:/Users/dev", None).is_empty());
}

#[test]
fn an_exact_outer_pattern_does_not_contain_a_nested_glob() {
    // Review fix: `deny_paths` here names ONE path, not a tree — nothing is
    // "under" a single file. The first version of `inert_place_rules` rooted
    // both sides the same way and compared with `starts_with`, so
    // "C:/x/exact-file/nested" (the allow entry's root) looked like it
    // started with "C:/x/exact-file" — a STRING prefix match, not a real
    // path-containment one — and flagged a rule `decide_file` still honors.
    // No `/**` on the outer means only an identical path can be "inside" it.
    let cfg = config::load(
        "[write]\nallow_paths = [\"C:/x/exact-file/nested/**\"]\ndeny_paths = [\"C:/x/exact-file\"]",
    ).unwrap();
    let findings = vouch::config::inert_place_rules(&cfg, "C:/Users/dev", None);
    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
fn a_glob_outer_pattern_does_contain_an_exact_inner_path() {
    // The other direction of the same fix, pinned so the correction above
    // does not overcorrect into never reporting anything: a REAL tree
    // (`deny_paths` ending `/**`) still swallows a single exact path
    // underneath it, exactly as it swallows a glob underneath it.
    let cfg = config::load(
        "[write]\nallow_paths = [\"C:/x/exact-file\"]\ndeny_paths = [\"C:/x/**\"]",
    ).unwrap();
    let findings = vouch::config::inert_place_rules(&cfg, "C:/Users/dev", None);
    assert!(findings.iter().any(|f| f.contains("allow_paths") && f.contains("deny_paths")), "{findings:?}");
}

#[test]
fn the_loosening_override_message_spells_the_action_the_way_the_config_does() {
    // Review fix: the message used `{action:?}`, Rust's Debug output
    // ("Allow"), not the TOML spelling an operator would type ("allow").
    let cfg = config::load(
        "[guards]\ndelete_recursive = \"ask\"\n[run]\ntrust_nothing_under = [\"D:/inbox/**\"]\n\
         [[run.guards]]\nunder = [\"D:/inbox/**\"]\ndelete_recursive = \"allow\"",
    ).unwrap();
    let findings = vouch::config::inert_place_rules(&cfg, "C:/Users/dev", None);
    let f = findings.iter().find(|f| f.contains("run.guards")).expect("the loosening finding is missing");
    assert!(f.contains("allow") && !f.contains("Allow"), "{f}");
}

#[test]
fn an_ask_entry_entirely_inside_a_wall_is_reported_inert() {
    // Correction folded into Task 11 (the comment this fixes lives in
    // `place_write_test.rs`): ask_paths/deny_paths overlap is legal at load
    // — only the three OPPOSING pairs refuse identical patterns — but an
    // ask_paths line the deny wall fully swallows can still never ask, since
    // deny is checked first every time. That is exactly the tier-2 shape the
    // other four checks cover, just for the fourth pair of lists.
    let cfg = config::load("[write]\nask_paths = [\"C:/x/sub/**\"]\ndeny_paths = [\"C:/x/**\"]").unwrap();
    let findings = vouch::config::inert_place_rules(&cfg, "C:/Users/dev", None);
    assert!(findings.iter().any(|f| f.contains("ask_paths") && f.contains("deny_paths") && f.contains("vouch-reconcile")));
}

#[test]
fn an_allow_entry_entirely_inside_the_ask_wall_is_reported_inert() {
    // The sixth shape, missing until the final whole-branch review: ask is
    // checked before allow (`decide_file_for`'s wall loop runs deny_paths
    // then ask_paths, both before allow_paths), so an allow_paths entry
    // entirely inside ask_paths is exactly as inert as one inside deny_paths
    // — the mirror of `an_allow_entry_entirely_inside_a_wall_is_reported_inert`
    // above, with the other wall list.
    let cfg = config::load("[write]\nallow_paths = [\"C:/x/sub/**\"]\nask_paths = [\"C:/x/**\"]").unwrap();
    let findings = vouch::config::inert_place_rules(&cfg, "C:/Users/dev", None);
    assert!(findings.iter().any(|f| f.contains("allow_paths") && f.contains("write.ask_paths") && f.contains("vouch-reconcile")), "{findings:?}");
}

#[test]
fn a_shadowed_two_token_scope_entry_is_reported_inert() {
    // The M2.66 fifth shape, decided during Task 9's fix round: a one-token
    // `[[write.scope]]` entry ("git") that appears BEFORE a two-token entry
    // for the same program ("git init") shadows it — vouch matches the
    // first entry that names a command, so the wider one wins for every
    // verb, including "init", and the narrower entry never separately
    // judges anything. Neither entry is refused at load
    // (`a_wider_entry_beside_a_verb_entry_is_not_refused` in
    // place_write_test.rs pins that this shape loads fine) — it is inert
    // only in THIS file order, which is doctor's job to say.
    let cfg = config::load(
        "[[write.scope]]\nprograms = [\"git\"]\nonly_under = [\"C:/scratch/**\"]\n\
         [[write.scope]]\nprograms = [\"git init\"]\nonly_under = [\"C:/work/**\"]",
    ).unwrap();
    let findings = vouch::config::inert_place_rules(&cfg, "C:/Users/dev", None);
    assert!(findings.iter().any(|f| f.contains("git") && f.contains("git init") && f.contains("vouch-reconcile")));
}

#[test]
fn a_shadowed_three_token_scope_entry_is_reported_inert() {
    // The same shape one word further in, reachable since scope entries
    // learned the second verb word: `git worktree` before `git worktree add`
    // matches every worktree operation first, so the narrower entry never
    // separately judges `worktree add`. Doctor's check is one rule — an
    // earlier entry stating strictly fewer words, all of which agree — so
    // both depths are reported by the same walk rather than by a special case
    // per depth.
    let cfg = config::load(
        "[[write.scope]]\nprograms = [\"git worktree\"]\nonly_under = [\"C:/scratch/**\"]\n\
         [[write.scope]]\nprograms = [\"git worktree add\"]\nonly_under = [\"C:/work/**\"]",
    ).unwrap();
    let findings = vouch::config::inert_place_rules(&cfg, "C:/Users/dev", None);
    assert!(
        findings.iter().any(|f| f.contains("git worktree add") && f.contains("vouch-reconcile")),
        "{findings:?}"
    );
}

#[test]
fn a_three_token_entry_before_the_wider_one_is_not_shadowed() {
    // The working file order at the new depth: the narrower entry first, so
    // it judges `worktree add` and the wider one judges the rest. No finding,
    // or doctor would flag a config that works exactly as written.
    let cfg = config::load(
        "[[write.scope]]\nprograms = [\"git worktree add\"]\nonly_under = [\"C:/scratch/**\"]\n\
         [[write.scope]]\nprograms = [\"git worktree\"]\nonly_under = [\"C:/work/**\"]",
    ).unwrap();
    let findings = vouch::config::inert_place_rules(&cfg, "C:/Users/dev", None);
    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
fn a_two_token_entry_before_a_one_token_entry_is_not_shadowed() {
    // The other file order: the two-token entry comes FIRST, so it wins for
    // its own verb and the one-token entry only ever judges the rest. This
    // is the shape `a_wider_entry_beside_a_verb_entry_is_not_refused` pins
    // as legal at load — here it must ALSO report no finding, or doctor
    // would flag a config that works exactly as written.
    let cfg = config::load(
        "[[write.scope]]\nprograms = [\"git init\"]\nonly_under = [\"C:/scratch/**\"]\n\
         [[write.scope]]\nprograms = [\"git\"]\nonly_under = [\"C:/work/**\"]",
    ).unwrap();
    let findings = vouch::config::inert_place_rules(&cfg, "C:/Users/dev", None);
    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
fn validate_place_scopes_is_wired_into_load_files() {
    // Step 3 asks for the call to be wired in exactly where
    // `validate_retraction` runs, inside `load_files`'s `Some(o) =>` arm —
    // the four tests above call `validate_place_scopes` directly, so this
    // one closes the gap and confirms the refusal actually reaches an
    // operator running vouch for real, not just the function in isolation.
    let dir = std::env::temp_dir().join(format!("vouch-place-scopes-wiring-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let shipped = dir.join("knowledge.toml");
    let mine = dir.join("my-knowledge.toml");
    std::fs::write(&shipped, &format!("version = {}\n[[program]]\nmatch = [\"examplecmd\"]\n", v())).unwrap();
    std::fs::write(&mine, "[[program]]\nmatch = [\"examplecmd\"]\nonly_under = [\"C:/scratch/**\"]\n").unwrap();
    let loaded = vouch::knowledge::load_files(&shipped, &mine);
    assert!(loaded.kb.program.is_empty(), "an ambiguous scope must fail the whole load closed: {:?}", loaded.kb.program);
    assert_eq!(loaded.gaps.len(), 1, "the refusal must be exactly one gap: {:?}", loaded.gaps);
    assert_eq!(loaded.gaps[0].source, vouch::knowledge::GapSource::MyKnowledge);
    assert_eq!(loaded.gaps[0].kind, vouch::knowledge::GapKind::PlaceScope);
    assert!(loaded.gaps[0].why.contains("examplecmd"), "the gap must name the offending entry: {:?}", loaded.gaps[0]);
    std::fs::remove_dir_all(&dir).ok();
}
