//! What happens when both files describe the same program.
//!
//! The operator's file wins, but only over the pieces they actually wrote.

use vouch::config::Action;
use vouch::guards::{entry_for, is_modeled, load, recognises, tool_entry, Knowledge, Program, Tool, ToolSnippet};
use vouch::knowledge::merge;
use vouch::syntax::Cmd;

fn kb(text: &str) -> Knowledge { load(text).expect("fixture parses") }
fn cmd(head: &str, args: &[&str]) -> Cmd {
    Cmd {
        head: head.into(),
        args: args.iter().map(|s| s.to_string()).collect(),
        chain: None,
        prefix_assigns: vec![],
    }
}
fn prog<'a>(k: &'a Knowledge, name: &str) -> &'a vouch::guards::Program {
    k.program.iter().find(|p| p.match_names.iter().any(|n| n == name)).expect("entry")
}

const BASE: &str = r#"
[[program]]
match = ["vcs"]
value_options = ["-C"]

[[program.rule]]
guard = "history_rewrite"
source = "shipped"
subcommand_in = ["reset"]
any_flag = ["--hard"]

[[program.rule]]
guard = "history_rewrite"
source = "shipped"
subcommand_in = ["push"]
any_flag = ["--force"]
"#;

#[test]
fn my_rule_for_one_subcommand_leaves_the_other_subcommands_alone() {
    let mine = r#"
[[program]]
match = ["vcs"]
[[program.rule]]
guard = "publish_outward"
source = "requested: mine"
subcommand_in = ["push"]
any_flag = ["--force"]
"#;
    let merged = merge(kb(BASE), kb(mine));
    let p = prog(&merged, "vcs");
    let resets: Vec<_> = p.rule.iter().filter(|r| r.subcommand_in == vec!["reset".to_string()]).collect();
    assert_eq!(resets.len(), 1, "the reset rule was lost");
    assert_eq!(resets[0].source, "shipped", "the reset rule was replaced");
    let pushes: Vec<_> = p.rule.iter().filter(|r| r.subcommand_in == vec!["push".to_string()]).collect();
    assert_eq!(pushes.len(), 1, "push should have one rule after replacement");
    assert_eq!(pushes[0].guard, "publish_outward", "the operator's rule did not win");
}

#[test]
fn adding_a_rule_to_a_verbless_program_does_not_delete_the_shipped_ones() {
    // [review] This is the one that mattered. Every rule with no
    // `subcommand_in` shared a key, so adding any rule wiped them all.
    // Reproduced against the real file: `rm -rf x` stopped tripping
    // delete_recursive after one unrelated rule was added.
    let base = r#"
[[program]]
match = ["wipe"]
[[program.rule]]
guard = "delete_recursive"
source = "shipped"
any_flag = ["-r"]
"#;
    let mine = r#"
[[program]]
match = ["wipe"]
[[program.rule]]
guard = "disk_or_system"
source = "requested: mine"
any_flag = ["--no-preserve-root"]
"#;
    let merged = merge(kb(base), kb(mine));
    let p = prog(&merged, "wipe");
    assert!(
        p.rule.iter().any(|r| r.guard == "delete_recursive"),
        "the shipped guard was deleted by an unrelated rule: {:?}",
        p.rule.iter().map(|r| &r.guard).collect::<Vec<_>>()
    );
    assert!(p.rule.iter().any(|r| r.guard == "disk_or_system"), "the operator's rule is missing");
}

#[test]
fn my_rule_replaces_the_shipped_one_when_it_matches_the_same_shape() {
    let base = r#"
[[program]]
match = ["wipe"]
[[program.rule]]
guard = "delete_recursive"
source = "shipped"
any_flag = ["-r"]
"#;
    let mine = r#"
[[program]]
match = ["wipe"]
[[program.rule]]
guard = "disk_or_system"
source = "requested: mine"
any_flag = ["-r"]
"#;
    let merged = merge(kb(base), kb(mine));
    let p = prog(&merged, "wipe");
    assert_eq!(p.rule.len(), 1, "same shape should replace, not accumulate: {:?}", p.rule);
    assert_eq!(p.rule[0].guard, "disk_or_system");
}

#[test]
fn the_veto_survives_the_entry_declaring_its_real_flag_vocabulary() {
    // The veto must not depend on an entry staying vocabulary-less. Under
    // `Abbrev::Accept`, `flags::spells` reads a fully-described short cluster
    // and an accepted abbreviation BOTH as "yes, exactly, no attached value"
    // — so an entry that declares its program's real no-value flags, which is
    // a true §3 statement and the obvious next improvement, would silently
    // stand the guard down on a combined token. The veto compares the token
    // itself for that reason.
    let kb = load(
        r#"
[[program]]
match = ["sig"]
case_sensitive_flags = true
no_value_options = ["-0", "-9"]

[[program.rule]]
guard = "process_control"
source = "shipped"
always = true
unless_flags = ["-0"]
"#,
    )
    .expect("fixture parses");
    let p = prog(&kb, "sig");
    let fires = |args: &[&str]| vouch::guards::rule_matches(&p.rule[0], &cmd("sig", args), p);

    assert!(!fires(&["-0", "1234"]), "the exact vetoed spelling must stand the guard down");
    assert!(
        fires(&["-09", "1234"]),
        "a described cluster is not the vetoed flag and must still trip the guard"
    );
    assert!(fires(&["-9", "1234"]), "an unvetoed flag must trip the guard");
    assert!(fires(&["-9", "-0"]), "the veto reads the FIRST argument only");
    assert!(fires(&["1234"]), "no flag at all still trips an `always` rule");
}

#[test]
fn a_veto_honours_the_entrys_own_case_sensitivity() {
    let insensitive = load(
        "[[program]]\nmatch = [\"sig\"]\n[[program.rule]]\nguard = \"process_control\"\n\
         source = \"s\"\nalways = true\nunless_flags = [\"-Q\"]\n",
    )
    .expect("fixture parses");
    let p = prog(&insensitive, "sig");
    assert!(
        !vouch::guards::rule_matches(&p.rule[0], &cmd("sig", &["-q"]), p),
        "with case-insensitive flags the veto matches either case"
    );

    let sensitive = load(
        "[[program]]\nmatch = [\"sig\"]\ncase_sensitive_flags = true\n[[program.rule]]\n\
         guard = \"process_control\"\nsource = \"s\"\nalways = true\nunless_flags = [\"-Q\"]\n",
    )
    .expect("fixture parses");
    let p = prog(&sensitive, "sig");
    assert!(
        vouch::guards::rule_matches(&p.rule[0], &cmd("sig", &["-q"]), p),
        "with case-sensitive flags the other case is a different flag (§7)"
    );
}

#[test]
fn a_rule_that_can_never_fire_is_refused_at_load() {
    // Not specific to the veto: a rule carrying only a guard and a source is
    // just as inert and was just as silent.
    // Through the FILE path, because that is where validation runs — `load`
    // alone only parses.
    let dir = std::env::temp_dir().join("vouch_inert_rule_test");
    std::fs::create_dir_all(&dir).expect("scratch dir");
    for (n, body) in [
        "[[program.rule]]\nguard = \"process_control\"\nsource = \"s\"\nunless_flags = [\"-0\"]\n",
        "[[program.rule]]\nguard = \"process_control\"\nsource = \"s\"\n",
    ]
    .iter()
    .enumerate()
    {
        let p = dir.join(format!("inert{n}.toml"));
        std::fs::write(&p, format!("[[program]]\nmatch = [\"sig\"]\n{body}")).expect("write");
        let loaded = vouch::knowledge::load_files(&p, std::path::Path::new("no-such-file.toml"));
        assert!(
            loaded.kb.program.is_empty(),
            "a rule that can never fire must fail the whole file: {:?}",
            loaded.kb.program
        );
        assert!(
            loaded.gaps.iter().any(|g| g.why.contains("never fire")),
            "the refusal must say what is wrong: {:?}",
            loaded.gaps
        );
    }
}

#[test]
fn a_rule_differing_only_by_its_veto_is_a_different_shape() {
    // `unless_flags` is part of WHAT a rule fires on, so two rules alike but
    // for the veto fire on different commands and neither may replace the
    // other. Left out of the identity key, an operator rule with no veto
    // would silently displace the shipped one that has it — for `kill` that
    // turns a liveness probe back into a prompt, with nothing said. The
    // identity key has been got wrong once before (see `rule_key`'s comment),
    // and the failure was silent then too.
    let base = r#"
[[program]]
match = ["sig"]
[[program.rule]]
guard = "process_control"
source = "shipped"
always = true
unless_flags = ["-0"]
"#;
    let mine = r#"
[[program]]
match = ["sig"]
[[program.rule]]
guard = "process_control"
source = "requested: mine"
always = true
"#;
    let merged = merge(kb(base), kb(mine));
    let p = prog(&merged, "sig");
    assert_eq!(
        p.rule.len(),
        2,
        "a rule with a veto and one without are different shapes: {:?}",
        p.rule
    );
    assert!(
        p.rule.iter().any(|r| r.unless_flags == vec!["-0".to_string()]),
        "the shipped rule's veto must survive the merge: {:?}",
        p.rule
    );
}

#[test]
fn an_entry_naming_two_programs_does_not_bleed_one_description_onto_the_other() {
    // [review] Reproduced: `match = ["rm", "cat"]` gave cat "writes all its
    // arguments" and delete_recursive, from an entry that claimed nothing.
    let base = r#"
[[program]]
match = ["wipe"]
writes = "all_args"
[[program.rule]]
guard = "delete_recursive"
source = "shipped"
any_flag = ["-r"]

[[program]]
match = ["show"]
"#;
    let mine = r#"
[[program]]
match = ["wipe", "show"]
"#;
    let merged = merge(kb(base), kb(mine));
    assert!(prog(&merged, "show").writes.is_empty(), "show was given wipe's write description");
    assert!(prog(&merged, "show").rule.is_empty(), "show was given wipe's guard");
    assert!(!prog(&merged, "wipe").writes.is_empty(), "wipe lost its own description");
}

#[test]
fn every_shipped_entry_for_a_name_is_overlaid_not_just_the_first() {
    // [review] Eight names appear in two entries each in the real file.
    let base = r#"
[[program]]
match = ["vcs"]
[[program.rule]]
guard = "history_rewrite"
source = "shipped one"
subcommand_in = ["push"]

[[program]]
match = ["vcs", "vcs2"]
[[program.rule]]
guard = "history_rewrite"
source = "shipped two"
subcommand_in = ["push"]
"#;
    let mine = r#"
[[program]]
match = ["vcs"]
[[program.rule]]
guard = "publish_outward"
source = "mine"
subcommand_in = ["push"]
"#;
    let merged = merge(kb(base), kb(mine));
    let survivors: Vec<&str> = merged.program.iter()
        .filter(|p| p.match_names.iter().any(|n| n == "vcs"))
        .flat_map(|p| p.rule.iter().map(|r| r.guard.as_str()))
        .collect();
    assert!(!survivors.contains(&"history_rewrite"), "a shipped twin survived: {survivors:?}");
    assert_eq!(survivors, vec!["publish_outward", "publish_outward"], "unexpected: {survivors:?}");
}

#[test]
fn an_operator_entry_naming_one_program_does_not_rewrite_the_others_in_the_same_shipped_entry() {
    // [review] CRITICAL, the mirror of the bleed bug above: this time the
    // SHIPPED entry names many programs and the operator entry names only
    // one. Reproduced against the real file: an operator file describing only
    // `time` silently rewrote `env`, `xargs` and the rest of the fourteen
    // programs grouped into the same shipped `[[program]]` entry, disarming
    // `delete_recursive` for `env rm -rf` and `xargs rm -rf`.
    let base = r#"
[[program]]
match = ["wipe", "show"]
writes = "all_args"
[[program.rule]]
guard = "delete_recursive"
source = "shipped"
any_flag = ["-r"]
"#;
    let mine = r#"
[[program]]
match = ["wipe"]
wraps = "after_flag"
wrap_flags = ["-o"]
wrap_lang = "bash"
"#;
    let merged = merge(kb(base), kb(mine));
    assert!(!prog(&merged, "show").writes.is_empty(), "show lost its shipped writes description");
    assert!(
        prog(&merged, "show").rule.iter().any(|r| r.guard == "delete_recursive"),
        "show lost its shipped guard: {:?}",
        prog(&merged, "show").rule
    );
    assert!(prog(&merged, "show").wraps.is_empty(), "show was given the operator's wraps claim: {:?}", prog(&merged, "show").wraps);
    assert_eq!(prog(&merged, "wipe").wraps, "after_flag", "the operator's own entry did not take effect");
}

#[test]
fn a_grammar_hint_survives_a_rule_added_for_one_subcommand() {
    let mine = r#"
[[program]]
match = ["vcs"]
[[program.rule]]
guard = "publish_outward"
source = "requested: mine"
subcommand_in = ["push"]
"#;
    let merged = merge(kb(BASE), kb(mine));
    assert_eq!(prog(&merged, "vcs").value_options, vec!["-C".to_string()], "the grammar hint was lost");
}

#[test]
fn i_can_replace_a_grammar_hint_by_writing_my_own() {
    let mine = "[[program]]\nmatch = [\"vcs\"]\nvalue_options = [\"-C\", \"--work-tree\"]\n";
    let merged = merge(kb(BASE), kb(mine));
    assert_eq!(prog(&merged, "vcs").value_options.len(), 2, "an explicit hint must win");
}

#[test]
fn recognition_is_widened_never_narrowed() {
    let base = "[[program]]\nmatch = [\"orch\"]\nsubcommands = [\"get\"]\n";
    let mine = "[[program]]\nmatch = [\"orch\"]\nsubcommands = [\"describe\"]\n";
    let merged = merge(kb(base), kb(mine));
    assert!(recognises(&merged, &cmd("orch", &["get", "x"]), "bash", true), "shipped verb was narrowed away");
    assert!(recognises(&merged, &cmd("orch", &["describe", "x"]), "bash", true), "my verb was not added");
    assert!(!recognises(&merged, &cmd("orch", &["delete", "x"]), "bash", true), "an unnamed verb became recognised");
}

#[test]
fn an_entry_that_mentions_no_subcommands_does_not_silently_widen_a_scoped_one() {
    let base = "[[program]]\nmatch = [\"orch\"]\nsubcommands = [\"get\"]\n";
    let mine = "[[program]]\nmatch = [\"orch\"]\nvalue_options = [\"--context\"]\n";
    let merged = merge(kb(base), kb(mine));
    assert!(!recognises(&merged, &cmd("orch", &["delete", "x"]), "bash", true), "scope was widened by accident");
    assert!(recognises(&merged, &cmd("orch", &["get", "x"]), "bash", true), "the shipped verb was lost");
}

#[test]
fn widening_to_the_whole_program_has_to_be_said_out_loud() {
    let base = "[[program]]\nmatch = [\"orch\"]\nsubcommands = [\"get\"]\n";
    let mine = "[[program]]\nmatch = [\"orch\"]\nall_subcommands = true\n";
    let merged = merge(kb(base), kb(mine));
    assert!(recognises(&merged, &cmd("orch", &["delete", "x"]), "bash", true), "an explicit claim was ignored");
}

#[test]
fn a_program_only_i_describe_is_added_whole() {
    let merged = merge(kb(BASE), kb("[[program]]\nmatch = [\"mytool\"]\n"));
    assert!(is_modeled(&merged, "mytool", "bash"));
    assert!(is_modeled(&merged, "vcs", "bash"));
}

#[test]
fn run_dir_flags_operator_override_and_shipped_kept_when_silent() {
    let base = "[[program]]\nmatch = [\"vcs\"]\nrun_dir_flags = [\"-C\"]\n";

    let mine_override = "[[program]]\nmatch = [\"vcs\"]\nrun_dir_flags = [\"--work-dir\"]\n";
    let merged = merge(kb(base), kb(mine_override));
    assert_eq!(
        prog(&merged, "vcs").run_dir_flags,
        vec!["--work-dir".to_string()],
        "the operator's run_dir_flags did not win"
    );

    let mine_silent = "[[program]]\nmatch = [\"vcs\"]\nvalue_options = [\"-x\"]\n";
    let merged = merge(kb(base), kb(mine_silent));
    assert_eq!(
        prog(&merged, "vcs").run_dir_flags,
        vec!["-C".to_string()],
        "the shipped run_dir_flags was dropped by an unrelated field"
    );
}

#[test]
fn no_value_options_operator_override_and_shipped_kept_when_silent() {
    let base = "[[program]]\nmatch = [\"vcs\"]\nno_value_options = [\"--verbose\"]\n";

    let mine_override = "[[program]]\nmatch = [\"vcs\"]\nno_value_options = [\"--quiet\"]\n";
    let merged = merge(kb(base), kb(mine_override));
    assert_eq!(
        prog(&merged, "vcs").no_value_options,
        vec!["--quiet".to_string()],
        "the operator's no_value_options did not win"
    );

    let mine_silent = "[[program]]\nmatch = [\"vcs\"]\nvalue_options = [\"-x\"]\n";
    let merged = merge(kb(base), kb(mine_silent));
    assert_eq!(
        prog(&merged, "vcs").no_value_options,
        vec!["--verbose".to_string()],
        "the shipped no_value_options was dropped by an unrelated field"
    );
}

// --- arg_names / writes_only_with_file_mode / wrap_join (Task 6, knowledge
// schema v4, spec 2026-08-07 python-snippets) -------------------------------

#[test]
fn arg_names_operator_override_and_shipped_kept_when_silent() {
    // Non-empty replaces, the same rule `value_options` follows.
    let base = "[[program]]\nmatch = [\"vcs\"]\narg_names = [\"path\", \"mode\"]\n";

    let mine_override = "[[program]]\nmatch = [\"vcs\"]\narg_names = [\"file\"]\n";
    let merged = merge(kb(base), kb(mine_override));
    assert_eq!(prog(&merged, "vcs").arg_names, vec!["file".to_string()], "the operator's arg_names did not win");

    let mine_silent = "[[program]]\nmatch = [\"vcs\"]\nvalue_options = [\"-x\"]\n";
    let merged = merge(kb(base), kb(mine_silent));
    assert_eq!(
        prog(&merged, "vcs").arg_names,
        vec!["path".to_string(), "mode".to_string()],
        "the shipped arg_names was dropped by an unrelated field"
    );
}

#[test]
fn writes_only_with_file_mode_kept_unset_by_an_unrelated_operator_field() {
    // Option pattern: unset means "the operator did not say", not "false" —
    // an unrelated operator field must not silently retract the shipped
    // claim.
    let base = "[[program]]\nmatch = [\"vcs\"]\nwrites_only_with_file_mode = true\narg_names = [\"path\", \"mode\"]\n";
    let mine_silent = "[[program]]\nmatch = [\"vcs\"]\nvalue_options = [\"-x\"]\n";
    let merged = merge(kb(base), kb(mine_silent));
    assert_eq!(
        prog(&merged, "vcs").writes_only_with_file_mode,
        Some(true),
        "an unrelated field silently dropped the shipped writes_only_with_file_mode claim"
    );

    let mine_override = "[[program]]\nmatch = [\"vcs\"]\nwrites_only_with_file_mode = false\n";
    let merged = merge(kb(base), kb(mine_override));
    assert_eq!(
        prog(&merged, "vcs").writes_only_with_file_mode,
        Some(false),
        "the operator's writes_only_with_file_mode did not win"
    );
}

#[test]
fn wrap_join_kept_unset_by_an_unrelated_operator_field() {
    let base = "[[program]]\nmatch = [\"vcs\"]\nwraps = \"after_flag\"\nwrap_flags = [\"-c\"]\nwrap_lang = \"bash\"\nwrap_join = true\n";
    let mine_silent = "[[program]]\nmatch = [\"vcs\"]\nvalue_options = [\"-x\"]\n";
    let merged = merge(kb(base), kb(mine_silent));
    assert_eq!(
        prog(&merged, "vcs").wrap_join,
        Some(true),
        "an unrelated field silently dropped the shipped wrap_join claim"
    );

    let mine_override = "[[program]]\nmatch = [\"vcs\"]\nwrap_join = false\n";
    let merged = merge(kb(base), kb(mine_override));
    assert_eq!(prog(&merged, "vcs").wrap_join, Some(false), "the operator's wrap_join did not win");
}

#[test]
fn a_bare_operator_sub_write_does_not_delete_the_shipped_takes_judgment() {
    // [review] An operator file written before `takes = "run_dir"` shipped for
    // bare `init` names only `subcommand = "init"`. Whole-entry replacement
    // (the old behaviour) let that silently delete the shipped judgment.
    let base = r#"
[[program]]
match = ["vcs"]
[[program.sub_write]]
subcommand = "init"
takes = "run_dir"
"#;
    let mine = r#"
[[program]]
match = ["vcs"]
[[program.sub_write]]
subcommand = "init"
"#;
    let merged = merge(kb(base), kb(mine));
    let p = prog(&merged, "vcs");
    assert_eq!(p.sub_write.len(), 1, "same key should merge, not duplicate: {:?}", p.sub_write);
    assert_eq!(p.sub_write[0].takes, "run_dir", "the bare init judgment was deleted by silence");
}

#[test]
fn an_operator_sub_write_can_still_replace_takes_and_min_positional_when_set() {
    let base = r#"
[[program]]
match = ["vcs"]
[[program.sub_write]]
subcommand = "init"
takes = "run_dir"
min_positional = 1
"#;
    let mine = r#"
[[program]]
match = ["vcs"]
[[program.sub_write]]
subcommand = "init"
takes = "first"
min_positional = 2
"#;
    let merged = merge(kb(base), kb(mine));
    let p = prog(&merged, "vcs");
    assert_eq!(p.sub_write.len(), 1);
    assert_eq!(p.sub_write[0].takes, "first", "an explicit takes must win");
    assert_eq!(p.sub_write[0].min_positional, 2, "an explicit min_positional must win");
}

#[test]
fn an_operator_sub_write_with_no_shipped_counterpart_appends() {
    let base = r#"
[[program]]
match = ["vcs"]
[[program.sub_write]]
subcommand = "init"
takes = "run_dir"
"#;
    let mine = r#"
[[program]]
match = ["vcs"]
[[program.sub_write]]
subcommand = "clone"
min_positional = 2
"#;
    let merged = merge(kb(base), kb(mine));
    let p = prog(&merged, "vcs");
    assert_eq!(p.sub_write.len(), 2, "the operator's new sub_write did not appear: {:?}", p.sub_write);
    assert!(p.sub_write.iter().any(|s| s.subcommand == "init" && s.takes == "run_dir"), "the shipped one was lost");
    assert!(p.sub_write.iter().any(|s| s.subcommand == "clone" && s.min_positional == 2), "the new one was lost");
}

#[test]
fn overlay_is_exhaustive_over_every_program_field() {
    // No `..Default::default()` on `mine` below — every field of `Program` is
    // named explicitly. If a field is ever added to the struct without an
    // overlay clause for it, this literal fails to COMPILE (missing field),
    // which is the entire point: the clause and this test are forced to move
    // together.
    let mine = vouch::guards::Program {
        match_names: vec!["p".to_string(), "q".to_string()],
        value_options: vec!["--opt".to_string()],
        run_dir_flags: vec!["--work-dir".to_string()],
        no_value_options: vec!["--flag".to_string()],
        writes: "all_args".to_string(),
        wraps: "rest".to_string(),
        write_flags: vec!["--out".to_string()],
        case_sensitive_flags: Some(true),
        wrap_flags: vec!["--wrap".to_string()],
        wrap_lang: "python".to_string(),
        flag_prefix: vec!["/".to_string()],
        evaluates_input: "always".to_string(),
        // `runs_file` and `runs_file_flags` follow the `value_options`
        // non-empty-replaces pattern (Task 17, M2.118).
        runs_file: "arg_0".to_string(),
        runs_file_flags: vec!["-m".to_string()],
        // `rebinds_name_flags` follows the same non-empty-replaces pattern
        // (Task 18, M2.113).
        rebinds_name_flags: vec!["-p".to_string()],
        // `args_from_input` is a plain bool: a false in an operator entry is
        // indistinguishable from unset, exactly like every other bare bool
        // this struct carries (Task 23, M2.116).
        args_from_input: true,
        // `here_write` follows the `value_options` non-empty-replaces
        // pattern, like every other list on this struct (Task 22, M2.129).
        // `remote_dest` is a bare bool, like `args_from_input` (Task 20,
        // M2.131.4).
        remote_dest: true,
        here_write: vec![vouch::guards::HereWrite {
            when_flags: vec!["-x".to_string()],
            unless_flags: vec!["-C".to_string()],
            subcommand: None,
            operands: None,
        }],
        rule: vec![vouch::guards::Rule {
            guard: "delete_recursive".to_string(),
            source: "requested: mine".to_string(),
            subcommand_in: vec!["rm".to_string()],
            sub_arg_0_in: vec![],
            any_flag: vec!["-r".to_string()],
            unless_flags: vec![],
            any_arg_exact: vec![],
            any_arg_prefix: vec![],
            grants_execute: false,
            always: false,
        }],
        sub_write: vec![vouch::guards::SubWrite {
            subcommand: "doit".to_string(),
            then: String::new(),
            min_positional: 2,
            takes: "last".to_string(),
        }],
        subcommands: Some(vec!["describe".to_string()]),
        all_subcommands: true,
        // `standalone_flags` follows the `value_options` non-empty-replaces
        // pattern (Task 1, spec 2026-08-20 §2/§3, knowledge schema v8).
        standalone_flags: vec!["--version".to_string()],
        // changes_dir / dest_dir_flags follow the ordinary field-level
        // pattern (Task 4, spec §2). `languages` is scoped to bash ON
        // PURPOSE — the shipped `base` below is left UNSCOPED, so this
        // exercises the case `overlay_all` has to split rather than
        // overlay whole: mine's bash-only claim must not silently narrow
        // away base's powershell coverage of the same name.
        changes_dir: Some("stated".to_string()),
        languages: vec!["bash".to_string()],
        dest_dir_flags: vec!["-Path".to_string()],
        // `only_under` follows the same Option pattern (Task 4, place-scoped
        // rules).
        only_under: Some(vec!["C:/scratch/**".to_string()]),
        // `arg_names` follows the `value_options` non-empty-replaces
        // pattern; `writes_only_with_file_mode` and `wrap_join` follow the
        // `case_sensitive_flags` Option pattern (Task 6, python-snippets).
        arg_names: vec!["file".to_string(), "mode".to_string()],
        // `callback_args` follows the same non-empty-replaces pattern as
        // `arg_names` (task 2b, M2.86 fix round).
        callback_args: vec!["cb".to_string()],
        writes_only_with_file_mode: Some(true),
        // `writes_via_handle` follows the same Option pattern (task 5,
        // M2.86, knowledge schema v5). This test exercises only the overlay
        // mechanics, not `knowledge::validate`'s exclusivity rule against
        // `writes` — `merge` never calls `validate`.
        writes_via_handle: Some("arg_1".to_string()),
        wrap_join: Some(true),
        // `named_positional` follows the same Option pattern (Task 6,
        // M2.128).
        named_positional: Some("first".to_string()),
        // `leading_args` follows the same Option pattern; `wrap_exec_flags`
        // and `wrap_exec_terminators` follow the `value_options`
        // non-empty-replaces one (Task 9, the wrapper walk). The three keys
        // belong to different `wraps` kinds and `knowledge::validate` says
        // so, but `merge` never calls `validate` — this literal exercises
        // the overlay mechanics only.
        leading_args: Some(1),
        wrap_head_flags: vec!["-FilePath".to_string()],
        wrap_exec_flags: vec!["-exec".to_string()],
        wrap_exec_terminators: vec![";".to_string()],
    };
    // The shipped side is otherwise blank, except for the two fields whose
    // documented semantics only show up against a non-empty starting point:
    // `match_names` (so there is something to overlay onto by name) and
    // `subcommands` (so `all_subcommands = true` has a scoped list to clear).
    let base = vouch::guards::Program {
        match_names: vec!["p".to_string()],
        subcommands: Some(vec!["get".to_string()]),
        ..Default::default()
    };
    let merged = merge(
        Knowledge { version: None, program: vec![base], tool: vec![], env_name: vec![] },
        Knowledge { version: None, program: vec![mine], tool: vec![], env_name: vec![] },
    );
    // `mine` only claims bash, so the entry carrying its overlay is found
    // through `entry_for` scoped to bash — the same primitive any
    // language-aware caller uses, and the only way to land on the RIGHT one
    // of the two "p" entries this merge now produces (see the powershell
    // assertion below).
    let p = entry_for(&merged, "p", "bash").expect("bash-scoped p entry");

    // match_names: deliberately NOT extended (documented at knowledge.rs
    // above `overlay`) — mine's second name "q" never arrives.
    assert_eq!(p.match_names, vec!["p".to_string()], "match_names must not be extended by an overlay");
    assert_eq!(p.value_options, vec!["--opt".to_string()], "value_options did not arrive");
    assert_eq!(p.run_dir_flags, vec!["--work-dir".to_string()], "run_dir_flags did not arrive");
    assert_eq!(p.no_value_options, vec!["--flag".to_string()], "no_value_options did not arrive");
    assert_eq!(p.writes, "all_args", "writes did not arrive");
    assert_eq!(p.wraps, "rest", "wraps did not arrive");
    assert_eq!(p.write_flags, vec!["--out".to_string()], "write_flags did not arrive");
    assert_eq!(p.case_sensitive_flags, Some(true), "case_sensitive_flags did not arrive");
    assert_eq!(p.wrap_flags, vec!["--wrap".to_string()], "wrap_flags did not arrive");
    assert_eq!(p.wrap_lang, "python", "wrap_lang did not arrive");
    assert_eq!(p.flag_prefix, vec!["/".to_string()], "flag_prefix did not arrive");
    assert_eq!(p.evaluates_input, "always", "evaluates_input did not arrive");
    assert_eq!(p.runs_file, "arg_0", "runs_file did not arrive");
    assert_eq!(p.runs_file_flags, vec!["-m".to_string()], "runs_file_flags did not arrive");
    assert_eq!(
        p.rebinds_name_flags,
        vec!["-p".to_string()],
        "rebinds_name_flags did not arrive"
    );
    assert!(p.args_from_input, "args_from_input did not arrive");
    assert!(p.remote_dest, "remote_dest did not arrive");
    assert_eq!(p.here_write.len(), 1, "here_write did not arrive");
    assert_eq!(p.here_write[0].when_flags, vec!["-x".to_string()]);
    assert_eq!(p.rule.len(), 1, "rule did not arrive: {:?}", p.rule);
    assert_eq!(p.rule[0].guard, "delete_recursive");
    assert_eq!(p.sub_write.len(), 1, "sub_write did not arrive: {:?}", p.sub_write);
    assert_eq!(p.sub_write[0].subcommand, "doit");
    // subcommands / all_subcommands: `all_subcommands` is a merge-time
    // instruction, not a persisted claim — `recognises` reads `None` as the
    // whole-program state. Its documented semantic is "widen, never
    // narrow": an explicit `all_subcommands = true` CLEARS the scoped list
    // to `None` rather than naively replacing it with mine's — "describe"
    // never arrives, and neither does the base's own "get".
    assert!(p.subcommands.is_none(), "all_subcommands should have cleared the scoped list to None: {:?}", p.subcommands);
    // standalone_flags follows the value_options non-empty-replaces pattern
    // (Task 1, knowledge schema v8).
    assert_eq!(p.standalone_flags, vec!["--version".to_string()], "standalone_flags did not arrive");
    // changes_dir / languages / dest_dir_flags: Task 4 (spec §2) wires these.
    assert_eq!(p.changes_dir, Some("stated".to_string()), "changes_dir did not arrive from mine");
    assert_eq!(p.languages, vec!["bash".to_string()], "languages did not arrive from mine");
    assert_eq!(p.dest_dir_flags, vec!["-Path".to_string()], "dest_dir_flags did not arrive from mine");
    assert_eq!(p.only_under.as_deref(), Some(&["C:/scratch/**".to_string()][..]), "only_under did not arrive from mine");
    // arg_names / writes_only_with_file_mode / wrap_join: Task 6
    // (python-snippets, knowledge schema v4).
    assert_eq!(p.arg_names, vec!["file".to_string(), "mode".to_string()], "arg_names did not arrive");
    assert_eq!(p.callback_args, vec!["cb".to_string()], "callback_args did not arrive");
    assert_eq!(p.writes_only_with_file_mode, Some(true), "writes_only_with_file_mode did not arrive");
    assert_eq!(p.writes_via_handle.as_deref(), Some("arg_1"), "writes_via_handle did not arrive");
    assert_eq!(p.wrap_join, Some(true), "wrap_join did not arrive");
    assert_eq!(p.named_positional.as_deref(), Some("first"), "named_positional did not arrive");
    // leading_args / wrap_exec_flags / wrap_exec_terminators: Task 9, the
    // wrapper walk (knowledge schema v6).
    assert_eq!(p.leading_args, Some(1), "leading_args did not arrive");
    assert_eq!(p.wrap_head_flags, vec!["-FilePath".to_string()], "wrap_head_flags did not arrive");
    assert_eq!(p.wrap_exec_flags, vec!["-exec".to_string()], "wrap_exec_flags did not arrive");
    assert_eq!(p.wrap_exec_terminators, vec![";".to_string()], "wrap_exec_terminators did not arrive");

    // The powershell portion of base's original (unscoped) claim for "p"
    // must survive untouched: mine never said anything about powershell, so
    // narrowing it away — or leaking mine's bash-only claim onto it — would
    // be the M2.26 defect recurring along the language axis.
    let leftover = entry_for(&merged, "p", "powershell").expect("powershell remainder of p was lost");
    assert_eq!(leftover.subcommands, Some(vec!["get".to_string()]), "the untouched shipped side of p was changed");
    assert!(leftover.standalone_flags.is_empty(), "mine's standalone_flags leaked into the scope mine never addressed");
    assert!(leftover.changes_dir.is_none(), "mine's changes_dir leaked into the scope mine never addressed");
    assert!(leftover.value_options.is_empty(), "mine's value_options leaked into the scope mine never addressed");
    assert!(leftover.only_under.is_none(), "mine's only_under leaked into the scope mine never addressed");
    assert!(leftover.arg_names.is_empty(), "mine's arg_names leaked into the scope mine never addressed");
    assert!(leftover.callback_args.is_empty(), "mine's callback_args leaked into the scope mine never addressed");
    assert!(
        leftover.writes_only_with_file_mode.is_none(),
        "mine's writes_only_with_file_mode leaked into the scope mine never addressed"
    );
    assert!(
        leftover.writes_via_handle.is_none(),
        "mine's writes_via_handle leaked into the scope mine never addressed"
    );
    assert!(leftover.wrap_join.is_none(), "mine's wrap_join leaked into the scope mine never addressed");
    assert!(
        leftover.named_positional.is_none(),
        "mine's named_positional leaked into the scope mine never addressed"
    );
}

#[test]
fn m2_26_a_name_beside_a_known_one_is_not_silently_dropped() {
    // docs/ROADMAP.md M2.26: `overlay_all` used to set its "did this operator
    // entry match anything" flag once per ENTRY rather than once per NAME, so
    // the instant "sudo" overlapped the shipped entry, "mytool" — which
    // shipped nowhere — had nowhere to go and silently vanished. Fixed as
    // part of generalising the remainder along the language axis (Task 4):
    // coverage is now tracked per name, so this works regardless of which
    // name in the list happens to already ship.
    let shipped = kb("[[program]]\nmatch = [\"sudo\"]\n");
    let mine = kb("[[program]]\nmatch = [\"sudo\", \"mytool\"]\n");
    let merged = merge(shipped, mine);
    assert!(is_modeled(&merged, "mytool", "bash"), "a name beside a known one was dropped");
    assert!(is_modeled(&merged, "sudo", "bash"), "the known name was lost too");
}

// --- language scoping (spec 2026-07-31 §2, Task 4) --------------------------

#[test]
fn an_unscoped_operator_entry_overlays_every_scope_and_keeps_the_remainder() {
    let shipped = load("version = 2\n[[program]]\nmatch = [\"sl\"]\nlanguages = [\"powershell\"]\nchanges_dir = \"stated\"\n").unwrap();
    let mine = load("[[program]]\nmatch = [\"sl\"]\nall_subcommands = true\n").unwrap();
    let kb = merge(shipped, mine);
    // PS scope: shipped kind survives the silent overlay.
    let ps = entry_for(&kb, "sl", "powershell").expect("ps entry");
    assert_eq!(ps.changes_dir.as_deref(), Some("stated"));
    // The bash remainder exists — today's unscoped semantics preserved.
    assert!(entry_for(&kb, "sl", "bash").is_some(), "remainder must persist, not silently drop");
    assert!(entry_for(&kb, "sl", "bash").unwrap().changes_dir.is_none());
}

// The retraction-ambiguity check (an unscoped `changes_dir = "no"` landing on
// a language-split shipped name) moved off the MERGED result and onto
// `load_files`, run on the operator's own entries against the shipped set
// BEFORE the merge (Finding 2 of the skeptical review, 2026-07-31 — the
// plan's Task 4 Interfaces were amended, commit 4666b8c, because a post-merge
// check cannot tell a deliberate per-language "no" pair from an unscoped "no"
// that got split by scope: both look identical once merged). Its tests now
// live in `tests/knowledge_source_test.rs`, beside `load_files`'s other
// validation tests, exercised through `load_files` itself rather than a
// standalone function: `an_unscoped_no_over_a_language_split_shipped_name_is_rejected`
// and its three valid-spelling neighbours.

#[test]
fn a_scoped_entry_beats_an_unscoped_one_for_the_same_name_and_language() {
    // Two entries legitimately sharing a name: an unscoped grab-bag claim and
    // an entry that names ONE language specifically. `entry_for` must prefer
    // the one that actually said "this language" — an unscoped claim reads
    // "everywhere", the weaker of the two once the caller asks about one.
    let both = kb(
        "[[program]]\nmatch = [\"cd\"]\nsubcommands = [\"get\"]\n\
         [[program]]\nmatch = [\"cd\"]\nlanguages = [\"bash\"]\nchanges_dir = \"stated\"\n",
    );
    let p = entry_for(&both, "cd", "bash").expect("bash entry");
    assert_eq!(p.changes_dir.as_deref(), Some("stated"), "the language-scoped entry should win over the unscoped one");
    // On powershell only the unscoped entry applies — it never claimed a kind.
    let ps = entry_for(&both, "cd", "powershell").expect("powershell falls back to the unscoped entry");
    assert!(ps.changes_dir.is_none());
}

#[test]
fn an_operator_entry_scoped_to_a_language_no_shipped_entry_carries_is_a_pure_remainder() {
    // No shipped entry named "z" at all, in EITHER language — the whole claim
    // is the operator's, and it must land exactly as scoped, not widen to
    // "every language" just because nothing shipped disagreed with it.
    let shipped = kb("[[program]]\nmatch = [\"zoxide\"]\n");
    let mine = kb("[[program]]\nmatch = [\"z\"]\nlanguages = [\"powershell\"]\nchanges_dir = \"unstated\"\n");
    let merged = merge(shipped, mine);
    let p = entry_for(&merged, "z", "powershell").expect("the operator's own entry");
    assert_eq!(p.changes_dir.as_deref(), Some("unstated"));
    assert!(entry_for(&merged, "z", "bash").is_none(), "a powershell-only claim must not recognise z on bash");
}

#[test]
fn is_modeled_and_recognises_respect_language_scope() {
    // `chdir` is a Set-Location alias in PowerShell and not a bash builtin at
    // all (spec §2) — an entry scoped to powershell must not leak into bash.
    let ps_only = kb("[[program]]\nmatch = [\"chdir\"]\nlanguages = [\"powershell\"]\nchanges_dir = \"stated\"\n");
    assert!(is_modeled(&ps_only, "chdir", "powershell"), "chdir must be modelled on a powershell line");
    assert!(!is_modeled(&ps_only, "chdir", "bash"), "chdir has no bash meaning and must not be modelled there");
    assert!(recognises(&ps_only, &cmd("chdir", &[]), "powershell", true), "chdir on powershell is recognised");
    assert!(!recognises(&ps_only, &cmd("chdir", &[]), "bash", true), "chdir on bash must stay unrecognised");
}

// --- skeptical review fixes, 2026-07-31 -----------------------------------

#[test]
fn an_operator_entrys_different_case_spelling_does_not_mint_a_stray_unscoped_entry() {
    // Finding 1: `overlay_all`'s `covered` map was keyed by the SHIPPED
    // entry's raw spelling at write time but looked up by the OPERATOR's raw
    // spelling at read time, and a `HashMap` key comparison does not know
    // `Program::same_name` treats `git` and `Git` as the same name. The
    // operator's differently-cased entry looked UNCOVERED even though it
    // plainly overlapped, minted a fresh unscoped `["Git"]` entry with EMPTY
    // (hence everything-recognising) `subcommands`, and flipped
    // `recognises("git push")` from false to true — reproduced by the
    // reviewer with a scratch crate. `covered` is now keyed by
    // `Entry::canonical_name`, the same form `same_name` compares.
    let shipped = kb("[[program]]\nmatch = [\"git\"]\nsubcommands = [\"status\"]\n");
    let mine = kb("[[program]]\nmatch = [\"Git\"]\nvalue_options = [\"-C\"]\n");
    let merged = merge(shipped, mine);
    assert!(
        !recognises(&merged, &cmd("git", &["push"]), "bash", true),
        "a differently-cased operator spelling minted a stray unscoped entry that recognised everything"
    );
    assert!(recognises(&merged, &cmd("git", &["status"]), "bash", true), "the shipped verb was lost");
}

#[test]
fn entry_for_is_first_wins_for_a_merge_produced_duplicate() {
    // Finding 3: `entry_for`'s doc comment used to claim duplicates "should
    // never exist after a merge". False — the shipped file already groups
    // several names into two `[[program]]` entries each (`sudo`, `doas`,
    // `runas`, `find`, `dd`), and an operator entry naming one of those names
    // overlays BOTH shipped entries independently (`overlay_all` splits by
    // NAME, not by "is this the same underlying program"), legitimately
    // producing two same-name, same-scope entries. `entry_for` must pick the
    // FIRST one in file order, deterministically — load-bearing for Task 6's
    // `dir_change_kind`, which reads a single entry's `changes_dir` through
    // this function.
    let shipped = kb(
        "[[program]]\nmatch = [\"dd\", \"partner-a\"]\nwrites = \"first-entry\"\n\
         [[program]]\nmatch = [\"dd\", \"partner-b\"]\nwrites = \"second-entry\"\n",
    );
    let mine = kb("[[program]]\nmatch = [\"dd\"]\nall_subcommands = true\n");
    let merged = merge(shipped, mine);
    let matches: Vec<&Program> = merged.program.iter().filter(|p| p.match_names.iter().any(|n| n == "dd")).collect();
    assert!(matches.len() >= 2, "expected the merge to keep both shipped dd entries, got {}", matches.len());
    let p = entry_for(&merged, "dd", "bash").expect("dd entry");
    assert_eq!(p.writes, "first-entry", "entry_for must deterministically pick the FIRST dd entry in file order");
}

// --- server entries have a merge identity (spec 2026-08-05, Task 3) --------
//
// A `server = "..."` entry names no individual tool (`match` is empty), so it
// has no name for `overlay_all` to key coverage on unless it is given one.
// Without a merge identity, an operator's server entry either collides with
// every other server-less entry (all sharing the empty `match_names` list)
// or — the actual old behaviour before this task — is treated as having no
// name at all and is silently dropped by the merge the moment ANY shipped
// tool entry exists, because `overlay_all`'s per-name remainder logic has
// nothing to iterate over.

#[test]
fn a_server_entry_is_not_dropped_by_the_merge() {
    let base = load(
        r#"version = 3
[[tool]]
match = ["SomeTool"]
source = "shipped""#,
    )
    .expect("fixture parses");
    let mine = load(
        r#"[[tool]]
server = "mcp__p_s"
source = "operator grant""#,
    )
    .expect("fixture parses");
    let merged = merge(base, mine);
    assert!(
        merged.tool.iter().any(|t| t.server.as_deref() == Some("mcp__p_s")),
        "the server entry vanished from the merge: {:?}",
        merged.tool.iter().map(|t| (&t.match_names, &t.server)).collect::<Vec<_>>()
    );
}

#[test]
fn operator_server_entry_overlays_shipped_server_entry_field_by_field() {
    let base = kb(r#"[[tool]]
server = "mcp__p_s"
source = "shipped"
action = "ask"
"#);
    let mine = kb(r#"[[tool]]
server = "mcp__p_s"
action = "deny"
"#);
    let merged = merge(base, mine);
    let matches: Vec<&Tool> = merged.tool.iter().filter(|t| t.server.as_deref() == Some("mcp__p_s")).collect();
    assert_eq!(matches.len(), 1, "expected one merged server entry, got {:?}", matches);
    assert_eq!(matches[0].source, "shipped", "source was overwritten by the operator's silence");
    assert_eq!(matches[0].action, Some(Action::Deny), "the operator's action did not win");
}

#[test]
fn tool_snippet_absent_keeps_shipped_snippet() {
    let base = kb(
        "[[tool]]\nmatch = [\"Bash\"]\nsource = \"shipped\"\n\n\
         [[tool.snippet]]\nfield = \"command\"\nlanguage = \"bash\"\n",
    );
    let mine = kb("[[tool]]\nmatch = [\"Bash\"]\nsource = \"mine\"\n");
    let merged = merge(base, mine);
    let t = merged.tool.iter().find(|t| t.match_names.iter().any(|n| n == "Bash")).expect("tool entry");
    assert!(t.snippet.is_some(), "the shipped snippet was dropped by an operator entry that never mentioned it");
    let snippet = t.snippet.as_ref().unwrap();
    assert_eq!(snippet.len(), 1);
    assert_eq!(snippet[0].field, "command");
    assert_eq!(t.source, "mine", "the operator's own source did not win");
}

#[test]
fn tool_snippet_present_replaces_the_shipped_list_whole() {
    // The other half of the Option rule `overlay_tool` documents: an operator
    // entry that DOES set `snippet` is describing the whole set of inspected
    // fields, not patching one entry into the shipped list. Two shipped
    // fields ("a", "b") plus one operator field ("c") must land as exactly
    // ["c"] - not a union, not an append.
    let base = kb(
        "[[tool]]\nmatch = [\"t\"]\nsource = \"shipped\"\n\n\
         [[tool.snippet]]\nfield = \"a\"\nlanguage = \"bash\"\n\n\
         [[tool.snippet]]\nfield = \"b\"\nlanguage = \"bash\"\n",
    );
    let mine = kb(
        "[[tool]]\nmatch = [\"t\"]\nsource = \"mine\"\n\n\
         [[tool.snippet]]\nfield = \"c\"\nlanguage = \"python\"\n",
    );
    let merged = merge(base, mine);
    let t = tool_entry(&merged, "t").expect("tool entry");
    let snippet = t.snippet.as_ref().expect("snippet did not arrive");
    assert_eq!(
        snippet.len(),
        1,
        "the operator's own snippet list must replace the shipped one whole, not merge into it: {:?}",
        snippet.iter().map(|p| &p.field).collect::<Vec<_>>()
    );
    assert_eq!(snippet[0].field, "c", "the operator's field did not win");
}

#[test]
fn write_path_field_and_cwd_from_call_present_replace_the_shipped_values() {
    let base = kb(
        "[[tool]]\nmatch = [\"t\"]\nsource = \"shipped\"\n\
         write_path_field = \"old\"\ncwd_from_call = false\n",
    );
    let mine = kb(
        "[[tool]]\nmatch = [\"t\"]\nsource = \"mine\"\n\
         write_path_field = \"new\"\ncwd_from_call = true\n",
    );
    let merged = merge(base, mine);
    let t = tool_entry(&merged, "t").expect("tool entry");
    assert_eq!(t.write_path_field.as_deref(), Some("new"), "write_path_field was not replaced");
    assert_eq!(t.cwd_from_call, Some(true), "cwd_from_call was not replaced");
}

#[test]
fn overlay_is_exhaustive_over_every_tool_field() {
    // Mirrors `overlay_is_exhaustive_over_every_program_field` above. No
    // `..Default::default()` on `mine` below - every field of `Tool` is named
    // explicitly. If a field is ever added to the struct without an overlay
    // clause for it (`overlay_tool` in src/knowledge.rs), this literal fails
    // to COMPILE (missing field), which is the entire point: the clause and
    // this test are forced to move together. `overlay_tool`'s own doc
    // comment records this exact class of defect happening once already - an
    // operator entry silently deleting a shipped `action = "ask"` because a
    // field was appended-whole instead of overlaid.
    let mine = Tool {
        match_names: vec!["t".to_string()],
        source: "requested: mine".to_string(),
        action: Some(Action::Deny),
        snippet: Some(vec![ToolSnippet {
            field: "code".to_string(),
            language: Some("python".to_string()),
            language_from: None,
            language_values: None,
        }]),
        write_path_field: Some("path".to_string()),
        cwd_from_call: Some(true),
        server: None,
        merge_names: Vec::new(),
    };
    let base = Tool { match_names: vec!["t".to_string()], ..Default::default() };
    let merged = merge(
        Knowledge { version: None, program: vec![], tool: vec![base], env_name: vec![] },
        Knowledge { version: None, program: vec![], tool: vec![mine], env_name: vec![] },
    );
    let t = tool_entry(&merged, "t").expect("t entry");

    assert_eq!(t.match_names, vec!["t".to_string()], "match_names must not be extended by an overlay");
    assert_eq!(t.source, "requested: mine", "source did not arrive");
    assert_eq!(t.action, Some(Action::Deny), "action did not arrive");
    let snippet = t.snippet.as_ref().expect("snippet did not arrive");
    assert_eq!(snippet.len(), 1, "snippet did not arrive: {:?}", snippet.iter().map(|p| &p.field).collect::<Vec<_>>());
    assert_eq!(snippet[0].field, "code");
    assert_eq!(snippet[0].language.as_deref(), Some("python"));
    assert_eq!(t.write_path_field.as_deref(), Some("path"), "write_path_field did not arrive");
    assert_eq!(t.cwd_from_call, Some(true), "cwd_from_call did not arrive");
    // `server` is identity, not a claim to lay - `mine.server` here is `None`
    // by construction (a match entry), so this only confirms `overlay_tool`
    // never touches it; the merge identity discipline itself is exercised by
    // the server-entry tests below.
    assert!(t.server.is_none(), "server must be left alone by the overlay");
}

// --- the overlay matrix, pinned cell by cell (spec 2026-08-20 §3, Task 2) --
//
// `base` is the shipped entry, `mine` the operator's. Every cell of the
// three-state `subcommands` merge matrix gets its own test, so no later
// rework can bend a cell silently. Base or operator entries that state an
// explicit `subcommands = []` also carry `standalone_flags` and
// `case_sensitive_flags` so they stay loadable once a later task refuses
// the bare empty spelling (spec §4, the inert-entry refusal).

#[test]
fn a_verb_list_laid_over_a_whole_program_entry_does_not_narrow_it() {
    // base None x mine Some(list): mine cannot narrow a shipped
    // whole-program entry (spec §3; the round-2 adversarial cell).
    let base = kb("[[program]]\nmatch = [\"zz\"]\n");
    let mine = kb("[[program]]\nmatch = [\"zz\"]\nsubcommands = [\"go\"]\n");
    let merged = merge(base, mine);
    assert_eq!(prog(&merged, "zz").subcommands, None, "a verb list narrowed a shipped whole-program entry");
}

#[test]
fn an_explicit_empty_list_laid_over_a_whole_program_entry_does_not_narrow_it() {
    // base None x mine Some(empty)+flags: still whole program.
    let base = kb("[[program]]\nmatch = [\"zz\"]\n");
    let mine = kb(
        "[[program]]\nmatch = [\"zz\"]\nsubcommands = []\nstandalone_flags = [\"--v\"]\ncase_sensitive_flags = true\n",
    );
    let merged = merge(base, mine);
    let p = prog(&merged, "zz");
    assert_eq!(p.subcommands, None, "an explicit empty list narrowed a shipped whole-program entry");
    assert_eq!(p.standalone_flags, vec!["--v".to_string()], "the field-replace clause did not still land");
}

#[test]
fn an_explicit_empty_list_against_shipped_verbs_keeps_the_verbs() {
    // base Some(list) x mine Some(empty): no-op union, base list stands.
    let base = kb("[[program]]\nmatch = [\"zz\"]\nsubcommands = [\"go\"]\n");
    let mine = kb(
        "[[program]]\nmatch = [\"zz\"]\nsubcommands = []\nstandalone_flags = [\"--v\"]\ncase_sensitive_flags = true\n",
    );
    let merged = merge(base, mine);
    assert_eq!(
        prog(&merged, "zz").subcommands,
        Some(vec!["go".to_string()]),
        "an explicit empty operator list discarded the shipped verbs"
    );
}

#[test]
fn verbs_laid_over_a_shipped_standalone_only_entry_widen_it() {
    // base Some(empty) x mine Some(list): union widens the narrow entry.
    let base = kb(
        "[[program]]\nmatch = [\"zz\"]\nsubcommands = []\nstandalone_flags = [\"--v\"]\ncase_sensitive_flags = true\n",
    );
    let mine = kb("[[program]]\nmatch = [\"zz\"]\nsubcommands = [\"go\"]\n");
    let merged = merge(base, mine);
    assert_eq!(
        prog(&merged, "zz").subcommands,
        Some(vec!["go".to_string()]),
        "an operator verb list did not widen a shipped standalone-only entry"
    );
}

#[test]
fn all_subcommands_still_clears_to_whole_program() {
    let base = kb("[[program]]\nmatch = [\"zz\"]\nsubcommands = [\"go\"]\n");
    let mine = kb("[[program]]\nmatch = [\"zz\"]\nall_subcommands = true\n");
    let merged = merge(base, mine);
    assert_eq!(
        prog(&merged, "zz").subcommands,
        None,
        "all_subcommands = true did not clear a scoped list to the whole-program state"
    );
}

#[test]
fn operator_standalone_flags_replace_shipped_ones_whole() {
    let base = kb("[[program]]\nmatch = [\"zz\"]\nstandalone_flags = [\"--a\"]\n");
    let mine = kb("[[program]]\nmatch = [\"zz\"]\nstandalone_flags = [\"--b\"]\n");
    let merged = merge(base, mine);
    assert_eq!(
        prog(&merged, "zz").standalone_flags,
        vec!["--b".to_string()],
        "the operator's standalone_flags did not replace the shipped ones whole"
    );
}

#[test]
fn the_scope_split_carries_standalone_flags_without_leaking() {
    // The language-scope split does not leak the new field (pattern at
    // tests/knowledge_merge_test.rs:759-777): an unscoped shipped entry, an
    // operator entry scoped to bash only. The powershell remainder must not
    // pick up mine's standalone_flags.
    let base = kb("[[program]]\nmatch = [\"zz\"]\n");
    let mine = kb(
        "[[program]]\nmatch = [\"zz\"]\nlanguages = [\"bash\"]\nstandalone_flags = [\"--v\"]\ncase_sensitive_flags = true\n",
    );
    let merged = merge(base, mine);
    let bash = entry_for(&merged, "zz", "bash").expect("bash-scoped zz entry");
    assert_eq!(bash.standalone_flags, vec!["--v".to_string()], "standalone_flags did not arrive on the scoped side");
    let ps = entry_for(&merged, "zz", "powershell").expect("powershell remainder of zz was lost");
    assert!(ps.standalone_flags.is_empty(), "mine's standalone_flags leaked into the scope mine never addressed");
}

#[test]
fn an_absent_mine_keeps_a_shipped_verb_list() {
    // base Some(["go"]) x mine key-absent -> Some(["go"]).
    let base = kb("[[program]]\nmatch = [\"zz\"]\nsubcommands = [\"go\"]\n");
    let mine = kb("[[program]]\nmatch = [\"zz\"]\n");
    let merged = merge(base, mine);
    assert_eq!(
        prog(&merged, "zz").subcommands,
        Some(vec!["go".to_string()]),
        "a mine entry silent on subcommands dropped the shipped verb list"
    );
}

#[test]
fn an_absent_mine_keeps_a_shipped_standalone_only_entry() {
    // base Some([]) (+flags+case key) x mine key-absent -> Some([]).
    let base = kb(
        "[[program]]\nmatch = [\"zz\"]\nsubcommands = []\nstandalone_flags = [\"--v\"]\ncase_sensitive_flags = true\n",
    );
    let mine = kb("[[program]]\nmatch = [\"zz\"]\n");
    let merged = merge(base, mine);
    assert_eq!(
        prog(&merged, "zz").subcommands,
        Some(Vec::<String>::new()),
        "a mine entry silent on subcommands widened a shipped standalone-only entry away from its narrow state"
    );
}

#[test]
fn two_explicit_empty_lists_stay_empty() {
    // base Some([]) (+flags+case key) x mine Some([]) -> Some([]).
    let base = kb(
        "[[program]]\nmatch = [\"zz\"]\nsubcommands = []\nstandalone_flags = [\"--v\"]\ncase_sensitive_flags = true\n",
    );
    let mine = kb(
        "[[program]]\nmatch = [\"zz\"]\nsubcommands = []\nstandalone_flags = [\"--v\"]\ncase_sensitive_flags = true\n",
    );
    let merged = merge(base, mine);
    assert_eq!(
        prog(&merged, "zz").subcommands,
        Some(Vec::<String>::new()),
        "two explicit empty lists did not stay empty"
    );
}
