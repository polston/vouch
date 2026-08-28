mod common;

use common::{config_text_with, hook_bash_at, hook_bash_at_env, v};

const HOME: &str = "C:/Users/dev";

fn config() -> String {
    config_text_with(&[
        ("bash", "unmodeled_command", "ask"),
        ("python", "unresolved_path", "ask"),
        ("python", "evaluated_input", "ask"),
        ("python", "dynamic_call", "ask"),
        ("python", "unmodeled_command", "ask"),
    ])
}

fn empty_overlay() -> String {
    format!("version = {}\n", v())
}

fn decide(tag: &str, command: &str) -> (String, String) {
    hook_bash_at(tag, &empty_overlay(), &config(), HOME, command)
}

fn assert_allows(tag: &str, command: &str) {
    let (verdict, reason) = decide(tag, command);
    assert_eq!(verdict, "allow", "{command}\n{reason}");
}

fn assert_unresolved(tag: &str, command: &str) {
    let (verdict, reason) = decide(tag, command);
    assert_eq!(verdict, "ask", "{command}\n{reason}");
    assert!(reason.contains("unresolved_path"), "{command}\n{reason}");
}

#[test]
fn direct_assigned_and_keyword_references_use_the_declared_trailing_vector() {
    assert_allows(
        "python-argv-direct",
        r#"python -c "import sys; open(sys.argv[1], 'w')" C:/work/direct.txt"#,
    );
    assert_allows(
        "python-argv-assigned",
        r#"python -c "import sys; target = sys.argv[1]; open(target, 'w')" C:/work/assigned.txt"#,
    );
    assert_allows(
        "python-argv-keyword",
        r#"python -c "import sys; open(file=sys.argv[1], mode='w')" C:/work/keyword.txt"#,
    );
    assert_allows(
        "python-argv-two-trailing",
        r#"python -c "import shutil, sys; shutil.copyfile(sys.argv[1], sys.argv[2])" C:/input/source.txt C:/work/copied.txt"#,
    );
}

#[test]
fn separate_attached_and_clustered_code_flags_share_one_argument_layout() {
    assert_allows(
        "python-argv-separate",
        r#"python -c "import sys; open(sys.argv[1], 'w')" C:/work/separate.txt"#,
    );
    assert_allows(
        "python-argv-attached",
        r#"python '-cimport sys; open(sys.argv[1], "w")' C:/work/attached.txt"#,
    );
    assert_allows(
        "python-argv-clustered",
        r#"python -Sc "import sys; open(sys.argv[1], 'w')" C:/work/clustered.txt"#,
    );
}

#[test]
fn raw_outer_variables_reach_the_existing_fixed_point_resolver() {
    assert_allows(
        "python-argv-same-line-variable",
        r#"ARG=C:/work/same-line.txt; python -c "import sys; open(sys.argv[1], 'w')" "$ARG""#,
    );

    let (verdict, reason) = hook_bash_at_env(
        "python-argv-environment-variable",
        &empty_overlay(),
        &config(),
        HOME,
        r#"python -c "import sys; open(sys.argv[1], 'w')" "$M2107_ARG""#,
        &[("M2107_ARG", "C:/work/environment.txt")],
    );
    assert_eq!(verdict, "allow", "{reason}");
}

#[test]
fn missing_dynamic_and_incomplete_arguments_remain_unresolved() {
    assert_unresolved(
        "python-argv-missing",
        r#"python -c "import sys; open(sys.argv[2], 'w')" C:/work/only-one.txt"#,
    );
    assert_unresolved(
        "python-argv-dynamic",
        r#"python -c "import sys; index = 1; open(sys.argv[index], 'w')" C:/work/dynamic.txt"#,
    );
    assert_unresolved(
        "python-argv-dynamic-reassignment",
        r#"python -c "import sys; target = sys.argv[1]; target = compute(); open(target, 'w')" C:/work/stale.txt"#,
    );
    assert_unresolved(
        "python-argv-incomplete",
        r#"python -c "import sys; open(sys.argv[1], 'w')" <(printf C:/work/hidden.txt)"#,
    );
}

#[test]
fn channel_appended_arguments_withhold_every_mapping() {
    assert_unresolved(
        "python-argv-channel-appended",
        r#"printf C:/work/appended.txt | xargs python -c "import sys; open(sys.argv[1], 'w')" C:/work/explicit.txt"#,
    );
}

#[test]
fn absent_and_retracted_layouts_remain_unresolved() {
    let undeclared = format!(
        "version = {}\n\
         [[program]]\n\
         match = [\"interpreter\"]\n\
         wraps = \"after_flag\"\n\
         wrap_flags = [\"-c\"]\n\
         wrap_lang = \"python\"\n\
         value_options = [\"-c\"]\n\
         case_sensitive_flags = true\n",
        v()
    );
    let (verdict, reason) = hook_bash_at(
        "python-argv-undeclared-layout",
        &undeclared,
        &config(),
        HOME,
        r#"interpreter -c "import sys; open(sys.argv[1], 'w')" C:/work/undeclared.txt"#,
    );
    assert_eq!(verdict, "ask", "{reason}");
    assert!(reason.contains("unresolved_path"), "{reason}");

    let retracted = format!(
        "version = {}\n[[program]]\nmatch = [\"python\", \"python3\", \"py\"]\nsnippet_args = []\n",
        v()
    );
    let (verdict, reason) = hook_bash_at(
        "python-argv-retracted-layout",
        &retracted,
        &config(),
        HOME,
        r#"python -c "import sys; open(sys.argv[1], 'w')" C:/work/retracted.txt"#,
    );
    assert_eq!(verdict, "ask", "{reason}");
    assert!(reason.contains("unresolved_path"), "{reason}");
}

#[test]
fn a_custom_declared_indexed_name_uses_the_same_generic_join() {
    let declared = format!(
        "version = {}\n\
         [[program]]\n\
         match = [\"interpreter\"]\n\
         wraps = \"after_flag\"\n\
         wrap_flags = [\"-c\"]\n\
         wrap_lang = \"python\"\n\
         value_options = [\"-c\"]\n\
         case_sensitive_flags = true\n\
         snippet_args = [{{ name = \"payload.items\", source_at = 0, trailing_from = 1 }}]\n",
        v()
    );
    let (verdict, reason) = hook_bash_at(
        "python-argv-custom-indexed-name",
        &declared,
        &config(),
        HOME,
        r#"interpreter -c "open(payload.items[1], 'w')" C:/work/generic.txt"#,
    );
    assert_eq!(verdict, "allow", "{reason}");
}

#[test]
fn an_ungated_tool_snippet_does_not_inherit_interpreter_arguments() {
    let kb = common::kb_with(
        r#"
[[tool]]
match = ["mcp__p_s__py"]
source = "runs the `code` field as python"
[[tool.snippet]]
field = "code"
language = "python"
"#,
    );
    let cfg = vouch::config::load(&config()).expect("config parses");
    let input = vouch::protocol::parse_input(
        r#"{"session_id":"s","cwd":"C:/Users/dev","tool_name":"mcp__p_s__py","tool_input":{"code":"import sys; open(sys.argv[1], 'w')"}}"#,
    )
    .expect("tool fixture parses");
    let outcome = vouch::route::decide(&cfg, &kb, HOME, &input);
    let vouch::protocol::Decision::Ask(reason) = outcome.decision else {
        panic!("an ungated tool's unconnected indexed value did not ask")
    };
    assert!(reason.contains("unresolved_path"), "{reason}");
}

#[test]
fn explicit_dash_held_input_maps_trailing_arguments() {
    assert_allows(
        "python-argv-held-input",
        r#"python - C:/work/held.txt <<'PY'
import sys
open(sys.argv[1], 'w')
PY
"#,
    );
}

#[test]
fn source_index_zero_maps_the_declared_spelling_for_inline_and_held_input() {
    fn expanded(source: &str) -> vouch::guards::ExpandedWrappers {
        let scan = vouch::syntax::scanner_for("bash")
            .expect("bash scanner exists")
            .scan(source)
            .unwrap_or_else(|error| panic!("fixture does not parse: {error}"));
        vouch::guards::expand_wrappers_with_sources(
            &common::shipped_kb(),
            &scan.commands,
            &scan.heredocs,
            &scan.input_source,
            &scan.args_complete,
            "bash",
            &|_| 4,
        )
    }

    for (source, expected) in [
        (r#"python -c "import sys; open(sys.argv[0], 'w')""#, "-c"),
        (
            "python - C:/work/unused.txt <<'PY'\nimport sys\nopen(sys.argv[0], 'w')\nPY\n",
            "-",
        ),
    ] {
        let expansion = expanded(source);
        let (index, command) = expansion
            .cmds
            .iter()
            .enumerate()
            .find(|(index, command)| {
                command.head.ends_with("open")
                    && expansion.langs.get(*index).is_some_and(|language| language == "python")
            })
            .expect("the Python open call was expanded");
        assert_eq!(command.args.first().map(String::as_str), Some(expected));
        assert!(!command.unread_args.contains(&0), "source mapping stayed unread at command {index}");
    }
}

#[test]
fn invalid_held_input_sources_and_records_remain_fail_closed() {
    for (tag, command) in [
        (
            "python-argv-no-source-spelling",
            "python <<'PY'\nimport sys\nopen(sys.argv[1], 'w')\nPY\n",
        ),
        (
            "python-argv-script-file",
            "python script.py C:/work/not-used.txt <<'PY'\nimport sys\nopen(sys.argv[1], 'w')\nPY\n",
        ),
        (
            "python-argv-module-source",
            "python -m package C:/work/not-used.txt <<'PY'\nimport sys\nopen(sys.argv[1], 'w')\nPY\n",
        ),
        (
            "python-argv-competing-input",
            "python - C:/work/not-used.txt <<'PY' < C:/work/source.py\nimport sys\nopen(sys.argv[1], 'w')\nPY\n",
        ),
        (
            "python-argv-modified-body",
            "python - C:/work/not-used.txt <<PY\nimport sys\nopen(sys.argv[1], 'w')\n# $M2107_BODY\nPY\n",
        ),
    ] {
        let (verdict, reason) = decide(tag, command);
        assert_eq!(verdict, "ask", "{command}\n{reason}");
    }
}

#[test]
fn marker_text_nested_wrappers_and_parse_failures_keep_their_polarity() {
    let marker = r#"python -c "open('$?', 'w')" C:/work/must-not-substitute.txt"#;
    let (verdict, reason) = decide("python-argv-marker-text", marker);
    assert_eq!(verdict, "ask", "{marker}\n{reason}");

    assert_allows(
        "python-argv-nested-wrapper",
        r#"sh -c "python -c 'import sys; open(sys.argv[1], \"w\")' C:/work/nested.txt""#,
    );

    let broken = r#"python -c "def broken(:" C:/work/not-used.txt"#;
    let (verdict, reason) = decide("python-argv-parse-failure", broken);
    assert_eq!(verdict, "ask", "{broken}\n{reason}");
    assert!(reason.contains("parse_failure"), "{reason}");
}

#[test]
fn unknown_programs_and_protected_targets_remain_closed() {
    let unknown = r#"unknown-interpreter -c "import sys; open(sys.argv[1], 'w')" C:/work/unknown.txt"#;
    let (verdict, reason) = decide("python-argv-unknown-program", unknown);
    assert_eq!(verdict, "ask", "{unknown}\n{reason}");
    assert!(reason.contains("unmodeled_command"), "{reason}");

    let wall_config = config().replacen(
        "[write]\ndefault = \"ask\"\n",
        "[write]\ndefault = \"ask\"\nask_paths = [\"C:/work/wall/**\"]\n",
        1,
    );
    let wall = r#"python -c "import sys; open(sys.argv[1], 'w')" C:/work/wall/blocked.txt"#;
    let (verdict, reason) = hook_bash_at(
        "python-argv-write-wall",
        &empty_overlay(),
        &wall_config,
        HOME,
        wall,
    );
    assert_eq!(verdict, "ask", "{wall}\n{reason}");
    assert!(!reason.contains("unresolved_path"), "the wall target was never resolved: {reason}");
}

#[test]
fn resolved_outside_targets_still_meet_write_policy() {
    let command = r#"python -c "import sys; open(sys.argv[1], 'w')" C:/outside/not-allowed.txt"#;
    let (verdict, reason) = decide("python-argv-outside-write", command);
    assert_eq!(verdict, "ask", "{command}\n{reason}");
    assert!(!reason.contains("unresolved_path"), "the mapping never reached write policy: {reason}");
}
