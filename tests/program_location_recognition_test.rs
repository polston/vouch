use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use vouch::engine::{decide_command_at, decide_command_in_unknown_dir};
use vouch::protocol::Decision;

fn scratch(tag: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "vouch-program-recognition-{tag}-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).unwrap();
    fs::canonicalize(dir).unwrap()
}

fn path(path: &Path) -> String {
    let text = path.to_string_lossy().replace('\\', "/");
    text.strip_prefix("//?/").unwrap_or(&text).to_string()
}

fn cfg_with(
    under: &str,
    name_patterns: &[&str],
    extra: &str,
    run_settings: &str,
) -> vouch::config::Config {
    let names = name_patterns
        .iter()
        .map(|name| format!("\"{name}\""))
        .collect::<Vec<_>>()
        .join(", ");
    vouch::config::load(&format!(
        "[lang.bash]\ndefault = \"allow\"\n[lang.bash.constructs]\n\
         unmodeled_command = \"ask\"\n[lang.powershell]\ndefault = \"allow\"\n\
         [lang.powershell.constructs]\nunmodeled_command = \"ask\"\n\
         {extra}\n[run]\n{run_settings}\n\
         [[run.trust_program]]\n\
         under = [\"{under}\"]\nname_patterns = [{names}]\n"
    ))
    .unwrap()
}

fn cfg(under: &str, name_patterns: &[&str]) -> vouch::config::Config {
    cfg_with(under, name_patterns, "", "")
}

fn decide_path(
    cfg: &vouch::config::Config,
    program: &Path,
    args: &str,
    cwd: Option<&Path>,
) -> Decision {
    let context = cwd.map(path);
    decide_command_at(
        cfg,
        "bash",
        &format!("{} {args}", path(program)),
        context.as_deref(),
        None,
        context.as_deref(),
    )
}

#[test]
fn an_existing_path_under_the_tree_with_a_matching_name_is_recognised() {
    let root = scratch("positive");
    let bin = root.join("bin");
    fs::create_dir(&bin).unwrap();
    let program = bin.join("probe-alpha");
    fs::write(&program, b"fixture").unwrap();
    let cfg = cfg(&format!("{}/**", path(&root)), &["probe", "probe-*"]);

    let decision = decide_path(&cfg, &program, "inspect", Some(&root));

    match decision {
        Decision::Allow(reason) => {
            assert!(reason.contains("[[run.trust_program]] #1"), "{reason}");
            assert!(reason.contains("probe-*"), "{reason}");
            assert!(reason.contains(&format!("{}/**", path(&root))), "{reason}");
            assert!(
                reason.contains("guards and write rules still apply"),
                "{reason}"
            );
        }
        other => panic!("matching location and name must recognise the program: {other:?}"),
    }

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn location_and_name_are_both_required() {
    let root = scratch("both-clauses");
    let outside = scratch("outside");
    let wrong_name = root.join("other-alpha");
    let wrong_place = outside.join("probe-alpha");
    fs::write(&wrong_name, b"fixture").unwrap();
    fs::write(&wrong_place, b"fixture").unwrap();
    let cfg = cfg(&format!("{}/**", path(&root)), &["probe-*"]);

    for program in [&wrong_name, &wrong_place] {
        let decision = decide_path(&cfg, program, "inspect", Some(&root));
        assert!(
            matches!(decision, Decision::Ask(_)),
            "{program:?}: {decision:?}"
        );
    }

    fs::remove_dir_all(root).unwrap();
    fs::remove_dir_all(outside).unwrap();
}

#[test]
fn sibling_prefix_missing_directory_unknown_cwd_and_bare_heads_do_not_match() {
    let root = scratch("negative-shapes");
    let sibling = root.with_file_name(format!(
        "{}-sibling",
        root.file_name().unwrap().to_string_lossy()
    ));
    fs::create_dir(&sibling).unwrap();
    let sibling_program = sibling.join("probe-alpha");
    fs::write(&sibling_program, b"fixture").unwrap();
    let cfg = cfg(&format!("{}/**", path(&root)), &["probe-*"]);

    let ordinary = [
        decide_path(&cfg, &sibling_program, "inspect", Some(&root)),
        decide_command_at(
            &cfg,
            "bash",
            "./probe-missing inspect",
            None,
            None,
            Some(path(&root).as_str()),
        ),
        decide_path(&cfg, &root, "inspect", Some(&root)),
        decide_command_at(
            &cfg,
            "bash",
            "probe-alpha inspect",
            None,
            None,
            Some(path(&root).as_str()),
        ),
    ];
    for decision in ordinary {
        assert!(matches!(decision, Decision::Ask(_)), "{decision:?}");
    }
    let unknown = decide_command_in_unknown_dir(
        &cfg,
        "bash",
        "./probe-alpha inspect",
        None,
        None,
        "the caller did not establish a run directory",
    );
    assert!(matches!(unknown, Decision::Ask(_)), "{unknown:?}");

    fs::remove_dir_all(root).unwrap();
    fs::remove_dir_all(sibling).unwrap();
}

#[test]
fn ordered_cd_and_wrapper_expansion_preserve_the_occurrences_run_directory() {
    let root = scratch("occurrence-cwd");
    let outside = scratch("occurrence-start");
    let bin = root.join("bin");
    fs::create_dir(&bin).unwrap();
    let program = bin.join("probe-alpha");
    fs::write(&program, b"fixture").unwrap();
    let cfg = cfg(&format!("{}/**", path(&root)), &["probe-*"]);

    let after_cd = decide_command_at(
        &cfg,
        "bash",
        &format!("cd {} && ./bin/probe-alpha inspect", path(&root)),
        None,
        None,
        Some(path(&outside).as_str()),
    );
    let wrapped = decide_command_at(
        &cfg,
        "bash",
        "env ./bin/probe-alpha inspect",
        None,
        None,
        Some(path(&root).as_str()),
    );
    let cross_language = decide_command_at(
        &cfg,
        "bash",
        "powershell -Command \"./bin/probe-alpha inspect\"",
        None,
        None,
        Some(path(&root).as_str()),
    );
    assert!(matches!(after_cd, Decision::Allow(_)), "{after_cd:?}");
    assert!(matches!(wrapped, Decision::Allow(_)), "{wrapped:?}");
    assert!(
        matches!(cross_language, Decision::Allow(_)),
        "{cross_language:?}"
    );

    fs::remove_dir_all(root).unwrap();
    fs::remove_dir_all(outside).unwrap();
}

#[test]
fn a_top_level_powershell_path_uses_the_same_location_rule() {
    let root = scratch("powershell-top-level");
    let program = root.join("probe-alpha");
    fs::write(&program, b"fixture").unwrap();
    let cfg = cfg(&format!("{}/**", path(&root)), &["probe-*"]);

    let decision = decide_command_at(
        &cfg,
        "powershell",
        &format!("{} inspect", path(&program)),
        None,
        None,
        Some(path(&root).as_str()),
    );
    assert!(matches!(decision, Decision::Allow(_)), "{decision:?}");

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn two_same_named_occurrences_are_decided_by_their_own_canonical_files() {
    let trusted = scratch("per-occurrence-trusted");
    let outside = scratch("per-occurrence-outside");
    let trusted_program = trusted.join("probe-alpha");
    let outside_program = outside.join("probe-alpha");
    fs::write(&trusted_program, b"fixture").unwrap();
    fs::write(&outside_program, b"fixture").unwrap();
    let cfg = cfg(&format!("{}/**", path(&trusted)), &["probe-*"]);

    let decision = decide_command_at(
        &cfg,
        "bash",
        &format!(
            "{} inspect && {} inspect",
            path(&trusted_program),
            path(&outside_program)
        ),
        None,
        None,
        Some(path(&trusted).as_str()),
    );
    assert!(matches!(decision, Decision::Ask(_)), "{decision:?}");

    fs::remove_dir_all(trusted).unwrap();
    fs::remove_dir_all(outside).unwrap();
}

#[cfg(unix)]
#[test]
fn dot_dot_and_symlink_escapes_do_not_match_the_written_tree() {
    use std::os::unix::fs::symlink;

    let parent = scratch("escapes");
    let trusted = parent.join("trusted");
    let work = trusted.join("work");
    let outside = parent.join("outside");
    fs::create_dir(&trusted).unwrap();
    fs::create_dir(&work).unwrap();
    fs::create_dir(&outside).unwrap();
    let outside_program = outside.join("probe-alpha");
    fs::write(&outside_program, b"fixture").unwrap();
    symlink(&outside_program, trusted.join("probe-link")).unwrap();
    let cfg = cfg(&format!("{}/**", path(&trusted)), &["probe-*"]);

    let dot_dot = decide_command_at(
        &cfg,
        "bash",
        "../../outside/probe-alpha inspect",
        None,
        None,
        Some(path(&work).as_str()),
    );
    let linked = decide_command_at(
        &cfg,
        "bash",
        "../probe-link inspect",
        None,
        None,
        Some(path(&work).as_str()),
    );
    assert!(matches!(dot_dot, Decision::Ask(_)), "{dot_dot:?}");
    assert!(matches!(linked, Decision::Ask(_)), "{linked:?}");

    fs::remove_dir_all(parent).unwrap();
}

#[test]
fn leading_parent_segments_are_composed_before_normalization() {
    let parent = scratch("leading-parent");
    let trusted = parent.join("trusted");
    let work = trusted.join("work");
    let misleading = work.join("outside");
    let outside = parent.join("outside");
    fs::create_dir_all(&misleading).unwrap();
    fs::create_dir_all(&outside).unwrap();

    // From `work`, the shell executes the file outside the trusted tree. A
    // resolver that collapses leading `..` before adding cwd instead finds
    // the deliberately misleading in-tree file and grants on the wrong one.
    fs::write(misleading.join("probe-alpha"), b"trusted decoy").unwrap();
    fs::write(outside.join("probe-alpha"), b"actual outside program").unwrap();
    let cfg = cfg(&format!("{}/**", path(&trusted)), &["probe-*"]);

    let decision = decide_command_at(
        &cfg,
        "bash",
        "../../outside/probe-alpha inspect",
        None,
        None,
        Some(path(&work).as_str()),
    );
    assert!(
        matches!(decision, Decision::Ask(_)),
        "leading parent segments proved a different in-tree file: {decision:?}"
    );

    fs::remove_dir_all(parent).unwrap();
}

#[test]
fn python_callable_names_are_not_shell_program_locations() {
    let root = scratch("python-callable");
    let cfg = cfg(&format!("{}/**", path(&root)), &["probe_*"]);
    let decision = decide_command_at(
        &cfg,
        "python",
        "probe_alpha()",
        None,
        None,
        Some(path(&root).as_str()),
    );
    assert!(matches!(decision, Decision::Ask(_)), "{decision:?}");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn recognition_precedence_is_distrust_then_knowledge_then_program_then_compatibility_zone() {
    let root = scratch("precedence");
    let probe = root.join("probe-alpha");
    fs::write(&probe, b"fixture").unwrap();

    let distrust_cfg = cfg_with(
        &format!("{}/**", path(&root)),
        &["probe-*"],
        "",
        &format!("trust_nothing_under = [\"{}/**\"]", path(&root)),
    );
    let distrusted = decide_path(&distrust_cfg, &probe, "inspect", Some(&root));
    match distrusted {
        Decision::Ask(reason) => assert!(reason.contains("trust_nothing_under"), "{reason}"),
        other => panic!("distrust must win: {other:?}"),
    }

    let known = root.join("git");
    fs::write(&known, b"fixture").unwrap();
    let knowledge_cfg = cfg(&format!("{}/**", path(&root)), &["git"]);
    let described = decide_path(&knowledge_cfg, &known, "status", Some(&root));
    match described {
        Decision::Allow(reason) => assert!(!reason.contains("trust_program"), "{reason}"),
        other => panic!("knowledge must recognise first: {other:?}"),
    }

    let compatibility_cfg = cfg_with(
        &format!("{}/**", path(&root)),
        &["probe-*"],
        "",
        &format!("trust_all_under = [\"{}/**\"]", path(&root)),
    );
    let by_program = decide_path(&compatibility_cfg, &probe, "inspect", Some(&root));
    match by_program {
        Decision::Allow(reason) => {
            assert!(reason.contains("trust_program"), "{reason}");
            assert!(!reason.contains("trust_all_under"), "{reason}");
        }
        other => panic!("program-location recognition must precede compatibility zones: {other:?}"),
    }

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn a_matching_rule_does_not_suppress_guards_walls_protection_or_constructs() {
    let root = scratch("composition");
    let rm = root.join("rm");
    let probe = root.join("probe-alpha");
    for program in [&rm, &probe] {
        fs::write(program, b"fixture").unwrap();
    }

    let guard_cfg = cfg_with(
        &format!("{}/**", path(&root)),
        &["rm"],
        "[guards]\ndelete_recursive = \"ask\"",
        "",
    );
    let guarded = decide_path(&guard_cfg, &rm, "-r victim", Some(&root));
    match guarded {
        Decision::Ask(reason) => assert!(reason.contains("delete_recursive"), "{reason}"),
        other => panic!("guard must survive recognition: {other:?}"),
    }

    let walled = root.join("walled");
    fs::create_dir(&walled).unwrap();
    let wall_cfg = cfg_with(
        &format!("{}/**", path(&root)),
        &["probe-*"],
        &format!(
            "[write]\ndefault = \"allow\"\nask_paths = [\"{}/**\"]",
            path(&walled)
        ),
        "",
    );
    let wall = decide_path(
        &wall_cfg,
        &probe,
        &format!("inspect > {}", path(&walled.join("new"))),
        Some(&root),
    );
    match wall {
        Decision::Ask(reason) => assert!(reason.contains("write.ask_paths"), "{reason}"),
        other => panic!("write wall must survive recognition: {other:?}"),
    }

    let protected_file = root.join("protected-file");
    let protected_cfg = cfg_with(
        &format!("{}/**", path(&root)),
        &["probe-*"],
        &format!(
            "[protected]\npaths = [\"{}\"]\n[write]\ndefault = \"allow\"",
            path(&protected_file)
        ),
        "",
    );
    let protected = decide_path(
        &protected_cfg,
        &probe,
        &format!("inspect > {}", path(&protected_file)),
        Some(&root),
    );
    match protected {
        Decision::Ask(reason) => assert!(reason.contains("protected file"), "{reason}"),
        other => panic!("protected path must survive recognition: {other:?}"),
    }

    let construct_cfg = cfg_with(
        &format!("{}/**", path(&root)),
        &["probe-*"],
        "subshell = \"ask\"",
        "",
    );
    let construct = decide_path(&construct_cfg, &probe, "$(echo value)", Some(&root));
    match construct {
        Decision::Ask(reason) => assert!(reason.contains("subshell"), "{reason}"),
        other => panic!("unreadable construct must survive recognition: {other:?}"),
    }

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn every_program_location_clause_is_independently_necessary() {
    let trusted = scratch("clause-matrix-trusted");
    let outside = scratch("clause-matrix-outside");
    let cfg = cfg(&format!("{}/**", path(&trusted)), &["probe-*"]);

    for exists in [false, true] {
        for contained in [false, true] {
            for name_matches in [false, true] {
                let directory = if contained { &trusted } else { &outside };
                let name = if name_matches {
                    "probe-matrix"
                } else {
                    "helper-matrix"
                };
                let program = directory.join(name);
                let _ = fs::remove_file(&program);
                if exists {
                    fs::write(&program, b"fixture").unwrap();
                }

                let decision = decide_path(&cfg, &program, "inspect", Some(&trusted));
                let allowed = matches!(decision, Decision::Allow(_));
                assert_eq!(
                    allowed,
                    exists && contained && name_matches,
                    "existence={exists}, containment={contained}, name={name_matches}: {decision:?}"
                );
            }
        }
    }

    fs::remove_dir_all(trusted).unwrap();
    fs::remove_dir_all(outside).unwrap();
}

#[test]
fn overlapping_rules_attribute_to_the_first_matching_entry_deterministically() {
    let root = scratch("overlapping-rules");
    let bin = root.join("bin");
    fs::create_dir(&bin).unwrap();
    let program = bin.join("probe-alpha");
    fs::write(&program, b"fixture").unwrap();

    let load = |first_under: &Path, first_name: &str, second_under: &Path, second_name: &str| {
        vouch::config::load(&format!(
            "[lang.bash]\ndefault = \"allow\"\n[lang.bash.constructs]\n\
             unmodeled_command = \"ask\"\n\
             [[run.trust_program]]\nunder = [\"{}/**\"]\nname_patterns = [\"{first_name}\"]\n\
             [[run.trust_program]]\nunder = [\"{}/**\"]\nname_patterns = [\"{second_name}\"]\n",
            path(first_under),
            path(second_under),
        ))
        .unwrap()
    };
    let broad_first = load(&root, "probe-*", &bin, "probe-alpha");
    let narrow_first = load(&bin, "probe-alpha", &root, "probe-*");

    for (cfg, first_pattern) in [(&broad_first, "probe-*"), (&narrow_first, "probe-alpha")] {
        let first = decide_path(cfg, &program, "inspect", Some(&root));
        let second = decide_path(cfg, &program, "inspect", Some(&root));
        match (first, second) {
            (Decision::Allow(a), Decision::Allow(b)) => {
                assert_eq!(a, b, "the same ordered rules changed attribution");
                assert!(a.contains("[[run.trust_program]] #1"), "{a}");
                assert!(a.contains(first_pattern), "{a}");
            }
            other => panic!("both overlapping-rule orders must allow: {other:?}"),
        }
    }

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn prefix_conventions_cover_literal_filename_edges_not_path_segments() {
    let root = scratch("adversarial-names");
    let cfg = cfg(&format!("{}/**", path(&root)), &["probe-*"]);
    let long_name = format!("probe-{}", "x".repeat(180));
    let mut cases = vec![
        ("probe-".to_string(), true),
        ("probe---many".to_string(), true),
        ("probe-λambda".to_string(), true),
        ("probe-.exe.exe".to_string(), true),
        (long_name, true),
        (
            "Probe-Case".to_string(),
            cfg!(any(windows, target_os = "macos")),
        ),
    ];
    for (name, should_allow) in cases.drain(..) {
        let program = root.join(name);
        fs::write(&program, b"fixture").unwrap();
        let decision = decide_path(&cfg, &program, "inspect", Some(&root));
        assert_eq!(
            matches!(decision, Decision::Allow(_)),
            should_allow,
            "literal filename convention classified the edge incorrectly: {decision:?}"
        );
    }

    let masquerading_directory = root.join("probe-directory");
    fs::create_dir(&masquerading_directory).unwrap();
    let other_name = masquerading_directory.join("helper");
    fs::write(&other_name, b"fixture").unwrap();
    let decision = decide_path(&cfg, &other_name, "inspect", Some(&root));
    assert!(
        matches!(decision, Decision::Ask(_)),
        "a matching path segment masqueraded as the canonical basename: {decision:?}"
    );

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn decisions_recheck_file_metadata_but_do_not_hash_contents() {
    let root = scratch("decision-time-metadata");
    let program = root.join("probe-alpha");
    let cfg = cfg(&format!("{}/**", path(&root)), &["probe-*"]);

    fs::write(&program, b"first contents").unwrap();
    let first = decide_path(&cfg, &program, "inspect", Some(&root));
    fs::write(&program, b"different contents").unwrap();
    let changed_contents = decide_path(&cfg, &program, "inspect", Some(&root));
    assert_eq!(
        first, changed_contents,
        "contents are not evidence in a program-location answer"
    );

    fs::remove_file(&program).unwrap();
    let absent = decide_path(&cfg, &program, "inspect", Some(&root));
    assert!(matches!(absent, Decision::Ask(_)), "{absent:?}");
    fs::write(&program, b"recreated").unwrap();
    let present_again = decide_path(&cfg, &program, "inspect", Some(&root));
    assert!(
        matches!(present_again, Decision::Allow(_)),
        "{present_again:?}"
    );

    // This pins the feasible race boundary: each decision consults current
    // metadata, but no content hash or execution-time file handle is retained.
    fs::remove_dir_all(root).unwrap();
}
