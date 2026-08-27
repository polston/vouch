use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use vouch::engine::{
    logical_program_name, program_head_has_unspecified_windows_drive,
    program_head_is_path_spelled, resolve_program_location, ProgramLocation,
    ProgramLocationCause,
};
use vouch::paths::{
    canonical_existing_file, canonical_existing_pattern_root, ExistingPathError,
};

fn scratch(tag: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "vouch-program-location-{tag}-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn text(path: &Path) -> &str {
    path.to_str().unwrap()
}

#[test]
fn complete_existing_regular_files_are_the_only_file_evidence() {
    let root = scratch("existing");
    let file = root.join("probe-tool");
    fs::write(&file, b"fixture").unwrap();

    assert!(canonical_existing_file(text(&file)).is_ok());
    assert_eq!(
        canonical_existing_file(text(&root)),
        Err(ExistingPathError::NotRegularFile)
    );
    assert_eq!(
        canonical_existing_file(text(&root.join("missing"))),
        Err(ExistingPathError::Missing)
    );

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn exact_and_tree_patterns_match_only_their_canonical_scope() {
    let root = scratch("scope");
    let nested = root.join("nested");
    fs::create_dir(&nested).unwrap();
    let inside = nested.join("probe-tool");
    let outside = root.with_file_name(format!(
        "{}-outside",
        root.file_name().unwrap().to_string_lossy()
    ));
    fs::write(&inside, b"inside").unwrap();
    fs::write(&outside, b"outside").unwrap();

    let inside_canonical = canonical_existing_file(text(&inside)).unwrap();
    let outside_canonical = canonical_existing_file(text(&outside)).unwrap();
    let exact = canonical_existing_pattern_root(text(&inside), "", None).unwrap();
    let tree = canonical_existing_pattern_root(&format!("{}/**", text(&root)), "", None)
        .unwrap();

    assert!(exact.matches(&inside_canonical));
    assert!(!exact.matches(&outside_canonical));
    assert!(tree.matches(&inside_canonical));
    assert!(!tree.matches(&outside_canonical));

    fs::remove_dir_all(root).unwrap();
    fs::remove_file(outside).unwrap();
}

#[cfg(unix)]
#[test]
fn a_root_tree_pattern_keeps_the_filesystem_root() {
    let root = scratch("root-tree");
    let file = root.join("probe-tool");
    fs::write(&file, b"fixture").unwrap();

    let pattern = canonical_existing_pattern_root("/**", "", None).unwrap();
    let canonical_file = canonical_existing_file(text(&file)).unwrap();
    assert!(pattern.tree);
    assert_eq!(pattern.root, "/");
    assert!(pattern.matches(&canonical_file));

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn pattern_roots_fail_typed_and_never_broaden() {
    let root = scratch("pattern-failure");
    let file = root.join("probe-tool");
    fs::write(&file, b"fixture").unwrap();

    assert_eq!(
        canonical_existing_pattern_root("$PROJECT_ROOT/build/**", "", None),
        Err(ExistingPathError::CannotExpandPattern)
    );
    assert_eq!(
        canonical_existing_pattern_root(text(&root.join("missing")), "", None),
        Err(ExistingPathError::Missing)
    );
    assert_eq!(
        canonical_existing_pattern_root(&format!("{}/**", text(&file)), "", None),
        Err(ExistingPathError::NotDirectory)
    );
    assert_eq!(
        canonical_existing_pattern_root(text(&root), "", None),
        Err(ExistingPathError::NotRegularFile)
    );

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn relative_heads_need_a_proven_run_directory_but_absolute_heads_do_not() {
    let root = scratch("run-place");
    let bin = root.join("bin");
    fs::create_dir(&bin).unwrap();
    let file = bin.join("probe-tool");
    fs::write(&file, b"fixture").unwrap();

    let relative = resolve_program_location("./bin/probe-tool", Some(text(&root)), "");
    let absolute = resolve_program_location(text(&file), None, "");
    let no_directory = resolve_program_location("./bin/probe-tool", None, "");

    assert!(matches!(relative, ProgramLocation::Proven { .. }));
    assert!(matches!(absolute, ProgramLocation::Proven { .. }));
    assert!(matches!(
        no_directory,
        ProgramLocation::Unproven {
            cause: ProgramLocationCause::NoRunDirectory,
            ..
        }
    ));

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn bare_unresolved_missing_and_directory_heads_never_prove_a_program() {
    let root = scratch("unproven");

    assert_eq!(
        resolve_program_location("probe-tool", Some(text(&root)), ""),
        ProgramLocation::NotPathSpelled { written_head: "probe-tool".to_string() }
    );
    assert!(matches!(
        resolve_program_location("./$TOOL", Some(text(&root)), ""),
        ProgramLocation::Unproven {
            cause: ProgramLocationCause::UnresolvedHead,
            ..
        }
    ));
    assert!(matches!(
        resolve_program_location("~another-user/probe", Some(text(&root)), ""),
        ProgramLocation::Unproven {
            cause: ProgramLocationCause::UnresolvedHead,
            ..
        }
    ));
    assert!(matches!(
        resolve_program_location("./missing", Some(text(&root)), ""),
        ProgramLocation::Unproven {
            cause: ProgramLocationCause::MissingFile,
            ..
        }
    ));
    assert!(matches!(
        resolve_program_location("./", Some(text(&root)), ""),
        ProgramLocation::Unproven {
            cause: ProgramLocationCause::NotRegularFile,
            ..
        }
    ));

    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn candidate_symlink_escape_resolves_outside_while_configured_symlink_roots_work() {
    use std::os::unix::fs::symlink;

    let trusted = scratch("trusted");
    let outside = scratch("outside");
    let outside_file = outside.join("probe-tool");
    fs::write(&outside_file, b"outside").unwrap();
    let escape = trusted.join("probe-tool");
    symlink(&outside_file, &escape).unwrap();

    let trusted_pattern = canonical_existing_pattern_root(
        &format!("{}/**", text(&trusted)),
        "",
        None,
    )
    .unwrap();
    let escaped_file = canonical_existing_file(text(&escape)).unwrap();
    assert!(!trusted_pattern.matches(&escaped_file));

    let root_link = trusted.with_file_name(format!(
        "{}-link",
        trusted.file_name().unwrap().to_string_lossy()
    ));
    symlink(&outside, &root_link).unwrap();
    let linked_pattern = canonical_existing_pattern_root(
        &format!("{}/**", text(&root_link)),
        "",
        None,
    )
    .unwrap();
    assert!(linked_pattern.matches(&escaped_file));

    fs::remove_file(root_link).unwrap();
    fs::remove_dir_all(trusted).unwrap();
    fs::remove_dir_all(outside).unwrap();
}

#[test]
fn path_shape_and_logical_name_follow_platform_rules() {
    assert!(!program_head_is_path_spelled("probe-tool"));
    assert!(program_head_is_path_spelled("./probe-tool"));
    assert!(program_head_is_path_spelled(r".\probe-tool"));

    let name = logical_program_name("C:/build/probe-tool.exe");
    if cfg!(windows) {
        assert_eq!(name, "probe-tool");
    } else {
        assert_eq!(name, "probe-tool.exe");
    }
}

#[test]
fn windows_root_relative_heads_are_distinct_from_complete_windows_roots() {
    assert!(program_head_has_unspecified_windows_drive(r"\probe-tool"));
    assert!(program_head_has_unspecified_windows_drive("/probe-tool"));
    assert!(!program_head_has_unspecified_windows_drive("C:/probe-tool"));
    assert!(!program_head_has_unspecified_windows_drive("/c/probe-tool"));
    assert!(!program_head_has_unspecified_windows_drive(
        r"\\server\share\probe-tool"
    ));
}

#[cfg(windows)]
#[test]
fn windows_root_relative_heads_never_borrow_the_vouch_process_drive() {
    assert!(matches!(
        resolve_program_location(r"\probe-tool", Some("D:/work"), "C:/Users/dev"),
        ProgramLocation::Unproven {
            cause: ProgramLocationCause::CanonicalizationFailed,
            ..
        }
    ));
}
