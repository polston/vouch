use vouch::paths::{normalize_with_mounts, MountEntry, MountTable};

const HOME: &str = "C:/Users/dev";

#[test]
fn empty_mount_table_leaves_paths_unchanged() {
    let mounts = MountTable::new();
    assert_eq!(
        normalize_with_mounts("/tmp/file.txt", HOME, &mounts),
        "/tmp/file.txt"
    );
    assert_eq!(
        normalize_with_mounts("C:/work/x", HOME, &mounts),
        "C:/work/x"
    );
}

#[test]
fn exact_alias_match_resolves_to_canonical() {
    let mut mounts = MountTable::new();
    mounts.add("/tmp", "C:/Users/dev/AppData/Local/Temp");

    assert_eq!(
        normalize_with_mounts("/tmp", HOME, &mounts),
        "C:/Users/dev/AppData/Local/Temp"
    );
    assert_eq!(
        normalize_with_mounts("/tmp/", HOME, &mounts),
        "C:/Users/dev/AppData/Local/Temp"
    );
}

#[test]
fn subdirectory_of_mount_alias_resolves_cleanly() {
    let mut mounts = MountTable::new();
    mounts.add("/tmp", "C:/Users/dev/AppData/Local/Temp");

    assert_eq!(
        normalize_with_mounts("/tmp/scratch/output.log", HOME, &mounts),
        "C:/Users/dev/AppData/Local/Temp/scratch/output.log"
    );
    assert_eq!(
        normalize_with_mounts(r"/tmp\nested\file.txt", HOME, &mounts),
        "C:/Users/dev/AppData/Local/Temp/nested/file.txt"
    );
}

#[test]
fn does_not_match_partial_segment_prefix() {
    let mut mounts = MountTable::new();
    mounts.add("/tmp", "C:/Users/dev/AppData/Local/Temp");

    // /tmpdir does not match /tmp
    assert_eq!(
        normalize_with_mounts("/tmpdir/file.txt", HOME, &mounts),
        "/tmpdir/file.txt"
    );
}

#[test]
fn longest_prefix_mount_match_wins() {
    let mounts = MountTable::from_entries(vec![
        MountEntry::new("/tmp", "C:/Temp"),
        MountEntry::new("/tmp/isolated", "D:/Isolated"),
    ]);

    assert_eq!(
        normalize_with_mounts("/tmp/isolated/sub/a.txt", HOME, &mounts),
        "D:/Isolated/sub/a.txt"
    );
    assert_eq!(
        normalize_with_mounts("/tmp/other/b.txt", HOME, &mounts),
        "C:/Temp/other/b.txt"
    );
}

#[test]
fn mount_resolution_is_idempotent() {
    let mut mounts = MountTable::new();
    mounts.add("/tmp", "C:/Users/dev/AppData/Local/Temp");

    let once = normalize_with_mounts("/tmp/scratch/test.txt", HOME, &mounts);
    let twice = normalize_with_mounts(&once, HOME, &mounts);
    assert_eq!(once, twice);
    assert_eq!(once, "C:/Users/dev/AppData/Local/Temp/scratch/test.txt");
}

#[test]
fn dot_segments_inside_mount_alias_collapse_correctly() {
    let mut mounts = MountTable::new();
    mounts.add("/tmp", "C:/Users/dev/AppData/Local/Temp");

    assert_eq!(
        normalize_with_mounts("/tmp/a/../b.txt", HOME, &mounts),
        "C:/Users/dev/AppData/Local/Temp/b.txt"
    );
    assert_eq!(
        normalize_with_mounts("/tmp/./b.txt", HOME, &mounts),
        "C:/Users/dev/AppData/Local/Temp/b.txt"
    );
}

#[test]
fn mount_alias_case_folding_on_case_insensitive_platforms() {
    let mut mounts = MountTable::new();
    mounts.add("/tmp", "C:/Users/dev/AppData/Local/Temp");

    if cfg!(any(windows, target_os = "macos")) {
        assert_eq!(
            normalize_with_mounts("/TMP/file.txt", HOME, &mounts),
            "C:/Users/dev/AppData/Local/Temp/file.txt"
        );
        assert_eq!(
            normalize_with_mounts("/Tmp/file.txt", HOME, &mounts),
            "C:/Users/dev/AppData/Local/Temp/file.txt"
        );
    }
}

#[test]
fn mount_canonical_uppercase_drive_letter() {
    let mut mounts = MountTable::new();
    mounts.add("/tmp", "c:/temp/dir");

    assert_eq!(
        normalize_with_mounts("/tmp/x", HOME, &mounts),
        "C:/temp/dir/x"
    );
}

#[test]
fn unix_system_symlink_mount_resolution() {
    let mut mounts = MountTable::new();
    mounts.add("/tmp", "/private/tmp");

    assert_eq!(
        normalize_with_mounts("/tmp/scratch.txt", "/Users/dev", &mounts),
        "/private/tmp/scratch.txt"
    );
    assert_eq!(
        normalize_with_mounts("/tmp", "/Users/dev", &mounts),
        "/private/tmp"
    );
}

#[test]
fn both_spellings_of_mount_aliased_path_get_identical_decisions() {
    let toml = r#"
version = 1
[lang.bash]
default = "allow"
[write]
default = "ask"
allow_paths = ["C:/Users/dev/AppData/Local/Temp/**"]
"#;
    let cfg = vouch::config::load(toml).expect("valid config");
    let mut mounts = MountTable::new();
    mounts.add("/tmp", "C:/Users/dev/AppData/Local/Temp");

    let alias_path = normalize_with_mounts("/tmp/output.log", HOME, &mounts);
    let canon_path = normalize_with_mounts("C:/Users/dev/AppData/Local/Temp/output.log", HOME, &mounts);

    assert_eq!(alias_path, canon_path);

    let d1 = vouch::engine::decide_file(&cfg, HOME, None, &alias_path);
    let d2 = vouch::engine::decide_file(&cfg, HOME, None, &canon_path);

    assert!(matches!(d1, vouch::protocol::Decision::Allow(_)));
    assert_eq!(d1, d2);
}

#[test]
fn mount_entry_strips_unc_prefix() {
    let entry = MountEntry::new("/tmp", r"//?/C:/Users/dev/AppData/Local/Temp");
    assert_eq!(entry.canonical, "C:/Users/dev/AppData/Local/Temp");

    let entry_bs = MountEntry::new("/tmp", r"\\?\C:\Users\dev\AppData\Local\Temp");
    assert_eq!(entry_bs.canonical, "C:/Users/dev/AppData/Local/Temp");
}

#[test]
fn canonicalize_mount_target_strips_unc_and_normalizes() {
    use vouch::paths::canonicalize_mount_target;

    // A nonexistent path falls back to forward-slash normalized string
    let fallback = canonicalize_mount_target(r"C:\Nonexistent\Mount\Target\Path");
    assert_eq!(fallback, "C:/Nonexistent/Mount/Target/Path");

    // An existing path canonicalizes without UNC prefix
    let cwd = std::env::current_dir().expect("cwd");
    let canon = canonicalize_mount_target(&cwd.to_string_lossy());
    assert!(!canon.starts_with("//?/"), "UNC prefix must be stripped: {canon}");
    assert!(!canon.starts_with(r"\\?\"), "UNC prefix must be stripped: {canon}");
    assert!(!canon.contains('\\'), "must use forward slashes: {canon}");
}
