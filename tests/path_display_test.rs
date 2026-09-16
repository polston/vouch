// tests/path_display_test.rs
//
// M2.28: Path display invariant test.
// Verifies user-facing paths emitted in diagnostics, install targets,
// and redirected environment notices use canonical forward slashes.

use std::path::Path;
use vouch::knowledge::display_path;

#[test]
fn test_display_path_converts_backslashes() {
    let p = Path::new("C:\\Users\\dev\\project\\data.txt");
    let disp = display_path(p);
    assert!(!disp.contains('\\'), "display_path should not contain backslashes: {disp}");
    assert!(disp.contains("C:/Users/dev/project/data.txt") || disp.contains('/'));
}

#[test]
fn test_display_path_posix_unchanged() {
    let p = Path::new("/var/log/app/output.log");
    let disp = display_path(p);
    assert_eq!(disp, "/var/log/app/output.log");
}

#[test]
fn test_display_path_relative_windows() {
    let p = Path::new("subdir\\sub2\\file.rs");
    let disp = display_path(p);
    assert_eq!(disp, "subdir/sub2/file.rs");
}
