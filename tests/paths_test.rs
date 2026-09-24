use vouch::paths::normalize;

const HOME: &str = "C:/Users/dev";

#[test]
fn all_four_spellings_of_one_path_are_equal() {
    let expect = "C:/work/x";
    assert_eq!(normalize("C:/work/x", HOME), expect);
    assert_eq!(normalize(r"C:\work\x", HOME), expect);
    assert_eq!(normalize("/c/work/x", HOME), expect);
    assert_eq!(normalize("C:/c/work/x", HOME), expect);
}

#[test]
fn expands_tilde_and_home_variable() {
    assert_eq!(normalize("~/.ssh/config", HOME), "C:/Users/dev/.ssh/config");
    assert_eq!(normalize("$HOME/.claude", HOME), "C:/Users/dev/.claude");
    assert_eq!(normalize("~", HOME), "C:/Users/dev");
}

#[test]
fn collapses_dot_segments() {
    assert_eq!(normalize("C:/work/a/../b", HOME), "C:/work/b");
    assert_eq!(normalize("C:/work/./b", HOME), "C:/work/b");
    assert_eq!(normalize("C:/work//b", HOME), "C:/work/b");
}

#[test]
fn dot_dot_cannot_climb_above_the_root() {
    assert_eq!(normalize("C:/../../windows", HOME), "C:/windows");
}

#[test]
fn is_case_insensitive_on_the_drive_letter() {
    assert_eq!(normalize("c:/work/x", HOME), "C:/work/x");
    assert_eq!(normalize("/C/work/x", HOME), "C:/work/x");
}

#[test]
fn a_posix_path_with_no_drive_is_left_alone() {
    // Mac/Linux paths must survive untouched.
    assert_eq!(normalize("/Users/dev/git/x", "/Users/dev"), "/Users/dev/git/x");
}

#[test]
fn normalisation_is_idempotent() {
    for raw in [r"C:\work\a\..\b", "/c/work/b", "C:/c/work/b", "~/x"] {
        let once = normalize(raw, HOME);
        let twice = normalize(&once, HOME);
        assert_eq!(once, twice, "not idempotent for {raw}");
    }
}

#[test]
fn sample_destination_relative_is_refused() {
    use vouch::paths::{check_sample_destination, DestinationRefusal};
    let res = check_sample_destination(std::path::Path::new("relative/samples.txt"));
    assert_eq!(res, Err(DestinationRefusal::NotAbsolute));
}

#[test]
fn sample_destination_with_no_existing_ancestor_is_refused() {
    use vouch::paths::{check_sample_destination_with, DestinationRefusal};
    let p = if cfg!(windows) {
        std::path::Path::new(r"Z:\nonexistent_drive\deep\samples.txt")
    } else {
        std::path::Path::new("/nonexistent_drive_or_mount/foo/bar.txt")
    };
    let res = check_sample_destination_with(p, |_| {
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "not found",
        ))
    });
    assert_eq!(res, Err(DestinationRefusal::NoExistingAncestor));
}

#[test]
fn sample_destination_inside_git_worktree_is_refused() {
    use vouch::paths::{check_sample_destination, DestinationRefusal};
    let manifest_dir = std::env::var_os("CARGO_MANIFEST_DIR")
        .map(std::path::PathBuf::from)
        .expect("CARGO_MANIFEST_DIR is unset: run this test through cargo");
    let in_tree = manifest_dir.join("tests/fixtures/samples.txt");
    match check_sample_destination(&in_tree) {
        Err(DestinationRefusal::InsideGitWorktree(root)) => {
            assert!(root.join(".git").exists());
        }
        other => panic!("expected InsideGitWorktree, got {:?}", other),
    }
}

#[test]
fn sample_destination_outside_git_worktree_is_accepted() {
    use vouch::paths::check_sample_destination;
    let tmp = std::env::temp_dir();
    if let Ok(canon) = tmp.canonicalize() {
        let mut anc = Some(canon.as_path());
        let mut inside_git = false;
        while let Some(d) = anc {
            if d.join(".git").exists() {
                inside_git = true;
                break;
            }
            anc = d.parent();
        }
        if !inside_git {
            let sample_dest = canon.join("dump_parse_samples_test.txt");
            assert_eq!(check_sample_destination(&sample_dest), Ok(canon));
        }
    }
}
