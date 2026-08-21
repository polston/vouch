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
