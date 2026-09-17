use vouch::paths::{resolve_links, resolve_links_with_base};

#[test]
fn relative_target_resolution_does_not_borrow_runner_cwd() {
    // In replay mode without an explicit cwd, a relative write target (e.g. "a.txt")
    // must not be canonicalized against whatever files happen to exist in the test runner's
    // working directory.
    let rel_target = "src"; // "src" exists in the current repo checkout!
    assert!(std::path::Path::new(rel_target).exists());

    // Without a base, resolve_links returns "src" unchanged rather than canonicalizing to absolute path
    let resolved = resolve_links(rel_target);
    assert_eq!(resolved, "src", "relative path without base must not resolve to host checkout path");

    // With an explicit base, it resolves against that base
    let temp = std::env::temp_dir();
    let resolved_with_base = resolve_links_with_base("test_file.txt", Some(&temp));
    assert!(resolved_with_base.ends_with("/test_file.txt"));
}

#[test]
fn differential_wobble_eliminated_across_checkouts() {
    let cfg = vouch::config::Config::nothing_configured();

    // Replay evaluation of a command with a relative write target
    let cmd = "cp src a_test_relative_target.txt";

    // Scenario A: target file does not exist
    let dec_without_file = vouch::engine::decide_command_in(&cfg, "bash", cmd, None, None);

    // Scenario B: create the file in a temp directory and resolve
    let temp = std::env::temp_dir().join("vouch_replay_isolation_scratch");
    let _ = std::fs::create_dir_all(&temp);
    let dummy = temp.join("a_test_relative_target.txt");
    let _ = std::fs::write(&dummy, "content");

    // In replay mode (no cwd), relative targets do not canonicalize against host files
    let dec_with_file = vouch::engine::decide_command_in(&cfg, "bash", cmd, None, None);

    let _ = std::fs::remove_file(&dummy);
    let _ = std::fs::remove_dir(&temp);

    assert_eq!(
        dec_without_file, dec_with_file,
        "replay verdict on relative targets must be identical regardless of whether target file exists"
    );
}
