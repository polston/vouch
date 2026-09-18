//! Integration tests for conditional write target derivation (M2.139).
//! Tests mode-dependent write derivation (e.g. tar -cf <out.tar> in/).

mod common;

use common::decision_at;
use vouch::guards::{load, written_paths_in, Knowledge};
use vouch::syntax::Cmd;

fn shipped_kb() -> Knowledge {
    load(include_str!("../knowledge.toml")).expect("shipped knowledge parses")
}

fn cmd(head: &str, args: &[&str]) -> Cmd {
    Cmd {
        head: head.into(),
        args: args.iter().map(|s| s.to_string()).collect(),
        unread_args: Default::default(),
        keyword_args: Default::default(),
        callable_args: Default::default(),
        chain: None,
        prefix_assigns: vec![],
        env_assigns: Default::default(),
        receiver_origin: vouch::syntax::ValueOrigin::Unknown,
        by_reference: false,
        is_intra_command_function: false,
        expandable_args: Default::default(),
    }
}

#[test]
fn tar_archive_creation_derives_output_target() {
    let kb = shipped_kb();

    // Standard separated flags: tar -c -f out.tar in/
    let c1 = cmd("tar", &["-c", "-f", "out.tar", "in/"]);
    let wt1 = written_paths_in(&kb, &c1, "bash");
    assert_eq!(wt1.paths, vec!["out.tar"]);

    // Clustered flags: tar -cf out.tar in/
    let c2 = cmd("tar", &["-cf", "out.tar", "in/"]);
    let wt2 = written_paths_in(&kb, &c2, "bash");
    assert_eq!(wt2.paths, vec!["out.tar"]);

    // Clustered with gzip: tar -czf out.tar.gz in/
    let c3 = cmd("tar", &["-czf", "out.tar.gz", "in/"]);
    let wt3 = written_paths_in(&kb, &c3, "bash");
    assert_eq!(wt3.paths, vec!["out.tar.gz"]);

    // Clustered with verbose & bzip2: tar -cjvf out.tar.bz2 in/
    let c4 = cmd("tar", &["-cjvf", "out.tar.bz2", "in/"]);
    let wt4 = written_paths_in(&kb, &c4, "bash");
    assert_eq!(wt4.paths, vec!["out.tar.bz2"]);

    // Long flag with attached value: tar --create --file=out.tar in/
    let c5 = cmd("tar", &["--create", "--file=out.tar", "in/"]);
    let wt5 = written_paths_in(&kb, &c5, "bash");
    assert_eq!(wt5.paths, vec!["out.tar"]);

    // Long flag separated: tar --create --file out.tar in/
    let c6 = cmd("tar", &["--create", "--file", "out.tar", "in/"]);
    let wt6 = written_paths_in(&kb, &c6, "bash");
    assert_eq!(wt6.paths, vec!["out.tar"]);

    // Mixed long and short: tar -c --file out.tar in/
    let c7 = cmd("tar", &["-c", "--file", "out.tar", "in/"]);
    let wt7 = written_paths_in(&kb, &c7, "bash");
    assert_eq!(wt7.paths, vec!["out.tar"]);
}

#[test]
fn tar_listing_mode_derives_no_write_target() {
    let kb = shipped_kb();

    // tar -tf out.tar
    let c1 = cmd("tar", &["-tf", "out.tar"]);
    let wt1 = written_paths_in(&kb, &c1, "bash");
    assert!(
        wt1.paths.is_empty(),
        "listing mode must derive no write targets, got: {:?}",
        wt1.paths
    );

    // tar -t -f out.tar
    let c2 = cmd("tar", &["-t", "-f", "out.tar"]);
    let wt2 = written_paths_in(&kb, &c2, "bash");
    assert!(
        wt2.paths.is_empty(),
        "listing mode with separated flags must derive no write targets"
    );

    // tar --list --file=out.tar
    let c3 = cmd("tar", &["--list", "--file=out.tar"]);
    let wt3 = written_paths_in(&kb, &c3, "bash");
    assert!(
        wt3.paths.is_empty(),
        "long listing mode must derive no write targets"
    );
}

#[test]
fn tar_extract_mode_does_not_derive_archive_as_write_target() {
    let kb = shipped_kb();

    // tar -xf out.tar -> here_write derives cwd ('.'), never out.tar
    let c1 = cmd("tar", &["-xf", "out.tar"]);
    let wt1 = written_paths_in(&kb, &c1, "bash");
    assert!(
        !wt1.paths.contains(&"out.tar".to_string()),
        "extract mode must not treat the input archive as a write target: {:?}",
        wt1.paths
    );

    // tar -xf out.tar -C /dest -> write_flags derives /dest, never out.tar
    let c2 = cmd("tar", &["-xf", "out.tar", "-C", "/dest"]);
    let wt2 = written_paths_in(&kb, &c2, "bash");
    assert_eq!(wt2.paths, vec!["/dest"]);
}

#[test]
fn tar_creation_without_f_writes_to_stdout_no_file_targets() {
    let kb = shipped_kb();

    // tar -c in/ -> writes to stdout, no -f provided
    let c1 = cmd("tar", &["-c", "in/"]);
    let wt1 = written_paths_in(&kb, &c1, "bash");
    assert!(
        wt1.paths.is_empty(),
        "tar -c without -f targets stdout, must derive 0 file write targets: {:?}",
        wt1.paths
    );
}

#[test]
fn conditional_write_unless_flags_suppress_derivation() {
    let kb = load(r#"
version = 15
[[program]]
match = ["archiver"]
writes = "flags_only"
value_options = ["-f"]
no_value_options = ["-c", "-n"]
[[program.conditional_write]]
when_flags = ["-c"]
unless_flags = ["-n"]
takes_flags = ["-f"]
"#).expect("fixture parses");

    // Normal creation: derives out.bin
    let c1 = cmd("archiver", &["-c", "-f", "out.bin"]);
    let wt1 = written_paths_in(&kb, &c1, "bash");
    assert_eq!(wt1.paths, vec!["out.bin"]);

    // Dry-run / unless flag present: derivation suppressed
    let c2 = cmd("archiver", &["-c", "-n", "-f", "out.bin"]);
    let wt2 = written_paths_in(&kb, &c2, "bash");
    assert!(
        wt2.paths.is_empty(),
        "unless_flag must suppress conditional write target: {:?}",
        wt2.paths
    );
}

#[test]
fn tar_protected_destination_halts_on_boundary() {
    let cfg = common::realistic_config_with(r#"
[protected]
paths = ["C:/Users/dev/.claude/settings.json"]
"#);

    // Attempting to overwrite a protected file with tar -cf must ask or deny
    let (d, r) = decision_at(
        &cfg,
        "tar -cf C:/Users/dev/.claude/settings.json in/",
        "C:/tmp",
    );
    assert_eq!(d, "ask", "writing protected target must halt with ask");
    assert!(
        r.contains("protected"),
        "reason must mention protected path: {r}"
    );
}

#[test]
fn tar_allowed_destination_allows() {
    let cfg = common::realistic_config();

    // Writing an archive inside allowed tree (C:/tmp/**)
    let (d, r) = decision_at(&cfg, "tar -cf C:/tmp/test.tar in/", "C:/tmp");
    assert_eq!(d, "allow", "writing to allowed tree must allow: {r}");
}
