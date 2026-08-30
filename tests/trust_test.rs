//! `vouch trust` — the primitive an allow-list needs.
//!
//! Without a cheap way to say "I recognise this program", the only options when
//! an unknown program appears are hand-editing a file or switching the whole
//! check off. The second is what the deny-list design quietly encouraged.
//!
//! Two things had to be true before this could work, and neither was:
//!   1. The user's knowledge file must ADD to the shipped set, not replace it.
//!      It replaced it, so describing one program would have deleted every
//!      shipped description.
//!   2. Something must actually read that file. Nothing did — the loader was
//!      dead code while the prompt told the user to edit it.

use std::path::Path;
use vouch::guards::{is_modeled, load};
use vouch::knowledge::load_files;

const SHIPPED: &str = "knowledge.toml";

fn scratch(name: &str, body: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join("vouch_trust_test");
    std::fs::create_dir_all(&dir).expect("mkdir");
    let p = dir.join(name);
    std::fs::write(&p, body).expect("write");
    p
}

#[test]
fn a_user_file_adds_to_the_shipped_knowledge_rather_than_replacing_it() {
    let mine = scratch("adds.toml", "[[program]]\nmatch = [\"totallymadeupprog\"]\n");
    let kb = load_files(Path::new(SHIPPED), &mine).kb;
    assert!(is_modeled(&kb, "totallymadeupprog", "bash"), "the user's file was not read");
    assert!(is_modeled(&kb, "git", "bash"), "describing one program deleted the shipped set");
}

#[test]
fn a_malformed_user_file_does_not_take_the_shipped_knowledge_down_with_it() {
    let mine = scratch("bad.toml", "this is not [[[ valid toml");
    let loaded = load_files(Path::new(SHIPPED), &mine);
    assert!(is_modeled(&loaded.kb, "git", "bash"), "a broken user file disarmed the shipped descriptions");
    assert_eq!(loaded.gaps.len(), 1, "and it must be reported, not swallowed");
}

#[test]
fn trusting_a_program_claims_only_recognition_not_safety() {
    // The entry `vouch trust` writes has no `writes`, no `wraps` and no rules.
    // It says "I recognise this name" and nothing else, so [write] rules and
    // guards still apply to whatever the program is given.
    let extra = load("[[program]]\nmatch = [\"kubectl\"]\n").expect("parses");
    let p = &extra.program[0];
    assert!(p.writes.is_empty(), "trust must not claim it writes nothing in particular");
    assert!(p.wraps.is_empty());
    assert!(p.rule.is_empty());
}

#[test]
fn a_cli_is_not_one_operation() {
    // Trusting the NAME `kubectl` vouches for every verb it has. Recognition is
    // per command, so an entry scoped to `get` leaves `delete` unknown.
    use vouch::guards::recognises;
    use vouch::syntax::Cmd;

    let kb = load("[[program]]\nmatch = [\"kubectl\"]\nsubcommands = [\"get\"]\n").expect("parses");
    let cmd = |head: &str, args: &[&str]| Cmd {
        head: head.into(),
        args: args.iter().map(|s| s.to_string()).collect(),
        unread_args: Default::default(),
        keyword_args: Default::default(),
        callable_args: Default::default(),
        chain: None,
        prefix_assigns: vec![],
        receiver_origin: vouch::syntax::ValueOrigin::Unknown,
        by_reference: false,
    };

    // Hand-built probes, so the argument record is complete and closed by
    // construction (spec 2026-08-20 §2.4).
    assert!(recognises(&kb, &cmd("kubectl", &["get", "pods"]), "bash", true), "trusted verb");
    assert!(!recognises(&kb, &cmd("kubectl", &["delete", "pod"]), "bash", true), "untrusted verb");
    assert!(!recognises(&kb, &cmd("kubectl", &[]), "bash", true), "bare program");
    assert!(!recognises(&kb, &cmd("docker", &["ps"]), "bash", true), "different program");
}

#[test]
fn an_entry_with_no_subcommands_covers_the_whole_program() {
    // Right for `ls`, which has no verbs. The shipped entries rely on this.
    use vouch::guards::recognises;
    use vouch::syntax::Cmd;

    let kb = load("[[program]]\nmatch = [\"ls\"]\n").expect("parses");
    assert!(recognises(
        &kb,
        &Cmd {
            head: "ls".into(),
            args: vec!["-la".into()],
            unread_args: Default::default(),
            keyword_args: Default::default(),
            callable_args: Default::default(),
            chain: None,
            prefix_assigns: vec![],
            receiver_origin: vouch::syntax::ValueOrigin::Unknown,
            by_reference: false,
        },
        "bash",
        true
    ));
}
