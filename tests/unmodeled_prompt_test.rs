//! `guards::unmodeled_descriptions` — the data behind the unmodeled-command
//! prompt. One (name, what-an-entry-would-trust) pair per unrecognised thing,
//! in words, because a printed `vouch trust …` line cannot say either (M2.12).
//!
//! Every call below passes `standalone_eligible = true`. These fixtures carry
//! no `standalone_flags`, so the value cannot change what any of them
//! describes; `true` is the plan's stated choice for a scanned slice in a
//! test rather than a claim derived per command (spec 2026-08-20 §2.4).

use vouch::guards::unmodeled_descriptions;
use vouch::knowledge::load_files;
use vouch::shell::parse;

#[path = "common/mod.rs"]
mod common;
use common::v;



/// A tiny knowledge set of our own: one program scoped to one verb, with a
/// value-taking flag. `tag` keeps each test's scratch files unique — tests
/// run on parallel threads and a shared file is a torn-read flake.
fn kb_with_scoped_program(tag: &str) -> vouch::guards::Knowledge {
    let scratch = |name: String, content: &str| {
        let p = std::env::temp_dir().join(name);
        std::fs::write(&p, content).unwrap();
        p
    };
    let k = scratch(
        format!("vouch_unmodeled_{tag}_knowledge.toml"),
        &format!("version = {}\n[[program]]\nmatch = [\"totallymadeupgit\"]\n\
         subcommands = [\"pull\"]\nvalue_options = [\"-o\"]\n", v()),
    );
    let m = scratch(format!("vouch_unmodeled_{tag}_mine.toml"), "");
    load_files(&k, &m).kb
}

#[test]
fn two_unknown_programs_get_two_descriptions_not_one_joined_instruction() {
    let kb = kb_with_scoped_program("two_unknown");
    let scan = parse("totallymadeupalpha x && totallymadeupbeta y").unwrap();
    let items = unmodeled_descriptions(&kb, &scan.commands, "bash", true);
    assert_eq!(items.len(), 2, "{items:?}");
    assert_eq!(items[0].0, "totallymadeupalpha");
    assert!(
        items[0].1.contains("every operation of `totallymadeupalpha`"),
        "{:?}", items[0]
    );
    assert_eq!(items[1].0, "totallymadeupbeta");
}

#[test]
fn an_unknown_verb_of_a_known_program_is_described_as_that_verb_only() {
    // Defect 4's severe shape: `<program> <sub>` must be its own item, saying
    // it would trust that verb and nothing else — never joined with anything.
    let kb = kb_with_scoped_program("unknown_verb");
    let scan = parse("totallymadeupgit installeverything now").unwrap();
    let items = unmodeled_descriptions(&kb, &scan.commands, "bash", true);
    assert_eq!(items.len(), 1, "{items:?}");
    assert_eq!(items[0].0, "totallymadeupgit installeverything");
    assert!(
        items[0].1.contains("`installeverything` operation of `totallymadeupgit`"),
        "{:?}", items[0]
    );
    assert!(items[0].1.contains("nothing else"), "{:?}", items[0]);
}

#[test]
fn a_value_flags_value_is_never_described_as_the_verb() {
    // The naive "first non-flag argument" pick names `out.txt` here. The
    // description must use the SAME subcommand computation `recognises`
    // uses (`subcommand_of`), or the prompt describes an entry that cannot
    // cover the command.
    let kb = kb_with_scoped_program("value_flag");
    let scan = parse("totallymadeupgit -o out.txt installeverything").unwrap();
    let items = unmodeled_descriptions(&kb, &scan.commands, "bash", true);
    assert_eq!(items.len(), 1, "{items:?}");
    assert_eq!(items[0].0, "totallymadeupgit installeverything", "{items:?}");
    assert!(!items[0].1.contains("out.txt"), "{:?}", items[0]);
}

#[test]
fn a_path_spelled_head_is_described_by_the_bare_name_recognition_compares() {
    // Defect 1: `vouch trust <path>` wrote a rule that could never fire,
    // because matching strips the directory and `.exe` first. The description
    // must name the bare name an entry would actually need.
    let kb = kb_with_scoped_program("path_head");
    let scan = parse("/c/tools/totallymadeupfrob.exe --go").unwrap();
    let items = unmodeled_descriptions(&kb, &scan.commands, "bash", true);
    assert_eq!(items.len(), 1, "{items:?}");
    assert_eq!(items[0].0, "/c/tools/totallymadeupfrob.exe");
    assert!(items[0].1.contains("bare name"), "{:?}", items[0]);
    assert!(items[0].1.contains("`totallymadeupfrob`"), "{:?}", items[0]);
}

#[test]
fn a_recognised_command_produces_no_item() {
    let kb = kb_with_scoped_program("recognised");
    let scan = parse("totallymadeupgit pull").unwrap();
    let items = unmodeled_descriptions(&kb, &scan.commands, "bash", true);
    assert!(items.is_empty(), "{items:?}");
}
