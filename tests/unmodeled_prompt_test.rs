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
use vouch::protocol::Decision;
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

fn program_rule_scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "vouch-program-prompt-{tag}-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::canonicalize(dir).unwrap()
}

fn portable(path: &std::path::Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn program_rule_cfg(under: &str, names: &[&str]) -> vouch::config::Config {
    let names = names
        .iter()
        .map(|name| format!("\"{name}\""))
        .collect::<Vec<_>>()
        .join(", ");
    vouch::config::load(&format!(
        "[lang.bash]\ndefault = \"allow\"\n[lang.bash.constructs]\n\
         unmodeled_command = \"ask\"\n[[run.trust_program]]\n\
         under = [\"{under}\"]\nname_patterns = [{names}]\n"
    ))
    .unwrap()
}

fn ask_reason(cfg: &vouch::config::Config, command: &str, cwd: &std::path::Path) -> String {
    match vouch::engine::decide_command_at(
        cfg,
        "bash",
        command,
        Some(portable(cwd).as_str()),
        None,
        Some(portable(cwd).as_str()),
    ) {
        Decision::Ask(reason) => reason,
        other => panic!("expected program-location miss to ask: {other:?}"),
    }
}

#[test]
fn a_matching_name_with_an_unproven_file_names_the_location_clause() {
    let root = program_rule_scratch("missing-file");
    let cfg = program_rule_cfg(&format!("{}/**", portable(&root)), &["probe-*"]);
    let reason = ask_reason(&cfg, "./probe-missing inspect", &root);

    assert!(reason.contains("[[run.trust_program]] #1"), "{reason}");
    assert!(reason.contains("`under`"), "{reason}");
    assert!(reason.contains("does not exist"), "{reason}");
    assert!(!reason.contains("use the vouch-trust skill"), "{reason}");

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn a_matching_location_with_the_wrong_name_points_to_name_patterns_not_vouch_trust() {
    let root = program_rule_scratch("wrong-name");
    let program = root.join("generated-alpha");
    std::fs::write(&program, b"fixture").unwrap();
    let cfg = program_rule_cfg(&format!("{}/**", portable(&root)), &["probe-*"]);
    let reason = ask_reason(&cfg, &format!("{} inspect", portable(&program)), &root);

    assert!(reason.contains("[[run.trust_program]] #1"), "{reason}");
    assert!(reason.contains("`name_patterns`"), "{reason}");
    assert!(reason.contains("generated-alpha"), "{reason}");
    assert!(!reason.contains("use the vouch-trust skill"), "{reason}");

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn a_missing_configured_root_is_advisory_and_names_only_its_written_spelling() {
    let root = program_rule_scratch("missing-root");
    let program = root.join("probe-alpha");
    std::fs::write(&program, b"fixture").unwrap();
    let missing = root.join("not-built");
    let written = format!("{}/**", portable(&missing));
    let cfg = program_rule_cfg(&written, &["probe-*"]);
    let reason = ask_reason(&cfg, &format!("{} inspect", portable(&program)), &root);

    assert!(reason.contains("[[run.trust_program]] #1"), "{reason}");
    assert!(reason.contains(&written), "{reason}");
    assert!(reason.contains("inert now"), "{reason}");
    assert!(!reason.contains("use the vouch-trust skill"), "{reason}");

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn a_bare_head_matching_a_convention_explains_that_path_is_never_searched() {
    let root = program_rule_scratch("bare-head");
    let cfg = program_rule_cfg(&format!("{}/**", portable(&root)), &["probe-*"]);
    let reason = ask_reason(&cfg, "probe-alpha inspect", &root);

    assert!(reason.contains("[[run.trust_program]] #1"), "{reason}");
    assert!(reason.contains("PATH"), "{reason}");
    assert!(reason.contains("`under`"), "{reason}");
    assert!(!reason.contains("use the vouch-trust skill"), "{reason}");

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn an_unknown_unrelated_to_every_program_rule_keeps_the_ordinary_prompt() {
    let root = program_rule_scratch("unrelated");
    let cfg = program_rule_cfg(&format!("{}/**", portable(&root)), &["probe-*"]);
    let reason = ask_reason(&cfg, "unrelated-tool inspect", &root);

    assert!(!reason.contains("[[run.trust_program]]"), "{reason}");
    assert!(reason.contains("use the vouch-trust skill"), "{reason}");

    std::fs::remove_dir_all(root).unwrap();
}
