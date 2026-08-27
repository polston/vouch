//! Counts-only baseline for exact nested command-path recognition (M2.197).
//!
//! Before schema 11, shipped recognition could scope only the first verb. This
//! measurement was captured before `subcommand_paths` existed and remains the
//! counts-only regression census for the four motivating Codex paths. It uses
//! vouch's Bash scanner and shared flag classifier, prints no corpus command
//! text, and never reports an unrecognised path's words.
//!
//! Run: cargo run --release --example count_nested_command_paths

#[path = "../tests/common/mod.rs"]
mod common;

use std::collections::BTreeSet;
use vouch::flags::{Abbrev, ArgWalk, Class};

const TARGETS: [[&str; 2]; 4] = [
    ["mcp", "get"],
    ["mcp", "remove"],
    ["plugin", "list"],
    ["plugin", "remove"],
];

#[derive(Default)]
struct Tally {
    occurrences: usize,
    rows: BTreeSet<usize>,
}

fn codex_program() -> vouch::guards::Program {
    let mut program = vouch::guards::Program::default();
    program.value_options = [
        "-c",
        "--config",
        "--enable",
        "--disable",
        "--remote",
        "--remote-auth-token-env",
        "-i",
        "--image",
        "-m",
        "--model",
        "--local-provider",
        "-p",
        "--profile",
        "-s",
        "--sandbox",
        "-C",
        "--cd",
        "--add-dir",
        "-a",
        "--ask-for-approval",
    ]
    .into_iter()
    .map(str::to_string)
    .collect();
    program.no_value_options = [
        "--strict-config",
        "--oss",
        "--approve-for-me",
        "--dangerously-bypass-approvals-and-sandbox",
        "--dangerously-bypass-hook-trust",
        "--search",
        "--no-alt-screen",
        "-h",
        "--help",
        "-V",
        "--version",
    ]
    .into_iter()
    .map(str::to_string)
    .collect();
    program.case_sensitive_flags = Some(true);
    program
}

fn first_two_positionals(
    cmd: &vouch::shell::Cmd,
    program: &vouch::guards::Program,
) -> Result<Vec<String>, ()> {
    let vocab = vouch::flags::vocab_for(program, Abbrev::Refuse);
    let mut walk = ArgWalk::new(&vocab);
    let mut out = Vec::new();
    let mut skip_next = false;

    for (index, arg) in cmd.args.iter().enumerate() {
        if skip_next {
            skip_next = false;
            continue;
        }
        match walk.next(arg) {
            Class::NotFlag => {
                if cmd.unread_args.contains(&index) {
                    return Err(());
                }
                out.push(vouch::paths::unquote(arg).to_string());
                if out.len() == 2 {
                    return Ok(out);
                }
            }
            Class::EndOfOptions => {}
            Class::Value { attached: None, .. } => skip_next = true,
            Class::Value {
                attached: Some(_), ..
            }
            | Class::Bool { .. } => {}
            Class::Undescribed { .. } | Class::RefusedAbbrev { .. } => return Err(()),
        }
    }
    Ok(out)
}

fn main() {
    let rows = common::real_or_exit();
    let scanner = vouch::syntax::scanner_for("bash").expect("bash scanner exists");
    let program = codex_program();
    let mut tallies: Vec<Tally> = (0..TARGETS.len()).map(|_| Tally::default()).collect();
    let mut scanned = 0usize;
    let mut codex_rows = BTreeSet::new();
    let mut codex_occurrences = 0usize;
    let mut other_readable = 0usize;
    let mut unread_or_short = 0usize;

    for (row_index, row) in rows.iter().enumerate() {
        let Ok(scan) = scanner.scan(&row.cmd) else {
            continue;
        };
        scanned += 1;
        for cmd in &scan.commands {
            if vouch::guards::base_name(&cmd.head) != "codex" {
                continue;
            }
            codex_rows.insert(row_index);
            codex_occurrences += 1;
            match first_two_positionals(cmd, &program) {
                Ok(parts) if parts.len() == 2 => {
                    if let Some(target_index) = TARGETS
                        .iter()
                        .position(|target| parts[0] == target[0] && parts[1] == target[1])
                    {
                        tallies[target_index].occurrences += 1;
                        tallies[target_index].rows.insert(row_index);
                    } else {
                        other_readable += 1;
                    }
                }
                _ => unread_or_short += 1,
            }
        }
    }

    println!("corpus rows: {} ({scanned} scanned clean)", rows.len());
    println!(
        "codex: {} occurrences across {} rows",
        codex_occurrences,
        codex_rows.len()
    );
    for (target, tally) in TARGETS.iter().zip(&tallies) {
        println!(
            "codex {} {}: {} occurrences across {} rows",
            target[0],
            target[1],
            tally.occurrences,
            tally.rows.len()
        );
    }
    println!("other readable two-word codex paths: {other_readable}");
    println!("unreadable or shorter codex invocations: {unread_or_short}");
}
