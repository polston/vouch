//! On-demand measurement for M2.88: how often Python snippets change their
//! working directory, and how often a later described write depends on that
//! changed base.
//!
//! Every predicate is evaluated over vouch's own Bash/Python scanners,
//! wrapper expansion, and shipped write knowledge. No corpus text, path,
//! command, session value, or callable name is printed — aggregate counts
//! only (CLAUDE.md §6).
//!
//! Run: `cargo run --release --example count_python_chdir_shapes`

#[path = "../tests/common/mod.rs"]
mod common;

use vouch::syntax::Order;

fn is_relative(path: &str) -> bool {
    let bytes = path.as_bytes();
    let drive_absolute = bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'/' | b'\\');
    !path.starts_with('/') && !path.starts_with("//") && !drive_absolute
}

fn main() {
    let rows = common::rows_for_measurement();
    let kb = common::shipped_kb();
    let chdir_entry = kb
        .program
        .iter()
        .find(|program| {
            program
                .match_names
                .iter()
                .any(|name| name == "python:os.chdir")
        })
        .expect("the measured mover is shipped");
    let bash = vouch::syntax::scanner_for("bash").expect("bash scanner exists");
    let python = vouch::syntax::scanner_for("python").expect("python scanner exists");

    let mut parsed_rows = 0usize;
    let mut python_snippets = 0usize;
    let mut snippets_with_chdir = 0usize;
    let mut rows_with_chdir = 0usize;
    let mut chdir_calls = 0usize;
    let mut literal_destination_calls = 0usize;
    let mut unreadable_destination_calls = 0usize;
    let mut relative_destination_calls = 0usize;
    let mut absolute_destination_calls = 0usize;
    let mut snippets_with_later_relative_write = 0usize;
    let mut rows_with_later_relative_write = 0usize;
    let mut later_relative_writes = 0usize;

    for row in &rows {
        let Ok(scan) = bash.scan(&row.cmd) else {
            continue;
        };
        parsed_rows += 1;
        let expanded = vouch::guards::expand_wrappers_with_sources(
            &kb,
            &scan.commands,
            &scan.heredocs,
            &scan.input_source,
            &scan.args_complete,
            "bash",
            &|_| 4,
        );
        let mut row_chdir = false;
        let mut row_later_write = false;

        for (lang, source) in expanded.srcs {
            if lang != "python" {
                continue;
            }
            python_snippets += 1;
            let Ok(inner) = python.scan(&source) else {
                continue;
            };
            let mut snippet_chdir = false;
            let mut snippet_later_write = false;
            let mut latest_ordered_chdir: Option<u32> = None;

            for (index, command) in inner.commands.iter().enumerate() {
                let order = inner.order.get(index);
                if command.head == "python:os.chdir" {
                    chdir_calls += 1;
                    snippet_chdir = true;
                    row_chdir = true;
                    let effective = vouch::guards::effective_args(chdir_entry, command);
                    match effective.values.first() {
                        Some(_) if effective.unread.contains(&0) => {
                            unreadable_destination_calls += 1;
                        }
                        Some(path) if !effective.padding.contains(&0) => {
                            literal_destination_calls += 1;
                            if is_relative(path) {
                                relative_destination_calls += 1;
                            } else {
                                absolute_destination_calls += 1;
                            }
                        }
                        _ => unreadable_destination_calls += 1,
                    }
                    latest_ordered_chdir = match order {
                        Some(Order::Seq(sequence)) => Some(*sequence),
                        _ => None,
                    };
                    continue;
                }

                let Some(chdir_order) = latest_ordered_chdir else {
                    continue;
                };
                let Some(Order::Seq(command_order)) = order else {
                    continue;
                };
                if *command_order <= chdir_order {
                    continue;
                }
                let writes = vouch::guards::written_paths_in(&kb, command, "python");
                let count = writes.paths.iter().filter(|path| is_relative(path)).count();
                if count > 0 {
                    later_relative_writes += count;
                    snippet_later_write = true;
                    row_later_write = true;
                }
            }

            snippets_with_chdir += usize::from(snippet_chdir);
            snippets_with_later_relative_write += usize::from(snippet_later_write);
        }

        rows_with_chdir += usize::from(row_chdir);
        rows_with_later_relative_write += usize::from(row_later_write);
    }

    println!("corpus_rows={}", rows.len());
    println!("parsed_bash_rows={parsed_rows}");
    println!("python_snippets={python_snippets}");
    println!("rows_with_chdir={rows_with_chdir}");
    println!("snippets_with_chdir={snippets_with_chdir}");
    println!("chdir_calls={chdir_calls}");
    println!("literal_destination_calls={literal_destination_calls}");
    println!("unreadable_destination_calls={unreadable_destination_calls}");
    println!("relative_destination_calls={relative_destination_calls}");
    println!("absolute_destination_calls={absolute_destination_calls}");
    println!("rows_with_later_relative_write={rows_with_later_relative_write}");
    println!("snippets_with_later_relative_write={snippets_with_later_relative_write}");
    println!("later_relative_writes={later_relative_writes}");
}
