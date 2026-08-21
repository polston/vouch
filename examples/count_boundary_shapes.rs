//! On-demand measurement (the eighth): pre-counts for the boundary-closure
//! changeset (`docs/specs/2026-08-14-boundary-closure-design.md` §7), which
//! requires counting the affected shapes in the real corpus BEFORE building
//! each track, so a track's cost is known ahead of the change rather than
//! argued about after (CLAUDE.md §6.2).
//!
//! Ten populations, one predicate each, stated as a comment directly above
//! the count that answers it. Every predicate is evaluated over vouch's own
//! parser output — `vouch::syntax::scanner_for("bash")`'s `Scan`/`Cmd`
//! structures and the loaded knowledge — never a regex over the raw corpus
//! text (CLAUDE.md §6.1). Three populations (script-file positionals, the
//! cmd-family flag population) derive their name/flag sets from the shipped
//! `knowledge.toml` itself — the `after_c`-wrapping shells entry, python's
//! own entry, and the `cmd` entry's own `wrap_flags` — rather than a
//! hand-typed list, so a knowledge edit cannot make them silently stale.
//!
//! A further line item from the spec's measurement protocol, the
//! conditional-chain count, is NOT here: its predicate (a mover whose chain
//! position is conditional with a later `;`) is only expressible once T10's
//! `ChainPos` representation exists in `src/`, and this branch is docs-only
//! (no `src/` changes) up to and including this commit. That count moved to
//! a later task's step 0, per the task brief.
//!
//! Prints ONLY aggregate counts. The corpus is real recorded command
//! history; no command text from it is printed.
//!
//! Run: `cargo run --release --example count_boundary_shapes`

#[path = "../tests/common/mod.rs"]
mod common;

use vouch::guards::{self, flag_matches};
use vouch::paths;

/// A raw token surrounded by one matching pair of quote marks — the shape
/// `paths::unquote` strips a layer from.
fn is_quoted(tok: &str) -> bool {
    tok.len() >= 2
        && ((tok.starts_with('"') && tok.ends_with('"'))
            || (tok.starts_with('\'') && tok.ends_with('\'')))
}

/// True when `raw` spells an ATTACHED or JOINED form of one of `write_flags`
/// that would NOT already match via `flag_matches` today: `--flag=value`
/// (long flag, `=`-joined), `-Xvalue` (two-character unix short flag,
/// attached with no separator), or `-Name:value` (PowerShell named
/// parameter, `:`-attached) — the three shapes design §4.1 items 2 and the
/// PowerShell attached form add. An exact `flag_matches` hit is excluded on
/// purpose: that spelling already matches today and is not part of the
/// population this count measures.
fn attached_write_flag(write_flags: &[String], case_sensitive: bool, raw: &str) -> bool {
    let tok = paths::unquote(raw);
    if flag_matches(write_flags, tok, case_sensitive) {
        return false;
    }
    let norm = |s: &str| {
        if case_sensitive {
            s.to_string()
        } else {
            s.to_lowercase()
        }
    };
    let tok_n = norm(tok);
    write_flags.iter().any(|wf| {
        let wf_n = norm(wf);
        match tok_n.strip_prefix(wf_n.as_str()) {
            Some(rest) if !rest.is_empty() => {
                if wf.starts_with("--") {
                    rest.starts_with('=')
                } else if wf.len() == 2 {
                    // -Xvalue: any attached remainder counts, no separator.
                    true
                } else {
                    rest.starts_with(':')
                }
            }
            _ => false,
        }
    })
}

/// The first token that is not itself a flag (does not start with `-`) — a
/// shell's or python's own script-file positional, once a `-c`-family
/// snippet flag has already been ruled out by the caller. A bare `-` is the
/// documented stdin marker (§knowledge.toml comment on the shells/python
/// entries), never a file, and is excluded here.
fn first_nonflag_positional(args: &[String]) -> Option<&str> {
    args.iter()
        .map(String::as_str)
        .find(|a| !a.starts_with('-'))
        .filter(|a| *a != "-")
}

/// A Windows drive-absolute spelling: one letter, `:`, then nothing or a
/// separator (`C:`, `C:/x`, `C:\x`). Anything else containing a `:` is a
/// RELATIVE colon-bearing destination for this count's purposes — the
/// alternate-data-stream shape (`notes.txt:hidden`) or a scheme-like prefix
/// the entry has not declared `remote_dest = true` for.
fn is_drive_absolute(t: &str) -> bool {
    let b = t.as_bytes();
    b.len() >= 2
        && b[0].is_ascii_alphabetic()
        && b[1] == b':'
        && (b.len() == 2 || b[2] == b'/' || b[2] == b'\\')
}

fn main() {
    let rows = common::rows_for_measurement();
    let kb = common::shipped_kb();
    let scanner = vouch::syntax::scanner_for("bash").expect("bash scanner exists");

    // Name sets derived from the loaded knowledge, not hand-typed, per the
    // task brief: they cannot go stale against a knowledge.toml edit.
    let shells_entry = kb
        .program
        .iter()
        .find(|p| p.wraps == "after_c")
        .expect("knowledge.toml declares the after_c shells entry (sh/bash/zsh/dash/ksh)");
    let python_entry = kb
        .program
        .iter()
        .find(|p| p.match_names.iter().any(|n| n == "python"))
        .expect("knowledge.toml declares python's own entry");
    let cmd_entry = kb
        .program
        .iter()
        .find(|p| p.match_names.iter().any(|n| n == "cmd"))
        .expect("knowledge.toml declares the cmd entry");

    let mut parsed_rows = 0usize;

    let (mut quoted_flag_rows, mut quoted_flag_hits) = (0usize, 0usize);
    let (mut attached_write_rows, mut attached_write_hits) = (0usize, 0usize);
    let mut script_file_shell_rows = 0usize;
    let mut script_file_python_rows = 0usize;
    let (mut colon_dest_rows, mut colon_dest_hits) = (0usize, 0usize);
    let (mut backslash_head_rows, mut backslash_head_hits) = (0usize, 0usize);
    let mut awk_inline_rows = 0usize;
    let mut cmd_c_flag_rows = 0usize;
    let (mut env_lookup_rows, mut env_startup_rows) = (0usize, 0usize);
    let mut here_write_rows = 0usize;
    let mut here_write_head_rows = 0usize;
    let (mut conditional_mover_rows, mut unfolded_rows) = (0usize, 0usize);

    for row in &rows {
        let Ok(scan) = scanner.scan(&row.cmd) else {
            continue;
        };
        parsed_rows += 1;

        let (mut row_quoted, mut row_attached) = (false, false);
        let (mut row_script_shell, mut row_script_python) = (false, false);
        let (mut row_backslash, mut row_awk, mut row_cmd_c) = (false, false, false);
        let mut row_colon = false;

        for cmd in &scan.commands {
            // Predicate 1: a raw argument token wrapped in matching quote
            // marks whose UNQUOTED text exactly names a flag in `any_flag` on
            // some rule of the command's matched knowledge entry, on an
            // entry that carries at least one guard rule (M2.119 — guard
            // matching compares raw tokens today, quotes included, so a
            // quoted spelling of a flag that would trip a guard bare never
            // does). Scoped to `any_flag`, the literal "flag" population;
            // the round-2-broadened non-flag arms (`any_arg_exact`,
            // `any_arg_prefix`) are a related, separate population not
            // counted here.
            if let Some(entry) = guards::entry_for(&kb, &cmd.head, "bash") {
                if !entry.rule.is_empty() {
                    let flags: Vec<&str> = entry
                        .rule
                        .iter()
                        .flat_map(|r| r.any_flag.iter().map(String::as_str))
                        .collect();
                    for a in &cmd.args {
                        if is_quoted(a) && flags.contains(&paths::unquote(a)) {
                            quoted_flag_hits += 1;
                            row_quoted = true;
                        }
                    }
                }

                // Predicate 2: a token on an entry declaring `write_flags`
                // (`writes = "named"` or `"flags_only"`) that spells an
                // attached or joined form of one of them rather than an
                // exact match (M2.128) — see `attached_write_flag`.
                if matches!(entry.writes.as_str(), "named" | "flags_only")
                    && !entry.write_flags.is_empty()
                {
                    let cs = entry.case_sensitive_flags.unwrap_or(false);
                    for a in &cmd.args {
                        if attached_write_flag(&entry.write_flags, cs, a) {
                            attached_write_hits += 1;
                            row_attached = true;
                        }
                    }
                }
            }

            let is_named = |names: &[String]| {
                names
                    .iter()
                    .any(|n| n.eq_ignore_ascii_case(&guards::base_name(&cmd.head)))
            };

            // Predicate 3a: the command's head is the after_c shells entry,
            // no exact `-c` token is present (mirrors the literal, unquoted
            // match `guards.rs`'s `after_c` wrap arm makes today), and the
            // first non-flag token is a script-file positional (§5.1).
            if is_named(&shells_entry.match_names)
                && !cmd.args.iter().any(|a| a == "-c")
                && first_nonflag_positional(&cmd.args).is_some()
            {
                row_script_shell = true;
            }

            // Predicate 3b: same shape for python's own entry, except "no
            // -c flag consumed a snippet" is answered by the real
            // `after_flag_snippet` extractor rather than a re-derived
            // literal match, since python's wrap is `after_flag` (attached
            // and `=`-joined spellings of `-c` are also snippets, not script
            // files).
            if is_named(&python_entry.match_names)
                && guards::after_flag_snippet(python_entry, &cmd.args).is_none()
                && first_nonflag_positional(&cmd.args).is_some()
            {
                row_script_python = true;
            }

            // Predicate 5: the command's HEAD, as the scanner recorded it —
            // before any normalisation — contains a literal backslash.
            // Today `guards::base_name` folds every `\` to `/` regardless of
            // language; §4.4.2 moves that fold out of bash, where an
            // unquoted `\` is an escape character, not a separator. Read
            // from the RAW head on purpose: `base_name` is the very
            // transformation this count is measuring the population behind.
            if cmd.head.contains('\\') {
                backslash_head_hits += 1;
                row_backslash = true;
            }

            // Predicate 6: the command's head is `awk`, no token (unquoted)
            // is `-f` or an attached `-f<file>` (the read-a-program-from-a-
            // file shape, a DIFFERENT population from the inline one), and
            // at least one non-flag token is present — the inline program
            // text itself.
            if guards::base_name(&cmd.head) == "awk" {
                let has_f_flag = cmd.args.iter().any(|a| {
                    let u = paths::unquote(a);
                    u == "-f" || (u.len() > 2 && u.starts_with("-f"))
                });
                let has_program_text =
                    cmd.args.iter().any(|a| !paths::unquote(a).starts_with('-'));
                if !has_f_flag && has_program_text {
                    row_awk = true;
                }
            }

            // Predicate 7: the command's head is the cmd entry (`cmd` /
            // `cmd.exe`) and a token (unquoted) exactly names one of that
            // entry's OWN `wrap_flags` — the `/c`-family switches
            // (`/c`, `/C`, `/k`, `/K`) read from the knowledge rather than
            // hand-typed.
            if is_named(&cmd_entry.match_names)
                && cmd
                    .args
                    .iter()
                    .any(|a| cmd_entry.wrap_flags.iter().any(|f| f == paths::unquote(a)))
            {
                row_cmd_c = true;
            }
        }

        // Predicate 4: a literal `>`/`>>`-style redirect target contains a
        // `:` and is not a Windows drive-absolute spelling — scoped to
        // `scan.redirect_targets`, the subset design §6.2 item 3 names as
        // the alternate-data-stream case; write targets reached through a
        // program's own flags (`write_flags`) are a separate, uncounted
        // channel for this predicate.
        for t in &scan.redirect_targets {
            if t.contains(':') && !is_drive_absolute(t) {
                colon_dest_hits += 1;
                row_colon = true;
            }
        }

        if row_quoted {
            quoted_flag_rows += 1;
        }
        if row_attached {
            attached_write_rows += 1;
        }
        if row_script_shell {
            script_file_shell_rows += 1;
        }
        if row_script_python {
            script_file_python_rows += 1;
        }
        if row_colon {
            colon_dest_rows += 1;
        }
        if row_backslash {
            backslash_head_rows += 1;
        }
        if row_awk {
            awk_inline_rows += 1;
        }
        if row_cmd_c {
            cmd_c_flag_rows += 1;
        }

        // Predicate 8: an assignment — a command's own PREFIX word, or a
        // same-line assignment the scan recorded — to a name declared in
        // `[[env_name]]` (M2.120). Names come from the loaded knowledge, so
        // this count cannot drift from what the judgement will read. Split
        // by effect, because the two produce different asks and therefore
        // different costs: a lookup name says the program described may not
        // be the program that runs, a startup name says unread code runs
        // first.
        let mut row_lookup = false;
        let mut row_startup = false;
        let declared = |n: &str| kb.env_name.iter().find(|e| e.name == n);
        for cmd in &scan.commands {
            for name in &cmd.prefix_assigns {
                match declared(name).map(|e| e.effect.as_str()) {
                    Some("lookup") => row_lookup = true,
                    Some("startup") => row_startup = true,
                    _ => {}
                }
            }
        }
        for (name, _) in &scan.assignments {
            match declared(name).map(|e| e.effect.as_str()) {
                Some("lookup") => row_lookup = true,
                Some("startup") => row_startup = true,
                _ => {}
            }
        }
        // Predicate 9: a command whose entry declares a "writes where it
        // stands" shape (M2.129) and whose derivation actually landed on it
        // — read from the real `written_paths`, so it counts what the
        // judgement counts rather than a re-derived approximation. Scoped by
        // the entry declaring `here_write`, since `run_dir_dest` is also
        // reachable through `sub_write.takes = "run_dir"` (git clone).
        let mut row_here_write = false;
        let mut row_here_write_head = false;
        for cmd in &scan.commands {
            let declares = guards::entry_for(&kb, &cmd.head, "bash")
                .is_some_and(|e| !e.here_write.is_empty());
            if declares {
                row_here_write_head = true;
            }
            if declares && guards::written_paths(&kb, cmd).run_dir_dest {
                row_here_write = true;
            }
        }
        if row_here_write_head {
            here_write_head_rows += 1;
        }

        // Predicate 10: the conditional-chain population (M2.130) — the count
        // T3 deferred until `ChainPos` existed. A row counts as carrying a
        // conditional mover when some directory-changing command is not the
        // first member of its and-or chain; it counts as UNFOLDED when a
        // later command on the same line does not imply that mover ran, which
        // is the shape whose base becomes Unknown. The fold question is asked
        // of `engine::folds_into` itself, never re-derived here.
        let movers: Vec<(usize, Option<vouch::syntax::ChainPos>)> = scan
            .commands
            .iter()
            .enumerate()
            .filter(|(_, c)| {
                matches!(
                    guards::dir_change_entry(&kb, &guards::base_name(&c.head), "bash"),
                    Some((k, _)) if k != guards::DirChangeKind::No
                )
            })
            .map(|(i, c)| (i, c.chain))
            .collect();
        let conditional: Vec<&(usize, Option<vouch::syntax::ChainPos>)> = movers
            .iter()
            .filter(|(_, ch)| ch.is_some_and(|cp| cp.idx > 0))
            .collect();
        if !conditional.is_empty() {
            conditional_mover_rows += 1;
            let unfolded = conditional.iter().any(|(mi, mch)| {
                scan.commands.iter().enumerate().skip(mi + 1).any(|(_, later)| {
                    !vouch::engine::folds_into(mch.as_ref(), later.chain.as_ref())
                })
            });
            if unfolded {
                unfolded_rows += 1;
            }
        }
        if row_here_write {
            here_write_rows += 1;
        }
        if row_lookup {
            env_lookup_rows += 1;
        }
        if row_startup {
            env_startup_rows += 1;
        }
    }

    println!("boundary-closure pre-counts ({parsed_rows} of {} rows parsed)", rows.len());
    println!(
        "1. quoted flag tokens on guard-bearing entries: {quoted_flag_rows} rows ({quoted_flag_hits} tokens)"
    );
    println!(
        "2. attached/joined write-flag spellings: {attached_write_rows} rows ({attached_write_hits} tokens)"
    );
    println!("3. script-file positionals: shells {script_file_shell_rows} rows, python {script_file_python_rows} rows");
    println!(
        "4. colon-bearing relative destinations: {colon_dest_rows} rows ({colon_dest_hits} targets)"
    );
    println!(
        "5. backslash-bearing heads: {backslash_head_rows} rows ({backslash_head_hits} heads)"
    );
    println!("6. awk inline programs: {awk_inline_rows} rows");
    println!("7. cmd-family heads with a /c-family flag: {cmd_c_flag_rows} rows");
    println!(
        "8. assignments to a declared env name: lookup {env_lookup_rows} rows, startup {env_startup_rows} rows"
    );
    println!(
        "9. writes-where-it-stands: {here_write_head_rows} rows run one of the declaring          programs, {here_write_rows} of them derive the run place"
    );
    println!(
        "10. conditional directory changes: {conditional_mover_rows} rows carry one,          {unfolded_rows} of them have a later command it does not fold into"
    );
}
