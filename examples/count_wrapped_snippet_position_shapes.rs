//! On-demand measurement for the wrapped-snippet-position changeset
//! (M2.225): how often a real command hands a snippet to a wrapper, how often
//! that snippet writes through a shell redirect, and how often it also moves
//! the shell before writing — the pool where the wrapper's own position can
//! differ from the snippet's.
//!
//! It also counts the snippets whose own scan allocates scanner scopes, which
//! is the population that gains a real position from this changeset: before
//! it, every one of them was flattened into the single scope the expansion
//! allocated per snippet, so a compound body inside a snippet had no position
//! at all.
//!
//! **Every arm is proved to fire before any corpus number is printed.** A
//! zero here is the answer this measurement is most likely to give — the
//! shapes are rare — and a broken predicate produces the identical zero
//! (CLAUDE.md §6.5, one layer up: an inert detector and an absent shape look
//! the same). The control set below is invented text, is counted into its own
//! tally, is never mixed into the corpus figures, and a control that does not
//! fire exits nonzero instead of reporting.
//!
//! Every predicate runs over vouch's own bash scanner, the shipped knowledge,
//! and the real decision engine. No corpus text, path, command, or
//! destination is printed — aggregate counts only (CLAUDE.md §6).
//!
//! Run: `cargo run --release --example count_wrapped_snippet_position_shapes`

#[path = "../tests/common/mod.rs"]
mod common;

use vouch::syntax::Order;

/// Invented commands, each one a known positive for exactly one arm. Not
/// corpus rows and never counted as measurement: they exist so a zero below
/// means "the corpus has none", not "the predicate is inert".
const CONTROLS: &[(&str, &str)] = &[
    ("a snippet with a relative redirect after its own cd", "bash -c 'cd sub; echo x > rel.txt'"),
    ("the same, redirect inside a body within the snippet", "bash -c 'cd sub; (echo x > rel.txt)'"),
];

fn is_relative(path: &str) -> bool {
    let bytes = path.as_bytes();
    let drive_absolute = bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'/' | b'\\');
    !path.starts_with('/') && !drive_absolute
}

#[derive(Default)]
struct Counts {
    parsed_rows: usize,
    rows_with_snippet: usize,
    snippets_total: usize,
    snippets_scannable: usize,
    snippets_parsed: usize,
    snippets_with_redirect: usize,
    snippets_with_relative_redirect: usize,
    snippets_with_mover: usize,
    snippets_relative_redirect_and_mover: usize,
    snippets_mover_provably_before_redirect: usize,
    redirects_at_snippet_top_level: usize,
    redirects_inside_a_snippet_body: usize,
    rows_in_pool: usize,
    snippets_with_own_scopes: usize,
    snippets_with_own_scopes_and_redirect: usize,
    pool_allow: usize,
    pool_ask: usize,
    pool_deny: usize,
}

/// One command through every predicate. `cfg` decides only the rows that land
/// in M2.225's pool, which is the only place a verdict is reported.
fn tally(
    command: &str,
    kb: &vouch::guards::Knowledge,
    bash: &dyn vouch::syntax::Scanner,
    cfg: &vouch::config::Config,
    c: &mut Counts,
) {
    let Ok(scan) = bash.scan(command) else {
        return;
    };
    c.parsed_rows += 1;

    let ex = vouch::guards::expand_wrappers_with_sources(
        kb,
        &scan.commands,
        &scan.heredocs,
        &scan.input_source,
        &scan.args_complete,
        "bash",
        &|_| 4,
    );
    if ex.srcs.is_empty() {
        return;
    }
    c.rows_with_snippet += 1;
    c.snippets_total += ex.srcs.len();

    let mut row_in_pool = false;
    for snippet in &ex.srcs {
        let plang = snippet.lang.as_str();
        let Some(ps) = vouch::syntax::scanner_for(plang) else {
            continue;
        };
        c.snippets_scannable += 1;
        let Ok(inner) = ps.scan(&snippet.src) else {
            continue;
        };
        c.snippets_parsed += 1;

        if !inner.scan_scopes.is_empty() {
            c.snippets_with_own_scopes += 1;
            if !inner.redirect_targets.is_empty() {
                c.snippets_with_own_scopes_and_redirect += 1;
            }
        }
        if inner.redirect_targets.is_empty() {
            continue;
        }
        c.snippets_with_redirect += 1;

        let mut relative_redirect_at: Option<Order> = None;
        for (j, target) in inner.redirect_targets.iter().enumerate() {
            match inner.redirect_scope.get(j) {
                Some(Some(0)) => c.redirects_at_snippet_top_level += 1,
                _ => c.redirects_inside_a_snippet_body += 1,
            }
            if is_relative(target) && relative_redirect_at.is_none() {
                relative_redirect_at = inner.redirect_order.get(j).cloned();
            }
        }
        let has_relative = relative_redirect_at.is_some();
        if has_relative {
            c.snippets_with_relative_redirect += 1;
        }

        // A directory mover inside the snippet, read in the SNIPPET's own
        // language: what the wrapper's stamped position cannot see.
        let mut earliest_mover: Option<u32> = None;
        let mut any_mover = false;
        for (i, cmd) in inner.commands.iter().enumerate() {
            let Some((kind, _)) = vouch::guards::dir_change_entry_for_cmd(kb, cmd, plang) else {
                continue;
            };
            if kind == vouch::guards::DirChangeKind::No {
                continue;
            }
            any_mover = true;
            if matches!(inner.cmd_scope.get(i), Some(Some(0))) {
                if let Some(Order::Seq(n)) = inner.order.get(i) {
                    earliest_mover = Some(earliest_mover.map_or(*n, |m: u32| m.min(*n)));
                }
            }
        }
        if any_mover {
            c.snippets_with_mover += 1;
        }
        if any_mover && has_relative {
            c.snippets_relative_redirect_and_mover += 1;
            row_in_pool = true;
            if let (Some(mover_n), Some(Order::Seq(redirect_n))) =
                (earliest_mover, relative_redirect_at.as_ref())
            {
                if *redirect_n > mover_n {
                    c.snippets_mover_provably_before_redirect += 1;
                }
            }
        }
    }

    if row_in_pool {
        c.rows_in_pool += 1;
        let (verdict, _) = common::decision_at(cfg, command, common::HOOK_HOME);
        match verdict.as_str() {
            "allow" => c.pool_allow += 1,
            "ask" => c.pool_ask += 1,
            "deny" => c.pool_deny += 1,
            _ => {}
        }
    }
}

fn main() {
    let rows = common::rows_for_measurement();
    let kb = common::shipped_kb();
    let bash = vouch::syntax::scanner_for("bash").expect("bash scanner exists");
    let cfg = common::realistic_config();

    // The known-positive controls run FIRST and gate the report.
    let mut control = Counts::default();
    for (_, command) in CONTROLS {
        tally(command, &kb, bash.as_ref(), &cfg, &mut control);
    }
    let checks: [(&str, bool); 4] = [
        ("a relative redirect inside a snippet", control.snippets_with_relative_redirect > 0),
        ("a directory mover inside a snippet", control.snippets_with_mover > 0),
        ("the two together (M2.225's pool)", control.snippets_relative_redirect_and_mover > 0),
        (
            "the mover provably sequenced before the redirect",
            control.snippets_mover_provably_before_redirect > 0,
        ),
    ];
    let mut inert = false;
    for (what, fired) in checks {
        if !fired {
            eprintln!("control did not fire: {what}");
            inert = true;
        }
    }
    if inert {
        eprintln!(
            "This measurement's predicates no longer detect the shapes they \
             were written for, so its corpus counts would be zeros about the \
             detector rather than about the corpus. Fix the predicates before \
             reading any number from this example."
        );
        std::process::exit(1);
    }
    println!("controls: all {} arms fire on invented text", checks.len());

    let mut c = Counts::default();
    for row in &rows {
        tally(&row.cmd, &kb, bash.as_ref(), &cfg, &mut c);
    }

    println!("rows: {}", rows.len());
    println!("parsed rows: {}", c.parsed_rows);
    println!();
    println!("rows handing a snippet to a wrapper: {}", c.rows_with_snippet);
    println!("snippets located: {}", c.snippets_total);
    println!("  in a language with a scanner: {}", c.snippets_scannable);
    println!("  that parsed: {}", c.snippets_parsed);
    println!();
    println!("--- M2.225: an inner redirect against the wrapper's own base ---");
    println!("snippets with a shell redirect: {}", c.snippets_with_redirect);
    println!("  redirects at the snippet's top level: {}", c.redirects_at_snippet_top_level);
    println!("  redirects inside a body within the snippet: {}", c.redirects_inside_a_snippet_body);
    println!("snippets with a RELATIVE redirect target: {}", c.snippets_with_relative_redirect);
    println!("snippets with a directory mover: {}", c.snippets_with_mover);
    println!("snippets with BOTH (the pool): {}", c.snippets_relative_redirect_and_mover);
    println!(
        "  … mover provably sequenced before the redirect: {}",
        c.snippets_mover_provably_before_redirect
    );
    println!("rows in the pool: {}", c.rows_in_pool);
    println!(
        "  decided at {} under the standing replay config: allow {} / ask {} / deny {}",
        common::HOOK_HOME,
        c.pool_allow,
        c.pool_ask,
        c.pool_deny
    );
    println!();
    println!("--- the snippets that gain a position of their own ---");
    println!("snippets whose own scan allocates scopes: {}", c.snippets_with_own_scopes);
    println!("  … and that also carry a redirect: {}", c.snippets_with_own_scopes_and_redirect);
}
