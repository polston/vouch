//! What the real corpus actually contains, counted with vouch's OWN parser.
//!
//! Text matching over whole command lines does not answer this. Two attempts
//! at counting `curl -o` by regex and by adjacent tokens both reported hundreds
//! of matches that were really one command containing the word list
//! `for t in curl wget git npm pip python` with an unrelated `-o` elsewhere.
//!
//! The parser sees exactly what the knowledge file will see: a program head and
//! its own arguments. That is the only count worth acting on.

mod common;

use std::collections::HashMap;
use vouch::guards::{expand_wrappers_with_sources, in_effect as builtin, is_modeled};
use vouch::paths::{unquote, unquote_snippet};
use vouch::python;
use vouch::shell::parse;
use vouch::syntax::Order;

/// The REAL corpus only. These are measurements; a count taken over invented
/// commands would be a fabricated number, so absence is a skip, never a
/// fallback to the synthetic corpus.
fn corpus() -> Option<Vec<String>> {
    Some(common::real()?.into_iter().map(|r| r.cmd).collect())
}

/// Every command a line contains after wrapper expansion, handing the expansion
/// the scan's OWN per-command facts.
///
/// One helper rather than the same seven-argument call at seventeen sites: a
/// site that passes an empty slice by mistake measures the fail-closed default
/// instead of what the scanner actually resolved, and a measurement that
/// silently measures the wrong thing is the failure mode §6 exists to prevent.
fn expanded(kb: &vouch::guards::Knowledge, scan: &vouch::syntax::Scan) -> Vec<vouch::syntax::Cmd> {
    expand_wrappers_with_sources(
        kb,
        &scan.commands,
        &scan.heredocs,
        &scan.input_source,
        &scan.args_complete,
        "bash",
        &|_| 4,
    )
    .cmds
}

/// Counts, per program, how many corpus commands invoke it — parsed, not matched.
fn head_counts(cmds: &[String]) -> HashMap<String, usize> {
    let kb = builtin();
    let mut counts: HashMap<String, usize> = HashMap::new();
    for c in cmds {
        let scan = match parse(c) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let cmds = expanded(kb, &scan);
        let mut seen = std::collections::HashSet::new();
        for cmd in &cmds {
            let h = cmd.head.rsplit('/').next().unwrap_or(&cmd.head).to_string();
            if seen.insert(h.clone()) {
                *counts.entry(h).or_default() += 1;
            }
        }
    }
    counts
}

#[test]
fn report_what_the_corpus_actually_runs() {
    let Some(cmds) = corpus() else {
        return common::skip("corpus_shapes");
    };
    let counts = head_counts(&cmds);
    let kb = builtin();
    let mut v: Vec<_> = counts.iter().collect();
    v.sort_by_key(|(_, n)| std::cmp::Reverse(**n));

    eprintln!("--- programs the corpus actually invokes (parsed) ---");
    for (name, n) in v.iter().take(40) {
        let known = if is_modeled(kb, name, "bash") { "modelled" } else { "" };
        eprintln!("  {n:>5}  {name:<24} {known}");
    }

    // Not an assertion about any particular program — only that the corpus
    // parsed into something. A silent empty result would make every count
    // above a lie of omission.
    assert!(
        counts.values().sum::<usize>() > 1000,
        "parsed almost nothing: {} total invocations",
        counts.values().sum::<usize>()
    );
}

#[test]
fn the_download_and_clone_shapes_are_counted_honestly() {
    let kb = builtin();
    let mut curl_o = 0usize;
    let mut git_clone_dir = 0usize;
    let mut git_init_dir = 0usize;
    let mut examples: Vec<String> = Vec::new();

    let Some(cmds) = corpus() else {
        return common::skip("corpus_shapes");
    };
    for c in cmds {
        let scan = match parse(&c) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let cmds = expanded(kb, &scan);
        for cmd in &cmds {
            let head = cmd.head.rsplit('/').next().unwrap_or(&cmd.head);
            if head == "curl" && cmd.args.iter().any(|a| a == "-o" || a == "--output") {
                curl_o += 1;
                if examples.len() < 5 {
                    examples.push(format!("curl: {}", cmd.args.join(" ")));
                }
            }
            if head == "git" {
                let sub = cmd.args.iter().find(|a| !a.starts_with('-'));
                let positional = cmd.args.iter().filter(|a| !a.starts_with('-')).count();
                match sub.map(String::as_str) {
                    Some("clone") if positional >= 3 => git_clone_dir += 1,
                    Some("init") if positional >= 2 => git_init_dir += 1,
                    _ => {}
                }
            }
        }
    }

    eprintln!("--- counted with the parser, not with a regex ---");
    eprintln!("  curl with an output file : {curl_o}");
    eprintln!("  git clone <url> <dir>    : {git_clone_dir}");
    eprintln!("  git init <dir>           : {git_init_dir}");
    for e in &examples {
        eprintln!("      {}", e.chars().take(110).collect::<String>());
    }
}

#[test]
fn show_which_download_destinations_fall_outside_the_declared_areas() {
    // Modelling `curl -o` adds prompts. This prints exactly which commands, so
    // the cost is inspectable rather than a delta in a summary line.
    let cfg = vouch::config::load(
        r#"
version = 1
[lang.bash]
default = "allow"
[lang.bash.constructs]
dynamic_command = "allow"
dynamic_redirect = "allow"
subshell = "allow"
background = "allow"
heredoc = "allow"
function_def = "allow"
unmodeled_command = "allow"
parse_failure = "allow"
redirect = "allow"
unresolved_path = "allow"
[write]
default = "ask"
allow_paths = [
  "C:/work/**", "C:/git/**", "C:/claude/**", "C:/tmp/**",
  "$HOME/**", "/tmp/**", "/private/tmp/**", "/Users/**",
]
"#,
    )
    .expect("parses");

    let mut shown = 0;
    let Some(cmds) = corpus() else {
        return common::skip("corpus_shapes");
    };
    for c in cmds {
        if !c.contains("curl") && !c.contains("wget") {
            continue;
        }
        if let vouch::protocol::Decision::Ask(r) =
            vouch::engine::decide_command_in(&cfg, "bash", &c, Some("C:/Users/dev"), None)
        {
            if !r.contains("allowed area") {
                continue;
            }
            shown += 1;
            if shown <= 10 {
                eprintln!("  ASK {}", r.lines().nth(1).unwrap_or("").trim());
                eprintln!("      {}", c.split_whitespace().collect::<Vec<_>>().join(" ").chars().take(110).collect::<String>());
            }
        }
    }
    eprintln!("download destinations outside the declared areas: {shown}");
}

#[test]
fn count_heredocs_that_feed_a_shell() {
    // A heredoc body fed to `python` is Python; fed to `bash` it is a shell
    // script that vouch could read but does not. Only the second is a gap, so
    // the two have to be counted apart rather than lumped as "heredoc".
    //
    // Re-keyed on the captured `scan.heredocs` records (Task 12) rather than
    // the `"heredoc"` construct note: a landing-command heredoc is now
    // CAPTURED, not noted, so gating on the construct here would silently
    // count ~0 (the exact §6.3 failure this file's own header warns about —
    // absence in a changed signal is evidence about the signal, not the
    // corpus). Reading `scan.heredocs[i].cmd_index` directly also drops the
    // old approximation ("any shell head anywhere in the command counts"),
    // since a heredoc now names its OWN consuming command exactly.
    let mut to_shell = 0usize;
    let mut to_other: HashMap<String, usize> = HashMap::new();
    let mut examples: Vec<String> = Vec::new();

    let Some(cmds) = corpus() else {
        return common::skip("corpus_shapes");
    };
    for c in cmds {
        if !c.contains("<<") {
            continue;
        }
        let scan = match parse(&c) {
            Ok(s) => s,
            Err(_) => continue,
        };
        for heredoc in &scan.heredocs {
            let Some(cmd) = scan.commands.get(heredoc.cmd_index) else {
                continue;
            };
            let h = cmd
                .head
                .rsplit('/')
                .next()
                .unwrap_or(&cmd.head)
                .to_lowercase();
            let h = h.trim_end_matches(".exe");
            if matches!(h, "bash" | "sh" | "zsh" | "dash" | "ksh") {
                to_shell += 1;
                if examples.len() < 5 {
                    examples.push(c.chars().take(100).collect());
                }
            } else if matches!(h, "python" | "python3" | "node" | "cat" | "jq" | "psql") {
                *to_other.entry(h.to_string()).or_default() += 1;
            }
        }
    }

    eprintln!("--- heredocs, by what consumes them ---");
    eprintln!("  fed to a SHELL (a gap): {to_shell}");
    let mut v: Vec<_> = to_other.iter().collect();
    v.sort_by_key(|(_, n)| std::cmp::Reverse(**n));
    for (name, n) in v {
        eprintln!("  fed to {name:<10} (not bash, not a gap): {n}");
    }
    for e in &examples {
        eprintln!("      {}", e.split_whitespace().collect::<Vec<_>>().join(" "));
    }
}

/// The spec's promised TRUE heredoc feed-count, replacing the 636 co-presence
/// upper bound (a command line merely CONTAINING both `<<` and a program name
/// is not the same as that heredoc actually reaching that program — the same
/// distinction the file header's `curl -o` story makes about text matching in
/// general). Counted with `guards::heredoc_feeds` — the exact predicate the
/// locator and the engine's marking both use — so this number is what Task
/// 12's own mechanism decides, not a re-derived approximation of it.
#[test]
fn measure_heredoc_feed_count() {
    let kb = builtin();
    let mut fired: HashMap<String, usize> = HashMap::new();
    let mut total = 0usize;
    let mut quoted = 0usize;
    let mut unquoted = 0usize;
    let mut expansion_bearing = 0usize;
    let mut expansion_free = 0usize;

    let Some(cmds) = corpus() else {
        return common::skip("corpus_shapes");
    };
    for c in cmds {
        if !c.contains("<<") {
            continue;
        }
        let scan = match parse(&c) {
            Ok(s) => s,
            Err(_) => continue,
        };
        for heredoc in &scan.heredocs {
            let Some(cmd) = scan.commands.get(heredoc.cmd_index) else {
                continue;
            };
            total += 1;
            if heredoc.quoted_delimiter {
                quoted += 1;
            } else {
                unquoted += 1;
            }
            if heredoc.body.contains('$') || heredoc.body.contains('`') {
                expansion_bearing += 1;
            } else {
                expansion_free += 1;
            }
            if let Some((_entry, lang)) = vouch::guards::heredoc_feeds(kb, cmd, heredoc) {
                let h = cmd
                    .head
                    .rsplit('/')
                    .next()
                    .unwrap_or(&cmd.head)
                    .to_lowercase();
                let h = h.trim_end_matches(".exe");
                let lang = if lang.is_empty() { "bash" } else { lang };
                *fired.entry(format!("{h} ({lang})")).or_default() += 1;
            }
        }
    }

    eprintln!("--- true heredoc feed-count (guards::heredoc_feeds fires) ---");
    eprintln!("  heredocs captured (landing command)  : {total}");
    eprintln!("  quoted delimiter   : {quoted}");
    eprintln!("  unquoted delimiter : {unquoted}");
    eprintln!("  expansion-bearing body : {expansion_bearing}");
    eprintln!("  expansion-free body    : {expansion_free}");
    let mut v: Vec<_> = fired.iter().collect();
    v.sort_by_key(|(_, n)| std::cmp::Reverse(**n));
    for (name, n) in v {
        eprintln!("  feeds {name:<24}: {n}");
    }
    eprintln!("  TOTAL fed (predicate true): {}", fired.values().sum::<usize>());
}

#[test]
fn show_the_commands_vouch_cannot_read() {
    // Three corpus commands fail to parse. A parse failure is vouch's own
    // defect, not a judgement about the command, so they get looked at.
    let mut n = 0;
    let Some(cmds) = corpus() else {
        return common::skip("corpus_shapes");
    };
    for c in cmds {
        if let Err(e) = parse(&c) {
            n += 1;
            if n <= 6 {
                eprintln!("  PARSE FAIL: {e}");
                eprintln!("    {}", c.split_whitespace().collect::<Vec<_>>().join(" ").chars().take(160).collect::<String>());
            }
        }
    }
    eprintln!("corpus commands vouch cannot read: {n}");
}

#[test]
fn count_the_iteration_23_candidates() {
    // Every one of these is a rule that could be written. The corpus decides
    // which are worth writing — a shape that never occurs is a guess dressed
    // up as coverage.
    let kb = builtin();
    let mut counts: HashMap<&str, usize> = HashMap::new();
    let Some(cmds) = corpus() else {
        return common::skip("corpus_shapes");
    };
    for c in cmds {
        let scan = match parse(&c) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let cmds = expanded(kb, &scan);
        for cmd in &cmds {
            let h = cmd.head.rsplit('/').next().unwrap_or(&cmd.head).to_lowercase();
            let h = h.trim_end_matches(".exe");
            let has = |f: &str| cmd.args.iter().any(|a| a == f);
            match h {
                "scp" => *counts.entry("scp").or_default() += 1,
                "docker" | "podman" if has("-v") || has("--volume") => {
                    *counts.entry("docker -v").or_default() += 1
                }
                "docker" | "podman" => *counts.entry("docker (no -v)").or_default() += 1,
                "pip" | "pip3" if has("--target") || has("-t") || has("--prefix") => {
                    *counts.entry("pip --target/--prefix").or_default() += 1
                }
                "npm" if has("--prefix") || has("-g") => {
                    *counts.entry("npm --prefix/-g").or_default() += 1
                }
                "chmod" => *counts.entry("chmod").or_default() += 1,
                "icacls" | "attrib" => *counts.entry("icacls/attrib").or_default() += 1,
                "mklink" => *counts.entry("mklink").or_default() += 1,
                "set-itemproperty" | "new-itemproperty" => {
                    *counts.entry("registry write").or_default() += 1
                }
                _ => {}
            }
        }
    }
    let mut v: Vec<_> = counts.iter().collect();
    v.sort_by_key(|(_, n)| std::cmp::Reverse(**n));
    eprintln!("--- iteration 23 candidate shapes, counted with the parser ---");
    for (name, n) in v {
        eprintln!("  {n:>5}  {name}");
    }
}

#[test]
fn count_the_iteration_24_candidates() {
    let kb = builtin();
    let mut counts: HashMap<&str, usize> = HashMap::new();
    let Some(cmds) = corpus() else {
        return common::skip("corpus_shapes");
    };
    for c in cmds {
        let scan = match parse(&c) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let cmds = expanded(kb, &scan);
        for cmd in &cmds {
            let h = cmd.head.rsplit('/').next().unwrap_or(&cmd.head).to_lowercase();
            let h = h.trim_end_matches(".exe");
            let has = |f: &str| cmd.args.iter().any(|a| a == f);
            match h {
                "cp" | "mv" | "install" if has("-t") || has("--target-directory") => {
                    *counts.entry("cp/mv -t <dir>").or_default() += 1
                }
                "tee" => *counts.entry("tee").or_default() += 1,
                "truncate" => *counts.entry("truncate").or_default() += 1,
                "sponge" => *counts.entry("sponge").or_default() += 1,
                "out-file" => *counts.entry("Out-File").or_default() += 1,
                "tee-object" => *counts.entry("Tee-Object").or_default() += 1,
                _ => {}
            }
        }
    }
    let mut v: Vec<_> = counts.iter().collect();
    v.sort_by_key(|(_, n)| std::cmp::Reverse(**n));
    eprintln!("--- iteration 24 candidate shapes ---");
    if v.is_empty() {
        eprintln!("  (none of them occur)");
    }
    for (name, n) in v {
        eprintln!("  {n:>5}  {name}");
    }
}

#[test]
fn count_interpreters_running_inline_code() {
    // Skeptical review 2026-07-25: `python -c "…"` can write any file,
    // including a protected one, and vouch allows it. Counted with the parser
    // so the size of the blind spot is a number rather than an impression.
    let kb = builtin();
    let mut counts: HashMap<&str, usize> = HashMap::new();
    let Some(cmds) = corpus() else {
        return common::skip("corpus_shapes");
    };
    for c in cmds {
        let scan = match parse(&c) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let cmds = expanded(kb, &scan);
        for cmd in &cmds {
            let h = cmd.head.rsplit('/').next().unwrap_or(&cmd.head).to_lowercase();
            let h = h.trim_end_matches(".exe");
            let inline = |f: &str| cmd.args.iter().any(|a| a == f);
            match h {
                "python" | "python3" | "py" if inline("-c") => {
                    *counts.entry("python -c").or_default() += 1
                }
                "python" | "python3" | "py" => *counts.entry("python <script>").or_default() += 1,
                "node" if inline("-e") || inline("--eval") => {
                    *counts.entry("node -e").or_default() += 1
                }
                "perl" | "ruby" if inline("-e") => *counts.entry("perl/ruby -e").or_default() += 1,
                _ => {}
            }
        }
    }
    let mut v: Vec<_> = counts.iter().collect();
    v.sort_by_key(|(_, n)| std::cmp::Reverse(**n));
    eprintln!("--- interpreters, counted with the parser ---");
    for (name, n) in v {
        eprintln!("  {n:>5}  {name}");
    }
}

#[test]
fn the_raw_prompt_rate_not_the_classified_one() {
    // Skeptical review: "3.4% noise" is a CLASSIFIED figure — prompts vouch
    // calls deliberate are excluded from it by vouch's own judgement. The
    // unclassified numbers cannot be argued with, so they are printed here.
    let cfg = vouch::config::load(
        r#"
version = 1
[lang.bash]
default = "allow"
[lang.bash.constructs]
dynamic_command = "allow"
dynamic_redirect = "allow"
subshell = "allow"
background = "allow"
heredoc = "allow"
function_def = "allow"
unmodeled_command = "allow"
parse_failure = "ask"
redirect = "allow"
[write]
default = "ask"
allow_paths = [
  "C:/work/**", "C:/git/**", "C:/claude/**", "C:/tmp/**",
  "$HOME/**", "/tmp/**", "/private/tmp/**", "/Users/**",
]
"#,
    )
    .expect("parses");

    let Some(rows) = common::real() else {
        return common::skip("corpus_shapes");
    };

    let (mut total, mut vouch_asks, mut old_asks, mut both, mut vouch_only) = (0, 0, 0, 0, 0);
    for r in &rows {
        let cmd = r.cmd.as_str();
        let old = r.verdict == "ask";
        let d = vouch::engine::decide_command_in(&cfg, "bash", cmd, Some("C:/Users/dev"), None);
        let asks = matches!(d, vouch::protocol::Decision::Ask(_) | vouch::protocol::Decision::Deny(_));
        total += 1;
        if asks {
            vouch_asks += 1;
        }
        if old {
            old_asks += 1;
        }
        if old && asks {
            both += 1;
        }
        if asks && !old {
            vouch_only += 1;
        }
    }
    eprintln!("--- RAW, unclassified, over {total} commands ---");
    eprintln!("  old tool prompted on : {old_asks}  ({:.1}%)", 100.0 * old_asks as f64 / total as f64);
    eprintln!("  vouch prompts on     : {vouch_asks}  ({:.1}%)", 100.0 * vouch_asks as f64 / total as f64);
    eprintln!("  both                 : {both}");
    eprintln!("  vouch only (new)     : {vouch_only}");
    eprintln!("  old only (removed)   : {}", old_asks - both);
}

#[test]
fn how_often_does_a_sensitive_path_appear_inside_unreadable_inline_code() {
    // vouch cannot understand Python, but it CAN notice that a protected path
    // is spelled out inside code it cannot read. Before building that, count
    // how often any absolute-looking path appears in such a snippet — that is
    // the upper bound on how noisy the check could be.
    let kb = builtin();
    let (mut snippets, mut with_path) = (0usize, 0usize);
    let mut examples: Vec<String> = Vec::new();
    let Some(cmds) = corpus() else {
        return common::skip("corpus_shapes");
    };
    for c in cmds {
        let scan = match parse(&c) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let cmds = expanded(kb, &scan);
        for cmd in &cmds {
            let h = cmd.head.rsplit('/').next().unwrap_or(&cmd.head).to_lowercase();
            let h = h.trim_end_matches(".exe");
            let flag = match h {
                "python" | "python3" | "py" => "-c",
                "node" => "-e",
                "perl" | "ruby" => "-e",
                _ => continue,
            };
            let Some(i) = cmd.args.iter().position(|a| a == flag) else {
                continue;
            };
            let Some(code) = cmd.args.get(i + 1) else { continue };
            snippets += 1;
            let looks_pathy = code.contains(":/")
                || code.contains(":\\")
                || code.contains("/c/")
                || code.contains(".claude");
            if looks_pathy {
                with_path += 1;
                if examples.len() < 4 {
                    examples.push(code.chars().take(100).collect());
                }
            }
        }
    }
    eprintln!("--- inline interpreter snippets ---");
    eprintln!("  snippets seen                     : {snippets}");
    eprintln!("  containing an absolute-looking path: {with_path}");
    for e in &examples {
        eprintln!("      {}", e.split_whitespace().collect::<Vec<_>>().join(" "));
    }
}

#[test]
fn how_much_of_the_corpus_is_fully_recognised() {
    // The user's model: allow only when EVERYTHING in a command is recognised.
    // That stands or falls on how much of real traffic vouch actually knows.
    let kb = builtin();
    let (mut total, mut fully_known, mut unknown_heads) = (0usize, 0usize, 0usize);
    let mut worst: HashMap<String, usize> = HashMap::new();
    let Some(cmds) = corpus() else {
        return common::skip("corpus_shapes");
    };
    for c in cmds {
        let scan = match parse(&c) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let cmds = expanded(kb, &scan);
        total += 1;
        let mut all_known = true;
        for cmd in &cmds {
            if cmd.head.is_empty() {
                continue;
            }
            if !is_modeled(kb, &cmd.head, "bash") {
                all_known = false;
                unknown_heads += 1;
                let h = cmd.head.rsplit('/').next().unwrap_or(&cmd.head).to_string();
                *worst.entry(h).or_default() += 1;
            }
        }
        if all_known {
            fully_known += 1;
        }
    }
    eprintln!("--- how much does vouch actually recognise? ---");
    eprintln!("  commands parsed                 : {total}");
    eprintln!("  EVERY program in it is modelled  : {fully_known}  ({:.1}%)",
        100.0 * fully_known as f64 / total as f64);
    eprintln!("  commands with an unknown program : {}  ({:.1}%)",
        total - fully_known, 100.0 * (total - fully_known) as f64 / total as f64);
    eprintln!("  unknown-program occurrences      : {unknown_heads}");
    let mut v: Vec<_> = worst.iter().collect();
    v.sort_by_key(|(_, n)| std::cmp::Reverse(**n));
    eprintln!("  most common unknown programs:");
    for (name, n) in v.iter().take(12) {
        eprintln!("    {n:>6}  {name}");
    }
}

#[test]
fn how_far_is_the_recognise_everything_model() {
    // If the user's model is right — allow only what is fully recognised —
    // the question is how much knowledge it would take. This measures coverage
    // as a function of how many of the most common programs are described.
    let kb = builtin();
    let mut freq: HashMap<String, usize> = HashMap::new();
    let mut parsed: Vec<Vec<String>> = Vec::new();
    let Some(cmds) = corpus() else {
        return common::skip("corpus_shapes");
    };
    for c in cmds {
        let scan = match parse(&c) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let cmds = expanded(kb, &scan);
        let heads: Vec<String> = cmds
            .iter()
            .filter(|c| !c.head.is_empty())
            .map(|c| c.head.rsplit('/').next().unwrap_or(&c.head).to_string())
            .collect();
        for h in &heads {
            if !is_modeled(kb, h, "bash") {
                *freq.entry(h.clone()).or_default() += 1;
            }
        }
        parsed.push(heads);
    }
    let mut ranked: Vec<(String, usize)> = freq.into_iter().collect();
    ranked.sort_by_key(|(_, n)| std::cmp::Reverse(*n));

    eprintln!("--- coverage if the top N unknown programs were described ---");
    for n in [0usize, 10, 25, 50, 100, 200] {
        let extra: std::collections::HashSet<&str> =
            ranked.iter().take(n).map(|(h, _)| h.as_str()).collect();
        let full = parsed
            .iter()
            .filter(|heads| {
                heads
                    .iter()
                    .all(|h| is_modeled(kb, h, "bash") || extra.contains(h.as_str()))
            })
            .count();
        eprintln!(
            "  top {n:>3} described -> {full:>6} of {} commands fully recognised ({:.1}%)",
            parsed.len(),
            100.0 * full as f64 / parsed.len() as f64
        );
    }
    eprintln!("  distinct unknown programs in total: {}", ranked.len());
}

#[test]
fn list_the_unknown_programs_to_describe() {
    let kb = builtin();
    let mut freq: HashMap<String, usize> = HashMap::new();
    let Some(cmds) = corpus() else {
        return common::skip("corpus_shapes");
    };
    for c in cmds {
        let scan = match parse(&c) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let cmds = expanded(kb, &scan);
        for cmd in &cmds {
            if cmd.head.is_empty() {
                continue;
            }
            let h = cmd.head.rsplit('/').next().unwrap_or(&cmd.head).to_string();
            if !is_modeled(kb, &h, "bash") {
                *freq.entry(h).or_default() += 1;
            }
        }
    }
    let mut v: Vec<_> = freq.into_iter().collect();
    v.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
    for (name, n) in v.iter().take(130) {
        eprintln!("{n:>7}  {name}");
    }
}

#[test]
fn the_knowledge_under_test_is_not_empty() {
    // Without this, every "for prog in &builtin().program" test below passes
    // vacuously the moment the file cannot be found.
    let kb = builtin();
    assert!(
        !kb.program.is_empty(),
        "no programs loaded — these tests would pass over an empty set. \
         Is .cargo/config.toml present and is VOUCH_KNOWLEDGE set?"
    );
}

// --- run-dir-flag pre-build measurements (§6.2), 2026-07-30 ---
//
// The shipped `git` entry's own `value_options` list, duplicated here on
// purpose: these tests measure what the corpus contains BEFORE the run-dir
// flag work changes anything about how `-C` is read, so they must not read
// the list they exist to help change.
const GIT_VALUE_OPTIONS: &[&str] = &["-C", "-c", "--git-dir", "--work-tree", "--namespace"];

/// Flags after a `clone`/`init`/`worktree add` subcommand judged benign enough
/// that a destination-walk hardening pass would not need to ask about them.
const GIT_BENIGN_POST_SUB_FLAGS: &[&str] =
    &["-q", "--quiet", "--bare", "--detach", "-b", "--depth", "-c"];

/// Mirrors `guards::subcommand`'s walk (skip a `value_options` flag and its
/// value, skip any other `-`-prefixed token, the first bare token is the
/// subcommand) but also returns the subcommand's own INDEX into `args` and how
/// many `-C` tokens were seen strictly before it.
fn git_subcommand_index_and_dash_c(args: &[String]) -> (Option<usize>, usize) {
    let mut skip = false;
    let mut c_count = 0usize;
    for (i, a) in args.iter().enumerate() {
        if skip {
            skip = false;
            continue;
        }
        if GIT_VALUE_OPTIONS.contains(&a.as_str()) {
            if a == "-C" {
                c_count += 1;
            }
            skip = true;
            continue;
        }
        if a.starts_with('-') {
            continue;
        }
        return (Some(i), c_count);
    }
    (None, c_count)
}

fn git_cmds<'a>(kb: &'a vouch::guards::Knowledge, cmds: &'a [vouch::syntax::Cmd]) -> Vec<&'a vouch::syntax::Cmd> {
    let _ = kb;
    cmds.iter()
        .filter(|cmd| {
            let h = cmd.head.rsplit('/').next().unwrap_or(&cmd.head).to_lowercase();
            h.trim_end_matches(".exe") == "git"
        })
        .collect()
}

#[test]
fn count_git_dash_c_by_subcommand() {
    // Bucketed count of `git` commands carrying at least one `-C` before the
    // subcommand, by subcommand — the wrong-ALLOW class the M2.11 note
    // estimated from a substring search. This is the parser-measured number.
    let kb = builtin();
    let mut by_sub: HashMap<String, usize> = HashMap::new();
    let mut total = 0usize;
    let Some(cmds) = corpus() else {
        return common::skip("corpus_shapes");
    };
    for c in cmds {
        let scan = match parse(&c) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let expanded = expanded(kb, &scan);
        for cmd in git_cmds(kb, &expanded) {
            let (sub_idx, c_count) = git_subcommand_index_and_dash_c(&cmd.args);
            if c_count == 0 {
                continue;
            }
            total += 1;
            let key = match sub_idx {
                Some(i) => cmd.args[i].clone(),
                None => "none".to_string(),
            };
            *by_sub.entry(key).or_default() += 1;
        }
    }
    eprintln!("--- git commands with -C before the subcommand, by subcommand (parser-measured) ---");
    let mut v: Vec<_> = by_sub.iter().collect();
    v.sort_by_key(|(_, n)| std::cmp::Reverse(**n));
    for (sub, n) in &v {
        eprintln!("MEASURE git_dash_c_subcommand_{sub}: {n}");
    }
    eprintln!("MEASURE git_dash_c_total: {total}");
}

#[test]
fn count_git_composed_dash_c() {
    // Two or more pre-subcommand `-C` occurrences on one `git` command — sizes
    // the composed-`-C` class the spec (§2.4) decides between "compose" and
    // "ask".
    let kb = builtin();
    let mut composed = 0usize;
    let Some(cmds) = corpus() else {
        return common::skip("corpus_shapes");
    };
    for c in cmds {
        let scan = match parse(&c) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let expanded = expanded(kb, &scan);
        for cmd in git_cmds(kb, &expanded) {
            let (_, c_count) = git_subcommand_index_and_dash_c(&cmd.args);
            if c_count >= 2 {
                composed += 1;
            }
        }
    }
    eprintln!("MEASURE git_dash_c_composed_two_or_more: {composed}");
}

#[test]
fn count_git_residual_post_subcommand_flags() {
    // `clone`/`init`/`worktree add` commands carrying a post-subcommand token
    // that starts with `-` and is not in the benign list — sizes the residual
    // ask class left over after describing the benign flags.
    let kb = builtin();
    let mut by_target: HashMap<&str, usize> = HashMap::new();
    let mut total = 0usize;
    let Some(cmds) = corpus() else {
        return common::skip("corpus_shapes");
    };
    for c in cmds {
        let scan = match parse(&c) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let expanded = expanded(kb, &scan);
        for cmd in git_cmds(kb, &expanded) {
            let (sub_idx, _) = git_subcommand_index_and_dash_c(&cmd.args);
            let Some(sub_idx) = sub_idx else { continue };
            let sub = cmd.args[sub_idx].as_str();

            // `worktree add` is the only two-word subcommand this test cares
            // about; the anchor to walk from is the `add` token, not
            // `worktree` itself.
            let (target, anchor_idx): (&str, usize) = match sub {
                "clone" => ("clone", sub_idx),
                "init" => ("init", sub_idx),
                "worktree" => {
                    let verb = cmd.args[sub_idx + 1..]
                        .iter()
                        .enumerate()
                        .find(|(_, a)| !a.starts_with('-'));
                    match verb {
                        Some((off, a)) if a == "add" => ("worktree add", sub_idx + 1 + off),
                        _ => continue,
                    }
                }
                _ => continue,
            };

            let flagged = cmd.args[anchor_idx + 1..]
                .iter()
                .any(|a| a.starts_with('-') && !GIT_BENIGN_POST_SUB_FLAGS.contains(&a.as_str()));
            if flagged {
                total += 1;
                *by_target.entry(target).or_default() += 1;
            }
        }
    }
    eprintln!("--- git clone/init/worktree-add: post-subcommand flags outside the benign list (parser-measured) ---");
    let mut v: Vec<_> = by_target.iter().collect();
    v.sort_by_key(|(_, n)| std::cmp::Reverse(**n));
    for (target, n) in &v {
        eprintln!("MEASURE git_residual_flag_{}: {n}", target.replace(' ', "_"));
    }
    eprintln!("MEASURE git_residual_flag_total: {total}");
}

#[test]
fn count_bare_git_init() {
    // `git init` with zero positionals after the subcommand — the shape where
    // the destination IS the run directory (no positional at all), which
    // ROADMAP.md's M2.11 note item 6 says the destination-walk sketch alone
    // does not fix.
    let kb = builtin();
    let mut bare = 0usize;
    let Some(cmds) = corpus() else {
        return common::skip("corpus_shapes");
    };
    for c in cmds {
        let scan = match parse(&c) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let expanded = expanded(kb, &scan);
        for cmd in git_cmds(kb, &expanded) {
            let (sub_idx, _) = git_subcommand_index_and_dash_c(&cmd.args);
            let Some(sub_idx) = sub_idx else { continue };
            if cmd.args[sub_idx] != "init" {
                continue;
            }
            let positionals_after = cmd.args[sub_idx + 1..]
                .iter()
                .filter(|a| !a.starts_with('-'))
                .count();
            if positionals_after == 0 {
                bare += 1;
            }
        }
    }
    eprintln!("MEASURE git_bare_init: {bare}");
}

#[test]
fn count_cd_family_with_subshell_or_background_construct() {
    // A `cd`-family head on the same row as a `subshell` or `background`
    // construct — the upper bound on ordering-unprovable `cd` shapes (M2.11
    // note item 4 and the second skeptical-review amendment).
    const CD_HEADS: &[&str] = &["cd", "chdir", "set-location", "sl", "pushd", "popd"];
    let mut n = 0usize;
    let Some(cmds) = corpus() else {
        return common::skip("corpus_shapes");
    };
    for c in cmds {
        let scan = match parse(&c) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let has_construct = scan
            .constructs
            .iter()
            .any(|k| k == "subshell" || k == "background");
        if !has_construct {
            continue;
        }
        let has_cd = scan.commands.iter().any(|cmd| {
            let h = cmd.head.rsplit('/').next().unwrap_or(&cmd.head).to_lowercase();
            CD_HEADS.contains(&h.trim_end_matches(".exe"))
        });
        if has_cd {
            n += 1;
        }
    }
    eprintln!("MEASURE cd_family_with_subshell_or_background: {n}");
}

// --- dir-change / source pre-build measurement (M2.33, task 1 of the
// changes-dir-knowledge plan, 2026-07-31) ---
//
// Before the cd-name list moves out of `engine.rs` and into `knowledge.toml`
// (M2.33), this counts what shapes the whole dir-change family — including
// `source`/`.`, which are RECOGNISED today but not walked as dir-changers at
// all — actually takes in the real corpus.

/// Every head the M2.33 spec's walk will need to read from knowledge, in the
/// spec's own casing. Duplicated from the spec (`docs/specs/2026-07-31-
/// changes-dir-knowledge-design.md`) on purpose, same reasoning as
/// `GIT_VALUE_OPTIONS` above: this measures the corpus BEFORE the change, so
/// it must not read a list the change itself will introduce.
const DIR_CHANGE_HEADS: &[&str] = &[
    "cd",
    "chdir",
    "sl",
    "set-location",
    "pushd",
    "popd",
    "push-location",
    "pop-location",
    "source",
    ".",
];

/// Per-head shape counts. Fields are independent buckets, not mutually
/// exclusive partitions — a segment with only flags and no destination is
/// both `option_shaped` and `bare`.
#[derive(Debug, Default, Clone, Copy)]
struct DirChangeShape {
    /// Every segment with this head, however it is shaped.
    total: usize,
    /// Two or more non-flag (not `-`-prefixed) tokens — the multi-positional
    /// shape where which token is the destination is not obvious.
    two_or_more_nonflag: usize,
    /// Any `-`-prefixed token at all, e.g. `cd -P`, `pushd -n`.
    option_shaped: usize,
    /// The first non-flag token starts with `~` or contains a glob
    /// metacharacter (`*`, `?`, `[`) — the spec's §5 "unknown" vocabulary.
    glob_or_tilde_dest: usize,
    /// Zero non-flag tokens at all — `cd` with nothing to go home to, or
    /// `pushd`/`popd`/`source` with no argument.
    bare: usize,
}

/// Mirrors `engine::is_relative` (private to that module, so duplicated here
/// on purpose): true when a redirect target has no root and so lands
/// wherever the shell's working directory happens to be at that point in the
/// script — the exact ambiguity a `source`/`.` earlier in the same line can
/// introduce, because a sourced script's own `cd` persists in the caller.
fn looks_relative(p: &str) -> bool {
    let p = p.replace('\\', "/");
    if p.starts_with('/') || p.starts_with('~') || p.starts_with('$') {
        return false;
    }
    let b = p.as_bytes();
    !(b.len() >= 2 && b[1] == b':')
}

#[test]
fn dir_change_shapes_in_the_corpus() {
    let kb = builtin();
    let mut shapes = vec![DirChangeShape::default(); DIR_CHANGE_HEADS.len()];
    let mut later_relative_write_lines = 0usize;

    let Some(cmds) = corpus() else {
        return common::skip("corpus_shapes");
    };
    for c in cmds {
        let scan = match parse(&c) {
            Ok(s) => s,
            Err(_) => continue,
        };

        // Per-head shape counts: on the wrapper-expanded commands, exactly
        // like every other shape count in this file, so `sudo cd x` is
        // counted the same way `sudo rm -rf` is counted elsewhere.
        let expanded = expanded(kb, &scan);
        for cmd in &expanded {
            let h = cmd.head.rsplit('/').next().unwrap_or(&cmd.head).to_lowercase();
            let h = h.trim_end_matches(".exe");
            let Some(idx) = DIR_CHANGE_HEADS.iter().position(|d| *d == h) else {
                continue;
            };
            let entry = &mut shapes[idx];
            entry.total += 1;
            let non_flag: Vec<&String> =
                cmd.args.iter().filter(|a| !a.starts_with('-')).collect();
            if non_flag.len() >= 2 {
                entry.two_or_more_nonflag += 1;
            }
            if non_flag.is_empty() {
                entry.bare += 1;
            }
            if cmd.args.iter().any(|a| a.starts_with('-')) {
                entry.option_shaped += 1;
            }
            if let Some(dest) = non_flag.first() {
                if dest.starts_with('~') || dest.chars().any(|c| matches!(c, '*' | '?' | '[')) {
                    entry.glob_or_tilde_dest += 1;
                }
            }
        }

        // A later relative write after a `source`/`.` segment: measured on
        // the RAW scan, not the expanded one — `expand_wrappers_with_sources`
        // does not carry `Order` through, and a redirect's `Order` is only
        // meaningful compared against the command it is attached to (both
        // are assigned from the same top-level counter, shell.rs::walk_simple).
        //
        // A `source`/`.` segment whose OWN position is not provable
        // (`Order::Unordered`) is excluded from the numerator: vouch cannot
        // say anything ran "after" a position it cannot place either. A
        // candidate write whose OWN order is Unordered is still counted,
        // conservatively, as possibly-later — it cannot be proven to come
        // after, but it cannot be ruled out either, and ruling it out by
        // construction is the mistake this measurement exists to avoid
        // (CLAUDE.md §1: absence of proof is not proof of absence).
        let earliest_source_seq = scan
            .commands
            .iter()
            .zip(scan.order.iter())
            .filter_map(|(cmd, ord)| {
                let h = cmd.head.rsplit('/').next().unwrap_or(&cmd.head).to_lowercase();
                if h != "source" && h != "." {
                    return None;
                }
                match ord {
                    Order::Seq(n) => Some(*n),
                    Order::Unordered => None,
                }
            })
            .min();
        if let Some(source_seq) = earliest_source_seq {
            let has_later_relative_write =
                scan.redirect_targets
                    .iter()
                    .zip(scan.redirect_order.iter())
                    .any(|(target, ord)| {
                        let maybe_later = match ord {
                            Order::Seq(n) => *n > source_seq,
                            Order::Unordered => true,
                        };
                        maybe_later && looks_relative(target)
                    });
            if has_later_relative_write {
                later_relative_write_lines += 1;
            }
        }
    }

    eprintln!("--- dir-change shapes in the corpus (parser-measured) ---");
    eprintln!(
        "  {:<14} {:>7} {:>10} {:>15} {:>13} {:>6}",
        "head", "total", ">=2 args", "option-shaped", "glob/~ dest", "bare"
    );
    for (head, s) in DIR_CHANGE_HEADS.iter().zip(shapes.iter()) {
        eprintln!(
            "  {:<14} {:>7} {:>10} {:>15} {:>13} {:>6}",
            head, s.total, s.two_or_more_nonflag, s.option_shaped, s.glob_or_tilde_dest, s.bare
        );
    }
    eprintln!(
        "  lines with a later relative write after a source/. segment: {later_relative_write_lines}"
    );
}

// --- python snippet pre-build measurements (M1.4, task 4 of the
// 2026-08-07-python-snippets plan) ---
//
// Before the shipped `-c` extractor exists (that is task 8) and before any
// python knowledge entries exist (task 11), this counts what the corpus's
// `python -c`/`python3 -c`/`py -c` snippets actually contain, using the
// strict `python::parse` gate directly. The extraction below is hand-rolled
// by necessity — it cannot reuse `expand_wrappers_with_sources`'s own
// `after_flag` handling for `-c`, because that mechanism rejoins every
// trailing token into one snippet (correct for `cmd /c`, wrong for `-c`,
// which takes exactly one argument as the code and hands everything after it
// to the script as `sys.argv`) and never unescapes it. Both are read directly
// from docs/specs/2026-08-07-python-snippets-design.md, "Snippet locators".

/// True when `head` names a python-family interpreter: `python`, `python3`,
/// or `py`, however spelled — bare, `.exe`-suffixed, or with a path in
/// front of it. The scanner keeps quotes in the head token verbatim (see
/// `paths::unquote`'s own doc comment), so a fully quoted path head
/// (`"C:/Python311/python.exe"`) is unquoted BEFORE taking the last `/`
/// segment; splitting first would leave the trailing quote stuck to
/// `python.exe` and the closing check would never match. Deliberately does
/// not match version-qualified spellings (`python3.11`) — the corpus has one
/// occurrence each of two such spellings, and the brief's own vocabulary
/// names exactly three bare forms.
fn python_family_head(head: &str) -> bool {
    let unquoted = unquote(head);
    let base = unquoted
        .rsplit('/')
        .next()
        .unwrap_or(unquoted)
        .to_lowercase();
    let base = base.trim_end_matches(".exe");
    matches!(base, "python" | "python3" | "py")
}

/// The `-c` snippet value, both spellings: the separate form (`-c`, then the
/// next token) and the attached form (`-cCODE`, one token — python's own
/// short-option parsing). Case-sensitive on purpose: `knowledge.toml`'s
/// python entry sets `case_sensitive_flags = true` and `-C` is not a python
/// flag. A `-c` with nothing after it (flag-only, or an empty attached
/// value) is not a snippet — the design's own extractor requires a code
/// argument to actually follow.
fn dash_c_value(args: &[String]) -> Option<String> {
    for (i, a) in args.iter().enumerate() {
        let Some(rest) = a.strip_prefix("-c") else {
            continue;
        };
        if !rest.is_empty() {
            return Some(rest.to_string());
        }
        return args.get(i + 1).filter(|v| !v.is_empty()).cloned();
    }
    None
}

/// True when `token` is shaped like a python keyword argument (`name=value`,
/// the shape `python::parse` emits for one) rather than a plain positional
/// value that happens to contain `=`.
fn looks_keyword_shaped(token: &str) -> bool {
    let Some(eq) = token.find('=') else {
        return false;
    };
    let name = &token[..eq];
    !name.is_empty()
        && name.starts_with(|c: char| c.is_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_alphanumeric() || c == '_')
}

/// The value at a positional-or-keyword-folded argument slot: `name` is the
/// keyword spelling that folds onto `index` (mirroring the design's
/// `arg_names` rule, "The argument model"); `index` is where it lands when
/// given positionally. A keyword-shaped token at `index` under a different
/// name is a different parameter's keyword, not this slot's positional, and
/// an unfolded keyword elsewhere is never read as this slot either — both
/// fail closed to `None`, matching the design's rule 4 exactly ("an absent
/// position, a marker token, an unfolded `name=value` — each is an
/// unresolved written path").
fn arg_slot<'a>(args: &'a [String], name: &str, index: usize) -> Option<&'a str> {
    if !name.is_empty() {
        let prefix = format!("{name}=");
        if let Some(v) = args.iter().find_map(|a| a.strip_prefix(prefix.as_str())) {
            return Some(v);
        }
    }
    let candidate = args.get(index)?;
    if looks_keyword_shaped(candidate) {
        None
    } else {
        Some(candidate.as_str())
    }
}

/// Every extracted `-c` snippet in the corpus, as its raw (unquoted,
/// unescaped) text. Shared by every measurement below so the extraction
/// logic — and therefore the denominator — is identical across all four.
fn python_snippets(kb: &vouch::guards::Knowledge, cmds: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for c in cmds {
        let scan = match parse(c) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let expanded = expanded(kb, &scan);
        for cmd in &expanded {
            if !python_family_head(&cmd.head) {
                continue;
            }
            let Some(raw) = dash_c_value(&cmd.args) else {
                continue;
            };
            out.push(unquote_snippet(&raw));
        }
    }
    out
}

#[test]
fn measure_python_snippet_parse_rate() {
    let kb = builtin();
    let Some(rows) = corpus() else {
        return common::skip("corpus_shapes");
    };
    let snippets = python_snippets(kb, &rows);
    let total = snippets.len();
    let parsed = snippets.iter().filter(|s| python::parse(s).is_ok()).count();
    let rate = if total > 0 {
        100.0 * parsed as f64 / total as f64
    } else {
        100.0
    };
    eprintln!("--- python -c snippet strict parse rate (hand-rolled extraction, task 4) ---");
    eprintln!("  snippets found : {total}");
    eprintln!("  parsed OK      : {parsed}  ({rate:.2}%)");
    eprintln!("  parse failures : {}", total - parsed);
    eprintln!(
        "  (restates docs/specs/2026-08-07-python-snippets-design.md's 99.5%, 2,272/2,283, \
         under this task's own hand-rolled extraction rather than the design's bench extractor)"
    );
}

/// The same `-c` snippets, extracted through the shared `after_flag_snippet`
/// (Task 8) instead of this file's own hand-rolled `dash_c_value`. Reuses the
/// SAME expansion (`expand_wrappers_with_sources`) and the same per-command
/// walk as `python_snippets` above, differing only in which extractor reads
/// the flag's value off the (already expanded) argument list — so a
/// disagreement here is about the extractor, not about corpus traversal.
fn python_snippets_via_after_flag_snippet(
    kb: &vouch::guards::Knowledge,
    cmds: &[String],
) -> Vec<String> {
    let mut out = Vec::new();
    for c in cmds {
        let scan = match parse(c) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let expanded = expanded(kb, &scan);
        for cmd in &expanded {
            if !python_family_head(&cmd.head) {
                continue;
            }
            // `expand_wrappers_with_sources` is called here directly, bypassing
            // the engine's own step 0 (`engine.rs`, "Resolve the PROGRAM NAME
            // the same way a written path is resolved") which unquotes a
            // top-level command's head before wrapper expansion ever sees it.
            // `python_family_head` above already unquotes to decide whether
            // this is a python call at all; the same unquoting has to happen
            // here too, or a quoted head (`"C:/…/python.exe" -c "…"`, real in
            // this corpus) finds no [[program]] entry and the snippet is
            // silently missed — not a gap in `after_flag_snippet` itself, but
            // in this test's own pre-resolution, kept faithful to what the
            // engine actually does before either extractor runs.
            let canonical = vouch::guards::base_name(unquote(&cmd.head));
            let Some(prog) = kb
                .program
                .iter()
                .find(|p| p.match_names.iter().any(|n| n.to_lowercase() == canonical))
            else {
                continue;
            };
            // `after_flag_snippet` returns the snippet the interpreter
            // receives, already unquoted (Task 9: the `wrap_join` shapes have
            // to unquote per TOKEN and then join, so the unquoting cannot sit
            // at the call site any more). Unquoting again here would strip a
            // second layer the interpreter never sees.
            let Some(src) = vouch::guards::after_flag_snippet(prog, &cmd.args) else {
                continue;
            };
            out.push(src);
        }
    }
    out
}

/// Task 8's reconciliation: the hand-rolled Task-4 extractor
/// (`python_snippets`, above) and the shared `after_flag_snippet` extractor
/// wired into the `after_flag` wrap arm must find the same snippets, or the
/// disagreement must be explained here rather than left as two silently
/// different numbers. Also prints the count of corpus rows the bash scanner
/// itself could not parse at all (a parse failure, not a missing snippet) —
/// the Task-4 review asked for that denominator alongside this reconciliation.
#[test]
fn the_hand_rolled_and_shared_extractors_agree() {
    let kb = builtin();
    let Some(rows) = corpus() else {
        return common::skip("corpus_shapes");
    };

    let dropped_rows = rows.iter().filter(|c| parse(c).is_err()).count();

    let hand_rolled = python_snippets(kb, &rows);
    let shared = python_snippets_via_after_flag_snippet(kb, &rows);

    let hand_total = hand_rolled.len();
    let hand_parsed = hand_rolled.iter().filter(|s| python::parse(s).is_ok()).count();
    let shared_total = shared.len();
    let shared_parsed = shared.iter().filter(|s| python::parse(s).is_ok()).count();

    eprintln!("--- extractor reconciliation: hand-rolled (task 4) vs after_flag_snippet (task 8) ---");
    eprintln!("  corpus rows                           : {}", rows.len());
    eprintln!("  rows the bash scanner could not parse  : {dropped_rows}");
    eprintln!("  hand-rolled extractor  : {hand_total} snippets found, {hand_parsed} parse OK");
    eprintln!("  after_flag_snippet     : {shared_total} snippets found, {shared_parsed} parse OK");

    assert_eq!(
        hand_total, shared_total,
        "the two extractors found a different NUMBER of -c snippets — see the printed counts"
    );
    assert_eq!(
        hand_rolled, shared,
        "the two extractors agree on count but disagree on snippet TEXT for at least one row"
    );
}

#[test]
fn measure_python_call_census() {
    let kb = builtin();
    let Some(rows) = corpus() else {
        return common::skip("corpus_shapes");
    };
    let snippets = python_snippets(kb, &rows);
    let mut counts: HashMap<String, usize> = HashMap::new();
    let mut total_calls = 0usize;
    for s in &snippets {
        let Ok(py_scan) = python::parse(s) else {
            continue;
        };
        for cmd in &py_scan.commands {
            total_calls += 1;
            *counts.entry(cmd.head.clone()).or_default() += 1;
        }
    }
    let mut v: Vec<_> = counts.into_iter().collect();
    v.sort_by_key(|(_, n)| std::cmp::Reverse(*n));

    // Lowercased on both sides: entry matching is case-insensitive
    // (guards::Entry::same_name), and an exact-spelling marker would print
    // "unmodeled" for a head the engine actually recognises.
    let known: std::collections::HashSet<String> = kb
        .program
        .iter()
        .flat_map(|p| p.match_names.iter().map(|s| s.to_lowercase()))
        .collect();
    let mut known_calls = 0usize;
    eprintln!("--- python call census (head, count, known?) across every successfully parsed snippet ---");
    eprintln!("  total calls emitted: {total_calls}");
    eprintln!("  distinct heads     : {}", v.len());
    for (name, n) in v.iter() {
        let k = known.contains(&name.to_lowercase());
        if k { known_calls += *n; }
        eprintln!("  {n:>6}  {}{name}", if k { "known    " } else { "unmodeled " });
    }
    eprintln!("  calls with a knowledge entry: {known_calls} of {total_calls}");
}

#[test]
fn measure_python_opens_and_modes() {
    let kb = builtin();
    let Some(rows) = corpus() else {
        return common::skip("corpus_shapes");
    };
    let snippets = python_snippets(kb, &rows);
    let (
        mut total,
        mut no_mode,
        mut mode_stating,
        mut write_mode,
        mut non_write_mode,
        mut unresolved_mode,
    ) = (0usize, 0usize, 0usize, 0usize, 0usize, 0usize);
    for s in &snippets {
        let Ok(py_scan) = python::parse(s) else {
            continue;
        };
        for cmd in &py_scan.commands {
            if cmd.head != "python:open" {
                continue;
            }
            total += 1;
            match arg_slot(&cmd.args, "mode", 1) {
                None => no_mode += 1,
                Some(v) => {
                    mode_stating += 1;
                    if v.starts_with('$') {
                        unresolved_mode += 1;
                    } else if is_write_mode(v) {
                        write_mode += 1;
                    } else {
                        non_write_mode += 1;
                    }
                }
            }
        }
    }
    eprintln!("--- python:open calls: total / mode-stating / write-mode ---");
    eprintln!("  total python:open calls          : {total}");
    eprintln!("  no mode given (defaults to read)  : {no_mode}");
    eprintln!("  states a mode at all              : {mode_stating}");
    eprintln!("    resolved write mode (w/a/x/+)   : {write_mode}");
    eprintln!("    resolved non-write mode         : {non_write_mode}");
    eprintln!("    unresolved mode value           : {unresolved_mode}");
    eprintln!(
        "  (restates docs/specs/2026-08-07-python-snippets-design.md's 29 of 423, 377 give no mode)"
    );
}

/// A resolved python file-mode string counts as a write mode only when it is
/// made ENTIRELY of mode-charset characters (`r`/`w`/`a`/`x`/`b`/`t`/`+`) and
/// at least one of them is write-indicating. The charset restriction is the
/// design's own guard: `encoding='windows-1252'` contains a `w` but is not a
/// mode string at all, and would otherwise be misread as one.
fn is_write_mode(v: &str) -> bool {
    let charset_only = !v.is_empty()
        && v.chars()
            .all(|c| matches!(c, 'r' | 'w' | 'a' | 'x' | 'b' | 't' | '+'));
    charset_only && v.chars().any(|c| matches!(c, 'w' | 'a' | 'x' | '+'))
}

/// One shipped write-position claim: which argument slot(s) a call writes
/// to, and the keyword name (if any) that folds onto its first slot.
/// Duplicated from docs/specs/2026-08-07-python-snippets-design.md, "The
/// knowledge entries" #1-5 and #8 — the write claims task 11 will add to
/// knowledge.toml. Measuring BEFORE that data exists, so it has to be
/// hand-rolled here too, the same reasoning as `GIT_VALUE_OPTIONS` above:
/// this sizes what the corpus needs from those entries, so it must not read
/// the entries themselves.
enum WritePos {
    Arg0,
    Arg1,
    AllArgs,
    /// The `open` family: `writes_only_with_file_mode` in the design (item
    /// 1 of "The knowledge entries") — the write claim on `arg_0` (or the
    /// receiver, for `.open`) applies only when the `mode` argument (index
    /// 1, keyword `mode`) resolves to a write mode or is itself unresolved
    /// (design rule 3: unresolved mode cannot rule out a write). A plain
    /// read (mode absent, or a resolved non-write mode) never contributes
    /// here, matching `measure_python_opens_and_modes`'s own mode check.
    Arg0IfWriteMode,
}

const PYTHON_WRITE_HEADS: &[(&str, &str, WritePos)] = &[
    ("python:open", "file", WritePos::Arg0IfWriteMode),
    ("python:io.open", "file", WritePos::Arg0IfWriteMode),
    ("python:codecs.open", "filename", WritePos::Arg0IfWriteMode),
    ("python:.open", "", WritePos::Arg0IfWriteMode),
    ("python:.write_text", "", WritePos::Arg0),
    ("python:.write_bytes", "", WritePos::Arg0),
    ("python:.touch", "", WritePos::Arg0),
    ("python:.mkdir", "", WritePos::Arg0),
    ("python:os.mkdir", "path", WritePos::Arg0),
    ("python:os.makedirs", "name", WritePos::Arg0),
    ("python:shutil.copy", "", WritePos::Arg1),
    ("python:shutil.copy2", "", WritePos::Arg1),
    ("python:shutil.copyfile", "", WritePos::Arg1),
    ("python:shutil.copytree", "", WritePos::Arg1),
    ("python:shutil.move", "", WritePos::AllArgs),
    ("python:os.rename", "", WritePos::AllArgs),
    ("python:os.replace", "", WritePos::AllArgs),
    ("python:os.renames", "", WritePos::AllArgs),
    ("python:os.remove", "path", WritePos::Arg0),
    ("python:os.unlink", "path", WritePos::Arg0),
    ("python:os.rmdir", "path", WritePos::Arg0),
    ("python:os.removedirs", "name", WritePos::Arg0),
    ("python:shutil.rmtree", "path", WritePos::Arg0),
    ("python:.unlink", "", WritePos::Arg0),
    ("python:.rmdir", "", WritePos::Arg0),
    ("python:os.chmod", "path", WritePos::Arg0),
    ("python:.chmod", "", WritePos::Arg0),
];

/// Heads the design also plans to ship (`wraps`/`evaluates_input` entries,
/// items 6-7 of "The knowledge entries"), listed so this measurement does
/// not misreport them as `unmodeled_command` — they are modelled, just not
/// as a write-position claim.
const PYTHON_OTHER_MODELED_EXACT: &[&str] = &[
    "python:os.system",
    "python:os.popen",
    "python:subprocess.run",
    "python:subprocess.call",
    "python:subprocess.check_call",
    "python:subprocess.check_output",
    "python:subprocess.Popen",
    "python:eval",
    "python:exec",
];

fn is_other_modeled(head: &str) -> bool {
    PYTHON_OTHER_MODELED_EXACT.contains(&head)
        || head.starts_with("python:os.exec")
        || head.starts_with("python:os.spawn")
}

/// True when `args[index]` (folded from `fold_name` when present) is
/// missing, keyword-shaped-but-unfolded, or a marker — every shape the
/// design's rule 4 fails closed on.
fn slot_unresolved(args: &[String], fold_name: &str, index: usize) -> bool {
    match arg_slot(args, fold_name, index) {
        None => true,
        // Containment, not `starts_with` — matches `src/engine.rs:698`
        // exactly. The scanner resolves f-strings and `+` concatenations
        // part by part (`src/python.rs`'s `literal`), so a path with its
        // literal segment first (`f"out/{x}.json"` -> `out/$?.json`) carries
        // a marker without starting with one; a narrower check would call
        // that resolved when the engine would ask on it.
        Some(v) => v.contains('$') || v.contains('`') || v.contains('%'),
    }
}

fn call_is_unresolved_write(head: &str, args: &[String]) -> bool {
    PYTHON_WRITE_HEADS
        .iter()
        .find(|(h, _, _)| *h == head)
        .is_some_and(|(_, fold, pos)| match pos {
            WritePos::Arg0 => slot_unresolved(args, fold, 0),
            WritePos::Arg1 => slot_unresolved(args, fold, 1),
            WritePos::AllArgs => slot_unresolved(args, fold, 0) || slot_unresolved(args, "", 1),
            WritePos::Arg0IfWriteMode => {
                let writes = match arg_slot(args, "mode", 1) {
                    None => false,
                    // Containment, matching `slot_unresolved` and
                    // `src/engine.rs:698` — see that function's doc comment.
                    Some(v) if v.contains('$') || v.contains('`') || v.contains('%') => true,
                    Some(v) => is_write_mode(v),
                };
                writes && slot_unresolved(args, fold, 0)
            }
        })
}

fn call_is_write_head(head: &str) -> bool {
    PYTHON_WRITE_HEADS.iter().any(|(h, _, _)| *h == head)
}

#[test]
fn measure_python_new_prompt_buckets() {
    let kb = builtin();
    let Some(rows) = corpus() else {
        return common::skip("corpus_shapes");
    };
    let snippets = python_snippets(kb, &rows);
    let (mut parse_fail, mut dynamic_call, mut unresolved_write, mut unmodeled, mut clean) =
        (0usize, 0usize, 0usize, 0usize, 0usize);
    let mut unmodeled_heads: HashMap<String, usize> = HashMap::new();
    for s in &snippets {
        let py_scan = match python::parse(s) {
            Ok(sc) => sc,
            Err(_) => {
                parse_fail += 1;
                continue;
            }
        };
        if py_scan.constructs.iter().any(|k| k == "dynamic_call") {
            dynamic_call += 1;
            continue;
        }
        let mut this_unresolved = false;
        let mut this_unmodeled: Vec<String> = Vec::new();
        for cmd in &py_scan.commands {
            if call_is_write_head(&cmd.head) {
                if call_is_unresolved_write(&cmd.head, &cmd.args) {
                    this_unresolved = true;
                }
            } else if !is_other_modeled(&cmd.head) {
                this_unmodeled.push(cmd.head.clone());
            }
        }
        if this_unresolved {
            unresolved_write += 1;
        } else if !this_unmodeled.is_empty() {
            unmodeled += 1;
            for h in this_unmodeled {
                *unmodeled_heads.entry(h).or_default() += 1;
            }
        } else {
            clean += 1;
        }
    }
    eprintln!(
        "--- python new-prompt buckets (config assumed: the write/other entries docs/specs/\
         2026-08-07-python-snippets-design.md \"The knowledge entries\" #1-5,#8 plan to ship; \
         priority dynamic_call > unresolved-write-position > unmodeled_command > clean; parse \
         failures counted separately, not one of the four named buckets; this is config-\
         independent head/shape counting, not the verdict mapping Task 14 builds) ---"
    );
    eprintln!("  snippets total            : {}", snippets.len());
    eprintln!("  parse failures            : {parse_fail}");
    eprintln!("  dynamic_call              : {dynamic_call}");
    eprintln!("  unresolved-write-position : {unresolved_write}");
    eprintln!("  unmodeled_command         : {unmodeled}");
    eprintln!("  clean                     : {clean}");
    let mut v: Vec<_> = unmodeled_heads.iter().collect();
    v.sort_by_key(|(_, n)| std::cmp::Reverse(**n));
    eprintln!("  unmodeled heads, top offenders:");
    for (name, n) in v.iter().take(40) {
        eprintln!("    {n:>5}  {name}");
    }
}
