//! On-demand measurement for spec §9.3: how much of the corpus holds a brace
//! group the shell would rewrite, and how much of THAT vouch can reproduce
//! exactly instead of asking about (§6.2, the count before the code).
//!
//! Three populations, kept apart because they mean different things:
//!
//! 1. **SIMPLE LIST** — an unquoted group with a top-level comma whose
//!    alternatives are plain text. vouch expands these into the words the
//!    shell really passes, so a brace-spelled delete trips the same guard as
//!    the plain spelling. These move a row toward ASK only when the expanded
//!    words satisfy a guard rule, and toward ALLOW when they turn a
//!    brace-spelled head or verb into a recognised one.
//! 2. **OTHER** — an unquoted group vouch will not reproduce: a range, a nest,
//!    several groups in one token, or alternatives carrying quoting, escaping
//!    or expansion. Each of these raises the `brace_expansion` construct, so
//!    this population IS the construct's firing rate.
//! 3. **EXCLUDED** — tokens the classification deliberately leaves alone,
//!    counted separately so that "the construct did not fire" and "there was
//!    no brace here at all" stay distinguishable. Split into parameter
//!    expansions (`${…}`, a different mechanism entirely) and literal brace
//!    tokens with neither a top-level comma nor a range (`{}`, `{a}`), which
//!    bash passes through unchanged.
//!
//! **Position scope is measured, not assumed.** §9.3 expands in head and
//! suffix-word positions only. A prefix assignment's value is never read at
//! all, because bash does not brace-expand there (probed). A redirect target is
//! classified but NEVER expanded: more than one word is a shell error, and a
//! group collapsing to exactly one word redirects fine (`f{7..7}.txt` writes
//! `f7.txt`, probed) into a path vouch cannot name — so at that position BOTH
//! non-literal classes raise the construct, and the tallies below fold a
//! simple list found there into OTHER, which is what the scanner does with it.
//! Every position is counted on its own line, so a reader can see what the
//! scope decision costs rather than taking it on trust.
//!
//! **How the tokens are found.** Through `brush_parser`'s own tokenizer — the
//! same tokenizer the bash scanner parses with — never a regex over the row
//! text (§6.1). The tokenizer hands back the RAW word text with quotes and
//! backslashes intact, which is what the classification needs and what the
//! scanner's own argument list no longer holds. Position is then derived from
//! the operators between the tokens; that derivation is this file's own and is
//! an approximation of the parser's, so it is reported as a position SPLIT of
//! an exact total rather than as an exact split.
//!
//! **Nothing but shapes is printed.** The corpus is real machine history. Head
//! names are printed the way `count_head_shapes` prints them — bare, with any
//! directory dropped — and a head that is not a plain literal name is reported
//! as its class instead. No token text, no alternative, no operand.
//!
//! Run: cargo run --release --example count_brace_tokens

#[path = "../tests/common/mod.rs"]
mod common;

use std::collections::{BTreeMap, BTreeSet};
use vouch::shell::{expand_braces, Braces};

/// Per-head counts of the two classes that move a verdict.
#[derive(Default)]
struct Tally {
    simple: usize,
    other: usize,
}

/// Where a word sat on the line, since §9.3 answers differently per position.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Position {
    /// The command name.
    Head,
    /// Any word after the command name.
    SuffixWord,
    /// A `NAME=value` word BEFORE the command name. bash does not brace-expand
    /// these, so neither does vouch.
    PrefixAssignValue,
    /// The word a redirect points at. bash refuses a multi-word redirect as
    /// ambiguous, so nothing can hide in one.
    RedirectTarget,
}

impl Position {
    /// Whether the classifier runs on this position at all.
    fn classified(self) -> bool {
        !matches!(self, Position::PrefixAssignValue)
    }
    /// Whether a simple list found here becomes several words. False at a
    /// redirect target, where a non-literal word raises the construct instead.
    fn expands(self) -> bool {
        matches!(self, Position::Head | Position::SuffixWord)
    }
    fn label(self) -> &'static str {
        match self {
            Position::Head => "head",
            Position::SuffixWord => "suffix word",
            Position::PrefixAssignValue => "prefix-assignment value",
            Position::RedirectTarget => "redirect target",
        }
    }
    fn rule(self) -> &'static str {
        match self {
            Position::Head | Position::SuffixWord => "expands, or asks",
            Position::PrefixAssignValue => "never read",
            Position::RedirectTarget => "asks, never expands",
        }
    }
}

/// What the classification said about one token.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Class {
    SimpleList,
    Other,
    ExcludedParameterExpansion,
    ExcludedLiteralBrace,
}

/// Every class, in the order both print loops report them.
const ALL_CLASSES: [Class; 4] = [
    Class::SimpleList,
    Class::Other,
    Class::ExcludedParameterExpansion,
    Class::ExcludedLiteralBrace,
];

impl Class {
    fn label(self) -> &'static str {
        match self {
            Class::SimpleList => "SIMPLE LIST (expands)",
            Class::Other => "OTHER (raises brace_expansion)",
            Class::ExcludedParameterExpansion => "excluded: parameter expansion",
            Class::ExcludedLiteralBrace => "excluded: literal brace, no comma or range",
        }
    }
}

/// Classify one raw token, or `None` when it holds no brace at all.
fn classify(raw: &str) -> Option<Class> {
    match expand_braces(raw) {
        Braces::Words(_) => Some(Class::SimpleList),
        Braces::Rewritten => Some(Class::Other),
        Braces::Literal => {
            if raw.contains("${") {
                Some(Class::ExcludedParameterExpansion)
            } else if raw.contains('{') {
                Some(Class::ExcludedLiteralBrace)
            } else {
                None
            }
        }
    }
}

/// Operators after which the next word starts a fresh command, so the word
/// after one is a head rather than an argument.
fn starts_a_command(op: &str) -> bool {
    matches!(op, ";" | ";;" | "&" | "&&" | "|" | "||" | "|&" | "(" | ")" | "\n")
}

/// Reserved words that likewise put the next word at the start of a command.
/// A shell keyword is a WORD token, not an operator, so the split above cannot
/// see it.
fn keyword_starts_a_command(w: &str) -> bool {
    matches!(
        w,
        "if" | "then" | "elif" | "else" | "fi" | "while" | "until" | "do" | "done"
            | "case" | "esac" | "in" | "{" | "}" | "!" | "time" | "select" | "for"
            | "function" | "coproc" | "[[" | "]]"
    )
}

/// An operator with its leading descriptor number stripped, since `2>` and `>`
/// are the same operator pointed at different descriptors and the spellings
/// below name the operator only.
fn bare_operator(op: &str) -> &str {
    op.trim_start_matches(|c: char| c.is_ascii_digit())
}

/// True when a token is a redirect operator, so the word after it is a target.
fn is_redirect(op: &str) -> bool {
    matches!(
        bare_operator(op),
        "<" | ">" | ">>" | "<<<" | "<&" | ">&" | "<>" | ">|" | "&>" | "&>>"
    )
}

/// True for the here-document operators, which are their own case: the
/// tokenizer hands back THREE words for one of them — the delimiter, the whole
/// body, and the closing tag (verified against the token stream). None of the
/// three is a word the shell brace-expands, and the body is arbitrary file
/// content, so counting it as an argument would attribute every braces-carrying
/// document to whatever program consumed it.
fn is_heredoc(op: &str) -> bool {
    matches!(bare_operator(op), "<<" | "<<-")
}

/// A `NAME=` prefix with a valid identifier in front of the `=`.
fn is_assignment_word(w: &str) -> bool {
    match w.split_once('=') {
        Some((name, _)) => {
            !name.is_empty()
                && !name.starts_with(|c: char| c.is_ascii_digit())
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        }
        None => false,
    }
}

/// A head that is safe to print: a bare literal program name. Anything else is
/// reported as its class, because a head can be an absolute path from a real
/// machine.
fn printable_head(head: &str) -> String {
    let bare = vouch::guards::base_name(head);
    let plain = !bare.is_empty()
        && !bare.contains(['$', '/', '\\', ':', '`', '\'', '"', '{'])
        && bare.chars().all(|c| !c.is_whitespace());
    if plain { bare } else { "<not a literal name>".to_string() }
}

/// Heads some shipped bash entry describes with at least one guard rule — the
/// population where an expansion can change a verdict rather than only a token
/// count.
fn guarded_heads(kb: &vouch::guards::Knowledge) -> BTreeSet<String> {
    kb.program
        .iter()
        .filter(|p| !p.rule.is_empty())
        .filter(|p| p.languages.is_empty() || p.languages.iter().any(|l| l == "bash"))
        .flat_map(|p| p.match_names.iter().map(|n| n.to_ascii_lowercase()))
        .collect()
}

fn main() {
    let rows = common::rows_for_measurement();
    let kb = vouch::guards::in_effect();
    let guarded = guarded_heads(&kb);

    // Tokens, counted per (position, class).
    let mut tokens: BTreeMap<(Position, Class), usize> = BTreeMap::new();
    // Rows holding at least one in-scope token of each class.
    let mut rows_with: BTreeMap<Class, usize> = BTreeMap::new();
    // In-scope tokens per head, for the two classes that move a verdict.
    let mut per_head: BTreeMap<String, Tally> = BTreeMap::new();
    // Rows the tokenizer read. Every row is either read or not, so the rows it
    // could not read are the remainder and are derived at the print site.
    let mut tokenised = 0usize;
    // How many words a simple list turns into, minus the one it replaced —
    // the arity a guard rule now gets to look at and did not before.
    let mut extra_words = 0usize;

    for row in &rows {
        let Ok(toks) = brush_parser::tokenize_str(&row.cmd) else {
            continue;
        };
        tokenised += 1;
        let mut at_command_start = true;
        let mut next_is_target = false;
        // Words still owed to a here-document: delimiter, body, closing tag.
        let mut heredoc_words = 0usize;
        // The word after `for`/`select` is the loop variable, not a command.
        let mut skip_loop_variable = false;
        let mut head = String::new();
        let mut seen: BTreeSet<Class> = BTreeSet::new();
        for t in &toks {
            match t {
                brush_parser::Token::Operator(op, _) => {
                    if starts_a_command(op) {
                        at_command_start = true;
                        head.clear();
                    }
                    next_is_target = is_redirect(op);
                    if is_heredoc(op) {
                        heredoc_words += 3;
                    }
                }
                brush_parser::Token::Word(raw, _) => {
                    if heredoc_words > 0 {
                        heredoc_words -= 1;
                        continue;
                    }
                    if skip_loop_variable {
                        skip_loop_variable = false;
                        continue;
                    }
                    let position = if next_is_target {
                        Position::RedirectTarget
                    } else if at_command_start {
                        if is_assignment_word(raw) {
                            Position::PrefixAssignValue
                        } else {
                            Position::Head
                        }
                    } else {
                        Position::SuffixWord
                    };
                    next_is_target = false;
                    if position == Position::Head {
                        if keyword_starts_a_command(raw) {
                            // Still at a command start; a keyword is not a head.
                            skip_loop_variable = raw == "for" || raw == "select";
                            continue;
                        }
                        head = printable_head(raw);
                        at_command_start = false;
                    }
                    let Some(class) = classify(raw) else { continue };
                    *tokens.entry((position, class)).or_default() += 1;
                    if !position.classified() {
                        continue;
                    }
                    // A simple list at a redirect target does NOT expand — it
                    // raises the construct like any other non-literal word, so
                    // it is tallied as what the scanner actually does with it.
                    let class = if class == Class::SimpleList && !position.expands() {
                        Class::Other
                    } else {
                        class
                    };
                    seen.insert(class);
                    if position.expands() {
                        if let Braces::Words(ws) = expand_braces(raw) {
                            extra_words += ws.len().saturating_sub(1);
                        }
                    }
                    if matches!(class, Class::SimpleList | Class::Other) {
                        // A head token names itself; a suffix word names the
                        // head it belongs to.
                        let key = if position == Position::Head {
                            printable_head(raw)
                        } else {
                            head.clone()
                        };
                        let slot = per_head.entry(key).or_default();
                        if class == Class::SimpleList {
                            slot.simple += 1;
                        } else {
                            slot.other += 1;
                        }
                    }
                }
            }
        }
        for c in seen {
            *rows_with.entry(c).or_default() += 1;
        }
    }

    let unreadable = rows.len() - tokenised;
    println!("corpus rows: {} ({tokenised} tokenised clean, {unreadable} not)", rows.len());
    println!();
    println!("=== tokens holding a brace, by position and class ===");
    for position in [
        Position::Head,
        Position::SuffixWord,
        Position::PrefixAssignValue,
        Position::RedirectTarget,
    ] {
        println!("  {} ({}):", position.label(), position.rule());
        for class in ALL_CLASSES {
            let n = tokens.get(&(position, class)).copied().unwrap_or(0);
            println!("    {:<44} {n}", class.label());
        }
    }
    println!();
    println!("=== rows with at least one CLASSIFIED token of each class ===");
    println!("  (a simple list at a redirect target is counted under OTHER: it asks there)");
    for class in ALL_CLASSES {
        println!("  {:<44} {}", class.label(), rows_with.get(&class).copied().unwrap_or(0));
    }
    println!();
    println!("extra words a simple list adds, in scope: {extra_words}");
    println!();
    println!("=== in-scope tokens per head (SIMPLE = expands, OTHER = asks) ===");
    println!("  a head marked `guard` has a shipped bash entry carrying at least one rule,");
    println!("  so an expansion there can change a verdict rather than only a token count");
    let mut ordered: Vec<_> = per_head.iter().collect();
    ordered.sort_by(|a, b| {
        (b.1.simple + b.1.other).cmp(&(a.1.simple + a.1.other)).then(a.0.cmp(b.0))
    });
    for (head, tally) in ordered {
        let (simple, other) = (tally.simple, tally.other);
        let mark = if guarded.contains(&head.to_ascii_lowercase()) { "guard" } else { "" };
        println!("    {head:<24} SIMPLE {simple:<6} OTHER {other:<6} {mark}");
    }
}
