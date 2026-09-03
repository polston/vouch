//! Bash parsing.
//!
//! Backed by `brush-parser` 0.4.0 (POSIX/bash tokenizer + parser, the one used
//! by the brush shell). Chosen on 2026-07-25 after checking crates.io: the
//! alternatives were `conch-parser` (0.1.1, dormant) and `yash-syntax`
//! (POSIX-only). brush is the maintained bash-capable option.
//!
//! Rules for this module:
//!   * A parse failure returns `Err`. NEVER an empty `Parsed`. The engine has to
//!     be able to tell "nothing objectionable here" apart from "I could not read
//!     this", because those get different settings and different messages.
//!   * Every construct we can name gets a stable string name, and that name is
//!     what the user puts in `[lang.bash.constructs]`. Adding a detection here
//!     without adding the name to `engine::KNOWN_CONSTRUCTS` will fail a test.
//!   * Compound bodies (loops, if, subshells, functions) are walked, not
//!     skipped — a command hidden in a `for` body counts exactly the same.

use brush_parser::ast;

pub use crate::syntax::{Cmd, Heredoc, Order, Scan as Parsed};

/// True when a word's value depends on something we cannot see at decision time.
fn is_dynamic(value: &str) -> bool {
    // One definition of "shell expansion acts on this text", shared with the
    // here-document rules in `guards` — see `guards::carries_expansion`.
    crate::guards::carries_expansion(value)
}

/// True when a word embeds a command substitution, which executes a command.
fn has_command_substitution(value: &str) -> bool {
    value.contains("$(") || value.contains('`')
}

/// Resolve `\X` -> `X` in the UNQUOTED regions of a word's raw text, leaving
/// quoted regions exactly as the parser handed them.
///
/// `brush_parser`'s `Word::value` is raw source text — quotes and backslashes
/// both still in it — so a word like `who\ami` arrives with the backslash
/// intact. A real bash reads that backslash as an escape (outside quotes,
/// `\X` means the literal character X, whatever X is) rather than as a path
/// separator, so `who\ami` and `whoami` are the SAME name to the shell —
/// vouch was reading them as different names because nothing resolved the
/// escape (M2.121).
///
/// Only the UNQUOTED regions are touched:
///   * Outside any quote, `\` consumes the next character and disappears —
///     the shell drops it before the program ever sees the argument, so
///     vouch drops it here too. A trailing lone backslash (nothing left to
///     escape) disappears with nothing pushed, the same convention
///     `paths::unquote_snippet`'s unquoted arm uses.
///   * Inside single quotes, backslash is ordinary text — single quotes make
///     escaping impossible, so the region is copied through untouched; the
///     only thing that ends it is a literal `'`.
///   * Inside double quotes, this function does nothing to the CONTENT
///     (today's treatment — double-quote escape processing belongs to
///     `paths::unquote_snippet`, applied where a snippet's own quoting layer
///     is stripped) but still has to track an escaped `\"` correctly so it
///     is not mistaken for the closing quote and does not resume unquoted
///     processing early.
/// Quote characters themselves are kept in the output (both as region
/// delimiters and, escaped, as ordinary content) — this is not a full
/// unquote, only the unquoted-region backslash fold; `paths::unquote` still
/// strips the one surviving layer of surrounding quotes downstream.
fn unescape_unquoted(raw: &str) -> String {
    #[derive(PartialEq)]
    enum Q {
        None,
        Single,
        Double,
    }
    let cs: Vec<char> = raw.chars().collect();
    let mut out = String::with_capacity(raw.len());
    let mut state = Q::None;
    let mut i = 0;
    while i < cs.len() {
        let c = cs[i];
        match state {
            Q::None => match c {
                '\'' => {
                    state = Q::Single;
                    out.push(c);
                    i += 1;
                }
                '"' => {
                    state = Q::Double;
                    out.push(c);
                    i += 1;
                }
                '\\' => {
                    if let Some(&next) = cs.get(i + 1) {
                        out.push(next);
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                _ => {
                    out.push(c);
                    i += 1;
                }
            },
            Q::Single => {
                out.push(c);
                i += 1;
                if c == '\'' {
                    state = Q::None;
                }
            }
            Q::Double => {
                if c == '\\' {
                    out.push(c);
                    if let Some(&next) = cs.get(i + 1) {
                        out.push(next);
                        i += 2;
                    } else {
                        i += 1;
                    }
                    continue;
                }
                out.push(c);
                i += 1;
                if c == '"' {
                    state = Q::None;
                }
            }
        }
    }
    out
}

/// The name of the construct raised for a brace group vouch will not
/// reproduce. One spelling, shared by the scanner and by the on-demand
/// measurement that counts how often it fires.
pub const BRACE_EXPANSION: &str = "brace_expansion";

/// What brace expansion makes of one word's RAW text.
///
/// The shell rewrites `rm -{r,f} d` into `rm -r -f d` before `rm` ever runs,
/// so recording the token as it was written describes a command line the shell
/// never produced — and a guard rule looking for `-r` sees nothing. Reading the
/// token is therefore not optional; the only question is whether vouch can
/// reproduce the rewrite exactly, and this type is that answer.
///
/// Every rule below was checked against bash 5.2 rather than reasoned about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Braces {
    /// Nothing here is subject to brace expansion, so the word records exactly
    /// as it stands and nothing is hidden. Covers a word with no brace at all,
    /// a group with neither a top-level comma nor a `..` range (`{}`, `{a}`,
    /// `{a-b}` — all literal in bash), a parameter expansion (`${VAR}`), and a
    /// quoted group (`"-{r,f}"`, which the program really does receive with
    /// the braces in it).
    Literal,
    /// A simple literal list: these RAW words, in order, are the ones the
    /// shell will pass. Raw rather than unescaped because the caller still
    /// owes each one the same unescaping every other word gets.
    Words(Vec<String>),
    /// The shell will rewrite this token in a way vouch does not reproduce —
    /// a range, a nest, several groups, or alternatives carrying quoting,
    /// escaping or expansion. The word still records as it stands, and the
    /// caller raises `BRACE_EXPANSION` beside it so the rewrite is not
    /// silent.
    Rewritten,
}

/// One brace group found in a word's raw text, with the top-level structure
/// the classification asks about already worked out.
struct Group {
    /// Byte offset of the `{`.
    open: usize,
    /// Byte offset of the matching `}`.
    close: usize,
    /// Byte ranges of the top-level alternatives, in order.
    alts: Vec<(usize, usize)>,
    /// A comma at the group's own top level, unquoted and unescaped — the
    /// separator bash would split on.
    has_comma: bool,
    /// A `..` at the group's own top level: a RANGE, which bash rewrites even
    /// though it carries no comma at all.
    has_range: bool,
}

/// Where a walk over a word's raw text stands with respect to quoting: inside
/// a single-quoted string, inside a double-quoted one, or neither.
///
/// Defined once because three walks over the same raw text need it — the
/// command-substitution skip, the top-level group scan, and the group-body
/// scan — and a copy per walk is three places a quoting fix has to be found.
/// It is deliberately NOT `unescape_unquoted`'s state machine: that one BUILDS
/// the unescaped text and so must keep the character a backslash protects,
/// while these three only need to know which positions the shell's own
/// structure characters can occupy.
#[derive(Default)]
struct Quoting {
    in_single: bool,
    in_double: bool,
}

impl Quoting {
    /// Consume the character at `i` when quoting alone decides what it means:
    /// any character inside a string, and the quotes and backslashes that only
    /// move this state. `Some(next)` is where the walk continues; `None` means
    /// the character is the caller's own to interpret.
    ///
    /// A step rather than a predicate because a backslash consumes the
    /// character after it — inside double quotes as well as outside — so the
    /// answer is a position, not a flag.
    fn step(&mut self, cs: &[(usize, char)], i: usize) -> Option<usize> {
        let c = cs[i].1;
        if self.in_single {
            if c == '\'' {
                self.in_single = false;
            }
            return Some(i + 1);
        }
        if self.in_double {
            if c == '\\' {
                return Some(i + 2);
            }
            if c == '"' {
                self.in_double = false;
            }
            return Some(i + 1);
        }
        match c {
            '\\' => Some(i + 2),
            '\'' => {
                self.in_single = true;
                Some(i + 1)
            }
            '"' => {
                self.in_double = true;
                Some(i + 1)
            }
            _ => None,
        }
    }
}

/// The position just past a `$( … )` command substitution that starts at the
/// `$`, or `None` when it never closes.
///
/// Nest- and quote-aware: a `)` inside a string or inside an inner
/// substitution does not end the outer one.
fn skip_command_substitution(cs: &[(usize, char)], dollar: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut quoting = Quoting::default();
    let mut i = dollar + 1;
    while i < cs.len() {
        if let Some(next) = quoting.step(cs, i) {
            i = next;
            continue;
        }
        match cs[i].1 {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i + 1);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// The position just past a backquoted command substitution that starts at the
/// opening backquote, or `None` when it never closes.
fn skip_backquotes(cs: &[(usize, char)], tick: usize) -> Option<usize> {
    let mut i = tick + 1;
    while i < cs.len() {
        match cs[i].1 {
            '\\' => i += 2,
            '`' => return Some(i + 1),
            _ => i += 1,
        }
    }
    None
}

/// Every brace group in a word's raw text that the shell would even look at:
/// unquoted, unescaped, outside any command substitution, and — for the `{`
/// itself — not introduced by a `$`, which makes it parameter expansion rather
/// than brace expansion.
///
/// A command substitution is skipped WHOLE, in both spellings. A brace group
/// written inside one belongs to the command the substitution RUNS, not to the
/// word being classified: bash hands `x$(echo {a,b})` to the program as the two
/// words `xa` and `b` (probed), which is nothing like the two words a reader
/// would get by expanding the outer token. Reading it as an outer group would
/// record tokens the shell never passes, and record them silently. A group
/// OUTSIDE the substitution is unaffected and still classifies —
/// `$(echo z){a,b}` really is a two-word expansion.
///
/// The `$` test is escape-aware, and that is not a liberty taken with the
/// rule: an escaped `$` is a literal dollar character, not the introducer of a
/// parameter expansion, and bash brace-expands `\${a,b}` into `$a $b` (probed).
/// Reading the raw byte alone would leave that spelling recorded as one
/// literal token, which is the exact silence this whole classification exists
/// to remove.
fn brace_groups(raw: &str) -> Vec<Group> {
    let cs: Vec<(usize, char)> = raw.char_indices().collect();
    let mut out = Vec::new();
    let mut i = 0;
    // Quote state, tracked because a group inside quotes is literal text the
    // program really receives.
    let mut quoting = Quoting::default();
    while i < cs.len() {
        if let Some(next) = quoting.step(&cs, i) {
            i = next;
            continue;
        }
        match cs[i].1 {
            // A parameter expansion is skipped WHOLE, so a brace inside its
            // body cannot be mistaken for a group of its own. An ESCAPED `$`
            // never reaches here — the quoting step above consumed it — which
            // is exactly why `\${a,b}` still counts as a group.
            '$' if cs.get(i + 1).is_some_and(|&(_, n)| n == '{') => {
                match scan_group(&cs, raw, i + 1) {
                    Some((_, next)) => {
                        i = next;
                        continue;
                    }
                    // Unterminated: nothing here can be a group either.
                    None => break,
                }
            }
            '$' if cs.get(i + 1).is_some_and(|&(_, n)| n == '(') => {
                match skip_command_substitution(&cs, i) {
                    Some(next) => {
                        i = next;
                        continue;
                    }
                    None => break,
                }
            }
            '`' => match skip_backquotes(&cs, i) {
                Some(next) => {
                    i = next;
                    continue;
                }
                None => break,
            },
            '{' => {
                if let Some((g, next)) = scan_group(&cs, raw, i) {
                    out.push(g);
                    i = next;
                    continue;
                }
            }
            _ => {}
        }
        i += 1;
    }
    out
}

/// Walk one group from its `{` to the matching `}`, recording where its
/// top-level alternatives sit and whether it carries a top-level comma or
/// range. Returns the group and the position just past its `}`. `None` when
/// no matching `}` arrives — an unterminated brace is ordinary text to the
/// shell.
fn scan_group(cs: &[(usize, char)], raw: &str, open_idx: usize) -> Option<(Group, usize)> {
    let open = cs[open_idx].0;
    let mut depth = 1usize;
    let mut alt_start = cs.get(open_idx + 1).map(|&(b, _)| b).unwrap_or(raw.len());
    let mut alts = Vec::new();
    let (mut has_comma, mut has_range) = (false, false);
    let mut quoting = Quoting::default();
    let mut i = open_idx + 1;
    while i < cs.len() {
        if let Some(next) = quoting.step(cs, i) {
            i = next;
            continue;
        }
        let (b, c) = cs[i];
        match c {
            '$' if cs.get(i + 1).is_some_and(|&(_, n)| n == '{') => {
                let (_, next) = scan_group(cs, raw, i + 1)?;
                i = next;
                continue;
            }
            // Skipped whole for the same reason as at the top level, and for
            // one more: a `}` or a `,` inside a substitution belongs to the
            // command it runs, so reading either as this group's structure
            // would find the wrong end and the wrong alternatives.
            '$' if cs.get(i + 1).is_some_and(|&(_, n)| n == '(') => {
                i = skip_command_substitution(cs, i)?;
                continue;
            }
            '`' => {
                i = skip_backquotes(cs, i)?;
                continue;
            }
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    alts.push((alt_start, b));
                    return Some((
                        Group { open, close: b, alts, has_comma, has_range },
                        i + 1,
                    ));
                }
            }
            ',' if depth == 1 => {
                alts.push((alt_start, b));
                alt_start = b + c.len_utf8();
                has_comma = true;
            }
            '.' if depth == 1 && cs.get(i + 1).is_some_and(|&(_, n)| n == '.') => {
                has_range = true;
                i += 2;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// The characters an alternative may not contain if vouch is to claim it knows
/// what the shell will pass. Quoting and escaping change where bash splits;
/// `$` and a backquote change what the alternative BECOMES; a brace or a range
/// means there is more expansion inside it.
fn alternative_is_plain(text: &str) -> bool {
    !text.contains("..")
        && !text.chars().any(|c| matches!(c, '{' | '}' | '$' | '`' | '\'' | '"' | '\\'))
}

/// Classify one word's RAW text — before unescaping, which is the whole point:
/// `unescape_unquoted` erases the backslash that tells `{a\,b,c}` (two
/// alternatives) from `{a,b,c}` (three), so a detector reading the unescaped
/// text cannot tell them apart.
pub fn expand_braces(raw: &str) -> Braces {
    // A word carrying no `{` byte cannot hold a group under any quoting, and
    // this runs on every command head, every suffix word and every redirect
    // target of every bash scan — so the common case must not pay for the
    // character vector `brace_groups` builds.
    if !raw.as_bytes().contains(&b'{') {
        return Braces::Literal;
    }
    let groups = brace_groups(raw);
    // "Subject to brace expansion" is rule 0: a top-level comma or a range.
    // A group with neither is literal in bash, so a token holding only those
    // is not this function's business at all.
    let subject: Vec<&Group> = groups.iter().filter(|g| g.has_comma || g.has_range).collect();
    if subject.is_empty() {
        return Braces::Literal;
    }
    // One SUBJECT group, not one brace of any kind: a literal `{}` sitting in
    // the prefix or suffix distributes as ordinary text and the result still
    // matches the shell exactly (`a{b,c}{}` → `ab{} ac{}`, probed). What rule
    // 2 refuses is the cross product of two expanding groups.
    if subject.len() == 1 {
        let g = subject[0];
        let alts: Vec<&str> = g.alts.iter().map(|&(s, e)| &raw[s..e]).collect();
        let prefix = &raw[..g.open];
        // `}` is one byte, so the suffix starts immediately after it.
        let suffix = &raw[g.close + 1..];
        // An empty alternative with nothing either side of the group leaves an
        // empty word, which bash then drops — a word count vouch would get
        // wrong. With an affix surviving there is no empty word and no guess.
        let empty_ok = !alts.iter().any(|a| a.is_empty()) || !prefix.is_empty() || !suffix.is_empty();
        if g.has_comma && empty_ok && alts.iter().all(|a| alternative_is_plain(a)) {
            return Braces::Words(
                alts.iter().map(|a| format!("{prefix}{a}{suffix}")).collect(),
            );
        }
    }
    Braces::Rewritten
}

pub fn parse(cmd: &str) -> Result<Parsed, String> {
    let options = brush_parser::ParserOptions::default();
    let mut parser = brush_parser::Parser::new(std::io::Cursor::new(cmd), &options);
    let program = parser
        .parse_program()
        .map_err(|e| format!("{e}").lines().next().unwrap_or("parse error").to_string())?;

    let mut out = Parsed::default();
    let mut counter = 0u32;
    // Identifies one and-or chain (`ChainPos.id`) uniquely across the whole
    // parse — unlike `counter`, never reset for a nested compound body, so
    // an inner `if a && b; then …` chain can never collide with an outer one.
    let mut chain_counter = 0u32;
    for cc in &program.complete_commands {
        walk_compound_list(cc, &mut out, &mut counter, false, &mut chain_counter, 0);
    }
    Ok(out)
}

/// The position/chain claim a construct makes about ITSELF within its parent
/// scope, converted to an `Order` — `Unordered` unconditionally when the
/// caller says this position cannot be trusted, otherwise the next value off
/// `counter`. Shared by every site that needs to capture a construct's own
/// anchor before descending into a scope that sequences with a fresh local
/// counter (design doc §3.1).
fn own_order(counter: &mut u32, unordered: bool) -> Order {
    if unordered {
        Order::Unordered
    } else {
        let n = *counter;
        *counter += 1;
        Order::Seq(n)
    }
}

/// Push a new `ScanScope` and return its id — 1-based, since scope 0 is the
/// top level and has no entry of its own in `scan_scopes` (see the type's
/// own doc).
fn alloc_scope(
    out: &mut Parsed,
    parent: usize,
    kind: crate::syntax::ScopeKind,
    class: Option<crate::syntax::ScopeClass>,
    anchor_order: Order,
    anchor_chain: Option<crate::syntax::ChainPos>,
) -> usize {
    out.scan_scopes.push(crate::syntax::ScanScope {
        parent,
        kind,
        class,
        anchor_order,
        anchor_chain,
    });
    out.scan_scopes.len()
}

/// `counter` is the running sequence position within `scope`; it only ever
/// advances on a path that is provably `Seq` (see `walk_simple`). `unordered`
/// is the accumulated "can this position even be trusted" state coming down
/// from the caller — once true it stays true for everything underneath, but
/// it resets to whatever the caller passed at the start of each new
/// list/chain, so a later `;`-separated item is not permanently poisoned by
/// an earlier `||` or subshell.
///
/// A `&`-terminated item is passed to `walk_and_or_list` as `async_list`
/// rather than folded into `unordered`: only that list's LAST pipeline is a
/// genuine process boundary (design doc §3.3) — earlier members still get a
/// locally-provable position, which OR-ing into `unordered` would destroy.
fn walk_compound_list(
    list: &ast::CompoundList,
    out: &mut Parsed,
    counter: &mut u32,
    unordered: bool,
    chain_counter: &mut u32,
    scope: usize,
) {
    for item in &list.0 {
        let async_item = matches!(item.1, ast::SeparatorOperator::Async);
        if async_item {
            out.note("background");
        }
        walk_and_or_list(&item.0, out, counter, unordered, chain_counter, scope, async_item);
    }
}

/// Assigns a `ChainPos` to every pipeline member of this and-or list — a
/// member being one `first`/`additional` element (a whole `a | b | c`
/// pipeline counts as ONE member; every `Cmd` it produces shares that one
/// `ChainPos`, see the type's own doc) — when the list has at least one
/// `&&`/`||` link. A list with no link at all (`list.additional` empty) is
/// not a chain; every command inside gets `chain: None`, per `Cmd.chain`'s
/// own doc.
///
/// `scope` is where every member of this list lands absent its own boundary.
/// `async_list` is true when the CALLER (`walk_compound_list`, from this
/// item's own separator) has already decided this whole list is the target of
/// a trailing `&` — only its LAST pipeline member is a genuine process
/// boundary; earlier members still run, just uncertified to finish before the
/// shell moves on, so they get their own `SameProcess` scope rather than
/// folding into the boundary (spec §3.3).
fn walk_and_or_list(
    list: &ast::AndOrList,
    out: &mut Parsed,
    counter: &mut u32,
    base_unordered: bool,
    chain_counter: &mut u32,
    scope: usize,
    async_list: bool,
) {
    let mut unordered = base_unordered;
    // A linkless list is not a chain — except when its sole pipeline is
    // NEGATED: the `!` bit has to survive somewhere, because a certified
    // walk that cannot see it would read `if ! cd X; then …` as proof the
    // cd succeeded — the inverted-status wrong-file allow (design §3.1; the
    // Task 2 round-0 deferred minor, load-bearing since body candidates).
    // A one-member chain certifies and refutes nothing by construction
    // (both predicates need m.idx < c.idx), so the id is inert otherwise.
    let id = if list.additional.is_empty() && !list.first.bang {
        None
    } else {
        let id = *chain_counter;
        *chain_counter += 1;
        Some(id)
    };
    let n_members = 1 + list.additional.len() as u32;
    // Meaningful only when `async_list` is true: the last member is the
    // genuine process boundary, every earlier one stays `SameProcess`.
    let boundary_for = |idx: u32| -> Option<crate::syntax::ScopeKind> {
        if !async_list {
            None
        } else if idx + 1 == n_members {
            Some(crate::syntax::ScopeKind::ProcessBoundary)
        } else {
            Some(crate::syntax::ScopeKind::SameProcess)
        }
    };
    let mut idx = 0u32;
    // The earliest member reachable from the CURRENT member by walking
    // backward over `&&` links only. Starts at 0 (the first member's own
    // index — nothing precedes it) and is carried forward unchanged across
    // every `&&`, then reset to the current member's own `idx` at every
    // `||` (§`ChainPos` doc: nothing before an `||` is certified by it
    // running).
    let mut and_run_from = 0u32;
    let first_pos = id.map(|id| crate::syntax::ChainPos {
        id,
        idx,
        and_run_from,
        negated: list.first.bang,
    });
    walk_pipeline(&list.first, out, counter, unordered, first_pos, chain_counter, scope, boundary_for(idx));
    idx += 1;
    for ao in &list.additional {
        match ao {
            // From the first `||` on, nothing in the rest of this chain is
            // provably going to run — the shell only reaches it if the
            // previous stage failed.
            ast::AndOr::Or(p) => {
                unordered = true;
                and_run_from = idx;
                let pos = id.map(|id| crate::syntax::ChainPos { id, idx, and_run_from, negated: p.bang });
                walk_pipeline(p, out, counter, unordered, pos, chain_counter, scope, boundary_for(idx));
            }
            ast::AndOr::And(p) => {
                let pos = id.map(|id| crate::syntax::ChainPos { id, idx, and_run_from, negated: p.bang });
                walk_pipeline(p, out, counter, unordered, pos, chain_counter, scope, boundary_for(idx));
            }
        }
        idx += 1;
    }
}

/// `scope` is where this pipeline's own members land absent any wrapper this
/// call allocates. `async_boundary` is `Some(kind)` when the caller has
/// already decided THIS pipeline is the target of a trailing `&` (only
/// `walk_and_or_list` ever passes it) — handling it here, before the
/// multi-member split below, means a one-member backgrounded pipeline still
/// gets the scope the background itself requires, even though a one-member
/// pipeline that is NOT backgrounded allocates nothing at all.
fn walk_pipeline(
    p: &ast::Pipeline,
    out: &mut Parsed,
    counter: &mut u32,
    base_unordered: bool,
    chain: Option<crate::syntax::ChainPos>,
    chain_counter: &mut u32,
    scope: usize,
    async_boundary: Option<crate::syntax::ScopeKind>,
) {
    if let Some(kind) = async_boundary {
        let anchor = own_order(counter, base_unordered);
        let class = match kind {
            crate::syntax::ScopeKind::SameProcess => Some(crate::syntax::ScopeClass::AsyncMember),
            crate::syntax::ScopeKind::ProcessBoundary => None,
        };
        let wrapper = alloc_scope(out, scope, kind, class, anchor, chain);
        let mut local_counter = 0u32;
        walk_pipeline(p, out, &mut local_counter, false, chain, chain_counter, wrapper, None);
        return;
    }
    // A pipeline runs its members concurrently; with more than one member
    // there is no single provable "this ran, then that ran" — each member
    // gets its own scope (last = `SameProcess`, the rest = `ProcessBoundary`,
    // spec §3.3), sequenced locally. A one-member pipeline is just a command
    // wearing pipeline syntax and keeps whatever order and scope it already
    // had — it allocates nothing of its own.
    if p.seq.len() > 1 {
        let anchor = own_order(counter, base_unordered);
        let last = p.seq.len() - 1;
        for (i, cmd) in p.seq.iter().enumerate() {
            let (kind, class) = if i == last {
                (
                    crate::syntax::ScopeKind::SameProcess,
                    Some(crate::syntax::ScopeClass::PipeTail),
                )
            } else {
                (crate::syntax::ScopeKind::ProcessBoundary, None)
            };
            let member_scope = alloc_scope(out, scope, kind, class, anchor.clone(), chain);
            let mut local_counter = 0u32;
            // Only members AFTER the first read the pipe; the first member's
            // own standard input is whatever the pipeline as a whole was
            // given. Every piped stage shares the SAME `chain` value — they
            // are one chain member, not several (`ChainPos` doc).
            walk_command(cmd, out, &mut local_counter, false, i > 0, chain, chain_counter, member_scope);
        }
    } else {
        for (i, cmd) in p.seq.iter().enumerate() {
            walk_command(cmd, out, counter, base_unordered, i > 0, chain, chain_counter, scope);
        }
    }
}

fn walk_command(
    cmd: &ast::Command,
    out: &mut Parsed,
    counter: &mut u32,
    unordered: bool,
    pipe_input: bool,
    chain: Option<crate::syntax::ChainPos>,
    chain_counter: &mut u32,
    scope: usize,
) {
    match cmd {
        ast::Command::Simple(sc) => {
            walk_simple(sc, out, counter, unordered, pipe_input, chain, chain_counter, scope)
        }
        ast::Command::Compound(cc, redirects) => {
            // The construct's own position in ITS enclosing scope, captured
            // here before descending — the body's own scope(s) anchor at this
            // value (`walk_compound`), and this is the only place it is known:
            // a compound command has no prefix/suffix argument walk the way a
            // simple command does, so there is nothing to compute it before.
            let anchor_order = own_order(counter, unordered);
            let scoping = BodyScoping::Fresh {
                parent: scope,
                anchor_order: anchor_order.clone(),
                anchor_chain: chain,
            };
            let range = walk_compound(cc, out, chain_counter, scoping);
            let mut own_stdin: Option<crate::syntax::InputSource> = None;
            if let Some(list) = redirects {
                for r in &list.0 {
                    // A compound body has no landing `Cmd` of its own to tie
                    // a heredoc capture to — `None` keeps the construct note.
                    // The LAST descriptor-0 redirect decides, same fold as a
                    // simple command's own.
                    //
                    // Design 2026-08-30 §3.3, both halves: the redirect is
                    // opened once, AT THE COMPOUND'S ANCHOR, in the scope
                    // CONTAINING the compound. The scope is the parent's, not
                    // the body's fresh one — `for f in 1; do cd /a; done >
                    // rel.txt` writes `rel.txt` from the PARENT's position,
                    // never the loop body's. The order is the construct's own
                    // anchor, which is why it is cloned above rather than
                    // moved: passing `Order::Unordered` here left the redirect
                    // owning no site, so it fell back to its scope and
                    // reported a position vouch could not place, wherever an
                    // ordered mover shared the line (M2.226). The anchor
                    // precedes the body, so a mover written INSIDE the
                    // compound still cannot decide where the redirect lands.
                    if let Some(claimed) = walk_redirect(
                        r,
                        out,
                        anchor_order.clone(),
                        None,
                        chain_counter,
                        scope,
                        chain,
                    )
                    {
                        own_stdin = Some(claimed);
                    }
                }
            }
            // The commands INSIDE take their standard input from this compound
            // whenever it supplies one — its own descriptor-0 redirect, or the
            // pipe when the compound itself is a pipeline member. Neither is
            // knowable while the body is being walked (the redirects are read
            // afterwards), so it is a fix-up over the range the body pushed.
            if own_stdin.is_some() || pipe_input {
                blank_inherited_input(out, range);
            }
        }
        ast::Command::Function(f) => {
            out.note("function_def");
            // A definition's body can never know its future caller's standard
            // input, so the blanking is unconditional — but it blanks the same
            // positions the compound arm does, leaving any command that
            // resolved a source of its OWN untouched. It is not a body/process
            // boundary of its own — `Passthrough` walks it straight into the
            // scope the definition itself sits in, unchanged from today.
            let range = walk_compound(&f.body.0, out, chain_counter, BodyScoping::Passthrough { scope });
            blank_inherited_input(out, range);
        }
        ast::Command::ExtendedTest(_, redirects) => {
            if let Some(list) = redirects {
                for r in &list.0 {
                    let order = own_order(counter, unordered);
                    // An extended-test expression has no landing `Cmd` of its
                    // own either — same `None` as the compound-body arm above.
                    // It pushes no commands, so whatever its redirects claim
                    // about standard input has no occurrence to belong to.
                    walk_redirect(r, out, order, None, chain_counter, scope, chain);
                }
            }
        }
    }
}

/// Rewrites the input source to `Unknown` for every command in `range` that
/// did not resolve a source of its OWN.
///
/// An enclosing construct — a compound carrying a descriptor-0 redirect, a
/// compound that is a pipeline member, a function body, a coprocess body —
/// supplies standard input to the commands inside it, and the walk never looked
/// at what that input is. `Nothing` would be a false statement of fact there;
/// `Unknown` is the true one. A command that DID resolve its own source keeps
/// it: redirections are applied per command at execution, so an inner
/// here-document or descriptor-0 redirect overrides whatever the enclosing
/// construct supplied, and a pipeline member inside the compound reads the
/// inner pipe rather than the outer redirect.
fn blank_inherited_input(out: &mut Parsed, range: std::ops::Range<usize>) {
    for i in range {
        if let Some(slot) = out.input_source.get_mut(i) {
            if matches!(slot, crate::syntax::InputSource::Nothing) {
                *slot = crate::syntax::InputSource::Unknown;
            }
        }
    }
}

/// How a compound command's own BODY relates to the scope table — the two
/// cases `walk_compound` has to serve from ONE shared per-variant dispatcher.
///
/// `Fresh` is the ordinary case: the compound command sits at some position
/// in an outer scope and its body gets a brand new `ScanScope` (kind decided
/// per variant), sequenced with a fresh local counter starting at 0. Calling
/// `.enter()` more than once allocates a DISTINCT scope each time, all
/// sharing the same cloned anchor — needed for a construct like `IfClause`
/// whose condition and branch are two separate scopes anchored at the same
/// `if`.
///
/// `Passthrough` is a function body: nothing about defining it is a
/// process/body boundary of its own — only calling it later is — so it walks
/// straight into the caller's existing scope, unchanged from before this
/// scope table existed, with every command inside still `Order::Unordered`.
enum BodyScoping {
    Fresh {
        parent: usize,
        anchor_order: Order,
        anchor_chain: Option<crate::syntax::ChainPos>,
    },
    Passthrough {
        scope: usize,
    },
}

impl BodyScoping {
    fn enter(
        &self,
        out: &mut Parsed,
        kind: crate::syntax::ScopeKind,
        class: Option<crate::syntax::ScopeClass>,
    ) -> usize {
        match self {
            BodyScoping::Fresh { parent, anchor_order, anchor_chain } => {
                alloc_scope(out, *parent, kind, class, anchor_order.clone(), *anchor_chain)
            }
            BodyScoping::Passthrough { scope } => *scope,
        }
    }

    /// Whether commands entering a body under this scoping stay
    /// `Order::Unordered` (`Passthrough` — a function body's contents are
    /// exactly as unprovable as they always were; only its future CALL site
    /// has a position) or get a fresh local `Seq` counter (`Fresh`).
    fn children_unordered(&self) -> bool {
        matches!(self, BodyScoping::Passthrough { .. })
    }
}

/// Every compound body — subshells, loops, if/case branches, brace groups,
/// coprocesses — gets its own `ScanScope` (kind per spec §3.3) anchored at
/// the construct's own claimed position in its enclosing scope (`scoping`,
/// captured by the caller before descending), and is sequenced internally
/// with a FRESH local counter starting at 0 rather than pinned
/// `Order::Unordered`. A function body is the one exception: `scoping` is
/// `BodyScoping::Passthrough` for it, which allocates nothing and leaves
/// every command inside `Order::Unordered`, same as before this scope table
/// existed.
///
/// Returns the range of command positions the body pushed, so the caller can
/// fix up their input source once it knows what the compound itself supplies —
/// which it cannot know while the body is being walked, because a compound's
/// own redirects are read afterwards.
fn walk_compound(
    cc: &ast::CompoundCommand,
    out: &mut Parsed,
    chain_counter: &mut u32,
    scoping: BodyScoping,
) -> std::ops::Range<usize> {
    let start = out.commands.len();
    let unordered = scoping.children_unordered();
    match cc {
        ast::CompoundCommand::BraceGroup(bg) => {
            let s = scoping.enter(out, crate::syntax::ScopeKind::SameProcess, Some(crate::syntax::ScopeClass::Brace));
            let mut counter = 0u32;
            walk_compound_list(&bg.list, out, &mut counter, unordered, chain_counter, s);
        }
        ast::CompoundCommand::Subshell(sub) => {
            out.note("subshell");
            let s = scoping.enter(out, crate::syntax::ScopeKind::ProcessBoundary, None);
            let mut counter = 0u32;
            walk_compound_list(&sub.list, out, &mut counter, unordered, chain_counter, s);
        }
        ast::CompoundCommand::ForClause(f) => {
            let s = scoping.enter(out, crate::syntax::ScopeKind::SameProcess, Some(crate::syntax::ScopeClass::LoopBody));
            let mut counter = 0u32;
            walk_compound_list(&f.body.list, out, &mut counter, unordered, chain_counter, s);
        }
        ast::CompoundCommand::CaseClause(c) => {
            for item in &c.cases {
                if let Some(body) = &item.cmd {
                    let s = scoping.enter(out, crate::syntax::ScopeKind::SameProcess, Some(crate::syntax::ScopeClass::BranchBody));
                    let mut counter = 0u32;
                    walk_compound_list(body, out, &mut counter, unordered, chain_counter, s);
                }
            }
        }
        ast::CompoundCommand::IfClause(i) => {
            let cond_scope = scoping.enter(out, crate::syntax::ScopeKind::SameProcess, Some(crate::syntax::ScopeClass::CondList));
            let mut cond_counter = 0u32;
            walk_compound_list(&i.condition, out, &mut cond_counter, unordered, chain_counter, cond_scope);
            let then_scope = scoping.enter(out, crate::syntax::ScopeKind::SameProcess, Some(crate::syntax::ScopeClass::ThenBody));
            let mut then_counter = 0u32;
            walk_compound_list(&i.then, out, &mut then_counter, unordered, chain_counter, then_scope);
            if let Some(elses) = &i.elses {
                for e in elses {
                    if let Some(cond) = &e.condition {
                        let s = scoping.enter(out, crate::syntax::ScopeKind::SameProcess, Some(crate::syntax::ScopeClass::ElifCond));
                        let mut counter = 0u32;
                        walk_compound_list(cond, out, &mut counter, unordered, chain_counter, s);
                    }
                    let s = scoping.enter(out, crate::syntax::ScopeKind::SameProcess, Some(crate::syntax::ScopeClass::BranchBody));
                    let mut counter = 0u32;
                    walk_compound_list(&e.body, out, &mut counter, unordered, chain_counter, s);
                }
            }
        }
        ast::CompoundCommand::WhileClause(w) | ast::CompoundCommand::UntilClause(w) => {
            let cond_scope = scoping.enter(out, crate::syntax::ScopeKind::SameProcess, Some(crate::syntax::ScopeClass::LoopCond));
            let mut cond_counter = 0u32;
            walk_compound_list(&w.0, out, &mut cond_counter, unordered, chain_counter, cond_scope);
            let body_scope = scoping.enter(out, crate::syntax::ScopeKind::SameProcess, Some(crate::syntax::ScopeClass::LoopBody));
            let mut body_counter = 0u32;
            walk_compound_list(&w.1.list, out, &mut body_counter, unordered, chain_counter, body_scope);
        }
        ast::CompoundCommand::Coprocess(c) => {
            out.note("background");
            // A coprocess's standard input is a pipe the shell creates, so the
            // commands inside inherit it — and this arm does not go through the
            // shared body walk, so it blanks its own range. Unconditional: the
            // pipe always exists. `start` is this function's own base and
            // nothing above pushed a command (`note` records a construct), so
            // it is already the right lower bound. The body is not itself an
            // and-or chain member — `chain: None`.
            let s = scoping.enter(out, crate::syntax::ScopeKind::ProcessBoundary, None);
            let mut counter = 0u32;
            walk_command(&c.body, out, &mut counter, unordered, false, None, chain_counter, s);
            blank_inherited_input(out, start..out.commands.len());
        }
        ast::CompoundCommand::Arithmetic(_) | ast::CompoundCommand::ArithmeticForClause(_) => {}
    }
    start..out.commands.len()
}

/// `pipe_input` is true when this command is a pipeline member other than the
/// FIRST — the only members whose standard input is the pipe. The `unordered`
/// flag cannot stand in for it: that is also set for background commands, for
/// the tail after `||`, and for every compound body.
fn walk_simple(
    sc: &ast::SimpleCommand,
    out: &mut Parsed,
    counter: &mut u32,
    unordered: bool,
    pipe_input: bool,
    chain: Option<crate::syntax::ChainPos>,
    chain_counter: &mut u32,
    scope: usize,
) {
    let mut cmd = Cmd::default();
    cmd.chain = chain;
    if let Some(w) = &sc.word_or_name {
        if is_dynamic(&w.value) {
            out.note("dynamic_command");
        }
        // The head is a word like any other, so a simple list there becomes
        // real words: `{echo,hi}` runs `echo hi`. Done BEFORE the prefix and
        // suffix are walked, so the extra words the head produced sit ahead of
        // every argument — which is where they are on the line, and what an
        // argument walk reads.
        match expand_braces(&w.value) {
            Braces::Words(words) => {
                let mut words = words.into_iter();
                let first = words.next().expect("a simple list has at least two alternatives");
                cmd.head = unescape_unquoted(&first);
                for extra in words {
                    cmd.args.push(unescape_unquoted(&extra));
                }
            }
            Braces::Rewritten => {
                out.note(BRACE_EXPANSION);
                cmd.head = unescape_unquoted(&w.value);
            }
            Braces::Literal => cmd.head = unescape_unquoted(&w.value),
        }
    }
    // This command's own here-document records, held here until the command
    // actually lands so they can be stamped with the index it lands AT.
    //
    // Neither a prospective index nor a lazy read at the redirect is right: a
    // process substitution in the prefix/suffix (`cmd <(sub) <<'EOF'`, or the
    // redirect-target spelling) pushes its OWN commands into `out` during this
    // walk, and it can appear either side of the heredoc — so an index
    // captured up front undershoots, and one read at the redirect overshoots
    // or undershoots depending on the order the two happen to be written in.
    // The only value that is always correct is `out.commands.len() - 1` at the
    // push below.
    //
    // Bookkeeping is POSITIONAL, never by index value: a substitution's inner
    // command pushes its own correctly-stamped record during this same walk,
    // and that record's index can EQUAL this command's — so anything that
    // rewrites records by matching a value would clobber it. Records reached
    // through the substitution belong to the inner `walk_simple` frame's own
    // `pending`, never to this one.
    let mut landing = Landing { args_complete: true, ..Landing::default() };
    // Decided once, up front, so the command and every redirect attached to
    // it (walked below) share the same value. Prefix/suffix parsing cannot
    // change `cmd.head`, so deciding this before walking them is safe.
    let order = if unordered {
        Order::Unordered
    } else if !cmd.head.is_empty() {
        let n = *counter;
        *counter += 1;
        Order::Seq(n)
    } else {
        // A bare `> file` with no command word occupies no sequence position
        // of its own, so there is nothing to prove.
        Order::Unordered
    };
    if let Some(prefix) = &sc.prefix {
        walk_items(&prefix.0, out, &mut cmd, false, order.clone(), &mut landing, chain_counter, scope);
    }
    if let Some(suffix) = &sc.suffix {
        walk_items(&suffix.0, out, &mut cmd, true, order.clone(), &mut landing, chain_counter, scope);
    }
    if !cmd.head.is_empty() {
        // `landing.stdin` already carries the correct, final
        // `InputSource::Heredoc(id)` when a pending record claimed
        // descriptor 0 — the id was stamped once, at `alloc_heredoc_id`, and
        // an identity does not shift when the record it names later moves
        // (flushes) to a different position in `out.heredocs`. No rebasing
        // step belongs here; carrying `landing.stdin` through unchanged is
        // the whole point of an identity over a position (M2.127).
        //
        // With no redirect of its own claiming standard input, it comes from
        // outside: the pipe when this is a pipeline member after the first,
        // otherwise nothing. An enclosing construct can still override this to
        // `Unknown` — see `walk_compound`'s range fix-up.
        let source = match landing.stdin {
            Some(other) => other,
            None if pipe_input => crate::syntax::InputSource::Pipe,
            None => crate::syntax::InputSource::Nothing,
        };
        out.push_cmd(
            cmd.head.clone(),
            cmd.args.clone(),
            order,
            source,
            landing.args_complete,
            cmd.chain,
            cmd.prefix_assigns.clone(),
            Some(scope),
        );
        // Stamp and flush: the index this command actually landed at. The
        // heredoc's own identity (`h.id`) was already stamped at capture —
        // carried through here, not assigned.
        let idx = out.commands.len() - 1;
        for h in landing.pending.drain(..) {
            out.heredocs.push(crate::syntax::Heredoc {
                id: h.id,
                body: h.body,
                quoted_delimiter: h.quoted_delimiter,
                cmd_index: idx,
                fd: h.fd,
            });
        }
    }
    // A command that never lands has no consumer to tie a capture to;
    // `walk_items` keeps such a redirect on the construct-note path, so
    // nothing was captured for it.
    debug_assert!(
        landing.pending.is_empty(),
        "a here-document was captured for a command that never landed"
    );
}

/// What a simple command's own prefix and suffix reveal about it, accumulated
/// as the items are walked and read once the command lands.
///
/// One struct rather than three loose out-parameters: they are one concept —
/// the facts being gathered about the command that is landing — and the next
/// per-command fact should not add a parameter at three call levels.
#[derive(Default)]
struct Landing {
    /// This command's own here-document records, held until it lands so they
    /// can be stamped with the CONSUMER index it lands AT. Body, quotedness,
    /// descriptor and identity; the `cmd_index` is the one thing supplied at
    /// the flush — the identity was already stamped at capture and travels
    /// with the record unchanged.
    pending: Vec<PendingHeredoc>,
    /// What its last descriptor-0 redirect says supplies standard input, if any
    /// redirect claimed it. A here-document's own `InputSource::Heredoc`
    /// already carries its final identity when this is set — no rebasing
    /// happens at the flush.
    stdin: Option<crate::syntax::InputSource>,
    /// False once the parser drops an argument the shell will pass.
    args_complete: bool,
}

/// A here-document captured before its consumer's `cmd_index` is known.
///
/// A distinct type rather than a `Heredoc` carrying a placeholder
/// `cmd_index`: `0` is a legitimate command index, so a placeholder would
/// leave nothing to distinguish a stamped record from an unstamped one. Its
/// `id`, unlike `cmd_index`, is already final at construction — see
/// `Scan::alloc_heredoc_id`.
struct PendingHeredoc {
    id: crate::syntax::HeredocId,
    body: String,
    quoted_delimiter: bool,
    fd: i32,
}

/// `is_suffix` distinguishes `dd if=x of=y` (arguments that merely look like
/// assignments) from `PY=x cmd` (environment set for the command).
fn walk_items(
    items: &[ast::CommandPrefixOrSuffixItem],
    out: &mut Parsed,
    cmd: &mut Cmd,
    is_suffix: bool,
    order: Order,
    landing: &mut Landing,
    chain_counter: &mut u32,
    scope: usize,
) {
    for item in items {
        match item {
            ast::CommandPrefixOrSuffixItem::IoRedirect(r) => {
                // A here-document is captured only when a command will land to
                // consume it; otherwise it keeps the construct note.
                let records = (!cmd.head.is_empty()).then_some(&mut landing.pending);
                if let Some(claimed) =
                    walk_redirect(r, out, order.clone(), records, chain_counter, scope, cmd.chain)
                {
                    // The LAST redirect resolving to descriptor 0 wins, which is
                    // the shell's own rule.
                    landing.stdin = Some(claimed);
                }
            }
            ast::CommandPrefixOrSuffixItem::ProcessSubstitution(_, s) => {
                out.note("subshell");
                // The shell passes this command the substitution's own pathname
                // as a positional argument — for an interpreter, the script that
                // runs — but the parser pushes no token for it. So the recorded
                // argument list is NOT a faithful record of what will be passed,
                // and anything reading those tokens has to know that.
                landing.args_complete = false;
                // The substitution's inner commands run in their OWN forked
                // process, whichever argument or redirect position spells it —
                // anchored at the ENCLOSING command's own pre-captured position,
                // never at the substitution's own (there isn't one: it is not a
                // pipeline/chain member of its own).
                let sub_scope = alloc_scope(
                    out,
                    scope,
                    crate::syntax::ScopeKind::ProcessBoundary,
                    None,
                    order.clone(),
                    cmd.chain,
                );
                let mut counter = 0u32;
                walk_compound_list(&s.list, out, &mut counter, false, chain_counter, sub_scope);
            }
            // A command substitution runs a command in a subshell, whether it
            // appears as an argument or on the right of an assignment. Both count.
            ast::CommandPrefixOrSuffixItem::Word(w) => {
                if has_command_substitution(&w.value) {
                    out.note("subshell");
                }
                push_word(out, cmd, &w.value);
            }
            ast::CommandPrefixOrSuffixItem::AssignmentWord(_, w) => {
                if has_command_substitution(&w.value) {
                    out.note("subshell");
                }
                if is_suffix {
                    // An assignment-shaped word AFTER the command name is an
                    // argument, and bash brace-expands it (`of={a,b}` becomes
                    // two arguments — probed). The recorded VALUE below is a
                    // different question and is left alone: a PREFIX
                    // assignment does not brace-expand at all.
                    push_word(out, cmd, &w.value);
                }
                // `f="C:/…/x.output"` followed by `> "$f"`: record the value so
                // the redirect target can be resolved.
                if let Some((name, value)) = w.value.split_once('=') {
                    if !name.is_empty()
                        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                    {
                        // A PREFIX assignment's own name is recorded regardless
                        // of whether its value is readable — this one
                        // invocation ran with this name set, even when what it
                        // was set TO is unknowable (T18 reads this).
                        if !is_suffix {
                            cmd.prefix_assigns.push(name.to_string());
                        }
                        // A value built by command substitution is genuinely
                        // not knowable in advance — recorded POISONED (`None`)
                        // rather than skipped, so a name whose LAST write is
                        // poisoned reads as unresolvable at resolution time
                        // instead of silently falling through to a lookup the
                        // shell never actually performed (M2.122).
                        let recorded = if has_command_substitution(&w.value) {
                            None
                        } else {
                            let unescaped = unescape_unquoted(value);
                            Some(crate::paths::unquote(&unescaped).to_string())
                        };
                        out.assignments.push((name.to_string(), recorded));
                    }
                }
            }
        }
    }
}

/// Record one argument word, letting brace expansion have its say first.
///
/// The RAW text is what arrives here, and that is the whole point:
/// `unescape_unquoted` erases the backslash that tells `{a\,b,c}` (two
/// alternatives) from `{a,b,c}` (three), so a detector past this push cannot
/// tell them apart. A simple list becomes the several words the shell really
/// passes; anything else records exactly as today, with the construct beside
/// it so the rewrite vouch did not reproduce is not silent.
fn push_word(out: &mut Parsed, cmd: &mut Cmd, raw: &str) {
    match expand_braces(raw) {
        Braces::Words(words) => {
            for w in words {
                cmd.args.push(unescape_unquoted(&w));
            }
        }
        Braces::Rewritten => {
            out.note(BRACE_EXPANSION);
            cmd.args.push(unescape_unquoted(raw));
        }
        Braces::Literal => cmd.args.push(unescape_unquoted(raw)),
    }
}

/// A redirect target is CLASSIFIED but never expanded.
///
/// The first draft left these alone on the rationale that bash refuses a
/// multi-word redirect as ambiguous, so nothing could hide in one. That
/// rationale was disproved by probe: a group collapsing to exactly ONE word
/// redirects perfectly well — `echo x > f{7..7}.txt` wrote `f7.txt` and
/// `echo y > {a,}` wrote `a`. The recorded target would then not be the path
/// written, and that path feeds the write rules and the protected list.
///
/// So both non-literal answers get the same treatment here, and it is the
/// construct rather than an expansion: more than one word is a shell error
/// anyway, and exactly one word is a target vouch cannot name.
fn note_target_braces(out: &mut Parsed, raw: &str) {
    if !matches!(expand_braces(raw), Braces::Literal) {
        out.note(BRACE_EXPANSION);
    }
}

/// `<<-` strips leading TAB characters (not spaces, and not from the middle
/// of a line) from every line of the body — the parser keeps them in the AST
/// (`IoHereDocument::doc`) rather than removing them itself, so text prep has
/// to do it before the body is treated as the consumer's real input.
fn strip_leading_tabs(body: &str) -> String {
    let mut out = String::with_capacity(body.len());
    for (i, line) in body.split('\n').enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(line.trim_start_matches('\t'));
    }
    out
}

/// `order` is the order of the command this redirect is attached to — the
/// interface's whole point is that a redirect never gets to claim a position
/// its own command couldn't prove.
///
/// `pending` is `Some(the consuming command's record list)` when the command
/// this redirect is attached to has a non-empty head, `None` when it does not
/// (a bare `<<EOF` with no command word, a compound body's own redirects, an
/// extended-test expression's) — a here-document in that shape has no consumer
/// to tie its capture to, so it keeps today's construct note instead. The
/// option is what selects between the two, so it must stay an option: handing
/// every caller a throwaway vector would silently swallow those records and
/// lose the note with them.
///
/// RETURNS what this one redirect says about standard input, `None` when it
/// says nothing. The caller folds — a returned value beats an out-parameter
/// here because two of the three call sites have no use for the answer and
/// would otherwise each need a throwaway local.
fn walk_redirect(
    r: &ast::IoRedirect,
    out: &mut Parsed,
    order: Order,
    pending: Option<&mut Vec<PendingHeredoc>>,
    chain_counter: &mut u32,
    scope: usize,
    chain: Option<crate::syntax::ChainPos>,
) -> Option<crate::syntax::InputSource> {
    use crate::syntax::InputSource;
    let mut claims_stdin = None;
    match r {
        ast::IoRedirect::File(fd, kind, target) => {
            // Two independent questions about the same operator, deliberately
            // not one boolean: whether it can CREATE the file (which decides
            // whether the target is recorded as a write) and which descriptor it
            // replaces by default. `<>` answers yes to the first and 0 to the
            // second, so a single flag cannot serve both.
            let creates = matches!(
                kind,
                ast::IoFileRedirectKind::Write
                    | ast::IoFileRedirectKind::Append
                    | ast::IoFileRedirectKind::Clobber
                    | ast::IoFileRedirectKind::DuplicateOutput
                    | ast::IoFileRedirectKind::ReadAndWrite
            );
            let default_fd = match kind {
                ast::IoFileRedirectKind::Write
                | ast::IoFileRedirectKind::Append
                | ast::IoFileRedirectKind::Clobber
                | ast::IoFileRedirectKind::DuplicateOutput => 1,
                // Read, ReadAndWrite and DuplicateInput all default to 0.
                _ => 0,
            };
            // The descriptor is read BEFORE the create-or-not split below,
            // because that split returns early for a plain read redirect and
            // `< f` is exactly the shape the input source needs most.
            if fd.unwrap_or(default_fd) == 0 {
                claims_stdin = Some(match target {
                    ast::IoFileRedirectTarget::Filename(_) => InputSource::File,
                    // A process substitution, a duplication and a close all
                    // hand over a stream rather than a named file. The parser
                    // delivers `<&3` and `<&-` alike as duplications, and its
                    // bare-descriptor target shape is never produced from
                    // written text — so every descriptor-shaped target is a
                    // stream, and no `File` case is invented for one.
                    _ => InputSource::Stream,
                });
            }
            match target {
                ast::IoFileRedirectTarget::Filename(w) => {
                    note_target_braces(out, &w.value);
                    // `<` READS the file. Recording it as a written path made
                    // `wc -l < hosts` prompt about writing a file it only reads
                    // — and that fired on real traffic, not just in a probe.
                    if creates {
                        if is_dynamic(&w.value) {
                            out.note("dynamic_redirect");
                        }
                        out.redirect_targets.push(unescape_unquoted(&w.value));
                        out.redirect_order.push(order);
                        out.redirect_scope.push(Some(scope));
                        out.redirect_chain.push(chain);
                    }
                }
                ast::IoFileRedirectTarget::ProcessSubstitution(_, s) => {
                    out.note("subshell");
                    // Same anchoring as the argument-position spelling in
                    // `walk_items`: the substitution's inner commands run in
                    // their OWN forked process, anchored at the ENCLOSING
                    // command's own pre-captured position, never at the
                    // redirect's own (a redirect is not a pipeline/chain
                    // member of its own).
                    let sub_scope = alloc_scope(
                        out,
                        scope,
                        crate::syntax::ScopeKind::ProcessBoundary,
                        None,
                        order.clone(),
                        chain,
                    );
                    let mut counter = 0u32;
                    walk_compound_list(&s.list, out, &mut counter, false, chain_counter, sub_scope);
                }
                // `>&word` duplicates a descriptor only when the word IS a
                // descriptor — a number, or `-` for close. With a NAME there
                // it is bash's own spelling for "send both streams to this
                // file", and it creates that file: verified by running
                // `echo <text> >& marker.txt`, which wrote the file. Recorded
                // as the write it is; without this the spelling reached even a
                // protected path, which CLAUDE.md 5 says no rule can open.
                ast::IoFileRedirectTarget::Duplicate(w) => {
                    note_target_braces(out, &w.value);
                    let v = unescape_unquoted(&w.value);
                    let names_a_descriptor =
                        v == "-" || (!v.is_empty() && v.chars().all(|c| c.is_ascii_digit()));
                    if creates && !names_a_descriptor {
                        if is_dynamic(&w.value) {
                            out.note("dynamic_redirect");
                        }
                        out.redirect_targets.push(v);
                        out.redirect_order.push(order);
                        out.redirect_scope.push(Some(scope));
                        out.redirect_chain.push(chain);
                    }
                }
                ast::IoFileRedirectTarget::Fd(_) => {}
            }
        }
        // A here-document is captured — tied to its consuming command — so a
        // locator can later decide whether that command actually reads it
        // (`guards::heredoc_feeds`). A here-string (`<<<`) is out of the
        // locator's scope and keeps the plain construct note unchanged.
        ast::IoRedirect::HereDocument(fd, doc) => match pending {
            Some(records) => {
                let body = if doc.remove_tabs {
                    strip_leading_tabs(&doc.doc.value)
                } else {
                    doc.doc.value.clone()
                };
                // `<<` defaults to descriptor 0; `3<< TAG` feeds descriptor 3
                // and never reaches standard input.
                let resolved = fd.unwrap_or(0);
                // Stamped here, once, from the owning scan's own counter — the
                // record's identity for as long as it exists, independent of
                // when this pending list flushes into `out.heredocs` relative
                // to any nested construct's own flush (`HeredocId`'s doc). No
                // rebasing step exists downstream any more; this is the value
                // every reader will compare against.
                let id = out.alloc_heredoc_id();
                if resolved == 0 {
                    claims_stdin = Some(InputSource::Heredoc(id));
                }
                records.push(PendingHeredoc {
                    id,
                    body,
                    // The parser itself decides quotedness — a quoted tag
                    // (`<<'EOF'`) or a backslash-escaped one both set
                    // `requires_expansion = false`; deriving it again from the
                    // delimiter TEXT here would miss the escaped-tag spelling.
                    quoted_delimiter: !doc.requires_expansion,
                    fd: resolved,
                });
            }
            None => out.note("heredoc"),
        },
        // A here-string supplies descriptor 0 too, but produces no record for a
        // locator to consume — so it is a stream, never a `Heredoc(i)` pointing
        // into a list that holds nothing for it.
        ast::IoRedirect::HereString(fd, _) => {
            if fd.unwrap_or(0) == 0 {
                claims_stdin = Some(InputSource::Stream);
            }
            out.note("heredoc");
        }
        // Its own grammar variant, with no descriptor slot at all: it sets
        // descriptors 1 and 2 and never standard input, so nothing is read for
        // it and it claims nothing.
        ast::IoRedirect::OutputAndError(w, _) => {
            note_target_braces(out, &w.value);
            if is_dynamic(&w.value) {
                out.note("dynamic_redirect");
            }
            out.redirect_targets.push(unescape_unquoted(&w.value));
            out.redirect_order.push(order);
            out.redirect_scope.push(Some(scope));
            out.redirect_chain.push(chain);
        }
    }
    claims_stdin
}

/// The bash scanner.
pub struct Bash;

impl crate::syntax::Scanner for Bash {
    fn lang(&self) -> &'static str {
        "bash"
    }
    fn scan(&self, src: &str) -> Result<crate::syntax::Scan, String> {
        parse(src)
    }
    fn known_constructs(&self) -> &'static [&'static str] {
        &[
            "dynamic_command",
            "dynamic_redirect",
            "subshell",
            "background",
            "heredoc",
            "function_def",
            "parse_failure",
            "unmodeled_command",
            // Emitted by the engine rather than the scanner, but settable in
            // exactly the same way, so they belong on the same list.
            "unresolved_path",
            "evaluated_input",
            "wrap_depth_exceeded",
            "wrap_unlocated",
            "wrap_ambiguous",
            "unreadable_language",
            "unread_verb",
            // Raised for the command a channel-fed wrapper runs, whose
            // arguments the line never states.
            "args_from_input",
            // The shell half of a construct that was python-only until M2.120:
            // an assignment to a name the shell reads when it looks a program
            // name up leaves the described name meaning something else.
            "rebound_name",
            // The shell will rewrite this token into words vouch did not
            // reproduce — a range, a nest, several groups, or alternatives
            // carrying quoting, escaping or expansion.
            BRACE_EXPANSION,
        ]
    }
}
