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

/// `\`-newline is deleted by bash before any expansion — inside double quotes
/// and inside an unquoted here-document body alike — so a substitution whose
/// opener is split across a continuation still runs (probed: a body holding
/// `$`, `\`, newline, `(touch M)` creates M). Every reader of raw text below
/// starts from this, or the text pre-filter would miss what bash runs.
pub fn strip_line_continuations(raw: &str) -> std::borrow::Cow<'_, str> {
    if raw.contains("\\\n") {
        std::borrow::Cow::Owned(raw.replace("\\\n", ""))
    } else {
        std::borrow::Cow::Borrowed(raw)
    }
}

/// See the struct's field docs; the rules are the design's §2.1.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Bodies {
    /// One entry per `$(…)` or backtick body, outermost only: a body's own
    /// nested substitutions are found by the walk over that body, never here.
    pub bodies: Vec<String>,
    /// True when the text plainly holds a substitution vouch could not
    /// delimit: the word failed to parse, or a literal piece still carries
    /// `$(` or a backtick after parsing. The scan (`scan`, below) returns at
    /// the first unreadable opener it meets — any bodies already found stay
    /// in `bodies`, but a second, perfectly readable substitution later in
    /// the same text is never reached and is silently dropped from `bodies`.
    /// Deliberately fail-closed: the engine notes `parse_failure` for the
    /// whole word rather than reporting a partial reading as though it were
    /// complete.
    pub unreadable: bool,
}

/// Which characters carry structure in the text the scan is walking. WORD
/// mode is a word's own raw text, read with the quoting the shell applies to
/// a command line. HERE-DOCUMENT mode is the body of an unquoted
/// here-document, where `'` and `"` are ordinary characters and bash honours
/// only four escapes. The extent of a `$( … )` found in EITHER is read in
/// WORD mode, because a substitution's content is shell (design §2.1 step 3).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Word,
    Heredoc,
}

/// The substitution bodies a word's raw text runs, delimited by vouch's own
/// scan — `$((1+2))` is arithmetic, `'$(x)'` is literal, `${a[$(x)]}` runs
/// `x`. Outermost bodies only: nesting is the walk's business, and it finds
/// an inner body by visiting the outer body's own words.
pub fn substitution_bodies(raw: &str) -> Bodies {
    bodies_via(raw, Mode::Word)
}

/// The substitution bodies an unquoted here-document body runs. Shares its
/// whole pipeline with `substitution_bodies` through `bodies_via` — the mode
/// is the only thing that differs, so nothing else about the two readings can
/// silently diverge.
pub fn heredoc_substitution_bodies(body: &str) -> Bodies {
    bodies_via(body, Mode::Heredoc)
}

/// Strip line continuations, pre-filter by text, then scan — the whole
/// pipeline `substitution_bodies` and `heredoc_substitution_bodies` share.
fn bodies_via(raw: &str, mode: Mode) -> Bodies {
    let text = strip_line_continuations(raw);
    let mut out = Bodies::default();
    if !has_command_substitution(&text) {
        return out;
    }
    scan(&text, mode, &mut out);
    out
}

/// One flat pass over already-stripped text, emitting one body per OUTERMOST
/// substitution and noting `unreadable` for one whose end vouch could not
/// find (design §2.1 steps 3 and 4).
///
/// Deliberately not `brush_parser::word::parse`: brush's `command()` rule is
/// not here-document aware, so an apostrophe or a backtick in the prose of
/// `$(cat <<'EOF' … EOF)` opens a quoted piece that swallows parentheses —
/// the substitution's closer is re-paired, the real body is truncated or
/// lost, and every markdown backtick pair becomes a body of its own. That is
/// the shape a commit message is written in, so it is not a rare one.
///
/// A flat scan also needs no structural reading of a parameter expansion:
/// bash expands a `$(` wherever it stands outside single quotes, and so does
/// this, which is why `${x:-$(a)}` and `${a[$(x)]}` need no arm of their own.
fn scan(text: &str, mode: Mode, out: &mut Bodies) {
    let cs: Vec<(usize, char)> = text.char_indices().collect();
    let mut quoting = Quoting::default();
    let mut memo = Memo::new();
    let mut i = 0;
    while i < cs.len() {
        if mode == Mode::Word {
            // `step_expanding` rather than `step`: double quotes leave a
            // substitution live, so the two characters that can open one have
            // to reach the match below from inside them as well as outside.
            if let Some(next) = quoting.step_expanding(&cs, i) {
                i = next;
                continue;
            }
        } else if cs[i].1 == '\\' {
            // bash's escape set inside an unquoted here-document body: these
            // four and nothing else, so every other backslash is text. The
            // newline can no longer be reached — `strip_line_continuations`
            // ran first — and is named so the set reads as bash's own.
            i += match cs.get(i + 1).map(|&(_, c)| c) {
                Some('$' | '`' | '\\' | '\n') => 2,
                _ => 1,
            };
            continue;
        }
        match cs[i].1 {
            '$' if cs.get(i + 1).is_some_and(|&(_, n)| n == '(') => {
                match substitution_at(&cs, text, i, out, &mut memo) {
                    Some(next) => i = next,
                    None => {
                        out.unreadable = true;
                        return;
                    }
                }
            }
            '`' => match skip_backquotes(&cs, i) {
                Some(next) => {
                    out.bodies
                        .push(collapse_backquote_escapes(&text[cs[i].0 + 1..cs[next - 1].0]));
                    i = next;
                }
                None => {
                    out.unreadable = true;
                    return;
                }
            },
            _ => i += 1,
        }
    }
}

/// What one `$( … )` turns out to be. `Arithmetic` carries the text between
/// the two inner parentheses, which runs no command of its own; `Body` carries
/// the command text the substitution runs.
#[derive(Clone, Copy)]
enum Reading<'t> {
    Arithmetic(&'t str),
    Body(&'t str),
}

/// Every `$(` opener one scan of one text has already resolved, keyed on the
/// index of its `$`.
///
/// It is not an optimisation, it is the bound on the work. `read_substitution`
/// may run TWO walks over the same text — the arithmetic probe and the real
/// one — and each walk resolves every nested opener it meets, so without a
/// memo each `$((`-shaped level doubles everything below it: forty levels of
/// `$((echo a); …)` costs 2^41 walks. That is not a contrived input. An
/// unquoted here-document's RAW body reaches this reader
/// (`heredoc_substitution_bodies`), so `cat <<EOF` and thirty openers is an
/// ordinary command line, and the cost would land inside a PreToolUse hook.
/// The nesting cap in `read_substitution` is the other half of the answer;
/// this half keeps the levels that ARE resolved to one walk each.
///
/// The index alone is a sound key for ONE walk: openers nest strictly, so a
/// given opener has exactly one enclosing chain within it. It is not sound
/// ACROSS the two walks a `$((`-shaped opener can run: a here-document
/// region the with-skip walk steps over as data can still be traversed by
/// the no-skip arithmetic probe, so the same `$` index can be reached at two
/// different depths depending on which walk gets there first. That order is
/// fixed, not merely possible either way: `delimit_substitution` always runs
/// the no-skip probe FIRST, and the no-skip probe is the one walk that can
/// descend into here-document-hidden openers — so whenever the two walks
/// diverge on an index, the no-skip probe is the one that reaches it, caches
/// it, and the later with-skip lookup reuses that cached reading. The cached
/// reading is therefore always the DEEPER of the two, which is harmless: the
/// shallower walk only inherits a MORE conservative (fail-closed) answer
/// than its own depth would have computed, never a more permissive one.
type Memo<'t> = std::collections::HashMap<usize, Option<(Reading<'t>, usize)>>;

/// Read the `$(` at `dollar` the one way the whole reader reads one, and say
/// where it ends. `None` when it never closes, or when it sits deeper than the
/// nesting cap.
///
/// `depth` is how many substitutions enclose this one, so a top-level opener
/// is 0. At `SUBSTITUTION_DEPTH_CAP` the opener is not resolved at all and the
/// enclosing extent is refused, which the reader reports as `unreadable` and
/// the engine as `parse_failure` — fail-closed, but not lossless: refusing an
/// opener this deep also makes every extent that ENCLOSES it unreadable, all
/// the way up to whichever call first receives the `None`, so a nest nine
/// deep drops the enclosing body's own shallower content too, not only the
/// one construct `walk_substitution_body`'s own depth check already refuses
/// to walk. Refusing HERE is what bounds the cost: that check runs after
/// this reader has returned.
///
/// One function rather than two so that the reading `extent` jumps over and
/// the reading `substitution_at` emits can never disagree.
fn read_substitution<'t>(
    cs: &[(usize, char)],
    text: &'t str,
    dollar: usize,
    depth: usize,
    memo: &mut Memo<'t>,
) -> Option<(Reading<'t>, usize)> {
    if depth >= SUBSTITUTION_DEPTH_CAP {
        return None;
    }
    if let Some(&cached) = memo.get(&dollar) {
        return cached;
    }
    let read = delimit_substitution(cs, text, dollar, depth, memo);
    memo.insert(dollar, read);
    read
}

/// `read_substitution` without the cap and the memo — the reading itself.
///
/// The arithmetic question is answered FIRST, and on the extent read WITHOUT
/// the here-document pass: an arithmetic reading never looks for a delimiter,
/// so the `<<` in `$(( x << 2 ))` is a shift (design §2.1 step 3). A
/// here-document reading of that text would go looking for a body terminated
/// by `2` and run off the end. Only a `$((` can be arithmetic, so that first
/// walk is skipped entirely unless the character after the opener is `(` —
/// which is exactly `arithmetic_inside`'s own first condition, and which keeps
/// an ordinary substitution to a single walk.
fn delimit_substitution<'t>(
    cs: &[(usize, char)],
    text: &'t str,
    dollar: usize,
    depth: usize,
    memo: &mut Memo<'t>,
) -> Option<(Reading<'t>, usize)> {
    if cs.get(dollar + 2).is_some_and(|&(_, c)| c == '(') {
        if let Some((span, after)) = extent(cs, text, dollar, false, depth, memo) {
            if let Some(inner) = arithmetic_inside(span) {
                return Some((Reading::Arithmetic(inner), after));
            }
        }
    }
    // Not arithmetic, so the body is the extent read WITH here-document
    // content skipped as data. That is the only reading that survives an
    // apostrophe, a backtick or an unbalanced parenthesis in the prose of a
    // here-document, and it is what bash does.
    let (span, after) = extent(cs, text, dollar, true, depth, memo)?;
    Some((Reading::Body(span), after))
}

/// One `$(` at `dollar`: emit its body, or recurse into it as arithmetic, and
/// answer where the scan continues. `None` when it never closes — the text
/// plainly holds a substitution whose edges vouch could not find.
fn substitution_at<'t>(
    cs: &[(usize, char)],
    text: &'t str,
    dollar: usize,
    out: &mut Bodies,
    memo: &mut Memo<'t>,
) -> Option<usize> {
    // A substitution the top-level scan meets has nothing enclosing it.
    let (reading, after) = read_substitution(cs, text, dollar, 0, memo)?;
    match reading {
        // Arithmetic runs no command of its own — and an arithmetic syntax
        // error at runtime runs nothing, so `$((touch M))` walks nothing —
        // but a substitution written inside it runs first.
        Reading::Arithmetic(inner) => {
            if has_command_substitution(inner) {
                scan(inner, Mode::Word, out);
            }
        }
        Reading::Body(span) => out.bodies.push(span.to_string()),
    }
    Some(after)
}

/// The inside of `$(( … ))` when this extent is arithmetic rather than a
/// command substitution: the span begins with `(`, ends with `)`, and what
/// lies between balances. Balance is the test because bash counts
/// parentheses — `$((echo a); (touch M))` really does run a subshell, and
/// `$((touch M))` is an arithmetic syntax error that runs nothing (both
/// probed). Arithmetic VALIDITY is deliberately not the test: it would refuse
/// `touch M` and send a spelling bash never runs to the guard.
fn arithmetic_inside(span: &str) -> Option<&str> {
    let inner = span.strip_prefix('(')?.strip_suffix(')')?;
    parens_balance(inner).then_some(inner)
}

/// The text between a `$(` at `dollar` and its depth-matched `)`, plus the
/// position just past that `)`.
///
/// What the walk counts as this substitution's own structure, and what it
/// steps over whole:
///   * Parentheses are counted outside quotes, with WORD-mode quoting applied
///     to the content whatever mode the scan itself is in, because a
///     substitution's content is shell.
///   * A NESTED substitution — `$( … )` or a backquoted one — is opaque: its
///     own extent is found first and the walk resumes past its closer, so
///     nothing written inside it reaches this level's paren count OR this
///     level's quote state. That is how bash reads it, and it is what makes
///     `$(echo "$(echo "a)")")` come out whole: the inner `"` pair belongs to
///     the inner substitution, and letting it flip the outer parity ended the
///     extent five characters early.
///   * A comment runs from a word-initial `#` to the end of its line, so a
///     `)` written in one closes nothing.
///   * Inside a `case` statement a `)` at this level's own depth terminates a
///     pattern rather than the substitution.
///   * With `skip_docs`, each `<<`/`<<-` operator's delimiter is read and that
///     here-document's lines are skipped as data — bash's own reading, and the
///     one the arithmetic test in `read_substitution` must not have.
///
/// `nesting` is how many substitutions enclose the one being delimited, and it
/// is passed on one deeper to every nested opener; `memo` is the per-scan
/// resolution cache both halves of `read_substitution`'s cost bound live in.
///
/// `None` when no depth-zero `)` arrives — including when the text ends inside
/// a comment, an unclosed nested substitution or an unclosed `case`, or when a
/// nested opener sits past the nesting cap — or before a here-document's
/// terminator.
fn extent<'t>(
    cs: &[(usize, char)],
    text: &'t str,
    dollar: usize,
    skip_docs: bool,
    nesting: usize,
    memo: &mut Memo<'t>,
) -> Option<(&'t str, usize)> {
    let content = dollar + 2;
    let start = cs.get(content)?.0;
    let mut depth = 0usize;
    let mut quoting = Quoting::default();
    // The index just past the most recent nested substitution's closer. That
    // `)` is INSIDE a word, unlike the `)` that ends a subshell, so it does not
    // end the word before a `#` — see `starts_comment`.
    let mut after_nested: Option<usize> = None;
    // The delimiters declared on the line being read, in the order they were
    // written: bash consumes their bodies in that order at the next newline.
    let mut pending: Vec<(String, bool)> = Vec::new();
    // How many `case` statements are open at this level. A COUNT rather than a
    // flag because a `case` nested in a `case` arm ends at its own `esac`, and
    // reading that inner `esac` as the end of both would hand the outer
    // statement's next pattern `)` back to the paren count.
    let mut cases = 0usize;
    let mut i = dollar + 1;
    while i < cs.len() {
        // `step_expanding`, not `step`: double quotes leave a nested
        // substitution live, and the arm below has to see the character that
        // opens one from inside them.
        if let Some(next) = quoting.step_expanding(cs, i) {
            i = next;
            continue;
        }
        match cs[i].1 {
            '$' if cs.get(i + 1).is_some_and(|&(_, c)| c == '(') => {
                i = read_substitution(cs, text, i, nesting + 1, memo)?.1;
                after_nested = Some(i);
                continue;
            }
            '`' => {
                i = skip_backquotes(cs, i)?;
                continue;
            }
            '(' => depth += 1,
            ')' => {
                // A pattern's terminator, not this substitution's closer. A
                // `)` deeper than this level is the mate of a `(` the walk
                // counted, which is the `(a)` pattern spelling as well as any
                // ordinary subshell.
                if cases > 0 && depth == 1 {
                    i += 1;
                    continue;
                }
                depth -= 1;
                if depth == 0 {
                    return Some((&text[start..cs[i].0], i + 1));
                }
            }
            // bash parses a substitution's content with its full parser, so a
            // `#` where a word can start runs a comment to the end of the
            // line and a `)` written in that comment closes nothing. BOTH
            // walks need it: an arithmetic `$(( … ))` cannot hold a comment,
            // but the no-skip extent of a body that is not arithmetic must
            // not be cut short by one either. Running out of text inside a
            // comment leaves the substitution unclosed, which is the `None`
            // below. A backquoted body is deliberately unlike this: bash
            // finds its closing backquote character-first, so a `#` inside
            // one protects nothing and `skip_backquotes` stays as it is.
            '#' if starts_comment(cs, i, after_nested) => {
                while i < cs.len() && cs[i].1 != '\n' {
                    i += 1;
                }
                continue;
            }
            // `case` takes a word, so bash requires a blank after it; `esac`
            // ends a command and may be followed by anything that ends one,
            // `)` included. Both count only at command position — `grep case
            // file` passes `case` as an argument and opens nothing.
            'c' if word_at(cs, i, "case", true) && at_command_position(cs, i, content) => {
                cases += 1;
                i += "case".chars().count();
                continue;
            }
            'e' if word_at(cs, i, "esac", false) && at_command_position(cs, i, content) => {
                cases = cases.saturating_sub(1);
                i += "esac".chars().count();
                continue;
            }
            '<' if skip_docs && is_heredoc_operator(cs, i) => {
                let (delim, strip_tabs, next) = heredoc_delimiter(cs, i);
                // An operator with no delimiter after it introduces no
                // here-document; the `<` is then ordinary text.
                if !delim.is_empty() {
                    pending.push((delim, strip_tabs));
                    i = next;
                    continue;
                }
            }
            '\n' if !pending.is_empty() => {
                i = skip_heredoc_bodies(cs, i + 1, &mut pending)?;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// A `#` that BEGINS A WORD, which is where the shell starts a comment. So the
/// set below is what a word can follow: whitespace or a newline, and the
/// operators `(`, `)`, `;`, `|`, `&`, each of which ends the word before it.
/// `a#b` is one word carrying a hash, and a `#` inside quotes is text — the
/// quoting step in `extent` consumed that one before this is asked.
///
/// `)` is in the set and needs `after_nested` to earn it, because two
/// different parentheses are spelled the same way. The `)` that ends a
/// SUBSHELL is an operator and does end the word before it, so `$( (echo
/// a)#x )` really is a comment — and the comment then swallows the `)` a
/// reader would otherwise close the substitution on. The `)` that closes a
/// nested `$( … )` or `$(( … ))` is INSIDE a word, so `$(echo $(echo a)#x)`
/// runs `echo` with the single argument `a#x`. `after_nested` is the one index
/// where the walk knows it just passed the second kind, which is exactly the
/// `after` that `read_substitution` returned.
///
/// The reference is zsh 5.9. macOS's bash 3.2 is known-deficient for command
/// substitutions and is not the reference: its reader honours only a blank, a
/// newline or the start of the substitution before a `#`.
///
/// The set is `ends_word` MINUS `<` and `>`, and the two that come out are the
/// redirection operators. They do end the word before them, but what follows
/// one is a redirect TARGET, and bash reads a `#` there as the first character
/// of a filename rather than as a comment — `echo >#x` redirects into a file
/// named `#x` (probed). Every other word-ending character really does put the
/// next `#` where a comment can start.
fn starts_comment(cs: &[(usize, char)], i: usize, after_nested: Option<usize>) -> bool {
    if after_nested == Some(i) {
        return false;
    }
    if i == 0 {
        return true;
    }
    let before = cs[i - 1].1;
    ends_word(before) && !matches!(before, '<' | '>')
}

/// The characters that END A WORD in the reader's own scan: blanks and a
/// newline, the list and pipeline operators, the two parentheses, and the two
/// redirection operators.
///
/// One set, because the two questions asked of it are the same question. A
/// keyword only counts as one when the next character ends the word
/// (`word_at`), and a bare here-document delimiter runs until the first
/// character that ends the word (`heredoc_delimiter`) — so `<<EOF)` and
/// `esac)` have to agree about `)`, and two hand-written copies could only
/// drift.
fn ends_word(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | ';' | '|' | '&' | '(' | ')' | '<' | '>')
}

/// The exact word `w` at `i`, ended by something that ends a word rather than
/// running on into a longer one. `blank_after` is bash's own difference
/// between the two keywords this is asked about: `case` takes a word, so a
/// blank must follow it, while `esac` ends a command and may be followed by
/// anything that ends one — `esac)` closes a substitution on the same line.
fn word_at(cs: &[(usize, char)], i: usize, w: &str, blank_after: bool) -> bool {
    if !w.chars().enumerate().all(|(k, c)| cs.get(i + k).is_some_and(|&(_, got)| got == c)) {
        return false;
    }
    match cs.get(i + w.chars().count()).map(|&(_, c)| c) {
        None => !blank_after,
        Some(c) if blank_after => matches!(c, ' ' | '\t' | '\n'),
        Some(c) => ends_word(c),
    }
}

/// Whether a word starting at `i` stands where a COMMAND starts rather than
/// where an argument does: at the beginning of the substitution's content, or
/// after `;`, `|`, `&`, `(`, `{` or a newline, with spaces and tabs skipped
/// back over. `;;` is covered by `;`. This is what separates the keyword
/// `case` from the argument in `grep case file`.
fn at_command_position(cs: &[(usize, char)], i: usize, content: usize) -> bool {
    let mut j = i;
    while j > content && matches!(cs[j - 1].1, ' ' | '\t') {
        j -= 1;
    }
    j == content || matches!(cs[j - 1].1, ';' | '|' | '&' | '(' | '{' | '\n')
}

/// A `<<` that really introduces a here-document: two of them and not three
/// (`<<<` is a here-string, whose word is not a delimiter), and not the
/// second `<` of a pair the walk has already read.
fn is_heredoc_operator(cs: &[(usize, char)], i: usize) -> bool {
    cs.get(i + 1).is_some_and(|&(_, c)| c == '<')
        && !cs.get(i + 2).is_some_and(|&(_, c)| c == '<')
        && !(i > 0 && cs[i - 1].1 == '<')
}

/// Read a here-document operator's delimiter, starting at its first `<`.
/// `<<-` strips leading tabs from the body lines and from the terminator;
/// spaces and tabs before the delimiter are skipped; a quoted delimiter runs
/// to its matching quote, and a bare one to the first character that ends a
/// word, with backslashes removed. Returns the delimiter, whether tabs are
/// stripped, and the position just past it.
///
/// Which quote the delimiter carried is not recorded, because this reader
/// does not expand a here-document's content: it only needs to know where the
/// content ENDS, and the terminator is the same either way.
fn heredoc_delimiter(cs: &[(usize, char)], op: usize) -> (String, bool, usize) {
    let mut i = op + 2;
    let strip_tabs = cs.get(i).is_some_and(|&(_, c)| c == '-');
    if strip_tabs {
        i += 1;
    }
    while cs.get(i).is_some_and(|&(_, c)| c == ' ' || c == '\t') {
        i += 1;
    }
    let mut delim = String::new();
    match cs.get(i).map(|&(_, c)| c) {
        Some(quote @ ('\'' | '"')) => {
            i += 1;
            while i < cs.len() {
                let c = cs[i].1;
                i += 1;
                if c == quote {
                    break;
                }
                delim.push(c);
            }
        }
        _ => {
            while let Some(&(_, c)) = cs.get(i) {
                if ends_word(c) {
                    break;
                }
                i += 1;
                if c == '\\' {
                    if let Some(&(_, escaped)) = cs.get(i) {
                        delim.push(escaped);
                        i += 1;
                    }
                    continue;
                }
                delim.push(c);
            }
        }
    }
    (delim, strip_tabs, i)
}

/// From the first character after the operator line's newline, skip each
/// pending here-document's lines up to and including its terminator, in the
/// order the operators were written. `None` when the text ends before a
/// terminator arrives: the body cannot be delimited, so the scan says so
/// rather than guessing where the content stopped.
fn skip_heredoc_bodies(
    cs: &[(usize, char)],
    from: usize,
    pending: &mut Vec<(String, bool)>,
) -> Option<usize> {
    let mut i = from;
    for (delim, strip_tabs) in pending.drain(..) {
        loop {
            if i >= cs.len() {
                return None;
            }
            let start = i;
            while i < cs.len() && cs[i].1 != '\n' {
                i += 1;
            }
            let line: String = cs[start..i].iter().map(|&(_, c)| c).collect();
            let unterminated = i >= cs.len();
            i += 1;
            let seen = if strip_tabs { line.trim_start_matches('\t') } else { line.as_str() };
            if seen == delim {
                break;
            }
            if unterminated {
                return None;
            }
        }
    }
    Some(i)
}

/// The three escapes bash processes inside backquotes before running the text
/// they enclose: an escaped backquote is a literal backquote, `\\` a literal
/// backslash, `\$` a literal dollar. Every other backslash reaches the
/// command unchanged, which is why this is not a general unescape.
fn collapse_backquote_escapes(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(&next) = chars.peek() {
                if matches!(next, '`' | '\\' | '$') {
                    out.push(next);
                    chars.next();
                    continue;
                }
            }
        }
        out.push(c);
    }
    out
}

/// How a `walk_parens` run ended. The three outcomes are what the two callers
/// below need between them, and neither invents a fourth.
enum ParenWalk {
    /// A `)` brought the depth back to zero; this is the index just past it.
    Closed(usize),
    /// A `)` arrived with nothing open — the text cannot balance from here.
    Underflow,
    /// The text ran out with `depth` parentheses still open (`0` when the walk
    /// never opened one, or opened and closed only whole balanced groups).
    Ran { depth: usize },
}

/// One quote-aware parenthesis walk, from `from` to whichever of the three
/// endings above arrives first: parentheses are counted only where `Quoting`
/// says the shell reads them as structure, so a `)` inside a string counts for
/// nothing.
///
/// Both readers below are this walk asking a different question of the same
/// stepping loop — "does this span balance" and "where does the depth opened
/// at this `(` return to zero" — and they were two hand-written copies of it,
/// which is one more place a quoting fix would have to be found. Restarting the
/// walk after `Closed` is sound and is what `parens_balance` does: the `)` that
/// returned the depth to zero was itself read as structure, so the quote state
/// at that point is the default one a fresh walk begins with.
fn walk_parens(cs: &[(usize, char)], from: usize) -> ParenWalk {
    let mut quoting = Quoting::default();
    let mut depth = 0usize;
    let mut i = from;
    while i < cs.len() {
        if let Some(next) = quoting.step(cs, i) {
            i = next;
            continue;
        }
        match cs[i].1 {
            '(' => depth += 1,
            ')' => {
                if depth == 0 {
                    return ParenWalk::Underflow;
                }
                depth -= 1;
                if depth == 0 {
                    return ParenWalk::Closed(i + 1);
                }
            }
            _ => {}
        }
        i += 1;
    }
    ParenWalk::Ran { depth }
}

/// Parentheses balance outside quotes — bash's own test for whether `$((`
/// opened arithmetic or a substitution.
///
/// The whole text has to balance, not just its first group, so a `Closed`
/// answer resumes the walk past that group rather than returning.
fn parens_balance(text: &str) -> bool {
    let cs: Vec<(usize, char)> = text.char_indices().collect();
    let mut i = 0;
    loop {
        match walk_parens(&cs, i) {
            ParenWalk::Closed(next) => i = next,
            ParenWalk::Underflow => return false,
            ParenWalk::Ran { depth } => return depth == 0,
        }
    }
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
/// a single-quoted string, inside a double-quoted one, inside an ANSI-C
/// quoted one (`$'…'`), or neither.
///
/// Defined once because six walks over raw text need it — the body reader and
/// its extent walk through `step_expanding`, and the paren-balance test, the
/// command-substitution skip, the top-level group scan and the group-body scan
/// through `step` — and a copy per walk is one more place a quoting fix has to
/// be found.
/// It is deliberately NOT `unescape_unquoted`'s state machine: that one BUILDS
/// the unescaped text and so must keep the character a backslash protects,
/// while all six of these only need to know which positions the shell's own
/// structure characters can occupy.
#[derive(Default)]
struct Quoting {
    in_single: bool,
    in_double: bool,
    /// Inside `$'…'` — ANSI-C quoting, the one single-quote spelling bash
    /// gives escapes. A plain `'…'` has none: `\` is ordinary text and the
    /// first `'` ends the string. `$'…'` is different on purpose — it exists
    /// so a script can write `\'`, `\\`, `\n` and the rest inside a quoted
    /// literal — so `$'\''` is a quoted `'` and the string runs past it
    /// rather than closing two characters early.
    in_ansi_c: bool,
}

impl Quoting {
    /// Consume the character at `i` when quoting alone decides what it means:
    /// any character inside a string, and the quotes and backslashes that only
    /// move this state. `Some(next)` is where the walk continues; `None` means
    /// the character is the caller's own to interpret.
    ///
    /// A step rather than a predicate because a backslash consumes the
    /// character after it — inside double quotes and inside an ANSI-C string,
    /// as well as outside — so the answer is a position, not a flag.
    fn step(&mut self, cs: &[(usize, char)], i: usize) -> Option<usize> {
        let c = cs[i].1;
        if self.in_ansi_c {
            if c == '\\' {
                return Some(i + 2);
            }
            if c == '\'' {
                self.in_ansi_c = false;
            }
            return Some(i + 1);
        }
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
                if dollar_before_is_unescaped(cs, i) {
                    self.in_ansi_c = true;
                } else {
                    self.in_single = true;
                }
                Some(i + 1)
            }
            '"' => {
                self.in_double = true;
                Some(i + 1)
            }
            _ => None,
        }
    }

    /// `step`, except that the two characters double quotes do NOT make
    /// literal are left for the caller: bash runs a `$( … )` and a backquoted
    /// command inside a double-quoted string, so the body reader has to see
    /// them there (design §2.1 step 3). `step` itself keeps its own rule — the
    /// four callers that still use it directly (the paren-balance test, the
    /// command-substitution skip, the top-level group scan and the group-body
    /// scan) classify structure characters the shell reads only outside every
    /// quote.
    fn step_expanding(&mut self, cs: &[(usize, char)], i: usize) -> Option<usize> {
        let c = cs[i].1;
        if !self.in_single && self.in_double && (c == '$' || c == '`') {
            return None;
        }
        self.step(cs, i)
    }
}

/// Whether the `$` sitting immediately before the `'` at `i` opens ANSI-C
/// quoting — present, and itself unescaped.
///
/// Outside every quote a backslash always escapes exactly the next
/// character, so a run of consecutive backslashes pairs off two at a time;
/// counting the run immediately before the `$` and checking its parity is
/// bash's own answer, and it does not depend on how the walk arrived at `i`.
/// Probed against zsh 5.9: `\$'x'` reads as a literal `$` followed by a plain
/// quoted string (one backslash — the `$` is escaped), while `\\$'x'` reads
/// as a literal `\` followed by an ANSI-C one (two backslashes — the `$` is
/// not). A single "is the previous character `$`" test would get the first
/// of those wrong.
fn dollar_before_is_unescaped(cs: &[(usize, char)], i: usize) -> bool {
    if i == 0 || cs[i - 1].1 != '$' {
        return false;
    }
    let mut j = i - 1;
    let mut backslashes = 0usize;
    while j > 0 && cs[j - 1].1 == '\\' {
        backslashes += 1;
        j -= 1;
    }
    backslashes % 2 == 0
}

/// The position just past a `$( … )` command substitution that starts at the
/// `$`, or `None` when it never closes.
///
/// Nest- and quote-aware: a `)` inside a string or inside an inner
/// substitution does not end the outer one.
///
/// The walk starts at the `(` this `$` introduces, so the first structural
/// character it reads opens the depth this is asking about — an `Underflow`
/// is unreachable from a real caller and is refused rather than guessed at.
fn skip_command_substitution(cs: &[(usize, char)], dollar: usize) -> Option<usize> {
    match walk_parens(cs, dollar + 1) {
        ParenWalk::Closed(next) => Some(next),
        ParenWalk::Underflow | ParenWalk::Ran { .. } => None,
    }
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
    let program = parse_source(cmd)
        .map_err(|e| format!("{e}").lines().next().unwrap_or("parse error").to_string())?;

    let mut out = Parsed::default();
    let mut counter = 0u32;
    // One walk, one `WalkState`: both of its fields are whole-walk state, and
    // both start at zero for every parse.
    let mut walk = WalkState::default();
    let mut env: std::collections::HashMap<String, Option<String>> = std::collections::HashMap::new();
    for cc in &program.complete_commands {
        walk_compound_list(cc, &mut out, &mut counter, false, &mut walk, 0, &mut env, cmd);
    }
    Ok(out)
}

fn is_export_like(head: &str) -> bool {
    matches!(head, "export" | "declare" | "typeset" | "local" | "readonly")
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
    walk: &mut WalkState,
    scope: usize,
    env: &mut std::collections::HashMap<String, Option<String>>,
    src: &str,
) {
    for item in &list.0 {
        let async_item = matches!(item.1, ast::SeparatorOperator::Async);
        if async_item {
            out.note("background");
            let mut async_env = env.clone();
            walk_and_or_list(&item.0, out, counter, unordered, walk, scope, async_item, &mut async_env, src);
        } else {
            walk_and_or_list(&item.0, out, counter, unordered, walk, scope, async_item, env, src);
        }
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
    walk: &mut WalkState,
    scope: usize,
    async_list: bool,
    env: &mut std::collections::HashMap<String, Option<String>>,
    src: &str,
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
        let id = walk.chains;
        walk.chains += 1;
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
    walk_pipeline(&list.first, out, counter, unordered, first_pos, walk, scope, boundary_for(idx), env, src);
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
                walk_pipeline(p, out, counter, unordered, pos, walk, scope, boundary_for(idx), env, src);
            }
            ast::AndOr::And(p) => {
                let pos = id.map(|id| crate::syntax::ChainPos { id, idx, and_run_from, negated: p.bang });
                walk_pipeline(p, out, counter, unordered, pos, walk, scope, boundary_for(idx), env, src);
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
    walk: &mut WalkState,
    scope: usize,
    async_boundary: Option<crate::syntax::ScopeKind>,
    env: &mut std::collections::HashMap<String, Option<String>>,
    src: &str,
) {
    if let Some(kind) = async_boundary {
        let anchor = own_order(counter, base_unordered);
        let class = match kind {
            crate::syntax::ScopeKind::SameProcess => Some(crate::syntax::ScopeClass::AsyncMember),
            crate::syntax::ScopeKind::ProcessBoundary => None,
        };
        let wrapper = alloc_scope(out, scope, kind, class, anchor, chain);
        let mut local_counter = 0u32;
        let mut async_env = env.clone();
        walk_pipeline(p, out, &mut local_counter, false, chain, walk, wrapper, None, &mut async_env, src);
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
            let mut stage_env = env.clone();
            // Only members AFTER the first read the pipe; the first member's
            // own standard input is whatever the pipeline as a whole was
            // given. Every piped stage shares the SAME `chain` value — they
            // are one chain member, not several (`ChainPos` doc).
            walk_command(cmd, out, &mut local_counter, false, i > 0, chain, walk, member_scope, &mut stage_env, src);
        }
    } else {
        for (i, cmd) in p.seq.iter().enumerate() {
            walk_command(cmd, out, counter, base_unordered, i > 0, chain, walk, scope, env, src);
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
    walk: &mut WalkState,
    scope: usize,
    env: &mut std::collections::HashMap<String, Option<String>>,
    src: &str,
) {
    match cmd {
        ast::Command::Simple(sc) => {
            walk_simple(sc, out, counter, unordered, pipe_input, chain, walk, scope, env, src)
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
            let range = walk_compound(cc, out, walk, scoping, env, src);
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
                        walk,
                        scope,
                        chain,
                        src,
                        env,
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
            let range = walk_compound(&f.body.0, out, walk, BodyScoping::Passthrough { scope }, env, src);
            blank_inherited_input(out, range);
            // The definition's OWN redirect list (`f() { :; } > $(…)`) is
            // performed at every future call, exactly as unplaceable as the
            // body it belongs to — `Order::Unordered`, no chain, no pending
            // heredoc records (a redirect on the definition itself has no
            // landing `Cmd` of its own to tie a capture to, same as the
            // extended-test arm below), in the definition's own scope. Never
            // visited before this task, so neither its write target nor a
            // substitution inside it was judged.
            if let Some(list) = &f.body.1 {
                for r in &list.0 {
                    walk_redirect(r, out, Order::Unordered, None, walk, scope, None, src, env);
                }
            }
        }
        ast::Command::ExtendedTest(test, redirects) => {
            // The construct's own position in its enclosing scope, minted
            // ONCE and unconditionally — before this, `own_order` was called
            // INSIDE the redirect loop below, so `[[ ]]` with two redirects
            // minted two positions and with none minted none, the same
            // construct answering "where am I" differently depending on how
            // many redirects happened to follow it (design §2.2, "The
            // extended test mints its anchor once"). Every operand
            // substitution and every redirect target now shares this one
            // anchor.
            let order = own_order(counter, unordered);
            // `[[ ]]`'s own operands can carry a substitution exactly as a
            // plain command's argument can, and a short-circuited operand
            // never runs at runtime — judged anyway, because a gate fails
            // closed rather than guessing which side of `||` bash would
            // evaluate (design §2.2, "Positions bash evaluates conditionally
            // are judged anyway").
            visit_test_words(&test.expr, out, scope, &order, chain, walk, env);
            if let Some(list) = redirects {
                for r in &list.0 {
                    // An extended-test expression has no landing `Cmd` of its
                    // own either — same `None` as the compound-body arm above.
                    // It pushes no commands, so whatever its redirects claim
                    // about standard input has no occurrence to belong to.
                    walk_redirect(r, out, order.clone(), None, walk, scope, chain, src, env);
                }
            }
        }
    }
}

/// Walks every operand word of a `[[ ]]` expression for a substitution body,
/// recursing through the boolean structure (`&&`, `||`, `!`, explicit parens)
/// without evaluating any of it: a short-circuited operand never actually
/// runs at scan time, but the walk judges it anyway (design §2.2, "Positions
/// bash evaluates conditionally are judged anyway") — a gate fails closed
/// rather than predicting which side of an operator bash would take. Every
/// operand shares the ONE anchor `walk_command`'s `ExtendedTest` arm mints
/// before calling this, so it is a parameter here rather than re-derived.
fn visit_test_words(
    expr: &ast::ExtendedTestExpr,
    out: &mut Parsed,
    scope: usize,
    order: &Order,
    chain: Option<crate::syntax::ChainPos>,
    walk: &mut WalkState,
    env: &std::collections::HashMap<String, Option<String>>,
) {
    match expr {
        ast::ExtendedTestExpr::And(a, b) | ast::ExtendedTestExpr::Or(a, b) => {
            visit_test_words(a, out, scope, order, chain, walk, env);
            visit_test_words(b, out, scope, order, chain, walk, env);
        }
        ast::ExtendedTestExpr::Not(e) | ast::ExtendedTestExpr::Parenthesized(e) => {
            visit_test_words(e, out, scope, order, chain, walk, env);
        }
        ast::ExtendedTestExpr::UnaryTest(_, w) => {
            visit_substitutions(&w.value, out, scope, order, chain, walk, env);
        }
        ast::ExtendedTestExpr::BinaryTest(_, a, b) => {
            visit_substitutions(&a.value, out, scope, order, chain, walk, env);
            visit_substitutions(&b.value, out, scope, order, chain, walk, env);
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

    /// The `(parent_scope, anchor_order, anchor_chain)` triple a compound
    /// WORD position — a for-clause value, a case subject or pattern, an
    /// arithmetic expression — hands to `visit_substitutions` so THAT call
    /// can allocate the substitution body's own `ProcessBoundary` scope; this
    /// method allocates nothing of its own (design §2.2, "Where the anchor
    /// comes from at a compound position"). `Fresh` hands over the
    /// construct's own parent and anchor, cloned exactly as `.enter()` clones
    /// them when it builds the construct's OWN body scope. `Passthrough` (a
    /// function body used directly as the compound) hands over its own scope
    /// as the parent, with `Order::Unordered` and no chain: there is no
    /// anchor of the definition's own to give, which is exactly as
    /// unprovable as everything else inside a function body.
    fn boundary(&self) -> (usize, Order, Option<crate::syntax::ChainPos>) {
        match self {
            BodyScoping::Fresh { parent, anchor_order, anchor_chain } => {
                (*parent, anchor_order.clone(), *anchor_chain)
            }
            BodyScoping::Passthrough { scope } => (*scope, Order::Unordered, None),
        }
    }
}

/// One WORD position belonging to a compound command itself rather than to
/// its body — a for-clause value, a case subject or pattern, an arithmetic
/// expression — visited at the boundary `scoping` hands over (design §2.2,
/// "Where the anchor comes from at a compound position").
///
/// `BodyScoping::boundary` is the whole reason this is one call: the triple it
/// returns is the CONSTRUCT's own parent and anchor, not the body scope
/// `.enter()` would allocate, and destructuring it by hand at each site was
/// four chances to hand a word the wrong one of the two.
fn visit_compound_word(
    raw: &str,
    out: &mut Parsed,
    scoping: &BodyScoping,
    walk: &mut WalkState,
    env: &std::collections::HashMap<String, Option<String>>,
) {
    let (parent, order, chain) = scoping.boundary();
    visit_substitutions(raw, out, parent, &order, chain, walk, env);
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
    walk: &mut WalkState,
    scoping: BodyScoping,
    env: &mut std::collections::HashMap<String, Option<String>>,
    src: &str,
) -> std::ops::Range<usize> {
    let start = out.commands.len();
    let unordered = scoping.children_unordered();
    match cc {
        ast::CompoundCommand::BraceGroup(bg) => {
            let s = scoping.enter(out, crate::syntax::ScopeKind::SameProcess, Some(crate::syntax::ScopeClass::Brace));
            let mut counter = 0u32;
            walk_compound_list(&bg.list, out, &mut counter, unordered, walk, s, env, src);
        }
        ast::CompoundCommand::Subshell(sub) => {
            walk_subshell(std::iter::once(&sub.list), out, walk, scoping, unordered, env, src);
        }
        ast::CompoundCommand::ForClause(f) => {
            // The words after `in` are classified where they stand (M2.155).
            // They reached no walker at all before this, so a brace form in a
            // value list was silent while the identical token in a head or an
            // argument raised its construct — and a word vouch never looks at
            // is always silent, whatever it holds. A value list is not an
            // argument to anything, so this records nothing.
            //
            // It raises only on `Rewritten`, NOT on the redirect-target
            // treatment's "anything but literal". That difference is the
            // construct's own contract — a simple comma list IS reproduced, so
            // it raises nothing — and a redirect target only departs from it
            // because a redirect must resolve to exactly one path, which has
            // nothing to say about a loop's value list. Measured, not
            // reasoned: the wider treatment was written first and moved two
            // real corpus rows to ask over a plain comma list of filenames,
            // which is the false positive §6.2's count exists to catch.
            // A value-list word can carry a substitution exactly as a plain
            // command's argument can — `for x in $(rm -rf d); do :; done` —
            // and reached no walker at all before this, so the body ran
            // silent whatever `subshell` was set to (M2.155 the other
            // half). It anchors at the `for` construct's own position, the
            // same boundary its loop body enters at (design §2.2's
            // for-clause row) — one boundary, shared by every word in the
            // list.
            for w in f.values.iter().flatten() {
                if matches!(expand_braces(&w.value), Braces::Rewritten) {
                    out.note(BRACE_EXPANSION);
                }
                visit_compound_word(&w.value, out, &scoping, walk, env);
            }
            let s = scoping.enter(out, crate::syntax::ScopeKind::SameProcess, Some(crate::syntax::ScopeClass::LoopBody));
            let mut counter = 0u32;
            walk_compound_list(&f.body.list, out, &mut counter, unordered, walk, s, env, src);
        }
        ast::CompoundCommand::CaseClause(c) => {
            // The subject and every pattern word can carry a substitution
            // too, and a `case` pattern after the matching clause is never
            // expanded at runtime — judged anyway, because a gate fails
            // closed rather than guessing which clause bash would pick
            // (design §2.2, "Positions bash evaluates conditionally are
            // judged anyway").
            visit_compound_word(&c.value.value, out, &scoping, walk, env);
            for item in &c.cases {
                for pat in &item.patterns {
                    visit_compound_word(&pat.value, out, &scoping, walk, env);
                }
                if let Some(body) = &item.cmd {
                    let s = scoping.enter(out, crate::syntax::ScopeKind::SameProcess, Some(crate::syntax::ScopeClass::BranchBody));
                    let mut counter = 0u32;
                    walk_compound_list(body, out, &mut counter, unordered, walk, s, env, src);
                }
            }
        }
        ast::CompoundCommand::IfClause(i) => {
            let cond_scope = scoping.enter(out, crate::syntax::ScopeKind::SameProcess, Some(crate::syntax::ScopeClass::CondList));
            let mut cond_counter = 0u32;
            walk_compound_list(&i.condition, out, &mut cond_counter, unordered, walk, cond_scope, env, src);
            let then_scope = scoping.enter(out, crate::syntax::ScopeKind::SameProcess, Some(crate::syntax::ScopeClass::ThenBody));
            let mut then_counter = 0u32;
            walk_compound_list(&i.then, out, &mut then_counter, unordered, walk, then_scope, env, src);
            if let Some(elses) = &i.elses {
                for e in elses {
                    if let Some(cond) = &e.condition {
                        let s = scoping.enter(out, crate::syntax::ScopeKind::SameProcess, Some(crate::syntax::ScopeClass::ElifCond));
                        let mut counter = 0u32;
                        walk_compound_list(cond, out, &mut counter, unordered, walk, s, env, src);
                    }
                    let s = scoping.enter(out, crate::syntax::ScopeKind::SameProcess, Some(crate::syntax::ScopeClass::BranchBody));
                    let mut counter = 0u32;
                    walk_compound_list(&e.body, out, &mut counter, unordered, walk, s, env, src);
                }
            }
        }
        ast::CompoundCommand::WhileClause(w) | ast::CompoundCommand::UntilClause(w) => {
            let cond_scope = scoping.enter(out, crate::syntax::ScopeKind::SameProcess, Some(crate::syntax::ScopeClass::LoopCond));
            let mut cond_counter = 0u32;
            walk_compound_list(&w.0, out, &mut cond_counter, unordered, walk, cond_scope, env, src);
            let body_scope = scoping.enter(out, crate::syntax::ScopeKind::SameProcess, Some(crate::syntax::ScopeClass::LoopBody));
            let mut body_counter = 0u32;
            walk_compound_list(&w.1.list, out, &mut body_counter, unordered, walk, body_scope, env, src);
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
            let mut coproc_env = env.clone();
            walk_command(&c.body, out, &mut counter, unordered, false, None, walk, s, &mut coproc_env, src);
            blank_inherited_input(out, start..out.commands.len());
        }
        ast::CompoundCommand::Arithmetic(a) => {
            // Which of the two things this node is comes from the SOURCE
            // SPELLING, because that is bash's own rule rather than a
            // heuristic: `((` opens an arithmetic evaluation, and `( (` opens
            // a subshell containing a subshell. brush hands both over as this
            // one node, so without the source they are indistinguishable —
            // `rm -rf /tmp/x` is also syntactically valid arithmetic (`rm`
            // minus `rf` divided by `tmp` divided by `x`), which is exactly
            // how an earlier token-shape rule let a recursive delete through.
            match arithmetic_opening(src, a.loc.start.index) {
                // A subshell the parser read as arithmetic. Read it as the
                // command list it is, in a process-boundary scope, the same
                // treatment the Subshell arm gives its own body (M2.222).
                //
                // Recursion terminates without a depth counter: the text
                // handed over is what sat BETWEEN the parentheses, so it
                // strictly shrinks at every level.
                Opening::NestedSubshell => match parse_program(&a.expr.value) {
                    Some(program) => walk_subshell(
                        &program.complete_commands,
                        out,
                        walk,
                        scoping,
                        unordered,
                        env,
                        &a.expr.value,
                    ),
                    // Spelled as a nested subshell and not parseable as one.
                    // Saying so is the point; falling through would restore
                    // the silence this row exists to remove.
                    None => out.note("parse_failure"),
                },
                Opening::Arithmetic => {
                    // Real arithmetic runs no command and writes nothing, so
                    // it says nothing on its own — the two exceptions are an
                    // EMPTY expression, which means the parser produced
                    // nothing for text that was plainly there, and a
                    // substitution inside it, which really does run a
                    // command. The text was never absent from the line; the
                    // walk simply never read it, and now it does (design
                    // §2.2, "The arithmetic parse_failure arms go").
                    let e = a.expr.value.trim();
                    if e.is_empty() {
                        out.note("parse_failure");
                    } else {
                        visit_compound_word(e, out, &scoping, walk, env);
                    }
                }
                // The source did not say. Fail closed rather than pick one.
                Opening::Unknown => out.note("parse_failure"),
            }
        }
        ast::CompoundCommand::ArithmeticForClause(f) => {
            // The three clauses are arithmetic TEXT, not commands, so they are
            // never recovered as commands the way `((…))` is: a for-loop's own
            // clauses are evaluated as arithmetic by bash whatever they
            // contain, so reading one as a command would be a claim about a
            // thing that never runs. Only a substitution inside one runs, and
            // that is what gets walked — the same visit the plain `((…))` arm
            // above makes, anchored at this construct's own boundary (design
            // §2.2, "The arithmetic parse_failure arms go"). Visited BEFORE
            // the body: bash evaluates the initializer once, before the
            // loop's first iteration, so pushing these first keeps recorded
            // order matching run order — the same reason the `ForClause` arm
            // above visits its value words before entering the loop body.
            for e in [&f.initializer, &f.condition, &f.updater].into_iter().flatten() {
                visit_compound_word(&e.value, out, &scoping, walk, env);
            }
            // The body holds real commands and is walked exactly as a plain
            // `for` body is — the same `LoopBody` class, the same fresh local
            // counter. Leaving this arm empty is what hid `rm -rf` inside an
            // arithmetic loop from recognition, guards and the write rules at
            // once (M2.224): an empty arm pushes nothing, so the line fell
            // through to the language default and the miss was
            // indistinguishable from there being nothing to report.
            let s = scoping.enter(out, crate::syntax::ScopeKind::SameProcess, Some(crate::syntax::ScopeClass::LoopBody));
            let mut counter = 0u32;
            walk_compound_list(&f.body.list, out, &mut counter, unordered, walk, s, env, src);
        }
    }
    start..out.commands.len()
}

/// Walk one or more command lists as a subshell body: the construct note, a
/// fresh process-boundary scope, and a local counter.
///
/// Shared by the `Subshell` arm and the nested-subshell recovery rather than
/// written twice. The design claims the recovered nest is treated "exactly as
/// the Subshell arm walks its own body"; two hand-written copies made that
/// true only for as long as nobody edited one of them.
///
/// `src` is a parameter rather than the caller's own, because the recovery
/// passes the RECOVERED text: spans inside a re-parsed program are relative to
/// the text it was parsed from, never to the outer line.
fn walk_subshell<'a>(
    lists: impl IntoIterator<Item = &'a ast::CompoundList>,
    out: &mut Parsed,
    walk: &mut WalkState,
    scoping: BodyScoping,
    unordered: bool,
    env: &std::collections::HashMap<String, Option<String>>,
    src: &str,
) {
    out.note("subshell");
    let s = scoping.enter(out, crate::syntax::ScopeKind::ProcessBoundary, None);
    let mut counter = 0u32;
    let mut sub_env = env.clone();
    for list in lists {
        walk_compound_list(list, out, &mut counter, unordered, walk, s, &mut sub_env, src);
    }
}

/// One constant serving two separate quantities, deliberately kept as one so
/// they can never drift apart. The READER's own per-word nesting cap: inside
/// a single `read_substitution` call, an opener nested `SUBSTITUTION_DEPTH_CAP`
/// levels deep inside the same word's text is refused rather than resolved,
/// independent of anything below. And how deep a nest of substitution BODIES
/// the WALK descends before it stops reading further — bounding substitution
/// nesting only, not the Rust stack in general: the arithmetic
/// `Opening::NestedSubshell` arm's own repeated `parse_program`/`walk_subshell`
/// recursion (pre-existing) has no cap of its own. Termination needs no
/// counter for either quantity — a body sits strictly between its own
/// delimiters, so the text shrinks at every level — but the Rust stack still
/// grows by one frame per level, so past this depth a body notes
/// `parse_failure` (already `ask` in every config on disk) and is not read.
/// The corpus nests three deep at most.
///
/// The reader's half reads its own `depth` parameter; the walk's half reads
/// `WalkState::depth`, which the walk threads through its own signatures.
const SUBSTITUTION_DEPTH_CAP: usize = 8;

/// The two counters one whole `parse` carries from top to bottom, borrowed
/// down through every walk function rather than passed as loose parameters or
/// parked in thread-local state.
///
/// Borrowed state is what makes both fields correct by construction. `chains`
/// must never reset for a nested body, or an inner `if a && b; then …` chain
/// could collide with an outer one; `depth` must be restored exactly on the
/// way back out of a substitution body, and a `&mut` that cannot outlive the
/// scan it belongs to cannot leak either value into the next scan the way a
/// thread-local could.
#[derive(Default)]
struct WalkState {
    /// Next and-or chain id (`ChainPos.id`), unique across the whole parse.
    chains: u32,
    /// How many substitution BODIES enclose the position being walked; 0 at
    /// the top level, checked against `SUBSTITUTION_DEPTH_CAP` by
    /// `walk_substitution_body`.
    depth: usize,
}

/// Walk every substitution body a word's raw text runs, each as the
/// process-boundary child it is, anchored at the ENCLOSING construct's own
/// position (design §2.1–§2.2). The `subshell` note stays and now means
/// only that the body's output becomes text vouch cannot read.
fn visit_substitutions(
    raw: &str,
    out: &mut Parsed,
    parent_scope: usize,
    anchor_order: &Order,
    anchor_chain: Option<crate::syntax::ChainPos>,
    walk: &mut WalkState,
    env: &std::collections::HashMap<String, Option<String>>,
) {
    visit_bodies(substitution_bodies(raw), out, parent_scope, anchor_order, anchor_chain, walk, env);
}

/// What a `Bodies` reading MEANS to the walk, in one place: text the reader
/// could not delimit is a `parse_failure` for the whole occurrence, and every
/// body it did delimit is walked as its own process-boundary child.
///
/// Both readers hand their answer here — a word's own raw text through
/// `visit_substitutions`, and an unquoted here-document body from
/// `walk_redirect`'s `HereDocument` arm — so the two can never come to differ
/// about what an unreadable reading costs.
fn visit_bodies(
    read: Bodies,
    out: &mut Parsed,
    parent_scope: usize,
    anchor_order: &Order,
    anchor_chain: Option<crate::syntax::ChainPos>,
    walk: &mut WalkState,
    env: &std::collections::HashMap<String, Option<String>>,
) {
    if read.unreadable {
        out.note("parse_failure");
    }
    for body in read.bodies {
        walk_substitution_body(&body, out, parent_scope, anchor_order, anchor_chain, walk, env);
    }
}

fn walk_substitution_body(
    body: &str,
    out: &mut Parsed,
    parent_scope: usize,
    anchor_order: &Order,
    anchor_chain: Option<crate::syntax::ChainPos>,
    walk: &mut WalkState,
    env: &std::collections::HashMap<String, Option<String>>,
) {
    out.note("subshell");
    if walk.depth >= SUBSTITUTION_DEPTH_CAP {
        out.note("parse_failure");
        return;
    }
    // A body that does not re-parse still gets its scope: the boundary is a
    // fact about the line, not about whether vouch could read what runs
    // inside it, and the empty child below is what keeps the scope table the
    // same shape either way.
    let parsed = parse_program(body);
    if parsed.is_none() {
        out.note("parse_failure");
    }
    // Saved and restored around the body walk alone. A plain saved value is
    // enough where a thread-local needed a `Drop` guard: this depth lives in
    // borrowed state that dies with the scan, so an unwind cannot carry an
    // elevated value into whatever runs next.
    let enclosing = walk.depth;
    walk.depth = enclosing + 1;
    walk_boundary_child(
        parsed.iter().flat_map(|p| &p.complete_commands),
        out,
        parent_scope,
        anchor_order,
        anchor_chain,
        walk,
        env,
        body,
    );
    walk.depth = enclosing;
}

/// The forked child a command substitution's body and both spellings of a
/// process substitution all are: a fresh `ProcessBoundary` scope anchored at
/// `(parent_scope, anchor_order, anchor_chain)`, then the list(s) walked
/// inside it with a local sequence counter starting at 0.
///
/// The scope is allocated BEFORE anything is walked, because the engine's
/// scope table is built in allocation order and a child must find its parent
/// already there.
///
/// `unordered` is FALSE at every one of these sites and this helper is where
/// that invariant lives: a child process starts at its own beginning, so its
/// first command really is provably first WITHIN the child, whatever the
/// enclosing scope could or could not prove about the position the child
/// itself occupies (that part is carried by `anchor_order`). A test pins the
/// `Order::Seq(0)` this produces, so passing the enclosing `unordered` here
/// would be a silent behaviour change rather than a compile error.
fn walk_boundary_child<'a>(
    lists: impl IntoIterator<Item = &'a ast::CompoundList>,
    out: &mut Parsed,
    parent_scope: usize,
    anchor_order: &Order,
    anchor_chain: Option<crate::syntax::ChainPos>,
    walk: &mut WalkState,
    env: &std::collections::HashMap<String, Option<String>>,
    src: &str,
) {
    let scope = alloc_scope(
        out,
        parent_scope,
        crate::syntax::ScopeKind::ProcessBoundary,
        None,
        anchor_order.clone(),
        anchor_chain,
    );
    let mut counter = 0u32;
    let mut child_env = env.clone();
    for list in lists {
        walk_compound_list(list, out, &mut counter, false, walk, scope, &mut child_env, src);
    }
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
    walk: &mut WalkState,
    scope: usize,
    env: &mut std::collections::HashMap<String, Option<String>>,
    src: &str,
) {
    let mut cmd = Cmd::default();
    cmd.chain = chain;
    cmd.env_assigns = env.clone();
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
    // The head is a word like any other: a substitution there runs at the
    // command's own position, before the prefix and suffix are walked so
    // that `cmd.head` and `cmd.chain` are already final (design §2.2).
    if let Some(w) = &sc.word_or_name {
        visit_substitutions(&w.value, out, scope, &order, cmd.chain, walk, &cmd.env_assigns);
    }
    if let Some(prefix) = &sc.prefix {
        walk_items(&prefix.0, out, &mut cmd, false, order.clone(), &mut landing, walk, scope, env, src);
    }
    if let Some(suffix) = &sc.suffix {
        walk_items(&suffix.0, out, &mut cmd, true, order.clone(), &mut landing, walk, scope, env, src);
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
            cmd.env_assigns.clone(),
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

fn evaluate_predictable_substitution(body: &str) -> Option<String> {
    let trimmed = body.trim().trim_end_matches(';').trim();
    if trimmed == "pwd" {
        return Some("$PWD".to_string());
    }
    if let Some(rest) = trimmed.strip_prefix("echo ") {
        let rest = rest.trim();
        if !rest.starts_with('-') && !has_command_substitution(rest) {
            let unquoted = crate::paths::unquote(rest);
            return Some(unquoted.to_string());
        }
    }
    None
}

/// Statically resolves a closed set of value-predictable substitutions in an
/// assignment value (M2.59). `$(pwd)` and `pwd` resolve to `$PWD`; `echo <lit>`
/// resolves to the literal. If any substitution is dynamic or cannot be
/// predicted, returns `None` (fail-closed, poisoned).
fn resolve_predictable_substitutions(value: &str) -> Option<String> {
    let text = strip_line_continuations(value);
    let cs: Vec<(usize, char)> = text.char_indices().collect();
    let mut quoting = Quoting::default();
    let mut memo = Memo::new();
    let mut result = String::new();
    let mut last_end = 0;
    let mut i = 0;
    let mut found_any = false;

    while i < cs.len() {
        if let Some(next) = quoting.step_expanding(&cs, i) {
            i = next;
            continue;
        }
        match cs[i].1 {
            '$' if cs.get(i + 1).is_some_and(|&(_, n)| n == '(') => {
                let dollar = i;
                let (reading, next) = read_substitution(&cs, &text, dollar, 0, &mut memo)?;
                match reading {
                    Reading::Body(span) => {
                        let repl = evaluate_predictable_substitution(span)?;
                        result.push_str(&text[last_end..cs[dollar].0]);
                        result.push_str(&repl);
                        last_end = if next < cs.len() { cs[next].0 } else { text.len() };
                        i = next;
                        found_any = true;
                    }
                    Reading::Arithmetic(_) => return None,
                }
            }
            '`' => {
                let next = skip_backquotes(&cs, i)?;
                let span = collapse_backquote_escapes(&text[cs[i].0 + 1..cs[next - 1].0]);
                let repl = evaluate_predictable_substitution(&span)?;
                result.push_str(&text[last_end..cs[i].0]);
                result.push_str(&repl);
                last_end = if next < cs.len() { cs[next].0 } else { text.len() };
                i = next;
                found_any = true;
            }
            _ => i += 1,
        }
    }

    if !found_any {
        return None;
    }
    result.push_str(&text[last_end..]);
    let unescaped = unescape_unquoted(&result);
    Some(crate::paths::unquote(&unescaped).to_string())
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
    walk: &mut WalkState,
    scope: usize,
    env: &mut std::collections::HashMap<String, Option<String>>,
    src: &str,
) {
    for item in items {
        match item {
            ast::CommandPrefixOrSuffixItem::IoRedirect(r) => {
                // A here-document is captured only when a command will land to
                // consume it; otherwise it keeps the construct note.
                let records = (!cmd.head.is_empty()).then_some(&mut landing.pending);
                if let Some(claimed) =
                    walk_redirect(r, out, order.clone(), records, walk, scope, cmd.chain, src, &cmd.env_assigns)
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
                walk_boundary_child(
                    std::iter::once(&s.list),
                    out,
                    scope,
                    &order,
                    cmd.chain,
                    walk,
                    &cmd.env_assigns,
                    src,
                );
            }
            // A command substitution runs a command in a subshell, whether it
            // appears as an argument or on the right of an assignment. Both
            // count, and both are now walked as the command list they run
            // (design §2.1–§2.2), anchored at this command's own position.
            ast::CommandPrefixOrSuffixItem::Word(w) => {
                visit_substitutions(&w.value, out, scope, &order, cmd.chain, walk, &cmd.env_assigns);
                push_word(out, cmd, &w.value);
                if is_suffix && is_export_like(&cmd.head) {
                    if let Some((name, value)) = w.value.split_once('=') {
                        if !name.is_empty()
                            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                        {
                            let recorded = if has_command_substitution(&w.value) {
                                resolve_predictable_substitutions(value)
                            } else {
                                let unescaped = unescape_unquoted(value);
                                let raw_val = crate::paths::unquote(&unescaped);
                                Some(crate::paths::resolve_with_assignments(raw_val, &cmd.env_assigns, None))
                            };
                            out.assignments.push((name.to_string(), recorded.clone()));
                            env.insert(name.to_string(), recorded.clone());
                            cmd.env_assigns.insert(name.to_string(), recorded);
                        }
                    }
                }
            }
            ast::CommandPrefixOrSuffixItem::AssignmentWord(_, w) => {
                visit_substitutions(&w.value, out, scope, &order, cmd.chain, walk, &cmd.env_assigns);
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
                        let recorded = if has_command_substitution(&w.value) {
                            resolve_predictable_substitutions(value)
                        } else {
                            let unescaped = unescape_unquoted(value);
                            let raw_val = crate::paths::unquote(&unescaped);
                            Some(crate::paths::resolve_with_assignments(raw_val, &cmd.env_assigns, None))
                        };

                        if is_suffix {
                            if is_export_like(&cmd.head) {
                                out.assignments.push((name.to_string(), recorded.clone()));
                                env.insert(name.to_string(), recorded.clone());
                                cmd.env_assigns.insert(name.to_string(), recorded);
                            }
                        } else {
                            if !cmd.head.is_empty() {
                                cmd.prefix_assigns.push(name.to_string());
                            }
                            out.assignments.push((name.to_string(), recorded.clone()));
                            cmd.env_assigns.insert(name.to_string(), recorded.clone());
                            if cmd.head.is_empty() {
                                env.insert(name.to_string(), recorded);
                            }
                        }
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

/// One redirect's own word, read the way all four of `walk_redirect`'s
/// word-bearing arms read it: bash expands a substitution written there before
/// the redirect opens, exactly as it does in an argument word (design §2.2),
/// so the visit happens before the arm classifies what the word turned out to
/// be.
///
/// `note_braces` is what the four arms genuinely differ on, and it carries the
/// split unchanged: the three arms whose word names a redirect TARGET pass
/// true, because a target must resolve to exactly one path and a brace rewrite
/// vouch did not reproduce would leave the recorded path wrong. The
/// here-string passes false — its word supplies standard input rather than
/// naming a file, so there is no target for a rewrite to make wrong.
fn visit_redirect_word(
    w: &ast::Word,
    out: &mut Parsed,
    scope: usize,
    order: &Order,
    chain: Option<crate::syntax::ChainPos>,
    walk: &mut WalkState,
    note_braces: bool,
    env: &std::collections::HashMap<String, Option<String>>,
) {
    visit_substitutions(&w.value, out, scope, order, chain, walk, env);
    if note_braces {
        note_target_braces(out, &w.value);
    }
}

/// Which construct a node the parser called arithmetic was actually written as.
pub(crate) enum Opening {
    /// `((` — an arithmetic evaluation, exactly as bash reads it.
    Arithmetic,
    /// `( (` — a subshell whose only content is a subshell. bash runs this;
    /// checked against bash 5.2, which really writes the file for
    /// `( ( echo A > f ) )`.
    NestedSubshell,
    /// The source did not answer, so neither does vouch.
    Unknown,
}

/// Read the two opening characters of an arithmetic-looking node.
///
/// Indexed by CHARACTER rather than by byte: the span type documents its
/// length as a count of characters, and slicing a multi-byte source by a
/// character index would either misalign or silently return nothing.
pub(crate) fn arithmetic_opening(src: &str, start: usize) -> Opening {
    let mut it = src.chars().skip(start);
    if it.next() != Some('(') {
        return Opening::Unknown;
    }
    match it.next() {
        Some('(') => Opening::Arithmetic,
        Some(c) if c.is_whitespace() => {
            // Any run of whitespace, then the inner open paren. Anything else
            // is a spelling this reading does not cover, and guessing at it is
            // what the Unknown arm exists to avoid.
            let mut rest = it.skip_while(|c| c.is_whitespace());
            match rest.next() {
                Some('(') => Opening::NestedSubshell,
                _ => Opening::Unknown,
            }
        }
        _ => Opening::Unknown,
    }
}

/// The one parser construction in this file. Both entry points go through it,
/// so a future change to the options cannot reach `parse` and miss the
/// recovered-text re-read — which a comment saying "keep these in sync" was
/// the only thing preventing.
fn parse_source(text: &str) -> Result<brush_parser::ast::Program, brush_parser::ParseError> {
    let options = brush_parser::ParserOptions::default();
    let mut parser = brush_parser::Parser::new(std::io::Cursor::new(text), &options);
    parser.parse_program()
}

/// The same parse, for a caller that has no error to report — a re-read of
/// text the walk recovered, whose failure is already a construct.
fn parse_program(text: &str) -> Option<brush_parser::ast::Program> {
    parse_source(text).ok()
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
        let stripped = line.trim_start_matches('\t');
        out.push_str(stripped);
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
    walk: &mut WalkState,
    scope: usize,
    chain: Option<crate::syntax::ChainPos>,
    src: &str,
    active_env: &std::collections::HashMap<String, Option<String>>,
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
                    // Visited before the target is classified, so the walk
                    // runs whether or not this turns out to be a write.
                    visit_redirect_word(w, out, scope, &order, chain, walk, true, active_env);
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
                        out.redirect_env.push(active_env.clone());
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
                    walk_boundary_child(
                        std::iter::once(&s.list),
                        out,
                        scope,
                        &order,
                        chain,
                        walk,
                        active_env,
                        src,
                    );
                }
                // `>&word` duplicates a descriptor only when the word IS a
                // descriptor — a number, or `-` for close. With a NAME there
                // it is bash's own spelling for "send both streams to this
                // file", and it creates that file: verified by running
                // `echo <text> >& marker.txt`, which wrote the file. Recorded
                // as the write it is; without this the spelling reached even a
                // protected path, which CLAUDE.md 5 says no rule can open.
                ast::IoFileRedirectTarget::Duplicate(w) => {
                    // Same reasoning as `Filename` above: `>&$(…)` expands the
                    // substitution before bash decides whether the word names
                    // a descriptor or a file.
                    visit_redirect_word(w, out, scope, &order, chain, walk, true, active_env);
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
                        out.redirect_env.push(active_env.clone());
                    }
                }
                ast::IoFileRedirectTarget::Fd(_) => {}
            }
        }
        // A here-document is captured — tied to its consuming command — so a
        // locator can later decide whether that command actually reads it
        // (`guards::heredoc_feeds`). A here-string (`<<<`) is out of the
        // locator's scope and keeps the plain construct note unchanged.
        ast::IoRedirect::HereDocument(fd, doc) => {
            // bash expands a substitution inside an unquoted here-document
            // body before the command that reads it ever runs (design §2.2's
            // "two here-document paths"). Visited on BOTH the captured
            // (`Some`) and construct-note (`None`) paths below, from the raw
            // body — never the tab-stripped copy the captured record keeps.
            // This runs BEFORE and separately from the `match pending` block
            // below, which is untouched and still computes the captured
            // record's own `body` and `quoted_delimiter` exactly as it did
            // before this task.
            if doc.requires_expansion {
                let read = heredoc_substitution_bodies(&doc.doc.value);
                visit_bodies(read, out, scope, &order, chain, walk, active_env);
            }
            match pending {
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
            }
        }
        // A here-string supplies descriptor 0 too, but produces no record for a
        // locator to consume — so it is a stream, never a `Heredoc(i)` pointing
        // into a list that holds nothing for it.
        ast::IoRedirect::HereString(fd, w) => {
            visit_redirect_word(w, out, scope, &order, chain, walk, false, active_env);
            if fd.unwrap_or(0) == 0 {
                claims_stdin = Some(InputSource::Stream);
            }
            out.note("heredoc");
        }
        // Its own grammar variant, with no descriptor slot at all: it sets
        // descriptors 1 and 2 and never standard input, so nothing is read for
        // it and it claims nothing.
        ast::IoRedirect::OutputAndError(w, _) => {
            visit_redirect_word(w, out, scope, &order, chain, walk, true, active_env);
            if is_dynamic(&w.value) {
                out.note("dynamic_redirect");
            }
            out.redirect_targets.push(unescape_unquoted(&w.value));
            out.redirect_order.push(order);
            out.redirect_scope.push(Some(scope));
            out.redirect_chain.push(chain);
            out.redirect_env.push(active_env.clone());
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
