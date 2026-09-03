//! PowerShell scanning.
//!
//! Deliberately a scanner, not PowerShell's own parser. Reaching
//! `System.Management.Automation.Language.Parser` from Rust costs 70ms minimum
//! (measured 2026-07-25: 70ms via a managed shim, 185ms via spawning
//! powershell.exe) which exceeds the entire per-call budget of ~58ms.
//!
//! The predecessor's defect was never scanner accuracy — it named
//! `type literal`, `foreach`, and `call operator` correctly in its messages. The
//! defect was that those names had no settings, so the prompt told the user to
//! change something that did not exist. Here, every name below is a settable key
//! under `[lang.powershell.constructs]`, enforced by a test.
//!
//! Second defect fixed here: `$env:X=1` was read as a command named `1`, and
//! `$n = 5` as a command named `5`. Assignment values are values.

pub use crate::syntax::{Cmd, Order, Scan as Parsed};

pub const KNOWN_CONSTRUCTS: &[&str] = &[
    "type_literal",
    "call_operator",
    "method_call",
    "redirect",
    "assignment",
    "env_assignment",
    "function_def",
    "keyword_foreach",
    "keyword_while",
    "keyword_do",
    "keyword_switch",
    "keyword_trap",
    "keyword_class",
    "keyword_try",
    "unbalanced_quotes",
    "parse_failure",
    "unmodeled_command",
    "splatting",
    // Emitted by the engine rather than the scanner, but settable in exactly
    // the same way, so they belong on the same list.
    "unresolved_path",
    "evaluated_input",
    "wrap_depth_exceeded",
    "args_from_input",
    // The shell half of a construct that was python-only until M2.120.
    "rebound_name",
    "wrap_unlocated",
    "wrap_ambiguous",
    "unreadable_language",
    "unread_verb",
];

/// Byte offset of a real redirect operator, or None.
///
/// A `>` only redirects when it is at the top level and outside quotes. Inside
/// a string, a `$( … )` expression or a `{ … }` block it is part of something
/// else — a format specifier, a comparison, a script block — and treating it as
/// a redirect invents a file that was never written.
fn redirect_operator(stmt: &str) -> Option<usize> {
    let b: Vec<char> = stmt.chars().collect();
    let mut quote: Option<char> = None;
    let mut depth = 0i32;
    let mut byte = 0usize;
    let mut i = 0usize;
    while i < b.len() {
        let c = b[i];
        match quote {
            Some(q) => {
                if c == q {
                    quote = None;
                }
            }
            None => match c {
                '\'' | '"' => quote = Some(c),
                '(' | '{' | '[' => depth += 1,
                ')' | '}' | ']' => depth -= 1,
                '>' if depth <= 0 => {
                    // `2>&1` and `>&1` merge streams; they name no file.
                    let next = b.get(i + 1).copied().unwrap_or(' ');
                    let next2 = if next == '>' {
                        b.get(i + 2).copied().unwrap_or(' ')
                    } else {
                        next
                    };
                    if next2 != '&' {
                        return Some(byte);
                    }
                }
                _ => {}
            },
        }
        byte += c.len_utf8();
        i += 1;
    }
    None
}

/// True for a splatted parameter set: `@name`, and nothing else.
///
/// Everything else `@` introduces is a different construct entirely — `@{}` a
/// hashtable, `@()` an array, `@'` / `@"` a here-string — and `@scope/package`
/// is an npm name that merely happens to appear in a PowerShell command line.
fn is_splat(tok: &str) -> bool {
    match tok.strip_prefix('@') {
        Some(rest) => {
            !rest.is_empty()
                && rest
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_')
        }
        None => false,
    }
}

/// A `[Something]` cast or a `[Something]::Member` access.
/// Not a blind spot we can follow, so it gets a name and a setting.
fn has_type_literal(src: &str) -> bool {
    let b: Vec<char> = src.chars().collect();
    let mut i = 0;
    while i < b.len() {
        if b[i] == '[' {
            let mut j = i + 1;
            let mut ident = String::new();
            while j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == '.' || b[j] == '_') {
                ident.push(b[j]);
                j += 1;
            }
            // `[System.Math]` / `[math]` / `[PSCustomObject]` — a bare identifier
            // in brackets. An index like `[0]` or `[$i]` is not a type.
            if j < b.len() && b[j] == ']'
                && !ident.is_empty()
                && ident.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
            {
                return true;
            }
            i = j;
            continue;
        }
        i += 1;
    }
    false
}

/// Returns the contents of every top-level `{...}` and `$(...)`, so commands
/// hidden inside a script block or subexpression are still found rather than
/// the block merely being flagged.
fn inner_blocks(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    let b: Vec<char> = src.chars().collect();
    let mut i = 0;
    while i < b.len() {
        let open_at = if b[i] == '{' {
            Some(i)
        } else if b[i] == '$' && i + 1 < b.len() && b[i + 1] == '(' {
            Some(i + 1)
        } else {
            None
        };
        if let Some(start) = open_at {
            let open = b[start];
            let close = if open == '{' { '}' } else { ')' };
            let mut depth = 0i32;
            let mut j = start;
            while j < b.len() {
                if b[j] == open {
                    depth += 1;
                } else if b[j] == close {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                j += 1;
            }
            if j < b.len() && j > start + 1 {
                out.push(b[start + 1..j].iter().collect());
            }
            i = j + 1;
            continue;
        }
        i += 1;
    }
    out
}

/// Sentinel separator characters `split_statements_with_sep` reports
/// alongside the literal one-character separators (`;`, `\n`, `|`). `&&` and
/// `||` are two characters wide and have no single source character to
/// report, so each gets an assigned sentinel outside the range any real
/// PowerShell text can contain — chosen so a caller can still tell "and" and
/// "or" apart from each other and from every literal separator.
const SEP_AND: char = '\u{1}';
const SEP_OR: char = '\u{2}';

/// Combines a carried-forward separator with a newly-seen one across a gap
/// with nothing real in it (see `split_statements_with_sep`'s doc). `|`
/// always wins, matching the pre-existing pipe-survives-a-blank-gap rule;
/// otherwise the newer separator replaces the older one.
fn merge_sep(prev: char, incoming: char) -> char {
    if prev == '|' || incoming == '|' {
        '|'
    } else {
        incoming
    }
}

/// Splits on statement separators that are outside quotes and brackets,
/// keeping the separator character (or sentinel — see `SEP_AND`/`SEP_OR`)
/// immediately before each statement (`\0` for the first one, or one that
/// opens a fresh line). Order attribution needs this: a `;`/newline-joined
/// statement is a provable top-level position; a `|`-joined one is a
/// pipeline member and unordered; a `&&`/`||`-joined one is an and-or chain
/// member (M2.126) — ordered up to the first `||`, unordered from there on,
/// same rule bash's own and-or walk uses (shell.rs).
///
/// `&&`/`||` are checked BEFORE the one-character separators, and consuming
/// their second character is the reader's job here, not the one-character
/// arm's — a lone `&` (the call operator, or PowerShell 7's background
/// suffix) never matches any separator arm and is left as ordinary text.
///
/// Trailing-pipe-then-newline (`gci |\n  sort`) is the idiomatic way to
/// write a multi-line PowerShell pipeline, and it puts nothing but
/// whitespace between the `|` and the `\n`. That gap must not be allowed to
/// LOSE the `|`: if it is dropped as an empty fragment before its separator
/// reaches the next real statement, that statement looks newline-joined
/// instead of pipe-joined, and a provably-unordered pipeline member gets
/// reported as a provable `Seq` position — the exact false certainty
/// CLAUDE.md §1 forbids. So a separator is only "spent" (pushed alongside a
/// fragment, then handed to the next one) when it precedes real content;
/// consecutive separators with nothing but whitespace between them collapse
/// into one, via `merge_sep`.
fn split_statements_with_sep(src: &str) -> Vec<(String, char)> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut sep_before_cur = '\0';
    let mut in_single = false;
    let mut in_double = false;
    let mut depth = 0i32;
    let mut chars = src.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '`' => {
                cur.push(c);
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
                continue;
            }
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            '(' | '[' | '{' if !in_single && !in_double => depth += 1,
            ')' | ']' | '}' if !in_single && !in_double => depth -= 1,
            '&' if !in_single && !in_double && depth <= 0 && chars.peek() == Some(&'&') => {
                chars.next();
                if cur.trim().is_empty() {
                    cur.clear();
                    sep_before_cur = merge_sep(sep_before_cur, SEP_AND);
                } else {
                    out.push((std::mem::take(&mut cur), sep_before_cur));
                    sep_before_cur = SEP_AND;
                }
                continue;
            }
            '|' if !in_single && !in_double && depth <= 0 && chars.peek() == Some(&'|') => {
                chars.next();
                if cur.trim().is_empty() {
                    cur.clear();
                    sep_before_cur = merge_sep(sep_before_cur, SEP_OR);
                } else {
                    out.push((std::mem::take(&mut cur), sep_before_cur));
                    sep_before_cur = SEP_OR;
                }
                continue;
            }
            ';' | '\n' | '|' if !in_single && !in_double && depth <= 0 => {
                if cur.trim().is_empty() {
                    // Nothing real accumulated since the last boundary —
                    // this separator is part of the same gap as the
                    // previous one.
                    cur.clear();
                    sep_before_cur = merge_sep(sep_before_cur, c);
                } else {
                    out.push((std::mem::take(&mut cur), sep_before_cur));
                    sep_before_cur = c;
                }
                continue;
            }
            _ => {}
        }
        cur.push(c);
    }
    out.push((cur, sep_before_cur));
    out.into_iter()
        .map(|(s, sep)| (s.trim().to_string(), sep))
        .filter(|(s, _)| !s.is_empty())
        .collect()
}

fn quotes_balanced(src: &str) -> bool {
    let mut in_single = false;
    let mut in_double = false;
    let mut chars = src.chars();
    while let Some(c) = chars.next() {
        match c {
            '`' => {
                chars.next();
            }
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            _ => {}
        }
    }
    !in_single && !in_double
}

/// The right-hand side of an assignment is a VALUE unless it starts with
/// something that actually invokes: a bare command word, or `&`.
fn rhs_is_a_command(rhs: &str) -> bool {
    let t = rhs.trim();
    if t.is_empty() {
        return false;
    }
    let first = t.chars().next().unwrap();
    // quoted, numeric, variable, hashtable, array, type literal, subexpression
    if matches!(first, '"' | '\'' | '$' | '@' | '[' | '(') || first.is_ascii_digit() {
        return false;
    }
    if first == '&' {
        return true;
    }
    // A bare word: treat as a command (e.g. `$d = Get-Date`).
    first.is_ascii_alphabetic() || first == '_' || first == '.' || first == '\\' || first == '/'
}

fn is_flag(tok: &str) -> bool {
    tok.starts_with('-') || tok.starts_with('/')
}

/// Splits a statement into whitespace-separated tokens, keeping quoted runs whole.
fn tokens(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match c {
            '`' => {
                cur.push(c);
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
            }
            '\'' if !in_double => {
                in_single = !in_single;
            }
            '"' if !in_single => {
                in_double = !in_double;
            }
            c if c.is_whitespace() && !in_single && !in_double => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            _ => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

const KEYWORDS: &[(&str, &str)] = &[
    ("foreach", "keyword_foreach"),
    ("while", "keyword_while"),
    ("do", "keyword_do"),
    ("switch", "keyword_switch"),
    ("trap", "keyword_trap"),
    ("class", "keyword_class"),
    ("try", "keyword_try"),
];

pub fn parse(src: &str) -> Result<Parsed, String> {
    let mut out = Parsed::default();

    if !quotes_balanced(src) {
        out.note("unbalanced_quotes");
    }

    // Whole-text constructs.
    if has_type_literal(src) {
        out.note("type_literal");
    }

    // Order and chain-identity attribution (M2.126): a `;`/newline-joined
    // statement gets the next top-level sequence position; a statement
    // joined to a neighbour by `|` — i.e. a pipeline with more than one
    // member — is unordered, same as bash. `&&`/`||`-joined statements are
    // and-or chain MEMBERS, mirroring shell.rs's own walk: a maximal
    // `|`-joined run is one member (every `Cmd` it expands to shares that
    // member's one `ChainPos`, per the type's own doc); a lone statement
    // with no `&&`/`||` neighbour is not a chain at all (`chain: None`,
    // same as a plain `;` statement); and inside a real chain, the member
    // right of the first `||` — and every member after it — is unordered,
    // because its execution is no longer certain (`Order`'s own doc).
    let stmts = split_statements_with_sep(src);
    let n_stmts = stmts.len();

    // A statement starts a fresh member unless the separator before it is
    // `|` — a multi-stage pipeline is one member.
    let mut member_of = vec![0usize; n_stmts];
    {
        let mut m = 0usize;
        for i in 0..n_stmts {
            if i > 0 && stmts[i].1 != '|' {
                m += 1;
            }
            member_of[i] = m;
        }
    }
    let num_members = if n_stmts > 0 { member_of[n_stmts - 1] + 1 } else { 0 };

    let mut member_is_pipe_run = vec![false; num_members];
    for i in 1..n_stmts {
        if stmts[i].1 == '|' {
            member_is_pipe_run[member_of[i]] = true;
        }
    }

    // The separator that joins each member to the PREVIOUS one — read off
    // the member's first statement, since a pipe run's interior statements
    // never start a new member and so never carry it.
    let mut member_join_sep = vec!['\0'; num_members];
    for i in 0..n_stmts {
        if i == 0 || member_of[i] != member_of[i - 1] {
            member_join_sep[member_of[i]] = stmts[i].1;
        }
    }

    // Group members into and-or CHAINS: a maximal run of members joined
    // consecutively by `&&`/`||`. `and_run_from` and the sticky-unordered
    // flag follow shell.rs's own walk exactly (see `ChainPos`'s doc): reset
    // to the member's own index at every `||`, otherwise carried forward.
    let mut member_chain: Vec<Option<crate::syntax::ChainPos>> = vec![None; num_members];
    let mut member_unordered = member_is_pipe_run.clone();
    {
        let mut chain_counter = 0u32;
        let mut m = 0usize;
        while m < num_members {
            let mut j = m;
            while j + 1 < num_members && matches!(member_join_sep[j + 1], SEP_AND | SEP_OR) {
                j += 1;
            }
            if j > m {
                let id = chain_counter;
                chain_counter += 1;
                let mut idx = 0u32;
                let mut and_run_from = 0u32;
                let mut unordered = false;
                member_chain[m] = Some(crate::syntax::ChainPos { id, idx, and_run_from, negated: false });
                idx += 1;
                for k in (m + 1)..=j {
                    if member_join_sep[k] == SEP_OR {
                        unordered = true;
                        and_run_from = idx;
                    }
                    member_chain[k] = Some(crate::syntax::ChainPos { id, idx, and_run_from, negated: false });
                    member_unordered[k] = member_unordered[k] || unordered;
                    idx += 1;
                }
            }
            m = j + 1;
        }
    }

    let mut counter = 0u32;
    let order_stmt: Vec<Order> = (0..n_stmts)
        .map(|i| {
            if member_unordered[member_of[i]] {
                Order::Unordered
            } else {
                let n = counter;
                counter += 1;
                Order::Seq(n)
            }
        })
        .collect();
    let chain_stmt: Vec<Option<crate::syntax::ChainPos>> =
        (0..n_stmts).map(|i| member_chain[member_of[i]]).collect();

    for (idx, (stmt, _sep)) in stmts.iter().enumerate() {
        let stmt = stmt.as_str();
        let order = order_stmt[idx].clone();
        let chain = chain_stmt[idx];
        let lower = stmt.to_lowercase();

        // keywords at statement start
        for (kw, name) in KEYWORDS {
            if lower == *kw || lower.starts_with(&format!("{kw} ")) || lower.starts_with(&format!("{kw}(")) {
                out.note(name);
            }
        }
        if lower.starts_with("function ") || lower.starts_with("filter ") {
            out.note("function_def");
        }

        // redirects — note the construct AND capture the target, so the file
        // goes through the same [write] rules as everything else.
        //
        // The `>` has to be a real redirect operator. Splitting on the first
        // one anywhere in the statement fabricated targets out of `-f` format
        // strings, `$( … )` expressions and `else { $c > … }` bodies, and those
        // fabricated paths then prompted. Only a `>` at the top level, outside
        // quotes, counts.
        if let Some(cut) = redirect_operator(stmt) {
            out.note("redirect");
            let mut rest = stmt[cut..].trim_start_matches('>').trim().to_string();
            if let Some(r) = rest.strip_prefix('>') {
                rest = r.trim().to_string();
            }
            if let Some(tok) = tokens(&rest).into_iter().next() {
                // `$null` is PowerShell's way of discarding output, the same as
                // `/dev/null`. It is not a file and must not be checked as one.
                if !tok.is_empty() && !tok.trim_end_matches(';').eq_ignore_ascii_case("$null") {
                    out.redirect_targets.push(tok);
                    out.redirect_order.push(order.clone());
                    out.redirect_scope.push(Some(0));
                    // The statement's own chain, which this walk already
                    // computed for the command — a PowerShell redirect is
                    // always part of the statement it is written on, so the
                    // two answers are the same one.
                    out.redirect_chain.push(chain);
                }
            }
        }

        // assignment: `$x = ...`, `$env:X = ...`, `$env:X=1`
        let mut body = stmt;
        if body.starts_with('$') {
            if let Some(eq) = body.find('=') {
                // avoid -eq / == / >= etc.
                let before = &body[..eq];
                let after = &body[eq + 1..];
                if !before.ends_with('-') && !before.ends_with('!') && !before.ends_with('<')
                    && !before.ends_with('>') && !after.starts_with('=')
                {
                    if before.to_lowercase().starts_with("$env:") {
                        out.note("env_assignment");
                    } else {
                        out.note("assignment");
                    }
                    if rhs_is_a_command(after) {
                        body = after.trim();
                    } else {
                        // The value is a value. Not a command. This is the bug
                        // that made the predecessor prompt on `$env:X=1`.
                        //
                        // Record it first: `$sp = "C:/…"` followed by a write to
                        // `$sp/x` is the same pattern bash uses, and without
                        // this the target is reported as unknowable even though
                        // it is stated in plain sight one line earlier.
                        // The prefix is trimmed case-INSENSITIVELY: PowerShell
                        // accepts `$env:`, `$Env:` and `$ENV:` alike, and a
                        // spelling this missed kept its colon, failed the
                        // name check below and was recorded as no assignment
                        // at all.
                        let stripped = before.trim().trim_start_matches('$');
                        let name = stripped
                            .get(..4)
                            .filter(|p| p.eq_ignore_ascii_case("env:"))
                            .map_or(stripped, |_| &stripped[4..])
                            .trim();
                        let value = crate::paths::unquote(after.trim());
                        // A value that itself mentions a variable is still
                        // worth recording: resolution runs to a fixed point, so
                        // `$a = "C:/x"; $b = "$a/y"` resolves, and a leftover
                        // reference correctly ends up unresolved.
                        if !name.is_empty()
                            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                        {
                            out.assignments.push((name.to_string(), Some(value.to_string())));
                        }
                        continue;
                    }
                }
            }
        }

        let body = body.trim();

        // Splatting: `Remove-Item @params`. The parameters — including which
        // paths and whether -Recurse is set — come from a hashtable, so the
        // guards have nothing to match on. The program name is still visible
        // and is still pushed; only the arguments are opaque.
        //
        // `@` starts several unrelated things: `@{…}` a hashtable, `@(…)` an
        // array, `@'…'@` and `@"…"@` here-strings, and `@scope/pkg` is not
        // PowerShell at all — it is an npm package name. A splat is `@` plus a
        // variable name and nothing else. Matching `@` loosely fired on 36 real
        // commands, none of which were splatting.
        if tokens(body).iter().skip(1).any(|t| is_splat(t)) {
            out.note("splatting");
        }

        // call operator
        if body.starts_with('&') {
            out.note("call_operator");
            let rest = body[1..].trim();
            let toks = tokens(rest);
            if let Some(head) = toks.first() {
                // The input source is not POPULATED for this language in this
                // changeset, which is not the same as being unknowable:
                // PowerShell has no input-redirection operator at all (`<` is
                // reserved and unimplemented, and standard input is not wired
                // to its pipeline), so a command's input here can only be a
                // pipe or nothing — both of which keep whatever ask they have.
                // Chain identity (M2.126) is populated from the order/chain
                // attribution above; prefix assignments stay unpopulated —
                // PowerShell's assignment statements have no shell-style
                // `NAME=val cmd` prefix shape.
                out.push_cmd(
                    head.clone(),
                    toks[1..].to_vec(),
                    order.clone(),
                    crate::syntax::InputSource::Unknown,
                    true,
                    chain,
                    vec![],
                    Some(0),
                );
            }
            continue;
        }

        // method call on a variable
        if body.starts_with('$') && body.contains(").") || (body.starts_with('$') && body.contains(".") && body.contains('(')) {
            out.note("method_call");
            continue;
        }
        if body.starts_with('[') {
            // already noted as type_literal above
            continue;
        }
        if body.starts_with('$') {
            continue;
        }

        let toks = tokens(body);
        if let Some(head) = toks.first() {
            if head.is_empty() || is_flag(head) {
                continue;
            }
            // keywords are not commands
            if KEYWORDS.iter().any(|(k, _)| *k == head.to_lowercase())
                || matches!(head.to_lowercase().as_str(), "if" | "else" | "elseif" | "function" | "return" | "param" | "begin" | "process" | "end" | "catch" | "finally")
            {
                continue;
            }
            // Input source and prefix assigns — see the call-operator arm
            // above. Chain identity comes from the order/chain attribution.
            out.push_cmd(
                head.clone(),
                toks[1..].to_vec(),
                order.clone(),
                crate::syntax::InputSource::Unknown,
                true,
                chain,
                vec![],
                Some(0),
            );
        }
    }

    // Look inside script blocks and subexpressions rather than flagging them.
    for block in inner_blocks(src) {
        if let Ok(inner) = parse(&block) {
            out.absorb(inner);
        }
    }

    Ok(out)
}

/// The PowerShell scanner.
pub struct PowerShell;

impl crate::syntax::Scanner for PowerShell {
    fn lang(&self) -> &'static str {
        "powershell"
    }
    fn scan(&self, src: &str) -> Result<crate::syntax::Scan, String> {
        parse(src)
    }
    fn known_constructs(&self) -> &'static [&'static str] {
        KNOWN_CONSTRUCTS
    }
}
