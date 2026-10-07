//! Dynamic Script Block Analysis for Complex PowerShell Pipelines (M5.2 & M6.5).
//!
//! Provides pure-Rust lexical tokenization and AST scriptblock inspection of
//! PowerShell pipelines and scriptblocks passed to cmdlets (`Where-Object`,
//! `ForEach-Object`, `Select-Object`).
//!
//! Replaces naive substring heuristic matching with a strongly typed lexical
//! tokenizer (`PsLexer`, `PsTokenStream`) and structural statement walker that
//! guarantees strict string-literal immunity and accurate member mutation detection.

use crate::syntax::Cmd;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PipelineStageType {
    Source,
    Filter { is_pure: bool },
    Iterator,
    Sink,
}

#[derive(Debug, Clone)]
pub struct PipelineStage {
    pub stage_type: PipelineStageType,
    pub command: Cmd,
    pub synthesized_commands: Vec<Cmd>,
}

/// Strongly typed lexical tokens for PowerShell scripts and scriptblocks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PsToken {
    Identifier(String),
    Variable(String),        // e.g. "$_", "$proc", "$item"
    MemberAccess(String),    // e.g. ".Kill", ".Delete"
    StringLiteral(String),   // Quoted strings '...' or "..." (immunity against substring false positives)
    OpenParen,
    CloseParen,
    OpenBrace,               // "{" scriptblock boundary
    CloseBrace,              // "}" scriptblock boundary
    Semicolon,
    Newline,
    Pipe,                    // "|"
    Other(String),
}

impl PsToken {
    pub fn member_name(&self) -> Option<&str> {
        match self {
            PsToken::MemberAccess(s) => Some(s.trim_start_matches('.')),
            _ => None,
        }
    }
}

/// Pure-Rust lexical tokenizer for PowerShell scriptblocks.
pub struct PsLexer<'a> {
    _input: &'a str,
    chars: Vec<(usize, char)>,
    cursor: usize,
}

impl<'a> PsLexer<'a> {
    pub fn new(input: &'a str) -> Self {
        Self {
            _input: input,
            chars: input.char_indices().collect(),
            cursor: 0,
        }
    }

    pub fn tokenize(input: &'a str) -> Vec<PsToken> {
        let mut lexer = Self::new(input);
        lexer.run()
    }

    fn peek_char(&self, offset: usize) -> Option<char> {
        self.chars.get(self.cursor + offset).map(|(_, c)| *c)
    }

    fn run(&mut self) -> Vec<PsToken> {
        let mut tokens = Vec::new();

        while self.cursor < self.chars.len() {
            let c = self.chars[self.cursor].1;

            // 1. Whitespace (spaces, tabs, carriage returns)
            if c == ' ' || c == '\t' || c == '\r' {
                self.cursor += 1;
                continue;
            }

            // 2. Newline
            if c == '\n' {
                self.cursor += 1;
                tokens.push(PsToken::Newline);
                continue;
            }

            // 3. Comments: multi-line <# ... #> or single-line # ...
            if c == '<' && self.peek_char(1) == Some('#') {
                self.cursor += 2;
                while self.cursor < self.chars.len() {
                    if self.chars[self.cursor].1 == '#' && self.peek_char(1) == Some('>') {
                        self.cursor += 2;
                        break;
                    }
                    self.cursor += 1;
                }
                continue;
            }

            if c == '#' {
                while self.cursor < self.chars.len() && self.chars[self.cursor].1 != '\n' {
                    self.cursor += 1;
                }
                continue;
            }

            // 4. Here-strings: @' ... '@ or @" ... "@
            if c == '@' && (self.peek_char(1) == Some('\'') || self.peek_char(1) == Some('"')) {
                let quote = self.peek_char(1).unwrap();
                self.cursor += 2;
                let mut content = String::new();
                while self.cursor < self.chars.len() {
                    if self.chars[self.cursor].1 == '\n'
                        && self.peek_char(1) == Some(quote)
                        && self.peek_char(2) == Some('@')
                    {
                        self.cursor += 3;
                        break;
                    }
                    content.push(self.chars[self.cursor].1);
                    self.cursor += 1;
                }
                tokens.push(PsToken::StringLiteral(content));
                continue;
            }

            // 5. Quoted string literals: '...' or "..."
            if c == '\'' {
                self.cursor += 1;
                let mut content = String::new();
                while self.cursor < self.chars.len() {
                    let ch = self.chars[self.cursor].1;
                    if ch == '\'' {
                        if self.peek_char(1) == Some('\'') {
                            content.push('\'');
                            self.cursor += 2;
                        } else {
                            self.cursor += 1;
                            break;
                        }
                    } else {
                        content.push(ch);
                        self.cursor += 1;
                    }
                }
                tokens.push(PsToken::StringLiteral(content));
                continue;
            }

            if c == '"' {
                self.cursor += 1;
                let mut content = String::new();
                while self.cursor < self.chars.len() {
                    let ch = self.chars[self.cursor].1;
                    if ch == '"' {
                        if self.peek_char(1) == Some('"') {
                            content.push('"');
                            self.cursor += 2;
                        } else {
                            self.cursor += 1;
                            break;
                        }
                    } else if ch == '`' && self.peek_char(1) == Some('"') {
                        content.push('"');
                        self.cursor += 2;
                    } else {
                        content.push(ch);
                        self.cursor += 1;
                    }
                }
                tokens.push(PsToken::StringLiteral(content));
                continue;
            }

            // 6. Delimiters
            if c == '(' {
                self.cursor += 1;
                tokens.push(PsToken::OpenParen);
                continue;
            }
            if c == ')' {
                self.cursor += 1;
                tokens.push(PsToken::CloseParen);
                continue;
            }
            if c == '{' {
                self.cursor += 1;
                tokens.push(PsToken::OpenBrace);
                continue;
            }
            if c == '}' {
                self.cursor += 1;
                tokens.push(PsToken::CloseBrace);
                continue;
            }
            if c == ';' {
                self.cursor += 1;
                tokens.push(PsToken::Semicolon);
                continue;
            }
            if c == '|' {
                self.cursor += 1;
                tokens.push(PsToken::Pipe);
                continue;
            }

            // 7. Variables: starts with $
            if c == '$' {
                self.cursor += 1;
                if self.cursor < self.chars.len() && self.chars[self.cursor].1 == '{' {
                    self.cursor += 1;
                    let mut var_name = String::from("${");
                    while self.cursor < self.chars.len() {
                        let ch = self.chars[self.cursor].1;
                        var_name.push(ch);
                        self.cursor += 1;
                        if ch == '}' {
                            break;
                        }
                    }
                    tokens.push(PsToken::Variable(var_name));
                    continue;
                } else if self.cursor < self.chars.len() && is_var_char(self.chars[self.cursor].1) {
                    let mut var_name = String::from("$");
                    while self.cursor < self.chars.len() && is_var_char(self.chars[self.cursor].1) {
                        var_name.push(self.chars[self.cursor].1);
                        self.cursor += 1;
                    }
                    tokens.push(PsToken::Variable(var_name));
                    continue;
                } else {
                    tokens.push(PsToken::Other("$".to_string()));
                    continue;
                }
            }

            // 8. Member access or dot: .
            if c == '.' {
                if self.peek_char(1).is_some_and(|ch| ch.is_ascii_digit()) {
                    let mut num = String::from(".");
                    self.cursor += 1;
                    while self.cursor < self.chars.len() && self.chars[self.cursor].1.is_ascii_digit() {
                        num.push(self.chars[self.cursor].1);
                        self.cursor += 1;
                    }
                    tokens.push(PsToken::Other(num));
                    continue;
                } else if self.peek_char(1) == Some('.') {
                    self.cursor += 2;
                    tokens.push(PsToken::Other("..".to_string()));
                    continue;
                } else if self.peek_char(1) == Some('/') || self.peek_char(1) == Some('\\') {
                    self.cursor += 1;
                    tokens.push(PsToken::Other(".".to_string()));
                    continue;
                } else {
                    // Check if followed by identifier (with optional whitespace)
                    let mut lookahead = 1;
                    while let Some(ch) = self.peek_char(lookahead) {
                        if ch == ' ' || ch == '\t' {
                            lookahead += 1;
                        } else {
                            break;
                        }
                    }

                    if let Some(ch) = self.peek_char(lookahead) {
                        if is_ident_start(ch) {
                            self.cursor += lookahead;
                            let mut member = String::from(".");
                            while self.cursor < self.chars.len() && is_ident_char(self.chars[self.cursor].1) {
                                member.push(self.chars[self.cursor].1);
                                self.cursor += 1;
                            }
                            tokens.push(PsToken::MemberAccess(member));
                            continue;
                        }
                    }

                    self.cursor += 1;
                    tokens.push(PsToken::Other(".".to_string()));
                    continue;
                }
            }

            // 9. Flags / operators starting with -
            if c == '-' && self.peek_char(1).is_some_and(|ch| ch.is_alphanumeric() || ch == '_') {
                let mut op = String::new();
                while self.cursor < self.chars.len()
                    && (self.chars[self.cursor].1.is_alphanumeric()
                        || self.chars[self.cursor].1 == '_'
                        || self.chars[self.cursor].1 == '-')
                {
                    op.push(self.chars[self.cursor].1);
                    self.cursor += 1;
                }
                tokens.push(PsToken::Other(op));
                continue;
            }

            // 10. Identifiers / Command names
            if is_ident_start(c) {
                let mut ident = String::new();
                while self.cursor < self.chars.len() && is_ident_char(self.chars[self.cursor].1) {
                    ident.push(self.chars[self.cursor].1);
                    self.cursor += 1;
                }
                tokens.push(PsToken::Identifier(ident));
                continue;
            }

            // 11. Numbers
            if c.is_ascii_digit() {
                let mut num = String::new();
                while self.cursor < self.chars.len()
                    && (self.chars[self.cursor].1.is_ascii_digit() || self.chars[self.cursor].1 == '.')
                {
                    num.push(self.chars[self.cursor].1);
                    self.cursor += 1;
                }
                tokens.push(PsToken::Other(num));
                continue;
            }

            // 12. Fallback single character
            tokens.push(PsToken::Other(c.to_string()));
            self.cursor += 1;
        }

        tokens
    }
}

fn is_var_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_' || c == ':' || c == '?' || c == '^'
}

fn is_ident_start(c: char) -> bool {
    c.is_alphabetic() || c == '_' || c == '\\' || c == '/'
}

fn is_ident_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_' || c == '-' || c == ':' || c == '\\' || c == '/'
}

/// Token stream for navigating and parsing PowerShell token sequences.
#[derive(Debug, Clone)]
pub struct PsTokenStream {
    tokens: Vec<PsToken>,
    cursor: usize,
}

impl PsTokenStream {
    pub fn new(tokens: Vec<PsToken>) -> Self {
        Self { tokens, cursor: 0 }
    }

    pub fn from_source(source: &str) -> Self {
        let tokens = PsLexer::tokenize(source);
        Self::new(tokens)
    }

    pub fn peek(&self) -> Option<&PsToken> {
        self.tokens.get(self.cursor)
    }

    pub fn peek_ahead(&self, n: usize) -> Option<&PsToken> {
        self.tokens.get(self.cursor + n)
    }

    pub fn next_token(&mut self) -> Option<PsToken> {
        if self.cursor < self.tokens.len() {
            let tok = self.tokens[self.cursor].clone();
            self.cursor += 1;
            Some(tok)
        } else {
            None
        }
    }

    pub fn is_empty(&self) -> bool {
        self.cursor >= self.tokens.len()
    }

    pub fn remaining(&self) -> &[PsToken] {
        if self.cursor < self.tokens.len() {
            &self.tokens[self.cursor..]
        } else {
            &[]
        }
    }

    pub fn all_tokens(&self) -> &[PsToken] {
        &self.tokens
    }
}

/// Parse scriptblock text to extract synthesized guard commands for destructive operations.
pub fn extract_scriptblock_synthesized_commands(script: &str) -> Vec<Cmd> {
    let mut out = Vec::new();
    let tokens = PsLexer::tokenize(script);

    let mut current_stmt: Vec<PsToken> = Vec::new();
    let mut brace_depth = 0usize;

    for tok in tokens {
        match &tok {
            PsToken::OpenBrace => {
                brace_depth += 1;
                if brace_depth > 1 {
                    current_stmt.push(tok);
                }
            }
            PsToken::CloseBrace => {
                if brace_depth > 1 {
                    current_stmt.push(tok);
                } else if brace_depth == 1 {
                    if !current_stmt.is_empty() {
                        analyze_statement(&current_stmt, &mut out);
                        current_stmt.clear();
                    }
                }
                if brace_depth > 0 {
                    brace_depth -= 1;
                }
            }
            PsToken::Semicolon | PsToken::Newline if brace_depth <= 1 => {
                if !current_stmt.is_empty() {
                    analyze_statement(&current_stmt, &mut out);
                    current_stmt.clear();
                }
            }
            _ => {
                current_stmt.push(tok);
            }
        }
    }

    if !current_stmt.is_empty() {
        analyze_statement(&current_stmt, &mut out);
    }

    out
}

fn analyze_statement(stmt: &[PsToken], out: &mut Vec<Cmd>) {
    // 1. Method invocations: look for MemberAccess followed by OpenParen
    for i in 0..stmt.len() {
        if let PsToken::MemberAccess(member) = &stmt[i] {
            if let Some(PsToken::OpenParen) = stmt.get(i + 1) {
                let m = member.trim_start_matches('.').to_lowercase();

                let mut var_name = "$_".to_string();
                if i > 0 {
                    let mut back = i;
                    while back > 0 {
                        back -= 1;
                        match &stmt[back] {
                            PsToken::Variable(v) => {
                                var_name = v.clone();
                                break;
                            }
                            PsToken::MemberAccess(_) => continue,
                            _ => break,
                        }
                    }
                }

                if m == "kill" || m == "terminate" {
                    out.push(Cmd {
                        head: "Stop-Process".to_string(),
                        args: vec!["-Id".to_string(), format!("{}.Id", var_name)],
                        ..Default::default()
                    });
                } else if m == "delete" || m == "remove" {
                    out.push(Cmd {
                        head: "Remove-Item".to_string(),
                        args: vec![
                            "-Recurse".to_string(),
                            "-Path".to_string(),
                            format!("{}.FullName", var_name),
                        ],
                        ..Default::default()
                    });
                }
            }
        }
    }

    // 2. Destructive command invocations
    if let Some(first) = stmt.first() {
        if let PsToken::Identifier(head) = first {
            let name_lower = head.to_lowercase();
            if name_lower.starts_with("remove-")
                || name_lower.starts_with("stop-")
                || name_lower.starts_with("set-")
                || matches!(name_lower.as_str(), "rm" | "del" | "erase" | "spps" | "kill")
            {
                let mut args = Vec::new();
                for tok in &stmt[1..] {
                    match tok {
                        PsToken::Identifier(s)
                        | PsToken::Other(s)
                        | PsToken::Variable(s)
                        | PsToken::StringLiteral(s) => {
                            args.push(s.clone());
                        }
                        _ => {}
                    }
                }
                out.push(Cmd {
                    head: head.clone(),
                    args,
                    ..Default::default()
                });
            }
        }
    }
}

/// Inspect a list of parsed PowerShell commands to extract member mutations
/// and classify pipeline stages.
pub fn analyze_pipeline_stages(cmds: &[Cmd]) -> Vec<Cmd> {
    let mut out = Vec::new();

    for cmd in cmds {
        out.push(cmd.clone());

        // Check if command is an iterator or filter cmdlet
        let head_lower = cmd.head.to_lowercase();
        let is_filter = matches!(head_lower.as_str(), "where-object" | "where" | "?");
        let is_iterator = matches!(head_lower.as_str(), "foreach-object" | "foreach" | "%");

        if is_filter || is_iterator {
            for arg in &cmd.args {
                let synthesized = extract_scriptblock_synthesized_commands(arg);
                out.extend(synthesized);
            }
        }
    }

    out
}

/// Returns true if a scriptblock text represents a pure read-only filter predicate.
pub fn is_pure_predicate_block(script: &str) -> bool {
    let tokens = PsLexer::tokenize(script);
    let mut meaningful = Vec::new();
    for tok in tokens {
        match tok {
            PsToken::OpenBrace | PsToken::CloseBrace | PsToken::Newline => {}
            other => meaningful.push(other),
        }
    }

    if meaningful.is_empty() {
        return true;
    }

    // Multiple statements separated by semicolon -> not a pure predicate
    if meaningful.iter().any(|t| matches!(t, PsToken::Semicolon)) {
        return false;
    }

    // Assignment (=) outside string literals -> not a pure predicate
    for tok in &meaningful {
        if let PsToken::Other(op) = tok {
            if op == "=" {
                return false;
            }
        }
    }

    // Destructive/mutating method calls (e.g. .Kill(), .Delete(), .Remove(), .Terminate())
    for (i, tok) in meaningful.iter().enumerate() {
        if let PsToken::MemberAccess(member) = tok {
            if let Some(next) = meaningful.get(i + 1) {
                if matches!(next, PsToken::OpenParen) {
                    let m = member.trim_start_matches('.').to_lowercase();
                    if matches!(m.as_str(), "kill" | "delete" | "remove" | "terminate" | "dispose") {
                        return false;
                    }
                }
            }
        }
    }

    // Mutating command invocations (e.g. Remove-Item, Set-Item, Stop-Process, del, rm, spps, etc.)
    for tok in &meaningful {
        if let PsToken::Identifier(ident) = tok {
            let id_lower = ident.to_lowercase();
            if id_lower.starts_with("remove-")
                || id_lower.starts_with("set-")
                || id_lower.starts_with("stop-")
                || id_lower.starts_with("new-")
                || id_lower.starts_with("clear-")
                || id_lower.starts_with("restart-")
                || id_lower.starts_with("kill-")
                || matches!(id_lower.as_str(), "rm" | "del" | "erase" | "spps" | "kill")
            {
                return false;
            }
        }
    }

    true
}
