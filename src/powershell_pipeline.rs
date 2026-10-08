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

/// Origin and taint classification for a variable within a PowerShell scriptblock scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VariableOrigin {
    Literal(String),
    DynamicInput { source: String }, // e.g. "Read-Host", "$input", "Get-Content"
    PipelineItem,                    // "$_" or "$PSItem"
    CmdletResult { cmdlet: String }, // e.g. "Get-Process", "Get-ChildItem"
    Environment(String),             // e.g. "$env:TEMP", "$env:PATH"
    TaintedExpression,               // Derived or combined with dynamic untrusted input
}

/// Scoped symbol table tracking variable assignments and dataflow taint within a scriptblock.
#[derive(Debug, Clone)]
pub struct VariableTaintTable {
    variables: std::collections::HashMap<String, VariableOrigin>,
}

impl Default for VariableTaintTable {
    fn default() -> Self {
        Self::new()
    }
}

impl VariableTaintTable {
    pub fn new() -> Self {
        let mut table = Self {
            variables: std::collections::HashMap::new(),
        };
        table.set("$_", VariableOrigin::PipelineItem);
        table.set("$PSItem", VariableOrigin::PipelineItem);
        table
    }

    fn normalize_key(name: &str) -> String {
        let trimmed = name.trim();
        let key = if !trimmed.starts_with('$') {
            format!("${}", trimmed)
        } else {
            trimmed.to_string()
        };
        key.to_lowercase()
    }

    pub fn set(&mut self, name: &str, origin: VariableOrigin) {
        self.variables.insert(Self::normalize_key(name), origin);
    }

    pub fn get(&self, name: &str) -> Option<&VariableOrigin> {
        self.variables.get(&Self::normalize_key(name))
    }

    pub fn is_tainted_or_dynamic(&self, name: &str) -> bool {
        match self.get(name) {
            Some(VariableOrigin::DynamicInput { .. }) | Some(VariableOrigin::TaintedExpression) => true,
            _ => false,
        }
    }
}

/// Parse scriptblock text to extract synthesized guard commands for destructive operations.
pub fn extract_scriptblock_synthesized_commands(script: &str) -> Vec<Cmd> {
    let mut taint_table = VariableTaintTable::new();
    extract_scriptblock_synthesized_commands_with_table(script, &mut taint_table)
}

/// Parse scriptblock text with a scoped variable taint table.
pub fn extract_scriptblock_synthesized_commands_with_table(
    script: &str,
    taint_table: &mut VariableTaintTable,
) -> Vec<Cmd> {
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
                        analyze_statement(&current_stmt, taint_table, &mut out);
                        current_stmt.clear();
                    }
                }
                if brace_depth > 0 {
                    brace_depth -= 1;
                }
            }
            PsToken::Semicolon | PsToken::Newline if brace_depth <= 1 => {
                if !current_stmt.is_empty() {
                    analyze_statement(&current_stmt, taint_table, &mut out);
                    current_stmt.clear();
                }
            }
            _ => {
                current_stmt.push(tok);
            }
        }
    }

    if !current_stmt.is_empty() {
        analyze_statement(&current_stmt, taint_table, &mut out);
    }

    out
}

fn analyze_statement(stmt: &[PsToken], taint_table: &mut VariableTaintTable, out: &mut Vec<Cmd>) {
    // 1. Variable assignments: look for $var = <expr>
    for (idx, tok) in stmt.iter().enumerate() {
        if let PsToken::Other(op) = tok {
            if (op == "=" || op == "+=") && idx > 0 {
                if let PsToken::Variable(var) = &stmt[idx - 1] {
                    let rhs = &stmt[idx + 1..];
                    let origin = classify_rhs_origin(rhs, taint_table);
                    taint_table.set(var, origin);
                }
            }
        }
    }

    // 2. Foreach loops: foreach ($var in $collection_or_cmd)
    if let Some(PsToken::Identifier(head)) = stmt.first() {
        if head.eq_ignore_ascii_case("foreach") {
            let filtered: Vec<&PsToken> = stmt
                .iter()
                .filter(|t| !matches!(t, PsToken::OpenParen | PsToken::CloseParen | PsToken::Newline))
                .collect();
            if filtered.len() >= 4 {
                if let (PsToken::Variable(var), PsToken::Identifier(in_kw), PsToken::Identifier(cmd)) =
                    (filtered[1], filtered[2], filtered[3])
                {
                    if in_kw.eq_ignore_ascii_case("in") {
                        let cmd_lower = cmd.to_lowercase();
                        if cmd_lower.starts_with("get-process") || cmd_lower == "gps" {
                            taint_table.set(var, VariableOrigin::CmdletResult { cmdlet: "Get-Process".into() });
                        } else if cmd_lower.starts_with("get-childitem") || cmd_lower == "gci" || cmd_lower == "dir" || cmd_lower == "ls" {
                            taint_table.set(var, VariableOrigin::CmdletResult { cmdlet: "Get-ChildItem".into() });
                        }
                    }
                }
            }
        }
    }

    // 3. Method invocations: look for MemberAccess followed by OpenParen
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

                let origin = taint_table.get(&var_name);

                if m == "kill" || m == "terminate" {
                    let mut args = vec!["-Id".to_string(), format!("{}.Id", var_name)];
                    if let Some(VariableOrigin::CmdletResult { cmdlet }) = origin {
                        args.push(format!("origin:{cmdlet}"));
                    }
                    out.push(Cmd {
                        head: "Stop-Process".to_string(),
                        args,
                        ..Default::default()
                    });
                } else if m == "delete" || m == "remove" {
                    let mut args = vec![
                        "-Recurse".to_string(),
                        "-Path".to_string(),
                        format!("{}.FullName", var_name),
                    ];
                    if taint_table.is_tainted_or_dynamic(&var_name) {
                        args.push("untrusted_input".to_string());
                    }
                    out.push(Cmd {
                        head: "Remove-Item".to_string(),
                        args,
                        ..Default::default()
                    });
                }
            }
        }
    }

    // 4. Destructive command invocations
    if let Some(first) = stmt.first() {
        if let PsToken::Identifier(head) = first {
            let name_lower = head.to_lowercase();
            if name_lower.starts_with("remove-")
                || name_lower.starts_with("stop-")
                || name_lower.starts_with("set-")
                || matches!(name_lower.as_str(), "rm" | "del" | "erase" | "spps" | "kill")
            {
                let mut args = Vec::new();
                let mut has_untrusted_var = false;

                for tok in &stmt[1..] {
                    match tok {
                        PsToken::Variable(v) => {
                            args.push(v.clone());
                            if taint_table.is_tainted_or_dynamic(v) {
                                has_untrusted_var = true;
                            }
                        }
                        PsToken::Identifier(s)
                        | PsToken::Other(s)
                        | PsToken::StringLiteral(s) => {
                            args.push(s.clone());
                        }
                        _ => {}
                    }
                }

                // If variable passed is untrusted/dynamic, ensure -Recurse is included so path guards evaluate
                if has_untrusted_var && (name_lower.starts_with("remove-") || matches!(name_lower.as_str(), "rm" | "del")) {
                    if !args.iter().any(|a| a.eq_ignore_ascii_case("-recurse")) {
                        args.push("-Recurse".to_string());
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

fn classify_rhs_origin(rhs: &[PsToken], taint_table: &VariableTaintTable) -> VariableOrigin {
    let meaningful: Vec<&PsToken> = rhs
        .iter()
        .filter(|t| !matches!(t, PsToken::OpenParen | PsToken::CloseParen | PsToken::Newline))
        .collect();

    if meaningful.is_empty() {
        return VariableOrigin::Literal(String::new());
    }

    // Check if right-hand side is a command invocation
    if let Some(PsToken::Identifier(cmd)) = meaningful.first() {
        let cmd_lower = cmd.to_lowercase();
        if cmd_lower == "read-host" || cmd_lower == "get-content" || cmd_lower == "gc" {
            return VariableOrigin::DynamicInput { source: (*cmd).clone() };
        } else if cmd_lower.starts_with("get-process") || cmd_lower == "gps" {
            return VariableOrigin::CmdletResult { cmdlet: "Get-Process".into() };
        } else if cmd_lower.starts_with("get-childitem") || cmd_lower == "gci" || cmd_lower == "dir" || cmd_lower == "ls" {
            return VariableOrigin::CmdletResult { cmdlet: "Get-ChildItem".into() };
        } else if cmd_lower.starts_with("get-") {
            return VariableOrigin::CmdletResult { cmdlet: (*cmd).clone() };
        } else {
            return VariableOrigin::DynamicInput { source: (*cmd).clone() };
        }
    }

    // Check if right-hand side references other variables
    for tok in &meaningful {
        if let PsToken::Variable(v) = tok {
            let v_lower = v.to_lowercase();
            if v_lower.starts_with("$env:") {
                return VariableOrigin::Environment((*v).clone());
            } else if taint_table.is_tainted_or_dynamic(v) {
                return VariableOrigin::TaintedExpression;
            } else if let Some(orig) = taint_table.get(v) {
                return orig.clone();
            }
        }
    }

    // Pure string literal
    if meaningful.iter().all(|t| matches!(t, PsToken::StringLiteral(_))) {
        let s: String = meaningful
            .iter()
            .filter_map(|t| match t {
                PsToken::StringLiteral(s) => Some(s.clone()),
                _ => None,
            })
            .collect();
        return VariableOrigin::Literal(s);
    }

    VariableOrigin::Literal("value".to_string())
}

/// Inspect a list of parsed PowerShell commands to extract member mutations
/// and classify pipeline stages.
pub fn analyze_pipeline_stages(cmds: &[Cmd]) -> Vec<Cmd> {
    let mut out = Vec::new();
    let mut taint_table = VariableTaintTable::new();

    for cmd in cmds {
        out.push(cmd.clone());

        let head_lower = cmd.head.to_lowercase();

        // Dataflow origin propagation across pipeline stages
        if head_lower == "read-host" || head_lower == "get-content" || head_lower == "gc" {
            taint_table.set("$_", VariableOrigin::DynamicInput { source: cmd.head.clone() });
        } else if head_lower == "get-process" || head_lower == "gps" {
            taint_table.set("$_", VariableOrigin::CmdletResult { cmdlet: "Get-Process".into() });
        } else if head_lower == "get-childitem" || head_lower == "gci" || head_lower == "dir" || head_lower == "ls" {
            taint_table.set("$_", VariableOrigin::CmdletResult { cmdlet: "Get-ChildItem".into() });
        }

        // Check if command is an iterator or filter cmdlet
        let is_filter = matches!(head_lower.as_str(), "where-object" | "where" | "?");
        let is_iterator = matches!(head_lower.as_str(), "foreach-object" | "foreach" | "%");

        if is_filter || is_iterator {
            for arg in &cmd.args {
                let synthesized = extract_scriptblock_synthesized_commands_with_table(arg, &mut taint_table);
                out.extend(synthesized);
            }
        } else {
            // Also inspect scriptblock arguments in commands like `& { ... }` or multi-statement blocks
            for arg in &cmd.args {
                if arg.trim_start().starts_with('{') && arg.trim_end().ends_with('}') {
                    let synthesized = extract_scriptblock_synthesized_commands_with_table(arg, &mut taint_table);
                    out.extend(synthesized);
                }
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
