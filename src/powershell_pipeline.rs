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
    SplatVariable(String),   // e.g. "@params", "@splatArgs"
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

            // 7b. Splat variables: starts with @ followed by variable characters (e.g. @params)
            if c == '@' && self.peek_char(1).is_some_and(is_var_char) {
                self.cursor += 1;
                let mut splat_name = String::from("@");
                while self.cursor < self.chars.len() && is_var_char(self.chars[self.cursor].1) {
                    splat_name.push(self.chars[self.cursor].1);
                    self.cursor += 1;
                }
                tokens.push(PsToken::SplatVariable(splat_name));
                continue;
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
    splat_args: std::collections::HashMap<String, Vec<String>>,
    /// `$PSDefaultParameterValues` bindings keyed by normalized `"cmdlet_pattern:parameter_name"`
    /// mapping to `(raw_cmdlet_pattern, param_name, rendered_value, origin)`.
    default_param_values: std::collections::HashMap<String, (String, String, String, VariableOrigin)>,
    /// Variable-to-class-type bindings (`$var` -> `"ClassName"` lowercased) for instance method dispatch.
    class_instances: std::collections::HashMap<String, String>,
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
            splat_args: std::collections::HashMap::new(),
            default_param_values: std::collections::HashMap::new(),
            class_instances: std::collections::HashMap::new(),
        };
        table.set("$_", VariableOrigin::PipelineItem);
        table.set("$PSItem", VariableOrigin::PipelineItem);
        table
    }

    fn normalize_key(name: &str) -> String {
        let trimmed = name.trim();
        let key = if let Some(rest) = trimmed.strip_prefix('@') {
            format!("${rest}")
        } else if !trimmed.starts_with('$') {
            format!("${trimmed}")
        } else {
            trimmed.to_string()
        };
        let lower = key.to_lowercase();
        let unbraced = if let Some(after_dollar) = lower.strip_prefix("${") {
            if let Some(close_idx) = after_dollar.find('}') {
                format!(
                    "${}{}",
                    &after_dollar[..close_idx],
                    &after_dollar[close_idx + 1..]
                )
            } else {
                lower
            }
        } else {
            lower
        };
        if let Some(rest) = unbraced.strip_prefix("$local:") {
            format!("${rest}")
        } else if let Some(rest) = unbraced.strip_prefix("$private:") {
            format!("${rest}")
        } else {
            unbraced
        }
    }

    pub fn set(&mut self, name: &str, origin: VariableOrigin) {
        self.variables.insert(Self::normalize_key(name), origin);
    }

    pub fn set_class_instance(&mut self, var_name: &str, class_name: &str) {
        self.class_instances.insert(
            Self::normalize_key(var_name),
            class_name.trim().to_ascii_lowercase(),
        );
    }

    pub fn get_class_instance(&self, var_name: &str) -> Option<&String> {
        let key = Self::normalize_key(var_name);
        if let Some(cls) = self.class_instances.get(&key) {
            return Some(cls);
        }
        if let Some(bare) = key.strip_prefix("$using:") {
            if let Some(cls) = self.class_instances.get(&format!("${bare}")) {
                return Some(cls);
            }
            if let Some(cls) = self.class_instances.get(&format!("$script:{bare}")) {
                return Some(cls);
            }
            if let Some(cls) = self.class_instances.get(&format!("$global:{bare}")) {
                return Some(cls);
            }
        } else if !key.contains(':') && key.starts_with('$') {
            let bare = &key[1..];
            if let Some(cls) = self.class_instances.get(&format!("$script:{bare}")) {
                return Some(cls);
            }
            if let Some(cls) = self.class_instances.get(&format!("$global:{bare}")) {
                return Some(cls);
            }
        }
        None
    }

    pub fn set_default_param(
        &mut self,
        cmd_pattern: &str,
        param_name: &str,
        rendered_val: String,
        origin: VariableOrigin,
    ) {
        let cmd_pat = cmd_pattern.trim();
        let param = param_name.trim().trim_start_matches('-');
        if cmd_pat.is_empty() || param.is_empty() {
            return;
        }
        let norm_key = format!(
            "{}:{}",
            cmd_pat.to_ascii_lowercase(),
            param.to_ascii_lowercase()
        );
        self.default_param_values.insert(
            norm_key,
            (
                cmd_pat.to_string(),
                param.to_string(),
                rendered_val,
                origin,
            ),
        );
    }

    /// Return all `$PSDefaultParameterValues` entries whose cmdlet pattern (exact or wildcard)
    /// matches `cmd_head`.
    pub fn matching_default_params(
        &self,
        cmd_head: &str,
    ) -> Vec<(String, String, VariableOrigin)> {
        let mut matches = Vec::new();
        for (cmd_pat, param, rendered_val, origin) in self.default_param_values.values() {
            let is_match = if cmd_pat.contains('*') || cmd_pat.contains('?') || cmd_pat.contains('[')
            {
                let rx_str = wildcard_to_regex(cmd_pat);
                regex::RegexBuilder::new(&rx_str)
                    .case_insensitive(true)
                    .build()
                    .map(|rx| rx.is_match(cmd_head))
                    .unwrap_or(false)
            } else {
                cmd_pat.eq_ignore_ascii_case(cmd_head)
            };
            if is_match {
                matches.push((param.clone(), rendered_val.clone(), origin.clone()));
            }
        }
        matches.sort_by(|a, b| a.0.cmp(&b.0));
        matches
    }

    pub fn set_splat_args(&mut self, name: &str, args: Vec<String>) {
        self.splat_args.insert(Self::normalize_key(name), args);
    }

    pub fn get_splat_args(&self, name: &str) -> Option<&Vec<String>> {
        let key = Self::normalize_key(name);
        if let Some(args) = self.splat_args.get(&key) {
            return Some(args);
        }
        if let Some(bare) = key.strip_prefix("$using:") {
            if let Some(args) = self.splat_args.get(&format!("${bare}")) {
                return Some(args);
            }
            if let Some(args) = self.splat_args.get(&format!("$script:{bare}")) {
                return Some(args);
            }
            if let Some(args) = self.splat_args.get(&format!("$global:{bare}")) {
                return Some(args);
            }
        } else if !key.contains(':') && key.starts_with('$') {
            let bare = &key[1..];
            if let Some(args) = self.splat_args.get(&format!("$script:{bare}")) {
                return Some(args);
            }
            if let Some(args) = self.splat_args.get(&format!("$global:{bare}")) {
                return Some(args);
            }
        }
        None
    }

    pub fn get(&self, name: &str) -> Option<&VariableOrigin> {
        let key = Self::normalize_key(name);
        if let Some(orig) = self.variables.get(&key) {
            return Some(orig);
        }
        if let Some(bare) = key.strip_prefix("$using:") {
            if let Some(orig) = self.variables.get(&format!("${bare}")) {
                return Some(orig);
            }
            if let Some(orig) = self.variables.get(&format!("$script:{bare}")) {
                return Some(orig);
            }
            if let Some(orig) = self.variables.get(&format!("$global:{bare}")) {
                return Some(orig);
            }
        } else if !key.contains(':') && key.starts_with('$') {
            let bare = &key[1..];
            if let Some(orig) = self.variables.get(&format!("$script:{bare}")) {
                return Some(orig);
            }
            if let Some(orig) = self.variables.get(&format!("$global:{bare}")) {
                return Some(orig);
            }
        }
        None
    }

    /// Propagate `$script:`, `$global:`, `$this.*`, and `$PSDefaultParameterValues` origins from a
    /// callee scope back into the caller scope while keeping function-local (`$x`, `$local:x`, `$private:x`)
    /// mutations isolated.
    pub fn propagate_cross_scope_from(&mut self, callee: &VariableTaintTable) {
        for (k, v) in &callee.variables {
            if k.starts_with("$script:") || k.starts_with("$global:") || k.starts_with("$this.") {
                self.variables.insert(k.clone(), v.clone());
            }
        }
        for (k, v) in &callee.splat_args {
            if k.starts_with("$script:") || k.starts_with("$global:") || k.starts_with("$this.") {
                self.splat_args.insert(k.clone(), v.clone());
            }
        }
        for (k, v) in &callee.default_param_values {
            self.default_param_values.insert(k.clone(), v.clone());
        }
        for (k, v) in &callee.class_instances {
            if k.starts_with("$script:") || k.starts_with("$global:") || k.starts_with("$this.") {
                self.class_instances.insert(k.clone(), v.clone());
            }
        }
    }

    pub fn is_tainted_or_dynamic(&self, name: &str) -> bool {
        let key = Self::normalize_key(name);
        if key.starts_with("$env:") || key.starts_with("$using:env:") {
            return true;
        }
        match self.get(name) {
            Some(VariableOrigin::DynamicInput { .. })
            | Some(VariableOrigin::TaintedExpression)
            | Some(VariableOrigin::Environment(_)) => true,
            _ => false,
        }
    }
}

pub const MAX_INTERPROCEDURAL_CALL_DEPTH: usize = 8;

/// Static boolean evaluation result for a PowerShell branch condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StaticTruthValue {
    True,
    False,
    Unknown,
}

/// Directed edge between basic blocks in a PowerShell Control Flow Graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfgEdge {
    pub from: usize,
    pub to: usize,
    pub label: String,
    pub traversable: bool,
}

/// Basic block node in a PowerShell Control Flow Graph.
#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub id: usize,
    pub label: String,
    pub statements: Vec<Vec<PsToken>>,
    pub reachable: bool,
    pub terminated_early: bool,
}

/// Inter-procedural local function summary (parameters + body tokens).
#[derive(Debug, Clone)]
pub struct PsFunctionSummary {
    pub name: String,
    pub params: Vec<String>,
    pub body_tokens: Vec<PsToken>,
}

/// Scoped table of locally declared PowerShell functions.
#[derive(Debug, Clone, Default)]
pub struct FunctionSummaryTable {
    functions: std::collections::HashMap<String, PsFunctionSummary>,
}

impl FunctionSummaryTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, summary: PsFunctionSummary) {
        self.functions
            .insert(summary.name.to_lowercase(), summary);
    }

    pub fn get(&self, name: &str) -> Option<&PsFunctionSummary> {
        self.functions.get(&name.to_lowercase())
    }

    pub fn len(&self) -> usize {
        self.functions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.functions.is_empty()
    }
}

/// Control Flow Graph (CFG) representation for a PowerShell script or scriptblock.
#[derive(Debug, Clone, Default)]
pub struct PsControlFlowGraph {
    pub blocks: Vec<BasicBlock>,
    pub edges: Vec<CfgEdge>,
    pub functions: FunctionSummaryTable,
    pub synthesized_commands: Vec<Cmd>,
    active_loop_jump: Option<String>,
}

impl PsControlFlowGraph {
    /// Construct and evaluate the inter-procedural Control Flow Graph for a PowerShell script or scriptblock.
    pub fn build(script: &str) -> Self {
        let mut taint_table = VariableTaintTable::new();
        Self::build_with_taint(script, &mut taint_table)
    }

    pub fn build_with_taint(script: &str, taint_table: &mut VariableTaintTable) -> Self {
        let mut cfg = Self::default();
        let entry_id = cfg.new_block("entry", true);
        let tokens = strip_outer_braces(PsLexer::tokenize(script));
        cfg.walk_tokens(&tokens, entry_id, true, taint_table, 0);
        cfg
    }

    pub fn reachable_block_count(&self) -> usize {
        self.blocks.iter().filter(|b| b.reachable).count()
    }

    pub fn unreachable_block_count(&self) -> usize {
        self.blocks.iter().filter(|b| !b.reachable).count()
    }

    fn new_block(&mut self, label: impl Into<String>, reachable: bool) -> usize {
        let id = self.blocks.len();
        self.blocks.push(BasicBlock {
            id,
            label: label.into(),
            statements: Vec::new(),
            reachable,
            terminated_early: false,
        });
        id
    }

    fn add_edge(&mut self, from: usize, to: usize, label: impl Into<String>, traversable: bool) {
        self.edges.push(CfgEdge {
            from,
            to,
            label: label.into(),
            traversable,
        });
    }

    fn walk_tokens(
        &mut self,
        tokens: &[PsToken],
        mut current_block: usize,
        mut block_reachable: bool,
        taint_table: &mut VariableTaintTable,
        call_depth: usize,
    ) -> usize {
        let mut trap_continues_on_throw = scope_has_trap_continue(tokens);
        let mut i = 0;
        while i < tokens.len() {
            // Skip leading separators
            if matches!(tokens[i], PsToken::Semicolon | PsToken::Newline) {
                i += 1;
                continue;
            }

            // 0. Labeled or unlabeled loop: `[:label] foreach|while|for|do ...`
            if let Some(next_idx) = self.handle_loop_statement(
                tokens,
                i,
                &mut current_block,
                block_reachable,
                taint_table,
                call_depth,
            ) {
                block_reachable = self.blocks[current_block].reachable
                    && !self.blocks[current_block].terminated_early;
                i = next_idx;
                continue;
            }

            if let PsToken::Identifier(kw) = &tokens[i] {
                // 1. Local function definition: `function <Name> [([param(...)])] { <body> }`
                if kw.eq_ignore_ascii_case("function") {
                    if let Some((summary, next_idx)) = parse_function_declaration(tokens, i) {
                        self.functions.insert(summary);
                        i = next_idx;
                        continue;
                    }
                }

                // 1b. PowerShell class definition: `class <ClassName> [: <Base>] { <members & methods> }`
                if kw.eq_ignore_ascii_case("class") {
                    if let Some((methods, next_idx)) = parse_class_declaration(tokens, i) {
                        for method in methods {
                            self.functions.insert(method);
                        }
                        i = next_idx;
                        continue;
                    }
                }

                // 2. Conditional `if (<cond>) { <then> } [elseif (<cond>) { ... }] [else { <else> }]`
                if kw.eq_ignore_ascii_case("if") {
                    if let Some(next_idx) = self.handle_if_chain(
                        tokens,
                        i,
                        &mut current_block,
                        block_reachable,
                        taint_table,
                        call_depth,
                    ) {
                        block_reachable = self.blocks[current_block].reachable;
                        i = next_idx;
                        continue;
                    }
                }

                // 3. `switch [-Regex|-Wildcard|-Exact|-CaseSensitive] (<expr>) { <case> { <body> } ... default { <body> } }`
                if kw.eq_ignore_ascii_case("switch") {
                    if let Some(next_idx) = self.handle_switch_statement(
                        tokens,
                        i,
                        &mut current_block,
                        block_reachable,
                        taint_table,
                        call_depth,
                    ) {
                        block_reachable = self.blocks[current_block].reachable;
                        i = next_idx;
                        continue;
                    }
                }

                // 4. `try { <body> } [catch [...] { <body> }]* [finally { <body> }]`
                if kw.eq_ignore_ascii_case("try") {
                    if let Some(next_idx) = self.handle_try_catch_finally(
                        tokens,
                        i,
                        &mut current_block,
                        block_reachable,
                        taint_table,
                        call_depth,
                    ) {
                        block_reachable = self.blocks[current_block].reachable;
                        i = next_idx;
                        continue;
                    }
                }

                // 4b. `trap [[ExceptionType]] { <body> }`
                if kw.eq_ignore_ascii_case("trap") {
                    if let Some((next_idx, continues)) = self.handle_trap_statement(
                        tokens,
                        i,
                        current_block,
                        block_reachable,
                        taint_table,
                        call_depth,
                    ) {
                        trap_continues_on_throw = continues;
                        i = next_idx;
                        continue;
                    }
                }

                // 5. Named scriptblock stages: `begin { ... }`, `process { ... }`, `end { ... }`
                if kw.eq_ignore_ascii_case("begin")
                    || kw.eq_ignore_ascii_case("process")
                    || kw.eq_ignore_ascii_case("end")
                {
                    if let Some((stage_body, next_idx)) =
                        extract_delimited_group(tokens, i + 1, false)
                    {
                        let stage_label = format!("{}_stage", kw.to_ascii_lowercase());
                        let stage_id = self.new_block(&stage_label, block_reachable);
                        self.add_edge(current_block, stage_id, stage_label, block_reachable);
                        let end_b = self.walk_tokens(
                            &stage_body,
                            stage_id,
                            block_reachable,
                            taint_table,
                            call_depth,
                        );
                        current_block = end_b;
                        block_reachable = self.blocks[current_block].reachable
                            && !self.blocks[current_block].terminated_early;
                        i = next_idx;
                        continue;
                    }
                }
            }

            // 6. Collect a single top-level statement up to `;` or `\n` (respecting nested braces/parens)
            let (stmt, next_idx) = collect_next_statement(tokens, i);
            i = next_idx;
            if stmt.is_empty() {
                continue;
            }

            // Check if current block already hit an unconditional return/exit/throw/break/continue
            if self.blocks[current_block].terminated_early {
                let dead_id = self.new_block("unreachable_after_exit", false);
                self.add_edge(current_block, dead_id, "dead_fallthrough", false);
                current_block = dead_id;
                block_reachable = false;
            }

            self.blocks[current_block].statements.push(stmt.clone());

            if block_reachable {
                if let Some(jump_target) = parse_loop_jump_statement(&stmt) {
                    if let Some(lbl) = jump_target {
                        self.active_loop_jump = Some(lbl);
                    }
                    self.blocks[current_block].terminated_early = true;
                } else if stmt_is_throw(&stmt) {
                    if !trap_continues_on_throw {
                        self.blocks[current_block].terminated_early = true;
                    }
                } else if is_unconditional_terminator(&stmt) {
                    self.blocks[current_block].terminated_early = true;
                } else {
                    self.analyze_statement_interprocedural(&stmt, taint_table, call_depth);
                }
            }
        }
        current_block
    }

    fn handle_if_chain(
        &mut self,
        tokens: &[PsToken],
        start_idx: usize,
        current_block: &mut usize,
        parent_reachable: bool,
        taint_table: &mut VariableTaintTable,
        call_depth: usize,
    ) -> Option<usize> {
        let mut cursor = start_idx;
        let mut branches: Vec<(Option<Vec<PsToken>>, Vec<PsToken>)> = Vec::new();

        while cursor < tokens.len() {
            while cursor < tokens.len() && matches!(tokens[cursor], PsToken::Newline | PsToken::Semicolon) {
                cursor += 1;
            }
            if cursor >= tokens.len() {
                break;
            }

            if let PsToken::Identifier(kw) = &tokens[cursor] {
                if kw.eq_ignore_ascii_case("if") && branches.is_empty() {
                    cursor += 1;
                    let (cond, after_cond) = extract_delimited_group(tokens, cursor, true)?;
                    let (body, after_body) = extract_delimited_group(tokens, after_cond, false)?;
                    branches.push((Some(cond), body));
                    cursor = after_body;
                    continue;
                } else if kw.eq_ignore_ascii_case("elseif") && !branches.is_empty() {
                    cursor += 1;
                    let (cond, after_cond) = extract_delimited_group(tokens, cursor, true)?;
                    let (body, after_body) = extract_delimited_group(tokens, after_cond, false)?;
                    branches.push((Some(cond), body));
                    cursor = after_body;
                    continue;
                } else if kw.eq_ignore_ascii_case("else") && !branches.is_empty() {
                    cursor += 1;
                    // Check for `else if` two-word spelling
                    let mut look = cursor;
                    while look < tokens.len() && matches!(tokens[look], PsToken::Newline) {
                        look += 1;
                    }
                    if let Some(PsToken::Identifier(next_kw)) = tokens.get(look) {
                        if next_kw.eq_ignore_ascii_case("if") {
                            let (cond, after_cond) = extract_delimited_group(tokens, look + 1, true)?;
                            let (body, after_body) = extract_delimited_group(tokens, after_cond, false)?;
                            branches.push((Some(cond), body));
                            cursor = after_body;
                            continue;
                        }
                    }
                    let (body, after_body) = extract_delimited_group(tokens, cursor, false)?;
                    branches.push((None, body));
                    cursor = after_body;
                    break;
                }
            }
            break;
        }

        if branches.is_empty() {
            return None;
        }

        let branch_origin = *current_block;
        let mut prior_definitely_taken = false;
        let mut any_branch_can_fallthrough = false;
        let has_explicit_else = branches.iter().any(|(c, _)| c.is_none());
        let mut branch_end_blocks = Vec::new();
        let mut accumulated_taint: Option<VariableTaintTable> = None;

        for (idx, (cond_opt, body_tokens)) in branches.into_iter().enumerate() {
            let (this_reachable, edge_label, definitely_true) = if !parent_reachable || prior_definitely_taken {
                (false, "pruned".to_string(), false)
            } else if let Some(ref cond) = cond_opt {
                match evaluate_static_condition(cond, taint_table) {
                    StaticTruthValue::True => (true, "cond == true".to_string(), true),
                    StaticTruthValue::False => (false, "cond == false (dead)".to_string(), false),
                    StaticTruthValue::Unknown => (true, "cond == unknown".to_string(), false),
                }
            } else {
                (true, "else".to_string(), true)
            };

            if definitely_true {
                prior_definitely_taken = true;
            }

            let b_label = if cond_opt.is_some() {
                format!("if_branch_{idx}")
            } else {
                "else_branch".to_string()
            };
            let b_id = self.new_block(b_label, this_reachable);
            self.add_edge(branch_origin, b_id, edge_label, this_reachable);

            let mut branch_taint = taint_table.clone();
            let end_b = self.walk_tokens(&body_tokens, b_id, this_reachable, &mut branch_taint, call_depth);
            if this_reachable {
                if !self.blocks[end_b].terminated_early {
                    any_branch_can_fallthrough = true;
                    match &mut accumulated_taint {
                        Some(acc) => acc.merge_from(&branch_taint),
                        None => accumulated_taint = Some(branch_taint),
                    }
                }
            }
            branch_end_blocks.push((end_b, this_reachable && !self.blocks[end_b].terminated_early));
        }

        if let Some(acc) = accumulated_taint {
            if prior_definitely_taken || has_explicit_else {
                *taint_table = acc;
            } else {
                taint_table.merge_from(&acc);
            }
        }

        if !has_explicit_else && !prior_definitely_taken && parent_reachable {
            any_branch_can_fallthrough = true;
        }

        let join_reachable = parent_reachable && any_branch_can_fallthrough;
        let join_id = self.new_block("if_join", join_reachable);
        for (end_b, falls_through) in branch_end_blocks {
            self.add_edge(end_b, join_id, "join", falls_through);
        }
        if !has_explicit_else {
            self.add_edge(
                branch_origin,
                join_id,
                "implicit_else",
                parent_reachable && !prior_definitely_taken,
            );
        }

        *current_block = join_id;
        Some(cursor)
    }

    fn handle_switch_statement(
        &mut self,
        tokens: &[PsToken],
        start_idx: usize,
        current_block: &mut usize,
        parent_reachable: bool,
        taint_table: &mut VariableTaintTable,
        call_depth: usize,
    ) -> Option<usize> {
        let mut cursor = start_idx + 1;
        let mut match_mode = SwitchMatchMode::Exact;
        let mut is_file_switch = false;
        let mut case_sensitive = false;

        // Parse optional switch flags: -Regex, -Wildcard, -Exact, -CaseSensitive, -File
        while cursor < tokens.len() {
            while cursor < tokens.len() && matches!(tokens[cursor], PsToken::Newline) {
                cursor += 1;
            }
            if let Some(PsToken::Other(flag)) = tokens.get(cursor) {
                if flag.starts_with('-') {
                    if flag.eq_ignore_ascii_case("-regex") {
                        match_mode = SwitchMatchMode::Regex;
                    } else if flag.eq_ignore_ascii_case("-wildcard") {
                        match_mode = SwitchMatchMode::Wildcard;
                    } else if flag.eq_ignore_ascii_case("-exact") {
                        match_mode = SwitchMatchMode::Exact;
                    } else if flag.eq_ignore_ascii_case("-casesensitive") {
                        case_sensitive = true;
                    } else if flag.eq_ignore_ascii_case("-file") {
                        is_file_switch = true;
                    }
                    cursor += 1;
                    continue;
                }
            }
            break;
        }

        while cursor < tokens.len() && matches!(tokens[cursor], PsToken::Newline) {
            cursor += 1;
        }
        if cursor >= tokens.len() {
            return None;
        }

        let (cond_tokens, after_cond) = if tokens.get(cursor) == Some(&PsToken::OpenParen) {
            extract_delimited_group(tokens, cursor, true)?
        } else {
            let mut cond = Vec::new();
            let mut look = cursor;
            while look < tokens.len() && tokens[look] != PsToken::OpenBrace {
                if !matches!(tokens[look], PsToken::Newline) {
                    cond.push(tokens[look].clone());
                }
                look += 1;
            }
            if cond.is_empty() || look >= tokens.len() {
                return None;
            }
            (cond, look)
        };

        let (switch_body, after_body) = extract_delimited_group(tokens, after_cond, false)?;
        let arms = parse_switch_arms(&switch_body);
        if arms.is_empty() {
            return Some(after_body);
        }

        let filtered_cond: Vec<&PsToken> = cond_tokens
            .iter()
            .filter(|t| !matches!(t, PsToken::Newline | PsToken::OpenParen | PsToken::CloseParen))
            .collect();
        let selector_scalar = if !is_file_switch && filtered_cond.len() == 1 {
            resolve_static_scalar(filtered_cond[0], taint_table)
        } else {
            None
        };

        let branch_origin = *current_block;
        let has_default = arms
            .iter()
            .any(|(p, _)| matches!(p, SwitchCasePattern::Default));
        let mut any_definitely_matched = false;
        let mut any_unknown_case = selector_scalar.is_none();
        let mut stopped_by_break_or_exit = false;
        let mut any_arm_falls_through = false;
        let mut accumulated_taint: Option<VariableTaintTable> = None;
        let mut arm_end_blocks = Vec::new();

        for (idx, (pattern, arm_body)) in arms.into_iter().enumerate() {
            let (this_reachable, edge_label, definitely_matched) =
                if !parent_reachable || stopped_by_break_or_exit {
                    (false, "pruned".to_string(), false)
                } else {
                    match pattern {
                        SwitchCasePattern::Token(ref case_tok) => {
                            match (&selector_scalar, resolve_static_scalar(case_tok, taint_table)) {
                                (Some(sel), Some(case_val)) => {
                                    match evaluate_switch_case_match(
                                        match_mode,
                                        case_sensitive,
                                        sel,
                                        &case_val,
                                    ) {
                                        Some(true) => (true, format!("case == {case_val}"), true),
                                        Some(false) => {
                                            (false, format!("case != {case_val} (dead)"), false)
                                        }
                                        None => {
                                            any_unknown_case = true;
                                            (true, "case == invalid_pattern".to_string(), false)
                                        }
                                    }
                                }
                                _ => {
                                    any_unknown_case = true;
                                    (true, "case == unknown".to_string(), false)
                                }
                            }
                        }
                        SwitchCasePattern::Dynamic => {
                            any_unknown_case = true;
                            (true, "case == dynamic".to_string(), false)
                        }
                        SwitchCasePattern::Default => {
                            if any_definitely_matched && !any_unknown_case {
                                (false, "default (dead)".to_string(), false)
                            } else {
                                (true, "default".to_string(), !any_unknown_case)
                            }
                        }
                    }
                };

            if definitely_matched {
                any_definitely_matched = true;
                if arm_has_top_level_terminator(&arm_body) {
                    stopped_by_break_or_exit = true;
                }
            }

            let b_id = self.new_block(format!("switch_arm_{idx}"), this_reachable);
            self.add_edge(branch_origin, b_id, edge_label, this_reachable);

            let mut arm_taint = taint_table.clone();
            let end_b =
                self.walk_tokens(&arm_body, b_id, this_reachable, &mut arm_taint, call_depth);

            let exited_script = arm_exits_function(&arm_body);
            let reaches_join = this_reachable && !exited_script;
            if reaches_join {
                any_arm_falls_through = true;
                match &mut accumulated_taint {
                    Some(acc) => acc.merge_from(&arm_taint),
                    None => accumulated_taint = Some(arm_taint),
                }
            }
            arm_end_blocks.push((end_b, reaches_join));
        }

        if let Some(acc) = accumulated_taint {
            if (any_definitely_matched || has_default) && !any_unknown_case {
                *taint_table = acc;
            } else {
                taint_table.merge_from(&acc);
            }
        }

        if !has_default && !any_definitely_matched && parent_reachable {
            any_arm_falls_through = true;
        }

        let join_reachable = parent_reachable && any_arm_falls_through;
        let join_id = self.new_block("switch_join", join_reachable);
        for (end_b, falls_through) in arm_end_blocks {
            self.add_edge(end_b, join_id, "join", falls_through);
        }
        if !has_default {
            self.add_edge(
                branch_origin,
                join_id,
                "implicit_default",
                parent_reachable && !any_definitely_matched,
            );
        }

        *current_block = join_id;
        Some(after_body)
    }

    fn handle_try_catch_finally(
        &mut self,
        tokens: &[PsToken],
        start_idx: usize,
        current_block: &mut usize,
        parent_reachable: bool,
        taint_table: &mut VariableTaintTable,
        call_depth: usize,
    ) -> Option<usize> {
        let (try_body, mut cursor) = extract_delimited_group(tokens, start_idx + 1, false)?;
        let mut catch_blocks: Vec<Vec<PsToken>> = Vec::new();
        let mut finally_block: Option<Vec<PsToken>> = None;

        while cursor < tokens.len() {
            while cursor < tokens.len()
                && matches!(tokens[cursor], PsToken::Newline | PsToken::Semicolon)
            {
                cursor += 1;
            }
            if cursor >= tokens.len() {
                break;
            }
            if let PsToken::Identifier(kw) = &tokens[cursor] {
                if kw.eq_ignore_ascii_case("catch") {
                    cursor += 1;
                    // Skip optional [ExceptionType] annotations before `{`
                    while cursor < tokens.len() && tokens[cursor] != PsToken::OpenBrace {
                        cursor += 1;
                    }
                    let (catch_body, after_catch) =
                        extract_delimited_group(tokens, cursor, false)?;
                    catch_blocks.push(catch_body);
                    cursor = after_catch;
                    continue;
                } else if kw.eq_ignore_ascii_case("finally") {
                    cursor += 1;
                    let (fin_body, after_fin) = extract_delimited_group(tokens, cursor, false)?;
                    finally_block = Some(fin_body);
                    cursor = after_fin;
                    break;
                }
            }
            break;
        }

        if catch_blocks.is_empty() && finally_block.is_none() {
            return None;
        }

        let origin_block = *current_block;
        let try_id = self.new_block("try_block", parent_reachable);
        self.add_edge(origin_block, try_id, "try", parent_reachable);

        let mut try_taint = taint_table.clone();
        let try_end =
            self.walk_tokens(&try_body, try_id, parent_reachable, &mut try_taint, call_depth);
        let try_completed = parent_reachable && !self.blocks[try_end].terminated_early;

        if parent_reachable {
            *taint_table = try_taint.clone();
        }

        let can_throw = block_can_throw(&try_body);
        let catch_reachable = parent_reachable && can_throw;
        let mut catch_ends = Vec::new();
        let mut any_catch_completed = false;

        for (idx, catch_body) in catch_blocks.into_iter().enumerate() {
            let catch_id = self.new_block(format!("catch_block_{idx}"), catch_reachable);
            self.add_edge(try_id, catch_id, "exception", catch_reachable);

            let mut catch_taint = taint_table.clone();
            // Inside `catch`, `$_` / `$PSItem` is the dynamic ErrorRecord exception object
            catch_taint.set(
                "$_",
                VariableOrigin::DynamicInput {
                    source: "catch".into(),
                },
            );
            catch_taint.set(
                "$PSItem",
                VariableOrigin::DynamicInput {
                    source: "catch".into(),
                },
            );

            let c_end = self.walk_tokens(
                &catch_body,
                catch_id,
                catch_reachable,
                &mut catch_taint,
                call_depth,
            );
            let c_completed = catch_reachable && !self.blocks[c_end].terminated_early;
            if c_completed {
                any_catch_completed = true;
                if try_completed {
                    taint_table.merge_from(&catch_taint);
                } else {
                    *taint_table = catch_taint;
                }
            }
            catch_ends.push((c_end, c_completed));
        }

        let mut finally_terminated = false;
        let last_before_join = if let Some(fin_body) = finally_block {
            // `finally` always runs if `try` was entered (`parent_reachable`), even on return/throw
            let fin_id = self.new_block("finally_block", parent_reachable);
            self.add_edge(try_end, fin_id, "finally", parent_reachable);
            for &(c_end, _) in &catch_ends {
                self.add_edge(c_end, fin_id, "finally", catch_reachable);
            }
            let fin_end =
                self.walk_tokens(&fin_body, fin_id, parent_reachable, taint_table, call_depth);
            finally_terminated = self.blocks[fin_end].terminated_early;
            Some(fin_end)
        } else {
            None
        };

        let join_reachable = (try_completed || any_catch_completed) && !finally_terminated;
        let join_id = self.new_block("try_join", join_reachable);
        if let Some(fin_end) = last_before_join {
            self.add_edge(fin_end, join_id, "join", join_reachable);
        } else {
            self.add_edge(try_end, join_id, "join", try_completed);
            for (c_end, c_completed) in catch_ends {
                self.add_edge(c_end, join_id, "join", c_completed);
            }
        }

        *current_block = join_id;
        Some(cursor)
    }

    fn handle_trap_statement(
        &mut self,
        tokens: &[PsToken],
        start_idx: usize,
        origin_block: usize,
        parent_reachable: bool,
        taint_table: &mut VariableTaintTable,
        call_depth: usize,
    ) -> Option<(usize, bool)> {
        let mut cursor = start_idx + 1;
        while cursor < tokens.len() && tokens[cursor] != PsToken::OpenBrace {
            cursor += 1;
        }
        if cursor >= tokens.len() {
            return None;
        }
        let (trap_body, after_trap) = extract_delimited_group(tokens, cursor, false)?;
        let can_throw = scope_can_throw(tokens);
        let trap_reachable = parent_reachable && can_throw;

        let trap_id = self.new_block("trap_handler", trap_reachable);
        self.add_edge(origin_block, trap_id, "trap_exception", trap_reachable);

        let mut trap_taint = taint_table.clone();
        trap_taint.set(
            "$_",
            VariableOrigin::DynamicInput {
                source: "trap".into(),
            },
        );
        trap_taint.set(
            "$PSItem",
            VariableOrigin::DynamicInput {
                source: "trap".into(),
            },
        );

        let _ = self.walk_tokens(
            &trap_body,
            trap_id,
            trap_reachable,
            &mut trap_taint,
            call_depth,
        );
        if trap_reachable {
            taint_table.merge_from(&trap_taint);
            taint_table.propagate_cross_scope_from(&trap_taint);
        }

        let continues = trap_body_continues(&trap_body);
        Some((after_trap, continues))
    }

    fn handle_loop_statement(
        &mut self,
        tokens: &[PsToken],
        start_idx: usize,
        current_block: &mut usize,
        parent_reachable: bool,
        taint_table: &mut VariableTaintTable,
        call_depth: usize,
    ) -> Option<usize> {
        let (label_opt, mut cursor) = match_loop_label_prefix(tokens, start_idx);
        while cursor < tokens.len() && matches!(tokens[cursor], PsToken::Newline) {
            cursor += 1;
        }
        let PsToken::Identifier(kw) = tokens.get(cursor)? else {
            return None;
        };
        let kw_lower = kw.to_ascii_lowercase();
        if !matches!(kw_lower.as_str(), "foreach" | "while" | "for" | "do") {
            return None;
        }

        let mut loop_taint = taint_table.clone();
        let mut effective_parent_reachable = parent_reachable;
        if self.blocks[*current_block].terminated_early {
            let dead_id = self.new_block("unreachable_after_exit", false);
            self.add_edge(*current_block, dead_id, "dead_fallthrough", false);
            *current_block = dead_id;
            effective_parent_reachable = false;
        }
        let mut body_reachable = effective_parent_reachable;

        let (body_tokens, after_loop) = match kw_lower.as_str() {
            "foreach" => {
                // Only match `foreach ($item in ...)` loop statement (not `foreach { ... }` cmdlet)
                let mut look = cursor + 1;
                while look < tokens.len() && matches!(tokens[look], PsToken::Newline) {
                    look += 1;
                }
                if tokens.get(look) != Some(&PsToken::OpenParen) {
                    return None;
                }
                let (header_tokens, after_paren) = extract_delimited_group(tokens, look, true)?;
                let (body, after_body) = extract_delimited_group(tokens, after_paren, false)?;
                bind_foreach_loop_variable(&header_tokens, &mut loop_taint);
                (body, after_body)
            }
            "while" => {
                let (cond_tokens, after_paren) =
                    extract_delimited_group(tokens, cursor + 1, true)?;
                let (body, after_body) = extract_delimited_group(tokens, after_paren, false)?;
                if evaluate_static_condition(&cond_tokens, taint_table) == StaticTruthValue::False {
                    body_reachable = false;
                }
                (body, after_body)
            }
            "for" => {
                let (_header_tokens, after_paren) =
                    extract_delimited_group(tokens, cursor + 1, true)?;
                let (body, after_body) = extract_delimited_group(tokens, after_paren, false)?;
                (body, after_body)
            }
            "do" => {
                let (body, mut after_body) = extract_delimited_group(tokens, cursor + 1, false)?;
                let mut look = after_body;
                while look < tokens.len() && matches!(tokens[look], PsToken::Newline) {
                    look += 1;
                }
                if let Some(PsToken::Identifier(tail_kw)) = tokens.get(look) {
                    if tail_kw.eq_ignore_ascii_case("while")
                        || tail_kw.eq_ignore_ascii_case("until")
                    {
                        if let Some((_cond, after_cond)) =
                            extract_delimited_group(tokens, look + 1, true)
                        {
                            after_body = after_cond;
                        }
                    }
                }
                (body, after_body)
            }
            _ => return None,
        };

        let loop_block_name = match &label_opt {
            Some(l) => format!("loop_{l}"),
            None => format!("{kw_lower}_loop"),
        };
        let loop_id = self.new_block(loop_block_name, body_reachable);
        self.add_edge(*current_block, loop_id, "loop_enter", body_reachable);

        let body_end = self.walk_tokens(
            &body_tokens,
            loop_id,
            body_reachable,
            &mut loop_taint,
            call_depth,
        );

        if body_reachable {
            taint_table.merge_from(&loop_taint);
            taint_table.propagate_cross_scope_from(&loop_taint);
        }

        if let Some(target) = self.active_loop_jump.clone() {
            if label_opt
                .as_deref()
                .is_some_and(|l| l.eq_ignore_ascii_case(&target))
            {
                self.active_loop_jump = None;
                let join_id = self.new_block("loop_join", effective_parent_reachable);
                self.add_edge(
                    body_end,
                    join_id,
                    format!("jump_{target}"),
                    effective_parent_reachable,
                );
                *current_block = join_id;
            } else {
                let join_id = self.new_block("loop_join", false);
                self.blocks[join_id].terminated_early = true;
                self.add_edge(body_end, join_id, "jump_outer_pruned", false);
                *current_block = join_id;
            }
        } else {
            let join_id = self.new_block("loop_join", effective_parent_reachable);
            self.add_edge(body_end, join_id, "loop_exit", effective_parent_reachable);
            *current_block = join_id;
        }

        Some(after_loop)
    }

    fn analyze_statement_interprocedural(
        &mut self,
        stmt: &[PsToken],
        taint_table: &mut VariableTaintTable,
        call_depth: usize,
    ) {
        analyze_statement(stmt, taint_table, &mut self.synthesized_commands);

        // Check if statement invokes a locally declared function, dynamic call (`& $fn`), or class instance method
        if call_depth < MAX_INTERPROCEDURAL_CALL_DEPTH {
            // 1. Direct or dynamic function call
            let resolved_call: Option<(String, &[PsToken])> = match stmt.first() {
                Some(PsToken::Identifier(head)) => Some((head.clone(), &stmt[1..])),
                Some(PsToken::Other(op)) if op == "&" || op == "." => match stmt.get(1) {
                    Some(PsToken::StringLiteral(s)) | Some(PsToken::Identifier(s)) => {
                        Some((s.clone(), stmt.get(2..).unwrap_or(&[])))
                    }
                    Some(PsToken::Variable(v)) => match taint_table.get(v) {
                        Some(VariableOrigin::Literal(lit)) if !lit.is_empty() && lit != "value" => {
                            Some((lit.clone(), stmt.get(2..).unwrap_or(&[])))
                        }
                        _ => None,
                    },
                    _ => None,
                },
                _ => None,
            };

            if let Some((head, rest_tokens)) = resolved_call {
                if let Some(func) = self.functions.get(&head).cloned() {
                    let mut callee_taint = taint_table.clone();
                    // Bind positional arguments to declared function parameters
                    let arg_tokens: Vec<&PsToken> = rest_tokens
                        .iter()
                        .filter(|t| {
                            !matches!(
                                t,
                                PsToken::OpenParen | PsToken::CloseParen | PsToken::Newline
                            )
                        })
                        .collect();
                    for (param_idx, param_name) in func.params.iter().enumerate() {
                        if let Some(arg_tok) = arg_tokens.get(param_idx) {
                            let single = [(*arg_tok).clone()];
                            let orig = classify_rhs_origin(&single, taint_table);
                            callee_taint.set(param_name, orig);
                        }
                    }
                    let call_block = self.new_block(format!("call_{}", func.name), true);
                    self.walk_tokens(
                        &func.body_tokens,
                        call_block,
                        true,
                        &mut callee_taint,
                        call_depth + 1,
                    );
                    taint_table.propagate_cross_scope_from(&callee_taint);
                }
            }

            // 2. Class instance method invocations: `$instance.Method($arg1, $arg2)`
            let mut idx = 0;
            while idx + 2 < stmt.len() {
                if let (
                    PsToken::Variable(inst_var),
                    PsToken::MemberAccess(member),
                    PsToken::OpenParen,
                ) = (&stmt[idx], &stmt[idx + 1], &stmt[idx + 2])
                {
                    let method_name = member.trim_start_matches('.');
                    let method_summary = taint_table
                        .get_class_instance(inst_var)
                        .and_then(|cls| self.functions.get(&format!("{cls}::{method_name}")))
                        .or_else(|| self.functions.get(&format!("method::{method_name}")))
                        .cloned();

                    if let Some(method_func) = method_summary {
                        if let Some((call_args, after_paren)) =
                            extract_delimited_group(stmt, idx + 2, true)
                        {
                            let mut callee_taint = taint_table.clone();
                            // Alias any existing `$inst_var.<prop>` entries into `$this.<prop>` for method body
                            let inst_prefix = format!("{}.", VariableTaintTable::normalize_key(inst_var));
                            let prop_snapshots: Vec<(String, VariableOrigin)> = callee_taint
                                .variables
                                .iter()
                                .filter_map(|(k, v)| {
                                    k.strip_prefix(&inst_prefix)
                                        .map(|prop| (format!("$this.{prop}"), v.clone()))
                                })
                                .collect();
                            for (this_prop, orig) in prop_snapshots {
                                callee_taint.set(&this_prop, orig);
                            }

                            // Split comma-separated argument expressions inside `(...)`
                            let arg_exprs = split_comma_separated_tokens(&call_args);
                            for (param_idx, param_name) in method_func.params.iter().enumerate() {
                                if let Some(arg_slice) = arg_exprs.get(param_idx) {
                                    let orig = classify_rhs_origin(arg_slice, taint_table);
                                    callee_taint.set(param_name, orig);
                                }
                            }

                            let call_block =
                                self.new_block(format!("method_{}", method_func.name), true);
                            self.walk_tokens(
                                &method_func.body_tokens,
                                call_block,
                                true,
                                &mut callee_taint,
                                call_depth + 1,
                            );
                            taint_table.propagate_cross_scope_from(&callee_taint);

                            // Copy any `$this.<prop>` mutations back onto `$inst_var.<prop>`
                            let this_updates: Vec<(String, VariableOrigin)> = taint_table
                                .variables
                                .iter()
                                .filter_map(|(k, v)| {
                                    k.strip_prefix("$this.").map(|prop| {
                                        (
                                            format!(
                                                "{}.{prop}",
                                                VariableTaintTable::normalize_key(inst_var)
                                            ),
                                            v.clone(),
                                        )
                                    })
                                })
                                .collect();
                            for (inst_prop, orig) in this_updates {
                                taint_table.set(&inst_prop, orig);
                            }

                            idx = after_paren;
                            continue;
                        }
                    }
                }
                idx += 1;
            }
        }
    }
}

fn match_loop_label_prefix(tokens: &[PsToken], idx: usize) -> (Option<String>, usize) {
    if let Some(PsToken::Other(s)) = tokens.get(idx) {
        if s == ":" {
            if let Some(PsToken::Identifier(lbl)) = tokens.get(idx + 1) {
                return (Some(lbl.clone()), idx + 2);
            }
        }
    }
    if let Some(PsToken::Identifier(s)) = tokens.get(idx) {
        if let Some(lbl) = s.strip_prefix(':') {
            if !lbl.is_empty() {
                return (Some(lbl.to_string()), idx + 1);
            }
        }
    }
    (None, idx)
}

fn bind_foreach_loop_variable(header_tokens: &[PsToken], taint_table: &mut VariableTaintTable) {
    let filtered: Vec<&PsToken> = header_tokens
        .iter()
        .filter(|t| !matches!(t, PsToken::Newline))
        .collect();
    if let Some(in_pos) = filtered.iter().position(|t| {
        matches!(t, PsToken::Identifier(kw) if kw.eq_ignore_ascii_case("in"))
    }) {
        if in_pos > 0 && in_pos + 1 < filtered.len() {
            if let PsToken::Variable(var) = filtered[in_pos - 1] {
                let rhs: Vec<PsToken> =
                    filtered[in_pos + 1..].iter().map(|t| (*t).clone()).collect();
                let orig = classify_rhs_origin(&rhs, taint_table);
                taint_table.set(var, orig);
            }
        }
    }
}

fn parse_loop_jump_statement(stmt: &[PsToken]) -> Option<Option<String>> {
    let Some(PsToken::Identifier(head)) = stmt.first() else {
        return None;
    };
    if !head.eq_ignore_ascii_case("break") && !head.eq_ignore_ascii_case("continue") {
        return None;
    }
    let rest: Vec<&PsToken> = stmt[1..]
        .iter()
        .filter(|t| !matches!(t, PsToken::Newline))
        .collect();
    if rest.is_empty() {
        return Some(None);
    }
    if let Some(PsToken::Other(colon)) = rest.first() {
        if colon == ":" {
            if let Some(PsToken::Identifier(lbl)) = rest.get(1) {
                return Some(Some(lbl.clone()));
            }
        }
    }
    if let Some(PsToken::Identifier(lbl)) = rest.first() {
        return Some(Some(lbl.trim_start_matches(':').to_string()));
    }
    Some(None)
}

fn stmt_is_throw(stmt: &[PsToken]) -> bool {
    matches!(
        stmt.first(),
        Some(PsToken::Identifier(kw)) if kw.eq_ignore_ascii_case("throw")
    )
}

fn trap_body_continues(trap_body: &[PsToken]) -> bool {
    let mut i = 0;
    let mut continues = false;
    while i < trap_body.len() {
        if matches!(trap_body[i], PsToken::Semicolon | PsToken::Newline) {
            i += 1;
            continue;
        }
        let (stmt, next_i) = collect_next_statement(trap_body, i);
        i = next_i;
        if let Some(PsToken::Identifier(first)) = stmt.first() {
            if first.eq_ignore_ascii_case("continue") {
                continues = true;
            } else if first.eq_ignore_ascii_case("break") {
                continues = false;
            }
        }
    }
    continues
}

fn scope_has_trap_continue(tokens: &[PsToken]) -> bool {
    let mut i = 0;
    let mut continues = false;
    while i < tokens.len() {
        if matches!(tokens[i], PsToken::Semicolon | PsToken::Newline) {
            i += 1;
            continue;
        }
        if let PsToken::Identifier(kw) = &tokens[i] {
            if kw.eq_ignore_ascii_case("trap") {
                let mut cursor = i + 1;
                while cursor < tokens.len() && tokens[cursor] != PsToken::OpenBrace {
                    cursor += 1;
                }
                if let Some((trap_body, after_trap)) = extract_delimited_group(tokens, cursor, false)
                {
                    if trap_body_continues(&trap_body) {
                        continues = true;
                    }
                    i = after_trap;
                    continue;
                }
            }
        }
        let (_, next_i) = collect_next_statement(tokens, i);
        i = next_i;
    }
    continues
}

fn scope_can_throw(tokens: &[PsToken]) -> bool {
    let mut non_trap = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        if matches!(tokens[i], PsToken::Semicolon | PsToken::Newline) {
            i += 1;
            continue;
        }
        if let PsToken::Identifier(kw) = &tokens[i] {
            if kw.eq_ignore_ascii_case("trap") {
                let mut cursor = i + 1;
                while cursor < tokens.len() && tokens[cursor] != PsToken::OpenBrace {
                    cursor += 1;
                }
                if let Some((_, after_trap)) = extract_delimited_group(tokens, cursor, false) {
                    i = after_trap;
                    continue;
                }
            }
        }
        let (stmt, next_i) = collect_next_statement(tokens, i);
        i = next_i;
        non_trap.extend(stmt);
        non_trap.push(PsToken::Semicolon);
    }
    block_can_throw(&non_trap)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SwitchMatchMode {
    Exact,
    Wildcard,
    Regex,
}

fn evaluate_switch_case_match(
    mode: SwitchMatchMode,
    case_sensitive: bool,
    selector: &str,
    pattern: &str,
) -> Option<bool> {
    match mode {
        SwitchMatchMode::Exact => {
            if case_sensitive {
                Some(selector == pattern)
            } else {
                Some(selector.eq_ignore_ascii_case(pattern))
            }
        }
        SwitchMatchMode::Wildcard => {
            let regex_str = wildcard_to_regex(pattern);
            let built = regex::RegexBuilder::new(&regex_str)
                .case_insensitive(!case_sensitive)
                .build()
                .ok()?;
            Some(built.is_match(selector))
        }
        SwitchMatchMode::Regex => {
            let built = regex::RegexBuilder::new(pattern)
                .case_insensitive(!case_sensitive)
                .build()
                .ok()?;
            Some(built.is_match(selector))
        }
    }
}

fn wildcard_to_regex(pat: &str) -> String {
    let mut out = String::from("^");
    let chars: Vec<char> = pat.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '`' if i + 1 < chars.len() => {
                out.push_str(&regex::escape(&chars[i + 1].to_string()));
                i += 2;
            }
            '*' => {
                out.push_str(".*");
                i += 1;
            }
            '?' => {
                out.push('.');
                i += 1;
            }
            '[' => {
                if let Some(rel_close) = chars[i + 1..].iter().position(|&c| c == ']') {
                    out.push('[');
                    for &ch in &chars[i + 1..=i + 1 + rel_close] {
                        out.push(ch);
                    }
                    i += rel_close + 2;
                } else {
                    out.push_str("\\[");
                    i += 1;
                }
            }
            c => {
                out.push_str(&regex::escape(&c.to_string()));
                i += 1;
            }
        }
    }
    out.push('$');
    out
}

#[derive(Debug, Clone)]
enum SwitchCasePattern {
    Token(PsToken),
    Dynamic,
    Default,
}

fn parse_switch_arms(body_tokens: &[PsToken]) -> Vec<(SwitchCasePattern, Vec<PsToken>)> {
    let mut cursor = 0;
    let mut arms = Vec::new();
    while cursor < body_tokens.len() {
        while cursor < body_tokens.len()
            && matches!(body_tokens[cursor], PsToken::Newline | PsToken::Semicolon)
        {
            cursor += 1;
        }
        if cursor >= body_tokens.len() {
            break;
        }
        match &body_tokens[cursor] {
            PsToken::Identifier(kw) if kw.eq_ignore_ascii_case("default") => {
                if let Some((arm_body, after_arm)) =
                    extract_delimited_group(body_tokens, cursor + 1, false)
                {
                    arms.push((SwitchCasePattern::Default, arm_body));
                    cursor = after_arm;
                    continue;
                }
            }
            PsToken::OpenBrace => {
                if let Some((_pred, after_pred)) =
                    extract_delimited_group(body_tokens, cursor, false)
                {
                    if let Some((arm_body, after_arm)) =
                        extract_delimited_group(body_tokens, after_pred, false)
                    {
                        arms.push((SwitchCasePattern::Dynamic, arm_body));
                        cursor = after_arm;
                        continue;
                    }
                }
            }
            PsToken::OpenParen => {
                if let Some((inner_expr, after_paren)) =
                    extract_delimited_group(body_tokens, cursor, true)
                {
                    if let Some((arm_body, after_arm)) =
                        extract_delimited_group(body_tokens, after_paren, false)
                    {
                        if inner_expr.len() == 1 {
                            arms.push((SwitchCasePattern::Token(inner_expr[0].clone()), arm_body));
                        } else {
                            arms.push((SwitchCasePattern::Dynamic, arm_body));
                        }
                        cursor = after_arm;
                        continue;
                    }
                }
            }
            tok => {
                if let Some((arm_body, after_arm)) =
                    extract_delimited_group(body_tokens, cursor + 1, false)
                {
                    arms.push((SwitchCasePattern::Token(tok.clone()), arm_body));
                    cursor = after_arm;
                    continue;
                }
            }
        }
        cursor += 1;
    }
    arms
}

fn arm_has_top_level_terminator(tokens: &[PsToken]) -> bool {
    let mut i = 0;
    while i < tokens.len() {
        if matches!(tokens[i], PsToken::Semicolon | PsToken::Newline) {
            i += 1;
            continue;
        }
        let (stmt, next_i) = collect_next_statement(tokens, i);
        i = next_i;
        if is_unconditional_terminator(&stmt) {
            return true;
        }
    }
    false
}

fn arm_exits_function(tokens: &[PsToken]) -> bool {
    let mut i = 0;
    while i < tokens.len() {
        if matches!(tokens[i], PsToken::Semicolon | PsToken::Newline) {
            i += 1;
            continue;
        }
        let (stmt, next_i) = collect_next_statement(tokens, i);
        i = next_i;
        if let Some(PsToken::Identifier(first)) = stmt.first() {
            if matches!(
                first.to_ascii_lowercase().as_str(),
                "return" | "exit" | "throw"
            ) {
                return true;
            }
            if first.eq_ignore_ascii_case("break") {
                return false;
            }
        }
    }
    false
}

fn block_can_throw(tokens: &[PsToken]) -> bool {
    let mut i = 0;
    while i < tokens.len() {
        if matches!(tokens[i], PsToken::Semicolon | PsToken::Newline) {
            i += 1;
            continue;
        }
        let (stmt, next_i) = collect_next_statement(tokens, i);
        i = next_i;
        if stmt.is_empty() {
            continue;
        }
        // Any `throw`, method invocation, or command invocation (excluding non-throwing return/exit/break) can throw at runtime
        if stmt.iter().any(|t| matches!(t, PsToken::MemberAccess(_))) {
            return true;
        }
        if let Some(PsToken::Identifier(head)) = stmt.first() {
            if !matches!(
                head.to_ascii_lowercase().as_str(),
                "return" | "exit" | "break" | "continue"
            ) {
                return true;
            }
        }
        // Check if assignment RHS invokes a command or method
        for (idx, tok) in stmt.iter().enumerate() {
            if let PsToken::Other(op) = tok {
                if op == "=" && idx + 1 < stmt.len() {
                    let rhs = &stmt[idx + 1..];
                    if rhs
                        .iter()
                        .any(|t| matches!(t, PsToken::Identifier(_) | PsToken::MemberAccess(_)))
                    {
                        return true;
                    }
                }
            }
        }
    }
    false
}

impl VariableTaintTable {
    pub fn merge_from(&mut self, other: &VariableTaintTable) {
        for (k, v) in &other.variables {
            match self.variables.get(k) {
                None => {
                    self.variables.insert(k.clone(), v.clone());
                }
                Some(existing) if existing != v => {
                    // If either branch taints the variable, preserve taint; if one is CmdletResult, preserve it
                    let merged = if matches!(
                        existing,
                        VariableOrigin::DynamicInput { .. } | VariableOrigin::TaintedExpression
                    ) || matches!(
                        v,
                        VariableOrigin::DynamicInput { .. } | VariableOrigin::TaintedExpression
                    ) {
                        VariableOrigin::TaintedExpression
                    } else if matches!(existing, VariableOrigin::CmdletResult { .. }) {
                        existing.clone()
                    } else if matches!(v, VariableOrigin::CmdletResult { .. }) {
                        v.clone()
                    } else {
                        v.clone()
                    };
                    self.variables.insert(k.clone(), merged);
                }
                _ => {}
            }
        }
        for (k, v) in &other.splat_args {
            self.splat_args
                .entry(k.clone())
                .and_modify(|existing| {
                    for arg in v {
                        if !existing.contains(arg) {
                            existing.push(arg.clone());
                        }
                    }
                })
                .or_insert_with(|| v.clone());
        }
        for (k, v) in &other.default_param_values {
            match self.default_param_values.get(k) {
                None => {
                    self.default_param_values.insert(k.clone(), v.clone());
                }
                Some((pat, param, val, existing_orig)) if existing_orig != &v.3 => {
                    let merged_orig = if matches!(
                        existing_orig,
                        VariableOrigin::DynamicInput { .. } | VariableOrigin::TaintedExpression
                    ) || matches!(
                        v.3,
                        VariableOrigin::DynamicInput { .. } | VariableOrigin::TaintedExpression
                    ) {
                        VariableOrigin::TaintedExpression
                    } else {
                        v.3.clone()
                    };
                    self.default_param_values.insert(
                        k.clone(),
                        (pat.clone(), param.clone(), val.clone(), merged_orig),
                    );
                }
                _ => {}
            }
        }
        for (k, v) in &other.class_instances {
            self.class_instances.insert(k.clone(), v.clone());
        }
    }
}

fn strip_outer_braces(tokens: Vec<PsToken>) -> Vec<PsToken> {
    let first_non_nl = tokens.iter().position(|t| !matches!(t, PsToken::Newline));
    let last_non_nl = tokens.iter().rposition(|t| !matches!(t, PsToken::Newline));
    if let (Some(f), Some(l)) = (first_non_nl, last_non_nl) {
        if f < l && matches!(tokens[f], PsToken::OpenBrace) && matches!(tokens[l], PsToken::CloseBrace) {
            // Verify the opening brace at `f` matches the closing brace at `l`
            let mut depth = 0i32;
            let mut matches_outer = true;
            for idx in f..=l {
                match tokens[idx] {
                    PsToken::OpenBrace => depth += 1,
                    PsToken::CloseBrace => {
                        depth -= 1;
                        if depth == 0 && idx < l {
                            matches_outer = false;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            if matches_outer {
                return tokens[f + 1..l].to_vec();
            }
        }
    }
    tokens
}

fn extract_delimited_group(
    tokens: &[PsToken],
    mut idx: usize,
    expect_paren: bool,
) -> Option<(Vec<PsToken>, usize)> {
    while idx < tokens.len() && matches!(tokens[idx], PsToken::Newline) {
        idx += 1;
    }
    if idx >= tokens.len() {
        return None;
    }
    let open = if expect_paren {
        PsToken::OpenParen
    } else {
        PsToken::OpenBrace
    };
    let close = if expect_paren {
        PsToken::CloseParen
    } else {
        PsToken::CloseBrace
    };
    if tokens[idx] != open {
        return None;
    }
    let mut depth = 0i32;
    let start_inner = idx + 1;
    let mut cursor = idx;
    while cursor < tokens.len() {
        if tokens[cursor] == open {
            depth += 1;
        } else if tokens[cursor] == close {
            depth -= 1;
            if depth == 0 {
                return Some((tokens[start_inner..cursor].to_vec(), cursor + 1));
            }
        }
        cursor += 1;
    }
    None
}

fn parse_function_declaration(tokens: &[PsToken], start_idx: usize) -> Option<(PsFunctionSummary, usize)> {
    let mut cursor = start_idx + 1;
    while cursor < tokens.len() && matches!(tokens[cursor], PsToken::Newline) {
        cursor += 1;
    }
    let PsToken::Identifier(func_name) = tokens.get(cursor)? else {
        return None;
    };
    cursor += 1;

    let mut params = Vec::new();
    while cursor < tokens.len() && matches!(tokens[cursor], PsToken::Newline) {
        cursor += 1;
    }

    // Optional parenthesized parameter list: `function Foo($a, $b)`
    if tokens.get(cursor) == Some(&PsToken::OpenParen) {
        let (param_tokens, after_paren) = extract_delimited_group(tokens, cursor, true)?;
        for pt in param_tokens {
            if let PsToken::Variable(v) = pt {
                params.push(v);
            }
        }
        cursor = after_paren;
    }

    let (mut body_tokens, after_body) = extract_delimited_group(tokens, cursor, false)?;

    // Also inspect leading `param($a, $b)` inside function body if params was empty
    if params.is_empty() {
        let first_non_nl = body_tokens.iter().position(|t| !matches!(t, PsToken::Newline));
        if let Some(f_idx) = first_non_nl {
            if let PsToken::Identifier(id) = &body_tokens[f_idx] {
                if id.eq_ignore_ascii_case("param") {
                    if let Some((param_group, after_p)) =
                        extract_delimited_group(&body_tokens, f_idx + 1, true)
                    {
                        for pt in param_group {
                            if let PsToken::Variable(v) = pt {
                                params.push(v);
                            }
                        }
                        body_tokens = body_tokens[after_p..].to_vec();
                    }
                }
            }
        }
    }

    Some((
        PsFunctionSummary {
            name: func_name.clone(),
            params,
            body_tokens,
        },
        after_body,
    ))
}

fn parse_class_declaration(
    tokens: &[PsToken],
    start_idx: usize,
) -> Option<(Vec<PsFunctionSummary>, usize)> {
    let mut cursor = start_idx + 1;
    while cursor < tokens.len() && matches!(tokens[cursor], PsToken::Newline) {
        cursor += 1;
    }
    let PsToken::Identifier(class_name) = tokens.get(cursor)? else {
        return None;
    };
    let class_lower = class_name.to_ascii_lowercase();
    cursor += 1;

    // Skip optional `: BaseClass, IInterface` up to `{`
    while cursor < tokens.len() && tokens[cursor] != PsToken::OpenBrace {
        cursor += 1;
    }
    let (class_body, after_body) = extract_delimited_group(tokens, cursor, false)?;

    let mut methods = Vec::new();
    let mut i = 0;
    while i < class_body.len() {
        while i < class_body.len()
            && matches!(class_body[i], PsToken::Newline | PsToken::Semicolon)
        {
            i += 1;
        }
        if i >= class_body.len() {
            break;
        }
        // Look for `<MethodName> ( <params> ) { <body> }` (optionally preceded by `[Type]` or `hidden`/`static`)
        if let PsToken::Identifier(ident) = &class_body[i] {
            let mut look = i + 1;
            while look < class_body.len() && matches!(class_body[look], PsToken::Newline) {
                look += 1;
            }
            if class_body.get(look) == Some(&PsToken::OpenParen) {
                if let Some((param_tokens, after_paren)) =
                    extract_delimited_group(&class_body, look, true)
                {
                    if let Some((method_body, after_method)) =
                        extract_delimited_group(&class_body, after_paren, false)
                    {
                        let mut params = Vec::new();
                        for pt in param_tokens {
                            if let PsToken::Variable(v) = pt {
                                params.push(v);
                            }
                        }
                        let method_lower = ident.to_ascii_lowercase();
                        methods.push(PsFunctionSummary {
                            name: format!("{class_lower}::{method_lower}"),
                            params: params.clone(),
                            body_tokens: method_body.clone(),
                        });
                        methods.push(PsFunctionSummary {
                            name: format!("method::{method_lower}"),
                            params,
                            body_tokens: method_body,
                        });
                        i = after_method;
                        continue;
                    }
                }
            }
        }
        i += 1;
    }

    Some((methods, after_body))
}

fn split_comma_separated_tokens(tokens: &[PsToken]) -> Vec<Vec<PsToken>> {
    let mut groups = Vec::new();
    let mut current = Vec::new();
    let mut depth = 0usize;
    for tok in tokens {
        match tok {
            PsToken::OpenParen | PsToken::OpenBrace => {
                depth += 1;
                current.push(tok.clone());
            }
            PsToken::CloseParen | PsToken::CloseBrace => {
                depth = depth.saturating_sub(1);
                current.push(tok.clone());
            }
            PsToken::Other(op) if op == "," && depth == 0 => {
                if !current.is_empty() {
                    groups.push(std::mem::take(&mut current));
                }
            }
            PsToken::Newline if depth == 0 => {}
            _ => current.push(tok.clone()),
        }
    }
    if !current.is_empty() {
        groups.push(current);
    }
    groups
}

fn collect_next_statement(tokens: &[PsToken], start_idx: usize) -> (Vec<PsToken>, usize) {
    let mut stmt = Vec::new();
    let mut cursor = start_idx;
    let mut brace_depth = 0usize;
    let mut paren_depth = 0usize;

    while cursor < tokens.len() {
        let tok = &tokens[cursor];
        match tok {
            PsToken::OpenBrace => {
                brace_depth += 1;
                stmt.push(tok.clone());
            }
            PsToken::CloseBrace => {
                brace_depth = brace_depth.saturating_sub(1);
                stmt.push(tok.clone());
            }
            PsToken::OpenParen => {
                paren_depth += 1;
                stmt.push(tok.clone());
            }
            PsToken::CloseParen => {
                paren_depth = paren_depth.saturating_sub(1);
                stmt.push(tok.clone());
            }
            PsToken::Semicolon | PsToken::Newline if brace_depth == 0 && paren_depth == 0 => {
                cursor += 1;
                break;
            }
            _ => {
                stmt.push(tok.clone());
            }
        }
        cursor += 1;
    }
    (stmt, cursor)
}

fn is_unconditional_terminator(stmt: &[PsToken]) -> bool {
    if let Some(PsToken::Identifier(first)) = stmt.first() {
        matches!(
            first.to_ascii_lowercase().as_str(),
            "return" | "exit" | "break" | "throw"
        )
    } else {
        false
    }
}

/// Evaluate a PowerShell branch condition statically against known literals and `VariableTaintTable`.
/// Returns `StaticTruthValue::Unknown` (fail-closed) whenever any variable or operand is dynamic,
/// environment-sourced, cmdlet-sourced, or unrecognized.
pub fn evaluate_static_condition(
    cond_tokens: &[PsToken],
    taint_table: &VariableTaintTable,
) -> StaticTruthValue {
    let tokens: Vec<&PsToken> = cond_tokens
        .iter()
        .filter(|t| !matches!(t, PsToken::Newline | PsToken::OpenParen | PsToken::CloseParen))
        .collect();

    if tokens.is_empty() {
        return StaticTruthValue::False;
    }

    // Handle unary `-not` or `!`
    if let Some(PsToken::Other(op)) = tokens.first() {
        if op.eq_ignore_ascii_case("-not") || op == "!" {
            let inner: Vec<PsToken> = tokens[1..].iter().map(|t| (*t).clone()).collect();
            return match evaluate_static_condition(&inner, taint_table) {
                StaticTruthValue::True => StaticTruthValue::False,
                StaticTruthValue::False => StaticTruthValue::True,
                StaticTruthValue::Unknown => StaticTruthValue::Unknown,
            };
        }
    }

    // Handle logical `-and` / `-or`
    for (idx, tok) in tokens.iter().enumerate() {
        if let PsToken::Other(op) = tok {
            if op.eq_ignore_ascii_case("-and") {
                let lhs: Vec<PsToken> = tokens[..idx].iter().map(|t| (*t).clone()).collect();
                let rhs: Vec<PsToken> = tokens[idx + 1..].iter().map(|t| (*t).clone()).collect();
                let l_val = evaluate_static_condition(&lhs, taint_table);
                let r_val = evaluate_static_condition(&rhs, taint_table);
                return match (l_val, r_val) {
                    (StaticTruthValue::False, _) | (_, StaticTruthValue::False) => {
                        StaticTruthValue::False
                    }
                    (StaticTruthValue::True, StaticTruthValue::True) => StaticTruthValue::True,
                    _ => StaticTruthValue::Unknown,
                };
            } else if op.eq_ignore_ascii_case("-or") {
                let lhs: Vec<PsToken> = tokens[..idx].iter().map(|t| (*t).clone()).collect();
                let rhs: Vec<PsToken> = tokens[idx + 1..].iter().map(|t| (*t).clone()).collect();
                let l_val = evaluate_static_condition(&lhs, taint_table);
                let r_val = evaluate_static_condition(&rhs, taint_table);
                return match (l_val, r_val) {
                    (StaticTruthValue::True, _) | (_, StaticTruthValue::True) => {
                        StaticTruthValue::True
                    }
                    (StaticTruthValue::False, StaticTruthValue::False) => StaticTruthValue::False,
                    _ => StaticTruthValue::Unknown,
                };
            }
        }
    }

    // Single token truthiness: `$true`, `$false`, `0`, `1`, `"str"`, or resolved variable literal
    if tokens.len() == 1 {
        let Some(scalar) = resolve_static_scalar(tokens[0], taint_table) else {
            return StaticTruthValue::Unknown;
        };
        return scalar_truthiness(&scalar);
    }

    // Binary comparison: `<lhs> -eq|-ne|-gt|-lt|-ge|-le <rhs>`
    if tokens.len() == 3 {
        if let PsToken::Other(op) = tokens[1] {
            let Some(lhs) = resolve_static_scalar(tokens[0], taint_table) else {
                return StaticTruthValue::Unknown;
            };
            let Some(rhs) = resolve_static_scalar(tokens[2], taint_table) else {
                return StaticTruthValue::Unknown;
            };
            let op_lower = op.to_ascii_lowercase();
            match op_lower.as_str() {
                "-eq" | "-ieq" => {
                    return if lhs.eq_ignore_ascii_case(&rhs) {
                        StaticTruthValue::True
                    } else {
                        StaticTruthValue::False
                    };
                }
                "-ceq" => {
                    return if lhs == rhs {
                        StaticTruthValue::True
                    } else {
                        StaticTruthValue::False
                    };
                }
                "-ne" | "-ine" => {
                    return if !lhs.eq_ignore_ascii_case(&rhs) {
                        StaticTruthValue::True
                    } else {
                        StaticTruthValue::False
                    };
                }
                "-gt" | "-lt" | "-ge" | "-le" => {
                    if let (Ok(l_num), Ok(r_num)) = (lhs.parse::<f64>(), rhs.parse::<f64>()) {
                        let res = match op_lower.as_str() {
                            "-gt" => l_num > r_num,
                            "-lt" => l_num < r_num,
                            "-ge" => l_num >= r_num,
                            "-le" => l_num <= r_num,
                            _ => unreachable!(),
                        };
                        return if res {
                            StaticTruthValue::True
                        } else {
                            StaticTruthValue::False
                        };
                    }
                }
                _ => {}
            }
        }
    }

    StaticTruthValue::Unknown
}

fn resolve_static_scalar(tok: &PsToken, taint_table: &VariableTaintTable) -> Option<String> {
    match tok {
        PsToken::StringLiteral(s) => Some(s.clone()),
        PsToken::Other(num) if num.chars().all(|c| c.is_ascii_digit() || c == '.') => {
            Some(num.clone())
        }
        PsToken::Variable(v) => {
            let v_lower = v.to_ascii_lowercase();
            if v_lower == "$true" {
                return Some("$true".to_string());
            }
            if v_lower == "$false" || v_lower == "$null" {
                return Some("$false".to_string());
            }
            match taint_table.get(v) {
                Some(VariableOrigin::Literal(lit)) => Some(lit.clone()),
                _ => None,
            }
        }
        _ => None,
    }
}

fn scalar_truthiness(val: &str) -> StaticTruthValue {
    let lower = val.to_ascii_lowercase();
    if lower == "$false" || lower == "$null" || lower.is_empty() || lower == "0" || lower == "0.0" {
        StaticTruthValue::False
    } else {
        StaticTruthValue::True
    }
}

/// Parse scriptblock text to extract synthesized guard commands for destructive operations.
pub fn extract_scriptblock_synthesized_commands(script: &str) -> Vec<Cmd> {
    let mut taint_table = VariableTaintTable::new();
    extract_scriptblock_synthesized_commands_with_table(script, &mut taint_table)
}

/// Parse scriptblock text with a scoped variable taint table using Inter-Procedural CFG Reachability.
pub fn extract_scriptblock_synthesized_commands_with_table(
    script: &str,
    taint_table: &mut VariableTaintTable,
) -> Vec<Cmd> {
    let cfg = PsControlFlowGraph::build_with_taint(script, taint_table);
    cfg.synthesized_commands
}

fn analyze_statement(stmt: &[PsToken], taint_table: &mut VariableTaintTable, out: &mut Vec<Cmd>) {
    // 0. If statement contains top-level pipeline segments (`|`), analyze each segment sequentially
    // so `-PipelineVariable` / `-pv` and `$_` propagate across inline scriptblock pipelines.
    if stmt.iter().any(|t| matches!(t, PsToken::Pipe)) {
        let mut depth_brace = 0usize;
        let mut depth_paren = 0usize;
        let mut segments: Vec<Vec<PsToken>> = Vec::new();
        let mut current = Vec::new();
        for tok in stmt {
            match tok {
                PsToken::OpenBrace => {
                    depth_brace += 1;
                    current.push(tok.clone());
                }
                PsToken::CloseBrace => {
                    depth_brace = depth_brace.saturating_sub(1);
                    current.push(tok.clone());
                }
                PsToken::OpenParen => {
                    depth_paren += 1;
                    current.push(tok.clone());
                }
                PsToken::CloseParen => {
                    depth_paren = depth_paren.saturating_sub(1);
                    current.push(tok.clone());
                }
                PsToken::Pipe if depth_brace == 0 && depth_paren == 0 => {
                    if !current.is_empty() {
                        segments.push(std::mem::take(&mut current));
                    }
                }
                _ => current.push(tok.clone()),
            }
        }
        if !current.is_empty() {
            segments.push(current);
        }
        if segments.len() > 1 {
            for seg in &segments {
                analyze_statement(seg, taint_table, out);
            }
            return;
        }
    }

    // Track `-PipelineVariable <name>` / `-pv <name>` on any command in this statement
    if let Some(PsToken::Identifier(head)) = stmt.first() {
        let stage_origin = classify_cmd_head_origin(head);
        if let Some(orig) = stage_origin {
            taint_table.set("$_", orig.clone());
            taint_table.set("$PSItem", orig.clone());
            for pv in extract_pipeline_variables_from_tokens(&stmt[1..]) {
                taint_table.set(&pv, orig.clone());
            }
        }
        let head_lower = head.to_ascii_lowercase();
        if matches!(
            head_lower.as_str(),
            "foreach-object" | "foreach" | "%" | "where-object" | "where" | "?"
        ) {
            let is_parallel = stmt[1..].iter().any(|t| match t {
                PsToken::Other(f) | PsToken::Identifier(f) => {
                    f.eq_ignore_ascii_case("-parallel") || f.eq_ignore_ascii_case("-pa")
                }
                _ => false,
            });
            let mut cursor = 1;
            let mut walked_scriptblock = false;
            while cursor < stmt.len() {
                if matches!(stmt[cursor], PsToken::OpenBrace) {
                    if let Some((inner, next_c)) = extract_delimited_group(stmt, cursor, false) {
                        walked_scriptblock = true;
                        let mut sub_cfg = PsControlFlowGraph::default();
                        let entry_id = sub_cfg.new_block("inline_stage", true);
                        if is_parallel {
                            let mut parallel_taint = taint_table.clone();
                            let body_tokens = strip_and_bind_scriptblock_params(
                                &inner,
                                &[],
                                &mut parallel_taint,
                            );
                            sub_cfg.walk_tokens(
                                &body_tokens,
                                entry_id,
                                true,
                                &mut parallel_taint,
                                0,
                            );
                        } else {
                            let body_tokens =
                                strip_and_bind_scriptblock_params(&inner, &[], taint_table);
                            sub_cfg.walk_tokens(&body_tokens, entry_id, true, taint_table, 0);
                        }
                        out.extend(sub_cfg.synthesized_commands);
                        cursor = next_c;
                        continue;
                    }
                }
                cursor += 1;
            }
            if walked_scriptblock {
                return;
            }
        } else if matches!(
            head_lower.as_str(),
            "start-job" | "sajb" | "start-threadjob" | "invoke-command" | "icm"
        ) {
            let arg_origins = extract_argument_list_origins(&stmt[1..], taint_table);
            let is_in_process_invoke =
                matches!(head_lower.as_str(), "invoke-command" | "icm");
            let mut cursor = 1;
            let mut walked_scriptblock = false;
            while cursor < stmt.len() {
                if matches!(stmt[cursor], PsToken::OpenBrace) {
                    if let Some((inner, next_c)) = extract_delimited_group(stmt, cursor, false) {
                        walked_scriptblock = true;
                        let mut job_taint = taint_table.clone();
                        bind_argument_list_to_job_scope(&arg_origins, &mut job_taint);
                        let body_tokens = strip_and_bind_scriptblock_params(
                            &inner,
                            &arg_origins,
                            &mut job_taint,
                        );
                        let mut sub_cfg = PsControlFlowGraph::default();
                        let entry_id = sub_cfg.new_block("job_scriptblock", true);
                        sub_cfg.walk_tokens(&body_tokens, entry_id, true, &mut job_taint, 0);
                        if is_in_process_invoke {
                            taint_table.propagate_cross_scope_from(&job_taint);
                        }
                        out.extend(sub_cfg.synthesized_commands);
                        cursor = next_c;
                        continue;
                    }
                }
                cursor += 1;
            }
            if walked_scriptblock {
                return;
            }
        }
    }

    // 1. Variable, property (`$this.Prop` / `$obj.Prop`), and `$PSDefaultParameterValues` assignments
    for (idx, tok) in stmt.iter().enumerate() {
        if let PsToken::Other(op) = tok {
            if (op == "=" || op == "+=") && idx > 0 {
                let rhs = &stmt[idx + 1..];
                let origin = classify_rhs_origin(rhs, taint_table);

                // 1a. Direct variable assignment: `$var = <expr>`
                if let PsToken::Variable(var) = &stmt[idx - 1] {
                    if var.eq_ignore_ascii_case("$PSDefaultParameterValues") {
                        parse_ps_default_parameter_hashtable(rhs, taint_table);
                    }
                    if let Some(cls) = extract_class_instantiation_name(rhs) {
                        taint_table.set_class_instance(var, &cls);
                    }
                    taint_table.set(var, origin.clone());
                    let splat_args = extract_splat_args_from_rhs(rhs, taint_table);
                    if !splat_args.is_empty() {
                        if op == "+=" {
                            let mut combined =
                                taint_table.get_splat_args(var).cloned().unwrap_or_default();
                            combined.extend(splat_args);
                            taint_table.set_splat_args(var, combined);
                        } else {
                            taint_table.set_splat_args(var, splat_args);
                        }
                    }
                }
                // 1b. Instance property assignment: `$this.Prop = <expr>` or `$obj.Prop = <expr>`
                else if idx >= 2 {
                    if let (PsToken::Variable(var), PsToken::MemberAccess(member)) =
                        (&stmt[idx - 2], &stmt[idx - 1])
                    {
                        let prop_key = format!("{}{}", var, member);
                        taint_table.set(&prop_key, origin.clone());
                        let splat_args = extract_splat_args_from_rhs(rhs, taint_table);
                        if !splat_args.is_empty() {
                            taint_table.set_splat_args(&prop_key, splat_args);
                        }
                    }
                }

                // 1c. Indexed `$PSDefaultParameterValues['Cmd:Param'] = <expr>`
                if idx >= 4 {
                    if let (
                        PsToken::Variable(var),
                        PsToken::Other(open_br),
                        PsToken::StringLiteral(key_str) | PsToken::Identifier(key_str),
                        PsToken::Other(close_br),
                    ) = (
                        &stmt[idx - 4],
                        &stmt[idx - 3],
                        &stmt[idx - 2],
                        &stmt[idx - 1],
                    ) {
                        if var.eq_ignore_ascii_case("$PSDefaultParameterValues")
                            && open_br == "["
                            && close_br == "]"
                        {
                            record_ps_default_parameter_entry(key_str, rhs, origin, taint_table);
                        }
                    }
                }
            }
        }
    }

    // 1d. `$PSDefaultParameterValues.Add('Cmd:Param', <expr>)`
    for i in 0..stmt.len() {
        if let (
            Some(PsToken::Variable(var)),
            Some(PsToken::MemberAccess(member)),
            Some(PsToken::OpenParen),
        ) = (stmt.get(i), stmt.get(i + 1), stmt.get(i + 2))
        {
            if var.eq_ignore_ascii_case("$PSDefaultParameterValues")
                && member.trim_start_matches('.').eq_ignore_ascii_case("add")
            {
                if let Some((call_args, _)) = extract_delimited_group(stmt, i + 2, true) {
                    let arg_groups = split_comma_separated_tokens(&call_args);
                    if arg_groups.len() >= 2 {
                        if let Some(PsToken::StringLiteral(key_str) | PsToken::Identifier(key_str)) =
                            arg_groups[0].first()
                        {
                            let val_rhs = &arg_groups[1];
                            let val_orig = classify_rhs_origin(val_rhs, taint_table);
                            record_ps_default_parameter_entry(
                                key_str,
                                val_rhs,
                                val_orig,
                                taint_table,
                            );
                        }
                    }
                }
            }
        }
    }

    // 2. Foreach loops: foreach ($var in $collection_or_cmd) { <body> }
    if let Some(PsToken::Identifier(head)) = stmt.first() {
        if head.eq_ignore_ascii_case("foreach") {
            let filtered: Vec<&PsToken> = stmt
                .iter()
                .filter(|t| {
                    !matches!(
                        t,
                        PsToken::OpenParen | PsToken::CloseParen | PsToken::Newline
                    )
                })
                .collect();
            if filtered.len() >= 4 {
                if let (
                    PsToken::Variable(var),
                    PsToken::Identifier(in_kw),
                    PsToken::Identifier(cmd),
                ) = (filtered[1], filtered[2], filtered[3])
                {
                    if in_kw.eq_ignore_ascii_case("in") {
                        let cmd_lower = cmd.to_lowercase();
                        if cmd_lower.starts_with("get-process") || cmd_lower == "gps" {
                            taint_table.set(
                                var,
                                VariableOrigin::CmdletResult {
                                    cmdlet: "Get-Process".into(),
                                },
                            );
                        } else if cmd_lower.starts_with("get-childitem")
                            || cmd_lower == "gci"
                            || cmd_lower == "dir"
                            || cmd_lower == "ls"
                        {
                            taint_table.set(
                                var,
                                VariableOrigin::CmdletResult {
                                    cmdlet: "Get-ChildItem".into(),
                                },
                            );
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

    // 3b. Dynamic call operator (`& <target> [args...]`) and dot-source operator (`. <target> [args...]`)
    if let Some(PsToken::Other(op)) = stmt.first() {
        if op == "&" || op == "." {
            if let Some(target_tok) = stmt.get(1) {
                match target_tok {
                    PsToken::Variable(v) => {
                        if let Some(VariableOrigin::Literal(lit)) = taint_table.get(v).cloned() {
                            if !lit.is_empty() && lit != "value" {
                                let mut synthetic_stmt = vec![PsToken::Identifier(lit)];
                                synthetic_stmt.extend_from_slice(stmt.get(2..).unwrap_or(&[]));
                                analyze_statement(&synthetic_stmt, taint_table, out);
                                return;
                            }
                        }
                        // Unresolved or tainted dynamic call/dot-source target -> synthesize Invoke-Expression
                        let mut args = vec!["-Command".to_string(), v.clone()];
                        let mut has_taint = taint_table.is_tainted_or_dynamic(v);
                        for tok in stmt.iter().skip(2) {
                            match tok {
                                PsToken::Variable(arg_v) => {
                                    args.push(arg_v.clone());
                                    if taint_table.is_tainted_or_dynamic(arg_v) {
                                        has_taint = true;
                                    }
                                }
                                PsToken::StringLiteral(s)
                                | PsToken::Identifier(s)
                                | PsToken::Other(s) => args.push(s.clone()),
                                _ => {}
                            }
                        }
                        if has_taint {
                            args.push("untrusted_input".to_string());
                        }
                        out.push(Cmd {
                            head: "Invoke-Expression".to_string(),
                            args,
                            ..Default::default()
                        });
                        return;
                    }
                    PsToken::StringLiteral(s) | PsToken::Identifier(s) => {
                        let mut synthetic_stmt = vec![PsToken::Identifier(s.clone())];
                        synthetic_stmt.extend_from_slice(stmt.get(2..).unwrap_or(&[]));
                        analyze_statement(&synthetic_stmt, taint_table, out);
                        return;
                    }
                    PsToken::OpenBrace => {
                        if let Some((inner, _)) = extract_delimited_group(stmt, 1, false) {
                            let mut sub_cfg = PsControlFlowGraph::default();
                            let entry_id = sub_cfg.new_block("call_scriptblock", true);
                            sub_cfg.walk_tokens(&inner, entry_id, true, taint_table, 0);
                            out.extend(sub_cfg.synthesized_commands);
                            return;
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    // 4. Destructive, splatted, or `$PSDefaultParameterValues`-augmented command invocations
    if let Some(first) = stmt.first() {
        if let PsToken::Identifier(head) = first {
            let name_lower = head.to_lowercase();
            let has_splat = stmt
                .iter()
                .skip(1)
                .any(|t| matches!(t, PsToken::SplatVariable(_)));
            let matching_defaults = taint_table.matching_default_params(head);
            if name_lower.starts_with("remove-")
                || name_lower.starts_with("stop-")
                || name_lower.starts_with("set-")
                || matches!(
                    name_lower.as_str(),
                    "rm"
                        | "del"
                        | "erase"
                        | "spps"
                        | "kill"
                        | "invoke-expression"
                        | "iex"
                        | "invoke-command"
                        | "icm"
                        | "invoke-restmethod"
                        | "irm"
                        | "invoke-webrequest"
                        | "iwr"
                )
                || has_splat
                || !matching_defaults.is_empty()
            {
                let mut args = Vec::new();
                let mut has_untrusted_var = false;

                let mut idx = 1;
                while idx < stmt.len() {
                    match &stmt[idx] {
                        PsToken::Variable(v) => {
                            let has_member =
                                matches!(stmt.get(idx + 1), Some(PsToken::MemberAccess(_)));
                            if !has_member {
                                if let Some(VariableOrigin::Literal(lit)) = taint_table.get(v) {
                                    args.push(lit.clone());
                                } else {
                                    args.push(v.clone());
                                    if taint_table.is_tainted_or_dynamic(v) {
                                        has_untrusted_var = true;
                                    }
                                }
                            } else if let Some(PsToken::MemberAccess(m)) = stmt.get(idx + 1) {
                                let prop_expr = format!("{}{}", v, m);
                                if let Some(VariableOrigin::Literal(lit)) =
                                    taint_table.get(&prop_expr)
                                {
                                    args.push(lit.clone());
                                } else {
                                    args.push(prop_expr.clone());
                                    if taint_table.is_tainted_or_dynamic(&prop_expr)
                                        || taint_table.is_tainted_or_dynamic(v)
                                    {
                                        has_untrusted_var = true;
                                    }
                                }
                                idx += 1;
                            }
                        }
                        PsToken::SplatVariable(sv) => {
                            if let Some(expanded) = taint_table.get_splat_args(sv) {
                                args.extend(expanded.iter().cloned());
                            } else {
                                args.push(sv.clone());
                            }
                            if taint_table.is_tainted_or_dynamic(sv) {
                                has_untrusted_var = true;
                                if !args.iter().any(|a| a == "untrusted_input") {
                                    args.push("untrusted_input".to_string());
                                }
                            }
                        }
                        PsToken::Identifier(s)
                        | PsToken::Other(s)
                        | PsToken::StringLiteral(s) => {
                            args.push(s.clone());
                        }
                        _ => {}
                    }
                    idx += 1;
                }

                // Inject matching `$PSDefaultParameterValues` parameters not already explicitly passed
                for (param, rendered_val, origin) in matching_defaults {
                    let flag_name = format!("-{param}");
                    let already_present = args
                        .iter()
                        .any(|a| a.eq_ignore_ascii_case(&flag_name));
                    if !already_present {
                        if rendered_val.eq_ignore_ascii_case("$true") {
                            args.push(flag_name);
                        } else if !rendered_val.eq_ignore_ascii_case("$false") {
                            args.push(flag_name);
                            if !rendered_val.is_empty() {
                                args.push(rendered_val);
                            }
                        }
                    }
                    if matches!(
                        origin,
                        VariableOrigin::DynamicInput { .. }
                            | VariableOrigin::TaintedExpression
                            | VariableOrigin::Environment(_)
                    ) {
                        has_untrusted_var = true;
                        if !args.iter().any(|a| a == "untrusted_input") {
                            args.push("untrusted_input".to_string());
                        }
                    }
                }

                // If variable passed is untrusted/dynamic, ensure -Recurse is included so path guards evaluate
                if has_untrusted_var
                    && (name_lower.starts_with("remove-")
                        || matches!(name_lower.as_str(), "rm" | "del" | "erase"))
                {
                    if !args.iter().any(|a| a.eq_ignore_ascii_case("-recurse")) {
                        args.push("-Recurse".to_string());
                    }
                    if !args.iter().any(|a| a == "untrusted_input") {
                        args.push("untrusted_input".to_string());
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

fn classify_cmd_head_origin(head: &str) -> Option<VariableOrigin> {
    let head_lower = head.to_ascii_lowercase();
    if matches!(
        head_lower.as_str(),
        "read-host"
            | "get-content"
            | "gc"
            | "cat"
            | "type"
            | "invoke-restmethod"
            | "irm"
            | "invoke-webrequest"
            | "iwr"
    ) {
        Some(VariableOrigin::DynamicInput {
            source: head.to_string(),
        })
    } else if head_lower.starts_with("get-process") || head_lower == "gps" {
        Some(VariableOrigin::CmdletResult {
            cmdlet: "Get-Process".into(),
        })
    } else if head_lower.starts_with("get-childitem")
        || matches!(head_lower.as_str(), "gci" | "dir" | "ls")
    {
        Some(VariableOrigin::CmdletResult {
            cmdlet: "Get-ChildItem".into(),
        })
    } else if head_lower.starts_with("get-") {
        Some(VariableOrigin::CmdletResult {
            cmdlet: head.to_string(),
        })
    } else {
        None
    }
}

fn extract_pipeline_variables_from_tokens(tokens: &[PsToken]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        if let PsToken::Identifier(id) | PsToken::Other(id) = &tokens[i] {
            let lower = id.to_ascii_lowercase();
            if lower == "-pipelinevariable" || lower == "-pv" {
                if let Some(next_tok) = tokens.get(i + 1) {
                    let name = match next_tok {
                        PsToken::Identifier(s)
                        | PsToken::StringLiteral(s)
                        | PsToken::Variable(s)
                        | PsToken::Other(s) => Some(s.trim_start_matches('$').to_string()),
                        _ => None,
                    };
                    if let Some(n) = name {
                        if !n.is_empty() {
                            out.push(format!("${n}"));
                        }
                        i += 2;
                        continue;
                    }
                }
            } else if let Some(rest) = lower
                .strip_prefix("-pipelinevariable:")
                .or_else(|| lower.strip_prefix("-pv:"))
            {
                let colon_idx = id.find(':').unwrap_or(0);
                let raw_name = id[colon_idx + 1..].trim_start_matches('$');
                if !raw_name.is_empty() && !rest.is_empty() {
                    out.push(format!("${raw_name}"));
                }
            }
        }
        i += 1;
    }
    out
}

fn extract_pipeline_variables_from_args(args: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].trim();
        let lower = arg.to_ascii_lowercase();
        if (lower == "-pipelinevariable" || lower == "-pv") && i + 1 < args.len() {
            let name = args[i + 1]
                .trim()
                .trim_matches(|c| c == '\'' || c == '"')
                .trim_start_matches('$');
            if !name.is_empty() {
                out.push(format!("${name}"));
            }
            i += 2;
            continue;
        } else if lower.starts_with("-pipelinevariable:") || lower.starts_with("-pv:") {
            if let Some(idx) = arg.find(':') {
                let name = arg[idx + 1..]
                    .trim()
                    .trim_matches(|c| c == '\'' || c == '"')
                    .trim_start_matches('$');
                if !name.is_empty() {
                    out.push(format!("${name}"));
                }
            }
        }
        i += 1;
    }
    out
}

fn tokens_to_arg_string(tokens: &[PsToken]) -> String {
    let mut parts = Vec::new();
    for tok in tokens {
        match tok {
            PsToken::Identifier(s)
            | PsToken::Variable(s)
            | PsToken::SplatVariable(s)
            | PsToken::MemberAccess(s)
            | PsToken::StringLiteral(s)
            | PsToken::Other(s) => parts.push(s.as_str()),
            _ => {}
        }
    }
    parts.join(" ")
}

fn extract_splat_args_from_rhs(rhs: &[PsToken], taint_table: &VariableTaintTable) -> Vec<String> {
    if rhs.len() < 2 {
        return Vec::new();
    }
    let Some(PsToken::Other(at)) = rhs.first() else {
        return Vec::new();
    };
    if at != "@" {
        return Vec::new();
    }

    // Hashtable literal: @{ Key = Val; Switch = $true; ... }
    if matches!(rhs.get(1), Some(PsToken::OpenBrace)) {
        let Some((inner, _)) = extract_delimited_group(rhs, 1, false) else {
            return Vec::new();
        };
        let mut args = Vec::new();
        let mut i = 0;
        while i < inner.len() {
            while i < inner.len()
                && matches!(inner[i], PsToken::Semicolon | PsToken::Newline)
            {
                i += 1;
            }
            if i >= inner.len() {
                break;
            }
            let key_opt = match &inner[i] {
                PsToken::Identifier(k) | PsToken::StringLiteral(k) => Some(k.clone()),
                _ => None,
            };
            if let Some(key) = key_opt {
                if matches!(inner.get(i + 1), Some(PsToken::Other(op)) if op == "=") {
                    i += 2;
                    let mut val_tokens = Vec::new();
                    let mut depth = 0usize;
                    while i < inner.len() {
                        match &inner[i] {
                            PsToken::OpenParen | PsToken::OpenBrace => {
                                depth += 1;
                                val_tokens.push(inner[i].clone());
                            }
                            PsToken::CloseParen | PsToken::CloseBrace => {
                                depth = depth.saturating_sub(1);
                                val_tokens.push(inner[i].clone());
                            }
                            PsToken::Semicolon | PsToken::Newline if depth == 0 => {
                                break;
                            }
                            _ => val_tokens.push(inner[i].clone()),
                        }
                        i += 1;
                    }
                    let flag_name = if key.starts_with('-') {
                        key
                    } else {
                        format!("-{key}")
                    };
                    if val_tokens.len() == 1 {
                        if let PsToken::Variable(v) = &val_tokens[0] {
                            if v.eq_ignore_ascii_case("$true") {
                                args.push(flag_name);
                                continue;
                            } else if v.eq_ignore_ascii_case("$false") {
                                continue;
                            } else if let Some(VariableOrigin::Literal(lit)) = taint_table.get(v) {
                                args.push(flag_name);
                                args.push(lit.clone());
                                continue;
                            } else {
                                args.push(flag_name);
                                args.push(v.clone());
                                continue;
                            }
                        } else if let PsToken::StringLiteral(s)
                        | PsToken::Identifier(s)
                        | PsToken::Other(s) = &val_tokens[0]
                        {
                            args.push(flag_name);
                            args.push(s.clone());
                            continue;
                        }
                    }
                    args.push(flag_name);
                    if !val_tokens.is_empty() {
                        args.push(tokens_to_arg_string(&val_tokens));
                    }
                    continue;
                }
            }
            i += 1;
        }
        return args;
    }

    // Array literal: @( arg1, arg2, ... )
    if matches!(rhs.get(1), Some(PsToken::OpenParen)) {
        let Some((inner, _)) = extract_delimited_group(rhs, 1, true) else {
            return Vec::new();
        };
        let mut args = Vec::new();
        for tok in &inner {
            match tok {
                PsToken::Other(c) if c == "," => continue,
                PsToken::Newline | PsToken::Semicolon => continue,
                PsToken::StringLiteral(s) | PsToken::Identifier(s) | PsToken::Other(s) => {
                    args.push(s.clone());
                }
                PsToken::Variable(v) => {
                    if let Some(VariableOrigin::Literal(lit)) = taint_table.get(v) {
                        args.push(lit.clone());
                    } else {
                        args.push(v.clone());
                    }
                }
                _ => {}
            }
        }
        return args;
    }

    Vec::new()
}

fn classify_rhs_origin(rhs: &[PsToken], taint_table: &VariableTaintTable) -> VariableOrigin {
    // Handle hashtable `@{ ... }` and array `@( ... )` literals: inspect inner expressions for taint
    if matches!(rhs.first(), Some(PsToken::Other(at)) if at == "@") {
        for tok in &rhs[1..] {
            match tok {
                PsToken::Identifier(id) => {
                    let lower = id.to_ascii_lowercase();
                    if matches!(
                        lower.as_str(),
                        "read-host"
                            | "get-content"
                            | "gc"
                            | "invoke-restmethod"
                            | "irm"
                            | "invoke-webrequest"
                            | "iwr"
                    ) {
                        return VariableOrigin::DynamicInput { source: id.clone() };
                    }
                }
                PsToken::Variable(v) => {
                    if v.eq_ignore_ascii_case("$true") || v.eq_ignore_ascii_case("$false") {
                        continue;
                    }
                    let norm_v = VariableTaintTable::normalize_key(v);
                    if norm_v.starts_with("$env:") || norm_v.starts_with("$using:env:") {
                        return VariableOrigin::Environment(v.clone());
                    } else if taint_table.is_tainted_or_dynamic(v) {
                        return VariableOrigin::TaintedExpression;
                    }
                }
                _ => {}
            }
        }
        return VariableOrigin::Literal("splat_literal".to_string());
    }

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
        if cmd_lower == "read-host"
            || cmd_lower == "get-content"
            || cmd_lower == "gc"
            || cmd_lower == "invoke-restmethod"
            || cmd_lower == "irm"
            || cmd_lower == "invoke-webrequest"
            || cmd_lower == "iwr"
        {
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

    // Check if right-hand side references other variables (including `$this.Prop` / `$obj.Prop`)
    for (idx, tok) in meaningful.iter().enumerate() {
        if let PsToken::Variable(v) = tok {
            if let Some(PsToken::MemberAccess(m)) = meaningful.get(idx + 1) {
                let prop_expr = format!("{}{}", v, m);
                if taint_table.is_tainted_or_dynamic(&prop_expr) {
                    return VariableOrigin::TaintedExpression;
                } else if let Some(orig) = taint_table.get(&prop_expr) {
                    return orig.clone();
                }
            }
            let norm_v = VariableTaintTable::normalize_key(v);
            if norm_v.starts_with("$env:") || norm_v.starts_with("$using:env:") {
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

fn extract_class_instantiation_name(rhs: &[PsToken]) -> Option<String> {
    // 1. `[ClassName]::new(...)`
    for i in 0..rhs.len() {
        if let (
            Some(PsToken::Other(open_br)),
            Some(PsToken::Identifier(cls)),
            Some(PsToken::Other(close_br)),
        ) = (rhs.get(i), rhs.get(i + 1), rhs.get(i + 2))
        {
            if open_br == "[" && close_br == "]" {
                // Check for `::new` or `:new` following `]`
                let rest_str = tokens_to_arg_string(rhs.get(i + 3..).unwrap_or(&[]));
                if rest_str.to_ascii_lowercase().contains("new") {
                    return Some(cls.clone());
                }
            }
        }
    }
    // 2. `New-Object [-TypeName] ClassName`
    if let Some(PsToken::Identifier(cmd)) = rhs.first() {
        if cmd.eq_ignore_ascii_case("new-object") {
            for tok in rhs.iter().skip(1) {
                match tok {
                    PsToken::Other(flag) if flag.starts_with('-') => continue,
                    PsToken::Identifier(cls) | PsToken::StringLiteral(cls) => {
                        return Some(cls.clone());
                    }
                    _ => {}
                }
            }
        }
    }
    None
}

fn record_ps_default_parameter_entry(
    key_str: &str,
    val_tokens: &[PsToken],
    origin: VariableOrigin,
    taint_table: &mut VariableTaintTable,
) {
    let Some((cmd_pat, param_name)) = key_str.split_once(':') else {
        return;
    };
    let rendered = if val_tokens.len() == 1 {
        match &val_tokens[0] {
            PsToken::Variable(v) => {
                if v.eq_ignore_ascii_case("$true") || v.eq_ignore_ascii_case("$false") {
                    v.clone()
                } else if let Some(VariableOrigin::Literal(lit)) = taint_table.get(v) {
                    lit.clone()
                } else {
                    v.clone()
                }
            }
            PsToken::StringLiteral(s) | PsToken::Identifier(s) | PsToken::Other(s) => s.clone(),
            _ => tokens_to_arg_string(val_tokens),
        }
    } else {
        tokens_to_arg_string(val_tokens)
    };
    taint_table.set_default_param(cmd_pat, param_name, rendered, origin);
}

fn parse_ps_default_parameter_hashtable(rhs: &[PsToken], taint_table: &mut VariableTaintTable) {
    if rhs.len() < 2 {
        return;
    }
    let Some(PsToken::Other(at)) = rhs.first() else {
        return;
    };
    if at != "@" || !matches!(rhs.get(1), Some(PsToken::OpenBrace)) {
        return;
    }
    let Some((inner, _)) = extract_delimited_group(rhs, 1, false) else {
        return;
    };
    let mut i = 0;
    while i < inner.len() {
        while i < inner.len() && matches!(inner[i], PsToken::Semicolon | PsToken::Newline) {
            i += 1;
        }
        if i >= inner.len() {
            break;
        }
        let key_opt = match &inner[i] {
            PsToken::Identifier(k) | PsToken::StringLiteral(k) => Some(k.clone()),
            _ => None,
        };
        if let Some(key_str) = key_opt {
            if matches!(inner.get(i + 1), Some(PsToken::Other(op)) if op == "=") {
                i += 2;
                let mut val_tokens = Vec::new();
                let mut depth = 0usize;
                while i < inner.len() {
                    match &inner[i] {
                        PsToken::OpenParen | PsToken::OpenBrace => {
                            depth += 1;
                            val_tokens.push(inner[i].clone());
                        }
                        PsToken::CloseParen | PsToken::CloseBrace => {
                            depth = depth.saturating_sub(1);
                            val_tokens.push(inner[i].clone());
                        }
                        PsToken::Semicolon | PsToken::Newline if depth == 0 => {
                            break;
                        }
                        _ => val_tokens.push(inner[i].clone()),
                    }
                    i += 1;
                }
                let origin = classify_rhs_origin(&val_tokens, taint_table);
                record_ps_default_parameter_entry(&key_str, &val_tokens, origin, taint_table);
                continue;
            }
        }
        i += 1;
    }
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
        let stage_origin = classify_cmd_head_origin(&cmd.head);
        if let Some(orig) = &stage_origin {
            taint_table.set("$_", orig.clone());
            taint_table.set("$PSItem", orig.clone());
        }

        // Bind any `-PipelineVariable <var>` / `-pv <var>` on this stage so it persists across ALL downstream stages
        if let Some(orig) = stage_origin.or_else(|| taint_table.get("$_").cloned()) {
            for pv in extract_pipeline_variables_from_args(&cmd.args) {
                taint_table.set(&pv, orig.clone());
            }
        }

        // Check if command is an iterator or filter cmdlet
        let is_filter = matches!(head_lower.as_str(), "where-object" | "where" | "?");
        let is_iterator = matches!(head_lower.as_str(), "foreach-object" | "foreach" | "%");

        if is_iterator {
            let is_parallel = cmd.args.iter().any(|a| {
                let lower = a.trim().to_ascii_lowercase();
                lower == "-parallel" || lower == "-pa"
            });
            let ordered_blocks = order_foreach_scriptblocks(&cmd.args);
            let mut next_stage_origin: Option<VariableOrigin> = None;
            for block_arg in ordered_blocks {
                let mut parallel_taint = taint_table.clone();
                let target_table = if is_parallel {
                    &mut parallel_taint
                } else {
                    &mut taint_table
                };
                let cfg = PsControlFlowGraph::build_with_taint(block_arg, target_table);
                if let Some(orig) = infer_stage_output_origin(&cfg, target_table) {
                    next_stage_origin = Some(orig);
                }
                out.extend(cfg.synthesized_commands);
            }
            if let Some(orig) = next_stage_origin {
                for pv in extract_pipeline_variables_from_args(&cmd.args) {
                    taint_table.set(&pv, orig.clone());
                }
                taint_table.set("$_", orig.clone());
                taint_table.set("$PSItem", orig);
            }
        } else if is_filter {
            for arg in &cmd.args {
                if arg.starts_with('-') && !arg.trim_start().starts_with('{') {
                    continue;
                }
                let synthesized =
                    extract_scriptblock_synthesized_commands_with_table(arg, &mut taint_table);
                out.extend(synthesized);
            }
        } else {
            // Also inspect scriptblock arguments in commands like `& { ... }`, `Start-Job`, `Invoke-Command`, or multi-statement blocks
            for arg in &cmd.args {
                if arg.trim_start().starts_with('{') && arg.trim_end().ends_with('}') {
                    let synthesized =
                        extract_scriptblock_synthesized_commands_with_table(arg, &mut taint_table);
                    out.extend(synthesized);
                }
            }
        }
    }

    out
}

fn extract_argument_list_origins(
    stmt_args: &[PsToken],
    taint_table: &VariableTaintTable,
) -> Vec<VariableOrigin> {
    let mut i = 0;
    while i < stmt_args.len() {
        let is_arg_list_flag = match &stmt_args[i] {
            PsToken::Other(f) | PsToken::Identifier(f) => {
                f.eq_ignore_ascii_case("-argumentlist")
                    || f.eq_ignore_ascii_case("-args")
                    || f.eq_ignore_ascii_case("-arg")
            }
            _ => false,
        };
        if is_arg_list_flag {
            let mut cursor = i + 1;
            while cursor < stmt_args.len() && matches!(stmt_args[cursor], PsToken::Newline) {
                cursor += 1;
            }
            if cursor >= stmt_args.len() {
                break;
            }
            // Case 1: `-ArgumentList @( ... )`
            if matches!(stmt_args.get(cursor), Some(PsToken::Other(at)) if at == "@")
                && stmt_args.get(cursor + 1) == Some(&PsToken::OpenParen)
            {
                if let Some((inner, _)) = extract_delimited_group(stmt_args, cursor + 1, true) {
                    return split_comma_separated_tokens(&inner)
                        .into_iter()
                        .map(|slice| classify_rhs_origin(&slice, taint_table))
                        .collect();
                }
            }
            // Case 2: `-ArgumentList ( ... )`
            if stmt_args.get(cursor) == Some(&PsToken::OpenParen) {
                if let Some((inner, _)) = extract_delimited_group(stmt_args, cursor, true) {
                    return split_comma_separated_tokens(&inner)
                        .into_iter()
                        .map(|slice| classify_rhs_origin(&slice, taint_table))
                        .collect();
                }
            }
            // Case 3: `-ArgumentList $a, $b` up to next top-level `-Flag` or `{`
            let mut collected = Vec::new();
            let mut depth = 0usize;
            while cursor < stmt_args.len() {
                match &stmt_args[cursor] {
                    PsToken::OpenParen => {
                        depth += 1;
                        collected.push(stmt_args[cursor].clone());
                    }
                    PsToken::CloseParen => {
                        depth = depth.saturating_sub(1);
                        collected.push(stmt_args[cursor].clone());
                    }
                    PsToken::OpenBrace if depth == 0 => break,
                    PsToken::Other(fl) if depth == 0 && fl.starts_with('-') => break,
                    _ => collected.push(stmt_args[cursor].clone()),
                }
                cursor += 1;
            }
            return split_comma_separated_tokens(&collected)
                .into_iter()
                .map(|slice| classify_rhs_origin(&slice, taint_table))
                .collect();
        }
        i += 1;
    }
    Vec::new()
}

fn bind_argument_list_to_job_scope(
    arg_origins: &[VariableOrigin],
    job_taint: &mut VariableTaintTable,
) {
    if arg_origins.is_empty() {
        return;
    }
    let any_tainted = arg_origins.iter().any(|o| {
        matches!(
            o,
            VariableOrigin::DynamicInput { .. }
                | VariableOrigin::TaintedExpression
                | VariableOrigin::Environment(_)
        )
    });
    if any_tainted {
        job_taint.set("$args", VariableOrigin::TaintedExpression);
    } else if arg_origins.len() == 1 {
        job_taint.set("$args", arg_origins[0].clone());
    }
    for (idx, orig) in arg_origins.iter().enumerate() {
        job_taint.set(&format!("$args[{idx}]"), orig.clone());
    }
}

fn strip_and_bind_scriptblock_params(
    inner: &[PsToken],
    arg_origins: &[VariableOrigin],
    taint_table: &mut VariableTaintTable,
) -> Vec<PsToken> {
    let first_non_nl = inner.iter().position(|t| !matches!(t, PsToken::Newline));
    if let Some(f_idx) = first_non_nl {
        if let PsToken::Identifier(id) = &inner[f_idx] {
            if id.eq_ignore_ascii_case("param") {
                if let Some((param_group, mut after_p)) =
                    extract_delimited_group(inner, f_idx + 1, true)
                {
                    let mut params = Vec::new();
                    for pt in param_group {
                        if let PsToken::Variable(v) = pt {
                            params.push(v);
                        }
                    }
                    for (param_idx, param_var) in params.iter().enumerate() {
                        if let Some(orig) = arg_origins.get(param_idx) {
                            taint_table.set(param_var, orig.clone());
                        }
                    }
                    while after_p < inner.len()
                        && matches!(inner[after_p], PsToken::Semicolon | PsToken::Newline)
                    {
                        after_p += 1;
                    }
                    return inner[after_p..].to_vec();
                }
            }
        }
    }
    inner.to_vec()
}

fn order_foreach_scriptblocks(args: &[String]) -> Vec<&str> {
    let mut begin_blocks = Vec::new();
    let mut positional_blocks = Vec::new();
    let mut process_blocks = Vec::new();
    let mut end_blocks = Vec::new();

    let mut i = 0;
    while i < args.len() {
        let a = args[i].trim();
        let lower = a.to_ascii_lowercase();
        if matches!(lower.as_str(), "-begin" | "-b") && i + 1 < args.len() {
            begin_blocks.push(args[i + 1].as_str());
            i += 2;
        } else if matches!(lower.as_str(), "-process" | "-p") && i + 1 < args.len() {
            process_blocks.push(args[i + 1].as_str());
            i += 2;
        } else if matches!(lower.as_str(), "-end" | "-e") && i + 1 < args.len() {
            end_blocks.push(args[i + 1].as_str());
            i += 2;
        } else if matches!(
            lower.as_str(),
            "-pipelinevariable" | "-pv" | "-outvariable" | "-ov" | "-errorvariable" | "-ev"
        ) && i + 1 < args.len()
        {
            i += 2;
        } else if a.starts_with('-') && !a.starts_with('{') {
            i += 1;
        } else {
            positional_blocks.push(args[i].as_str());
            i += 1;
        }
    }

    let mut ordered = Vec::with_capacity(
        begin_blocks.len() + positional_blocks.len() + process_blocks.len() + end_blocks.len(),
    );
    ordered.extend(begin_blocks);
    ordered.extend(positional_blocks);
    ordered.extend(process_blocks);
    ordered.extend(end_blocks);
    ordered
}

fn infer_stage_output_origin(
    cfg: &PsControlFlowGraph,
    taint_table: &VariableTaintTable,
) -> Option<VariableOrigin> {
    let mut inferred: Option<VariableOrigin> = None;
    for block in &cfg.blocks {
        if !block.reachable {
            continue;
        }
        for stmt in &block.statements {
            if stmt.is_empty() {
                continue;
            }
            // Skip assignments ($v = ...)
            if stmt
                .iter()
                .any(|t| matches!(t, PsToken::Other(op) if op == "=" || op == "+="))
            {
                continue;
            }
            if stmt.len() == 1 {
                if let PsToken::Variable(v) = &stmt[0] {
                    if let Some(orig) = taint_table.get(v) {
                        inferred = Some(orig.clone());
                    }
                } else if let PsToken::Identifier(cmd) = &stmt[0] {
                    let orig = classify_rhs_origin(stmt, taint_table);
                    if !matches!(orig, VariableOrigin::Literal(_)) {
                        let _ = cmd;
                        inferred = Some(orig);
                    }
                }
            } else if let Some(PsToken::Identifier(head)) = stmt.first() {
                if head.eq_ignore_ascii_case("write-output") || head.eq_ignore_ascii_case("echo") {
                    if let Some(PsToken::Variable(v)) = stmt.get(1) {
                        if let Some(orig) = taint_table.get(v) {
                            inferred = Some(orig.clone());
                        }
                    }
                } else {
                    let head_lower = head.to_ascii_lowercase();
                    if head_lower == "read-host"
                        || head_lower == "get-content"
                        || head_lower == "gc"
                        || head_lower.starts_with("get-process")
                        || head_lower == "gps"
                        || head_lower.starts_with("get-childitem")
                        || head_lower == "gci"
                    {
                        inferred = Some(classify_rhs_origin(stmt, taint_table));
                    }
                }
            }
        }
    }
    inferred
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
