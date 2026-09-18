//! JavaScript inline snippet scanner.
//!
//! Scans JavaScript code (used in `node -e`, `bun -e`, or MCP tool snippets)
//! for commands, file writes, subprocess invocations, and dynamic evaluation.
//! Emits `Cmd` records prefixed with `javascript:` for function calls and
//! records `dynamic_call` constructs for `eval` and `new Function`.

use std::collections::HashMap;

pub use crate::syntax::{Cmd, Order, Scan};

pub const KNOWN_CONSTRUCTS: &[&str] = &[
    "parse_failure",
    "unmodeled_command",
    "dynamic_call",
    "unresolved_path",
    "unreadable_language",
];

pub struct JavaScript;

impl crate::syntax::Scanner for JavaScript {
    fn lang(&self) -> &'static str {
        "javascript"
    }

    fn scan(&self, src: &str) -> Result<Scan, String> {
        parse(src)
    }

    fn known_constructs(&self) -> &'static [&'static str] {
        KNOWN_CONSTRUCTS
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Ident(String),
    StringLit(String),
    NumberLit(String),
    // Keywords
    Const,
    Let,
    Var,
    Function,
    Return,
    New,
    Import,
    From,
    Await,
    Async,
    If,
    Else,
    For,
    While,
    Do,
    Try,
    Catch,
    Finally,
    Throw,
    // Delimiters
    Dot,
    Comma,
    Semi,
    Colon,
    Question,
    OpenParen,
    CloseParen,
    OpenBracket,
    CloseBracket,
    OpenBrace,
    CloseBrace,
    // Operators
    Assign,
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    Exclamation,
    Ampersand,
    Pipe,
    Caret,
    Tilde,
    Arrow,
    Eq,
    NotEq,
    LogicalAnd,
    LogicalOr,
    NullishCoalescing,
    OtherOp(String),
    Newline,
}

fn tokenize(src: &str) -> Result<Vec<Token>, String> {
    let chars: Vec<char> = src.chars().collect();
    let len = chars.len();
    let mut i = 0;
    let mut tokens = Vec::new();
    let mut delim_stack: Vec<char> = Vec::new();

    while i < len {
        let c = chars[i];

        // Whitespace
        if c == '\n' {
            if tokens.last() != Some(&Token::Newline) {
                tokens.push(Token::Newline);
            }
            i += 1;
            continue;
        }
        if c.is_whitespace() {
            i += 1;
            continue;
        }

        // Single-line comment
        if c == '/' && i + 1 < len && chars[i + 1] == '/' {
            i += 2;
            while i < len && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }

        // Multi-line comment
        if c == '/' && i + 1 < len && chars[i + 1] == '*' {
            i += 2;
            let mut closed = false;
            while i + 1 < len {
                if chars[i] == '*' && chars[i + 1] == '/' {
                    i += 2;
                    closed = true;
                    break;
                }
                i += 1;
            }
            if !closed {
                return Err("unclosed multi-line comment".to_string());
            }
            continue;
        }

        // Single quote string
        if c == '\'' {
            i += 1;
            let mut s = String::new();
            let mut closed = false;
            while i < len {
                let sc = chars[i];
                if sc == '\\' {
                    if i + 1 < len {
                        let next = chars[i + 1];
                        match next {
                            'n' => s.push('\n'),
                            't' => s.push('\t'),
                            'r' => s.push('\r'),
                            '\\' => s.push('\\'),
                            '\'' => s.push('\''),
                            '"' => s.push('"'),
                            other => {
                                s.push('\\');
                                s.push(other);
                            }
                        }
                        i += 2;
                        continue;
                    } else {
                        return Err("unclosed single-quoted string escape".to_string());
                    }
                }
                if sc == '\'' {
                    i += 1;
                    closed = true;
                    break;
                }
                s.push(sc);
                i += 1;
            }
            if !closed {
                return Err("unclosed single-quoted string".to_string());
            }
            tokens.push(Token::StringLit(s));
            continue;
        }

        // Double quote string
        if c == '"' {
            i += 1;
            let mut s = String::new();
            let mut closed = false;
            while i < len {
                let sc = chars[i];
                if sc == '\\' {
                    if i + 1 < len {
                        let next = chars[i + 1];
                        match next {
                            'n' => s.push('\n'),
                            't' => s.push('\t'),
                            'r' => s.push('\r'),
                            '\\' => s.push('\\'),
                            '\'' => s.push('\''),
                            '"' => s.push('"'),
                            other => {
                                s.push('\\');
                                s.push(other);
                            }
                        }
                        i += 2;
                        continue;
                    } else {
                        return Err("unclosed double-quoted string escape".to_string());
                    }
                }
                if sc == '"' {
                    i += 1;
                    closed = true;
                    break;
                }
                s.push(sc);
                i += 1;
            }
            if !closed {
                return Err("unclosed double-quoted string".to_string());
            }
            tokens.push(Token::StringLit(s));
            continue;
        }

        // Template literal
        if c == '`' {
            i += 1;
            let mut s = String::new();
            let mut closed = false;
            while i < len {
                let tc = chars[i];
                if tc == '\\' {
                    if i + 1 < len {
                        s.push(chars[i + 1]);
                        i += 2;
                        continue;
                    } else {
                        return Err("unclosed template literal escape".to_string());
                    }
                }
                if tc == '`' {
                    i += 1;
                    closed = true;
                    break;
                }
                if tc == '$' && i + 1 < len && chars[i + 1] == '{' {
                    // Interpolated expression
                    i += 2;
                    let mut expr = String::new();
                    let mut brace_depth = 1;
                    while i < len && brace_depth > 0 {
                        let ic = chars[i];
                        if ic == '{' {
                            brace_depth += 1;
                        } else if ic == '}' {
                            brace_depth -= 1;
                            if brace_depth == 0 {
                                i += 1;
                                break;
                            }
                        }
                        expr.push(ic);
                        i += 1;
                    }
                    let var_name = expr.trim();
                    if !var_name.is_empty() && var_name.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '_') {
                        s.push('$');
                        s.push_str(var_name);
                    } else {
                        s.push_str("$?");
                    }
                    continue;
                }
                s.push(tc);
                i += 1;
            }
            if !closed {
                return Err("unclosed template literal".to_string());
            }
            tokens.push(Token::StringLit(s));
            continue;
        }

        // Delimiters with pairing check
        match c {
            '(' => {
                delim_stack.push('(');
                tokens.push(Token::OpenParen);
                i += 1;
                continue;
            }
            ')' => {
                if delim_stack.pop() != Some('(') {
                    return Err("unbalanced parenthesis ')'".to_string());
                }
                tokens.push(Token::CloseParen);
                i += 1;
                continue;
            }
            '[' => {
                delim_stack.push('[');
                tokens.push(Token::OpenBracket);
                i += 1;
                continue;
            }
            ']' => {
                if delim_stack.pop() != Some('[') {
                    return Err("unbalanced bracket ']'".to_string());
                }
                tokens.push(Token::CloseBracket);
                i += 1;
                continue;
            }
            '{' => {
                delim_stack.push('{');
                tokens.push(Token::OpenBrace);
                i += 1;
                continue;
            }
            '}' => {
                if delim_stack.pop() != Some('{') {
                    return Err("unbalanced brace '}'".to_string());
                }
                tokens.push(Token::CloseBrace);
                i += 1;
                continue;
            }
            '.' => {
                tokens.push(Token::Dot);
                i += 1;
                continue;
            }
            ',' => {
                tokens.push(Token::Comma);
                i += 1;
                continue;
            }
            ';' => {
                tokens.push(Token::Semi);
                i += 1;
                continue;
            }
            ':' => {
                tokens.push(Token::Colon);
                i += 1;
                continue;
            }
            '?' => {
                if i + 1 < len && chars[i + 1] == '?' {
                    tokens.push(Token::NullishCoalescing);
                    i += 2;
                } else {
                    tokens.push(Token::Question);
                    i += 1;
                }
                continue;
            }
            _ => {}
        }

        // Multi-char operators
        if c == '=' {
            if i + 1 < len && chars[i + 1] == '>' {
                tokens.push(Token::Arrow);
                i += 2;
                continue;
            }
            if i + 2 < len && chars[i + 1] == '=' && chars[i + 2] == '=' {
                tokens.push(Token::Eq);
                i += 3;
                continue;
            }
            if i + 1 < len && chars[i + 1] == '=' {
                tokens.push(Token::Eq);
                i += 2;
                continue;
            }
            tokens.push(Token::Assign);
            i += 1;
            continue;
        }

        if c == '!' {
            if i + 2 < len && chars[i + 1] == '=' && chars[i + 2] == '=' {
                tokens.push(Token::NotEq);
                i += 3;
                continue;
            }
            if i + 1 < len && chars[i + 1] == '=' {
                tokens.push(Token::NotEq);
                i += 2;
                continue;
            }
            tokens.push(Token::Exclamation);
            i += 1;
            continue;
        }

        if c == '&' {
            if i + 1 < len && chars[i + 1] == '&' {
                tokens.push(Token::LogicalAnd);
                i += 2;
            } else {
                tokens.push(Token::Ampersand);
                i += 1;
            }
            continue;
        }

        if c == '|' {
            if i + 1 < len && chars[i + 1] == '|' {
                tokens.push(Token::LogicalOr);
                i += 2;
            } else {
                tokens.push(Token::Pipe);
                i += 1;
            }
            continue;
        }

        // Single operators
        match c {
            '+' => {
                tokens.push(Token::Plus);
                i += 1;
                continue;
            }
            '-' => {
                tokens.push(Token::Minus);
                i += 1;
                continue;
            }
            '*' => {
                tokens.push(Token::Star);
                i += 1;
                continue;
            }
            '/' => {
                // Check if this could be a regex literal:
                // Preceded by operator or beginning of expression
                let is_regex = tokens.last().map_or(true, |t| {
                    matches!(
                        t,
                        Token::OpenParen
                            | Token::OpenBracket
                            | Token::OpenBrace
                            | Token::Assign
                            | Token::Colon
                            | Token::Comma
                            | Token::Semi
                            | Token::LogicalAnd
                            | Token::LogicalOr
                            | Token::Return
                    )
                });
                if is_regex {
                    i += 1;
                    let mut reg = String::new();
                    let mut reg_closed = false;
                    while i < len {
                        let rc = chars[i];
                        if rc == '\\' && i + 1 < len {
                            reg.push(rc);
                            reg.push(chars[i + 1]);
                            i += 2;
                            continue;
                        }
                        if rc == '/' {
                            i += 1;
                            reg_closed = true;
                            // skip flags
                            while i < len && chars[i].is_ascii_alphabetic() {
                                i += 1;
                            }
                            break;
                        }
                        reg.push(rc);
                        i += 1;
                    }
                    if !reg_closed {
                        return Err("unclosed regex literal".to_string());
                    }
                    tokens.push(Token::StringLit(reg));
                    continue;
                }
                tokens.push(Token::Slash);
                i += 1;
                continue;
            }
            '%' => {
                tokens.push(Token::Percent);
                i += 1;
                continue;
            }
            '^' => {
                tokens.push(Token::Caret);
                i += 1;
                continue;
            }
            '~' => {
                tokens.push(Token::Tilde);
                i += 1;
                continue;
            }
            _ => {}
        }

        // Numbers
        if c.is_ascii_digit() {
            let mut num = String::new();
            while i < len && (chars[i].is_ascii_alphanumeric() || chars[i] == '.') {
                num.push(chars[i]);
                i += 1;
            }
            tokens.push(Token::NumberLit(num));
            continue;
        }

        // Identifiers and Keywords
        if c.is_ascii_alphabetic() || c == '_' || c == '$' {
            let mut id = String::new();
            while i < len && (chars[i].is_ascii_alphanumeric() || chars[i] == '_' || chars[i] == '$') {
                id.push(chars[i]);
                i += 1;
            }
            let tok = match id.as_str() {
                "const" => Token::Const,
                "let" => Token::Let,
                "var" => Token::Var,
                "function" => Token::Function,
                "return" => Token::Return,
                "new" => Token::New,
                "import" => Token::Import,
                "from" => Token::From,
                "await" => Token::Await,
                "async" => Token::Async,
                "if" => Token::If,
                "else" => Token::Else,
                "for" => Token::For,
                "while" => Token::While,
                "do" => Token::Do,
                "try" => Token::Try,
                "catch" => Token::Catch,
                "finally" => Token::Finally,
                "throw" => Token::Throw,
                _ => Token::Ident(id),
            };
            tokens.push(tok);
            continue;
        }

        // Unknown character
        tokens.push(Token::OtherOp(c.to_string()));
        i += 1;
    }

    if !delim_stack.is_empty() {
        return Err(format!("unclosed delimiter '{}'", delim_stack.last().unwrap()));
    }

    Ok(tokens)
}

struct Parser<'a> {
    tokens: &'a [Token],
    pos: usize,
    modules: HashMap<String, String>,
    bindings: HashMap<String, String>,
    out: Scan,
    seq: u32,
}

impl<'a> Parser<'a> {
    fn new(tokens: &'a [Token]) -> Self {
        Self {
            tokens,
            pos: 0,
            modules: HashMap::new(),
            bindings: HashMap::new(),
            out: Scan::default(),
            seq: 0,
        }
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn next(&mut self) -> Option<&Token> {
        if self.pos < self.tokens.len() {
            let t = &self.tokens[self.pos];
            self.pos += 1;
            Some(t)
        } else {
            None
        }
    }

    fn match_token(&mut self, expected: &Token) -> bool {
        if let Some(t) = self.peek() {
            if t == expected {
                self.pos += 1;
                return true;
            }
        }
        false
    }

    fn skip_redundant_terminators(&mut self) {
        while self.match_token(&Token::Semi) || self.match_token(&Token::Newline) {}
    }

    fn check_statement_terminator(&mut self) -> Result<(), String> {
        if self.pos >= self.tokens.len() || self.peek() == Some(&Token::CloseBrace) {
            return Ok(());
        }
        if self.match_token(&Token::Semi) || self.match_token(&Token::Newline) {
            self.skip_redundant_terminators();
            return Ok(());
        }
        Err(format!("unexpected token '{:?}'", self.peek().unwrap()))
    }

    fn parse_all(&mut self) -> Result<(), String> {
        self.skip_redundant_terminators();
        while self.pos < self.tokens.len() {
            self.parse_statement()?;
            self.skip_redundant_terminators();
        }
        Ok(())
    }

    fn parse_statement(&mut self) -> Result<(), String> {
        self.skip_redundant_terminators();
        let tok = match self.peek() {
            Some(t) => t.clone(),
            None => return Ok(()),
        };

        match tok {
            Token::Semi | Token::Newline => {
                self.next();
                Ok(())
            }
            Token::OpenBrace => {
                self.next();
                self.skip_redundant_terminators();
                while self.pos < self.tokens.len() {
                    if self.match_token(&Token::CloseBrace) {
                        break;
                    }
                    self.parse_statement()?;
                    self.skip_redundant_terminators();
                }
                Ok(())
            }
            Token::Const | Token::Let | Token::Var => {
                self.next();
                self.parse_var_decl()?;
                self.check_statement_terminator()
            }
            Token::Import => {
                self.next();
                self.parse_import()?;
                self.check_statement_terminator()
            }
            Token::Function => {
                self.next();
                if let Some(Token::Ident(_)) = self.peek() {
                    self.next();
                }
                self.skip_parens()?;
                self.parse_statement()
            }
            Token::If => {
                self.next();
                self.skip_parens()?;
                self.parse_statement()?;
                self.skip_redundant_terminators();
                if self.match_token(&Token::Else) {
                    self.parse_statement()?;
                }
                Ok(())
            }
            Token::For | Token::While => {
                self.next();
                self.skip_parens()?;
                self.parse_statement()
            }
            Token::Do => {
                self.next();
                self.parse_statement()?;
                self.skip_redundant_terminators();
                if self.match_token(&Token::While) {
                    self.skip_parens()?;
                }
                self.check_statement_terminator()
            }
            Token::Try => {
                self.next();
                self.parse_statement()?;
                self.skip_redundant_terminators();
                if self.match_token(&Token::Catch) {
                    self.next();
                    if let Some(Token::OpenParen) = self.peek() {
                        self.skip_parens()?;
                    }
                    self.parse_statement()?;
                }
                self.skip_redundant_terminators();
                if self.match_token(&Token::Finally) {
                    self.next();
                    self.parse_statement()?;
                }
                Ok(())
            }
            Token::Return | Token::Throw => {
                self.next();
                if self.pos < self.tokens.len()
                    && self.peek() != Some(&Token::Semi)
                    && self.peek() != Some(&Token::Newline)
                    && self.peek() != Some(&Token::CloseBrace)
                {
                    self.parse_expression()?;
                }
                self.check_statement_terminator()
            }
            _ => {
                self.parse_expression()?;
                self.check_statement_terminator()
            }
        }
    }

    fn skip_parens(&mut self) -> Result<(), String> {
        if !self.match_token(&Token::OpenParen) {
            return Ok(());
        }
        let mut depth = 1;
        while self.pos < self.tokens.len() && depth > 0 {
            match self.next().unwrap() {
                Token::OpenParen => depth += 1,
                Token::CloseParen => depth -= 1,
                _ => {}
            }
        }
        Ok(())
    }

    fn parse_var_decl(&mut self) -> Result<(), String> {
        let peeked = self.peek().cloned();
        match peeked {
            Some(Token::Ident(name)) => {
                self.next();
                if self.match_token(&Token::Assign) {
                    // Check if assigned a require()
                    if let Some(req) = self.try_parse_require()? {
                        self.modules.insert(name.clone(), req);
                    } else if let Some(Token::StringLit(s)) = self.peek().cloned() {
                        self.next();
                        self.bindings.insert(name, s);
                    } else {
                        self.parse_expression()?;
                    }
                }
            }
            Some(Token::OpenBrace) => {
                // Destructuring: const { execSync, spawn } = require('child_process');
                self.next();
                let mut imported_names = Vec::new();
                while self.pos < self.tokens.len() {
                    if self.match_token(&Token::CloseBrace) {
                        break;
                    }
                    if let Some(Token::Ident(prop)) = self.peek().cloned() {
                        self.next();
                        let local = if self.match_token(&Token::Colon) {
                            if let Some(Token::Ident(alias)) = self.peek().cloned() {
                                self.next();
                                alias
                            } else {
                                prop.clone()
                            }
                        } else {
                            prop.clone()
                        };
                        imported_names.push((prop, local));
                    }
                    self.match_token(&Token::Comma);
                }
                if self.match_token(&Token::Assign) {
                    if let Some(mod_name) = self.try_parse_require()? {
                        for (prop, local) in imported_names {
                            self.modules.insert(local, format!("{mod_name}.{prop}"));
                        }
                    } else {
                        self.parse_expression()?;
                    }
                }
            }
            other => return Err(format!("unexpected token in variable declaration: {:?}", other)),
        }
        Ok(())
    }

    fn parse_import(&mut self) -> Result<(), String> {
        // import ... from 'module'
        let mut default_import: Option<String> = None;
        let mut named_imports: Vec<String> = Vec::new();

        if let Some(Token::Ident(id)) = self.peek().cloned() {
            self.next();
            default_import = Some(id);
            self.match_token(&Token::Comma);
        }

        if self.match_token(&Token::OpenBrace) {
            while self.pos < self.tokens.len() {
                if self.match_token(&Token::CloseBrace) {
                    break;
                }
                if let Some(Token::Ident(id)) = self.peek().cloned() {
                    self.next();
                    named_imports.push(id);
                }
                self.match_token(&Token::Comma);
            }
        }

        while self.pos < self.tokens.len() && !self.match_token(&Token::From) {
            self.next();
        }

        if let Some(Token::StringLit(mod_name)) = self.peek().cloned() {
            self.next();
            if let Some(def) = default_import {
                self.modules.insert(def, mod_name.clone());
            }
            for name in named_imports {
                self.modules.insert(name.clone(), format!("{mod_name}.{name}"));
            }
        }
        Ok(())
    }

    fn try_parse_require(&mut self) -> Result<Option<String>, String> {
        if let Some(Token::Ident(id)) = self.peek() {
            if id == "require" {
                self.next();
                if self.match_token(&Token::OpenParen) {
                    let mod_name = if let Some(Token::StringLit(s)) = self.peek().cloned() {
                        self.next();
                        Some(s)
                    } else {
                        None
                    };
                    self.match_token(&Token::CloseParen);
                    if let Some(m) = mod_name {
                        // Check if chained: require('child_process').execSync
                        if self.match_token(&Token::Dot) {
                            if let Some(Token::Ident(sub)) = self.peek().cloned() {
                                self.next();
                                return Ok(Some(format!("{m}.{sub}")));
                            }
                        }
                        return Ok(Some(m));
                    }
                }
            }
        }
        Ok(None)
    }

    fn parse_expression(&mut self) -> Result<(), String> {
        self.parse_binary_or_assignment()
    }

    fn parse_binary_or_assignment(&mut self) -> Result<(), String> {
        self.parse_unary_or_primary()?;
        while self.pos < self.tokens.len() {
            let is_binary_op = matches!(
                self.peek(),
                Some(
                    Token::Assign
                        | Token::Plus
                        | Token::Minus
                        | Token::Star
                        | Token::Slash
                        | Token::Percent
                        | Token::Eq
                        | Token::NotEq
                        | Token::LogicalAnd
                        | Token::LogicalOr
                        | Token::NullishCoalescing
                        | Token::Ampersand
                        | Token::Pipe
                        | Token::Caret
                        | Token::Arrow
                        | Token::OtherOp(_)
                )
            );
            if is_binary_op {
                self.next();
                self.parse_unary_or_primary()?;
            } else if self.match_token(&Token::Question) {
                self.parse_expression()?;
                if !self.match_token(&Token::Colon) {
                    return Err("expected ':' in ternary operator".to_string());
                }
                self.parse_expression()?;
            } else {
                break;
            }
        }
        Ok(())
    }

    fn parse_unary_or_primary(&mut self) -> Result<(), String> {
        let is_unary = matches!(
            self.peek(),
            Some(
                Token::Exclamation
                    | Token::Tilde
                    | Token::Plus
                    | Token::Minus
            )
        );
        if is_unary {
            self.next();
            return self.parse_unary_or_primary();
        }
        self.parse_primary_and_postfix()
    }

    fn parse_primary_and_postfix(&mut self) -> Result<(), String> {
        let mut callee_parts: Vec<String> = Vec::new();

        // Check for `new Function(...)` or `new X(...)`
        if self.match_token(&Token::New) {
            if let Some(Token::Ident(id)) = self.peek() {
                if id == "Function" {
                    self.next();
                    self.out.note("dynamic_call");
                    let args = self.parse_call_args()?;
                    self.out.push_cmd(
                        "javascript:Function".to_string(),
                        args,
                        Order::Seq(self.seq),
                        crate::syntax::InputSource::Unknown,
                        true,
                        None,
                        vec![],
                        None,
                        HashMap::new(),
                        false,
                    );
                    self.seq += 1;
                    return Ok(());
                }
            }
        }

        // Check for `require('...')`
        if let Some(req_mod) = self.try_parse_require()? {
            callee_parts.push(req_mod);
        } else if let Some(Token::Ident(id)) = self.peek().cloned() {
            self.next();
            callee_parts.push(id);
        } else if let Some(Token::StringLit(_)) = self.peek().cloned() {
            self.next();
        } else if let Some(Token::NumberLit(_)) = self.peek().cloned() {
            self.next();
        } else if self.match_token(&Token::OpenParen) {
            self.parse_expression()?;
            if !self.match_token(&Token::CloseParen) {
                return Err("unclosed parenthesis in expression".to_string());
            }
        } else if self.match_token(&Token::OpenBracket) {
            // Array literal
            while self.pos < self.tokens.len() {
                if self.match_token(&Token::CloseBracket) {
                    break;
                }
                self.parse_expression()?;
                self.match_token(&Token::Comma);
            }
        } else if self.match_token(&Token::OpenBrace) {
            // Object literal
            let mut depth = 1;
            while self.pos < self.tokens.len() && depth > 0 {
                match self.next().unwrap() {
                    Token::OpenBrace => depth += 1,
                    Token::CloseBrace => depth -= 1,
                    _ => {}
                }
            }
        } else if self.match_token(&Token::Function) {
            // Anonymous or named function expression
            if let Some(Token::Ident(_)) = self.peek() {
                self.next();
            }
            self.skip_parens()?;
            self.parse_statement()?;
        } else {
            return Err(format!("unexpected token '{:?}' in expression", self.peek()));
        }

        // Parse member accesses and calls (postfix chaining)
        while self.pos < self.tokens.len() {
            if self.match_token(&Token::Dot) {
                if let Some(Token::Ident(prop)) = self.peek().cloned() {
                    self.next();
                    callee_parts.push(prop);
                } else {
                    return Err("expected identifier after '.'".to_string());
                }
            } else if self.match_token(&Token::OpenBracket) {
                self.parse_expression()?;
                if !self.match_token(&Token::CloseBracket) {
                    return Err("unclosed bracket in member access".to_string());
                }
                callee_parts.push("$computed".to_string());
            } else if self.peek() == Some(&Token::OpenParen) {
                let args = self.parse_call_args()?;
                self.record_call(&callee_parts, args);
                callee_parts = vec!["$call_result".to_string()];
            } else {
                break;
            }
        }

        Ok(())
    }

    fn parse_call_args(&mut self) -> Result<Vec<String>, String> {
        if !self.match_token(&Token::OpenParen) {
            return Err("expected '(' for call arguments".to_string());
        }
        let mut args = Vec::new();
        while self.pos < self.tokens.len() {
            if self.match_token(&Token::CloseParen) {
                break;
            }
            let arg_val = self.parse_argument_value()?;
            args.push(arg_val);
            if self.match_token(&Token::Comma) {
                continue;
            } else if self.peek() == Some(&Token::CloseParen) {
                self.next();
                break;
            } else {
                return Err(format!("expected ',' or ')' after argument, got '{:?}'", self.peek()));
            }
        }
        Ok(args)
    }

    fn parse_argument_value(&mut self) -> Result<String, String> {
        let peeked = self.peek().cloned();
        match peeked {
            Some(Token::StringLit(s)) => {
                self.next();
                // Check if string concatenation: 'a' + 'b'
                if self.match_token(&Token::Plus) {
                    let next_val = self.parse_argument_value()?;
                    Ok(format!("{s}{next_val}"))
                } else {
                    Ok(s)
                }
            }
            Some(Token::NumberLit(n)) => {
                self.next();
                Ok(n)
            }
            Some(Token::Ident(id)) => {
                self.next();
                let val = if let Some(v) = self.bindings.get(&id) {
                    v.clone()
                } else {
                    format!("${id}")
                };
                if self.match_token(&Token::Plus) {
                    let next_val = self.parse_argument_value()?;
                    Ok(format!("{val}{next_val}"))
                } else {
                    Ok(val)
                }
            }
            Some(Token::OpenBracket) => {
                // Array literal: ['-rf', '/']
                self.next();
                let mut elements = Vec::new();
                while self.pos < self.tokens.len() {
                    if self.match_token(&Token::CloseBracket) {
                        break;
                    }
                    let el = self.parse_argument_value()?;
                    elements.push(el);
                    self.match_token(&Token::Comma);
                }
                Ok(serde_json::to_string(&elements).unwrap_or_else(|_| "$array".to_string()))
            }
            Some(Token::OpenBrace) => {
                // Object literal
                self.next();
                let mut depth = 1;
                while self.pos < self.tokens.len() && depth > 0 {
                    match self.next().unwrap() {
                        Token::OpenBrace => depth += 1,
                        Token::CloseBrace => depth -= 1,
                        _ => {}
                    }
                }
                Ok("$object".to_string())
            }
            Some(t) => Err(format!("unexpected token '{:?}' in argument", t)),
            None => Err("unexpected end of input in argument".to_string()),
        }
    }

    fn record_call(&mut self, callee_parts: &[String], args: Vec<String>) {
        if callee_parts.is_empty() {
            return;
        }

        // Resolve module alias:
        let first = &callee_parts[0];
        let mut canonical_parts = Vec::new();
        if let Some(target) = self.modules.get(first) {
            for seg in target.split('.') {
                canonical_parts.push(seg.to_string());
            }
            canonical_parts.extend(callee_parts[1..].iter().cloned());
        } else {
            canonical_parts = callee_parts.to_vec();
        }

        let full_name = canonical_parts.join(".");

        // Check for dynamic_call (eval)
        if full_name == "eval" {
            self.out.note("dynamic_call");
            self.out.push_cmd(
                "javascript:eval".to_string(),
                args,
                Order::Seq(self.seq),
                crate::syntax::InputSource::Unknown,
                true,
                None,
                vec![],
                None,
                HashMap::new(),
                false,
            );
            self.seq += 1;
            return;
        }

        // Check for subprocess spawn / spawnSync / execFile / execFileSync
        if full_name == "child_process.spawn"
            || full_name == "child_process.spawnSync"
            || full_name == "spawn"
            || full_name == "spawnSync"
            || full_name == "child_process.execFile"
            || full_name == "child_process.execFileSync"
            || full_name == "execFile"
            || full_name == "execFileSync"
        {
            // arg0 is binary name, arg1 is args array
            let prog = args.first().cloned().unwrap_or_default();
            let mut argv = vec![prog];
            if let Some(arg1) = args.get(1) {
                if let Ok(extra_args) = serde_json::from_str::<Vec<String>>(arg1) {
                    argv.extend(extra_args);
                } else if !arg1.is_empty() && arg1 != "$?" {
                    argv.push(arg1.clone());
                }
            }
            let argv_json = serde_json::to_string(&argv).unwrap_or_default();
            let head = format!("javascript:{full_name}");
            self.out.push_cmd(
                head,
                vec![argv_json],
                Order::Seq(self.seq),
                crate::syntax::InputSource::Unknown,
                true,
                None,
                vec![],
                None,
                HashMap::new(),
                false,
            );
            self.seq += 1;
            return;
        }

        // Standard command emission:
        let head = format!("javascript:{full_name}");
        self.out.push_cmd(
            head,
            args,
            Order::Seq(self.seq),
            crate::syntax::InputSource::Unknown,
            true,
            None,
            vec![],
            None,
            HashMap::new(),
            false,
        );
        self.seq += 1;
    }
}

pub fn parse(src: &str) -> Result<Scan, String> {
    let tokens = tokenize(src)?;
    let mut parser = Parser::new(&tokens);
    parser.parse_all()?;
    Ok(parser.out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_pure_math_and_console_log() {
        let scan = parse("const x = 1 + 2; console.log(x);").unwrap();
        assert_eq!(scan.commands.len(), 1);
        assert_eq!(scan.commands[0].head, "javascript:console.log");
        assert_eq!(scan.commands[0].args, vec!["$x"]);
    }

    #[test]
    fn parses_subprocess_exec_sync() {
        let scan = parse("require('child_process').execSync('rm -rf /');").unwrap();
        assert_eq!(scan.commands.len(), 1);
        assert_eq!(scan.commands[0].head, "javascript:child_process.execSync");
        assert_eq!(scan.commands[0].args, vec!["rm -rf /"]);
    }

    #[test]
    fn parses_destructured_exec_sync() {
        let scan = parse("const { execSync } = require('child_process'); execSync('echo hi');").unwrap();
        assert_eq!(scan.commands.len(), 1);
        assert_eq!(scan.commands[0].head, "javascript:child_process.execSync");
        assert_eq!(scan.commands[0].args, vec!["echo hi"]);
    }

    #[test]
    fn parses_aliased_child_process() {
        let scan = parse("const cp = require('child_process'); cp.execSync('date');").unwrap();
        assert_eq!(scan.commands.len(), 1);
        assert_eq!(scan.commands[0].head, "javascript:child_process.execSync");
        assert_eq!(scan.commands[0].args, vec!["date"]);
    }

    #[test]
    fn parses_spawn_sync_into_argv() {
        let scan = parse("require('child_process').spawnSync('rm', ['-rf', '/']);").unwrap();
        assert_eq!(scan.commands.len(), 1);
        assert_eq!(scan.commands[0].head, "javascript:child_process.spawnSync");
        assert_eq!(scan.commands[0].args, vec![r#"["rm","-rf","/"]"#]);
    }

    #[test]
    fn parses_fs_write_file_sync() {
        let scan = parse("const fs = require('fs'); fs.writeFileSync('/tmp/out.txt', 'hello');").unwrap();
        assert_eq!(scan.commands.len(), 1);
        assert_eq!(scan.commands[0].head, "javascript:fs.writeFileSync");
        assert_eq!(scan.commands[0].args, vec!["/tmp/out.txt", "hello"]);
    }

    #[test]
    fn notes_dynamic_call_on_eval() {
        let scan = parse("eval('1 + 2');").unwrap();
        assert!(scan.constructs.contains(&"dynamic_call".to_string()));
    }

    #[test]
    fn notes_dynamic_call_on_new_function() {
        let scan = parse("const f = new Function('return 42');").unwrap();
        assert!(scan.constructs.contains(&"dynamic_call".to_string()));
    }

    #[test]
    fn refuses_unclosed_quotes() {
        assert!(parse("console.log('unclosed);").is_err());
        assert!(parse("console.log(\"unclosed);").is_err());
        assert!(parse("console.log(`unclosed);").is_err());
    }

    #[test]
    fn refuses_unbalanced_delimiters() {
        assert!(parse("console.log(42;").is_err());
        assert!(parse("function foo() { console.log(42);").is_err());
    }
}
