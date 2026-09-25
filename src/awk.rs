//! AWK script AST snippet scanner (M2.134).
//!
//! Provides lexical analysis and statement recognition for AWK scripts.
//! Recognizes output formatting (`print`, `printf`), field references (`$1`),
//! output write redirections (`print > "file"`, `printf >> "file"`),
//! process execution (`system("cmd")`), and command pipelines (`print | "cmd"`,
//! `"cmd" | getline`), enabling fine-grained allow-listing for read-only AWK
//! invocations while gating writes and process execution.

pub use crate::syntax::{Cmd, InputSource, Order, Scan};

pub const KNOWN_CONSTRUCTS: &[&str] = &[
    "parse_failure",
    "unmodeled_command",
    "dynamic_redirect",
    "unresolved_path",
    "unreadable_language",
];

pub struct Awk;

impl crate::syntax::Scanner for Awk {
    fn lang(&self) -> &'static str {
        "awk"
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
    StringLit(String),
    RegexLit(String),
    Number(String),
    Ident(String),
    Dollar,         // $
    Gt,             // >
    GtGt,           // >>
    Pipe,           // |
    Lt,             // <
    LBrace,         // {
    RBrace,         // }
    LParen,         // (
    RParen,         // )
    LBracket,       // [
    RBracket,       // ]
    Semicolon,      // ;
    Newline,        // \n
    Comma,          // ,
    Assign,         // =
    Op(String),     // operators like +, -, ==, !=, ~, !~
}

fn tokenize(src: &str) -> Result<Vec<Token>, String> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = src.chars().collect();
    let len = chars.len();
    let mut i = 0;

    let mut can_be_regex = true;

    while i < len {
        let c = chars[i];

        if c == '#' {
            // Comment: skip to newline
            while i < len && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }

        if c.is_whitespace() {
            if c == '\n' {
                tokens.push(Token::Newline);
                can_be_regex = true;
            }
            i += 1;
            continue;
        }

        if c == '"' {
            i += 1;
            let mut s = String::new();
            let mut escaped = false;
            let mut closed = false;
            while i < len {
                let sc = chars[i];
                if escaped {
                    match sc {
                        'n' => s.push('\n'),
                        't' => s.push('\t'),
                        'r' => s.push('\r'),
                        '\\' => s.push('\\'),
                        '"' => s.push('"'),
                        other => {
                            s.push('\\');
                            s.push(other);
                        }
                    }
                    escaped = false;
                } else if sc == '\\' {
                    escaped = true;
                } else if sc == '"' {
                    closed = true;
                    i += 1;
                    break;
                } else {
                    s.push(sc);
                }
                i += 1;
            }
            if !closed {
                return Err("unclosed string literal in AWK script".to_string());
            }
            tokens.push(Token::StringLit(s));
            can_be_regex = false;
            continue;
        }

        // Regex literal: /pattern/ when regex is permitted in current grammar position
        if c == '/' && can_be_regex {
            i += 1;
            let mut pattern = String::new();
            let mut escaped = false;
            let mut closed = false;
            while i < len {
                let rc = chars[i];
                if escaped {
                    pattern.push('\\');
                    pattern.push(rc);
                    escaped = false;
                } else if rc == '\\' {
                    escaped = true;
                } else if rc == '/' {
                    closed = true;
                    i += 1;
                    break;
                } else {
                    pattern.push(rc);
                }
                i += 1;
            }
            if !closed {
                return Err("unclosed regex literal in AWK script".to_string());
            }
            tokens.push(Token::RegexLit(pattern));
            can_be_regex = false;
            continue;
        }

        if c == '$' {
            tokens.push(Token::Dollar);
            i += 1;
            can_be_regex = false;
            continue;
        }

        if c == '{' {
            tokens.push(Token::LBrace);
            i += 1;
            can_be_regex = true;
            continue;
        }

        if c == '}' {
            tokens.push(Token::RBrace);
            i += 1;
            can_be_regex = true;
            continue;
        }

        if c == '(' {
            tokens.push(Token::LParen);
            i += 1;
            can_be_regex = true;
            continue;
        }

        if c == ')' {
            tokens.push(Token::RParen);
            i += 1;
            can_be_regex = false;
            continue;
        }

        if c == '[' {
            tokens.push(Token::LBracket);
            i += 1;
            can_be_regex = true;
            continue;
        }

        if c == ']' {
            tokens.push(Token::RBracket);
            i += 1;
            can_be_regex = false;
            continue;
        }

        if c == ';' {
            tokens.push(Token::Semicolon);
            i += 1;
            can_be_regex = true;
            continue;
        }

        if c == ',' {
            tokens.push(Token::Comma);
            i += 1;
            can_be_regex = true;
            continue;
        }

        if c == '>' {
            if i + 1 < len && chars[i + 1] == '>' {
                tokens.push(Token::GtGt);
                i += 2;
            } else if i + 1 < len && chars[i + 1] == '=' {
                tokens.push(Token::Op(">=".to_string()));
                i += 2;
            } else {
                tokens.push(Token::Gt);
                i += 1;
            }
            can_be_regex = true;
            continue;
        }

        if c == '<' {
            if i + 1 < len && chars[i + 1] == '=' {
                tokens.push(Token::Op("<=".to_string()));
                i += 2;
            } else {
                tokens.push(Token::Lt);
                i += 1;
            }
            can_be_regex = true;
            continue;
        }

        if c == '|' {
            if i + 1 < len && chars[i + 1] == '|' {
                tokens.push(Token::Op("||".to_string()));
                i += 2;
            } else {
                tokens.push(Token::Pipe);
                i += 1;
            }
            can_be_regex = true;
            continue;
        }

        if c == '=' {
            if i + 1 < len && chars[i + 1] == '=' {
                tokens.push(Token::Op("==".to_string()));
                i += 2;
            } else {
                tokens.push(Token::Assign);
                i += 1;
            }
            can_be_regex = true;
            continue;
        }

        if c == '!' {
            if i + 1 < len && chars[i + 1] == '=' {
                tokens.push(Token::Op("!=".to_string()));
                i += 2;
            } else if i + 1 < len && chars[i + 1] == '~' {
                tokens.push(Token::Op("!~".to_string()));
                i += 2;
            } else {
                tokens.push(Token::Op("!".to_string()));
                i += 1;
            }
            can_be_regex = true;
            continue;
        }

        if c == '~' {
            tokens.push(Token::Op("~".to_string()));
            i += 1;
            can_be_regex = true;
            continue;
        }

        if c.is_ascii_digit() {
            let start = i;
            while i < len && (chars[i].is_ascii_digit() || chars[i] == '.') {
                i += 1;
            }
            let num: String = chars[start..i].iter().collect();
            tokens.push(Token::Number(num));
            can_be_regex = false;
            continue;
        }

        if c.is_ascii_alphabetic() || c == '_' {
            let start = i;
            while i < len && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            let ident: String = chars[start..i].iter().collect();
            tokens.push(Token::Ident(ident));
            can_be_regex = false;
            continue;
        }

        // Other operators (+, -, *, %, ^)
        tokens.push(Token::Op(c.to_string()));
        i += 1;
        can_be_regex = true;
    }

    Ok(tokens)
}

pub fn parse(src: &str) -> Result<Scan, String> {
    let tokens = tokenize(src)?;
    let mut scan = Scan::default();

    let mut brace_depth: i32 = 0;
    let mut paren_depth: i32 = 0;
    let mut i = 0;
    let n = tokens.len();

    while i < n {
        match &tokens[i] {
            Token::LBrace => {
                brace_depth += 1;
                i += 1;
            }
            Token::RBrace => {
                brace_depth -= 1;
                if brace_depth < 0 {
                    return Err("unmatched closing brace '}' in AWK script".to_string());
                }
                i += 1;
            }
            Token::LParen => {
                paren_depth += 1;
                i += 1;
            }
            Token::RParen => {
                paren_depth -= 1;
                if paren_depth < 0 {
                    return Err("unmatched closing parenthesis ')' in AWK script".to_string());
                }
                i += 1;
            }
            Token::Ident(name) if name == "system" => {
                // system("cmd") invocation
                i += 1;
                if i < n && tokens[i] == Token::LParen {
                    i += 1;
                    if i < n {
                        match &tokens[i] {
                            Token::StringLit(cmd_str) => {
                                scan.push_cmd(
                                    "awk:system".to_string(),
                                    vec![cmd_str.clone()],
                                    Order::Unordered,
                                    InputSource::Nothing,
                                    true,
                                    None,
                                    Vec::new(),
                                    None,
                                    std::collections::HashMap::new(),
                                    false,
                                );
                                i += 1;
                            }
                            _ => {
                                scan.note("unmodeled_command");
                                i += 1;
                            }
                        }
                        // Advance to closing paren
                        while i < n && tokens[i] != Token::RParen {
                            i += 1;
                        }
                        if i < n && tokens[i] == Token::RParen {
                            i += 1;
                        }
                    }
                }
            }
            Token::Ident(name) if name == "print" || name == "printf" => {
                // Scan statement tokens until terminator (newline, semicolon, RBrace)
                // checking for write redirections (> or >>) and pipes (|)
                i += 1;
                while i < n && !matches!(tokens[i], Token::Newline | Token::Semicolon | Token::RBrace) {
                    if matches!(tokens[i], Token::Gt | Token::GtGt) {
                        let is_append = matches!(tokens[i], Token::GtGt);
                        i += 1;
                        // Skip whitespace/newlines if any
                        while i < n && matches!(tokens[i], Token::Newline) {
                            i += 1;
                        }
                        if i < n {
                            match &tokens[i] {
                                Token::StringLit(target_path) => {
                                    scan.redirect_targets.push(target_path.clone());
                                    scan.redirect_order.push(Order::Unordered);
                                    scan.redirect_env.push(std::collections::HashMap::new());
                                    scan.redirect_scope.push(None);
                                    scan.redirect_chain.push(None);
                                    let _ = is_append;
                                    i += 1;
                                }
                                _ => {
                                    scan.note("dynamic_redirect");
                                    i += 1;
                                }
                            }
                        }
                    } else if matches!(tokens[i], Token::Pipe) {
                        i += 1;
                        while i < n && matches!(tokens[i], Token::Newline) {
                            i += 1;
                        }
                        if i < n {
                            match &tokens[i] {
                                Token::StringLit(pipe_cmd) => {
                                    scan.push_cmd(
                                        "awk:pipe_to".to_string(),
                                        vec![pipe_cmd.clone()],
                                        Order::Unordered,
                                        InputSource::Nothing,
                                        true,
                                        None,
                                        Vec::new(),
                                        None,
                                        std::collections::HashMap::new(),
                                        false,
                                    );
                                    i += 1;
                                }
                                _ => {
                                    scan.note("unmodeled_command");
                                    i += 1;
                                }
                            }
                        }
                    } else {
                        i += 1;
                    }
                }
            }
            _ => {
                i += 1;
            }
        }
    }

    if brace_depth != 0 {
        return Err(format!("unclosed brace in AWK script: depth {brace_depth}"));
    }
    if paren_depth != 0 {
        return Err(format!("unclosed parenthesis in AWK script: depth {paren_depth}"));
    }

    Ok(scan)
}
