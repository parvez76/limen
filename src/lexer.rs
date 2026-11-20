//! Hand-written lexer. Produces INDENT/DEDENT tokens from leading spaces,
//! and ignores newlines inside (), [] so expressions may span lines.

use anyhow::{Result, bail};

#[derive(Debug, Clone, PartialEq)]
pub enum Tok {
    Ident(String),
    Int(String),
    Float(String),
    /// Raw string body (escape sequences kept verbatim, Rust-compatible).
    Str(String),
    /// `'a'`, `'\n'`, `'\u{1F600}'`: raw body between the quotes
    Char(String),
    // keywords
    Fn,
    Type,
    If,
    Elif,
    Else,
    For,
    In,
    While,
    Ret,
    Break,
    Continue,
    True,
    False,
    And,
    Or,
    Not,
    Match,
    Enum,
    Impl,
    Use,
    Async,
    // operators / punctuation
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    Assign,
    PlusEq,
    MinusEq,
    StarEq,
    SlashEq,
    PercentEq,
    Eq,
    Ne,
    Lt,
    Gt,
    Le,
    Ge,
    Arrow,
    LParen,
    RParen,
    LBracket,
    RBracket,
    Comma,
    Colon,
    PathSep,
    Dot,
    DotDot,
    DotDotEq,
    Question,
    Bang,
    Tilde,
    Amp,
    Pipe,
    LBrace,
    RBrace,
    At,
    // layout
    Newline,
    Indent,
    Dedent,
    Eof,
}

#[derive(Debug, Clone)]
pub struct Token {
    pub tok: Tok,
    pub line: usize,
}

fn keyword(s: &str) -> Option<Tok> {
    Some(match s {
        "fn" => Tok::Fn,
        "type" => Tok::Type,
        "if" => Tok::If,
        "elif" => Tok::Elif,
        "else" => Tok::Else,
        "for" => Tok::For,
        "in" => Tok::In,
        "while" => Tok::While,
        "ret" => Tok::Ret,
        "break" => Tok::Break,
        "continue" => Tok::Continue,
        "true" => Tok::True,
        "false" => Tok::False,
        "and" => Tok::And,
        "or" => Tok::Or,
        "not" => Tok::Not,
        "match" => Tok::Match,
        "enum" => Tok::Enum,
        "impl" => Tok::Impl,
        "use" => Tok::Use,
        "async" => Tok::Async,
        _ => return None,
    })
}

/// Spelling of a keyword token (keywords may be used as field names).
pub fn keyword_text(t: &Tok) -> Option<&'static str> {
    Some(match t {
        Tok::Fn => "fn",
        Tok::Type => "type",
        Tok::If => "if",
        Tok::Elif => "elif",
        Tok::Else => "else",
        Tok::For => "for",
        Tok::In => "in",
        Tok::While => "while",
        Tok::Ret => "ret",
        Tok::Break => "break",
        Tok::Continue => "continue",
        Tok::True => "true",
        Tok::False => "false",
        Tok::And => "and",
        Tok::Or => "or",
        Tok::Not => "not",
        Tok::Match => "match",
        Tok::Enum => "enum",
        Tok::Impl => "impl",
        Tok::Use => "use",
        Tok::Async => "async",
        _ => return None,
    })
}

/// Body of a `"""` string -> raw one-line string content: drop the newline
/// after the opening quotes and the indentation-only last line, remove the
/// common indentation, then escape newlines, tabs and quotes.
fn triple_quoted(body: &str) -> String {
    let body = body.strip_prefix("\r\n").or_else(|| body.strip_prefix('\n')).unwrap_or(body);
    let mut lines: Vec<&str> = body.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l)).collect();
    if lines.len() > 1 && lines.last().is_some_and(|l| l.trim().is_empty()) {
        lines.pop();
    }
    let indent = lines
        .iter()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.len() - l.trim_start().len())
        .min()
        .unwrap_or(0);
    let mut out = String::new();
    for (k, l) in lines.iter().enumerate() {
        if k > 0 {
            out.push_str("\\n");
        }
        let l = if l.len() >= indent { &l[indent..] } else { l.trim_start() };
        for ch in l.chars() {
            match ch {
                '"' => out.push_str("\\\""),
                '\t' => out.push_str("\\t"),
                _ => out.push(ch),
            }
        }
    }
    out
}

pub fn lex(src: &str) -> Result<Vec<Token>> {
    lex_from(src, 1)
}

/// Lex starting at a given line number (used for string interpolation).
pub fn lex_from(src: &str, start_line: usize) -> Result<Vec<Token>> {
    let c: Vec<char> = src.chars().collect();
    let n = c.len();
    let mut i = 0;
    let mut line = start_line;
    let mut out: Vec<Token> = Vec::new();
    let mut indents = vec![0usize];
    let mut open: Vec<usize> = Vec::new(); // lines of unclosed ( / [
    let mut at_start = true;

    macro_rules! push {
        ($t:expr) => {
            out.push(Token { tok: $t, line })
        };
    }

    while i < n {
        if at_start && open.is_empty() {
            let mut col = 0;
            while i < n && c[i] == ' ' {
                col += 1;
                i += 1;
            }
            if i >= n {
                break;
            }
            match c[i] {
                '\t' => bail!("line {line}: tabs are not allowed for indentation; use spaces"),
                '\r' => {
                    i += 1;
                    continue;
                }
                '\n' => {
                    i += 1;
                    line += 1;
                    continue;
                }
                '#' => {
                    while i < n && c[i] != '\n' {
                        i += 1;
                    }
                    continue;
                }
                _ => {}
            }
            let top = *indents.last().unwrap();
            if col > top {
                indents.push(col);
                push!(Tok::Indent);
            } else if col < top {
                while col < *indents.last().unwrap() {
                    indents.pop();
                    push!(Tok::Dedent);
                }
                if col != *indents.last().unwrap() {
                    bail!("line {line}: inconsistent dedent (indentation does not match any outer block)");
                }
            }
            at_start = false;
            continue;
        }

        let ch = c[i];
        let next = if i + 1 < n { c[i + 1] } else { '\0' };
        match ch {
            ' ' | '\t' | '\r' => i += 1,
            '\n' => {
                i += 1;
                line += 1;
                if open.is_empty() {
                    // A next line starting with `.name` continues a method chain.
                    let mut j = i;
                    while j < n && (c[j] == ' ' || c[j] == '\t' || c[j] == '\r') {
                        j += 1;
                    }
                    let continues = j + 1 < n && c[j] == '.' && (c[j + 1].is_alphabetic() || c[j + 1] == '_');
                    if continues {
                        i = j;
                    } else {
                        line -= 1;
                        push!(Tok::Newline);
                        line += 1;
                        at_start = true;
                    }
                }
            }
            '\'' => {
                let start = i;
                i += 1;
                let mut body = String::new();
                while i < n && c[i] != '\'' && c[i] != '\n' {
                    if c[i] == '\\' && i + 1 < n {
                        body.push(c[i]);
                        body.push(c[i + 1]);
                        i += 2;
                        continue;
                    }
                    body.push(c[i]);
                    i += 1;
                }
                let one_char = body.chars().count() == 1 || body.starts_with('\\');
                if i >= n || c[i] != '\'' || body.is_empty() || !one_char {
                    let _ = start;
                    bail!("line {line}: invalid char literal; use 'x' (one character) or \"text\" for strings");
                }
                i += 1;
                push!(Tok::Char(body));
            }
            '#' => {
                while i < n && c[i] != '\n' {
                    i += 1;
                }
            }
            '"' if i + 2 < n && c[i + 1] == '"' && c[i + 2] == '"' => {
                // """multi-line""": dedented, newlines/quotes escaped so the
                // body is a valid one-line Rust string literal.
                let start_line = line;
                i += 3;
                let mut body = String::new();
                loop {
                    if i + 2 >= n {
                        bail!("line {start_line}: unterminated \"\"\" string");
                    }
                    if c[i] == '"' && c[i + 1] == '"' && c[i + 2] == '"' {
                        i += 3;
                        break;
                    }
                    if c[i] == '\n' {
                        line += 1;
                    }
                    if c[i] == '\\' && i + 1 < n {
                        body.push(c[i]);
                        body.push(c[i + 1]);
                        i += 2;
                        continue;
                    }
                    body.push(c[i]);
                    i += 1;
                }
                let tok = Tok::Str(triple_quoted(&body));
                out.push(Token { tok, line: start_line });
            }
            '"' => {
                i += 1;
                let mut s = String::new();
                loop {
                    if i >= n || c[i] == '\n' {
                        bail!("line {line}: unterminated string literal");
                    }
                    if c[i] == '"' {
                        i += 1;
                        break;
                    }
                    if c[i] == '\\' && i + 1 < n {
                        s.push(c[i]);
                        s.push(c[i + 1]);
                        i += 2;
                        continue;
                    }
                    s.push(c[i]);
                    i += 1;
                }
                push!(Tok::Str(s));
            }
            d if d.is_ascii_digit() => {
                let st = i;
                while i < n && (c[i].is_ascii_digit() || c[i] == '_') {
                    i += 1;
                }
                let mut float = false;
                if i + 1 < n && c[i] == '.' && c[i + 1].is_ascii_digit() {
                    float = true;
                    i += 1;
                    while i < n && (c[i].is_ascii_digit() || c[i] == '_') {
                        i += 1;
                    }
                }
                let s: String = c[st..i].iter().collect();
                push!(if float { Tok::Float(s) } else { Tok::Int(s) });
            }
            a if a.is_alphabetic() || a == '_' => {
                let st = i;
                while i < n && (c[i].is_alphanumeric() || c[i] == '_') {
                    i += 1;
                }
                let s: String = c[st..i].iter().collect();
                push!(keyword(&s).unwrap_or(Tok::Ident(s)));
            }
            _ => {
                let (tok, len) = match (ch, next) {
                    ('-', '>') => (Tok::Arrow, 2),
                    ('+', '=') => (Tok::PlusEq, 2),
                    ('-', '=') => (Tok::MinusEq, 2),
                    ('*', '=') => (Tok::StarEq, 2),
                    ('/', '=') => (Tok::SlashEq, 2),
                    ('%', '=') => (Tok::PercentEq, 2),
                    ('=', '=') => (Tok::Eq, 2),
                    ('!', '=') => (Tok::Ne, 2),
                    ('<', '=') => (Tok::Le, 2),
                    ('>', '=') => (Tok::Ge, 2),
                    (':', ':') => (Tok::PathSep, 2),
                    ('.', '.') => {
                        if i + 2 < n && c[i + 2] == '=' {
                            (Tok::DotDotEq, 3)
                        } else {
                            (Tok::DotDot, 2)
                        }
                    }
                    ('+', _) => (Tok::Plus, 1),
                    ('-', _) => (Tok::Minus, 1),
                    ('*', _) => (Tok::Star, 1),
                    ('/', _) => (Tok::Slash, 1),
                    ('%', _) => (Tok::Percent, 1),
                    ('=', _) => (Tok::Assign, 1),
                    ('<', _) => (Tok::Lt, 1),
                    ('>', _) => (Tok::Gt, 1),
                    ('(', _) => (Tok::LParen, 1),
                    (')', _) => (Tok::RParen, 1),
                    ('[', _) => (Tok::LBracket, 1),
                    (']', _) => (Tok::RBracket, 1),
                    (',', _) => (Tok::Comma, 1),
                    (':', _) => (Tok::Colon, 1),
                    ('.', _) => (Tok::Dot, 1),
                    ('?', _) => (Tok::Question, 1),
                    ('!', _) => (Tok::Bang, 1),
                    ('~', _) => (Tok::Tilde, 1),
                    ('&', _) => (Tok::Amp, 1),
                    ('|', _) => (Tok::Pipe, 1),
                    ('{', _) => (Tok::LBrace, 1),
                    ('}', _) => (Tok::RBrace, 1),
                    ('@', _) => (Tok::At, 1),
                    _ => bail!("line {line}: unexpected character '{ch}'"),
                };
                match tok {
                    Tok::LParen | Tok::LBracket | Tok::LBrace => open.push(line),
                    Tok::RParen | Tok::RBracket | Tok::RBrace => {
                        if open.pop().is_none() {
                            bail!("line {line}: unmatched '{ch}'");
                        }
                    }
                    _ => {}
                }
                push!(tok);
                i += len;
            }
        }
    }
    if let Some(l) = open.last() {
        bail!("line {l}: unclosed '(' or '['");
    }
    if !matches!(out.last().map(|t| &t.tok), None | Some(Tok::Newline)) {
        push!(Tok::Newline);
    }
    while indents.len() > 1 {
        indents.pop();
        push!(Tok::Dedent);
    }
    push!(Tok::Eof);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn toks(s: &str) -> Vec<Tok> {
        lex(s).unwrap().into_iter().map(|t| t.tok).collect()
    }

    #[test]
    fn indent_dedent() {
        let t = toks("fn f():\n    x = 1\n\n    # c\ny = 2\n");
        assert_eq!(
            t,
            vec![
                Tok::Fn,
                Tok::Ident("f".into()),
                Tok::LParen,
                Tok::RParen,
                Tok::Colon,
                Tok::Newline,
                Tok::Indent,
                Tok::Ident("x".into()),
                Tok::Assign,
                Tok::Int("1".into()),
                Tok::Newline,
                Tok::Dedent,
                Tok::Ident("y".into()),
                Tok::Assign,
                Tok::Int("2".into()),
                Tok::Newline,
                Tok::Eof
            ]
        );
    }

    #[test]
    fn operators_and_ranges() {
        let t = toks("~a += 0..=5 != 1.5 -> ! :: ..");
        assert_eq!(
            t[..10],
            [
                Tok::Tilde,
                Tok::Ident("a".into()),
                Tok::PlusEq,
                Tok::Int("0".into()),
                Tok::DotDotEq,
                Tok::Int("5".into()),
                Tok::Ne,
                Tok::Float("1.5".into()),
                Tok::Arrow,
                Tok::Bang
            ]
        );
    }

    #[test]
    fn newlines_ignored_in_brackets() {
        let t = toks("x = [1,\n  2]\n");
        assert!(!t[..t.len() - 2].contains(&Tok::Newline));
    }

    #[test]
    fn triple_quoted_strings() {
        let t = lex("q = \"\"\"\n    SELECT *\n      FROM t\n    WHERE a = \"x\"\n    \"\"\"\ny = 1\n").unwrap();
        assert_eq!(t[2].tok, Tok::Str("SELECT *\\n  FROM t\\nWHERE a = \\\"x\\\"".into()));
        assert_eq!((t[2].line, t[5].line), (1, 6), "lines keep counting through the string");
        let t = lex("s = \"\"\"one line\"\"\"\n").unwrap();
        assert_eq!(t[2].tok, Tok::Str("one line".into()));
    }

    #[test]
    fn char_literals_and_dot_continuation() {
        let t = toks("c = 'a'\nd = '\\n'\nx = a\n    .b()\n    .c()\ny = 1\n");
        assert_eq!(t[2], Tok::Char("a".into()));
        assert_eq!(t[6], Tok::Char("\\n".into()));
        // `x = a .b() .c()` on one logical line, then `y`
        let nl = t.iter().position(|x| *x == Tok::Ident("y".into())).unwrap();
        assert!(!t[9..nl - 1].contains(&Tok::Newline), "{t:?}");
        assert!(lex("c = 'ab'\n").is_err());
    }

    #[test]
    fn errors() {
        assert!(lex("x = \"abc\n").is_err());
        assert!(lex("fn f():\n\tx = 1\n").is_err());
        assert!(lex("if a:\n        x\n    y\n").is_err());
        assert!(lex("x = \"\"\"abc\n").is_err());
        let e = lex("fn f():\n    x = (1 +\n\n").unwrap_err().to_string();
        assert!(e.starts_with("line 2:"), "{e}");
    }
}
