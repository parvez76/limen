//! `parvez fmt`: one canonical layout for `.prvz` and `.msd` files.
//!
//! Formatting is line-based so comments survive: indentation becomes 4 spaces
//! per block level, spacing around `,` `:` `=` `->` and brackets is normalized,
//! blank lines are collapsed, and top-level items are separated by one blank
//! line. Every change is verified: the token stream (`.prvz`) or the parsed
//! pages (`.msd`) must be identical before and after, otherwise the file is
//! left untouched and an error is reported.
use crate::lexer::lex;
use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};

/// Formats `path` (a file, or every .prvz/.msd under a directory). Returns the
/// files that changed (or would change, with `check`).
pub fn run(path: &Path, check: bool) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    collect(path, &mut files)?;
    if files.is_empty() {
        bail!("no .prvz or .msd files under {}", path.display());
    }
    let mut changed = Vec::new();
    for f in files {
        let src = std::fs::read_to_string(&f).with_context(|| format!("reading {}", f.display()))?;
        let out = format_file(&f, &src).with_context(|| format!("formatting {}", f.display()))?;
        if out != src {
            if !check {
                std::fs::write(&f, &out)?;
                eprintln!("parvez: formatted {}", f.display());
            }
            changed.push(f);
        }
    }
    Ok(changed)
}

fn collect(path: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let meta = std::fs::symlink_metadata(path).with_context(|| format!("{}", path.display()))?;
    if meta.is_file() {
        if matches!(path.extension().and_then(|e| e.to_str()), Some("prvz" | "msd")) {
            out.push(path.to_path_buf());
        }
        return Ok(());
    }
    if !meta.is_dir() {
        return Ok(());
    }
    let mut entries: Vec<_> = std::fs::read_dir(path)?.collect::<std::io::Result<_>>()?;
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let name = e.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') || matches!(name.as_str(), "target" | "node_modules") {
            continue;
        }
        collect(&e.path(), out)?;
    }
    Ok(())
}

pub fn format_file(path: &Path, src: &str) -> Result<String> {
    let masud = path.extension().is_some_and(|e| e == "msd");
    let out = format_source(src, masud);
    verify(src, &out, masud)?;
    Ok(out)
}

/// Same program before and after: identical tokens (.prvz) or pages (.msd).
fn verify(before: &str, after: &str, masud: bool) -> Result<()> {
    if masud {
        let a = crate::masud::parse(before, 1).map(|i| strip_lines(&format!("{i:?}")));
        let b = crate::masud::parse(after, 1).map(|i| strip_lines(&format!("{i:?}")));
        match (a, b) {
            (Ok(a), Ok(b)) if a == b => Ok(()),
            (Err(e), _) => bail!("{e}"),
            _ => bail!("internal error: formatting would change this page; file left unchanged (please report it)"),
        }
    } else {
        let toks = |s: &str| lex(s).map(|t| t.into_iter().map(|t| t.tok).collect::<Vec<_>>());
        let a = toks(before)?;
        match toks(after) {
            Ok(b) if a == b => Ok(()),
            _ => bail!("internal error: formatting would change this program; file left unchanged (please report it)"),
        }
    }
}

/// Debug output with `line: N` values removed (blank-line changes move lines).
fn strip_lines(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find("line: ") {
        out.push_str(&rest[..i]);
        rest = rest[i + 6..].trim_start_matches(|c: char| c.is_ascii_digit());
    }
    out.push_str(rest);
    out
}

const ITEM_STARTS: &[&str] = &[
    "fn ", "async ", "type ", "enum ", "impl ", "impl<", "trait ", "route ", "socket ", "test ", "state:", "every ",
    "page ", "priv ", "const ", "@", "#",
];

fn format_source(src: &str, masud: bool) -> String {
    let lines: Vec<&str> = src.lines().collect();
    let mut out: Vec<String> = Vec::new();
    // block indentation: original widths of open levels
    let mut stack: Vec<usize> = vec![0];
    let mut depth = 0usize; // open ( [ { across lines
    let mut cont_indent = 0usize; // new indent for continuation lines
    let mut k = 0;
    while k < lines.len() {
        let raw = lines[k].trim_end();
        k += 1;
        if raw.trim().is_empty() {
            out.push(String::new());
            continue;
        }
        let width = raw.len() - raw.trim_start_matches(' ').len();
        let body = &raw[width..];
        // continuation: inside brackets, or a `.method` line continuing a chain
        if depth > 0 || (!masud && body.starts_with('.') && body[1..].starts_with(|c: char| c.is_alphabetic() || c == '_')) {
            let text = if masud { body.to_string() } else { normalize(body) };
            depth = (depth as isize + bracket_delta(body)).max(0) as usize;
            out.push(format!("{}{}", " ".repeat(cont_indent), text));
            continue;
        }
        if body.starts_with('#') && !masud {
            // comments keep their nesting relative to the current block
            // a comment opening a deeper block belongs to that block
            let level = if width > *stack.last().unwrap() {
                stack.len()
            } else {
                stack.iter().filter(|w| **w <= width).count().saturating_sub(1)
            };
            out.push(format!("{}{}", "    ".repeat(level), comment(body)));
            continue;
        }
        while stack.len() > 1 && width < *stack.last().unwrap() {
            stack.pop();
        }
        if width > *stack.last().unwrap() {
            stack.push(width);
        }
        let level = stack.len() - 1;
        let indent = "    ".repeat(level);
        let text = if masud { body.to_string() } else { normalize(body) };
        out.push(format!("{indent}{text}"));
        cont_indent = level * 4 + 4;
        if !masud {
            depth = (depth as isize + bracket_delta(body)).max(0) as usize;
            // """multi-line strings: shift their lines with the opening line
            if count_triple(body) % 2 == 1 {
                let delta = (level * 4) as isize - width as isize;
                while k < lines.len() {
                    let l = lines[k];
                    k += 1;
                    let w = l.len() - l.trim_start_matches(' ').len();
                    let shifted = if l.trim().is_empty() {
                        String::new()
                    } else {
                        let nw = (w as isize + delta).max(0) as usize;
                        format!("{}{}", " ".repeat(nw), l.trim_start_matches(' ').trim_end())
                    };
                    let closes = count_triple(l) % 2 == 1;
                    out.push(shifted);
                    if closes {
                        // brackets after the closing quotes, e.g. `""")`
                        let after = l.rsplit_once("\"\"\"").map(|(_, a)| a).unwrap_or("");
                        depth = (depth as isize + bracket_delta(after)).max(0) as usize;
                        break;
                    }
                }
            }
        }
    }
    layout_blank_lines(out)
}

/// Collapse blank runs, trim the file's ends, and put one blank line before a
/// top-level item that follows an indented block.
fn layout_blank_lines(lines: Vec<String>) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut pending_blank = false;
    for l in lines {
        if l.is_empty() {
            pending_blank = !out.is_empty();
            continue;
        }
        let top_item = !l.starts_with(' ') && ITEM_STARTS.iter().any(|s| l.starts_with(s));
        let after_block = out.last().is_some_and(|p| p.starts_with(' '));
        if pending_blank || (top_item && after_block) {
            out.push(String::new());
        }
        pending_blank = false;
        out.push(l);
    }
    let mut s = out.join("\n");
    s.push('\n');
    s
}

fn comment(c: &str) -> String {
    let rest = c.trim_start_matches('#');
    let hashes = &c[..c.len() - rest.len()];
    if rest.is_empty() || rest.starts_with(' ') { c.to_string() } else { format!("{hashes} {rest}") }
}

fn count_triple(line: &str) -> usize {
    // `"""` outside ordinary strings and comments
    let c: Vec<char> = line.chars().collect();
    let (mut i, mut n, mut in_str) = (0, 0, false);
    while i < c.len() {
        if !in_str && c[i] == '#' {
            break;
        }
        if c[i] == '"' && i + 2 < c.len() && c[i + 1] == '"' && c[i + 2] == '"' {
            n += 1;
            i += 3;
            continue;
        }
        if c[i] == '\\' {
            i += 2;
            continue;
        }
        if c[i] == '"' {
            in_str = !in_str;
        }
        i += 1;
    }
    n
}

/// Net `(`/`[`/`{` opened by the code part of a line (strings and comments skipped).
fn bracket_delta(line: &str) -> isize {
    let mut d = 0;
    for seg in segments(line) {
        if let Seg::Code(s) = seg {
            for ch in s.chars() {
                match ch {
                    '(' | '[' | '{' => d += 1,
                    ')' | ']' | '}' => d -= 1,
                    _ => {}
                }
            }
        }
    }
    d
}

enum Seg {
    Code(String),
    /// a string or char literal, verbatim
    Lit(String),
    Comment(String),
}

fn segments(line: &str) -> Vec<Seg> {
    let c: Vec<char> = line.chars().collect();
    let mut out = Vec::new();
    let mut code = String::new();
    let mut i = 0;
    while i < c.len() {
        match c[i] {
            '#' => {
                if !code.is_empty() {
                    out.push(Seg::Code(std::mem::take(&mut code)));
                }
                out.push(Seg::Comment(c[i..].iter().collect()));
                return out;
            }
            q @ ('"' | '\'') => {
                if !code.is_empty() {
                    out.push(Seg::Code(std::mem::take(&mut code)));
                }
                let start = i;
                // """ on this line: keep the rest verbatim
                if q == '"' && i + 2 < c.len() && c[i + 1] == '"' && c[i + 2] == '"' {
                    out.push(Seg::Lit(c[start..].iter().collect()));
                    return out;
                }
                i += 1;
                while i < c.len() && c[i] != q {
                    if c[i] == '\\' {
                        i += 1;
                    }
                    i += 1;
                }
                i = (i + 1).min(c.len());
                out.push(Seg::Lit(c[start..i].iter().collect()));
                continue;
            }
            ch => code.push(ch),
        }
        i += 1;
    }
    if !code.is_empty() {
        out.push(Seg::Code(code));
    }
    out
}

/// Canonical spacing for one line of code (strings, chars and comments untouched).
/// Literals are swapped for one placeholder char each while spacing runs.
fn normalize(line: &str) -> String {
    let mut code = String::new();
    let mut lits: Vec<String> = Vec::new();
    let mut tail = None;
    for seg in segments(line) {
        match seg {
            Seg::Code(s) => code.push_str(&s),
            Seg::Lit(s) => {
                code.push(char::from_u32(0xE000 + lits.len() as u32).unwrap_or('\u{E000}'));
                lits.push(s);
            }
            Seg::Comment(c) => tail = Some(comment(&c)),
        }
    }
    let spaced = space_code(&code);
    let mut out = String::new();
    for ch in spaced.chars() {
        let k = ch as u32;
        if (0xE000..0xE000 + lits.len() as u32).contains(&k) {
            out.push_str(&lits[(k - 0xE000) as usize]);
        } else {
            out.push(ch);
        }
    }
    match tail {
        Some(c) if out.trim().is_empty() => c,
        Some(c) => format!("{}  {c}", out.trim_end()),
        None => out,
    }
}

fn space_code(s: &str) -> String {
    let c: Vec<char> = s.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    fn push_sp(out: &mut String) {
        if !out.is_empty() && !out.ends_with(' ') {
            out.push(' ');
        }
    }
    while i < c.len() {
        let ch = c[i];
        let next = c.get(i + 1).copied().unwrap_or('\0');
        let two: String = [ch, next].iter().collect();
        match ch {
            ' ' => {
                let run = c[i..].iter().take_while(|x| **x == ' ').count();
                let following = c.get(i + run).copied();
                let after = c.get(i + run + 1).copied();
                let prev = out.chars().last();
                let drop = matches!(following, Some(',' | ')' | ']' | '}') | None)
                    || matches!(prev, Some('(' | '[' | '{') | None)
                    || (following == Some(':') && after != Some(':'));
                if !drop {
                    push_sp(&mut out);
                }
                i += run;
                continue;
            }
            ',' => {
                while out.ends_with(' ') {
                    out.pop();
                }
                out.push(',');
                if !matches!(next, ' ' | ')' | ']' | '}' | '\0') {
                    out.push(' ');
                }
            }
            ':' if next == ':' => {
                out.push_str("::");
                i += 2;
                continue;
            }
            ':' => {
                while out.ends_with(' ') {
                    out.pop();
                }
                out.push(':');
                if !matches!(next, ' ' | '\0') {
                    out.push(' ');
                }
            }
            _ if ["==", "!=", "<=", ">=", "+=", "-=", "*=", "/=", "%=", "->"].contains(&two.as_str()) => {
                push_sp(&mut out);
                out.push_str(&two);
                if !matches!(c.get(i + 2), Some(' ') | None) {
                    out.push(' ');
                }
                i += 2;
                continue;
            }
            '=' => {
                push_sp(&mut out);
                out.push('=');
                if !matches!(next, ' ' | '\0') {
                    out.push(' ');
                }
            }
            _ => out.push(ch),
        }
        i += 1;
    }
    out.trim_end().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_layout_spacing_and_keeps_comments() {
        let src = "import store\n# models\n@json\ntype Item:  id:i64,name : str\nfn f(a:i64,b :i64)->i64:\n  # body\n  x=a+b   # sum\n  if x>=3 :ret x\n  m = { \"a\":1 , \"b\" :2 }\n  q = sqlx::query(\"\"\"\n      SELECT 1\n        FROM t\n      \"\"\")\n      .bind(x)\n  ret x\n@public\nroute GET \"/x\" -> str:\n      ret \"a,b:c=d\"\n\n\n\ntest \"t\":\n  assert(f(1,2)==3)\n";
        let want = "import store\n# models\n@json\ntype Item: id: i64, name: str\nfn f(a: i64, b: i64) -> i64:\n    # body\n    x = a+b  # sum\n    if x >= 3: ret x\n    m = {\"a\": 1, \"b\": 2}\n    q = sqlx::query(\"\"\"\n        SELECT 1\n          FROM t\n        \"\"\")\n        .bind(x)\n    ret x\n\n@public\nroute GET \"/x\" -> str:\n    ret \"a,b:c=d\"\n\ntest \"t\":\n    assert(f(1, 2) == 3)\n";
        let out = format_file(Path::new("a.prvz"), src).unwrap();
        assert_eq!(out, want, "\n{out}");
        // idempotent
        assert_eq!(format_file(Path::new("a.prvz"), &out).unwrap(), out);
    }

    #[test]
    fn masud_indentation_is_normalized_and_verified() {
        let src = "@public\npage GET \"/\" -> html:\n  ul:\n     li a\n     li b\n  p done   \n";
        let out = format_file(Path::new("p.msd"), src).unwrap();
        assert_eq!(out, "@public\npage GET \"/\" -> html:\n    ul:\n        li a\n        li b\n    p done\n");
        assert!(format_file(Path::new("p.msd"), "@public\npage GET \"/\" -> html:\n    p {x\n").is_err());
    }
}
