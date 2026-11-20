//! Masud page headers share the HTTP parser. Template lines lower to typed render
//! statements so rustc and the security linter see the original expressions.
use crate::{
    ast::*,
    lexer::{Tok, lex_from},
    parser,
};
use anyhow::{Result, bail};

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn check_expression(expr: &Expr, line: usize) -> Result<()> {
    let mut private = false;
    visit_expr(expr, &mut |e| private |= matches!(e, Expr::Ident(n) if n == "__masud"));
    if private {
        bail!("line {line}: __masud is reserved for the renderer");
    }
    Ok(())
}

fn content(text: &str, line: usize, raw: bool, dynamic: bool) -> Result<Vec<HtmlPart>> {
    let mut out = Vec::new();
    for p in parser::parse_str(text, line)? {
        match p {
            StrPart::Lit(s) if raw && !s.trim().is_empty() => bail!("line {line}: raw expects {{expr}}"),
            StrPart::Lit(s) => out.push(HtmlPart::Markup(escape(&s))),
            StrPart::Interp(e, None) if dynamic => {
                check_expression(&e, line)?;
                out.push(HtmlPart::Value(e, raw));
            }
            // `{cpu:.1}` / `{n:>5}` / `{x:?}`: formatted like a Parvez string, then escaped
            StrPart::Interp(e, Some(spec)) if dynamic && !raw => {
                check_expression(&e, line)?;
                if !valid_spec(&spec) {
                    bail!("line {line}: unsupported format spec {spec:?} (e.g. {{x:.2}}, {{x:>8}}, {{x:08.3}}, {{x:?}})");
                }
                out.push(HtmlPart::Value(Expr::Str(vec![StrPart::Interp(e, Some(spec))]), false));
            }
            StrPart::Interp(..) => {
                bail!("line {line}: interpolation requires text or a plain text attribute and no format specifier")
            }
        }
    }
    Ok(out)
}

/// Rust format specs without width/precision arguments (`{x:.1$}` etc. would read other args).
fn valid_spec(spec: &str) -> bool {
    !spec.is_empty()
        && spec.len() <= 16
        && !spec.contains('$')
        && !spec.contains('*')
        && spec.chars().all(|c| c.is_ascii_digit() || "<>^+-#.?xXobeE".contains(c))
}

const TAGS: &str = "html head title body main section article aside nav header footer div span h1 h2 h3 h4 h5 h6 p strong em small code pre a button form label input textarea select option table thead tbody tr td th ul ol li dl dt dd details summary time img br hr meta link script canvas svg g path rect circle line polyline polygon text tspan defs linearGradient stop";

/// Inline-SVG presentation/geometry attributes: plain values (escaped), never URLs or script.
const SVG_ATTRS: &[&str] = &[
    "viewBox", "xmlns", "width", "height", "d", "x", "y", "x1", "y1", "x2", "y2", "cx", "cy", "r", "rx", "ry", "points",
    "fill", "stroke", "stroke-width", "stroke-linecap", "stroke-linejoin", "stroke-dasharray", "fill-opacity",
    "stroke-opacity", "opacity", "transform", "text-anchor", "dominant-baseline", "font-size", "font-weight", "offset",
    "stop-color", "stop-opacity", "preserveAspectRatio", "gradientTransform",
];
const VOID: &[&str] = &["input", "img", "br", "hr", "meta", "link"];

fn element(source: &str, line: usize) -> Result<(Vec<HtmlPart>, Option<String>)> {
    let (tag, mut rest) = source.split_at(source.find([' ', '(', ':']).unwrap_or(source.len()));
    if !TAGS.split_whitespace().any(|s| s == tag) {
        bail!("line {line}: unknown Masud element {tag:?}");
    }
    let mut parts = vec![HtmlPart::Markup(format!("<{tag}"))];
    if let Some(attrs) = rest.strip_prefix('(') {
        rest = attrs.trim_start();
        while !rest.starts_with(')') {
            let (key, val) = rest
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("line {line}: expected attribute=value"))?;
            let key = key.trim();
            let data = key.strip_prefix("data-").is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'));
            let svg = SVG_ATTRS.contains(&key);
            if key == "xmlns" && !val.trim_start().starts_with("\"http://www.w3.org/2000/svg\"") {
                bail!("line {line}: xmlns must be \"http://www.w3.org/2000/svg\"");
            }
            let dynamic = matches!(key, "class" | "title" | "alt" | "placeholder" | "value")
                || key.starts_with("aria-")
                || data
                || (svg && key != "xmlns");
            let valid = dynamic
                || svg
                || matches!(
                    key,
                    "id" | "name"
                        | "type"
                        | "href"
                        | "src"
                        | "rel"
                        | "action"
                        | "method"
                        | "for"
                        | "role"
                        | "lang"
                        | "charset"
                        | "hx-get"
                        | "hx-post"
                        | "hx-put"
                        | "hx-patch"
                        | "hx-delete"
                        | "hx-target"
                        | "hx-swap"
                        | "hx-trigger"
                );
            let shape_ok = svg || data || key.bytes().all(|b| b.is_ascii_lowercase() || b == b'-');
            if !valid || !shape_ok {
                bail!("line {line}: unsupported attribute {key:?}");
            }
            let Some(quoted) = val.trim_start().strip_prefix('"') else {
                bail!("line {line}: quote attribute values")
            };
            let Some((value, tail)) = quoted.split_once('"') else {
                bail!("line {line}: unterminated attribute")
            };
            parts.push(HtmlPart::Markup(format!(" {key}=\"")));
            parts.extend(content(value, line, false, dynamic)?);
            parts.push(HtmlPart::Markup("\"".into()));
            rest = tail.trim_start();
        }
        rest = &rest[1..];
    }
    parts.push(HtmlPart::Markup(">".into()));
    let rest = rest.trim();
    if tag == "script" {
        if !rest.is_empty() {
            bail!("line {line}: script elements may only load an external source");
        }
        parts.push(HtmlPart::Markup("</script>".into()));
        return Ok((parts, None));
    }
    if VOID.contains(&tag) {
        if !rest.is_empty() {
            bail!("line {line}: void element {tag} cannot contain text or children");
        }
        return Ok((parts, None));
    }
    if rest == ":" {
        return Ok((parts, Some(tag.into())));
    }
    parts.extend(content(rest, line, false, true)?);
    parts.push(HtmlPart::Markup(format!("</{tag}>")));
    Ok((parts, None))
}

/// An open element or control block in a page template. Block variants carry
/// the enclosing scope's statements (`outer`) while their body is collected.
enum Frame {
    Tag(String),
    For(String, Expr, usize),
    /// branches so far (the last one is being filled), line of the `if`
    If(Vec<(Expr, Block)>, usize),
    Else(Vec<(Expr, Block)>, usize),
    Outer(Box<Frame>, Vec<Located>),
}

impl Frame {
    fn with_outer(self, outer: Vec<Located>) -> Frame {
        Frame::Outer(Box::new(self), outer)
    }
}

/// Closes a frame: an element emits its end tag; a block wraps the collected
/// body into its statement and appends it to the enclosing scope.
fn close(frame: Frame, out: &mut Vec<Located>, line: usize) {
    match frame {
        Frame::Tag(t) => out.push(Located {
            line,
            stmt: Stmt::Render(vec![HtmlPart::Markup(format!("</{t}>"))]),
        }),
        Frame::Outer(inner, outer) => {
            let body = std::mem::replace(out, outer);
            let (stmt, at) = match *inner {
                Frame::For(var, iter, at) => (Stmt::For { var, iter, body }, at),
                Frame::If(mut branches, at) => {
                    branches.last_mut().unwrap().1 = body;
                    (Stmt::If { branches, els: None }, at)
                }
                Frame::Else(branches, at) => (Stmt::If { branches, els: Some(body) }, at),
                other => {
                    close(other, out, line);
                    return;
                }
            };
            out.push(Located { line: at, stmt });
        }
        _ => unreachable!("control frames are always wrapped with their outer scope"),
    }
}

fn visit_stmt_exprs(stmt: &Stmt, line: usize) -> Result<()> {
    match stmt {
        Stmt::For { iter, var, .. } => {
            if var.contains("__masud") {
                bail!("line {line}: __masud is reserved for the renderer");
            }
            check_expression(iter, line)
        }
        Stmt::If { branches, .. } => branches.iter().try_for_each(|(c, _)| check_expression(c, line)),
        _ => Ok(()),
    }
}

pub fn parse(src: &str, start: usize) -> Result<Vec<Item>> {
    let mut iter = src.lines().enumerate().peekable();
    let mut items = Vec::new();
    let mut reason = false;
    let mut guards: Vec<String> = Vec::new();
    let mut public: Option<String> = None;
    while let Some((i, text)) = iter.next() {
        let line = start + i;
        if text.trim().is_empty() || text.trim_start().starts_with('#') {
            continue;
        }
        if text.starts_with("@public") {
            let toks: Vec<Tok> = lex_from(text, line)?.into_iter().map(|t| t.tok).collect();
            public = Some(match &toks[..] {
                [Tok::At, Tok::Ident(k), Tok::Newline, Tok::Eof] if k == "public" => String::new(),
                [Tok::At, Tok::Ident(k), Tok::LParen, Tok::Str(why), Tok::RParen, Tok::Newline, Tok::Eof]
                    if k == "public" && !why.trim().is_empty() =>
                {
                    why.clone()
                }
                _ => bail!("line {line}: expected @public or @public(\"reason\") on its own line"),
            });
            continue;
        }
        if text.starts_with("@guard") {
            // `@guard(fn)` / `@guard(module::fn)`, exactly as on a `route`
            let toks: Vec<Tok> = lex_from(text, line)?.into_iter().map(|t| t.tok).collect();
            let [Tok::At, Tok::Ident(k), Tok::LParen, rest @ ..] = &toks[..] else {
                bail!("line {line}: expected @guard(fn_name)");
            };
            let mut path = Vec::new();
            let mut it = rest.iter();
            loop {
                match (it.next(), it.next()) {
                    (Some(Tok::Ident(seg)), Some(Tok::PathSep)) => path.push(seg.clone()),
                    (Some(Tok::Ident(seg)), Some(Tok::RParen)) => {
                        path.push(seg.clone());
                        break;
                    }
                    _ => bail!("line {line}: expected @guard(fn_name)"),
                }
            }
            if k != "guard" || !matches!((it.next(), it.next()), (Some(Tok::Newline), Some(Tok::Eof))) {
                bail!("line {line}: expected @guard(fn_name) on its own line");
            }
            guards.push(path.join("::"));
            continue;
        }
        if text.starts_with("@allow_unsafe_html") {
            let toks = lex_from(text, line)?;
            let ts: Vec<_> = toks.into_iter().map(|t| t.tok).collect();
            if reason
                || !matches!(&ts[..], [Tok::At, Tok::Ident(k), Tok::LParen, Tok::Str(s), Tok::RParen, Tok::Newline, Tok::Eof] if k == "allow_unsafe_html" && !s.trim().is_empty())
            {
                bail!("line {line}: @allow_unsafe_html requires one non-empty reason");
            }
            reason = true;
            continue;
        }
        if !reason && guards.is_empty() && public.is_none() && text.starts_with("import ") {
            items.extend(parser::parse_items(lex_from(text, line)?)?);
            continue;
        }
        let Some(header) = text
            .trim_end()
            .strip_prefix("page ")
            .and_then(|s| s.strip_suffix(':'))
            .and_then(|s| s.trim_end().strip_suffix("html"))
            .and_then(|s| s.trim_end().strip_suffix("->"))
        else {
            bail!("line {line}: expected page GET \"/path\" -> html:");
        };
        let mut parsed = parser::parse_items(lex_from(&format!("route {header} -> str!: ret \"\""), line)?)?;
        let Some(Item::Route(mut route)) = parsed.pop() else {
            bail!("line {line}: invalid page header");
        };
        if route.method != "GET" {
            bail!("line {line}: pages use GET");
        }
        if route.params.iter().any(|(n, _)| n == "__masud") {
            bail!("line {line}: __masud is reserved");
        }
        route.page = true;
        route.guards = std::mem::take(&mut guards);
        route.public = public.take();
        route.body = vec![Located {
            line,
            stmt: Stmt::Let {
                name: "__masud".into(),
                mutable: true,
                ty: None,
                value: Expr::Str(vec![StrPart::Lit(String::new())]),
            },
        }];
        // Open elements and control blocks; a block keeps the statements of its
        // enclosing scope while its own body is collected in `out`.
        let mut parents: Vec<(usize, Frame)> = Vec::new();
        let mut out: Vec<Located> = std::mem::take(&mut route.body);
        let mut levels = Vec::new();
        let mut child_expected = true;
        let mut last_indent = 0;
        let mut last_line = line;
        while let Some(&(idx, row)) = iter.peek() {
            let n = start + idx;
            if row.trim().is_empty() || row.trim_start().starts_with('#') {
                iter.next();
                continue;
            }
            let indent = row.len() - row.trim_start_matches(' ').len();
            if row[indent..].starts_with('\t') {
                bail!("line {n}: indent Masud with spaces");
            }
            if indent == 0 {
                break;
            }
            iter.next();
            if child_expected {
                if indent <= last_indent {
                    bail!("line {n}: expected indented child");
                }
                levels.push(indent);
            } else {
                while levels.last().is_some_and(|l| *l > indent) {
                    levels.pop();
                }
                if levels.last() != Some(&indent) {
                    bail!("line {n}: invalid template indentation");
                }
            }
            last_indent = indent;
            last_line = n;
            child_expected = false;
            while parents.last().is_some_and(|(i, _)| *i >= indent) {
                let (_, frame) = parents.pop().unwrap();
                close(frame, &mut out, n);
            }
            let row = row.trim();
            if let Some(binding) = row.strip_prefix("let ") {
                let binding = parser::page_binding(binding, n)?;
                if let Stmt::Let { value, .. } = &binding.stmt {
                    check_expression(value, n)?;
                }
                out.push(binding);
                continue;
            }
            let control = ["for ", "if ", "elif ", "else:"].iter().any(|k| row.starts_with(k));
            if control {
                // elif/else continue the `if` that was just closed at this indentation
                let continues = row.starts_with("elif ") || row.starts_with("else");
                let reopened = if continues {
                    match out.pop() {
                        Some(Located { stmt: Stmt::If { branches, els: None }, line }) => Some((branches, line)),
                        _ => bail!("line {n}: {} without a preceding if", if row.starts_with("else") { "else" } else { "elif" }),
                    }
                } else {
                    None
                };
                let frame = if row == "else:" {
                    let (branches, at) = reopened.unwrap();
                    Frame::Else(branches, at)
                } else {
                    let stmt = parser::page_control(row, n)?;
                    visit_stmt_exprs(&stmt.stmt, n)?;
                    match (stmt.stmt, reopened) {
                        (Stmt::For { var, iter, .. }, None) => Frame::For(var, iter, n),
                        (Stmt::If { mut branches, .. }, prev) => {
                            let (cond, _) = branches.pop().unwrap();
                            let (mut before, at) = prev.unwrap_or((Vec::new(), n));
                            before.push((cond, Vec::new()));
                            Frame::If(before, at)
                        }
                        _ => bail!("line {n}: invalid control line"),
                    }
                };
                parents.push((indent, frame.with_outer(std::mem::take(&mut out))));
                child_expected = true;
                continue;
            }
            let mut parts = Vec::new();
            if let Some(raw) = row.strip_prefix("raw ") {
                if !reason {
                    bail!("line {n}: raw needs @allow_unsafe_html(\"reason\") on this page");
                }
                parts.extend(content(raw, n, true, true)?);
            } else {
                let (chunk, parent) = element(row, n)?;
                parts.extend(chunk);
                if let Some(tag) = parent {
                    parents.push((indent, Frame::Tag(tag)));
                    child_expected = true;
                }
            }
            out.push(Located {
                line: n,
                stmt: Stmt::Render(parts),
            });
        }
        if child_expected {
            bail!("line {last_line}: expected indented page content");
        }
        while let Some((_, frame)) = parents.pop() {
            close(frame, &mut out, last_line);
        }
        out.push(Located {
            line: last_line,
            stmt: Stmt::Ret(Some(Expr::Ident("__masud".into()))),
        });
        route.body = out;
        items.push(Item::Route(route));
        reason = false;
    }
    if !guards.is_empty() || public.is_some() {
        bail!("line {}: expected a page after @guard(...) / @public", start + src.lines().count());
    }
    if reason {
        bail!(
            "line {}: expected page after @allow_unsafe_html",
            start + src.lines().count()
        );
    }
    Ok(items)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_nesting_and_unsafe_contexts() {
        for body in [
            "    div:\n    span sibling",
            "    br:\n        p child",
            "    p hello\n        p extra",
            "    a(href=\"{query.url}\") go",
            "    script {query.code}",
            "    div(onclick=\"{x}\") click",
            "    raw {x}",
            "    p {x",
            "    let value = __masud.clone()",
            "    p {__masud}",
            "    p {}",
            "    else:\n        p x",
            "    elif x:\n        p y",
            "    if x:\n        p a\n    else:\n        p b\n    else:\n        p c",
            "    if x:\n    p no child",
            "    for __masud in xs:\n        p y",
            "    for x in __masud.chars():\n        p y",
            "    if __masud.is_empty():\n        p y",
            "    while x:\n        p y",
            "    div:\n        if x:\n            p a\n    elif y:\n        p b",
        ] {
            assert!(parse(&format!("@public\npage GET \"/\" -> html:\n{body}"), 1).is_err(), "{body}");
        }
        let two = "@public\n@allow_unsafe_html(\"reviewed fragment\")\npage GET \"/a\" -> html:\n    raw {x}\n@public\npage GET \"/b\" -> html:\n    raw {x}";
        assert!(parse(two, 1).unwrap_err().to_string().contains("line 7"));
        assert!(parse(&two.replace("reviewed fragment", " "), 1).is_err());
    }

    #[test]
    fn control_blocks_nest_inside_elements() {
        let src = "@public\npage GET \"/\" -> html:\n    ul:\n        for d in &ds:\n            li {d}\n            if d.a:\n                em a\n            elif d.b:\n                em b\n            else:\n                em c\n    p end";
        let items = parse(src, 1).unwrap();
        let Item::Route(r) = &items[0] else { panic!() };
        let kinds: Vec<_> = r.body.iter().map(|l| match &l.stmt {
            Stmt::Render(_) => "render",
            Stmt::For { body, .. } => {
                assert!(matches!(&body[1].stmt, Stmt::If { branches, els: Some(_) } if branches.len() == 2));
                "for"
            }
            Stmt::Ret(_) => "ret",
            _ => "other",
        }).collect();
        assert_eq!(kinds, ["other", "render", "for", "render", "render", "ret"]);
    }

    #[test]
    fn format_specs_svg_canvas_and_data_attributes() {
        let src = "@public\npage GET \"/\" -> html:\n    p {cpu:.1}% {n:>4}\n    svg(viewBox=\"0 0 100 20\" xmlns=\"http://www.w3.org/2000/svg\" width=\"100\"):\n        polyline(points=\"{pts}\" fill=\"none\" stroke=\"#0a7\" stroke-width=\"2\")\n        text(x=\"2\" y=\"12\" font-size=\"8\") {label}\n    canvas(id=\"chart\" width=\"300\" height=\"80\" data-series=\"{series}\") no canvas\n";
        let items = parse(src, 1).unwrap();
        let Item::Route(r) = &items[0] else { panic!() };
        let values: Vec<String> = r.body.iter().filter_map(|l| match &l.stmt {
            Stmt::Render(parts) => Some(parts.iter().map(|p| match p {
                HtmlPart::Markup(m) => m.clone(),
                HtmlPart::Value(Expr::Str(sp), _) => format!("<fmt:{:?}>", sp.iter().filter_map(|x| if let StrPart::Interp(_, s) = x { s.clone() } else { None }).collect::<Vec<_>>()),
                HtmlPart::Value(_, _) => "<v>".into(),
            }).collect::<String>()),
            _ => None,
        }).collect();
        let html = values.join("");
        assert!(html.contains("<p><fmt:[\".1\"]>% <fmt:[\">4\"]></p>"), "{html}");
        assert!(html.contains("<svg viewBox=\"0 0 100 20\" xmlns=\"http://www.w3.org/2000/svg\" width=\"100\">"), "{html}");
        assert!(html.contains("<polyline points=\"<v>\" fill=\"none\""), "{html}");
        assert!(html.contains("<canvas id=\"chart\" width=\"300\" height=\"80\" data-series=\"<v>\">no canvas</canvas>"), "{html}");
        for bad in [
            "    p {x:1$}",
            "    p {x:.*}",
            "    p {x:}x}",
            "    svg(onload=\"{x}\") a",
            "    svg(style=\"x\") a",
            "    path(href=\"{x}\") a",
            "    svg(xmlns=\"http://evil\") a",
            "    div(data-=\"x\") a",
            "    div(data-X=\"x\") a",
            "    foreignObject x",
            "    a(href=\"{x}\") go",
        ] {
            assert!(parse(&format!("@public\npage GET \"/\" -> html:\n{bad}"), 1).is_err(), "{bad}");
        }
    }

    #[test]
    fn guards_attach_to_the_next_page() {
        let items = parse("@guard(auth::staff)\n@guard(audit)\npage GET \"/a\" (auth) -> html:\n    p {auth.email}\n@public\npage GET \"/b\" -> html:\n    p b", 1).unwrap();
        let Item::Route(a) = &items[0] else { panic!() };
        let Item::Route(b) = &items[1] else { panic!() };
        assert_eq!(a.guards, ["auth::staff", "audit"]);
        assert!(a.auth && b.guards.is_empty());
        for bad in ["@guard(x)\n", "@guard()\npage GET \"/\" -> html:\n    p x", "@guard(x) junk\npage GET \"/\" -> html:\n    p x"] {
            assert!(parse(bad, 1).is_err(), "{bad}");
        }
    }

    #[test]
    fn pages_declare_an_access_policy() {
        let items = parse("@public(\"marketing page\")\npage GET \"/\" -> html:\n    p hi", 1).unwrap();
        let Item::Route(r) = &items[0] else { panic!() };
        assert_eq!(r.public.as_deref(), Some("marketing page"));
        assert!(parse("@public(\" \")\npage GET \"/\" -> html:\n    p hi", 1).is_err());
        assert!(parse("@public\n", 1).is_err());
    }

    #[test]
    fn mutated_templates_parse_without_panics() {
        let seed =
            "import models\n@public\npage GET \"/a\" -> html:\n    main:\n        for x in xs:\n            if x.a:\n                button(hx-get=\"/a\" title=\"{x.y}\") {x}\n            else:\n                p no";
        for (pos, ch) in seed.char_indices() {
            for replacement in ["", "\n  ", "}", "😀", "@", "\t", "(", "\""] {
                let mut mutated = seed.to_string();
                mutated.replace_range(pos..pos + ch.len_utf8(), replacement);
                let _ = parse(&mutated, 1);
            }
        }
    }
}
