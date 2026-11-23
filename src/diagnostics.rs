//! Turns rustc JSON diagnostics (from `cargo build --message-format=json`)
//! into compact errors that point at `.lmn` lines via the codegen source map.
//!
//! Output shape (one block per error, grep- and agent-friendly):
//! ```text
//! app.lmn:7: error[E0308]: mismatched types
//!    7 |     p = port(" 8080 ")?
//!      = expected `&str`, found `String`
//!      = line 3: function defined here
//!      = help: consider borrowing here
//!      = rust: let p = port(String::from(" 8080 "))?;
//! ```

use serde_json::Value;

pub struct Ctx<'a> {
    /// `.lmn` path as the user typed it
    pub lmn_path: &'a str,
    pub lmn_src: &'a str,
    pub rust_src: &'a str,
    /// Rust line (1-based) -> `.lmn` line, see `codegen::Generated::map`
    pub map: &'a [usize],
    /// (name, source) of imported files; index k-1 for file k of an encoded line
    pub modules: &'a [(String, String)],
}

impl Ctx<'_> {
    fn lmn_line(&self, rust_line: u64) -> usize {
        let i = rust_line.saturating_sub(1) as usize;
        self.map.get(i).copied().unwrap_or(0)
    }
    /// (file name, line within it) for an encoded line.
    fn place(&self, n: usize) -> (&str, usize) {
        let (k, line) = crate::ast::split_line(n);
        match k {
            0 => (self.lmn_path, line),
            _ => (self.modules.get(k - 1).map(|m| m.0.as_str()).unwrap_or("?"), line),
        }
    }
    fn src_line(&self, n: usize) -> Option<&str> {
        let (k, line) = crate::ast::split_line(n);
        let src = if k == 0 { self.lmn_src } else { self.modules.get(k - 1)?.1.as_str() };
        src.lines().nth(line.checked_sub(1)?)
    }
    fn rust_line(&self, n: u64) -> Option<&str> {
        self.rust_src.lines().nth((n as usize).checked_sub(1)?)
    }
}

/// One `.lmn` location per generated Rust line (`file:line`, or empty).
pub fn location_table(ctx: &Ctx) -> String {
    let mut out = String::new();
    for n in ctx.map {
        if *n > 0 {
            let (file, line) = ctx.place(*n);
            out.push_str(&format!("{file}:{line}"));
        }
        out.push('\n');
    }
    out
}

/// `thread 't' panicked at src/main.rs:120:9:` -> `... panicked at app.lmn:14:`.
/// Lines without a known location are left alone.
pub fn map_panic_location(line: &str, places: &[&str]) -> String {
    // rustc writes `src\\main.rs` on Windows
    let (i, at) = match ["panicked at src/main.rs:", "panicked at src\\main.rs:"].iter().find_map(|at| line.find(at).map(|i| (i, *at))) {
        Some(found) => found,
        None => return line.to_string(),
    };
    let rest = &line[i + at.len()..];
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    let place = digits.parse::<usize>().ok().and_then(|n| places.get(n.checked_sub(1)?)).filter(|p| !p.is_empty());
    let Some(place) = place else { return line.to_string() };
    let tail = rest[digits.len()..].trim_start_matches(|c: char| c == ':' || c.is_ascii_digit());
    format!("{}panicked at {place}:{tail}", &line[..i])
}

/// Spans that refer to the generated program (not std or dependencies). A span
/// inside a macro expansion (e.g. the `format!` behind an interpolated string)
/// is traced back through `expansion.span` to its call site in our code.
fn our_spans(v: &Value) -> Vec<&Value> {
    fn ours(s: &Value) -> bool {
        s["file_name"].as_str().is_some_and(|f| f.ends_with("src/main.rs") || f.ends_with("src\\main.rs"))
    }
    v["spans"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|s| {
                    let mut cur = s;
                    for _ in 0..32 {
                        if ours(cur) {
                            return Some(cur);
                        }
                        cur = cur.get("expansion").and_then(|e| e.get("span"))?;
                    }
                    None
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Renders every error in cargo's JSON stream. Returns one string per error.
pub fn render(json_stream: &str, ctx: &Ctx) -> Vec<String> {
    let mut out = Vec::new();
    for line in json_stream.lines() {
        let Ok(v) = serde_json::from_str::<Value>(line) else { continue };
        if v["reason"] != "compiler-message" {
            continue;
        }
        let msg = &v["message"];
        if msg["level"] != "error" {
            continue;
        }
        let text = msg["message"].as_str().unwrap_or("");
        if text.starts_with("aborting due to") {
            continue;
        }
        out.push(render_one(msg, ctx));
    }
    out
}

fn render_one(msg: &Value, ctx: &Ctx) -> String {
    let text = msg["message"].as_str().unwrap_or("");
    let code = msg["code"]["code"].as_str().map(|c| format!("[{c}]")).unwrap_or_default();
    let spans = our_spans(msg);
    let primary = spans.iter().find(|s| s["is_primary"] == true).or(spans.first()).copied();

    let Some(primary) = primary else {
        return format!("{}: error{code}: {text}\n", ctx.lmn_path);
    };
    let rust_ln = primary["line_start"].as_u64().unwrap_or(0);
    let ln = ctx.lmn_line(rust_ln);

    let mut s = String::new();
    if ln > 0 {
        let (file, l) = ctx.place(ln);
        s.push_str(&format!("{file}:{l}: error{code}: {text}\n"));
        if let Some(src) = ctx.src_line(ln) {
            s.push_str(&format!("{l:>4} | {src}\n"));
        }
    } else {
        s.push_str(&format!("{} (generated line {rust_ln}): error{code}: {text}\n", ctx.lmn_path));
    }

    let mut notes: Vec<String> = Vec::new();
    let mut note = |n: String| {
        if !n.trim().is_empty() && !notes.contains(&n) {
            notes.push(n);
        }
    };
    let at = |l: usize| {
        if l == 0 || l == ln {
            return String::new();
        }
        let (file, line) = ctx.place(l);
        if crate::ast::split_line(l).0 == crate::ast::split_line(ln).0 {
            format!("line {line}: ")
        } else {
            format!("{file}:{line}: ")
        }
    };

    if let Some(label) = primary["label"].as_str() {
        note(label.to_string());
    }
    for sp in &spans {
        if std::ptr::eq(*sp, primary) {
            continue;
        }
        if let Some(label) = sp["label"].as_str() {
            let l = ctx.lmn_line(sp["line_start"].as_u64().unwrap_or(0));
            note(format!("{}{label}", at(l)));
        }
    }
    for child in msg["children"].as_array().into_iter().flatten() {
        let level = child["level"].as_str().unwrap_or("note");
        let m = child["message"].as_str().unwrap_or("");
        let l = our_spans(child)
            .first()
            .map(|sp| ctx.lmn_line(sp["line_start"].as_u64().unwrap_or(0)))
            .unwrap_or(0);
        note(format!("{}{level}: {m}", at(l)));
    }
    for n in notes {
        s.push_str(&format!("     = {n}\n"));
    }
    if let Some(r) = ctx.rust_line(rust_ln) {
        s.push_str(&format!("     = rust: {}\n", r.trim()));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    const RUST: &str = "// header\n#![allow(unused)]\nfn port(raw: &str) -> i32 {\n    0\n}\nfn main() {\n    let p = port(String::from(\"80\"));\n}\n";
    const LMN: &str = "fn port(raw: &str) -> i32:\n    ret 0\nfn main():\n    p = port(\"80\")\n";
    const MAP: [usize; 8] = [0, 0, 1, 2, 2, 3, 4, 4];

    fn ctx() -> Ctx<'static> {
        Ctx { lmn_path: "app.lmn", lmn_src: LMN, rust_src: RUST, map: &MAP, modules: &[] }
    }

    #[test]
    fn panic_locations_point_at_lmn_lines() {
        let places = ["", "app.lmn:3", "store.lmn:9"];
        assert_eq!(
            map_panic_location("thread 'tests::t' (42) panicked at src/main.rs:3:9:", &places),
            "thread 'tests::t' (42) panicked at store.lmn:9:"
        );
        // unknown or unmapped lines stay as they are
        assert_eq!(
            map_panic_location("thread 'tests::t' (42) panicked at src\\main.rs:3:9:", &places),
            map_panic_location("thread 'tests::t' (42) panicked at src/main.rs:3:9:", &places),
            "Windows paths map the same way"
        );
        for l in ["panicked at src/main.rs:1:5:", "panicked at src/main.rs:99:1:", "ok"] {
            assert_eq!(map_panic_location(l, &places), l);
        }
    }

    #[test]
    fn maps_errors_inside_macro_expansions_to_the_call_site() {
        let msg = r#"{"reason":"compiler-message","message":{"level":"error","message":"mismatched types","code":{"code":"E0308"},
            "spans":[{"file_name":"/rustc/abc/library/alloc/src/macros.rs","line_start":116,"is_primary":true,"label":"expected `&str`, found `String`",
            "expansion":{"span":{"file_name":"src/main.rs","line_start":7,"is_primary":false}}}],"children":[]}}"#;
        let out = render(&msg.replace('\n', ""), &ctx());
        assert!(out[0].starts_with("app.lmn:4: error[E0308]: mismatched types"), "{}", out[0]);
    }

    #[test]
    fn maps_error_to_lmn_line() {
        let json = r#"{"reason":"compiler-artifact"}
{"reason":"compiler-message","message":{"message":"mismatched types","code":{"code":"E0308"},"level":"error","spans":[{"file_name":"src/main.rs","line_start":7,"is_primary":true,"label":"expected `&str`, found `String`"},{"file_name":"src/main.rs","line_start":7,"is_primary":false,"label":"arguments to this function are incorrect"}],"children":[{"message":"function defined here","level":"note","spans":[{"file_name":"src/main.rs","line_start":3,"is_primary":true,"label":null}]},{"message":"consider borrowing here","level":"help","spans":[]}]}}
{"reason":"compiler-message","message":{"message":"aborting due to 1 previous error","code":null,"level":"error","spans":[],"children":[]}}
not json at all"#;
        let errs = render(json, &ctx());
        assert_eq!(errs.len(), 1);
        let e = &errs[0];
        assert!(e.starts_with("app.lmn:4: error[E0308]: mismatched types\n"), "{e}");
        assert!(e.contains("   4 |     p = port(\"80\")\n"));
        assert!(e.contains("= expected `&str`, found `String`"));
        assert!(e.contains("= arguments to this function are incorrect"));
        assert!(e.contains("= line 1: note: function defined here"));
        assert!(e.contains("= help: consider borrowing here"));
        assert!(e.contains("= rust: let p = port(String::from(\"80\"));"));
        assert!(!e.contains("src/main.rs"));
    }

    #[test]
    fn maps_errors_into_module_files() {
        let modules = [("store.lmn".to_string(), "fn f() -> i32:\n    ret \"x\"\n".to_string())];
        let map = [0, 0, 1, 2, 2, 3, 4, 1_000_002];
        let ctx = Ctx { lmn_path: "app.lmn", lmn_src: LMN, rust_src: RUST, map: &map, modules: &modules };
        let json = r#"{"reason":"compiler-message","message":{"message":"mismatched types","code":{"code":"E0308"},"level":"error","spans":[{"file_name":"src/main.rs","line_start":8,"is_primary":true,"label":"expected `i32`"},{"file_name":"src/main.rs","line_start":3,"is_primary":false,"label":"return type"}],"children":[]}}"#;
        let e = &render(json, &ctx)[0];
        assert!(e.starts_with("store.lmn:2: error[E0308]: mismatched types\n   2 |     ret \"x\"\n"), "{e}");
        assert!(e.contains("= app.lmn:1: return type"), "{e}");
    }

    #[test]
    fn ignores_warnings_and_foreign_spans() {
        let json = r#"{"reason":"compiler-message","message":{"message":"unused","code":null,"level":"warning","spans":[],"children":[]}}
{"reason":"compiler-message","message":{"message":"boom","code":null,"level":"error","spans":[{"file_name":"/rustc/x/library/core/src/lib.rs","line_start":9,"is_primary":true,"label":"here"}],"children":[]}}"#;
        let errs = render(json, &ctx());
        assert_eq!(errs, vec!["app.lmn: error: boom\n".to_string()]);
    }
}
