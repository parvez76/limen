//! Turns rustc JSON diagnostics (from `cargo build --message-format=json`)
//! into compact errors that point at `.prvz` lines via the codegen source map.
//!
//! Output shape (one block per error, grep- and agent-friendly):
//! ```text
//! app.prvz:7: error[E0308]: mismatched types
//!    7 |     p = port(" 8080 ")?
//!      = expected `&str`, found `String`
//!      = line 3: function defined here
//!      = help: consider borrowing here
//!      = rust: let p = port(String::from(" 8080 "))?;
//! ```

use serde_json::Value;

pub struct Ctx<'a> {
    /// `.prvz` path as the user typed it
    pub prvz_path: &'a str,
    pub prvz_src: &'a str,
    pub rust_src: &'a str,
    /// Rust line (1-based) -> `.prvz` line, see `codegen::Generated::map`
    pub map: &'a [usize],
    /// (name, source) of imported files; index k-1 for file k of an encoded line
    pub modules: &'a [(String, String)],
}

impl Ctx<'_> {
    fn prvz_line(&self, rust_line: u64) -> usize {
        let i = rust_line.saturating_sub(1) as usize;
        self.map.get(i).copied().unwrap_or(0)
    }
    /// (file name, line within it) for an encoded line.
    fn place(&self, n: usize) -> (&str, usize) {
        let (k, line) = crate::ast::split_line(n);
        match k {
            0 => (self.prvz_path, line),
            _ => (self.modules.get(k - 1).map(|m| m.0.as_str()).unwrap_or("?"), line),
        }
    }
    fn src_line(&self, n: usize) -> Option<&str> {
        let (k, line) = crate::ast::split_line(n);
        let src = if k == 0 { self.prvz_src } else { self.modules.get(k - 1)?.1.as_str() };
        src.lines().nth(line.checked_sub(1)?)
    }
    fn rust_line(&self, n: u64) -> Option<&str> {
        self.rust_src.lines().nth((n as usize).checked_sub(1)?)
    }
}

/// Spans that refer to the generated program (not std or dependencies).
fn our_spans(v: &Value) -> Vec<&Value> {
    v["spans"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter(|s| s["file_name"].as_str().is_some_and(|f| f.ends_with("src/main.rs")))
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
        return format!("{}: error{code}: {text}\n", ctx.prvz_path);
    };
    let rust_ln = primary["line_start"].as_u64().unwrap_or(0);
    let ln = ctx.prvz_line(rust_ln);

    let mut s = String::new();
    if ln > 0 {
        let (file, l) = ctx.place(ln);
        s.push_str(&format!("{file}:{l}: error{code}: {text}\n"));
        if let Some(src) = ctx.src_line(ln) {
            s.push_str(&format!("{l:>4} | {src}\n"));
        }
    } else {
        s.push_str(&format!("{} (generated line {rust_ln}): error{code}: {text}\n", ctx.prvz_path));
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
            let l = ctx.prvz_line(sp["line_start"].as_u64().unwrap_or(0));
            note(format!("{}{label}", at(l)));
        }
    }
    for child in msg["children"].as_array().into_iter().flatten() {
        let level = child["level"].as_str().unwrap_or("note");
        let m = child["message"].as_str().unwrap_or("");
        let l = our_spans(child)
            .first()
            .map(|sp| ctx.prvz_line(sp["line_start"].as_u64().unwrap_or(0)))
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
    const PRVZ: &str = "fn port(raw: &str) -> i32:\n    ret 0\nfn main():\n    p = port(\"80\")\n";
    const MAP: [usize; 8] = [0, 0, 1, 2, 2, 3, 4, 4];

    fn ctx() -> Ctx<'static> {
        Ctx { prvz_path: "app.prvz", prvz_src: PRVZ, rust_src: RUST, map: &MAP, modules: &[] }
    }

    #[test]
    fn maps_error_to_prvz_line() {
        let json = r#"{"reason":"compiler-artifact"}
{"reason":"compiler-message","message":{"message":"mismatched types","code":{"code":"E0308"},"level":"error","spans":[{"file_name":"src/main.rs","line_start":7,"is_primary":true,"label":"expected `&str`, found `String`"},{"file_name":"src/main.rs","line_start":7,"is_primary":false,"label":"arguments to this function are incorrect"}],"children":[{"message":"function defined here","level":"note","spans":[{"file_name":"src/main.rs","line_start":3,"is_primary":true,"label":null}]},{"message":"consider borrowing here","level":"help","spans":[]}]}}
{"reason":"compiler-message","message":{"message":"aborting due to 1 previous error","code":null,"level":"error","spans":[],"children":[]}}
not json at all"#;
        let errs = render(json, &ctx());
        assert_eq!(errs.len(), 1);
        let e = &errs[0];
        assert!(e.starts_with("app.prvz:4: error[E0308]: mismatched types\n"), "{e}");
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
        let modules = [("store.prvz".to_string(), "fn f() -> i32:\n    ret \"x\"\n".to_string())];
        let map = [0, 0, 1, 2, 2, 3, 4, 1_000_002];
        let ctx = Ctx { prvz_path: "app.prvz", prvz_src: PRVZ, rust_src: RUST, map: &map, modules: &modules };
        let json = r#"{"reason":"compiler-message","message":{"message":"mismatched types","code":{"code":"E0308"},"level":"error","spans":[{"file_name":"src/main.rs","line_start":8,"is_primary":true,"label":"expected `i32`"},{"file_name":"src/main.rs","line_start":3,"is_primary":false,"label":"return type"}],"children":[]}}"#;
        let e = &render(json, &ctx)[0];
        assert!(e.starts_with("store.prvz:2: error[E0308]: mismatched types\n   2 |     ret \"x\"\n"), "{e}");
        assert!(e.contains("= app.prvz:1: return type"), "{e}");
    }

    #[test]
    fn ignores_warnings_and_foreign_spans() {
        let json = r#"{"reason":"compiler-message","message":{"message":"unused","code":null,"level":"warning","spans":[],"children":[]}}
{"reason":"compiler-message","message":{"message":"boom","code":null,"level":"error","spans":[{"file_name":"/rustc/x/library/core/src/lib.rs","line_start":9,"is_primary":true,"label":"here"}],"children":[]}}"#;
        let errs = render(json, &ctx());
        assert_eq!(errs, vec!["app.prvz: error: boom\n".to_string()]);
    }
}
