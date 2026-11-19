//! `parvez fuzz`: builds the service, starts it, and fires edge-case and
//! malformed requests at every route, derived from the route's declared
//! types. A run fails if the server crashes, hangs, drops a connection, or
//! leaks internals (panic text, source paths, OS errors) in a response.
//! 5xx responses that leak nothing are reported as warnings.

use crate::ast::*;
use crate::parser::path_params;
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const LEAK_PATTERNS: &[&str] = &[
    "panicked at",
    "stack backtrace",
    "RUST_BACKTRACE",
    "called `Result::unwrap()`",
    "called `Option::unwrap()`",
    ".rs:",
    "os error",
    "/home/",
    "/root/",
    "/usr/",
    "Error {",
];

/// The first internal-detail pattern found in a response body, if any.
pub fn leak(body: &str) -> Option<&'static str> {
    LEAK_PATTERNS.iter().find(|p| body.contains(**p)).copied()
}

#[derive(Debug, Clone)]
pub struct Case {
    pub route: String,
    pub method: String,
    pub path: String,
    pub content_type: Option<&'static str>,
    pub body: Vec<u8>,
    pub label: String,
}

struct Ctx<'a> {
    prog: &'a Program,
}

impl Ctx<'_> {
    fn struct_def(&self, name: &str) -> Option<&StructDef> {
        self.prog.items.iter().find_map(|i| match i {
            Item::Struct(s) if s.name == name => Some(s),
            _ => None,
        })
    }
    fn enum_def(&self, name: &str) -> Option<&EnumDef> {
        self.prog.items.iter().find_map(|i| match i {
            Item::Enum(e) if e.name == name => Some(e),
            _ => None,
        })
    }

    /// A valid JSON value for a Parvez type.
    fn sample(&self, t: &Type, depth: usize) -> Value {
        match t {
            Type::Named(n, args) => match n.as_str() {
                "i8" | "i16" | "i32" | "i64" | "i128" | "isize" | "u8" | "u16" | "u32" | "u64" | "u128" | "usize" => json!(1),
                "f32" | "f64" => json!(1.5),
                "bool" => json!(true),
                "str" | "String" => json!("x"),
                "Vec" => args.first().map(|a| json!([self.sample(a, depth + 1)])).unwrap_or(json!([])),
                "Option" => Value::Null,
                other if depth < 4 => {
                    if let Some(s) = self.struct_def(other) {
                        let mut m = serde_json::Map::new();
                        for (f, ft) in &s.fields {
                            m.insert(f.clone(), self.sample(ft, depth + 1));
                        }
                        Value::Object(m)
                    } else if let Some(e) = self.enum_def(other) {
                        match e.variants.iter().find(|v| v.data == VariantData::Unit) {
                            Some(v) => json!(v.name),
                            None => json!({ e.variants[0].name.clone(): Value::Null }),
                        }
                    } else {
                        Value::Null
                    }
                }
                _ => Value::Null,
            },
            Type::List(e) => json!([self.sample(e, depth + 1)]),
            Type::Opt(_) => Value::Null,
            Type::Ref(inner, _) => self.sample(inner, depth),
        }
    }

    /// Hostile values for a field of type `t`.
    fn edges(&self, t: &Type) -> Vec<(&'static str, Value)> {
        let mut v = vec![("null", Value::Null), ("wrong-type-object", json!({"$": 1}))];
        match t {
            Type::Named(n, _) if n.starts_with('i') || n.starts_with('u') => v.extend([
                ("zero", json!(0)),
                ("negative", json!(-1)),
                ("i64-max", json!(i64::MAX)),
                ("i64-min", json!(i64::MIN)),
                ("u64-max", json!(u64::MAX)),
                ("huge-float", json!(1e300)),
                ("numeric-string", json!("1")),
            ]),
            Type::Named(n, _) if n == "f32" || n == "f64" => {
                v.extend([("max", json!(f64::MAX)), ("min", json!(f64::MIN)), ("nan-string", json!("NaN"))])
            }
            Type::Named(n, _) if n == "bool" => v.extend([("string-bool", json!("true")), ("int-bool", json!(1))]),
            Type::Named(n, _) if n == "str" || n == "String" => v.extend([
                ("empty", json!("")),
                ("100kb", json!("a".repeat(100_000))),
                ("unicode", json!("😀\u{0}\u{202e}")),
                ("traversal", json!("../../../../etc/passwd")),
                ("sql", json!("' OR 1=1 --")),
                ("html", json!("<script>alert(1)</script>")),
                ("number", json!(123)),
            ]),
            Type::List(_) => v.extend([("empty-list", json!([])), ("10k-list", json!(vec![Value::Null; 10_000])), ("not-a-list", json!("x"))]),
            _ => v.push(("unknown-variant", json!("NoSuchVariant___"))),
        }
        v
    }
}

const PATH_EDGES: &[(&str, &str)] = &[
    ("zero", "0"),
    ("negative", "-1"),
    ("overflow", "99999999999999999999999999"),
    ("non-numeric", "abc"),
    ("encoded-traversal", "%2e%2e%2f%2e%2e%2fetc%2fpasswd"),
    ("traversal", "..%2F..%2F..%2Fetc%2Fpasswd"),
    ("nul", "%00"),
    ("emoji", "%F0%9F%98%80"),
    ("percent", "%25"),
    ("sql", "%27%20OR%201%3D1--"),
];

fn path_value(t: Option<&Type>) -> &'static str {
    match t {
        Some(Type::Named(n, _)) if n.starts_with('i') || n.starts_with('u') => "1",
        Some(Type::Named(n, _)) if n == "bool" => "true",
        _ => "x",
    }
}

fn query_string(obj: &Value) -> String {
    let Value::Object(m) = obj else { return String::new() };
    m.iter()
        .filter(|(_, v)| !v.is_null())
        .map(|(k, v)| {
            let s = match v {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            let enc: String = s
                .bytes()
                .map(|b| if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") })
                .collect();
            format!("{k}={enc}")
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// Every fuzz request for every route.
pub fn cases(prog: &Program) -> Vec<Case> {
    let cx = Ctx { prog };
    let mut out = Vec::new();
    for item in &prog.items {
        let Item::Route(r) = item else { continue };
        let route = format!("{} {}", r.method, r.path);
        let ty = |n: &str| r.params.iter().find(|(p, _)| p == n).map(|(_, t)| t);
        let holes = path_params(&r.path);
        let fill = |over: Option<(&str, &str)>| {
            let mut p = r.path.clone();
            for h in &holes {
                let v = match over {
                    Some((name, val)) if name == h => val.to_string(),
                    _ => path_value(ty(h)).to_string(),
                };
                p = p.replace(&format!("{{{h}}}"), &v);
            }
            p
        };
        let base_query = ty("query").map(|t| cx.sample(t, 0)).unwrap_or(Value::Null);
        let with_query = |path: String, q: &Value| {
            let qs = query_string(q);
            if qs.is_empty() { path } else { format!("{path}?{qs}") }
        };
        let base_body = ty("body").map(|t| cx.sample(t, 0));
        let base_path = with_query(fill(None), &base_query);
        let mut push = |method: &str, path: String, ct: Option<&'static str>, body: Vec<u8>, label: String| {
            out.push(Case { route: route.clone(), method: method.into(), path, content_type: ct, body, label });
        };
        let json_ct = Some("application/json");
        let body_bytes = |v: &Value| serde_json::to_vec(v).unwrap();
        let default_body = base_body.as_ref().map(body_bytes).unwrap_or_default();
        let default_ct = if base_body.is_some() { json_ct } else { None };

        push(&r.method, base_path.clone(), default_ct, default_body.clone(), "baseline".into());
        let other = if r.method == "PATCH" { "PUT" } else { "PATCH" };
        push(other, base_path.clone(), default_ct, default_body.clone(), "wrong-method".into());

        for h in &holes {
            for (label, v) in PATH_EDGES {
                push(&r.method, with_query(fill(Some((h, v))), &base_query), default_ct, default_body.clone(), format!("path {{{h}}}={label}"));
            }
            push(&r.method, with_query(fill(Some((h, &"a".repeat(4000)))), &base_query), default_ct, default_body.clone(), format!("path {{{h}}}=4kb"));
        }

        if let Some(qt) = ty("query") {
            let fill_path = fill(None);
            push(&r.method, fill_path.clone(), default_ct, default_body.clone(), "query missing".into());
            push(&r.method, format!("{fill_path}?&&&==%ZZ"), default_ct, default_body.clone(), "query garbage".into());
            if let (Value::Object(m), Type::Named(n, _)) = (&base_query, qt)
                && let Some(s) = cx.struct_def(n)
            {
                for (f, ft) in &s.fields {
                    for (label, ev) in cx.edges(ft) {
                        if ev.is_object() || matches!(&ev, Value::String(x) if x.len() > 5000) {
                            continue;
                        }
                        let mut q = m.clone();
                        q.insert(f.clone(), ev);
                        push(&r.method, with_query(fill_path.clone(), &Value::Object(q)), default_ct, default_body.clone(), format!("query {f}={label}"));
                    }
                }
            }
        }

        if let (Some(bt), Some(base)) = (ty("body"), &base_body) {
            if let (Value::Object(m), Type::Named(n, _)) = (base, bt)
                && let Some(s) = cx.struct_def(n)
            {
                for (f, ft) in &s.fields {
                    let mut missing = m.clone();
                    missing.remove(f);
                    push(&r.method, base_path.clone(), json_ct, body_bytes(&Value::Object(missing)), format!("body missing {f}"));
                    for (label, ev) in cx.edges(ft) {
                        let mut b = m.clone();
                        b.insert(f.clone(), ev);
                        push(&r.method, base_path.clone(), json_ct, body_bytes(&Value::Object(b)), format!("body {f}={label}"));
                    }
                }
                let mut extra = m.clone();
                extra.insert("__unexpected".into(), json!({"deep": [1, 2, 3]}));
                push(&r.method, base_path.clone(), json_ct, body_bytes(&Value::Object(extra)), "body extra field".into());
            }
            let raw: Vec<(&str, Vec<u8>)> = vec![
                ("empty", vec![]),
                ("json-null", b"null".to_vec()),
                ("json-array", b"[]".to_vec()),
                ("json-string", b"\"x\"".to_vec()),
                ("truncated", b"{\"a\":".to_vec()),
                ("invalid-utf8", vec![0xff, 0xfe, 0x7b]),
                ("nested-50k", format!("{}{}", "[".repeat(50_000), "]".repeat(50_000)).into_bytes()),
                ("3mb", format!("\"{}\"", "a".repeat(3 * 1024 * 1024)).into_bytes()),
            ];
            for (label, b) in raw {
                push(&r.method, base_path.clone(), json_ct, b, format!("body {label}"));
            }
            push(&r.method, base_path.clone(), Some("text/plain"), default_body.clone(), "body wrong content-type".into());
            push(&r.method, base_path.clone(), None, default_body.clone(), "body no content-type".into());
        }
    }
    out
}

/// Sends one request; returns (status, body).
fn send(port: u16, c: &Case) -> std::io::Result<(u16, String)> {
    let mut s = TcpStream::connect(("127.0.0.1", port))?;
    s.set_read_timeout(Some(Duration::from_secs(40)))?;
    s.set_write_timeout(Some(Duration::from_secs(10)))?;
    let mut head = format!("{} {} HTTP/1.1\r\nHost: fuzz\r\nConnection: close\r\n", c.method, c.path);
    if let Some(ct) = c.content_type {
        head.push_str(&format!("Content-Type: {ct}\r\n"));
    }
    head.push_str(&format!("Content-Length: {}\r\n\r\n", c.body.len()));
    s.write_all(head.as_bytes())?;
    // The server may reject (413) and close before reading everything.
    let _ = s.write_all(&c.body);
    let mut raw = Vec::new();
    s.read_to_end(&mut raw)?;
    let text = String::from_utf8_lossy(&raw).to_string();
    let status = text.get(9..12).and_then(|x| x.parse().ok()).ok_or_else(|| std::io::Error::other("no HTTP status line"))?;
    Ok((status, text.split_once("\r\n\r\n").map(|x| x.1.to_string()).unwrap_or_default()))
}

struct Server(Child);
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Fuzzes the built service binary. Returns Ok(()) when nothing crashed,
/// hung, or leaked.
pub fn run(prog: &Program, bin: &Path) -> Result<()> {
    let cases = cases(prog);
    if cases.is_empty() {
        bail!("no `route`s to fuzz");
    }
    let port = std::net::TcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
    let log = std::env::temp_dir().join(format!("parvez-fuzz-{}.log", std::process::id()));
    let mut server = Server(
        Command::new(bin)
            .env("PORT", port.to_string())
            .stdout(Stdio::null())
            .stderr(std::fs::File::create(&log)?)
            .spawn()
            .with_context(|| format!("starting {}", bin.display()))?,
    );
    let deadline = Instant::now() + Duration::from_secs(15);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        if let Some(st) = server.0.try_wait()? {
            bail!("service exited on startup ({st}); log: {}", std::fs::read_to_string(&log).unwrap_or_default());
        }
        anyhow::ensure!(Instant::now() < deadline, "service did not start listening");
        std::thread::sleep(Duration::from_millis(50));
    }

    let (mut ok, mut warns, mut fails) = (0usize, Vec::new(), Vec::new());
    let routes: std::collections::BTreeSet<&str> = cases.iter().map(|c| c.route.as_str()).collect();
    for c in &cases {
        let what = format!("{} {} [{}]", c.method, c.route.split_once(' ').map(|x| x.1).unwrap_or(""), c.label);
        match send(port, c) {
            Ok((status, body)) => {
                if let Some(p) = leak(&body) {
                    let shown: String = body.chars().take(160).collect();
                    fails.push(format!("LEAK   {what} -> {status}: response contains `{p}`: {shown}"));
                } else if status >= 500 {
                    warns.push(format!("5xx    {what} -> {status} {body}"));
                } else {
                    ok += 1;
                }
            }
            Err(e) => {
                if let Some(st) = server.0.try_wait()? {
                    fails.push(format!("CRASH  {what}: server exited ({st})"));
                    break;
                }
                fails.push(format!("DROP   {what}: no HTTP response ({e})"));
            }
        }
    }
    if fails.iter().all(|f| !f.starts_with("CRASH")) && server.0.try_wait()?.is_some() {
        fails.push("CRASH  server exited during the run".into());
    }
    drop(server);
    let panics = std::fs::read_to_string(&log).unwrap_or_default().matches("handler panicked").count();
    let _ = std::fs::remove_file(&log);

    for w in warns.iter().take(25) {
        eprintln!("parvez: fuzz: warning: {w}");
    }
    if warns.len() > 25 {
        eprintln!("parvez: fuzz: ... {} more 5xx warnings", warns.len() - 25);
    }
    for f in &fails {
        eprintln!("parvez: fuzz: FAIL {f}");
    }
    eprintln!(
        "parvez: fuzz: {} requests across {} route(s): {ok} ok, {} 5xx (no leak), {} failure(s); {panics} handler panic(s) contained",
        cases.len(),
        routes.len(),
        warns.len(),
        fails.len()
    );
    if !fails.is_empty() {
        bail!("fuzzing found {} failure(s)", fails.len());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{lexer::lex, parser::parse};

    #[test]
    fn leak_detection() {
        assert_eq!(leak(r#"{"error":"internal server error"}"#), None);
        assert_eq!(leak("thread 'tokio' panicked at src/main.rs:10:5"), Some("panicked at"));
        assert_eq!(leak(r#"{"error":"No such file or directory (os error 2)"}"#), Some("os error"));
        assert_eq!(leak(r#"{"error":"bad config /home/app/.env"}"#), Some("/home/"));
    }

    #[test]
    fn cases_cover_path_query_and_body() {
        let src = "@json\ntype Ev: id: str, n: i32\n@json\ntype Q: page: u32\nroute POST \"/ev/{id}\" (id: u64, query: Q, body: Ev) -> Ev:\n    ret body\nroute GET \"/health\" -> str:\n    ret \"ok\"\n";
        let prog = parse(lex(src).unwrap()).unwrap();
        let cs = cases(&prog);
        let base = &cs[0];
        assert_eq!((base.method.as_str(), base.path.as_str(), base.label.as_str()), ("POST", "/ev/1?page=1", "baseline"));
        assert_eq!(String::from_utf8_lossy(&base.body), r#"{"id":"x","n":1}"#);
        let labels: Vec<&str> = cs.iter().map(|c| c.label.as_str()).collect();
        for want in ["wrong-method", "path {id}=encoded-traversal", "query page=negative", "body missing id", "body n=i64-max", "body id=100kb", "body nested-50k", "body 3mb", "body no content-type"] {
            assert!(labels.contains(&want), "missing {want}");
        }
        assert!(cs.iter().any(|c| c.route == "GET /health" && c.label == "baseline"));
    }
}
