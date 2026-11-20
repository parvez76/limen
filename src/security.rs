//! Compile-time security checks on the `.prvz` AST. Insecure patterns are
//! compile errors with a concrete fix; `@allow_insecure("reason")` on a
//! `fn` / `route` / `state` opts that item out (and is reported on build).
//!
//! Rules:
//! - sql-injection: interpolated / concatenated strings passed to SQL APIs
//! - command-injection: non-literal program names, or dynamic `sh -c` scripts
//! - path-traversal: route input reaching filesystem calls without `safe_join`
//! - hardcoded-secret: literals in secret-named bindings, or key-like literals
//!
//! Taint (route params, `body`, `query`, and values derived from them) is
//! tracked within each route body; it does not flow through other functions.

use crate::ast::*;
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub line: usize,
    pub rule: &'static str,
    pub msg: String,
    pub fix: &'static str,
}

impl Finding {
    pub fn render(&self, file: &str) -> String {
        let mut out = format!("{file}:{}: security[{}]: {}\n     = fix: {}", self.line, self.rule, self.msg, self.fix);
        if let Some(r) = rule(self.rule) {
            out.push_str(&format!("\n     = see: {}", r.references()));
        }
        out
    }
}

pub struct Report {
    pub findings: Vec<Finding>,
    /// (line, reason) for every `@allow_insecure` item
    pub allowed: Vec<(usize, String)>,
    /// findings inside `@allow_insecure` items, with the item's reason (SARIF suppressions)
    pub suppressed: Vec<(Finding, String)>,
}

/// A lint rule and the standards it enforces: CWE, OWASP Top 10 (2021) and
/// OWASP ASVS 4.0.3 requirement numbers. Shown with every finding and
/// exported in SARIF so scanners and auditors can file it.
pub struct Rule {
    pub id: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub cwe: &'static [u32],
    pub owasp: &'static str,
    pub asvs: &'static [&'static str],
    /// CVSS-style score (0-10) for GitHub code scanning's severity
    pub severity: &'static str,
    pub fix: &'static str,
}

impl Rule {
    pub fn references(&self) -> String {
        let mut refs: Vec<String> = self.cwe.iter().map(|c| format!("CWE-{c}")).collect();
        refs.push(format!("OWASP {}", self.owasp));
        refs.extend(self.asvs.iter().map(|a| format!("ASVS {a}")));
        refs.join(", ")
    }
}

pub const RULES: &[Rule] = &[
    Rule {
        id: "sql-injection",
        title: "SQL built from interpolation or concatenation",
        description: "A string built with interpolation or `+` reaches a SQL API. Untrusted parts can change the query.",
        cwe: &[89],
        owasp: "A03:2021 Injection",
        asvs: &["5.3.4", "5.3.5"],
        severity: "9.8",
        fix: FIX_SQL,
    },
    Rule {
        id: "command-injection",
        title: "Dynamic program name or shell script",
        description: "A process is started with a non-literal program name, or a shell (`sh -c` style) runs a dynamic script.",
        cwe: &[78, 77],
        owasp: "A03:2021 Injection",
        asvs: &["5.3.8"],
        severity: "9.8",
        fix: FIX_CMD,
    },
    Rule {
        id: "path-traversal",
        title: "Request input reaches the filesystem unsanitized",
        description: "A route parameter, body or query value (or a value derived from it) reaches a filesystem call without `safe_join`.",
        cwe: &[22],
        owasp: "A01:2021 Broken Access Control",
        asvs: &["12.3.1", "12.3.2"],
        severity: "7.5",
        fix: FIX_PATH,
    },
    Rule {
        id: "hardcoded-secret",
        title: "Credential in source code",
        description: "A string literal is assigned to a secret-named binding, looks like a known key format, or creates a Secret.",
        cwe: &[798, 259],
        owasp: "A07:2021 Identification and Authentication Failures",
        asvs: &["2.10.4", "6.4.1"],
        severity: "7.5",
        fix: FIX_SECRET,
    },
    Rule {
        id: "secret-exposure",
        title: "Exposed Secret reaches output",
        description: "`.expose()` on a Secret is passed to a log, print, error, JSON or page output, or interpolated into a string.",
        cwe: &[532, 200],
        owasp: "A09:2021 Security Logging and Monitoring Failures",
        asvs: &["7.1.1", "7.1.2"],
        severity: "6.5",
        fix: FIX_EXPOSE,
    },
    Rule {
        id: "secret-type",
        title: "Secret held as plain `str`",
        description: "A `state:` field with a secret-like name is typed `str`, so it can be logged, serialized and stays in memory after use.",
        cwe: &[312, 316],
        owasp: "A04:2021 Insecure Design",
        asvs: &["8.3.6", "6.4.1"],
        severity: "4.0",
        fix: FIX_SECRET_TYPE,
    },
];

pub fn rule(id: &str) -> Option<&'static Rule> {
    RULES.iter().find(|r| r.id == id)
}

const SQL_FNS: &[&str] = &[
    "query", "query_as", "query_scalar", "execute", "sql", "raw_sql", "prepare", "query_one",
    "query_opt", "batch_execute", "simple_query", "query_raw", "execute_raw",
];
const SHELLS: &[&str] = &["sh", "bash", "zsh", "dash", "ksh", "fish", "cmd", "cmd.exe", "powershell", "pwsh"];
const FS_FNS: &[&str] = &[
    "read_to_string", "read", "write", "open", "create", "remove_file", "remove_dir", "remove_dir_all",
    "create_dir", "create_dir_all", "read_dir", "copy", "rename", "metadata", "canonicalize",
    "hard_link", "symlink", "set_permissions", "File::open", "File::create",
];
const SECRET_NAMES: &[&str] = &[
    "secret", "password", "passwd", "api_key", "apikey", "token", "private_key", "privatekey",
    "access_key", "credential", "auth_key", "signing_key",
];
const KEY_PREFIXES: &[&str] = &[
    "sk_live_", "sk_test_", "rk_live_", "AKIA", "ASIA", "ghp_", "gho_", "ghs_", "github_pat_",
    "xoxb-", "xoxp-", "xapp-", "AIza", "-----BEGIN", "glpat-", "SG.",
];

const FIX_SQL: &str = "never build SQL with interpolation or `+`; use a parameterized query, e.g. sqlx::query(\"SELECT * FROM users WHERE id = $1\").bind(id)";
const FIX_CMD: &str = "use a fixed program name (string literal) and pass input as separate `.arg(x)` values; never run input through `sh -c`";
const FIX_PATH: &str = "join untrusted names with `safe_join(\"/base/dir\", name)?`, which rejects `..`, absolute paths and separators";
const FIX_EXPOSE: &str = "pass `s.expose()` only to the API that needs the value (a DB bind, an HMAC key, a header); print or log the Secret itself, which shows [redacted]";
const FIX_SECRET_TYPE: &str = "store it as a Secret so it can't be logged or serialized: `api_key: Secret = env_secret(\"API_KEY\")?`";
/// Calls whose arguments end up in output: logs, stdout/stderr, error messages, JSON.
const OUTPUT_SINKS: &[&str] = &["print", "eprint", "log_info", "log_warn", "log_error", "fail", "assert", "assert_eq", "json", "json_encode", "json_pretty", "metric_inc"];
const FIX_SECRET: &str = "load secrets at runtime as a Secret: `api_key: Secret = env_secret(\"API_KEY\")?` in `state:`; never commit them";

pub fn lint(prog: &Program) -> Report {
    let mut l = Linter { findings: Vec::new() };
    let mut allowed = Vec::new();
    let mut suppressed = Vec::new();
    let test_mods = prog.test_only_modules();
    for (module, item) in prog.all_items() {
        // test code never ships (fixture keys, fake IdPs): `parvez build` strips it
        if prog.is_test_scope(module, item, &test_mods) {
            continue;
        }
        match item {
            Item::Const { name, value, line, .. } => {
                l.secret_binding(name, value, *line);
                l.expr(value, *line, &Cx::default());
            }
            Item::Fn(f) => l.function(f, &mut allowed, &mut suppressed),
            Item::Impl(i) => i.methods.iter().for_each(|m| l.function(m, &mut allowed, &mut suppressed)),
            Item::Trait(t) => t.methods.iter().for_each(|m| l.function(m, &mut allowed, &mut suppressed)),
            Item::Every(e) => l.block(&e.body, &mut Cx::default()),
            Item::Route(r) => {
                let mut cx = Cx::default();
                cx.taint.extend(r.params.iter().map(|(n, _)| n.clone()));
                if let Some(why) = &r.allow_insecure {
                    allowed.push((r.line, why.clone()));
                    let mut s = Linter { findings: Vec::new() };
                    s.block(&r.body, &mut cx);
                    suppressed.extend(s.findings.into_iter().map(|f| (f, why.clone())));
                    continue;
                }
                l.block(&r.body, &mut cx);
            }
            Item::State(st) => {
                let mut s = Linter { findings: Vec::new() };
                let l = if st.allow_insecure.is_some() { &mut s } else { &mut l };
                let mut cx = Cx::default();
                for (name, ty, value, line) in &st.fields {
                    let lower = name.to_lowercase();
                    if matches!(ty, Type::Named(t, a) if t == "str" && a.is_empty()) && SECRET_NAMES.iter().any(|n| lower.contains(n)) {
                        l.push(*line, "secret-type", format!("state field `{name}` holds a secret as plain `str`"), FIX_SECRET_TYPE);
                    }
                    l.secret_binding(name, value, *line);
                    l.expr(value, *line, &mut cx);
                }
                if let Some(why) = &st.allow_insecure {
                    allowed.push((st.line, why.clone()));
                    suppressed.extend(s.findings.into_iter().map(|f| (f, why.clone())));
                }
            }
            _ => {}
        }
    }
    // One finding per (line, rule): e.g. `api_token = "ghp_..."` trips both the
    // secret-name and key-shape checks. Name checks run first, so the kept
    // message names the binding to fix. The sort is stable.
    l.findings.sort_by_key(|f| f.line);
    let mut seen = HashSet::new();
    l.findings.retain(|f| seen.insert((f.line, f.rule)));
    suppressed.sort_by_key(|(f, _)| f.line);
    Report { findings: l.findings, allowed, suppressed }
}

#[derive(Default, Clone)]
struct Cx {
    /// names holding untrusted (request-derived) data
    taint: HashSet<String>,
    /// names holding strings built by interpolation / concatenation
    dynamic: HashSet<String>,
}

struct Linter {
    findings: Vec<Finding>,
}

fn last_segment(name: &str) -> &str {
    name.rsplit("::").next().unwrap_or(name)
}

impl Linter {
    fn function(&mut self, f: &FnDef, allowed: &mut Vec<(usize, String)>, suppressed: &mut Vec<(Finding, String)>) {
        if let Some(why) = &f.allow_insecure {
            allowed.push((f.line, why.clone()));
            let mut s = Linter { findings: Vec::new() };
            s.block(&f.body, &mut Cx::default());
            suppressed.extend(s.findings.into_iter().map(|f| (f, why.clone())));
            return;
        }
        self.block(&f.body, &mut Cx::default());
    }

    fn push(&mut self, line: usize, rule: &'static str, msg: String, fix: &'static str) {
        self.findings.push(Finding { line, rule, msg, fix });
    }

    fn block(&mut self, b: &Block, cx: &mut Cx) {
        for s in b {
            self.stmt(&s.stmt, s.line, cx);
        }
    }

    fn stmt(&mut self, s: &Stmt, line: usize, cx: &mut Cx) {
        match s {
            Stmt::Render(parts) => {
                for p in parts {
                    if let HtmlPart::Value(e, _) = p {
                        if exposes(e) {
                            self.push(line, "secret-exposure", "an exposed Secret is rendered into the page".into(), FIX_EXPOSE);
                        }
                        self.expr(e, line, cx);
                    }
                }
            }
            Stmt::Let { name, value, .. } => {
                self.secret_binding(name, value, line);
                self.expr(value, line, cx);
                if tainted(value, cx) {
                    cx.taint.insert(name.clone());
                }
                if is_dynamic(value, cx) {
                    cx.dynamic.insert(name.clone());
                }
            }
            Stmt::Assign { target, value, .. } => {
                if let Expr::Field(_, f) = target {
                    self.secret_binding(f, value, line);
                }
                self.expr(target, line, cx);
                self.expr(value, line, cx);
                if let Expr::Ident(n) = target {
                    if tainted(value, cx) {
                        cx.taint.insert(n.clone());
                    }
                    if is_dynamic(value, cx) {
                        cx.dynamic.insert(n.clone());
                    }
                }
            }
            Stmt::Expr(e) | Stmt::Ret(Some(e)) => self.expr(e, line, cx),
            Stmt::LetTuple { names, value } => {
                self.expr(value, line, cx);
                if tainted(value, cx) {
                    cx.taint.extend(names.iter().map(|(n, _)| n.clone()));
                }
            }
            Stmt::Ret(None) | Stmt::Break | Stmt::Continue => {}
            Stmt::If { branches, els } => {
                for (c, b) in branches {
                    self.expr(c, line, cx);
                    let mut inner = cx.clone();
                    if let Expr::LetPat(p, x) = c {
                        if tainted(x, cx) {
                            inner.taint.extend(pattern_binds(p));
                        }
                        if is_dynamic(x, cx) {
                            inner.dynamic.extend(pattern_binds(p));
                        }
                    }
                    self.block(b, &mut inner);
                }
                if let Some(b) = els {
                    self.block(b, &mut cx.clone());
                }
            }
            Stmt::For { var, iter, body } => {
                self.expr(iter, line, cx);
                let mut inner = cx.clone();
                if tainted(iter, cx) {
                    inner.taint.insert(var.clone());
                }
                self.block(body, &mut inner);
            }
            Stmt::While { cond, body } => {
                self.expr(cond, line, cx);
                self.block(body, &mut cx.clone());
            }
            Stmt::Loop(body) => self.block(body, &mut cx.clone()),
        }
    }

    fn expr(&mut self, e: &Expr, line: usize, cx: &Cx) {
        match e {
            Expr::Str(parts) => {
                for p in parts {
                    match p {
                        StrPart::Lit(s) => self.key_like(s, line),
                        StrPart::Interp(x, _) => {
                            if exposes(x) {
                                self.push(line, "secret-exposure", "an exposed Secret is interpolated into a string".into(), FIX_EXPOSE);
                            }
                            self.expr(x, line, cx)
                        }
                    }
                }
            }
            Expr::Call(name, _, args) => {
                self.call_rules(name, args, line, cx);
                args.iter().for_each(|a| self.expr(a, line, cx));
            }
            Expr::Method(recv, m, _, args) => {
                self.method_rules(recv, m, args, line, cx);
                self.expr(recv, line, cx);
                let recv_tainted = tainted(recv, cx);
                for a in args {
                    match a {
                        // `tainted.iter().map(|x| ..)`: the closure's params carry the taint
                        Expr::Closure { params, body, .. } if recv_tainted => {
                            let mut inner = cx.clone();
                            inner.taint.extend(params.iter().map(|(n, _)| n.clone()));
                            self.closure_body(body, line, &mut inner);
                        }
                        other => self.expr(other, line, cx),
                    }
                }
            }
            Expr::Closure { body, .. } | Expr::Spawn(body) => self.closure_body(body, line, &mut cx.clone()),
            Expr::Tuple(xs) => xs.iter().for_each(|x| self.expr(x, line, cx)),
            Expr::Named(_, x) => self.expr(x, line, cx),
            Expr::StructLit(_, fields) => {
                for (f, v) in fields {
                    self.secret_binding(f, v, line);
                    self.expr(v, line, cx);
                }
            }
            Expr::List(xs) => xs.iter().for_each(|x| self.expr(x, line, cx)),
            Expr::Binary(a, _, b) | Expr::Range(a, b, _) | Expr::Index(a, b) => {
                self.expr(a, line, cx);
                self.expr(b, line, cx);
            }
            Expr::Unary(_, x) | Expr::Ref(x, _) | Expr::Field(x, _) | Expr::Try(x) | Expr::Await(x) => {
                self.expr(x, line, cx)
            }
            Expr::If(c, a, b) => {
                for e in [c, a, b] {
                    self.expr(e, line, cx);
                }
            }
            Expr::LetPat(_, x) => self.expr(x, line, cx),
            Expr::Match(scrut, arms) => {
                self.expr(scrut, line, cx);
                for arm in arms {
                    let mut inner = cx.clone();
                    if tainted(scrut, cx) {
                        inner.taint.extend(pattern_binds(&arm.pat));
                    }
                    if let Some(g) = &arm.guard {
                        self.expr(g, arm.line, &inner);
                    }
                    self.block(&arm.body, &mut inner);
                }
            }
            Expr::Cast(x, _) => self.expr(x, line, cx),
            Expr::Map(kvs) => {
                for (k, v) in kvs {
                    if let Expr::Str(p) = k
                        && let [StrPart::Lit(name)] = p.as_slice()
                    {
                        self.secret_binding(name, v, line);
                    }
                    self.expr(k, line, cx);
                    self.expr(v, line, cx);
                }
            }
            Expr::Catch { expr, handler, .. } => {
                self.expr(expr, line, cx);
                self.closure_body(handler, line, &mut cx.clone());
            }
            Expr::Int(_) | Expr::Float(_) | Expr::Char(_) | Expr::Bool(_) | Expr::Ident(_) => {}
        }
    }

    fn closure_body(&mut self, body: &ClosureBody, line: usize, cx: &mut Cx) {
        match body {
            ClosureBody::Expr(x) => self.expr(x, line, cx),
            ClosureBody::Block(b) => self.block(b, cx),
        }
    }

    fn call_rules(&mut self, name: &str, args: &[Expr], line: usize, cx: &Cx) {
        let seg = last_segment(name);
        if OUTPUT_SINKS.contains(&name) && args.iter().any(exposes) {
            self.push(line, "secret-exposure", format!("an exposed Secret is passed to `{name}(..)`"), FIX_EXPOSE);
        }
        if matches!(name, "secret" | "Secret::new" | "Secret") && args.iter().any(|a| matches!(a, Expr::Str(p) if p.iter().any(|x| matches!(x, StrPart::Lit(l) if !l.is_empty())))) {
            self.push(line, "hardcoded-secret", "a Secret is created from a string literal".into(), FIX_SECRET);
        }
        if SQL_FNS.contains(&seg) && args.iter().any(|a| is_dynamic(a, cx)) {
            self.push(line, "sql-injection", format!("`{name}(..)` receives a string built from interpolation/concatenation"), FIX_SQL);
        }
        if name.ends_with("Command::new") {
            match args.first() {
                Some(Expr::Str(p)) if matches!(p.as_slice(), [StrPart::Lit(_)]) => {}
                Some(a) if is_dynamic(a, cx) || tainted(a, cx) => self.push(
                    line,
                    "command-injection",
                    "the program run by `Command::new` is built from dynamic input".into(),
                    FIX_CMD,
                ),
                _ => {}
            }
        }
        let fs_call = name.contains("fs::") || name.starts_with("File::") || name.contains("::File::");
        let fs_name = FS_FNS.contains(&seg) || FS_FNS.iter().any(|f| name.ends_with(f));
        if fs_call && fs_name && args.iter().any(|a| tainted(a, cx)) {
            self.push(line, "path-traversal", format!("request input reaches `{name}(..)` unsanitized"), FIX_PATH);
        }
    }

    fn method_rules(&mut self, recv: &Expr, m: &str, args: &[Expr], line: usize, cx: &Cx) {
        if SQL_FNS.contains(&m) && args.iter().any(|a| is_dynamic(a, cx)) {
            self.push(line, "sql-injection", format!("`.{m}(..)` receives a string built from interpolation/concatenation"), FIX_SQL);
        }
        if (m == "arg" || m == "args") && shell_root(recv) {
            let dynamic_arg = args.iter().any(|a| {
                let items: Vec<&Expr> = match a {
                    Expr::List(xs) => xs.iter().collect(),
                    Expr::Ref(x, _) if matches!(&**x, Expr::List(_)) => match &**x {
                        Expr::List(xs) => xs.iter().collect(),
                        _ => vec![],
                    },
                    other => vec![other],
                };
                items.iter().any(|x| is_dynamic(x, cx) || tainted(x, cx))
            });
            if dynamic_arg {
                self.push(line, "command-injection", "a shell (`sh -c` style) receives a dynamic script".into(), FIX_CMD);
            }
        }
        if m == "open" && chain_mentions(recv, "OpenOptions") && args.iter().any(|a| tainted(a, cx)) {
            self.push(line, "path-traversal", "request input reaches `OpenOptions::open(..)` unsanitized".into(), FIX_PATH);
        }
    }

    fn secret_binding(&mut self, name: &str, value: &Expr, line: usize) {
        let lower = name.to_lowercase();
        if !SECRET_NAMES.iter().any(|s| lower.contains(s)) {
            return;
        }
        if let Expr::Str(parts) = value
            && let [StrPart::Lit(s)] = parts.as_slice()
            && !s.is_empty()
        {
            self.push(line, "hardcoded-secret", format!("`{name}` is assigned a string literal"), FIX_SECRET);
        }
    }

    fn key_like(&mut self, s: &str, line: usize) {
        let prefixed = KEY_PREFIXES.iter().any(|p| s.starts_with(p)) && s.len() >= 16;
        let random = s.len() >= 32
            && !s.contains(char::is_whitespace)
            && !s.contains("://")
            && s.chars().any(|c| c.is_ascii_digit())
            && s.chars().any(|c| c.is_ascii_alphabetic())
            && entropy(s) >= 4.3;
        if prefixed || random {
            let shown: String = s.chars().take(6).collect();
            self.push(line, "hardcoded-secret", format!("string literal \"{shown}...\" looks like a credential"), FIX_SECRET);
        }
    }
}

/// Shannon entropy in bits per character.
pub fn entropy(s: &str) -> f64 {
    let mut counts = std::collections::HashMap::new();
    for c in s.chars() {
        *counts.entry(c).or_insert(0usize) += 1;
    }
    let n = s.chars().count() as f64;
    counts.values().map(|&c| {
        let p = c as f64 / n;
        -p * p.log2()
    }).sum()
}

/// A string assembled at runtime (interpolation, `+`, or a name holding one).
fn is_dynamic(e: &Expr, cx: &Cx) -> bool {
    match e {
        Expr::Str(parts) => parts.iter().any(|p| matches!(p, StrPart::Interp(..))),
        Expr::Binary(a, op, b) if op == "+" => {
            is_dynamic(a, cx) || is_dynamic(b, cx) || matches!(**a, Expr::Str(_)) || matches!(**b, Expr::Str(_))
        }
        Expr::If(_, a, b) => is_dynamic(a, cx) || is_dynamic(b, cx),
        Expr::Ident(n) => cx.dynamic.contains(n),
        Expr::Ref(x, _) | Expr::Try(x) => is_dynamic(x, cx),
        Expr::Method(x, m, _, _) if matches!(m.as_str(), "as_str" | "clone" | "to_string" | "trim") => is_dynamic(x, cx),
        Expr::Call(n, _, _) if n == "format" => true,
        _ => false,
    }
}

/// Does `e` reveal a Secret's value (`s.expose()`) anywhere inside?
fn exposes(e: &Expr) -> bool {
    let mut found = false;
    visit_expr(e, &mut |x| found |= matches!(x, Expr::Method(_, m, _, _) if m == "expose"));
    found
}

/// Does the expression carry request-derived data? `safe_join(..)` cleans it.
fn tainted(e: &Expr, cx: &Cx) -> bool {
    match e {
        Expr::If(c, a, b) => [c, a, b].iter().any(|x| tainted(x, cx)),
        Expr::LetPat(_, x) => tainted(x, cx),
        Expr::Ident(n) => cx.taint.contains(n),
        Expr::Call(n, _, _) if n == "safe_join" => false,
        Expr::Call(_, _, args) => args.iter().any(|a| tainted(a, cx)),
        Expr::Method(x, _, _, args) => tainted(x, cx) || args.iter().any(|a| tainted(a, cx)),
        Expr::Str(parts) => parts.iter().any(|p| matches!(p, StrPart::Interp(x, _) if tainted(x, cx))),
        Expr::Binary(a, _, b) | Expr::Index(a, b) | Expr::Range(a, b, _) => tainted(a, cx) || tainted(b, cx),
        Expr::Unary(_, x) | Expr::Ref(x, _) | Expr::Field(x, _) | Expr::Try(x) | Expr::Await(x) => tainted(x, cx),
        Expr::List(xs) => xs.iter().any(|x| tainted(x, cx)),
        Expr::StructLit(_, fs) => fs.iter().any(|(_, v)| tainted(v, cx)),
        Expr::Match(s, _) => tainted(s, cx),
        Expr::Tuple(xs) => xs.iter().any(|x| tainted(x, cx)),
        Expr::Named(_, x) => tainted(x, cx),
        Expr::Closure { .. } | Expr::Spawn(_) => false,
        Expr::Cast(x, _) => tainted(x, cx),
        Expr::Map(kvs) => kvs.iter().any(|(k, v)| tainted(k, cx) || tainted(v, cx)),
        Expr::Catch { expr, .. } => tainted(expr, cx),
        Expr::Int(_) | Expr::Float(_) | Expr::Char(_) | Expr::Bool(_) => false,
    }
}

/// Is the root of this method chain `Command::new("sh" | "bash" | ...)`?
fn shell_root(e: &Expr) -> bool {
    match e {
        Expr::Method(x, ..) => shell_root(x),
        Expr::Call(n, _, args) if n.ends_with("Command::new") => matches!(
            args.first(),
            Some(Expr::Str(p)) if matches!(p.as_slice(), [StrPart::Lit(s)] if SHELLS.contains(&s.as_str()))
        ),
        _ => false,
    }
}

fn chain_mentions(e: &Expr, needle: &str) -> bool {
    match e {
        Expr::Method(x, ..) => chain_mentions(x, needle),
        Expr::Call(n, ..) | Expr::Ident(n) => n.contains(needle),
        _ => false,
    }
}

fn pattern_binds(p: &Pat) -> Vec<String> {
    match p {
        Pat::Bind(n) => vec![n.clone()],
        Pat::Or(ps) => ps.iter().flat_map(pattern_binds).collect(),
        Pat::Variant(_, Some(subs)) => subs.iter().flat_map(|(_, p)| pattern_binds(p)).collect(),
        _ => vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{lexer::lex, parser::parse};

    fn rules(src: &str) -> Vec<(usize, &'static str)> {
        lint(&parse(lex(src).unwrap()).unwrap()).findings.iter().map(|f| (f.line, f.rule)).collect()
    }

    #[test]
    fn sql_injection() {
        let src = "@public\nroute GET \"/u/{id}\" (id: str) -> str!:\n    q = \"SELECT * FROM users WHERE id = {id}\"\n    rows = sqlx::query(&q).fetch_all(&pool).await?\n    sqlx::query(\"DELETE FROM t WHERE x = \" + id).execute(&pool).await?\n    ok = sqlx::query(\"SELECT * FROM users WHERE id = $1\").bind(id).fetch_one(&pool).await?\n    ret \"\"\n";
        assert_eq!(rules(src), [(4, "sql-injection"), (5, "sql-injection")]);
        // interpolation into SQL is flagged outside routes too
        assert_eq!(rules("fn f(t: &str):\n    db.execute(\"DROP TABLE {t}\")\n"), [(2, "sql-injection")]);
    }

    #[test]
    fn command_injection() {
        let src = "@public\nroute POST \"/run\" (body: Job) -> str!:\n    Command::new(\"sh\").arg(\"-c\").arg(\"tar czf {body.name}.tgz\").output()?\n    Command::new(body.tool).output()?\n    Command::new(\"tar\").arg(\"czf\").arg(body.name).output()?\n    Command::new(\"bash\").args([\"-c\", \"echo hi\"]).output()?\n    ret \"\"\n";
        assert_eq!(rules(src), [(3, "command-injection"), (4, "command-injection")]);
    }

    #[test]
    fn path_traversal() {
        let src = "@public\nroute GET \"/files/{name}\" (name: str) -> str!:\n    p = \"/srv/data/{name}\"\n    a = std::fs::read_to_string(&p)?\n    b = fs::read(Path::new(\"/srv\").join(&name))?\n    ok = std::fs::read_to_string(safe_join(\"/srv/data\", &name)?)?\n    c = std::fs::read_to_string(\"/etc/app.conf\")?\n    ret a\n";
        assert_eq!(rules(src), [(4, "path-traversal"), (5, "path-traversal")]);
        // CLI tools may read user-given paths: not flagged outside routes
        assert!(rules("fn main(path: str)!:\n    x = std::fs::read_to_string(&path)?\n").is_empty());
    }

    #[test]
    fn hardcoded_secrets() {
        let src = "state:\n    api_key: str = \"abc123secret\"\n    db_url: str = env(\"DATABASE_URL\")\n    jwt_secret: str = env(\"JWT_SECRET\")\n@public\nroute GET \"/\" (state) -> str:\n    ret \"\"\nfn f():\n    password = \"hunter22\"\n    token = \"\"\n    c = Cfg(client_secret: \"s3cr3t\")\n    k = \"sk_live_51HxQ2abcdef0123456789\"\n    r = \"q8Zt3LmX9vB2nR7kW4pY6sD1fG5hJ0cV8aE3uI\"\n    uuid = \"550e8400-e29b-41d4-a716-446655440000\"\n    url = \"https://api.example.com/v1/users/12345/profile\"\n";
        assert_eq!(
            rules(src),
            [
                (2, "secret-type"),
                (2, "hardcoded-secret"),
                (4, "secret-type"),
                (9, "hardcoded-secret"),
                (11, "hardcoded-secret"),
                (12, "hardcoded-secret"),
                (13, "hardcoded-secret")
            ]
        );
    }

    #[test]
    fn secrets_stay_secret() {
        let src = "state:\n    token: Secret = env_secret(\"T\")?\n    db_password: str = env(\"DB\")\n@public\nroute GET \"/\" (state) -> str:\n    print(\"{state.token}\")\n    q = sqlx::query(\"SELECT 1 WHERE k = $1\").bind(state.token.expose())\n    log_warn(\"x\", t: state.token.expose().clone())\n    s = \"Bearer {state.token.expose()}\"\n    k = secret(\"abc\")\n    ret \"\"\n";
        assert_eq!(rules(src), [(3, "secret-type"), (8, "secret-exposure"), (9, "secret-exposure"), (10, "hardcoded-secret")]);
    }

    #[test]
    fn one_finding_per_line_and_rule() {
        let src = "fn main():\n    api_token = \"ghp_abcdef1234567890abcdef\"\n    cfg = Cfg(secret: \"sk_live_51HxQ2abcdef0123456789\")\n    q = \"SELECT {x}\"\n    db.execute(q).query(\"DELETE {x}\")\n";
        let r = lint(&parse(lex(src).unwrap()).unwrap());
        let got: Vec<(usize, &str, &str)> = r.findings.iter().map(|f| (f.line, f.rule, f.msg.as_str())).collect();
        assert_eq!(
            got,
            [
                (2, "hardcoded-secret", "`api_token` is assigned a string literal"),
                (3, "hardcoded-secret", "`secret` is assigned a string literal"),
                (5, "sql-injection", "`.query(..)` receives a string built from interpolation/concatenation"),
            ]
        );
    }

    #[test]
    fn taint_flows_into_closures_over_tainted_data() {
        let src = "@public\nroute POST \"/x\" (body: Req) -> str!:\n    texts = body.files.iter().map(|f| std::fs::read_to_string(f)).collect()\n    ok = [\"a\"].iter().map(|f| std::fs::read_to_string(f)).collect()\n    q = sqlx::query(\"\"\"\n        SELECT * FROM t\n        WHERE id = $1\n        \"\"\").bind(body.id)\n    ret \"\"\n";
        assert_eq!(rules(src), [(3, "path-traversal")]);
    }

    #[test]
    fn allow_insecure_opts_out_and_is_reported() {
        let src = "@public\n@allow_insecure(\"internal admin tool, input is trusted\")\nroute GET \"/f/{n}\" (n: str) -> str!:\n    ret std::fs::read_to_string(&n)?\n@public\nroute GET \"/g/{n}\" (n: str) -> str!:\n    ret std::fs::read_to_string(&n)?\n";
        let r = lint(&parse(lex(src).unwrap()).unwrap());
        assert_eq!(r.findings.iter().map(|f| f.line).collect::<Vec<_>>(), [7]);
        assert_eq!(r.allowed, [(3, "internal admin tool, input is trusted".to_string())]);
        let f = &r.findings[0];
        assert!(f.render("app.prvz").starts_with("app.prvz:7: security[path-traversal]: request input reaches `std::fs::read_to_string(..)` unsanitized\n     = fix: join untrusted"));
        assert!(f.render("app.prvz").ends_with("\n     = see: CWE-22, OWASP A01:2021 Broken Access Control, ASVS 12.3.1, ASVS 12.3.2"));
        // the waived finding is still known (SARIF exports it as suppressed)
        let [(w, why)] = r.suppressed.as_slice() else { panic!("{:?}", r.suppressed) };
        assert_eq!((w.line, w.rule, why.as_str()), (4, "path-traversal", "internal admin tool, input is trusted"));
    }

    #[test]
    fn every_rule_maps_to_standards() {
        // each rule id pushed by the linter has a catalog entry with references
        let code = include_str!("security.rs");
        let pushed: HashSet<&str> = code
            .split("self.push(")
            .skip(1)
            .chain(code.split("l.push(").skip(1))
            .filter_map(|c| c.split('"').nth(1))
            .filter(|id| id.chars().all(|c| c.is_ascii_lowercase() || c == '-') && id.contains('-'))
            .collect();
        assert!(pushed.len() >= 6, "{pushed:?}");
        for id in pushed {
            let r = rule(id).unwrap_or_else(|| panic!("rule {id} has no catalog entry"));
            assert!(!r.cwe.is_empty() && !r.asvs.is_empty() && r.owasp.contains(":2021"), "{id}");
        }
        assert!(rule("nope").is_none());
    }

    #[test]
    fn taint_flows_through_lets_and_match() {
        let src = "@public\nroute POST \"/x\" (body: Req) -> str!:\n    n = body.name.trim().to_string()\n    m = match body.kind:\n        k -> k\n    ret std::fs::read_to_string(m)?\n";
        assert_eq!(rules(src), [(6, "path-traversal")]);
    }
}
