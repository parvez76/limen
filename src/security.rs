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
//! Taint sources: route params, `body`, `query`, `req`, a socket's `conn`,
//! and the inputs of guard functions. Taint follows values derived from them
//! and flows into user functions and methods: each function gets a summary
//! (which parameters reach which sinks), computed to a fixed point, so a
//! route that passes request data to a helper that opens a file is caught
//! at the call, naming the sink inside the helper.

use crate::ast::*;
use std::collections::{HashMap, HashSet};

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
    /// set when the analysis hit its safety limit: callers must fail, not report "clean"
    pub incomplete: Option<String>,
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
        id: "disallowed-call",
        title: "A call this project disallows",
        description: "A function or method listed in `[security] disallow` in parvez.toml is called.",
        cwe: &[676],
        owasp: "A04:2021 Insecure Design",
        asvs: &[],
        severity: "5.0",
        fix: FIX_DISALLOW,
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

/// Project rules from `[security]` in parvez.toml: banned calls (like Clippy's
/// `disallowed_methods`) and extra sinks, so a third-party crate that opens files,
/// runs programs or runs SQL is checked like `std::fs`, `Command` and `sqlx`.
/// A pattern is a path (`duct::cmd`, matching that call or a `use`d `cmd`) or,
/// with a leading dot, a method name (`.read_to_string`).
#[derive(Clone, Debug, Default)]
pub struct Custom {
    pub disallow: Vec<(String, String)>,
    pub path_sinks: Vec<String>,
    pub command_sinks: Vec<String>,
    pub sql_sinks: Vec<String>,
}

fn call_matches(name: &str, pat: &str) -> bool {
    !pat.starts_with('.') && (name == pat || name.ends_with(&format!("::{pat}")) || pat.ends_with(&format!("::{name}")))
}

fn method_matches(m: &str, pat: &str) -> bool {
    pat.strip_prefix('.') == Some(m)
}

const FIX_DISALLOW: &str = "use the alternative given in parvez.toml's reason, or remove the entry from [security] disallow";

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

#[cfg_attr(not(test), allow(dead_code))] // used by the playground and the tests
pub fn lint(prog: &Program) -> Report {
    lint_with(prog, &Custom::default())
}

pub fn lint_with(prog: &Program, custom: &Custom) -> Report {
    let test_mods = prog.test_only_modules();
    let items: Vec<(&[String], &Item)> =
        prog.all_items().into_iter().filter(|(m, i)| !prog.is_test_scope(m, i, &test_mods)).collect();
    let mut fx = Fx::new(prog, &items);
    fx.custom = custom.clone();
    let mut incomplete = (!fx.summarize()).then(|| "function summaries did not converge".to_string());
    // guards run on every request before the handler: their inputs are untrusted too
    let mut guards: HashSet<String> = HashSet::new();
    for (module, item) in &items {
        if let Item::Route(r) = item {
            guards.extend(r.guards.iter().filter_map(|g| fx.resolve(module, g)));
        }
    }
    // `state:` fields that end up holding request data, to a fixed point
    // (a stored value copied into another field taints that one too)
    // Each pass that changes anything adds at least one field, so this ends after
    // at most one pass per `state:` field; the limit is only a guard against bugs.
    let fields: usize = items.iter().map(|(_, i)| if let Item::State(st) = i { st.fields.len() } else { 0 }).sum();
    let mut run = analyze(&fx, &items, &guards);
    let mut passes = 0;
    loop {
        let mut stored = (*fx.stored).clone();
        for (field, at) in &run.writes {
            stored.entry(field.clone()).or_insert_with(|| at.clone());
            // data sent on a channel arrives at its receivers
            for rx in fx.channels.get(field).into_iter().flatten() {
                stored.entry(rx.clone()).or_insert_with(|| format!("{at}, sent through `state.{field}`"));
            }
        }
        if stored.len() == fx.stored.len() {
            break;
        }
        passes += 1;
        if passes > fields + 1 {
            incomplete.get_or_insert_with(|| "stored-state analysis did not converge".to_string());
            break;
        }
        fx.stored = std::rc::Rc::new(stored);
        run = analyze(&fx, &items, &guards);
    }
    // One finding per (line, rule): e.g. `api_token = "ghp_..."` trips both the
    // secret-name and key-shape checks. Name checks run first, so the kept
    // message names the binding to fix. The sort is stable.
    let mut findings = run.findings;
    findings.sort_by_key(|f| f.line);
    let mut seen = HashSet::new();
    findings.retain(|f| seen.insert((f.line, f.rule)));
    let mut suppressed = run.suppressed;
    suppressed.sort_by_key(|(f, _)| f.line);
    Report { findings, allowed: run.allowed, suppressed, incomplete }
}

struct Run {
    findings: Vec<Finding>,
    allowed: Vec<(usize, String)>,
    suppressed: Vec<(Finding, String)>,
    /// (state field, "file:line") where request data was stored
    writes: Vec<(String, String)>,
}

/// One pass over every item with the current knowledge of tainted state fields.
fn analyze(fx: &Fx, items: &[(&[String], &Item)], guards: &HashSet<String>) -> Run {
    let mut l = Linter::new(fx, &[]);
    let mut allowed = Vec::new();
    let mut suppressed = Vec::new();
    let mut waived_writes = Vec::new();
    for (module, item) in items {
        l.module = module.to_vec();
        match item {
            Item::Const { name, value, line, .. } => {
                l.secret_binding(name, value, *line);
                l.expr(value, *line, &fx.cx());
            }
            Item::Fn(f) => {
                let key = qualify(module, &f.name);
                let guard = guards.contains(&key);
                l.function(&key, f, guard, &mut allowed, &mut suppressed, &mut waived_writes)
            }
            Item::Impl(i) => i.methods.iter().for_each(|m| {
                l.function(&qualify(module, &format!("{}::{}", i.ty, m.name)), m, false, &mut allowed, &mut suppressed, &mut waived_writes)
            }),
            Item::Trait(t) => t.methods.iter().for_each(|m| {
                l.function(&qualify(module, &format!("{}::{}", t.name, m.name)), m, false, &mut allowed, &mut suppressed, &mut waived_writes)
            }),
            Item::Every(e) => l.block(&e.body, &mut fx.cx()),
            Item::Route(r) => {
                let mut cx = fx.cx();
                cx.taint.extend(r.params.iter().filter(|(_, t)| carries_text(t)).map(|(n, _)| n.clone()));
                for (n, t) in &r.params {
                    if let Some(d) = fx.desc(t, &HashMap::new()) {
                        cx.types.insert(n.clone(), d);
                    }
                }
                // `req` exposes headers, params and the raw body; a socket's `conn` yields client messages
                if r.req {
                    cx.taint.insert("req".into());
                }
                if r.conn {
                    cx.taint.insert("conn".into());
                }
                if let Some(why) = &r.allow_insecure {
                    allowed.push((r.line, why.clone()));
                    let mut s = Linter::new(fx, module);
                    s.block(&r.body, &mut cx);
                    suppressed.extend(s.findings.into_iter().map(|f| (f, why.clone())));
                    waived_writes.extend(s.writes);
                    continue;
                }
                l.block(&r.body, &mut cx);
            }
            Item::State(st) => {
                let mut s = Linter::new(fx, module);
                let l = if st.allow_insecure.is_some() { &mut s } else { &mut l };
                let mut cx = fx.cx();
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
    // data stored by waived code is still request data when other code reads it
    let mut writes = l.writes;
    writes.extend(waived_writes);
    Run { findings: l.findings, allowed, suppressed, writes }
}

/// Where untrusted data entering one parameter of a function ends up.
#[derive(Clone, Debug, PartialEq)]
struct Sink {
    rule: &'static str,
    /// "`std::fs::read(..)` at files.prvz:3", the deepest sink in the call chain
    what: String,
    fix: &'static str,
}

/// Interprocedural context: every function in the program (by qualified
/// name) and, per parameter, the sinks that parameter reaches, directly or
/// through further calls. Summaries are computed to a fixed point, so
/// helper chains and recursion are followed.
struct Fx<'a> {
    files: Vec<String>,
    /// `f`, `store::f`, `Type::m`, `store::Type::m` -> the function and where it lives
    fns: HashMap<String, FnInfo<'a>>,
    /// method name -> keys of methods with a receiver (used when the receiver's type is unknown and the name is unique)
    methods: HashMap<String, Vec<String>>,
    /// key -> per parameter (same order as `FnDef::params`): sinks reached and state fields written
    sums: HashMap<String, Vec<ParamSum>>,
    /// struct / enum names
    user_types: HashSet<String>,
    /// trait -> implementing types; type -> implemented traits
    trait_impls: HashMap<String, Vec<String>>,
    type_traits: HashMap<String, Vec<String>>,
    /// `state:` field -> its type (a user type or `dyn Trait`), for method dispatch
    state_types: HashMap<String, String>,
    /// `state:` field -> the type of its elements (`Vec<Box<dyn Store>>`)
    state_elems: HashMap<String, String>,
    /// `state:` fields holding request data -> where it was stored ("file:line")
    stored: std::rc::Rc<HashMap<String, String>>,
    /// project rules from parvez.toml
    custom: Custom,
    /// channel sender field -> the receiver fields of the same element type
    channels: HashMap<String, Vec<String>>,
}

struct FnInfo<'a> {
    module: &'a [String],
    /// the `impl` type (or trait) a method belongs to
    owner: Option<&'a str>,
    /// generic parameter -> the user trait it's bounded by (`S: Store`)
    bounds: HashMap<String, String>,
    f: &'a FnDef,
}

#[derive(Clone, Debug, Default, PartialEq)]
struct ParamSum {
    sinks: Vec<Sink>,
    /// (state field, "file:line"): the parameter's value is stored there
    writes: Vec<(String, String)>,
    /// the parameter's value is stored in a field of `self` (`self.path = p`)
    self_write: bool,
}

/// Calls that return rows from the database: their values may have been written
/// by an earlier request (second-order injection), so file paths and commands
/// built from them are checked like request input.
const DB_READS: &[&str] = &["fetch_one", "fetch_all", "fetch_optional", "fetch", "query_one", "query_opt", "try_get"];
/// `via` marker for taint that comes from a database read.
const FROM_DB: &str = "#db";

/// Wrappers a method call sees through (`Arc<dyn Store>`, `Mutex<Cache>`).
const WRAPPERS: &[&str] = &["Box", "Arc", "Rc", "Mutex", "RwLock", "RefCell", "Cell"];
/// Methods that store their argument into the receiver.
const WRITE_METHODS: &[&str] = &[
    "insert", "push", "push_back", "push_front", "extend", "append", "set", "replace", "store", "send", "try_send",
    "put", "or_insert", "or_insert_with", "entry", "insert_str", "push_str",
];
/// A `let` holding one of these (after unwrap/await) is a handle into the state field.
const GUARD_METHODS: &[&str] = &["lock", "write", "borrow_mut", "get_mut", "entry", "as_mut", "try_lock", "blocking_lock"];

/// Numbers, `bool` and `char` can't hold a path, a script or SQL: parameters of
/// those types aren't taint sources (`/files/{id}` with `id: i64` is safe).
fn carries_text(t: &Type) -> bool {
    const SCALARS: &[&str] = &[
        "i8", "i16", "i32", "i64", "i128", "isize", "u8", "u16", "u32", "u64", "u128", "usize", "f32", "f64", "bool", "char",
    ];
    !matches!(t, Type::Named(n, a) if a.is_empty() && SCALARS.contains(&n.as_str()))
}

/// A channel end: (is the sender, element type), seeing through Mutex/Arc/...
fn channel_end(t: &Type) -> Option<(bool, String)> {
    match t {
        Type::Ref(x, _) => channel_end(x),
        Type::Named(n, args) => {
            let base = last_segment(n);
            if WRAPPERS.contains(&base) && args.len() == 1 {
                return channel_end(&args[0]);
            }
            let elem = args.first().map(|a| format!("{a:?}")).unwrap_or_default();
            match base {
                "Sender" | "UnboundedSender" | "SyncSender" => Some((true, elem)),
                "Receiver" | "UnboundedReceiver" => Some((false, elem)),
                _ => None,
            }
        }
        _ => None,
    }
}

/// `tx, rx = mpsc::channel()` and friends.
const CHANNEL_CTORS: &[&str] = &["channel", "unbounded_channel", "sync_channel", "bounded", "unbounded"];

fn qualify(module: &[String], name: &str) -> String {
    if module.is_empty() { name.to_string() } else { format!("{}::{name}", module.join("::")) }
}

impl<'a> Fx<'a> {
    fn new(prog: &Program, items: &[(&'a [String], &'a Item)]) -> Fx<'a> {
        let mut fx = Fx {
            files: prog.files.iter().map(|f| f.0.clone()).collect(),
            fns: HashMap::new(),
            methods: HashMap::new(),
            sums: HashMap::new(),
            user_types: HashSet::new(),
            trait_impls: HashMap::new(),
            type_traits: HashMap::new(),
            state_types: HashMap::new(),
            state_elems: HashMap::new(),
            stored: Default::default(),
            custom: Custom::default(),
            channels: HashMap::new(),
        };
        let mut traits: HashSet<String> = HashSet::new();
        for (_, item) in items {
            match item {
                Item::Struct(st) => {
                    fx.user_types.insert(st.name.clone());
                }
                Item::Enum(e) => {
                    fx.user_types.insert(e.name.clone());
                }
                Item::Trait(t) => {
                    traits.insert(t.name.clone());
                }
                Item::Impl(i) => {
                    if let Some(Type::Named(t, _)) = &i.trait_ {
                        let t = last_segment(t).to_string();
                        fx.trait_impls.entry(t.clone()).or_default().push(i.ty.clone());
                        fx.type_traits.entry(i.ty.clone()).or_default().push(t);
                    }
                }
                _ => {}
            }
        }
        let bounds_of = |gs: &[Generic], out: &mut HashMap<String, String>| {
            for g in gs {
                if let Some(Type::Named(b, _)) = g.bounds.iter().find(|b| matches!(b, Type::Named(n, _) if traits.contains(last_segment(n)))) {
                    out.insert(g.name.clone(), last_segment(b).to_string());
                }
            }
        };
        for (module, item) in items {
            let mut add = |owner: Option<&'a str>, extra: &[Generic], f: &'a FnDef| {
                if !f.has_body && f.body.is_empty() {
                    return;
                }
                let local = match owner { Some(t) => format!("{t}::{}", f.name), None => f.name.clone() };
                let key = qualify(module, &local);
                if f.receiver.is_some() {
                    fx.methods.entry(f.name.clone()).or_default().push(key.clone());
                }
                let mut bounds = HashMap::new();
                bounds_of(extra, &mut bounds);
                bounds_of(&f.generics, &mut bounds);
                fx.fns.insert(key, FnInfo { module, owner, bounds, f });
            };
            match item {
                Item::Fn(f) => add(None, &[], f),
                Item::Impl(i) => i.methods.iter().for_each(|m| add(Some(&i.ty), i.generics.as_deref().unwrap_or(&[]), m)),
                Item::Trait(t) => t.methods.iter().for_each(|m| add(Some(&t.name), &t.generics, m)),
                _ => {}
            }
        }
        for (_, item) in items {
            if let Item::State(st) = item {
                for (name, ty, _, _) in &st.fields {
                    if let Some(d) = fx.desc(ty, &HashMap::new()) {
                        fx.state_types.insert(name.clone(), d);
                    }
                    if let Some(d) = fx.elem_desc(ty, &HashMap::new()) {
                        fx.state_elems.insert(name.clone(), d);
                    }
                }
                // channel ends: a sender connects to every receiver of the same element type
                let ends: Vec<(&String, bool, String)> = st.fields.iter().filter_map(|(n, t, _, _)| channel_end(t).map(|(s, e)| (n, s, e))).collect();
                for (sender, _, elem) in ends.iter().filter(|e| e.1) {
                    let rx: Vec<String> = ends.iter().filter(|e| !e.1 && &e.2 == elem).map(|e| e.0.clone()).collect();
                    if !rx.is_empty() {
                        fx.channels.insert((*sender).clone(), rx);
                    }
                }
            }
        }
        fx
    }

    /// A fresh context that knows which state fields hold request data.
    fn cx(&self) -> Cx {
        Cx { stored: self.stored.clone(), db: true, ..Cx::default() }
    }

    /// The element type of a list type: `[Disk]`, `Vec<Box<dyn Store>>`, `&[S]`.
    fn elem_desc(&self, t: &Type, bounds: &HashMap<String, String>) -> Option<String> {
        match t {
            Type::Ref(x, _) => self.elem_desc(x, bounds),
            Type::List(x) => self.desc(x, bounds),
            Type::Named(n, args) if args.len() == 1 && matches!(last_segment(n), "Vec" | "VecDeque" | "HashSet" | "BTreeSet") => {
                self.desc(&args[0], bounds)
            }
            Type::Named(n, args) if args.len() == 1 && WRAPPERS.contains(&last_segment(n)) => self.elem_desc(&args[0], bounds),
            _ => None,
        }
    }

    /// The type a method call on a value of type `t` dispatches on: a user type
    /// name, or `dyn Trait` (also for a generic bounded by a user trait).
    fn desc(&self, t: &Type, bounds: &HashMap<String, String>) -> Option<String> {
        match t {
            Type::Ref(x, _) => self.desc(x, bounds),
            Type::Named(n, args) => {
                let base = last_segment(n);
                if WRAPPERS.contains(&base) && args.len() == 1 {
                    return self.desc(&args[0], bounds);
                }
                if let Some(tr) = n.strip_prefix("dyn ") {
                    return Some(format!("dyn {}", last_segment(tr)));
                }
                if let Some(tr) = bounds.get(n) {
                    return Some(format!("dyn {tr}"));
                }
                self.user_types.contains(base).then(|| base.to_string())
            }
            _ => None,
        }
    }

    /// `name` as written in `module`: its own items first, then the main file's,
    /// then a unique suffix match (`tokens::f` for module `auth::tokens`).
    fn resolve(&self, module: &[String], name: &str) -> Option<String> {
        let name = name.strip_prefix("crate::").unwrap_or(name);
        let local = qualify(module, name);
        if self.fns.contains_key(&local) {
            return Some(local);
        }
        if self.fns.contains_key(name) {
            return Some(name.to_string());
        }
        if !name.contains("::") {
            return None;
        }
        let suffix = format!("::{name}");
        let mut hits = self.fns.keys().filter(|k| k.ends_with(&suffix));
        match (hits.next(), hits.next()) {
            (Some(k), None) => Some(k.clone()),
            _ => None,
        }
    }

    /// Per-parameter summaries for every function, to a fixed point. A worklist
    /// re-summarizes only the callers of a function whose summary changed, so a
    /// call chain of any depth is followed to its sink. Summaries only grow and
    /// are finite, so this terminates; `false` means the safety limit was hit
    /// (a bug), and the caller fails closed rather than report a clean result.
    fn summarize(&mut self) -> bool {
        let mut keys: Vec<String> = self.fns.keys().cloned().collect();
        keys.sort();
        let mut queue: std::collections::VecDeque<String> = keys.iter().cloned().collect();
        let mut queued: HashSet<String> = keys.iter().cloned().collect();
        let mut callers: HashMap<String, std::collections::BTreeSet<String>> = HashMap::new();
        let limit = (keys.len() + 1) * 10_000;
        let mut steps = 0;
        while let Some(key) = queue.pop_front() {
            queued.remove(&key);
            steps += 1;
            if steps > limit {
                return false;
            }
            let (sum, consulted) = self.summarize_one(&key);
            for callee in consulted {
                callers.entry(callee).or_default().insert(key.clone());
            }
            if self.sums.get(&key) != Some(&sum) {
                self.sums.insert(key.clone(), sum);
                for c in callers.get(&key).into_iter().flatten() {
                    if queued.insert(c.clone()) {
                        queue.push_back(c.clone());
                    }
                }
            }
        }
        true
    }

    /// One function's summary from the current summaries of its callees, and the callees it consulted.
    fn summarize_one(&self, key: &str) -> (Vec<ParamSum>, Vec<String>) {
        let info = &self.fns[key];
        let mut consulted = Vec::new();
        let per_param = info
            .f
            .params
            .iter()
            .map(|(p, t)| {
                if p == "state" || !carries_text(t) {
                    return ParamSum::default();
                }
                let mut probe = Linter::new(self, info.module);
                // probes ignore stored state: a sink fed by state isn't this parameter's
                let mut cx = Cx::default();
                probe.enter(info, &mut cx);
                cx.taint.insert(p.clone());
                probe.block(&info.f.body, &mut cx);
                consulted.append(&mut probe.consulted);
                let mut sum = ParamSum::default();
                for s in probe.sinks {
                    if !sum.sinks.contains(&s) {
                        sum.sinks.push(s);
                    }
                }
                for w in probe.writes {
                    if !sum.writes.iter().any(|x| x.0 == w.0) {
                        sum.writes.push(w);
                    }
                }
                sum.self_write = probe.self_write;
                sum
            })
            .collect();
        (per_param, consulted)
    }

    fn locate(&self, line: usize) -> String {
        let (k, l) = crate::ast::split_line(line);
        format!("{}:{l}", self.files.get(k).map(String::as_str).unwrap_or("?"))
    }
}

#[derive(Default, Clone)]
struct Cx {
    /// names holding untrusted (request-derived) data
    taint: HashSet<String>,
    /// names holding strings built by interpolation / concatenation
    dynamic: HashSet<String>,
    /// name -> its type, for method dispatch (a user type or `dyn Trait`)
    types: HashMap<String, String>,
    /// name -> the state field it's a handle into (`g = state.cache.lock().unwrap()`)
    aliases: HashMap<String, String>,
    /// name -> the stored state field its taint came from (for messages)
    via: HashMap<String, String>,
    /// state fields holding request data -> where it was stored
    stored: std::rc::Rc<HashMap<String, String>>,
    /// name -> the type of its elements (`[Disk(..)]`, `Vec<Box<dyn Store>>`)
    elems: HashMap<String, String>,
    /// local channel: sender name -> receiver name (`tx, rx = mpsc::channel()`)
    links: HashMap<String, String>,
    /// database reads count as untrusted (off in summaries' probes)
    db: bool,
}

impl Cx {
    /// The same context minus everything that's tainted only because it was read from state.
    fn without_stored(&self) -> Cx {
        let mut cx = Cx { stored: Default::default(), aliases: HashMap::new(), via: HashMap::new(), db: false, ..self.clone() };
        cx.taint.retain(|n| !self.via.contains_key(n));
        cx
    }
}

struct Linter<'f, 'a> {
    findings: Vec<Finding>,
    /// taint-driven sinks hit (for function summaries)
    sinks: Vec<Sink>,
    /// request data stored into state fields: (field, "file:line")
    writes: Vec<(String, String)>,
    /// request data stored into a field of `self` (for summaries)
    self_write: bool,
    /// receivers that took request data into their fields during the current
    /// statement (`job.set_path(name)` taints `job`); applied after it
    pending: Vec<String>,
    /// functions whose summaries this analysis read (the worklist's dependencies)
    consulted: Vec<String>,
    fx: &'f Fx<'a>,
    module: Vec<String>,
}

fn last_segment(name: &str) -> &str {
    name.rsplit("::").next().unwrap_or(name)
}

impl<'f, 'a> Linter<'f, 'a> {
    fn new(fx: &'f Fx<'a>, module: &[String]) -> Self {
        Linter { findings: Vec::new(), sinks: Vec::new(), writes: Vec::new(), self_write: false, pending: Vec::new(), consulted: Vec::new(), fx, module: module.to_vec() }
    }

    /// Parameter and `self` types for method dispatch inside a function.
    fn enter(&self, info: &FnInfo, cx: &mut Cx) {
        if let Some(owner) = info.owner {
            let own = if self.fx.trait_impls.contains_key(owner) { format!("dyn {owner}") } else { owner.to_string() };
            cx.types.insert("self".into(), own);
        }
        for (n, t) in &info.f.params {
            if let Some(d) = self.fx.desc(t, &info.bounds) {
                cx.types.insert(n.clone(), d);
            }
        }
    }

    /// `guard`: the fn is a route guard, so its `req` and path params carry request data.
    fn function(
        &mut self,
        key: &str,
        f: &FnDef,
        guard: bool,
        allowed: &mut Vec<(usize, String)>,
        suppressed: &mut Vec<(Finding, String)>,
        waived_writes: &mut Vec<(String, String)>,
    ) {
        let mut cx = self.fx.cx();
        if let Some(info) = self.fx.fns.get(key) {
            self.enter(info, &mut cx);
        }
        if guard {
            cx.taint.extend(f.params.iter().filter(|(n, t)| n != "state" && carries_text(t)).map(|(n, _)| n.clone()));
        }
        if let Some(why) = &f.allow_insecure {
            allowed.push((f.line, why.clone()));
            let mut s = Linter::new(self.fx, &self.module);
            s.block(&f.body, &mut cx);
            suppressed.extend(s.findings.into_iter().map(|f| (f, why.clone())));
            waived_writes.extend(s.writes);
            return;
        }
        self.block(&f.body, &mut cx);
    }

    /// "request input", or where the stored request data came from.
    fn source(&self, args: &[&Expr], cx: &Cx) -> String {
        let direct = cx.without_stored();
        if args.iter().any(|a| tainted(a, &direct)) {
            return "request input".into();
        }
        match args.iter().find_map(|a| stored_from(a, cx)) {
            Some(f) if f == FROM_DB => "data read from the database (an earlier request may have stored it)".into(),
            Some(f) => format!("request input stored in `state.{f}` (at {})", cx.stored.get(&f).map(String::as_str).unwrap_or("?")),
            None => "request input".into(),
        }
    }

    /// Where a method call can land: the `impl` of the receiver's type, every
    /// implementation of a `dyn Trait` / bounded generic, or (type unknown) the
    /// one user method with that name.
    fn method_targets(&self, recv: &Expr, m: &str, cx: &Cx) -> Vec<String> {
        let fx = self.fx;
        let in_type = |ty: &str| -> Option<String> {
            fx.resolve(&self.module, &format!("{ty}::{m}")).or_else(|| {
                fx.type_traits.get(ty)?.iter().find_map(|tr| fx.resolve(&self.module, &format!("{tr}::{m}")))
            })
        };
        let mut keys: Vec<String> = match self.type_of(recv, cx) {
            Some(t) => match t.strip_prefix("dyn ") {
                Some(tr) => {
                    let mut k: Vec<String> = fx.trait_impls.get(tr).into_iter().flatten().filter_map(|ty| in_type(ty)).collect();
                    k.extend(fx.resolve(&self.module, &format!("{tr}::{m}")));
                    k
                }
                None => in_type(&t).into_iter().collect(),
            },
            None => match fx.methods.get(m).map(Vec::as_slice) {
                Some([key]) => vec![key.clone()],
                _ => vec![],
            },
        };
        keys.sort();
        keys.dedup();
        keys
    }

    fn type_of(&self, e: &Expr, cx: &Cx) -> Option<String> {
        match e {
            Expr::Ident(n) => cx.types.get(n).cloned(),
            Expr::Field(x, f) if matches!(&**x, Expr::Ident(s) if s == "state") => self.fx.state_types.get(f).cloned(),
            Expr::Ref(x, _) | Expr::Try(x) | Expr::Await(x) | Expr::Unary(_, x) => self.type_of(x, cx),
            Expr::Method(x, m, _, _)
                if matches!(
                    m.as_str(),
                    "clone" | "as_ref" | "as_mut" | "unwrap" | "expect" | "lock" | "read" | "write" | "borrow" | "borrow_mut" | "blocking_lock"
                ) =>
            {
                self.type_of(x, cx)
            }
            Expr::StructLit(n, _) => {
                let b = last_segment(n);
                self.fx.user_types.contains(b).then(|| b.to_string())
            }
            // a user fn or `Disk::new(..)`: its declared return type
            Expr::Call(n, _, _) => {
                let key = self.fx.resolve(&self.module, n)?;
                self.ret_type(&key)
            }
            // a user method on a value of known type: its declared return type
            Expr::Method(x, m, _, _) => {
                let key = self.method_targets(x, m, cx).into_iter().next()?;
                self.ret_type(&key)
            }
            _ => None,
        }
    }

    fn ret_type(&self, key: &str) -> Option<String> {
        let info = self.fx.fns.get(key)?;
        match info.f.ret.as_ref()? {
            Type::Named(r, _) if r == "Self" => info.owner.filter(|o| self.fx.user_types.contains(*o)).map(str::to_string),
            t => self.fx.desc(t, &info.bounds),
        }
    }

    /// The element type of a collection expression: `[Disk(..)]`, a typed
    /// variable or `state:` field, `.iter()` / `&` of one.
    fn elem_type(&self, e: &Expr, cx: &Cx) -> Option<String> {
        match e {
            Expr::List(xs) => xs.iter().find_map(|x| self.type_of(x, cx)),
            Expr::Ident(n) => cx.elems.get(n).cloned(),
            Expr::Field(x, f) if matches!(&**x, Expr::Ident(s) if s == "state") => self.fx.state_elems.get(f).cloned(),
            Expr::Ref(x, _) | Expr::Try(x) | Expr::Await(x) => self.elem_type(x, cx),
            Expr::Method(x, m, _, _)
                if matches!(m.as_str(), "iter" | "iter_mut" | "into_iter" | "clone" | "lock" | "read" | "unwrap" | "expect" | "values") =>
            {
                self.elem_type(x, cx)
            }
            // `disks()` / `repo.all()` declared to return `[Disk]`
            Expr::Call(n, _, _) => {
                let key = self.fx.resolve(&self.module, n)?;
                self.ret_elems(&key)
            }
            Expr::Method(x, m, _, _) => {
                let key = self.method_targets(x, m, cx).into_iter().next()?;
                self.ret_elems(&key)
            }
            _ => None,
        }
    }

    fn ret_elems(&self, key: &str) -> Option<String> {
        let info = self.fx.fns.get(key)?;
        self.fx.elem_desc(info.f.ret.as_ref()?, &info.bounds)
    }

    fn push(&mut self, line: usize, rule: &'static str, msg: String, fix: &'static str) {
        self.findings.push(Finding { line, rule, msg, fix });
    }

    /// A sink reached by request data at `line`: reported, and recorded for summaries.
    fn taint_sink(&mut self, line: usize, rule: &'static str, msg: String, sink: &str, fix: &'static str) {
        let what = format!("{sink} at {}", self.fx.locate(line));
        self.sinks.push(Sink { rule, what, fix });
        self.push(line, rule, msg, fix);
    }

    /// A call into a user function: request data in an argument reaches the
    /// sinks that parameter leads to (from the function's summary).
    fn through_call(&mut self, key: &str, shown: &str, recv: Option<&Expr>, args: &[Expr], line: usize, cx: &Cx) {
        // recorded even before the callee has a summary: when it gets one, this caller is redone
        self.consulted.push(key.to_string());
        let Some(sums) = self.fx.sums.get(key) else { return };
        let Some(FnInfo { f, .. }) = self.fx.fns.get(key) else { return };
        let mut positional = 0;
        for a in args {
            let idx = match a {
                Expr::Named(n, _) => f.params.iter().position(|(p, _)| p == n),
                _ => {
                    positional += 1;
                    Some(positional - 1)
                }
            };
            let value = if let Expr::Named(_, v) = a { v } else { a };
            let Some(sum) = idx.and_then(|i| sums.get(i)) else { continue };
            if (sum.sinks.is_empty() && sum.writes.is_empty() && !sum.self_write) || !tainted(value, cx) {
                continue;
            }
            let src = self.source(&[value], cx);
            for s in sum.sinks.clone() {
                let msg = format!("{src} passed to `{shown}(..)` reaches {} unsanitized", s.what);
                self.sinks.push(s.clone());
                self.push(line, s.rule, msg, s.fix);
            }
            self.writes.extend(sum.writes.iter().cloned());
            // the method stored the value in its object: the receiver now holds request data
            if sum.self_write
                && let Some(r) = recv
            {
                match state_root(r, cx) {
                    Some(f) => self.writes.push((f, self.fx.locate(line))),
                    None => self.pending.extend(root_ident(r).map(str::to_string)),
                }
            }
        }
    }

    fn block(&mut self, b: &Block, cx: &mut Cx) {
        for s in b {
            self.stmt(&s.stmt, s.line, cx);
        }
    }

    fn stmt(&mut self, s: &Stmt, line: usize, cx: &mut Cx) {
        self.stmt_inner(s, line, cx);
        // `job.set_path(name)`: from here on `job` holds request data
        for n in std::mem::take(&mut self.pending) {
            if n == "self" {
                self.self_write = true;
            }
            // `tx.send(x)`: what's sent comes out of the receiver
            if let Some(rx) = cx.links.get(&n).cloned() {
                cx.taint.insert(rx);
            }
            cx.taint.insert(n);
        }
    }

    fn stmt_inner(&mut self, s: &Stmt, line: usize, cx: &mut Cx) {
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
            Stmt::Let { name, value, ty, .. } => {
                self.secret_binding(name, value, line);
                self.expr(value, line, cx);
                // `n: i64 = ...` can't hold a path or a script, whatever it was parsed from
                if tainted(value, cx) && ty.as_ref().is_none_or(carries_text) {
                    cx.taint.insert(name.clone());
                    if let Some(f) = stored_from(value, cx).filter(|_| !tainted(value, &cx.without_stored())) {
                        cx.via.insert(name.clone(), f);
                    }
                }
                if is_dynamic(value, cx) {
                    cx.dynamic.insert(name.clone());
                }
                if let Some(t) = ty.as_ref().and_then(|t| self.fx.desc(t, &HashMap::new())).or_else(|| self.type_of(value, cx)) {
                    cx.types.insert(name.clone(), t);
                }
                if let Some(t) = ty.as_ref().and_then(|t| self.fx.elem_desc(t, &HashMap::new())).or_else(|| self.elem_type(value, cx)) {
                    cx.elems.insert(name.clone(), t);
                }
                // `g = state.cache.lock().unwrap()`: writes through `g` land in the field
                if is_guard(value)
                    && let Some(f) = state_root(value, cx)
                {
                    cx.aliases.insert(name.clone(), f);
                }
            }
            Stmt::Assign { target, value, .. } => {
                if let Expr::Field(_, f) = target {
                    self.secret_binding(f, value, line);
                }
                self.expr(target, line, cx);
                self.expr(value, line, cx);
                // `*state.last.lock().unwrap() = name` / `*g = name` / `state.x = name`
                if !matches!(target, Expr::Ident(_))
                    && let Some(f) = state_root(target, cx)
                    && tainted(value, cx)
                {
                    self.writes.push((f, self.fx.locate(line)));
                }
                // `self.path = p`: the object now holds request data
                if root_ident(target) == Some("self") && !matches!(target, Expr::Ident(_)) && tainted(value, cx) {
                    self.self_write = true;
                }
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
                if let (Expr::Call(f, _, _), [(tx, _), (rx, _)]) = (value, names.as_slice())
                    && CHANNEL_CTORS.contains(&last_segment(f))
                {
                    cx.links.insert(tx.clone(), rx.clone());
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
                            if let Some(f) = stored_from(x, cx).filter(|_| !tainted(x, &cx.without_stored())) {
                                inner.via.extend(pattern_binds(p).into_iter().map(|b| (b, f.clone())));
                            }
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
                if let Some(t) = self.elem_type(iter, cx) {
                    inner.types.insert(var.clone(), t);
                }
                if tainted(iter, cx) {
                    inner.taint.insert(var.clone());
                    if let Some(f) = stored_from(iter, cx).filter(|_| !tainted(iter, &cx.without_stored())) {
                        inner.via.insert(var.clone(), f);
                    }
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
                if WRITE_METHODS.contains(&m.as_str()) && args.iter().any(|a| tainted(a, cx)) {
                    if let Some(f) = state_root(recv, cx) {
                        self.writes.push((f, self.fx.locate(line)));
                    } else if let Some(n) = root_ident(recv) {
                        // `self.items.push(p)` / `list.push(name)`: the container holds request data
                        self.pending.push(n.to_string());
                    }
                }
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
                Some(a) if tainted(a, cx) => self.taint_sink(
                    line,
                    "command-injection",
                    format!("the program run by `Command::new` is built from {}", self.source(&[a], cx)),
                    "`Command::new(..)`",
                    FIX_CMD,
                ),
                Some(a) if is_dynamic(a, cx) => self.push(
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
            let src = self.source(&args.iter().collect::<Vec<_>>(), cx);
            self.taint_sink(line, "path-traversal", format!("{src} reaches `{name}(..)` unsanitized"), &format!("`{name}(..)`"), FIX_PATH);
        }
        let custom = &self.fx.custom;
        if let Some((_, why)) = custom.disallow.iter().find(|(p, _)| call_matches(name, p)) {
            let msg = format!("`{name}(..)` is disallowed by parvez.toml: {why}");
            self.push(line, "disallowed-call", msg, FIX_DISALLOW);
        }
        if custom.path_sinks.iter().any(|p| call_matches(name, p)) && args.iter().any(|a| tainted(a, cx)) {
            let src = self.source(&args.iter().collect::<Vec<_>>(), cx);
            self.taint_sink(line, "path-traversal", format!("{src} reaches `{name}(..)` unsanitized"), &format!("`{name}(..)`"), FIX_PATH);
        }
        if self.fx.custom.command_sinks.iter().any(|p| call_matches(name, p)) && args.iter().any(|a| tainted(a, cx)) {
            let src = self.source(&args.iter().collect::<Vec<_>>(), cx);
            self.taint_sink(line, "command-injection", format!("{src} reaches `{name}(..)`"), &format!("`{name}(..)`"), FIX_CMD);
        }
        if self.fx.custom.sql_sinks.iter().any(|p| call_matches(name, p)) && args.iter().any(|a| is_dynamic(a, cx)) {
            self.push(line, "sql-injection", format!("`{name}(..)` receives a string built from interpolation/concatenation"), FIX_SQL);
        }
        if let Some(key) = self.fx.resolve(&self.module, name) {
            self.through_call(&key, name, None, args, line, cx);
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
            let tainted_arg = args.iter().any(|a| tainted(a, cx));
            if tainted_arg {
                let src = self.source(&args.iter().collect::<Vec<_>>(), cx);
                self.taint_sink(line, "command-injection", format!("a shell (`sh -c` style) receives a script built from {src}"), "a shell script (`sh -c`)", FIX_CMD);
            } else if dynamic_arg {
                self.push(line, "command-injection", "a shell (`sh -c` style) receives a dynamic script".into(), FIX_CMD);
            }
        }
        if m == "open" && chain_mentions(recv, "OpenOptions") && args.iter().any(|a| tainted(a, cx)) {
            let src = self.source(&args.iter().collect::<Vec<_>>(), cx);
            self.taint_sink(line, "path-traversal", format!("{src} reaches `OpenOptions::open(..)` unsanitized"), "`OpenOptions::open(..)`", FIX_PATH);
        }
        let custom = &self.fx.custom;
        if let Some((_, why)) = custom.disallow.iter().find(|(p, _)| method_matches(m, p)) {
            let msg = format!("`.{m}(..)` is disallowed by parvez.toml: {why}");
            self.push(line, "disallowed-call", msg, FIX_DISALLOW);
        }
        if custom.path_sinks.iter().any(|p| method_matches(m, p)) && args.iter().any(|a| tainted(a, cx)) {
            let src = self.source(&args.iter().collect::<Vec<_>>(), cx);
            self.taint_sink(line, "path-traversal", format!("{src} reaches `.{m}(..)` unsanitized"), &format!("`.{m}(..)`"), FIX_PATH);
        }
        if self.fx.custom.command_sinks.iter().any(|p| method_matches(m, p)) && args.iter().any(|a| tainted(a, cx)) {
            let src = self.source(&args.iter().collect::<Vec<_>>(), cx);
            self.taint_sink(line, "command-injection", format!("{src} reaches `.{m}(..)`"), &format!("`.{m}(..)`"), FIX_CMD);
        }
        if self.fx.custom.sql_sinks.iter().any(|p| method_matches(m, p)) && args.iter().any(|a| is_dynamic(a, cx)) {
            self.push(line, "sql-injection", format!("`.{m}(..)` receives a string built from interpolation/concatenation"), FIX_SQL);
        }
        // `x.helper(..)` on a user type, a `dyn Trait` or a bounded generic
        for key in self.method_targets(recv, m, cx) {
            let shown = key.rsplit("::").take(2).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join("::");
            self.through_call(&key, &shown, Some(recv), args, line, cx);
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
        Expr::Ident(n) => cx.taint.contains(n) || cx.aliases.get(n).is_some_and(|f| cx.stored.contains_key(f)),
        Expr::Field(x, f) if matches!(&**x, Expr::Ident(s) if s == "state") => cx.stored.contains_key(f),
        Expr::Call(n, _, _) if n == "safe_join" => false,
        Expr::Method(_, m, _, _) if cx.db && DB_READS.contains(&m.as_str()) => true,
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

/// The `state:` field an expression reads or writes through: `state.f`,
/// `state.f.lock().unwrap()`, `*g` / `g.insert(..)` for a guard alias of it.
fn state_root(e: &Expr, cx: &Cx) -> Option<String> {
    match e {
        Expr::Field(x, f) if matches!(&**x, Expr::Ident(s) if s == "state") => Some(f.clone()),
        Expr::Field(x, _) | Expr::Unary(_, x) | Expr::Method(x, ..) | Expr::Index(x, _) | Expr::Try(x) | Expr::Await(x) | Expr::Ref(x, _) => {
            state_root(x, cx)
        }
        Expr::Ident(n) => cx.aliases.get(n).cloned(),
        _ => None,
    }
}

/// The variable at the root of a place or method chain: `job` in `job.items.push(x)`.
fn root_ident(e: &Expr) -> Option<&str> {
    match e {
        Expr::Ident(n) => Some(n),
        Expr::Field(x, _) | Expr::Unary(_, x) | Expr::Method(x, ..) | Expr::Index(x, _) | Expr::Try(x) | Expr::Await(x) | Expr::Ref(x, _) => root_ident(x),
        _ => None,
    }
}

/// `state.f.lock().unwrap()`, `.write().await`, `.borrow_mut()`, `.entry(k)`: a handle, not a copy.
fn is_guard(e: &Expr) -> bool {
    match e {
        Expr::Try(x) | Expr::Await(x) => is_guard(x),
        Expr::Method(x, m, ..) if matches!(m.as_str(), "unwrap" | "expect") => is_guard(x),
        Expr::Method(_, m, ..) => GUARD_METHODS.contains(&m.as_str()),
        _ => false,
    }
}

/// The stored state field an expression's taint comes from, if any.
fn stored_from(e: &Expr, cx: &Cx) -> Option<String> {
    let mut found = None;
    visit_expr(e, &mut |x| {
        if found.is_some() {
            return;
        }
        found = match x {
            Expr::Field(y, f) if matches!(&**y, Expr::Ident(s) if s == "state") && cx.stored.contains_key(f) => Some(f.clone()),
            Expr::Method(_, m, _, _) if cx.db && DB_READS.contains(&m.as_str()) => Some(FROM_DB.to_string()),
            Expr::Ident(n) => cx.via.get(n).cloned().or_else(|| cx.aliases.get(n).filter(|f| cx.stored.contains_key(*f)).cloned()),
            _ => None,
        };
    });
    found
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
            .chain(code.split("self.taint_sink(").skip(1))
            .filter_map(|c| c.split('"').nth(1))
            .filter(|id| id.chars().all(|c| c.is_ascii_lowercase() || c == '-') && id.contains('-'))
            .collect();
        assert!(pushed.len() >= 6, "{pushed:?}");
        for id in pushed {
            let r = rule(id).unwrap_or_else(|| panic!("rule {id} has no catalog entry"));
            assert!(!r.cwe.is_empty() && (!r.asvs.is_empty() || id == "disallowed-call") && r.owasp.contains(":2021"), "{id}");
        }
        assert!(rule("nope").is_none());
    }

    #[test]
    fn taint_follows_calls_into_helpers() {
        let src = "fn load(name: str) -> str!:\n    ret inner(&name)\nfn inner(n: &str) -> str!:\n    p = \"/srv/{n}\"\n    ret std::fs::read_to_string(&p)?\nfn clean(n: &str) -> str!:\n    ret std::fs::read_to_string(safe_join(\"/srv\", n)?)?\nfn run(t: &str):\n    Command::new(\"sh\").arg(\"-c\").arg(t).status()\n@public\nroute GET \"/a/{x}\" (x: str) -> str!:\n    a = load(x)?\n    b = clean(&x)?\n    c = load(\"fixed\")?\n    run(&x)\n    run(path: &x)\n    ret a\n";
        let r = lint(&parse(lex(src).unwrap()).unwrap());
        let got: Vec<(usize, &str, &str)> = r.findings.iter().map(|f| (f.line, f.rule, f.msg.as_str())).collect();
        assert_eq!(
            got,
            [
                (12, "path-traversal", "request input passed to `load(..)` reaches `std::fs::read_to_string(..)` at ?:5 unsanitized"),
                (15, "command-injection", "request input passed to `run(..)` reaches a shell script (`sh -c`) at ?:9 unsanitized"),
            ]
        );
        // helpers alone (no request caller) aren't flagged: CLI tools may take paths
        assert!(rules("fn load(name: str) -> str!:\n    ret std::fs::read_to_string(&name)?\nfn main():\n    load(\"x\")\n").is_empty());
    }

    #[test]
    fn taint_follows_methods_and_recursion() {
        let src = "type S: root: str\nimpl S:\n    fn read(&self, n: &str) -> str!:\n        ret self.go(n, 3)\n    fn go(&self, n: &str, d: i32) -> str!:\n        if d > 0:\n            ret self.go(n, d - 1)\n        ret std::fs::read_to_string(n)?\n@public\nroute GET \"/m/{n}\" (n: str) -> str!:\n    s = S(root: \"/\")\n    ret s.read(&n)?\n";
        assert_eq!(rules(src), [(12, "path-traversal")]);
    }

    #[test]
    fn req_conn_and_guards_are_sources() {
        let src = "fn staff(req) -> str!:\n    who = req.header(\"x-user\").unwrap_or_default()\n    ret std::fs::read_to_string(\"/etc/{who}\")?\nfn helper(req) -> str!:\n    ret std::fs::read_to_string(\"/etc/{who}\")?\n@guard(staff)\nroute GET \"/a\" (req, auth) -> str!:\n    f = req.param(\"f\").unwrap_or_default()\n    ret std::fs::read_to_string(f)?\n@public\nsocket \"/ws\" (conn):\n    msg = conn.recv().await?\n    Command::new(msg).status()\n";
        assert_eq!(rules(src), [(3, "path-traversal"), (9, "path-traversal"), (13, "command-injection")]);
    }

    #[test]
    fn taint_flows_through_lets_and_match() {
        let src = "@public\nroute POST \"/x\" (body: Req) -> str!:\n    n = body.name.trim().to_string()\n    m = match body.kind:\n        k -> k\n    ret std::fs::read_to_string(m)?\n";
        assert_eq!(rules(src), [(6, "path-traversal")]);
    }
}
