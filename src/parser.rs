//! Recursive-descent parser: tokens -> AST.

use crate::ast::*;
use crate::lexer::{Tok, Token, keyword_text, lex_from};
use anyhow::{Result, bail};

/// Top-level items of one file (no whole-program checks; see `validate`).
pub fn parse_items(tokens: Vec<Token>) -> Result<Vec<Item>> {
    let mut p = Parser { toks: tokens, pos: 0, depth: 0 };
    let mut items = Vec::new();
    loop {
        p.skip_newlines();
        let private = matches!(p.peek(), Tok::Ident(k) if k == "priv");
        if private {
            p.next();
            let line = p.line();
            let item = match p.peek() {
                Tok::Fn | Tok::Async => Item::Fn(p.parse_fn()?),
                Tok::Type => Item::Struct(p.parse_struct()?),
                Tok::Enum => Item::Enum(p.parse_enum()?),
                Tok::Ident(k) if k == "trait" => Item::Trait(p.parse_trait()?),
                Tok::Ident(k) if k == "const" => p.parse_const()?,
                t => bail!("line {line}: `priv` goes before `fn`, `type`, `enum`, `trait` or `const`, found {t:?}"),
            };
            items.push(item);
            set_flags(items.last_mut().unwrap(), |f| f.private = true);
            continue;
        }
        match p.peek() {
            Tok::Eof => break,
            Tok::Fn | Tok::Async => items.push(Item::Fn(p.parse_fn()?)),
            Tok::Ident(k) if k == "trait" && matches!(p.peek_at(1), Tok::Ident(_)) => items.push(Item::Trait(p.parse_trait()?)),
            Tok::Ident(k) if k == "every" && matches!(p.peek_at(1), Tok::Int(_)) => items.push(Item::Every(p.parse_every()?)),
            Tok::Type => items.push(Item::Struct(p.parse_struct()?)),
            Tok::Enum => items.push(Item::Enum(p.parse_enum()?)),
            Tok::Impl => items.push(Item::Impl(p.parse_impl()?)),
            Tok::Use => items.push(Item::Use(p.parse_use()?)),
            Tok::Ident(k) if k == "const" => items.push(p.parse_const()?),
            Tok::At if matches!(p.peek_at(1), Tok::Ident(k) if k == "embed_dir") => {
                let line = p.line();
                p.next();
                p.next();
                p.expect(Tok::LParen, "`(`")?;
                let Tok::Str(dir) = p.next() else {
                    bail!("line {line}: expected directory string")
                };
                p.expect(Tok::RParen, "`)`")?;
                p.end_stmt()?;
                items.push(Item::Embed {
                    dir,
                    files: vec![],
                    line,
                });
            }
            Tok::At => {
                let line = p.line();
                let attrs = p.parse_attrs()?;
                let reason = attrs.allow_insecure.clone();
                let only_reason = !attrs.json && attrs.derives.is_empty();
                let test_only = attrs.test_only;
                let plain = only_reason
                    && attrs.guards.is_empty()
                    && attrs.body_error.is_none()
                    && reason.is_none()
                    && attrs.public.is_none();
                // `@test_only` alone may also mark impl / use / import / const / trait / priv items
                let simple = match p.peek().clone() {
                    Tok::Impl if plain && test_only => Some(Item::Impl(p.parse_impl()?)),
                    Tok::Use if plain && test_only => Some(Item::Use(p.parse_use()?)),
                    Tok::Ident(k) if k == "import" && plain && test_only => Some(p.parse_import()?),
                    Tok::Ident(k) if k == "const" && plain && test_only => Some(p.parse_const()?),
                    Tok::Ident(k) if k == "trait" && plain && test_only => Some(Item::Trait(p.parse_trait()?)),
                    Tok::Ident(k) if k == "priv" => {
                        p.next();
                        let mut item = match p.peek() {
                            Tok::Fn | Tok::Async if only_reason => {
                                let mut f = p.parse_fn()?;
                                f.allow_insecure = reason.clone();
                                Item::Fn(f)
                            }
                            Tok::Type if reason.is_none() => {
                                let mut s = p.parse_struct()?;
                                s.attrs = attrs.clone();
                                Item::Struct(s)
                            }
                            Tok::Enum if reason.is_none() => {
                                let mut e = p.parse_enum()?;
                                e.attrs = attrs.clone();
                                Item::Enum(e)
                            }
                            t => bail!("line {line}: `priv` after decorators goes before `fn`, `type` or `enum`, found {t:?}"),
                        };
                        set_flags(&mut item, |f| f.private = true);
                        Some(item)
                    }
                    _ => None,
                };
                if let Some(mut item) = simple {
                    if test_only {
                        set_flags(&mut item, |f| f.test_only = true);
                    }
                    items.push(item);
                    continue;
                }
                if test_only && matches!(p.peek(), Tok::Ident(r) if r == "route" || r == "socket" || r == "state") {
                    bail!("line {line}: @test_only goes on helpers (`fn`, `type`, `enum`, `impl`, `trait`, `const`, `use`, `import`), not on routes or `state:`");
                }
                let is_route = matches!(p.peek(), Tok::Ident(r) if r == "route" || r == "socket");
                let is_socket = matches!(p.peek(), Tok::Ident(r) if r == "socket");
                if attrs.socket != SocketOpts::default() && !is_socket {
                    bail!("line {line}: @protocols / @max_message go on a `socket`");
                }
                if !attrs.guards.is_empty() && !is_route {
                    bail!("line {line}: @guard(...) goes on a `route`");
                }
                if attrs.body_error.is_some() && !is_route {
                    bail!("line {line}: @body_error(...) goes on a `route`");
                }
                if attrs.public.is_some() && !is_route {
                    bail!("line {line}: @public goes on a `route` or `socket`");
                }
                match p.peek().clone() {
                    Tok::Fn | Tok::Async if only_reason => {
                        let mut f = p.parse_fn()?;
                        f.allow_insecure = reason;
                        items.push(Item::Fn(f));
                    }
                    Tok::Ident(r) if (r == "route" || r == "socket") && only_reason => {
                        let mut rt = p.parse_route()?;
                        if let Some(so) = rt.socket.as_mut() {
                            *so = attrs.socket.clone();
                        }
                        rt.allow_insecure = reason;
                        rt.guards = attrs.guards.clone();
                        rt.public = attrs.public.clone();
                        rt.body_error = attrs.body_error.clone();
                        items.push(Item::Route(rt));
                    }
                    Tok::Ident(r) if r == "state" && only_reason => {
                        let mut st = p.parse_state()?;
                        st.allow_insecure = reason;
                        items.push(Item::State(st));
                    }
                    Tok::Type | Tok::Enum if reason.is_some() => {
                        bail!("line {line}: @allow_insecure goes on `fn`, `route` or `state`, not on types")
                    }
                    Tok::Type => {
                        let mut s = p.parse_struct()?;
                        s.attrs = attrs;
                        items.push(Item::Struct(s));
                    }
                    Tok::Enum => {
                        let mut e = p.parse_enum()?;
                        e.attrs = attrs;
                        items.push(Item::Enum(e));
                    }
                    t => bail!(
                        "line {}: @json/@derive apply to `type`/`enum`; @allow_insecure to `fn`/`route`/`state` (found {:?})",
                        p.line(),
                        t
                    ),
                }
                if test_only {
                    set_flags(items.last_mut().unwrap(), |f| f.test_only = true);
                }
            }
            Tok::Ident(r) if r == "route" => items.push(Item::Route(p.parse_route()?)),
            Tok::Ident(r) if r == "socket" && matches!(p.peek_at(1), Tok::Str(_)) => items.push(Item::Route(p.parse_route()?)),
            Tok::Ident(r) if r == "test" && matches!(p.peek_at(1), Tok::Str(_)) => {
                let line = p.line();
                p.next();
                let Tok::Str(name) = p.next() else { unreachable!() };
                if name.trim().is_empty() {
                    bail!("line {line}: a test needs a name: test \"what it checks\":");
                }
                let body = p.parse_block()?;
                items.push(Item::Test(TestDef { name, body, line }));
            }
            Tok::Ident(r) if r == "import" && matches!(p.peek_at(1), Tok::Ident(_)) => items.push(p.parse_import()?),
            Tok::Ident(r) if r == "state" && p.peek_at(1) == &Tok::Colon => items.push(Item::State(p.parse_state()?)),
            t => bail!(
                "line {}: expected `fn`, `type`, `enum`, `trait`, `impl`, `use`, `import`, `route` or `every` at top level, found {:?}",
                p.line(),
                t
            ),
        }
    }
    Ok(items)
}

/// Names a user type can't take: Rust prelude items and the Limen runtime's own types.
fn reserved_type_name(name: &str) -> Option<&'static str> {
    const RUST: &[&str] = &[
        "Result", "Option", "Ok", "Err", "Some", "None", "String", "Vec", "Box", "Self", "Send", "Sync", "Sized",
        "Copy", "Clone", "Default", "Debug", "Display", "Drop", "Fn", "FnMut", "FnOnce", "Eq", "PartialEq", "Ord",
        "PartialOrd", "Hash", "Iterator", "IntoIterator", "Into", "From", "TryFrom", "TryInto", "AsRef", "AsMut",
        "ToString", "ToOwned", "Extend", "Unpin", "Future",
    ];
    const RUNTIME: &[&str] = &[
        "ApiError", "AppError", "Claims", "Conn", "HttpError", "JwksCache", "LoginRequired", "LoginState", "Metrics",
        "NeedsLogin", "Req", "Revocations", "Secret", "ServiceConfig", "SessionConfig", "SessionData", "TestApp",
        "TestRequest", "TestResponse", "WsMsg", "WsOut", "WsSender", "AppState",
    ];
    if RUST.contains(&name) {
        Some("Rust's built-in type of that name is used by the generated code")
    } else if RUNTIME.contains(&name) {
        Some("the Limen runtime defines a type of that name")
    } else {
        None
    }
}

fn type_names(t: &Type, out: &mut Vec<String>) {
    match t {
        Type::Named(n, args) => {
            out.push(n.clone());
            args.iter().for_each(|a| type_names(a, out));
        }
        Type::Ref(x, _) | Type::List(x) | Type::Opt(x) => type_names(x, out),
        Type::Tuple(xs) => xs.iter().for_each(|x| type_names(x, out)),
        Type::Fn(xs, r) => {
            xs.iter().for_each(|x| type_names(x, out));
            if let Some(r) = r {
                type_names(r, out);
            }
        }
    }
}

/// Applies `f` to an item's `priv` / `@test_only` flags; items without flags are rejected earlier.
fn set_flags(item: &mut Item, f: impl FnOnce(&mut Flags)) {
    match item {
        Item::Fn(x) => f(&mut x.flags),
        Item::Struct(x) => f(&mut x.flags),
        Item::Enum(x) => f(&mut x.flags),
        Item::Impl(x) => f(&mut x.flags),
        Item::Trait(x) => f(&mut x.flags),
        Item::Use(x) => f(&mut x.flags),
        Item::Import(x) => f(&mut x.flags),
        Item::Const { flags, .. } => f(flags),
        Item::Embed { .. } | Item::Route(_) | Item::State(_) | Item::Test(_) | Item::Every(_) => {}
    }
}

/// Parses a single-file program and runs the whole-program checks.
#[cfg(test)]
pub fn parse(tokens: Vec<Token>) -> Result<Program> {
    let prog = Program { items: parse_items(tokens)?, modules: vec![], files: vec![] };
    validate(&prog)?;
    Ok(prog)
}

/// Whole-program checks across the main file and every imported module:
/// one `state:` (main file only), guards exist and take only `state`/`req`,
/// `fn main` vs routes, duplicate routes.
pub fn validate(prog: &Program) -> Result<()> {
    let all = prog.all_items();
    let mut embedded = false;
    for (module, item) in &all {
        if let Item::Embed { line, .. } = item {
            if embedded || !module.is_empty() {
                bail!("line {line}: @embed_dir belongs once in the main file");
            }
            embedded = true;
        }
    }
    if embedded
        && let Some(f) = prog.items.iter().find_map(|i| match i {
            Item::Fn(f) if f.name == "main" => Some(f),
            _ => None,
        })
    {
        bail!("line {}: @embed_dir generates the server main", f.line);
    }
    let routes: Vec<(&[String], &RouteDef)> =
        all.iter().filter_map(|(m, i)| if let Item::Route(r) = i { Some((*m, r)) } else { None }).collect();
    let states: Vec<(&[String], &StateDef)> =
        all.iter().filter_map(|(m, i)| if let Item::State(s) = i { Some((*m, s)) } else { None }).collect();
    if let Some((_, s)) = states.iter().find(|(m, _)| !m.is_empty()) {
        bail!("line {}: `state:` belongs in the main file, not in an imported module", s.line);
    }
    if let [_, (_, second), ..] = states.as_slice() {
        bail!("line {}: only one `state:` block is allowed", second.line);
    }
    if let Some((_, s)) = states.first()
        && routes.is_empty()
        && !embedded
    {
        bail!("line {}: `state:` is shared by `route`s, but this program has none", s.line);
    }
    if states.is_empty()
        && let Some((_, r)) = routes.iter().find(|(_, r)| r.state)
    {
        bail!("line {}: route uses `state` but there is no `state:` block", r.line);
    }
    // fns by qualified name: `verify` (main file), `auth::verify` (module auth)
    let fns: Vec<(String, &FnDef)> = all
        .iter()
        .filter_map(|(m, i)| match i {
            Item::Fn(f) if m.is_empty() => Some((f.name.clone(), f)),
            Item::Fn(f) => Some((format!("{}::{}", m.join("::"), f.name), f)),
            _ => None,
        })
        .collect();
    if let Some((_, f)) = all.iter().find_map(|(m, i)| match i {
        Item::Fn(f) if !m.is_empty() && f.name == "main" => Some((m, f)),
        _ => None,
    }) {
        bail!("line {}: `fn main` belongs in the main file, not in an imported module", f.line);
    }
    // Type names the generated Rust relies on: a user `type Result` would shadow
    // std's Result in every signature Limen emits (rustc then reports E0107 deep
    // inside runtime code). Reject them here with a rename hint.
    for (_, item) in &all {
        let (kind, name, line) = match item {
            Item::Struct(s) => ("type", &s.name, s.line),
            Item::Enum(e) => ("enum", &e.name, e.line),
            Item::Trait(t) => ("trait", &t.name, t.line),
            _ => continue,
        };
        if let Some(why) = reserved_type_name(name) {
            bail!("line {line}: {kind} `{name}` is reserved ({why}); rename it, e.g. `{name}Info` or a name from your domain");
        }
    }
    // A Secret never leaves as JSON: a route can't return a type that holds one.
    let mut secret_types: Vec<&str> = Vec::new();
    for (_, item) in &all {
        if let Item::Struct(st) = item {
            let mut names = Vec::new();
            st.fields.iter().for_each(|(_, t)| type_names(t, &mut names));
            if names.iter().any(|n| n == "Secret") {
                secret_types.push(&st.name);
            }
        }
    }
    for (_, r) in &routes {
        let mut names = Vec::new();
        if let Some(t) = &r.ret {
            type_names(t, &mut names);
        }
        if let Some(n) = names.iter().find(|n| n.as_str() == "Secret" || secret_types.contains(&n.rsplit("::").next().unwrap_or(n))) {
            bail!(
                "line {}: {} {} returns `{n}`, which holds a Secret; secrets never leave as JSON. Return a type without it",
                r.line,
                r.method,
                r.path
            );
        }
    }
    // Deny-by-default access control (OWASP A01): every endpoint states who may call it.
    for (_, r) in &routes {
        let kind = if r.page { "page" } else if r.socket.is_some() { "socket" } else { "route" };
        match (r.guards.is_empty(), &r.public) {
            (true, None) => bail!(
                "line {}: {kind} {} {} has no access policy. Add @guard(fn) to require sign-in or another check, \
                 or @public(\"why anyone may call it\") to serve it to everyone (Limen denies by default)",
                r.line,
                r.method,
                r.path
            ),
            (false, Some(_)) => bail!(
                "line {}: {kind} {} {} has both @guard and @public; keep one",
                r.line,
                r.method,
                r.path
            ),
            _ => {}
        }
    }
    let app_state = Type::Ref(Box::new(Type::Named("AppState".into(), vec![])), false);
    let req_ty = Type::Ref(Box::new(Type::Named("Req".into(), vec![])), false);
    for (m, r) in &routes {
        if r.auth && r.guards.is_empty() {
            bail!("line {}: route takes `auth` but has no @guard(fn) to produce it", r.line);
        }
        for g in &r.guards {
            let local = format!("{}::{g}", m.join("::"));
            let found = fns.iter().find(|(n, _)| (!m.is_empty() && *n == local) || n == g);
            let Some((_, f)) = found else {
                bail!("line {}: @guard({g}): no `fn {g}` in this program", r.line);
            };
            for (pname, pty) in &f.params {
                let ok = (pname == "state" && *pty == app_state) || (pname == "req" && *pty == req_ty);
                if !ok {
                    bail!("line {}: guard `{g}` may only take untyped `state` and/or `req` params, found `{pname}`", f.line);
                }
                if pname == "state" && states.is_empty() {
                    bail!("line {}: guard `{g}` takes `state` but there is no `state:` block", f.line);
                }
            }
        }
    }
    let test_mods = prog.test_only_modules();
    for (m, item) in &all {
        let in_test_mod = test_mods.iter().any(|t| m.starts_with(t));
        match item {
            Item::Every(e) => {
                if routes.is_empty() && !embedded {
                    bail!("line {}: `every` workers run inside a service; this program has no `route`s", e.line);
                }
                if e.state && states.is_empty() {
                    bail!("line {}: worker takes `state` but there is no `state:` block", e.line);
                }
                if in_test_mod {
                    bail!("line {}: a @test_only module can't start `every` workers", e.line);
                }
            }
            Item::Route(r) if in_test_mod => {
                bail!("line {}: a @test_only module can't define routes (they would vanish from `limen build`)", r.line);
            }
            _ => {}
        }
    }
    for (_, r) in &routes {
        for g in &r.guards {
            if let Some((_, f)) = fns.iter().find(|(n, _)| n == g || n.ends_with(&format!("::{g}"))) {
                if f.flags.test_only {
                    bail!("line {}: @guard({g}) is @test_only, so production builds would have no guard", r.line);
                }
            }
        }
    }
    if let Some((_, r)) = routes.first() {
        if let Some((_, f)) = fns.iter().find(|(n, _)| n == "main") {
            bail!(
                "line {}: this file has `route`s (first at line {}), so Limen generates `main` (the HTTP server); rename or remove `fn main`",
                f.line,
                r.line
            );
        }
        for (k, (_, a)) in routes.iter().enumerate() {
            if let Some((_, b)) = routes[..k].iter().find(|(_, b)| b.method == a.method && b.path == a.path) {
                bail!("line {}: duplicate route {} {} (already at line {})", a.line, a.method, a.path, b.line);
            }
        }
    }
    Ok(())
}

pub(crate) fn page_binding(source: &str, line: usize) -> Result<Located> {
    let mut p = Parser {
        toks: lex_from(source, line)?,
        pos: 0,
        depth: 0,
    };
    let stmt = p.parse_stmt()?;
    p.skip_newlines();
    if !matches!(&stmt.stmt, Stmt::Let { name, .. } if name != "__masud") || p.peek() != &Tok::Eof {
        bail!("line {line}: expected a page binding, e.g. let user = models::user()");
    }
    Ok(stmt)
}

/// A Masud control line (`for x in xs:`, `if c:`, `elif c:`, `else:`) parsed with the
/// normal statement parser over a placeholder body, which the template replaces.
pub(crate) fn page_control(source: &str, line: usize) -> Result<Located> {
    let head = source.trim_start_matches("el");
    let mut p = Parser {
        toks: lex_from(&format!("{head}\n    __masud_placeholder = 0"), line)?,
        pos: 0,
        depth: 0,
    };
    let stmt = p.parse_stmt()?;
    p.skip_newlines();
    let ok = match &stmt.stmt {
        Stmt::For { .. } => !source.starts_with("el"),
        Stmt::If { branches, els } => branches.len() == 1 && els.is_none(),
        _ => false,
    };
    if !ok || p.peek() != &Tok::Eof {
        bail!("line {line}: expected `for x in items:`, `if cond:`, `elif cond:` or `else:`");
    }
    Ok(stmt)
}

struct Parser {
    toks: Vec<Token>,
    pos: usize,
    /// current nesting (expressions, blocks, types, patterns)
    depth: usize,
}

/// Deeper input is rejected with an error instead of overflowing the stack
/// (the compiler runs untrusted code, e.g. snippets sent to `limen mcp`).
const MAX_DEPTH: usize = 256;
/// Longest `a + b + c ...` chain: it becomes an equally deep expression tree.
const MAX_CHAIN: usize = 2_000;

impl Parser {
    /// Runs `f` one nesting level deeper, failing cleanly past MAX_DEPTH.
    fn nest<T>(&mut self, f: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        if self.depth >= MAX_DEPTH {
            bail!("line {}: nesting too deep (more than {MAX_DEPTH} levels)", self.line());
        }
        self.depth += 1;
        let r = f(self);
        self.depth -= 1;
        r
    }

    fn peek(&self) -> &Tok {
        &self.toks[self.pos].tok
    }
    fn peek_at(&self, n: usize) -> &Tok {
        let i = (self.pos + n).min(self.toks.len() - 1);
        &self.toks[i].tok
    }
    fn line(&self) -> usize {
        self.toks[self.pos].line
    }
    fn next(&mut self) -> Tok {
        let t = self.toks[self.pos].tok.clone();
        if self.pos < self.toks.len() - 1 {
            self.pos += 1;
        }
        t
    }
    fn eat(&mut self, t: &Tok) -> bool {
        if self.peek() == t {
            self.next();
            true
        } else {
            false
        }
    }
    fn expect(&mut self, t: Tok, what: &str) -> Result<()> {
        if self.peek() == &t {
            self.next();
            Ok(())
        } else {
            bail!("line {}: expected {what}, found {:?}", self.line(), self.peek())
        }
    }
    fn ident(&mut self, what: &str) -> Result<String> {
        match self.peek().clone() {
            Tok::Ident(s) => {
                self.next();
                Ok(s)
            }
            t => bail!("line {}: expected {what}, found {:?}", self.line(), t),
        }
    }
    /// An identifier, or a keyword used as a field name (`e.type`, `Event(type: ..)`).
    fn field_name(&mut self, what: &str) -> Result<String> {
        if let Some(k) = keyword_text(self.peek()) {
            self.next();
            return Ok(k.to_string());
        }
        self.ident(what)
    }

    /// `name:` (identifier or keyword followed by a colon) starts here.
    fn at_named(&self) -> bool {
        (matches!(self.peek(), Tok::Ident(_)) || keyword_text(self.peek()).is_some())
            && self.peek_at(1) == &Tok::Colon
    }

    fn skip_newlines(&mut self) {
        while self.eat(&Tok::Newline) {}
    }
    fn end_stmt(&mut self) -> Result<()> {
        // Block-bodied expressions (`match`, closures, `spawn:`) end with their
        // own DEDENT, or with the NEWLINE of an inline body.
        if self.pos > 0 && matches!(self.toks[self.pos - 1].tok, Tok::Dedent | Tok::Newline) {
            return Ok(());
        }
        match self.peek() {
            Tok::Newline => {
                self.next();
                Ok(())
            }
            Tok::Eof | Tok::Dedent => Ok(()),
            t => bail!("line {}: expected end of line, found {:?}", self.line(), t),
        }
    }

    // ---------- items ----------

    fn parse_struct(&mut self) -> Result<StructDef> {
        let line = self.line();
        self.expect(Tok::Type, "`type`")?;
        let name = self.ident("type name")?;
        let generics = self.parse_generics()?;
        self.expect(Tok::Colon, "`:` after type name")?;
        let mut fields = Vec::new();
        let mut field_attrs = Vec::new();
        let block = self.eat(&Tok::Newline);
        if block {
            self.skip_newlines();
            self.expect(Tok::Indent, "indented field list")?;
        }
        loop {
            self.skip_newlines_if(block);
            if block && self.eat(&Tok::Dedent) {
                break;
            }
            let fa = self.parse_field_attrs()?;
            let f = self.field_name("field name")?;
            self.expect(Tok::Colon, "`:` after field name")?;
            let ty = self.parse_type()?;
            if fa.omit_none && !matches!(ty, Type::Opt(_)) {
                bail!("line {}: @omit_none needs an optional field (`{f}: T?`)", self.line());
            }
            fields.push((f, ty));
            field_attrs.push(fa);
            if self.eat(&Tok::Comma) {
                continue;
            }
            if !block {
                self.end_stmt()?;
                break;
            }
            if !matches!(self.peek(), Tok::Dedent) {
                self.expect(Tok::Newline, "newline or `,` between fields")?;
            }
        }
        if fields.is_empty() {
            bail!("line {}: type `{name}` has no fields", self.line());
        }
        Ok(StructDef { name, generics, fields, field_attrs, line, attrs: Attrs::default(), flags: Flags::default() })
    }

    /// `@rename("x")`, `@default`, `@omit_none` lines before a field.
    fn parse_field_attrs(&mut self) -> Result<FieldAttrs> {
        let mut fa = FieldAttrs::default();
        while self.eat(&Tok::At) {
            let line = self.line();
            match self.ident("field decorator")?.as_str() {
                "rename" => {
                    self.expect(Tok::LParen, "`(\"json_name\")`")?;
                    fa.rename = match self.next() {
                        Tok::Str(s) if !s.is_empty() => Some(s),
                        _ => bail!("line {line}: @rename needs a JSON name string"),
                    };
                    self.expect(Tok::RParen, "`)`")?;
                }
                "default" => fa.default = true,
                "omit_none" => fa.omit_none = true,
                other => bail!("line {line}: unknown field decorator `@{other}` (known: @rename(\"x\"), @default, @omit_none)"),
            }
            self.expect(Tok::Newline, "newline after field decorator (put the field on the next line)")?;
            self.skip_newlines();
        }
        Ok(fa)
    }

    /// `enum Name: A, B(str)` or an indented list of variants.
    fn parse_enum(&mut self) -> Result<EnumDef> {
        let line = self.line();
        self.expect(Tok::Enum, "`enum`")?;
        let name = self.ident("enum name")?;
        let generics = self.parse_generics()?;
        self.expect(Tok::Colon, "`:` after enum name")?;
        let block = self.eat(&Tok::Newline);
        if block {
            self.skip_newlines();
            self.expect(Tok::Indent, "indented variant list")?;
        }
        let mut variants = Vec::new();
        loop {
            self.skip_newlines_if(block);
            if block && self.eat(&Tok::Dedent) {
                break;
            }
            variants.push(self.parse_variant()?);
            if self.eat(&Tok::Comma) {
                continue;
            }
            if !block {
                self.end_stmt()?;
                break;
            }
            if !matches!(self.peek(), Tok::Dedent) {
                self.expect(Tok::Newline, "newline or `,` between variants")?;
            }
        }
        if variants.is_empty() {
            bail!("line {line}: enum `{name}` has no variants");
        }
        Ok(EnumDef { name, generics, variants, line, attrs: Attrs::default(), flags: Flags::default() })
    }

    fn parse_variant(&mut self) -> Result<Variant> {
        let name = self.ident("variant name")?;
        if !self.eat(&Tok::LParen) {
            return Ok(Variant { name, data: VariantData::Unit });
        }
        let named = self.at_named();
        let mut types = Vec::new();
        let mut fields = Vec::new();
        while !self.eat(&Tok::RParen) {
            if named {
                let f = self.field_name("field name (use `name: type` for every field)")?;
                self.expect(Tok::Colon, "`:`")?;
                fields.push((f, self.parse_type()?));
            } else {
                types.push(self.parse_type()?);
            }
            if !self.eat(&Tok::Comma) {
                self.expect(Tok::RParen, "`,` or `)`")?;
                break;
            }
        }
        let data = if named { VariantData::Named(fields) } else { VariantData::Tuple(types) };
        Ok(Variant { name, data })
    }

    /// `impl Type:` followed by an indented list of `fn`s.
    fn parse_impl(&mut self) -> Result<ImplDef> {
        let line = self.line();
        self.expect(Tok::Impl, "`impl`")?;
        let generics = if self.peek() == &Tok::Lt { Some(self.parse_generics()?) } else { None };
        let first = self.parse_type()?;
        let (trait_, target) = if self.eat(&Tok::For) { (Some(first), self.parse_type()?) } else { (None, first) };
        let Type::Named(ty, ty_args) = target else {
            bail!("line {line}: `impl` needs a named type, e.g. `impl Page<T>:` or `impl Store for Mem:`");
        };
        self.expect(Tok::Colon, "`:` after impl type")?;
        self.expect(Tok::Newline, "newline after `impl Type:`")?;
        self.skip_newlines();
        self.expect(Tok::Indent, "indented `fn` definitions")?;
        let mut methods = Vec::new();
        loop {
            self.skip_newlines();
            match self.peek() {
                Tok::Dedent => {
                    self.next();
                    break;
                }
                Tok::Eof => break,
                Tok::Fn | Tok::Async => methods.push(self.parse_fn()?),
                Tok::Ident(k) if k == "priv" => {
                    self.next();
                    let mut f = self.parse_fn()?;
                    f.flags.private = true;
                    methods.push(f);
                }
                Tok::At => {
                    let attrs = self.parse_attrs()?;
                    if attrs.json || !attrs.derives.is_empty() || attrs.test_only {
                        bail!("line {}: only @allow_insecure can decorate a method", self.line());
                    }
                    let mut f = self.parse_fn()?;
                    f.allow_insecure = attrs.allow_insecure;
                    methods.push(f);
                }
                t => bail!("line {}: only `fn` is allowed inside `impl`, found {:?}", self.line(), t),
            }
        }
        if trait_.is_some() && methods.iter().any(|m| m.flags.private) {
            bail!("line {line}: trait methods can't be `priv`");
        }
        Ok(ImplDef { ty, ty_args, generics, trait_, methods, line, flags: Flags::default() })
    }

    fn skip_newlines_if(&mut self, yes: bool) {
        if yes {
            self.skip_newlines();
        }
    }

    fn parse_fn(&mut self) -> Result<FnDef> {
        self.parse_fn_sig(false)
    }

    /// `fn`; with `sig_ok`, a signature line without a body (trait methods).
    fn parse_fn_sig(&mut self, sig_ok: bool) -> Result<FnDef> {
        let line = self.line();
        let is_async = self.eat(&Tok::Async);
        self.expect(Tok::Fn, "`fn` (after `async`)")?;
        let name = self.ident("function name")?;
        let generics = self.parse_generics()?;
        self.expect(Tok::LParen, "`(`")?;
        let receiver = self.parse_receiver()?;
        if receiver.is_some() && !self.eat(&Tok::Comma) && self.peek() != &Tok::RParen {
            bail!("line {}: expected `,` or `)` after self", self.line());
        }
        let mut params = Vec::new();
        while !self.eat(&Tok::RParen) {
            let p = self.ident("parameter name")?;
            // untyped `state` / `req`: the service's &AppState / &Req (for guards and helpers)
            if (p == "state" || p == "req") && self.peek() != &Tok::Colon {
                let ty = if p == "state" { "AppState" } else { "Req" };
                params.push((p, Type::Ref(Box::new(Type::Named(ty.into(), vec![])), false)));
            } else {
                self.expect(Tok::Colon, "`:` after parameter name (types are required)")?;
                params.push((p, self.parse_type()?));
            }
            if !self.eat(&Tok::Comma) {
                self.expect(Tok::RParen, "`,` or `)`")?;
                break;
            }
        }
        let ret = if self.eat(&Tok::Arrow) { Some(self.parse_type()?) } else { None };
        let fallible = self.eat(&Tok::Bang);
        if sig_ok && matches!(self.peek(), Tok::Newline | Tok::Dedent | Tok::Eof) {
            self.end_stmt()?;
            return Ok(FnDef { name, generics, is_async, receiver, params, ret, fallible, line, has_body: false, ..Default::default() });
        }
        let body = self.parse_block()?;
        Ok(FnDef { name, generics, is_async, receiver, params, ret, fallible, body, line, has_body: true, ..Default::default() })
    }

    /// `<T, U: Clone + Store>` after a type or function name (empty when absent).
    fn parse_generics(&mut self) -> Result<Vec<Generic>> {
        let mut out = Vec::new();
        if !self.eat(&Tok::Lt) {
            return Ok(out);
        }
        loop {
            let name = self.ident("generic parameter name, e.g. `T`")?;
            let mut bounds = Vec::new();
            if self.eat(&Tok::Colon) {
                loop {
                    bounds.push(self.parse_type()?);
                    if !self.eat(&Tok::Plus) {
                        break;
                    }
                }
            }
            if out.iter().any(|g: &Generic| g.name == name) {
                bail!("line {}: generic parameter `{name}` is declared twice", self.line());
            }
            out.push(Generic { name, bounds });
            if !self.eat(&Tok::Comma) {
                self.expect(Tok::Gt, "`,` or `>` after generic parameters")?;
                break;
            }
        }
        Ok(out)
    }

    /// `trait Name[<T>]:` NEWLINE INDENT (fn signature | fn with default body)+ DEDENT
    fn parse_trait(&mut self) -> Result<TraitDef> {
        let line = self.line();
        self.next(); // `trait`
        let name = self.ident("trait name")?;
        let generics = self.parse_generics()?;
        self.expect(Tok::Colon, "`:` after trait name")?;
        self.expect(Tok::Newline, "newline after `trait Name:`")?;
        self.skip_newlines();
        self.expect(Tok::Indent, "indented method signatures")?;
        let mut methods = Vec::new();
        loop {
            self.skip_newlines();
            match self.peek() {
                Tok::Dedent => {
                    self.next();
                    break;
                }
                Tok::Eof => break,
                Tok::Fn | Tok::Async => {
                    let f = self.parse_fn_sig(true)?;
                    if f.is_async && f.has_body {
                        bail!("line {}: an async trait method can't have a default body yet; declare the signature and implement it in each `impl`", f.line);
                    }
                    methods.push(f);
                }
                t => bail!("line {}: only `fn` signatures are allowed inside `trait`, found {:?}", self.line(), t),
            }
        }
        if methods.is_empty() {
            bail!("line {line}: trait `{name}` has no methods");
        }
        Ok(TraitDef { name, generics, methods, line, flags: Flags::default() })
    }

    /// `every 30s (state):` / `every 1h:` -- units ms, s, m, h, d
    fn parse_every(&mut self) -> Result<EveryDef> {
        let line = self.line();
        self.next(); // `every`
        let Tok::Int(n) = self.next() else { unreachable!() };
        let unit = self.ident("a time unit right after the number: ms, s, m, h or d (e.g. `every 30s:`)")?;
        let factor: u64 = match unit.as_str() {
            "ms" => 1,
            "s" => 1_000,
            "m" => 60_000,
            "h" => 3_600_000,
            "d" => 86_400_000,
            u => bail!("line {line}: unknown time unit `{u}` (use ms, s, m, h or d)"),
        };
        let count: u64 = n.replace('_', "").parse().map_err(|_| anyhow::anyhow!("line {line}: period too large"))?;
        let period_ms = count.checked_mul(factor).filter(|ms| *ms >= 100).ok_or_else(|| anyhow::anyhow!("line {line}: the period must be at least 100ms"))?;
        let mut state = false;
        if self.eat(&Tok::LParen) {
            match self.next() {
                Tok::Ident(s) if s == "state" => state = true,
                t => bail!("line {line}: a worker takes only `(state)`, found {t:?}"),
            }
            self.expect(Tok::RParen, "`)`")?;
        }
        let body = self.parse_block()?;
        Ok(EveryDef { period_ms, label: format!("{n}{unit}"), state, body, line })
    }

    fn parse_const(&mut self) -> Result<Item> {
        let line = self.line();
        self.next(); // `const`
        let name = self.ident("constant name")?;
        self.expect(Tok::Colon, "constant type")?;
        let ty = self.parse_type()?;
        self.expect(Tok::Assign, "`=`")?;
        let value = self.parse_expr()?;
        self.end_stmt()?;
        Ok(Item::Const { name, ty, value, line, flags: Flags::default() })
    }

    fn parse_import(&mut self) -> Result<Item> {
        let line = self.line();
        self.next(); // `import`
        let mut path = vec![self.ident("module name after `import`")?];
        while self.eat(&Tok::Dot) {
            path.push(self.ident("module name after `.`")?);
        }
        self.end_stmt()?;
        Ok(Item::Import(ImportDef { path, line, flags: Flags::default() }))
    }

    /// `@json` / `@derive(Hash, Eq)` lines before a `type` or `enum`.
    fn parse_attrs(&mut self) -> Result<Attrs> {
        let mut attrs = Attrs::default();
        while self.eat(&Tok::At) {
            let line = self.line();
            match self.ident("decorator name after `@`")?.as_str() {
                "json" => attrs.json = true,
                "test_only" => attrs.test_only = true,
                "public" => {
                    // `@public` or `@public("why anyone may call this")`
                    let mut why = String::new();
                    if self.eat(&Tok::LParen) {
                        why = match self.next() {
                            Tok::Str(s) if !s.trim().is_empty() => s,
                            _ => bail!("line {line}: @public(\"reason\") needs a non-empty reason, or write plain @public"),
                        };
                        self.expect(Tok::RParen, "`)`")?;
                    }
                    attrs.public = Some(why);
                }
                "protocols" => {
                    self.expect(Tok::LParen, "`(\"proto\", ...)` after @protocols")?;
                    while !self.eat(&Tok::RParen) {
                        match self.next() {
                            Tok::Str(s) => attrs.socket.protocols.push(s),
                            _ => bail!("line {line}: @protocols takes strings, e.g. @protocols(\"ro.v1\")"),
                        }
                        if !self.eat(&Tok::Comma) {
                            self.expect(Tok::RParen, "`,` or `)`")?;
                            break;
                        }
                    }
                }
                "max_message" => {
                    self.expect(Tok::LParen, "`(bytes)` after @max_message")?;
                    attrs.socket.max_message = match self.next() {
                        Tok::Int(n) => Some(n),
                        _ => bail!("line {line}: @max_message takes a byte count, e.g. @max_message(8388608)"),
                    };
                    self.expect(Tok::RParen, "`)`")?;
                }
                "body_error" => {
                    // @body_error(400, code: "bad_request", "invalid JSON body")
                    self.expect(Tok::LParen, "`(status, code: \"..\", \"message\")`")?;
                    let status = match self.next() {
                        Tok::Int(n) => n,
                        _ => bail!("line {line}: @body_error needs an HTTP status first, e.g. @body_error(400, \"invalid JSON body\")"),
                    };
                    self.expect(Tok::Comma, "`,`")?;
                    let mut code = None;
                    if matches!(self.peek(), Tok::Ident(c) if c == "code") && self.peek_at(1) == &Tok::Colon {
                        self.next();
                        self.next();
                        code = match self.next() {
                            Tok::Str(s) => Some(s),
                            _ => bail!("line {line}: `code:` needs a string"),
                        };
                        self.expect(Tok::Comma, "`,`")?;
                    }
                    let message = match self.next() {
                        Tok::Str(s) => s,
                        _ => bail!("line {line}: @body_error needs a message string"),
                    };
                    self.expect(Tok::RParen, "`)`")?;
                    attrs.body_error = Some(BodyError { status, code, message });
                }
                "guard" => {
                    self.expect(Tok::LParen, "`(fn_name)` after @guard")?;
                    let mut g = self.ident("guard function name")?;
                    while self.eat(&Tok::PathSep) {
                        g = format!("{g}::{}", self.ident("path segment")?);
                    }
                    attrs.guards.push(g);
                    self.expect(Tok::RParen, "`)`")?;
                }
                "allow_insecure" => {
                    self.expect(Tok::LParen, "`(\"reason\")` after @allow_insecure")?;
                    let reason = match self.next() {
                        Tok::Str(s) if !s.trim().is_empty() => s,
                        _ => bail!("line {line}: @allow_insecure needs a non-empty reason string, e.g. @allow_insecure(\"admin-only tool\")"),
                    };
                    self.expect(Tok::RParen, "`)`")?;
                    attrs.allow_insecure = Some(reason);
                }
                "derive" => {
                    self.expect(Tok::LParen, "`(` after @derive")?;
                    while !self.eat(&Tok::RParen) {
                        let mut d = self.ident("trait name")?;
                        while self.eat(&Tok::PathSep) {
                            d = format!("{d}::{}", self.ident("path segment")?);
                        }
                        attrs.derives.push(d);
                        if !self.eat(&Tok::Comma) {
                            self.expect(Tok::RParen, "`,` or `)`")?;
                            break;
                        }
                    }
                }
                other => bail!("line {line}: unknown decorator `@{other}` (known: @json, @derive(...), @guard(fn), @public, @body_error(..), @allow_insecure(\"reason\"), @test_only)"),
            }
            self.expect(Tok::Newline, "newline after decorator")?;
            self.skip_newlines();
        }
        Ok(attrs)
    }

    /// `use a::b::{C, D}`, `use reqwest`, `use x::*`, `use a::b as c`
    fn parse_use(&mut self) -> Result<UseDef> {
        let line = self.line();
        self.expect(Tok::Use, "`use`")?;
        let mut path = self.ident("crate or module name after `use`")?;
        while self.eat(&Tok::PathSep) {
            match self.next() {
                Tok::Ident(s) => path = format!("{path}::{s}"),
                Tok::Star => path.push_str("::*"),
                Tok::LBrace => {
                    let mut names = Vec::new();
                    while !self.eat(&Tok::RBrace) {
                        let mut n = self.ident("name in `{...}`")?;
                        while self.eat(&Tok::PathSep) {
                            n = format!("{n}::{}", self.ident("path segment")?);
                        }
                        names.push(n);
                        if !self.eat(&Tok::Comma) {
                            self.expect(Tok::RBrace, "`,` or `}`")?;
                            break;
                        }
                    }
                    path = format!("{path}::{{{}}}", names.join(", "));
                    break;
                }
                t => bail!("line {line}: expected a name, `*` or `{{` after `::`, found {t:?}"),
            }
        }
        if matches!(self.peek(), Tok::Ident(a) if a == "as") {
            self.next();
            path = format!("{path} as {}", self.ident("alias after `as`")?);
        }
        self.end_stmt()?;
        Ok(UseDef { path, line, flags: Flags::default() })
    }

    /// `route METHOD "/path/{p}" [(params)] [-> T][!]:` block, or
    /// `socket "/path/{p}" [(params)]:` (a WebSocket; GET upgrade)
    fn parse_route(&mut self) -> Result<RouteDef> {
        let line = self.line();
        let is_socket = matches!(self.next(), Tok::Ident(k) if k == "socket");
        let method = if is_socket { "GET".to_string() } else { self.ident("HTTP method (GET, POST, PUT, PATCH, DELETE)")? };
        if !["GET", "POST", "PUT", "PATCH", "DELETE"].contains(&method.as_str()) {
            bail!("line {line}: unknown HTTP method `{method}` (use GET, POST, PUT, PATCH or DELETE)");
        }
        let path = match self.next() {
            Tok::Str(s) if s.starts_with('/') => s,
            t => bail!("line {line}: expected a path string starting with `/`, found {t:?}"),
        };
        let mut params = Vec::new();
        let (mut state, mut req, mut auth, mut conn) = (false, false, false, false);
        if self.eat(&Tok::LParen) {
            while !self.eat(&Tok::RParen) {
                let p = self.ident("parameter name")?;
                if p == "state" && self.peek() != &Tok::Colon {
                    state = true;
                } else if p == "req" && self.peek() != &Tok::Colon {
                    req = true;
                } else if p == "auth" && self.peek() != &Tok::Colon {
                    auth = true;
                } else if p == "conn" && self.peek() != &Tok::Colon {
                    if !is_socket {
                        bail!("line {line}: `conn` is the WebSocket connection; it only exists in a `socket`");
                    }
                    conn = true;
                } else {
                    self.expect(Tok::Colon, "`:` after parameter name (types are required)")?;
                    params.push((p, self.parse_type()?));
                }
                if !self.eat(&Tok::Comma) {
                    self.expect(Tok::RParen, "`,` or `)`")?;
                    break;
                }
            }
        }
        let ret = if self.eat(&Tok::Arrow) { Some(self.parse_type()?) } else { None };
        let fallible = self.eat(&Tok::Bang) || is_socket;
        if is_socket && (ret.is_some() || !conn) {
            bail!("line {line}: a socket takes `conn` and returns nothing: socket \"{path}\" (conn):");
        }
        let holes = path_params(&path);
        for (p, _) in &params {
            if !holes.contains(p) && p != "body" && p != "query" {
                bail!(
                    "line {line}: route param `{p}` must be a path param (`{{{p}}}` in the path), `body` (JSON body), `query` (query string), or untyped `state` / `req` / `auth`"
                );
            }
        }
        for h in &holes {
            if !params.iter().any(|(p, _)| p == h) {
                bail!("line {line}: path param `{{{h}}}` needs a typed parameter, e.g. ({h}: str)");
            }
        }
        let body = self.parse_block()?;
        Ok(RouteDef {
            page: false,
            method,
            path,
            params,
            state,
            req,
            auth,
            socket: if is_socket { Some(SocketOpts::default()) } else { None },
            conn,
            guards: vec![],
            public: None,
            body_error: None,
            ret,
            fallible,
            body,
            line,
            allow_insecure: None,
        })
    }

    /// `state:` NEWLINE INDENT (`name: Type = expr` NEWLINE)+ DEDENT
    fn parse_state(&mut self) -> Result<StateDef> {
        let line = self.line();
        self.next(); // `state`
        self.expect(Tok::Colon, "`:` after state")?;
        self.expect(Tok::Newline, "newline after `state:`")?;
        self.skip_newlines();
        self.expect(Tok::Indent, "indented `name: Type = value` lines")?;
        let mut fields = Vec::new();
        let mut tasks = Vec::new();
        loop {
            self.skip_newlines();
            if self.eat(&Tok::Dedent) || self.peek() == &Tok::Eof {
                break;
            }
            let fline = self.line();
            if matches!(self.peek(), Tok::Ident(s) if s == "spawn") {
                tasks.push((self.parse_expr()?, fline));
                self.end_stmt()?;
                continue;
            }
            let name = self.field_name("state field name")?;
            self.expect(Tok::Colon, "`:` and a type (state fields need `name: Type = value`)")?;
            let ty = self.parse_type()?;
            self.expect(Tok::Assign, "`=` and an initial value")?;
            let value = self.parse_expr()?;
            self.end_stmt()?;
            fields.push((name, ty, value, fline));
        }
        if fields.is_empty() {
            bail!("line {line}: `state:` has no fields");
        }
        Ok(StateDef { fields, tasks, line, allow_insecure: None })
    }

    /// `&self`, `&~self`, `self`, `~self` as the first parameter.
    fn parse_receiver(&mut self) -> Result<Option<Receiver>> {
        let is_self = |t: &Tok| matches!(t, Tok::Ident(s) if s == "self");
        let (r, n) = match (self.peek(), self.peek_at(1), self.peek_at(2)) {
            (Tok::Amp, Tok::Tilde, t) if is_self(t) => (Receiver::RefMut, 3),
            (Tok::Amp, t, _) if is_self(t) => (Receiver::Ref, 2),
            (Tok::Tilde, t, _) if is_self(t) => (Receiver::MutValue, 2),
            (t, next, _) if is_self(t) && next != &Tok::Colon => (Receiver::Value, 1),
            _ => return Ok(None),
        };
        for _ in 0..n {
            self.next();
        }
        Ok(Some(r))
    }

    fn parse_type(&mut self) -> Result<Type> {
        self.nest(|p| p.parse_type_inner())
    }

    fn parse_type_inner(&mut self) -> Result<Type> {
        let mut ty = match self.peek().clone() {
            Tok::Amp => {
                self.next();
                let m = self.eat(&Tok::Tilde);
                Type::Ref(Box::new(self.parse_type()?), m)
            }
            Tok::LBracket => {
                self.next();
                let inner = self.parse_type()?;
                self.expect(Tok::RBracket, "`]`")?;
                Type::List(Box::new(inner))
            }
            Tok::LParen => {
                self.next();
                Type::Tuple(self.type_list(Tok::RParen)?)
            }
            Tok::Fn => {
                self.next();
                self.expect(Tok::LParen, "`(` after `fn` in a function type")?;
                let args = self.type_list(Tok::RParen)?;
                let ret = if self.eat(&Tok::Arrow) { Some(Box::new(self.parse_type()?)) } else { None };
                Type::Fn(args, ret)
            }
            Tok::Ident(d) if d == "dyn" && matches!(self.peek_at(1), Tok::Ident(_)) => {
                self.next();
                match self.parse_type()? {
                    Type::Named(n, args) => Type::Named(format!("dyn {n}"), args),
                    _ => bail!("line {}: `dyn` needs a trait name, e.g. `Arc<dyn Store>`", self.line()),
                }
            }
            Tok::Ident(_) => {
                let mut name = self.ident("type")?;
                while self.eat(&Tok::PathSep) {
                    name = format!("{name}::{}", self.ident("type path segment")?);
                }
                let mut args = Vec::new();
                if self.eat(&Tok::Lt) {
                    loop {
                        args.push(self.parse_type()?);
                        if !self.eat(&Tok::Comma) {
                            break;
                        }
                    }
                    self.expect(Tok::Gt, "`>`")?;
                }
                Type::Named(name, args)
            }
            t => bail!("line {}: expected a type, found {:?}", self.line(), t),
        };
        while self.eat(&Tok::Question) {
            ty = Type::Opt(Box::new(ty));
        }
        Ok(ty)
    }

    /// Comma-separated types up to (and consuming) `close`.
    fn type_list(&mut self, close: Tok) -> Result<Vec<Type>> {
        let mut ts = Vec::new();
        while !self.eat(&close) {
            ts.push(self.parse_type()?);
            if !self.eat(&Tok::Comma) {
                self.expect(close.clone(), "`,` or closing bracket")?;
                break;
            }
        }
        Ok(ts)
    }

    // ---------- statements ----------

    /// `:` followed by either an indented block or a single inline statement.
    fn parse_block(&mut self) -> Result<Block> {
        self.nest(|p| p.parse_block_inner())
    }

    fn parse_block_inner(&mut self) -> Result<Block> {
        self.expect(Tok::Colon, "`:` to open a block")?;
        self.parse_body()
    }

    /// An indented block (after NEWLINE) or a single inline statement.
    fn parse_body(&mut self) -> Result<Block> {
        if !self.eat(&Tok::Newline) {
            return Ok(vec![self.parse_stmt()?]);
        }
        self.skip_newlines();
        self.expect(Tok::Indent, "an indented block")?;
        let mut body = Vec::new();
        loop {
            self.skip_newlines();
            match self.peek() {
                Tok::Dedent => {
                    self.next();
                    break;
                }
                Tok::Eof => break,
                _ => body.push(self.parse_stmt()?),
            }
        }
        Ok(body)
    }

    fn parse_stmt(&mut self) -> Result<Located> {
        let line = self.line();
        let stmt = self.parse_stmt_kind()?;
        Ok(Located { line, stmt })
    }

    fn parse_stmt_kind(&mut self) -> Result<Stmt> {
        match self.peek().clone() {
            Tok::If => {
                if self.toks[self.pos..]
                    .iter()
                    .take_while(|t| t.tok != Tok::Newline)
                    .any(|t| t.tok == Tok::Else)
                {
                    let start = self.pos;
                    if let Ok(value) = self.parse_expr() {
                        self.end_stmt()?;
                        return Ok(Stmt::Expr(value));
                    }
                    self.pos = start;
                }
                self.parse_if()
            }
            Tok::For => {
                self.next();
                let var = if self.eat(&Tok::LParen) {
                    let mut names = Vec::new();
                    while !self.eat(&Tok::RParen) {
                        names.push(self.ident("name in `for (a, b) in ...`")?);
                        if !self.eat(&Tok::Comma) {
                            self.expect(Tok::RParen, "`,` or `)`")?;
                            break;
                        }
                    }
                    format!("({})", names.join(", "))
                } else {
                    self.ident("loop variable")?
                };
                self.expect(Tok::In, "`in`")?;
                let iter = self.parse_expr()?;
                let body = self.parse_block()?;
                Ok(Stmt::For { var, iter, body })
            }
            Tok::Ident(l) if l == "loop" && self.peek_at(1) == &Tok::Colon => {
                self.next();
                Ok(Stmt::Loop(self.parse_block()?))
            }
            Tok::While => {
                self.next();
                let cond = self.parse_expr()?;
                let body = self.parse_block()?;
                Ok(Stmt::While { cond, body })
            }
            Tok::Ret => {
                self.next();
                let e = if matches!(self.peek(), Tok::Newline | Tok::Dedent | Tok::Eof) {
                    None
                } else {
                    Some(self.parse_expr()?)
                };
                self.end_stmt()?;
                Ok(Stmt::Ret(e))
            }
            Tok::Break => {
                self.next();
                self.end_stmt()?;
                Ok(Stmt::Break)
            }
            Tok::Continue => {
                self.next();
                self.end_stmt()?;
                Ok(Stmt::Continue)
            }
            // `a, ~b = expr`
            Tok::Ident(_) | Tok::Tilde
                if self.peek_at(1) == &Tok::Comma
                    || (self.peek() == &Tok::Tilde && self.peek_at(2) == &Tok::Comma) =>
            {
                let mut names = Vec::new();
                loop {
                    let m = self.eat(&Tok::Tilde);
                    names.push((self.ident("name in `a, b = ...`")?, m));
                    if !self.eat(&Tok::Comma) {
                        break;
                    }
                }
                self.expect(Tok::Assign, "`=` after `a, b`")?;
                let value = self.parse_expr()?;
                self.end_stmt()?;
                Ok(Stmt::LetTuple { names, value })
            }
            Tok::Tilde => {
                self.next();
                let name = self.ident("variable name after `~`")?;
                let ty = if self.eat(&Tok::Colon) { Some(self.parse_type()?) } else { None };
                self.expect(Tok::Assign, "`=`")?;
                let value = self.parse_expr()?;
                self.end_stmt()?;
                Ok(Stmt::Let { name, mutable: true, ty, value })
            }
            Tok::Ident(name) if self.peek_at(1) == &Tok::Colon => {
                self.next();
                self.next();
                let ty = Some(self.parse_type()?);
                self.expect(Tok::Assign, "`=`")?;
                let value = self.parse_expr()?;
                self.end_stmt()?;
                Ok(Stmt::Let { name, mutable: false, ty, value })
            }
            _ => {
                let target = self.parse_expr()?;
                let op = match self.peek() {
                    Tok::Assign => "=",
                    Tok::PlusEq => "+=",
                    Tok::MinusEq => "-=",
                    Tok::StarEq => "*=",
                    Tok::SlashEq => "/=",
                    Tok::PercentEq => "%=",
                    _ => {
                        self.end_stmt()?;
                        return Ok(Stmt::Expr(target));
                    }
                };
                self.next();
                let value = self.parse_expr()?;
                self.end_stmt()?;
                Ok(match target {
                    Expr::Ident(name) if op == "=" && !name.contains("::") => {
                        Stmt::Let { name, mutable: false, ty: None, value }
                    }
                    Expr::Ident(_) | Expr::Field(..) | Expr::Index(..) | Expr::Unary(..) => {
                        Stmt::Assign { target, op: op.into(), value }
                    }
                    _ => bail!("line {}: invalid assignment target", self.line()),
                })
            }
        }
    }

    fn condition(&mut self) -> Result<Expr> {
        if matches!(self.peek(), Tok::Ident(s) if s == "let") {
            let start = self.pos;
            self.next();
            if let Ok(pat) = self.parse_pat()
                && self.eat(&Tok::Assign)
            {
                return Ok(Expr::LetPat(Box::new(pat), Box::new(self.parse_expr()?)));
            }
            self.pos = start;
        }
        self.parse_expr()
    }

    fn parse_if(&mut self) -> Result<Stmt> {
        self.expect(Tok::If, "`if`")?;
        let mut branches = vec![(self.condition()?, self.parse_block()?)];
        let mut els = None;
        loop {
            self.skip_newlines();
            if self.eat(&Tok::Elif) {
                branches.push((self.condition()?, self.parse_block()?));
            } else if self.eat(&Tok::Else) {
                if self.eat(&Tok::If) {
                    branches.push((self.condition()?, self.parse_block()?));
                    continue;
                }
                els = Some(self.parse_block()?);
                break;
            } else {
                break;
            }
        }
        Ok(Stmt::If { branches, els })
    }

    // ---------- expressions ----------

    pub fn parse_expr(&mut self) -> Result<Expr> {
        let e = self.parse_bin(0)?;
        // `expr catch [err]: handler` -- lowest precedence, ends the expression
        let is_catch = matches!(self.peek(), Tok::Ident(c) if c == "catch")
            && (self.peek_at(1) == &Tok::Colon || (matches!(self.peek_at(1), Tok::Ident(_)) && self.peek_at(2) == &Tok::Colon));
        if !is_catch {
            return Ok(e);
        }
        self.next();
        let binding = if let Tok::Ident(b) = self.peek().clone() {
            self.next();
            Some(b)
        } else {
            None
        };
        let handler = self.parse_block()?;
        Ok(Expr::Catch { expr: Box::new(e), binding, handler: Box::new(ClosureBody::Block(handler)) })
    }

    fn bin_op(&self) -> Option<(u8, &'static str)> {
        Some(match self.peek() {
            Tok::Or => (1, "||"),
            Tok::And => (2, "&&"),
            Tok::Eq => (3, "=="),
            Tok::Ne => (3, "!="),
            Tok::Lt => (3, "<"),
            Tok::Gt => (3, ">"),
            Tok::Le => (3, "<="),
            Tok::Ge => (3, ">="),
            Tok::DotDot => (4, ".."),
            Tok::DotDotEq => (4, "..="),
            Tok::Plus => (5, "+"),
            Tok::Minus => (5, "-"),
            Tok::Star => (6, "*"),
            Tok::Slash => (6, "/"),
            Tok::Percent => (6, "%"),
            _ => return None,
        })
    }

    fn parse_bin(&mut self, min: u8) -> Result<Expr> {
        let mut left = self.parse_unary()?;
        let mut chain = 0;
        while let Some((prec, op)) = self.bin_op() {
            if prec < min {
                break;
            }
            chain += 1;
            if chain > MAX_CHAIN {
                bail!("line {}: expression too long (more than {MAX_CHAIN} operators in a row); split it up", self.line());
            }
            self.next();
            let right = self.parse_bin(prec + 1)?;
            left = match op {
                ".." | "..=" => Expr::Range(Box::new(left), Box::new(right), op == "..="),
                _ => Expr::Binary(Box::new(left), op.into(), Box::new(right)),
            };
        }
        Ok(left)
    }

    fn parse_unary(&mut self) -> Result<Expr> {
        self.nest(|p| p.parse_unary_inner())
    }

    fn parse_unary_inner(&mut self) -> Result<Expr> {
        match self.peek() {
            Tok::Minus => {
                self.next();
                Ok(Expr::Unary("-".into(), Box::new(self.parse_unary()?)))
            }
            Tok::Not => {
                self.next();
                Ok(Expr::Unary("!".into(), Box::new(self.parse_unary()?)))
            }
            Tok::Star => {
                self.next();
                Ok(Expr::Unary("*".into(), Box::new(self.parse_unary()?)))
            }
            Tok::Amp => {
                self.next();
                let m = self.eat(&Tok::Tilde);
                Ok(Expr::Ref(Box::new(self.parse_unary()?), m))
            }
            _ => {
                let mut e = self.parse_postfix()?;
                // `e as T` binds tighter than binary operators
                while matches!(self.peek(), Tok::Ident(a) if a == "as") {
                    self.next();
                    e = Expr::Cast(Box::new(e), self.parse_type()?);
                }
                Ok(e)
            }
        }
    }

    fn parse_postfix(&mut self) -> Result<Expr> {
        let mut e = self.parse_primary()?;
        loop {
            match self.peek() {
                Tok::LParen => {
                    let Expr::Ident(name) = e else {
                        bail!("line {}: only named functions can be called", self.line());
                    };
                    e = self.parse_call(name, Vec::new())?;
                }
                // `f<T>(..)` / `f::<T>(..)`
                Tok::Lt | Tok::PathSep if matches!(e, Expr::Ident(_)) => {
                    let Some(generics) = self.try_generics() else { return Ok(e) };
                    let Expr::Ident(name) = e else { unreachable!() };
                    e = self.parse_call(name, generics)?;
                }
                Tok::Dot => {
                    self.next();
                    let name = match self.next() {
                        Tok::Ident(s) | Tok::Int(s) => s,
                        t if keyword_text(&t).is_some() => keyword_text(&t).unwrap().to_string(),
                        t => bail!("line {}: expected field or method after `.`, found {:?}", self.line(), t),
                    };
                    if name == "await" {
                        e = Expr::Await(Box::new(e));
                        continue;
                    }
                    let generics = self.try_generics().unwrap_or_default();
                    if self.eat(&Tok::LParen) {
                        let args = self.parse_args()?;
                        e = Expr::Method(Box::new(e), name, generics, args);
                    } else if !generics.is_empty() {
                        bail!("line {}: expected `(` after generic arguments", self.line());
                    } else {
                        e = Expr::Field(Box::new(e), name);
                    }
                }
                Tok::LBracket => {
                    self.next();
                    let idx = self.parse_expr()?;
                    self.expect(Tok::RBracket, "`]`")?;
                    e = Expr::Index(Box::new(e), Box::new(idx));
                }
                Tok::Question => {
                    self.next();
                    e = Expr::Try(Box::new(e));
                }
                _ => return Ok(e),
            }
        }
    }

    /// Speculatively parse `<T, U>` (or `::<T>`) followed by `(`; restores on failure.
    fn try_generics(&mut self) -> Option<Vec<Type>> {
        let start = self.pos;
        if self.peek() == &Tok::PathSep && self.peek_at(1) == &Tok::Lt {
            self.next();
        }
        if !self.eat(&Tok::Lt) {
            self.pos = start;
            return None;
        }
        let mut types = Vec::new();
        loop {
            match self.parse_type() {
                Ok(t) => types.push(t),
                Err(_) => {
                    self.pos = start;
                    return None;
                }
            }
            if !self.eat(&Tok::Comma) {
                break;
            }
        }
        if !self.eat(&Tok::Gt) || self.peek() != &Tok::LParen {
            self.pos = start;
            return None;
        }
        Some(types)
    }

    /// `|a, b: i32| expr` or `|x| -> T:` + block (at the `|`).
    fn parse_closure(&mut self, is_move: bool) -> Result<Expr> {
        self.expect(Tok::Pipe, "`|`")?;
        let mut params = Vec::new();
        while !self.eat(&Tok::Pipe) {
            let p = self.ident("closure parameter")?;
            let ty = if self.eat(&Tok::Colon) { Some(self.parse_type()?) } else { None };
            params.push((p, ty));
            if !self.eat(&Tok::Comma) {
                self.expect(Tok::Pipe, "`,` or `|`")?;
                break;
            }
        }
        let ret = if self.eat(&Tok::Arrow) { Some(self.parse_type()?) } else { None };
        let body = if self.peek() == &Tok::Colon {
            ClosureBody::Block(self.parse_block()?)
        } else if ret.is_some() {
            bail!("line {}: a closure with `-> T` needs a `:` block body", self.line());
        } else {
            ClosureBody::Expr(self.parse_expr()?)
        };
        Ok(Expr::Closure { params, ret, body: Box::new(body), is_move })
    }

    fn parse_args(&mut self) -> Result<Vec<Expr>> {
        let mut args = Vec::new();
        while !self.eat(&Tok::RParen) {
            if self.at_named() {
                let n = self.field_name("argument name")?;
                self.next(); // `:`
                args.push(Expr::Named(n, Box::new(self.parse_expr()?)));
            } else {
                args.push(self.parse_expr()?);
            }
            if !self.eat(&Tok::Comma) {
                self.expect(Tok::RParen, "`,` or `)`")?;
                break;
            }
        }
        Ok(args)
    }

    /// `f(a, b)` is a call; `User(name: x, age: y)` is a struct literal.
    fn parse_call(&mut self, name: String, generics: Vec<Type>) -> Result<Expr> {
        self.expect(Tok::LParen, "`(`")?;
        if !self.at_named() {
            return Ok(Expr::Call(name, generics, self.parse_args()?));
        }
        let mut fields = Vec::new();
        while !self.eat(&Tok::RParen) {
            let f = self.field_name("field name (struct literals use `name: value` for every field)")?;
            self.expect(Tok::Colon, "`:`")?;
            fields.push((f, self.parse_expr()?));
            if !self.eat(&Tok::Comma) {
                self.expect(Tok::RParen, "`,` or `)`")?;
                break;
            }
        }
        Ok(Expr::StructLit(name, fields))
    }

    fn parse_primary(&mut self) -> Result<Expr> {
        let line = self.line();
        Ok(match self.next() {
            Tok::Int(s) => Expr::Int(s),
            Tok::Char(c) => Expr::Char(c),
            Tok::Float(s) => Expr::Float(s),
            Tok::True => Expr::Bool(true),
            Tok::False => Expr::Bool(false),
            Tok::Str(s) => Expr::Str(parse_str(&s, line)?),
            Tok::Ident(m) if m == "move" && self.peek() == &Tok::Pipe => self.parse_closure(true)?,
            Tok::Ident(sp) if sp == "spawn" && self.peek() == &Tok::Colon => {
                Expr::Spawn(Box::new(ClosureBody::Block(self.parse_block()?)))
            }
            Tok::Ident(sp) if sp == "spawn" && matches!(self.peek(), Tok::Ident(_)) => {
                Expr::Spawn(Box::new(ClosureBody::Expr(self.parse_expr()?)))
            }
            Tok::Ident(mut s) => {
                while self.peek() == &Tok::PathSep && self.peek_at(1) != &Tok::Lt {
                    self.next();
                    s = format!("{s}::{}", self.ident("path segment")?);
                }
                Expr::Ident(s)
            }
            Tok::LParen => {
                if self.eat(&Tok::RParen) {
                    return Ok(Expr::Tuple(vec![]));
                }
                let e = self.parse_expr()?;
                if self.eat(&Tok::Comma) {
                    let mut items = vec![e];
                    while !self.eat(&Tok::RParen) {
                        items.push(self.parse_expr()?);
                        if !self.eat(&Tok::Comma) {
                            self.expect(Tok::RParen, "`,` or `)`")?;
                            break;
                        }
                    }
                    return Ok(Expr::Tuple(items));
                }
                self.expect(Tok::RParen, "`)`")?;
                e
            }
            Tok::Pipe => {
                self.pos -= 1;
                self.parse_closure(false)?
            }
            Tok::If => {
                let c = self.parse_expr()?;
                self.expect(Tok::Colon, "`:` after condition")?;
                let a = self.parse_expr()?;
                self.expect(Tok::Else, "`else` in conditional expression")?;
                self.expect(Tok::Colon, "`:` after else")?;
                Expr::If(Box::new(c), Box::new(a), Box::new(self.parse_expr()?))
            }
            Tok::Match => self.parse_match(line)?,
            Tok::LBrace => {
                // `{"key": value, ...}` map literal (newlines allowed inside the braces)
                let mut kvs = Vec::new();
                while !self.eat(&Tok::RBrace) {
                    let k = self.parse_bin(0)?;
                    self.expect(Tok::Colon, "`:` between a map key and its value")?;
                    let v = self.parse_expr()?;
                    kvs.push((k, v));
                    if !self.eat(&Tok::Comma) {
                        self.expect(Tok::RBrace, "`,` or `}` in a map literal")?;
                        break;
                    }
                }
                Expr::Map(kvs)
            }
            Tok::LBracket => {
                let mut items = Vec::new();
                while !self.eat(&Tok::RBracket) {
                    items.push(self.parse_expr()?);
                    if !self.eat(&Tok::Comma) {
                        self.expect(Tok::RBracket, "`,` or `]`")?;
                        break;
                    }
                }
                Expr::List(items)
            }
            t => bail!("line {line}: expected an expression, found {t:?}"),
        })
    }
}

impl Parser {
    /// `match e:` NEWLINE INDENT (`pat [if guard] -> stmt | block`)+ DEDENT
    fn parse_match(&mut self, line: usize) -> Result<Expr> {
        let scrut = self.parse_expr()?;
        self.expect(Tok::Colon, "`:` after match expression")?;
        self.expect(Tok::Newline, "newline after `match ...:` (arms go on indented lines)")?;
        self.skip_newlines();
        self.expect(Tok::Indent, "indented match arms")?;
        let mut arms = Vec::new();
        loop {
            self.skip_newlines();
            match self.peek() {
                Tok::Dedent => {
                    self.next();
                    break;
                }
                Tok::Eof => break,
                _ => {}
            }
            let line = self.line();
            let pat = self.parse_pat()?;
            let guard = if self.eat(&Tok::If) { Some(self.parse_expr()?) } else { None };
            self.expect(Tok::Arrow, "`->` after match pattern")?;
            let body = self.parse_body()?;
            arms.push(Arm { pat, guard, body, line });
        }
        if arms.is_empty() {
            bail!("line {line}: `match` has no arms");
        }
        Ok(Expr::Match(Box::new(scrut), arms))
    }

    fn parse_pat(&mut self) -> Result<Pat> {
        let first = self.parse_pat1()?;
        if self.peek() != &Tok::Pipe {
            return Ok(first);
        }
        let mut alts = vec![first];
        while self.eat(&Tok::Pipe) {
            alts.push(self.parse_pat1()?);
        }
        Ok(Pat::Or(alts))
    }

    fn parse_pat1(&mut self) -> Result<Pat> {
        self.nest(|p| p.parse_pat1_inner())
    }

    fn parse_pat1_inner(&mut self) -> Result<Pat> {
        match self.peek().clone() {
            Tok::Ident(mut name) => {
                self.next();
                while self.eat(&Tok::PathSep) {
                    name = format!("{name}::{}", self.ident("path segment")?);
                }
                if name == "_" {
                    return Ok(Pat::Wild);
                }
                if self.eat(&Tok::LParen) {
                    let mut subs = Vec::new();
                    while !self.eat(&Tok::RParen) {
                        let field = if self.at_named() {
                            let f = self.field_name("field name")?;
                            self.next();
                            Some(f)
                        } else {
                            None
                        };
                        subs.push((field, self.parse_pat()?));
                        if !self.eat(&Tok::Comma) {
                            self.expect(Tok::RParen, "`,` or `)` in pattern")?;
                            break;
                        }
                    }
                    return Ok(Pat::Variant(name, Some(subs)));
                }
                let upper = name.starts_with(|c: char| c.is_uppercase());
                Ok(if upper || name.contains("::") { Pat::Variant(name, None) } else { Pat::Bind(name) })
            }
            Tok::DotDot => {
                self.next();
                Ok(Pat::Rest)
            }
            Tok::Minus | Tok::Int(_) | Tok::Float(_) | Tok::Str(_) | Tok::True | Tok::False => {
                let lo = self.pat_lit()?;
                let inc = match self.peek() {
                    Tok::DotDot => false,
                    Tok::DotDotEq => true,
                    _ => return Ok(Pat::Lit(lo)),
                };
                self.next();
                Ok(Pat::Range(lo, self.pat_lit()?, inc))
            }
            t => bail!("line {}: expected a pattern, found {:?}", self.line(), t),
        }
    }

    fn pat_lit(&mut self) -> Result<Expr> {
        if self.eat(&Tok::Minus) {
            return Ok(Expr::Unary("-".into(), Box::new(self.pat_lit()?)));
        }
        match self.peek() {
            Tok::Int(_) | Tok::Float(_) | Tok::Str(_) | Tok::True | Tok::False => self.parse_primary(),
            t => bail!("line {}: expected a literal in pattern, found {:?}", self.line(), t),
        }
    }
}

/// `{name}` placeholders in a route path, in order.
pub fn path_params(path: &str) -> Vec<String> {
    path.split('{').skip(1).filter_map(|s| s.split_once('}').map(|(n, _)| n.to_string())).collect()
}

/// Split a raw string body into literal text and `{expr[:spec]}` holes.
/// `{{` / `}}` are literal braces.
pub(crate) fn parse_str(raw: &str, line: usize) -> Result<Vec<StrPart>> {
    let c: Vec<char> = raw.chars().collect();
    let mut parts = Vec::new();
    let mut lit = String::new();
    let mut i = 0;
    while i < c.len() {
        match c[i] {
            // `\u{1F600}` is a Rust escape, not an interpolation
            '\\' if c.get(i + 1) == Some(&'u') && c.get(i + 2) == Some(&'{') => {
                while i < c.len() {
                    lit.push(c[i]);
                    i += 1;
                    if c[i - 1] == '}' {
                        break;
                    }
                }
            }
            '\\' if i + 1 < c.len() => {
                lit.push(c[i]);
                lit.push(c[i + 1]);
                i += 2;
            }
            '{' if c.get(i + 1) == Some(&'{') => {
                lit.push('{');
                i += 2;
            }
            '}' if c.get(i + 1) == Some(&'}') => {
                lit.push('}');
                i += 2;
            }
            '{' => {
                let mut depth = 1;
                let mut j = i + 1;
                while j < c.len() {
                    match c[j] {
                        '{' => depth += 1,
                        '}' => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        _ => {}
                    }
                    j += 1;
                }
                if j >= c.len() {
                    bail!("line {line}: unclosed `{{` in string (use `{{{{` for a literal brace)");
                }
                let inner: String = c[i + 1..j].iter().collect();
                let full = |src: &str| -> Result<Expr> {
                    let mut p = Parser {
                        toks: lex_from(src, line)?,
                        pos: 0,
                        depth: 0,
                    };
                    let e = p.parse_expr()?;
                    p.skip_newlines();
                    if p.peek() != &Tok::Eof {
                        bail!("line {line}: invalid interpolation {{{inner}}}");
                    }
                    Ok(e)
                };
                let (src, spec) = split_spec(&inner);
                if src.trim().is_empty() {
                    bail!("line {line}: empty `{{}}` in string; write `{{expr}}`");
                }
                let (e, spec) = if spec.is_some()
                    && let Ok(e) = full(&inner)
                {
                    (e, None)
                } else {
                    (full(src)?, spec)
                };
                if !lit.is_empty() {
                    parts.push(StrPart::Lit(std::mem::take(&mut lit)));
                }
                parts.push(StrPart::Interp(e, spec.map(str::to_string)));
                i = j + 1;
            }
            ch => {
                lit.push(ch);
                i += 1;
            }
        }
    }
    if !lit.is_empty() || parts.is_empty() {
        parts.push(StrPart::Lit(lit));
    }
    Ok(parts)
}

/// `x:?` -> ("x", Some("?")); `a::b` is a path, not a spec.
fn split_spec(s: &str) -> (&str, Option<&str>) {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b':' {
            if b.get(i + 1) == Some(&b':') {
                i += 2;
                continue;
            }
            return (&s[..i], Some(&s[i + 1..]));
        }
        i += 1;
    }
    (s, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::lex;

    fn prog(s: &str) -> Program {
        parse(lex(s).unwrap()).unwrap()
    }

    #[test]
    fn struct_inline_and_block() {
        let p = prog("type A: x: i32, y: str\ntype B:\n    a: [u8]\n    b: i32?\n");
        let Item::Struct(a) = &p.items[0] else { panic!() };
        assert_eq!(a.fields.len(), 2);
        let Item::Struct(b) = &p.items[1] else { panic!() };
        assert_eq!(b.fields[0].1, Type::List(Box::new(Type::Named("u8".into(), vec![]))));
        assert_eq!(b.fields[1].1, Type::Opt(Box::new(Type::Named("i32".into(), vec![]))));
    }

    #[test]
    fn fn_signature() {
        let p = prog("fn f(a: i32, b: &str) -> i32!:\n    ret a\nfn main()!:\n    f(1, \"x\")?\n");
        let Item::Fn(f) = &p.items[0] else { panic!() };
        assert!(f.fallible && f.ret.is_some() && f.params.len() == 2);
        let Item::Fn(m) = &p.items[1] else { panic!() };
        assert!(m.fallible && m.ret.is_none());
        assert!(matches!(m.body[0].stmt, Stmt::Expr(Expr::Try(_))));
    }

    #[test]
    fn precedence() {
        let p = prog("fn f():\n    x = 1 + 2 * 3 == 7 and not y\n");
        let Item::Fn(f) = &p.items[0] else { panic!() };
        let Stmt::Let { value: Expr::Binary(l, op, _), .. } = &f.body[0].stmt else { panic!() };
        assert_eq!(op, "&&");
        assert!(matches!(**l, Expr::Binary(_, ref o, _) if o == "=="));
    }

    #[test]
    fn if_elif_else_and_inline_block() {
        let p = prog("fn f(x: i32):\n    if x > 1: ret\n    elif x < 0:\n        ret\n    else: ret\n");
        let Item::Fn(f) = &p.items[0] else { panic!() };
        let Stmt::If { branches, els } = &f.body[0].stmt else { panic!() };
        assert_eq!(branches.len(), 2);
        assert!(els.is_some());
    }

    #[test]
    fn interpolation() {
        let parts = parse_str("hi {u.name}, {n:?} {{x}}", 1).unwrap();
        assert_eq!(parts.len(), 5);
        assert!(matches!(&parts[1], StrPart::Interp(Expr::Field(..), None)));
        assert!(matches!(&parts[3], StrPart::Interp(Expr::Ident(_), Some(s)) if s == "?"));
        assert_eq!(parts[4], StrPart::Lit(" {x}".into()));
    }

    #[test]
    fn struct_literal_vs_call() {
        let p = prog("fn f():\n    u = User(name: \"a\", age: 1)\n    g(1, 2)\n");
        let Item::Fn(f) = &p.items[0] else { panic!() };
        assert!(matches!(&f.body[0].stmt, Stmt::Let { value: Expr::StructLit(..), .. }));
        assert!(matches!(&f.body[1].stmt, Stmt::Expr(Expr::Call(..))));
    }

    #[test]
    fn statement_lines() {
        let p = prog("fn f():\n    a = 1\n\n    # c\n    b = 2\n");
        let Item::Fn(f) = &p.items[0] else { panic!() };
        assert_eq!((f.line, f.body[0].line, f.body[1].line), (1, 2, 5));
    }

    #[test]
    fn enums() {
        let p = prog("enum S:\n    Active\n    Pending(str)\n    Failed(code: i32, reason: str)\nenum C: R, G, B\n");
        let Item::Enum(e) = &p.items[0] else { panic!() };
        assert_eq!(e.variants[0].data, VariantData::Unit);
        assert!(matches!(&e.variants[1].data, VariantData::Tuple(t) if t.len() == 1));
        assert!(matches!(&e.variants[2].data, VariantData::Named(f) if f[1].0 == "reason"));
        let Item::Enum(c) = &p.items[1] else { panic!() };
        assert_eq!(c.variants.len(), 3);
    }

    #[test]
    fn impl_receivers() {
        let p = prog("impl U:\n    fn a(&self) -> str:\n        ret self.n\n    fn b(&~self, x: i32):\n        self.v += x\n    fn c(self):\n        ret\n    fn new() -> Self:\n        ret Self(v: 0)\n");
        let Item::Impl(i) = &p.items[0] else { panic!() };
        let r: Vec<_> = i.methods.iter().map(|m| m.receiver).collect();
        assert_eq!(r, [Some(Receiver::Ref), Some(Receiver::RefMut), Some(Receiver::Value), None]);
        assert_eq!(i.methods[1].params.len(), 1);
    }

    #[test]
    fn match_arms_and_patterns() {
        let p = prog("fn f():\n    x = match s:\n        Active | Idle -> 1\n        Failed(c, reason: r) if c > 0 -> 2\n        1..=9 -> 3\n        _ ->\n            print(\"x\")\n            4\n    y = 5\n");
        let Item::Fn(f) = &p.items[0] else { panic!() };
        let Stmt::Let { value: Expr::Match(_, arms), .. } = &f.body[0].stmt else { panic!() };
        assert_eq!(arms.len(), 4);
        assert!(matches!(&arms[0].pat, Pat::Or(a) if a.len() == 2));
        assert!(arms[1].guard.is_some());
        assert!(matches!(&arms[1].pat, Pat::Variant(n, Some(s)) if n == "Failed" && s[1].0.as_deref() == Some("reason")));
        assert!(matches!(&arms[2].pat, Pat::Range(_, _, true)));
        assert_eq!((arms[3].pat.clone(), arms[3].body.len(), arms[3].line), (Pat::Wild, 2, 6));
        assert_eq!(f.body[1].line, 9);
    }

    #[test]
    fn use_decorators_async() {
        let p = prog("use serde::{Serialize, Deserialize}\nuse reqwest\nuse std::collections::*\n@json\n@derive(Hash, Eq)\ntype E: id: str\nasync fn f() -> str!:\n    r = reqwest::get(\"u\").await?\n    ret r.text().await?\n");
        let Item::Use(u) = &p.items[0] else { panic!() };
        assert_eq!(u.path, "serde::{Serialize, Deserialize}");
        let Item::Use(u) = &p.items[2] else { panic!() };
        assert_eq!(u.path, "std::collections::*");
        let Item::Struct(s) = &p.items[3] else { panic!() };
        assert!(s.attrs.json && s.attrs.derives == ["Hash", "Eq"]);
        let Item::Fn(f) = &p.items[4] else { panic!() };
        assert!(f.is_async && f.fallible);
        let Stmt::Let { value: Expr::Try(inner), .. } = &f.body[0].stmt else { panic!() };
        assert!(matches!(&**inner, Expr::Await(c) if matches!(&**c, Expr::Call(n, _, _) if n == "reqwest::get")));
    }

    #[test]
    fn generic_calls_vs_comparison() {
        let p = prog("fn f():\n    e = json_decode<Event>(raw)\n    n = s.parse<i32>()\n    m = s.parse::<u8>()\n    b = a < b\n    c = x < y and y > (z)\n");
        let Item::Fn(f) = &p.items[0] else { panic!() };
        let val = |i: usize| match &f.body[i].stmt { Stmt::Let { value, .. } => value.clone(), _ => panic!() };
        assert!(matches!(val(0), Expr::Call(n, g, _) if n == "json_decode" && g.len() == 1));
        assert!(matches!(val(1), Expr::Method(_, m, g, _) if m == "parse" && g.len() == 1));
        assert!(matches!(val(2), Expr::Method(_, _, g, _) if g.len() == 1));
        assert!(matches!(val(3), Expr::Binary(_, ref o, _) if o == "<"));
        assert!(matches!(val(4), Expr::Binary(_, ref o, _) if o == "&&"));
    }

    #[test]
    fn routes() {
        let p = prog("@public\nroute GET \"/health\" -> str:\n    ret \"ok\"\n@public\nroute POST \"/users/{id}/events\" (id: u64, body: Event) -> Event!:\n    ret body\n");
        let Item::Route(r) = &p.items[1] else { panic!() };
        assert_eq!((r.method.as_str(), r.path.as_str(), r.params.len(), r.fallible), ("POST", "/users/{id}/events", 2, true));
        let err = |src: &str| parse(lex(src).unwrap()).unwrap_err().to_string();
        assert!(err("@public\nroute GET \"/a/{id}\" -> str:\n    ret \"\"\n").contains("needs a typed parameter"));
        assert!(err("@public\nroute GET \"/a\" (x: i32):\n    ret\n").contains("must be a path param"));
        assert!(err("@public\nroute GET \"/a\":\n    ret\n@public\nroute GET \"/a\":\n    ret\n").contains("duplicate route"));
        assert!(err("@public\nroute GET \"/a\":\n    ret\nfn main():\n    ret\n").contains("Limen generates `main`"));
        assert!(err("@public\nroute FETCH \"/a\":\n    ret\n").contains("unknown HTTP method"));
    }

    #[test]
    fn state_block_and_state_param() {
        let p = prog("state:\n    hits: AtomicU64 = AtomicU64::new(0)\n    env: str = env(\"APP\", \"dev\")\n@public\nroute GET \"/a/{id}\" (state, id: str) -> str:\n    ret state.env.clone()\n");
        let Item::State(s) = &p.items[0] else { panic!() };
        assert_eq!((s.fields.len(), s.fields[1].0.as_str(), s.fields[1].3), (2, "env", 3));
        let Item::Route(r) = &p.items[1] else { panic!() };
        assert!(r.state && r.params.len() == 1);
        let err = |src: &str| parse(lex(src).unwrap()).unwrap_err().to_string();
        assert!(err("@public\nroute GET \"/a\" (state) -> str:\n    ret \"\"\n").contains("no `state:` block"));
        assert!(err("state:\n    a: i32 = 1\nfn main():\n    ret\n").contains("has none"));
        assert!(err("state:\n    a: i32 = 1\nstate:\n    b: i32 = 1\n@public\nroute GET \"/\":\n    ret\n").contains("only one"));
    }

    #[test]
    fn keywords_as_field_names() {
        let p = prog("@json\ntype E: type: str, match: i32\nenum V:\n    K(in: i32)\nfn f(e: E):\n    x = e.type\n    y = E(type: \"a\", match: 1)\n    match v:\n        K(in: n) -> print(n)\n");
        let Item::Struct(s) = &p.items[0] else { panic!() };
        assert_eq!(s.fields[0].0, "type");
        let Item::Fn(f) = &p.items[2] else { panic!() };
        assert!(matches!(&f.body[0].stmt, Stmt::Let { value: Expr::Field(_, n), .. } if n == "type"));
        assert!(matches!(&f.body[1].stmt, Stmt::Let { value: Expr::StructLit(_, fs), .. } if fs[1].0 == "match"));
    }

    #[test]
    fn v06_closures_spawn_loop_tuples_named_args() {
        let p = prog("fn f()!:\n    a = xs.map(|x| x * 2)\n    b = move |x: i32, y| -> i32:\n        ret x\n    t = (1, \"a\")\n    u = ()\n    loop:\n        break\n    for (k, v) in m: print(k)\n    h = spawn work(1)\n    j = spawn:\n        print(1)\n    fail(401, code: \"X\", \"m\")\n");
        let Item::Fn(f) = &p.items[0] else { panic!() };
        let val = |i: usize| match &f.body[i].stmt { Stmt::Let { value, .. } => value.clone(), _ => panic!("{i}") };
        assert!(matches!(val(0), Expr::Method(_, _, _, a) if matches!(a[0], Expr::Closure { .. })));
        assert!(matches!(val(1), Expr::Closure { is_move: true, ref params, ret: Some(_), .. } if params.len() == 2));
        assert!(matches!(val(2), Expr::Tuple(ref x) if x.len() == 2));
        assert_eq!(val(3), Expr::Tuple(vec![]));
        assert!(matches!(f.body[4].stmt, Stmt::Loop(_)));
        assert!(matches!(&f.body[5].stmt, Stmt::For { var, .. } if var == "(k, v)"));
        assert!(matches!(val(6), Expr::Spawn(ref b) if matches!(**b, ClosureBody::Expr(_))));
        assert!(matches!(val(7), Expr::Spawn(ref b) if matches!(**b, ClosureBody::Block(_))));
        assert!(matches!(&f.body[8].stmt, Stmt::Expr(Expr::Call(_, _, a)) if matches!(&a[1], Expr::Named(n, _) if n == "code")));
        // `loop` / `spawn` stay usable as names
        assert!(parse(lex("fn loop(spawn: i32) -> i32:\n    ret loop(spawn)\n").unwrap()).is_ok());
    }

    #[test]
    fn v06_field_attrs_types_guards() {
        let p = prog("@json\ntype E:\n    @rename(\"type\")\n    kind: str\n    @default\n    @omit_none\n    note: str?\nfn g(f: fn(i32) -> str, t: (i32, str)) -> ():\n    ret\n");
        let Item::Struct(s) = &p.items[0] else { panic!() };
        assert_eq!(s.field_attrs[0].rename.as_deref(), Some("type"));
        assert!(s.field_attrs[1].default && s.field_attrs[1].omit_none);
        let Item::Fn(f) = &p.items[1] else { panic!() };
        assert!(matches!(&f.params[0].1, Type::Fn(a, Some(_)) if a.len() == 1));
        assert_eq!(f.ret, Some(Type::Tuple(vec![])));
        let err = |src: &str| parse(lex(src).unwrap()).unwrap_err().to_string();
        assert!(err("@guard(nope)\nroute GET \"/\" -> str:\n    ret \"\"\n").contains("no `fn nope`"));
        assert!(err("fn g(x: i32) -> str!:\n    ret \"\"\n@guard(g)\nroute GET \"/\":\n    ret\n").contains("may only take untyped"));
        assert!(err("@public\nroute GET \"/\" (auth):\n    ret\n").contains("no @guard"));
        assert!(err("@guard(g)\nfn f():\n    ret\n").contains("goes on a `route`"));
        assert!(err("type E:\n    @omit_none\n    a: i32\n").contains("needs an optional field"));
    }

    #[test]
    fn v07_imports_sockets_ergonomics() {
        let items = parse_items(lex("import store\nimport auth.tokens\nfn main():\n    n, ~s = pair()\n    c = '!'\n    x = a\n        .b()\n").unwrap()).unwrap();
        assert!(matches!(&items[1], Item::Import(d) if d.path == ["auth", "tokens"]));
        let Item::Fn(f) = &items[2] else { panic!() };
        assert!(matches!(&f.body[0].stmt, Stmt::LetTuple { names, .. } if names == &[("n".to_string(), false), ("s".to_string(), true)]));
        assert!(matches!(&f.body[1].stmt, Stmt::Let { value: Expr::Char(c), .. } if c == "!"));
        assert!(matches!(&f.body[2].stmt, Stmt::Let { value: Expr::Method(..), .. }));
        let p = prog("@public\n@protocols(\"ro.v1\")\n@max_message(1024)\nsocket \"/ws/{id}\" (id: str, conn):\n    ret\n");
        let Item::Route(r) = &p.items[0] else { panic!() };
        assert!(r.conn && r.fallible);
        assert_eq!(r.socket, Some(SocketOpts { protocols: vec!["ro.v1".into()], max_message: Some("1024".into()) }));
        let err = |src: &str| parse(lex(src).unwrap()).unwrap_err().to_string();
        assert!(err("@public\nroute GET \"/x\" (conn):\n    ret\n").contains("only exists in a `socket`"));
        assert!(err("@public\nsocket \"/x\":\n    ret\n").contains("a socket takes `conn`"));
        assert!(err("@public\n@protocols(\"a\")\nroute GET \"/x\":\n    ret\n").contains("go on a `socket`"));
        // whole-program checks see module routes, guards and stray `state`/`main`
        let module = |src: &str| Module { path: vec!["m".into()], items: parse_items(lex(src).unwrap()).unwrap() };
        let mk = |main: &str, m: &str| Program { items: parse_items(lex(main).unwrap()).unwrap(), modules: vec![module(m)], files: vec![] };
        assert!(validate(&mk("fn x():\n    ret\n", "fn g(req) -> str!:\n    ret \"a\"\n@guard(g)\nroute GET \"/a\" (auth) -> str:\n    ret auth\n")).is_ok());
        assert!(validate(&mk("fn x():\n    ret\n", "state:\n    a: i32 = 1\n")).unwrap_err().to_string().contains("main file"));
        assert!(validate(&mk("@public\nroute GET \"/a\":\n    ret\n", "@public\nroute GET \"/a\":\n    ret\n")).unwrap_err().to_string().contains("duplicate route"));
    }

    #[test]
    fn v091_items_and_expressions() {
        let p = prog("@json\ntype Page<T: Clone>: items: [T], total: i64\ntrait Store:\n    async fn get(&self, id: i64) -> str?!\n    fn name(&self) -> str:\n        ret \"s\"\nimpl Store for Mem:\n    async fn get(&self, id: i64) -> str?!:\n        ret None\npriv fn helper() -> i64:\n    ret 1 as i64\n@test_only\nfn fake():\n    m = {\"a\": 1, \"b\": 2}\n    x = load()? catch e: 0\n");
        let Item::Struct(st) = &p.items[0] else { panic!() };
        assert_eq!(st.generics[0].name, "T");
        assert_eq!(st.generics[0].bounds.len(), 1);
        let Item::Trait(t) = &p.items[1] else { panic!() };
        assert!(!t.methods[0].has_body && t.methods[1].has_body);
        let Item::Impl(i) = &p.items[2] else { panic!() };
        assert!(i.trait_.is_some() && i.ty == "Mem");
        let Item::Fn(h) = &p.items[3] else { panic!() };
        assert!(h.flags.private && matches!(&h.body[0].stmt, Stmt::Ret(Some(Expr::Cast(..)))));
        let Item::Fn(f) = &p.items[4] else { panic!() };
        assert!(f.flags.test_only);
        assert!(matches!(&f.body[0].stmt, Stmt::Let { value: Expr::Map(kv), .. } if kv.len() == 2));
        assert!(matches!(&f.body[1].stmt, Stmt::Let { value: Expr::Catch { binding: Some(b), .. }, .. } if b == "e"));
    }

    #[test]
    fn deny_by_default_access_policy() {
        let err = |src: &str| lex(src).and_then(parse).map(|_| ()).unwrap_err().to_string();
        let e = err("route GET \"/x\" -> str:\n    ret \"x\"\n");
        assert!(e.contains("line 1: route GET /x has no access policy") && e.contains("@public(\"why anyone may call it\")"), "{e}");
        assert!(err("socket \"/ws\" (conn):\n    ret\n").contains("socket GET /ws has no access policy"));
        assert!(err("fn g(req) -> str!:\n    ret \"a\"\n@guard(g)\n@public\nroute GET \"/x\" -> str:\n    ret \"x\"\n").contains("both @guard and @public"));
        assert!(err("@public(\"\")\nroute GET \"/x\" -> str:\n    ret \"x\"\n").contains("non-empty reason"));
        assert!(err("@public\nfn f():\n    ret\n").contains("@public goes on a `route`"));
        let p = prog("@public(\"health probe for the load balancer\")\nroute GET \"/ping\" -> str:\n    ret \"pong\"\n");
        let Item::Route(r) = &p.items[0] else { panic!() };
        assert_eq!(r.public.as_deref(), Some("health probe for the load balancer"));
    }

    #[test]
    fn reserved_type_names() {
        let err = |src: &str| lex(src).and_then(parse).map(|_| ()).unwrap_err().to_string();
        let e = err("type Result: ok: bool, user: str\n");
        assert!(e.contains("line 1: type `Result` is reserved") && e.contains("Rust's built-in"), "{e}");
        assert!(err("enum Option:\n    A\n").contains("enum `Option` is reserved"));
        assert!(err("trait Clone:\n    fn f(&self)\n").contains("trait `Clone` is reserved"));
        assert!(err("type AppError: m: str\n").contains("the Limen runtime defines"));
        assert!(err("type Secret: v: str\n").contains("the Limen runtime defines"));
        prog("type LoginResult: ok: bool\ntype State: n: int\n");
    }

    #[test]
    fn v091_errors() {
        for (src, msg) in [
            ("trait S:\n    async fn f(&self):\n        ret\n", "async trait method can't have a default body"),
            ("every 5x:\n    ret\n", "unknown time unit"),
            ("every 10ms:\n    ret\n", "at least 100ms"),
            ("priv route GET \"/\":\n    ret\n", "`priv` goes before"),
            ("@public\n@test_only\nroute GET \"/\":\n    ret\n", "@test_only goes on helpers"),
            ("every 1s:\n    ret\nfn main():\n    ret\n", "run inside a service"),
            ("type P<T, T>: x: T\n", "declared twice"),
        ] {
            let err = lex(src).and_then(parse).map(|_| ()).unwrap_err().to_string();
            assert!(err.contains(msg), "{src:?}: {err}");
        }
    }

    #[test]
    fn deep_or_long_input_is_an_error_not_a_crash() {
        // the compiler runs on a 64 MB thread (main.rs); test under the same stack
        std::thread::Builder::new().stack_size(64 << 20).spawn(deep_or_long_body).unwrap().join().unwrap();
    }

    fn deep_or_long_body() {
        let src = |e: &str| format!("fn main():\n    x = {e}\n");
        let err = |e: &str| parse(lex(&src(e)).unwrap()).map(|_| ()).unwrap_err().to_string();
        let nested = format!("{}1{}", "(".repeat(5000), ")".repeat(5000));
        assert!(err(&nested).contains("nesting too deep"));
        assert!(err(&format!("{}1", "-".repeat(5000))).contains("nesting too deep"));
        assert!(err(&format!("[{}]", "[".repeat(400) + &"]".repeat(400))).contains("nesting too deep"));
        assert!(err(&format!("1{}", " + 1".repeat(MAX_CHAIN + 1))).contains("expression too long"));
        // at the limits it still parses
        assert!(parse(lex(&src(&format!("{}1{}", "(".repeat(200), ")".repeat(200)))).unwrap()).is_ok());
        assert!(parse(lex(&src(&format!("1{}", " + 1".repeat(MAX_CHAIN)))).unwrap()).is_ok());
    }

    #[test]
    fn parse_errors() {
        assert!(parse(lex("x = 1\n").unwrap()).is_err());
        assert!(parse(lex("fn f(a):\n    ret\n").unwrap()).is_err());
        assert!(parse(lex("fn f()\n    ret\n").unwrap()).is_err());
    }
}
