//! Parvez abstract syntax tree.

#[derive(Debug, Clone, PartialEq)]
pub struct Program {
    /// items of the main file
    pub items: Vec<Item>,
    /// imported files, each a module (`import auth.tokens` -> path ["auth", "tokens"])
    pub modules: Vec<Module>,
    /// (display name, source) per file; index 0 is the main file
    pub files: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Module {
    pub path: Vec<String>,
    pub items: Vec<Item>,
}

impl Program {
    /// Every item with the module path it lives in (empty = main file).
    /// Module paths imported only with `@test_only import` (every import of them).
    pub fn test_only_modules(&self) -> std::collections::BTreeSet<Vec<String>> {
        let mut imports: std::collections::HashMap<Vec<String>, bool> = std::collections::HashMap::new();
        for (_, item) in self.all_items() {
            if let Item::Import(i) = item {
                *imports.entry(i.path.clone()).or_insert(true) &= i.flags.test_only;
            }
        }
        imports.into_iter().filter(|(_, t)| *t).map(|(p, _)| p).collect()
    }

    /// Items that exist only in `parvez test` builds: `test` blocks, `@test_only`
    /// items and everything in a test-only module.
    pub fn is_test_scope(&self, module: &[String], item: &Item, test_mods: &std::collections::BTreeSet<Vec<String>>) -> bool {
        let flagged = match item {
            Item::Fn(x) => x.flags.test_only,
            Item::Struct(x) => x.flags.test_only,
            Item::Enum(x) => x.flags.test_only,
            Item::Impl(x) => x.flags.test_only,
            Item::Trait(x) => x.flags.test_only,
            Item::Use(x) => x.flags.test_only,
            Item::Import(x) => x.flags.test_only,
            Item::Const { flags, .. } => flags.test_only,
            Item::Test(_) => true,
            _ => false,
        };
        flagged || test_mods.iter().any(|m| module.starts_with(m))
    }

    pub fn all_items(&self) -> Vec<(&[String], &Item)> {
        let mut v: Vec<(&[String], &Item)> = self.items.iter().map(|i| (&[][..], i)).collect();
        for m in &self.modules {
            v.extend(m.items.iter().map(|i| (m.path.as_slice(), i)));
        }
        v
    }
}

/// Lines are encoded as `file_index * FILE_STRIDE + line` so every error and
/// source-map entry can name its file. File 0 (the main file) is unchanged.
pub const FILE_STRIDE: usize = 1_000_000;

/// Encoded line -> (file index, line within that file).
pub fn split_line(n: usize) -> (usize, usize) {
    (n / FILE_STRIDE, n % FILE_STRIDE)
}

#[derive(Debug, Clone, PartialEq)]
pub struct TestDef {
    pub name: String,
    pub body: Block,
    pub line: usize,
}

/// `import a.b`
#[derive(Debug, Clone, PartialEq)]
pub struct ImportDef {
    pub flags: Flags,
    pub path: Vec<String>,
    pub line: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Item {
    Const {
        name: String,
        ty: Type,
        value: Expr,
        line: usize,
        flags: Flags,
    },
    Embed {
        dir: String,
        files: Vec<(String, std::path::PathBuf)>,
        line: usize,
    },
    Fn(FnDef),
    Struct(StructDef),
    Enum(EnumDef),
    Impl(ImplDef),
    Use(UseDef),
    Route(RouteDef),
    State(StateDef),
    Import(ImportDef),
    /// `test "name":` block (compiled only for `parvez test`)
    Test(TestDef),
    /// `trait Name:` with method signatures and optional default bodies
    Trait(TraitDef),
    /// `every 1h (state):` scheduled background worker
    Every(EveryDef),
}

/// `priv` (module-private) and `@test_only` (built only for `parvez test` / `check`).
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Flags {
    pub private: bool,
    pub test_only: bool,
}

/// A generic parameter: `T` or `T: Clone + Store`.
#[derive(Debug, Clone, PartialEq)]
pub struct Generic {
    pub name: String,
    pub bounds: Vec<Type>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TraitDef {
    pub name: String,
    pub generics: Vec<Generic>,
    /// methods; `has_body == false` for required signatures
    pub methods: Vec<FnDef>,
    pub line: usize,
    pub flags: Flags,
}

/// `every 1h (state):` -> a worker that runs the body once per period.
#[derive(Debug, Clone, PartialEq)]
pub struct EveryDef {
    /// period in milliseconds
    pub period_ms: u64,
    /// the period as written, e.g. `1h` (logs, metrics)
    pub label: String,
    pub state: bool,
    pub body: Block,
    pub line: usize,
}

/// `state:` block: shared resources built once at server start.
#[derive(Debug, Clone, PartialEq)]
pub struct StateDef {
    /// (name, type, initializer, line)
    pub fields: Vec<(String, Type, Expr, usize)>,
    /// `spawn ...` lines: background tasks started after the fields exist
    pub tasks: Vec<(Expr, usize)>,
    pub line: usize,
    /// `@allow_insecure("reason")`
    pub allow_insecure: Option<String>,
}

/// `use serde::{Serialize, Deserialize}` / `use reqwest`
#[derive(Debug, Clone, PartialEq)]
pub struct UseDef {
    /// Rust path as written, e.g. `serde::{Serialize, Deserialize}`
    pub path: String,
    pub line: usize,
    pub flags: Flags,
}

/// `route POST "/events/{id}" (id: str, body: Event) -> Event!:`
#[derive(Debug, Clone, PartialEq)]
pub struct RouteDef {
    pub page: bool,
    /// GET, POST, PUT, PATCH, DELETE
    pub method: String,
    pub path: String,
    pub params: Vec<(String, Type)>,
    /// `(state, ...)`: the route receives `state: &AppState`
    pub state: bool,
    /// `(req, ...)`: the route receives `req: &Req` (headers, raw body, client IP)
    pub req: bool,
    /// `(auth, ...)`: the route receives the last guard's return value
    pub auth: bool,
    /// `socket` routes: WebSocket upgrade options; the body runs per connection
    pub socket: Option<SocketOpts>,
    /// `(conn, ...)` in a socket: the connection (`&mut Conn`)
    pub conn: bool,
    /// `@guard(fn_name)` lines, run in order before the handler
    pub guards: Vec<String>,
    /// `@body_error(400, code: "bad_request", "invalid JSON body")`
    pub body_error: Option<BodyError>,
    /// `@allow_insecure("reason")`
    pub allow_insecure: Option<String>,
    pub ret: Option<Type>,
    pub fallible: bool,
    pub body: Block,
    pub line: usize,
}

/// Decorators on `type` / `enum`: `@json`, `@derive(Hash, Eq)`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Attrs {
    pub json: bool,
    pub derives: Vec<String>,
    /// `@allow_insecure("reason")`: skip security checks for this item
    pub allow_insecure: Option<String>,
    /// `@guard(fn_name)` (routes only)
    pub guards: Vec<String>,
    /// `@body_error(status, code: "..", "msg")` (routes only)
    pub body_error: Option<BodyError>,
    /// `@protocols(..)` / `@max_message(n)` (sockets only)
    pub socket: SocketOpts,
    /// `@test_only`
    pub test_only: bool,
}

/// `@protocols("ro.v1")`, `@max_message(8388608)` on a `socket`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SocketOpts {
    pub protocols: Vec<String>,
    pub max_message: Option<String>,
}

/// Response for a request body that fails to decode as the route's `body: T`.
#[derive(Debug, Clone, PartialEq)]
pub struct BodyError {
    pub status: String,
    pub code: Option<String>,
    pub message: String,
}

/// Per-field decorators on `@json` types: `@rename("x")`, `@default`, `@omit_none`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct FieldAttrs {
    pub rename: Option<String>,
    pub default: bool,
    pub omit_none: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct StructDef {
    pub name: String,
    pub generics: Vec<Generic>,
    pub fields: Vec<(String, Type)>,
    /// same length as `fields`
    pub field_attrs: Vec<FieldAttrs>,
    pub line: usize,
    pub attrs: Attrs,
    pub flags: Flags,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EnumDef {
    pub name: String,
    pub generics: Vec<Generic>,
    pub variants: Vec<Variant>,
    pub line: usize,
    pub attrs: Attrs,
    pub flags: Flags,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Variant {
    pub name: String,
    pub data: VariantData,
}

#[derive(Debug, Clone, PartialEq)]
pub enum VariantData {
    /// `Active`
    Unit,
    /// `Pending(str)`
    Tuple(Vec<Type>),
    /// `Failed(code: i32, reason: str)`
    Named(Vec<(String, Type)>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct ImplDef {
    /// the implementing type's base name (`Page` in `impl Page<T>:`)
    pub ty: String,
    /// its type arguments (`[T]`)
    pub ty_args: Vec<Type>,
    /// `impl<T: X> ...`: explicit generics; otherwise inferred from the type's declaration
    pub generics: Option<Vec<Generic>>,
    /// `impl Store for Mem:`
    pub trait_: Option<Type>,
    pub methods: Vec<FnDef>,
    pub line: usize,
    pub flags: Flags,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Receiver {
    /// `&self`
    Ref,
    /// `&~self` -> `&mut self`
    RefMut,
    /// `self`
    Value,
    /// `~self` -> `mut self`
    MutValue,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct FnDef {
    pub name: String,
    pub generics: Vec<Generic>,
    pub is_async: bool,
    pub receiver: Option<Receiver>,
    pub params: Vec<(String, Type)>,
    pub ret: Option<Type>,
    /// `!` in the return position: function returns `anyhow::Result<ret>`.
    pub fallible: bool,
    pub body: Block,
    pub line: usize,
    /// `@allow_insecure("reason")`
    pub allow_insecure: Option<String>,
    /// false for a trait method signature without a body
    pub has_body: bool,
    pub flags: Flags,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Type {
    /// `i32`, `str`, `Vec<T>`, `HashMap<K, V>` ...
    Named(String, Vec<Type>),
    /// `&T` / `&~T` (mutable)
    Ref(Box<Type>, bool),
    /// `[T]` -> Vec<T>
    List(Box<Type>),
    /// `T?` -> Option<T>
    Opt(Box<Type>),
    /// `()` / `(A, B)`
    Tuple(Vec<Type>),
    /// `fn(A, B) -> R` -> `impl Fn(A, B) -> R` (parameter/return position)
    Fn(Vec<Type>, Option<Box<Type>>),
}

pub type Block = Vec<Located>;

/// A statement plus the `.prvz` line it starts on (drives the source map).
#[derive(Debug, Clone, PartialEq)]
pub struct Located {
    pub line: usize,
    pub stmt: Stmt,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Stmt {
    Render(Vec<HtmlPart>),
    /// `x = e`, `~x = e`, `x: T = e`. Codegen turns `x = e` into an
    /// assignment when `x` is an already-declared mutable binding.
    Let {
        name: String,
        mutable: bool,
        ty: Option<Type>,
        value: Expr,
    },
    /// `target op value` where op is `=`, `+=`, ...
    Assign { target: Expr, op: String, value: Expr },
    Expr(Expr),
    /// `a, ~b = expr` -> `let (a, mut b) = expr;`
    LetTuple { names: Vec<(String, bool)>, value: Expr },
    Ret(Option<Expr>),
    If {
        branches: Vec<(Expr, Block)>,
        els: Option<Block>,
    },
    /// `var` is a name or a tuple pattern like `(k, v)`
    For { var: String, iter: Expr, body: Block },
    /// `loop:`
    Loop(Block),
    While { cond: Expr, body: Block },
    Break,
    Continue,
}

#[derive(Debug, Clone, PartialEq)]
pub enum HtmlPart {
    Markup(String),
    Value(Expr, bool), // true only for explicitly authorized raw output
}

#[derive(Debug, Clone, PartialEq)]
pub enum StrPart {
    /// Literal text (Rust escape sequences preserved, braces unescaped).
    Lit(String),
    /// `{expr}` or `{expr:spec}`
    Interp(Expr, Option<String>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Arm {
    pub pat: Pat,
    pub guard: Option<Expr>,
    pub body: Block,
    pub line: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Pat {
    /// `_`
    Wild,
    /// lowercase name: binds the value
    Bind(String),
    /// int / float / str / bool literal
    Lit(Expr),
    /// `1..=5`
    Range(Expr, Expr, bool),
    /// `Active`, `Pending(msg)`, `Failed(code, reason: r)`, `Some(x)`, `Enum::V`.
    /// Sub-patterns may be positional (`None` name) or named.
    Variant(String, Option<Vec<(Option<String>, Pat)>>),
    /// `A | B`
    Or(Vec<Pat>),
    /// `..` inside a variant pattern: ignore remaining fields
    Rest,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    If(Box<Expr>, Box<Expr>, Box<Expr>),
    /// Only produced for statement conditions.
    LetPat(Box<Pat>, Box<Expr>),
    Int(String),
    Float(String),
    /// `'a'` (raw body, escapes kept)
    Char(String),
    Str(Vec<StrPart>),
    Bool(bool),
    /// Identifier or path (`a`, `Vec::new`).
    Ident(String),
    List(Vec<Expr>),
    Binary(Box<Expr>, String, Box<Expr>),
    Unary(String, Box<Expr>),
    /// `&e` / `&~e`
    Ref(Box<Expr>, bool),
    Range(Box<Expr>, Box<Expr>, bool),
    /// `f(args)`, `f<T>(args)` (generic args become a turbofish)
    Call(String, Vec<Type>, Vec<Expr>),
    StructLit(String, Vec<(String, Expr)>),
    Field(Box<Expr>, String),
    Method(Box<Expr>, String, Vec<Type>, Vec<Expr>),
    Index(Box<Expr>, Box<Expr>),
    Try(Box<Expr>),
    /// `e.await`
    Await(Box<Expr>),
    Match(Box<Expr>, Vec<Arm>),
    /// `(a, b)`
    Tuple(Vec<Expr>),
    /// `|a, b: i32| expr` / `move |x| -> T:` block
    Closure {
        params: Vec<(String, Option<Type>)>,
        ret: Option<Type>,
        body: Box<ClosureBody>,
        is_move: bool,
    },
    /// `spawn fut` -> tokio::spawn(fut); `spawn:` block -> tokio::spawn(async move { .. })
    Spawn(Box<ClosureBody>),
    /// `name: value` inside call args, e.g. `fail(401, code: "x", "msg")`
    Named(String, Box<Expr>),
    /// `e as T`
    Cast(Box<Expr>, Type),
    /// `{"k": v, ...}` -> HashMap (or a JSON object inside `json(...)`)
    Map(Vec<(Expr, Expr)>),
    /// `e catch err: handler` -- `?`/`fail` inside `e` land in the handler
    Catch {
        expr: Box<Expr>,
        binding: Option<String>,
        handler: Box<ClosureBody>,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum ClosureBody {
    Expr(Expr),
    Block(Block),
}

/// Calls `f` on every expression in `b`, recursively (statements, nested
/// blocks, match arms, closures, spawn bodies, string interpolations).
pub fn visit_exprs(b: &Block, f: &mut dyn FnMut(&Expr)) {
    for s in b {
        visit_stmt(&s.stmt, f);
    }
}

fn visit_stmt(s: &Stmt, f: &mut dyn FnMut(&Expr)) {
    match s {
        Stmt::Render(parts) => {
            for p in parts {
                if let HtmlPart::Value(x, _) = p {
                    visit_expr(x, f);
                }
            }
        }
        Stmt::Let { value, .. } => visit_expr(value, f),
        Stmt::Assign { target, value, .. } => {
            visit_expr(target, f);
            visit_expr(value, f);
        }
        Stmt::Expr(e) | Stmt::Ret(Some(e)) | Stmt::LetTuple { value: e, .. } => visit_expr(e, f),
        Stmt::Ret(None) | Stmt::Break | Stmt::Continue => {}
        Stmt::If { branches, els } => {
            for (c, b) in branches {
                visit_expr(c, f);
                visit_exprs(b, f);
            }
            if let Some(b) = els {
                visit_exprs(b, f);
            }
        }
        Stmt::For { iter, body, .. } => {
            visit_expr(iter, f);
            visit_exprs(body, f);
        }
        Stmt::While { cond, body } => {
            visit_expr(cond, f);
            visit_exprs(body, f);
        }
        Stmt::Loop(body) => visit_exprs(body, f),
    }
}

pub fn visit_expr(e: &Expr, f: &mut dyn FnMut(&Expr)) {
    f(e);
    let body = |b: &ClosureBody, f: &mut dyn FnMut(&Expr)| match b {
        ClosureBody::Expr(x) => visit_expr(x, f),
        ClosureBody::Block(b) => visit_exprs(b, f),
    };
    match e {
        Expr::Call(_, _, args) => args.iter().for_each(|a| visit_expr(a, f)),
        Expr::Method(x, _, _, args) => {
            visit_expr(x, f);
            args.iter().for_each(|a| visit_expr(a, f));
        }
        Expr::Str(parts) => {
            for p in parts {
                if let StrPart::Interp(x, _) = p {
                    visit_expr(x, f);
                }
            }
        }
        Expr::List(xs) | Expr::Tuple(xs) => xs.iter().for_each(|x| visit_expr(x, f)),
        Expr::StructLit(_, fs) => fs.iter().for_each(|(_, v)| visit_expr(v, f)),
        Expr::Binary(a, _, b) | Expr::Range(a, b, _) | Expr::Index(a, b) => {
            visit_expr(a, f);
            visit_expr(b, f);
        }
        Expr::Unary(_, x) | Expr::Ref(x, _) | Expr::Field(x, _) | Expr::Try(x) | Expr::Await(x) | Expr::Named(_, x) => {
            visit_expr(x, f)
        }
        Expr::If(c, a, b) => {
            for e in [c, a, b] {
                visit_expr(e, f);
            }
        }
        Expr::LetPat(_, x) => visit_expr(x, f),
        Expr::Match(x, arms) => {
            visit_expr(x, f);
            for a in arms {
                if let Some(g) = &a.guard {
                    visit_expr(g, f);
                }
                visit_exprs(&a.body, f);
            }
        }
        Expr::Closure { body: b, .. } | Expr::Spawn(b) => body(b, f),
        Expr::Cast(x, _) => visit_expr(x, f),
        Expr::Map(kvs) => kvs.iter().for_each(|(k, v)| {
            visit_expr(k, f);
            visit_expr(v, f);
        }),
        Expr::Catch { expr, handler, .. } => {
            visit_expr(expr, f);
            body(handler, f);
        }
        Expr::Int(_) | Expr::Float(_) | Expr::Char(_) | Expr::Bool(_) | Expr::Ident(_) => {}
    }
}
