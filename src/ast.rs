//! Parvez abstract syntax tree.

#[derive(Debug, Clone, PartialEq)]
pub struct Program {
    pub items: Vec<Item>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Item {
    Fn(FnDef),
    Struct(StructDef),
    Enum(EnumDef),
    Impl(ImplDef),
}

#[derive(Debug, Clone, PartialEq)]
pub struct StructDef {
    pub name: String,
    pub fields: Vec<(String, Type)>,
    pub line: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EnumDef {
    pub name: String,
    pub variants: Vec<Variant>,
    pub line: usize,
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
    pub ty: String,
    pub methods: Vec<FnDef>,
    pub line: usize,
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

#[derive(Debug, Clone, PartialEq)]
pub struct FnDef {
    pub name: String,
    pub receiver: Option<Receiver>,
    pub params: Vec<(String, Type)>,
    pub ret: Option<Type>,
    /// `!` in the return position: function returns `anyhow::Result<ret>`.
    pub fallible: bool,
    pub body: Block,
    pub line: usize,
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
    Ret(Option<Expr>),
    If {
        branches: Vec<(Expr, Block)>,
        els: Option<Block>,
    },
    For { var: String, iter: Expr, body: Block },
    While { cond: Expr, body: Block },
    Break,
    Continue,
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
    Int(String),
    Float(String),
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
    Call(String, Vec<Expr>),
    StructLit(String, Vec<(String, Expr)>),
    Field(Box<Expr>, String),
    Method(Box<Expr>, String, Vec<Expr>),
    Index(Box<Expr>, Box<Expr>),
    Try(Box<Expr>),
    Match(Box<Expr>, Vec<Arm>),
}
