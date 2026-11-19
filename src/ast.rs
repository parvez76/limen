//! Parvez abstract syntax tree.

#[derive(Debug, Clone, PartialEq)]
pub struct Program {
    pub items: Vec<Item>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Item {
    Fn(FnDef),
    Struct(StructDef),
}

#[derive(Debug, Clone, PartialEq)]
pub struct StructDef {
    pub name: String,
    pub fields: Vec<(String, Type)>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FnDef {
    pub name: String,
    pub params: Vec<(String, Type)>,
    pub ret: Option<Type>,
    /// `!` in the return position: function returns `anyhow::Result<ret>`.
    pub fallible: bool,
    pub body: Vec<Stmt>,
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
        branches: Vec<(Expr, Vec<Stmt>)>,
        els: Option<Vec<Stmt>>,
    },
    For { var: String, iter: Expr, body: Vec<Stmt> },
    While { cond: Expr, body: Vec<Stmt> },
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
}
