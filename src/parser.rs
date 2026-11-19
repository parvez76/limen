//! Recursive-descent parser: tokens -> AST.

use crate::ast::*;
use crate::lexer::{Tok, Token, lex_from};
use anyhow::{Result, bail};

pub fn parse(tokens: Vec<Token>) -> Result<Program> {
    let mut p = Parser { toks: tokens, pos: 0 };
    let mut items = Vec::new();
    loop {
        p.skip_newlines();
        match p.peek() {
            Tok::Eof => break,
            Tok::Fn | Tok::Async => items.push(Item::Fn(p.parse_fn()?)),
            Tok::Type => items.push(Item::Struct(p.parse_struct()?)),
            Tok::Enum => items.push(Item::Enum(p.parse_enum()?)),
            Tok::Impl => items.push(Item::Impl(p.parse_impl()?)),
            Tok::Use => items.push(Item::Use(p.parse_use()?)),
            Tok::At => {
                let attrs = p.parse_attrs()?;
                match p.peek() {
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
                    t => bail!("line {}: decorators apply to `type` or `enum`, found {:?}", p.line(), t),
                }
            }
            Tok::Ident(r) if r == "route" => items.push(Item::Route(p.parse_route()?)),
            t => bail!(
                "line {}: expected `fn`, `type`, `enum`, `impl`, `use` or `route` at top level, found {:?}",
                p.line(),
                t
            ),
        }
    }
    let routes: Vec<&RouteDef> =
        items.iter().filter_map(|i| if let Item::Route(r) = i { Some(r) } else { None }).collect();
    if let Some(r) = routes.first() {
        for i in &items {
            if let Item::Fn(f) = i
                && f.name == "main"
            {
                bail!(
                    "line {}: this file has `route`s (first at line {}), so Parvez generates `main` (the HTTP server); rename or remove `fn main`",
                    f.line,
                    r.line
                );
            }
        }
        for (k, a) in routes.iter().enumerate() {
            if let Some(b) = routes[..k].iter().find(|b| b.method == a.method && b.path == a.path) {
                bail!("line {}: duplicate route {} {} (already at line {})", a.line, a.method, a.path, b.line);
            }
        }
    }
    Ok(Program { items })
}

struct Parser {
    toks: Vec<Token>,
    pos: usize,
}

impl Parser {
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
    fn skip_newlines(&mut self) {
        while self.eat(&Tok::Newline) {}
    }
    fn end_stmt(&mut self) -> Result<()> {
        // A `match` expression ends with its own DEDENT.
        if self.pos > 0 && self.toks[self.pos - 1].tok == Tok::Dedent {
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
        self.expect(Tok::Colon, "`:` after type name")?;
        let mut fields = Vec::new();
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
            let f = self.ident("field name")?;
            self.expect(Tok::Colon, "`:` after field name")?;
            fields.push((f, self.parse_type()?));
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
        Ok(StructDef { name, fields, line, attrs: Attrs::default() })
    }

    /// `enum Name: A, B(str)` or an indented list of variants.
    fn parse_enum(&mut self) -> Result<EnumDef> {
        let line = self.line();
        self.expect(Tok::Enum, "`enum`")?;
        let name = self.ident("enum name")?;
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
        Ok(EnumDef { name, variants, line, attrs: Attrs::default() })
    }

    fn parse_variant(&mut self) -> Result<Variant> {
        let name = self.ident("variant name")?;
        if !self.eat(&Tok::LParen) {
            return Ok(Variant { name, data: VariantData::Unit });
        }
        let named = matches!(self.peek(), Tok::Ident(_)) && self.peek_at(1) == &Tok::Colon;
        let mut types = Vec::new();
        let mut fields = Vec::new();
        while !self.eat(&Tok::RParen) {
            if named {
                let f = self.ident("field name (use `name: type` for every field)")?;
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
        let ty = self.ident("type name after `impl`")?;
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
                t => bail!("line {}: only `fn` is allowed inside `impl`, found {:?}", self.line(), t),
            }
        }
        Ok(ImplDef { ty, methods, line })
    }

    fn skip_newlines_if(&mut self, yes: bool) {
        if yes {
            self.skip_newlines();
        }
    }

    fn parse_fn(&mut self) -> Result<FnDef> {
        let line = self.line();
        let is_async = self.eat(&Tok::Async);
        self.expect(Tok::Fn, "`fn` (after `async`)")?;
        let name = self.ident("function name")?;
        self.expect(Tok::LParen, "`(`")?;
        let receiver = self.parse_receiver()?;
        if receiver.is_some() && !self.eat(&Tok::Comma) && self.peek() != &Tok::RParen {
            bail!("line {}: expected `,` or `)` after self", self.line());
        }
        let mut params = Vec::new();
        while !self.eat(&Tok::RParen) {
            let p = self.ident("parameter name")?;
            self.expect(Tok::Colon, "`:` after parameter name (types are required)")?;
            params.push((p, self.parse_type()?));
            if !self.eat(&Tok::Comma) {
                self.expect(Tok::RParen, "`,` or `)`")?;
                break;
            }
        }
        let ret = if self.eat(&Tok::Arrow) { Some(self.parse_type()?) } else { None };
        let fallible = self.eat(&Tok::Bang);
        let body = self.parse_block()?;
        Ok(FnDef { name, is_async, receiver, params, ret, fallible, body, line })
    }

    /// `@json` / `@derive(Hash, Eq)` lines before a `type` or `enum`.
    fn parse_attrs(&mut self) -> Result<Attrs> {
        let mut attrs = Attrs::default();
        while self.eat(&Tok::At) {
            let line = self.line();
            match self.ident("decorator name after `@`")?.as_str() {
                "json" => attrs.json = true,
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
                other => bail!("line {line}: unknown decorator `@{other}` (known: @json, @derive(...))"),
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
        Ok(UseDef { path, line })
    }

    /// `route METHOD "/path/{p}" [(params)] [-> T][!]:` block
    fn parse_route(&mut self) -> Result<RouteDef> {
        let line = self.line();
        self.next(); // `route`
        let method = self.ident("HTTP method (GET, POST, PUT, PATCH, DELETE)")?;
        if !["GET", "POST", "PUT", "PATCH", "DELETE"].contains(&method.as_str()) {
            bail!("line {line}: unknown HTTP method `{method}` (use GET, POST, PUT, PATCH or DELETE)");
        }
        let path = match self.next() {
            Tok::Str(s) if s.starts_with('/') => s,
            t => bail!("line {line}: expected a path string starting with `/`, found {t:?}"),
        };
        let mut params = Vec::new();
        if self.eat(&Tok::LParen) {
            while !self.eat(&Tok::RParen) {
                let p = self.ident("parameter name")?;
                self.expect(Tok::Colon, "`:` after parameter name (types are required)")?;
                params.push((p, self.parse_type()?));
                if !self.eat(&Tok::Comma) {
                    self.expect(Tok::RParen, "`,` or `)`")?;
                    break;
                }
            }
        }
        let ret = if self.eat(&Tok::Arrow) { Some(self.parse_type()?) } else { None };
        let fallible = self.eat(&Tok::Bang);
        let holes = path_params(&path);
        for (p, _) in &params {
            if !holes.contains(p) && p != "body" && p != "query" {
                bail!(
                    "line {line}: route param `{p}` must be a path param (`{{{p}}}` in the path), `body` (JSON body) or `query` (query string)"
                );
            }
        }
        for h in &holes {
            if !params.iter().any(|(p, _)| p == h) {
                bail!("line {line}: path param `{{{h}}}` needs a typed parameter, e.g. ({h}: str)");
            }
        }
        let body = self.parse_block()?;
        Ok(RouteDef { method, path, params, ret, fallible, body, line })
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

    // ---------- statements ----------

    /// `:` followed by either an indented block or a single inline statement.
    fn parse_block(&mut self) -> Result<Block> {
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
            Tok::If => self.parse_if(),
            Tok::For => {
                self.next();
                let var = self.ident("loop variable")?;
                self.expect(Tok::In, "`in`")?;
                let iter = self.parse_expr()?;
                let body = self.parse_block()?;
                Ok(Stmt::For { var, iter, body })
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

    fn parse_if(&mut self) -> Result<Stmt> {
        self.expect(Tok::If, "`if`")?;
        let mut branches = vec![(self.parse_expr()?, self.parse_block()?)];
        let mut els = None;
        loop {
            self.skip_newlines();
            if self.eat(&Tok::Elif) {
                branches.push((self.parse_expr()?, self.parse_block()?));
            } else if self.eat(&Tok::Else) {
                if self.eat(&Tok::If) {
                    branches.push((self.parse_expr()?, self.parse_block()?));
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
        self.parse_bin(0)
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
        while let Some((prec, op)) = self.bin_op() {
            if prec < min {
                break;
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
            _ => self.parse_postfix(),
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

    fn parse_args(&mut self) -> Result<Vec<Expr>> {
        let mut args = Vec::new();
        while !self.eat(&Tok::RParen) {
            args.push(self.parse_expr()?);
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
        let named = matches!(self.peek(), Tok::Ident(_)) && self.peek_at(1) == &Tok::Colon;
        if !named {
            return Ok(Expr::Call(name, generics, self.parse_args()?));
        }
        let mut fields = Vec::new();
        while !self.eat(&Tok::RParen) {
            let f = self.ident("field name (struct literals use `name: value` for every field)")?;
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
            Tok::Float(s) => Expr::Float(s),
            Tok::True => Expr::Bool(true),
            Tok::False => Expr::Bool(false),
            Tok::Str(s) => Expr::Str(parse_str(&s, line)?),
            Tok::Ident(mut s) => {
                while self.peek() == &Tok::PathSep && self.peek_at(1) != &Tok::Lt {
                    self.next();
                    s = format!("{s}::{}", self.ident("path segment")?);
                }
                Expr::Ident(s)
            }
            Tok::LParen => {
                let e = self.parse_expr()?;
                self.expect(Tok::RParen, "`)`")?;
                e
            }
            Tok::Match => self.parse_match(line)?,
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
                        let field = if matches!(self.peek(), Tok::Ident(_)) && self.peek_at(1) == &Tok::Colon {
                            let f = self.ident("field name")?;
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
fn parse_str(raw: &str, line: usize) -> Result<Vec<StrPart>> {
    let c: Vec<char> = raw.chars().collect();
    let mut parts = Vec::new();
    let mut lit = String::new();
    let mut i = 0;
    while i < c.len() {
        match c[i] {
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
                let (src, spec) = split_spec(&inner);
                if src.trim().is_empty() {
                    bail!("line {line}: empty `{{}}` in string; write `{{expr}}`");
                }
                let mut p = Parser { toks: lex_from(src, line)?, pos: 0 };
                let e = p.parse_expr()?;
                p.skip_newlines();
                if p.peek() != &Tok::Eof {
                    bail!("line {line}: invalid expression in string interpolation `{{{inner}}}`");
                }
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
        let p = prog("route GET \"/health\" -> str:\n    ret \"ok\"\nroute POST \"/users/{id}/events\" (id: u64, body: Event) -> Event!:\n    ret body\n");
        let Item::Route(r) = &p.items[1] else { panic!() };
        assert_eq!((r.method.as_str(), r.path.as_str(), r.params.len(), r.fallible), ("POST", "/users/{id}/events", 2, true));
        let err = |src: &str| parse(lex(src).unwrap()).unwrap_err().to_string();
        assert!(err("route GET \"/a/{id}\" -> str:\n    ret \"\"\n").contains("needs a typed parameter"));
        assert!(err("route GET \"/a\" (x: i32):\n    ret\n").contains("must be a path param"));
        assert!(err("route GET \"/a\":\n    ret\nroute GET \"/a\":\n    ret\n").contains("duplicate route"));
        assert!(err("route GET \"/a\":\n    ret\nfn main():\n    ret\n").contains("Parvez generates `main`"));
        assert!(err("route FETCH \"/a\":\n    ret\n").contains("unknown HTTP method"));
    }

    #[test]
    fn parse_errors() {
        assert!(parse(lex("x = 1\n").unwrap()).is_err());
        assert!(parse(lex("fn f(a):\n    ret\n").unwrap()).is_err());
        assert!(parse(lex("fn f()\n    ret\n").unwrap()).is_err());
    }
}
