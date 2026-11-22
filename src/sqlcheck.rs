//! SQL checked against the schema, offline, on every build. When `schema.sql` or
//! `migrations/*.sql` sits next to the program, every query whose SQL is a
//! literal (`sqlx::query`, `query_as`, `query_scalar`) is checked for:
//! - tables and columns that exist in the schema;
//! - the number of `$n` placeholders against the number of `.bind()` calls;
//! - bound values whose type doesn't fit the column they're compared with or written to;
//! - `query_as` result types: every field selected, with a fitting type, and
//!   `?` (Option) where the column can be NULL.
//! SQL the parser can't read is skipped, not guessed at.
use crate::ast::*;
use sqlparser::ast::{self as sql, Expr as SExpr, SelectItem, SetExpr, Statement, TableFactor, Value as SValue};
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;
use std::collections::HashMap;
use std::ops::ControlFlow;
use std::path::Path;

#[derive(Clone, Debug)]
struct Column {
    name: String,
    ty: String,
    nullable: bool,
}

#[derive(Default, Debug)]
pub struct Schema {
    tables: HashMap<String, Vec<Column>>,
    /// where the schema came from, for messages
    pub source: String,
}

fn lower(i: &sql::Ident) -> String {
    i.value.to_lowercase()
}

fn last(n: &sql::ObjectName) -> String {
    n.0.last().and_then(|p| p.as_ident()).map(lower).unwrap_or_default()
}

/// `schema.sql`, or `migrations/*.sql` in name order, next to the entry file.
pub fn load(entry: &Path) -> anyhow::Result<Option<Schema>> {
    let dir = entry.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let mut files = vec![];
    let single = dir.join("schema.sql");
    if single.is_file() {
        files.push(single);
    } else if dir.join("migrations").is_dir() {
        let mut m: Vec<_> = std::fs::read_dir(dir.join("migrations"))?
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e == "sql") && !p.to_string_lossy().ends_with(".down.sql"))
            .collect();
        m.sort();
        files = m;
    }
    if files.is_empty() {
        return Ok(None);
    }
    // `schema.sql`, `migrations/001.sql`: `/` on every platform, no leading `./`
    let shown = |f: &Path| {
        let s = f.display().to_string().replace('\\', "/");
        s.strip_prefix("./").map(str::to_string).unwrap_or(s)
    };
    let mut schema = Schema { source: files.iter().map(|f| shown(f)).collect::<Vec<_>>().join(", "), ..Default::default() };
    for f in &files {
        let text = std::fs::read_to_string(f)?;
        let stmts = Parser::parse_sql(&PostgreSqlDialect {}, &text)
            .map_err(|e| anyhow::anyhow!("{}: the schema couldn't be parsed: {e}", f.display()))?;
        for st in stmts {
            schema.apply(&st);
        }
    }
    Ok(Some(schema))
}

impl Schema {
    #[cfg(test)]
    pub fn from_sql(text: &str) -> anyhow::Result<Schema> {
        let mut s = Schema::default();
        for st in Parser::parse_sql(&PostgreSqlDialect {}, text)? {
            s.apply(&st);
        }
        Ok(s)
    }

    fn apply(&mut self, st: &Statement) {
        match st {
            Statement::CreateTable(ct) => {
                let pk: Vec<String> = ct
                    .constraints
                    .iter()
                    .flat_map(|c| match c {
                        sql::TableConstraint::PrimaryKey(p) => p.columns.iter().map(|c| c.column.expr.to_string().to_lowercase()).collect(),
                        _ => vec![],
                    })
                    .collect();
                let cols = ct
                    .columns
                    .iter()
                    .map(|c| {
                        let name = lower(&c.name);
                        let not_null = c.options.iter().any(|o| {
                            matches!(o.option, sql::ColumnOption::NotNull)
                                || matches!(&o.option, sql::ColumnOption::PrimaryKey(_))
                        });
                        Column { nullable: !not_null && !pk.contains(&name), ty: c.data_type.to_string().to_uppercase(), name }
                    })
                    .collect();
                self.tables.insert(last(&ct.name), cols);
            }
            Statement::AlterTable(at) => {
                let t = last(&at.name);
                for op in &at.operations {
                    if let sql::AlterTableOperation::AddColumn { column_def: c, .. } = op
                        && let Some(cols) = self.tables.get_mut(&t)
                    {
                        let not_null = c.options.iter().any(|o| matches!(o.option, sql::ColumnOption::NotNull));
                        cols.push(Column { name: lower(&c.name), ty: c.data_type.to_string().to_uppercase(), nullable: !not_null });
                    }
                }
            }
            _ => {}
        }
    }

    fn table(&self, t: &str) -> Option<&Vec<Column>> {
        self.tables.get(t)
    }
}

/// What one SQL statement selects, needs and binds.
struct Analysis {
    errors: Vec<String>,
    placeholders: usize,
    /// result columns (None = an expression we can't name or type)
    result: Option<Vec<Option<Column>>>,
    /// `$n` -> the column it's compared with or written to
    bound: HashMap<usize, (String, Column)>,
}

fn placeholder(e: &SExpr) -> Option<usize> {
    match e {
        SExpr::Value(v) => match &v.value {
            SValue::Placeholder(p) => p.strip_prefix('$').and_then(|n| n.parse().ok()),
            _ => None,
        },
        SExpr::Cast { expr, .. } | SExpr::Nested(expr) => placeholder(expr),
        _ => None,
    }
}

/// Every table (and alias) anywhere in a statement, subqueries included, and the
/// names of named function arguments (`make_interval(secs => $1)`), which aren't columns.
#[derive(Default)]
struct Collect {
    scope: HashMap<String, String>,
    arg_names: Vec<String>,
}

impl sql::Visitor for Collect {
    type Break = ();
    fn pre_visit_table_factor(&mut self, f: &TableFactor) -> ControlFlow<()> {
        if let TableFactor::Table { name, alias, .. } = f {
            let t = last(name);
            if let Some(al) = alias {
                self.scope.insert(lower(&al.name), t.clone());
            }
            self.scope.insert(t.clone(), t);
        }
        ControlFlow::Continue(())
    }
    fn pre_visit_expr(&mut self, e: &SExpr) -> ControlFlow<()> {
        if let SExpr::Function(f) = e
            && let sql::FunctionArguments::List(l) = &f.args
        {
            for a in &l.args {
                match a {
                    sql::FunctionArg::Named { name, .. } => self.arg_names.push(lower(name)),
                    sql::FunctionArg::ExprNamed { name: SExpr::Identifier(i), .. } => self.arg_names.push(lower(i)),
                    _ => {}
                }
            }
        }
        ControlFlow::Continue(())
    }
}

fn analyze(schema: &Schema, text: &str) -> Option<Analysis> {
    let stmts = Parser::parse_sql(&PostgreSqlDialect {}, text).ok()?;
    let [st] = stmts.as_slice() else { return None };
    let mut a = Analysis { errors: vec![], placeholders: 0, result: None, bound: HashMap::new() };

    // tables in scope: name or alias -> table name; CTE names are not schema tables
    let mut scope: HashMap<String, String> = HashMap::new();
    let mut ctes: Vec<String> = vec![];
    let add_factor = |f: &TableFactor, scope: &mut HashMap<String, String>| {
        if let TableFactor::Table { name, alias, .. } = f {
            let t = last(name);
            if let Some(al) = alias {
                scope.insert(lower(&al.name), t.clone());
            }
            scope.insert(t.clone(), t);
        }
    };
    let from_select = |s: &sql::Select, scope: &mut HashMap<String, String>| {
        for twj in &s.from {
            add_factor(&twj.relation, scope);
            for j in &twj.joins {
                add_factor(&j.relation, scope);
            }
        }
    };
    let mut target: Option<String> = None;
    let mut projection: Option<&Vec<SelectItem>> = None;
    match st {
        Statement::Query(q) => {
            if let Some(w) = &q.with {
                ctes.extend(w.cte_tables.iter().map(|c| lower(&c.alias.name)));
            }
            if let SetExpr::Select(s) = q.body.as_ref() {
                from_select(s, &mut scope);
                projection = Some(&s.projection);
            }
        }
        Statement::Insert(i) => {
            if let sql::TableObject::TableName(n) = &i.table {
                let t = last(n);
                scope.insert(t.clone(), t.clone());
                target = Some(t);
            }
            projection = i.returning.as_ref();
        }
        Statement::Update(u) => {
            add_factor(&u.table.relation, &mut scope);
            if let TableFactor::Table { name, .. } = &u.table.relation {
                target = Some(last(name));
            }
            projection = u.returning.as_ref();
        }
        Statement::Delete(d) => {
            let (sql::FromTable::WithFromKeyword(t) | sql::FromTable::WithoutKeyword(t)) = &d.from;
            for twj in t {
                add_factor(&twj.relation, &mut scope);
            }
            projection = d.returning.as_ref();
        }
        _ => return None,
    }

    let mut all = Collect::default();
    let _ = sql::Visit::visit(st, &mut all);
    for (k, v) in all.scope {
        scope.entry(k).or_insert(v);
    }
    let arg_names = all.arg_names;
    // every table exists
    let _ = sql::visit_relations(st, |r| {
        let t = last(r);
        if !ctes.contains(&t) && schema.table(&t).is_none() && !a.errors.iter().any(|e| e.contains(&format!("`{t}`"))) {
            a.errors.push(format!("table `{t}` isn't in the schema"));
        }
        ControlFlow::<()>::Continue(())
    });
    let mut tables: Vec<&String> = scope.values().filter(|t| schema.table(t).is_some()).collect();
    tables.sort();
    tables.dedup();
    let find = |col: &str| -> Option<(String, Column)> {
        tables.iter().find_map(|t| schema.table(t)?.iter().find(|c| c.name == col).map(|c| ((*t).clone(), c.clone())))
    };
    let aliases: Vec<String> = projection
        .into_iter()
        .flatten()
        .filter_map(|p| if let SelectItem::ExprWithAlias { alias, .. } = p { Some(lower(alias)) } else { None })
        .collect();
    let columns_of = |t: &str| schema.table(t).map(|c| c.iter().map(|c| c.name.clone()).collect::<Vec<_>>().join(", ")).unwrap_or_default();
    let qualified = |q: &str, c: &str| -> Result<Option<Column>, String> {
        let Some(t) = scope.get(q) else { return Ok(None) }; // a subquery alias: not checked
        match schema.table(t).and_then(|cs| cs.iter().find(|x| x.name == c)) {
            Some(col) => Ok(Some(col.clone())),
            None if schema.table(t).is_some() => Err(format!("column `{c}` isn't in table `{t}` (columns: {})", columns_of(t))),
            None => Ok(None),
        }
    };

    // every column exists; placeholders and what they're compared with
    let mut errors = vec![];
    let mut max_ph = 0;
    let mut bound = HashMap::new();
    let col_of = |e: &SExpr| -> Option<(String, Column)> {
        match e {
            SExpr::Identifier(i) => find(&lower(i)),
            SExpr::CompoundIdentifier(p) if p.len() == 2 => {
                let t = scope.get(&lower(&p[0]))?;
                schema.table(t)?.iter().find(|c| c.name == lower(&p[1])).map(|c| (t.clone(), c.clone()))
            }
            _ => None,
        }
    };
    let _ = sql::visit_expressions(st, |e| {
        if let Some(n) = placeholder(e) {
            max_ph = max_ph.max(n);
        }
        match e {
            SExpr::Identifier(i) if i.quote_style.is_none() || i.quote_style == Some('"') => {
                let c = lower(i);
                if !tables.is_empty() && find(&c).is_none() && !aliases.contains(&c) && !arg_names.contains(&c) && ctes.is_empty() {
                    let names: Vec<&str> = tables.iter().map(|t| t.as_str()).collect();
                    errors.push(format!("column `{c}` isn't in {} (columns: {})", names.iter().map(|t| format!("`{t}`")).collect::<Vec<_>>().join(", "), names.iter().map(|t| columns_of(t)).collect::<Vec<_>>().join("; ")));
                }
            }
            SExpr::CompoundIdentifier(p) if p.len() == 2 => {
                if let Err(m) = qualified(&lower(&p[0]), &lower(&p[1])) {
                    errors.push(m);
                }
            }
            SExpr::BinaryOp { left, right, .. } => {
                if let (Some(n), Some(c)) = (placeholder(right), col_of(left)) {
                    bound.insert(n, c);
                } else if let (Some(n), Some(c)) = (placeholder(left), col_of(right)) {
                    bound.insert(n, c);
                }
            }
            _ => {}
        }
        ControlFlow::<()>::Continue(())
    });
    // INSERT column lists and VALUES, UPDATE SET targets
    if let (Statement::Insert(i), Some(t)) = (st, &target)
        && let Some(cols) = schema.table(t)
    {
        let names: Vec<String> = i.columns.iter().map(last).collect();
        for n in &names {
            if !cols.iter().any(|c| &c.name == n) {
                errors.push(format!("column `{n}` isn't in table `{t}` (columns: {})", columns_of(t)));
            }
        }
        if let Some(src) = &i.source
            && let SetExpr::Values(v) = src.body.as_ref()
        {
            for row in &v.rows {
                if !names.is_empty() && row.len() != names.len() {
                    errors.push(format!("INSERT names {} columns but gives {} values", names.len(), row.len()));
                }
                for (val, n) in row.iter().zip(&names) {
                    if let (Some(k), Some(c)) = (placeholder(val), cols.iter().find(|c| &c.name == n)) {
                        bound.insert(k, (t.clone(), c.clone()));
                    }
                }
            }
        }
    }
    if let (Statement::Update(u), Some(t)) = (st, &target)
        && let Some(cols) = schema.table(t)
    {
        for asg in &u.assignments {
            if let sql::AssignmentTarget::ColumnName(n) = &asg.target {
                let n = last(n);
                match cols.iter().find(|c| c.name == n) {
                    None => errors.push(format!("column `{n}` isn't in table `{t}` (columns: {})", columns_of(t))),
                    Some(c) => {
                        if let Some(k) = placeholder(&asg.value) {
                            bound.insert(k, (t.clone(), c.clone()));
                        }
                    }
                }
            }
        }
    }
    // what the statement returns
    if let Some(items) = projection {
        let mut out = vec![];
        for it in items {
            match it {
                SelectItem::UnnamedExpr(e) => out.push(col_of(e).map(|(_, c)| c).or_else(|| {
                    // a column of a subquery or unknown table: its name is known, its type isn't
                    let name = match e {
                        SExpr::Identifier(i) => Some(lower(i)),
                        SExpr::CompoundIdentifier(p) => p.last().map(lower),
                        _ => None,
                    }?;
                    Some(Column { name, ty: String::new(), nullable: true })
                })),
                SelectItem::ExprWithAlias { expr, alias } => {
                    out.push(col_of(expr).map(|(_, c)| Column { name: lower(alias), ..c }).or(Some(Column { name: lower(alias), ty: String::new(), nullable: true })))
                }
                SelectItem::Wildcard(_) => {
                    for t in &tables {
                        out.extend(schema.table(t).into_iter().flatten().cloned().map(Some));
                    }
                }
                _ => out.push(None),
            }
        }
        a.result = Some(out);
    }
    errors.dedup();
    a.errors.extend(errors);
    a.placeholders = max_ph;
    a.bound = bound;
    Some(a)
}

/// The Parvez types a SQL column type accepts.
fn fits(sql_ty: &str, ty: &Type) -> Option<bool> {
    let base = match ty {
        Type::Ref(t, _) => return fits(sql_ty, t),
        Type::Opt(t) => return fits(sql_ty, t),
        Type::Named(n, a) if n == "Option" && a.len() == 1 => return fits(sql_ty, &a[0]),
        Type::Named(n, _) => n.rsplit("::").next().unwrap_or(n).to_string(),
        Type::List(t) if matches!(&**t, Type::Named(n, _) if n == "u8") => "bytes".into(),
        _ => return None,
    };
    let s = sql_ty.split('(').next().unwrap_or(sql_ty).trim();
    let want: &[&str] = match s {
        "TEXT" | "VARCHAR" | "CHARACTER VARYING" | "CHAR" | "CHARACTER" | "CITEXT" | "NAME" => &["str", "String"],
        "BIGINT" | "INT8" | "BIGSERIAL" | "SERIAL8" => &["i64"],
        "INT" | "INTEGER" | "INT4" | "SERIAL" | "SERIAL4" => &["i32"],
        "SMALLINT" | "INT2" | "SMALLSERIAL" => &["i16"],
        "BOOLEAN" | "BOOL" => &["bool"],
        "REAL" | "FLOAT4" => &["f32"],
        "DOUBLE PRECISION" | "FLOAT8" => &["f64"],
        "UUID" => &["Uuid"],
        "BYTEA" => &["bytes"],
        "JSON" | "JSONB" => &["Value"],
        "TIMESTAMPTZ" | "TIMESTAMP WITH TIME ZONE" => &["DateTime"],
        "TIMESTAMP" | "TIMESTAMP WITHOUT TIME ZONE" => &["NaiveDateTime"],
        "DATE" => &["NaiveDate"],
        _ => return None, // a type we don't map: not checked
    };
    Some(want.contains(&base.as_str()))
}

fn shown(t: &Type) -> String {
    match t {
        Type::Named(n, a) if a.is_empty() => n.clone(),
        Type::Named(n, a) => format!("{n}<{}>", a.iter().map(shown).collect::<Vec<_>>().join(", ")),
        Type::Ref(x, _) => shown(x),
        Type::List(x) => format!("[{}]", shown(x)),
        Type::Opt(x) => format!("{}?", shown(x)),
        _ => "?".into(),
    }
}

/// A query call chain: the SQL literal, the bind arguments, the root function, the fetch method.
fn query_chain(e: &Expr) -> Option<(String, Vec<&Expr>, String, Option<String>, Option<Type>)> {
    let mut e = e;
    let mut binds = vec![];
    let mut fetch = None;
    loop {
        match e {
            Expr::Try(x) | Expr::Await(x) => e = x,
            Expr::Method(recv, m, _, args) => {
                if m == "bind"
                    && let [a] = args.as_slice()
                {
                    binds.push(a);
                } else if m.starts_with("fetch") {
                    fetch = Some(m.clone());
                }
                e = recv;
            }
            Expr::Call(name, generics, args) => {
                let f = name.rsplit("::").next().unwrap_or(name);
                if !matches!(f, "query" | "query_as" | "query_scalar") {
                    return None;
                }
                let Some(Expr::Str(parts)) = args.first() else { return None };
                let [StrPart::Lit(text)] = parts.as_slice() else { return None };
                binds.reverse();
                // `query_as<_, Device>(...)`: the row type, spelled out
                let row = generics.last().filter(|t| !matches!(t, Type::Named(n, _) if n == "_")).cloned();
                return Some((unescape(text), binds, f.to_string(), fetch, row));
            }
            _ => return None,
        }
    }
}

/// String literals keep their source escapes (`\n`, `\"`, `\u{..}`); SQL needs the real text.
fn unescape(s: &str) -> String {
    let mut out = String::new();
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match it.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('0') => out.push('\0'),
            Some('u') if it.peek() == Some(&'{') => {
                it.next();
                let hex: String = it.by_ref().take_while(|c| *c != '}').collect();
                out.extend(u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32));
            }
            Some(other) => out.push(other),
            None => out.push('\\'),
        }
    }
    out
}

/// One literal query, for checking against a live database (`parvez check --db`).
pub struct Site {
    pub line: usize,
    pub sql: String,
    /// the Parvez type of each bound value, where known
    binds: Vec<Option<Type>>,
    /// `query_as` row type: (struct name, fields)
    row: Option<(String, Vec<(String, Type)>)>,
}

/// How many of the program's SQL calls were actually checked. Every call to
/// `query` / `query_as` / `query_scalar` counts, wherever it is.
#[derive(Debug, Default)]
pub struct Coverage {
    pub recognized: usize,
    pub checked: usize,
    /// SQL that isn't a literal (built at run time, or passed in a variable)
    pub not_literal: Vec<usize>,
    /// literal SQL the parser couldn't read
    pub unparsed: Vec<usize>,
}

struct Ctx<'a> {
    schema: &'a Schema,
    structs: HashMap<String, &'a StructDef>,
    errors: Vec<(usize, String)>,
    sites: Vec<Site>,
    cov: Coverage,
}

fn is_sql_call(name: &str) -> bool {
    let f = name.rsplit("::").next().unwrap_or(name);
    matches!(f, "query" | "query_as" | "query_scalar") && (name.starts_with("sqlx::") || !name.contains("::"))
}

impl Ctx<'_> {
    fn type_of(&self, e: &Expr, vars: &HashMap<String, Type>) -> Option<Type> {
        match e {
            Expr::Ref(x, _) => self.type_of(x, vars),
            Expr::Ident(n) => vars.get(n).cloned(),
            Expr::Str(_) => Some(Type::Named("str".into(), vec![])),
            Expr::Bool(_) => Some(Type::Named("bool".into(), vec![])),
            Expr::Field(x, f) => {
                // the verified identity: `auth.sub` etc. are strings
                if matches!(&**x, Expr::Ident(n) if n == "auth")
                    && matches!(f.as_str(), "sub" | "email" | "name" | "username")
                    && !vars.contains_key("auth")
                {
                    return Some(Type::Named("str".into(), vec![]));
                }
                let Type::Named(sn, _) = self.type_of(x, vars)? else { return None };
                let s = self.structs.get(sn.rsplit("::").next().unwrap_or(&sn))?;
                s.fields.iter().find(|(n, _)| n == f).map(|(_, t)| t.clone())
            }
            Expr::Method(x, m, _, _) if matches!(m.as_str(), "clone" | "to_string" | "as_str") => self.type_of(x, vars),
            _ => None,
        }
    }

    fn check_query(&mut self, line: usize, e: &Expr, expected: Option<&Type>, vars: &HashMap<String, Type>) {
        let Some((text, binds, func, fetch, row_type)) = query_chain(e) else { return };
        // the row type, from `query_as<_, T>`, a typed `let` or the function's return type
        let inner = |t: &'_ Type, wrapper: &str| -> Option<Type> {
            match t {
                Type::List(x) if wrapper == "Vec" => Some((**x).clone()),
                Type::Opt(x) if wrapper == "Option" => Some((**x).clone()),
                Type::Named(n, a) if n == wrapper && a.len() == 1 => Some(a[0].clone()),
                _ => None,
            }
        };
        let row_ty = row_type.clone().or_else(|| match (fetch.as_deref(), expected) {
            (Some("fetch_all"), Some(t)) => inner(t, "Vec"),
            (Some("fetch_optional"), Some(t)) => inner(t, "Option"),
            (Some("fetch_one"), Some(t)) => Some(t.clone()),
            _ => None,
        });
        let row_struct = match (&row_ty, func.as_str()) {
            (Some(Type::Named(sn, _)), "query_as") => {
                self.structs.get(sn.rsplit("::").next().unwrap_or(sn)).map(|s| (s.name.clone(), s.fields.clone()))
            }
            _ => None,
        };
        self.sites.push(Site { line, sql: text.clone(), binds: binds.iter().map(|b| self.type_of(b, vars)).collect(), row: row_struct });
        self.cov.recognized += 1;
        let Some(a) = analyze(self.schema, &text) else {
            self.cov.unparsed.push(line);
            return;
        };
        self.cov.checked += 1;
        for m in a.errors {
            self.errors.push((line, format!("SQL: {m}")));
        }
        if a.placeholders != binds.len() {
            self.errors.push((line, format!("SQL uses {} parameter(s) ($1..${}) but {} value(s) are bound with .bind()", a.placeholders, a.placeholders, binds.len())));
        }
        for (k, arg) in binds.iter().enumerate() {
            let Some((t, col)) = a.bound.get(&(k + 1)) else { continue };
            let Some(ty) = self.type_of(arg, vars) else { continue };
            if fits(&col.ty, &ty) == Some(false) {
                self.errors.push((line, format!("SQL: ${} is `{t}.{}` ({}), but the value bound is {}", k + 1, col.name, col.ty, shown(&ty))));
            }
        }
        // query_as: the result type's fields against the selected columns
        if func != "query_as" {
            return;
        }
        let Some(result) = a.result else { return };
        let inner = |t: &'_ Type, wrapper: &str| -> Option<Type> {
            match t {
                Type::List(x) if wrapper == "Vec" => Some((**x).clone()),
                Type::Opt(x) if wrapper == "Option" => Some((**x).clone()),
                Type::Named(n, a) if n == wrapper && a.len() == 1 => Some(a[0].clone()),
                _ => None,
            }
        };
        let row = row_type.or_else(|| match (fetch.as_deref(), expected) {
            (Some("fetch_all"), Some(t)) => inner(t, "Vec"),
            (Some("fetch_optional"), Some(t)) => inner(t, "Option"),
            (Some("fetch_one"), Some(t)) => Some(t.clone()),
            _ => None,
        });
        let Some(row) = row else { return };
        let row = &row;
        let Type::Named(sn, _) = row else { return };
        let Some(s) = self.structs.get(sn.rsplit("::").next().unwrap_or(sn)) else { return };
        // an unnamed expression could supply any field: then only named columns are checked
        let complete = result.iter().all(Option::is_some);
        let cols: Vec<Column> = result.into_iter().flatten().collect();
        for (field, fty) in &s.fields {
            match cols.iter().find(|c| &c.name == field) {
                None if !complete => {}
                None => self.errors.push((
                    line,
                    format!("SQL: `{}.{field}` isn't selected (the query returns {})", s.name, cols.iter().map(|c| c.name.as_str()).collect::<Vec<_>>().join(", ")),
                )),
                Some(c) => {
                    if !c.ty.is_empty() && fits(&c.ty, fty) == Some(false) {
                        self.errors.push((line, format!("SQL: `{}.{field}` is {} but the column is {}", s.name, shown(fty), c.ty)));
                    }
                    let optional = matches!(fty, Type::Opt(_)) || matches!(fty, Type::Named(n, a) if n == "Option" && a.len() == 1);
                    if c.nullable && !optional && !c.ty.is_empty() {
                        self.errors.push((line, format!("SQL: column `{field}` can be NULL (no NOT NULL in the schema), so `{}.{field}` must be `{}?`", s.name, shown(fty))));
                    }
                }
            }
        }
    }

    // The walk is an exhaustive match over every statement and expression form
    // (no `_ =>` arms): new syntax doesn't compile until it's handled here, so
    // no query can sit somewhere this check never looks.
    fn block(&mut self, b: &Block, vars: &mut HashMap<String, Type>, ret: Option<&Type>) {
        for s in b {
            let l = s.line;
            match &s.stmt {
                Stmt::Render(parts) => {
                    for p in parts {
                        match p {
                            HtmlPart::Value(e, _) => self.walk(e, l, None, vars, ret),
                            HtmlPart::Markup(_) => {}
                        }
                    }
                }
                Stmt::Let { name, ty, value, .. } => {
                    self.walk(value, l, ty.as_ref(), vars, ret);
                    if let Some(t) = ty {
                        vars.insert(name.clone(), t.clone());
                    }
                }
                Stmt::Assign { target, value, .. } => {
                    self.walk(target, l, None, vars, ret);
                    self.walk(value, l, None, vars, ret);
                }
                Stmt::Expr(e) | Stmt::LetTuple { value: e, .. } => self.walk(e, l, None, vars, ret),
                Stmt::Ret(Some(e)) => self.walk(e, l, ret, vars, ret),
                Stmt::Ret(None) | Stmt::Break | Stmt::Continue => {}
                Stmt::If { branches, els } => {
                    for (c, b) in branches {
                        self.walk(c, l, None, vars, ret);
                        self.block(b, &mut vars.clone(), ret);
                    }
                    if let Some(b) = els {
                        self.block(b, &mut vars.clone(), ret);
                    }
                }
                Stmt::For { iter, body, .. } => {
                    self.walk(iter, l, None, vars, ret);
                    self.block(body, &mut vars.clone(), ret);
                }
                Stmt::While { cond, body } => {
                    self.walk(cond, l, None, vars, ret);
                    self.block(body, &mut vars.clone(), ret);
                }
                Stmt::Loop(body) => self.block(body, &mut vars.clone(), ret),
            }
        }
    }

    fn closure(&mut self, b: &ClosureBody, line: usize, vars: &HashMap<String, Type>, ret: Option<&Type>) {
        match b {
            ClosureBody::Expr(x) => self.walk(x, line, None, vars, ret),
            ClosureBody::Block(b) => self.block(b, &mut vars.clone(), None),
        }
    }

    fn walk(&mut self, e: &Expr, line: usize, expected: Option<&Type>, vars: &HashMap<String, Type>, ret: Option<&Type>) {
        if query_chain(e).is_some() {
            self.check_query(line, e, expected, vars);
            return;
        }
        let w = |this: &mut Self, x: &Expr| this.walk(x, line, None, vars, ret);
        match e {
            Expr::Call(name, _, args) => {
                if is_sql_call(name) {
                    self.cov.recognized += 1;
                    self.cov.not_literal.push(line);
                }
                for a in args {
                    w(self, a);
                }
            }
            Expr::Method(x, _, _, args) => {
                w(self, x);
                for a in args {
                    w(self, a);
                }
            }
            Expr::If(c, a, b) => {
                w(self, c);
                w(self, a);
                w(self, b);
            }
            Expr::LetPat(_, x)
            | Expr::Unary(_, x)
            | Expr::Ref(x, _)
            | Expr::Field(x, _)
            | Expr::Try(x)
            | Expr::Await(x)
            | Expr::Named(_, x)
            | Expr::Cast(x, _) => w(self, x),
            Expr::Binary(a, _, b) | Expr::Range(a, b, _) | Expr::Index(a, b) => {
                w(self, a);
                w(self, b);
            }
            Expr::List(xs) | Expr::Tuple(xs) => {
                for x in xs {
                    w(self, x);
                }
            }
            Expr::StructLit(_, fs) => {
                for (_, x) in fs {
                    w(self, x);
                }
            }
            Expr::Map(kvs) => {
                for (k, v) in kvs {
                    w(self, k);
                    w(self, v);
                }
            }
            Expr::Str(parts) => {
                for p in parts {
                    match p {
                        StrPart::Interp(x, _) => w(self, x),
                        StrPart::Lit(_) => {}
                    }
                }
            }
            Expr::Match(x, arms) => {
                w(self, x);
                for a in arms {
                    if let Some(g) = &a.guard {
                        self.walk(g, a.line, None, vars, ret);
                    }
                    self.block(&a.body, &mut vars.clone(), ret);
                }
            }
            Expr::Closure { body, .. } | Expr::Spawn(body) => self.closure(body, line, vars, ret),
            Expr::Catch { expr, handler, .. } => {
                w(self, expr);
                self.closure(handler, line, vars, ret);
            }
            Expr::Int(_) | Expr::Float(_) | Expr::Char(_) | Expr::Bool(_) | Expr::Ident(_) => {}
        }
    }
}

/// Check every literal query in the program. Returns (encoded line, message).
pub fn check(prog: &Program, schema: &Schema) -> (Vec<(usize, String)>, Coverage) {
    let (errors, _, cov) = scan(prog, schema);
    (errors, cov)
}

/// Every literal query in the program, for `parvez check --db`.
pub fn sites(prog: &Program) -> Vec<Site> {
    scan(prog, &Schema::default()).1
}

/// Compare what the database says about each query (`describe`: the same thing
/// `sqlx::query!` asks) with the program: errors from the database itself,
/// parameter count and types, and `query_as` fields (name, type, NULL).
pub fn compare_with_db(sites: &[Site], described: &[serde_json::Value]) -> Vec<(usize, String)> {
    let mut out = vec![];
    for (site, d) in sites.iter().zip(described) {
        if let Some(e) = d["error"].as_str() {
            out.push((site.line, format!("SQL (database): {e}")));
            continue;
        }
        let params: Vec<&str> = d["params"].as_array().into_iter().flatten().filter_map(|p| p.as_str()).collect();
        if params.len() != site.binds.len() {
            out.push((site.line, format!("SQL (database): the query takes {} parameter(s) but {} value(s) are bound", params.len(), site.binds.len())));
        }
        for (k, (p, b)) in params.iter().zip(&site.binds).enumerate() {
            if let Some(t) = b
                && fits(&p.to_uppercase(), t) == Some(false)
            {
                out.push((site.line, format!("SQL (database): ${} is {p}, but the value bound is {}", k + 1, shown(t))));
            }
        }
        let Some((sname, fields)) = &site.row else { continue };
        let cols = d["columns"].as_array().cloned().unwrap_or_default();
        let names: Vec<&str> = cols.iter().filter_map(|c| c["name"].as_str()).collect();
        for (field, fty) in fields {
            let Some(c) = cols.iter().find(|c| c["name"].as_str() == Some(field)) else {
                out.push((site.line, format!("SQL (database): `{sname}.{field}` isn't selected (the query returns {})", names.join(", "))));
                continue;
            };
            let cty = c["type"].as_str().unwrap_or("").to_uppercase();
            if fits(&cty, fty) == Some(false) {
                out.push((site.line, format!("SQL (database): `{sname}.{field}` is {} but the column is {cty}", shown(fty))));
            }
            let optional = matches!(fty, Type::Opt(_)) || matches!(fty, Type::Named(n, a) if n == "Option" && a.len() == 1);
            if c["nullable"].as_bool() == Some(true) && !optional {
                out.push((site.line, format!("SQL (database): column `{field}` can be NULL, so `{sname}.{field}` must be `{}?`", shown(fty))));
            }
        }
    }
    out
}

fn scan(prog: &Program, schema: &Schema) -> (Vec<(usize, String)>, Vec<Site>, Coverage) {
    let items = prog.all_items();
    let structs = items
        .iter()
        .filter_map(|(_, i)| if let Item::Struct(s) = i { Some((s.name.clone(), s)) } else { None })
        .collect();
    let mut cx = Ctx { schema, structs, errors: vec![], sites: vec![], cov: Coverage::default() };
    let fn_body = |cx: &mut Ctx, f: &FnDef| {
        let mut vars: HashMap<String, Type> = f.params.iter().cloned().collect();
        cx.block(&f.body, &mut vars, f.ret.as_ref());
    };
    // every item that can hold code, tests included
    for (_, item) in &items {
        match item {
            Item::Route(r) => {
                let mut vars: HashMap<String, Type> = r.params.iter().cloned().collect();
                cx.block(&r.body, &mut vars, r.ret.as_ref());
            }
            Item::Fn(f) => fn_body(&mut cx, f),
            Item::Impl(i) => i.methods.iter().for_each(|m| fn_body(&mut cx, m)),
            Item::Trait(t) => t.methods.iter().for_each(|m| fn_body(&mut cx, m)),
            Item::Every(e) => cx.block(&e.body, &mut HashMap::new(), None),
            Item::Test(t) => cx.block(&t.body, &mut HashMap::new(), None),
            Item::State(st) => {
                for (_, ty, value, line) in &st.fields {
                    cx.walk(value, *line, Some(ty), &HashMap::new(), None);
                }
            }
            Item::Const { value, ty, line, .. } => cx.walk(value, *line, Some(ty), &HashMap::new(), None),
            Item::Struct(_) | Item::Enum(_) | Item::Use(_) | Item::Import(_) | Item::Embed { .. } => {}
        }
    }
    cx.errors.sort();
    cx.errors.dedup();
    (cx.errors, cx.sites, cx.cov)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{lexer::lex, parser::parse};

    const SCHEMA: &str = "CREATE TABLE tasks (id BIGSERIAL PRIMARY KEY, owner TEXT NOT NULL, title TEXT NOT NULL, done BOOLEAN NOT NULL DEFAULT false, note TEXT);
        CREATE TABLE users (id BIGINT PRIMARY KEY, name TEXT NOT NULL);
        ALTER TABLE tasks ADD COLUMN priority INT NOT NULL DEFAULT 0;";

    fn errors(body: &str) -> Vec<String> {
        let src = format!(
            "@derive(sqlx::FromRow)\ntype Task: id: i64, title: str, done: bool\n@derive(sqlx::FromRow)\ntype Noted: id: i64, note: str\n\
             state:\n    db: sqlx::PgPool = sqlx::PgPool::connect_lazy(\"x\")?\n@public\nroute GET \"/t/{{id}}/{{name}}\" (state, id: i64, name: str) -> [Task]!:\n{body}"
        );
        let prog = parse(lex(&src).unwrap()).unwrap();
        check(&prog, &Schema::from_sql(SCHEMA).unwrap()).0.into_iter().map(|(_, m)| m).collect()
    }

    #[test]
    fn correct_queries_pass() {
        let ok = errors(
            "    a: [Task] = sqlx::query_as(\"SELECT id, title, done FROM tasks WHERE owner = $1 AND id > $2\").bind(&name).bind(id).fetch_all(&state.db).await?\n\
             \x20   b: Task? = sqlx::query_as(\"UPDATE tasks SET done = $1 WHERE id = $2 RETURNING id, title, done\").bind(true).bind(id).fetch_optional(&state.db).await?\n\
             \x20   sqlx::query(\"INSERT INTO tasks (owner, title) VALUES ($1, $2)\").bind(&name).bind(&name).execute(&state.db).await?\n\
             \x20   c: [Task] = sqlx::query_as(\"SELECT t.id, t.title, t.done FROM tasks t JOIN users u ON u.id = t.id ORDER BY t.priority\").fetch_all(&state.db).await?\n\
             \x20   ret sqlx::query_as(\"SELECT * FROM tasks\").fetch_all(&state.db).await?\n",
        );
        assert!(ok.is_empty(), "{ok:?}");
    }

    #[test]
    fn names_counts_types_and_rows_are_checked() {
        let e = errors("    ret sqlx::query_as(\"SELECT id, titel, done FROM tasks\").fetch_all(&state.db).await?\n");
        assert!(e.iter().any(|m| m.contains("column `titel` isn't in `tasks`")), "{e:?}");
        let e = errors("    ret sqlx::query_as(\"SELECT id, title, done FROM taks\").fetch_all(&state.db).await?\n");
        assert!(e.iter().any(|m| m.contains("table `taks` isn't in the schema")), "{e:?}");
        let e = errors("    ret sqlx::query_as(\"SELECT id, title, done FROM tasks WHERE owner = $1 AND id = $2\").bind(&name).fetch_all(&state.db).await?\n");
        assert!(e.iter().any(|m| m.contains("uses 2 parameter(s)") && m.contains("1 value(s)")), "{e:?}");
        let e = errors("    ret sqlx::query_as(\"SELECT id, title, done FROM tasks WHERE id = $1\").bind(&name).fetch_all(&state.db).await?\n");
        assert!(e.iter().any(|m| m.contains("$1 is `tasks.id` (BIGSERIAL), but the value bound is str")), "{e:?}");
        let e = errors("    ret sqlx::query_as(\"SELECT id, done FROM tasks\").fetch_all(&state.db).await?\n");
        assert!(e.iter().any(|m| m.contains("`Task.title` isn't selected (the query returns id, done)")), "{e:?}");
        let e = errors("    x: [Noted] = sqlx::query_as(\"SELECT id, note FROM tasks\").fetch_all(&state.db).await?\n    ret []\n");
        assert!(e.iter().any(|m| m.contains("column `note` can be NULL") && m.contains("`Noted.note` must be `str?`")), "{e:?}");
        let e = errors("    sqlx::query(\"INSERT INTO tasks (owner, titel) VALUES ($1, $2)\").bind(&name).bind(&name).execute(&state.db).await?\n    ret []\n");
        assert!(e.iter().any(|m| m.contains("column `titel` isn't in table `tasks`")), "{e:?}");
        let e = errors("    sqlx::query(\"UPDATE tasks SET done = $1 WHERE id = $2\").bind(&name).bind(id).execute(&state.db).await?\n    ret []\n");
        assert!(e.iter().any(|m| m.contains("$1 is `tasks.done` (BOOLEAN), but the value bound is str")), "{e:?}");
        let e = errors("    ret sqlx::query_as(\"SELECT t.id, t.titel, t.done FROM tasks t\").fetch_all(&state.db).await?\n");
        assert!(e.iter().any(|m| m.contains("column `titel` isn't in table `tasks`")), "{e:?}");
        // SQL the parser can't read is skipped, not guessed at (and counted: see coverage_counts_every_query)
        assert!(errors("    ret sqlx::query_as(\"SELECT FROM WHERE (((\").fetch_all(&state.db).await?\n").is_empty());
    }

    #[test]
    fn queries_in_nested_code_are_checked() {
        // match arms, closures, spawn and test blocks: each was invisible before v0.21
        for (label, code) in [
            ("match arm", "    m = match id:\n        1 -> sqlx::query(\"SELECT titel FROM tasks\").execute(&state.db)\n        _ -> sqlx::query(\"SELECT 1\").execute(&state.db)\n    ret []\n"),
            ("closure", "    f = |x: i64| sqlx::query(\"SELECT titel FROM tasks WHERE id = $1\").bind(x)\n    ret []\n"),
            ("spawn", "    h = spawn:\n        sqlx::query(\"SELECT titel FROM tasks\").execute(&state.db).await\n    ret []\n"),
        ] {
            let e = errors(code);
            assert!(e.iter().any(|m| m.contains("column `titel` isn't in `tasks`")), "{label}: {e:?}");
        }
    }

    #[test]
    fn coverage_counts_every_query() {
        let src = "state:\n    db: sqlx::PgPool = sqlx::PgPool::connect_lazy(\"x\")?\n@public\nroute GET \"/t\" (state) -> str!:\n    \
            sqlx::query(\"SELECT id FROM tasks\").execute(&state.db).await?\n    \
            sqlx::query(\"SELECT FROM WHERE (((\").execute(&state.db).await?\n    \
            q = \"SELECT 1\"\n    sqlx::query(&q).execute(&state.db).await?\n    ret \"ok\"\n\
            test \"sql in a test\":\n    sqlx::query(\"SELECT titel FROM tasks\").execute(&pool).await?\n";
        let prog = parse(lex(src).unwrap()).unwrap();
        let (errs, cov) = check(&prog, &Schema::from_sql(SCHEMA).unwrap());
        assert_eq!((cov.recognized, cov.checked, cov.unparsed.len(), cov.not_literal.len()), (4, 2, 1, 1), "{cov:?}");
        assert!(errs.iter().any(|(_, m)| m.contains("column `titel`")), "SQL in tests is checked too: {errs:?}");
    }
}
