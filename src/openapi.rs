//! `limen types --openapi`: an OpenAPI 3.1 description of a service, so tools and
//! AI agents (e.g. "code mode" clients that program against an API) can call it
//! without hand-written docs. Schemas follow serde's default wire format, like
//! the TypeScript export; access rules come from `@guard` / `@public`.
use crate::ast::*;
use anyhow::{Result, bail};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

fn qualified(module: &[String], name: &str) -> String {
    if module.is_empty() { name.into() } else { format!("{}::{name}", module.join("::")) }
}

fn option_inner(ty: &Type) -> Option<&Type> {
    match ty {
        Type::Opt(t) => Some(t),
        Type::Named(n, args) if n == "Option" && args.len() == 1 => args.first(),
        _ => None,
    }
}

/// @json models by qualified name -> schema name
struct Models(BTreeMap<String, String>);

impl Models {
    fn schema(&self, module: &[String], ty: &Type, generics: &[String]) -> Result<Value> {
        let rec = |t: &Type| self.schema(module, t, generics);
        Ok(match ty {
            Type::Named(n, a) if a.is_empty() && generics.contains(n) => json!({}),
            Type::Ref(t, _) => rec(t)?,
            Type::List(t) => json!({ "type": "array", "items": rec(t)? }),
            Type::Tuple(ts) if ts.is_empty() => json!({ "type": "null" }),
            Type::Tuple(ts) => {
                json!({ "type": "array", "prefixItems": ts.iter().map(rec).collect::<Result<Vec<_>>>()?, "items": false })
            }
            Type::Opt(t) => json!({ "anyOf": [rec(t)?, { "type": "null" }] }),
            Type::Named(n, args) => {
                if let Some(name) = self.0.get(&qualified(module, n)).or_else(|| self.0.get(n)) {
                    return Ok(json!({ "$ref": format!("#/components/schemas/{name}") }));
                }
                match (n.as_str(), args.as_slice()) {
                    ("i8" | "i16" | "i32" | "i64" | "i128" | "isize" | "u8" | "u16" | "u32" | "u64" | "u128" | "usize", []) => {
                        json!({ "type": "integer", "format": if n.contains("64") || n.contains("128") || n.ends_with("size") { "int64" } else { "int32" } })
                    }
                    ("f32" | "f64", []) => json!({ "type": "number" }),
                    ("str" | "String" | "char", []) => json!({ "type": "string" }),
                    ("Uuid" | "uuid::Uuid", []) => json!({ "type": "string", "format": "uuid" }),
                    ("NaiveDate" | "chrono::NaiveDate", []) => json!({ "type": "string", "format": "date" }),
                    ("DateTime" | "chrono::DateTime", [_]) => json!({ "type": "string", "format": "date-time" }),
                    ("bool", []) => json!({ "type": "boolean" }),
                    ("Secret", []) => json!({ "type": "string", "writeOnly": true }),
                    ("Value" | "serde_json::Value", []) => json!({}),
                    ("Option", [t]) => json!({ "anyOf": [rec(t)?, { "type": "null" }] }),
                    ("Vec", [t]) => json!({ "type": "array", "items": rec(t)? }),
                    ("Box", [t]) => rec(t)?,
                    ("HashMap" | "BTreeMap" | "std::collections::HashMap" | "std::collections::BTreeMap", [_, v]) => {
                        json!({ "type": "object", "additionalProperties": rec(v)? })
                    }
                    _ => bail!("no JSON schema for {n}; use a supported JSON type or an @json model"),
                }
            }
            Type::Fn(..) => bail!("functions have no JSON wire type"),
        })
    }
}

/// The success status a route sets with `status(N)`, if any.
fn status_of(body: &Block) -> Option<i64> {
    let mut found = None;
    visit_exprs(body, &mut |e| {
        if let Expr::Call(n, _, args) = e
            && n == "status"
            && let [Expr::Int(code)] = args.as_slice()
        {
            found = code.parse().ok();
        }
    });
    found
}

fn calls(body: &Block, names: &[&str]) -> bool {
    let mut found = false;
    visit_exprs(body, &mut |e| found |= matches!(e, Expr::Call(n, ..) if names.contains(&n.as_str())));
    found
}

pub fn generate(prog: &Program, title: &str) -> Result<String> {
    let items = prog.all_items();
    let mut models = Models(BTreeMap::new());
    for (module, item) in &items {
        let name = match item {
            Item::Struct(s) if s.attrs.json => &s.name,
            Item::Enum(e) if e.attrs.json => &e.name,
            _ => continue,
        };
        let q = qualified(module, name);
        let short_unique = items.iter().filter(|(_, i)| matches!(i, Item::Struct(s) if s.attrs.json && &s.name == name) || matches!(i, Item::Enum(e) if e.attrs.json && &e.name == name)).count() == 1;
        models.0.insert(q.clone(), if short_unique { name.clone() } else { q.replace("::", "_") });
    }
    let mut schemas = Map::new();
    schemas.insert(
        "Error".into(),
        json!({ "type": "object", "required": ["error"], "properties": { "error": { "type": "string" }, "code": { "type": "string", "description": "stable machine-readable code, when the service sets one" } } }),
    );
    for (module, item) in &items {
        let (name, generics, schema) = match item {
            Item::Struct(s) if s.attrs.json => {
                let generics: Vec<String> = s.generics.iter().map(|g| g.name.clone()).collect();
                let mut props = Map::new();
                let mut required = vec![];
                for ((field, t), attr) in s.fields.iter().zip(&s.field_attrs) {
                    let key = attr.rename.clone().unwrap_or_else(|| field.clone());
                    let inner = option_inner(t);
                    let shown = if attr.omit_none { inner.unwrap_or(t) } else { t };
                    props.insert(key.clone(), models.schema(module, shown, &generics)?);
                    if inner.is_none() && !attr.default {
                        required.push(key);
                    }
                }
                (&s.name, generics, json!({ "type": "object", "properties": props, "required": required }))
            }
            Item::Enum(e) if e.attrs.json => {
                let generics: Vec<String> = e.generics.iter().map(|g| g.name.clone()).collect();
                let mut one_of = vec![];
                for v in &e.variants {
                    one_of.push(match &v.data {
                        VariantData::Unit => json!({ "const": v.name }),
                        VariantData::Tuple(ts) => {
                            let inner = if ts.len() == 1 {
                                models.schema(module, &ts[0], &generics)?
                            } else {
                                json!({ "type": "array", "prefixItems": ts.iter().map(|t| models.schema(module, t, &generics)).collect::<Result<Vec<_>>>()?, "items": false })
                            };
                            json!({ "type": "object", "properties": { v.name.clone(): inner }, "required": [v.name], "additionalProperties": false })
                        }
                        VariantData::Named(fs) => {
                            let mut props = Map::new();
                            let mut req = vec![];
                            for (n, t) in fs {
                                props.insert(n.clone(), models.schema(module, t, &generics)?);
                                if option_inner(t).is_none() {
                                    req.push(n.clone());
                                }
                            }
                            json!({ "type": "object", "properties": { v.name.clone(): { "type": "object", "properties": props, "required": req } }, "required": [v.name], "additionalProperties": false })
                        }
                    });
                }
                (&e.name, generics, json!({ "oneOf": one_of }))
            }
            _ => continue,
        };
        let mut schema = schema;
        if !generics.is_empty() {
            schema["description"] = json!(format!("generic over {}: each use fills these in", generics.join(", ")));
        }
        schemas.insert(models.0[&qualified(module, name)].clone(), schema);
    }

    // guard fns that validate OpenID Connect tokens
    let mut bearer_guards = vec![];
    for (module, item) in &items {
        if let Item::Fn(f) = item
            && calls(&f.body, &["oidc", "oidc_session"])
        {
            bearer_guards.push(qualified(module, &f.name));
            bearer_guards.push(f.name.clone());
        }
    }
    let mut uses_bearer = false;
    let mut paths: BTreeMap<String, Map<String, Value>> = BTreeMap::new();
    for (module, item) in &items {
        let Item::Route(r) = item else { continue };
        if r.socket.is_some() {
            continue; // WebSockets aren't described by OpenAPI
        }
        let mut op = Map::new();
        let mut params = vec![];
        for (n, t) in &r.params {
            match n.as_str() {
                "body" => {
                    op.insert("requestBody".into(), json!({ "required": true, "content": { "application/json": { "schema": models.schema(module, t, &[])? } } }));
                }
                "query" => {
                    // a query struct's fields become query parameters
                    let fields = items.iter().find_map(|(m, i)| match (i, t) {
                        (Item::Struct(s), Type::Named(tn, _)) if (s.name == *tn || qualified(m, &s.name) == *tn) => Some((*m, s)),
                        _ => None,
                    });
                    if let Some((m, s)) = fields {
                        for ((field, ft), attr) in s.fields.iter().zip(&s.field_attrs) {
                            let required = option_inner(ft).is_none() && !attr.default;
                            params.push(json!({ "name": attr.rename.clone().unwrap_or_else(|| field.clone()), "in": "query", "required": required, "schema": models.schema(m, option_inner(ft).unwrap_or(ft), &[])? }));
                        }
                    }
                }
                _ => params.push(json!({ "name": n, "in": "path", "required": true, "schema": models.schema(module, t, &[])? })),
            }
        }
        if !params.is_empty() {
            op.insert("parameters".into(), Value::Array(params));
        }
        let ok = status_of(&r.body).unwrap_or(200).to_string();
        let mut responses = Map::new();
        let success = match (&r.ret, r.page) {
            (_, true) => json!({ "description": "HTML page", "content": { "text/html": { "schema": { "type": "string" } } } }),
            (None, _) => json!({ "description": "done" }),
            (Some(Type::Named(n, a)), _) if a.is_empty() && matches!(n.as_str(), "str" | "String") => {
                json!({ "description": "text", "content": { "text/plain": { "schema": { "type": "string" } } } })
            }
            (Some(t), _) => json!({ "description": "OK", "content": { "application/json": { "schema": models.schema(module, t, &[])? } } }),
        };
        responses.insert(ok, success);
        let error = json!({ "description": "error", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/Error" } } } });
        let access = match &r.public {
            Some(why) => {
                op.insert("security".into(), json!([]));
                json!({ "public": why })
            }
            None => {
                responses.insert("401".into(), json!({ "description": "not signed in", "content": error["content"].clone() }));
                responses.insert("403".into(), json!({ "description": "not allowed", "content": error["content"].clone() }));
                if r.guards.iter().any(|g| bearer_guards.contains(g)) {
                    uses_bearer = true;
                    op.insert("security".into(), json!([{ "bearer": [] }]));
                }
                json!({ "guards": r.guards })
            }
        };
        responses.insert("default".into(), error);
        op.insert("responses".into(), Value::Object(responses));
        op.insert("x-limen-access".into(), access);
        op.insert("operationId".into(), json!(format!("{} {}", r.method, r.path)));
        paths.entry(r.path.clone()).or_default().insert(r.method.to_lowercase(), Value::Object(op));
    }
    let mut components = json!({ "schemas": schemas });
    if uses_bearer {
        components["securitySchemes"] = json!({ "bearer": { "type": "http", "scheme": "bearer", "bearerFormat": "JWT", "description": "an OpenID Connect access token" } });
    }
    let doc = json!({
        "openapi": "3.1.0",
        "info": {
            "title": title,
            "version": "0.0.0",
            "description": "Generated by limen types --openapi. Every operation's x-limen-access says who may call it: its @guard functions, or why it's @public. Built-in endpoints (/healthz, /readyz, /metrics) aren't listed.",
        },
        "paths": paths,
        "components": components,
    });
    Ok(serde_json::to_string_pretty(&doc)? + "\n")
}
