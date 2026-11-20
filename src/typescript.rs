//! TypeScript declarations for serde's default (externally tagged) wire format.
use crate::ast::*;
use anyhow::{Context, Result, bail};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;

fn quoted(value: &str) -> String {
    serde_json::Value::String(value.into()).to_string()
}

fn qualified(module: &[String], name: &str) -> String {
    if module.is_empty() {
        name.into()
    } else {
        format!("{}::{name}", module.join("::"))
    }
}

fn option_inner(ty: &Type) -> Option<&Type> {
    match ty {
        Type::Opt(t) => Some(t),
        Type::Named(n, args) if n == "Option" && args.len() == 1 => args.first(),
        _ => None,
    }
}

/// model names, plus the generic parameters of the model being declared
struct Names(BTreeMap<String, String>, Vec<String>);
impl Names {
    fn ty(&self, module: &[String], ty: &Type, input: bool) -> Result<String> {
        let recurse = |t: &Type| self.ty(module, t, input);
        Ok(match ty {
            Type::Named(n, args) if args.is_empty() && self.1.contains(n) => n.clone(),
            Type::Ref(t, _) => recurse(t)?,
            Type::List(t) => format!("Array<{}>", recurse(t)?),
            Type::Tuple(ts) if ts.is_empty() => "null".into(),
            Type::Tuple(ts) => format!("[{}]", ts.iter().map(recurse).collect::<Result<Vec<_>>>()?.join(", ")),
            Type::Opt(t) => format!("{} | null", recurse(t)?),
            Type::Named(n, args) => {
                let model = self.0.get(&qualified(module, n)).or_else(|| self.0.get(n));
                match (n.as_str(), args.as_slice()) {
                    (_, []) if model.is_some() => format!("{}{}", model.unwrap(), if input { "Input" } else { "" }),
                    (_, args) if model.is_some() => {
                        let a = args.iter().map(recurse).collect::<Result<Vec<_>>>()?;
                        format!("{}{}<{}>", model.unwrap(), if input { "Input" } else { "" }, a.join(", "))
                    }
                    (
                        "i8" | "i16" | "i32" | "i64" | "i128" | "isize" | "u8" | "u16" | "u32" | "u64" | "u128"
                        | "usize" | "f32" | "f64",
                        [],
                    ) => "number".into(),
                    ("str" | "String" | "char" | "Uuid" | "uuid::Uuid" | "NaiveDate" | "chrono::NaiveDate", []) => {
                        "string".into()
                    }
                    ("DateTime" | "chrono::DateTime", [_]) => "string".into(),
                    ("bool", []) => "boolean".into(),
                    ("Value" | "serde_json::Value", []) => "unknown".into(),
                    ("Option", [t]) => format!("{} | null", recurse(t)?),
                    ("Vec", [t]) => format!("Array<{}>", recurse(t)?),
                    ("Box", [t]) => recurse(t)?,
                    ("HashMap" | "BTreeMap" | "std::collections::HashMap" | "std::collections::BTreeMap", [_, v]) => {
                        format!("Record<string, {}>", recurse(v)?)
                    }
                    _ => bail!("no TypeScript wire type for {n}; use a supported JSON type or @json model"),
                }
            }
            Type::Fn(..) => bail!("functions have no JSON wire type"),
        })
    }
}

pub fn generate(prog: &Program) -> Result<String> {
    let items = prog.all_items();
    let mut models = BTreeMap::new();
    for (module, item) in &items {
        let name = match item {
            Item::Struct(s) if s.attrs.json => &s.name,
            Item::Enum(e) if e.attrs.json => &e.name,
            _ => continue,
        };
        if models.insert(qualified(module, name), (*module, *item, name)).is_some() {
            bail!("duplicate @json model {name}");
        }
    }
    let mut names = Names(BTreeMap::new(), Vec::new());
    let mut used: BTreeSet<String> = ["Routes", "Array", "Record"].map(String::from).into();
    for (q, (_, _, short)) in &models {
        let unique = models.values().filter(|(_, _, n)| n == short).count() == 1;
        let mut name = if unique {
            short.to_string()
        } else {
            q.replace("::", "_")
        };
        // A prefix also avoids TypeScript keywords used as lower-case model names.
        if !name.starts_with(|c: char| c.is_ascii_uppercase()) {
            name = format!("Model_{name}");
        }
        while used.contains(&name) || used.contains(&format!("{name}Input")) {
            name.push('_');
        }
        used.insert(name.clone());
        used.insert(format!("{name}Input"));
        names.0.insert(q.clone(), name);
    }
    let mut out = String::new();
    for (q, (module, item, _)) in &models {
        let name = &names.0[q].clone();
        let generics: Vec<String> = match item {
            Item::Struct(s) => s.generics.iter().map(|g| g.name.clone()).collect(),
            Item::Enum(e) => e.generics.iter().map(|g| g.name.clone()).collect(),
            _ => vec![],
        };
        names.1 = generics.clone();
        let params = if generics.is_empty() { String::new() } else { format!("<{}>", generics.join(", ")) };
        let mut output = String::new();
        for input in [false, true] {
            let decl = match item {
                Item::Struct(s) => {
                    let mut fields = String::new();
                    for ((field, t), attr) in s.fields.iter().zip(&s.field_attrs) {
                        let inner = option_inner(t);
                        let optional = if input {
                            attr.default || inner.is_some()
                        } else {
                            attr.omit_none
                        };
                        let t = if !input && attr.omit_none {
                            inner.unwrap_or(t)
                        } else {
                            t
                        };
                        writeln!(
                            fields,
                            "  {}{}: {};",
                            quoted(attr.rename.as_ref().unwrap_or(field)),
                            if optional { "?" } else { "" },
                            names.ty(module, t, input).with_context(|| format!("{q}.{field}"))?
                        )?;
                    }
                    format!("{{\n{fields}}}")
                }
                Item::Enum(e) => {
                    let mut variants = vec![];
                    for v in &e.variants {
                        let tag = quoted(&v.name);
                        let value = match &v.data {
                            VariantData::Unit => {
                                variants.push(tag);
                                continue;
                            }
                            VariantData::Tuple(ts) => {
                                let ts = ts
                                    .iter()
                                    .map(|t| names.ty(module, t, input))
                                    .collect::<Result<Vec<_>>>()?;
                                if ts.len() == 1 {
                                    ts[0].clone()
                                } else {
                                    format!("[{}]", ts.join(", "))
                                }
                            }
                            VariantData::Named(fs) => {
                                let fields = fs
                                    .iter()
                                    .map(|(n, t)| {
                                        Ok(format!(
                                            "{}{}: {}",
                                            quoted(n),
                                            if input && option_inner(t).is_some() { "?" } else { "" },
                                            names.ty(module, t, input)?
                                        ))
                                    })
                                    .collect::<Result<Vec<_>>>()?;
                                format!("{{ {} }}", fields.join("; "))
                            }
                        };
                        variants.push(format!("{{ {tag}: {value} }}"));
                    }
                    if variants.is_empty() {
                        "never".into()
                    } else {
                        variants.join(" | ")
                    }
                }
                _ => unreachable!(),
            };
            if !input {
                writeln!(out, "export type {name}{params} = {decl};")?;
                output = decl;
            } else {
                let same = format!("{name}{params}");
                writeln!(out, "export type {name}Input{params} = {};\n", if decl == output { &same } else { &decl })?;
            }
        }
    }
    names.1.clear();
    out.push_str("export interface Routes {\n");
    for (module, item) in items {
        if let Item::Route(r) = item {
            if r.socket.is_some() {
                continue;
            }
            writeln!(out, "  {}: {{", quoted(&format!("{} {}", r.method, r.path)))?;
            let mut path = Vec::new();
            for (n, t) in &r.params {
                let ty = names.ty(module, t, true)?;
                if matches!(n.as_str(), "body" | "query") {
                    writeln!(out, "    {n}: {ty};")?;
                } else {
                    path.push(format!("{}: {ty}", quoted(n)));
                }
            }
            if !path.is_empty() {
                writeln!(out, "    params: {{ {} }};", path.join("; "))?;
            }
            let response = r
                .ret
                .as_ref()
                .map(|t| names.ty(module, t, false))
                .transpose()?
                .unwrap_or_else(|| "void".into());
            writeln!(out, "    response: {response};\n  }};")?;
        }
    }
    out.push_str("}\n");
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn enum_shapes_defaults_nullable_and_colliding_names() {
        let items = |s| crate::parser::parse_items(crate::lexer::lex(s).unwrap()).unwrap();
        let prog = Program {
            items: items("@json\ntype Record: x: i32\n@json\nenum Reply: Empty, One(str), Pair(i32, bool), Named(msg: str)\n"),
            modules: vec!["a","b"].into_iter().map(|m| Module {path: vec![m.into()],items:items("@json\ntype User:\n    @rename(\"display-name\")\n    @default\n    name: str\n    @omit_none\n    note: str?\n")}).collect(),
            files: vec![],
        };
        let ts = generate(&prog).unwrap();
        for snippet in [
            "a_User",
            "b_User",
            "Record_",
            "\"display-name\"?: string",
            "\"note\"?: string | null",
            "\"Empty\" | { \"One\": string } | { \"Pair\": [number, boolean] } | { \"Named\": { \"msg\": string } }",
        ] {
            assert!(ts.contains(snippet), "{ts}");
        }
    }
}
