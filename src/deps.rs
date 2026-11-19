//! Crate dependency resolution: detected crates -> generated Cargo.toml.
//!
//! Known crates get a tested version + features. Anything else falls back to
//! `*` (latest). `parvez.toml` next to the `.prvz` file overrides both:
//!
//! ```toml
//! [dependencies]
//! reqwest = { version = "0.12", features = ["json", "rustls-tls"], default-features = false }
//! chrono = "0.4"
//! ```

use anyhow::{Context, Result};
use std::collections::BTreeSet;
use std::path::Path;
use toml::{Table, Value};

/// (module name, package name, version, features, default-features)
const KNOWN: &[(&str, &str, &str, &[&str], bool)] = &[
    ("anyhow", "anyhow", "1", &[], true),
    ("tokio", "tokio", "1", &["full"], true),
    ("axum", "axum", "0.8", &[], true),
    ("serde", "serde", "1", &["derive"], true),
    ("serde_json", "serde_json", "1", &[], true),
    // rustls: no system OpenSSL needed, keeps binaries portable
    ("reqwest", "reqwest", "0.12", &["json", "rustls-tls"], false),
    ("chrono", "chrono", "0.4", &["serde"], true),
    ("uuid", "uuid", "1", &["v4", "serde"], true),
    ("regex", "regex", "1", &[], true),
    ("rand", "rand", "0.8", &[], true),
    ("tracing", "tracing", "0.1", &[], true),
    ("tracing_subscriber", "tracing-subscriber", "0.3", &[], true),
    ("tower_http", "tower-http", "0.6", &["full"], true),
    ("futures", "futures", "0.3", &[], true),
    ("clap", "clap", "4", &["derive"], true),
    ("base64", "base64", "0.22", &[], true),
    ("sha2", "sha2", "0.10", &[], true),
    ("thiserror", "thiserror", "2", &[], true),
    ("sqlx", "sqlx", "0.8", &["runtime-tokio", "postgres", "chrono", "uuid", "json", "derive", "migrate"], false),
    ("hmac", "hmac", "0.12", &[], true),
    ("hex", "hex", "0.4", &[], true),
    ("ed25519_dalek", "ed25519-dalek", "2", &[], true),
    ("subtle", "subtle", "2", &[], true),
    ("jsonwebtoken", "jsonwebtoken", "9", &[], true),
    ("redis", "redis", "0.27", &["tokio-comp"], true),
];

const BUILTIN: &[&str] = &["std", "core", "alloc", "crate", "self", "super", "Self"];

/// Is this path's first segment an external crate we should depend on?
/// `strict` = only known crates (for paths in expressions, which may be
/// user types like `User::new`); otherwise any non-std crate (for `use`).
pub fn crate_of(path: &str, strict: bool) -> Option<String> {
    let first = path.split("::").next()?.trim();
    if first.is_empty() || BUILTIN.contains(&first) {
        return None;
    }
    let known = KNOWN.iter().any(|k| k.0 == first);
    if strict && !known {
        return None;
    }
    // Lowercase-led identifiers only: `User::new` is never a crate.
    if !first.starts_with(|c: char| c.is_ascii_lowercase()) {
        return None;
    }
    Some(first.to_string())
}

/// Builds the `[dependencies]` table for the detected crates.
pub fn dependencies(crates: &BTreeSet<String>, overrides: Option<&Table>) -> Table {
    let mut deps = Table::new();
    for c in crates {
        let (pkg, spec) = match KNOWN.iter().find(|k| k.0 == c) {
            Some(&(_, pkg, ver, feats, default)) => {
                if feats.is_empty() && default {
                    (pkg.to_string(), Value::String(ver.into()))
                } else {
                    let mut t = Table::new();
                    t.insert("version".into(), Value::String(ver.into()));
                    if !feats.is_empty() {
                        t.insert(
                            "features".into(),
                            Value::Array(feats.iter().map(|f| Value::String((*f).into())).collect()),
                        );
                    }
                    if !default {
                        t.insert("default-features".into(), Value::Boolean(false));
                    }
                    (pkg.to_string(), Value::Table(t))
                }
            }
            None => (c.replace('_', "-"), Value::String("*".into())),
        };
        deps.insert(pkg, spec);
    }
    if let Some(o) = overrides {
        for (k, v) in o {
            deps.insert(k.clone(), v.clone());
        }
    }
    deps
}

/// Reads `[dependencies]` from `parvez.toml` beside the source file, if any.
pub fn load_overrides(prvz: &Path) -> Result<Option<Table>> {
    let cfg = prvz.parent().unwrap_or(Path::new(".")).join("parvez.toml");
    if !cfg.exists() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(&cfg).with_context(|| format!("reading {}", cfg.display()))?;
    let table: Table = text.parse().with_context(|| format!("parsing {}", cfg.display()))?;
    Ok(match table.get("dependencies") {
        Some(Value::Table(t)) => Some(t.clone()),
        _ => None,
    })
}

fn load_table(prvz: &Path) -> Result<Option<Table>> {
    let cfg = prvz.parent().unwrap_or(Path::new(".")).join("parvez.toml");
    if !cfg.exists() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(&cfg).with_context(|| format!("reading {}", cfg.display()))?;
    Ok(Some(text.parse().with_context(|| format!("parsing {}", cfg.display()))?))
}

/// `[service]` in parvez.toml: body_limit_bytes, timeout_secs, max_concurrency.
pub fn service_config(prvz: &Path) -> Result<crate::codegen::ServiceConfig> {
    let mut cfg = crate::codegen::ServiceConfig::default();
    if let Some(t) = load_table(prvz)?
        && let Some(Value::Table(s)) = t.get("service")
    {
        let get = |k: &str, d: u64| s.get(k).and_then(|v| v.as_integer()).map(|v| v.max(1) as u64).unwrap_or(d);
        cfg.body_limit_bytes = get("body_limit_bytes", cfg.body_limit_bytes);
        cfg.timeout_secs = get("timeout_secs", cfg.timeout_secs);
        cfg.max_concurrency = get("max_concurrency", cfg.max_concurrency);
    }
    Ok(cfg)
}

/// Advisory policy: `PARVEZ_AUDIT` env, else `[security] audit` in
/// parvez.toml, else "deny". One of "deny" | "warn" | "off".
pub fn audit_policy(prvz: &Path) -> Result<String> {
    if let Ok(v) = std::env::var("PARVEZ_AUDIT") {
        return Ok(v);
    }
    let from_file = load_table(prvz)?
        .and_then(|t| t.get("security").and_then(|s| s.get("audit")).and_then(|a| a.as_str().map(String::from)));
    Ok(from_file.unwrap_or_else(|| "deny".into()))
}

/// Crates resolved to `*` (unknown and not pinned) — worth a warning.
pub fn unpinned(deps: &Table) -> Vec<String> {
    deps.iter().filter(|(_, v)| v.as_str() == Some("*")).map(|(k, _)| k.clone()).collect()
}

pub fn manifest(name: &str, deps: Table) -> String {
    let mut doc = Table::new();
    let mut pkg = Table::new();
    pkg.insert("name".into(), Value::String(format!("prvz-{name}")));
    pkg.insert("version".into(), Value::String("0.1.0".into()));
    pkg.insert("edition".into(), Value::String("2024".into()));
    doc.insert("package".into(), Value::Table(pkg));
    let mut bin = Table::new();
    bin.insert("name".into(), Value::String(name.into()));
    bin.insert("path".into(), Value::String("src/main.rs".into()));
    doc.insert("bin".into(), Value::Array(vec![Value::Table(bin)]));
    doc.insert("dependencies".into(), Value::Table(deps));
    let mut release = Table::new();
    release.insert("strip".into(), Value::Boolean(true));
    let mut profile = Table::new();
    profile.insert("release".into(), Value::Table(release));
    doc.insert("profile".into(), Value::Table(profile));
    // Standalone: never join a parent workspace.
    doc.insert("workspace".into(), Value::Table(Table::new()));
    toml::to_string(&doc).expect("manifest serializes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crate_detection() {
        assert_eq!(crate_of("serde::{Serialize, Deserialize}", false).as_deref(), Some("serde"));
        assert_eq!(crate_of("my_crate::x", false).as_deref(), Some("my_crate"));
        assert_eq!(crate_of("my_crate::x", true), None, "strict mode: only known crates");
        assert_eq!(crate_of("reqwest::get", true).as_deref(), Some("reqwest"));
        assert_eq!(crate_of("std::collections::HashMap", false), None);
        assert_eq!(crate_of("User::new", false), None);
    }

    #[test]
    fn manifest_with_known_unknown_and_overrides() {
        let crates: BTreeSet<String> =
            ["anyhow", "tokio", "reqwest", "tracing_subscriber", "weird_crate", "chrono"].map(String::from).into();
        let over: Table = "chrono = \"=0.4.38\"\nextra = { version = \"2\" }".parse().unwrap();
        let deps = dependencies(&crates, Some(&over));
        let m = manifest("svc", deps.clone());
        let doc: Table = m.parse().unwrap();
        let d = doc["dependencies"].as_table().unwrap();
        assert_eq!(d["anyhow"].as_str(), Some("1"));
        assert_eq!(d["tokio"]["features"].as_array().unwrap()[0].as_str(), Some("full"));
        assert_eq!(d["reqwest"]["default-features"].as_bool(), Some(false));
        assert_eq!(d["tracing-subscriber"].as_str(), Some("0.3"));
        assert_eq!(d["weird-crate"].as_str(), Some("*"));
        assert_eq!(d["chrono"].as_str(), Some("=0.4.38"), "override wins");
        assert_eq!(d["extra"]["version"].as_str(), Some("2"));
        assert!(doc.contains_key("workspace"));
        assert_eq!(doc["bin"][0]["name"].as_str(), Some("svc"));
        assert_eq!(unpinned(&deps), ["weird-crate"]);
    }
}
