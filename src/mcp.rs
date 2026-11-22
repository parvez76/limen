//! `parvez mcp`: a Model Context Protocol server over stdio (newline-delimited
//! JSON-RPC 2.0). Tools: `parvez_spec`, `parvez_check`, `parvez_eject`.
//!
//! Register with an MCP client, e.g. Claude Code:
//! `claude mcp add parvez -- parvez mcp`

use crate::audit::cache_dir;
use crate::{Mode, Outcome, codegen, compile_at, transpile};
use anyhow::Result;
use serde_json::{Value, json};
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

const SPEC: &str = include_str!("../SPEC.md");

/// Sections of SPEC.md served on request (topic, heading prefix, what it covers).
/// Everything else is the core, sent by default with an index of these: an agent
/// writing a CLI tool doesn't need the HTTP, security or sign-in chapters.
const TOPICS: &[(&str, &str, &str)] = &[
    ("http", "## HTTP services", "routes, `state:`, guards, request access, status codes, WebSockets"),
    ("security", "## Security", "the compile-time security rules and the safe way to write SQL, commands, file paths and secrets"),
    ("tests", "## Tests", "`test` blocks, `test_app()` and assertions"),
    ("masud", "## Masud", "server-rendered HTML pages (`.msd`)"),
    ("oidc", "## OIDC", "validating bearer tokens from Keycloak, Entra ID, Auth0"),
    ("browser", "## Browser sign-in", "sign-in and sessions for Masud pages"),
    ("modules", "## Files and modules", "multi-file programs and `import`"),
    ("crates", "## Crates", "using Rust crates and `parvez.toml`"),
    ("generics", "## Generics, traits", "generics, traits, `dyn`, `priv`"),
    ("frontend", "## Embedded frontend", "serving a built frontend and exporting TypeScript types"),
    ("observability", "## Observability", "logs, metrics and health checks every service gets"),
    ("cli", "## CLI", "every `parvez` command"),
];

/// SPEC.md split at `## ` headings: (heading line, whole section).
fn spec_sections() -> (&'static str, Vec<(&'static str, &'static str)>) {
    let starts: Vec<usize> = SPEC.match_indices("\n## ").map(|(i, _)| i + 1).collect();
    let preamble = &SPEC[..starts.first().copied().unwrap_or(SPEC.len())];
    let sections = starts
        .iter()
        .enumerate()
        .map(|(n, &i)| {
            let end = starts.get(n + 1).copied().unwrap_or(SPEC.len());
            let body = &SPEC[i..end];
            (body.lines().next().unwrap_or(""), body)
        })
        .collect();
    (preamble, sections)
}

/// `parvez_spec`: the core by default, one topic, or `all`.
fn spec(topic: Option<&str>) -> Result<String, String> {
    let (preamble, sections) = spec_sections();
    match topic.map(str::trim).filter(|t| !t.is_empty()) {
        Some("all") => Ok(SPEC.to_string()),
        Some(t) => {
            let Some((_, prefix, _)) = TOPICS.iter().find(|(name, ..)| *name == t) else {
                let names: Vec<&str> = TOPICS.iter().map(|(n, ..)| *n).collect();
                return Err(format!("unknown topic {t:?}; topics: {}, all", names.join(", ")));
            };
            Ok(sections.iter().filter(|(h, _)| h.starts_with(prefix)).map(|(_, b)| *b).collect())
        }
        None => {
            let mut out = preamble.to_string();
            for (h, body) in &sections {
                if !TOPICS.iter().any(|(_, prefix, _)| h.starts_with(prefix)) {
                    out.push_str(body);
                }
            }
            out.push_str("\n## More topics (call parvez_spec with `topic`)\nWriting a web service? Fetch `http` and `security` first.\n");
            for (name, _, what) in TOPICS {
                out.push_str(&format!("- `{name}`: {what}\n"));
            }
            out.push_str("- `all`: the whole spec\n");
            Ok(out)
        }
    }
}
const PROTOCOL: &str = "2025-06-18";

pub fn serve() -> Result<()> {
    let stdin = std::io::stdin();
    let mut out = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let resp = match serde_json::from_str::<Value>(&line) {
            // A compiler bug must not take the whole server down.
            Ok(req) => std::panic::catch_unwind(|| handle(&req)).unwrap_or_else(|_| {
                Some(json!({
                    "jsonrpc": "2.0", "id": req.get("id").cloned().unwrap_or(Value::Null),
                    "error": { "code": -32603, "message": "internal compiler error" }
                }))
            }),
            Err(e) => Some(json!({
                "jsonrpc": "2.0", "id": null,
                "error": { "code": -32700, "message": format!("parse error: {e}") }
            })),
        };
        if let Some(r) = resp {
            writeln!(out, "{r}")?;
            out.flush()?;
        }
    }
    Ok(())
}

/// One JSON-RPC message in, at most one response out (notifications get none).
pub fn handle(req: &Value) -> Option<Value> {
    let id = req.get("id").cloned();
    let method = req["method"].as_str().unwrap_or("");
    let result: Result<Value, (i64, String)> = match method {
        "initialize" => Ok(json!({
            "protocolVersion": req["params"]["protocolVersion"].as_str().unwrap_or(PROTOCOL),
            "capabilities": { "tools": {} },
            "serverInfo": { "name": "parvez", "version": env!("CARGO_PKG_VERSION") },
            "instructions": "Parvez (.prvz) is a token-dense language that compiles to Rust. \
                Call parvez_spec to learn the core syntax (and parvez_spec with a topic, e.g. `http` or `security`, \
                for the parts your program needs), write code, then loop on parvez_check \
                until it returns ok. Errors point at .prvz lines."
        })),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({ "tools": tools() })),
        "tools/call" => call_tool(&req["params"]),
        _ if id.is_none() => return None, // e.g. notifications/initialized
        _ => Err((-32601, format!("method not found: {method}"))),
    };
    let id = id?;
    Some(match result {
        Ok(r) => json!({ "jsonrpc": "2.0", "id": id, "result": r }),
        Err((code, message)) => json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } }),
    })
}

fn tools() -> Value {
    let source = json!({
        "code": { "type": "string", "description": "Full .prvz program source (needs `fn main` or `route`s)" },
        "path": { "type": "string", "description": "Path to a .prvz file (alternative to `code`)" }
    });
    let mut eject_props = source.clone();
    eject_props["map"] = json!({ "type": "boolean", "description": "Append `// @prvz:N` source-line comments" });
    json!([
        {
            "name": "parvez_spec",
            "description": "Returns the Parvez language spec. With no topic: the core language and an index of topics (http, security, tests, masud, oidc, browser, modules, crates, generics, frontend, observability, cli). With a topic: that section. `all`: the whole spec.",
            "inputSchema": { "type": "object", "properties": { "topic": { "type": "string", "description": "a topic from the index, or `all`" } } }
        },
        {
            "name": "parvez_check",
            "description": "Type- and borrow-checks .prvz code with rustc (cargo check). Returns `ok` or errors mapped to .prvz lines, e.g. `snippet.prvz:6: error[E0308]: mismatched types`.",
            "inputSchema": { "type": "object", "properties": source }
        },
        {
            "name": "parvez_eject",
            "description": "Returns the Rust code generated from .prvz code (plain Rust, no runtime).",
            "inputSchema": { "type": "object", "properties": eject_props }
        }
    ])
}

fn text(t: impl Into<String>, is_error: bool) -> Value {
    json!({ "content": [{ "type": "text", "text": t.into() }], "isError": is_error })
}

/// Resolve the tool's `code` / `path` args to a .prvz file on disk plus the
/// name to show in messages. Inline code is written to the MCP cache dir.
fn source_file(args: &Value) -> Result<(PathBuf, PathBuf, String), String> {
    if let Some(code) = args["code"].as_str() {
        let dir = cache_dir().join("mcp");
        std::fs::create_dir_all(&dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
        let file = dir.join("snippet.prvz");
        std::fs::write(&file, code).map_err(|e| format!("writing {}: {e}", file.display()))?;
        return Ok((file, dir, "snippet.prvz".into()));
    }
    if let Some(p) = args["path"].as_str() {
        let file = PathBuf::from(p);
        let root = cache_dir().join("mcp");
        std::fs::create_dir_all(&root).map_err(|e| format!("creating {}: {e}", root.display()))?;
        return Ok((file, root, p.to_string()));
    }
    Err("pass `code` (program source) or `path` (a .prvz file)".into())
}

/// Messages mention the real file path; show the name the caller used.
fn rename(msg: &str, file: &Path, shown: &str) -> String {
    // messages name files with `/` on every platform (see `load_into`); match both spellings
    let native = file.display().to_string();
    msg.replace(&native.replace('\\', "/"), shown).replace(&native, shown)
}

fn call_tool(params: &Value) -> Result<Value, (i64, String)> {
    let name = params["name"].as_str().unwrap_or("");
    let args = &params["arguments"];
    match name {
        "parvez_spec" => Ok(match spec(args["topic"].as_str()) {
            Ok(t) => text(&t, false),
            Err(e) => text(&e, true),
        }),
        "parvez_check" => {
            let (file, root, shown) = match source_file(args) {
                Ok(x) => x,
                Err(e) => return Ok(text(e, true)),
            };
            // Checking compiles dependencies, and their build scripts run on this
            // machine: never fetch crates the caller merely named in a `use`.
            if let Ok((_, g)) = transpile(&file) {
                let allowed: Vec<String> = std::env::var("PARVEZ_MCP_ALLOW_CRATES")
                    .unwrap_or_default()
                    .split(',')
                    .map(|c| c.trim().replace('-', "_"))
                    .filter(|c| !c.is_empty())
                    .collect();
                let blocked: Vec<&String> =
                    g.deps.iter().filter(|c| !crate::deps::is_known(c) && !allowed.contains(c)).collect();
                if !blocked.is_empty() {
                    let names: Vec<&str> = blocked.iter().map(|c| c.as_str()).collect();
                    return Ok(text(
                        format!(
                            "refused: unknown crate(s) {} would be downloaded and their build scripts run. \
                             Use known crates, or allow these with PARVEZ_MCP_ALLOW_CRATES={}",
                            names.join(", "),
                            names.join(",")
                        ),
                        true,
                    ));
                }
            }
            Ok(match compile_at(&file, Mode::Check, &root) {
                Ok(Outcome::Built(_)) => text(format!("ok: {shown} has no errors"), false),
                Ok(Outcome::Errors(errs)) => {
                    let body = errs.iter().map(|e| rename(e, &file, &shown)).collect::<Vec<_>>().join("\n");
                    text(format!("{body}\n{} error(s)", errs.len()), true)
                }
                Err(e) => text(rename(&format!("{e:#}"), &file, &shown), true),
            })
        }
        "parvez_eject" => {
            let (file, _, shown) = match source_file(args) {
                Ok(x) => x,
                Err(e) => return Ok(text(e, true)),
            };
            Ok(match transpile(&file) {
                Ok((_, g)) => text(if args["map"].as_bool() == Some(true) { codegen::annotate(&g) } else { g.code }, false),
                Err(e) => text(rename(&format!("{e:#}"), &file, &shown), true),
            })
        }
        _ => Err((-32602, format!("unknown tool: {name}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initialize_list_and_errors() {
        let r = handle(&json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}})).unwrap();
        assert_eq!(r["result"]["protocolVersion"], "2025-03-26");
        assert_eq!(r["result"]["serverInfo"]["name"], "parvez");
        assert!(handle(&json!({"jsonrpc":"2.0","method":"notifications/initialized"})).is_none());
        let r = handle(&json!({"jsonrpc":"2.0","id":2,"method":"tools/list"})).unwrap();
        let names: Vec<&str> = r["result"]["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert_eq!(names, ["parvez_spec", "parvez_check", "parvez_eject"]);
        let r = handle(&json!({"jsonrpc":"2.0","id":3,"method":"nope"})).unwrap();
        assert_eq!(r["error"]["code"], -32601);
        let r = handle(&json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"zzz"}})).unwrap();
        assert_eq!(r["error"]["code"], -32602);
    }

    #[test]
    fn spec_tool_returns_spec() {
        let r = handle(&json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"parvez_spec","arguments":{}}})).unwrap();
        let t = r["result"]["content"][0]["text"].as_str().unwrap();
        assert!(t.starts_with("# PARVEZ"));
        assert_eq!(r["result"]["isError"], false);
        // the core leaves out topic chapters but lists them
        assert!(t.contains("## Statements") && !t.contains("## HTTP services") && t.contains("- `http`:"), "{t}");
        assert!(t.len() < SPEC.len() / 2);
    }

    #[test]
    fn spec_topics_cover_every_section_once() {
        let (_, sections) = spec_sections();
        // every topic matches exactly one section; core + topics = the whole spec
        for (name, prefix, _) in TOPICS {
            assert_eq!(sections.iter().filter(|(h, _)| h.starts_with(prefix)).count(), 1, "topic {name}");
        }
        let topics: usize = TOPICS.iter().map(|(n, ..)| spec(Some(n)).unwrap().len()).sum();
        let core = spec(None).unwrap();
        let index_len = core.len() - core.find("\n## More topics").unwrap();
        assert_eq!(core.len() - index_len + topics, SPEC.len());
        assert_eq!(spec(Some("all")).unwrap(), SPEC);
        assert!(spec(Some("nope")).unwrap_err().contains("topics: http"));
        let r = handle(&json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"parvez_spec","arguments":{"topic":"security"}}})).unwrap();
        assert!(r["result"]["content"][0]["text"].as_str().unwrap().starts_with("## Security"));
    }

    #[test]
    fn eject_parse_error_uses_shown_name() {
        let dir = std::env::temp_dir().join("parvez-mcp-unit");
        unsafe { std::env::set_var("PARVEZ_CACHE_DIR", &dir) };
        let r = handle(&json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"parvez_eject","arguments":{"code":"fn main():\n    x = (1 +\n"}}})).unwrap();
        let t = r["result"]["content"][0]["text"].as_str().unwrap();
        assert_eq!(r["result"]["isError"], true);
        assert!(t.starts_with("snippet.prvz:2: unclosed"), "{t}");
    }
}
