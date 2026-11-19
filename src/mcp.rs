//! `parvez mcp`: a Model Context Protocol server over stdio (newline-delimited
//! JSON-RPC 2.0). Tools: `parvez_spec`, `parvez_check`, `parvez_eject`.
//!
//! Register with an MCP client, e.g. Claude Code:
//! `claude mcp add parvez -- parvez mcp`

use crate::{Mode, Outcome, codegen, compile_at, transpile};
use anyhow::Result;
use serde_json::{Value, json};
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

const SPEC: &str = include_str!("../SPEC.md");
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
            Ok(req) => handle(&req),
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
                Call parvez_spec once to learn the syntax, write code, then loop on parvez_check \
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
            "description": "Returns the Parvez language spec (SPEC.md): everything needed to write valid .prvz code.",
            "inputSchema": { "type": "object", "properties": {} }
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

fn cache_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("PARVEZ_CACHE_DIR") {
        return PathBuf::from(d);
    }
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
        .unwrap_or_else(std::env::temp_dir);
    base.join("parvez")
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
    msg.replace(&file.display().to_string(), shown)
}

fn call_tool(params: &Value) -> Result<Value, (i64, String)> {
    let name = params["name"].as_str().unwrap_or("");
    let args = &params["arguments"];
    match name {
        "parvez_spec" => Ok(text(SPEC, false)),
        "parvez_check" => {
            let (file, root, shown) = match source_file(args) {
                Ok(x) => x,
                Err(e) => return Ok(text(e, true)),
            };
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
