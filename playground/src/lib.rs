//! Parvez in the browser: parse, validate, run the security checks and generate
//! Rust for one `.prvz` file, entirely in memory. The modules are the compiler's
//! own files, so results match `parvez lint` / `parvez show` exactly.
//!
//! Interface (no wasm-bindgen): the host writes UTF-8 source into memory from
//! `pz_alloc`, calls `pz_check(ptr, len)`, and reads `pz_result_len()` bytes of
//! JSON at the returned pointer.
#![allow(dead_code)]

#[path = "../../src/ast.rs"]
pub mod ast;
#[path = "../../src/codegen.rs"]
pub mod codegen;
#[path = "../../src/deps.rs"]
pub mod deps;
#[path = "../../src/embed.rs"]
pub mod embed;
#[path = "../../src/lexer.rs"]
pub mod lexer;
#[path = "../../src/parser.rs"]
pub mod parser;
#[path = "../../src/security.rs"]
pub mod security;

use serde_json::{Value, json};

/// `line N: msg` (the compiler's error format) -> (N, msg).
fn split_error(e: &str) -> (Option<usize>, String) {
    match e.strip_prefix("line ").and_then(|r| r.split_once(": ")) {
        Some((n, rest)) => match n.parse::<usize>() {
            Ok(n) => (Some(ast::split_line(n).1), rest.to_string()),
            Err(_) => (None, e.to_string()),
        },
        None => (None, e.to_string()),
    }
}

/// Check one file. Pure: no filesystem, no network, no rustc.
pub fn check(name: &str, src: &str) -> Value {
    let error = |e: anyhow::Error| {
        let (line, msg) = split_error(&format!("{e:#}"));
        json!({ "ok": false, "errors": [{ "line": line, "message": msg }], "findings": [], "rust": null })
    };
    let tokens = match lexer::lex(src) {
        Ok(t) => t,
        Err(e) => return error(e),
    };
    let items = match parser::parse_items(tokens) {
        Ok(i) => i,
        Err(e) => return error(e),
    };
    if items.iter().any(|i| matches!(i, ast::Item::Import(_) | ast::Item::Embed { .. })) {
        return json!({ "ok": false, "errors": [{ "line": null, "message": "imports and @embed_dir need files on disk; the playground checks one file at a time (use `parvez lint` locally)" }], "findings": [], "rust": null });
    }
    let prog = ast::Program { items, modules: vec![], files: vec![(name.to_string(), src.to_string())] };
    if let Err(e) = parser::validate(&prog) {
        return error(e);
    }
    let report = security::lint(&prog);
    if let Some(why) = &report.incomplete {
        return json!({ "ok": false, "errors": [{ "line": null, "message": format!("the security analysis is incomplete ({why})") }], "findings": [], "rust": null });
    }
    let finding = |f: &security::Finding, waived: Option<&str>| {
        let r = security::rule(f.rule);
        json!({
            "line": ast::split_line(f.line).1,
            "rule": f.rule,
            "message": f.msg,
            "fix": f.fix,
            "see": r.map(|r| r.references()),
            "waived": waived,
        })
    };
    let mut findings: Vec<Value> = report.findings.iter().map(|f| finding(f, None)).collect();
    findings.extend(report.suppressed.iter().map(|(f, why)| finding(f, Some(why))));
    let has_main = prog.items.iter().any(|i| match i {
        ast::Item::Fn(f) => f.name == "main",
        ast::Item::Route(_) | ast::Item::Test(_) => true,
        _ => false,
    });
    let rust = if report.findings.is_empty() && has_main {
        Some(codegen::generate_with(&prog, &codegen::ServiceConfig::default()).code)
    } else {
        None
    };
    json!({ "ok": report.findings.is_empty(), "errors": [], "findings": findings, "rust": rust, "version": env!("PARVEZ_VERSION") })
}

static mut RESULT: Vec<u8> = Vec::new();

#[unsafe(no_mangle)]
pub extern "C" fn pz_alloc(len: usize) -> *mut u8 {
    let mut v = Vec::<u8>::with_capacity(len.max(1));
    let p = v.as_mut_ptr();
    std::mem::forget(v);
    p
}

/// # Safety
/// `ptr` must come from `pz_alloc(len)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pz_free(ptr: *mut u8, len: usize) {
    drop(unsafe { Vec::from_raw_parts(ptr, 0, len.max(1)) });
}

/// # Safety
/// `ptr..ptr+len` must be the UTF-8 source written into memory from `pz_alloc`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pz_check(ptr: *const u8, len: usize) -> *const u8 {
    let src = unsafe { std::slice::from_raw_parts(ptr, len) };
    let out = match std::str::from_utf8(src) {
        Ok(s) => check("playground.prvz", s),
        Err(_) => json!({ "ok": false, "errors": [{ "line": null, "message": "the source isn't valid UTF-8" }], "findings": [], "rust": null }),
    };
    let bytes = out.to_string().into_bytes();
    unsafe {
        RESULT = bytes;
        (*std::ptr::addr_of!(RESULT)).as_ptr()
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn pz_result_len() -> usize {
    unsafe { (*std::ptr::addr_of!(RESULT)).len() }
}
