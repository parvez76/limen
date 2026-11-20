# Parvez

Python's token efficiency with Rust's production reliability.

Parvez is a small, indentation-based language for backend microservices and DevOps tools. Its dense syntax keeps code short for both humans and LLMs. The `parvez` compiler translates `.prvz` files into plain, readable Rust, and `cargo` builds that Rust into a single standalone binary. rustc does all the type and borrow checking, and the generated code has no Parvez runtime, so there's no lock-in.

```
type User: name: str, age: u8

fn port(raw: &str) -> i32!:
    p: i32 = raw.trim().parse()?
    if p < 1 or p > 65535: fail("port {p} out of range")
    ret p

fn main()!:
    users = [User(name: "Ada", age: 36), User(name: "Linus", age: 12)]
    ~adults = 0
    for u in &users:
        if u.age >= 18: adults += 1
    p = port("8080")?
    print("adults: {adults}, port: {p}")
```

A complete JSON REST microservice ([examples/service.prvz](examples/service.prvz)) is 16 lines of Parvez instead of about 77 lines of axum + tokio + serde Rust, roughly 79% fewer tokens:

```
@json
type Event: id: str, kind: str, count: i32

route GET "/health" -> str:
    ret "ok"

route POST "/events" (body: Event) -> Event!:
    if body.count < 0: fail(400, "count must be >= 0")
    ret body
```

`parvez run service.prvz` serves this on `:8080` (or `$PORT`) as a 1.4 MB native binary. Every error, including bad JSON, unknown routes and wrong methods, comes back as `{"error": ...}` with the right status. A `state:` block adds shared resources such as DB pools, clients and in-memory stores, available to any route that takes `state`.

## Secure by default

Parvez generates every line that ships, so security isn't left to each developer:

- **Compile-time security checks.** SQL built by string interpolation, shell commands built from input, request data reaching the filesystem (`safe_join` is the fix), and hard-coded secrets are compile errors pointing at the `.prvz` line, each with the safe alternative. Opting out takes an explicit `@allow_insecure("reason")`.
- **Hardened services.** Internal errors and panics become a generic 500, with details logged server-side only. Body size limits, timeouts, concurrency backpressure, security headers and graceful SIGTERM shutdown are always on.
- **Supply chain.** Builds fail on dependencies with known RustSec advisories, `parvez heal` moves to patched versions, and every build writes a CycloneDX SBOM.
- **`parvez fuzz`** sends hostile, type-aware input to every route and fails on any crash, hang or leak.

Memory safety and data-race freedom come from Rust itself. Logic flaws, such as a missing permission check, are still yours to get right; Parvez removes whole classes of bugs, not all of them.

## Install

You need the Rust toolchain from [rustup.rs](https://rustup.rs).

```
git clone https://github.com/parvez76/project-parvez.git
cd project-parvez
cargo install --path .
```

## Usage

| Command | What it does |
|---|---|
| `parvez types --ts app.prvz --out types.ts` | Exports TypeScript request, response, and JSON model types across imports |
| `parvez check app.prvz` | Fast type and borrow check (`cargo check`) with `.prvz`-mapped errors, for agent loops |
| `parvez run app.prvz [-- args]` | Builds the program and runs it |
| `parvez build app.prvz` | Builds a release binary and writes it to `./app` |
| `parvez heal app.prvz` | Updates to patched compatible dependency versions; reports advisories needing a major upgrade |
| `parvez fuzz app.prvz` | Starts the service and fires malformed/edge-case requests at every route; fails on crash, hang or leak |
| `parvez mcp` | MCP server on stdio for AI agents: `parvez_spec`, `parvez_check`, `parvez_eject` tools (`claude mcp add parvez -- parvez mcp`) |
| `parvez show app.prvz [-o app.rs] [--map]` | Prints the generated Rust (`--map` adds `// @prvz:N` line comments), or writes it with `-o` |

Builds happen in `.parvez_build/<name>/` in the current directory, and cargo reuses that cache between builds.

## Full-stack services in v0.8

A service can serve a static build, JSON endpoints, and Masud HTML pages from one binary. For example, put this in `main.prvz`.

```
@embed_dir("web/dist")
import models
import ui.dashboard

route GET "/api/summary" -> models::Summary:
    ret models::summary()
```

Use ordinary Parvez types in `models.prvz`.

```
const TARGET: i32 = 8
@json
type Summary: label: str

fn summary() -> Summary:
    label = if TARGET >= 8: "Ready" else: "Waiting"
    ret Summary(label: label)
```

In `ui/dashboard.msd`, indentation nests elements and braces interpolate escaped values. Changing the backend field name makes `parvez check main.prvz` point to the reference in this page.

```
import models
page GET "/dashboard" -> html:
    let summary = models::summary()
    main:
        h1 Dashboard
        p {summary.label}
```

Run `parvez types --ts --out web/types.ts` before building the frontend. Build the frontend into `web/dist`, then run `parvez build main.prvz`. The resulting binary serves `/dashboard`, `/api/summary`, and the frontend's assets and client-side routes.

## Language at a glance

| Parvez | Rust |
|---|---|
| `x = 10` / `~x = 0` | `let x = 10;` / `let mut x = 0;` |
| `type User: name: str, age: u8` | `#[derive(Debug, Clone)] struct User { name: String, age: u8 }` |
| `fn add(a: i32, b: i32) -> i32:` | `fn add(a: i32, b: i32) -> i32 { ... }` |
| `fn main()!:` / `-> T!` | `-> anyhow::Result<()>` / `-> anyhow::Result<T>` |
| `ret x` | `return x` (or the tail expression) |
| `[T]`, `T?`, `&~T` | `Vec<T>`, `Option<T>`, `&mut T` |
| `print("hi {name}")` | `println!("hi {}", name)` |
| `fail("bad {x}")` | `anyhow::bail!("bad {}", x)` |
| `and` `or` `not` | `&&` `\|\|` `!` |
| `if let Some(v) = opt: print(v)` | `if let Some(v) = opt { println!("{}", v); }` |
| `enum S: A, B(str), C(code: i32)` | `#[derive(Debug, Clone, PartialEq)] enum S { A, B(String), C { code: i32 } }` |
| `match s:` / `B(msg) -> print(msg)` | `match s { S::B(msg) => println!(..), .. }` |
| `impl User:` / `fn greet(&self)`, `fn bump(&~self)` | `impl User { fn greet(&self) .. fn bump(&mut self) .. }` |
| `@json type Event: ...` | adds `#[derive(serde::Serialize, serde::Deserialize)]` |
| `async fn f() -> str!:` / `x.await` | `async fn f() -> anyhow::Result<String>` / `x.await` |
| `json_decode<Event>(raw)?` / `json_encode(e)?` | `serde_json::from_str::<Event>(&raw)?` / `serde_json::to_string(&e)?` |
| `use serde::{Serialize}` / `use reqwest` | `use` + automatic Cargo.toml dependencies (pin in `parvez.toml`) |
| `route POST "/x/{id}" (id: u64, body: T) -> T!:` | axum handler + router + `#[tokio::main]` server |
| `@guard(verify)` + `(req, auth)` / `req.header("x")` / `req.client_ip()` | Pre-handler auth with raw request access |
| `import store` / `store::find(id)` | Multi-file programs (nested `pub mod`s, one binary) |
| `socket "/ws/{id}" (auth, conn):` / `conn.recv()` / `conn.sender().text(..)` | WebSockets with guards, subprotocols, a bounded send queue |
| `status(204)` / `fail(401, code: "X", "msg")` | Any status / `{"error", "code"}` contracts |
| `\|x\| x * 2` / `loop:` / `spawn work()` / `"""SQL"""` / `(a, b)` | closures / `loop` / `tokio::spawn` / dedented multi-line string / tuples |
| `state:` / `hits: AtomicU64 = AtomicU64::new(0)` / `(state)` | `Arc<AppState>` built at startup, injected via axum `State` |

There's also `if`/`elif`/`else`, `for x in ...:`, `while`, `break` and `continue`.

## Errors point at your `.prvz` file

rustc's errors are mapped back through a source map, so humans and AI agents can fix the right line without reading the generated Rust:

```
app.prvz:6: error[E0308]: mismatched types
   6 |     ret raw.len()
     = expected `i32`, found `usize`
     = line 5: expected `i32` because of return type
     = rust: raw.len()
```

The full spec is in [SPEC.md](SPEC.md). It's written as a compact system prompt, so you can paste it into an AI agent and it will write valid Parvez.

## Project layout

```
src/lexer.rs    tokens, INDENT/DEDENT
src/parser.rs   recursive descent -> AST (src/ast.rs)
src/codegen.rs  AST -> formatted Rust + source map
src/diagnostics.rs  rustc JSON errors -> .prvz lines
src/deps.rs     crate detection -> generated Cargo.toml (+ parvez.toml overrides)
src/mcp.rs      `parvez mcp`: JSON-RPC stdio server for AI agents
src/security.rs compile-time security checks (SQLi, command injection, path traversal, secrets)
src/audit.rs    RustSec advisory gate + CycloneDX SBOM
src/fuzz.rs     `parvez fuzz`: type-aware HTTP fuzzing of generated services
src/main.rs     CLI: build / run / show
examples/       sample .prvz programs
```

Run the tests with `cargo test`. The tests in `tests/cli.rs` compile real programs with rustc.

## Status

Parvez v0.8 includes Masud v0.1. For traits, generics on your own types, `as` casts, or Rust macros, use `parvez show` to continue in Rust.

## License

[MIT](LICENSE)
