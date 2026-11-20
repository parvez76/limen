# Parvez reference

Everything the [README](../README.md) leaves out: the language at a glance, every command, what's built into every service, full-stack services, and how errors are reported. The complete language definition is [SPEC.md](../SPEC.md); the security model and rules are in [SECURITY.md](../SECURITY.md).

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
| `type Page<T>: items: [T]` / `fn f<T: Clone>(x: T)` | generic structs and functions |
| `trait Store:` / `impl Store for Pg:` / `Arc<dyn Store>` | traits (async methods via `async-trait`), usable as `dyn` |
| `{"k": v}` / `json({"k": v, "n": [1]})` | `HashMap::from([..])` / `serde_json::json!({..})` |
| `x = load(id) catch e: fallback` / `n as f64` | `match load(id) { Ok(v) => v, Err(e) => .. }` / `n as f64` |
| `a, b = parallel(f(), g())?` / `every 1h (state):` | `tokio::try_join!` / an interval worker with logged errors |
| `priv fn helper()` / `@test_only import testkit` | module-private items / `#[cfg(test)]` code and dev-dependencies |
| `oidc_session(req)` in a page guard | Browser sign-in (code + PKCE), encrypted session cookies, refresh, CSRF |

There's also `if`/`elif`/`else`, `for x in ...:`, `while`, `break` and `continue`.

## Commands

| Command | What it does |
|---|---|
| `parvez types --ts app.prvz --out types.ts` | Exports TypeScript request, response, and JSON model types across imports |
| `parvez check app.prvz` | Fast type and borrow check (`cargo check`) with `.prvz`-mapped errors, for agent loops |
| `parvez run app.prvz [-- args]` | Builds the program and runs it |
| `parvez build app.prvz [--target <triple>]` | Builds a release binary (`./app`, or `./app-<triple>` when cross-compiling, e.g. static `x86_64-unknown-linux-musl`) plus `app.sha256` |
| `parvez lint app.prvz [--sarif -o out.sarif]` | Security rules only (no build), with CWE/OWASP/ASVS references; SARIF 2.1.0 for code scanning. `--rules` lists the rules |
| `parvez routes app.prvz [--json]` | Access map: every endpoint with its guards or `@public` reason, for security review |
| `parvez new <name>` | Scaffolds a project (`parvez.toml`, `main.prvz` with tests, `ui/`) that passes `parvez test` immediately |
| `parvez fmt [paths...] [--check]` | Formats `.prvz`/`.msd` files; every change is verified to leave the program identical |
| `parvez heal app.prvz` | Updates to patched compatible dependency versions; reports advisories needing a major upgrade |
| `parvez fuzz app.prvz` | Starts the service and fires malformed/edge-case requests at every route; fails on crash, hang or leak |
| `parvez test app.prvz [filter]` | Runs `test "..."` blocks, with in-process HTTP tests via `test_app()` |
| `parvez doctor` | Checks the setup (Rust 1.88+, cargo, the C linker or, on Windows, the Visual Studio C++ build tools, git, advisory database, targets, PATH) and prints the fix for anything missing |
| `parvez upgrade [--version vX.Y.Z] [--check]` | Updates to a newer release after verifying it (SHA256SUMS, and the build attestation when `gh` is installed) |
| `parvez mcp` | MCP server on stdio for AI agents: `parvez_spec`, `parvez_check`, `parvez_eject` tools (`claude mcp add parvez -- parvez mcp`) |
| `parvez show app.prvz [-o app.rs] [--map]` | Prints the generated Rust (`--map` adds `// @prvz:N` line comments), or writes it with `-o` |

Builds happen in `.parvez_build/<name>/` in the current directory, and cargo reuses that cache between builds.

## Quickstart, in full

```bash
parvez new hello && cd hello        # parvez.toml, main.prvz (a route + tests), ui/home.msd
parvez check main.prvz              # type/borrow check, errors point at .prvz lines
parvez test main.prvz               # the test blocks, with an in-process HTTP client
parvez run main.prvz                # http://localhost:8080
parvez fuzz main.prvz               # hostile input at every route: crashes, hangs, leaks fail it
parvez fmt --check .                # canonical formatting (CI)

rustup target add x86_64-unknown-linux-musl
parvez build main.prvz --target x86_64-unknown-linux-musl
#   -> ./main-x86_64-unknown-linux-musl (static, runs on any Linux) + .sha256 + SBOM
```

## Secure by default

Parvez generates every line that ships, so security isn't left to each developer:

- **Deny-by-default access control.** Every route, socket and page must declare `@guard(fn)` or `@public("reason")`, or it doesn't compile, so a forgotten permission check (OWASP's #1 risk, broken access control) can't ship. `parvez routes` prints the complete access map for review.
- **Secrets can't leak.** `Secret` values print as `[redacted]`, can't be serialized into JSON or logs, compare in constant time and are zeroed in memory (best effort, see SECURITY.md); `s.expose()` into a log, print, error or string is a compile error, and secret-named `state:` fields must use `Secret`.
- **Compile-time security checks.** SQL built by string interpolation, shell commands built from input, request data reaching the filesystem (`safe_join` is the fix), followed into helper functions and across modules, and hard-coded secrets are compile errors pointing at the `.prvz` line, each with the safe alternative. Opting out takes an explicit `@allow_insecure("reason")`.
- **Standards-mapped findings.** Every rule names the CWE, OWASP Top 10 and ASVS requirement it enforces, and `parvez lint --sarif` feeds GitHub code scanning and other security dashboards. [SECURITY.md](../SECURITY.md) has the full control map and how to report a vulnerability.
- **Hardened services.** Internal errors and panics become a generic 500, with details logged server-side only. Body size limits, timeouts, concurrency backpressure, security headers (a strict Content-Security-Policy on pages, HSTS, anti-framing, no-sniff) and graceful SIGTERM shutdown are always on.
- **Supply chain.** Builds fail on dependencies with known RustSec advisories, `parvez heal` moves to patched versions, and every build writes a CycloneDX SBOM.
- **`parvez fuzz`** sends hostile, type-aware input to every route and fails on any crash, hang or leak.

Memory safety and data-race freedom come from Rust itself. Logic flaws, such as a missing permission check, are still yours to get right; Parvez removes whole classes of bugs, not all of them.

## Production essentials, built in

- **Tests in Parvez:** `test "..."` blocks with `assert`/`assert_eq` and an in-process HTTP client, run by `parvez test`. Failures point at `.prvz` lines.
- **Observability:** JSON logs with request IDs, Prometheus `/metrics` (route-template labels, latency histogram, custom events), and `/healthz` / `/readyz`, all without writing any code.
- **OIDC:** `oidc(req).await?` in a guard validates Keycloak/Entra/Auth0 bearer tokens (JWKS discovery and rotation, asymmetric algorithms only, and issuer, audience, token-type and expiry checks). `oidc_session(req)` adds browser sign-in for Masud pages: code flow with PKCE, encrypted session cookies, refresh and CSRF checks. `@guard(...)` works on pages and routes alike.

## Full-stack services

A service can serve a static build, JSON endpoints, and Masud HTML pages from one binary. For example, put this in `main.prvz`.

```
@embed_dir("web/dist")
import models
import ui.dashboard

@public
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
@public
page GET "/dashboard" -> html:
    let summary = models::summary()
    main:
        h1 Dashboard
        p {summary.label}
```

Run `parvez types --ts --out web/types.ts` before building the frontend. Build the frontend into `web/dist`, then run `parvez build main.prvz`. The resulting binary serves `/dashboard`, `/api/summary`, and the frontend's assets and client-side routes.

## Errors point at your `.prvz` file

rustc's errors are mapped back through a source map, so humans and AI agents can fix the right line without reading the generated Rust:

```
app.prvz:6: error[E0308]: mismatched types
   6 |     ret raw.len()
     = expected `i32`, found `usize`
     = line 5: expected `i32` because of return type
     = rust: raw.len()
```

The full spec is in [SPEC.md](../SPEC.md). It's written as a compact system prompt for AI agents; `parvez mcp` lets an agent check its own code against the compiler.

## Working on Parvez itself

```
src/lexer.rs    tokens, INDENT/DEDENT
src/parser.rs   recursive descent -> AST (src/ast.rs)
src/codegen.rs  AST -> formatted Rust + source map
src/diagnostics.rs  rustc JSON errors -> .prvz lines
src/deps.rs     crate detection -> generated Cargo.toml (+ parvez.toml overrides)
src/mcp.rs      `parvez mcp`: JSON-RPC stdio server for AI agents
src/security.rs compile-time security checks + rule catalog (CWE / OWASP / ASVS)
src/sarif.rs    `parvez lint --sarif`: SARIF 2.1.0 export
src/audit.rs    RustSec advisory gate + CycloneDX SBOM
src/fuzz.rs     `parvez fuzz`: type-aware HTTP fuzzing of generated services
src/main.rs     CLI: build / run / show
examples/       sample .prvz programs
```

Run the tests with `cargo test`. The tests in `tests/cli.rs` compile real programs with rustc.
