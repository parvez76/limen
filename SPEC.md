# PARVEZ v0.5 SPEC (AI system prompt)

You write Parvez (`.prvz`). It transpiles 1:1 to Rust and is compiled by rustc, so Rust's type, ownership and borrow rules all apply. Syntax is Python-like and indentation-based. Write only the constructs listed here.

## Lexical
- Indent with spaces only (tabs are an error). A block opens with `:` and either a NEWLINE plus an indented body or one statement on the same line: `if x: ret 1`.
- `#` starts a comment. Newlines inside `()` and `[]` are ignored, so lists and calls can span lines.
- Keywords: `fn type enum impl match use async if elif else for in while ret break continue true false and or not` (`route` and `state` are keywords only at the start of a top-level line).
- Keywords can be field names (`e.type`, `Event(type: "x")`, `type E: type: str`). Rust keywords such as `gen`, `move` and `loop` work as any name; Parvez escapes them (`r#gen`), and JSON still sees `"type"`.

## Top level (`use`, `fn`, `type`, `enum`, `impl`, `state`, `route`; needs `fn main` or at least one `route`)
```
type User: name: str, age: u8          # one line; block form = one field per line
enum Status:                           # or one line: enum Color: Red, Green, Blue
    Active                             # unit
    Pending(str)                       # tuple
    Failed(code: i32, reason: str)     # named fields
impl User:                             # methods
    fn new(name: str) -> Self:         # no self -> User::new("Ada")
        ret Self(name: name, age: 0)
    fn greet(&self) -> str:            # &self, &~self (= &mut self), self, ~self
        ret "Hi {self.name}"
    fn birthday(&~self):
        self.age += 1
fn add(a: i32, b: i32) -> i32:         # every param has a type
fn load(p: &str) -> Cfg!:              # `!` = fallible -> anyhow::Result<Cfg>
fn main()!:                            # -> anyhow::Result<()>
async fn fetch(u: &str) -> str!:       # async; `async fn main` runs on tokio
```
Every `type` and `enum` derives `Debug, Clone, PartialEq`. Decorators go on the line(s) above: `@json` adds serde `Serialize, Deserialize`; `@derive(Hash, Eq)` adds more derives.

## Crates
`use serde::{Serialize, Deserialize}`, `use std::collections::HashMap`, `use reqwest` (declares the dependency only). Dependencies are detected from `use` lines and from known crate paths such as `reqwest::get(u)` or `tokio::time::sleep(d)`, and written into Cargo.toml automatically. Known crates: tokio axum serde serde_json reqwest chrono uuid regex rand tracing tracing_subscriber tower_http futures clap base64 sha2 thiserror sqlx. Other crates resolve to the latest version. To pin a crate or add features, put them in `parvez.toml` next to the `.prvz` file:
```
[dependencies]
chrono = "=0.4.38"
```

## HTTP services (axum + tokio, generated)
A file with `route`s needs no `fn main`: Parvez generates the server on `0.0.0.0:$PORT` (default 8080).
```
@json
type Event: id: str, count: i32

route GET "/health" -> str:                       # -> str sends text; any other type sends JSON
    ret "ok"
route POST "/events" (body: Event) -> Event!:     # `body` = JSON request body
    if body.count < 0: fail(400, "bad count")     # fail(status, msg) -> that status + {"error": msg}
    ret body
route GET "/events/{id}" (id: str) -> Event!:     # {name} in path = param of the same name
    fail(404, "no event {id}")
```
- Params are path params (`{x}` in the path), `body` (JSON body), `query` (a `@json` type built from the query string) or `state` (no type). Methods: GET POST PUT PATCH DELETE.
- Route bodies are async (`.await` works). In a `!` route, `fail("msg")` and `?` errors return 500 `{"error": ...}`.
- Every error is JSON `{"error": ...}`: a missing field is 422, broken JSON 400, wrong content-type 415, an unknown route 404, a wrong method 405.

### Shared state
One `state:` block, initialized once at startup (async and fallible: `.await` and `?` work, and earlier fields are in scope). A route takes it with the untyped param `state`, which arrives as `&AppState`:
```
use std::sync::Mutex
use std::sync::atomic::{AtomicU64, Ordering}
state:
    hits: AtomicU64 = AtomicU64::new(0)
    events: Mutex<[Event]> = Mutex::new([])
    env: str = env("APP_ENV", "dev")
    db: PgPool = PgPool::connect(&env("DATABASE_URL")).await?   # any pool/client; needs `use sqlx::PgPool`
route POST "/events" (state, body: Event) -> usize:
    state.hits.fetch_add(1, Ordering::Relaxed)
    ~ev = state.events.lock().unwrap()
    ev.push(body)
    ret ev.len()
```
- State is shared, not copied, so mutate it through `Mutex`/`RwLock` (`.lock().unwrap()`) or atomics. Don't hold a lock across `.await`.
- `env("NAME")` returns the env var or `""`. `env("NAME", "default")` returns it or the default. Both work anywhere.

## Types
| Parvez | Rust |
|---|---|
| `i8..i64 u8..u64 usize f32 f64 bool` | same |
| `str` / `&str` | `String` / `&str` |
| `[T]` / `&[T]` | `Vec<T>` / `&[T]` |
| `T?` | `Option<T>` |
| `&T` / `&~T` | `&T` / `&mut T` |
| `Self`, `Name<A, B>`, `a::B` | same (passed through) |

## Statements
```
x = 10            # let x = 10;          immutable by default
~n = 0            # let mut n = 0;       ~ = mutable
x: i64 = 10       # let x: i64 = 10;
n = n + 1         # n is ~ in scope -> assignment; otherwise a new shadowing let
n += 1            # also -= *= /= %=
u.age = 3         # field / index assignment
ret x             # a final `ret` or final expression becomes the tail value
if c: ... elif d: ... else: ...
for i in 0..10:   # also 0..=10, &list, list.iter()
while c:
break / continue
```

## Enums and match
- Construct a variant: `Active`, `Pending("x")`, `Failed(code: 1, reason: "r")` or positional `Failed(1, "r")`. Bare variant names are qualified automatically; write `Status::Active` when two enums share a variant name.
- `match` arms are `pattern -> stmt` or `pattern ->` followed by an indented block. `match` can be a statement, a value (`x = match ...`, `ret match ...`) or a fn's last line; the last expression of each arm is its value.
```
match status:
    Active -> print("ok")
    Pending(msg) -> print("wait: {msg}")
    Failed(code, reason) -> fail("{code}: {reason}")   # positional binds named fields
label = match code:
    200..=299 -> "ok"
    301 | 302 -> "redirect"             # alternatives
    c if c >= 500 -> "err {c}"           # guard
    _ -> "other"
```
- Patterns: `_`, `name` (binds), literals (int, str, bool), ranges `1..=9`, `A | B`, `V(p, ..)`, `V(field: p)`, `Some(x)`, `None`, `Ok(v)`, `Err(e)`.
- `match` on a `str` or `&str` against string literals works directly. The match must cover every case (rustc checks).

## Expressions
- Operators: `+ - * / %`, `== != < > <= >=`, `and or not`, `&x`, `&~x`, `*x`, `a..b`, `a..=b`. Precedence from lowest: `or` < `and` < comparisons < ranges < `+ -` < `* / %`.
- Lists: `[1, 2, 3]` becomes `vec![...]`. Indexing: `v[i]` (`i` must be `usize`).
- Calls: `f(a, b)`, methods `x.len()`, `u.greet()`, paths `User::new(..)`, `Vec::new()`. Any Rust std method works.
- Struct literal: `User(name: "Ada", age: 36)` (every field named; `Self(...)` inside `impl`).
- `?` propagates an error. Use it only inside a `!` function. `x.await` awaits a future (only inside `async fn` and routes).
- Generic calls: `json_decode<Event>(raw)`, `s.parse<i32>()` (or Rust's `::<T>`).
- JSON: `json_encode(x)?` gives a `str` (`json_pretty` for indented output). `json_decode<T>(raw)?` or `e: T = json_decode(raw)?` parses into `T`. Both return Results, so add `?`.

## Strings
- `"text {expr} {expr:?} {x:.2}"` interpolates any expression, with an optional Rust format spec after `:`. Write `{{` and `}}` for literal braces. A string literal can't appear inside `{...}`; assign it to a variable first.
- A literal becomes `String` or `&str` to match the declared param, field, variant or return type. Don't add `.to_string()` for Parvez-declared types.
- Args to Rust std methods have no declared type: a plain `"lit"` passes as `&str` and an interpolated `"..{x}.."` as `String`. Write `.to_string()` or `&"..."` when the method needs the other kind.
- `print(a, b, ...)` prints its arguments separated by spaces (`println!`); `eprint(...)` does the same on stderr. `fail("msg {x}")` returns an error immediately (`anyhow::bail!`, only in `!` functions).

## Rules rustc enforces
- Values move. Pass `&x` to `&T` params, iterate with `for u in &users:`, and use `.clone()` when you need a copy. Methods with `&~self` need a `~` binding.
- Integer literals default to `i32`. Annotate when you need another type: `x: u64 = 5`.
- A fallible call in a non-`!` fn needs explicit handling, e.g. `.unwrap_or(0)` or `.is_err()`.
- Casts (`as`) don't exist yet. Use typed literals (`x: u64 = 5`) or `.into()` / `T::from(x)` / `.try_into()?`.
- Not in v0.3: closures, traits, generics on your own types, macros (`vec!`, `json!`), shared state across routes. If you need one of these, run `parvez show f.prvz -o f.rs` and write Rust.

## Security (enforced at compile time)
Insecure patterns are compile errors (`file.prvz:N: security[rule]: ...` plus `= fix: ...`). Write the safe form from the start:
| rule | rejected | write instead |
|---|---|---|
| sql-injection | `query("... {x}")`, `query("..." + x)`, or a variable holding either | `sqlx::query("... WHERE id = $1").bind(x)` |
| command-injection | `Command::new(dynamic)`; `Command::new("sh").arg("-c").arg("{x}")` | `Command::new("tar").arg("czf").arg(x)` (fixed program, input as separate args) |
| path-traversal | route input (`{path}` params, `body`, `query`, or values derived from them) reaching `fs::*` / `File::open` | `std::fs::read_to_string(safe_join("/srv/data", &name)?)?` |
| hardcoded-secret | a string literal in a binding named like secret/password/token/api_key/private_key, or a key-like literal (`sk_live_`, `AKIA`, `ghp_`, long random strings) | `env("API_KEY")`, usually in `state:` |
- `safe_join(base, name)?` rejects `..`, absolute paths, separators and empty names: 400 in routes, an error elsewhere.
- Taint is tracked inside each route body only, not into other fns. SQL and secret checks apply everywhere.
- Opt out only deliberately: `@allow_insecure("reason")` on the line before a `fn`, `route`, method or `state:`. Every build prints the reason.

Services are hardened automatically (nothing to write):
- An unexpected error or panic returns 500 `{"error":"internal server error"}`. Details go to stderr only, and the server keeps running.
- Limits: body 2 MB (413), timeout 30 s (503), max 512 concurrent requests (then queue, then 503). Change the defaults in `parvez.toml` with `[service] body_limit_bytes`, `timeout_secs` and `max_concurrency`, or at runtime with `PARVEZ_BODY_LIMIT_BYTES`, `PARVEZ_TIMEOUT_SECS` and `PARVEZ_MAX_CONCURRENCY`.
- Every response carries `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Cache-Control: no-store` and `Referrer-Policy: no-referrer`.
- SIGINT and SIGTERM trigger a graceful shutdown: in-flight requests finish, then the process exits 0.

Supply chain (on `parvez build` and `parvez run`):
- Cargo.lock is checked against the RustSec advisory DB (cached, refreshed daily). A known vulnerability fails the build. Set `PARVEZ_AUDIT=warn|off` or `[security] audit` in parvez.toml to relax this.
- `<name>.sbom.json` (CycloneDX 1.5: every crate with its version, license and purl) is written next to the binary.

## Errors (fix loop)
Syntax and rustc errors both point at `.prvz` lines:
```
app.prvz:6: error[E0308]: mismatched types
   6 |     ret raw.len()
     = expected `i32`, found `usize`
     = rust: raw.len()
```
`= rust:` shows the generated Rust line. Fix the `.prvz` line it names. `parvez show --map f.prvz` prints the Rust with `// @prvz:N` comments.

## CLI
- `parvez check f.prvz`: fast type and borrow check with mapped errors and no binary. Use it in edit loops.
- `parvez run f.prvz [-- args]`: builds and executes.
- `parvez build f.prvz`: produces `./f`, a release binary.
- `parvez show f.prvz [-o f.rs] [--map]`: prints or writes the Rust.
- `parvez heal f.prvz`: updates dependencies to the newest compatible versions, then re-scans and re-checks. It reports advisories that need a major upgrade (pin those in parvez.toml).
- `parvez fuzz f.prvz`: builds and starts the service, then sends type-aware malformed and edge-case requests (bad types, boundary numbers, 100 KB strings, traversal and SQL payloads, 3 MB and 50k-deep bodies, wrong methods) to every route. It fails on a crash, a hang, or a leak of internals (panic text, `.rs:` paths, OS errors).
- `parvez mcp`: an MCP server on stdio with tools `parvez_spec`, `parvez_check` (code or path in, mapped errors or `ok` out) and `parvez_eject`. Register it with `claude mcp add parvez -- parvez mcp`.
