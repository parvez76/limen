# PARVEZ v0.8 SPEC (AI system prompt)

You write Parvez (`.prvz`). It transpiles 1:1 to Rust and is compiled by rustc, so Rust's type, ownership and borrow rules all apply. Syntax is Python-like and indentation-based. Write only the constructs listed here.

## Lexical
- Indent with spaces only (tabs are an error). A block opens with `:` and either a NEWLINE plus an indented body or one statement on the same line: `if x: ret 1`.
- `#` starts a comment. Newlines inside `()` and `[]` are ignored, so lists and calls can span lines. A long method chain can wrap inside `( ... )`.
- A line that starts with `.name` continues the previous line, so method chains need no parentheses:
  ```
  rows = sqlx::query("SELECT 1")
      .fetch_all(&state.db)
      .await?
  ```
- `'a'`, `'\n'` and `'\u{1F600}'` are char literals. `\u{..}` escapes work inside interpolated strings.
- `"""` starts a multi-line string, ideal for SQL and templates. Common indentation and the first and last blank lines are removed, `"` needs no escaping, and `{x}` still interpolates.
- Keywords: `fn type enum impl match use async if elif else for in while ret break continue true false and or not` (`route`, `state`, `loop`, `spawn` and `move` act as keywords only in their positions, so they still work as names).
- Keywords can be field names (`e.type`, `Event(type: "x")`, `type E: type: str`). Rust keywords such as `gen`, `move` and `loop` work as any name; Parvez escapes them (`r#gen`), and JSON still sees `"type"`.

## Files and modules
`import store` loads `store.prvz`, and `import auth.tokens` loads `auth/tokens.prvz` (paths are relative to the main file). Refer to a module's items as `store::find(id)` or `store::Item`. Inside a module, its own names come first, then the main file's. An import can also resolve to a Masud `.msd` module. A module path must resolve to a single file. Modules may hold `const`, `fn`, `type`, `enum`, `impl`, `use`, `route` and `socket`; `state:` and `fn main` stay in the main file. Errors name the file: `auth/tokens.prvz:12: ...`.

## Top level
```
const MIN_AGE: u8 = 18                 # public as people::MIN_AGE in module people
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
Field decorators on a `@json` type (block form, on the line above the field): `@rename("type")` sets the JSON name, `@default` makes a missing field take its default, and `@omit_none` leaves out a `T?` field that is `None`.

Rust checks constant initializers at compile time. A `str` constant stores static string data. Parvez converts it to an owned string in typed value positions.

```
fn label(count: i32?) -> str:
    if let Some(n) = count:
        ret if n == 1: "one" else: "many"
    ret "unknown"
```

An `if` expression evaluates one branch and requires an `else` and compatible branch types. Statement conditions support `if let PATTERN = expr`, including `Some(v)` and `Ok(v)`. Pattern variables are scoped to the matching branch.

## Crates
`use serde::{Serialize, Deserialize}`, `use std::collections::HashMap`, `use reqwest` (declares the dependency only). Dependencies are detected from `use` lines and from known crate paths such as `reqwest::get(u)` or `tokio::time::sleep(d)`, and written into Cargo.toml automatically. Known crates: tokio axum serde serde_json reqwest chrono uuid regex rand tracing tracing_subscriber tower_http futures clap base64 sha2 hmac hex ed25519_dalek subtle jsonwebtoken redis thiserror sqlx (postgres + chrono/uuid/json/derive/migrate). Other crates resolve to the latest version. To pin a crate or add features, put them in `parvez.toml` next to the `.prvz` file:
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
- Params are path params (`{x}` in the path), `body` (JSON body), `query` (a `@json` type built from the query string), and the untyped `state`, `req` and `auth`. Methods: GET POST PUT PATCH DELETE.
- Route bodies are async (`.await` works). In a `!` route, `fail("msg")` and `?` errors return 500 `{"error": ...}`.
- `fail(401, code: "INVALID_SIG", "bad signature")` returns `{"error": "bad signature", "code": "INVALID_SIG"}` with that status.
- `status(204)` in a route (or any fn it calls) sets the success status. An empty route plus `status(204)` gives No Content; use `status(201)` before `ret value` for Created.

### Request access and guards
```
fn verify(state, req) -> Uuid!:                    # a guard: untyped `state` and/or `req` params only
    id = req.header("x-device-id")                 # -> str? (case-insensitive)
    if id.is_none(): fail(401, code: "unauthenticated", "missing x-device-id")
    ret id.unwrap().parse<Uuid>()?
@guard(verify)                                      # runs before the handler; several run in order
route POST "/hb" (state, req, auth, body: Beat)!:  # auth = the last guard's return value
    print("{auth} from {req.client_ip()}")
    status(204)
```
- `req` methods: `header(name) -> str?`, `raw_body() -> &[u8]` (exact bytes, e.g. for signatures), `text_body() -> str`, `client_ip() -> str`, `method()`, `path()`, `query_string()`.
- Set `PARVEZ_TRUST_PROXY=1` behind a reverse proxy so `client_ip()` uses `X-Real-IP` / `X-Forwarded-For`.
- A route with `req` still accepts `body: T`: it's parsed from the raw bytes, and invalid JSON gives 422. `@body_error(400, code: "bad_request", "invalid JSON body")` on a route sets that response instead.
- `req.param("id")` reads a path parameter (useful in guards). `@guard(auth::verify)` can name a guard in another module.

### WebSockets
```
@guard(ticket)                  # runs before the upgrade: it can still answer 401/409
@protocols("ro.v1")             # subprotocol negotiation
@max_message(8388608)           # bytes per message
socket "/ws/{room}" (state, auth, room: str, conn):
    peers_add(state, conn.sender())        # WsSender: cloneable, storable in state, usable from any task
    loop:
        match conn.recv().await?:          # WsMsg::Text(str) / WsMsg::Binary([u8]); None once closed
            Some(msg) -> conn.sender().send(&msg)
            None -> break
```
- On `conn`: `recv()`, `recv_json<T>()`, `send_text(s)`, `send_bytes(b)` and `send_json(&v)` (these wait for queue space), plus `sender()`, `protocol()` and `close(code, reason)`.
- On `WsSender`: `text(s)`, `bytes(b)`, `send(&msg)` and `json(&v)` never block. If the client is slow (queue of 64 full) or gone, the frame is dropped and they return `false`. Also `close(code, reason)` and `same(&other)`.
- On `WsMsg`: `is_text()`, `len()`, `text()`, `bytes()`.
- Pings every 20 s (`PARVEZ_WS_PING_SECS`) are automatic. When the handler returns, the socket closes with 1000.
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

### Background tasks
`spawn fut` (e.g. `spawn cleanup(db.clone())`) or a `spawn:` block runs in the background (`tokio::spawn`) and returns a handle you can `.await`. A `spawn ...` line inside `state:` starts a worker at startup, once all fields exist:
```
state:
    db: PgPool = PgPool::connect(&env("DATABASE_URL")).await?
    spawn retention(db.clone())          # e.g. an async fn with `loop:` + tokio::time::interval
```

## Embedded frontend and TypeScript

Place `@embed_dir("web/dist")` on its own line in the entry file. The directory is relative to that file and must contain `index.html`. Build the frontend first, using static export for Next.js. The compiler embeds regular files recursively and rejects symlinks. A service can consist entirely of this directive.

Explicit routes and pages take precedence. GET and HEAD serve assets with extension-based MIME types, directory indexes and extensionless HTML exports. Unmatched extensionless paths serve the root index for SPA navigation, but only to browser navigations (`Accept: text/html`). An API client calling a wrong path gets the JSON 404. Missing file-like paths return 404, and methods other than GET/HEAD on unmatched paths return 404 too.

`parvez types --ts [entry.prvz] [--out types.ts]` follows transitive imports from `main.prvz` by default. It works before the frontend build exists. Without `--out` it writes to stdout. It exports each `@json` model, a corresponding `Input` type that accounts for serde defaults, and `Routes` indexed by method and path. For example, `Routes["POST /events/{id}"]["body"]` is the JSON request type. Path parameters live in `params`, query parameters in `query`, and the success payload in `response`. Unit enum variants become string literals and variants with payloads become externally tagged unions.

## Masud v0.1

Import a page module with `import ui.dashboard`. In `ui/dashboard.msd`, import backend modules just as in Parvez. Page headers accept the route parameter syntax. The renderer supports local `let` bindings, Parvez expressions, and serializable values. Strings render as text, other values use their JSON representation.

```
import models
page GET "/users/{id}" (id: u32) -> html:
    let user = models::find(id)?
    main:
        h1 {user.name}
        button(hx-get="/users" hx-target="#list") Refresh
        div(id="list") {user.status}
```

A trailing colon opens children. Attributes use double quotes inside parentheses. Load a local htmx bundle with `script(src="/assets/htmx.min.js")`. Text and plain text attributes such as `title`, `alt`, and `aria-label` accept interpolation. The compiler escapes ampersands, angle brackets, and both quote characters. URL and htmx attributes take literals. Inline scripts and event-handler attributes are outside the template grammar.

A page can insert a trusted fragment with an explicit raw line. Other interpolations on the same page still escape their values.

```
@allow_unsafe_html("fragment generated by the trusted Markdown sanitizer")
page GET "/help" -> html:
    article:
        raw {models::sanitized_help()}
```

## Types
| Parvez | Rust |
|---|---|
| `i8..i64 u8..u64 usize f32 f64 bool` | same |
| `str` / `&str` | `String` / `&str` |
| `[T]` / `&[T]` | `Vec<T>` / `&[T]` |
| `T?` | `Option<T>` |
| `&T` / `&~T` | `&T` / `&mut T` |
| `()` / `(A, B)` | unit / tuple |
| `fn(A, B) -> R` | `impl Fn(A, B) -> R` (fn params and returns) |
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
for (k, v) in &map:
while c:
loop:             # forever, until `break`
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
- Tuples: `(1, "a")`, `()`; fields `t.0`, `t.1`. Destructure with `a, ~b = pair()`.
- Closures: `|x| x * 2`, `|a, b: i32| a + b`, `move |x| ...`. With a return type, a closure takes a block: `|x: i32| -> str:` and then an indented body (`ret` returns from the closure). Use them with `.map`, `.filter`, callbacks and `fn(A) -> R` params.
- `?` propagates an error. Use it only inside a `!` function. `x.await` awaits a future (only inside `async fn` and routes).
- Generic calls: `json_decode<Event>(raw)`, `s.parse<i32>()` (or Rust's `::<T>`).
- JSON: `json_encode(x)?` gives a `str` (`json_pretty` for indented output). `json_decode<T>(raw)?` or `e: T = json_decode(raw)?` parses into `T`. Both return Results, so add `?`.

## Strings
- `"text {expr} {expr:?} {x:.2}"` interpolates any expression, with an optional Rust format spec after `:`. Write `{{` and `}}` for literal braces. A string literal can't appear inside `{...}`; assign it to a variable first.
- A literal becomes `String` or `&str` to match the declared param, field, variant or return type. Don't add `.to_string()` for Parvez-declared types.
- Calls into Rust/crate code have no declared types here, so a plain `"lit"` passes as `&str` (e.g. `sqlx::query("...")`, `Path::new("/x")`) and an interpolated `"..{x}.."` as `String`. `Some("x")`, `Ok(..)`, `Arc::new(..)` and similar constructors get an owned `String`. Write `.to_string()` when an API needs ownership, e.g. `map.insert("k".to_string(), v)`.
- `print(a, b, ...)` prints its arguments separated by spaces (`println!`); `eprint(...)` does the same on stderr. `fail("msg {x}")` returns an error immediately (`anyhow::bail!`, only in `!` functions).

## Rules rustc enforces
- Values move. Pass `&x` to `&T` params, iterate with `for u in &users:`, and use `.clone()` when you need a copy. Methods with `&~self` need a `~` binding.
- Integer literals default to `i32`. Annotate when you need another type: `x: u64 = 5`.
- A fallible call in a non-`!` fn needs explicit handling, e.g. `.unwrap_or(0)` or `.is_err()`.
- Casts (`as`) don't exist yet. Use typed literals (`x: u64 = 5`) or `.into()` / `T::from(x)` / `.try_into()?`.
- Not supported yet: traits, generics on your own types, macros (`vec!`, `json!`). If you need one of these, run `parvez show f.prvz -o f.rs` and write Rust.

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
- The crates actually compiled into the binary are checked against the RustSec advisory DB (cached, refreshed daily). Optional dependencies of disabled features are ignored. A known vulnerability fails the build. Set `PARVEZ_AUDIT=warn|off` or `[security] audit` in parvez.toml to relax this.
- `<name>.sbom.json` (CycloneDX 1.5: every compiled crate with its version, license and purl) is written next to the binary.

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
  - It reports per-route **coverage**: how many requests got past validation and guards into the handler.
  - To reach handlers, put `fuzz.toml` next to the file. `[params]` gives path or query values (e.g. a real UUID), `[body]` sets JSON body fields, and `[headers]` is sent with every request. `[sign] command = ["python3", "sign.py"]` signs each request: it gets `FUZZ_METHOD`, `FUZZ_PATH` and `FUZZ_QUERY` in env and the body on stdin, and prints `Header: value` lines. Each route also gets one `no-auth` request. A route that decodes its own body with `json_decode<T>(&req.text_body())` is fuzzed with `T`-shaped bodies.
- Compiler limits: nesting deeper than 256 levels, or more than 2000 operators in one expression, is a clean error.
- `parvez mcp`: an MCP server on stdio. Each request is isolated (a compiler bug returns an error). `parvez_check` **refuses unknown crates** because their build scripts would run; allow specific ones with `PARVEZ_MCP_ALLOW_CRATES=a,b`.
- `parvez mcp` tools: `parvez_spec`, `parvez_check` (code or path in, mapped errors or `ok` out) and `parvez_eject`. Register it with `claude mcp add parvez -- parvez mcp`.
