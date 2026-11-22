# PARVEZ v0.19.0 SPEC (AI system prompt)

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

**Access is denied by default.** Every `route`, `socket` and Masud `page` must say who may call it, or it doesn't compile:
- `@guard(fn)`: the guard runs first and must succeed (sign-in, roles, ownership: see below);
- `@public` or `@public("why anyone may call it")`: deliberately open (health checks, sign-up, public pages).
Both on one endpoint is an error. `parvez routes app.prvz [--json]` prints the access map: every endpoint, its guards or public reason, and its file:line, plus the built-ins (`/healthz`, `/readyz`, `/metrics`, `/auth/*`).
```
@json
type Event: id: str, count: i32

@public
route GET "/health" -> str:                       # -> str sends text; any other type sends JSON
    ret "ok"
@public
route POST "/events" (body: Event) -> Event!:     # `body` = JSON request body
    if body.count < 0: fail(400, "bad count")     # fail(status, msg) -> that status + {"error": msg}
    ret body
@public
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
- `req.param("id")` reads a path parameter, so ownership/tenancy checks live in a reusable guard instead of every handler:
```
type DeviceOp: op: Operator, device: Uuid
async fn require_device(state, req) -> DeviceOp!:
    op = require_engineer(state, req).await?
    id = req.param("id").unwrap_or_default()
    if not visible(state, &op, &id).await?: fail(404, code: "not_found", "device not found")
    ret DeviceOp(op: op, device: id.parse<Uuid>()?)
@guard(require_device)
route GET "/devices/{id}" (state, auth, id: str) -> Device!:   # auth.device is already checked
```
- `@guard(auth::verify)` can name a guard in another module.

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
@public
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
Periodic work is declarative with `every` (units `ms s m h d`, at least 100ms), at the top level of any service file:
```
every 1h (state):                        # `(state)` is optional
    deleted = sqlx::query("DELETE FROM events WHERE at < now() - interval '30 days'").execute(&state.db).await?
    log_info("cleanup", rows: deleted.rows_affected())
```
The first run is one period after start. Runs never overlap; an error or panic is logged (`every 1h failed` in `/metrics`) and the next period runs again. Workers don't run under `parvez test` (call the logic as a function there).

Run futures concurrently with `parallel`: `a, b = parallel(fetch_a(), fetch_b())` waits for all (`tokio::join!`); `a, b = parallel(x(), y())?` requires every result to be `Ok` and returns the first error otherwise (`tokio::try_join!`). Pass the futures without `.await`.

## Embedded frontend and TypeScript

Place `@embed_dir("web/dist")` on its own line in the entry file. The directory is relative to that file and must contain `index.html`. Build the frontend first, using static export for Next.js. The compiler embeds regular files recursively and rejects symlinks. A service can consist entirely of this directive.

Explicit routes and pages take precedence. GET and HEAD serve assets with extension-based MIME types, directory indexes and extensionless HTML exports. Unmatched extensionless paths serve the root index for SPA navigation, but only to browser navigations (`Accept: text/html`). An API client calling a wrong path gets the JSON 404. Missing file-like paths return 404, and methods other than GET/HEAD on unmatched paths return 404 too.

`parvez types --ts [entry.prvz] [--out types.ts]` follows transitive imports from `main.prvz` by default. It works before the frontend build exists. Without `--out` it writes to stdout. It exports each `@json` model, a corresponding `Input` type that accounts for serde defaults, and `Routes` indexed by method and path. For example, `Routes["POST /events/{id}"]["body"]` is the JSON request type. Path parameters live in `params`, query parameters in `query`, and the success payload in `response`. Unit enum variants become string literals and variants with payloads become externally tagged unions.

`parvez types --openapi [entry.prvz] [--out api.json]` writes an OpenAPI 3.1 description instead: every route's path and query parameters, JSON request and response schemas (serde's wire format, as above), the success status set by `status(N)`, the shared `{"error", "code"}` error shape, a bearer-token security scheme for routes whose guard calls `oidc`/`oidc_session`, and each operation's guards or `@public` reason in `x-parvez-access`. WebSockets and the built-in endpoints aren't listed.

## Masud v0.1

Import a page module with `import ui.dashboard`. In `ui/dashboard.msd`, import backend modules just as in Parvez. Page headers accept the route parameter syntax. The renderer supports local `let` bindings, Parvez expressions, and serializable values. Control lines work like Parvez blocks: `for item in &items:`, `if cond:`, `elif cond:` and `else:`, each with indented markup underneath. Interpolated values inside them are escaped the same way. Strings render as text, other values use their JSON representation.

```
import models
@public
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
@public
@allow_unsafe_html("fragment generated by the trusted Markdown sanitizer")
page GET "/help" -> html:
    article:
        raw {models::sanitized_help()}
```
- `@guard(fn)` lines before a `page` (several run in order) work as on a `route`: the page header takes `auth` for the last guard's result, e.g. `@guard(require_staff)` + `page GET "/admin" (state, auth) -> html:`. A failing guard answers before any template code runs.
- Format specs in markup: `td {cpu:.1}%`, `{n:>6}`, `{x:08.3}`, `{v:?}`; the result is escaped like any value. Specs that read other arguments (`$`, `*`) are rejected.
- Inline SVG (charts, sparklines): `svg g path rect circle line polyline polygon text tspan defs linearGradient stop` with geometry and presentation attributes (`viewBox`, `d`, `points`, `x`/`y`/`cx`/`r`..., `fill`, `stroke`, `stroke-width`, `transform`, `opacity`, `text-anchor`, `font-size`, `offset`, `stop-color`...), which accept interpolation (escaped). `xmlns` must be the SVG namespace. No `href`, `style` or event handlers, so SVG can't run script.
```
svg(viewBox="0 0 100 8" width="60" height="8"):
    rect(width="{cpu}" height="8" fill="#1a7f37")
```
- `canvas(id="chart" width="300" height="80" data-series="{json}")` for a chart drawn by an external script; `data-*` attributes (lower-case names) accept interpolation on any element.

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

Reserved type names: a `type`, `enum` or `trait` can't be named after a Rust prelude item (`Result`, `Option`, `String`, `Vec`, `Box`, `Ok`, `Some`, `Clone`, `Iterator`, ...) or a Parvez runtime type (`AppError`, `Req`, `Secret`, `AppState`, ...): the generated code uses those names, so `parvez check` rejects them. Pick a domain name such as `LoginResult`.

## Generics, traits and visibility
```
@json
type Page<T>: items: [T], total: i64       # generic types (bounds: `type Sorted<T: Ord>: ...`)

impl Page<T>:                              # generics come from the type's declaration
    fn first(&self) -> Option<&T>:
        ret self.items.first()

fn page_of<T: Clone>(xs: &[T]) -> Page<T>:
    ret Page(items: xs.to_vec(), total: xs.len() as i64)

trait Store:                               # always Send + Sync, so it works in services and `state:`
    async fn get(&self, id: i64) -> Item?! # a signature: implement it in each `impl`
    fn name(&self) -> str:                 # a default body (sync methods only)
        ret "store"

impl Store for Postgres:
    async fn get(&self, id: i64) -> Item?!:
        ...

state:
    repo: Arc<dyn Store> = Arc::new(Postgres(...))   # swap in a fake Store in tests
```
- Use a trait either generically (`fn f<S: Store>(s: &S)`) or as `dyn Store` (`&dyn Store`, `Arc<dyn Store>`). Async trait methods are supported through `async-trait`.
- `parvez types --ts` exports generic `@json` types as `export type Page<T> = {...}`.
- `priv fn helper()` / `priv type` / `priv enum` / `priv trait` / `priv const` (and `priv fn` inside `impl`) are visible only inside their own file; everything else in a module is public. Calling a `priv` item from another file is a compile error at that line.

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
- Maps: `{"a": 1, "b": 2}` is a `HashMap` (`{}` is an empty one); keys and values are any expressions, string literals become `String`. Newlines are allowed inside the braces.
- `json({"sub": id, "n": 3, "tags": ["x"], "ratio": a as f64 / 2.0})` builds a `serde_json::Value` with mixed value types (nested maps and lists allowed); `json(x)` converts any serializable value.
- Casts: `x as i64`, `n as f64` (binds tighter than `+ - * /`).
- `catch` recovers from an error instead of failing the whole handler:
```
name = lookup(id).await catch e:         # a Result-returning call: Err(e) runs the handler
    log_warn("lookup failed", err: e.to_string())
    "unknown"                             # the handler's last expression is the value
port = env("PORT").parse<i32>()? catch: 8080   # `?` and fail(..) inside the left side land in the handler
```
  The handler runs in the enclosing function, so it may `ret`, `fail(...)` or use `?` itself.

## Strings
- `"text {expr} {expr:?} {x:.2}"` interpolates any expression, with an optional Rust format spec after `:`. Write `{{` and `}}` for literal braces. A string literal can't appear inside `{...}`; assign it to a variable first.
- A literal becomes `String` or `&str` to match the declared param, field, variant or return type. Don't add `.to_string()` for Parvez-declared types.
- Calls into Rust/crate code have no declared types here, so a plain `"lit"` passes as `&str` (e.g. `sqlx::query("...")`, `Path::new("/x")`) and an interpolated `"..{x}.."` as `String`. `Some("x")`, `Ok(..)`, `Arc::new(..)` and similar constructors get an owned `String`. Write `.to_string()` when an API needs ownership, e.g. `map.insert("k".to_string(), v)`.
- `print(a, b, ...)` prints its arguments separated by spaces (`println!`); `eprint(...)` does the same on stderr. `fail("msg {x}")` returns an error immediately (`anyhow::bail!`, only in `!` functions).

## Rules rustc enforces
- Values move. Pass `&x` to `&T` params, iterate with `for u in &users:`, and use `.clone()` when you need a copy. Methods with `&~self` need a `~` binding.
- Integer literals default to `i32`. Annotate when you need another type: `x: u64 = 5`.
- A fallible call in a non-`!` fn needs explicit handling, e.g. `.unwrap_or(0)` or `.is_err()`.
- `as` casts numbers (truncating like Rust); use `.try_into()?` when a value may not fit.
- Not supported: Rust macros (`vec!` - use `[..]`; `json!` - use `json({..})`), lifetimes, `unsafe`. For those, run `parvez show f.prvz -o f.rs` and continue in Rust.

## Security (enforced at compile time)
Insecure patterns are compile errors (`file.prvz:N: security[rule]: ...` plus `= fix: ...` and `= see: CWE-..., OWASP ..., ASVS ...`). Write the safe form from the start:
| rule | CWE | rejected | write instead |
|---|---|---|---|
| sql-injection | 89 | `query("... {x}")`, `query("..." + x)`, or a variable holding either | `sqlx::query("... WHERE id = $1").bind(x)` |
| command-injection | 78 | `Command::new(dynamic)`; `Command::new("sh").arg("-c").arg("{x}")` | `Command::new("tar").arg("czf").arg(x)` (fixed program, input as separate args) |
| path-traversal | 22 | request input (`{path}` params, `body`, `query`, `req`, a socket's `conn`, a guard's inputs, or values derived from them) reaching `fs::*` / `File::open`, also inside a helper fn it is passed to | `std::fs::read_to_string(safe_join("/srv/data", &name)?)?` |
| hardcoded-secret | 798 | a string literal in a binding named like secret/password/token/api_key/private_key, or a key-like literal (`sk_live_`, `AKIA`, `ghp_`, long random strings) | `api_key: Secret = env_secret("API_KEY")?` in `state:` |
| secret-type | 312, 316 | a `state:` field named like a secret (`token`, `password`, `api_key`, ...) typed `str` | `api_key: Secret = env_secret("API_KEY")?` |
| secret-exposure | 532, 200 | `s.expose()` inside `print`, `log_*`, `fail`, `assert`, `json`, `metric_inc`, an interpolated string, or a page | pass `s.expose()` only to the API that needs it: `.bind(s.expose())`, an HMAC key, a header |
- `safe_join(base, name)?` rejects `..`, absolute paths, separators and empty names: 400 in routes, an error elsewhere.
- Request input is followed into the functions and methods it is passed to, across modules, helper chains and recursion. The finding is on the route's call line and names the sink: "request input passed to `files::load(..)` reaches `std::fs::read_to_string(..)` at lib/files.prvz:6 unsanitized". Sanitize at either end with `safe_join`. A helper that only ever receives constants isn't flagged. SQL and secret checks apply everywhere.
- Parameters typed as numbers, `bool` or `char` aren't untrusted text: `/files/{id}` with `id: i64` can go into a path.
- Method calls follow the receiver's type: a known type (`Disk(..)`, a typed parameter or `state:` field, `Disk::new(..)`) goes to its `impl`; a `dyn Trait`, `Arc<dyn Trait>` or generic `S: Trait` goes to every implementation. When the type isn't known locally, the call is followed only if exactly one `impl` defines that method name.
- Types for method dispatch are also inferred from list elements (`[Disk(..)]`, `Vec<Box<dyn Store>>`, loops over them) and the declared return types of your functions and methods.
- A method that stores its argument in its object (`self.path = p`, `self.items.push(p)`) makes the receiver hold request data: after `job.set_path(name)`, `job.path` is untrusted.
- Database reads (`fetch_one`, `fetch_all`, `fetch_optional`, `query_as`/`query_scalar` results) are untrusted for file paths and commands (second-order injection): "data read from the database (an earlier request may have stored it) reaches ...". Declare numeric results with their type (`n: i64 = ...`), which is never treated as text.
- Request data stored in a `state:` field (`*state.f.lock().unwrap() = x`, `state.f.lock().unwrap().push(x)`, a lock guard, or a helper that stores its argument) taints every later read of that field, in any route, `every` worker or function. The finding names where it was stored: "request input stored in `state.last` (at app.prvz:14) reaches ...".
- Opt out only deliberately: `@allow_insecure("reason")` on the line before a `fn`, `route`, method or `state:`. Every build prints the reason.

Services are hardened automatically (nothing to write):
- An unexpected error or panic returns 500 `{"error":"internal server error"}`. Details go to stderr only, and the server keeps running.
- Limits: body 2 MB (413), timeout 30 s (503), max 512 concurrent requests (then queue, then 503). Change the defaults in `parvez.toml` with `[service] body_limit_bytes`, `timeout_secs` and `max_concurrency`, or at runtime with `PARVEZ_BODY_LIMIT_BYTES`, `PARVEZ_TIMEOUT_SECS` and `PARVEZ_MAX_CONCURRENCY`.
- Every response carries `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Cache-Control: no-store`, `Referrer-Policy: no-referrer` and `Strict-Transport-Security: max-age=31536000`.
- HTML responses (pages, embedded `.html` files) carry `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; base-uri 'self'; form-action 'self' <identity provider>; frame-ancestors 'none'`. Put scripts in files under `@embed_dir` (e.g. `/assets/app.js`), not inline `<script>` blocks or `onclick=` attributes. htmx works as is. Other responses get `default-src 'none'; frame-ancestors 'none'`.
- `PARVEZ_CSP` replaces the page policy and `PARVEZ_HSTS` the HSTS value (e.g. `max-age=63072000; includeSubDomains; preload`); `off` drops the header. An invalid value is reported at startup and the default is kept.
- SIGINT and SIGTERM trigger a graceful shutdown: in-flight requests finish, then the process exits 0.

Supply chain (on `parvez build` and `parvez run`):
- The crates actually compiled into the binary are checked against the RustSec advisory DB (cached, refreshed daily). Optional dependencies of disabled features are ignored. A known vulnerability fails the build. Set `PARVEZ_AUDIT=warn|off` or `[security] audit` in parvez.toml to relax this.
- `<name>.sbom.json` (CycloneDX 1.5: every compiled crate with its version, license and purl) is written next to the binary.


### Secrets
`Secret` holds a value that must never reach logs, output or responses:
```
state:
    api_key: Secret = env_secret("API_KEY")?           # fails at startup if unset; the error names only the variable
    break_glass: Secret = secret(env("BREAK_GLASS", ""))  # optional (empty = disabled)

@json
type Login: user: str, password: Secret               # input-only: decodes from requests, can't be returned

fn admin(state, req) -> str!:
    given = req.header("authorization").unwrap_or_default()
    if not state.api_key.matches(given.strip_prefix("Bearer ").unwrap_or("")):   # constant-time
        fail(401, code: "unauthenticated", "bad token")
    ret "admin"
```
- `print("{s}")`, `{x:?}` of a struct holding it, and panic messages show `[redacted]`. It has no `Serialize`, so it can't go into JSON or a log field, and a route returning a type that holds one is a compile error.
- `s.matches(candidate)` compares in constant time: both sides are hashed to SHA-256 and the digests compared with the `subtle` crate, so the time doesn't depend on where they differ or on the secret's length. `s == t` works the same way. `s.is_empty()` checks for a configured value.
- `s.expose()` is the only way to the value, for the API that needs it (`.bind(s.expose())`, an HMAC key, a header). The `secret-exposure` rule rejects it in output.
- The memory is zeroed when the value is dropped (the `zeroize` crate). `Secret<Vec<u8>>` holds binary keys.
- Limits: copies you make from `s.expose()` (a `.to_string()`, a formatted header) are ordinary values and aren't wiped, so pass `s.expose()` straight to the API that needs it. Memory freed when a value grew (a `String` that reallocated before it became a Secret) isn't wiped either; load secrets with `env_secret` or `secret(..)` so they're wrapped once. Constant time is best effort, as in every language: the compiler and CPU give no hard guarantee.
## Tests
Put `test "what it checks":` blocks in any file. They compile only for `parvez test` and may use `.await` and `?`.
```
test "orders need an api key":
    app = test_app().await?                       # the whole service in-process (state, guards, middleware), no port
    res = app.post("/orders", &Order(item: "pen", qty: 2)).await?
    assert_eq(res.status, 401)
    res = app.request("POST", "/orders").header("x-api-key", "k1").json(&order).send().await?
    r: Receipt = res.json()?
    assert(res.header("x-request-id").is_some(), "every response has a request id")
```
- `assert(cond)` and `assert(cond, "msg {x}")` fail with `file.prvz:LINE: ...`, as does `assert_eq(a, b)`.
- A response has `.status`, `.text()`, `.json<T>()` and `.header(name)`. Besides `get` and `post`, `app.request(method, path)` takes `.header(k, v)`, `.json(&v)` and `.body(b)`, then `.send()`.
- `parvez test f.prvz [name-filter]` runs every test in the program, including imported modules, and exits non-zero on failure. Failures point at `.prvz` lines (`panicked at tests.prvz:42:`).
- **Test-only code:** `@test_only` before a `fn`, `type`, `enum`, `impl`, `trait`, `const` or `use` (or `@test_only import testkit` for a whole module of helpers, fakes and fixtures) compiles it only for `parvez test` and `parvez check`. `parvez build` strips it, crates it alone uses become `[dev-dependencies]`, and it isn't security-linted as production code (fixture keys are fine). A guard, route or `every` worker can't be test-only.

## Observability (every service, automatic)
- **Request id:** a valid incoming `x-request-id` is propagated; otherwise one is generated. It's returned on every response and attached to every log line.
- **Logs:** JSON lines on stderr, including an access log (method, path, route template, status, duration_ms, request_id), errors and panics. Health checks aren't logged, and `PARVEZ_LOG=off` silences logging. Add your own with `log_info("order placed", user: id, qty: n)`, `log_warn(..)` or `log_error(..)`; these also work in CLI programs.
- **Metrics:** `GET /metrics` serves Prometheus text:
  - `parvez_http_requests_total{method,route,status}`, labelled by route **template**, with unknown paths as `unmatched`
  - the histogram `parvez_http_request_duration_seconds`
  - `parvez_http_requests_in_flight`
  - `parvez_events_total{event}` from `metric_inc("name")`

  Set `PARVEZ_METRICS_TOKEN` to require `Authorization: Bearer <token>`.
- **Health:** `GET /healthz` returns `ok`, and `GET /readyz` returns `{"status":"ready"}` once `state:` is initialized. A route of your own with the same path replaces the built-in one.

## OIDC sign-in (Keycloak, Entra ID, Auth0...)
```
async fn admin(req) -> Claims!:
    c = oidc(req).await?                     # validates Authorization: Bearer <jwt>
    if not c.has_role("App.Admin"): fail(403, code: "forbidden", "admin role required")
    ret c
@guard(admin)
route GET "/admin/devices" (auth) -> str:
    ret auth.email.clone()
```
- **Configuration:**
  - `PARVEZ_OIDC_ISSUER`: the issuer URL. It must be `https://`, except localhost for development.
  - `PARVEZ_OIDC_AUDIENCE`: the expected `aud`. **Required:** when it's unset every request fails closed with 401, because another client's token from the same realm would otherwise pass.
  - `PARVEZ_OIDC_JWKS_URL`: optional; by default it's taken from discovery.
- **Checks:** the signature, using asymmetric algorithms only (`none` and HMAC are rejected), plus issuer, audience, `exp` and `nbf` with 60 s leeway, a non-empty `sub`, and `typ`: when `typ` is present it must be `Bearer`, so Keycloak ID and refresh tokens (same signing key) are rejected. Signing keys are cached for 10 minutes, and an unknown key ID triggers one refetch to handle key rotation. Any failure returns 401 `{"code":"unauthenticated"}`.
- `PARVEZ_OIDC_LEEWAY_SECS` (default 60) is the allowed clock skew. If the signing keys can't be fetched and none are cached, the answer is 503 `idp_unavailable` (an outage, not a bad token).
- **`Claims`:** `sub`, `email`, `name`, `username` and `roles` (merged from `realm_access.roles`, `resource_access.<audience>.roles` (only this API's own client) and `roles`). `email` falls back to `preferred_username`, and `name` falls back to `email`, plus `has_role(r)`, `claim(name)` and `raw`.

## Browser sign-in (Masud pages)
`oidc_session(req)` returns the same `Claims` as `oidc(req)`, for people in a browser and for API clients alike: a request with `Authorization: Bearer` is validated as with `oidc`, otherwise the encrypted session cookie is used.
```
async fn require_staff(req) -> Claims!:
    c = oidc_session(req).await?
    if not c.has_role("App.Engineer"): fail(403, code: "forbidden", "engineers only")
    ret c

# ui/dash.msd: @guard works on pages exactly as on routes; `auth` is its result
@guard(require_staff)
page GET "/dash" (auth) -> html:
    p Signed in as {auth.email}
    form(method="post" action="/auth/logout"):
        button(type="submit") Sign out
```
- Using `oidc_session` adds `GET /auth/login?next=/path`, `GET /auth/callback` and `POST /auth/logout`. Sign-in is the authorization code flow with PKCE (S256), a random `state`, and an encrypted 10-minute login cookie; `next` only accepts local paths.
- The session (access + refresh token) is an AES-256-GCM encrypted cookie: `HttpOnly`, `SameSite=Lax`, `Path=/`, plus `Secure` and the `__Host-` prefix on https. Large sessions are split over several cookies. An expired access token is refreshed transparently; the session ends after `PARVEZ_SESSION_MAX_AGE_SECS` (default 8 h) or when refresh fails.
- Not signed in: a browser navigation is redirected to `/auth/login`, an htmx request gets `HX-Redirect`, an API client gets 401 `{"code":"unauthenticated"}`.
- CSRF: a cookie-authenticated request other than GET/HEAD must carry this site's `Origin` (or `Sec-Fetch-Site: same-origin`), otherwise 403 `csrf`.
- Logout clears the cookies and redirects to the IdP's `end_session_endpoint` (register `PARVEZ_PUBLIC_URL/` as a post-logout redirect URI).
- **Revocation:**
  - `POST /auth/backchannel-logout` implements OIDC Back-Channel Logout. Set the client's back-channel logout URL to `PARVEZ_PUBLIC_URL/auth/backchannel-logout` (Keycloak: "Backchannel logout URL", session required). A verified logout token (signature, issuer, `aud` = the client id, logout event, no `nonce`, recent `iat`) ends that session at once; a token with only `sub` ends all of the user's sessions. Bearer tokens of a revoked session or user (issued before the logout) are refused too. The revocation list lives in memory, per instance.
  - Every `PARVEZ_SESSION_RECHECK_SECS` (default 60) a browser session is re-confirmed with the IdP through a refresh, even while its access token is valid. A disabled or deleted user, or an ended IdP session, is therefore signed out within that interval on every instance, with or without back-channel calls.
  - Bearer tokens without a back-channel logout stay valid until they expire (as with any locally validated JWT); keep access-token lifetimes short.
- CSRF: `Origin: null` (sent by browsers for form posts under `Referrer-Policy: no-referrer`) defers to `Sec-Fetch-Site: same-origin`.
- Environment: `PARVEZ_OIDC_CLIENT_ID` (the browser client, e.g. `my-dashboard`), `PARVEZ_OIDC_CLIENT_SECRET` (confidential clients), `PARVEZ_PUBLIC_URL` (what users open; https, or http://localhost for development; the redirect URI is `PARVEZ_PUBLIC_URL/auth/callback`), `PARVEZ_SESSION_KEY` (64 hex characters: `openssl rand -hex 32`), plus the `PARVEZ_OIDC_*` settings above. Without them nobody can sign in, and the `/auth` routes log why.
- Every service with Masud pages answers failing browser navigations with a small HTML error page instead of JSON.

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
- `parvez test f.prvz [filter]`: runs the `test` blocks.
- `parvez doctor`: checks the setup (Rust 1.88+, cargo, a C linker or, on Windows, the Visual Studio C++ build tools, git, the advisory database, cross targets, PATH) and prints the fix for anything missing; exits 1 if building can't work.
- `parvez upgrade [--version vX.Y.Z] [--check] [--force]`: replaces parvez with a newer release after checking it against the release's SHA256SUMS (and its build attestation when `gh` is installed). A cargo-installed parvez is told to update with cargo instead.
- `parvez lint f.prvz [--sarif [-o out.sarif]]`: the security rules only, no build. Exits 1 on findings. `--sarif` writes SARIF 2.1.0 for GitHub code scanning and similar tools (CWE tags, severity, `@allow_insecure` waivers as suppressed results). `parvez lint --rules` lists the rules with their CWE / OWASP / ASVS references.
- `parvez routes f.prvz [--json]`: the access map for security review (every endpoint with its guards or `@public` reason).
- `parvez check f.prvz`: fast type and borrow check with mapped errors and no binary, including `test` blocks and `@test_only` code. Use it in edit loops.
- `parvez run f.prvz [-- args]`: builds and executes.
- `parvez build f.prvz [--target <triple>]`: produces `./f`, a release binary, and `./f.sha256` (`sha256sum -c f.sha256` verifies it). `--target x86_64-unknown-linux-musl` builds a static Linux binary, `--target aarch64-unknown-linux-gnu` an ARM one; the output is `./f-<triple>`. A missing target says which `rustup target add` to run; another CPU architecture needs its cross linker (or `cargo-zigbuild`, which Parvez uses automatically when installed).
- `parvez new <name>`: creates `<name>/` with `parvez.toml`, `main.prvz` (a route and two tests), `ui/home.msd`, `.gitignore` and a README. `parvez test main.prvz` passes immediately.
- `parvez fmt [paths...]`: formats `.prvz` and `.msd` files in place (directories recursively): 4-space indentation, canonical spacing, one blank line between top-level items, comments kept. Each change is verified to leave the program identical. `--check` lists files that would change and exits 1 (for CI).
- `parvez show f.prvz [-o f.rs] [--map]`: prints or writes the Rust.
- `parvez heal f.prvz`: updates dependencies to the newest compatible versions, then re-scans and re-checks. It reports advisories that need a major upgrade (pin those in parvez.toml).
- `parvez fuzz f.prvz`: builds and starts the service, then sends type-aware malformed and edge-case requests (bad types, boundary numbers, 100 KB strings, traversal and SQL payloads, 3 MB and 50k-deep bodies, wrong methods) to every route. It fails on a crash, a hang, or a leak of internals (panic text, `.rs:` paths, OS errors).
  - It reports per-route **coverage**: how many requests got past validation and guards into the handler.
  - To reach handlers, put `fuzz.toml` next to the file. `[params]` gives path or query values (e.g. a real UUID), `[body]` sets JSON body fields, and `[headers]` is sent with every request. `[sign] command = ["python3", "sign.py"]` signs each request: it gets `FUZZ_METHOD`, `FUZZ_PATH` and `FUZZ_QUERY` in env and the body on stdin, and prints `Header: value` lines. Each route also gets one `no-auth` request. A route that decodes its own body with `json_decode<T>(&req.text_body())` is fuzzed with `T`-shaped bodies.
- Compiler limits: nesting deeper than 256 levels, or more than 2000 operators in one expression, is a clean error.
- `parvez mcp`: an MCP server on stdio. Each request is isolated (a compiler bug returns an error). `parvez_check` **refuses unknown crates** because their build scripts would run; allow specific ones with `PARVEZ_MCP_ALLOW_CRATES=a,b`.
- `parvez mcp` tools: `parvez_spec`, `parvez_check` (code or path in, mapped errors or `ok` out) and `parvez_eject`. Register it with `claude mcp add parvez -- parvez mcp`.
