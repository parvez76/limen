# Parvez

**The usual security mistakes don't compile.**

Parvez is a small language for backend services and DevOps tools. You write a few lines. The compiler refuses the route nobody guarded, the secret headed for a log, and the query pasted together from strings. What you get back is one native binary.

## Picture this

It's Friday afternoon. You asked your AI agent for one more admin endpoint, and it wrote one. It reads fine. It also forgot the permission check, the kind of line a tired reviewer skims past.

You build it:

```
parvez: error: admin.prvz:1: route GET /admin/users has no access policy. Add @guard(fn) to require
sign-in or another check, or @public("why anyone may call it") to serve it to everyone (Parvez denies by default)
```

Nothing shipped. You add one line, `@guard(staff)`, and go home on time.

## Friday deploys get boring

Some mistakes can't reach production unless someone waives them on purpose, in writing, with `@allow_insecure("why")`. Every endpoint says who may call it, or the build stops. A `Secret` prints as `[redacted]`, can't be turned into JSON, and passing its value to a log, a print or an error message is a compile error. SQL pasted together from strings is a compile error anywhere. File paths and shell commands built from request input are compile errors too, even when the input went through helper functions, a trait or `state:` first. Every error comes with the fix:

```
leak.prvz:7: security[secret-exposure]: an exposed Secret is passed to `log_info(..)`
     = fix: pass `s.expose()` only to the API that needs the value (a DB bind, an HMAC key, a header);
            print or log the Secret itself, which shows [redacted]
leak.prvz:8: security[sql-injection]: `sqlx::query(..)` receives a string built from interpolation/concatenation
     = fix: never build SQL with interpolation or `+`; use a parameterized query,
            e.g. sqlx::query("SELECT * FROM users WHERE id = $1").bind(id)
```

Before a review, one command shows who can call what:

```
$ parvez routes app.prvz
METHOD  PATH          KIND      ACCESS                                                AT
GET     /ping         route     PUBLIC (load balancer health probe)                   app.prvz:5
GET     /admin/users  route     guard staff                                           app.prvz:9
GET     /healthz      built-in  PUBLIC (built-in health check)                        -
```

Before a release, `parvez fuzz` throws hostile input at every route and fails on any crash, hang or leaked internal detail.

## The whole service fits on one screen

This is a complete JSON service:

```
@json
type Event: id: str, kind: str, count: i32

@public
route GET "/health" -> str:
    ret "ok"

@public
route POST "/events" (body: Event) -> Event!:
    if body.count < 0: fail(400, "count must be >= 0")
    ret body
```

The same service written by hand in Rust with axum takes 48 lines plus a `Cargo.toml`. This one is 9, and 76 tokens instead of 402.¹ Both answer the same requests with the same status codes and the same JSON error format. Yours also comes with health checks, Prometheus metrics, request limits, timeouts and security headers you didn't write.

Short code is quicker to review, and it leaves room in an AI's context window for the part of the problem that's actually hard.

## When your agent slips, it lands on the right line

[SPEC.md](SPEC.md) is written as a compact system prompt, so an agent can learn the whole language from one file. `parvez mcp` lets the agent check its own code against the compiler (`claude mcp add parvez -- parvez mcp`). When something's wrong, the error points at the `.prvz` line it wrote, not at generated code:

```
typo.prvz:2: error[E0308]: mismatched types
   2 |     ret raw.len()
     = expected `i32`, found `usize`
     = line 1: expected `i32` because of return type
     = rust: raw.len()
```

## Leaving costs nothing

Parvez compiles to plain Rust. There's no separate runtime or library to depend on: what your program needs is in the generated code, where you can read it. The service above is a single 1.7 MB binary. If you ever outgrow Parvez, `parvez show app.prvz -o app.rs` hands you the Rust, and the matching `Cargo.toml` is already in `.parvez_build/app/`. From then on it's a Rust project:

```rust
fn staff(req: &Req) -> anyhow::Result<String> {
    Ok(req.header("x-user").unwrap_or_default())
}
```

## From nothing to running

On Linux or an Apple-silicon Mac:

```bash
curl -fsSL https://parvez76.github.io/parvez/install.sh | sh
parvez doctor                      # checks the setup and says how to fix anything missing
parvez new hello && cd hello       # a service with a page and passing tests
parvez test main.prvz
parvez run main.prvz               # http://localhost:8080
```

The installer checks the download against the release's published checksums before installing anything, and offers to set up Rust if you don't have it. The first build compiles the web stack once (about 30 seconds on an 8-core laptop, longer on smaller machines); later builds reuse it. `parvez upgrade` keeps you current, verified the same way. You can also [verify a release by hand](SECURITY.md#verifying-a-release) or build from source with `cargo install --git https://github.com/parvez76/parvez --tag v0.17.0 --locked`.

## What Parvez won't do

- **It won't catch your logic mistakes.** If your guard returns the wrong answer, Parvez enforces the wrong answer. The checks remove whole classes of bugs, not all of them. The known blind spots are listed in [SECURITY.md](SECURITY.md) and kept in a test suite.
- **It won't make memory perfectly clean.** `Secret` wipes its own memory and compares in constant time, but copies you make from it aren't wiped. [SECURITY.md](SECURITY.md) says exactly where the line is.
- **It isn't for everything.** It's built for services and command-line tools. Rust macros and lifetimes aren't supported; for those, run `parvez show` and continue in Rust.
- **It doesn't replace Rust.** It runs on top of it. The installer sets Rust up, and you also need a C linker; `parvez doctor` tells you what's missing.
- **It isn't on every platform yet.** Prebuilt binaries cover Linux (x86_64, ARM64) and Apple-silicon Macs. Windows is untested.
- **It's young.** Before 1.0, syntax and defaults can change between minor versions. The [changelog](docs/CHANGELOG.md) says when they do and what to change.

## Learn more

- [Reference](docs/REFERENCE.md): the language at a glance, every command, what's built into every service, full-stack services with Masud pages
- [SPEC.md](SPEC.md): the complete language, written for humans and AI agents
- [SECURITY.md](SECURITY.md): what Parvez enforces, mapped to CWE, OWASP and ASVS; how to verify a release; how to report a vulnerability
- [Changelog](docs/CHANGELOG.md)
- [examples/](examples/)

¹ Counting non-blank lines, and tokens with OpenAI's `tiktoken` (`o200k_base`; `cl100k_base` gives 76 and 403). The Rust version handles the same cases: the two routes, the validation error, bad JSON, and JSON 404 and 405 responses. Both versions and how to check them are in [docs/comparison](docs/comparison/).

## License

[MIT](LICENSE)
