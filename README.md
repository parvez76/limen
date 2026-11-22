# Parvez

A small language for HTTP services and command-line tools. It compiles to plain Rust, and its compiler always runs a fixed set of security checks: a route without an access policy, SQL built from strings, request data reaching the filesystem or a process, and secrets reaching logs are build errors.

**Status:** experimental and pre-1.0. One maintainer, not independently audited. Syntax and defaults can still change.

![An admin route without an access policy is refused by `parvez check`; adding a guard makes it compile](docs/demo/demo.svg)

[Try it in your browser](https://parvez76.github.io/parvez/play/) (the real compiler, as WebAssembly; no install) · [Why a language, and not a Rust crate?](docs/WHY-A-LANGUAGE.md) · [How it was built](docs/HOW-IT-WAS-BUILT.md)

## What it is

- **Syntax:** indentation-based and compact. A JSON service with two routes and validation is [9 lines](docs/comparison/); a multi-user app with Postgres, sign-in, a page and tests is [about 90](examples/tasks/).
- **Output:** readable Rust (axum, tokio, serde, sqlx). `rustc` does all type and borrow checking, and errors are mapped back to `.prvz` lines. There's no separate runtime library, and `parvez show` prints the generated Rust if you want to leave.
- **Scope:** HTTP/JSON services, server-rendered HTML pages, WebSockets, background workers and CLI tools. Programs can call any Rust crate. No macros, lifetimes or `unsafe`.
- **For AI agents:** [SPEC.md](SPEC.md) is written to be read by an agent (about 3,000 tokens for the core, more by topic), and `parvez mcp` lets an agent check its own code. Whether agents write correct Parvez more reliably than correct Rust **hasn't been measured yet**.

## What the compiler checks

These checks run on every `build`, `run`, `check`, `test` and `show`; there's no setting to turn them off. The only way to waive one is `@allow_insecure("reason")` on a function, route or `state:` block, which is printed on every build and recorded in the SARIF report.

| Check | What it catches | Limits |
|---|---|---|
| Access policy | A route, socket or page without `@guard(fn)` or `@public("reason")` | Doesn't check that a guard's logic is right |
| SQL built from strings | Interpolated, concatenated or `format`-ed strings passed to SQL calls (`query`, `execute`, ...), anywhere | Recognizes SQL calls by name; add others with `[security.sinks] sql` |
| SQL against the schema | With `schema.sql` or `migrations/*.sql` next to the program: unknown tables and columns, placeholder count vs `.bind()`, bound-value types, `query_as` fields (selected, typed, `?` when the column can be NULL). `parvez check --db` also asks the live database to describe every query, as `sqlx::query!` does | Offline: names and simple types only, not function return types or views; SQL the parser can't read is skipped. `--db` needs a reachable database and only describes queries |
| Request data to files and processes | Route parameters, bodies, headers, WebSocket messages and database reads reaching `std::fs`, `File`, `OpenOptions` or `Command`, followed through functions, modules, traits, objects and `state:` with no depth limit | Only those sinks, plus any added with `[security.sinks]` in `parvez.toml`. Data passed through channels, and file, environment or HTTP-response contents, aren't treated as untrusted |
| Secrets | `Secret` values print as `[redacted]` and can't be serialized; passing `.expose()` to logs, prints, errors, pages or strings; secret-named `state:` fields typed `str`; credential-like literals | Literal detection is pattern- and entropy-based; copies made from `.expose()` aren't wiped from memory |

Projects can add their own rules in `parvez.toml`: banned calls with a reason (`[security] disallow`, like Clippy's `disallowed_methods`) and extra sinks. Each rule maps to CWE, OWASP Top 10 and ASVS, `parvez lint --sarif` produces a report for code scanning, and the [adversarial test corpus](tests/security_corpus/) (including the known misses) runs on every change. Details and the full limits: [SECURITY.md](SECURITY.md).

## What generated services do by default

- JSON errors for every failure; panics and internal errors become a generic 500, with details in the server log only.
- A 2 MB body limit, a 30 s timeout and at most 512 concurrent requests (configurable), and graceful shutdown.
- `Content-Security-Policy` on pages, `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy` and `Cache-Control: no-store` headers.
- JSON logs with request IDs, Prometheus `/metrics`, `/healthz` and `/readyz`.
- Optional OpenID Connect: bearer tokens, or browser sign-in with encrypted session cookies, CSRF checks and back-channel logout.
- On `parvez build`: dependencies checked against the RustSec advisory database (a known vulnerability fails the build), an optional license allowlist and banned-crate list (`[security] licenses`, `ban`), and a CycloneDX SBOM.

## What it doesn't do

- It doesn't catch logic errors. A guard that returns the wrong answer is enforced as written.
- It doesn't replace Rust. It needs the Rust toolchain and a C linker (the installer and `parvez doctor` help with both).
- It covers backend services and tools, not general-purpose programming.
- It has no editor plugin or language server yet.
- Its tests run on Linux and Windows in CI (Windows support is beta). macOS binaries are built and released, but the test suite doesn't run on macOS in CI yet.

## Install

```bash
curl -fsSL https://parvez76.github.io/parvez/install.sh | sh        # Linux, macOS (Apple silicon)
irm https://parvez76.github.io/parvez/install.ps1 | iex             # Windows, in PowerShell
```

The installers verify the download against the release's checksums before installing, and offer to install Rust if it's missing. Or build from source: `cargo install --git https://github.com/parvez76/parvez --tag v0.20.0 --locked`. Releases are signed and reproducible; see [verifying a release](SECURITY.md#verifying-a-release).

```bash
parvez doctor                    # check the setup
parvez new hello && cd hello     # a small service with a page and tests
parvez test main.prvz
parvez run main.prvz             # http://localhost:8080
```

## Learn more

- [Why a language, and not a Rust crate?](docs/WHY-A-LANGUAGE.md): what existing Rust tools already do, and where Parvez differs
- [Reference](docs/REFERENCE.md): the language at a glance, every command, what's built into services
- [SPEC.md](SPEC.md): the full language definition
- [SECURITY.md](SECURITY.md): the rules and their limits, how to verify a release, how to report a vulnerability
- [Contributing](CONTRIBUTING.md): if you find a way past a check, that's the most useful report
- [Changelog](docs/CHANGELOG.md) · [examples/](examples/) · [How it was built](docs/HOW-IT-WAS-BUILT.md)

## License

[MIT](LICENSE)
