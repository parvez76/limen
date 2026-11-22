# Why a language, and not a Rust crate?

It's the right first question. Most of what Parvez enforces can be approximated in plain Rust, and a disciplined team of Rust experts already gets most of the way there today. This page starts with what the existing tools do well, then says what's left, and who that difference is for.

## What plain Rust already gives you

Credit where it's due. These are good tools, and some are stronger than Parvez in their own lane:

| Concern | In Rust today | Compared with Parvez |
|---|---|---|
| Secrets in logs | The [`secrecy`](https://crates.io/crates/secrecy) crate: redacted `Debug`, zeroized on drop, no serialization unless you opt in, an explicit `expose_secret()` | **Stronger.** Parvez's `Secret` is the same idea, plus a compile error when an exposed value reaches a log, print, error or page. |
| SQL | [`sqlx::query!`](https://docs.rs/sqlx/latest/sqlx/macro.query.html) asks the database to describe the query at compile time (or reads a prepared cache), for the queries written with the macro | **Matches, and covers more.** Every literal query is checked offline against `schema.sql` or `migrations/` on every build (tables, columns, placeholder count, bound-value types, `query_as` fields and NULL-ability), and `parvez check --db` asks the live database to describe each one, as `sqlx::query!` does. SQL built from strings is a build error everywhere, not just where the macro was used. |
| Missing auth checks | Axum extractors: a handler that takes an `AuthUser` argument can't run without authentication. A custom router wrapper can require one on every route | **Stronger.** In Parvez a route without `@guard` or `@public("reason")` isn't a valid program, so there's no wrapper to forget. |
| Banned calls, risky patterns | Clippy's [`disallowed_methods`](https://rust-lang.github.io/rust-clippy/master/index.html#disallowed_methods), custom lints ([Dylint](https://github.com/trailofbits/dylint)), [Semgrep](https://semgrep.dev) rules for Rust | **Matches `disallowed_methods`, not Semgrep.** `[security] disallow` in `parvez.toml` bans calls with a reason, and `[security.sinks]` adds third-party functions to the request-data analysis. Arbitrary code patterns (Semgrep, Dylint) aren't supported. |
| Vulnerable dependencies, licenses, SBOM | [`cargo-deny`](https://github.com/EmbarkStudios/cargo-deny), `cargo-audit`, `cargo-cyclonedx` | **Matches the core of cargo-deny.** RustSec check, license allowlist (`[security] licenses`), banned crates (`[security] ban`) and an SBOM on every build, without setup. cargo-deny's source and duplicate-version checks aren't covered. |
| Memory safety | Rust | **Identical:** Parvez generates safe Rust and inherits it. |

If your team is experienced in Rust, reviews carefully, and has these tools wired into CI on every project, you already have most of what Parvez offers. Keep using Rust.

## What's left: who decides that the checks run

Every row above is **opt-in, per project, and can be switched off a line at a time**:

- The crate, the wrapper, the lint config and the CI job have to be added, and kept, in every project. A new service starts without them.
- `#[allow(clippy::...)]`, `// nosemgrep`, or one handler written without the wrapper silences a check right where it's inconvenient. Nobody sees it unless they read that line.
- An AI agent writing plain axum doesn't know about your wrapper unless you tell it every time. Agents routinely add `#[allow(...)]` to make a warning go away.

In Parvez those decisions aren't available:

- **There's no "off".** The checks are part of the compiler: `parvez build`, `run`, `check`, `test` and `show` all refuse an insecure program. There's no lint step to skip and no config that turns them off.
- **One way to waive, and it's loud.** `@allow_insecure("reason")` is the only waiver. It needs a written reason, covers a whole function, route or `state:` block (not one quiet line), is printed on every build, and appears in the SARIF report as a suppressed finding with that reason. A reviewer can find every exception with one search.
- **Deny-by-default is the grammar, not a convention.** A route without `@guard` or `@public("why")` isn't a warning. It isn't a valid program.
- **No hiding places.** Parvez has no macros, no `unsafe`, no procedural attributes and no inline Rust, so every line the checks need to see is in one syntax tree they read in full. The request-data tracking follows values through helpers, modules, traits, generics, objects, `state:` and database reads, with no depth limit.

The short version: **you can't lint a language that permits everything into safety. You can only shrink what it permits.** Rust has to allow everything a systems language needs; a checker on top of it has an unbounded surface to cover. Parvez is small on purpose, so its checks can cover nearly all of it.

"Nearly" is deliberate. Parvez programs can call any Rust crate, and a crate function the rules don't know about can still reach a dangerous sink: for example, a third-party process-spawning library that isn't `std::process::Command`. A project can add such functions to the analysis with `[security.sinks]` in `parvez.toml`. The [known blind spots](../SECURITY.md#rules) are listed and kept in a test suite that fails if they change, so the list stays honest.

## Why that matters now: agents and tired people

The bet isn't on experts. Experts with good tooling are already fine. It's on the code that gets written fast:

- **By AI agents.** An agent learns all of Parvez from one file ([SPEC.md](../SPEC.md), written as a system prompt), checks its own work with `parvez mcp`, and gets errors that point at the `.prvz` line it wrote, not at generated code. It can't silence a check, because there's nothing to silence it with except a written, visible waiver.
- **By people at the end of a long day.** The Friday-afternoon endpoint is when the permission check gets forgotten. Parvez makes "forgot" a build error rather than a review comment.
- **In fewer tokens.** In the one service measured so far, Parvez is 9 lines and 76 tokens where hand-written axum is 48 lines and 402 tokens ([both versions](comparison/)). Smaller code is quicker to review and leaves more of an agent's context for the actual problem. One measurement isn't a law; a larger example and an agent benchmark are next.

## The costs, honestly

Choosing Parvez over Rust means accepting these:

- **Agents know Rust far better.** Models have seen enormous amounts of Rust and almost no Parvez. Parvez depends on its spec being in the agent's context. Whether agents write correct Parvez more reliably than correct Rust hasn't been measured yet; that benchmark is planned, with published prompts and transcripts.
- **A smaller toolbox.** No editor plugin or language server yet, a young ecosystem, one maintainer, and pre-1.0 syntax that can still change.
- **Less expressive by design.** No macros, lifetimes or `unsafe`. When you need them, you leave.
- **Leaving is cheap, though.** `parvez show` prints the generated Rust, and the `Cargo.toml` is already in `.parvez_build/`. You end up with a normal Rust project, not a migration.

## When to choose which

| Choose Rust (with `secrecy`, `sqlx::query!`, Clippy, `cargo-deny`) | Choose Parvez |
|---|---|
| An experienced Rust team owns the code long-term | Agents write much of the code, or many people touch it briefly |
| You need macros, lifetimes, `unsafe`, or full control | It's a backend service or a DevOps tool, the shape Parvez is built for |
| You'll maintain the lint setup in every repository | You want the checks on by default, with exceptions visible |
| You need SQL checked against the real schema | Readable Rust as a way out is enough insurance |

Both are reasonable. Parvez exists for the right-hand column.
