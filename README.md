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

`parvez run service.prvz` serves this on `:8080` (or `$PORT`) as a 1.4 MB native binary. Invalid input gets proper 400/404/422 JSON errors.

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
| `parvez check app.prvz` | Fast type and borrow check (`cargo check`) with `.prvz`-mapped errors, for agent loops |
| `parvez run app.prvz [-- args]` | Builds the program and runs it |
| `parvez build app.prvz` | Builds a release binary and writes it to `./app` |
| `parvez show app.prvz [-o app.rs] [--map]` | Prints the generated Rust (`--map` adds `// @prvz:N` line comments), or writes it with `-o` |

Builds happen in `.parvez_build/<name>/` in the current directory, and cargo reuses that cache between builds.

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
| `enum S: A, B(str), C(code: i32)` | `#[derive(Debug, Clone, PartialEq)] enum S { A, B(String), C { code: i32 } }` |
| `match s:` / `B(msg) -> print(msg)` | `match s { S::B(msg) => println!(..), .. }` |
| `impl User:` / `fn greet(&self)`, `fn bump(&~self)` | `impl User { fn greet(&self) .. fn bump(&mut self) .. }` |
| `@json type Event: ...` | adds `#[derive(serde::Serialize, serde::Deserialize)]` |
| `async fn f() -> str!:` / `x.await` | `async fn f() -> anyhow::Result<String>` / `x.await` |
| `json_decode<Event>(raw)?` / `json_encode(e)?` | `serde_json::from_str::<Event>(&raw)?` / `serde_json::to_string(&e)?` |
| `use serde::{Serialize}` / `use reqwest` | `use` + automatic Cargo.toml dependencies (pin in `parvez.toml`) |
| `route POST "/x/{id}" (id: u64, body: T) -> T!:` | axum handler + router + `#[tokio::main]` server |

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
src/main.rs     CLI: build / run / show
examples/       sample .prvz programs
```

Run the tests with `cargo test`. The tests in `tests/cli.rs` compile real programs with rustc.

## Status

This is v0.3. These aren't supported yet: closures, traits, generics on your own types, `as` casts, macros, and shared state across routes. When you need one of them, run `parvez show` and continue in Rust.

## License

[MIT](LICENSE)
