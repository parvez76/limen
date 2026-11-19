# Parvez

Python's token efficiency with Rust's production reliability.

Parvez is a small, indentation-based language for backend services and DevOps tools. Its dense syntax keeps code short for both humans and LLMs. The `parvez` compiler translates `.prvz` files into plain, readable Rust, and `cargo` builds that Rust into a single standalone binary. rustc does all the type and borrow checking, and the generated code has no Parvez runtime, so there's no lock-in.

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
| `parvez run app.prvz [-- args]` | Builds the program and runs it |
| `parvez build app.prvz` | Builds a release binary and writes it to `./app` |
| `parvez show app.prvz [-o app.rs]` | Prints the generated Rust, or writes it with `-o` |

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

There's also `if`/`elif`/`else`, `for x in ...:`, `while`, `break` and `continue`.

The full spec is in [SPEC.md](SPEC.md). It's written as a compact system prompt, so you can paste it into an AI agent and it will write valid Parvez.

## Project layout

```
src/lexer.rs    tokens, INDENT/DEDENT
src/parser.rs   recursive descent -> AST (src/ast.rs)
src/codegen.rs  AST -> formatted Rust
src/main.rs     CLI: build / run / show
examples/       sample .prvz programs
```

Run the tests with `cargo test`.

## Status

This is v0.1, an MVP. These aren't supported yet: `match`, enums, `impl` blocks, closures, imports and crates, and `async`. When you need one of them, run `parvez show` and continue in Rust.

## License

[MIT](LICENSE)
