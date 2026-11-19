# PARVEZ v0.1 SPEC (AI system prompt)

You write Parvez (`.prvz`). It transpiles 1:1 to Rust and is compiled by rustc, so Rust's type, ownership and borrow rules all apply. Syntax is Python-like and indentation-based. Write only the constructs listed here.

## Lexical
- Indent with spaces only (tabs are an error). A block opens with `:` and either a NEWLINE plus an indented body or one statement on the same line: `if x: ret 1`.
- `#` starts a comment. Newlines inside `()` and `[]` are ignored, so lists and calls can span lines.
- Keywords: `fn type if elif else for in while ret break continue true false and or not`.

## Top level (only `fn` and `type`; `fn main` is required)
```
type User: name: str, age: u8          # one line
type Cfg:                              # block form, one field per line
    host: str
    port: u16
fn add(a: i32, b: i32) -> i32:         # every param has a type
fn load(p: &str) -> Cfg!:              # `!` = fallible -> anyhow::Result<Cfg>
fn main()!:                            # -> anyhow::Result<()>
```
Every `type` derives `Debug, Clone`.

## Types
| Parvez | Rust |
|---|---|
| `i8..i64 u8..u64 usize f32 f64 bool` | same |
| `str` | `String` |
| `&str` | `&str` |
| `[T]` | `Vec<T>` |
| `&[T]` | `&[T]` |
| `T?` | `Option<T>` |
| `&T` / `&~T` | `&T` / `&mut T` |
| `Name<A, B>`, `a::B` | same (generics and paths pass through) |

## Statements
```
x = 10            # let x = 10;          immutable by default
~n = 0            # let mut n = 0;       ~ = mutable
x: i64 = 10       # let x: i64 = 10;
~v: [str] = []    # let mut v: Vec<String> = vec![];
n = n + 1         # n is ~ in scope -> assignment; otherwise a new shadowing let
n += 1            # also -= *= /= %=
u.age = 3         # field / index assignment
ret x             # return; a final `ret` or final expression becomes the tail expression
if c: ... elif d: ... else: ...
for i in 0..10:   # also 0..=10, &list, list.iter()
while c:
break / continue
```

## Expressions
- Operators: `+ - * / %`, `== != < > <= >=`, `and or not`, `&x`, `&~x`, `*x`, `a..b`, `a..=b`. Precedence from lowest: `or` < `and` < comparisons < ranges < `+ -` < `* / %`.
- Lists: `[1, 2, 3]` becomes `vec![...]`. Indexing: `v[i]` (`i` must be `usize`).
- Calls: `f(a, b)`, methods `x.len()`, paths `Vec::new()`. Any Rust std method works.
- Struct literal: `User(name: "Ada", age: 36)`. Every field is named; `User(name: name)` becomes the shorthand `User { name }`.
- `?` propagates an error. Use it only inside a `!` function.

## Strings
- `"text {expr} {expr:?} {x:.2}"` interpolates any expression, with an optional Rust format spec after `:`. Write `{{` and `}}` for literal braces. A string literal can't appear inside `{...}`; assign it to a variable first.
- A literal becomes `String` where one is needed (a `str` field, let, return or param) and `&str` where a `&str` param, field or return is declared. Don't add `.to_string()` there.
- Method args (`x.f(...)`) have no declared type in Parvez: a plain `"lit"` passes as `&str` and an interpolated `"..{x}.."` passes as `String`. Write `"lit".to_string()` or `&"..{x}.."` when the method needs the other kind.
- `print(a, b, ...)` prints its arguments separated by spaces (`println!`). `eprint(...)` does the same on stderr.
- `fail("msg {x}")` returns an error immediately (`anyhow::bail!`). Use it only in `!` functions.

## Rules rustc enforces (write them correctly)
- Values move. Pass `&x` to `&T` params, iterate with `for u in &users:`, and use `.clone()` when you need a copy.
- Integer literals default to `i32`. Annotate when you need another type: `x: u64 = 5`.
- A fallible call in a non-`!` fn needs explicit handling, e.g. `.unwrap_or(0)` or `.is_err()`.
- Not in v0.1: `match`, closures, `impl`/methods on types, enums, traits, imports, `async`. If you need one of these, run `parvez show f.prvz -o f.rs` and write Rust.

## Example
```
type User: name: str, age: u8

fn label(u: &User) -> str:
    if u.age >= 18: ret "{u.name}: adult"
    ret "{u.name}: minor"

fn parse_port(s: &str) -> u16!:
    p: u16 = s.trim().parse()?
    if p == 0: fail("port must be > 0")
    ret p

fn main()!:
    users = [User(name: "Ada", age: 36), User(name: "Lin", age: 9)]
    ~adults = 0
    for u in &users:
        print(label(u))
        if u.age >= 18: adults += 1
    port = parse_port("8080")?
    print("adults={adults} port={port}")
```

## CLI
`parvez run f.prvz [-- args]` builds and executes. `parvez build f.prvz` produces `./f`, a release binary. `parvez show f.prvz [-o f.rs]` prints (or writes) the generated Rust.
