# Limen by example

A short tour of the syntax. Every snippet here compiles with `limen check` (the refused ones are refused with the messages shown). For the full definition see [SPEC.md](../SPEC.md); for a side-by-side table with Rust, [REFERENCE.md](REFERENCE.md#language-at-a-glance).

Limen reads like Python (indentation, `:`, no semicolons), keeps Rust's types, and can call any Rust crate directly. It compiles to plain Rust.

## Variables and functions

```limen
fn main()!:
    x = 10                  # immutable
    ~total = 0              # ~ makes it mutable
    for i in 0..x:
        if i % 2 == 0 and i > 2: total += i
        elif i == 1: continue
    print("total {total}")  # strings interpolate {expressions}
```

`ret` returns a value. `fn main()!:` means main can fail: `!` marks a function whose errors propagate with `?`.

## Types, enums and methods

```limen
type User: name: str, age: u8

enum Shape: Circle(f64), Square(side: f64)

impl User:
    fn greet(&self) -> str:
        ret "hi {self.name}"

fn area(s: &Shape) -> f64:
    match s:
        Circle(r) -> ret 3.14 * r * r
        Square(side) -> ret side * side
```

`str` is an owned string, `[T]` a list, `T?` an optional value. Records are built with named fields: `User(name: "ana", age: 31)`.

## Errors and missing values

```limen
fn parse_age(raw: &str) -> u8!:
    n = raw.trim().parse<u8>()?
    if n > 150: fail("age {n} is not believable")
    ret n

fn find(users: &[User], name: &str) -> User?:
    for u in users:
        if u.name == name: ret Some(u.clone())
    ret None
```

`-> T!` can fail; `fail(..)` returns an error; `?` passes an error up. Handle one in place with `catch`:

```limen
age = parse_age("42") catch e: 0
if let Some(u) = find(&users, "ana"): print(u.greet())
```

Closures and iterators are Rust's: `users.iter().filter(|u| u.age >= 18).count()`.

## Routes and access policies

```limen
@json
@derive(sqlx::FromRow)
type Note: id: i64, body: str

async fn signed_in(req) -> Claims!:
    ret oidc_session(req).await?

@public("load balancer health check")
route GET "/health" -> str:
    ret "ok"

@guard(signed_in)
route GET "/notes/{id}" (state, auth, id: i64) -> Note!:
    ...
```

A file with routes is a server; there's no `main` to write. Every route needs `@guard(fn)` (the function runs first and its result is `auth`) or `@public("reason")`. Without one, the program doesn't compile:

```
limen: error: main.lmn:1: route GET /notes/{id} has no access policy. Add @guard(fn) to require sign-in
or another check, or @public("why anyone may call it") to serve it to everyone (Limen denies by default)
```

Route parameters are path parameters (`{id}`), `body: T` (JSON), `query: T` (query string), and `state`, `req`, `auth`. `fail(404, "no such note")` answers with a status and a JSON error; `status(201)` sets the success status.

## State and the database

```limen
state:
    db: sqlx::PgPool = sqlx::PgPool::connect_lazy(&env("DATABASE_URL", "postgres://localhost/notes"))?
    api_key: Secret = env_secret("API_KEY")?

@guard(signed_in)
route POST "/notes" (state, auth, body: NewNote) -> Note!:
    if body.body.is_empty(): fail(422, "a note can't be empty")
    note: Note = sqlx::query_as("INSERT INTO notes (owner, body) VALUES ($1, $2) RETURNING id, body")
        .bind(&auth.sub)
        .bind(&body.body)
        .fetch_one(&state.db)
        .await?
    status(201)
    ret note
```

`state:` is built once at startup and shared by every route. With a `schema.sql` next to the program, every query is checked against it on each build (`SQL: 3 of 3 queries checked against schema.sql`). SQL built from strings doesn't compile:

```limen
r = sqlx::query("SELECT count(*) FROM notes WHERE body LIKE '%{q}%'").execute(&state.db).await?
```
```
limen: error: main.lmn:6: security[sql-injection]: `sqlx::query(..)` receives a string built from interpolation/concatenation
```

## Secrets

A `Secret` prints as `[redacted]` and can't be serialized. Using its value is explicit (`.expose()`), and sending that to a log, print, error or page doesn't compile:

```limen
print("key is {state.api_key.expose()}")
```
```
limen: error: main.lmn:6: security[secret-exposure]: an exposed Secret is passed to `print(..)`
```

## Background work and tests

```limen
every 1h (state):
    sqlx::query("DELETE FROM notes WHERE body = ''").execute(&state.db).await?

test "notes need a signed-in user":
    app = test_app().await?
    res = app.get("/notes/1").await?
    assert_eq(res.status, 401)
```

`limen test main.lmn` runs the tests against the whole service in process (state, guards, middleware), with no port.

## The one way out

A check can be waived only with a written reason, on a whole function, route or `state:` block:

```limen
@allow_insecure("internal tool, runs only on the admin's laptop")
@public("local only")
route GET "/debug" (state) -> str:
    ...
```

Every build prints each waiver, and `limen lint --sarif` records it with its reason, so a reviewer can find every exception with one search.
