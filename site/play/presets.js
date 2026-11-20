// Built-in examples. The adversarial corpus is added at build time (presets/corpus/*.prvz).
export const PRESETS = [
  {
    id: "unguarded",
    title: "1. An admin route nobody guarded",
    src: `# An agent added an admin endpoint and forgot the permission check.
# Parvez denies by default: every route says who may call it.
route GET "/admin/users" -> str:
    ret "everyone"
`,
  },
  {
    id: "guarded",
    title: "2. The same route, guarded",
    src: `# One line, @guard(staff), and it compiles. Open the Rust tab.
fn staff(req) -> str!:
    user = req.header("x-user").unwrap_or_default()
    if user.is_empty(): fail(401, "sign in first")
    ret user

@guard(staff)
route GET "/admin/users" (auth) -> str:
    ret "hello {auth}"

@public("load balancer health probe")
route GET "/ping" -> str:
    ret "pong"
`,
  },
  {
    id: "sql",
    title: "3. SQL pasted together from strings",
    src: `state:
    db: sqlx::PgPool = sqlx::PgPool::connect_lazy(&env("DATABASE_URL", "postgres://localhost/app"))?

@json
type User: id: i64, name: str

@public("search")
route GET "/users/{name}" (state, name: str) -> [User]!:
    # injectable: Parvez refuses this line
    q = "SELECT id, name FROM users WHERE name = '{name}'"
    ret sqlx::query_as(&q).fetch_all(&state.db).await?
    # the safe form: a parameter, bound separately
    # ret sqlx::query_as("SELECT id, name FROM users WHERE name = $1").bind(&name).fetch_all(&state.db).await?
`,
  },
  {
    id: "secret",
    title: "4. A secret headed for a log",
    src: `state:
    api_key: Secret = env_secret("BILLING_API_KEY")?

@public("demo")
route POST "/charge" (state) -> str!:
    log_info("charging with key {state.api_key.expose()}")
    # printing the Secret itself is fine: it shows [redacted]
    log_info("charging with key {state.api_key}")
    ret "ok"
`,
  },
  {
    id: "helpers",
    title: "5. Request data through three helpers",
    src: `# The file path is built three calls away from the route. Still caught.
fn read_report(name: &str) -> str!:
    ret load(name)

fn load(name: &str) -> str!:
    ret read_file("/srv/reports/{name}")

fn read_file(path: &str) -> str!:
    ret std::fs::read_to_string(path)?

@public("reports")
route GET "/reports/{name}" (name: str) -> str!:
    ret read_report(&name)
    # fix: ret std::fs::read_to_string(safe_join("/srv/reports", &name)?)?
`,
  },
  {
    id: "service",
    title: "6. A complete JSON service",
    src: `@json
type Event: id: str, kind: str, count: i32

@public
route GET "/health" -> str:
    ret "ok"

@public
route POST "/events" (body: Event) -> Event!:
    if body.count < 0: fail(400, "count must be >= 0")
    ret body
`,
  },
];
