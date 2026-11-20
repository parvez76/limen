//! End-to-end tests: drive the real `parvez` binary, which runs cargo/rustc.

use std::path::PathBuf;
use std::process::{Command, Output};

/// `parvez` with a hermetic (empty) advisory DB so tests never hit the
/// network for RustSec data; tests that exercise the gate override it.
fn parvez() -> Command {
    let empty_db = std::env::temp_dir().join("parvez-it-empty-advisory-db");
    std::fs::create_dir_all(empty_db.join("crates")).unwrap();
    let mut c = Command::new(env!("CARGO_BIN_EXE_parvez"));
    c.env("PARVEZ_ADVISORY_DB", empty_db);
    c
}

/// Scratch dir per test. Everything except `.parvez_build` (cargo's cache)
/// is wiped so each run starts clean but rebuilds stay fast.
fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("parvez-it-{name}"));
    std::fs::create_dir_all(&d).unwrap();
    for entry in std::fs::read_dir(&d).unwrap().flatten() {
        if entry.file_name() != ".parvez_build" {
            let p = entry.path();
            let _ = if p.is_dir() { std::fs::remove_dir_all(&p) } else { std::fs::remove_file(&p) };
        }
    }
    d
}

fn run_in(dir: &PathBuf, args: &[&str]) -> Output {
    parvez().args(args).current_dir(dir).output().expect("spawn parvez")
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

#[test]
fn hello_example_runs() {
    let example = std::fs::canonicalize("examples/hello.prvz").unwrap();
    let dir = scratch("hello");
    let out = run_in(&dir, &["run", example.to_str().unwrap()]);
    let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
    assert!(out.status.success(), "stderr:\n{stderr}");
    for want in [
        "Ada (36) is an adult",
        "Hi Linus - now 13",
        "report: Report { total: 60, adults: 2 }",
        "503 server error 503",
        "wait: db migration",
    ] {
        assert!(stdout.contains(want), "missing {want:?} in:\n{stdout}");
    }
    assert!(stderr.contains("[failed] 503: upstream down"), "{stderr}");
    assert!(dir.join("hello").exists(), "binary copied to cwd");
}

#[test]
fn enum_match_impl_compile_and_run() {
    let dir = scratch("enums");
    std::fs::write(
        dir.join("svc.prvz"),
        r#"enum Cmd:
    Ping
    Echo(str)
    Add(a: i32, b: i32)

type Counter: hits: i32

impl Counter:
    fn bump(&~self, by: i32):
        self.hits += by

fn handle(c: &Cmd) -> str:
    ret match c:
        Ping -> "pong"
        Echo(s) -> "echo {s}"
        Add(a, b) -> "sum {a + b}"

fn verb(m: &str) -> i32:
    match m:
        "GET" | "HEAD" -> 1
        _ -> 0

fn main():
    owned = "HEAD"
    print("verbs", verb("GET"), verb(&owned), verb("PUT"))
    ~ctr = Counter(hits: 0)
    for c in [Ping, Echo("hi"), Add(a: 2, b: 3)]:
        ctr.bump(1)
        print(handle(&c))
    print("hits={ctr.hits}")
"#,
    )
    .unwrap();
    let out = run_in(&dir, &["run", "svc.prvz"]);
    assert!(out.status.success(), "stderr:\n{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "verbs 1 1 0\npong\necho hi\nsum 5\nhits=3\n");
}

#[test]
fn rustc_errors_point_at_prvz_lines() {
    let dir = scratch("errors");
    std::fs::write(
        dir.join("bad.prvz"),
        "enum S:\n    A\n    B(str)\n\nfn size(raw: &str) -> i32:\n    ret raw.len()\n\nfn main():\n    s = A\n    match s:\n        A -> print(size(\"x\"))\n",
    )
    .unwrap();
    let out = run_in(&dir, &["build", "bad.prvz"]);
    let err = text(&out.stderr);
    assert!(!out.status.success());
    // type error inside a fn body -> line 6
    assert!(err.contains("bad.prvz:6: error[E0308]: mismatched types"), "{err}");
    assert!(err.contains("   6 |     ret raw.len()"), "{err}");
    assert!(err.contains("expected `i32`, found `usize`"), "{err}");
    // non-exhaustive match -> line 10
    assert!(err.contains("bad.prvz:10: error[E0004]"), "{err}");
    // no raw rustc paths leak through
    assert!(!err.contains("src/main.rs"), "{err}");
    assert!(err.contains("2 error(s)"), "{err}");
}

#[test]
fn parse_errors_use_file_line_format() {
    let dir = scratch("parse");
    std::fs::write(dir.join("p.prvz"), "fn main():\n    match x:\n        1 => 2\n").unwrap();
    let out = run_in(&dir, &["build", "p.prvz"]);
    assert!(text(&out.stderr).contains("p.prvz:3: expected `->` after match pattern"));
}

#[test]
fn show_with_map() {
    let dir = scratch("show");
    std::fs::write(dir.join("m.prvz"), "fn main():\n    x = 1\n    print(x)\n").unwrap();
    let out = run_in(&dir, &["show", "--map", "m.prvz"]);
    let s = text(&out.stdout);
    assert!(s.contains("fn main() {  // @prvz:1"), "{s}");
    assert!(s.contains("let x = 1;  // @prvz:2"), "{s}");
    let plain = text(&run_in(&dir, &["show", "m.prvz"]).stdout);
    assert!(!plain.contains("@prvz"));
}

// ---------- v0.3 ----------

#[test]
fn check_mode_maps_errors_and_passes_good_code() {
    let dir = scratch("check");
    std::fs::write(dir.join("ok.prvz"), "fn main():\n    print(\"hi\")\n").unwrap();
    let out = run_in(&dir, &["check", "ok.prvz"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("parvez: ok ok.prvz"));
    assert!(!dir.join("ok").exists(), "check produces no binary");

    std::fs::write(dir.join("bad.prvz"), "fn main():\n    x: i32 = \"nope\"\n").unwrap();
    let out = run_in(&dir, &["check", "bad.prvz"]);
    let err = text(&out.stderr);
    assert!(!out.status.success());
    assert!(err.contains("bad.prvz:2: error[E0308]: mismatched types"), "{err}");
}

#[test]
fn json_async_use_and_parvez_toml() {
    let dir = scratch("jsonasync");
    std::fs::write(
        dir.join("cfg.prvz"),
        r#"use std::collections::HashMap

@json
type Cfg: name: str, ports: [u16]

@json
enum Level: Low, High

async fn load(raw: &str) -> Cfg!:
    tokio::time::sleep(std::time::Duration::from_millis(5)).await
    ret json_decode<Cfg>(raw)?

async fn main()!:
    c = load("{{\"name\": \"api\", \"ports\": [80, 443]}}").await?
    ~seen: HashMap<str, i32> = HashMap::new()
    seen.insert(c.name.clone(), 1)
    print(json_encode(&c)?)
    lvl: Level = json_decode("\"High\"")?
    print("{lvl:?} {seen:?}")
    bad = json_decode<Cfg>("{{}}")
    print(bad.is_err())
"#,
    )
    .unwrap();
    // parvez.toml overrides are merged into the generated manifest
    std::fs::write(dir.join("parvez.toml"), "[dependencies]\nanyhow = { version = \"1\", features = [\"backtrace\"] }\n").unwrap();
    let out = run_in(&dir, &["run", "cfg.prvz"]);
    assert!(out.status.success(), "stderr:\n{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "{\"name\":\"api\",\"ports\":[80,443]}\nHigh {\"api\": 1}\ntrue\n");
    let manifest = std::fs::read_to_string(dir.join(".parvez_build/cfg/Cargo.toml")).unwrap();
    for dep in ["tokio", "serde", "serde_json", "backtrace"] {
        assert!(manifest.contains(dep), "{dep} missing from:\n{manifest}");
    }
}

/// Minimal HTTP/1.1 client so tests need no extra crates.
fn http(port: u16, method: &str, path: &str, body: &str) -> (u16, String) {
    use std::io::{Read, Write};
    let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    // A server may answer (e.g. 413) and close before reading a large body,
    // so a failed write is fine as long as a response arrives.
    let _ = write!(
        s,
        "{method} {path} HTTP/1.1\r\nHost: t\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let mut raw = Vec::new();
    let _ = s.read_to_end(&mut raw);
    let resp = String::from_utf8_lossy(&raw).into_owned();
    let status = resp[9..12].parse().unwrap();
    (status, resp.split_once("\r\n\r\n").map(|x| x.1.to_string()).unwrap_or_default())
}

struct KillOnDrop(std::process::Child);
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn service_example_serves_json() {
    let example = std::fs::canonicalize("examples/service.prvz").unwrap();
    let dir = scratch("service");
    let out = run_in(&dir, &["build", example.to_str().unwrap()]);
    assert!(out.status.success(), "stderr:\n{}", text(&out.stderr));

    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let _server = KillOnDrop(
        Command::new(dir.join("service"))
            .env("PORT", port.to_string())
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(std::time::Instant::now() < deadline, "server did not start");
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    assert_eq!(http(port, "GET", "/health", ""), (200, "ok".into()));
    assert_eq!(
        http(port, "POST", "/events", r#"{"id":"e1","kind":"click","count":4}"#),
        (200, r#"{"id":"e1","score":40,"accepted":true}"#.into())
    );
    assert_eq!(
        http(port, "POST", "/events", r#"{"id":"e2","kind":"x","count":-1}"#),
        (400, r#"{"error":"count must be >= 0, got -1"}"#.into())
    );
    assert_eq!(http(port, "POST", "/events", r#"{"id":"e3"}"#).0, 422);
    assert_eq!(
        http(port, "GET", "/events/abc", ""),
        (200, r#"{"id":"abc","kind":"demo","count":1}"#.into())
    );
    assert_eq!(http(port, "GET", "/events/missing", ""), (404, r#"{"error":"no event missing"}"#.into()));

    // v0.4: shared state across requests (e1 stored; e2 counted but rejected; e3 never reached the handler)
    assert_eq!(http(port, "GET", "/events", ""), (200, r#"[{"id":"e1","kind":"click","count":4}]"#.into()));
    assert_eq!(http(port, "GET", "/stats", ""), (200, r#"{"received":2,"stored":1,"env":"dev"}"#.into()));
    // v0.4: every rejection is JSON with its status
    let (code, body) = http(port, "POST", "/events", r#"{"id":"e3"}"#);
    assert_eq!(code, 422);
    assert!(body.starts_with(r#"{"error":"Failed to deserialize the JSON body"#), "{body}");
    let (code, body) = http(port, "POST", "/events", r#"{"id":"#);
    assert_eq!(code, 400);
    assert!(body.starts_with(r#"{"error":"#), "{body}");
    assert_eq!(http(port, "GET", "/nope", ""), (404, r#"{"error":"not found"}"#.into()));
    assert_eq!(http(port, "DELETE", "/health", ""), (405, r#"{"error":"Method Not Allowed"}"#.into()));

    // v0.5: the example survives fuzzing with no crash, hang or leak
    let out = run_in(&dir, &["fuzz", example.to_str().unwrap()]);
    let err = text(&out.stderr);
    assert!(out.status.success(), "{err}");
    assert!(err.contains("0 failure(s)"), "{err}");
}

// ---------- v0.4 ----------

#[test]
fn stateful_counter_and_store_across_requests() {
    let dir = scratch("state");
    std::fs::write(
        dir.join("counter.prvz"),
        r#"use std::sync::Mutex
use std::sync::atomic::{AtomicU64, Ordering}

@json
type Note: text: str

state:
    hits: AtomicU64 = AtomicU64::new(0)
    notes: Mutex<[str]> = Mutex::new([])
    prefix: str = env("NOTE_PREFIX", "note")

route POST "/hit" (state) -> u64:
    ret state.hits.fetch_add(1, Ordering::SeqCst) + 1

route POST "/notes" (state, body: Note) -> usize:
    ~notes = state.notes.lock().unwrap()
    notes.push("{state.prefix}: {body.text}")
    ret notes.len()

route GET "/notes" (state) -> [str]:
    ret state.notes.lock().unwrap().clone()
"#,
    )
    .unwrap();
    let out = run_in(&dir, &["build", "counter.prvz"]);
    assert!(out.status.success(), "stderr:\n{}", text(&out.stderr));
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let _server = KillOnDrop(
        Command::new(dir.join("counter"))
            .env("PORT", port.to_string())
            .env("NOTE_PREFIX", "n")
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(std::time::Instant::now() < deadline, "server did not start");
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    // concurrent hits all land on the same counter
    let threads: Vec<_> = (0..8).map(|_| std::thread::spawn(move || http(port, "POST", "/hit", "").0)).collect();
    assert!(threads.into_iter().all(|t| t.join().unwrap() == 200));
    assert_eq!(http(port, "POST", "/hit", ""), (200, "9".into()));
    assert_eq!(http(port, "POST", "/notes", r#"{"text":"a"}"#), (200, "1".into()));
    assert_eq!(http(port, "POST", "/notes", r#"{"text":"b"}"#), (200, "2".into()));
    assert_eq!(http(port, "GET", "/notes", ""), (200, r#"["n: a","n: b"]"#.into()));
    assert_eq!(http(port, "POST", "/notes", r#"{"txt":"x"}"#).0, 422);
}

#[test]
fn rust_keywords_are_escaped() {
    let dir = scratch("keywords");
    std::fs::write(
        dir.join("kw.prvz"),
        r#"@json
type Item: type: str, gen: i32, move: bool

enum Op:
    Box(ref: i32)
    Yield

fn loop(try: i32) -> i32:
    ~gen = try
    gen += 1
    ret gen

fn main()!:
    i = Item(type: "widget", gen: loop(1), move: true)
    for box in [i.gen]:
        print(i.type, box, i.move)
    print(json_encode(&i)?)
    back: Item = json_decode("{{\"type\":\"x\",\"gen\":7,\"move\":false}}")?
    print(back.type, back.gen)
    match Box(ref: 5):
        Box(ref: r) -> print("ref", r)
        Yield -> print("yield")
"#,
    )
    .unwrap();
    let out = run_in(&dir, &["run", "kw.prvz"]);
    assert!(out.status.success(), "stderr:\n{}", text(&out.stderr));
    assert_eq!(
        text(&out.stdout),
        "widget 2 true\n{\"type\":\"widget\",\"gen\":2,\"move\":true}\nx 7\nref 5\n"
    );
}

/// Talks newline-delimited JSON-RPC to `parvez mcp`.
struct Mcp {
    child: std::process::Child,
    out: std::io::BufReader<std::process::ChildStdout>,
}

impl Mcp {
    fn start(cache: &PathBuf) -> Self {
        let mut child = parvez()
            .arg("mcp")
            .env("PARVEZ_CACHE_DIR", cache)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let out = std::io::BufReader::new(child.stdout.take().unwrap());
        Mcp { child, out }
    }
    fn send(&mut self, msg: serde_json::Value) {
        use std::io::Write;
        let stdin = self.child.stdin.as_mut().unwrap();
        writeln!(stdin, "{msg}").unwrap();
        stdin.flush().unwrap();
    }
    fn call(&mut self, msg: serde_json::Value) -> serde_json::Value {
        use std::io::BufRead;
        self.send(msg);
        let mut line = String::new();
        self.out.read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap()
    }
    fn tool(&mut self, id: u32, name: &str, args: serde_json::Value) -> (bool, String) {
        let r = self.call(serde_json::json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":name,"arguments":args}}));
        let res = &r["result"];
        (res["isError"].as_bool().unwrap(), res["content"][0]["text"].as_str().unwrap().to_string())
    }
}

impl Drop for Mcp {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn mcp_server_tools() {
    use serde_json::json;
    let cache = scratch("mcp");
    let mut m = Mcp::start(&cache);
    let r = m.call(json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}));
    assert_eq!(r["result"]["serverInfo"]["name"], "parvez");
    m.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
    let r = m.call(json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}));
    assert_eq!(r["result"]["tools"].as_array().unwrap().len(), 3);

    let (err, spec) = m.tool(3, "parvez_spec", json!({}));
    assert!(!err && spec.contains("## HTTP services"));

    let (err, out) = m.tool(4, "parvez_check", json!({"code": "fn size(s: &str) -> i32:\n    ret s.len()\n\nfn main():\n    print(size(\"x\"))\n"}));
    assert!(err, "{out}");
    assert!(out.starts_with("snippet.prvz:2: error[E0308]: mismatched types"), "{out}");
    assert!(out.contains("expected `i32`, found `usize`"), "{out}");
    assert!(!out.contains(&cache.display().to_string()), "no cache paths leak: {out}");

    let (err, out) = m.tool(5, "parvez_check", json!({"code": "fn main():\n    print(\"hi\")\n"}));
    assert!(!err, "{out}");
    assert_eq!(out, "ok: snippet.prvz has no errors");

    let (err, out) = m.tool(6, "parvez_check", json!({"code": "fn main(:\n"}));
    assert!(err && out.starts_with("snippet.prvz:1:"), "{out}");

    let example = std::fs::canonicalize("examples/hello.prvz").unwrap();
    let (err, out) = m.tool(7, "parvez_eject", json!({"path": example, "map": true}));
    assert!(!err && out.contains("struct User {") && out.contains("// @prvz:"), "{out}");
}

// ---------- v0.5 ----------

#[test]
fn security_lint_blocks_insecure_code() {
    let dir = scratch("seclint");
    std::fs::write(
        dir.join("bad.prvz"),
        r#"state:
    api_key: str = "abc123-not-from-env"
route GET "/u/{id}" (state, id: str) -> str!:
    q = "SELECT * FROM users WHERE id = '{id}'"
    rows = sqlx::query(&q).fetch_all(&db).await?
    ret std::fs::read_to_string("/srv/{id}")?
"#,
    )
    .unwrap();
    let out = run_in(&dir, &["check", "bad.prvz"]);
    let err = text(&out.stderr);
    assert!(!out.status.success());
    assert!(err.contains("bad.prvz:2: security[hardcoded-secret]: `api_key` is assigned a string literal"), "{err}");
    assert!(err.contains("bad.prvz:5: security[sql-injection]"), "{err}");
    assert!(err.contains("bad.prvz:6: security[path-traversal]"), "{err}");
    assert!(err.contains("= fix: never build SQL with interpolation"), "{err}");
    assert!(err.contains("3 security error(s)"), "{err}");

    // explicit, reasoned opt-out: allowed, but reported on every build
    std::fs::write(
        dir.join("ok.prvz"),
        "@allow_insecure(\"one-off migration script, input is a constant\")\nfn migrate(t: &str):\n    db.execute(\"DROP TABLE {t}\")\nfn main():\n    ret\n",
    )
    .unwrap();
    let out = run_in(&dir, &["show", "ok.prvz"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("ok.prvz:2: security checks disabled by @allow_insecure: one-off migration script"));
}

fn http_raw(port: u16, req: &[u8]) -> String {
    use std::io::{Read, Write};
    let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    let _ = s.write_all(req);
    let mut resp = Vec::new();
    let _ = s.read_to_end(&mut resp);
    String::from_utf8_lossy(&resp).into_owned()
}

#[test]
fn hardened_service_no_leaks_limits_shutdown_and_fuzz() {
    let dir = scratch("hardened");
    std::fs::write(
        dir.join("hard.prvz"),
        r#"@json
type Msg: text: str

route GET "/boom" -> i32!:
    n: i32 = "not a number".parse()?
    ret n

route GET "/panic/{i}" (i: usize) -> i32:
    v = [10]
    ret v[i]

route GET "/slow" -> str:
    tokio::time::sleep(std::time::Duration::from_secs(3)).await
    ret "late"

route POST "/echo" (body: Msg) -> Msg:
    ret body

route GET "/leak/{name}" (name: str) -> str!:
    fail(500, "cannot open /home/app/{name}.db (os error 2)")
"#,
    )
    .unwrap();
    let out = run_in(&dir, &["build", "hard.prvz"]);
    assert!(out.status.success(), "stderr:\n{}", text(&out.stderr));

    // SBOM next to the binary
    let sbom: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(dir.join("hard.sbom.json")).unwrap()).unwrap();
    assert_eq!(sbom["bomFormat"], "CycloneDX");
    let comps = sbom["components"].as_array().unwrap();
    let axum = comps.iter().find(|c| c["name"] == "axum").expect("axum in SBOM");
    assert!(axum["purl"].as_str().unwrap().starts_with("pkg:cargo/axum@0.8."));
    assert!(axum["licenses"][0]["expression"].as_str().is_some());

    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let log = dir.join("server.log");
    let mut server = KillOnDrop(
        Command::new(dir.join("hard"))
            .env("PORT", port.to_string())
            .env("PARVEZ_TIMEOUT_SECS", "1")
            .stdout(std::process::Stdio::null())
            .stderr(std::fs::File::create(&log).unwrap())
            .spawn()
            .unwrap(),
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(std::time::Instant::now() < deadline, "server did not start");
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let generic = r#"{"error":"internal server error"}"#.to_string();
    // internal error: generic body to the client, details only in the server log
    assert_eq!(http(port, "GET", "/boom", ""), (500, generic.clone()));
    // a panicking handler is contained; the server keeps serving
    assert_eq!(http(port, "GET", "/panic/0", ""), (200, "10".into()));
    assert_eq!(http(port, "GET", "/panic/1", ""), (500, generic.clone()));
    assert_eq!(http(port, "GET", "/panic/0", ""), (200, "10".into()));
    // request timeout (PARVEZ_TIMEOUT_SECS=1)
    assert_eq!(http(port, "GET", "/slow", ""), (503, r#"{"error":"request timed out"}"#.into()));
    // body limit (2 MB default) -> JSON 413
    let big = format!("{{\"text\":\"{}\"}}", "a".repeat(3 * 1024 * 1024));
    let (code, body) = http(port, "POST", "/echo", &big);
    assert_eq!(code, 413);
    assert!(body.starts_with(r#"{"error":"#), "{body}");
    // security headers on every response
    let raw = http_raw(port, b"GET /panic/0 HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n").to_lowercase();
    for h in ["x-content-type-options: nosniff", "x-frame-options: deny", "cache-control: no-store"] {
        assert!(raw.contains(h), "missing {h} in:\n{raw}");
    }
    // graceful shutdown on SIGTERM
    let pid = server.0.id().to_string();
    assert!(Command::new("kill").args(["-TERM", &pid]).status().unwrap().success());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let status = loop {
        if let Some(st) = server.0.try_wait().unwrap() {
            break st;
        }
        assert!(std::time::Instant::now() < deadline, "server ignored SIGTERM");
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    assert!(status.success(), "exit {status}");
    let log = std::fs::read_to_string(&log).unwrap();
    assert!(log.contains("parvez: internal error: invalid digit found in string"), "{log}");
    assert!(log.contains("handler panicked"), "{log}");
    assert!(log.contains("shutting down gracefully"), "{log}");

    // fuzz: panics and errors are contained (warnings), the deliberate leak fails the run
    let out = run_in(&dir, &["fuzz", "hard.prvz"]);
    let err = text(&out.stderr);
    assert!(!out.status.success(), "{err}");
    assert!(err.contains("FAIL LEAK   GET /leak/{name} [baseline] -> 500: response contains `"), "{err}");
    assert!(err.contains("5xx    GET /panic/{i} [baseline] -> 500"), "{err}");
    assert!(!err.contains("CRASH") && !err.contains("DROP"), "{err}");
    assert!(err.contains("handler panic(s) contained") && !err.contains(" 0 handler panic(s)"), "{err}");
}

#[test]
fn advisory_gate_blocks_vulnerable_deps_and_heal_reports() {
    let dir = scratch("advisory");
    let db = dir.join("advisory-db");
    std::fs::create_dir_all(db.join("crates/anyhow")).unwrap();
    std::fs::write(
        db.join("crates/anyhow/RUSTSEC-2099-0042.md"),
        "```toml\n[advisory]\nid = \"RUSTSEC-2099-0042\"\npackage = \"anyhow\"\ntitle = \"Test advisory: remote code execution\"\n\n[versions]\npatched = [\">= 99.0.0\"]\n```\n",
    )
    .unwrap();
    std::fs::write(dir.join("app.prvz"), "fn main():\n    print(\"hi\")\n").unwrap();
    let with_db = |args: &[&str], audit: Option<&str>| {
        let mut c = parvez();
        c.args(args).current_dir(&dir).env("PARVEZ_ADVISORY_DB", &db);
        if let Some(a) = audit {
            c.env("PARVEZ_AUDIT", a);
        }
        c.output().unwrap()
    };

    let out = with_db(&["build", "app.prvz"], None);
    let err = text(&out.stderr);
    assert!(!out.status.success(), "{err}");
    assert!(err.contains("1 known-vulnerable dependency:"), "{err}");
    assert!(err.contains("RUSTSEC-2099-0042 anyhow@1."), "{err}");
    assert!(err.contains("run `parvez heal app.prvz`"), "{err}");
    assert!(!dir.join("app").exists(), "no binary is shipped when the gate fails");

    let out = with_db(&["heal", "app.prvz"], None);
    let err = text(&out.stderr);
    assert!(!out.status.success(), "{err}");
    assert!(err.contains("parvez: heal: needs a breaking upgrade: RUSTSEC-2099-0042"), "{err}");
    assert!(err.contains("[dependencies] anyhow = "), "{err}");

    let out = with_db(&["build", "app.prvz"], Some("warn"));
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("parvez: warning: 1 known-vulnerable dependency"));
    assert!(dir.join("app").exists() && dir.join("app.sbom.json").exists());
}

// ---------- v0.6 ----------

#[test]
fn general_purpose_language_features_run() {
    let dir = scratch("lang6");
    std::fs::write(
        dir.join("lang.prvz"),
        r#"use std::collections::HashMap

@json
type Ev:
    @rename("type")
    kind: str
    @default
    count: i32
    @omit_none
    note: str?

fn apply(f: fn(i32) -> i32, x: i32) -> i32:
    ret f(x)

fn pair() -> (i32, str):
    ret (1, "one")

async fn work(n: i32) -> i32:
    ret n * 10

async fn main()!:
    nums = [1, 2, 3, 4]
    doubled: [i32] = nums.iter().map(|x| x * 2).collect()
    evens: [i32] = nums.iter().filter(|x| *x % 2 == 0).cloned().collect()
    print("{doubled:?} {evens:?}")
    add = |a: i32, b: i32| a + b
    print(add(2, 3), apply(|x| x + 1, 41))
    big = |x: i32| -> str:
        if x > 2: ret "big"
        ret "small"
    print(big(5), big(1))
    ~n = 0
    loop:
        n += 1
        if n == 3: break
    print("loop {n}")
    p = pair()
    print(p.0, p.1)
    ~m: HashMap<str, i32> = HashMap::new()
    m.insert("a".to_string(), 1)
    for (k, v) in &m:
        print(k, v)
    sql = """
        SELECT *
          FROM t
        WHERE name = "x"
        """
    print(sql)
    h = spawn work(4)
    print(h.await?)
    j = spawn:
        print("in task")
    j.await?
    e: Ev = json_decode("{{\"type\":\"click\"}}")?
    print(e.kind, e.count, json_encode(&e)?)
    name: str? = Some("x")
    print(name.unwrap())
    unit: () = ()
    print(std::path::Path::new("/").exists())
"#,
    )
    .unwrap();
    let out = run_in(&dir, &["run", "lang.prvz"]);
    assert!(out.status.success(), "stderr:\n{}", text(&out.stderr));
    assert_eq!(
        text(&out.stdout),
        "[2, 4, 6, 8] [2, 4]\n5 42\nbig small\nloop 3\n1 one\na 1\nSELECT *\n  FROM t\nWHERE name = \"x\"\n40\nin task\nclick 0 {\"type\":\"click\",\"count\":0}\nx\ntrue\n"
    );
}

#[test]
fn req_guards_status_codes_and_signed_fuzz() {
    let dir = scratch("auth6");
    std::fs::write(
        dir.join("api.prvz"),
        r#"@json
type Who: user: str, ip: str

fn require_key(req) -> str!:
    match req.header("x-api-key"):
        Some(k) if k == env("API_KEY", "test-key") -> ret "alice"
        Some(_) -> fail(403, code: "FORBIDDEN", "bad key")
        None -> fail(401, code: "UNAUTHENTICATED", "missing x-api-key")

@guard(require_key)
route GET "/whoami/{n}" (req, auth, n: u32) -> Who:
    ret Who(user: "{auth}-{n}", ip: req.client_ip())

@guard(require_key)
route POST "/ping":
    status(204)

route POST "/echo" (req, body: Who) -> Who!:
    status(201)
    ret body
"#,
    )
    .unwrap();
    let out = run_in(&dir, &["build", "api.prvz"]);
    assert!(out.status.success(), "stderr:\n{}", text(&out.stderr));
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let _server = KillOnDrop(
        Command::new(dir.join("api")).env("PORT", port.to_string()).stdout(std::process::Stdio::null()).spawn().unwrap(),
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(std::time::Instant::now() < deadline, "server did not start");
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let get = |key: Option<&str>, path: &str| {
        let h = key.map(|k| format!("x-api-key: {k}\r\n")).unwrap_or_default();
        let raw = http_raw(port, format!("GET {path} HTTP/1.1\r\nHost: t\r\n{h}Connection: close\r\n\r\n").as_bytes());
        (raw[9..12].to_string(), raw.split_once("\r\n\r\n").unwrap().1.to_string())
    };
    assert_eq!(get(None, "/whoami/1"), ("401".into(), r#"{"code":"UNAUTHENTICATED","error":"missing x-api-key"}"#.into()));
    assert_eq!(get(Some("nope"), "/whoami/1"), ("403".into(), r#"{"code":"FORBIDDEN","error":"bad key"}"#.into()));
    assert_eq!(get(Some("test-key"), "/whoami/7"), ("200".into(), r#"{"user":"alice-7","ip":"127.0.0.1"}"#.into()));
    let ping = http_raw(port, b"POST /ping HTTP/1.1\r\nHost: t\r\nx-api-key: test-key\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    assert!(ping.starts_with("HTTP/1.1 204"), "{ping}");
    assert_eq!(http(port, "POST", "/echo", r#"{"user":"bob","ip":"x"}"#), (201, r#"{"user":"bob","ip":"x"}"#.into()));
    let (code, body) = http(port, "POST", "/echo", r#"{"user":"#);
    assert_eq!(code, 422);
    assert!(body.starts_with(r#"{"error":"invalid JSON body"#), "{body}");

    // fuzz with fuzz.toml credentials gets past the guard; without them it can't
    let out = run_in(&dir, &["fuzz", "api.prvz"]);
    let err = text(&out.stderr);
    assert!(err.contains("GET /whoami/{n}: 0/"), "guard rejections are not coverage: {err}");
    assert!(err.contains("was never reached"), "{err}");
    std::fs::write(dir.join("fuzz.toml"), "[headers]\nx-api-key = \"test-key\"\n").unwrap();
    let out = run_in(&dir, &["fuzz", "api.prvz"]);
    let err = text(&out.stderr);
    assert!(out.status.success(), "{err}");
    assert!(!err.contains("was never reached"), "{err}");
    assert!(err.contains("0 failure(s)"), "{err}");
}

// ---------- v0.7 ----------

#[test]
fn multi_file_modules_build_serve_and_map_errors() {
    let dir = scratch("modules7");
    std::fs::create_dir_all(dir.join("auth")).unwrap();
    std::fs::write(
        dir.join("app.prvz"),
        "import store\nimport auth.tokens\n\nstate:\n    hits: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0)\n\nroute GET \"/items/{id}\" (id: u32) -> store::Item!:\n    ret store::find(id)?\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("store.prvz"),
        "@json\ntype Item: id: u32, name: str, kind: Kind\n\n@json\nenum Kind: Tool, Book\n\nfn find(id: u32) -> Item!:\n    if id == 0: fail(404, code: \"not_found\", \"no item {id}\")\n    ret Item(id: id, name: \"item-{id}\", kind: if_book(id))\n\nfn if_book(id: u32) -> Kind:\n    if id % 2 == 0: ret Book\n    ret Tool\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("auth/tokens.prvz"),
        "fn bearer(req) -> str!:\n    match req.header(\"authorization\"):\n        Some(h) if h == \"Bearer t0k\" -> ret \"admin\"\n        _ -> fail(401, code: \"unauthenticated\", \"bad token\")\n\n@guard(bearer)\nroute GET \"/admin/count\" (state, auth) -> str:\n    n = state.hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1\n    ret \"{auth} {n}\"\n",
    )
    .unwrap();
    let out = run_in(&dir, &["build", "app.prvz"]);
    assert!(out.status.success(), "stderr:\n{}", text(&out.stderr));
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let _server = KillOnDrop(
        Command::new(dir.join("app")).env("PORT", port.to_string()).stdout(std::process::Stdio::null()).spawn().unwrap(),
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(std::time::Instant::now() < deadline, "server did not start");
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert_eq!(http(port, "GET", "/items/4", ""), (200, r#"{"id":4,"name":"item-4","kind":"Book"}"#.into()));
    assert_eq!(http(port, "GET", "/items/0", ""), (404, r#"{"code":"not_found","error":"no item 0"}"#.into()));
    let admin = |tok: &str| {
        let raw = http_raw(port, format!("GET /admin/count HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer {tok}\r\nConnection: close\r\n\r\n").as_bytes());
        (raw[9..12].to_string(), raw.split_once("\r\n\r\n").unwrap().1.to_string())
    };
    assert_eq!(admin("nope").0, "401");
    assert_eq!(admin("t0k"), ("200".into(), "admin 1".into()));

    // a type error inside a module is reported against that module's file and line
    std::fs::write(dir.join("store.prvz"), "fn find(id: u32) -> i32:\n    ret \"x\"\n").unwrap();
    let out = run_in(&dir, &["check", "app.prvz"]);
    let err = text(&out.stderr);
    assert!(err.contains("store.prvz:2: error[E0308]"), "{err}");
}

/// Minimal WebSocket client (RFC 6455) over std, for tests.
struct Ws(std::net::TcpStream);

impl Ws {
    fn connect(port: u16, path: &str, protocols: &str) -> Result<(Ws, String), String> {
        use std::io::{Read, Write};
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
        write!(
            s,
            "GET {path} HTTP/1.1\r\nHost: t\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: {protocols}\r\n\r\n"
        )
        .unwrap();
        let mut head = Vec::new();
        let mut b = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            if s.read(&mut b).unwrap_or(0) == 0 {
                break;
            }
            head.push(b[0]);
        }
        let head = String::from_utf8_lossy(&head).into_owned();
        if head.starts_with("HTTP/1.1 101") { Ok((Ws(s), head)) } else { Err(head) }
    }

    fn send(&mut self, opcode: u8, payload: &[u8]) {
        use std::io::Write;
        let mask = [7u8, 1, 9, 3];
        let mut f = vec![0x80 | opcode];
        if payload.len() < 126 {
            f.push(0x80 | payload.len() as u8);
        } else {
            f.push(0x80 | 126);
            f.extend((payload.len() as u16).to_be_bytes());
        }
        f.extend(mask);
        f.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
        self.0.write_all(&f).unwrap();
    }

    /// (opcode, payload) of the next non-ping frame.
    fn recv(&mut self) -> (u8, Vec<u8>) {
        use std::io::Read;
        loop {
            let mut h = [0u8; 2];
            self.0.read_exact(&mut h).unwrap();
            let mut len = (h[1] & 0x7f) as usize;
            if len == 126 {
                let mut l = [0u8; 2];
                self.0.read_exact(&mut l).unwrap();
                len = u16::from_be_bytes(l) as usize;
            } else if len == 127 {
                let mut l = [0u8; 8];
                self.0.read_exact(&mut l).unwrap();
                len = u64::from_be_bytes(l) as usize;
            }
            let mut p = vec![0u8; len];
            self.0.read_exact(&mut p).unwrap();
            if h[0] & 0x0f != 0x9 {
                return (h[0] & 0x0f, p);
            }
        }
    }

    fn text(&mut self) -> String {
        let (op, p) = self.recv();
        assert_eq!(op, 1, "expected a text frame");
        String::from_utf8(p).unwrap()
    }
}

#[test]
fn websocket_guard_subprotocol_and_relay() {
    let dir = scratch("ws7");
    std::fs::write(
        dir.join("chat.prvz"),
        r#"use std::collections::HashMap
use std::sync::Mutex

state:
    peers: Mutex<HashMap<str, WsSender>> = Mutex::new(HashMap::new())

fn ticket(req) -> str!:
    offered = req.header("sec-websocket-protocol").unwrap_or_default()
    for p in offered.split(','):
        t = p.trim()
        if t.starts_with("tok."): ret t.trim_start_matches("tok.").to_string()
    room = req.param("room").unwrap_or_default()
    fail(401, code: "unauthenticated", "no token for room {room}")

@guard(ticket)
@protocols("chat.v1")
socket "/ws/{room}" (state, auth, room: str, conn):
    key = "{room}/{auth}"
    state.peers.lock().unwrap().insert(key.clone(), conn.sender())
    conn.send_text("hello {auth} via {conn.protocol().unwrap_or_default()}").await?
    loop:
        match conn.recv().await?:
            Some(msg) ->
                for (k, peer) in state.peers.lock().unwrap().iter():
                    if k.starts_with(&"{room}/") and *k != key: peer.send(&msg)
            None -> break
    state.peers.lock().unwrap().remove(&key)
"#,
    )
    .unwrap();
    let out = run_in(&dir, &["build", "chat.prvz"]);
    assert!(out.status.success(), "stderr:\n{}", text(&out.stderr));
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let _server = KillOnDrop(
        Command::new(dir.join("chat")).env("PORT", port.to_string()).stdout(std::process::Stdio::null()).spawn().unwrap(),
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(std::time::Instant::now() < deadline, "server did not start");
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    // the guard rejects before the upgrade, with the JSON error contract
    let rejected = Ws::connect(port, "/ws/r1", "chat.v1").err().expect("must not upgrade");
    assert!(rejected.starts_with("HTTP/1.1 401"), "{rejected}");

    let (mut a, head) = Ws::connect(port, "/ws/r1", "chat.v1, tok.alice").unwrap();
    assert!(head.to_lowercase().contains("sec-websocket-protocol: chat.v1"), "{head}");
    let (mut b, _) = Ws::connect(port, "/ws/r1", "chat.v1, tok.bob").unwrap();
    let (mut c, _) = Ws::connect(port, "/ws/r2", "chat.v1, tok.carol").unwrap();
    assert_eq!(a.text(), "hello alice via chat.v1");
    assert_eq!(b.text(), "hello bob via chat.v1");
    assert_eq!(c.text(), "hello carol via chat.v1");
    a.send(1, b"hi bob");
    assert_eq!(b.text(), "hi bob");
    b.send(2, b"\x00\x01bin");
    assert_eq!(a.recv(), (2, b"\x00\x01bin".to_vec()), "binary stays binary");
    // carol is in another room: nothing arrives
    c.0.set_read_timeout(Some(std::time::Duration::from_millis(400))).unwrap();
    let mut probe = [0u8; 1];
    assert!(std::io::Read::read(&mut c.0, &mut probe).is_err(), "room isolation");
    // closing: the server answers with a close frame
    a.send(8, &1000u16.to_be_bytes());
    assert_eq!(a.recv().0, 8);
}
