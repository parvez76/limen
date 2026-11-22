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
/// A built program's file: `name`, or `name.exe` on Windows.
fn exe(dir: &std::path::Path, name: &str) -> PathBuf {
    dir.join(format!("{name}{}", std::env::consts::EXE_SUFFIX))
}

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
    assert!(exe(&dir, "hello").exists(), "binary copied to cwd");
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

@public
route POST "/hit" (state) -> u64:
    ret state.hits.fetch_add(1, Ordering::SeqCst) + 1

@public
route POST "/notes" (state, body: Note) -> usize:
    ~notes = state.notes.lock().unwrap()
    notes.push("{state.prefix}: {body.text}")
    ret notes.len()

@public
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
    assert!(!err && spec.contains("## Statements") && !spec.contains("## HTTP services") && spec.contains("- `http`:"), "{spec}");
    let (err, http) = m.tool(30, "parvez_spec", json!({"topic": "http"}));
    assert!(!err && http.starts_with("## HTTP services"), "{http}");

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
@public
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
    assert!(err.contains("bad.prvz:6: security[sql-injection]"), "{err}");
    assert!(err.contains("bad.prvz:7: security[path-traversal]"), "{err}");
    assert!(err.contains("= fix: never build SQL with interpolation"), "{err}");
    assert!(err.contains("bad.prvz:2: security[secret-type]: state field `api_key` holds a secret as plain `str`"), "{err}");
    assert!(err.contains("4 security error(s)"), "{err}");

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

@public
route GET "/boom" -> i32!:
    n: i32 = "not a number".parse()?
    ret n

@public
route GET "/panic/{i}" (i: usize) -> i32:
    v = [10]
    ret v[i]

@public
route GET "/slow" -> str:
    tokio::time::sleep(std::time::Duration::from_secs(3)).await
    ret "late"

@public
route POST "/echo" (body: Msg) -> Msg:
    ret body

@public
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
    // graceful shutdown on SIGTERM (Unix signals; Windows services stop on Ctrl+C)
    #[cfg(unix)]
    {
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
    }
    #[cfg(not(unix))]
    {
        let _ = server.0.kill();
        let _ = server.0.wait();
    }
    let log = std::fs::read_to_string(&log).unwrap();
    assert!(log.contains("parvez: internal error: invalid digit found in string"), "{log}");
    assert!(log.contains("handler panicked"), "{log}");
    #[cfg(unix)]
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
    assert!(!exe(&dir, "app").exists(), "no binary is shipped when the gate fails");

    let out = with_db(&["heal", "app.prvz"], None);
    let err = text(&out.stderr);
    assert!(!out.status.success(), "{err}");
    assert!(err.contains("parvez: heal: needs a breaking upgrade: RUSTSEC-2099-0042"), "{err}");
    assert!(err.contains("[dependencies] anyhow = "), "{err}");

    let out = with_db(&["build", "app.prvz"], Some("warn"));
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("parvez: warning: 1 known-vulnerable dependency"));
    assert!(exe(&dir, "app").exists() && dir.join("app.sbom.json").exists());
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

@public
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
        "import store\nimport auth.tokens\n\nstate:\n    hits: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0)\n\n@public\nroute GET \"/items/{id}\" (id: u32) -> store::Item!:\n    ret store::find(id)?\n",
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

#[test]
fn frontend_bridge_and_typed_pages() {
    let dir = scratch("frontend8");
    std::fs::create_dir_all(dir.join("ui")).unwrap();
    std::fs::write(
        dir.join("main.prvz"),
        r#"@embed_dir("dist")
import ui.dashboard
@public
route GET "/api" -> models::Card:
    ret models::card()
"#,
    )
    .unwrap();
    let model = r#"const LEVEL: i32 = if true: 8 else: 7
const TITLE: str = "Parvez"
@json
type Card: title: str, level: i32, kind: Kind
@json
enum Kind: New, Old
fn unwrap(x: i32?) -> i32:
    if let Some(v) = x: ret v
    ret 0
fn result(x: Result<i32, str>) -> i32:
    if let Ok(v) = x: ret v
    ret 0
fn card() -> Card:
    ret Card(title: TITLE, level: result(Ok(unwrap(Some(LEVEL)))), kind: New)
"#;
    std::fs::write(dir.join("models.prvz"), model).unwrap();
    let page = r#"import models
@public
page GET "/card/{name}" (name: str) -> html:
    let card = models::card()
    main:
        h1 {card.title} {models::LEVEL}
        p(title="{name}") {name}
        button(hx-get="/api") {card.kind}
@public
@allow_unsafe_html("fragment from our static layout")
page GET "/trusted" -> html:
    raw {"<b>ok</b>"}
"#;
    let page_path = dir.join("ui/dashboard.msd");
    std::fs::write(&page_path, page).unwrap();
    let ts = run_in(&dir, &["types", "--ts", "--out", "types.ts"]);
    assert!(ts.status.success(), "{}", text(&ts.stderr));
    let ts = std::fs::read_to_string(dir.join("types.ts")).unwrap();
    for want in [
        "export type Card",
        "export type Kind = \"New\" | \"Old\"",
        "\"GET /api\"",
        "response: Card",
        "params: { \"name\": string }",
    ] {
        assert!(ts.contains(want), "{ts}");
    }
    std::fs::create_dir_all(dir.join("dist/static")).unwrap();
    std::fs::write(dir.join("dist/index.html"), "<main>spa</main>").unwrap();
    std::fs::write(dir.join("dist/static/app.js"), "let app = 8;").unwrap();
    std::fs::create_dir_all(dir.join("dist/about")).unwrap();
    std::fs::write(dir.join("dist/about/index.html"), "<main>about</main>").unwrap();
    let out = run_in(&dir, &["build", "main.prvz"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    std::fs::rename(dir.join("dist"), dir.join("offline-dist")).unwrap();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let _server = KillOnDrop(
        Command::new(dir.join("main"))
            .env("PORT", port.to_string())
            .spawn()
            .unwrap(),
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(std::time::Instant::now() < deadline);
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    let request = |path: &str| {
        http_raw(
            port,
            format!("GET {path} HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n").as_bytes(),
        )
    };
    let html = request("/card/%3C%26%3E%22%27");
    let safe = "&lt;&amp;&gt;&quot;&#39;";
    assert!(
        html.contains("text/html")
            && html.ends_with(&format!(
                "<main><h1>Parvez 8</h1><p title=\"{safe}\">{safe}</p><button hx-get=\"/api\">New</button></main>"
            )),
        "{html}"
    );
    assert!(request("/trusted").ends_with("<b>ok</b>"));
    assert!(request("/api").ends_with(r#"{"title":"Parvez","level":8,"kind":"New"}"#));
    let asset = request("/static/app.js?v=8");
    assert!(asset.contains("text/javascript") && asset.ends_with("let app = 8;"));
    assert!(request("/about/").ends_with("<main>about</main>"));
    // SPA fallback only for browser navigations; API clients get the JSON 404
    let navigate = |path: &str| {
        http_raw(
            port,
            format!("GET {path} HTTP/1.1\r\nHost: t\r\nAccept: text/html,application/xhtml+xml\r\nConnection: close\r\n\r\n").as_bytes(),
        )
    };
    assert!(navigate("/client/nested").ends_with("<main>spa</main>"));
    let api_typo = request("/api/v1/typo");
    assert!(api_typo.starts_with("HTTP/1.1 404") && api_typo.ends_with(r#"{"error":"not found"}"#), "{api_typo}");
    assert!(request("/static/missing.css").starts_with("HTTP/1.1 404"));
    // unknown paths are 404 for every method, not 405
    assert_eq!(http(port, "POST", "/client/nested", ""), (404, r#"{"error":"not found"}"#.into()));
    assert_eq!(http(port, "DELETE", "/static/app.js", "").0, 404);

    std::fs::rename(dir.join("offline-dist"), dir.join("dist")).unwrap();
    std::fs::write(dir.join("models.prvz"), model.replace("title:", "label:")).unwrap();
    let check = run_in(&dir, &["check", "main.prvz"]);
    assert!(
        !check.status.success() && text(&check.stderr).contains("dashboard.msd:6: error[E0609]"),
        "{}",
        text(&check.stderr)
    );
}

#[test]
fn generated_typescript_passes_tsc_strict() {
    if Command::new("npx").arg("--version").output().map(|o| !o.status.success()).unwrap_or(true) {
        eprintln!("skipping: npx (Node.js) not installed");
        return;
    }
    let dir = scratch("tsc8");
    std::fs::write(
        dir.join("main.prvz"),
        "@json\ntype User:\n    id: u32\n    name: str\n    @default\n    tags: [str]\n    note: str?\n\n@json\nenum Kind: Admin, Member(str)\n\n@json\ntype Q: page: u32\n\n@public\nroute GET \"/users/{id}\" (id: u32, query: Q) -> User:\n    ret User(id: id, name: \"a\", tags: [], note: None)\n\n@public\nroute POST \"/users\" (body: User) -> Kind:\n    ret Kind::Admin\n",
    )
    .unwrap();
    let out = run_in(&dir, &["types", "--ts", "main.prvz", "--out", "types.ts"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    std::fs::write(
        dir.join("use.ts"),
        r#"import type { User, UserInput, Kind, Routes } from "./types";
const u: User = { id: 1, name: "a", tags: [], note: null };
const input: UserInput = { id: 1, name: "a" };
const k: Kind[] = ["Admin", { Member: "x" }];
const p: Routes["GET /users/{id}"]["params"] = { id: 7 };
const q: Routes["GET /users/{id}"]["query"] = { page: 1 };
const b: Routes["POST /users"]["body"] = input;
const r: Routes["POST /users"]["response"] = k[0];
// @ts-expect-error a string is not a number: the types must reject it
const bad: User = { id: "1", name: "a", tags: [], note: null };
export { u, p, q, b, r, bad };
"#,
    )
    .unwrap();
    let tsc = Command::new("npx")
        .args(["-y", "-p", "typescript@5.6.3", "tsc", "--strict", "--noEmit", "--target", "es2020", "--moduleResolution", "node", "use.ts", "types.ts"])
        .current_dir(&dir)
        .output()
        .unwrap();
    assert!(tsc.status.success(), "tsc --strict failed:\n{}{}", text(&tsc.stdout), text(&tsc.stderr));
}

// ---------- v0.9 ----------

#[test]
fn parvez_test_runs_blocks_and_maps_failures() {
    let dir = scratch("tests9");
    std::fs::write(
        dir.join("app.prvz"),
        "import pricing\nuse std::sync::atomic::{AtomicU64, Ordering}\n\n@json\ntype Order: item: str, qty: u32\n\nstate:\n    orders: AtomicU64 = AtomicU64::new(0)\n\nfn require_key(req) -> str!:\n    match req.header(\"x-api-key\"):\n        Some(k) if k == \"k1\" -> ret \"alice\"\n        _ -> fail(401, code: \"unauthenticated\", \"missing key\")\n\n@guard(require_key)\nroute POST \"/orders\" (state, auth, body: Order) -> u32:\n    state.orders.fetch_add(1, Ordering::SeqCst)\n    status(201)\n    ret pricing::total(body.qty)\n\ntest \"orders need an api key\":\n    app = test_app().await?\n    res = app.post(\"/orders\", &Order(item: \"pen\", qty: 2)).await?\n    assert_eq(res.status, 401)\n\ntest \"an order is priced and counted\":\n    app = test_app().await?\n    res = app.request(\"POST\", \"/orders\").header(\"x-api-key\", \"k1\").json(&Order(item: \"pen\", qty: 10)).send().await?\n    assert_eq(res.status, 201)\n    assert_eq(res.text(), \"90\")\n    assert(res.header(\"x-request-id\").is_some(), \"responses carry a request id\")\n\ntest \"this one fails on purpose\":\n    x = pricing::total(2)\n    assert(x == 21, \"expected 21 but got {x}\")\n",
    )
    .unwrap();
    std::fs::write(dir.join("pricing.prvz"), "fn total(qty: u32) -> u32:\n    if qty >= 10: ret qty * 9\n    ret qty * 10\n\ntest \"module tests run too\":\n    assert(total(0) == 0)\n").unwrap();
    let out = run_in(&dir, &["test", "app.prvz"]);
    let all = text(&out.stdout) + &text(&out.stderr);
    assert!(!out.status.success(), "{all}");
    assert!(all.contains("3 passed; 1 failed"), "{all}");
    assert!(all.contains("app.prvz:35: expected 21 but got 20"), "{all}");
    // panics point at the .prvz line, never the generated Rust; no rustc warnings
    assert!(all.contains("panicked at app.prvz:35:"), "{all}");
    assert!(!all.contains("src/main.rs") && !all.contains("warning:"), "{all}");
    let out = run_in(&dir, &["test", "app.prvz", "priced and counted"]);
    let all = text(&out.stdout) + &text(&out.stderr);
    assert!(out.status.success() && all.contains("1 passed"), "{all}");
}

#[test]
fn services_log_json_with_request_ids_and_export_metrics() {
    let dir = scratch("obs9");
    std::fs::write(
        dir.join("svc.prvz"),
        "@public\nroute POST \"/orders/{id}\" (id: u32) -> str:\n    log_info(\"order placed\", order: id)\n    metric_inc(\"orders_placed\")\n    ret \"ok\"\n",
    )
    .unwrap();
    let out = run_in(&dir, &["build", "svc.prvz"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let log = dir.join("svc.log");
    let mut server = KillOnDrop(
        Command::new(dir.join("svc"))
            .env("PORT", port.to_string())
            .env("PARVEZ_METRICS_TOKEN", "m3tr1cs")
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
    let raw = http_raw(port, b"POST /orders/7 HTTP/1.1\r\nHost: t\r\nx-request-id: trace-42\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    assert!(raw.to_lowercase().contains("x-request-id: trace-42"), "{raw}");
    assert_eq!(http(port, "GET", "/nope", "").0, 404);
    assert_eq!(http(port, "GET", "/healthz", ""), (200, "ok".into()));
    assert_eq!(http(port, "GET", "/metrics", "").0, 401, "metrics token enforced");
    let metrics = http_raw(port, b"GET /metrics HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer m3tr1cs\r\nConnection: close\r\n\r\n");
    for want in [
        r#"parvez_http_requests_total{method="POST",route="/orders/{id}",status="200"} 1"#,
        r#"parvez_http_requests_total{method="GET",route="unmatched",status="404"} 1"#,
        r#"parvez_http_request_duration_seconds_count{method="POST",route="/orders/{id}"} 1"#,
        r#"parvez_events_total{event="orders_placed"} 1"#,
    ] {
        assert!(metrics.contains(want), "missing {want} in:\n{metrics}");
    }
    let _ = server.0.kill();
    let _ = server.0.wait();
    let lines: Vec<serde_json::Value> = std::fs::read_to_string(&log)
        .unwrap()
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    let custom = lines.iter().find(|l| l["msg"] == "order placed").expect("log_info line");
    assert_eq!((custom["order"].as_u64(), custom["request_id"].as_str()), (Some(7), Some("trace-42")));
    let access = lines.iter().find(|l| l["msg"] == "request" && l["path"] == "/orders/7").expect("access log line");
    assert_eq!((access["route"].as_str(), access["status"].as_u64(), access["request_id"].as_str()), (Some("/orders/{id}"), Some(200), Some("trace-42")));
    assert!(!lines.iter().any(|l| l["path"] == "/healthz"), "health checks are not logged");
}

fn b64url(data: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..=c.len() {
            out.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    out
}

#[test]
fn oidc_guard_validates_tokens_against_jwks() {
    if Command::new("openssl").arg("version").output().map(|o| !o.status.success()).unwrap_or(true) {
        eprintln!("skipping: openssl not installed");
        return;
    }
    let dir = scratch("oidc9");
    let openssl = |args: &[&str], input: Option<&[u8]>| {
        use std::io::Write;
        let mut c = Command::new("openssl")
            .args(args)
            .current_dir(&dir)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        c.stdin.take().unwrap().write_all(input.unwrap_or_default()).unwrap();
        c.wait_with_output().unwrap().stdout
    };
    openssl(&["genrsa", "-out", "key.pem", "2048"], None);
    openssl(&["genrsa", "-out", "other.pem", "2048"], None);
    let modulus = String::from_utf8(openssl(&["rsa", "-in", "key.pem", "-noout", "-modulus"], None)).unwrap();
    let hex = modulus.trim().split('=').nth(1).unwrap();
    let n: Vec<u8> = (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect();

    // fake identity provider: discovery + JWKS
    let idp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let iss = format!("http://127.0.0.1:{}", idp.local_addr().unwrap().port());
    let discovery = format!(r#"{{"issuer":"{iss}","jwks_uri":"{iss}/jwks"}}"#);
    let jwks = format!(r#"{{"keys":[{{"kty":"RSA","kid":"k1","alg":"RS256","use":"sig","n":"{}","e":"AQAB"}}]}}"#, b64url(&n));
    std::thread::spawn(move || {
        use std::io::{Read, Write};
        for s in idp.incoming().flatten() {
            let mut s = s;
            let mut buf = [0u8; 2048];
            let n = s.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]);
            let body = if req.starts_with("GET /jwks") { &jwks } else { &discovery };
            let _ = write!(s, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
        }
    });
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let signed = |alg: &str, key: &str, payload: String| {
        let h = b64url(format!(r#"{{"alg":"{alg}","kid":"k1","typ":"JWT"}}"#).as_bytes());
        let p = b64url(payload.as_bytes());
        let msg = format!("{h}.{p}");
        let sig = openssl(&["dgst", "-sha256", "-sign", key], Some(msg.as_bytes()));
        format!("{msg}.{}", b64url(&sig))
    };
    let token = |alg: &str, key: &str, extra: &str, exp: u64, aud: &str| {
        signed(alg, key, format!(r#"{{"iss":"{iss}","sub":"u-1","aud":"{aud}","exp":{exp},"email":"ada@adn.test","realm_access":{{"roles":["App.Engineer"{extra}]}}}}"#))
    };
    // Keycloak shapes: `typ` access/ID/refresh, client roles, missing e-mail
    let keycloak = |top: &str| {
        signed("RS256", "key.pem", format!(r#"{{"iss":"{iss}","sub":"u-2","aud":["my-api","account"],"exp":{},"preferred_username":"bob"{top}}}"#, now + 300))
    };
    std::fs::write(
        dir.join("svc.prvz"),
        "async fn admin(req) -> Claims!:\n    c = oidc(req).await?\n    if not c.has_role(\"App.Admin\"): fail(403, code: \"forbidden\", \"admin role required\")\n    ret c\n\n@guard(admin)\nroute GET \"/admin\" (auth) -> str:\n    ret auth.email.clone()\n",
    )
    .unwrap();
    let out = run_in(&dir, &["build", "svc.prvz"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let _server = KillOnDrop(
        Command::new(dir.join("svc"))
            .env("PORT", port.to_string())
            .env("PARVEZ_OIDC_ISSUER", &iss)
            .env("PARVEZ_OIDC_AUDIENCE", "my-api")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(std::time::Instant::now() < deadline, "server did not start");
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let call = |tok: &str| {
        let raw = http_raw(port, format!("GET /admin HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer {tok}\r\nConnection: close\r\n\r\n").as_bytes());
        (raw[9..12].to_string(), raw.split_once("\r\n\r\n").map(|x| x.1.to_string()).unwrap_or_default())
    };
    let admin = token("RS256", "key.pem", r#","App.Admin""#, now + 300, "my-api");
    assert_eq!(call(&admin), ("200".into(), "ada@adn.test".into()));
    assert_eq!(call(&token("RS256", "key.pem", "", now + 300, "my-api")).0, "403", "no admin role");
    assert_eq!(call(&token("RS256", "key.pem", r#","App.Admin""#, now - 3600, "my-api")).0, "401", "expired");
    assert_eq!(call(&token("RS256", "key.pem", r#","App.Admin""#, now + 300, "other-api")).0, "401", "audience");
    assert_eq!(call(&token("RS256", "other.pem", r#","App.Admin""#, now + 300, "my-api")).0, "401", "forged signature");
    assert_eq!(call(&token("HS256", "key.pem", r#","App.Admin""#, now + 300, "my-api")).0, "401", "HMAC algorithm confusion");
    let parts: Vec<&str> = admin.split('.').collect();
    let none = format!("{}.{}.", b64url(br#"{"alg":"none","typ":"JWT"}"#), parts[1]);
    assert_eq!(call(&none).0, "401", "alg none");
    assert_eq!(call("").0, "401");
    let admin_role = r#","realm_access":{"roles":["App.Admin"]}"#;
    assert_eq!(call(&keycloak(&format!(r#","typ":"Bearer"{admin_role}"#))), ("200".into(), "bob".into()), "access token, e-mail falls back to username");
    assert_eq!(call(&keycloak(&format!(r#","typ":"ID"{admin_role}"#))).0, "401", "ID token");
    assert_eq!(call(&keycloak(&format!(r#","typ":"Refresh"{admin_role}"#))).0, "401", "refresh token");
    assert_eq!(call(&keycloak(r#","resource_access":{"my-api":{"roles":["App.Admin"]}}"#)).0, "200", "own client role");
    assert_eq!(call(&keycloak(r#","resource_access":{"account":{"roles":["App.Admin"]}}"#)).0, "403", "another client's role");
    assert_eq!(call(&keycloak(&format!(r#","sub":""{admin_role}"#))).0, "401", "empty subject");
}

/// v0.9.1 language: generics, traits (async + dyn), map literals, json(..),
/// catch, `as`, `priv`, parallel, `every`, guard path params, @test_only.
#[test]
fn language_completeness_features() {
    let dir = scratch("lang091");
    for f in ["main.prvz", "store.prvz", "testkit.prvz", "ts.prvz"] {
        std::fs::copy(format!("tests/fixtures/lang091/{f}"), dir.join(f)).unwrap();
    }
    let ts = text(&run_in(&dir, &["types", "--ts", "ts.prvz"]).stdout);
    assert!(ts.contains("export type Page<T> = {") && ts.contains("response: Page<Item>;"), "{ts}");
    let out = run_in(&dir, &["test", "main.prvz"]);
    let all = text(&out.stdout) + &text(&out.stderr);
    assert!(out.status.success() && all.contains("3 passed"), "{all}");

    // production build: test code and its crates are gone
    let out = run_in(&dir, &["build", "main.prvz"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let manifest = std::fs::read_to_string(dir.join(".parvez_build/main/Cargo.toml")).unwrap();
    let (prod, dev) = manifest.split_once("[dev-dependencies]").expect("dev-dependencies section");
    for c in ["sha2", "hex", "tower"] {
        assert!(!prod.contains(&format!("\n{c} ")) && dev.contains(c), "{c} must be dev-only:\n{manifest}");
    }
    let bin = std::fs::read(exe(&dir, "main")).unwrap();
    assert!(!bin.windows(20).any(|w| w == b"fixture-only-not-a-r"), "test fixture leaked into the release binary");

    // the worker runs in the real binary
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let _server = KillOnDrop(
        Command::new(dir.join("main"))
            .env("PORT", port.to_string())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(std::time::Instant::now() < deadline, "server did not start");
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    std::thread::sleep(std::time::Duration::from_millis(500));
    let stats = http_raw(port, b"GET /stats HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n");
    assert!(stats.contains(r#""ticks":true"#) && stats.contains(r#""sum":37"#), "{stats}");

    // `priv` is enforced across modules, reported at the .prvz line
    std::fs::write(dir.join("priv.prvz"), "import store\nfn main():\n    print(store::secret_helper())\n").unwrap();
    let out = run_in(&dir, &["check", "priv.prvz"]);
    let err = text(&out.stderr);
    assert!(!out.status.success() && err.contains("priv.prvz:3: error[E0603]"), "{err}");
}

/// v0.9.1 CLI: `new` scaffolds a passing project, `fmt` is canonical and
/// verified, every release build writes `<binary>.sha256`, `--target` cross-builds.
#[test]
fn new_fmt_checksums_and_targets() {
    let parent = scratch("new091");
    let _ = std::fs::remove_dir_all(parent.join("demo"));
    let out = run_in(&parent, &["new", "demo"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(!run_in(&parent, &["new", "demo"]).status.success(), "refuses a non-empty directory");
    assert!(!run_in(&parent, &["new", "Bad Name"]).status.success());
    let dir = parent.join("demo");
    for f in ["parvez.toml", "main.prvz", "ui/home.msd", ".gitignore", "README.md"] {
        assert!(dir.join(f).is_file(), "{f}");
    }
    assert!(run_in(&dir, &["fmt", "--check", "."]).status.success(), "scaffold is formatted");
    let out = run_in(&dir, &["test", "main.prvz"]);
    let all = text(&out.stdout) + &text(&out.stderr);
    assert!(out.status.success() && all.contains("2 passed"), "{all}");

    // fmt rewrites in place, keeps comments, and is idempotent; --check fails on unformatted files
    std::fs::write(dir.join("extra.prvz"), "fn f(a:i64,b :i64)->i64:\n  # keep me\n  ret a+b\n").unwrap();
    assert_eq!(run_in(&dir, &["fmt", "--check", "extra.prvz"]).status.code(), Some(1));
    assert!(run_in(&dir, &["fmt", "extra.prvz"]).status.success());
    assert_eq!(
        std::fs::read_to_string(dir.join("extra.prvz")).unwrap(),
        "fn f(a: i64, b: i64) -> i64:\n    # keep me\n    ret a+b\n"
    );
    assert!(run_in(&dir, &["fmt", "--check", "."]).status.success());

    let out = run_in(&dir, &["build", "main.prvz"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let bin = format!("main{}", std::env::consts::EXE_SUFFIX); // main.exe on Windows
    let sum = std::fs::read_to_string(dir.join(format!("{bin}.sha256"))).unwrap();
    let (hex, name) = sum.trim_end().split_once("  ").unwrap();
    assert_eq!(name, bin);
    assert_eq!(hex.len(), 64);
    if Command::new("sha256sum").arg("--version").output().is_ok() {
        let check = Command::new("sha256sum").args(["-c", &format!("{bin}.sha256")]).current_dir(&dir).output().unwrap();
        assert!(check.status.success(), "{}", text(&check.stdout));
    }

    let out = run_in(&dir, &["build", "main.prvz", "--target", "not-a-real-target"]);
    assert!(text(&out.stderr).contains("rustup target add not-a-real-target"), "{}", text(&out.stderr));
    let musl = "x86_64-unknown-linux-musl";
    let installed = Command::new("rustup")
        .args(["target", "list", "--installed"])
        .output()
        .map(|o| text(&o.stdout).lines().any(|l| l == musl))
        .unwrap_or(false);
    if installed && cfg!(all(target_arch = "x86_64", target_os = "linux")) {
        let out = run_in(&dir, &["build", "main.prvz", "--target", musl]);
        assert!(out.status.success(), "{}", text(&out.stderr));
        let bin = dir.join(format!("main-{musl}"));
        assert!(bin.is_file() && dir.join(format!("main-{musl}.sha256")).is_file());
        let probe = Command::new(&bin).env("PORT", "0").arg("--version").stdout(std::process::Stdio::null()).spawn();
        if let Ok(mut c) = probe {
            let _ = c.kill();
        }
    }
}

/// v0.9.1 browser sign-in: authorization code + PKCE against a fake IdP,
/// encrypted session cookies, login redirects (HX-Redirect for htmx), CSRF,
/// transparent refresh, logout, and HTML error pages for navigations.
#[test]
fn browser_sign_in_with_session_cookies() {
    if Command::new("openssl").arg("version").output().map(|o| !o.status.success()).unwrap_or(true) {
        eprintln!("skipping: openssl not installed");
        return;
    }
    let dir = scratch("session091");
    let openssl = |args: &[&str], input: Option<&[u8]>| {
        use std::io::Write;
        let mut c = Command::new("openssl")
            .args(args)
            .current_dir(&dir)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        c.stdin.take().unwrap().write_all(input.unwrap_or_default()).unwrap();
        c.wait_with_output().unwrap().stdout
    };
    openssl(&["genrsa", "-out", "key.pem", "2048"], None);
    let modulus = String::from_utf8(openssl(&["rsa", "-in", "key.pem", "-noout", "-modulus"], None)).unwrap();
    let hex = modulus.trim().split('=').nth(1).unwrap();
    let n: Vec<u8> = (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect();
    let idp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let iss = format!("http://127.0.0.1:{}", idp.local_addr().unwrap().port());
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let sign = |exp: u64, email: &str| {
        let h = b64url(br#"{"alg":"RS256","kid":"k1","typ":"JWT"}"#);
        let p = b64url(format!(r#"{{"iss":"{iss}","sub":"u-9","aud":["api","account"],"typ":"Bearer","exp":{exp},"email":"{email}"}}"#).as_bytes());
        let msg = format!("{h}.{p}");
        let sig = openssl(&["dgst", "-sha256", "-sign", "key.pem"], Some(msg.as_bytes()));
        format!("{msg}.{}", b64url(&sig))
    };
    let long = sign(now + 3600, "ada<b>@adn.test");
    // signed right before use (the build takes a while): see the refresh step
    let short = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let short_idp = short.clone();
    // the IdP refuses refreshes once the user is "disabled"
    let disabled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let disabled_idp = disabled.clone();
    let refreshed = sign(now + 3600, "fresh@adn.test");
    let discovery = format!(
        r#"{{"issuer":"{iss}","jwks_uri":"{iss}/jwks","authorization_endpoint":"{iss}/authorize","token_endpoint":"{iss}/token","end_session_endpoint":"{iss}/logout"}}"#
    );
    let jwks = format!(r#"{{"keys":[{{"kty":"RSA","kid":"k1","alg":"RS256","use":"sig","n":"{}","e":"AQAB"}}]}}"#, b64url(&n));
    std::thread::spawn(move || {
        use std::io::{Read, Write};
        for s in idp.incoming().flatten() {
            let mut s = s;
            let mut buf = vec![0u8; 16384];
            let n = s.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let form = req.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
            let verifier_ok = form.split('&').any(|kv| kv.strip_prefix("code_verifier=").is_some_and(|v| v.len() == 43));
            let (status, body) = if req.starts_with("GET /jwks") {
                ("200 OK", jwks.clone())
            } else if req.starts_with("POST /token") && form.contains("grant_type=authorization_code") && verifier_ok {
                let at = if form.contains("code=short") { short_idp.lock().unwrap().clone() } else { long.clone() };
                ("200 OK", format!(r#"{{"access_token":"{at}","refresh_token":"rt-1","token_type":"Bearer"}}"#))
            } else if req.starts_with("POST /token")
                && form.contains("grant_type=refresh_token")
                && form.contains("refresh_token=rt-")
                && !disabled_idp.load(std::sync::atomic::Ordering::SeqCst)
            {
                ("200 OK", format!(r#"{{"access_token":"{refreshed}","refresh_token":"rt-2"}}"#))
            } else if req.starts_with("POST /token") {
                ("400 Bad Request", r#"{"error":"invalid_grant"}"#.to_string())
            } else {
                ("200 OK", discovery.clone())
            };
            let _ = write!(s, "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
        }
    });
    std::fs::write(
        dir.join("app.prvz"),
        "import dash\n\nasync fn me(req) -> Claims!:\n    ret oidc_session(req).await?\n\n@guard(me)\nroute GET \"/whoami\" (auth) -> str:\n    ret auth.email.clone()\n\n@guard(me)\nroute POST \"/act\" (auth) -> str:\n    ret \"done\"\n",
    )
    .unwrap();
    std::fs::write(dir.join("dash.msd"), "@public\npage GET \"/dash\" (req) -> html:\n    let c = me(req).await?\n    p Hello {c.email}\n    form(method=\"post\" action=\"/auth/logout\"):\n        button(type=\"submit\") Sign out\n\n@guard(me)\npage GET \"/guarded/{tab}\" (auth, tab: str) -> html:\n    h1 Welcome {auth.email}\n    p tab {tab}\n").unwrap();
    let out = run_in(&dir, &["build", "app.prvz"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let public = format!("http://127.0.0.1:{port}");
    let _server = KillOnDrop(
        Command::new(dir.join("app"))
            .env("PORT", port.to_string())
            .env("PARVEZ_OIDC_ISSUER", &iss)
            .env("PARVEZ_OIDC_AUDIENCE", "api")
            .env("PARVEZ_OIDC_CLIENT_ID", "dashboard")
            .env("PARVEZ_PUBLIC_URL", &public)
            .env("PARVEZ_SESSION_KEY", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
            .env("PARVEZ_OIDC_LEEWAY_SECS", "0")
            .env("PARVEZ_SESSION_RECHECK_SECS", "4")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(std::time::Instant::now() < deadline, "server did not start");
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let get = |path: &str, extra: &str| http_raw(port, format!("GET {path} HTTP/1.1\r\nHost: t\r\n{extra}Connection: close\r\n\r\n").as_bytes());
    let header = |raw: &str, name: &str| -> Vec<String> {
        raw.split("\r\n\r\n").next().unwrap_or("").lines().filter_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.eq_ignore_ascii_case(name).then(|| v.trim().to_string())
        }).collect()
    };
    let jar = |raw: &str| -> String {
        header(raw, "set-cookie").iter().filter_map(|c| c.split(';').next()).filter(|kv| !kv.ends_with('=')).collect::<Vec<_>>().join("; ")
    };

    // not signed in: navigation redirects, htmx gets HX-Redirect, APIs get JSON 401
    let r = get("/dash", "Accept: text/html\r\n");
    assert!(r.starts_with("HTTP/1.1 303") && header(&r, "location") == ["/auth/login?next=/dash"], "{r}");
    let r = get("/dash", "HX-Request: true\r\nHX-Current-URL: http://x/dash?tab=1\r\n");
    assert!(r.starts_with("HTTP/1.1 401") && header(&r, "hx-redirect") == ["/auth/login?next=/dash%3Ftab%3D1"], "{r}");
    let r = get("/whoami", "");
    assert!(r.starts_with("HTTP/1.1 401") && r.contains(r#""code":"unauthenticated""#), "{r}");
    // a page with @guard: the guard runs before the template, exactly like a route
    let r = get("/guarded/x", "Accept: text/html\r\n");
    assert!(r.starts_with("HTTP/1.1 303") && header(&r, "location") == ["/auth/login?next=/guarded/x"], "{r}");

    // login: PKCE redirect + sealed state cookie
    let r = get("/auth/login?next=/dash", "");
    let loc = header(&r, "location").pop().unwrap_or_default();
    assert!(loc.starts_with(&format!("{iss}/authorize?")) && loc.contains("code_challenge_method=S256") && loc.contains("client_id=dashboard"), "{r}");
    assert!(loc.contains(&format!("redirect_uri=http%3A%2F%2F127.0.0.1%3A{port}%2Fauth%2Fcallback")), "{loc}");
    let state = loc.split("state=").nth(1).unwrap().split('&').next().unwrap().to_string();
    let login_cookie = jar(&r);
    assert!(login_cookie.starts_with("parvez_login=") && header(&r, "set-cookie")[0].contains("HttpOnly; SameSite=Lax"), "{r}");

    // callback: a wrong state or a missing login cookie fails; the right one starts a session
    let r = get("/auth/callback?code=good&state=nope", &format!("Cookie: {login_cookie}\r\n"));
    assert!(r.starts_with("HTTP/1.1 401") && r.contains("state mismatch"), "{r}");
    let r = get(&format!("/auth/callback?code=good&state={state}"), "Accept: text/html\r\n");
    assert!(r.starts_with("HTTP/1.1 401") && r.contains("<h1>401 Unauthorized</h1>"), "HTML error page for navigations: {r}");
    let r = get(&format!("/auth/callback?code=good&state={state}"), &format!("Cookie: {login_cookie}\r\n"));
    assert!(r.starts_with("HTTP/1.1 303") && header(&r, "location") == ["/dash"], "{r}");
    let session = jar(&r);
    assert!(session.starts_with("parvez_session.0="), "{r}");
    assert!(!session.contains("eyJ"), "tokens must not be readable in the cookie");

    // signed in: page renders (escaped), API works, tampering is rejected
    let r = get("/dash", &format!("Accept: text/html\r\nCookie: {session}\r\n"));
    assert!(r.starts_with("HTTP/1.1 200") && r.contains("Hello ada&lt;b&gt;@adn.test"), "{r}");
    // security headers: strict CSP on pages (forms may post to the IdP for sign-out), none on data, HSTS
    assert_eq!(
        header(&r, "content-security-policy"),
        [format!(
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; base-uri 'self'; form-action 'self' {iss}; frame-ancestors 'none'"
        )],
        "{r}"
    );
    assert_eq!(header(&r, "strict-transport-security"), ["max-age=31536000"]);
    let api = get("/whoami", &format!("Cookie: {session}\r\n"));
    assert_eq!(header(&api, "content-security-policy"), ["default-src 'none'; frame-ancestors 'none'"], "{api}");
    assert_eq!(get("/whoami", &format!("Cookie: {session}\r\n")).rsplit("\r\n\r\n").next().unwrap(), "ada<b>@adn.test");
    let r = get("/guarded/a%3Cb", &format!("Accept: text/html\r\nCookie: {session}\r\n"));
    assert!(r.starts_with("HTTP/1.1 200") && r.contains("<h1>Welcome ada&lt;b&gt;@adn.test</h1><p>tab a&lt;b</p>"), "{r}");
    let mut bad = session.clone();
    let k = bad.len() - 5;
    bad.replace_range(k..k + 1, if &bad[k..k + 1] == "A" { "B" } else { "A" });
    assert!(get("/dash", &format!("Accept: text/html\r\nCookie: {bad}\r\n")).starts_with("HTTP/1.1 303"));

    // CSRF: unsafe methods need our own Origin
    let post = |extra: &str| http_raw(port, format!("POST /act HTTP/1.1\r\nHost: t\r\nCookie: {session}\r\n{extra}Content-Length: 0\r\nConnection: close\r\n\r\n").as_bytes());
    assert!(post("").starts_with("HTTP/1.1 403"));
    assert!(post("Origin: https://evil.example\r\n").starts_with("HTTP/1.1 403"));
    assert!(post(&format!("Origin: {public}\r\n")).starts_with("HTTP/1.1 200"));
    // a same-origin form post under no-referrer: Chrome sends `Origin: null` + Sec-Fetch-Site
    assert!(post("Origin: null\r\nSec-Fetch-Site: same-origin\r\n").starts_with("HTTP/1.1 200"));
    assert!(post("Origin: null\r\nSec-Fetch-Site: cross-site\r\n").starts_with("HTTP/1.1 403"));
    assert!(post("Origin: null\r\n").starts_with("HTTP/1.1 403"));

    // open redirects are refused
    let r = get("/auth/login?next=//evil.example/x", "");
    let st = header(&r, "location").pop().unwrap().split("state=").nth(1).unwrap().split('&').next().unwrap().to_string();
    let r = get(&format!("/auth/callback?code=good&state={st}"), &format!("Cookie: {}\r\n", jar(&r)));
    assert_eq!(header(&r, "location"), ["/"]);

    // an expired access token is refreshed transparently and the cookie is replaced
    let soon = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + 2;
    *short.lock().unwrap() = sign(soon, "short@adn.test");
    let r = get("/auth/login?next=/whoami", "");
    let st = header(&r, "location").pop().unwrap().split("state=").nth(1).unwrap().split('&').next().unwrap().to_string();
    let r = get(&format!("/auth/callback?code=short&state={st}"), &format!("Cookie: {}\r\n", jar(&r)));
    let short_session = jar(&r);
    std::thread::sleep(std::time::Duration::from_secs(3));
    let r = get("/whoami", &format!("Cookie: {short_session}\r\n"));
    assert!(r.ends_with("fresh@adn.test") && jar(&r).starts_with("parvez_session.0="), "{r}");

    // a disabled user: within the recheck interval the session still works, after it the
    // IdP refuses the refresh and the session ends (no back-channel call needed)
    let fresh_session = jar(&r);
    disabled.store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(get("/whoami", &format!("Cookie: {fresh_session}\r\n")).ends_with("fresh@adn.test"));
    std::thread::sleep(std::time::Duration::from_secs(5));
    let r = get("/whoami", &format!("Cookie: {fresh_session}\r\n"));
    assert!(r.starts_with("HTTP/1.1 401") && header(&r, "set-cookie").iter().any(|c| c.contains("Max-Age=0")), "{r}");
    disabled.store(false, std::sync::atomic::Ordering::SeqCst);

    // back-channel logout: a signed logout token from the IdP ends the user's sessions
    // and bearer tokens at once; forged or malformed tokens are refused
    let r = get("/auth/login?next=/whoami", "");
    let st = header(&r, "location").pop().unwrap().split("state=").nth(1).unwrap().split('&').next().unwrap().to_string();
    let r = get(&format!("/auth/callback?code=good&state={st}"), &format!("Cookie: {}\r\n", jar(&r)));
    let live = jar(&r);
    assert!(get("/whoami", &format!("Cookie: {live}\r\n")).ends_with("ada<b>@adn.test"));
    let bearer = format!("Authorization: Bearer {}\r\n", sign(now + 3600, "api@adn.test"));
    assert!(get("/whoami", &bearer).ends_with("api@adn.test"));
    let logout_token = |key: &str, aud: &str, extra: &str| {
        let h = b64url(br#"{"alg":"RS256","kid":"k1","typ":"logout+jwt"}"#);
        let iat = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let p = b64url(format!(r#"{{"iss":"{iss}","aud":"{aud}","iat":{iat},"jti":"j1","sub":"u-9","events":{{"http://schemas.openid.net/event/backchannel-logout":{{}}}}{extra}}}"#).as_bytes());
        let msg = format!("{h}.{p}");
        let sig = openssl(&["dgst", "-sha256", "-sign", key], Some(msg.as_bytes()));
        format!("{msg}.{}", b64url(&sig))
    };
    openssl(&["genrsa", "-out", "other.pem", "2048"], None);
    let bc = |tok: &str| {
        let body = format!("logout_token={tok}");
        http_raw(port, format!("POST /auth/backchannel-logout HTTP/1.1\r\nHost: t\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes())
    };
    assert!(bc(&logout_token("other.pem", "dashboard", "")).starts_with("HTTP/1.1 400"), "forged signature");
    assert!(bc(&logout_token("key.pem", "other-client", "")).starts_with("HTTP/1.1 400"), "wrong audience");
    assert!(bc(&logout_token("key.pem", "dashboard", r#","nonce":"n""#)).starts_with("HTTP/1.1 400"), "nonce present");
    assert!(get("/whoami", &format!("Cookie: {live}\r\n")).ends_with("ada<b>@adn.test"), "still signed in");
    assert!(bc(&logout_token("key.pem", "dashboard", "")).starts_with("HTTP/1.1 200"));
    assert!(get("/whoami", &format!("Cookie: {live}\r\n")).starts_with("HTTP/1.1 401"), "session ended at once");
    assert!(get("/dash", &format!("Accept: text/html\r\nCookie: {live}\r\n")).starts_with("HTTP/1.1 303"));
    assert!(get("/whoami", &bearer).starts_with("HTTP/1.1 401"), "the user's bearer tokens too");

    // logout: same-origin POST clears every chunk and ends the IdP session
    let r = http_raw(port, format!("POST /auth/logout HTTP/1.1\r\nHost: t\r\nOrigin: {public}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes());
    let loc = header(&r, "location").pop().unwrap_or_default();
    assert!(r.starts_with("HTTP/1.1 303") && loc.starts_with(&format!("{iss}/logout?client_id=dashboard")), "{r}");
    assert!(header(&r, "set-cookie").iter().filter(|c| c.contains("Max-Age=0")).count() >= 4, "{r}");
}

/// Deny-by-default: an endpoint without @guard or @public doesn't compile, and
/// `parvez routes` prints the complete access map for review.
#[test]
fn deny_by_default_and_access_map() {
    let dir = scratch("access092");
    std::fs::write(dir.join("open.prvz"), "route GET \"/admin/users\" -> str:\n    ret \"everyone\"\n").unwrap();
    let out = run_in(&dir, &["check", "open.prvz"]);
    let err = text(&out.stderr);
    assert!(!out.status.success() && err.contains("open.prvz:1: route GET /admin/users has no access policy"), "{err}");
    std::fs::write(
        dir.join("app.prvz"),
        "import ui\n\nfn staff(req) -> str!:\n    ret req.header(\"x-user\").unwrap_or_default()\n\n@public(\"load balancer health probe\")\nroute GET \"/ping\" -> str:\n    ret \"pong\"\n\n@guard(staff)\nroute POST \"/users/{id}\" (auth, id: str) -> str:\n    ret auth\n",
    )
    .unwrap();
    std::fs::write(dir.join("ui.msd"), "@guard(staff)\npage GET \"/admin\" (auth) -> html:\n    p {auth}\n").unwrap();
    let out = run_in(&dir, &["routes", "app.prvz"]);
    let map = text(&out.stdout);
    assert!(out.status.success(), "{}", text(&out.stderr));
    for want in [
        "GET     /ping",
        "PUBLIC (load balancer health probe)",
        "POST    /users/{id}",
        "guard staff",
        "app.prvz:7",
        "/admin",
        "ui.msd:2",
        "/healthz",
    ] {
        assert!(map.contains(want), "{want}\n{map}");
    }
    let json: serde_json::Value = serde_json::from_slice(&run_in(&dir, &["routes", "app.prvz", "--json"]).stdout).unwrap();
    let admin = json.as_array().unwrap().iter().find(|r| r["path"] == "/admin").unwrap();
    assert_eq!(admin["kind"], "page");
    assert_eq!(admin["guards"][0], "staff");
}

/// v0.10.1 `Secret`: redacted in output, no JSON, constant-time checks, input-only
/// JSON types, env_secret fails closed; exposure into output is a compile error.
#[test]
fn secret_type_never_leaks() {
    let dir = scratch("secret0101");
    for f in ["app.prvz", "bad.prvz", "bad2.prvz"] {
        std::fs::copy(format!("tests/fixtures/secret/{f}"), dir.join(f)).unwrap();
    }
    let out = run_in(&dir, &["check", "bad.prvz"]);
    let err = text(&out.stderr);
    for want in ["bad.prvz:5: security[secret-type]", "bad.prvz:6: security[hardcoded-secret]", "bad.prvz:10: security[secret-exposure]",
        "bad.prvz:11: security[secret-exposure]", "bad.prvz:12: security[secret-exposure]", "bad.prvz:13: security[secret-exposure]"] {
        assert!(err.contains(want), "{want}\n{err}");
    }
    let err = text(&run_in(&dir, &["check", "bad2.prvz"]).stderr);
    assert!(err.contains("bad2.prvz:5: POST /echo returns `Login`, which holds a Secret"), "{err}");

    let out = run_in(&dir, &["build", "app.prvz"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let missing = Command::new(dir.join("app")).env("PORT", "0").env_remove("APP_ADMIN_TOKEN").output().unwrap();
    assert!(!missing.status.success() && text(&missing.stderr).contains("environment variable APP_ADMIN_TOKEN is not set"));
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let log = dir.join("out.log");
    let mut server = Command::new(dir.join("app"))
        .env("PORT", port.to_string())
        .env("APP_ADMIN_TOKEN", "s3cret-admin-token")
        .stdout(std::fs::File::create(&log).unwrap())
        .stderr(std::fs::File::create(dir.join("err.log")).unwrap())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(std::time::Instant::now() < deadline, "server did not start");
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let (code, body) = http(port, "POST", "/login", r#"{"user":"ada","password":"correct horse"}"#);
    assert_eq!((code, body.as_str()), (200, r#"{"ok":true,"user":"ada"}"#));
    let stats = http_raw(port, b"GET /stats HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer s3cret-admin-token\r\nConnection: close\r\n\r\n");
    assert!(stats.ends_with("admin: 1 logins, token [redacted]"), "{stats}");
    let wrong = http_raw(port, b"GET /stats HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer s3cret-admin-tokeX\r\nConnection: close\r\n\r\n");
    assert!(wrong.starts_with("HTTP/1.1 401"), "{wrong}");
    let _ = server.kill();
    let _ = server.wait();
    let printed = std::fs::read_to_string(&log).unwrap() + &std::fs::read_to_string(dir.join("err.log")).unwrap();
    assert!(printed.contains("debug: [redacted] Login { user: \"ada\", password: [redacted] }"), "{printed}");
    assert!(!printed.contains("correct horse") && !printed.contains("s3cret-admin"), "a secret leaked:\n{printed}");
}

#[test]
fn lint_reports_standards_and_sarif() {
    let dir = scratch("lint012");
    std::fs::create_dir_all(dir.join("sub")).unwrap();
    std::fs::write(
        dir.join("app.prvz"),
        "import sub.store\n\n@public(\"demo\")\nroute GET \"/u/{name}\" (name: str) -> str:\n    db.execute(\"DELETE FROM u WHERE n = '{name}'\")\n    ret \"ok\"\n\n@allow_insecure(\"admin tool, input is a fixed enum\")\n@public(\"demo\")\nroute GET \"/r/{name}\" (name: str) -> str!:\n    ret std::fs::read_to_string(name)?\n",
    )
    .unwrap();
    std::fs::write(dir.join("sub/store.prvz"), "fn key() -> str:\n    api_key = \"sk_live_abcdefghijklmnop1234\"\n    ret api_key\n").unwrap();
    // plain: findings with fix + standards, exit 1
    let out = run_in(&dir, &["lint", "app.prvz"]);
    let (so, se) = (text(&out.stdout), text(&out.stderr));
    assert_eq!(out.status.code(), Some(1), "{so}{se}");
    assert!(so.contains("app.prvz:5: security[sql-injection]") && so.contains("= see: CWE-89, OWASP A03:2021 Injection, ASVS 5.3.4"), "{so}");
    assert!(so.contains("sub/store.prvz:2: security[hardcoded-secret]") && so.contains("CWE-798"), "{so}");
    assert!(!so.contains("app.prvz:11"), "waived finding printed: {so}");
    assert!(se.contains("app.prvz:10: @allow_insecure: admin tool") && se.contains("1 finding(s) waived") && se.contains("2 security finding(s)"), "{se}");
    // SARIF 2.1.0 file for code scanning
    let out = run_in(&dir, &["lint", "app.prvz", "--sarif", "-o", "out.sarif"]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    let doc: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(dir.join("out.sarif")).unwrap()).unwrap();
    assert_eq!(doc["version"], "2.1.0");
    let run = &doc["runs"][0];
    assert_eq!(run["tool"]["driver"]["name"], "parvez");
    let rules = run["tool"]["driver"]["rules"].as_array().unwrap();
    let sql = rules.iter().find(|r| r["id"] == "sql-injection").unwrap();
    assert_eq!(sql["properties"]["security-severity"], "9.8");
    assert!(sql["properties"]["tags"].as_array().unwrap().iter().any(|t| t == "external/cwe/cwe-89"));
    let results = run["results"].as_array().unwrap();
    let got: Vec<(String, String, u64, bool)> = results
        .iter()
        .map(|r| {
            let loc = &r["locations"][0]["physicalLocation"];
            (
                r["ruleId"].as_str().unwrap().to_string(),
                loc["artifactLocation"]["uri"].as_str().unwrap().to_string(),
                loc["region"]["startLine"].as_u64().unwrap(),
                r.get("suppressions").is_some(),
            )
        })
        .collect();
    let rel = |f: &str| {
        // URIs are relative to the enclosing git checkout (the scratch dir may be inside one)
        let base = dir.canonicalize().unwrap();
        let root = base.ancestors().find(|d| d.join(".git").exists()).map(|p| p.to_path_buf()).unwrap_or(base.clone());
        base.join(f).strip_prefix(&root).unwrap().to_string_lossy().replace('\\', "/")
    };
    assert_eq!(
        got,
        [
            ("sql-injection".into(), rel("app.prvz"), 5, false),
            ("hardcoded-secret".into(), rel("sub/store.prvz"), 2, false),
            ("path-traversal".into(), rel("app.prvz"), 11, true),
        ]
    );
    assert!(!std::fs::read_to_string(dir.join("out.sarif")).unwrap().contains(&*dir.canonicalize().unwrap().to_string_lossy()), "absolute path leaked");
    // clean program: exit 0; rule catalog
    std::fs::write(dir.join("ok.prvz"), "@public(\"demo\")\nroute GET \"/\" -> str:\n    ret \"hi\"\n").unwrap();
    let out = run_in(&dir, &["lint", "ok.prvz"]);
    assert!(out.status.success() && text(&out.stderr).contains("no security findings"), "{}", text(&out.stderr));
    let out = run_in(&dir, &["lint", "--rules"]);
    let cat = text(&out.stdout);
    for id in ["sql-injection", "command-injection", "path-traversal", "hardcoded-secret", "secret-exposure", "secret-type"] {
        assert!(cat.contains(id), "{cat}");
    }
}

#[test]
fn taint_crosses_modules_and_functions() {
    let dir = scratch("taint013");
    std::fs::create_dir_all(dir.join("lib")).unwrap();
    std::fs::write(
        dir.join("app.prvz"),
        "import lib.files\n\nfn staff(req) -> str!:\n    who = req.header(\"x-user\").unwrap_or_default()\n    ret std::fs::read_to_string(\"/etc/staff/{who}\")?\n\n@guard(staff)\nroute GET \"/a/{name}\" (name: str) -> str!:\n    ret files::load(name)?\n\n@public(\"demo\")\nroute GET \"/b\" (req) -> str!:\n    f = req.param(\"f\").unwrap_or_default()\n    ret std::fs::read_to_string(f)?\n\n@public(\"demo\")\nroute POST \"/c\" (body: Job) -> str!:\n    files::run_tool(&body.tool)\n    ret \"ok\"\n\n@public(\"demo\")\nroute GET \"/safe/{name}\" (name: str) -> str!:\n    ret files::load_safe(name)?\n\n@json\ntype Job: tool: str\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("lib/files.prvz"),
        "fn load(name: str) -> str!:\n    ret inner(name)\n\nfn inner(n: str) -> str!:\n    path = \"/srv/data/{n}\"\n    ret std::fs::read_to_string(&path)?\n\nfn load_safe(name: str) -> str!:\n    ret std::fs::read_to_string(safe_join(\"/srv/data\", &name)?)?\n\nfn run_tool(t: &str):\n    std::process::Command::new(t).status()\n",
    )
    .unwrap();
    let out = run_in(&dir, &["lint", "app.prvz"]);
    let so = text(&out.stdout);
    assert_eq!(out.status.code(), Some(1), "{so}{}", text(&out.stderr));
    for want in [
        "app.prvz:5: security[path-traversal]: request input reaches `std::fs::read_to_string(..)` unsanitized",
        "app.prvz:9: security[path-traversal]: request input passed to `files::load(..)` reaches `std::fs::read_to_string(..)` at lib/files.prvz:6 unsanitized",
        "app.prvz:14: security[path-traversal]: request input reaches `std::fs::read_to_string(..)` unsanitized",
        "app.prvz:18: security[command-injection]: request input passed to `files::run_tool(..)` reaches `Command::new(..)` at lib/files.prvz:12 unsanitized",
    ] {
        assert!(so.contains(want), "missing: {want}\n{so}");
    }
    assert!(!so.contains("app.prvz:23") && so.matches("security[").count() == 4, "{so}");
    // the build gate reports the same findings
    let err = text(&run_in(&dir, &["check", "app.prvz"]).stderr);
    assert!(err.contains("app.prvz:9: security[path-traversal]") && err.contains("4 security error(s)"), "{err}");
}

/// Adversarial corpus: every `# expect: rule` line must be reported, every
/// `# known-miss: rule` line must not be (yet), and nothing else may be.
#[test]
fn security_corpus() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/security_corpus");
    let mut expected = std::collections::BTreeSet::new();
    let mut known_miss = std::collections::BTreeSet::new();
    let mut stack = vec![root.clone()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            if p.extension().and_then(|x| x.to_str()) != Some("prvz") {
                continue;
            }
            let rel = p.strip_prefix(&root).unwrap().to_string_lossy().replace('\\', "/");
            for (i, line) in std::fs::read_to_string(&p).unwrap().lines().enumerate() {
                for (tag, set) in [("# expect: ", &mut expected), ("# known-miss: ", &mut known_miss)] {
                    if let Some(rule) = line.split(tag).nth(1) {
                        set.insert((rel.clone(), i + 1, rule.trim().to_string()));
                    }
                }
            }
        }
    }
    assert!(expected.len() >= 30, "corpus too small: {}", expected.len());
    let mut found = std::collections::BTreeSet::new();
    let mut entries: Vec<_> = std::fs::read_dir(&root).unwrap().map(|e| e.unwrap().path()).collect();
    entries.sort();
    for main in entries.iter().filter(|p| p.extension().and_then(|x| x.to_str()) == Some("prvz")) {
        let name = main.file_name().unwrap().to_str().unwrap();
        let out = parvez().current_dir(&root).args(["lint", name]).output().unwrap();
        let (so, se) = (text(&out.stdout), text(&out.stderr));
        assert!(se.contains("security finding") || out.status.success(), "{name} failed to lint:\n{se}");
        for line in so.lines() {
            // "file.prvz:12: security[rule]: ..."
            let Some((loc, rest)) = line.split_once(": security[") else { continue };
            let (file, n) = loc.rsplit_once(':').unwrap();
            let rule = rest.split(']').next().unwrap();
            found.insert((file.to_string(), n.parse::<usize>().unwrap(), rule.to_string()));
        }
    }
    let missed: Vec<_> = expected.difference(&found).collect();
    let extra: Vec<_> = found.difference(&expected).filter(|f| !known_miss.contains(*f)).collect();
    let caught_known: Vec<_> = known_miss.intersection(&found).collect();
    assert!(missed.is_empty(), "bypasses (expected but not reported): {missed:?}");
    assert!(extra.is_empty(), "false positives (reported but not expected): {extra:?}");
    assert!(caught_known.is_empty(), "now caught, change `known-miss` to `expect`: {caught_known:?}");
}

#[test]
fn security_header_overrides() {
    let dir = scratch("headers013");
    std::fs::write(dir.join("app.prvz"), "@public(\"demo\")\nroute GET \"/\" -> str:\n    ret \"hi\"\n").unwrap();
    let out = run_in(&dir, &["build", "app.prvz"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let serve = |env: &[(&str, &str)]| -> (String, String) {
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let mut cmd = Command::new(dir.join("app"));
        cmd.env("PORT", port.to_string()).env("PARVEZ_LOG", "on").env_remove("PARVEZ_CSP").env_remove("PARVEZ_HSTS");
        for (k, v) in env {
            cmd.env(k, v);
        }
        let mut server = cmd.stdout(std::process::Stdio::null()).stderr(std::process::Stdio::piped()).spawn().unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
            assert!(std::time::Instant::now() < deadline, "server did not start");
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        let r = http_raw(port, b"GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n");
        server.kill().unwrap();
        let mut err = String::new();
        std::io::Read::read_to_string(server.stderr.as_mut().unwrap(), &mut err).unwrap();
        server.wait().unwrap();
        (r.to_lowercase(), err)
    };
    // text/plain: the data policy and default HSTS
    let (r, _) = serve(&[]);
    assert!(r.contains("content-security-policy: default-src 'none'; frame-ancestors 'none'") && r.contains("strict-transport-security: max-age=31536000\r\n"), "{r}");
    // overrides
    let (r, _) = serve(&[("PARVEZ_HSTS", "max-age=63072000; includeSubDomains; preload")]);
    assert!(r.contains("strict-transport-security: max-age=63072000; includesubdomains; preload"), "{r}");
    let (r, _) = serve(&[("PARVEZ_CSP", "off"), ("PARVEZ_HSTS", "off")]);
    assert!(!r.contains("content-security-policy") && !r.contains("strict-transport-security"), "{r}");
    // an invalid override keeps the default and says so at startup
    let (r, err) = serve(&[("PARVEZ_HSTS", "bad\u{1}value")]);
    assert!(r.contains("strict-transport-security: max-age=31536000\r\n"), "{r}");
    assert!(err.contains("PARVEZ_HSTS is not a valid header value; using the default"), "{err}");
}

/// A tiny release server: `/latest` redirects to the tag, `/dl/<tag>/<file>` serves files.
#[cfg(unix)]
fn release_server(files: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>>) -> u16 {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let mut buf = [0u8; 4096];
            let n = s.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let mut parts = req.split_whitespace();
            let (method, path) = (parts.next().unwrap_or(""), parts.next().unwrap_or("").to_string());
            let head = method == "HEAD";
            let resp: Vec<u8> = if path == "/latest" {
                b"HTTP/1.1 302 Found\r\nLocation: /tag/v9.9.9\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
            } else if path.starts_with("/tag/") {
                b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
            } else if let Some(body) = files.lock().unwrap().get(&path).cloned() {
                let mut r = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).into_bytes();
                if !head {
                    r.extend(body);
                }
                r
            } else {
                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
            };
            let _ = s.write_all(&resp);
        }
    });
    port
}

#[test]
#[cfg(unix)] // the fake release's "binary" is a shell script; Windows is covered by CI's install test
fn upgrade_verifies_before_replacing() {
    use sha2::Digest;
    let Some(target) = (match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Some("x86_64-unknown-linux-musl"),
        ("linux", "aarch64") => Some("aarch64-unknown-linux-musl"),
        ("macos", "aarch64") => Some("aarch64-apple-darwin"),
        _ => None,
    }) else {
        return;
    };
    let dir = scratch("upgrade017");
    // a fake v9.9.9 release whose "binary" is a script
    let name = format!("parvez-v9.9.9-{target}");
    std::fs::create_dir_all(dir.join("rel").join(&name)).unwrap();
    std::fs::write(dir.join("rel").join(&name).join("parvez"), "#!/bin/sh\necho parvez 9.9.9\n").unwrap();
    let tgz = dir.join(format!("{name}.tar.gz"));
    assert!(Command::new("tar").arg("-czf").arg(&tgz).arg("-C").arg(dir.join("rel")).arg(&name).status().unwrap().success());
    let archive = std::fs::read(&tgz).unwrap();
    let good = format!("{:x}  {name}.tar.gz\n", sha2::Sha256::digest(&archive));
    let bad = format!("{}  {name}.tar.gz\n", "0".repeat(64));
    let files = std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
    files.lock().unwrap().insert(format!("/dl/v9.9.9/{name}.tar.gz"), archive);
    files.lock().unwrap().insert("/dl/v9.9.9/SHA256SUMS".to_string(), bad.into_bytes());
    let port = release_server(files.clone());
    // the installed copy, and a PATH with only curl and tar (no `gh`: the fake has no attestation)
    std::fs::create_dir_all(dir.join("bin")).unwrap();
    let exe = dir.join("bin/parvez");
    std::fs::copy(env!("CARGO_BIN_EXE_parvez"), &exe).unwrap();
    std::fs::create_dir_all(dir.join("tools")).unwrap();
    for tool in ["curl", "tar", "gzip"] {
        let found = std::env::split_paths(&std::env::var_os("PATH").unwrap()).map(|d| d.join(tool)).find(|p| p.is_file()).unwrap();
        let _ = std::os::unix::fs::symlink(found, dir.join("tools").join(tool));
    }
    let run = |args: &[&str]| {
        Command::new(&exe)
            .args(args)
            .env("PATH", dir.join("tools"))
            .env("PARVEZ_DOWNLOAD_BASE", format!("http://127.0.0.1:{port}/dl"))
            .env("PARVEZ_LATEST_URL", format!("http://127.0.0.1:{port}/latest"))
            .output()
            .unwrap()
    };
    let out = run(&["upgrade", "--check"]);
    assert!(text(&out.stdout).contains("-> v9.9.9 is available"), "{}{}", text(&out.stdout), text(&out.stderr));
    // a tampered download: refused, binary untouched
    let before = std::fs::read(&exe).unwrap();
    let out = run(&["upgrade"]);
    assert!(!out.status.success() && text(&out.stderr).contains("checksum mismatch"), "{}", text(&out.stderr));
    assert!(std::fs::read(&exe).unwrap() == before, "binary changed after a failed check");
    // the real thing
    files.lock().unwrap().insert("/dl/v9.9.9/SHA256SUMS".to_string(), good.into_bytes());
    let out = run(&["upgrade"]);
    assert!(out.status.success() && text(&out.stderr).contains("checksum OK"), "{}", text(&out.stderr));
    let v = Command::new(&exe).arg("--version").output().unwrap();
    assert_eq!(text(&v.stdout).trim(), "parvez 9.9.9");
    // bad version strings never reach the network
    let out = Command::new(env!("CARGO_BIN_EXE_parvez")).args(["upgrade", "--version", "v1.0.0/../../x"]).output().unwrap();
    assert!(text(&out.stderr).contains("isn't a release version"), "{}", text(&out.stderr));
}

#[test]
fn doctor_reports_the_toolchain() {
    let out = parvez().arg("doctor").output().unwrap();
    let so = text(&out.stdout);
    assert!(so.contains("ok    rustc ") && so.contains("ok    cargo ") && so.contains("ok    git version"), "{so}");
    assert!(
        so.contains("ok    C linker") || so.contains("ok    Xcode command line tools") || so.contains("ok    Visual Studio C++ build tools"),
        "{so}"
    );
    // without Rust on PATH it fails with the fix
    let empty = scratch("doctor017");
    let out = parvez().arg("doctor").env("PATH", &empty).output().unwrap();
    let so = text(&out.stdout);
    assert!(!out.status.success() && so.contains("FAIL  Rust isn't installed") && so.contains("sh.rustup.rs"), "{so}");
    if cfg!(target_os = "linux") {
        assert!(so.contains("FAIL  no C linker"), "{so}");
    }
}

#[test]
fn openapi_describes_routes_types_and_access() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/tasks");
    let out = parvez().current_dir(&root).args(["types", "--openapi", "main.prvz"]).output().unwrap();
    assert!(out.status.success(), "{}", text(&out.stderr));
    let d: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(d["openapi"], "3.1.0");
    let create = &d["paths"]["/api/tasks"]["post"];
    assert!(create["responses"]["201"]["content"]["application/json"]["schema"]["$ref"] == "#/components/schemas/Task", "{create}");
    assert_eq!(create["requestBody"]["content"]["application/json"]["schema"]["$ref"], "#/components/schemas/NewTask");
    assert_eq!(create["security"][0]["bearer"], serde_json::json!([]));
    assert_eq!(create["x-parvez-access"]["guards"][0], "tasks::me");
    assert!(d["paths"]["/api/tasks/{id}"]["delete"]["responses"]["204"].is_object());
    assert_eq!(d["paths"]["/api/tasks/{id}"]["patch"]["parameters"][0]["schema"]["type"], "integer");
    assert_eq!(d["components"]["schemas"]["Task"]["required"], serde_json::json!(["id", "title", "done"]));
    assert_eq!(d["components"]["securitySchemes"]["bearer"]["scheme"], "bearer");
    // public routes say why, and need no credentials
    let svc = parvez().current_dir(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples")).args(["types", "--openapi", "service.prvz"]).output().unwrap();
    let s: serde_json::Value = serde_json::from_slice(&svc.stdout).unwrap();
    let health = s["paths"].as_object().unwrap().values().flat_map(|ops| ops.as_object().unwrap().values()).find(|o| o["x-parvez-access"]["public"].is_string()).expect("a public route");
    assert_eq!(health["security"], serde_json::json!([]));
    // exactly one format at a time
    let both = parvez().args(["types", "--ts", "--openapi"]).output().unwrap();
    assert!(text(&both.stderr).contains("choose one"), "{}", text(&both.stderr));
}

#[test]
fn project_rules_and_dependency_policy() {
    let dir = scratch("policy020");
    std::fs::write(
        dir.join("parvez.toml"),
        "[security]\ndisallow = [{ call = \"std::env::set_var\", reason = \"configuration comes from parvez.toml\" }]\nlicenses = [\"MIT\"]\nban = [\"serde\"]\n\n[security.sinks]\ncommand = [\"duct::cmd\"]\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("app.prvz"),
        "@public(\"demo\")\nroute GET \"/run/{tool}\" (tool: str) -> str!:\n    duct::cmd(&tool, [\"--version\"]).run()?\n    ret \"ok\"\n\nfn main_tool():\n    std::env::set_var(\"X\", \"1\")\n",
    )
    .unwrap();
    let out = run_in(&dir, &["lint", "app.prvz"]);
    let so = text(&out.stdout);
    assert!(so.contains("app.prvz:3: security[command-injection]: request input reaches `duct::cmd(..)`"), "{so}");
    assert!(so.contains("app.prvz:7: security[disallowed-call]: `std::env::set_var(..)` is disallowed by parvez.toml: configuration comes from parvez.toml"), "{so}");
    // the dependency policy is checked on build, against what's actually compiled
    std::fs::write(dir.join("ok.prvz"), "@public(\"demo\")\nroute GET \"/\" -> str:\n    ret \"hi\"\n").unwrap();
    let out = run_in(&dir, &["build", "ok.prvz"]);
    let err = text(&out.stderr);
    assert!(!out.status.success() && err.contains("dependency policy violation(s)"), "{err}");
    assert!(err.contains("serde 1.") && err.contains("banned in parvez.toml"), "{err}");
    assert!(err.contains("isn't in [security] licenses"), "{err}");
    assert!(!exe(&dir, "ok").exists(), "no binary is shipped when the policy fails");
}
