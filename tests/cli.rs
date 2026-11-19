//! End-to-end tests: drive the real `parvez` binary, which runs cargo/rustc.

use std::path::PathBuf;
use std::process::{Command, Output};

fn parvez() -> Command {
    Command::new(env!("CARGO_BIN_EXE_parvez"))
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
    write!(
        s,
        "{method} {path} HTTP/1.1\r\nHost: t\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).unwrap();
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
