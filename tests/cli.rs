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
}
