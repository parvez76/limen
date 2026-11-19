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
