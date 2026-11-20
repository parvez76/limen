//! `parvez new <name>`: a project that builds, serves a page and passes its tests.
use anyhow::{Result, bail};
use std::path::Path;

pub fn new_project(parent: &Path, name: &str) -> Result<()> {
    let valid = !name.is_empty()
        && name.len() <= 64
        && name.starts_with(|c: char| c.is_ascii_lowercase())
        && name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_');
    if !valid {
        bail!("project name {name:?}: use lower-case letters, digits, `-` or `_`, starting with a letter");
    }
    let dir = parent.join(name);
    if dir.exists() && std::fs::read_dir(&dir)?.next().is_some() {
        bail!("{} already exists and is not empty", dir.display());
    }
    std::fs::create_dir_all(dir.join("ui"))?;
    let files: [(&str, String); 5] = [
        ("parvez.toml", PARVEZ_TOML.to_string()),
        ("main.prvz", MAIN.replace("__NAME__", name)),
        ("ui/home.msd", HOME.replace("__NAME__", name)),
        (".gitignore", GITIGNORE.to_string()),
        ("README.md", README.replace("__NAME__", name)),
    ];
    for (path, body) in files {
        std::fs::write(dir.join(path), body)?;
    }
    eprintln!("parvez: created {}/", dir.display());
    eprintln!("  cd {name}");
    eprintln!("  parvez test main.prvz     # run the tests");
    eprintln!("  parvez run main.prvz      # serve on :8080 (PORT=...)");
    Ok(())
}

const PARVEZ_TOML: &str = r#"# Pin or extend crates here; Parvez detects the rest from your code.
# [dependencies]
# chrono = "0.4"

[security]
# deny: known-vulnerable dependencies fail `parvez build` (warn | off to relax)
audit = "deny"
"#;

const MAIN: &str = r#"# __NAME__: a Parvez service.
#   parvez test main.prvz    run the tests below
#   parvez run main.prvz     serve on :8080
#   parvez fmt               format every .prvz/.msd file
import ui.home

@json
type Status: ok: bool, service: str

@json
type HomeQuery:
    @default
    name: str

route GET "/api/status" -> Status:
    ret Status(ok: true, service: "__NAME__")

test "status reports ok":
    app = test_app().await?
    res = app.get("/api/status").await?
    assert_eq(res.status, 200)
    s: Status = res.json()?
    assert(s.ok, "status should be ok")

test "the home page escapes input":
    app = test_app().await?
    page = app.get("/?name=%3Cb%3Ehi%3C%2Fb%3E").await?
    assert(page.text().contains("Hello, &lt;b&gt;hi&lt;/b&gt;!"), page.text())
"#;

const HOME: &str = r#"page GET "/" (query: HomeQuery) -> html:
    let who = if query.name.is_empty(): "world" else: query.name.clone()
    html(lang="en"):
        head:
            meta(charset="utf-8")
            title __NAME__
        body:
            main:
                h1 Hello, {who}!
                p Edit ui/home.msd and main.prvz, then run parvez run main.prvz.
"#;

const GITIGNORE: &str = ".parvez_build/\n/main\n/main-*\n*.sha256\n*.sbom.json\n";

const README: &str = r#"# __NAME__

A [Parvez](https://github.com/parvez76/project-parvez) service.

```bash
parvez test main.prvz              # tests
parvez run main.prvz               # http://localhost:8080
parvez build main.prvz             # ./main + main.sha256
parvez build main.prvz --target x86_64-unknown-linux-musl   # static ./main-x86_64-unknown-linux-musl
```
"#;
