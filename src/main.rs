//! `parvez` — the Parvez (.prvz) compiler: transpiles to Rust, builds with cargo.

mod ast;
mod audit;
mod codegen;
mod deps;
mod diagnostics;
mod embed;
mod fuzz;
mod lexer;
mod masud;
mod mcp;
mod fmt;
mod scaffold;
mod parser;
mod security;
mod typescript;

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use std::io::Write;
use std::process::Command;

#[derive(Parser)]
#[command(name = "parvez", version, about = "Parvez: Python-dense syntax, Rust-grade binaries")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Transpile + `cargo build --release`; copies the binary (and `<binary>.sha256`) to the current directory.
    Build {
        file: PathBuf,
        /// cross-compile, e.g. x86_64-unknown-linux-musl (static) or aarch64-unknown-linux-gnu;
        /// the binary is written as `<name>-<target>`
        #[arg(long)]
        target: Option<String>,
    },
    /// Access map for review: every route, socket and page with its guards or @public reason.
    Routes {
        #[arg(default_value = "main.prvz")]
        file: PathBuf,
        /// machine-readable output
        #[arg(long)]
        json: bool,
    },
    /// Create a new project: parvez.toml, main.prvz with a route and a test, ui/, .gitignore.
    New { name: String },
    /// Format .prvz and .msd files in place (a directory is searched recursively).
    Fmt {
        #[arg(default_value = ".")]
        paths: Vec<PathBuf>,
        /// report files that would change and exit 1 instead of writing (CI)
        #[arg(long)]
        check: bool,
    },
    /// Fast type/borrow check (`cargo check`) with .prvz-mapped errors. No binary.
    Check { file: PathBuf },
    /// Run the program's `test "..."` blocks (compile errors mapped to .prvz lines).
    Test {
        file: PathBuf,
        /// only tests whose name contains this
        filter: Option<String>,
    },
    /// Run an MCP server on stdio (tools: parvez_spec, parvez_check, parvez_eject).
    Mcp,
    /// Emit the JSON models and HTTP contracts of an entry point and its imports.
    Types {
        #[arg(long, required = true)]
        ts: bool,
        #[arg(default_value = "main.prvz")]
        file: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Update dependencies to patched compatible releases; report what still needs a major upgrade.
    Heal { file: PathBuf },
    /// Build the service, start it, and fire malformed/edge-case requests at every route.
    Fuzz { file: PathBuf },
    /// Build, then execute. Arguments after `--` are passed to the program.
    Run {
        file: PathBuf,
        #[arg(last = true)]
        args: Vec<String>,
    },
    /// Print the generated Rust source (or write it with -o). Zero lock-in.
    Show {
        file: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Append `// @prvz:N` source-line comments.
        #[arg(long)]
        map: bool,
    },
}

fn main() {
    // The compiler recurses over (bounded, but possibly large) syntax trees
    // from untrusted input; a big stack keeps that from aborting the process.
    let worker = std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(real_main)
        .expect("spawn compiler thread");
    match worker.join() {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            eprintln!("parvez: error: {e:#}");
            std::process::exit(1);
        }
        Err(_) => {
            eprintln!("parvez: error: internal compiler error (please report it with the input that caused it)");
            std::process::exit(101);
        }
    }
}

fn real_main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Build { file, target } => {
            if let Some(t) = target {
                check_target(&t)?;
                TARGET.set(t).expect("target is set once");
            }
            let bin = compile(&file, Mode::Release)?.expect("release build yields a binary");
            eprintln!("parvez: built {}", bin.display());
        }
        Cmd::New { name } => scaffold::new_project(&std::env::current_dir()?, &name)?,
        Cmd::Routes { file, json } => print_routes(&file, json)?,
        Cmd::Fmt { paths, check } => {
            let mut changed = Vec::new();
            for path in &paths {
                changed.extend(fmt::run(path, check)?);
            }
            if check && !changed.is_empty() {
                for f in &changed {
                    eprintln!("parvez: would reformat {}", f.display());
                }
                std::process::exit(1);
            }
        }
        Cmd::Check { file } => {
            compile(&file, Mode::Check)?;
            eprintln!("parvez: ok {}", file.display());
        }
        Cmd::Test { file, filter } => {
            compile(&file, Mode::Test)?;
            let proj = std::env::current_dir()?.join(".parvez_build").join(bin_name(&file));
            let mut args = vec!["test".to_string(), "--quiet".into(), "--".into()];
            if let Some(f) = filter {
                args.push(test_filter(&f));
            }
            let table = std::fs::read_to_string(proj.join("prvz.map")).unwrap_or_default();
            let places: Vec<&str> = table.lines().collect();
            let mut child = Command::new("cargo")
                .args(&args)
                .current_dir(&proj)
                .stdout(std::process::Stdio::piped())
                .spawn()
                .context("running cargo test")?;
            let stdout = child.stdout.take().expect("piped stdout");
            let mut out = std::io::stdout().lock();
            for line in std::io::BufRead::lines(std::io::BufReader::new(stdout)) {
                writeln!(out, "{}", diagnostics::map_panic_location(&line?, &places))?;
            }
            drop(out);
            let status = child.wait().context("running cargo test")?;
            std::process::exit(status.code().unwrap_or(1));
        }
        Cmd::Types { file, out, .. } => {
            let prog = load_program(&file)?;
            let ts = typescript::generate(&prog)?;
            if let Some(out) = out {
                write_if_changed(&out, &ts)?;
            } else {
                print!("{ts}");
            }
        }
        Cmd::Mcp => mcp::serve()?,
        Cmd::Heal { file } => heal(&file)?,
        Cmd::Fuzz { file } => {
            let (_, prog) = parse_checked(&file)?;
            let bin = compile(&file, Mode::Release)?.expect("release build yields a binary");
            fuzz::run(&prog, &bin, &fuzz::FuzzConfig::load(&file)?)?;
        }
        Cmd::Run { file, args } => {
            let bin = compile(&file, Mode::Release)?.expect("release build yields a binary");
            let status = Command::new(&bin)
                .args(&args)
                .status()
                .with_context(|| format!("failed to execute {}", bin.display()))?;
            std::process::exit(status.code().unwrap_or(1));
        }
        Cmd::Show { file, output, map } => {
            let (_, g) = transpile(&file)?;
            let code = if map { codegen::annotate(&g) } else { g.code };
            match output {
                Some(out) => {
                    std::fs::write(&out, code).with_context(|| format!("writing {}", out.display()))?
                }
                None => print!("{code}"),
            }
        }
    }
    Ok(())
}

/// .prvz source -> (source text, Rust source + source map).
pub(crate) fn transpile(file: &Path) -> Result<(String, codegen::Generated)> {
    let (src, mut prog) = parse_checked(file)?;
    let base = file
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    for item in &mut prog.items {
        if let ast::Item::Embed { dir, files, line } = item {
            *files =
                embed::assets(base, dir).with_context(|| format!("{}:{line}: @embed_dir({dir:?})", file.display()))?;
        }
    }
    Ok((src, codegen::generate_with(&prog, &deps::service_config(file)?)))
}

/// `file:line` for an encoded line (see `ast::FILE_STRIDE`).
fn locate(files: &[(String, String)], encoded: usize) -> String {
    let (k, line) = ast::split_line(encoded);
    let name = files.get(k).map(|f| f.0.as_str()).unwrap_or("?");
    format!("{name}:{line}")
}

/// "line N: msg" (N encoded) -> "file.prvz:N: msg".
fn located(files: &[(String, String)], e: anyhow::Error) -> anyhow::Error {
    let m = e.to_string();
    match m.strip_prefix("line ").and_then(|r| r.split_once(": ")) {
        Some((n, rest)) if n.parse::<usize>().is_ok() => anyhow!("{}: {rest}", locate(files, n.parse().unwrap())),
        _ => anyhow!("{}: {m}", files.first().map(|f| f.0.as_str()).unwrap_or("?")),
    }
}

/// Reads the main file and every file it (transitively) imports:
/// `import auth.tokens` -> `<main dir>/auth/tokens.prvz`. Each file is lexed
/// with an encoded line base so errors and the source map name the file.
fn load_program(file: &Path) -> Result<ast::Program> {
    let mut files: Vec<(String, String)> = Vec::new();
    let result = load_into(file, &mut files);
    result.map_err(|e| located(&files, e))
}

fn load_into(file: &Path, files: &mut Vec<(String, String)>) -> Result<ast::Program> {
    let src = std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
    files.push((file.display().to_string(), src.clone()));
    let items = parser::parse_items(lexer::lex(&src)?)?;
    let base = file.parent().unwrap_or(Path::new("."));
    let mut modules: Vec<ast::Module> = Vec::new();
    let mut queue: std::collections::VecDeque<ast::ImportDef> = imports(&items).into();
    while let Some(imp) = queue.pop_front() {
        if modules.iter().any(|m| m.path == imp.path) {
            continue;
        }
        let rel = format!("{}.prvz", imp.path.join("/"));
        let mut path = base.join(&rel);
        let msd = path.with_extension("msd");
        if msd.exists() {
            if path.exists() {
                bail!("line {}: ambiguous module: both {rel} and .msd exist", imp.line);
            }
            path = msd;
        }
        if !path.exists() {
            bail!("line {}: `import {}`: no file {rel} next to the main file", imp.line, imp.path.join("."));
        }
        let k = files.len();
        let msrc = std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
        files.push((path.display().to_string(), msrc.clone()));
        let start = k * ast::FILE_STRIDE + 1;
        let mitems = if path.extension().is_some_and(|e| e == "msd") {
            masud::parse(&msrc, start)?
        } else {
            parser::parse_items(lexer::lex_from(&msrc, start)?)?
        };
        queue.extend(imports(&mitems));
        modules.push(ast::Module { path: imp.path, items: mitems });
    }
    let prog = ast::Program { items, modules, files: files.clone() };
    parser::validate(&prog)?;
    Ok(prog)
}

fn imports(items: &[ast::Item]) -> Vec<ast::ImportDef> {
    items.iter().filter_map(|i| if let ast::Item::Import(d) = i { Some(d.clone()) } else { None }).collect()
}

/// Read, parse (with imports) and security-lint a .prvz program.
pub(crate) fn parse_checked(file: &Path) -> Result<(String, ast::Program)> {
    if file.extension().and_then(|e| e.to_str()) != Some("prvz") {
        bail!("{}: expected a .prvz file", file.display());
    }
    let prog = load_program(file)?;
    let files = prog.files.clone();
    let report = security::lint(&prog);
    for (line, why) in &report.allowed {
        eprintln!("parvez: warning: {}: security checks disabled by @allow_insecure: {why}", locate(&files, *line));
    }
    if !report.findings.is_empty() {
        let all: Vec<String> = report
            .findings
            .iter()
            .map(|f| {
                let (k, l) = ast::split_line(f.line);
                let name = files.get(k).map(|x| x.0.as_str()).unwrap_or("?");
                security::Finding { line: l, ..f.clone() }.render(name)
            })
            .collect();
        bail!(
            "{}\n{}: {} security error(s); fix them or add @allow_insecure(\"reason\") to the fn/route",
            all.join("\n"),
            file.display(),
            report.findings.len()
        );
    }
    let has_main = prog.all_items().iter().any(|(m, i)| match i {
        ast::Item::Fn(f) => m.is_empty() && f.name == "main",
        ast::Item::Route(_) | ast::Item::Embed { .. } => true, // routes generate the server's main
        ast::Item::Test(_) => true,                            // a test-only file gets an empty main
        _ => false,
    });
    if !has_main {
        bail!("{}: no `fn main()` (or `route`) found", file.display());
    }
    Ok((files[0].1.clone(), prog))
}

/// Binary name from the file stem: `my-tool.prvz` -> `my_tool`.
fn bin_name(file: &Path) -> String {
    let stem = file.file_stem().and_then(|s| s.to_str()).unwrap_or("app");
    let mut n: String =
        stem.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect();
    if n.is_empty() || n.starts_with(|c: char| c.is_ascii_digit()) {
        n.insert_str(0, "app_");
    }
    n
}

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Mode {
    Release,
    Check,
    /// compile the test harness (cargo test --no-run)
    Test,
}

/// "rejects bad tokens" -> a fragment of the generated test fn name.
fn test_filter(f: &str) -> String {
    f.chars().map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '_' }).collect()
}

pub(crate) enum Outcome {
    /// Success; the binary path in `Release` mode.
    Built(Option<PathBuf>),
    /// rustc errors, already mapped to .prvz lines.
    Errors(Vec<String>),
}

/// CLI wrapper: prints mapped errors and fails if there are any.
fn compile(file: &Path, mode: Mode) -> Result<Option<PathBuf>> {
    match compile_at(file, mode, &std::env::current_dir()?)? {
        Outcome::Built(bin) => Ok(bin),
        Outcome::Errors(errors) => {
            for e in &errors {
                eprintln!("{e}");
            }
            let path = file.display();
            bail!("{path}: {} error(s). Generated Rust: `parvez show --map {path}`", errors.len())
        }
    }
}

/// Transpile into `<root>/.parvez_build/<name>/` and run cargo. In `Release`
/// mode the binary is copied to `<root>/<name>`.
pub(crate) fn compile_at(file: &Path, mode: Mode, root: &Path) -> Result<Outcome> {
    let (src, generated) = transpile(file)?;
    let code = &generated.code;
    let name = bin_name(file);
    let cwd = root.to_path_buf();
    let proj = cwd.join(".parvez_build").join(&name);
    std::fs::create_dir_all(proj.join("src"))?;

    let overrides = deps::load_overrides(file)?;
    let deps = deps::dependencies(&generated.deps, overrides.as_ref());
    let dev_deps = deps::dependencies(&generated.dev_deps, overrides.as_ref());
    for c in deps::unpinned(&deps).into_iter().chain(deps::unpinned(&dev_deps)) {
        eprintln!("parvez: note: crate `{c}` is not in the known list; using latest (pin it in parvez.toml)");
    }
    write_if_changed(&proj.join("Cargo.toml"), &deps::manifest(&name, deps, dev_deps))?;
    write_if_changed(&proj.join("src/main.rs"), code)?;
    if !proj.join("target").exists() {
        eprintln!("parvez: first build of `{name}`: fetching and compiling dependencies...");
    }

    let target = TARGET.get().filter(|_| mode == Mode::Release);
    let zig = target.is_some_and(|t| needs_cross_linker(t)) && which("cargo-zigbuild");
    let mut release: Vec<&str> = vec![if zig { "zigbuild" } else { "build" }, "--release", "--quiet", "--message-format=json"];
    if let Some(t) = target {
        release.extend(["--target", t.as_str()]);
    }
    let args: &[&str] = match mode {
        Mode::Release => &release,
        // --all-targets: also type-check `test` blocks and `@test_only` helpers
        Mode::Check => &["check", "--all-targets", "--quiet", "--message-format=json"],
        Mode::Test => &["test", "--no-run", "--quiet", "--message-format=json"],
    };
    let out = Command::new("cargo")
        .args(args)
        .current_dir(&proj)
        .output()
        .context("failed to run `cargo` — is the Rust toolchain installed? (https://rustup.rs)")?;
    if !out.status.success() {
        let path = file.display().to_string();
        let modules = generated.files.get(1..).unwrap_or(&[]);
        let ctx = diagnostics::Ctx { prvz_path: &path, prvz_src: &src, rust_src: code, map: &generated.map, modules };
        let errors = diagnostics::render(&String::from_utf8_lossy(&out.stdout), &ctx);
        if errors.is_empty() {
            // Not a compile error (network, toolchain, ...): show cargo's own output.
            std::io::stderr().write_all(&out.stderr)?;
            if let Some(t) = target
                && String::from_utf8_lossy(&out.stderr).contains("link")
            {
                bail!(
                    "cargo build failed for {path} (target {t}): no linker for that target. Install its cross toolchain \
                     (e.g. `sudo apt install gcc-aarch64-linux-gnu` and set CARGO_TARGET_{}_LINKER), or install \
                     `cargo-zigbuild` + zig and parvez uses it automatically",
                    t.to_uppercase().replace('-', "_")
                );
            }
            bail!("cargo build failed for {path}");
        }
        return Ok(Outcome::Errors(errors));
    }

    if mode == Mode::Test {
        // `parvez test` rewrites `panicked at src/main.rs:N:C` with this table.
        let path = file.display().to_string();
        let modules = generated.files.get(1..).unwrap_or(&[]);
        let ctx = diagnostics::Ctx { prvz_path: &path, prvz_src: &src, rust_src: code, map: &generated.map, modules };
        write_if_changed(&proj.join("prvz.map"), &diagnostics::location_table(&ctx))?;
    }
    if mode == Mode::Check || mode == Mode::Test {
        return Ok(Outcome::Built(None));
    }
    advisory_gate(file, &proj)?;
    let exe_suffix = if target.is_some_and(|t| t.contains("windows")) { ".exe" } else if target.is_some() { "" } else { std::env::consts::EXE_SUFFIX };
    let exe = format!("{name}{exe_suffix}");
    let built = match target {
        Some(t) => proj.join("target").join(t).join("release").join(&exe),
        None => proj.join("target/release").join(&exe),
    };
    let out_name = match target {
        Some(t) => format!("{name}-{t}{exe_suffix}"),
        None => exe.clone(),
    };
    let dest = cwd.join(&out_name);
    // Copy beside the target, then rename: replacing a running binary in
    // place fails ("text file busy"); a rename swaps it atomically.
    let tmp = cwd.join(format!(".{out_name}.parvez-tmp"));
    std::fs::copy(&built, &tmp).with_context(|| format!("copying binary to {}", tmp.display()))?;
    std::fs::rename(&tmp, &dest).with_context(|| format!("installing binary at {}", dest.display()))?;
    // `<binary>.sha256` in `sha256sum` format: `sha256sum -c app.sha256` verifies it
    let digest = sha256_hex(&std::fs::read(&dest)?);
    std::fs::write(cwd.join(format!("{out_name}.sha256")), format!("{digest}  {out_name}\n"))?;
    eprintln!("parvez: sha256 {digest}  {out_name}");
    let sbom = cwd.join(format!("{name}.sbom.json"));
    match audit::write_sbom(&proj, &name, &sbom) {
        Ok(n) => eprintln!("parvez: sbom {} ({n} components)", sbom.display()),
        Err(e) => eprintln!("parvez: warning: could not write SBOM: {e:#}"),
    }
    Ok(Outcome::Built(Some(dest)))
}

/// Fails the build when Cargo.lock has crates with known RustSec advisories
/// (policy: PARVEZ_AUDIT / parvez.toml `[security] audit` = deny | warn | off).
fn advisory_gate(file: &Path, proj: &Path) -> Result<()> {
    let policy = deps::audit_policy(file)?;
    if policy == "off" {
        return Ok(());
    }
    let db = match audit::advisory_db() {
        audit::Db::Unavailable(why) => {
            eprintln!("parvez: warning: dependency advisory check skipped: {why}");
            return Ok(());
        }
        audit::Db::Ready(db, stale) => {
            if let Some(w) = stale {
                eprintln!("parvez: warning: {w}");
            }
            db
        }
    };
    let compiled = audit::compiled_packages(proj)?;
    let (vulns, notes) = audit::scan_filtered(&proj.join("Cargo.lock"), &db, Some(&compiled))?;
    for n in &notes {
        eprintln!("parvez: note: {} advisory: {}", n.adv.informational.as_deref().unwrap_or("info"), n.render());
    }
    if vulns.is_empty() {
        return Ok(());
    }
    let list: Vec<String> = vulns.iter().map(|v| format!("  {}", v.render())).collect();
    let msg = format!("{} known-vulnerable dependenc{}:\n{}", vulns.len(), if vulns.len() == 1 { "y" } else { "ies" }, list.join("\n"));
    if policy == "warn" {
        eprintln!("parvez: warning: {msg}");
        return Ok(());
    }
    bail!(
        "{msg}\nrun `parvez heal {}` to move to patched versions (PARVEZ_AUDIT=warn overrides)",
        file.display()
    )
}

/// `parvez heal`: `cargo update` to the newest semver-compatible releases,
/// re-scan, re-check, and report anything that needs a breaking upgrade.
fn heal(file: &Path) -> Result<()> {
    let root = std::env::current_dir()?;
    if let Outcome::Errors(errors) = compile_at(file, Mode::Check, &root)? {
        errors.iter().for_each(|e| eprintln!("{e}"));
        bail!("{}: fix compile errors before healing", file.display());
    }
    let proj = root.join(".parvez_build").join(bin_name(file));
    let db = match audit::advisory_db() {
        audit::Db::Ready(db, stale) => {
            if let Some(w) = stale {
                eprintln!("parvez: warning: {w}");
            }
            db
        }
        audit::Db::Unavailable(why) => bail!("{why}"),
    };
    let lock = proj.join("Cargo.lock");
    let (before, _) = audit::scan_filtered(&lock, &db, Some(&audit::compiled_packages(&proj)?))?;
    let out = Command::new("cargo").args(["update"]).current_dir(&proj).output().context("running cargo update")?;
    if !out.status.success() {
        std::io::stderr().write_all(&out.stderr)?;
        bail!("cargo update failed");
    }
    let updates: Vec<String> = String::from_utf8_lossy(&out.stderr)
        .lines()
        .filter(|l| l.contains(" -> "))
        .map(|l| l.trim().to_string())
        .collect();
    let (after, _) = audit::scan_filtered(&lock, &db, Some(&audit::compiled_packages(&proj)?))?;
    if let Outcome::Errors(errors) = compile_at(file, Mode::Check, &root)? {
        errors.iter().for_each(|e| eprintln!("{e}"));
        bail!("updated dependencies no longer compile with {}; see errors above", file.display());
    }
    for u in &updates {
        eprintln!("parvez: heal: {u}");
    }
    let fixed = before.iter().filter(|b| !after.iter().any(|a| a.adv.id == b.adv.id && a.package == b.package)).count();
    eprintln!(
        "parvez: heal: {} update(s), {fixed} advisor{} fixed, {} remaining",
        updates.len(),
        if fixed == 1 { "y" } else { "ies" },
        after.len()
    );
    if after.is_empty() {
        return Ok(());
    }
    for v in &after {
        eprintln!("parvez: heal: needs a breaking upgrade: {}", v.render());
        eprintln!(
            "    pin a patched major in parvez.toml: [dependencies] {} = \"<version matching: {}>\" (if it is a transitive dependency, upgrade the crate that pulls it in)",
            v.package,
            v.adv.patched.join(" | ")
        );
    }
    bail!("{} advisor{} need manual major upgrades", after.len(), if after.len() == 1 { "y" } else { "ies" })
}

/// Avoid touching mtimes so cargo's incremental build cache stays warm.
fn write_if_changed(path: &Path, content: &str) -> Result<()> {
    if std::fs::read_to_string(path).ok().as_deref() != Some(content) {
        std::fs::write(path, content).with_context(|| format!("writing {}", path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert_eq!(bin_name(Path::new("a/my-tool.prvz")), "my_tool");
        assert_eq!(bin_name(Path::new("9x.prvz")), "app_9x");
    }

    #[test]
    fn example_transpiles() {
        let (_, g) = transpile(Path::new("examples/hello.prvz")).unwrap();
        let code = g.code;
        assert!(code.contains("fn main() -> anyhow::Result<()> {"));
        assert!(code.contains("struct User {"));
    }
}

/// `--target` for the current `parvez build` (set once from the command line).
static TARGET: std::sync::OnceLock<String> = std::sync::OnceLock::new();

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

fn which(program: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|paths| std::env::split_paths(&paths).any(|d| d.join(program).is_file()))
}

/// Host triple from `rustc -vV`.
fn host_triple() -> Option<String> {
    let out = Command::new("rustc").arg("-vV").output().ok()?;
    String::from_utf8_lossy(&out.stdout).lines().find_map(|l| l.strip_prefix("host: ").map(String::from))
}

/// A different CPU architecture (or OS) needs a cross linker; musl on the same
/// arch links with the host toolchain (Rust ships its own musl CRT).
fn needs_cross_linker(target: &str) -> bool {
    let arch = |t: &str| t.split('-').next().unwrap_or("").to_string();
    let os = |t: &str| t.split('-').nth(2).unwrap_or("").to_string();
    let linker_var = format!("CARGO_TARGET_{}_LINKER", target.to_uppercase().replace('-', "_"));
    match host_triple() {
        Some(h) => (arch(&h) != arch(target) || os(&h) != os(target)) && std::env::var_os(linker_var).is_none(),
        None => false,
    }
}

/// Fails early, with the fix, when the Rust standard library for `target` is missing.
fn check_target(target: &str) -> Result<()> {
    if !target.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.') || target.is_empty() {
        bail!("invalid target triple {target:?}");
    }
    let Ok(out) = Command::new("rustup").args(["target", "list", "--installed"]).output() else {
        return Ok(()); // no rustup: let cargo report it
    };
    let installed = String::from_utf8_lossy(&out.stdout);
    if out.status.success() && !installed.lines().any(|l| l.trim() == target) {
        bail!("the Rust standard library for {target} is not installed; run `rustup target add {target}`");
    }
    Ok(())
}

/// `parvez routes`: who may call what. Built-in endpoints are listed too, so the
/// map is the service's complete surface.
fn print_routes(file: &Path, json: bool) -> Result<()> {
    let prog = load_program(file)?;
    let mut rows: Vec<serde_json::Value> = Vec::new();
    let uses_session = prog.all_items().iter().any(|(_, i)| match i {
        ast::Item::Fn(f) => codegen_calls(&f.body, "oidc_session"),
        ast::Item::Route(r) => codegen_calls(&r.body, "oidc_session"),
        ast::Item::Impl(im) => im.methods.iter().any(|m| codegen_calls(&m.body, "oidc_session")),
        _ => false,
    });
    for (_, item) in prog.all_items() {
        if let ast::Item::Route(r) = item {
            let (fidx, line) = ast::split_line(r.line);
            let fname = prog.files.get(fidx).map(|f| f.0.clone()).unwrap_or_else(|| file.display().to_string());
            let kind = if r.page { "page" } else if r.socket.is_some() { "socket" } else { "route" };
            let access = match &r.public {
                Some(why) if why.is_empty() => "PUBLIC".to_string(),
                Some(why) => format!("PUBLIC ({why})"),
                None => format!("guard {}", r.guards.join(" -> ")),
            };
            rows.push(serde_json::json!({"method": r.method, "path": r.path, "kind": kind, "access": access,
                "guards": r.guards, "public": r.public.is_some(), "at": format!("{fname}:{line}")}));
        }
    }
    let mut builtin = vec![("GET", "/healthz", "PUBLIC (built-in health check)"), ("GET", "/readyz", "PUBLIC (built-in readiness)"),
        ("GET", "/metrics", "PUBLIC unless PARVEZ_METRICS_TOKEN is set (built-in)")];
    if uses_session {
        builtin.extend([("GET", "/auth/login", "PUBLIC (built-in sign-in)"), ("GET", "/auth/callback", "PUBLIC (built-in sign-in)"),
            ("POST", "/auth/logout", "same-origin only (built-in)"), ("POST", "/auth/backchannel-logout", "IdP-signed logout token (built-in)")]);
    }
    for (m, p, a) in builtin {
        rows.push(serde_json::json!({"method": m, "path": p, "kind": "built-in", "access": a, "guards": [], "public": a.starts_with("PUBLIC"), "at": "-"}));
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&rows)?);
        return Ok(());
    }
    let w = |k: &str| rows.iter().map(|r| r[k].as_str().unwrap_or("").len()).max().unwrap_or(0);
    let (wm, wp, wk, wa) = (w("method").max(6), w("path").max(4), w("kind").max(4), w("access").max(6));
    println!("{:wm$}  {:wp$}  {:wk$}  {:wa$}  AT", "METHOD", "PATH", "KIND", "ACCESS");
    for r in &rows {
        let g = |k: &str| r[k].as_str().unwrap_or("").to_string();
        println!("{:wm$}  {:wp$}  {:wk$}  {:wa$}  {}", g("method"), g("path"), g("kind"), g("access"), g("at"));
    }
    Ok(())
}

fn codegen_calls(b: &ast::Block, name: &str) -> bool {
    let mut found = false;
    ast::visit_exprs(b, &mut |e| {
        found |= matches!(e, ast::Expr::Call(n, ..) if n == name);
    });
    found
}
