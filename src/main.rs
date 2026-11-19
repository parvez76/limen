//! `parvez` — the Parvez (.prvz) compiler: transpiles to Rust, builds with cargo.

mod ast;
mod audit;
mod codegen;
mod deps;
mod fuzz;
mod diagnostics;
mod lexer;
mod mcp;
mod parser;
mod security;

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
    /// Transpile + `cargo build --release`; copies the binary to the current directory.
    Build { file: PathBuf },
    /// Fast type/borrow check (`cargo check`) with .prvz-mapped errors. No binary.
    Check { file: PathBuf },
    /// Run an MCP server on stdio (tools: parvez_spec, parvez_check, parvez_eject).
    Mcp,
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
    if let Err(e) = real_main() {
        eprintln!("parvez: error: {e:#}");
        std::process::exit(1);
    }
}

fn real_main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Build { file } => {
            let bin = compile(&file, Mode::Release)?.expect("release build yields a binary");
            eprintln!("parvez: built {}", bin.display());
        }
        Cmd::Check { file } => {
            compile(&file, Mode::Check)?;
            eprintln!("parvez: ok {}", file.display());
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
    let (src, prog) = parse_checked(file)?;
    Ok((src, codegen::generate_with(&prog, &deps::service_config(file)?)))
}

/// Read, parse and security-lint a .prvz file.
pub(crate) fn parse_checked(file: &Path) -> Result<(String, ast::Program)> {
    if file.extension().and_then(|e| e.to_str()) != Some("prvz") {
        bail!("{}: expected a .prvz file", file.display());
    }
    let src = std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
    // "line N: msg" -> "file.prvz:N: msg"
    let located = |e: anyhow::Error| {
        let m = e.to_string();
        match m.strip_prefix("line ").and_then(|r| r.split_once(": ")) {
            Some((n, rest)) => anyhow!("{}:{n}: {rest}", file.display()),
            None => anyhow!("{}: {m}", file.display()),
        }
    };
    let tokens = lexer::lex(&src).map_err(located)?;
    let prog = parser::parse(tokens).map_err(located)?;
    let report = security::lint(&prog);
    for (line, why) in &report.allowed {
        eprintln!("parvez: warning: {}:{line}: security checks disabled by @allow_insecure: {why}", file.display());
    }
    if !report.findings.is_empty() {
        let path = file.display().to_string();
        let all: Vec<String> = report.findings.iter().map(|f| f.render(&path)).collect();
        bail!(
            "{}\n{path}: {} security error(s); fix them or add @allow_insecure(\"reason\") to the fn/route",
            all.join("\n"),
            report.findings.len()
        );
    }
    let has_main = prog.items.iter().any(|i| match i {
        ast::Item::Fn(f) => f.name == "main",
        ast::Item::Route(_) => true, // routes generate the server's main
        _ => false,
    });
    if !has_main {
        bail!("{}: no `fn main()` (or `route`) found", file.display());
    }
    Ok((src, prog))
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

    let deps = deps::dependencies(&generated.deps, deps::load_overrides(file)?.as_ref());
    for c in deps::unpinned(&deps) {
        eprintln!("parvez: note: crate `{c}` is not in the known list; using latest (pin it in parvez.toml)");
    }
    write_if_changed(&proj.join("Cargo.toml"), &deps::manifest(&name, deps))?;
    write_if_changed(&proj.join("src/main.rs"), code)?;
    if !proj.join("target").exists() {
        eprintln!("parvez: first build of `{name}`: fetching and compiling dependencies...");
    }

    let args: &[&str] = match mode {
        Mode::Release => &["build", "--release", "--quiet", "--message-format=json"],
        Mode::Check => &["check", "--quiet", "--message-format=json"],
    };
    let out = Command::new("cargo")
        .args(args)
        .current_dir(&proj)
        .output()
        .context("failed to run `cargo` — is the Rust toolchain installed? (https://rustup.rs)")?;
    if !out.status.success() {
        let path = file.display().to_string();
        let ctx = diagnostics::Ctx { prvz_path: &path, prvz_src: &src, rust_src: code, map: &generated.map };
        let errors = diagnostics::render(&String::from_utf8_lossy(&out.stdout), &ctx);
        if errors.is_empty() {
            // Not a compile error (network, toolchain, ...): show cargo's own output.
            std::io::stderr().write_all(&out.stderr)?;
            bail!("cargo build failed for {path}");
        }
        return Ok(Outcome::Errors(errors));
    }

    if mode == Mode::Check {
        return Ok(Outcome::Built(None));
    }
    advisory_gate(file, &proj)?;
    let exe = format!("{name}{}", std::env::consts::EXE_SUFFIX);
    let dest = cwd.join(&exe);
    // Copy beside the target, then rename: replacing a running binary in
    // place fails ("text file busy"); a rename swaps it atomically.
    let tmp = cwd.join(format!(".{exe}.parvez-tmp"));
    std::fs::copy(proj.join("target/release").join(&exe), &tmp)
        .with_context(|| format!("copying binary to {}", tmp.display()))?;
    std::fs::rename(&tmp, &dest).with_context(|| format!("installing binary at {}", dest.display()))?;
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
