//! `parvez` — the Parvez (.prvz) compiler: transpiles to Rust, builds with cargo.

mod ast;
mod codegen;
mod deps;
mod diagnostics;
mod lexer;
mod mcp;
mod parser;

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
    let has_main = prog.items.iter().any(|i| match i {
        ast::Item::Fn(f) => f.name == "main",
        ast::Item::Route(_) => true, // routes generate the server's main
        _ => false,
    });
    if !has_main {
        bail!("{}: no `fn main()` (or `route`) found", file.display());
    }
    Ok((src, codegen::generate_mapped(&prog)))
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
    let exe = format!("{name}{}", std::env::consts::EXE_SUFFIX);
    let dest = cwd.join(&exe);
    std::fs::copy(proj.join("target/release").join(&exe), &dest)
        .with_context(|| format!("copying binary to {}", dest.display()))?;
    Ok(Outcome::Built(Some(dest)))
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
