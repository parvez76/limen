//! `parvez` — the Parvez (.prvz) compiler: transpiles to Rust, builds with cargo.

mod ast;
mod codegen;
mod lexer;
mod parser;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
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
            let bin = build(&file)?;
            eprintln!("parvez: built {}", bin.display());
        }
        Cmd::Run { file, args } => {
            let bin = build(&file)?;
            let status = Command::new(&bin)
                .args(&args)
                .status()
                .with_context(|| format!("failed to execute {}", bin.display()))?;
            std::process::exit(status.code().unwrap_or(1));
        }
        Cmd::Show { file, output } => {
            let code = transpile(&file)?;
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

/// .prvz source -> Rust source.
fn transpile(file: &Path) -> Result<String> {
    if file.extension().and_then(|e| e.to_str()) != Some("prvz") {
        bail!("{}: expected a .prvz file", file.display());
    }
    let src = std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
    let tokens = lexer::lex(&src).with_context(|| file.display().to_string())?;
    let prog = parser::parse(tokens).with_context(|| file.display().to_string())?;
    if !prog.items.iter().any(|i| matches!(i, ast::Item::Fn(f) if f.name == "main")) {
        bail!("{}: no `fn main()` found", file.display());
    }
    Ok(codegen::generate(&prog))
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

/// Transpile into `.parvez_build/<name>/`, cargo-build it, copy the binary to `./<name>`.
fn build(file: &Path) -> Result<PathBuf> {
    let code = transpile(file)?;
    let name = bin_name(file);
    let cwd = std::env::current_dir()?;
    let proj = cwd.join(".parvez_build").join(&name);
    std::fs::create_dir_all(proj.join("src"))?;

    let manifest = format!(
        r#"[package]
name = "prvz-{name}"
version = "0.1.0"
edition = "2024"

[[bin]]
name = "{name}"
path = "src/main.rs"

[dependencies]
anyhow = "1"

[profile.release]
strip = true

# Standalone: never join a parent workspace.
[workspace]
"#
    );
    write_if_changed(&proj.join("Cargo.toml"), &manifest)?;
    write_if_changed(&proj.join("src/main.rs"), &code)?;

    let status = Command::new("cargo")
        .args(["build", "--release", "--quiet"])
        .current_dir(&proj)
        .status()
        .context("failed to run `cargo` — is the Rust toolchain installed? (https://rustup.rs)")?;
    if !status.success() {
        bail!(
            "rustc rejected the generated code (errors above refer to {}). \
             Run `parvez show {}` to inspect it.",
            proj.join("src/main.rs").display(),
            file.display()
        );
    }

    let exe = format!("{name}{}", std::env::consts::EXE_SUFFIX);
    let dest = cwd.join(&exe);
    std::fs::copy(proj.join("target/release").join(&exe), &dest)
        .with_context(|| format!("copying binary to {}", dest.display()))?;
    Ok(dest)
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
        let code = transpile(Path::new("examples/hello.prvz")).unwrap();
        assert!(code.contains("fn main() -> anyhow::Result<()> {"));
        assert!(code.contains("struct User {"));
    }
}
