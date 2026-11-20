//! `parvez upgrade` and `parvez doctor`: keeping an installation current and healthy.
//!
//! Upgrades download the release archive for this platform, check it against the
//! release's SHA256SUMS (and its GitHub build attestation when the `gh` CLI is
//! installed), and only then replace the running binary. Downloads go through
//! `curl`, which every supported platform has.
use anyhow::{Context, Result, bail};
use sha2::Digest;
use std::path::{Path, PathBuf};
use std::process::Command;

const REPO: &str = "parvez76/parvez";
/// The name releases before the rename (v0.16.0, v0.17.0) were attested under.
const LEGACY_REPO: &str = "parvez76/project-parvez";
/// Minimum Rust for the generated code (edition 2024, let-chains).
const MIN_RUST: (u64, u64) = (1, 88);

fn download_base() -> String {
    std::env::var("PARVEZ_DOWNLOAD_BASE").unwrap_or_else(|_| format!("https://github.com/{REPO}/releases/download"))
}

fn latest_url() -> String {
    std::env::var("PARVEZ_LATEST_URL").unwrap_or_else(|_| format!("https://github.com/{REPO}/releases/latest"))
}

/// The release target for the platform this binary was built for.
pub fn target() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Some("x86_64-unknown-linux-musl"),
        ("linux", "aarch64") => Some("aarch64-unknown-linux-musl"),
        ("macos", "aarch64") => Some("aarch64-apple-darwin"),
        // Windows on ARM runs the x64 build through its built-in emulation
        ("windows", "x86_64" | "aarch64") => Some("x86_64-pc-windows-msvc"),
        _ => None,
    }
}

/// Where curl can throw away a response body.
const NULL_DEVICE: &str = if cfg!(windows) { "NUL" } else { "/dev/null" };

fn curl(args: &[&str]) -> Result<std::process::Output> {
    let out = Command::new("curl")
        .args(["-fsSL", "--retry", "2"])
        .args(args)
        .output()
        .context("`curl` is needed to download releases")?;
    Ok(out)
}

/// The newest release tag (`/releases/latest` redirects to `/releases/tag/<tag>`).
fn latest_tag() -> Result<String> {
    let out = curl(&["-I", "-o", NULL_DEVICE, "-w", "%{url_effective}", &latest_url()])?;
    if !out.status.success() {
        bail!("could not reach GitHub to find the latest release");
    }
    let url = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let tag = url.rsplit('/').next().unwrap_or_default().to_string();
    if !valid_tag(&tag) {
        bail!("unexpected latest-release address {url:?}");
    }
    Ok(tag)
}

fn valid_tag(t: &str) -> bool {
    t.strip_prefix('v').is_some_and(|v| {
        let mut parts = v.split('.');
        let ok = (0..3).all(|_| parts.next().is_some_and(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())));
        ok && parts.next().is_none()
    })
}

fn version_of(tag: &str) -> semver::Version {
    semver::Version::parse(tag.trim_start_matches('v')).unwrap_or(semver::Version::new(0, 0, 0))
}

/// The expected SHA-256 of `archive` from a SHA256SUMS file.
pub fn expected_sum(sums: &str, archive: &str) -> Option<String> {
    sums.lines().find_map(|l| {
        let (sum, name) = l.split_once(char::is_whitespace)?;
        let name = name.trim().trim_start_matches('*');
        (name == archive && sum.len() == 64 && sum.bytes().all(|b| b.is_ascii_hexdigit())).then(|| sum.to_ascii_lowercase())
    })
}

pub fn upgrade(version: Option<String>, check: bool, force: bool) -> Result<()> {
    let current = semver::Version::parse(env!("CARGO_PKG_VERSION"))?;
    // binaries earlier Windows upgrades moved aside (in use then, usually free now)
    if let Some(dir) = std::env::current_exe().ok().and_then(|e| e.parent().map(Path::to_path_buf)) {
        for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
            if e.file_name().to_string_lossy().starts_with(".parvez.old") {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
    let Some(target) = target() else {
        bail!(
            "no prebuilt Parvez for {}/{}; update from source with `cargo install --git https://github.com/{REPO} --locked`",
            std::env::consts::OS,
            std::env::consts::ARCH
        );
    };
    let tag = match version {
        Some(v) => {
            let v = if v.starts_with('v') { v } else { format!("v{v}") };
            if !valid_tag(&v) {
                bail!("{v:?} isn't a release version (expected e.g. v0.17.0)");
            }
            v
        }
        None => latest_tag()?,
    };
    let wanted = version_of(&tag);
    if check {
        if wanted > current {
            println!("parvez {current} -> {tag} is available; run `parvez upgrade`");
        } else {
            println!("parvez {current} is up to date");
        }
        return Ok(());
    }
    if wanted == current && !force {
        eprintln!("parvez: already at {tag}");
        return Ok(());
    }
    let exe = std::env::current_exe()?.canonicalize()?;
    if exe.components().any(|c| c.as_os_str() == ".cargo") && !force {
        bail!(
            "this parvez was installed with cargo ({}); update it the same way:\n    cargo install --git https://github.com/{REPO} --tag {tag} --locked\n(or pass --force to replace it with the release binary)",
            exe.display()
        );
    }

    let tmp = tempdir()?;
    let archive = format!("parvez-{tag}-{target}.tar.gz");
    let base = download_base();
    eprintln!("parvez: downloading {tag} for {target}");
    let a = tmp.join(&archive);
    let s = tmp.join("SHA256SUMS");
    for (url, dest) in [(format!("{base}/{tag}/{archive}"), &a), (format!("{base}/{tag}/SHA256SUMS"), &s)] {
        let out = curl(&["-o", &dest.to_string_lossy(), &url])?;
        if !out.status.success() {
            bail!("download failed: {url}");
        }
    }
    let sums = std::fs::read_to_string(&s)?;
    let Some(expected) = expected_sum(&sums, &archive) else {
        bail!("{archive} is not listed in the release's SHA256SUMS");
    };
    let actual = hex(&sha2::Sha256::digest(std::fs::read(&a)?));
    if actual != expected {
        bail!("checksum mismatch for {archive} (expected {expected}, got {actual}); nothing was changed");
    }
    eprintln!("parvez: checksum OK");
    if which("gh").is_some() {
        let verify = |repo: &str| {
            Command::new("gh").args(["attestation", "verify"]).arg(&a).args(["--repo", repo]).output().is_ok_and(|o| o.status.success())
        };
        let ok = verify(REPO) || verify(LEGACY_REPO);
        if !ok {
            bail!("the GitHub build attestation for {archive} did not verify; nothing was changed");
        }
        eprintln!("parvez: build attestation OK");
    }
    let status = Command::new("tar").arg("-xzf").arg(&a).arg("-C").arg(&tmp).status().context("`tar` is needed to unpack releases")?;
    if !status.success() {
        bail!("could not unpack {archive}");
    }
    let new_bin = tmp.join(format!("parvez-{tag}-{target}")).join(format!("parvez{}", std::env::consts::EXE_SUFFIX));
    if !new_bin.is_file() {
        bail!("{archive} has no parvez binary");
    }
    // stage next to the running binary, then rename over it (atomic on one filesystem)
    let staged = exe.with_file_name(".parvez.upgrade");
    std::fs::copy(&new_bin, &staged).with_context(|| format!("writing {}", staged.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755))?;
    }
    // Windows won't overwrite a running .exe, but it will rename one: move it aside
    // under a unique name (an older leftover may still be in use)
    let old = exe.with_file_name(format!(".parvez.old-{}", std::process::id()));
    if cfg!(windows) {
        std::fs::rename(&exe, &old).with_context(|| format!("moving {} aside", exe.display()))?;
    }
    if let Err(e) = std::fs::rename(&staged, &exe) {
        if cfg!(windows) {
            let _ = std::fs::rename(&old, &exe); // put the working binary back
        }
        return Err(e).with_context(|| format!("replacing {}", exe.display()));
    }
    let _ = std::fs::remove_dir_all(&tmp);
    eprintln!("parvez: upgraded {current} -> {tag} ({})", shown(&exe));
    Ok(())
}

/// The Visual Studio installation with the C++ tools, via Microsoft's `vswhere`.
fn msvc_tools() -> Option<String> {
    let base = std::env::var_os("ProgramFiles(x86)").or_else(|| std::env::var_os("ProgramFiles"))?;
    let vswhere = PathBuf::from(base).join("Microsoft Visual Studio").join("Installer").join("vswhere.exe");
    let out = Command::new(vswhere)
        .args(["-latest", "-products", "*", "-requires", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-property", "installationPath"])
        .output()
        .ok()?;
    let p = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (out.status.success() && !p.is_empty()).then_some(p)
}

/// The package command that installs a C linker on this Linux distribution.
fn linker_hint() -> &'static str {
    let has = |t: &str| which(t).is_some();
    if has("apt-get") {
        "sudo apt-get install -y build-essential"
    } else if has("dnf") {
        "sudo dnf install -y gcc"
    } else if has("apk") {
        "sudo apk add build-base"
    } else if has("pacman") {
        "sudo pacman -S --needed base-devel"
    } else if has("zypper") {
        "sudo zypper install -y gcc"
    } else {
        "your distribution's gcc or clang package"
    }
}

/// A path for people: without Windows' `\\?\` prefix that `canonicalize` adds.
fn shown(p: &Path) -> String {
    let s = p.display().to_string();
    s.strip_prefix(r"\\?\").map(str::to_string).unwrap_or(s)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn tempdir() -> Result<PathBuf> {
    let base = std::env::temp_dir().join(format!("parvez-upgrade-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base)?;
    Ok(base)
}

fn which(tool: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    let name = format!("{tool}{}", std::env::consts::EXE_SUFFIX);
    std::env::split_paths(&path).map(|d| d.join(&name)).find(|p| p.is_file())
}

fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(cmd).args(args).output().ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// "rustc 1.100.0 (0ef1bc386 2026-11-09)" -> (1, 100)
fn rust_version(s: &str) -> Option<(u64, u64)> {
    let v = s.split_whitespace().nth(1)?;
    let mut p = v.split('.');
    Some((p.next()?.parse().ok()?, p.next()?.parse().ok()?))
}

pub fn doctor() -> Result<()> {
    let mut problems = 0;
    let ok = |m: &str| println!("  ok    {m}");
    let warn = |m: &str| println!("  warn  {m}");
    let mut fail = |m: &str| {
        problems += 1;
        println!("  FAIL  {m}");
    };
    println!("parvez doctor");
    let exe = std::env::current_exe().ok().and_then(|p| p.canonicalize().ok());
    ok(&format!(
        "parvez {} ({})",
        env!("CARGO_PKG_VERSION"),
        exe.as_deref().map(shown).unwrap_or_else(|| "?".into())
    ));
    match run("rustc", &["--version"]) {
        Some(v) => match rust_version(&v) {
            Some(rv) if rv >= MIN_RUST => ok(&v),
            _ => fail(&format!("{v}: Parvez needs Rust {}.{} or newer; run `rustup update`", MIN_RUST.0, MIN_RUST.1)),
        },
        None => fail("Rust isn't installed (Parvez builds programs with it): curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"),
    }
    match run("cargo", &["--version"]) {
        Some(v) => ok(&v),
        None => fail("cargo isn't on PATH; open a new terminal after installing Rust, or run `. \"$HOME/.cargo/env\"`"),
    }
    // rustc links with the system C toolchain, which rustup doesn't install
    let host = run("rustc", &["-vV"]).and_then(|v| v.lines().find_map(|l| l.strip_prefix("host: ").map(str::to_string)));
    if host.as_deref().is_some_and(|h| h.ends_with("windows-msvc")) {
        match msvc_tools() {
            Some(p) => ok(&format!("Visual Studio C++ build tools ({p})")),
            None => fail(
                "the Visual Studio C++ build tools (Rust's linker on Windows) aren't installed: winget install Microsoft.VisualStudio.2022.BuildTools --override \"--quiet --wait --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended\"",
            ),
        }
    } else if cfg!(target_os = "macos") {
        match run("xcode-select", &["-p"]) {
            Some(p) => ok(&format!("Xcode command line tools ({p})")),
            None => fail("the Xcode command line tools (Rust's linker) aren't installed: xcode-select --install"),
        }
    } else {
        match ["cc", "gcc", "clang"].iter().find_map(|c| which(c)) {
            Some(p) => ok(&format!("C linker ({})", p.display())),
            None => fail(&format!("no C linker (`cc`): Rust needs one to link programs. Install it with: {}", linker_hint())),
        }
    }
    match run("git", &["--version"]) {
        Some(v) => ok(&format!("{v} (dependency security audit)")),
        None => fail("git isn't installed; `parvez build` uses it to fetch the RustSec advisory database"),
    }
    let db = crate::audit::cache_dir().join("advisory-db");
    match std::fs::metadata(&db).and_then(|m| m.modified()) {
        Ok(t) => {
            let days = t.elapsed().map(|d| d.as_secs() / 86_400).unwrap_or(0);
            ok(&format!("RustSec advisory database cached ({days} day(s) old; refreshed by builds)"))
        }
        Err(_) => warn("RustSec advisory database not cached yet; the first `parvez build` downloads it"),
    }
    match run("rustup", &["target", "list", "--installed"]) {
        Some(list) => {
            let musl = format!("{}-unknown-linux-musl", std::env::consts::ARCH);
            if cfg!(target_os = "linux") && !list.lines().any(|l| l == musl) {
                warn(&format!("static Linux builds (`--target {musl}`) need: rustup target add {musl}"));
            } else {
                ok(&format!("installed targets: {}", list.lines().collect::<Vec<_>>().join(", ")));
            }
        }
        None => warn("rustup not found; cross-compiling with --target needs it"),
    }
    if let Some(dir) = exe.as_deref().and_then(Path::parent) {
        let on_path = std::env::var_os("PATH")
            .map(|p| std::env::split_paths(&p).any(|d| d.canonicalize().is_ok_and(|d| d == dir)))
            .unwrap_or(false);
        if on_path {
            ok(&format!("{} is on PATH", shown(dir)));
        } else {
            warn(&format!("{} isn't on PATH; open a new terminal or add it to your shell profile", shown(dir)));
        }
    }
    if target().is_none() {
        warn("no prebuilt releases for this platform; `parvez upgrade` won't work here (use cargo install)");
    }
    if problems > 0 {
        println!("\n{problems} problem(s) to fix before building");
        std::process::exit(1);
    }
    println!("\nready");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_sums_and_versions() {
        assert!(valid_tag("v0.17.0") && valid_tag("v1.2.30"));
        for bad in ["0.17.0", "v0.17", "v0.17.0-rc1", "v0.17.0/../x", "latest", "v.1.2"] {
            assert!(!valid_tag(bad), "{bad}");
        }
        let sums = "aa  other.tar.gz\n4b61c214e761454fb9416bda22b09d079b7b688c4ddcb50e233f266a04b7977b  parvez-v0.16.0-x86_64-unknown-linux-musl.tar.gz\n";
        assert_eq!(
            expected_sum(sums, "parvez-v0.16.0-x86_64-unknown-linux-musl.tar.gz").as_deref(),
            Some("4b61c214e761454fb9416bda22b09d079b7b688c4ddcb50e233f266a04b7977b")
        );
        assert_eq!(expected_sum(sums, "other.tar.gz"), None, "short sums are rejected");
        assert_eq!(rust_version("rustc 1.100.0 (0ef1bc386 2026-11-09)"), Some((1, 100)));
        assert!(rust_version("rustc 1.87.0 (x)").unwrap() < MIN_RUST);
    }
}
