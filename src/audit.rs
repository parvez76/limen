//! Supply-chain checks for built programs:
//! - SBOM: CycloneDX 1.5 JSON of every resolved crate (version, license, purl)
//! - Advisory gate: Cargo.lock vs the RustSec advisory database
//!   (cached clone of github.com/rustsec/advisory-db, refreshed daily;
//!   `PARVEZ_ADVISORY_DB=<dir>` uses a local copy as-is)

use anyhow::{Context, Result};
use semver::{Version, VersionReq};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

const ADVISORY_REPO: &str = "https://github.com/rustsec/advisory-db";

pub fn cache_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("PARVEZ_CACHE_DIR") {
        return PathBuf::from(d);
    }
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
        .unwrap_or_else(std::env::temp_dir);
    base.join("parvez")
}

// ---------- SBOM ----------

/// Writes a CycloneDX SBOM for the cargo project at `proj`. Returns the
/// number of components.
pub fn write_sbom(proj: &Path, app: &str, out: &Path) -> Result<usize> {
    // Only what is compiled into this binary: the host platform's dependency graph.
    let host = Command::new("rustc")
        .arg("-vV")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.lines().find_map(|l| l.strip_prefix("host: ").map(String::from)))
        .context("detecting host target (rustc -vV)")?;
    let meta = Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--offline", "--filter-platform", &host])
        .current_dir(proj)
        .output()
        .context("running cargo metadata")?;
    anyhow::ensure!(meta.status.success(), "cargo metadata failed: {}", String::from_utf8_lossy(&meta.stderr));
    let meta: Value = serde_json::from_slice(&meta.stdout)?;
    let resolved: std::collections::HashSet<&str> = meta["resolve"]["nodes"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|n| n["id"].as_str())
        .collect();
    let root = meta["resolve"]["root"].as_str().unwrap_or("");
    let mut comps: Vec<Value> = meta["packages"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|p| p["id"].as_str().is_some_and(|id| resolved.contains(id) && id != root))
        .map(|p| {
            let (name, ver) = (p["name"].as_str().unwrap_or(""), p["version"].as_str().unwrap_or(""));
            let purl = format!("pkg:cargo/{name}@{ver}");
            let mut c = json!({ "type": "library", "bom-ref": purl, "name": name, "version": ver, "purl": purl });
            if let Some(l) = p["license"].as_str() {
                c["licenses"] = json!([{ "expression": l.replace('/', " OR ") }]);
            }
            c
        })
        .collect();
    comps.sort_by(|a, b| (a["name"].as_str(), a["version"].as_str()).cmp(&(b["name"].as_str(), b["version"].as_str())));
    let n = comps.len();
    let bom = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "tools": { "components": [{ "type": "application", "name": "parvez", "version": env!("CARGO_PKG_VERSION") }] },
            "component": { "type": "application", "name": app, "bom-ref": format!("app:{app}") }
        },
        "components": comps
    });
    std::fs::write(out, serde_json::to_string_pretty(&bom)? + "\n").with_context(|| format!("writing {}", out.display()))?;
    Ok(n)
}

// ---------- advisories ----------

#[derive(Debug, Clone)]
pub struct Advisory {
    pub id: String,
    pub title: String,
    pub patched: Vec<String>,
    pub unaffected: Vec<String>,
    /// "unmaintained" / "unsound" / "notice": reported, not blocking
    pub informational: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Hit {
    pub package: String,
    pub version: String,
    pub adv: Advisory,
}

impl Hit {
    pub fn render(&self) -> String {
        let fix = if self.adv.patched.is_empty() {
            "no patched release; replace the crate".to_string()
        } else {
            format!("patched: {}", self.adv.patched.join(" | "))
        };
        format!("{} {}@{}: {} ({fix})", self.adv.id, self.package, self.version, self.adv.title)
    }
}

pub enum Db {
    /// usable database, plus a staleness warning if refresh failed
    Ready(PathBuf, Option<String>),
    Unavailable(String),
}

/// Locates (and refreshes, at most daily) the advisory database.
pub fn advisory_db() -> Db {
    if let Some(d) = std::env::var_os("PARVEZ_ADVISORY_DB") {
        return Db::Ready(PathBuf::from(d), None);
    }
    let dir = cache_dir().join("advisory-db");
    let stamp = dir.join(".parvez-fetched");
    let fresh = std::fs::metadata(&stamp)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| SystemTime::now().duration_since(t).ok())
        .is_some_and(|age| age < Duration::from_secs(24 * 3600));
    if fresh {
        return Db::Ready(dir, None);
    }
    let git = |args: &[&str], cwd: &Path| {
        Command::new("git").args(args).current_dir(cwd).output().map(|o| o.status.success()).unwrap_or(false)
    };
    let ok = if dir.join(".git").exists() {
        git(&["fetch", "--depth", "1", "--quiet", "origin", "HEAD"], &dir) && git(&["reset", "--hard", "--quiet", "FETCH_HEAD"], &dir)
    } else {
        let _ = std::fs::create_dir_all(cache_dir());
        let target = dir.to_string_lossy().to_string();
        git(&["clone", "--depth", "1", "--quiet", ADVISORY_REPO, &target], &cache_dir())
    };
    if ok {
        let _ = std::fs::write(&stamp, "");
        Db::Ready(dir, None)
    } else if dir.join("crates").exists() {
        Db::Ready(dir, Some("could not refresh the RustSec advisory database; using the cached copy".into()))
    } else {
        Db::Unavailable(format!("could not download the RustSec advisory database ({ADVISORY_REPO})"))
    }
}

fn parse_advisory(text: &str) -> Option<Advisory> {
    let start = text.find("```toml")? + "```toml".len();
    let end = start + text[start..].find("```")?;
    let t: toml::Table = text[start..end].parse().ok()?;
    let a = t.get("advisory")?.as_table()?;
    if a.contains_key("withdrawn") {
        return None;
    }
    let list = |k: &str| -> Vec<String> {
        t.get("versions")
            .and_then(|v| v.get(k))
            .and_then(|v| v.as_array())
            .map(|xs| xs.iter().filter_map(|x| x.as_str().map(String::from)).collect())
            .unwrap_or_default()
    };
    Some(Advisory {
        id: a.get("id")?.as_str()?.to_string(),
        title: a.get("title").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        patched: list("patched"),
        unaffected: list("unaffected"),
        informational: a.get("informational").and_then(|x| x.as_str()).map(String::from),
    })
}

fn affected(version: &str, adv: &Advisory) -> bool {
    let Ok(v) = Version::parse(version) else { return false };
    let matches = |reqs: &[String]| reqs.iter().any(|r| VersionReq::parse(r).is_ok_and(|req| req.matches(&v)));
    !matches(&adv.patched) && !matches(&adv.unaffected)
}

/// Returns (vulnerabilities, informational notices) for a Cargo.lock.
pub fn scan(lockfile: &Path, db: &Path) -> Result<(Vec<Hit>, Vec<Hit>)> {
    let lock: toml::Table = std::fs::read_to_string(lockfile)
        .with_context(|| format!("reading {}", lockfile.display()))?
        .parse()?;
    let (mut vulns, mut notes) = (Vec::new(), Vec::new());
    for p in lock.get("package").and_then(|p| p.as_array()).into_iter().flatten() {
        let (Some(name), Some(ver)) = (p.get("name").and_then(|x| x.as_str()), p.get("version").and_then(|x| x.as_str()))
        else {
            continue;
        };
        if !p.get("source").and_then(|s| s.as_str()).is_some_and(|s| s.starts_with("registry+")) {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(db.join("crates").join(name)) else { continue };
        for e in entries.flatten() {
            let Some(adv) = std::fs::read_to_string(e.path()).ok().and_then(|t| parse_advisory(&t)) else { continue };
            if !affected(ver, &adv) {
                continue;
            }
            let hit = Hit { package: name.into(), version: ver.into(), adv };
            if hit.adv.informational.is_some() { notes.push(hit) } else { vulns.push(hit) }
        }
    }
    vulns.sort_by(|a, b| a.adv.id.cmp(&b.adv.id));
    notes.sort_by(|a, b| a.adv.id.cmp(&b.adv.id));
    Ok((vulns, notes))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADV: &str = "```toml\n[advisory]\nid = \"RUSTSEC-2099-0001\"\npackage = \"demo\"\ntitle = \"Heap overflow in parse\"\n\n[versions]\npatched = [\">= 1.4.2, < 2.0.0\", \">= 2.1.0\"]\nunaffected = [\"< 1.0.0\"]\n```\n\n# Heap overflow\n";

    #[test]
    fn advisory_version_matching() {
        let a = parse_advisory(ADV).unwrap();
        assert_eq!(a.id, "RUSTSEC-2099-0001");
        for (v, hit) in [("0.9.0", false), ("1.0.0", true), ("1.4.1", true), ("1.4.2", false), ("2.0.5", true), ("2.1.0", false)] {
            assert_eq!(affected(v, &a), hit, "{v}");
        }
        assert!(parse_advisory(&ADV.replace("[versions]", "withdrawn = \"2099-01-02\"\n[versions]")).is_none());
    }

    #[test]
    fn scan_lockfile_against_db() {
        let dir = std::env::temp_dir().join("parvez-audit-unit");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("db/crates/demo")).unwrap();
        std::fs::create_dir_all(dir.join("db/crates/old")).unwrap();
        std::fs::write(dir.join("db/crates/demo/RUSTSEC-2099-0001.md"), ADV).unwrap();
        std::fs::write(
            dir.join("db/crates/old/RUSTSEC-2099-0002.md"),
            ADV.replace("0001", "0002").replace("title =", "informational = \"unmaintained\"\ntitle ="),
        )
        .unwrap();
        let reg = "source = \"registry+https://github.com/rust-lang/crates.io-index\"";
        std::fs::write(
            dir.join("Cargo.lock"),
            format!("version = 4\n[[package]]\nname = \"demo\"\nversion = \"1.2.0\"\n{reg}\n[[package]]\nname = \"old\"\nversion = \"1.0.0\"\n{reg}\n[[package]]\nname = \"app\"\nversion = \"1.0.0\"\n"),
        )
        .unwrap();
        let (v, n) = scan(&dir.join("Cargo.lock"), &dir.join("db")).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].render(), "RUSTSEC-2099-0001 demo@1.2.0: Heap overflow in parse (patched: >= 1.4.2, < 2.0.0 | >= 2.1.0)");
        assert_eq!(n.len(), 1);
        assert_eq!(n[0].adv.informational.as_deref(), Some("unmaintained"));
    }
}
