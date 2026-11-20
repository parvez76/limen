//! `parvez lint --sarif`: security findings as SARIF 2.1.0, the format GitHub
//! code scanning, Azure DevOps, GitLab and most security dashboards ingest.
//! Each rule carries its CWE / OWASP / ASVS references and a severity score;
//! findings inside `@allow_insecure` items are exported as suppressed results
//! with the stated reason, so reviewers see what was waived and why.
use crate::security::{Finding, RULES, Report};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

const INFO_URI: &str = "https://github.com/parvez76/parvez";
const RULES_URI: &str = "https://github.com/parvez76/parvez/blob/main/SECURITY.md#rules";

/// `files` are (display path, source) as loaded; paths become repo-relative URIs.
pub fn report(report: &Report, files: &[(String, String)]) -> Value {
    let rules: Vec<Value> = RULES
        .iter()
        .map(|r| {
            let mut tags = vec!["security".to_string()];
            tags.extend(r.cwe.iter().map(|c| format!("external/cwe/cwe-{c}")));
            tags.push(format!("external/owasp/{}", r.owasp.split(' ').next().unwrap_or(r.owasp).to_lowercase()));
            tags.extend(r.asvs.iter().map(|a| format!("external/asvs/{a}")));
            json!({
                "id": r.id,
                "name": camel(r.id),
                "shortDescription": {"text": r.title},
                "fullDescription": {"text": r.description},
                "help": {
                    "text": format!("{}\n\nFix: {}\n\nReferences: {}", r.description, r.fix, r.references()),
                    "markdown": format!("{}\n\n**Fix:** {}\n\n**References:** {}", r.description, r.fix, r.references()),
                },
                "helpUri": RULES_URI,
                "defaultConfiguration": {"level": "error"},
                "properties": {"tags": tags, "precision": "high", "problem.severity": "error", "security-severity": r.severity},
            })
        })
        .collect();
    let base = repo_root();
    let result = |f: &Finding, suppression: Option<&str>| {
        let (k, line) = crate::ast::split_line(f.line);
        let uri = files.get(k).map(|x| uri_for(&x.0, base.as_deref())).unwrap_or_else(|| "unknown".into());
        let mut r = json!({
            "ruleId": f.rule,
            "ruleIndex": RULES.iter().position(|r| r.id == f.rule).unwrap_or(0),
            "level": "error",
            "message": {"text": format!("{}. Fix: {}", f.msg, f.fix)},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"},
                "region": {"startLine": line.max(1)},
            }}],
        });
        if let Some(why) = suppression {
            r["suppressions"] = json!([{"kind": "inSource", "justification": format!("@allow_insecure: {why}")}]);
        }
        r
    };
    let mut results: Vec<Value> = report.findings.iter().map(|f| result(f, None)).collect();
    results.extend(report.suppressed.iter().map(|(f, why)| result(f, Some(why))));
    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "parvez",
                "semanticVersion": env!("CARGO_PKG_VERSION"),
                "version": env!("CARGO_PKG_VERSION"),
                "informationUri": INFO_URI,
                "rules": rules,
            }},
            "results": results,
        }],
    })
}

/// `sql-injection` -> `SqlInjection` (SARIF rule names are PascalCase by convention).
fn camel(id: &str) -> String {
    id.split('-').map(|w| w[..1].to_uppercase() + &w[1..]).collect()
}

/// The enclosing git checkout (so URIs match what code scanning shows), else the cwd.
/// URIs stay relative: the report never records the build machine's absolute paths.
fn repo_root() -> Option<PathBuf> {
    let cwd = std::env::current_dir().ok()?.canonicalize().ok()?;
    Some(cwd.ancestors().find(|d| d.join(".git").exists()).map(Path::to_path_buf).unwrap_or(cwd))
}

fn uri_for(path: &str, base: Option<&Path>) -> String {
    let p = Path::new(path);
    let rel = match (p.canonicalize(), base) {
        (Ok(abs), Some(b)) => abs.strip_prefix(b).map(Path::to_path_buf).unwrap_or(abs),
        _ => p.to_path_buf(),
    };
    let s = rel.to_string_lossy().replace('\\', "/");
    encode(s.trim_start_matches("./"))
}

/// Percent-encode what a URI can't hold literally (spaces, `%`, `#`, `?`, non-ASCII).
fn encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~/:".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_and_uris() {
        assert_eq!(camel("sql-injection"), "SqlInjection");
        assert_eq!(encode("a b/c#d.prvz"), "a%20b/c%23d.prvz");
        assert_eq!(uri_for("./x/y.prvz", None), "x/y.prvz");
        let v = report(&Report { findings: vec![], allowed: vec![], suppressed: vec![], incomplete: None }, &[]);
        let rules = v["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), RULES.len());
        for r in rules {
            let sev: f64 = r["properties"]["security-severity"].as_str().unwrap().parse().unwrap();
            assert!((0.0..=10.0).contains(&sev));
            assert!(r["properties"]["tags"].as_array().unwrap().iter().any(|t| t.as_str().unwrap().starts_with("external/cwe/cwe-")));
        }
    }
}
