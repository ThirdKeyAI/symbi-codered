//! pip-audit JSON output → RawFinding (one per vulnerability per package).

use serde_json::Value;
use thiserror::Error;

use super::RawFinding;

#[derive(Debug, Error)]
pub enum PipAuditParseError {
    #[error("missing dependencies array")]
    MissingDependencies,
}

pub fn parse(raw: &Value) -> Result<Vec<RawFinding>, PipAuditParseError> {
    let deps = raw
        .get("dependencies")
        .and_then(|v| v.as_array())
        .ok_or(PipAuditParseError::MissingDependencies)?;
    let mut out = Vec::new();
    for d in deps {
        let name = d.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let version = d.get("version").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let Some(vulns) = d.get("vulns").and_then(|v| v.as_array()) else { continue; };
        for v in vulns {
            let id = v.get("id").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let cve = v.get("aliases").and_then(|x| x.as_array())
                .and_then(|arr| arr.iter().filter_map(|a| a.as_str()).find(|s| s.starts_with("CVE-")))
                .map(str::to_string);
            let fix_versions = v.get("fix_versions").and_then(|x| x.as_array())
                .map(|arr| arr.iter().filter_map(|s| s.as_str()).collect::<Vec<_>>().join(", "))
                .unwrap_or_default();
            let description = v.get("description").and_then(|x| x.as_str()).unwrap_or("").to_string();
            out.push(RawFinding {
                tool: "pip-audit".into(),
                rule_id: id.clone(),
                file_path: "requirements.txt".into(),
                line_start: 0,
                line_end: 0,
                severity: "high".into(),
                confidence: "high".into(),
                cwe: None,
                owasp: cve,
                title: format!("{name} {version}: {id}"),
                description: format!("{description}\nFix versions: {fix_versions}"),
            });
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_single_vuln_per_dep() {
        let raw = json!({
            "dependencies": [{
                "name": "flask",
                "version": "1.0.0",
                "vulns": [{
                    "id": "GHSA-m2qf-hxjv-5gpq",
                    "aliases": ["CVE-2018-1000656"],
                    "description": "Flask before 0.12.3 has open redirect vulnerability",
                    "fix_versions": ["0.12.3"]
                }]
            }]
        });
        let out = parse(&raw).unwrap();
        assert_eq!(out.len(), 1);
        let f = &out[0];
        assert_eq!(f.tool, "pip-audit");
        assert_eq!(f.rule_id, "GHSA-m2qf-hxjv-5gpq");
        assert_eq!(f.severity, "high");
        assert_eq!(f.owasp.as_deref(), Some("CVE-2018-1000656"));
        assert!(f.description.contains("0.12.3"));
    }

    #[test]
    fn ignores_deps_without_vulns() {
        let raw = json!({
            "dependencies": [
                { "name": "clean", "version": "1.0", "vulns": [] }
            ]
        });
        assert!(parse(&raw).unwrap().is_empty());
    }
}
