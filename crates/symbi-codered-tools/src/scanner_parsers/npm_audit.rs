//! `npm audit --json` output → RawFinding per advisory (one finding per
//! resolved `via[]` entry, not per package).
//!
//! Input shape (npm 9+, auditReportVersion 2):
//! ```json
//! {
//!   "auditReportVersion": 2,
//!   "vulnerabilities": {
//!     "minimist": {
//!       "name": "minimist",
//!       "severity": "high",
//!       "isDirect": true,
//!       "via": [{
//!         "source": 1179,
//!         "name": "minimist",
//!         "title": "Prototype Pollution in minimist",
//!         "url": "https://github.com/advisories/GHSA-...",
//!         "severity": "high",
//!         "cwe": ["CWE-1321"],
//!         "cvss": {"score": 7.5, "vectorString": "..."}
//!       }],
//!       "range": "<0.2.1",
//!       "fixAvailable": true
//!     }
//!   },
//!   "metadata": {"vulnerabilities": {"info":0,"low":0,"moderate":0,"high":1,"critical":0,"total":1}}
//! }
//! ```
//!
//! `via[]` can contain either objects (the advisory itself) or strings
//! (references to other vulnerable package keys, in a transitive chain).
//! Only the object entries produce a finding; the strings are walked
//! implicitly when we iterate the top-level vulnerabilities map.

use serde_json::Value;
use thiserror::Error;

use super::RawFinding;

#[derive(Debug, Error)]
pub enum NpmAuditParseError {
    #[error("missing vulnerabilities map")]
    MissingVulnerabilities,
}

pub fn parse(raw: &Value) -> Result<Vec<RawFinding>, NpmAuditParseError> {
    let vulns = raw
        .get("vulnerabilities")
        .and_then(|v| v.as_object())
        .ok_or(NpmAuditParseError::MissingVulnerabilities)?;
    let mut out = Vec::new();
    for (_pkg_key, entry) in vulns {
        let pkg_name = entry
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let pkg_range = entry
            .get("range")
            .and_then(|v| v.as_str())
            .unwrap_or("*")
            .to_string();
        let Some(via_arr) = entry.get("via").and_then(|v| v.as_array()) else {
            continue;
        };
        for via in via_arr {
            // String entries are transitive references to other vulnerable
            // pkg keys; the actual advisory lives on that target entry which
            // we'll process in its own loop iteration. Skip.
            let Some(via_obj) = via.as_object() else { continue };
            let via_name = via_obj
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or(&pkg_name)
                .to_string();
            let via_title = via_obj
                .get("title")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let via_url = via_obj
                .get("url")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let severity = normalize_severity(
                via_obj
                    .get("severity")
                    .and_then(|v| v.as_str())
                    .or_else(|| entry.get("severity").and_then(|v| v.as_str()))
                    .unwrap_or(""),
            );
            let cwe = via_obj
                .get("cwe")
                .and_then(|v| v.as_array())
                .and_then(|arr| arr.first())
                .and_then(|v| v.as_str())
                .map(str::to_string);
            // rule_id prefers the numeric advisory ID (npm's `source`) so the
            // chain_builder / dedupe layer can key on a stable identifier.
            let rule_id = via_obj
                .get("source")
                .and_then(|v| {
                    v.as_u64()
                        .map(|n| n.to_string())
                        .or_else(|| v.as_str().map(str::to_string))
                })
                .unwrap_or_else(|| via_name.clone());
            let title = if via_title.is_empty() {
                via_name.clone()
            } else {
                format!("{via_name}: {via_title}")
            };
            let description = format!("via {pkg_name}@{pkg_range} ({via_url})");
            out.push(RawFinding {
                tool: "npm-audit".into(),
                rule_id,
                file_path: "package.json".into(),
                line_start: 0,
                line_end: 0,
                severity,
                confidence: "high".into(),
                cwe,
                owasp: None,
                title,
                description,
            });
        }
    }
    Ok(out)
}

fn normalize_severity(s: &str) -> String {
    match s.to_ascii_lowercase().as_str() {
        "critical" => "critical",
        "high" => "high",
        "moderate" | "medium" => "medium",
        "low" => "low",
        "info" => "info",
        _ => "medium",
    }
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_single_via_advisory() {
        let raw = json!({
            "auditReportVersion": 2,
            "vulnerabilities": {
                "minimist": {
                    "name": "minimist",
                    "severity": "high",
                    "isDirect": true,
                    "via": [{
                        "source": 1179,
                        "name": "minimist",
                        "title": "Prototype Pollution in minimist",
                        "url": "https://github.com/advisories/GHSA-xvch-5gv4-984h",
                        "severity": "high",
                        "cwe": ["CWE-1321"],
                        "cvss": {"score": 7.5, "vectorString": "CVSS:3.1/..."}
                    }],
                    "effects": [],
                    "range": "<0.2.1",
                    "nodes": ["node_modules/minimist"],
                    "fixAvailable": true
                }
            },
            "metadata": {"vulnerabilities": {"info":0,"low":0,"moderate":0,"high":1,"critical":0,"total":1}}
        });
        let out = parse(&raw).unwrap();
        assert_eq!(out.len(), 1);
        let f = &out[0];
        assert_eq!(f.tool, "npm-audit");
        assert_eq!(f.rule_id, "1179");
        assert_eq!(f.severity, "high");
        assert_eq!(f.cwe.as_deref(), Some("CWE-1321"));
        assert_eq!(f.file_path, "package.json");
        assert_eq!(f.line_start, 0);
        assert!(f.title.starts_with("minimist:"));
        assert!(f.description.contains("minimist@<0.2.1"));
        assert!(f.description.contains("GHSA-xvch-5gv4-984h"));
    }

    #[test]
    fn skips_string_via_entries() {
        // npm sometimes records `via: ["minimist"]` to indicate a transitive
        // dependency without inlining the advisory; we skip those entries.
        let raw = json!({
            "vulnerabilities": {
                "mkdirp": {
                    "name": "mkdirp",
                    "severity": "high",
                    "via": ["minimist"],
                    "range": "0.4.0 - 0.5.1",
                    "fixAvailable": true
                }
            }
        });
        assert!(parse(&raw).unwrap().is_empty());
    }

    #[test]
    fn missing_vulnerabilities_map_errors() {
        assert!(parse(&json!({"auditReportVersion": 2})).is_err());
    }

    #[test]
    fn falls_back_to_via_name_when_source_absent() {
        let raw = json!({
            "vulnerabilities": {
                "foo": {
                    "name": "foo",
                    "severity": "moderate",
                    "via": [{
                        "name": "foo",
                        "title": "something",
                        "url": "",
                        "severity": "moderate"
                    }],
                    "range": "*"
                }
            }
        });
        let out = parse(&raw).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].rule_id, "foo");
        assert_eq!(out[0].severity, "medium");
        assert!(out[0].cwe.is_none());
    }
}
