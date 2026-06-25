//! trivy fs --format json output → RawFinding.
//!
//! trivy emits `{"Results": [{"Target": ..., "Vulnerabilities": [...],
//! "Misconfigurations": [...], "Secrets": [...]}]}`. Each of the three
//! finding classes has a slightly different shape; we normalize them all
//! to RawFinding.

use serde_json::Value;
use thiserror::Error;

use super::RawFinding;

#[derive(Debug, Error)]
pub enum TrivyParseError {
    #[error("missing Results array")]
    MissingResults,
}

pub fn parse(raw: &Value) -> Result<Vec<RawFinding>, TrivyParseError> {
    let results = raw
        .get("Results")
        .and_then(|v| v.as_array())
        .ok_or(TrivyParseError::MissingResults)?;
    let mut out = Vec::new();
    for r in results {
        let target = r.get("Target").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if let Some(vulns) = r.get("Vulnerabilities").and_then(|v| v.as_array()) {
            for v in vulns {
                out.push(vuln_finding(v, &target));
            }
        }
        if let Some(misc) = r.get("Misconfigurations").and_then(|v| v.as_array()) {
            for m in misc {
                out.push(misconfig_finding(m, &target));
            }
        }
        if let Some(secs) = r.get("Secrets").and_then(|v| v.as_array()) {
            for s in secs {
                out.push(secret_finding(s, &target));
            }
        }
    }
    Ok(out)
}

fn vuln_finding(v: &Value, target: &str) -> RawFinding {
    let id = v.get("VulnerabilityID").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let pkg = v.get("PkgName").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let installed = v.get("InstalledVersion").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let fixed = v.get("FixedVersion").and_then(|x| x.as_str()).unwrap_or("(none)").to_string();
    let title = v.get("Title").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let severity = v.get("Severity").and_then(|x| x.as_str()).map(|s| s.to_lowercase()).unwrap_or_else(|| "medium".into());
    let description = v.get("Description").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let cwes = v
        .get("CweIDs")
        .and_then(|x| x.as_array())
        .and_then(|arr| arr.iter().filter_map(|c| c.as_str()).next())
        .map(str::to_string);
    RawFinding {
        tool: "trivy".into(),
        rule_id: id.clone(),
        file_path: target.into(),
        line_start: 0,
        line_end: 0,
        severity,
        confidence: "high".into(),
        cwe: cwes,
        owasp: Some(id.clone()),
        title: if title.is_empty() {
            format!("trivy {id} ({pkg} {installed})")
        } else {
            format!("{id}: {title}")
        },
        description: format!(
            "Package: {pkg} {installed}\nFix: {fixed}\n\n{description}"
        ),
    }
}

fn misconfig_finding(m: &Value, target: &str) -> RawFinding {
    let id = m.get("ID").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let title = m.get("Title").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let severity = m.get("Severity").and_then(|x| x.as_str()).map(|s| s.to_lowercase()).unwrap_or_else(|| "medium".into());
    let message = m.get("Message").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let resolution = m.get("Resolution").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let (line_start, line_end) = m
        .get("CauseMetadata")
        .map(|cm| {
            let s = cm.get("StartLine").and_then(|x| x.as_i64()).unwrap_or(0).max(0) as u32;
            let e = cm.get("EndLine").and_then(|x| x.as_i64()).unwrap_or(0).max(0) as u32;
            (s, e)
        })
        .unwrap_or((0, 0));
    RawFinding {
        tool: "trivy".into(),
        rule_id: id.clone(),
        file_path: target.into(),
        line_start,
        line_end,
        severity,
        confidence: "high".into(),
        cwe: None,
        owasp: None,
        title: format!("{id}: {title}"),
        description: if resolution.is_empty() { message } else { format!("{message}\n\nResolution: {resolution}") },
    }
}

fn secret_finding(s: &Value, target: &str) -> RawFinding {
    let category = s.get("Category").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let title = s.get("Title").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let rule_id = s.get("RuleID").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let severity = s.get("Severity").and_then(|x| x.as_str()).map(|s| s.to_lowercase()).unwrap_or_else(|| "critical".into());
    let line_start = s.get("StartLine").and_then(|x| x.as_i64()).unwrap_or(0).max(0) as u32;
    let line_end = s.get("EndLine").and_then(|x| x.as_i64()).unwrap_or(0).max(0) as u32;
    let match_text = s.get("Match").and_then(|x| x.as_str()).unwrap_or("");
    RawFinding {
        tool: "trivy".into(),
        rule_id: rule_id.clone(),
        file_path: target.into(),
        line_start,
        line_end,
        severity,
        confidence: "high".into(),
        cwe: Some("CWE-798".into()),
        owasp: None,
        title: format!("Secret leak ({category}): {title}"),
        description: format!("Rule: {rule_id}\nMatch (redacted): {match_text}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_vulnerability() {
        let raw = json!({
            "Results": [{
                "Target": "go.sum",
                "Vulnerabilities": [{
                    "VulnerabilityID": "CVE-2023-12345",
                    "PkgName": "golang.org/x/net",
                    "InstalledVersion": "0.7.0",
                    "FixedVersion": "0.17.0",
                    "Title": "HTTP/2 rapid reset",
                    "Severity": "HIGH",
                    "Description": "DoS via rapid stream creation",
                    "CweIDs": ["CWE-400"]
                }]
            }]
        });
        let out = parse(&raw).unwrap();
        assert_eq!(out.len(), 1);
        let f = &out[0];
        assert_eq!(f.severity, "high");
        assert_eq!(f.cwe.as_deref(), Some("CWE-400"));
        assert!(f.description.contains("0.17.0"));
    }

    #[test]
    fn parses_misconfiguration() {
        let raw = json!({
            "Results": [{
                "Target": "Dockerfile",
                "Misconfigurations": [{
                    "ID": "DS002",
                    "Title": "Image user should not be 'root'",
                    "Severity": "HIGH",
                    "Message": "Specify USER directive",
                    "CauseMetadata": {"StartLine": 1, "EndLine": 1}
                }]
            }]
        });
        let out = parse(&raw).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].rule_id, "DS002");
        assert_eq!(out[0].severity, "high");
        assert_eq!(out[0].line_start, 1);
    }

    #[test]
    fn parses_secret() {
        let raw = json!({
            "Results": [{
                "Target": ".env",
                "Secrets": [{
                    "Category": "AWS",
                    "Title": "AWS Access Key ID",
                    "RuleID": "aws-access-key-id",
                    "Severity": "CRITICAL",
                    "StartLine": 3,
                    "EndLine": 3,
                    "Match": "AKIA****"
                }]
            }]
        });
        let out = parse(&raw).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity, "critical");
        assert_eq!(out[0].cwe.as_deref(), Some("CWE-798"));
        assert_eq!(out[0].line_start, 3);
    }

    #[test]
    fn empty_results_yields_empty_vec() {
        let raw = json!({"Results": []});
        assert!(parse(&raw).unwrap().is_empty());
    }
}
