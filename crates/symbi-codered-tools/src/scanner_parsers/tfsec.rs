//! tfsec --format json output → RawFinding.
//!
//! tfsec emits `{"results": [ {rule_id, severity, description, location:
//! {filename, start_line, end_line}, ...}, ... ]}`. Severities are lowercase.

use serde_json::Value;
use thiserror::Error;

use super::RawFinding;

#[derive(Debug, Error)]
pub enum TfsecParseError {
    #[error("missing results array")]
    MissingResults,
}

pub fn parse(raw: &Value) -> Result<Vec<RawFinding>, TfsecParseError> {
    let results = raw
        .get("results")
        .and_then(|v| v.as_array())
        .ok_or(TfsecParseError::MissingResults)?;
    let mut out = Vec::new();
    for r in results {
        let rule_id = r.get("rule_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let description = r
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let severity = r
            .get("severity")
            .and_then(|v| v.as_str())
            .map(|s| s.to_lowercase())
            .unwrap_or_else(|| "medium".into());
        let (file_path, line_start, line_end) = r
            .get("location")
            .map(|loc| {
                let file = loc
                    .get("filename")
                    .and_then(|v| v.as_str())
                    .map(|s| s.trim_start_matches('/').to_string())
                    .unwrap_or_default();
                let start = loc.get("start_line").and_then(|v| v.as_i64()).unwrap_or(0).max(0) as u32;
                let end = loc.get("end_line").and_then(|v| v.as_i64()).unwrap_or(0).max(0) as u32;
                (file, start, end)
            })
            .unwrap_or_default();
        let resolution = r
            .get("resolution")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        out.push(RawFinding {
            tool: "tfsec".into(),
            rule_id: rule_id.clone(),
            file_path,
            line_start,
            line_end,
            severity,
            confidence: "high".into(),
            cwe: None,
            owasp: None,
            title: format!("tfsec {rule_id}: {description}"),
            description: if resolution.is_empty() {
                description
            } else {
                format!("{description}\n\nResolution: {resolution}")
            },
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_terraform_finding() {
        let raw = json!({
            "results": [{
                "rule_id": "aws-s3-enable-bucket-encryption",
                "severity": "HIGH",
                "description": "Bucket does not have encryption enabled",
                "resolution": "Configure bucket encryption",
                "location": {
                    "filename": "/main.tf",
                    "start_line": 14,
                    "end_line": 18
                }
            }]
        });
        let out = parse(&raw).unwrap();
        assert_eq!(out.len(), 1);
        let f = &out[0];
        assert_eq!(f.tool, "tfsec");
        assert_eq!(f.severity, "high");
        assert_eq!(f.file_path, "main.tf");
        assert_eq!(f.line_start, 14);
        assert!(f.description.contains("Configure bucket encryption"));
    }

    #[test]
    fn empty_results_returns_empty_vec() {
        let raw = json!({"results": []});
        assert!(parse(&raw).unwrap().is_empty());
    }

    #[test]
    fn missing_results_array_errors() {
        let raw = json!({});
        assert!(parse(&raw).is_err());
    }
}
