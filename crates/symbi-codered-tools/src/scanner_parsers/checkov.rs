//! checkov JSON output → RawFinding.
//!
//! checkov can emit one of two shapes depending on which frameworks matched:
//!  - object with `results.failed_checks` (single-framework run)
//!  - array of `{check_type, results: {failed_checks: [...]}}` objects
//!    (multi-framework auto-detection run, our typical case)

use serde_json::Value;
use thiserror::Error;

use super::RawFinding;

#[derive(Debug, Error)]
pub enum CheckovParseError {
    #[error("unexpected checkov JSON shape")]
    UnexpectedShape,
}

pub fn parse(raw: &Value) -> Result<Vec<RawFinding>, CheckovParseError> {
    let mut out = Vec::new();
    match raw {
        Value::Array(arr) => {
            for fwk_result in arr {
                collect_from_framework(fwk_result, &mut out);
            }
        }
        Value::Object(_) => {
            collect_from_framework(raw, &mut out);
        }
        _ => return Err(CheckovParseError::UnexpectedShape),
    }
    Ok(out)
}

fn collect_from_framework(fwk: &Value, out: &mut Vec<RawFinding>) {
    let check_type = fwk
        .get("check_type")
        .and_then(|v| v.as_str())
        .unwrap_or("iac");
    let failed = fwk
        .get("results")
        .and_then(|r| r.get("failed_checks"))
        .and_then(|f| f.as_array());
    let Some(failed) = failed else { return };
    for c in failed {
        let check_id = c.get("check_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let check_name = c.get("check_name").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let file_path = c
            .get("file_path")
            .and_then(|v| v.as_str())
            .map(|s| s.trim_start_matches('/').to_string())
            .unwrap_or_default();
        let (line_start, line_end) = c
            .get("file_line_range")
            .and_then(|v| v.as_array())
            .map(|arr| {
                let start = arr.first().and_then(|x| x.as_i64()).unwrap_or(0).max(0) as u32;
                let end = arr.get(1).and_then(|x| x.as_i64()).unwrap_or(0).max(0) as u32;
                (start, end)
            })
            .unwrap_or((0, 0));
        let severity = c
            .get("severity")
            .and_then(|v| v.as_str())
            .map(|s| s.to_lowercase())
            .unwrap_or_else(|| "medium".into());
        let guideline = c
            .get("guideline")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        out.push(RawFinding {
            tool: "checkov".into(),
            rule_id: check_id.clone(),
            file_path,
            line_start,
            line_end,
            severity,
            confidence: "high".into(),
            cwe: None,
            owasp: None,
            title: format!("{check_type}: {check_name}"),
            description: if guideline.is_empty() {
                check_name.clone()
            } else {
                format!("{check_name}\n\nGuideline: {guideline}")
            },
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_multi_framework_array() {
        let raw = json!([
            {
                "check_type": "terraform",
                "results": {
                    "failed_checks": [{
                        "check_id": "CKV_AWS_19",
                        "check_name": "Ensure all data stored in S3 is encrypted",
                        "file_path": "/main.tf",
                        "file_line_range": [4, 11],
                        "severity": "HIGH",
                        "guideline": "https://docs.bridgecrew.io/docs/s3-19-encrypt-data"
                    }]
                }
            },
            {
                "check_type": "dockerfile",
                "results": { "failed_checks": [] }
            }
        ]);
        let out = parse(&raw).unwrap();
        assert_eq!(out.len(), 1);
        let f = &out[0];
        assert_eq!(f.tool, "checkov");
        assert_eq!(f.rule_id, "CKV_AWS_19");
        assert_eq!(f.file_path, "main.tf");
        assert_eq!(f.line_start, 4);
        assert_eq!(f.line_end, 11);
        assert_eq!(f.severity, "high");
        assert!(f.title.contains("terraform"));
        assert!(f.description.contains("Ensure all data"));
    }

    #[test]
    fn parses_single_framework_object() {
        let raw = json!({
            "check_type": "kubernetes",
            "results": {
                "failed_checks": [{
                    "check_id": "CKV_K8S_8",
                    "check_name": "Liveness Probe Should be Configured",
                    "file_path": "/deploy.yaml",
                    "file_line_range": [1, 20]
                }]
            }
        });
        let out = parse(&raw).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].rule_id, "CKV_K8S_8");
        assert_eq!(out[0].severity, "medium");
    }

    #[test]
    fn empty_failed_checks_yields_nothing() {
        let raw = json!({"check_type": "x", "results": {"failed_checks": []}});
        assert!(parse(&raw).unwrap().is_empty());
    }
}
