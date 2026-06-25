//! eslint JSON output → RawFinding for security-relevant lints.
//!
//! eslint (`--format json`) emits a top-level array, one entry per file:
//! ```json
//! [{
//!   "filePath": "/repo/src/api.ts",
//!   "messages": [{
//!     "ruleId": "security/detect-eval-with-expression",
//!     "severity": 2,
//!     "message": "eval with non-literal expression",
//!     "line": 42, "column": 7,
//!     "endLine": 42, "endColumn": 30
//!   }],
//!   "errorCount": 1,
//!   "warningCount": 0
//! }]
//! ```
//!
//! severity is the eslint numeric level: 1=warn (Medium), 2=error (High).
//! CWE comes from a hand-curated map of the security / no-unsanitized rule
//! IDs we ship in the typescript-scanner sidecar config; everything else
//! gets `cwe: None` (callers can decide whether to keep uncategorized lints).

use serde_json::Value;
use thiserror::Error;

use super::RawFinding;

#[derive(Debug, Error)]
pub enum EslintParseError {
    #[error("input must be a JSON array of per-file result objects")]
    BadShape,
}

pub fn parse(raw: &Value) -> Result<Vec<RawFinding>, EslintParseError> {
    let files = raw.as_array().ok_or(EslintParseError::BadShape)?;
    let mut out = Vec::new();
    for file in files {
        let raw_path = file
            .get("filePath")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        // eslint runs inside the sidecar with /repo as the scan root; strip
        // that prefix so file_path stays repo-relative.
        let file_path = raw_path
            .strip_prefix("/repo/")
            .unwrap_or(raw_path)
            .to_string();
        let Some(messages) = file.get("messages").and_then(|v| v.as_array()) else {
            continue;
        };
        for msg in messages {
            let rule_id = msg
                .get("ruleId")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            // Messages without a ruleId are parse errors — skip; the orchestrator
            // surfaces those via stderr instead.
            if rule_id.is_empty() {
                continue;
            }
            let severity_num = msg.get("severity").and_then(|v| v.as_u64()).unwrap_or(1);
            let severity = match severity_num {
                2 => "high",
                _ => "medium",
            }
            .to_string();
            let title = msg
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or(&rule_id)
                .to_string();
            let line_start = u32::try_from(
                msg.get("line").and_then(|v| v.as_u64()).unwrap_or(0),
            )
            .unwrap_or(0);
            let line_end = u32::try_from(
                msg.get("endLine")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(u64::from(line_start)),
            )
            .unwrap_or(line_start);
            out.push(RawFinding {
                tool: "eslint".into(),
                rule_id: rule_id.clone(),
                file_path: file_path.clone(),
                line_start,
                line_end,
                severity,
                confidence: "medium".into(),
                cwe: cwe_for(&rule_id).map(str::to_string),
                owasp: None,
                title,
                description: String::new(),
            });
        }
    }
    Ok(out)
}

fn cwe_for(rule_id: &str) -> Option<&'static str> {
    match rule_id {
        "security/detect-eval-with-expression" => Some("CWE-95"),
        "security/detect-non-literal-fs-filename" => Some("CWE-22"),
        "security/detect-non-literal-require" => Some("CWE-95"),
        "security/detect-object-injection" => Some("CWE-471"),
        "security/detect-possible-timing-attacks" => Some("CWE-208"),
        "security/detect-pseudoRandomBytes" => Some("CWE-338"),
        "security/detect-unsafe-regex" => Some("CWE-1333"),
        "security/detect-buffer-noassert" => Some("CWE-120"),
        "security/detect-child-process" => Some("CWE-78"),
        "security/detect-disable-mustache-escape" => Some("CWE-79"),
        "security/detect-no-csrf-before-method-override" => Some("CWE-352"),
        "security/detect-non-literal-regexp" => Some("CWE-1333"),
        "no-unsanitized/method" => Some("CWE-79"),
        "no-unsanitized/property" => Some("CWE-79"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_eval_with_expression_to_cwe_95_high() {
        let raw = json!([{
            "filePath": "/repo/src/api.ts",
            "messages": [{
                "ruleId": "security/detect-eval-with-expression",
                "severity": 2,
                "message": "eval with non-literal expression",
                "line": 42,
                "column": 7,
                "endLine": 42,
                "endColumn": 30,
                "nodeType": "CallExpression"
            }],
            "errorCount": 1,
            "warningCount": 0,
            "fixableErrorCount": 0,
            "fixableWarningCount": 0
        }]);
        let out = parse(&raw).unwrap();
        assert_eq!(out.len(), 1);
        let f = &out[0];
        assert_eq!(f.tool, "eslint");
        assert_eq!(f.rule_id, "security/detect-eval-with-expression");
        assert_eq!(f.cwe.as_deref(), Some("CWE-95"));
        assert_eq!(f.severity, "high");
        // /repo/ prefix stripped → repo-relative path.
        assert_eq!(f.file_path, "src/api.ts");
        assert_eq!(f.line_start, 42);
        assert_eq!(f.line_end, 42);
        assert_eq!(f.title, "eval with non-literal expression");
    }

    #[test]
    fn warning_severity_maps_to_medium() {
        let raw = json!([{
            "filePath": "/repo/src/x.ts",
            "messages": [{
                "ruleId": "security/detect-object-injection",
                "severity": 1,
                "message": "variable bracket access",
                "line": 7,
                "column": 1
            }]
        }]);
        let out = parse(&raw).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity, "medium");
        assert_eq!(out[0].cwe.as_deref(), Some("CWE-471"));
        // endLine missing → falls back to line.
        assert_eq!(out[0].line_end, 7);
    }

    #[test]
    fn skips_messages_without_rule_id() {
        let raw = json!([{
            "filePath": "/repo/src/bad.ts",
            "messages": [{"severity": 2, "message": "parse error", "line": 1, "fatal": true}]
        }]);
        assert!(parse(&raw).unwrap().is_empty());
    }

    #[test]
    fn unmapped_rule_emits_finding_with_no_cwe() {
        let raw = json!([{
            "filePath": "/repo/src/x.ts",
            "messages": [{
                "ruleId": "@typescript-eslint/no-explicit-any",
                "severity": 1,
                "message": "any",
                "line": 1
            }]
        }]);
        let out = parse(&raw).unwrap();
        assert_eq!(out.len(), 1);
        assert!(out[0].cwe.is_none());
    }

    #[test]
    fn non_array_input_errors() {
        assert!(parse(&json!({})).is_err());
    }
}
