//! Semgrep JSON output → RawFinding.

use serde_json::Value;
use thiserror::Error;

use super::RawFinding;

#[derive(Debug, Error)]
pub enum SemgrepParseError {
    #[error("missing results array")]
    MissingResults,
    #[error("entry shape: {0}")]
    Shape(String),
}

pub fn parse(raw: &Value) -> Result<Vec<RawFinding>, SemgrepParseError> {
    let results = raw
        .get("results")
        .and_then(|v| v.as_array())
        .ok_or(SemgrepParseError::MissingResults)?;
    let mut out = Vec::new();
    for r in results {
        let path = r.get("path").and_then(|v| v.as_str())
            .ok_or_else(|| SemgrepParseError::Shape("missing path".into()))?
            .to_string();
        let check_id = r.get("check_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let start_line = r.get("start").and_then(|v| v.get("line")).and_then(|v| v.as_u64())
            .unwrap_or(0);
        let end_line = r.get("end").and_then(|v| v.get("line")).and_then(|v| v.as_u64())
            .unwrap_or(start_line);
        let start_line_u32 = u32::try_from(start_line).unwrap_or(0);
        let end_line_u32 = u32::try_from(end_line).unwrap_or(start_line_u32);
        let extra = r.get("extra").unwrap_or(&Value::Null);
        let severity_raw = extra.get("severity").and_then(|v| v.as_str()).unwrap_or("");
        let severity = normalize_severity(severity_raw);
        let message = extra.get("message").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let cwe = extra
            .get("metadata")
            .and_then(|v| v.get("cwe"))
            .and_then(|v| v.as_array())
            .and_then(|arr| arr.first())
            .and_then(|v| v.as_str())
            .and_then(|s| s.split(':').next().map(str::to_string));
        let owasp = extra
            .get("metadata")
            .and_then(|v| v.get("owasp"))
            .and_then(|v| v.as_array())
            .and_then(|arr| arr.first())
            .and_then(|v| v.as_str())
            .map(str::to_string);
        out.push(RawFinding {
            tool: "semgrep".into(),
            rule_id: check_id.clone(),
            file_path: path,
            line_start: start_line_u32,
            line_end: end_line_u32,
            severity,
            confidence: "medium".into(),
            cwe,
            owasp,
            title: check_id,
            description: message,
        });
    }
    Ok(out)
}

fn normalize_severity(s: &str) -> String {
    match s.to_ascii_uppercase().as_str() {
        "ERROR" => "high",
        "WARNING" => "medium",
        "INFO" => "low",
        _ => "low",
    }.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_single_finding_with_cwe() {
        let raw = json!({
            "results": [{
                "check_id": "python.flask.security.injection.sql-injection",
                "path": "app/routes/users.py",
                "start": {"line": 12, "col": 4},
                "end":   {"line": 12, "col": 70},
                "extra": {
                    "severity": "ERROR",
                    "message": "Possible SQL injection via interpolated string",
                    "metadata": {
                        "cwe": ["CWE-89: SQL Injection"],
                        "owasp": ["A03:2021 - Injection"]
                    }
                }
            }],
            "errors": []
        });
        let out = parse(&raw).unwrap();
        assert_eq!(out.len(), 1);
        let f = &out[0];
        assert_eq!(f.tool, "semgrep");
        assert_eq!(f.file_path, "app/routes/users.py");
        assert_eq!(f.line_start, 12);
        assert_eq!(f.severity, "high");
        assert_eq!(f.cwe.as_deref(), Some("CWE-89"));
        assert!(f.owasp.as_deref().unwrap().contains("A03:2021"));
    }

    #[test]
    fn parses_empty_results_to_empty_vec() {
        let raw = json!({"results": [], "errors": []});
        let out = parse(&raw).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn missing_results_errors() {
        let raw = json!({"errors": []});
        assert!(parse(&raw).is_err());
    }

    #[test]
    fn normalizes_warning_to_medium() {
        let raw = json!({
            "results": [{
                "check_id": "x",
                "path": "x.py",
                "start": {"line": 1, "col": 1},
                "end":   {"line": 1, "col": 1},
                "extra": {"severity": "WARNING", "message": ""}
            }]
        });
        assert_eq!(parse(&raw).unwrap()[0].severity, "medium");
    }
}
