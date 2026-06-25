//! Progpilot JSON output → RawFinding (one per vulnerability).
//!
//! Progpilot prints a JSON array to stdout when run as `php progpilot.phar
//! <dir>` (no `--configuration` needed). Each element shape (progpilot 1.x):
//! ```json
//! [{
//!   "sink_name": "mysqli_query",
//!   "sink_file": "/repo/index.php",
//!   "sink_line": 7,
//!   "vuln_name": "sql_injection",
//!   "vuln_cwe": "CWE_89",
//!   "vuln_id": "abc123",
//!   "source_name": ["$_GET"],
//!   "source_line": [4],
//!   "source_file": "/repo/index.php"
//! }]
//! ```
//! Progpilot does not emit a severity; taint-style findings are treated as
//! High with Medium confidence (a static taint flow, not a runtime proof).

use serde_json::Value;
use thiserror::Error;

use super::RawFinding;

#[derive(Debug, Error)]
pub enum ProgpilotParseError {
    #[error("expected a JSON array of results")]
    NotAnArray,
}

/// Normalize progpilot's CWE form (`CWE_89`, `CWE-89`, `89`) to `CWE-89`.
/// Returns `None` when no digits are present.
fn normalize_cwe(raw: &str) -> Option<String> {
    let digits: String = raw.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        None
    } else {
        Some(format!("CWE-{digits}"))
    }
}

pub fn parse(raw: &Value) -> Result<Vec<RawFinding>, ProgpilotParseError> {
    let items = raw.as_array().ok_or(ProgpilotParseError::NotAnArray)?;
    let mut out = Vec::new();
    for item in items {
        let sink_name = item.get("sink_name").and_then(|v| v.as_str()).unwrap_or("");
        // sink_file is the in-container absolute path (e.g. /repo/index.php);
        // strip the bind-mount prefix so findings are repo-relative, matching
        // the other sidecar parsers (gosec, eslint, clippy, ...).
        let raw_path = item.get("sink_file").and_then(|v| v.as_str()).unwrap_or("");
        let file_path = raw_path
            .strip_prefix("/repo/")
            .unwrap_or(raw_path)
            .to_string();
        let line = item
            .get("sink_line")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        let vuln_name = item.get("vuln_name").and_then(|v| v.as_str()).unwrap_or("");
        let cwe = item
            .get("vuln_cwe")
            .and_then(|v| v.as_str())
            .and_then(normalize_cwe);

        // Summarize the tainted source(s) for the description.
        let sources: Vec<String> = item
            .get("source_name")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let src_summary = if sources.is_empty() {
            "tainted input".to_string()
        } else {
            sources.join(", ")
        };

        let rule_id = if vuln_name.is_empty() { "taint" } else { vuln_name };
        out.push(RawFinding {
            tool: "progpilot".into(),
            rule_id: rule_id.to_string(),
            file_path,
            line_start: line,
            line_end: line,
            severity: "high".into(),
            confidence: "medium".into(),
            cwe,
            owasp: None,
            title: format!("Progpilot: {rule_id}"),
            description: format!("Tainted data from {src_summary} reaches sink {sink_name}."),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_a_sql_injection_result() {
        let raw = json!([{
            "sink_name": "mysqli_query",
            "sink_file": "/repo/index.php",
            "sink_line": 7,
            "vuln_name": "sql_injection",
            "vuln_cwe": "CWE_89",
            "vuln_id": "abc123",
            "source_name": ["$_GET"],
            "source_line": [4]
        }]);
        let findings = parse(&raw).unwrap();
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.tool, "progpilot");
        assert_eq!(f.rule_id, "sql_injection");
        assert_eq!(f.file_path, "index.php");
        assert_eq!(f.line_start, 7);
        assert_eq!(f.cwe.as_deref(), Some("CWE-89"));
        assert_eq!(f.severity, "high");
        assert!(f.description.contains("$_GET"));
        assert!(f.description.contains("mysqli_query"));
    }

    #[test]
    fn empty_array_yields_no_findings() {
        let findings = parse(&json!([])).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn non_array_is_an_error() {
        assert!(parse(&json!({"oops": true})).is_err());
    }
}
