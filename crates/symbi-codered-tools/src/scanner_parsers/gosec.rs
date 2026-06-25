//! gosec JSON output → RawFinding (one per Issue).
//!
//! Input shape (gosec 2.21):
//! ```json
//! {
//!   "Stats": {"files": 12, "lines": 4321, "nosec": 0, "found": 3},
//!   "Issues": [{
//!     "severity": "HIGH",
//!     "confidence": "HIGH",
//!     "cwe": {"ID": "78", "URL": "https://cwe.mitre.org/data/definitions/78.html"},
//!     "rule_id": "G204",
//!     "details": "Subprocess launched with variable",
//!     "file": "/repo/cmd/run.go",
//!     "code": "exec.Command(userInput)",
//!     "line": "42",
//!     "column": "7",
//!     "nosec": false,
//!     "suppressions": null
//!   }],
//!   "Golang errors": {}
//! }
//! ```
//!
//! gosec emits `line` as a *string* (it can be a single number like `"42"`
//! or a range `"42-44"`). We parse the first integer and treat ranges as
//! line_start..line_end.

use serde_json::Value;
use thiserror::Error;

use super::RawFinding;

#[derive(Debug, Error)]
pub enum GosecParseError {
    #[error("missing Issues array")]
    MissingIssues,
}

pub fn parse(raw: &Value) -> Result<Vec<RawFinding>, GosecParseError> {
    let issues = raw
        .get("Issues")
        .and_then(|v| v.as_array())
        .ok_or(GosecParseError::MissingIssues)?;
    let mut out = Vec::new();
    for issue in issues {
        let rule_id = issue
            .get("rule_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let details = issue
            .get("details")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let severity = normalize_severity(
            issue.get("severity").and_then(|v| v.as_str()).unwrap_or(""),
        );
        let confidence = normalize_confidence(
            issue.get("confidence").and_then(|v| v.as_str()).unwrap_or(""),
        );
        let cwe = issue
            .get("cwe")
            .and_then(|v| v.get("ID"))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|id| format!("CWE-{id}"));
        let raw_path = issue.get("file").and_then(|v| v.as_str()).unwrap_or("");
        let file_path = raw_path
            .strip_prefix("/repo/")
            .unwrap_or(raw_path)
            .to_string();
        // gosec encodes line as a string: "42" or "42-44".
        let line_str = issue.get("line").and_then(|v| v.as_str()).unwrap_or("");
        let (line_start, line_end) = parse_line_range(line_str);
        let title = if details.is_empty() {
            rule_id.clone()
        } else {
            truncate(&details, 100)
        };
        out.push(RawFinding {
            tool: "gosec".into(),
            rule_id,
            file_path,
            line_start,
            line_end,
            severity,
            confidence,
            cwe,
            owasp: None,
            title,
            description: details,
        });
    }
    Ok(out)
}

fn parse_line_range(s: &str) -> (u32, u32) {
    if let Some((a, b)) = s.split_once('-') {
        let start = a.trim().parse::<u32>().unwrap_or(0);
        let end = b.trim().parse::<u32>().unwrap_or(start);
        (start, end)
    } else {
        let n = s.trim().parse::<u32>().unwrap_or(0);
        (n, n)
    }
}

fn normalize_severity(s: &str) -> String {
    match s.to_ascii_uppercase().as_str() {
        "HIGH" => "high",
        "MEDIUM" => "medium",
        "LOW" => "low",
        _ => "medium",
    }
    .into()
}

fn normalize_confidence(s: &str) -> String {
    match s.to_ascii_uppercase().as_str() {
        "HIGH" => "high",
        "MEDIUM" => "medium",
        "LOW" => "low",
        _ => "medium",
    }
    .into()
}

fn truncate(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        return s.to_string();
    }
    s.chars().take(max_chars).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_subprocess_issue_with_cwe_78() {
        let raw = json!({
            "Stats": {"files": 1, "lines": 50, "nosec": 0, "found": 1},
            "Issues": [{
                "severity": "HIGH",
                "confidence": "HIGH",
                "cwe": {"ID": "78", "URL": "https://cwe.mitre.org/data/definitions/78.html"},
                "rule_id": "G104",
                "details": "Subprocess launched with variable",
                "file": "/repo/cmd/run.go",
                "code": "exec.Command(userInput)",
                "line": "42",
                "column": "7",
                "nosec": false,
                "suppressions": null
            }],
            "Golang errors": {}
        });
        let out = parse(&raw).unwrap();
        assert_eq!(out.len(), 1);
        let f = &out[0];
        assert_eq!(f.tool, "gosec");
        assert_eq!(f.rule_id, "G104");
        assert_eq!(f.cwe.as_deref(), Some("CWE-78"));
        assert_eq!(f.severity, "high");
        assert_eq!(f.confidence, "high");
        // /repo/ prefix stripped → repo-relative path.
        assert_eq!(f.file_path, "cmd/run.go");
        assert_eq!(f.line_start, 42);
        assert_eq!(f.line_end, 42);
        assert_eq!(f.title, "Subprocess launched with variable");
        assert_eq!(f.description, "Subprocess launched with variable");
    }

    #[test]
    fn parses_line_range() {
        let raw = json!({
            "Issues": [{
                "severity": "MEDIUM",
                "confidence": "LOW",
                "cwe": {"ID": "327"},
                "rule_id": "G401",
                "details": "Use of weak cryptographic primitive",
                "file": "crypto/md5.go",
                "line": "12-14",
                "column": "2"
            }]
        });
        let out = parse(&raw).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].line_start, 12);
        assert_eq!(out[0].line_end, 14);
        assert_eq!(out[0].cwe.as_deref(), Some("CWE-327"));
        assert_eq!(out[0].severity, "medium");
        assert_eq!(out[0].confidence, "low");
        // No /repo/ prefix → path passes through unchanged.
        assert_eq!(out[0].file_path, "crypto/md5.go");
    }

    #[test]
    fn empty_details_falls_back_to_rule_id_in_title() {
        let raw = json!({
            "Issues": [{
                "severity": "LOW",
                "confidence": "HIGH",
                "cwe": {"ID": ""},
                "rule_id": "G999",
                "details": "",
                "file": "foo.go",
                "line": "1"
            }]
        });
        let out = parse(&raw).unwrap();
        assert_eq!(out[0].title, "G999");
        assert!(out[0].cwe.is_none());
    }

    #[test]
    fn missing_issues_errors() {
        let raw = json!({"Stats": {}});
        assert!(parse(&raw).is_err());
    }
}
