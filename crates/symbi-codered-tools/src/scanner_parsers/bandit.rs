//! Bandit JSON output → RawFinding.

use serde_json::Value;
use thiserror::Error;

use super::RawFinding;

#[derive(Debug, Error)]
pub enum BanditParseError {
    #[error("missing results array")]
    MissingResults,
}

pub fn parse(raw: &Value) -> Result<Vec<RawFinding>, BanditParseError> {
    let results = raw
        .get("results")
        .and_then(|v| v.as_array())
        .ok_or(BanditParseError::MissingResults)?;
    let mut out = Vec::new();
    for r in results {
        let filename = r.get("filename").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let line = u32::try_from(
            r.get("line_number").and_then(|v| v.as_u64()).unwrap_or(0)
        ).unwrap_or(0);
        let line_range = r.get("line_range")
            .and_then(|v| v.as_array())
            .map(|arr| {
                let s = u32::try_from(
                    arr.first().and_then(|x| x.as_u64()).unwrap_or(u64::from(line))
                ).unwrap_or(line);
                let e = u32::try_from(
                    arr.last().and_then(|x| x.as_u64()).unwrap_or(u64::from(line))
                ).unwrap_or(line);
                (s, e)
            })
            .unwrap_or((line, line));
        let severity = normalize(
            r.get("issue_severity").and_then(|v| v.as_str()).unwrap_or(""));
        let confidence = normalize_conf(
            r.get("issue_confidence").and_then(|v| v.as_str()).unwrap_or(""));
        let rule_id = r.get("test_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let title = r.get("test_name").and_then(|v| v.as_str())
            .unwrap_or(&rule_id).to_string();
        let description = r.get("issue_text").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let cwe = r.get("issue_cwe").and_then(|v| v.get("id"))
            .and_then(|v| v.as_u64())
            .map(|id| format!("CWE-{id}"));
        out.push(RawFinding {
            tool: "bandit".into(),
            rule_id,
            file_path: filename,
            line_start: line_range.0,
            line_end:   line_range.1,
            severity,
            confidence,
            cwe,
            owasp: None,
            title,
            description,
        });
    }
    Ok(out)
}

fn normalize(s: &str) -> String {
    match s.to_ascii_uppercase().as_str() {
        "HIGH" => "high",
        "MEDIUM" => "medium",
        "LOW" => "low",
        _ => "low",
    }.into()
}

fn normalize_conf(s: &str) -> String {
    match s.to_ascii_uppercase().as_str() {
        "HIGH" => "high",
        "MEDIUM" => "medium",
        _ => "low",
    }.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_sqli_finding() {
        let raw = json!({
            "results": [{
                "filename": "app/routes/users.py",
                "line_number": 12,
                "line_range": [12, 12],
                "issue_severity": "MEDIUM",
                "issue_confidence": "MEDIUM",
                "issue_text": "Possible SQL injection vector through string-based query construction.",
                "test_id": "B608",
                "test_name": "hardcoded_sql_expressions",
                "issue_cwe": {"id": 89, "link": "https://cwe.mitre.org/data/definitions/89.html"}
            }]
        });
        let out = parse(&raw).unwrap();
        assert_eq!(out.len(), 1);
        let f = &out[0];
        assert_eq!(f.tool, "bandit");
        assert_eq!(f.rule_id, "B608");
        assert_eq!(f.cwe.as_deref(), Some("CWE-89"));
        assert_eq!(f.severity, "medium");
        assert_eq!(f.line_start, 12);
    }

    #[test]
    fn empty_results_ok() {
        let raw = json!({"results": []});
        assert!(parse(&raw).unwrap().is_empty());
    }
}
