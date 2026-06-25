//! Ruff (security selects) JSON output → RawFinding.

use serde_json::Value;
use thiserror::Error;

use super::RawFinding;

#[derive(Debug, Error)]
pub enum RuffParseError {
    #[error("expected JSON array")]
    NotArray,
}

pub fn parse(raw: &Value) -> Result<Vec<RawFinding>, RuffParseError> {
    let arr = raw.as_array().ok_or(RuffParseError::NotArray)?;
    let mut out = Vec::new();
    for entry in arr {
        let code = entry.get("code").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if !code.starts_with('S') {
            continue;
        }
        let filename = entry.get("filename").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let message = entry.get("message").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let start = u32::try_from(
            entry.get("location").and_then(|v| v.get("row"))
                .and_then(|v| v.as_u64()).unwrap_or(0)
        ).unwrap_or(0);
        let end = u32::try_from(
            entry.get("end_location").and_then(|v| v.get("row"))
                .and_then(|v| v.as_u64()).unwrap_or(u64::from(start))
        ).unwrap_or(start);
        let severity = severity_for(&code);
        out.push(RawFinding {
            tool: "ruff".into(),
            rule_id: code.clone(),
            file_path: filename,
            line_start: start,
            line_end:   end,
            severity,
            confidence: "medium".into(),
            cwe: cwe_for(&code),
            owasp: None,
            title: code,
            description: message,
        });
    }
    Ok(out)
}

fn severity_for(code: &str) -> String {
    if code.starts_with("S6") || code.starts_with("S5") { "high".into() }
    else if code.starts_with("S1") || code.starts_with("S2") || code.starts_with("S3") { "medium".into() }
    else { "low".into() }
}

fn cwe_for(code: &str) -> Option<String> {
    match code {
        "S608" => Some("CWE-89".into()),
        "S605" | "S606" | "S607" => Some("CWE-78".into()),
        "S301" | "S302" => Some("CWE-502".into()),
        "S324" => Some("CWE-327".into()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_s608_sqli() {
        let raw = json!([{
            "code": "S608",
            "filename": "app/routes/users.py",
            "message": "Possible SQL injection vector through string-based query construction",
            "location": {"row": 12, "column": 4},
            "end_location": {"row": 12, "column": 70}
        }]);
        let out = parse(&raw).unwrap();
        assert_eq!(out.len(), 1);
        let f = &out[0];
        assert_eq!(f.tool, "ruff");
        assert_eq!(f.rule_id, "S608");
        assert_eq!(f.cwe.as_deref(), Some("CWE-89"));
        assert_eq!(f.severity, "high");
    }

    #[test]
    fn ignores_non_security_codes() {
        let raw = json!([
            { "code": "E501", "filename": "x.py", "message": "line too long",
              "location": {"row":1,"column":1}, "end_location":{"row":1,"column":1} }
        ]);
        assert!(parse(&raw).unwrap().is_empty());
    }
}
