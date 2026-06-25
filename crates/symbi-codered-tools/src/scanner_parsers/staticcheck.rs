//! staticcheck NDJSON output → RawFinding for correctness lints.
//!
//! `staticcheck -f json` emits one JSON object per line:
//! ```json
//! {
//!   "code": "SA1019",
//!   "severity": "warning",
//!   "location": {"file": "/repo/foo.go", "line": 42, "column": 7},
//!   "end": {"file": "/repo/foo.go", "line": 42, "column": 15},
//!   "message": "tls.CipherSuiteName has been deprecated …",
//!   "related": []
//! }
//! ```
//!
//! Severity comes from the `severity` field (`warning` → low, `error` →
//! high). CWE comes from a small hand-curated map keyed on the SA*/S* code;
//! everything else gets `cwe: None` (callers can decide whether to keep
//! uncategorized correctness lints).

use serde::Deserialize;
use thiserror::Error;

use super::RawFinding;

#[derive(Debug, Error)]
pub enum StaticcheckParseError {
    #[error("no parseable NDJSON lines in input")]
    Empty,
}

#[derive(Debug, Deserialize)]
struct Diagnostic {
    #[serde(default)]
    code: String,
    #[serde(default)]
    severity: String,
    #[serde(default)]
    location: Option<Location>,
    #[serde(default)]
    end: Option<Location>,
    #[serde(default)]
    message: String,
}

#[derive(Debug, Deserialize)]
struct Location {
    #[serde(default)]
    file: String,
    #[serde(default)]
    line: u64,
}

pub fn parse(stdout: &str) -> Result<Vec<RawFinding>, StaticcheckParseError> {
    let mut out = Vec::new();
    let mut saw_any_line = false;
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        saw_any_line = true;
        let Ok(diag) = serde_json::from_str::<Diagnostic>(line) else {
            continue;
        };
        if diag.code.is_empty() {
            continue;
        }
        let severity = match diag.severity.as_str() {
            "error" => "high",
            _ => "low",
        }
        .to_string();
        let (file_path, line_start) = diag
            .location
            .as_ref()
            .map(|loc| {
                let path = loc
                    .file
                    .strip_prefix("/repo/")
                    .unwrap_or(&loc.file)
                    .to_string();
                let line = u32::try_from(loc.line).unwrap_or(0);
                (path, line)
            })
            .unwrap_or_default();
        let line_end = diag
            .end
            .as_ref()
            .map(|loc| u32::try_from(loc.line).unwrap_or(line_start))
            .unwrap_or(line_start);
        let title_raw = format!("{}: {}", diag.code, diag.message);
        let title = truncate(&title_raw, 100);
        out.push(RawFinding {
            tool: "staticcheck".into(),
            rule_id: diag.code.clone(),
            file_path,
            line_start,
            line_end,
            severity,
            confidence: "medium".into(),
            cwe: cwe_for(&diag.code).map(str::to_string),
            owasp: None,
            title,
            description: diag.message,
        });
    }
    if !saw_any_line {
        return Err(StaticcheckParseError::Empty);
    }
    Ok(out)
}

fn cwe_for(code: &str) -> Option<&'static str> {
    match code {
        // Style / unused / deprecation — not security-relevant on their own.
        "SA1019" | "SA4006" | "S1024" | "S1028" => None,
        // Printf-family format-string mismatches.
        "SA1006" | "SA5009" => Some("CWE-134"),
        // append to a slice with nil cap → resource exhaustion / DOS pattern.
        "SA1031" => Some("CWE-770"),
        // Default for any SA-class diagnostic: correctness / improper logic.
        _ if code.starts_with("SA") => Some("CWE-754"),
        _ => None,
    }
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

    #[test]
    fn parses_sa1006_to_cwe_134_low_warning() {
        let ndjson = r#"{"code":"SA1006","severity":"warning","location":{"file":"/repo/foo.go","line":42,"column":7},"end":{"file":"/repo/foo.go","line":42,"column":15},"message":"Printf-style function with dynamic format string and no further arguments","related":[]}
"#;
        let out = parse(ndjson).unwrap();
        assert_eq!(out.len(), 1);
        let f = &out[0];
        assert_eq!(f.tool, "staticcheck");
        assert_eq!(f.rule_id, "SA1006");
        assert_eq!(f.cwe.as_deref(), Some("CWE-134"));
        assert_eq!(f.severity, "low");
        assert_eq!(f.file_path, "foo.go");
        assert_eq!(f.line_start, 42);
        assert_eq!(f.line_end, 42);
        assert!(f.title.starts_with("SA1006: "));
    }

    #[test]
    fn deprecation_sa1019_has_no_cwe() {
        let ndjson = r#"{"code":"SA1019","severity":"warning","location":{"file":"x.go","line":1,"column":1},"end":{"file":"x.go","line":1,"column":2},"message":"deprecated"}"#;
        let out = parse(ndjson).unwrap();
        assert_eq!(out.len(), 1);
        assert!(out[0].cwe.is_none());
    }

    #[test]
    fn unknown_sa_code_falls_back_to_cwe_754() {
        let ndjson = r#"{"code":"SA9999","severity":"error","location":{"file":"x.go","line":3,"column":1},"end":{"file":"x.go","line":4,"column":1},"message":"something"}"#;
        let out = parse(ndjson).unwrap();
        assert_eq!(out[0].cwe.as_deref(), Some("CWE-754"));
        // error severity → high.
        assert_eq!(out[0].severity, "high");
        // end.line passes through.
        assert_eq!(out[0].line_end, 4);
    }

    #[test]
    fn s_prefix_style_codes_have_no_cwe() {
        let ndjson = r#"{"code":"S1024","severity":"warning","location":{"file":"x.go","line":1},"end":{"file":"x.go","line":1},"message":"redundant"}"#;
        let out = parse(ndjson).unwrap();
        assert!(out[0].cwe.is_none());
    }

    #[test]
    fn empty_input_errors() {
        assert!(parse("").is_err());
        assert!(parse("   \n").is_err());
    }

    #[test]
    fn unparseable_lines_are_skipped() {
        let ndjson = r#"not json
{"code":"SA1031","severity":"warning","location":{"file":"x.go","line":2},"end":{"file":"x.go","line":2},"message":"append nil cap"}
"#;
        let out = parse(ndjson).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].cwe.as_deref(), Some("CWE-770"));
    }
}
