//! clippy `--message-format=json` output → RawFinding for security-relevant
//! lints.
//!
//! clippy emits NDJSON (one JSON object per line). We accept either:
//! - a single `serde_json::Value::String` containing the raw stdout text
//!   (NDJSON), or
//! - a `serde_json::Value::Array` of pre-parsed message objects (callers that
//!   have already split lines).
//!
//! We filter for `{"reason": "compiler-message"}` envelopes whose inner
//! `message.code.code` starts with `clippy::`, and emit one `RawFinding` per
//! such message keyed on the primary span.
//!
//! Only a hand-curated subset of clippy codes gets a CWE mapping; the rest
//! emit findings with `cwe: None`. The orchestrator decides whether to keep
//! uncategorized clippy warnings.

use serde_json::Value;
use thiserror::Error;

use super::RawFinding;

#[derive(Debug, Error)]
pub enum ClippyParseError {
    #[error("input must be a JSON string (raw ndjson stdout) or array of message objects")]
    BadShape,
}

pub fn parse(raw: &Value) -> Result<Vec<RawFinding>, ClippyParseError> {
    let messages: Vec<Value> = match raw {
        Value::String(s) => s
            .lines()
            .filter(|line| !line.trim().is_empty())
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .collect(),
        Value::Array(arr) => arr.clone(),
        _ => return Err(ClippyParseError::BadShape),
    };

    let mut out = Vec::new();
    for env in &messages {
        if env.get("reason").and_then(|v| v.as_str()) != Some("compiler-message") {
            continue;
        }
        let Some(message) = env.get("message") else { continue };
        let rule_id = message
            .get("code")
            .and_then(|v| v.get("code"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if !rule_id.starts_with("clippy::") {
            continue;
        }
        let level = message.get("level").and_then(|v| v.as_str()).unwrap_or("");
        // Only treat warning|error as findings; ignore note/help envelopes.
        let severity = match level {
            "error" => "high",
            "warning" => "low",
            _ => continue,
        }
        .to_string();
        let title = message
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or(rule_id)
            .to_string();
        let description = message
            .get("rendered")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map_or_else(|| title.clone(), str::to_string);
        let primary_span = message
            .get("spans")
            .and_then(|v| v.as_array())
            .and_then(|arr| {
                arr.iter()
                    .find(|s| s.get("is_primary").and_then(|v| v.as_bool()) == Some(true))
                    .or_else(|| arr.first())
            });
        let (file_path, line_start, line_end) = match primary_span {
            Some(span) => {
                let raw_path = span
                    .get("file_name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                // clippy reports paths relative to the manifest dir; when the
                // runner sets manifest-path=/repo/Cargo.toml, paths look like
                // `src/foo.rs`. Some workflows surface `/repo/src/foo.rs`
                // instead — strip that prefix so file_path stays repo-relative.
                let path = raw_path
                    .strip_prefix("/repo/")
                    .unwrap_or(raw_path)
                    .to_string();
                let ls = u32::try_from(
                    span.get("line_start")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0),
                )
                .unwrap_or(0);
                let le = u32::try_from(
                    span.get("line_end")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(u64::from(ls)),
                )
                .unwrap_or(ls);
                (path, ls, le)
            }
            None => (String::new(), 0_u32, 0_u32),
        };
        out.push(RawFinding {
            tool: "clippy".into(),
            rule_id: rule_id.to_string(),
            file_path,
            line_start,
            line_end,
            severity,
            confidence: "medium".into(),
            cwe: cwe_for(rule_id).map(str::to_string),
            owasp: None,
            title,
            description,
        });
    }
    Ok(out)
}

fn cwe_for(rule_id: &str) -> Option<&'static str> {
    match rule_id {
        "clippy::unwrap_used" | "clippy::expect_used" => Some("CWE-248"),
        "clippy::indexing_slicing" => Some("CWE-129"),
        "clippy::integer_arithmetic" | "clippy::integer_overflow" => Some("CWE-190"),
        "clippy::cast_possible_truncation" | "clippy::cast_sign_loss" => Some("CWE-704"),
        // TOCTOU-adjacent: check-time vs. use-time on filetypes.
        "clippy::filetype_is_file" => Some("CWE-367"),
        "clippy::suspicious_open_options" => Some("CWE-732"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn compiler_message(code: &str, level: &str, file: &str, line: u64) -> Value {
        json!({
            "reason": "compiler-message",
            "message": {
                "code": {"code": code, "explanation": null},
                "level": level,
                "message": format!("used `{}` here", code),
                "rendered": format!("warning: used `{}` here\n --> {}:{}:1\n", code, file, line),
                "spans": [{
                    "file_name": file,
                    "line_start": line,
                    "line_end": line,
                    "column_start": 1,
                    "column_end": 5,
                    "is_primary": true
                }]
            }
        })
    }

    #[test]
    fn parses_unwrap_used_with_cwe_from_string_ndjson() {
        let line = serde_json::to_string(&compiler_message(
            "clippy::unwrap_used",
            "warning",
            "/repo/src/main.rs",
            42,
        ))
        .unwrap();
        // Mix in a build-script-noise envelope to ensure it is filtered out.
        let other = json!({"reason": "build-script-executed"}).to_string();
        let raw = Value::String(format!("{other}\n{line}\n"));
        let out = parse(&raw).unwrap();
        assert_eq!(out.len(), 1);
        let f = &out[0];
        assert_eq!(f.tool, "clippy");
        assert_eq!(f.rule_id, "clippy::unwrap_used");
        assert_eq!(f.cwe.as_deref(), Some("CWE-248"));
        assert_eq!(f.severity, "low");
        // The `/repo/` prefix must be stripped so the path is repo-relative.
        assert_eq!(f.file_path, "src/main.rs");
        assert_eq!(f.line_start, 42);
        assert_eq!(f.line_end, 42);
    }

    #[test]
    fn error_level_maps_to_high() {
        let msg = compiler_message("clippy::indexing_slicing", "error", "src/x.rs", 7);
        let out = parse(&Value::Array(vec![msg])).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity, "high");
        assert_eq!(out[0].cwe.as_deref(), Some("CWE-129"));
    }

    #[test]
    fn ignores_non_clippy_codes_and_notes() {
        // rustc warning (not clippy) — should be skipped.
        let rustc = json!({
            "reason": "compiler-message",
            "message": {
                "code": {"code": "unused_variables"},
                "level": "warning",
                "message": "unused variable",
                "rendered": "",
                "spans": [{"file_name":"x.rs","line_start":1,"line_end":1,"is_primary":true}]
            }
        });
        // clippy note — should be skipped (only warning/error become findings).
        let note = compiler_message("clippy::unwrap_used", "note", "src/x.rs", 1);
        let out = parse(&Value::Array(vec![rustc, note])).unwrap();
        assert!(out.is_empty());
    }
}
