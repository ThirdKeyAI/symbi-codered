//! cargo-audit JSON output → RawFinding (one per RustSec advisory).
//!
//! Input shape (cargo-audit 0.21):
//! ```json
//! {
//!   "vulnerabilities": {
//!     "found": true,
//!     "count": 1,
//!     "list": [{
//!       "advisory": {
//!         "id": "RUSTSEC-2024-0003",
//!         "package": "h2",
//!         "title": "Resource exhaustion vulnerability in h2 may lead to DOS",
//!         "description": "An attacker with...",
//!         "severity": "high",
//!         "url": "https://rustsec.org/advisories/RUSTSEC-2024-0003"
//!       },
//!       "package": {"name": "h2", "version": "0.3.21"},
//!       "versions": {"patched": [">=0.3.24"]},
//!       "kind": "vulnerability"
//!     }]
//!   }
//! }
//! ```
//!
//! RustSec advisories don't carry CWE consistently, so `cwe` stays None.

use serde_json::Value;
use thiserror::Error;

use super::RawFinding;

#[derive(Debug, Error)]
pub enum CargoAuditParseError {
    #[error("missing vulnerabilities.list array")]
    MissingList,
}

pub fn parse(raw: &Value) -> Result<Vec<RawFinding>, CargoAuditParseError> {
    let list = raw
        .get("vulnerabilities")
        .and_then(|v| v.get("list"))
        .and_then(|v| v.as_array())
        .ok_or(CargoAuditParseError::MissingList)?;
    let mut out = Vec::new();
    for entry in list {
        let advisory = entry.get("advisory").unwrap_or(&Value::Null);
        let id = advisory
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let title_raw = advisory
            .get("title")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let description = advisory
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let severity = normalize_severity(
            advisory.get("severity").and_then(|v| v.as_str()).unwrap_or(""),
        );
        // Package metadata can live on either advisory.package (string) or
        // entry.package.{name,version} (object); the latter is the canonical
        // location in cargo-audit 0.21 output.
        let pkg_name = entry
            .get("package")
            .and_then(|v| v.get("name"))
            .and_then(|v| v.as_str())
            .or_else(|| advisory.get("package").and_then(|v| v.as_str()))
            .unwrap_or("")
            .to_string();
        let pkg_version = entry
            .get("package")
            .and_then(|v| v.get("version"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let patched = entry
            .get("versions")
            .and_then(|v| v.get("patched"))
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();
        let title = if title_raw.is_empty() {
            id.clone()
        } else {
            format!("{id}: {title_raw}")
        };
        let body = if patched.is_empty() {
            description.clone()
        } else {
            format!("{description}\n\nPackage: {pkg_name} {pkg_version}\nPatched: {patched}")
        };
        out.push(RawFinding {
            tool: "cargo-audit".into(),
            rule_id: id,
            file_path: "Cargo.toml".into(),
            line_start: 0,
            line_end: 0,
            severity,
            confidence: "high".into(),
            // RustSec advisories don't ship a stable CWE field.
            cwe: None,
            owasp: None,
            title,
            description: body,
        });
    }
    Ok(out)
}

fn normalize_severity(s: &str) -> String {
    match s.to_ascii_uppercase().as_str() {
        "CRITICAL" => "critical",
        "HIGH" => "high",
        "MEDIUM" | "MODERATE" => "medium",
        "LOW" => "low",
        // RustSec advisories without a severity field map to medium —
        // they're still confirmed vulnerabilities, just unscored.
        _ => "medium",
    }
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_single_advisory() {
        let raw = json!({
            "vulnerabilities": {
                "found": true,
                "count": 1,
                "list": [{
                    "advisory": {
                        "id": "RUSTSEC-2024-0003",
                        "title": "h2: resource exhaustion DOS",
                        "description": "An attacker can flood the server with HEADERS frames.",
                        "severity": "high",
                        "url": "https://rustsec.org/advisories/RUSTSEC-2024-0003"
                    },
                    "package": {"name": "h2", "version": "0.3.21"},
                    "versions": {"patched": [">=0.3.24"]},
                    "kind": "vulnerability"
                }]
            }
        });
        let out = parse(&raw).unwrap();
        assert_eq!(out.len(), 1);
        let f = &out[0];
        assert_eq!(f.tool, "cargo-audit");
        assert_eq!(f.rule_id, "RUSTSEC-2024-0003");
        assert_eq!(f.severity, "high");
        assert!(f.cwe.is_none(), "cargo-audit must not invent CWE");
        assert_eq!(f.file_path, "Cargo.toml");
        assert_eq!(f.line_start, 0);
        assert!(f.title.starts_with("RUSTSEC-2024-0003"));
        assert!(f.description.contains(">=0.3.24"));
        assert!(f.description.contains("h2 0.3.21"));
    }

    #[test]
    fn empty_list_parses_to_empty_vec() {
        let raw = json!({
            "vulnerabilities": {"found": false, "count": 0, "list": []}
        });
        assert!(parse(&raw).unwrap().is_empty());
    }

    #[test]
    fn missing_list_errors() {
        let raw = json!({"vulnerabilities": {}});
        assert!(parse(&raw).is_err());
    }
}
