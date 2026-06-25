//! govulncheck NDJSON output → RawFinding (one per reachable Finding).
//!
//! `govulncheck -json` emits a stream of newline-delimited JSON messages.
//! Each line is a `Message` envelope with exactly one of these keys:
//! `config`, `progress`, `osv`, or `finding`.
//!
//! - `osv` entries define vuln metadata (id, summary, details, aliases, …).
//! - `finding` entries report actual call traces referencing an OSV id.
//!
//! Parse strategy: walk the NDJSON twice (or once with a single pass that
//! buffers OSV metadata). For each `finding`, look up the OSV by id and
//! emit a RawFinding whose file/line come from the first trace frame (the
//! reachable call site) and whose CWE — if any — comes from the OSV aliases.
//!
//! govulncheck doesn't carry per-finding severity; we treat reachable vulns
//! as `high` and findings with no trace (vuln present in deps but never
//! called) as `medium`.

use std::collections::HashMap;

use serde::Deserialize;
use thiserror::Error;

use super::RawFinding;

#[derive(Debug, Error)]
pub enum GovulncheckParseError {
    #[error("no parseable NDJSON lines in input")]
    Empty,
}

#[derive(Debug, Deserialize)]
struct Envelope {
    #[serde(default)]
    osv: Option<Osv>,
    #[serde(default)]
    finding: Option<Finding>,
}

#[derive(Debug, Deserialize, Clone)]
struct Osv {
    #[serde(default)]
    id: String,
    #[serde(default)]
    summary: String,
    #[serde(default)]
    details: String,
    #[serde(default)]
    aliases: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Finding {
    #[serde(default)]
    osv: String,
    #[serde(default)]
    trace: Vec<TraceFrame>,
}

#[derive(Debug, Deserialize)]
struct TraceFrame {
    #[serde(default)]
    position: Option<Position>,
}

#[derive(Debug, Deserialize)]
struct Position {
    #[serde(default)]
    filename: String,
    #[serde(default)]
    line: u64,
}

pub fn parse(stdout: &str) -> Result<Vec<RawFinding>, GovulncheckParseError> {
    let mut osvs: HashMap<String, Osv> = HashMap::new();
    let mut findings: Vec<Finding> = Vec::new();
    let mut saw_any_line = false;

    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        saw_any_line = true;
        let Ok(env) = serde_json::from_str::<Envelope>(line) else {
            continue;
        };
        if let Some(osv) = env.osv {
            if !osv.id.is_empty() {
                osvs.insert(osv.id.clone(), osv);
            }
        }
        if let Some(finding) = env.finding {
            findings.push(finding);
        }
    }

    if !saw_any_line {
        return Err(GovulncheckParseError::Empty);
    }

    let mut out = Vec::new();
    for finding in &findings {
        let Some(osv) = osvs.get(&finding.osv) else { continue };
        // Reachable findings have a non-empty trace; unreachable (vuln in
        // dep tree but never called) findings have an empty trace and are
        // downgraded to medium.
        let reachable = !finding.trace.is_empty();
        let severity = if reachable { "high" } else { "medium" }.to_string();
        let (file_path, line_start) = finding
            .trace
            .first()
            .and_then(|frame| frame.position.as_ref())
            .map(|pos| {
                let path = pos
                    .filename
                    .strip_prefix("/repo/")
                    .unwrap_or(&pos.filename)
                    .to_string();
                let line = u32::try_from(pos.line).unwrap_or(0);
                (path, line)
            })
            .unwrap_or_else(|| ("go.mod".to_string(), 0_u32));
        let line_end = line_start;
        let cwe = osv
            .aliases
            .iter()
            .find(|s| s.starts_with("CWE-"))
            .cloned();
        let title = if osv.summary.is_empty() {
            osv.id.clone()
        } else {
            format!("{}: {}", osv.id, osv.summary)
        };
        let description = if osv.details.is_empty() {
            osv.summary.clone()
        } else {
            osv.details.clone()
        };
        out.push(RawFinding {
            tool: "govulncheck".into(),
            rule_id: osv.id.clone(),
            file_path,
            line_start,
            line_end,
            severity,
            confidence: "high".into(),
            cwe,
            owasp: None,
            title,
            description,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_osv_plus_finding_to_reachable_high() {
        let ndjson = r#"{"config":{"protocol_version":"v1.0.0"}}
{"progress":{"message":"Scanning your code…"}}
{"osv":{"id":"GO-2024-2611","summary":"Stack overflow in encoding/gob","details":"A maliciously crafted gob input can cause stack exhaustion.","aliases":["CVE-2024-24789","CWE-674"],"affected":[{"package":{"name":"stdlib","ecosystem":"Go"}}]}}
{"finding":{"osv":"GO-2024-2611","trace":[{"module":"main","package":"main","function":"main","position":{"filename":"/repo/cmd/server/main.go","line":42,"column":1}}]}}
"#;
        let out = parse(ndjson).unwrap();
        assert_eq!(out.len(), 1);
        let f = &out[0];
        assert_eq!(f.tool, "govulncheck");
        assert_eq!(f.rule_id, "GO-2024-2611");
        assert_eq!(f.severity, "high");
        assert_eq!(f.cwe.as_deref(), Some("CWE-674"));
        // /repo/ stripped → repo-relative.
        assert_eq!(f.file_path, "cmd/server/main.go");
        assert_eq!(f.line_start, 42);
        assert_eq!(f.line_end, 42);
        assert!(f.title.starts_with("GO-2024-2611: "));
        assert!(f.description.contains("stack exhaustion"));
    }

    #[test]
    fn finding_without_trace_is_medium() {
        let ndjson = r#"{"osv":{"id":"GO-2024-9999","summary":"unreachable advisory","aliases":[]}}
{"finding":{"osv":"GO-2024-9999","trace":[]}}
"#;
        let out = parse(ndjson).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity, "medium");
        assert!(out[0].cwe.is_none());
        // No trace → fallback file_path.
        assert_eq!(out[0].file_path, "go.mod");
        assert_eq!(out[0].line_start, 0);
    }

    #[test]
    fn finding_without_matching_osv_is_skipped() {
        let ndjson = r#"{"finding":{"osv":"GO-NOPE","trace":[]}}"#;
        let out = parse(ndjson).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn empty_input_errors() {
        assert!(parse("").is_err());
        assert!(parse("   \n  \n").is_err());
    }

    #[test]
    fn unparseable_lines_are_skipped_not_fatal() {
        // First line is garbage; the parser must keep scanning the rest.
        let ndjson = r#"this is not json
{"osv":{"id":"GO-2024-1","summary":"x","aliases":[]}}
{"finding":{"osv":"GO-2024-1","trace":[{"position":{"filename":"a.go","line":3}}]}}
"#;
        let out = parse(ndjson).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].rule_id, "GO-2024-1");
        assert_eq!(out[0].line_start, 3);
    }
}
