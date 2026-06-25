//! SARIF 2.1.0 renderer — turns a slice of `Finding` rows into a SARIF
//! `serde_json::Value` ready for `serde_json::to_writer_pretty`. Hand-rolled
//! via `serde_json::json!` (no external SARIF crate) to keep the dependency
//! surface small and the spec wiring auditable.
//!
//! Per Plan G spec §5.4, each finding becomes both a rule (under
//! `runs[0].tool.driver.rules`) and a result (under `runs[0].results`). The
//! rule and result share the finding's `id` as `ruleId`. CWE + tool_origin
//! ride along under `properties` so downstream consumers (GitHub Code
//! Scanning, etc.) can filter.

use serde_json::{json, Value};
use symbi_evidence_schema::Finding;
use symbi_evidence_schema::finding::Severity;

/// Render the given findings to a SARIF 2.1.0 JSON Value.
///
/// `engagement_id` and `specifier_hash` flow into `runs[0].properties` and
/// the result-level `properties` so a consumer can correlate back to the
/// run that produced the report.
pub fn render(findings: &[Finding], engagement_id: &str, specifier_hash: &str) -> Value {
    let rules: Vec<Value> = findings
        .iter()
        .map(|f| {
            json!({
                "id": f.id,
                "shortDescription": { "text": f.title },
                "fullDescription":  { "text": f.description },
                "defaultConfiguration": {
                    "level": severity_to_sarif_level(&f.severity)
                },
                "properties": {
                    "cwe":         f.cwe,
                    "tool_origin": f.tool_origin,
                },
            })
        })
        .collect();

    let results: Vec<Value> = findings
        .iter()
        .map(|f| {
            json!({
                "ruleId": f.id,
                "level":  severity_to_sarif_level(&f.severity),
                "message": { "text": f.title },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": f.file_path },
                        "region": {
                            "startLine": f.line_start,
                            "endLine":   f.line_end,
                        }
                    }
                }],
                "properties": {
                    "specifier_hash":   specifier_hash,
                    "advocate_verdict": f.advocate_verdict,
                    "poc_status":       f.poc_status,
                },
            })
        })
        .collect();

    json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name":    "symbi-codered",
                    "version": env!("CARGO_PKG_VERSION"),
                    "rules":   rules,
                }
            },
            "results": results,
            "properties": {
                "engagement_id":  engagement_id,
                "specifier_hash": specifier_hash,
            },
        }]
    })
}

/// Map our Severity enum onto SARIF's three-level scale.
fn severity_to_sarif_level(s: &Severity) -> &'static str {
    match s {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use symbi_evidence_schema::finding::{
        AdvocateVerdict, Confidence, Phase, PocStatus, Status,
    };
    use uuid::Uuid;

    fn sample() -> Finding {
        Finding {
            id: "F-pattern-scout-0001".into(),
            engagement_id: Uuid::nil(),
            phase: Phase::Sast,
            severity: Severity::High,
            confidence: Confidence::High,
            cwe: Some("CWE-89".into()),
            owasp: Some("A03:2021".into()),
            file_path: "app/users.py".into(),
            line_start: 88,
            line_end: 92,
            title: "SQL injection via sort parameter".into(),
            description: "Untrusted sort value reaches cursor.execute".into(),
            reachable: Some(true),
            exploitable: None,
            evidence_envelope_id: "S-001-semgrep-deadbeef0000".into(),
            status: Status::Open,
            rank_score: Some(0.92),
            specifier_hash: Some("abc123".into()),
            advocate_verdict: Some(AdvocateVerdict::Confirmed),
            tool_origin: Some("semgrep".into()),
            poc_status: Some(PocStatus::Reproduced),
            created_at: Utc::now(),
        }
    }

    #[test]
    fn render_emits_driver_name_and_version() {
        let v = render(&[sample()], "eng-1", "spec-hash");
        assert_eq!(v["version"], "2.1.0");
        let driver = &v["runs"][0]["tool"]["driver"];
        assert_eq!(driver["name"], "symbi-codered");
        assert!(driver["version"].is_string());
    }

    #[test]
    fn render_embeds_rule_id_and_cwe() {
        let v = render(&[sample()], "eng-1", "spec-hash");
        let rule = &v["runs"][0]["tool"]["driver"]["rules"][0];
        assert_eq!(rule["id"], "F-pattern-scout-0001");
        assert_eq!(rule["properties"]["cwe"], "CWE-89");
        assert_eq!(rule["defaultConfiguration"]["level"], "error");
    }

    #[test]
    fn render_attaches_engagement_and_specifier_to_run_properties() {
        let v = render(&[sample()], "eng-1", "spec-hash");
        let props = &v["runs"][0]["properties"];
        assert_eq!(props["engagement_id"], "eng-1");
        assert_eq!(props["specifier_hash"], "spec-hash");
    }

    #[test]
    fn render_result_carries_file_and_region() {
        let v = render(&[sample()], "eng-1", "spec-hash");
        let result = &v["runs"][0]["results"][0];
        assert_eq!(result["ruleId"], "F-pattern-scout-0001");
        assert_eq!(result["level"], "error");
        let loc = &result["locations"][0]["physicalLocation"];
        assert_eq!(loc["artifactLocation"]["uri"], "app/users.py");
        assert_eq!(loc["region"]["startLine"], 88);
        assert_eq!(loc["region"]["endLine"], 92);
    }

    #[test]
    fn severity_levels_map_as_documented() {
        assert_eq!(severity_to_sarif_level(&Severity::Critical), "error");
        assert_eq!(severity_to_sarif_level(&Severity::High), "error");
        assert_eq!(severity_to_sarif_level(&Severity::Medium), "warning");
        assert_eq!(severity_to_sarif_level(&Severity::Low), "note");
        assert_eq!(severity_to_sarif_level(&Severity::Info), "note");
    }

    #[test]
    fn render_empty_findings_emits_well_formed_skeleton() {
        let v = render(&[], "eng-1", "spec-hash");
        assert_eq!(v["runs"][0]["results"].as_array().unwrap().len(), 0);
        assert_eq!(
            v["runs"][0]["tool"]["driver"]["rules"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
    }
}
