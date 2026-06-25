//! engagement-seed.json renderer — Cedar-filtered handoff envelope for the
//! redteam phase. Plan G spec §5.6.
//!
//! For each candidate `Finding`, we build a Cedar resource entity carrying:
//!   - `citations`        (Set<String>): citation_type values for this finding
//!   - `advocate_verdict` (String):     empty if NULL
//!   - `poc_status`       (String):     empty if NULL
//!   - `severity`         (String):     lowercase
//!
//! and evaluate
//!   Agent::"reporter" / Action::"emit_to_seed" / Finding::"<id>"
//!
//! against the loaded policies. Only `Decision::Allow` findings land in the
//! seed; `Decision::Deny` increments a counter so the caller (Task 11) can
//! surface it in the audit summary and CLI output.
//!
//! `signature` is left as an empty string here; Task 11 fills it in after
//! signing the canonical JSON form of the seed payload.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result};
use cedar_policy::{Decision, RestrictedExpression};
use chrono::Utc;
use rusqlite::Connection;
use serde_json::{json, Value};
use uuid::Uuid;

use symbi_codered_core::db::KnowledgeTriple;
use symbi_codered_core::policy::PolicyEngine;
use symbi_evidence_schema::finding::{AdvocateVerdict, PocStatus, Severity};
use symbi_evidence_schema::{AttackChainNode, Finding};

/// Render the engagement-seed JSON. Returns `(value, findings_in_seed, findings_filtered)`.
///
/// `value["signature"]` is the empty string here — Task 11 (`generate_all`)
/// computes the Ed25519 signature over the canonical bytes of this Value
/// after stripping the signature field, then re-inserts the hex digest.
#[allow(clippy::too_many_arguments)]
pub fn render(
    conn: &Connection,
    policy: &Arc<PolicyEngine>,
    engagement_id: Uuid,
    specifier_hash: &str,
    findings: &[Finding],
    attack_chains: &[AttackChainNode],
    knowledge_triples: &[KnowledgeTriple],
) -> Result<(Value, usize, usize)> {
    let mut seed_findings: Vec<Value> = Vec::new();
    let mut filtered: usize = 0;

    for f in findings {
        let citations = read_finding_citation_types(conn, &f.id)
            .with_context(|| format!("reading citations for {}", f.id))?;

        let attrs = build_attrs(f, &citations);

        let resource_uid = format!(r#"Finding::"{}""#, f.id);
        let (decision, _diag) = policy
            .evaluate_with_attrs(
                r#"Agent::"reporter""#,
                r#"Action::"emit_to_seed""#,
                &resource_uid,
                attrs,
            )
            .with_context(|| format!("evaluating handoff policy for {}", f.id))?;

        match decision {
            Decision::Allow => seed_findings.push(finding_to_seed_json(f, &citations)),
            Decision::Deny => filtered += 1,
        }
    }

    let chains: Vec<Value> = attack_chains.iter().map(chain_to_seed_json).collect();
    let triples: Vec<Value> = knowledge_triples.iter().map(triple_to_seed_json).collect();

    let value = json!({
        "engagement_id":     engagement_id.to_string(),
        "specifier_hash":    specifier_hash,
        "signature":         "",                       // filled in by generate_all
        "generated_at":      Utc::now().to_rfc3339(),
        "findings":          seed_findings,
        "attack_chains":     chains,
        "knowledge_triples": triples,
    });

    let in_seed = value["findings"].as_array().map(|a| a.len()).unwrap_or(0);
    Ok((value, in_seed, filtered))
}

/// Read the citation_type column for one finding. Cedar treats the result
/// as a `Set<String>`; the handoff-requires-citation rule checks `.contains("analyzer")`.
fn read_finding_citation_types(conn: &Connection, finding_id: &str) -> Result<Vec<String>> {
    let mut stmt = conn.prepare(
        "SELECT citation_type FROM finding_citations WHERE finding_id = ?1",
    )?;
    let rows = stmt.query_map(rusqlite::params![finding_id], |r| r.get::<_, String>(0))?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

fn build_attrs(f: &Finding, citations: &[String]) -> HashMap<String, RestrictedExpression> {
    let mut attrs = HashMap::new();

    let advocate = f
        .advocate_verdict
        .as_ref()
        .map(advocate_label)
        .unwrap_or("")
        .to_string();
    attrs.insert(
        "advocate_verdict".into(),
        RestrictedExpression::new_string(advocate),
    );

    let poc = f
        .poc_status
        .as_ref()
        .map(poc_label)
        .unwrap_or("")
        .to_string();
    attrs.insert(
        "poc_status".into(),
        RestrictedExpression::new_string(poc),
    );

    attrs.insert(
        "severity".into(),
        RestrictedExpression::new_string(severity_label(f.severity).to_string()),
    );

    let citation_set: Vec<RestrictedExpression> = citations
        .iter()
        .map(|c| RestrictedExpression::new_string(c.clone()))
        .collect();
    attrs.insert(
        "citations".into(),
        RestrictedExpression::new_set(citation_set),
    );

    attrs
}

fn finding_to_seed_json(f: &Finding, citations: &[String]) -> Value {
    json!({
        "id":                   f.id,
        "file_path":            f.file_path,
        "line_start":           f.line_start,
        "line_end":             f.line_end,
        "severity":             severity_label(f.severity),
        "cwe":                  f.cwe,
        "owasp":                f.owasp,
        "title":                f.title,
        "description":          f.description,
        "citations":            citations,
        "advocate_verdict":     f.advocate_verdict.as_ref().map(advocate_label),
        "poc_status":           f.poc_status.as_ref().map(poc_label),
        "tool_origin":          f.tool_origin,
        "evidence_envelope_id": f.evidence_envelope_id,
    })
}

fn chain_to_seed_json(c: &AttackChainNode) -> Value {
    let stage = serde_json::to_string(&c.stage)
        .map(|s| s.trim_matches('"').to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    json!({
        "id":            c.id,
        "stage":         stage,
        "finding_id":    c.finding_id,
        "evidence_id":   c.evidence_id,
        "next_chain_id": c.next_chain_id,
        "rationale":     c.rationale,
    })
}

fn triple_to_seed_json(t: &KnowledgeTriple) -> Value {
    json!({
        "id":           t.id,
        "subject":      t.subject,
        "predicate":    t.predicate,
        "object":       t.object,
        "confidence":   t.confidence,
        "rationale":    t.rationale,
        "source_phase": t.source_phase,
    })
}

fn severity_label(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

fn advocate_label(v: &AdvocateVerdict) -> &'static str {
    match v {
        AdvocateVerdict::Confirmed => "confirmed",
        AdvocateVerdict::Rebutted => "rebutted",
        AdvocateVerdict::Uncertain => "uncertain",
    }
}

fn poc_label(p: &PocStatus) -> &'static str {
    match p {
        PocStatus::Hypothesis => "hypothesis",
        PocStatus::PocAttempted => "poc_attempted",
        PocStatus::Reproduced => "reproduced",
        PocStatus::Refuted => "refuted",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use symbi_codered_core::db::{self};
    use symbi_evidence_schema::finding::{Confidence, Phase, Status};
    use symbi_evidence_schema::{Citation, Engagement};
    use tempfile::TempDir;

    fn fresh_with_policy() -> (TempDir, Connection, Arc<PolicyEngine>, Uuid) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.db");
        let conn = db::init_db(path.to_str().unwrap()).unwrap();
        let e = Engagement::new("acme", "h", "2026-05-22", "2026-05-29");
        let eng_id = e.id;
        db::insert_engagement(&conn, &e).unwrap();
        // CARGO_MANIFEST_DIR resolves to <workspace>/crates/symbi-codered-tools
        // at compile time, so the policies dir is unaffected by cwd-mutating
        // sibling tests (e.g. reporter::tests::generate_all_*).
        let policies = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../policies");
        let policy = Arc::new(PolicyEngine::from_dir(policies).unwrap());
        (dir, conn, policy, eng_id)
    }

    fn mk_finding(
        eng: Uuid,
        id: &str,
        sev: Severity,
        verdict: Option<AdvocateVerdict>,
        poc: Option<PocStatus>,
    ) -> Finding {
        Finding {
            id: id.into(),
            engagement_id: eng,
            phase: Phase::Sast,
            severity: sev,
            confidence: Confidence::High,
            cwe: Some("CWE-89".into()),
            owasp: None,
            file_path: "x.py".into(),
            line_start: 1,
            line_end: 1,
            title: "t".into(),
            description: "d".into(),
            reachable: Some(true),
            exploitable: None,
            evidence_envelope_id: format!("env-{id}"),
            status: Status::Open,
            rank_score: None,
            specifier_hash: None,
            advocate_verdict: verdict,
            tool_origin: Some("semgrep".into()),
            poc_status: poc,
            created_at: Utc::now(),
        }
    }

    fn insert_analyzer_citation(conn: &Connection, fid: &str) {
        db::insert_finding_citation(
            conn,
            fid,
            &Citation::Analyzer {
                finding_id: "F-source".into(),
            },
        )
        .unwrap();
    }

    #[test]
    fn rebutted_verdict_is_filtered_out() {
        let (_dir, conn, policy, eng) = fresh_with_policy();
        let f = mk_finding(
            eng,
            "F-1",
            Severity::High,
            Some(AdvocateVerdict::Rebutted),
            Some(PocStatus::Reproduced),
        );
        db::insert_finding(&conn, &f).unwrap();
        insert_analyzer_citation(&conn, &f.id);

        let (value, in_seed, filtered) =
            render(&conn, &policy, eng, "spec", &[f], &[], &[]).unwrap();
        assert_eq!(in_seed, 0);
        assert_eq!(filtered, 1);
        assert_eq!(value["findings"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn refuted_poc_is_filtered_out() {
        let (_dir, conn, policy, eng) = fresh_with_policy();
        let f = mk_finding(
            eng,
            "F-2",
            Severity::High,
            Some(AdvocateVerdict::Confirmed),
            Some(PocStatus::Refuted),
        );
        db::insert_finding(&conn, &f).unwrap();
        insert_analyzer_citation(&conn, &f.id);

        let (_v, in_seed, filtered) =
            render(&conn, &policy, eng, "spec", &[f], &[], &[]).unwrap();
        assert_eq!(in_seed, 0);
        assert_eq!(filtered, 1);
    }

    #[test]
    fn low_severity_is_filtered_out() {
        let (_dir, conn, policy, eng) = fresh_with_policy();
        let f = mk_finding(
            eng,
            "F-3",
            Severity::Low,
            Some(AdvocateVerdict::Confirmed),
            Some(PocStatus::Reproduced),
        );
        db::insert_finding(&conn, &f).unwrap();
        insert_analyzer_citation(&conn, &f.id);

        let (_v, in_seed, filtered) =
            render(&conn, &policy, eng, "spec", &[f], &[], &[]).unwrap();
        assert_eq!(in_seed, 0);
        assert_eq!(filtered, 1);
    }

    #[test]
    fn satisfying_finding_lands_in_seed() {
        let (_dir, conn, policy, eng) = fresh_with_policy();
        let f = mk_finding(
            eng,
            "F-4",
            Severity::High,
            Some(AdvocateVerdict::Confirmed),
            Some(PocStatus::Reproduced),
        );
        db::insert_finding(&conn, &f).unwrap();
        insert_analyzer_citation(&conn, &f.id);

        let (v, in_seed, filtered) =
            render(&conn, &policy, eng, "spec-hash", &[f], &[], &[]).unwrap();
        assert_eq!(in_seed, 1);
        assert_eq!(filtered, 0);

        let row = &v["findings"][0];
        assert_eq!(row["id"], "F-4");
        assert_eq!(row["severity"], "high");
        assert_eq!(row["advocate_verdict"], "confirmed");
        assert_eq!(row["poc_status"], "reproduced");
        let cits = row["citations"].as_array().unwrap();
        assert!(cits.iter().any(|c| c == "analyzer"));

        // Signature placeholder is empty pre-Task-11.
        assert_eq!(v["signature"], "");
        assert_eq!(v["specifier_hash"], "spec-hash");
        assert_eq!(v["engagement_id"], eng.to_string());
    }

    fn insert_code_citation(conn: &Connection, fid: &str) {
        db::insert_finding_citation(
            conn,
            fid,
            &Citation::Code {
                file_path: "x.py".into(),
                line_start: 1,
                line_end: 5,
            },
        )
        .unwrap();
    }

    /// A finding with only a "code" citation and no validation (uncertain
    /// verdict, no reproduced PoC) is still filtered out — it is not
    /// evidence-backed.
    #[test]
    fn unvalidated_code_only_finding_is_filtered_out() {
        let (_dir, conn, policy, eng) = fresh_with_policy();
        let f = mk_finding(eng, "F-5", Severity::High, Some(AdvocateVerdict::Uncertain), None);
        db::insert_finding(&conn, &f).unwrap();
        insert_code_citation(&conn, &f.id);

        let (_v, in_seed, filtered) =
            render(&conn, &policy, eng, "spec", &[f], &[], &[]).unwrap();
        assert_eq!(in_seed, 0);
        assert_eq!(filtered, 1);
    }

    /// A reproduced PoC admits a finding to the seed even without an analyzer
    /// citation — this is the chain-aware pattern_scout case (e.g. the Go SQLi
    /// the tracer surfaced and poc_forge reproduced natively).
    #[test]
    fn reproduced_poc_admits_finding_without_analyzer_citation() {
        let (_dir, conn, policy, eng) = fresh_with_policy();
        let f = mk_finding(
            eng,
            "F-6",
            Severity::High,
            Some(AdvocateVerdict::Uncertain),
            Some(PocStatus::Reproduced),
        );
        db::insert_finding(&conn, &f).unwrap();
        insert_code_citation(&conn, &f.id);

        let (_v, in_seed, filtered) =
            render(&conn, &policy, eng, "spec", &[f], &[], &[]).unwrap();
        assert_eq!(in_seed, 1);
        assert_eq!(filtered, 0);
    }

    /// A confirmed advocate verdict likewise admits a code-only finding (the
    /// cross-file authz/CWE-285 case).
    #[test]
    fn confirmed_verdict_admits_finding_without_analyzer_citation() {
        let (_dir, conn, policy, eng) = fresh_with_policy();
        let f = mk_finding(eng, "F-7", Severity::High, Some(AdvocateVerdict::Confirmed), None);
        db::insert_finding(&conn, &f).unwrap();
        insert_code_citation(&conn, &f.id);

        let (_v, in_seed, filtered) =
            render(&conn, &policy, eng, "spec", &[f], &[], &[]).unwrap();
        assert_eq!(in_seed, 1);
        assert_eq!(filtered, 0);
    }
}
