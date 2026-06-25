//! codered's deliverable generator: SARIF + Markdown + engagement-seed.json.
//!
//! Deterministic; no LLM. Plan G design doc §5. The three renderers live in
//! sibling modules (`sarif`, `markdown`, `seed`); `generate_all` orchestrates
//! them, signs the seed with the engagement Ed25519 key, writes the three
//! files to `<output_dir>/<engagement_id>/<UTC-timestamp>/`, and appends a
//! journal entry. A `latest` symlink in `<output_dir>/<engagement_id>/`
//! always points at the most-recent run.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use rusqlite::params;
use serde_json::Value;
use uuid::Uuid;

use symbi_codered_core::audit;
use symbi_codered_core::db;
use symbi_codered_core::policy::PolicyEngine;
use symbi_codered_core::signing;

pub mod sarif;
pub mod markdown;
pub mod seed;

/// All the inputs `generate_all` needs to produce the three reports.
pub struct ReportInput {
    pub engagement_id: Uuid,
    pub db_path: PathBuf,
    pub policy: Arc<PolicyEngine>,
    pub output_dir: PathBuf,
    pub journal_path: PathBuf,
    /// Optional override for the Ed25519 keys directory. `None` uses the
    /// default `.symbiont/keys/` resolved via `signing::load`. Tests pass
    /// `Some(tmp_dir)` to avoid mutating cwd.
    pub signing_keys_dir: Option<PathBuf>,
}

/// Counters + paths returned by `generate_all` for the CLI summary line.
pub struct ReportSummary {
    pub sarif_path: PathBuf,
    pub markdown_path: PathBuf,
    pub seed_path: PathBuf,
    pub findings_in_seed: usize,
    pub findings_filtered: usize,
}

/// Generate all three deliverables in `<output_dir>/<engagement_id>/`.
///
/// 1. Open DB; read engagement + threat_model (specifier_hash + signed_at).
/// 2. Read findings, attack_chains, knowledge_triples.
/// 3. Render SARIF, Markdown, seed JSON.
/// 4. Sign canonical bytes of the seed (signature field empty) with the
///    engagement's Ed25519 key; re-insert the signature.
/// 5. Write the 3 files. Append one journal entry (principal "reporter",
///    action "generate_report").
pub fn generate_all(input: ReportInput) -> Result<ReportSummary> {
    let ReportInput {
        engagement_id,
        db_path,
        policy,
        output_dir,
        journal_path,
        signing_keys_dir,
    } = input;

    // 1. Open DB + load engagement / threat_model.
    let conn = db::init_db(db_path.to_str().context("db path not utf-8")?)
        .with_context(|| format!("opening {}", db_path.display()))?;
    let _engagement = db::get_engagement(&conn, engagement_id)?
        .with_context(|| format!("engagement {engagement_id} not found"))?;

    let (specifier_hash, signed_at) = read_threat_model(&conn, engagement_id)?;

    // 2. Read findings, chains, triples.
    let findings = db::list_findings_for(&conn, engagement_id)
        .context("listing findings")?;
    let attack_chains = db::list_attack_chains_for(&conn, engagement_id)
        .context("listing attack_chains")?;
    let triples = db::list_all_knowledge_triples_for(&conn, engagement_id)
        .context("listing knowledge_triples")?;

    // 3. Render the three deliverables.
    let sarif_value = sarif::render(&findings, &engagement_id.to_string(), &specifier_hash);
    let markdown_str = markdown::render(
        &engagement_id.to_string(),
        &specifier_hash,
        &signed_at,
        &findings,
        &attack_chains,
        &triples,
    );
    let (mut seed_value, in_seed, filtered) = seed::render(
        &conn,
        &policy,
        engagement_id,
        &specifier_hash,
        &findings,
        &attack_chains,
        &triples,
    )
    .context("rendering engagement-seed")?;

    // 4. Sign canonical bytes (signature field empty) and re-insert.
    let canonical = serde_json::to_string(&seed_value)
        .context("canonical-serialising seed for signing")?;
    let keypair = match signing_keys_dir {
        Some(dir) => signing::load_from(&dir, engagement_id),
        None => signing::load(engagement_id),
    }
    .with_context(|| {
        format!(
            "loading engagement signing key for {engagement_id}; \
             run `codered specifier` first"
        )
    })?;
    let signature_hex = keypair.sign_hex(canonical.as_bytes());
    if let Some(obj) = seed_value.as_object_mut() {
        obj.insert("signature".into(), Value::String(signature_hex));
    }

    // 5. Write the three files under output_dir/<engagement_id>/<UTC-stamp>/
    //    so successive runs against the same engagement don't clobber each
    //    other. Stamp is `YYYY-MM-DDTHH-MM-SSZ` — colons replaced with `-`
    //    because Windows file systems can't have ':' in paths and we
    //    sometimes ship deliverables off-box. A symlink `latest` is
    //    refreshed to point at the newest run for convenience.
    let stamp = chrono::Utc::now().format("%Y-%m-%dT%H-%M-%SZ").to_string();
    let engagement_dir = output_dir.join(engagement_id.to_string());
    let report_dir = engagement_dir.join(&stamp);
    std::fs::create_dir_all(&report_dir)
        .with_context(|| format!("creating {}", report_dir.display()))?;

    let latest_link = engagement_dir.join("latest");
    let _ = std::fs::remove_file(&latest_link);
    #[cfg(unix)]
    {
        if let Err(e) = std::os::unix::fs::symlink(&stamp, &latest_link) {
            tracing::warn!("could not refresh latest symlink at {}: {e}", latest_link.display());
        }
    }

    let sarif_path = report_dir.join("findings.sarif");
    let markdown_path = report_dir.join("report.md");
    let seed_path = report_dir.join("engagement-seed.json");

    let sarif_pretty = serde_json::to_string_pretty(&sarif_value)
        .context("pretty-serialising SARIF")?;
    std::fs::write(&sarif_path, sarif_pretty)
        .with_context(|| format!("writing {}", sarif_path.display()))?;

    std::fs::write(&markdown_path, &markdown_str)
        .with_context(|| format!("writing {}", markdown_path.display()))?;

    let seed_pretty = serde_json::to_string_pretty(&seed_value)
        .context("pretty-serialising seed")?;
    std::fs::write(&seed_path, seed_pretty)
        .with_context(|| format!("writing {}", seed_path.display()))?;

    // 6. Append one journal entry; failure to write the journal is a hard
    //    error (the report itself is the audit trail's witness).
    audit::append_entry(
        &journal_path,
        "reporter",
        "generate_report",
        format!(r#"Report::"{engagement_id}""#),
        "permit",
        None,
    )
    .with_context(|| format!("appending journal entry to {}", journal_path.display()))?;

    Ok(ReportSummary {
        sarif_path,
        markdown_path,
        seed_path,
        findings_in_seed: in_seed,
        findings_filtered: filtered,
    })
}

/// Pull `(specifier_hash, signed_at)` for the most-recently-signed threat
/// model on this engagement. Reporter requires it (specifier_hash is the
/// reproducibility anchor); missing row is a hard error.
fn read_threat_model(
    conn: &rusqlite::Connection,
    engagement_id: Uuid,
) -> Result<(String, String)> {
    let mut stmt = conn
        .prepare(
            "SELECT specifier_hash, signed_at FROM threat_models
             WHERE engagement_id = ?1
             ORDER BY signed_at DESC LIMIT 1",
        )
        .context("preparing threat_model query")?;
    let mut rows = stmt
        .query(params![engagement_id.to_string()])
        .context("executing threat_model query")?;
    let row = rows
        .next()
        .context("threat_model query failed")?
        .with_context(|| {
            format!(
                "no threat_model found for engagement {engagement_id}; \
                 run `codered specifier` first"
            )
        })?;
    let hash: String = row.get(0)?;
    let signed_at: String = row.get(1)?;
    Ok((hash, signed_at))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use symbi_codered_core::signing as core_signing;
    use symbi_evidence_schema::finding::{
        AdvocateVerdict, Confidence, Phase, PocStatus, Severity, Status,
    };
    use symbi_evidence_schema::{
        AttackChainNode, Citation, Engagement, Finding, KillChainStage, ThreatModel,
    };
    use tempfile::TempDir;

    fn mk_finding(eng: Uuid) -> Finding {
        Finding {
            id: "F-pattern-scout-0001".into(),
            engagement_id: eng,
            phase: Phase::Sast,
            severity: Severity::High,
            confidence: Confidence::High,
            cwe: Some("CWE-89".into()),
            owasp: None,
            file_path: "app/users.py".into(),
            line_start: 88,
            line_end: 92,
            title: "SQLi via sort".into(),
            description: "...".into(),
            reachable: Some(true),
            exploitable: None,
            evidence_envelope_id: "env-1".into(),
            status: Status::Open,
            rank_score: Some(0.9),
            specifier_hash: Some("h".into()),
            advocate_verdict: Some(AdvocateVerdict::Confirmed),
            tool_origin: Some("semgrep".into()),
            poc_status: Some(PocStatus::Reproduced),
            created_at: Utc::now(),
        }
    }

    fn mk_chain(eng: Uuid) -> AttackChainNode {
        AttackChainNode {
            id: "AC-0001".into(),
            engagement_id: eng,
            stage: KillChainStage::SurfaceMapping,
            finding_id: Some("F-pattern-scout-0001".into()),
            evidence_id: None,
            next_chain_id: None,
            rationale: "Surface enumerated".into(),
            created_at: Utc::now(),
        }
    }

    #[test]
    fn generate_all_writes_three_files_and_signs_seed() {
        let tmp = TempDir::new().unwrap();
        let db_path = tmp.path().join("test.db");
        let conn = db::init_db(db_path.to_str().unwrap()).unwrap();

        // Engagement + signing key + threat_model + a Finding-with-citation + a chain.
        let e = Engagement::new("acme", "h", "2026-05-22", "2026-05-29");
        let eng = e.id;
        db::insert_engagement(&conn, &e).unwrap();

        let keys_dir = tmp.path().join("keys");
        core_signing::generate_and_persist_in(&keys_dir, eng).unwrap();

        let canonical_tm = r#"{"engagement_id":"x","scope":["src/**"]}"#;
        let tm = ThreatModel {
            specifier_hash: ThreatModel::hash_for(canonical_tm),
            engagement_id: eng,
            canonical_json: canonical_tm.into(),
            signed_at: Utc::now(),
            signature: "sig".into(),
        };
        db::insert_threat_model(&conn, &tm).unwrap();

        let f = mk_finding(eng);
        db::insert_finding(&conn, &f).unwrap();
        db::insert_finding_citation(
            &conn,
            &f.id,
            &Citation::Analyzer {
                finding_id: "F-src".into(),
            },
        )
        .unwrap();

        let chain = mk_chain(eng);
        db::insert_attack_chain_node(&conn, &chain).unwrap();

        drop(conn);

        // Absolute policies path resolved at compile time — cwd-independent.
        let policies = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../policies");
        let policy = Arc::new(PolicyEngine::from_dir(policies).unwrap());

        let output_dir = tmp.path().join("reports");
        let journal_path = tmp.path().join("audit.jsonl");

        let summary = generate_all(ReportInput {
            engagement_id: eng,
            db_path,
            policy,
            output_dir: output_dir.clone(),
            journal_path: journal_path.clone(),
            signing_keys_dir: Some(keys_dir),
        })
        .expect("generate_all should succeed");

        assert!(summary.sarif_path.exists());
        assert!(summary.markdown_path.exists());
        assert!(summary.seed_path.exists());
        assert_eq!(summary.findings_in_seed, 1);
        assert_eq!(summary.findings_filtered, 0);

        let seed_str = std::fs::read_to_string(&summary.seed_path).unwrap();
        let seed_json: Value = serde_json::from_str(&seed_str).unwrap();
        let sig = seed_json["signature"].as_str().unwrap();
        assert!(!sig.is_empty(), "signature field must be populated");
        assert_eq!(sig.len(), 128, "ed25519 hex sig is 64 bytes / 128 chars");
        assert_eq!(seed_json["engagement_id"], eng.to_string());
        assert_eq!(seed_json["findings"].as_array().unwrap().len(), 1);

        let journal_text = std::fs::read_to_string(&journal_path).unwrap();
        assert!(journal_text.contains("generate_report"));
        assert!(journal_text.contains("reporter"));
    }
}
