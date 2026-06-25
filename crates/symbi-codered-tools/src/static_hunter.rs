//! static_hunter orchestrator — the witness layer.
//!
//! Runs analyzers in language-specific scanner sidecars, normalizes their
//! output, attaches Citation::Analyzer to each derived Finding, and
//! Cedar-gates every store_finding through the citation.cedar / evidence.cedar
//! policies.
//!
//! Plan F (Group 4): scanner dispatch is language-aware. At hunt() entry we
//! read the engagement's detected `language` repo_facts and select the subset
//! of jobs in [`JOBS`] whose language matches. Jobs that share the same
//! (container, tool) — e.g., the TypeScript sidecar runs the same eslint
//! invocation regardless of whether the repo is tagged "typescript" or
//! "javascript" — are deduplicated so each sidecar is invoked at most once
//! per tool.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use cedar_policy::RestrictedExpression;
use chrono::Utc;
use rusqlite::Connection;
use serde_json::Value;
use thiserror::Error;
use uuid::Uuid;

use symbi_codered_core::audit;
use symbi_codered_core::db;
use symbi_codered_core::policy::PolicyEngine;
use symbi_evidence_schema::{
    Citation, Finding,
    evidence::{hex_sha256, EvidenceEnvelope},
    finding::{Confidence, Phase, Severity, Status},
};

use crate::scanner_client::{self, ScannerRequest};
use crate::scanner_parsers::{
    bandit, cargo_audit, checkov, clippy, compromised_packages, eslint, gosec, govulncheck,
    npm_audit, pip_audit, progpilot, ruff, semgrep, staticcheck, tfsec, trivy, RawFinding,
};

#[derive(Debug, Error)]
pub enum StaticHunterError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("db: {0}")]
    Db(#[from] db::DbError),
    #[error("audit: {0}")]
    Audit(#[from] symbi_codered_core::audit::AuditError),
    #[error("scanner_client: {0}")]
    ScannerClient(#[from] scanner_client::ScannerClientError),
    #[error("semgrep parse: {0}")]
    Semgrep(#[from] semgrep::SemgrepParseError),
    #[error("bandit parse: {0}")]
    Bandit(#[from] bandit::BanditParseError),
    #[error("pip-audit parse: {0}")]
    PipAudit(#[from] pip_audit::PipAuditParseError),
    #[error("ruff parse: {0}")]
    Ruff(#[from] ruff::RuffParseError),
    #[error("cargo-audit parse: {0}")]
    CargoAudit(#[from] cargo_audit::CargoAuditParseError),
    #[error("clippy parse: {0}")]
    Clippy(#[from] clippy::ClippyParseError),
    #[error("eslint parse: {0}")]
    Eslint(#[from] eslint::EslintParseError),
    #[error("npm-audit parse: {0}")]
    NpmAudit(#[from] npm_audit::NpmAuditParseError),
    #[error("gosec parse: {0}")]
    Gosec(#[from] gosec::GosecParseError),
    #[error("govulncheck parse: {0}")]
    Govulncheck(#[from] govulncheck::GovulncheckParseError),
    #[error("staticcheck parse: {0}")]
    Staticcheck(#[from] staticcheck::StaticcheckParseError),
    #[error("compromised-packages parse: {0}")]
    CompromisedPackages(#[from] compromised_packages::CompromisedPackagesParseError),
    #[error("checkov parse: {0}")]
    Checkov(#[from] checkov::CheckovParseError),
    #[error("tfsec parse: {0}")]
    Tfsec(#[from] tfsec::TfsecParseError),
    #[error("trivy parse: {0}")]
    Trivy(#[from] trivy::TrivyParseError),
    #[error("progpilot parse: {0}")]
    Progpilot(#[from] progpilot::ProgpilotParseError),
    #[error("missing threat model — call specifier first")]
    MissingThreatModel,
    #[error("policy: {0}")]
    Policy(String),
}

pub struct HuntInput {
    pub engagement_id: Uuid,
    pub target_in_container: String,
    /// Default sidecar container. Plan F overrides this per-language via the
    /// [`JOBS`] table; this field is retained for backward compatibility with
    /// callers (`codered hunt --scanner-container ...`) and shows up as the
    /// initial value before language dispatch overrides it.
    pub scanner_container: String,
    pub evidence_dir: String,
    pub journal_path: String,
    pub policy: Arc<PolicyEngine>,
}

pub struct HuntSummary {
    pub findings_inserted: usize,
    pub denied_by_cedar: usize,
    pub scanner_runs: usize,
    /// Scanners that returned a non-success exit code (e.g., semgrep
    /// failing to reach the registry, ruff failing on a read-only mount).
    /// Distinct from `denied_by_cedar`: this is a tool failure, not a
    /// policy denial.
    pub scanner_errors: usize,
    /// Number of language-specific (container, tool) jobs that ran after
    /// dedup. With Plan F this varies by detected languages.
    pub scanners_invoked: usize,
    /// Findings that were collapsed because another finding with the same
    /// (file_path, line_start, cwe-or-rule-id) was already inserted in this
    /// run. Almost always cross-tool duplicates (semgrep + ruff + bandit
    /// catching the same line) or within-tool duplicates (multiple semgrep
    /// rules firing on the same line).
    pub deduped: usize,
}

/// Single per-language scanner invocation. The table below is the full
/// matrix; dispatch filters by detected languages then dedupes on
/// `(container, tool)` so the same sidecar+tool is never invoked twice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScannerJob {
    pub language: &'static str,
    pub container: &'static str,
    pub tool: &'static str,
    pub phase: Phase,
}

pub const JOBS: &[ScannerJob] = &[
    // --- Python (Plan C baseline) --------------------------------------
    ScannerJob { language: "python", container: "symbi-codered-scanner-python", tool: "semgrep",   phase: Phase::Sast },
    ScannerJob { language: "python", container: "symbi-codered-scanner-python", tool: "bandit",    phase: Phase::Sast },
    ScannerJob { language: "python", container: "symbi-codered-scanner-python", tool: "ruff",      phase: Phase::Sast },
    ScannerJob { language: "python", container: "symbi-codered-scanner-python", tool: "pip_audit", phase: Phase::Deps },
    // --- Rust ----------------------------------------------------------
    ScannerJob { language: "rust", container: "symbi-codered-scanner-rust", tool: "cargo_audit", phase: Phase::Deps },
    ScannerJob { language: "rust", container: "symbi-codered-scanner-rust", tool: "clippy",      phase: Phase::Sast },
    ScannerJob { language: "rust", container: "symbi-codered-scanner-rust", tool: "semgrep",     phase: Phase::Sast },
    // --- TypeScript / JavaScript (same sidecar) ------------------------
    ScannerJob { language: "typescript", container: "symbi-codered-scanner-typescript", tool: "eslint",    phase: Phase::Sast },
    ScannerJob { language: "typescript", container: "symbi-codered-scanner-typescript", tool: "npm_audit", phase: Phase::Deps },
    ScannerJob { language: "typescript", container: "symbi-codered-scanner-typescript", tool: "semgrep",   phase: Phase::Sast },
    ScannerJob { language: "javascript", container: "symbi-codered-scanner-typescript", tool: "eslint",    phase: Phase::Sast },
    ScannerJob { language: "javascript", container: "symbi-codered-scanner-typescript", tool: "npm_audit", phase: Phase::Deps },
    ScannerJob { language: "javascript", container: "symbi-codered-scanner-typescript", tool: "semgrep",   phase: Phase::Sast },
    // --- Go ------------------------------------------------------------
    ScannerJob { language: "go", container: "symbi-codered-scanner-go", tool: "gosec",       phase: Phase::Sast },
    ScannerJob { language: "go", container: "symbi-codered-scanner-go", tool: "govulncheck", phase: Phase::Deps },
    ScannerJob { language: "go", container: "symbi-codered-scanner-go", tool: "staticcheck", phase: Phase::Sast },
    // --- Java ----------------------------------------------------------
    // semgrep carries the SAST surface (its java ruleset covers injection,
    // deserialization, XXE, SSRF, weak-crypto). Dependency CVEs and the
    // known-malicious package check run in the same sidecar over Maven/Gradle
    // manifests. (find-sec-bugs/spotbugs need compiled bytecode and are out
    // of scope for the source-only sidecar.)
    ScannerJob { language: "java", container: "symbi-codered-scanner-java", tool: "semgrep",              phase: Phase::Sast },
    ScannerJob { language: "java", container: "symbi-codered-scanner-java", tool: "compromised_packages", phase: Phase::Deps },
    // --- PHP -----------------------------------------------------------
    // semgrep php ruleset + Progpilot (PHP-native security taint) carry the
    // SAST surface; the compromised-packages check runs over composer
    // manifests. All source-only — no network, no vendor/autoload needed.
    ScannerJob { language: "php", container: "symbi-codered-scanner-php", tool: "semgrep",              phase: Phase::Sast },
    ScannerJob { language: "php", container: "symbi-codered-scanner-php", tool: "progpilot",            phase: Phase::Sast },
    ScannerJob { language: "php", container: "symbi-codered-scanner-php", tool: "compromised_packages", phase: Phase::Deps },
    // --- compromised_packages (jaschadub/compromised-packages-check) ---
    // Catches KNOWN-MALICIOUS package versions from supply-chain compromise
    // events. Distinct from pip_audit/cargo_audit/npm_audit which catch
    // known-VULNERABLE packages. Runs in every language sidecar that has a
    // matching lockfile parser; the script itself walks the repo and figures
    // out which manifests to scan.
    ScannerJob { language: "python",     container: "symbi-codered-scanner-python",     tool: "compromised_packages", phase: Phase::Deps },
    ScannerJob { language: "rust",       container: "symbi-codered-scanner-rust",       tool: "compromised_packages", phase: Phase::Deps },
    ScannerJob { language: "typescript", container: "symbi-codered-scanner-typescript", tool: "compromised_packages", phase: Phase::Deps },
    ScannerJob { language: "javascript", container: "symbi-codered-scanner-typescript", tool: "compromised_packages", phase: Phase::Deps },
    // --- IaC sidecar (checkov / tfsec / trivy) -------------------------
    // All three run inside one IaC sidecar; carto signals the iac
    // language whenever it sees terraform / kubernetes / helm /
    // dockerfile / github-actions files. Phases:
    //   - checkov, tfsec → SAST-style policy violations on declarative IaC.
    //   - trivy combines container-image vuln scanning + IaC misconfig +
    //     secret detection; we run it in the same Sast bucket because
    //     misconfigs dominate; vuln results still ride along.
    ScannerJob { language: "iac", container: "symbi-codered-scanner-iac", tool: "checkov", phase: Phase::Sast },
    // tfsec is dropped from the JOBS table — it panics on real-world
    // Terraform with `defsec` "value is unknown" errors during S3 bucket
    // adaptation, and the upstream project has been superseded by trivy
    // ("tfsec is joining the Trivy family", per its own deprecation
    // banner). trivy fs --scanners misconfig covers the same surface.
    // Binary still installed in the iac sidecar so an operator can
    // invoke it manually if needed; just no JOBS row.
    ScannerJob { language: "iac", container: "symbi-codered-scanner-iac", tool: "trivy",   phase: Phase::Sast },
];

/// Filter [`JOBS`] to the detected languages and deduplicate by
/// `(container, tool)` so e.g. a polyglot TS+JS repo runs eslint once, not
/// twice. Pure function so unit tests can exercise the matrix without
/// docker or a SQLite connection.
pub fn select_jobs(detected: &HashSet<String>) -> Vec<&'static ScannerJob> {
    let mut seen: HashSet<(&'static str, &'static str)> = HashSet::new();
    let mut out = Vec::new();
    for job in JOBS {
        if !detected.contains(job.language) {
            continue;
        }
        if seen.insert((job.container, job.tool)) {
            out.push(job);
        }
    }
    out
}

/// Read engagement `language` repo_facts and collect the JSON `name` of each
/// into a set. Mirrors `specifier::draft_threat_model`'s parsing path so
/// hunt() and specifier() agree on which languages are "detected".
fn detected_languages(
    conn: &Connection,
    engagement_id: Uuid,
) -> Result<HashSet<String>, StaticHunterError> {
    let rows = db::list_repo_facts(conn, engagement_id, "language")?;
    Ok(rows
        .iter()
        .filter_map(|row| {
            let v: Value = serde_json::from_str(row).ok()?;
            v.get("name").and_then(|n| n.as_str()).map(String::from)
        })
        .collect())
}

pub fn hunt(conn: &Connection, input: &HuntInput) -> Result<HuntSummary, StaticHunterError> {
    let specifier_hash: String = conn
        .query_row(
            "SELECT specifier_hash FROM threat_models WHERE engagement_id = ?1 \
             ORDER BY signed_at DESC LIMIT 1",
            rusqlite::params![input.engagement_id.to_string()],
            |r| r.get(0),
        )
        .map_err(|_| StaticHunterError::MissingThreatModel)?;

    let mut summary = HuntSummary {
        findings_inserted: 0,
        denied_by_cedar: 0,
        scanner_runs: 0,
        scanner_errors: 0,
        scanners_invoked: 0,
        deduped: 0,
    };

    let detected = detected_languages(conn, input.engagement_id)?;
    let jobs = select_jobs(&detected);
    summary.scanners_invoked = jobs.len();

    std::fs::create_dir_all(&input.evidence_dir)?;

    // Counter for ID generation that increments for EVERY raw finding seen,
    // independent of Cedar's allow/deny verdict. The previous formula used
    // `summary.findings_inserted + idx`, which left gaps when findings were
    // denied — and because multiple jobs share the same tool name (e.g.,
    // semgrep runs for python/rust/typescript/javascript), the next job could
    // re-issue an ID a denied finding had already taken, blowing up the
    // UNIQUE constraint on findings.id.
    let mut total_seen: usize = 0;

    // Cross-job dedup set. The same vulnerability often surfaces under
    // multiple scanners (semgrep + bandit + ruff all flag subprocess shell
    // injection) AND under multiple semgrep rules on the same line. Collapse
    // by (file_path, line_start, cwe_or_rule). When cwe is present it's the
    // stable cross-tool key; when absent we fall back to rule_id so two
    // distinct rules on the same line don't merge.
    let mut seen_keys: std::collections::HashSet<(String, u32, String)> =
        std::collections::HashSet::new();

    for job in jobs {
        let resp = scanner_client::run_scanner(
            job.container,
            &ScannerRequest {
                tool: job.tool.to_string(),
                target_dir: input.target_in_container.clone(),
                extra_args: vec![],
            },
        )?;
        summary.scanner_runs += 1;

        // Plan C uses static Rust-side enforcement: tool-authorization.cedar
        // permits static_hunter to invoke analyzer tools (resource.type ==
        // "Audit::StaticHunter"). Per-call PolicyEngine::evaluate() with
        // attribute-bearing entities is deferred to Plan E. Label scanner
        // exit failures as "error" (not "deny") to keep cedar_decision
        // honest about what was actually checked.
        let decision = if resp.ok { "permit" } else { "error" };
        audit::append_entry(
            &input.journal_path,
            "static_hunter",
            "execute_tool",
            format!("Audit::StaticHunter/{}", job.tool),
            decision,
            None,
        )?;

        if !resp.ok {
            summary.scanner_errors += 1;
            continue;
        }

        // Serialize the most informative payload for the evidence envelope.
        // raw_json (when the scanner runner pre-parsed it) is preferred so the
        // envelope stays canonical JSON; otherwise wrap the raw stdout as a
        // string (used for clippy/govulncheck/staticcheck NDJSON output).
        let envelope_payload = resp
            .raw_json
            .clone()
            .unwrap_or_else(|| Value::String(resp.stdout.clone()));
        let envelope_bytes = serde_json::to_vec_pretty(&envelope_payload)?;
        let scan_id = format!("S-{}", &input.engagement_id.simple().to_string()[..8]);
        let envelope = EvidenceEnvelope {
            scan_id: scan_id.clone(),
            tool: job.tool.to_string(),
            content_type: "application/json".into(),
            bytes: envelope_bytes.clone(),
        };
        let envelope_id = envelope.envelope_id();
        let evidence_path = format!("{}/{}.json", input.evidence_dir, envelope_id);
        std::fs::write(&evidence_path, &envelope_bytes)?;
        conn.execute(
            "INSERT OR IGNORE INTO evidence (envelope_id, sha256, path, content_type, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                &envelope_id,
                hex_sha256(&envelope_bytes),
                &evidence_path,
                "application/json",
                Utc::now().to_rfc3339(),
            ],
        ).map_err(db::DbError::Sqlite)?;

        // Per-tool parser dispatch. The Plan F additions are clippy /
        // govulncheck / staticcheck which carry their NDJSON in `stdout`
        // (raw_json is None) — wrap as Value::String for clippy (its parser
        // accepts that shape) and pass the &str directly to the others.
        let raw_findings: Vec<RawFinding> = match (job.tool, resp.raw_json.as_ref()) {
            // Python
            ("semgrep",   Some(j)) => semgrep::parse(j)?,
            ("bandit",    Some(j)) => bandit::parse(j)?,
            ("pip_audit", Some(j)) => pip_audit::parse(j)?,
            ("ruff",      Some(j)) => ruff::parse(j)?,
            // Rust
            ("cargo_audit", Some(j)) => cargo_audit::parse(j)?,
            ("clippy", _) => {
                let stdout = resp.stdout.clone();
                if stdout.trim().is_empty() {
                    Vec::new()
                } else {
                    clippy::parse(&Value::String(stdout))?
                }
            }
            // TypeScript / JavaScript
            ("eslint",    Some(j)) => eslint::parse(j)?,
            ("npm_audit", Some(j)) => npm_audit::parse(j)?,
            // Go
            ("gosec",       Some(j)) => gosec::parse(j)?,
            ("govulncheck", _) => {
                if resp.stdout.trim().is_empty() {
                    Vec::new()
                } else {
                    govulncheck::parse(&resp.stdout)?
                }
            }
            ("staticcheck", _) => {
                if resp.stdout.trim().is_empty() {
                    Vec::new()
                } else {
                    staticcheck::parse(&resp.stdout)?
                }
            }
            // compromised-packages-check (jaschadub) — text output, parsed
            // line-by-line. Empty stdout (no hits, exit 0) is the common
            // case and yields zero findings.
            ("compromised_packages", _) => {
                if resp.stdout.trim().is_empty() {
                    Vec::new()
                } else {
                    compromised_packages::parse(&resp.stdout)?
                }
            }
            // IaC sidecar: each tool emits a single JSON document.
            ("checkov",    Some(j)) => checkov::parse(j)?,
            ("tfsec",      Some(j)) => tfsec::parse(j)?,
            ("trivy",      Some(j)) => trivy::parse(j)?,
            // PHP: Progpilot emits a JSON array.
            ("progpilot",  Some(j)) => progpilot::parse(j)?,
            _ => Vec::new(),
        };

        for (idx, rf) in raw_findings.iter().enumerate() {
            // Dedup before allocating a finding_id so collapsed duplicates
            // don't consume id-counter slots. Key strategy:
            //   - Code-line findings (line_start > 0): prefer CWE so two
            //     scanners flagging the same line for the same weakness
            //     class collapse to one finding.
            //   - Dep/whole-file findings (line_start == 0, e.g. pip_audit,
            //     compromised_packages): use rule_id, because multiple
            //     distinct dependency hits naturally share file_path and
            //     CWE — dedup by CWE would incorrectly collapse them.
            let dedup_discriminator = if rf.line_start == 0 {
                rf.rule_id.clone()
            } else {
                rf.cwe.clone().unwrap_or_else(|| rf.rule_id.clone())
            };
            let dedup_key = (
                rf.file_path.clone(),
                rf.line_start,
                dedup_discriminator,
            );
            if !seen_keys.insert(dedup_key) {
                summary.deduped += 1;
                continue;
            }

            let finding_id = format!("F-{}-{:04}", job.tool, total_seen + idx);
            let f = Finding {
                id: finding_id.clone(),
                engagement_id: input.engagement_id,
                phase: job.phase,
                severity: parse_severity(&rf.severity),
                confidence: parse_confidence(&rf.confidence),
                cwe: rf.cwe.clone(),
                owasp: rf.owasp.clone(),
                file_path: rf.file_path.clone(),
                line_start: rf.line_start,
                line_end: rf.line_end,
                title: rf.title.clone(),
                description: rf.description.clone(),
                reachable: None,
                exploitable: None,
                evidence_envelope_id: envelope_id.clone(),
                status: Status::Open,
                rank_score: None,
                specifier_hash: Some(specifier_hash.clone()),
                advocate_verdict: None,
                tool_origin: Some(job.tool.to_string()),
                poc_status: None,
                created_at: Utc::now(),
            };

            // Citation::Analyzer per the witness/lawyer rule.
            let citation = Citation::Analyzer { finding_id: rf.rule_id.clone() };

            // Cedar gate: attach the analyzer citation type on the Finding
            // resource so citation.cedar's forbid-unless rule is satisfied,
            // and surface the other Finding attrs evidence.cedar inspects
            // (specifier_hash presence, non-empty evidence_envelope_id).
            // Then run the combined permit + forbid policy set.
            let mut attrs = HashMap::new();
            attrs.insert(
                "citations".to_string(),
                RestrictedExpression::new_set(vec![
                    RestrictedExpression::new_string("analyzer".to_string()),
                ]),
            );
            if let Some(sh) = &f.specifier_hash {
                attrs.insert(
                    "specifier_hash".to_string(),
                    RestrictedExpression::new_string(sh.clone()),
                );
            }
            attrs.insert(
                "evidence_envelope_id".to_string(),
                RestrictedExpression::new_string(f.evidence_envelope_id.clone()),
            );
            let resource_uid = format!(r#"Finding::"{}""#, f.id);
            let (decision, diag) = input
                .policy
                .evaluate_with_attrs(
                    r#"Agent::"static_hunter""#,
                    r#"Action::"store_finding""#,
                    &resource_uid,
                    attrs,
                )
                .map_err(|e| StaticHunterError::Policy(e.to_string()))?;

            if decision != cedar_policy::Decision::Allow {
                audit::append_entry(
                    &input.journal_path,
                    "static_hunter",
                    "store_finding",
                    resource_uid.clone(),
                    "deny",
                    None,
                )?;
                summary.denied_by_cedar += 1;
                tracing::warn!(
                    finding_id = %f.id,
                    reason = ?diag.primary_reason(),
                    "static_hunter store_finding denied by Cedar"
                );
                continue;
            }

            db::insert_finding(conn, &f)?;
            db::insert_finding_citation(conn, &f.id, &citation)?;
            summary.findings_inserted += 1;
        }
        total_seen += raw_findings.len();
    }

    Ok(summary)
}

fn parse_severity(s: &str) -> Severity {
    match s {
        "critical" => Severity::Critical,
        "high"     => Severity::High,
        "medium"   => Severity::Medium,
        "low"      => Severity::Low,
        _          => Severity::Info,
    }
}

fn parse_confidence(s: &str) -> Confidence {
    match s {
        "high"   => Confidence::High,
        "medium" => Confidence::Medium,
        _        => Confidence::Low,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lang_set<I: IntoIterator<Item = &'static str>>(it: I) -> HashSet<String> {
        it.into_iter().map(String::from).collect()
    }

    fn job_keys(jobs: &[&ScannerJob]) -> Vec<(&'static str, &'static str)> {
        jobs.iter().map(|j| (j.container, j.tool)).collect()
    }

    #[test]
    fn python_only_repo_dispatches_five_python_scanners() {
        let jobs = select_jobs(&lang_set(["python"]));
        assert_eq!(jobs.len(), 5);
        let keys = job_keys(&jobs);
        assert!(keys.contains(&("symbi-codered-scanner-python", "semgrep")));
        assert!(keys.contains(&("symbi-codered-scanner-python", "bandit")));
        assert!(keys.contains(&("symbi-codered-scanner-python", "ruff")));
        assert!(keys.contains(&("symbi-codered-scanner-python", "pip_audit")));
        assert!(keys.contains(&("symbi-codered-scanner-python", "compromised_packages")));
        // No other sidecar should be touched.
        assert!(jobs.iter().all(|j| j.container == "symbi-codered-scanner-python"));
    }

    #[test]
    fn rust_only_repo_dispatches_four_rust_scanners() {
        let jobs = select_jobs(&lang_set(["rust"]));
        assert_eq!(jobs.len(), 4);
        let keys = job_keys(&jobs);
        assert!(keys.contains(&("symbi-codered-scanner-rust", "cargo_audit")));
        assert!(keys.contains(&("symbi-codered-scanner-rust", "clippy")));
        assert!(keys.contains(&("symbi-codered-scanner-rust", "semgrep")));
        assert!(keys.contains(&("symbi-codered-scanner-rust", "compromised_packages")));
    }

    #[test]
    fn polyglot_python_plus_rust_dispatches_nine_scanners() {
        let jobs = select_jobs(&lang_set(["python", "rust"]));
        assert_eq!(jobs.len(), 9);
        // Per-container counts.
        let py_count = jobs.iter().filter(|j| j.container == "symbi-codered-scanner-python").count();
        let rs_count = jobs.iter().filter(|j| j.container == "symbi-codered-scanner-rust").count();
        assert_eq!(py_count, 5);
        assert_eq!(rs_count, 4);
    }

    #[test]
    fn typescript_plus_javascript_dedup_to_four_scanners() {
        // Both languages share the typescript sidecar with the same tool
        // matrix; dedup must collapse the 8 candidate rows to 4.
        let jobs = select_jobs(&lang_set(["typescript", "javascript"]));
        assert_eq!(jobs.len(), 4);
        let keys = job_keys(&jobs);
        assert!(keys.contains(&("symbi-codered-scanner-typescript", "eslint")));
        assert!(keys.contains(&("symbi-codered-scanner-typescript", "npm_audit")));
        assert!(keys.contains(&("symbi-codered-scanner-typescript", "semgrep")));
        assert!(keys.contains(&("symbi-codered-scanner-typescript", "compromised_packages")));
    }

    #[test]
    fn go_only_repo_dispatches_three_go_scanners() {
        let jobs = select_jobs(&lang_set(["go"]));
        assert_eq!(jobs.len(), 3);
        assert!(jobs.iter().all(|j| j.container == "symbi-codered-scanner-go"));
    }

    #[test]
    fn java_only_repo_dispatches_two_java_scanners() {
        let jobs = select_jobs(&lang_set(["java"]));
        assert_eq!(jobs.len(), 2);
        let keys = job_keys(&jobs);
        assert!(keys.contains(&("symbi-codered-scanner-java", "semgrep")));
        assert!(keys.contains(&("symbi-codered-scanner-java", "compromised_packages")));
        assert!(jobs.iter().all(|j| j.container == "symbi-codered-scanner-java"));
    }

    #[test]
    fn iac_only_repo_dispatches_two_iac_scanners() {
        // tfsec is intentionally not in the JOBS table — it panics on
        // real-world terraform; trivy covers the same surface.
        let jobs = select_jobs(&lang_set(["iac"]));
        assert_eq!(jobs.len(), 2);
        let keys = job_keys(&jobs);
        assert!(keys.contains(&("symbi-codered-scanner-iac", "checkov")));
        assert!(keys.contains(&("symbi-codered-scanner-iac", "trivy")));
        assert!(jobs.iter().all(|j| j.container == "symbi-codered-scanner-iac"));
    }

    #[test]
    fn php_only_repo_dispatches_three_php_scanners() {
        let jobs = select_jobs(&lang_set(["php"]));
        assert_eq!(jobs.len(), 3);
        let keys = job_keys(&jobs);
        assert!(keys.contains(&("symbi-codered-scanner-php", "semgrep")));
        assert!(keys.contains(&("symbi-codered-scanner-php", "progpilot")));
        assert!(keys.contains(&("symbi-codered-scanner-php", "compromised_packages")));
        assert!(jobs.iter().all(|j| j.container == "symbi-codered-scanner-php"));
    }

    #[test]
    fn unknown_language_produces_no_jobs() {
        let jobs = select_jobs(&lang_set(["cobol"]));
        assert!(jobs.is_empty());
    }

    #[test]
    fn phase_carries_through_filter() {
        // pip_audit/cargo_audit/npm_audit/govulncheck are Deps; everything
        // else is Sast. Spot-check the mapping survives selection.
        let jobs = select_jobs(&lang_set(["python", "rust", "typescript", "go"]));
        for j in &jobs {
            let expected = match j.tool {
                "pip_audit" | "cargo_audit" | "npm_audit" | "govulncheck"
                | "compromised_packages" => Phase::Deps,
                _ => Phase::Sast,
            };
            assert_eq!(j.phase, expected, "tool {} phase mismatch", j.tool);
        }
    }
}
