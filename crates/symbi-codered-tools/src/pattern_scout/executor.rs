//! Pattern_scout's ORGA `ActionExecutor`.
//!
//! Plan D Task 17: real dispatchers for the six tools pattern_scout calls
//! through `read_context_range`, `query_threat_model`, `query_findings`,
//! `query_taint_chains`, `hypothesis_repl`, and `store_finding`. Every
//! `store_finding` is Cedar-gated through `PolicyEngine::evaluate_with_attrs`
//! against the agent's `citations` / `specifier_hash` /
//! `evidence_envelope_id` attributes.
//!
//! Symbiont's `ActionExecutor` trait has BATCH semantics — see
//! `symbi_runtime::reasoning::executor::ActionExecutor`. We accept a slice
//! of `ProposedAction` and return one `Observation` per `ToolCall` action.
//! Non-tool actions (Respond / Delegate / Terminate) are ignored, matching
//! the behavior of `DefaultActionExecutor`.
//!
//! `hypothesis_repl` is wired through to [`crate::hypothesis_repl::run`]
//! (Plan D Task 19). The sub-context returns `{verdict,
//! transcript_envelope_id}` to the parent agent; an empty `hypothesis_text`
//! is rejected before the sub-context spins up.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use cedar_policy::{Decision, RestrictedExpression};
use chrono::Utc;
use rusqlite::Connection;
use serde_json::{json, Value};
use uuid::Uuid;

use symbi_codered_core::audit;
use symbi_codered_core::db;
use symbi_codered_core::policy::PolicyEngine;
use symbi_evidence_schema::{
    evidence::{hex_sha256, EvidenceEnvelope},
    finding::{Confidence, Phase, Severity, Status},
    Citation, Finding,
};
use symbi_runtime::reasoning::circuit_breaker::CircuitBreakerRegistry;
use symbi_runtime::reasoning::executor::ActionExecutor;
use symbi_runtime::reasoning::loop_types::{LoopConfig, Observation, ProposedAction};

use crate::pattern_scout_tools;

/// Per-run counters reported back to the caller after the loop terminates.
#[derive(Default)]
pub struct ScoutSummaryInner {
    pub findings_inserted: usize,
    pub denied_by_cedar: usize,
    pub tool_calls: usize,
    /// Consecutive read-class tool calls (query_*/read_context_range)
    /// since the last store_finding. Drives the analysis-paralysis
    /// watchdog: scout tends to read source endlessly without ever
    /// committing a finding, so once this crosses a threshold we nudge
    /// it (deterministically, in the tool result) to store now.
    pub reads_since_store: usize,
}

/// After this many consecutive read-class calls without a store_finding,
/// the read tool's result is prefixed with a directive to store. Chosen
/// empirically: scout needs ~3-5 reads to investigate one unguarded
/// chain (sink + 1-2 siblings); 6 gives margin for one deeper dig before
/// the nudge fires.
const READS_BEFORE_STORE_NUDGE: usize = 6;

/// `ActionExecutor` for pattern_scout. Dispatches each tool call to a
/// helper in [`crate::pattern_scout_tools`] or to the local
/// [`do_store_finding`] / [`do_hypothesis_repl`] handlers.
///
/// The runner (see `super::run`) keeps an `Arc` to this executor so it can
/// read the `summary()` after `CoderedOrga::run` completes.
pub struct PatternScoutExecutor {
    pub engagement_id: Uuid,
    pub db_path: PathBuf,
    pub journal_path: PathBuf,
    pub target_repo: PathBuf,
    pub policy: Arc<PolicyEngine>,
    pub state: Mutex<ScoutSummaryInner>,
}

impl PatternScoutExecutor {
    pub fn new(
        engagement_id: Uuid,
        db_path: PathBuf,
        journal_path: PathBuf,
        target_repo: PathBuf,
        policy: Arc<PolicyEngine>,
    ) -> Self {
        Self {
            engagement_id,
            db_path,
            journal_path,
            target_repo,
            policy,
            state: Mutex::new(ScoutSummaryInner::default()),
        }
    }

    /// Snapshot the per-run counters into the public `ScoutSummary` type.
    pub fn summary(&self) -> super::ScoutSummary {
        let s = self.state.lock().expect("scout summary mutex poisoned");
        super::ScoutSummary {
            findings_inserted: s.findings_inserted,
            denied_by_cedar: s.denied_by_cedar,
            tool_calls: s.tool_calls,
            tokens_in: 0,
            tokens_out: 0,
            iterations: 0,
        }
    }

    /// Verify a cited `file_path` resolves to an existing regular file inside
    /// `target_repo`. Reuses the same path-escape guard as
    /// `read_context_range` (canonicalize + containment); canonicalize also
    /// fails when the path does not exist, which is exactly the hallucination
    /// case we want to reject.
    fn verify_file_in_target(&self, file_path: &str) -> Result<(), String> {
        let joined = self.target_repo.join(file_path);
        let resolved = resolve_within(&self.target_repo, &joined)?;
        if resolved.is_file() {
            Ok(())
        } else {
            Err(format!("not a regular file: {}", resolved.display()))
        }
    }

    fn open_conn(&self) -> Result<Connection, String> {
        let path = self
            .db_path
            .to_str()
            .ok_or_else(|| format!("non-UTF8 db_path: {:?}", self.db_path))?;
        db::init_db(path).map_err(|e| format!("db open: {e}"))
    }

    /// `query_threat_model` returns `Option<Value>` — `Ok(None)` becomes a
    /// JSON `null` for the agent.
    fn do_query_threat_model(&self) -> Observation {
        let conn = match self.open_conn() {
            Ok(c) => c,
            Err(e) => return Observation::tool_error("query_threat_model", e),
        };
        match pattern_scout_tools::query_threat_model(&conn, self.engagement_id) {
            Ok(Some(v)) => Observation::tool_result("query_threat_model", v.to_string()),
            Ok(None) => Observation::tool_result("query_threat_model", "null".to_string()),
            Err(e) => Observation::tool_error("query_threat_model", e.to_string()),
        }
    }

    fn do_query_findings(&self, args: &Value) -> Observation {
        let conn = match self.open_conn() {
            Ok(c) => c,
            Err(e) => return Observation::tool_error("query_findings", e),
        };
        let tool_origin = args
            .get("tool_origin")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty());
        let page = args.get("page").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        let page_size = args.get("page_size").and_then(|v| v.as_u64()).map(|n| n as u32);
        let compact = args.get("compact").and_then(|v| v.as_bool()).unwrap_or(false);
        match pattern_scout_tools::query_findings(&conn, self.engagement_id, tool_origin, page, page_size, compact) {
            Ok(v) => Observation::tool_result("query_findings", v.to_string()),
            Err(e) => Observation::tool_error("query_findings", e.to_string()),
        }
    }

    fn do_query_finding_detail(&self, args: &Value) -> Observation {
        let finding_id = args
            .get("finding_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if finding_id.is_empty() {
            return Observation::tool_error("query_finding_detail", "finding_id required");
        }
        let conn = match self.open_conn() {
            Ok(c) => c,
            Err(e) => return Observation::tool_error("query_finding_detail", e),
        };
        match pattern_scout_tools::query_finding_detail(&conn, self.engagement_id, finding_id) {
            Ok(Some(v)) => Observation::tool_result("query_finding_detail", v.to_string()),
            Ok(None) => Observation::tool_result("query_finding_detail", "null".to_string()),
            Err(e) => Observation::tool_error("query_finding_detail", e.to_string()),
        }
    }

    fn do_query_taint_chains(&self, args: &Value) -> Observation {
        let conn = match self.open_conn() {
            Ok(c) => c,
            Err(e) => return Observation::tool_error("query_taint_chains", e),
        };
        let page = args.get("page").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        let page_size = args.get("page_size").and_then(|v| v.as_u64()).map(|n| n as u32);
        match pattern_scout_tools::query_taint_chains_paged(
            &conn,
            self.engagement_id,
            page,
            page_size,
        ) {
            Ok(v) => Observation::tool_result("query_taint_chains", v.to_string()),
            Err(e) => Observation::tool_error("query_taint_chains", e.to_string()),
        }
    }

    /// `read_context_range` is path-traversal-gated: the requested
    /// `file_path` must canonicalize INSIDE `self.target_repo`. Any attempt
    /// to escape the repo root (e.g. `../../etc/passwd`, or absolute paths
    /// outside the root) returns an error observation and does NOT touch
    /// the filesystem.
    fn do_read_context(&self, args: &Value) -> Observation {
        let file_path = match args.get("file_path").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => {
                return Observation::tool_error(
                    "read_context_range",
                    "missing required arg: file_path",
                )
            }
        };
        let line_start = match args.get("line_start").and_then(|v| v.as_i64()) {
            Some(n) => n,
            None => {
                return Observation::tool_error(
                    "read_context_range",
                    "missing required arg: line_start (i64)",
                )
            }
        };
        let line_end = match args.get("line_end").and_then(|v| v.as_i64()) {
            Some(n) => n,
            None => {
                return Observation::tool_error(
                    "read_context_range",
                    "missing required arg: line_end (i64)",
                )
            }
        };

        let joined = self.target_repo.join(file_path);
        let resolved = match resolve_within(&self.target_repo, &joined) {
            Ok(p) => p,
            Err(e) => return Observation::tool_error("read_context_range", e),
        };

        match pattern_scout_tools::read_context_range(&resolved, line_start, line_end) {
            Ok(v) => Observation::tool_result("read_context_range", v.to_string()),
            Err(e) => Observation::tool_error("read_context_range", format!("read: {e}")),
        }
    }

    /// Cedar-gated `store_finding`. See module doc for the attribute
    /// contract. On Allow: writes evidence + finding + per-citation rows
    /// and bumps `findings_inserted`. On Deny: bumps `denied_by_cedar`,
    /// appends a `"deny"` journal entry, returns a policy_denial
    /// observation. The Cedar attrs are derived from the agent's claimed
    /// `citations` array — pattern_scout is trusted to type its citations
    /// correctly, and the Cedar policy verifies the set is non-empty and
    /// of the expected shape.
    fn do_store_finding(&self, args: &Value) -> Observation {
        let conn = match self.open_conn() {
            Ok(c) => c,
            Err(e) => return Observation::tool_error("store_finding", e),
        };

        // 1) Parse the agent's claim into a Finding draft + Citation list.
        let citations_array = match args.get("citations").and_then(|v| v.as_array()) {
            Some(a) => a.clone(),
            None => {
                return Observation::tool_error(
                    "store_finding",
                    "missing required arg: citations (non-empty array)",
                )
            }
        };
        if citations_array.is_empty() {
            // Cedar would also catch this, but a clear error before
            // construction is friendlier to the agent's transcript.
            return Observation::tool_error(
                "store_finding",
                "citations must be a non-empty array",
            );
        }
        let citation_types: Vec<String> = citations_array
            .iter()
            .filter_map(|c| c.get("type").and_then(|v| v.as_str()).map(String::from))
            .collect();

        // File-existence gate: the cited file_path MUST be a real file inside
        // the target repo. pattern_scout has been observed to confabulate
        // findings about files that don't exist in the target (e.g. the
        // auditor's OWN source when hunt runs from the wrong cwd). Reject such
        // claims here — before the Cedar gate and before they can reach
        // chain_builder or the handoff seed. Defense-in-depth alongside the
        // `--target` flag that anchors this root correctly.
        if let Some(file_path) = args.get("file_path").and_then(|v| v.as_str()) {
            if let Err(e) = self.verify_file_in_target(file_path) {
                tracing::warn!(
                    file_path = %file_path,
                    reason = %e,
                    "pattern_scout store_finding rejected: cited file not in target repo"
                );
                return Observation::tool_error(
                    "store_finding",
                    format!(
                        "cited file_path is not a readable file inside the target repo \
                         ({file_path}): {e}. Findings must cite a real file in the target \
                         — do not invent or reference out-of-tree paths."
                    ),
                );
            }
        }

        // Parse each citation eagerly so a malformed entry fails BEFORE the
        // Cedar gate (otherwise we'd pay the gate cost for a doomed call).
        let mut citations: Vec<Citation> = Vec::with_capacity(citations_array.len());
        for c in &citations_array {
            match parse_citation(c) {
                Ok(cit) => citations.push(cit),
                Err(e) => {
                    return Observation::tool_error("store_finding", format!("citation: {e}"))
                }
            }
        }

        // 2) Look up the pinned specifier_hash for this engagement (Cedar
        // policies inspect it; static_hunter follows the same pattern).
        let specifier_hash: Option<String> = conn
            .query_row(
                "SELECT specifier_hash FROM threat_models WHERE engagement_id = ?1 \
                 ORDER BY signed_at DESC LIMIT 1",
                rusqlite::params![self.engagement_id.to_string()],
                |r| r.get::<_, String>(0),
            )
            .ok();

        // 3) Build the per-finding EvidenceEnvelope. Bytes = canonical JSON
        // of the agent's full claim (args + parsed citations). The envelope
        // hash makes this finding's evidence pointer reproducible.
        let envelope_bytes = match serde_json::to_vec_pretty(args) {
            Ok(b) => b,
            Err(e) => {
                return Observation::tool_error(
                    "store_finding",
                    format!("envelope serialize: {e}"),
                )
            }
        };
        let scan_id = format!("PS-{}", &self.engagement_id.simple().to_string()[..8]);
        let envelope = EvidenceEnvelope {
            scan_id: scan_id.clone(),
            tool: "pattern_scout".into(),
            content_type: "application/json".into(),
            bytes: envelope_bytes.clone(),
        };
        let envelope_id = envelope.envelope_id();

        // 4) Assemble the Finding draft. The id is engagement-scoped using
        // the current findings_inserted counter, mirroring static_hunter.
        let next_idx = {
            let s = self.state.lock().expect("scout summary mutex poisoned");
            s.findings_inserted
        };
        let finding_id = format!("F-pattern-scout-{:04}", next_idx);

        let f = match build_finding(
            &finding_id,
            self.engagement_id,
            specifier_hash.clone(),
            envelope_id.clone(),
            args,
        ) {
            Ok(f) => f,
            Err(e) => return Observation::tool_error("store_finding", e),
        };

        // 5) Cedar attrs. `citations` is a set of the citation type strings
        // the agent claimed. `specifier_hash` + `evidence_envelope_id` are
        // surfaced for the evidence.cedar policies.
        let mut attrs: HashMap<String, RestrictedExpression> = HashMap::new();
        attrs.insert(
            "citations".to_string(),
            RestrictedExpression::new_set(
                citation_types
                    .iter()
                    .map(|t| RestrictedExpression::new_string(t.clone()))
                    .collect::<Vec<_>>(),
            ),
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
        let (decision, diag) = match self.policy.evaluate_with_attrs(
            r#"Agent::"pattern_scout""#,
            r#"Action::"store_finding""#,
            &resource_uid,
            attrs,
        ) {
            Ok(p) => p,
            Err(e) => {
                return Observation::tool_error("store_finding", format!("policy: {e}"));
            }
        };

        if decision != Decision::Allow {
            let mut s = self.state.lock().expect("scout summary mutex poisoned");
            s.denied_by_cedar += 1;
            drop(s);
            if let Err(e) = audit::append_entry(
                &self.journal_path,
                "pattern_scout",
                "store_finding",
                resource_uid.clone(),
                "deny",
                None,
            ) {
                tracing::warn!(error = %e, "failed to append deny journal entry");
            }
            let reason = diag.primary_reason().unwrap_or("no reason").to_string();
            tracing::warn!(
                finding_id = %f.id,
                reason = %reason,
                "pattern_scout store_finding denied by Cedar"
            );
            return Observation::policy_denial(reason);
        }

        // 6) Permit path: write evidence row, finding, and per-citation
        // rows. Errors here are surfaced as tool errors (not policy
        // denials) since the gate already permitted.
        let evidence_dir = self
            .db_path
            .parent()
            .map(|p| p.join("evidence"))
            .unwrap_or_else(|| PathBuf::from("evidence"));
        if let Err(e) = std::fs::create_dir_all(&evidence_dir) {
            return Observation::tool_error("store_finding", format!("evidence dir: {e}"));
        }
        let evidence_path = evidence_dir.join(format!("{envelope_id}.json"));
        if let Err(e) = std::fs::write(&evidence_path, &envelope_bytes) {
            return Observation::tool_error("store_finding", format!("evidence write: {e}"));
        }
        if let Err(e) = conn.execute(
            "INSERT OR IGNORE INTO evidence (envelope_id, sha256, path, content_type, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                &envelope_id,
                hex_sha256(&envelope_bytes),
                evidence_path.display().to_string(),
                "application/json",
                Utc::now().to_rfc3339(),
            ],
        ) {
            return Observation::tool_error("store_finding", format!("evidence insert: {e}"));
        }

        if let Err(e) = db::insert_finding(&conn, &f) {
            return Observation::tool_error("store_finding", format!("insert finding: {e}"));
        }
        for cit in &citations {
            if let Err(e) = db::insert_finding_citation(&conn, &f.id, cit) {
                return Observation::tool_error(
                    "store_finding",
                    format!("insert citation: {e}"),
                );
            }
        }

        {
            let mut s = self.state.lock().expect("scout summary mutex poisoned");
            s.findings_inserted += 1;
        }
        if let Err(e) = audit::append_entry(
            &self.journal_path,
            "pattern_scout",
            "store_finding",
            resource_uid.clone(),
            "permit",
            Some(envelope_id.clone()),
        ) {
            tracing::warn!(error = %e, "failed to append permit journal entry");
        }

        Observation::tool_result(
            "store_finding",
            json!({
                "finding_id":           f.id,
                "evidence_envelope_id": envelope_id,
                "citations":            citation_types,
            })
            .to_string(),
        )
    }

    /// Dispatch a `hypothesis_repl` tool call into the real sub-context
    /// runner (`crate::hypothesis_repl::run`). The sub-agent reaches a
    /// verdict in `<= budget_iterations` turns; the transcript is written
    /// as an evidence envelope under `<db_dir>/evidence/`, and the parent
    /// receives `{verdict, transcript_envelope_id}`.
    ///
    /// An empty `hypothesis_text` is rejected before spinning up the
    /// sub-context — the LLM would otherwise loop on a meaningless prompt.
    async fn do_hypothesis_repl(&self, args: &Value) -> Observation {
        use crate::hypothesis_repl::{self, ReplInput};

        let hyp = args
            .get("hypothesis_text")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if hyp.is_empty() {
            return Observation::tool_error(
                "hypothesis_repl",
                "hypothesis_text required",
            );
        }
        let budget = args
            .get("budget_iterations")
            .and_then(|v| v.as_u64())
            .unwrap_or(5) as u32;
        // Mirror do_store_finding (lines ~351-355): evidence sits next to
        // the SQLite DB. Fallback to a relative "evidence" dir is the same
        // safety net we use there.
        let evidence_dir = self
            .db_path
            .parent()
            .map(|p| p.join("evidence"))
            .unwrap_or_else(|| PathBuf::from("evidence"));

        match hypothesis_repl::run(ReplInput {
            engagement_id: self.engagement_id,
            hypothesis_text: hyp.to_string(),
            budget_iterations: budget,
            evidence_dir,
        })
        .await
        {
            Ok(out) => Observation::tool_result(
                "hypothesis_repl",
                json!({
                    "verdict":                out.verdict.as_str(),
                    "transcript_envelope_id": out.transcript_envelope_id,
                })
                .to_string(),
            ),
            Err(e) => Observation::tool_error(
                "hypothesis_repl",
                format!("hypothesis_repl: {e}"),
            ),
        }
    }
}

/// Resolve `requested` against `root`, ensuring the canonical result is
/// inside `root`. Returns the canonical path on success.
///
/// We canonicalize `root` once and require the result to start with the
/// canonical root prefix. If `requested` doesn't yet exist (rare for
/// read_context_range — the agent is reading existing source), we still
/// reject paths whose lexical resolution escapes.
fn resolve_within(root: &Path, requested: &Path) -> Result<PathBuf, String> {
    let canon_root = root
        .canonicalize()
        .map_err(|e| format!("target_repo canonicalize: {e}"))?;
    let canon = requested
        .canonicalize()
        .map_err(|e| format!("path canonicalize ({}): {e}", requested.display()))?;
    if !canon.starts_with(&canon_root) {
        return Err(format!(
            "path escapes target_repo: {} not inside {}",
            canon.display(),
            canon_root.display()
        ));
    }
    Ok(canon)
}

/// Parse one citation entry from the agent's `citations` array. The
/// `Citation` enum uses `file_path` + `u32` line numbers, which differs
/// from the plan draft (`path` + `i64`); we adapt here.
fn parse_citation(v: &Value) -> Result<Citation, String> {
    let ctype = v
        .get("type")
        .and_then(|x| x.as_str())
        .ok_or_else(|| "missing 'type' field".to_string())?;
    match ctype {
        "analyzer" => {
            let finding_id = v
                .get("finding_id")
                .or_else(|| v.get("rule_id"))
                .and_then(|x| x.as_str())
                .ok_or_else(|| "analyzer citation needs 'finding_id'".to_string())?;
            Ok(Citation::Analyzer {
                finding_id: finding_id.to_string(),
            })
        }
        "code" => {
            let file_path = v
                .get("file_path")
                .or_else(|| v.get("path"))
                .and_then(|x| x.as_str())
                .ok_or_else(|| "code citation needs 'file_path'".to_string())?;
            let line_start = v
                .get("line_start")
                .and_then(|x| x.as_u64())
                .ok_or_else(|| "code citation needs 'line_start' (u32)".to_string())?;
            let line_end = v
                .get("line_end")
                .and_then(|x| x.as_u64())
                .ok_or_else(|| "code citation needs 'line_end' (u32)".to_string())?;
            Ok(Citation::Code {
                file_path: file_path.to_string(),
                line_start: line_start as u32,
                line_end: line_end as u32,
            })
        }
        "hypothesis" => {
            let hypothesis_id = v
                .get("hypothesis_id")
                .and_then(|x| x.as_str())
                .ok_or_else(|| "hypothesis citation needs 'hypothesis_id'".to_string())?;
            let intended_poc = v
                .get("intended_poc")
                .and_then(|x| x.as_str())
                .ok_or_else(|| "hypothesis citation needs 'intended_poc'".to_string())?;
            Ok(Citation::Hypothesis {
                hypothesis_id: hypothesis_id.to_string(),
                intended_poc: intended_poc.to_string(),
            })
        }
        other => Err(format!("unknown citation type: {other}")),
    }
}

/// Construct a `Finding` from the agent's `store_finding` arguments. We
/// default to `Phase::Triage` since pattern_scout's claims are
/// reasoning-derived rather than directly tied to a SAST / Deps phase.
fn build_finding(
    id: &str,
    engagement_id: Uuid,
    specifier_hash: Option<String>,
    evidence_envelope_id: String,
    args: &Value,
) -> Result<Finding, String> {
    let severity = parse_severity(args.get("severity").and_then(|v| v.as_str()).unwrap_or("info"));
    let confidence =
        parse_confidence(args.get("confidence").and_then(|v| v.as_str()).unwrap_or("low"));
    let cwe = args
        .get("cwe")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(String::from);
    let owasp = args
        .get("owasp")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(String::from);
    let file_path = args
        .get("file_path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing required arg: file_path".to_string())?
        .to_string();
    let line_start = args
        .get("line_start")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| "missing required arg: line_start (u32)".to_string())? as u32;
    let line_end = args
        .get("line_end")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| "missing required arg: line_end (u32)".to_string())? as u32;
    let title = args
        .get("title")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing required arg: title".to_string())?
        .to_string();
    let description = args
        .get("description")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing required arg: description".to_string())?
        .to_string();

    Ok(Finding {
        id: id.to_string(),
        engagement_id,
        phase: Phase::Triage,
        severity,
        confidence,
        cwe,
        owasp,
        file_path,
        line_start,
        line_end,
        title,
        description,
        reachable: None,
        exploitable: None,
        evidence_envelope_id,
        status: Status::Open,
        rank_score: None,
        specifier_hash,
        advocate_verdict: None,
        tool_origin: Some("pattern_scout".to_string()),
        poc_status: None,
        created_at: Utc::now(),
    })
}

fn parse_severity(s: &str) -> Severity {
    match s {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}

fn parse_confidence(s: &str) -> Confidence {
    match s {
        "high" => Confidence::High,
        "medium" => Confidence::Medium,
        _ => Confidence::Low,
    }
}

#[async_trait::async_trait]
impl ActionExecutor for PatternScoutExecutor {
    async fn execute_actions(
        &self,
        actions: &[ProposedAction],
        _config: &LoopConfig,
        _circuit_breakers: &CircuitBreakerRegistry,
    ) -> Vec<Observation> {
        // Only `ToolCall` actions produce observations. The default executor
        // follows the same convention — Respond/Delegate/Terminate are loop
        // control, not tool dispatch.
        let mut observations = Vec::new();
        for action in actions {
            if let ProposedAction::ToolCall {
                call_id,
                name,
                arguments,
            } = action
            {
                {
                    let mut s = self.state.lock().expect("scout summary mutex poisoned");
                    s.tool_calls += 1;
                }
                let parsed: Value = serde_json::from_str(arguments).unwrap_or(Value::Null);
                let mut obs = match name.as_str() {
                    "query_threat_model" => self.do_query_threat_model(),
                    "query_findings" => self.do_query_findings(&parsed),
                    "query_finding_detail" => self.do_query_finding_detail(&parsed),
                    "query_taint_chains" => self.do_query_taint_chains(&parsed),
                    "read_context_range" => self.do_read_context(&parsed),
                    "store_finding" => self.do_store_finding(&parsed),
                    "hypothesis_repl" => self.do_hypothesis_repl(&parsed).await,
                    other => {
                        Observation::tool_error(name.clone(), format!("unknown tool: {other}"))
                    }
                };

                // Analysis-paralysis watchdog. Track read-class calls
                // since the last store_finding; once the threshold is
                // crossed, append a directive to the read result so the
                // model is told — in-band, where it can't ignore a
                // system-prompt line — to commit a finding. store_finding
                // (success OR Cedar-allowed) resets the counter.
                let is_read = matches!(
                    name.as_str(),
                    "query_threat_model"
                        | "query_findings"
                        | "query_finding_detail"
                        | "query_taint_chains"
                        | "read_context_range"
                );
                let nudge = {
                    let mut s = self.state.lock().expect("scout summary mutex poisoned");
                    if name == "store_finding" && !obs.is_error {
                        s.reads_since_store = 0;
                        false
                    } else if is_read {
                        s.reads_since_store += 1;
                        s.reads_since_store >= READS_BEFORE_STORE_NUDGE
                    } else {
                        false
                    }
                };
                if nudge && is_read && !obs.is_error {
                    obs.content.push_str(
                        "\n\n[SCOUT DIRECTIVE] You have made several read calls \
                         without storing a finding. Per your output quota, your \
                         NEXT action MUST be store_finding for your strongest \
                         current candidate (use a Citation::Code pointing at the \
                         file:line you just read). If you genuinely have no \
                         candidate, call query_findings(page=N+1) to advance to \
                         the next batch — do not keep reading the same area.",
                    );
                }

                tracing::debug!(
                    tool = name.as_str(),
                    is_error = obs.is_error,
                    detail = if obs.is_error { obs.content.chars().take(160).collect::<String>() } else { String::new() },
                    "pattern_scout tool dispatch"
                );
                observations.push(obs.with_call_id(call_id.clone()));
            }
        }
        observations
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use symbi_evidence_schema::{Engagement, ThreatModel};
    use tempfile::TempDir;

    /// A PolicyEngine that permits store_finding only when the citation set
    /// contains at least one allowed type. Mirrors the production
    /// citation.cedar contract closely enough for unit testing.
    fn policy_with_citation_gate(dir: &Path) -> Arc<PolicyEngine> {
        std::fs::write(
            dir.join("citation.cedar"),
            r#"
            @id("permit-store")
            permit(principal, action == Action::"store_finding", resource);

            @id("require-citation")
            forbid(principal, action == Action::"store_finding", resource)
            unless {
                resource has citations &&
                (resource.citations.contains("analyzer") ||
                 resource.citations.contains("code") ||
                 resource.citations.contains("hypothesis"))
            };
            "#,
        )
        .unwrap();
        Arc::new(PolicyEngine::from_dir(dir).unwrap())
    }

    /// A PolicyEngine that always denies store_finding. Used to verify the
    /// deny path bumps `denied_by_cedar` and emits a policy_denial obs.
    fn policy_deny_all(dir: &Path) -> Arc<PolicyEngine> {
        std::fs::write(
            dir.join("deny.cedar"),
            r#"
            @id("forbid-everything")
            forbid(principal, action == Action::"store_finding", resource);
            "#,
        )
        .unwrap();
        Arc::new(PolicyEngine::from_dir(dir).unwrap())
    }

    fn fresh_executor(
        repo: PathBuf,
        policy: Arc<PolicyEngine>,
    ) -> (TempDir, PathBuf, PatternScoutExecutor) {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("codered.db");
        let journal_path = dir.path().join("journal.jsonl");
        let conn = db::init_db(db_path.to_str().unwrap()).unwrap();
        let e = Engagement::new("acme", "h", "2026-05-24", "2026-05-31");
        let eid = e.id;
        db::insert_engagement(&conn, &e).unwrap();
        let tm = ThreatModel {
            specifier_hash: "a".repeat(64),
            engagement_id: eid,
            canonical_json: r#"{"scope":["src/**"]}"#.into(),
            signed_at: Utc::now(),
            signature: "0".repeat(128),
        };
        db::insert_threat_model(&conn, &tm).unwrap();
        drop(conn);
        let executor = PatternScoutExecutor::new(eid, db_path.clone(), journal_path, repo, policy);
        (dir, db_path, executor)
    }

    #[tokio::test]
    async fn unknown_tool_returns_error_observation_with_call_id() {
        let policy_dir = TempDir::new().unwrap();
        let policy = Arc::new(PolicyEngine::from_dir(policy_dir.path()).unwrap());
        let repo = TempDir::new().unwrap();
        let (_dir, _db, exec) = fresh_executor(repo.path().to_path_buf(), policy);
        let actions = vec![ProposedAction::ToolCall {
            call_id: "c1".into(),
            name: "not_a_real_tool".into(),
            arguments: "{}".into(),
        }];
        let obs = exec
            .execute_actions(&actions, &LoopConfig::default(), &CircuitBreakerRegistry::default())
            .await;
        assert_eq!(obs.len(), 1);
        assert!(obs[0].is_error);
        assert!(obs[0].content.contains("unknown tool"));
        assert_eq!(obs[0].call_id.as_deref(), Some("c1"));
    }

    #[tokio::test]
    async fn query_threat_model_dispatches_and_returns_pinned_row() {
        let policy_dir = TempDir::new().unwrap();
        let policy = Arc::new(PolicyEngine::from_dir(policy_dir.path()).unwrap());
        let repo = TempDir::new().unwrap();
        let (_dir, _db, exec) = fresh_executor(repo.path().to_path_buf(), policy);
        let actions = vec![ProposedAction::ToolCall {
            call_id: "c1".into(),
            name: "query_threat_model".into(),
            arguments: "{}".into(),
        }];
        let obs = exec
            .execute_actions(&actions, &LoopConfig::default(), &CircuitBreakerRegistry::default())
            .await;
        assert_eq!(obs.len(), 1);
        assert!(!obs[0].is_error, "got error: {}", obs[0].content);
        let v: Value = serde_json::from_str(&obs[0].content).unwrap();
        assert_eq!(v.get("specifier_hash").unwrap().as_str().unwrap().len(), 64);
    }

    #[tokio::test]
    async fn read_context_range_blocks_path_escape() {
        let policy_dir = TempDir::new().unwrap();
        let policy = Arc::new(PolicyEngine::from_dir(policy_dir.path()).unwrap());
        let repo = TempDir::new().unwrap();
        std::fs::write(repo.path().join("x.py"), "a\nb\nc\n").unwrap();
        let (_dir, _db, exec) = fresh_executor(repo.path().to_path_buf(), policy);
        let actions = vec![ProposedAction::ToolCall {
            call_id: "c1".into(),
            name: "read_context_range".into(),
            arguments: json!({
                "file_path":  "../../../../../../etc/passwd",
                "line_start": 1,
                "line_end":   1,
            })
            .to_string(),
        }];
        let obs = exec
            .execute_actions(&actions, &LoopConfig::default(), &CircuitBreakerRegistry::default())
            .await;
        assert_eq!(obs.len(), 1);
        assert!(obs[0].is_error, "expected error on path escape");
        // The error is either "escapes" (canonicalize succeeded) or
        // "canonicalize" (path doesn't exist). Either is acceptable —
        // both prevent the read.
        let c = &obs[0].content;
        assert!(
            c.contains("escapes") || c.contains("canonicalize"),
            "unexpected error: {c}"
        );
    }

    #[tokio::test]
    async fn read_context_range_reads_inside_repo() {
        let policy_dir = TempDir::new().unwrap();
        let policy = Arc::new(PolicyEngine::from_dir(policy_dir.path()).unwrap());
        let repo = TempDir::new().unwrap();
        std::fs::write(repo.path().join("x.py"), "a\nb\nc\n").unwrap();
        let (_dir, _db, exec) = fresh_executor(repo.path().to_path_buf(), policy);
        let actions = vec![ProposedAction::ToolCall {
            call_id: "c1".into(),
            name: "read_context_range".into(),
            arguments: json!({
                "file_path":  "x.py",
                "line_start": 2,
                "line_end":   3,
            })
            .to_string(),
        }];
        let obs = exec
            .execute_actions(&actions, &LoopConfig::default(), &CircuitBreakerRegistry::default())
            .await;
        assert_eq!(obs.len(), 1);
        assert!(!obs[0].is_error, "got error: {}", obs[0].content);
        let v: Value = serde_json::from_str(&obs[0].content).unwrap();
        let s = v.get("snippet").unwrap().as_str().unwrap();
        assert!(s.contains("2: b"));
        assert!(s.contains("3: c"));
    }

    #[tokio::test]
    async fn store_finding_inserts_when_cedar_permits() {
        let policy_dir = TempDir::new().unwrap();
        let policy = policy_with_citation_gate(policy_dir.path());
        let repo = TempDir::new().unwrap();
        // The cited file must exist in the target repo (file-existence gate).
        std::fs::create_dir_all(repo.path().join("src")).unwrap();
        std::fs::write(repo.path().join("src/users.py"), "x\n".repeat(100)).unwrap();
        let (_dir, db_path, exec) = fresh_executor(repo.path().to_path_buf(), policy);

        let args = json!({
            "severity":    "high",
            "confidence":  "medium",
            "cwe":         "CWE-89",
            "owasp":       "A03:2021",
            "file_path":   "src/users.py",
            "line_start":  88,
            "line_end":    95,
            "title":       "SQL injection via sort param",
            "description": "Untrusted sort reaches cursor.execute",
            "citations": [
                {"type": "analyzer", "finding_id": "F-semgrep-0001"},
                {"type": "code", "file_path": "src/users.py", "line_start": 88, "line_end": 95},
            ],
        });
        let actions = vec![ProposedAction::ToolCall {
            call_id: "c1".into(),
            name: "store_finding".into(),
            arguments: args.to_string(),
        }];
        let obs = exec
            .execute_actions(&actions, &LoopConfig::default(), &CircuitBreakerRegistry::default())
            .await;
        assert_eq!(obs.len(), 1);
        assert!(!obs[0].is_error, "got error: {}", obs[0].content);

        let summary = exec.summary();
        assert_eq!(summary.findings_inserted, 1);
        assert_eq!(summary.denied_by_cedar, 0);
        assert_eq!(summary.tool_calls, 1);

        // Verify the row + citations landed.
        let conn = db::init_db(db_path.to_str().unwrap()).unwrap();
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM findings", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1);
        let cites: i64 = conn
            .query_row("SELECT COUNT(*) FROM finding_citations", [], |r| r.get(0))
            .unwrap();
        assert_eq!(cites, 2);
        let ev: i64 = conn
            .query_row("SELECT COUNT(*) FROM evidence", [], |r| r.get(0))
            .unwrap();
        assert_eq!(ev, 1);
    }

    #[tokio::test]
    async fn store_finding_denies_and_journals_when_cedar_forbids() {
        let policy_dir = TempDir::new().unwrap();
        let policy = policy_deny_all(policy_dir.path());
        let repo = TempDir::new().unwrap();
        // File must exist so the call reaches the Cedar gate (not the
        // file-existence gate) — this test asserts the Cedar deny path.
        std::fs::create_dir_all(repo.path().join("src")).unwrap();
        std::fs::write(repo.path().join("src/users.py"), "x\n").unwrap();
        let (_dir, db_path, exec) = fresh_executor(repo.path().to_path_buf(), policy);

        let args = json!({
            "severity":    "high",
            "confidence":  "high",
            "file_path":   "src/users.py",
            "line_start":  1,
            "line_end":    1,
            "title":       "x",
            "description": "x",
            "citations":   [{"type": "analyzer", "finding_id": "F-x-0001"}],
        });
        let actions = vec![ProposedAction::ToolCall {
            call_id: "c1".into(),
            name: "store_finding".into(),
            arguments: args.to_string(),
        }];
        let obs = exec
            .execute_actions(&actions, &LoopConfig::default(), &CircuitBreakerRegistry::default())
            .await;
        assert_eq!(obs.len(), 1);
        assert!(obs[0].is_error, "expected denial to surface as error obs");
        assert_eq!(obs[0].source, "policy_gate");

        let summary = exec.summary();
        assert_eq!(summary.findings_inserted, 0);
        assert_eq!(summary.denied_by_cedar, 1);

        // No row should have landed.
        let conn = db::init_db(db_path.to_str().unwrap()).unwrap();
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM findings", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn store_finding_rejects_nonexistent_file_in_target() {
        // A hallucinated finding citing a file that isn't in the target repo
        // must be rejected by the file-existence gate, BEFORE Cedar, and must
        // not insert a row.
        let policy_dir = TempDir::new().unwrap();
        let policy = policy_with_citation_gate(policy_dir.path());
        let repo = TempDir::new().unwrap(); // empty: no such file exists
        let (_dir, db_path, exec) = fresh_executor(repo.path().to_path_buf(), policy);

        let args = json!({
            "severity":    "high",
            "confidence":  "high",
            "file_path":   "crates/does-not-exist/src/ghost.rs",
            "line_start":  10,
            "line_end":    20,
            "title":       "Hallucinated finding",
            "description": "About a file that is not in the target tree",
            "citations":   [{"type": "code", "file_path": "crates/does-not-exist/src/ghost.rs", "line_start": 10, "line_end": 20}],
        });
        let actions = vec![ProposedAction::ToolCall {
            call_id: "c1".into(),
            name: "store_finding".into(),
            arguments: args.to_string(),
        }];
        let obs = exec
            .execute_actions(&actions, &LoopConfig::default(), &CircuitBreakerRegistry::default())
            .await;
        assert_eq!(obs.len(), 1);
        assert!(obs[0].is_error, "expected rejection for nonexistent file");
        assert!(
            obs[0].content.contains("not a readable file") || obs[0].content.contains("does-not-exist"),
            "unexpected error: {}",
            obs[0].content
        );
        // Rejected before Cedar, so not counted as a Cedar denial.
        assert_eq!(exec.summary().denied_by_cedar, 0);
        assert_eq!(exec.summary().findings_inserted, 0);

        let conn = db::init_db(db_path.to_str().unwrap()).unwrap();
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM findings", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn store_finding_rejects_empty_citations_before_cedar() {
        let policy_dir = TempDir::new().unwrap();
        let policy = policy_with_citation_gate(policy_dir.path());
        let repo = TempDir::new().unwrap();
        let (_dir, _db, exec) = fresh_executor(repo.path().to_path_buf(), policy);
        let args = json!({
            "severity":    "low",
            "confidence":  "low",
            "file_path":   "x.py",
            "line_start":  1,
            "line_end":    1,
            "title":       "x",
            "description": "x",
            "citations":   [],
        });
        let actions = vec![ProposedAction::ToolCall {
            call_id: "c1".into(),
            name: "store_finding".into(),
            arguments: args.to_string(),
        }];
        let obs = exec
            .execute_actions(&actions, &LoopConfig::default(), &CircuitBreakerRegistry::default())
            .await;
        assert!(obs[0].is_error);
        assert!(obs[0].content.contains("non-empty"));
        // Empty citations is an arg-validation error, NOT a Cedar denial.
        assert_eq!(exec.summary().denied_by_cedar, 0);
    }

    #[tokio::test]
    async fn non_tool_actions_produce_no_observations() {
        let policy_dir = TempDir::new().unwrap();
        let policy = Arc::new(PolicyEngine::from_dir(policy_dir.path()).unwrap());
        let repo = TempDir::new().unwrap();
        let (_dir, _db, exec) = fresh_executor(repo.path().to_path_buf(), policy);
        let actions = vec![ProposedAction::Terminate {
            reason: "done".into(),
            output: "ok".into(),
        }];
        let obs = exec
            .execute_actions(&actions, &LoopConfig::default(), &CircuitBreakerRegistry::default())
            .await;
        assert!(obs.is_empty());
        assert_eq!(exec.summary().tool_calls, 0);
    }
}
