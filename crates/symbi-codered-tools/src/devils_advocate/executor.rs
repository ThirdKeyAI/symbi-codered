//! devils_advocate's ORGA `ActionExecutor`.
//!
//! Plan E Tasks 5 + 6. Dispatches two tools:
//!
//! - `query_findings`   — delegates to [`crate::pattern_scout_tools::query_findings`]
//! - `advocate_finding` — writes the agent's verdict via
//!   [`symbi_codered_core::db::set_advocate_verdict`] and appends a
//!   `devils_advocate` permit entry to the audit journal.
//!
//! Verdicts are constrained to `"confirmed"`, `"rebutted"`,
//! `"uncertain"`; anything else is rejected before touching the DB. The
//! Cedar gate that prevents `store_finding` from this principal lives
//! alongside the `.symbi` manifest (Task 4) — this executor only refuses
//! unknown tool names; it does not need to police `store_finding`
//! explicitly.

use cedar_policy::{Decision, RestrictedExpression};
use rusqlite::Connection;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

use symbi_codered_core::policy::PolicyEngine;
use symbi_codered_core::{audit, db};
use symbi_evidence_schema::evidence::EvidenceEnvelope;

use crate::pattern_scout_tools;
use symbi_runtime::reasoning::circuit_breaker::CircuitBreakerRegistry;
use symbi_runtime::reasoning::executor::ActionExecutor;
use symbi_runtime::reasoning::loop_types::{LoopConfig, Observation, ProposedAction};

/// Recognized witness kinds a `rebutted` verdict may cite. Mirrors the
/// `analyzer`/`code`/`hypothesis` citation taxonomy that gates `store_finding`.
///
/// `wrong_library` witnesses a rule/library mismatch: a SAST rule fired on a
/// symbol it does not actually own (e.g. semgrep's jQuery `prohibit-html` rule
/// matching Lit/lit-html's auto-escaping `html` tagged template). The `ref`
/// should point at the structural proof — the import line that shows the file
/// uses the OTHER library — so the rebuttal stays a verifiable fact, not prose.
const WITNESS_KINDS: &[&str] =
    &["envelope", "sanitizer", "closed_set", "constant_caller", "wrong_library"];

/// Per-run counters reported back to the caller after the loop terminates.
#[derive(Default)]
pub struct DevilsAdvocateInner {
    pub confirmed: usize,
    pub rebutted: usize,
    pub uncertain: usize,
    pub tool_calls: usize,
    /// `rebutted` verdicts denied by Cedar for lacking a witness.
    pub rebuttals_denied: usize,
}

/// `ActionExecutor` for devils_advocate. The runner (`super::run`) keeps
/// an `Arc` to this executor so it can read [`Self::summary`] after
/// `CoderedOrga::run` completes.
pub struct DevilsAdvocateExecutor {
    pub engagement_id: Uuid,
    pub db_path: PathBuf,
    pub journal_path: PathBuf,
    /// Repo root the advocate may read source from (path-escape guarded). This
    /// is what lets it VERIFY caller context — e.g. that a SQLi sink's `field`
    /// argument is a closed set of string literals — rather than confirming a
    /// finding on its (possibly self-serving) description alone.
    pub target_repo: PathBuf,
    pub state: Mutex<DevilsAdvocateInner>,
    /// Optional severity floor ("critical" / "high" / "medium" / "low").
    /// Forwarded to query_findings_prioritized so the agent never sees
    /// findings below the threshold.
    pub severity_min: Option<String>,
    /// Cedar engine used to gate `advocate_finding`. A `rebutted` verdict is
    /// authorized through `advocate.cedar`'s witness rule — the same
    /// attribute-bearing `evaluate_with_attrs` path that gates `store_finding`.
    pub policy: Arc<PolicyEngine>,
}

impl DevilsAdvocateExecutor {
    pub fn new(
        engagement_id: Uuid,
        db_path: PathBuf,
        journal_path: PathBuf,
        policy: Arc<PolicyEngine>,
    ) -> Self {
        Self::new_with_severity_floor(
            engagement_id,
            db_path,
            journal_path,
            PathBuf::from("."),
            None,
            policy,
        )
    }

    pub fn new_with_severity_floor(
        engagement_id: Uuid,
        db_path: PathBuf,
        journal_path: PathBuf,
        target_repo: PathBuf,
        severity_min: Option<String>,
        policy: Arc<PolicyEngine>,
    ) -> Self {
        Self {
            engagement_id,
            db_path,
            journal_path,
            target_repo,
            state: Mutex::new(DevilsAdvocateInner::default()),
            severity_min,
            policy,
        }
    }

    /// Read a line range from a file inside `target_repo` (read-only,
    /// path-escape guarded — identical semantics to poc_forge's reader). Gives
    /// the advocate eyes on the actual code before it adjudicates.
    fn do_read_context(&self, args: &Value) -> Observation {
        let file = args.get("file_path").and_then(|v| v.as_str()).unwrap_or("");
        if file.is_empty() {
            return Observation::tool_error("read_context_range", "file_path required");
        }
        let ls = args.get("line_start").and_then(|v| v.as_i64()).unwrap_or(1);
        let le = args.get("line_end").and_then(|v| v.as_i64()).unwrap_or(ls);

        // Canonicalize the repo root and the requested file; refuse anything
        // that escapes the root (`..` traversal or symlink).
        let canon_root = match self.target_repo.canonicalize() {
            Ok(p) => p,
            Err(e) => {
                return Observation::tool_error(
                    "read_context_range",
                    format!("target_repo canonicalize failed: {e}"),
                )
            }
        };
        let candidate = if std::path::Path::new(file).is_absolute() {
            PathBuf::from(file)
        } else {
            self.target_repo.join(file)
        };
        let canon = match candidate.canonicalize() {
            Ok(p) => p,
            Err(e) => {
                return Observation::tool_error(
                    "read_context_range",
                    format!("path does not exist: {} ({e})", candidate.display()),
                )
            }
        };
        if !canon.starts_with(&canon_root) {
            return Observation::tool_error(
                "read_context_range",
                format!("path escapes target_repo: {}", canon.display()),
            );
        }
        match pattern_scout_tools::read_context_range(&canon, ls, le) {
            Ok(v) => Observation::tool_result("read_context_range", v.to_string()),
            Err(e) => Observation::tool_error("read_context_range", format!("{e}")),
        }
    }

    /// Snapshot the per-run counters into the public `AdvocateSummary` type.
    pub fn summary(&self) -> super::AdvocateSummary {
        let s = self
            .state
            .lock()
            .expect("devils_advocate summary mutex poisoned");
        super::AdvocateSummary {
            confirmed: s.confirmed,
            rebutted: s.rebutted,
            uncertain: s.uncertain,
            tool_calls: s.tool_calls,
            rebuttals_denied: s.rebuttals_denied,
            tokens_in: 0,
            tokens_out: 0,
            iterations: 0,
        }
    }

    fn open_conn(&self) -> Result<Connection, String> {
        let path = self
            .db_path
            .to_str()
            .ok_or_else(|| format!("non-UTF8 db_path: {:?}", self.db_path))?;
        db::init_db(path).map_err(|e| format!("db open: {e}"))
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
        // devils_advocate defaults to compact: it can advocate from headline metadata.
        let compact = args.get("compact").and_then(|v| v.as_bool()).unwrap_or(true);
        // devils_advocate uses the prioritized variant so the iteration
        // budget is spent on high-severity real-code findings first. Path
        // prefixes for CI/ops/scripts/internal-docs are dropped at the SQL
        // layer; ordering is severity DESC, then id ASC. Schema of the
        // response envelope is identical to query_findings (with an extra
        // "prioritized": true marker the agent can ignore).
        match pattern_scout_tools::query_findings_prioritized(
            &conn,
            self.engagement_id,
            tool_origin,
            page,
            page_size,
            compact,
            self.severity_min.as_deref(),
        ) {
            Ok(v) => Observation::tool_result("query_findings", v.to_string()),
            Err(e) => Observation::tool_error("query_findings", e.to_string()),
        }
    }

    /// Authorize an `advocate_finding` call through Cedar (`advocate.cedar`).
    /// Builds a `Finding` resource carrying `verdict` + `witness_types` and
    /// evaluates it — mirroring `store_finding`'s `evaluate_with_attrs` witness
    /// gate. `confirmed`/`uncertain` carry an empty witness set and are
    /// permitted; `rebutted` is permitted only when the witness names a
    /// recognized kind (envelope / sanitizer / closed_set / constant_caller).
    fn gate_advocate(
        &self,
        verdict: &str,
        resource_uid: &str,
        args: &Value,
    ) -> Result<Decision, String> {
        let witness_types: Vec<String> = args
            .get("witness")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|w| w.get("type").and_then(|t| t.as_str()))
                    .filter(|t| WITNESS_KINDS.contains(t))
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default();

        let mut attrs: HashMap<String, RestrictedExpression> = HashMap::new();
        attrs.insert(
            "verdict".to_string(),
            RestrictedExpression::new_string(verdict.to_string()),
        );
        attrs.insert(
            "witness_types".to_string(),
            RestrictedExpression::new_set(
                witness_types
                    .iter()
                    .map(|t| RestrictedExpression::new_string(t.clone()))
                    .collect::<Vec<_>>(),
            ),
        );
        self.policy
            .evaluate_with_attrs(
                r#"Agent::"devils_advocate""#,
                r#"Action::"advocate_finding""#,
                resource_uid,
                attrs,
            )
            .map(|(decision, _diag)| decision)
            .map_err(|e| format!("{e}"))
    }

    /// Record the agent's verdict against a single finding. The agent
    /// passes:
    ///
    /// - `finding_id`: id of the finding being adjudicated
    /// - `verdict`: one of `"confirmed"`, `"rebutted"`, `"uncertain"`
    /// - `reason`: free-form explanation. **Required and non-empty when
    ///   `verdict == "rebutted"`** — suppressing a finding must be argued
    ///   (asymmetric cost; confirming or marking uncertain needs no reason).
    ///   The reason is echoed in the tool result; durable persistence and a
    ///   Cedar witness gate on the rebuttal are the structural follow-on.
    fn do_advocate_finding(&self, args: &Value) -> Observation {
        let finding_id = args
            .get("finding_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let verdict = args.get("verdict").and_then(|v| v.as_str()).unwrap_or("");
        if finding_id.is_empty() || !["confirmed", "rebutted", "uncertain"].contains(&verdict) {
            return Observation::tool_error(
                "advocate_finding",
                format!(
                    "finding_id and verdict required (verdict in \
                     confirmed|rebutted|uncertain); got id={finding_id:?} \
                     verdict={verdict:?}"
                ),
            );
        }

        // Asymmetric cost (suppression must be argued). Confirming or marking
        // uncertain keeps a finding in play and needs no justification, but
        // `rebutted` SUPPRESSES a finding — the dangerous direction for an
        // auditor and the one most exposed to confabulation. Require a
        // non-empty prose `reason` AND a typed witness (below) for rebuttals.
        let reason = args
            .get("reason")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim();
        if verdict == "rebutted" && reason.is_empty() {
            return Observation::tool_error(
                "advocate_finding",
                "a 'rebutted' verdict must carry a non-empty `reason` arguing the \
                 rebuttal. Confirming or marking uncertain needs no reason; \
                 suppressing a finding does."
                    .to_string(),
            );
        }

        // Structural witness gate (symmetric with store_finding's citation
        // gate). Parse the typed witness array and run advocate_finding through
        // Cedar with `verdict` + `witness_types` resource attributes. The
        // `advocate.cedar` rule forbids a `rebutted` verdict UNLESS the witness
        // set names a recognized kind, so a finding can never be dropped by an
        // unwitnessed rebuttal — and the guarantee lives in the policy
        // substrate, not the prompt.
        let resource_uid = format!(r#"Finding::"{finding_id}""#);
        match self.gate_advocate(verdict, &resource_uid, args) {
            Ok(Decision::Allow) => {}
            Ok(_) => {
                let mut s = self
                    .state
                    .lock()
                    .expect("devils_advocate summary mutex poisoned");
                s.rebuttals_denied += 1;
                drop(s);
                let _ = audit::append_entry(
                    &self.journal_path,
                    "devils_advocate",
                    "advocate_finding",
                    resource_uid.clone(),
                    "deny",
                    None,
                );
                return Observation::policy_denial(
                    "rebuttal denied by Cedar (advocate.cedar): a 'rebutted' verdict \
                     must cite a witness. Pass witness:[{\"type\":\"envelope|sanitizer|\
                     closed_set|constant_caller|wrong_library\",\"ref\":\"<id-or-name>\"}] \
                     — e.g. the read_context_range envelope you read, the sanitizer you \
                     found, the closed-set/constant callers that prove the input is not \
                     attacker-controlled, or (wrong_library) the import line proving the \
                     rule fired on the wrong library (e.g. lit-html, not jQuery)."
                        .to_string(),
                );
            }
            Err(e) => return Observation::tool_error("advocate_finding", format!("policy: {e}")),
        }

        let conn = match self.open_conn() {
            Ok(c) => c,
            Err(e) => return Observation::tool_error("advocate_finding", e),
        };
        if let Err(e) = db::set_advocate_verdict(&conn, finding_id, verdict) {
            return Observation::tool_error("advocate_finding", format!("{e}"));
        }

        // Make the SUPPRESSION reviewable, not just gated. For a rebuttal,
        // persist {verdict, reason, witness} as a tamper-evident evidence
        // envelope and reference it from the signed, hash-chained journal —
        // symmetric with how store_finding records a finding's evidence — so an
        // auditor can later see WHY a finding was dropped, not merely that it was.
        let witness_envelope_id: Option<String> = if verdict == "rebutted" {
            let bytes = json!({
                "verdict": verdict,
                "reason": reason,
                "witness": args.get("witness").cloned().unwrap_or(Value::Null),
            })
            .to_string()
            .into_bytes();
            let envelope = EvidenceEnvelope {
                scan_id: format!("DA-{}", &self.engagement_id.simple().to_string()[..8]),
                tool: "devils_advocate".into(),
                content_type: "application/json".into(),
                bytes: bytes.clone(),
            };
            let eid = envelope.envelope_id();
            let evidence_dir = self
                .db_path
                .parent()
                .map(|p| p.join("evidence"))
                .unwrap_or_else(|| PathBuf::from("evidence"));
            if let Err(e) = std::fs::create_dir_all(&evidence_dir) {
                tracing::warn!(error = %e, "failed to create evidence dir for advocate witness");
            } else if let Err(e) = std::fs::write(evidence_dir.join(format!("{eid}.json")), &bytes) {
                tracing::warn!(error = %e, "failed to persist advocate witness envelope");
            }
            Some(eid)
        } else {
            None
        };

        if let Err(e) = audit::append_entry(
            &self.journal_path,
            "devils_advocate",
            "advocate_finding",
            resource_uid,
            "permit",
            witness_envelope_id,
        ) {
            tracing::warn!(
                error = %e,
                "failed to append devils_advocate permit journal entry"
            );
        }

        {
            let mut s = self
                .state
                .lock()
                .expect("devils_advocate summary mutex poisoned");
            match verdict {
                "confirmed" => s.confirmed += 1,
                "rebutted" => s.rebutted += 1,
                _ => s.uncertain += 1,
            }
        }

        Observation::tool_result(
            "advocate_finding",
            json!({
                "finding_id": finding_id,
                "verdict":    verdict,
                "reason":     reason,
                "status":     "ok",
            })
            .to_string(),
        )
    }
}

#[async_trait::async_trait]
impl ActionExecutor for DevilsAdvocateExecutor {
    async fn execute_actions(
        &self,
        actions: &[ProposedAction],
        _config: &LoopConfig,
        _circuit_breakers: &CircuitBreakerRegistry,
    ) -> Vec<Observation> {
        let mut observations = Vec::new();
        for action in actions {
            if let ProposedAction::ToolCall {
                call_id,
                name,
                arguments,
            } = action
            {
                {
                    let mut s = self
                        .state
                        .lock()
                        .expect("devils_advocate summary mutex poisoned");
                    s.tool_calls += 1;
                }
                let parsed: Value = serde_json::from_str(arguments).unwrap_or(Value::Null);
                let obs = match name.as_str() {
                    "query_findings" => self.do_query_findings(&parsed),
                    "read_context_range" => self.do_read_context(&parsed),
                    "advocate_finding" => self.do_advocate_finding(&parsed),
                    other => Observation::tool_error(
                        name.clone(),
                        format!("unknown tool for devils_advocate: {other}"),
                    ),
                };
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
    use std::path::Path;
    use symbi_evidence_schema::{
        finding::{Confidence, Phase, Severity, Status},
        Engagement, Finding,
    };
    use tempfile::TempDir;

    /// The advocate permit + advocate.cedar witness rule, loaded from a temp
    /// dir so the unit tests exercise the real gate logic in isolation (not the
    /// whole policy set). Kept in sync with `policies/advocate.cedar`.
    fn test_policy() -> Arc<PolicyEngine> {
        let dir = TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("advocate.cedar"),
            r#"
            permit(principal == Agent::"devils_advocate", action == Action::"advocate_finding", resource);
            @id("advocate-rebuttal-requires-witness")
            forbid(
                principal == Agent::"devils_advocate",
                action == Action::"advocate_finding",
                resource
            ) when {
                resource has verdict && resource.verdict == "rebutted"
            } unless {
                resource has witness_types &&
                (resource.witness_types.contains("envelope") ||
                 resource.witness_types.contains("sanitizer") ||
                 resource.witness_types.contains("closed_set") ||
                 resource.witness_types.contains("constant_caller") ||
                 resource.witness_types.contains("wrong_library"))
            };
            "#,
        )
        .unwrap();
        Arc::new(PolicyEngine::from_dir(dir.path()).unwrap())
    }

    fn fresh_executor() -> (TempDir, PathBuf, DevilsAdvocateExecutor, Uuid) {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("codered.db");
        let journal_path = dir.path().join("journal.jsonl");
        let conn = db::init_db(db_path.to_str().unwrap()).unwrap();
        let e = Engagement::new("acme", "h", "2026-05-24", "2026-05-31");
        let eid = e.id;
        db::insert_engagement(&conn, &e).unwrap();
        drop(conn);
        let exec = DevilsAdvocateExecutor::new(eid, db_path.clone(), journal_path, test_policy());
        (dir, db_path, exec, eid)
    }

    fn insert_finding(db_path: &Path, eid: Uuid, id: &str, envelope: &str) {
        let conn = db::init_db(db_path.to_str().unwrap()).unwrap();
        let f = Finding {
            id: id.to_string(),
            engagement_id: eid,
            phase: Phase::Triage,
            severity: Severity::High,
            confidence: Confidence::Medium,
            cwe: Some("CWE-89".into()),
            owasp: None,
            file_path: "src/x.py".into(),
            line_start: 1,
            line_end: 2,
            title: "t".into(),
            description: "d".into(),
            reachable: None,
            exploitable: None,
            evidence_envelope_id: envelope.to_string(),
            status: Status::Open,
            rank_score: None,
            specifier_hash: None,
            advocate_verdict: None,
            tool_origin: Some("semgrep".into()),
            poc_status: None,
            created_at: Utc::now(),
        };
        conn.execute(
            "INSERT OR IGNORE INTO evidence (envelope_id, sha256, path, content_type, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                envelope,
                "0".repeat(64),
                "/tmp/x",
                "application/json",
                Utc::now().to_rfc3339(),
            ],
        )
        .unwrap();
        db::insert_finding(&conn, &f).unwrap();
    }

    #[tokio::test]
    async fn read_context_range_lets_advocate_inspect_callers() {
        // The whole point of the fix: the advocate can now READ SOURCE to check
        // caller context (e.g. that a SQLi sink's `field` arg is a closed set of
        // string literals) instead of confirming on plausible metadata alone.
        let (_dir, _db, mut exec, _eid) = fresh_executor();
        let repo = _dir.path().join("repo");
        std::fs::create_dir_all(repo.join("api")).unwrap();
        std::fs::write(
            repo.join("api/visit.go"),
            "case A:\n    newExtract(\"YEAR\", t)\ncase B:\n    newExtract(\"MONTH\", t)\n",
        )
        .unwrap();
        exec.target_repo = repo;

        let args = json!({"file_path": "api/visit.go", "line_start": 2, "line_end": 2});
        let actions = vec![ProposedAction::ToolCall {
            call_id: "c1".into(),
            name: "read_context_range".into(),
            arguments: args.to_string(),
        }];
        let obs = exec
            .execute_actions(&actions, &LoopConfig::default(), &CircuitBreakerRegistry::default())
            .await;
        assert!(!obs[0].is_error, "got error: {}", obs[0].content);
        assert!(obs[0].content.contains("newExtract(\\\"YEAR\\\"") || obs[0].content.contains("YEAR"),
            "expected source snippet, got: {}", obs[0].content);
    }

    #[tokio::test]
    async fn read_context_range_rejects_path_escape() {
        let (_dir, _db, mut exec, _eid) = fresh_executor();
        let repo = _dir.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::write(_dir.path().join("secret.txt"), "top-secret").unwrap();
        exec.target_repo = repo;

        let args = json!({"file_path": "../secret.txt", "line_start": 1, "line_end": 1});
        let actions = vec![ProposedAction::ToolCall {
            call_id: "c1".into(),
            name: "read_context_range".into(),
            arguments: args.to_string(),
        }];
        let obs = exec
            .execute_actions(&actions, &LoopConfig::default(), &CircuitBreakerRegistry::default())
            .await;
        assert!(obs[0].is_error, "path escape must be rejected");
    }

    #[tokio::test]
    async fn unknown_tool_returns_error_observation_with_call_id() {
        let (_dir, _db, exec, _eid) = fresh_executor();
        let actions = vec![ProposedAction::ToolCall {
            call_id: "c1".into(),
            name: "store_finding".into(),
            arguments: "{}".into(),
        }];
        let obs = exec
            .execute_actions(
                &actions,
                &LoopConfig::default(),
                &CircuitBreakerRegistry::default(),
            )
            .await;
        assert_eq!(obs.len(), 1);
        assert!(obs[0].is_error);
        assert!(obs[0].content.contains("unknown tool"));
        assert_eq!(obs[0].call_id.as_deref(), Some("c1"));
        assert_eq!(exec.summary().tool_calls, 1);
    }

    #[tokio::test]
    async fn advocate_finding_writes_verdict_and_bumps_counter() {
        let (_dir, db_path, exec, eid) = fresh_executor();
        insert_finding(&db_path, eid, "F-1", "env-1");

        let args = json!({
            "finding_id": "F-1",
            "verdict":    "rebutted",
            "reason":     "Path is only reachable from a unit test",
            "witness":    [{"type": "closed_set", "ref": "callers all pass a literal"}],
        });
        let actions = vec![ProposedAction::ToolCall {
            call_id: "c1".into(),
            name: "advocate_finding".into(),
            arguments: args.to_string(),
        }];
        let obs = exec
            .execute_actions(
                &actions,
                &LoopConfig::default(),
                &CircuitBreakerRegistry::default(),
            )
            .await;
        assert_eq!(obs.len(), 1);
        assert!(!obs[0].is_error, "got error: {}", obs[0].content);
        let v: Value = serde_json::from_str(&obs[0].content).unwrap();
        assert_eq!(v.get("verdict").and_then(|x| x.as_str()), Some("rebutted"));
        assert_eq!(v.get("status").and_then(|x| x.as_str()), Some("ok"));

        let summary = exec.summary();
        assert_eq!(summary.rebutted, 1);
        assert_eq!(summary.confirmed, 0);
        assert_eq!(summary.uncertain, 0);
        assert_eq!(summary.tool_calls, 1);

        let conn = db::init_db(db_path.to_str().unwrap()).unwrap();
        let verdict: Option<String> = conn
            .query_row(
                "SELECT advocate_verdict FROM findings WHERE id = 'F-1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(verdict.as_deref(), Some("rebutted"));
    }

    #[tokio::test]
    async fn advocate_finding_rejects_unknown_verdict() {
        let (_dir, _db, exec, _eid) = fresh_executor();
        let args = json!({
            "finding_id": "F-1",
            "verdict":    "definitely-broken",
        });
        let actions = vec![ProposedAction::ToolCall {
            call_id: "c1".into(),
            name: "advocate_finding".into(),
            arguments: args.to_string(),
        }];
        let obs = exec
            .execute_actions(
                &actions,
                &LoopConfig::default(),
                &CircuitBreakerRegistry::default(),
            )
            .await;
        assert!(obs[0].is_error);
        assert!(obs[0].content.contains("verdict"));
        // No verdict counter should advance on validation failure.
        let s = exec.summary();
        assert_eq!(s.confirmed + s.rebutted + s.uncertain, 0);
    }

    #[tokio::test]
    async fn advocate_finding_rejects_empty_finding_id() {
        let (_dir, _db, exec, _eid) = fresh_executor();
        let args = json!({
            "finding_id": "",
            "verdict":    "confirmed",
        });
        let actions = vec![ProposedAction::ToolCall {
            call_id: "c1".into(),
            name: "advocate_finding".into(),
            arguments: args.to_string(),
        }];
        let obs = exec
            .execute_actions(
                &actions,
                &LoopConfig::default(),
                &CircuitBreakerRegistry::default(),
            )
            .await;
        assert!(obs[0].is_error);
        let s = exec.summary();
        assert_eq!(s.confirmed + s.rebutted + s.uncertain, 0);
    }

    #[tokio::test]
    async fn rebutted_without_reason_is_rejected() {
        // Suppressing a finding must be argued: a `rebutted` verdict with an
        // empty/whitespace reason is refused, and no counter advances.
        let (_dir, db_path, exec, eid) = fresh_executor();
        insert_finding(&db_path, eid, "F-1", "env-1");
        for reason in ["", "   ", "\n\t "] {
            let args = json!({"finding_id": "F-1", "verdict": "rebutted", "reason": reason});
            let actions = vec![ProposedAction::ToolCall {
                call_id: "c1".into(),
                name: "advocate_finding".into(),
                arguments: args.to_string(),
            }];
            let obs = exec
                .execute_actions(
                    &actions,
                    &LoopConfig::default(),
                    &CircuitBreakerRegistry::default(),
                )
                .await;
            assert!(obs[0].is_error, "empty reason {reason:?} should be rejected");
            assert!(obs[0].content.contains("reason"));
        }
        // The finding was never suppressed.
        let s = exec.summary();
        assert_eq!(s.rebutted, 0);
        let conn = db::init_db(db_path.to_str().unwrap()).unwrap();
        let verdict: Option<String> = conn
            .query_row(
                "SELECT advocate_verdict FROM findings WHERE id = 'F-1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(verdict, None, "finding must not be rebutted without a reason");
    }

    #[tokio::test]
    async fn confirm_and_uncertain_need_no_reason() {
        // Asymmetric cost: keeping a finding in play is cheap — confirmed and
        // uncertain succeed with no reason at all.
        let (_dir, db_path, exec, eid) = fresh_executor();
        insert_finding(&db_path, eid, "F-1", "env-1");
        insert_finding(&db_path, eid, "F-2", "env-2");
        for (id, verdict) in [("F-1", "confirmed"), ("F-2", "uncertain")] {
            let args = json!({"finding_id": id, "verdict": verdict});
            let actions = vec![ProposedAction::ToolCall {
                call_id: "c1".into(),
                name: "advocate_finding".into(),
                arguments: args.to_string(),
            }];
            let obs = exec
                .execute_actions(
                    &actions,
                    &LoopConfig::default(),
                    &CircuitBreakerRegistry::default(),
                )
                .await;
            assert!(!obs[0].is_error, "{verdict} should need no reason: {}", obs[0].content);
        }
        let s = exec.summary();
        assert_eq!(s.confirmed, 1);
        assert_eq!(s.uncertain, 1);
    }

    #[tokio::test]
    async fn rebutted_without_witness_is_denied_by_cedar() {
        // The structural gate: a rebuttal with a reason but NO witness is
        // denied by advocate.cedar — the finding is not dropped.
        let (_dir, db_path, exec, eid) = fresh_executor();
        insert_finding(&db_path, eid, "F-1", "env-1");
        let args = json!({
            "finding_id": "F-1",
            "verdict":    "rebutted",
            "reason":     "I claim this is unreachable",
            // witness omitted
        });
        let actions = vec![ProposedAction::ToolCall {
            call_id: "c1".into(),
            name: "advocate_finding".into(),
            arguments: args.to_string(),
        }];
        let obs = exec
            .execute_actions(
                &actions,
                &LoopConfig::default(),
                &CircuitBreakerRegistry::default(),
            )
            .await;
        assert!(obs[0].is_error, "unwitnessed rebuttal must be denied");
        assert!(obs[0].content.contains("witness"));
        let s = exec.summary();
        assert_eq!(s.rebutted, 0, "verdict counter must not advance");
        assert_eq!(s.rebuttals_denied, 1);
        let conn = db::init_db(db_path.to_str().unwrap()).unwrap();
        let verdict: Option<String> = conn
            .query_row(
                "SELECT advocate_verdict FROM findings WHERE id = 'F-1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(verdict, None, "finding must not be suppressed without a witness");
    }

    #[tokio::test]
    async fn rebutted_with_witness_is_allowed() {
        // A rebuttal that cites a recognized witness kind passes the Cedar gate
        // and writes the verdict.
        let (_dir, db_path, exec, eid) = fresh_executor();
        insert_finding(&db_path, eid, "F-1", "env-1");
        let args = json!({
            "finding_id": "F-1",
            "verdict":    "rebutted",
            "reason":     "field is a closed set of literals across all callers",
            "witness":    [{"type": "envelope", "ref": "env-read-42"},
                           {"type": "bogus", "ref": "ignored"}],
        });
        let actions = vec![ProposedAction::ToolCall {
            call_id: "c1".into(),
            name: "advocate_finding".into(),
            arguments: args.to_string(),
        }];
        let obs = exec
            .execute_actions(
                &actions,
                &LoopConfig::default(),
                &CircuitBreakerRegistry::default(),
            )
            .await;
        assert!(!obs[0].is_error, "witnessed rebuttal should pass: {}", obs[0].content);
        let s = exec.summary();
        assert_eq!(s.rebutted, 1);
        assert_eq!(s.rebuttals_denied, 0);
        let conn = db::init_db(db_path.to_str().unwrap()).unwrap();
        let verdict: Option<String> = conn
            .query_row(
                "SELECT advocate_verdict FROM findings WHERE id = 'F-1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(verdict.as_deref(), Some("rebutted"));
    }

    #[tokio::test]
    async fn rebutted_with_wrong_library_witness_is_allowed() {
        // A library/rule-mismatch rebuttal (e.g. a jQuery rule firing on Lit's
        // auto-escaping `html` template) passes the witness gate via the
        // `wrong_library` kind — letting the advocate REBUT such false
        // positives instead of parking them at "uncertain".
        let (_dir, db_path, exec, eid) = fresh_executor();
        insert_finding(&db_path, eid, "F-1", "env-1");
        let args = json!({
            "finding_id": "F-1",
            "verdict":    "rebutted",
            "reason":     "semgrep jQuery prohibit-html fired on a Lit component; \
                           the file imports `html` from 'lit', which auto-escapes",
            "witness":    [{"type": "wrong_library", "ref": "audit-entry-row.ts:1 import { html } from 'lit'"}],
        });
        let actions = vec![ProposedAction::ToolCall {
            call_id: "c1".into(),
            name: "advocate_finding".into(),
            arguments: args.to_string(),
        }];
        let obs = exec
            .execute_actions(
                &actions,
                &LoopConfig::default(),
                &CircuitBreakerRegistry::default(),
            )
            .await;
        assert!(!obs[0].is_error, "wrong_library rebuttal should pass: {}", obs[0].content);
        let s = exec.summary();
        assert_eq!(s.rebutted, 1);
        assert_eq!(s.rebuttals_denied, 0);
        let conn = db::init_db(db_path.to_str().unwrap()).unwrap();
        let verdict: Option<String> = conn
            .query_row(
                "SELECT advocate_verdict FROM findings WHERE id = 'F-1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(verdict.as_deref(), Some("rebutted"));
    }

    #[tokio::test]
    async fn rebuttal_persists_witness_evidence_referenced_from_journal() {
        // A suppression must be reviewable: the witness is persisted as an
        // evidence envelope and its id is recorded in the signed journal.
        let (_dir, db_path, exec, eid) = fresh_executor();
        insert_finding(&db_path, eid, "F-1", "env-1");
        let args = json!({
            "finding_id": "F-1",
            "verdict":    "rebutted",
            "reason":     "field is a closed set of literals across all callers",
            "witness":    [{"type": "closed_set", "ref": "visit_call_func.go:88"}],
        });
        let actions = vec![ProposedAction::ToolCall {
            call_id: "c1".into(),
            name: "advocate_finding".into(),
            arguments: args.to_string(),
        }];
        let obs = exec
            .execute_actions(
                &actions,
                &LoopConfig::default(),
                &CircuitBreakerRegistry::default(),
            )
            .await;
        assert!(!obs[0].is_error, "{}", obs[0].content);

        // The witness envelope was persisted with the reason + witness.
        let evidence_dir = db_path.parent().unwrap().join("evidence");
        let files: Vec<_> = std::fs::read_dir(&evidence_dir)
            .expect("evidence dir")
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(files.len(), 1, "expected exactly one witness envelope");
        let env_path = files[0].path();
        let body = std::fs::read_to_string(&env_path).unwrap();
        assert!(body.contains("closed_set"));
        assert!(body.contains("closed set of literals"));

        // The signed journal references that envelope id (not None).
        let env_id = env_path.file_stem().unwrap().to_string_lossy().to_string();
        let journal = std::fs::read_to_string(&exec.journal_path).unwrap();
        assert!(
            journal.contains(&env_id),
            "journal must reference the witness envelope id {env_id}"
        );
    }

    #[tokio::test]
    async fn query_findings_dispatches_against_engagement() {
        let (_dir, db_path, exec, eid) = fresh_executor();
        insert_finding(&db_path, eid, "F-1", "env-1");
        let actions = vec![ProposedAction::ToolCall {
            call_id: "c1".into(),
            name: "query_findings".into(),
            arguments: "{}".into(),
        }];
        let obs = exec
            .execute_actions(
                &actions,
                &LoopConfig::default(),
                &CircuitBreakerRegistry::default(),
            )
            .await;
        assert_eq!(obs.len(), 1);
        assert!(!obs[0].is_error, "got error: {}", obs[0].content);
        let v: Value = serde_json::from_str(&obs[0].content).unwrap();
        let arr = v.get("findings").and_then(|x| x.as_array()).expect("findings array");
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0].get("id").and_then(|x| x.as_str()), Some("F-1"));
        assert_eq!(v.get("total").and_then(|x| x.as_i64()), Some(1));
    }

    #[tokio::test]
    async fn non_tool_actions_produce_no_observations() {
        let (_dir, _db, exec, _eid) = fresh_executor();
        let actions = vec![ProposedAction::Terminate {
            reason: "done".into(),
            output: "ok".into(),
        }];
        let obs = exec
            .execute_actions(
                &actions,
                &LoopConfig::default(),
                &CircuitBreakerRegistry::default(),
            )
            .await;
        assert!(obs.is_empty());
        assert_eq!(exec.summary().tool_calls, 0);
    }
}
