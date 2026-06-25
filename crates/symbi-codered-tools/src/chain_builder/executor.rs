//! chain_builder's ORGA `ActionExecutor`.
//!
//! Plan D Task 21. Dispatches three tools:
//!
//! - `query_findings`     — delegates to [`crate::pattern_scout_tools::query_findings`]
//! - `query_taint_chains` — delegates to [`crate::pattern_scout_tools::query_taint_chains`]
//! - `build_attack_chain` — writes one or more `attack_chains` rows
//!
//! Each `build_attack_chain` call corresponds to ONE chain at ONE stage.
//! For N `finding_ids`, we mint N unique node ids
//! (`AC-<eng8>-<chain_idx>-<i>`) and link them in order via
//! `next_chain_id`. The `id` column is the table's PRIMARY KEY, so the
//! per-call chain index alone is not enough — we suffix the in-chain
//! index as well.
//!
//! On a successful permit, we append a `chain_builder` permit entry to
//! the hash-chained audit journal. There is no Cedar gate here in Task
//! 21: the per-agent Cedar permits live alongside the .symbi manifest
//! and are wired in Task 22 (manifest registration). The executor is
//! structured so a future gate would slot in alongside the
//! [`do_build`] path.

use rusqlite::Connection;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Mutex;
#[cfg(test)]
use std::path::Path;
use uuid::Uuid;

use chrono::Utc;
use symbi_codered_core::{audit, db};
use symbi_evidence_schema::{attack_chain::KillChainStage, AttackChainNode};

use crate::pattern_scout_tools;
use symbi_runtime::reasoning::circuit_breaker::CircuitBreakerRegistry;
use symbi_runtime::reasoning::executor::ActionExecutor;
use symbi_runtime::reasoning::loop_types::{LoopConfig, Observation, ProposedAction};

/// Per-run counters reported back to the caller after the loop terminates.
#[derive(Default)]
pub struct ChainBuilderInner {
    pub chains_built: usize,
    pub nodes_inserted: usize,
    pub tool_calls: usize,
}

/// `ActionExecutor` for chain_builder. The runner (`super::run`) keeps an
/// `Arc` to this executor so it can read [`Self::summary`] after
/// `CoderedOrga::run` completes.
pub struct ChainBuilderExecutor {
    pub engagement_id: Uuid,
    pub db_path: PathBuf,
    pub journal_path: PathBuf,
    pub state: Mutex<ChainBuilderInner>,
}

impl ChainBuilderExecutor {
    pub fn new(engagement_id: Uuid, db_path: PathBuf, journal_path: PathBuf) -> Self {
        Self {
            engagement_id,
            db_path,
            journal_path,
            state: Mutex::new(ChainBuilderInner::default()),
        }
    }

    /// Snapshot the per-run counters into the public `ChainSummary` type.
    pub fn summary(&self) -> super::ChainSummary {
        let s = self.state.lock().expect("chain_builder summary mutex poisoned");
        super::ChainSummary {
            chains_built: s.chains_built,
            nodes_inserted: s.nodes_inserted,
            tool_calls: s.tool_calls,
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
        // chain_builder defaults to compact: it only needs id+file:line+cwe to cluster.
        let compact = args.get("compact").and_then(|v| v.as_bool()).unwrap_or(true);
        match pattern_scout_tools::query_findings(&conn, self.engagement_id, tool_origin, page, page_size, compact) {
            Ok(v) => Observation::tool_result("query_findings", v.to_string()),
            Err(e) => Observation::tool_error("query_findings", e.to_string()),
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

    /// Build one attack chain at one stage. The agent passes:
    ///
    /// - `stage`: one of the seven snake_case kill-chain stage names
    /// - `finding_ids`: non-empty array of finding ids that constitute
    ///   this chain at this stage, in causal order
    /// - `rationale` (optional): short string explaining why these
    ///   findings cluster at this stage. Defaults to an auto-generated
    ///   stub so the NOT NULL column is always satisfied.
    ///
    /// Writes one `attack_chains` row per finding id, linked in order
    /// via `next_chain_id`. The first row in the chain is the one the
    /// agent would walk from; the last has `next_chain_id = NULL`.
    fn do_build(&self, args: &Value) -> Observation {
        let conn = match self.open_conn() {
            Ok(c) => c,
            Err(e) => return Observation::tool_error("build_attack_chain", e),
        };

        let stage_str = args
            .get("stage")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let stage = match parse_stage(&stage_str) {
            Some(s) => s,
            None => {
                return Observation::tool_error(
                    "build_attack_chain",
                    format!(
                        "unknown stage: {stage_str:?}; valid: surface_mapping, \
                         tool_subversion, instruction_injection, reasoning_capture, \
                         gate_evasion, privileged_action, audit_evasion"
                    ),
                )
            }
        };

        let finding_ids: Vec<String> = args
            .get("finding_ids")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        if finding_ids.is_empty() {
            return Observation::tool_error(
                "build_attack_chain",
                "finding_ids required (non-empty array of strings)",
            );
        }

        let rationale = args
            .get("rationale")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(String::from)
            .unwrap_or_else(|| {
                format!(
                    "chain_builder cluster: {} findings at stage {stage_str}",
                    finding_ids.len()
                )
            });

        // Reserve the chain index up front so the minted node ids are
        // stable even if a later insert fails (we won't reuse the index).
        let chain_idx = {
            let mut s = self.state.lock().expect("chain_builder summary mutex poisoned");
            let idx = s.chains_built;
            s.chains_built += 1;
            idx
        };

        // Mint all node ids first so we can compute `next_chain_id`
        // forward references in one pass.
        let eng8 = &self.engagement_id.simple().to_string()[..8];
        let node_ids: Vec<String> = (0..finding_ids.len())
            .map(|i| format!("AC-{eng8}-{chain_idx:04}-{i:03}"))
            .collect();

        let now = Utc::now();
        let mut inserted = 0usize;
        // Insert tail-first so each row's `next_chain_id` FK resolves
        // against an already-present row. The schema's `next_chain_id`
        // is a self-FK on `attack_chains(id)` and SQLite does not defer
        // FK checks by default — reverse order is the simplest way to
        // satisfy the constraint without touching pragmas.
        for i in (0..finding_ids.len()).rev() {
            let nid = &node_ids[i];
            let fid = &finding_ids[i];
            let next = node_ids.get(i + 1).cloned();
            let node = AttackChainNode {
                id: nid.clone(),
                engagement_id: self.engagement_id,
                stage,
                finding_id: Some(fid.clone()),
                evidence_id: None,
                next_chain_id: next,
                rationale: rationale.clone(),
                created_at: now,
            };
            if let Err(e) = db::insert_attack_chain_node(&conn, &node) {
                // Roll the counter forward by what we DID insert; the
                // chain_idx is already consumed so the agent can retry
                // without colliding. Surface the error.
                let mut s = self.state.lock().expect("chain_builder summary mutex poisoned");
                s.nodes_inserted += inserted;
                return Observation::tool_error(
                    "build_attack_chain",
                    format!("insert node {nid}: {e}"),
                );
            }
            inserted += 1;
        }

        {
            let mut s = self.state.lock().expect("chain_builder summary mutex poisoned");
            s.nodes_inserted += inserted;
        }

        if let Err(e) = audit::append_entry(
            &self.journal_path,
            "chain_builder",
            "execute_tool",
            "Audit::ChainBuilder",
            "permit",
            None,
        ) {
            tracing::warn!(error = %e, "failed to append chain_builder permit journal entry");
        }

        Observation::tool_result(
            "build_attack_chain",
            json!({
                "chain_head_id": node_ids.first().cloned().unwrap_or_default(),
                "stage":         stage_str,
                "nodes":         inserted,
                "node_ids":      node_ids,
            })
            .to_string(),
        )
    }
}

#[async_trait::async_trait]
impl ActionExecutor for ChainBuilderExecutor {
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
                    let mut s = self.state.lock().expect("chain_builder summary mutex poisoned");
                    s.tool_calls += 1;
                }
                let parsed: Value = serde_json::from_str(arguments).unwrap_or(Value::Null);
                let obs = match name.as_str() {
                    "query_findings" => self.do_query_findings(&parsed),
                    "query_taint_chains" => self.do_query_taint_chains(&parsed),
                    "build_attack_chain" => self.do_build(&parsed),
                    other => {
                        Observation::tool_error(name.clone(), format!("unknown tool: {other}"))
                    }
                };
                observations.push(obs.with_call_id(call_id.clone()));
            }
        }
        observations
    }
}

fn parse_stage(s: &str) -> Option<KillChainStage> {
    match s {
        "surface_mapping" => Some(KillChainStage::SurfaceMapping),
        "tool_subversion" => Some(KillChainStage::ToolSubversion),
        "instruction_injection" => Some(KillChainStage::InstructionInjection),
        "reasoning_capture" => Some(KillChainStage::ReasoningCapture),
        "gate_evasion" => Some(KillChainStage::GateEvasion),
        "privileged_action" => Some(KillChainStage::PrivilegedAction),
        "audit_evasion" => Some(KillChainStage::AuditEvasion),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use symbi_evidence_schema::{
        finding::{Confidence, Phase, Severity, Status},
        Engagement, Finding,
    };
    use tempfile::TempDir;

    fn fresh_executor() -> (TempDir, PathBuf, ChainBuilderExecutor, Uuid) {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("codered.db");
        let journal_path = dir.path().join("journal.jsonl");
        let conn = db::init_db(db_path.to_str().unwrap()).unwrap();
        let e = Engagement::new("acme", "h", "2026-05-24", "2026-05-31");
        let eid = e.id;
        db::insert_engagement(&conn, &e).unwrap();
        drop(conn);
        let exec = ChainBuilderExecutor::new(eid, db_path.clone(), journal_path);
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
        // The findings table has an FK to evidence; insert a dummy evidence
        // row first so the finding insert succeeds.
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
    async fn unknown_tool_returns_error_observation_with_call_id() {
        let (_dir, _db, exec, _eid) = fresh_executor();
        let actions = vec![ProposedAction::ToolCall {
            call_id: "c1".into(),
            name: "not_a_real_tool".into(),
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
    async fn build_attack_chain_writes_linked_nodes() {
        let (_dir, db_path, exec, eid) = fresh_executor();
        insert_finding(&db_path, eid, "F-1", "env-1");
        insert_finding(&db_path, eid, "F-2", "env-2");

        let args = json!({
            "stage":      "tool_subversion",
            "finding_ids": ["F-1", "F-2"],
            "rationale":   "Both findings target the same dangerous tool param",
        });
        let actions = vec![ProposedAction::ToolCall {
            call_id: "c1".into(),
            name: "build_attack_chain".into(),
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
        assert_eq!(v.get("nodes").and_then(|x| x.as_u64()), Some(2));
        assert_eq!(v.get("stage").and_then(|x| x.as_str()), Some("tool_subversion"));

        let summary = exec.summary();
        assert_eq!(summary.chains_built, 1);
        assert_eq!(summary.nodes_inserted, 2);
        assert_eq!(summary.tool_calls, 1);

        let conn = db::init_db(db_path.to_str().unwrap()).unwrap();
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM attack_chains", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 2);
        // The first row points at the second.
        let head: String = conn
            .query_row(
                "SELECT next_chain_id FROM attack_chains WHERE finding_id = 'F-1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let tail: Option<String> = conn
            .query_row(
                "SELECT next_chain_id FROM attack_chains WHERE finding_id = 'F-2'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(head.starts_with("AC-"));
        assert!(tail.is_none(), "last node must have NULL next_chain_id");
    }

    #[tokio::test]
    async fn build_attack_chain_rejects_unknown_stage() {
        let (_dir, _db, exec, _eid) = fresh_executor();
        let args = json!({
            "stage":      "lateral_movement",
            "finding_ids": ["F-1"],
        });
        let actions = vec![ProposedAction::ToolCall {
            call_id: "c1".into(),
            name: "build_attack_chain".into(),
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
        assert!(obs[0].content.contains("unknown stage"));
        // Counter must NOT advance on validation failure.
        assert_eq!(exec.summary().chains_built, 0);
        assert_eq!(exec.summary().nodes_inserted, 0);
    }

    #[tokio::test]
    async fn build_attack_chain_rejects_empty_finding_ids() {
        let (_dir, _db, exec, _eid) = fresh_executor();
        let args = json!({
            "stage":       "surface_mapping",
            "finding_ids": [],
        });
        let actions = vec![ProposedAction::ToolCall {
            call_id: "c1".into(),
            name: "build_attack_chain".into(),
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
        assert!(obs[0].content.contains("non-empty"));
        assert_eq!(exec.summary().chains_built, 0);
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

    #[test]
    fn parse_stage_round_trips_all_seven() {
        for s in [
            "surface_mapping",
            "tool_subversion",
            "instruction_injection",
            "reasoning_capture",
            "gate_evasion",
            "privileged_action",
            "audit_evasion",
        ] {
            assert!(parse_stage(s).is_some(), "stage {s} should parse");
        }
        assert!(parse_stage("nope").is_none());
        assert!(parse_stage("").is_none());
    }
}
