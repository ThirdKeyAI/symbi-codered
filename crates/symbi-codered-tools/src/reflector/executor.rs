//! reflector's ORGA `ActionExecutor`.
//!
//! Plan G Task 4. Dispatches five tools:
//!
//! - `query_findings`        — delegates to [`crate::pattern_scout_tools::query_findings`]
//! - `query_finding_detail`  — delegates to [`crate::pattern_scout_tools::query_finding_detail`]
//! - `query_taint_chains`    — delegates to [`crate::pattern_scout_tools::query_taint_chains`]
//! - `query_attack_chains`   — paginated read of the `attack_chains` table
//! - `write_knowledge_triple` — inserts one `knowledge_triples` row via
//!   [`symbi_codered_core::db::insert_knowledge_triple`] and appends a
//!   `reflector` permit entry to the hash-chained audit journal.
//!
//! Subject / predicate / object are required string args.
//! Confidence is optional (number 0-1; clamped) and rationale is optional.
//! Each successful write mints a stable id of the form `KT-<eng8>-<count>`.
//! The Cedar gate that prevents `store_finding` from this principal lives
//! alongside the `.symbi` manifest (Task 2) — this executor only refuses
//! unknown tool names; it does not need to police `store_finding`
//! explicitly.

use rusqlite::Connection;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Mutex;
use uuid::Uuid;

use chrono::Utc;
use symbi_codered_core::{audit, db};

use crate::pattern_scout_tools;
use symbi_runtime::reasoning::circuit_breaker::CircuitBreakerRegistry;
use symbi_runtime::reasoning::executor::ActionExecutor;
use symbi_runtime::reasoning::loop_types::{LoopConfig, Observation, ProposedAction};

/// Per-run counters reported back to the caller after the loop terminates.
#[derive(Default)]
pub struct ReflectorInner {
    pub triples_written: usize,
    pub tool_calls: usize,
}

/// `ActionExecutor` for reflector. The runner (`super::run`) keeps an `Arc`
/// to this executor so it can read [`Self::summary`] after `CoderedOrga::run`
/// completes.
pub struct ReflectorExecutor {
    pub engagement_id: Uuid,
    pub db_path: PathBuf,
    pub journal_path: PathBuf,
    pub state: Mutex<ReflectorInner>,
}

impl ReflectorExecutor {
    pub fn new(engagement_id: Uuid, db_path: PathBuf, journal_path: PathBuf) -> Self {
        Self {
            engagement_id,
            db_path,
            journal_path,
            state: Mutex::new(ReflectorInner::default()),
        }
    }

    /// Snapshot the per-run counters into the public `ReflectSummary` type.
    pub fn summary(&self) -> super::ReflectSummary {
        let s = self.state.lock().expect("reflector summary mutex poisoned");
        super::ReflectSummary {
            triples_written: s.triples_written,
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
        // reflector defaults to compact: it walks pages to form a model, then
        // can query_finding_detail for any row whose description it needs.
        let compact = args.get("compact").and_then(|v| v.as_bool()).unwrap_or(true);
        match pattern_scout_tools::query_findings(&conn, self.engagement_id, tool_origin, page, page_size, compact) {
            Ok(v) => Observation::tool_result("query_findings", v.to_string()),
            Err(e) => Observation::tool_error("query_findings", e.to_string()),
        }
    }

    fn do_query_finding_detail(&self, args: &Value) -> Observation {
        let finding_id = args.get("finding_id").and_then(|v| v.as_str()).unwrap_or("");
        if finding_id.is_empty() {
            return Observation::tool_error("query_finding_detail", "finding_id required");
        }
        let conn = match self.open_conn() {
            Ok(c) => c,
            Err(e) => return Observation::tool_error("query_finding_detail", e),
        };
        match pattern_scout_tools::query_finding_detail(&conn, self.engagement_id, finding_id) {
            Ok(Some(v)) => Observation::tool_result("query_finding_detail", v.to_string()),
            Ok(None) => Observation::tool_error(
                "query_finding_detail",
                format!("finding {finding_id} not found in engagement"),
            ),
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

    /// Paginated read of `attack_chains` rows for this engagement. Mirrors the
    /// shape of `query_findings`'s response: `{nodes, page, page_size, total,
    /// returned, has_more}`. `page` is 0-indexed; `page_size` clamped to
    /// `[1, 100]` with a default of 30 (matches
    /// [`crate::pattern_scout_tools::DEFAULT_PAGE_SIZE`]).
    fn do_query_attack_chains(&self, args: &Value) -> Observation {
        let conn = match self.open_conn() {
            Ok(c) => c,
            Err(e) => return Observation::tool_error("query_attack_chains", e),
        };
        let page = args.get("page").and_then(|v| v.as_u64()).unwrap_or(0) as i64;
        let page_size = args
            .get("page_size")
            .and_then(|v| v.as_u64())
            .map(|n| n as u32)
            .unwrap_or(30)
            .clamp(1, 100) as i64;
        let offset = page * page_size;
        let eid = self.engagement_id.to_string();

        let total: i64 = match conn.query_row(
            "SELECT COUNT(*) FROM attack_chains WHERE engagement_id = ?1",
            rusqlite::params![&eid],
            |r| r.get(0),
        ) {
            Ok(n) => n,
            Err(e) => {
                return Observation::tool_error("query_attack_chains", format!("count: {e}"));
            }
        };

        let mut stmt = match conn.prepare(
            "SELECT id, stage, finding_id, evidence_id, next_chain_id, rationale, created_at
             FROM attack_chains
             WHERE engagement_id = ?1
             ORDER BY id LIMIT ?2 OFFSET ?3",
        ) {
            Ok(s) => s,
            Err(e) => {
                return Observation::tool_error("query_attack_chains", format!("prepare: {e}"));
            }
        };
        let rows_iter = match stmt.query_map(rusqlite::params![&eid, page_size, offset], |r| {
            Ok(json!({
                "id":            r.get::<_, String>(0)?,
                "stage":         r.get::<_, String>(1)?,
                "finding_id":    r.get::<_, Option<String>>(2)?,
                "evidence_id":   r.get::<_, Option<String>>(3)?,
                "next_chain_id": r.get::<_, Option<String>>(4)?,
                "rationale":     r.get::<_, String>(5)?,
                "created_at":    r.get::<_, String>(6)?,
            }))
        }) {
            Ok(it) => it,
            Err(e) => {
                return Observation::tool_error("query_attack_chains", format!("query: {e}"));
            }
        };
        let rows: Vec<Value> = rows_iter.filter_map(|r| r.ok()).collect();
        let returned = rows.len() as i64;
        let has_more = offset + returned < total;
        Observation::tool_result(
            "query_attack_chains",
            json!({
                "nodes":     rows,
                "page":      page,
                "page_size": page_size,
                "total":     total,
                "returned":  returned,
                "has_more":  has_more,
            })
            .to_string(),
        )
    }

    /// Insert one `knowledge_triples` row. The agent passes:
    ///
    /// - `subject`, `predicate`, `object`: required non-empty strings
    /// - `confidence` (optional): number; clamped to `[0.0, 1.0]`
    /// - `rationale` (optional): free-form explanation
    ///
    /// `id` is minted as `KT-<eng8>-<count>` from a monotonically-incrementing
    /// per-run counter, so successive calls within one ORGA loop never
    /// collide. `source_phase` is hard-coded to `"reflector"`.
    fn do_write_knowledge_triple(&self, args: &Value) -> Observation {
        let subject = args.get("subject").and_then(|v| v.as_str()).unwrap_or("");
        let predicate = args.get("predicate").and_then(|v| v.as_str()).unwrap_or("");
        let object = args.get("object").and_then(|v| v.as_str()).unwrap_or("");
        if subject.is_empty() || predicate.is_empty() || object.is_empty() {
            return Observation::tool_error(
                "write_knowledge_triple",
                format!(
                    "subject, predicate, object are all required non-empty strings; \
                     got subject={subject:?} predicate={predicate:?} object={object:?}"
                ),
            );
        }
        let confidence = args
            .get("confidence")
            .and_then(|v| v.as_f64())
            .map(|c| c.clamp(0.0, 1.0));
        let rationale = args
            .get("rationale")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(String::from);

        let conn = match self.open_conn() {
            Ok(c) => c,
            Err(e) => return Observation::tool_error("write_knowledge_triple", e),
        };

        // Reserve the index up front so the minted id is stable even if
        // insert fails (we won't reuse the index).
        let idx = {
            let mut s = self.state.lock().expect("reflector summary mutex poisoned");
            let i = s.triples_written;
            s.triples_written += 1;
            i
        };
        let eng8 = &self.engagement_id.simple().to_string()[..8];
        let id = format!("KT-{eng8}-{idx:04}");

        let kt = db::KnowledgeTriple {
            id: id.clone(),
            engagement_id: self.engagement_id,
            subject: subject.to_string(),
            predicate: predicate.to_string(),
            object: object.to_string(),
            confidence,
            rationale,
            source_phase: "reflector".to_string(),
            created_at: Utc::now(),
        };
        if let Err(e) = db::insert_knowledge_triple(&conn, &kt) {
            // Roll the counter back so the index isn't burned on a transient
            // insert failure (e.g. unique-constraint racing in tests).
            {
                let mut s = self.state.lock().expect("reflector summary mutex poisoned");
                if s.triples_written > 0 {
                    s.triples_written -= 1;
                }
            }
            return Observation::tool_error(
                "write_knowledge_triple",
                format!("insert {id}: {e}"),
            );
        }

        if let Err(e) = audit::append_entry(
            &self.journal_path,
            "reflector",
            "write_knowledge_triple",
            format!(r#"KnowledgeTriple::"{id}""#),
            "permit",
            None,
        ) {
            tracing::warn!(
                error = %e,
                "failed to append reflector permit journal entry"
            );
        }

        Observation::tool_result(
            "write_knowledge_triple",
            json!({
                "id":         id,
                "subject":    subject,
                "predicate":  predicate,
                "object":     object,
                "confidence": confidence,
                "status":     "ok",
            })
            .to_string(),
        )
    }
}

#[async_trait::async_trait]
impl ActionExecutor for ReflectorExecutor {
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
                    let mut s = self.state.lock().expect("reflector summary mutex poisoned");
                    s.tool_calls += 1;
                }
                let parsed: Value = serde_json::from_str(arguments).unwrap_or(Value::Null);
                let obs = match name.as_str() {
                    "query_findings" => self.do_query_findings(&parsed),
                    "query_finding_detail" => self.do_query_finding_detail(&parsed),
                    "query_taint_chains" => self.do_query_taint_chains(&parsed),
                    "query_attack_chains" => self.do_query_attack_chains(&parsed),
                    "write_knowledge_triple" => self.do_write_knowledge_triple(&parsed),
                    other => Observation::tool_error(
                        name.clone(),
                        format!("unknown tool for reflector: {other}"),
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
    use symbi_evidence_schema::Engagement;
    use tempfile::TempDir;

    fn fresh_executor() -> (TempDir, PathBuf, ReflectorExecutor, Uuid) {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("codered.db");
        let journal_path = dir.path().join("journal.jsonl");
        let conn = db::init_db(db_path.to_str().unwrap()).unwrap();
        let e = Engagement::new("acme", "h", "2026-05-24", "2026-05-31");
        let eid = e.id;
        db::insert_engagement(&conn, &e).unwrap();
        drop(conn);
        let exec = ReflectorExecutor::new(eid, db_path.clone(), journal_path);
        (dir, db_path, exec, eid)
    }

    #[tokio::test]
    async fn write_knowledge_triple_writes_row_and_bumps_counter() {
        let (_dir, db_path, exec, eid) = fresh_executor();
        let args = json!({
            "subject":    "axum::extract::Query",
            "predicate":  "is_taint_source_for",
            "object":     "sqlx::query",
            "confidence": 0.85,
            "rationale":  "Two findings in engagement chained Query->sqlx",
        });
        let actions = vec![ProposedAction::ToolCall {
            call_id: "c1".into(),
            name: "write_knowledge_triple".into(),
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
        assert_eq!(v.get("subject").and_then(|x| x.as_str()), Some("axum::extract::Query"));
        assert_eq!(v.get("status").and_then(|x| x.as_str()), Some("ok"));
        assert!(v.get("id").and_then(|x| x.as_str()).unwrap().starts_with("KT-"));

        let summary = exec.summary();
        assert_eq!(summary.triples_written, 1);
        assert_eq!(summary.tool_calls, 1);

        // Row materialized in DB.
        let conn = db::init_db(db_path.to_str().unwrap()).unwrap();
        let row_count = db::count_knowledge_triples(&conn, eid).unwrap();
        assert_eq!(row_count, 1);
        let rows = db::list_knowledge_triples(&conn, eid, 0, None).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].subject, "axum::extract::Query");
        assert_eq!(rows[0].predicate, "is_taint_source_for");
        assert_eq!(rows[0].object, "sqlx::query");
        assert_eq!(rows[0].confidence, Some(0.85));
        assert_eq!(rows[0].source_phase, "reflector");
    }

    #[tokio::test]
    async fn write_knowledge_triple_rejects_missing_object() {
        let (_dir, _db, exec, _eid) = fresh_executor();
        let args = json!({
            "subject":   "axum::extract::Query",
            "predicate": "is_taint_source_for",
            // object missing
        });
        let actions = vec![ProposedAction::ToolCall {
            call_id: "c1".into(),
            name: "write_knowledge_triple".into(),
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
        assert!(obs[0].is_error);
        assert!(obs[0].content.contains("required"));
        // Counter must NOT advance on validation failure.
        assert_eq!(exec.summary().triples_written, 0);
        assert_eq!(exec.summary().tool_calls, 1);
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
    async fn query_attack_chains_returns_paginated_envelope() {
        let (_dir, db_path, exec, eid) = fresh_executor();
        // Seed two attack_chain rows directly.
        let conn = db::init_db(db_path.to_str().unwrap()).unwrap();
        use symbi_evidence_schema::{attack_chain::KillChainStage, AttackChainNode};
        for i in 0..2 {
            let n = AttackChainNode {
                id: format!("AC-{i:04}"),
                engagement_id: eid,
                stage: KillChainStage::SurfaceMapping,
                finding_id: None,
                evidence_id: None,
                next_chain_id: None,
                rationale: format!("node {i}"),
                created_at: Utc::now(),
            };
            db::insert_attack_chain_node(&conn, &n).unwrap();
        }
        drop(conn);

        let actions = vec![ProposedAction::ToolCall {
            call_id: "c1".into(),
            name: "query_attack_chains".into(),
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
        assert_eq!(v.get("total").and_then(|x| x.as_i64()), Some(2));
        assert_eq!(v.get("returned").and_then(|x| x.as_i64()), Some(2));
        let arr = v.get("nodes").and_then(|x| x.as_array()).expect("nodes array");
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0].get("stage").and_then(|x| x.as_str()), Some("surface_mapping"));
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
