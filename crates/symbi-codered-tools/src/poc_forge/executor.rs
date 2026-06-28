//! poc_forge's ORGA `ActionExecutor`.
//!
//! Plan E Tasks 11 + 12. Dispatches four tools:
//!
//! - `query_findings`     — delegates to
//!   [`symbi_codered_core::db::list_poc_candidates`] (already filters
//!   to CWE-89/78/22/94/79, `status = 'open'`, `poc_status IS NULL`)
//! - `read_context_range` — delegates to
//!   [`crate::pattern_scout_tools::read_context_range`] after enforcing
//!   that the requested path is inside `target_repo` (canonicalize both
//!   and verify the prefix; refuses symlink escapes)
//! - `run_reproducer`     — ships the script to the python-sandbox
//!   sidecar via [`crate::sandbox_client::run_reproducer`]
//! - `mark_poc_status`    — writes `reproduced` / `refuted` via
//!   [`symbi_codered_core::db::set_poc_status`] and appends a permit
//!   entry to the hash-chained audit journal
//!
//! Validation: `mark_poc_status` rejects anything other than
//! `"reproduced"`, `"refuted"`, or `"reproduced_by_citation"`. A
//! `reproduced*` label additionally requires a persisted PoC exhibit — a
//! `poc` citation written by `run_reproducer` (on a sandbox verdict of
//! `reproduced`) or `emit_source_proof` (verified source citations). The DB
//! layer ([`symbi_codered_core::db::set_poc_status`]) enforces this, so the
//! label can never outrun the evidence. `run_reproducer` requires a non-empty
//! `script`. `read_context_range` refuses any path that — after
//! canonicalization — does not live under the engagement's
//! `target_repo` root.

use rusqlite::Connection;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Mutex;
use uuid::Uuid;

use symbi_codered_core::{audit, db};

use crate::pattern_scout_tools;
use crate::sandbox_client;
use symbi_runtime::reasoning::circuit_breaker::CircuitBreakerRegistry;
use symbi_runtime::reasoning::executor::ActionExecutor;
use symbi_runtime::reasoning::loop_types::{LoopConfig, Observation, ProposedAction};

/// Map a finding's file extension to a sandbox language tag.
///
/// Returns `None` for unrecognized extensions so the caller can fall
/// back to the python sandbox (the historic default).
fn infer_language(file_path: &str) -> Option<String> {
    let p = std::path::Path::new(file_path);
    let ext = p.extension()?.to_str()?.to_ascii_lowercase();
    Some(
        match ext.as_str() {
            "py" => "python",
            "rs" => "rust",
            "ts" | "tsx" => "typescript",
            "js" | "jsx" | "mjs" | "cjs" => "javascript",
            "go" => "go",
            "php" => "php",
            _ => return None,
        }
        .into(),
    )
}

/// Per-run counters reported back to the caller after the loop terminates.
#[derive(Default)]
pub struct PocForgeInner {
    pub reproduced: usize,
    pub refuted: usize,
    /// `mark_poc_status` calls with status = "inconclusive" — the reproducer
    /// could not run (compile/sandbox error, timeout), so the finding is
    /// neither proven nor disproven and stays in play for a human.
    pub inconclusive: usize,
    pub scripts_run: usize,
    pub tool_calls: usize,
    /// Per-finding record of whether the LAST `run_reproducer` for that finding
    /// was an environmental failure (timed out / sandbox error / non-zero exit
    /// without reproduction). Used to refuse a `refuted` label that would
    /// masquerade a non-execution as a disproof.
    pub last_run_env_failure: std::collections::HashMap<String, bool>,
}

/// `ActionExecutor` for poc_forge. The runner (`super::run`) keeps an
/// `Arc` to this executor so it can read [`Self::summary`] after
/// `CoderedOrga::run` completes.
pub struct PocForgeExecutor {
    pub engagement_id: Uuid,
    pub db_path: PathBuf,
    pub journal_path: PathBuf,
    pub target_repo: PathBuf,
    /// Default / python sandbox container name.
    pub sandbox_container: String,
    /// Rust sandbox container name (Plan F).
    pub rust_sandbox_container: String,
    /// TypeScript / JavaScript sandbox container name (Plan F).
    pub typescript_sandbox_container: String,
    /// Go sandbox container name (Plan F).
    pub go_sandbox_container: String,
    /// PHP sandbox container name.
    pub php_sandbox_container: String,
    pub state: Mutex<PocForgeInner>,
}

impl PocForgeExecutor {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        engagement_id: Uuid,
        db_path: PathBuf,
        journal_path: PathBuf,
        target_repo: PathBuf,
        sandbox_container: String,
        rust_sandbox_container: String,
        typescript_sandbox_container: String,
        go_sandbox_container: String,
        php_sandbox_container: String,
    ) -> Self {
        Self {
            engagement_id,
            db_path,
            journal_path,
            target_repo,
            sandbox_container,
            rust_sandbox_container,
            typescript_sandbox_container,
            go_sandbox_container,
            php_sandbox_container,
            state: Mutex::new(PocForgeInner::default()),
        }
    }

    /// Snapshot the per-run counters into the public `PocSummary` type.
    pub fn summary(&self) -> super::PocSummary {
        let s = self.state.lock().expect("poc_forge summary mutex poisoned");
        super::PocSummary {
            reproduced: s.reproduced,
            refuted: s.refuted,
            inconclusive: s.inconclusive,
            scripts_run: s.scripts_run,
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
        let page = args.get("page").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        let page_size = args
            .get("page_size")
            .and_then(|v| v.as_u64())
            .map(|n| n as u32);
        let total = match db::count_poc_candidates(&conn, self.engagement_id) {
            Ok(n) => n,
            Err(e) => return Observation::tool_error("query_findings", format!("{e}")),
        };
        match db::list_poc_candidates(&conn, self.engagement_id, page, page_size) {
            Ok(rows) => {
                let returned = rows.len() as i64;
                let effective_page_size = page_size.unwrap_or(30).clamp(1, 100) as i64;
                let offset = (page as i64) * effective_page_size;
                let has_more = offset + returned < total;
                let findings: Vec<Value> = rows
                    .into_iter()
                    .map(|(id, file_path, title, cwe, ls, le)| {
                        json!({
                            "id":         id,
                            "file_path":  file_path,
                            "title":      title,
                            "cwe":        cwe,
                            "line_start": ls,
                            "line_end":   le,
                        })
                    })
                    .collect();
                let envelope = json!({
                    "findings":  findings,
                    "page":      page,
                    "page_size": effective_page_size,
                    "total":     total,
                    "returned":  returned,
                    "has_more":  has_more,
                });
                Observation::tool_result("query_findings", envelope.to_string())
            }
            Err(e) => Observation::tool_error("query_findings", format!("{e}")),
        }
    }

    fn do_read_context(&self, args: &Value) -> Observation {
        let file = args.get("file_path").and_then(|v| v.as_str()).unwrap_or("");
        if file.is_empty() {
            return Observation::tool_error(
                "read_context_range",
                "file_path required",
            );
        }
        let ls = args.get("line_start").and_then(|v| v.as_i64()).unwrap_or(1);
        let le = args.get("line_end").and_then(|v| v.as_i64()).unwrap_or(ls);

        // Path-traversal guard: canonicalize the engagement's target_repo
        // root and the requested file, then verify the file's canonical
        // path lives under the root. This refuses both `..` traversal and
        // symlink escapes.
        let canon_root = match self.target_repo.canonicalize() {
            Ok(p) => p,
            Err(e) => {
                return Observation::tool_error(
                    "read_context_range",
                    format!("canonicalize target_repo: {e}"),
                )
            }
        };
        let requested = self.target_repo.join(file);
        let canon = match requested.canonicalize() {
            Ok(p) => p,
            Err(e) => {
                return Observation::tool_error(
                    "read_context_range",
                    format!("canonicalize requested path: {e}"),
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

    fn do_run_reproducer(&self, args: &Value) -> Observation {
        let script = args.get("script").and_then(|v| v.as_str()).unwrap_or("");
        if script.is_empty() {
            return Observation::tool_error("run_reproducer", "script required");
        }
        let timeout = args
            .get("timeout_seconds")
            .and_then(|v| v.as_u64())
            .unwrap_or(30) as u32;

        // Language dispatch: explicit `language` arg wins; otherwise look up
        // the referenced finding's file_path in DB and infer from its
        // extension; otherwise default to the python sandbox.
        let explicit_lang = args
            .get("language")
            .and_then(|v| v.as_str())
            .map(|s| s.to_ascii_lowercase());
        let inferred_lang = if explicit_lang.is_none() {
            args.get("finding_id")
                .and_then(|v| v.as_str())
                .and_then(|fid| {
                    let conn = self.open_conn().ok()?;
                    let fp: String = conn
                        .query_row(
                            "SELECT file_path FROM findings WHERE id = ?1",
                            rusqlite::params![fid],
                            |r| r.get(0),
                        )
                        .ok()?;
                    infer_language(&fp)
                })
        } else {
            None
        };
        let lang = explicit_lang.or(inferred_lang);

        let container: &str = match lang.as_deref() {
            None | Some("python") => &self.sandbox_container,
            Some("rust") => &self.rust_sandbox_container,
            Some("typescript") | Some("javascript") => &self.typescript_sandbox_container,
            Some("go") => &self.go_sandbox_container,
            Some("php") => &self.php_sandbox_container,
            Some(other) => {
                return Observation::tool_error(
                    "run_reproducer",
                    format!(
                        "unsupported language {other:?}; expected one of \
                         python|rust|typescript|javascript|go|php"
                    ),
                );
            }
        };

        {
            let mut s = self.state.lock().expect("poc_forge summary mutex poisoned");
            s.scripts_run += 1;
        }

        let req = sandbox_client::SandboxRequest {
            script: script.to_string(),
            timeout_seconds: timeout,
        };
        let finding_id = args.get("finding_id").and_then(|v| v.as_str()).unwrap_or("");
        match sandbox_client::run_reproducer(container, &req) {
            Ok(resp) => {
                let language = lang.as_deref().unwrap_or("python");
                // Persist a PoC exhibit ONLY for an actual reproduction (the
                // sandbox sets verdict=="reproduced" iff the script printed the
                // REPRODUCED sentinel). This is the durable proof that
                // `mark_poc_status reproduced` will later require — binding the
                // label to a real sandbox run rather than the model's say-so.

                // Classify the run STRUCTURALLY so a non-reproduction can't be
                // silently mislabeled `refuted`. An environmental failure — a
                // timeout, a sandbox/tool error, or a non-zero exit without
                // reproduction — means the exploit was NOT actually tested.
                // That is `inconclusive`, never `refuted`. Recorded per-finding
                // so `mark_poc_status` can refuse a masqueraded refutation.
                let env_failure = resp.timed_out
                    || !resp.ok
                    || resp.error.is_some()
                    || (resp.verdict != "reproduced" && resp.exit_code != 0);
                let (outcome, suggested_status) = if resp.verdict == "reproduced" {
                    ("reproduced", "reproduced")
                } else if env_failure {
                    ("errored_or_incomplete", "inconclusive")
                } else {
                    ("ran_no_reproduction", "refuted")
                };
                if !finding_id.is_empty() {
                    self.state
                        .lock()
                        .expect("poc_forge summary mutex poisoned")
                        .last_run_env_failure
                        .insert(finding_id.to_string(), env_failure);
                }

                if resp.verdict == "reproduced" && !finding_id.is_empty() {
                    if let Ok(conn) = self.open_conn() {
                        let exhibit = json!({
                            "kind": "reproducer",
                            "verdict": resp.verdict,
                            "language": language,
                            "exit_code": resp.exit_code,
                            "script": script,
                            "stdout": resp.stdout,
                            "stderr": resp.stderr,
                        })
                        .to_string();
                        if let Err(e) = db::record_poc_artifact(&conn, finding_id, &exhibit) {
                            tracing::warn!(error = %e, finding_id, "failed to persist poc exhibit");
                        }
                    }
                }
                Observation::tool_result(
                    "run_reproducer",
                    json!({
                        "verdict":   resp.verdict,
                        "ok":        resp.ok,
                        "exit_code": resp.exit_code,
                        "timed_out": resp.timed_out,
                        "stdout":    resp.stdout,
                        "stderr":    resp.stderr,
                        "language":  language,
                        // Structural routing hint for mark_poc_status. The agent
                        // should pass `suggested_status` unless it has a reason to
                        // override (which the journal will record).
                        "outcome":   outcome,
                        "suggested_status": suggested_status,
                    })
                    .to_string(),
                )
            }
            Err(e) => {
                // The reproducer could not run at all — container unreachable,
                // docker error, or sandbox-internal error. That is an
                // environmental failure: the exploit was NOT tested. Record it
                // so a later `refuted` for this finding is refused (the honest
                // label is inconclusive).
                if !finding_id.is_empty() {
                    self.state
                        .lock()
                        .expect("poc_forge summary mutex poisoned")
                        .last_run_env_failure
                        .insert(finding_id.to_string(), true);
                }
                Observation::tool_error(
                    "run_reproducer",
                    format!(
                        "{e} — the reproducer could not run (environmental failure); \
                         the exploit was NOT tested. Use mark_poc_status \
                         inconclusive, never refuted."
                    ),
                )
            }
        }
    }

    fn do_mark_poc_status(&self, args: &Value) -> Observation {
        let finding_id = args
            .get("finding_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let status = args.get("status").and_then(|v| v.as_str()).unwrap_or("");
        if finding_id.is_empty()
            || !["reproduced", "refuted", "inconclusive", "reproduced_by_citation"]
                .contains(&status)
        {
            return Observation::tool_error(
                "mark_poc_status",
                format!(
                    "finding_id and status required (status in \
                     reproduced|refuted|inconclusive|reproduced_by_citation); \
                     got id={finding_id:?} status={status:?}"
                ),
            );
        }

        // Anti-masquerade guard: `refuted` means the exploit RAN and did not
        // fire. If the last run_reproducer for this finding was an
        // environmental failure (timeout / sandbox error / errored exit), a
        // `refuted` label would dress a non-execution up as a disproof — the
        // dangerous direction for an auditor. Refuse it; the honest label is
        // `inconclusive` (or re-run the reproducer to completion first).
        if status == "refuted" {
            let env_failed = self
                .state
                .lock()
                .expect("poc_forge summary mutex poisoned")
                .last_run_env_failure
                .get(finding_id)
                .copied()
                .unwrap_or(false);
            if env_failed {
                return Observation::tool_error(
                    "mark_poc_status",
                    format!(
                        "refusing status=refuted for {finding_id}: the last \
                         run_reproducer was an environmental failure (it did not \
                         test the exploit). Use status=inconclusive, or re-run the \
                         reproducer to completion first — a refutation requires a \
                         clean run that ran and disproved the exploit."
                    ),
                );
            }
        }

        let conn = match self.open_conn() {
            Ok(c) => c,
            Err(e) => return Observation::tool_error("mark_poc_status", e),
        };
        if let Err(e) = db::set_poc_status(&conn, finding_id, status) {
            return Observation::tool_error("mark_poc_status", format!("{e}"));
        }

        if let Err(e) = audit::append_entry(
            &self.journal_path,
            "poc_forge",
            "mark_poc_status",
            format!(r#"Finding::"{finding_id}""#),
            "permit",
            None,
        ) {
            tracing::warn!(
                error = %e,
                "failed to append poc_forge permit journal entry"
            );
        }

        {
            let mut s = self.state.lock().expect("poc_forge summary mutex poisoned");
            match status {
                "reproduced" | "reproduced_by_citation" => s.reproduced += 1,
                "inconclusive" => s.inconclusive += 1,
                _ => s.refuted += 1,
            }
        }

        Observation::tool_result(
            "mark_poc_status",
            json!({
                "finding_id": finding_id,
                "status":     status,
                "ok":         true,
            })
            .to_string(),
        )
    }

    /// Tier-B PoC: verify each cited source range still contains the
    /// expected substring, then set poc_status='reproduced_by_citation'.
    /// This proves a finding by quoted code rather than by running an
    /// exploit — the right shape for authz bypass, missing-auth chains,
    /// and multi-service flows that can't fit in a 30-second sandbox.
    ///
    /// Verification is deterministic: read the file on disk, slice
    /// [line_start..line_end], check it contains `expected_substring`. If
    /// any citation fails, the proof is rejected and the finding's
    /// poc_status is NOT updated.
    fn do_emit_source_proof(&self, args: &Value) -> Observation {
        use std::path::Path;

        let finding_id = args
            .get("finding_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let claim = args.get("claim").and_then(|v| v.as_str()).unwrap_or("");
        let citations = match args.get("citations").and_then(|v| v.as_array()) {
            Some(c) if !c.is_empty() => c,
            _ => {
                return Observation::tool_error(
                    "emit_source_proof",
                    "citations array (>=1 entry) required",
                );
            }
        };
        if finding_id.is_empty() || claim.is_empty() {
            return Observation::tool_error(
                "emit_source_proof",
                "finding_id and claim required",
            );
        }

        let mut verified = Vec::new();
        for c in citations {
            let file_path = c.get("file_path").and_then(|v| v.as_str()).unwrap_or("");
            let line_start = c.get("line_start").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
            let line_end = c.get("line_end").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
            let expected = c
                .get("expected_substring")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let role = c.get("role").and_then(|v| v.as_str()).unwrap_or("");

            if file_path.is_empty() || expected.is_empty() || line_start == 0 || line_end < line_start {
                return Observation::tool_error(
                    "emit_source_proof",
                    format!(
                        "citation malformed: file_path={file_path:?} line_start={line_start} \
                         line_end={line_end} expected_substring_len={}",
                        expected.len()
                    ),
                );
            }

            // Canonicalize the path under target_repo. Reuses pattern_scout_tools'
            // path-escape guard semantics: refuse anything that escapes the repo.
            let candidate = if Path::new(file_path).is_absolute() {
                PathBuf::from(file_path)
            } else {
                self.target_repo.join(file_path)
            };
            let canon_target = match self.target_repo.canonicalize() {
                Ok(p) => p,
                Err(e) => {
                    return Observation::tool_error(
                        "emit_source_proof",
                        format!("target_repo canonicalize failed: {e}"),
                    );
                }
            };
            let canon_cand = match candidate.canonicalize() {
                Ok(p) => p,
                Err(e) => {
                    return Observation::tool_error(
                        "emit_source_proof",
                        format!("citation path does not exist: {} ({e})", candidate.display()),
                    );
                }
            };
            if !canon_cand.starts_with(&canon_target) {
                return Observation::tool_error(
                    "emit_source_proof",
                    format!(
                        "citation path escapes target_repo: {}",
                        canon_cand.display()
                    ),
                );
            }

            let body = match std::fs::read_to_string(&canon_cand) {
                Ok(s) => s,
                Err(e) => {
                    return Observation::tool_error(
                        "emit_source_proof",
                        format!("could not read {}: {e}", canon_cand.display()),
                    );
                }
            };
            let lines: Vec<&str> = body.lines().collect();
            let end = line_end.min(lines.len());
            let start = line_start.saturating_sub(1).min(end);
            if start >= end {
                return Observation::tool_error(
                    "emit_source_proof",
                    format!(
                        "citation range [{line_start}..{line_end}] empty in {} ({} lines)",
                        canon_cand.display(),
                        lines.len()
                    ),
                );
            }
            let snippet = lines[start..end].join("\n");
            if !snippet.contains(expected) {
                return Observation::tool_error(
                    "emit_source_proof",
                    format!(
                        "verification failed: expected_substring not present in \
                         {}:{line_start}-{line_end} (snippet len {})",
                        canon_cand.display(),
                        snippet.len()
                    ),
                );
            }

            verified.push(json!({
                "file_path": file_path,
                "line_start": line_start,
                "line_end": line_end,
                "role": role,
                "verified": true,
            }));
        }

        // All citations verified → persist the exhibit, then mark
        // poc_status=reproduced_by_citation. Recording the exhibit FIRST is what
        // satisfies the db integrity guard: the label is never written without a
        // durable, re-inspectable proof attached to the finding.
        let conn = match self.open_conn() {
            Ok(c) => c,
            Err(e) => return Observation::tool_error("emit_source_proof", e),
        };
        let exhibit = json!({
            "kind": "source_proof",
            "verdict": "reproduced_by_citation",
            "claim": claim,
            "citations": verified,
        })
        .to_string();
        if let Err(e) = db::record_poc_artifact(&conn, finding_id, &exhibit) {
            return Observation::tool_error("emit_source_proof", format!("{e}"));
        }
        if let Err(e) = db::set_poc_status(&conn, finding_id, "reproduced_by_citation") {
            return Observation::tool_error("emit_source_proof", format!("{e}"));
        }
        if let Err(e) = audit::append_entry(
            &self.journal_path,
            "poc_forge",
            "emit_source_proof",
            format!(r#"Finding::"{finding_id}""#),
            "permit",
            None,
        ) {
            tracing::warn!(
                error = %e,
                "failed to append poc_forge emit_source_proof journal entry"
            );
        }
        {
            let mut s = self.state.lock().expect("poc_forge summary mutex poisoned");
            s.reproduced += 1;
        }

        Observation::tool_result(
            "emit_source_proof",
            json!({
                "finding_id": finding_id,
                "claim": claim,
                "citations_verified": verified.len(),
                "citations": verified,
                "poc_status": "reproduced_by_citation",
                "ok": true,
            })
            .to_string(),
        )
    }
}

#[async_trait::async_trait]
impl ActionExecutor for PocForgeExecutor {
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
                    let mut s = self.state.lock().expect("poc_forge summary mutex poisoned");
                    s.tool_calls += 1;
                }
                let parsed: Value = serde_json::from_str(arguments).unwrap_or(Value::Null);
                let obs = match name.as_str() {
                    "query_findings" => self.do_query_findings(&parsed),
                    "read_context_range" => self.do_read_context(&parsed),
                    "run_reproducer" => self.do_run_reproducer(&parsed),
                    "mark_poc_status" => self.do_mark_poc_status(&parsed),
                    "emit_source_proof" => self.do_emit_source_proof(&parsed),
                    other => Observation::tool_error(
                        name.clone(),
                        format!("unknown tool for poc_forge: {other}"),
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
    use symbi_evidence_schema::{
        finding::{Confidence, Phase, Severity, Status},
        Engagement, Finding,
    };
    use tempfile::TempDir;

    fn fresh_executor() -> (TempDir, PathBuf, PocForgeExecutor, Uuid) {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("codered.db");
        let journal_path = dir.path().join("journal.jsonl");
        let target_repo = dir.path().join("repo");
        std::fs::create_dir_all(&target_repo).unwrap();
        let conn = db::init_db(db_path.to_str().unwrap()).unwrap();
        let e = Engagement::new("acme", "h", "2026-05-24", "2026-05-31");
        let eid = e.id;
        db::insert_engagement(&conn, &e).unwrap();
        drop(conn);
        let exec = PocForgeExecutor::new(
            eid,
            db_path.clone(),
            journal_path,
            target_repo,
            "python-sandbox".to_string(),
            "rust-sandbox".to_string(),
            "typescript-sandbox".to_string(),
            "go-sandbox".to_string(),
            "php-sandbox".to_string(),
        );
        (dir, db_path, exec, eid)
    }

    fn insert_poc_candidate(db_path: &std::path::Path, eid: Uuid, id: &str, envelope: &str) {
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
            title: "sqli".into(),
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
    async fn query_findings_returns_only_poc_candidates() {
        let (_dir, db_path, exec, eid) = fresh_executor();
        insert_poc_candidate(&db_path, eid, "F-1", "env-1");
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
        assert_eq!(arr[0].get("cwe").and_then(|x| x.as_str()), Some("CWE-89"));
        assert_eq!(v.get("total").and_then(|x| x.as_i64()), Some(1));
        assert!(!v.get("has_more").unwrap().as_bool().unwrap());
    }

    #[tokio::test]
    async fn mark_poc_status_rejects_invalid_status() {
        let (_dir, db_path, exec, eid) = fresh_executor();
        insert_poc_candidate(&db_path, eid, "F-1", "env-1");
        let args = json!({"finding_id": "F-1", "status": "maybe"});
        let actions = vec![ProposedAction::ToolCall {
            call_id: "c1".into(),
            name: "mark_poc_status".into(),
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
        assert!(obs[0].content.contains("reproduced|refuted|inconclusive|reproduced_by_citation"));
        assert_eq!(exec.summary().reproduced, 0);
        assert_eq!(exec.summary().refuted, 0);
    }

    async fn mark(exec: &PocForgeExecutor, id: &str, status: &str) -> Vec<Observation> {
        let args = json!({"finding_id": id, "status": status});
        let actions = vec![ProposedAction::ToolCall {
            call_id: "c1".into(),
            name: "mark_poc_status".into(),
            arguments: args.to_string(),
        }];
        exec.execute_actions(
            &actions,
            &LoopConfig::default(),
            &CircuitBreakerRegistry::default(),
        )
        .await
    }

    #[tokio::test]
    async fn mark_poc_status_reproduced_without_exhibit_is_rejected() {
        // The integrity guard: you cannot label a finding "reproduced" unless a
        // PoC exhibit was actually persisted. This is the F-pattern-scout-0001
        // overstatement, made impossible.
        let (_dir, db_path, exec, _eid) = fresh_executor();
        insert_poc_candidate(&db_path, _eid, "F-1", "env-1");
        let obs = mark(&exec, "F-1", "reproduced").await;
        assert!(obs[0].is_error, "reproduced with no exhibit must be rejected");
        assert!(
            obs[0].content.contains("no PoC exhibit") || obs[0].content.contains("integrity"),
            "unexpected error: {}",
            obs[0].content
        );
        assert_eq!(exec.summary().reproduced, 0);
        let conn = db::init_db(db_path.to_str().unwrap()).unwrap();
        let status: Option<String> = conn
            .query_row("SELECT poc_status FROM findings WHERE id = 'F-1'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(status, None, "poc_status must remain unset");
    }

    #[tokio::test]
    async fn mark_poc_status_reproduced_succeeds_after_exhibit_recorded() {
        let (_dir, db_path, exec, eid) = fresh_executor();
        insert_poc_candidate(&db_path, eid, "F-1", "env-1");
        // Simulate run_reproducer having persisted a successful exhibit.
        {
            let conn = db::init_db(db_path.to_str().unwrap()).unwrap();
            db::record_poc_artifact(
                &conn, "F-1",
                r#"{"verdict":"reproduced","language":"python","stdout":"REPRODUCED"}"#,
            )
            .unwrap();
        }
        let obs = mark(&exec, "F-1", "reproduced").await;
        assert!(!obs[0].is_error, "got error: {}", obs[0].content);
        assert_eq!(exec.summary().reproduced, 1);
        let conn = db::init_db(db_path.to_str().unwrap()).unwrap();
        let status: Option<String> = conn
            .query_row("SELECT poc_status FROM findings WHERE id = 'F-1'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(status.as_deref(), Some("reproduced"));
    }

    #[tokio::test]
    async fn emit_source_proof_records_exhibit_and_marks_reproduced_by_citation() {
        let (_dir, db_path, exec, eid) = fresh_executor();
        insert_poc_candidate(&db_path, eid, "F-1", "env-1");
        // A real source file inside target_repo that the citation will verify.
        let src = exec.target_repo.join("src").join("x.py");
        std::fs::create_dir_all(src.parent().unwrap()).unwrap();
        std::fs::write(&src, "line1\nDANGEROUS_SINK(user_input)\nline3\n").unwrap();

        let args = json!({
            "finding_id": "F-1",
            "claim": "untrusted input reaches DANGEROUS_SINK",
            "citations": [{
                "file_path": "src/x.py",
                "line_start": 2, "line_end": 2,
                "expected_substring": "DANGEROUS_SINK",
                "role": "sink"
            }]
        });
        let actions = vec![ProposedAction::ToolCall {
            call_id: "c1".into(),
            name: "emit_source_proof".into(),
            arguments: args.to_string(),
        }];
        let obs = exec
            .execute_actions(&actions, &LoopConfig::default(), &CircuitBreakerRegistry::default())
            .await;
        assert!(!obs[0].is_error, "got error: {}", obs[0].content);

        let conn = db::init_db(db_path.to_str().unwrap()).unwrap();
        // The verified citations were persisted as a PoC exhibit...
        assert!(db::has_poc_artifact(&conn, "F-1").unwrap(), "exhibit must be persisted");
        // ...and the finding is labelled reproduced_by_citation.
        let status: Option<String> = conn
            .query_row("SELECT poc_status FROM findings WHERE id = 'F-1'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(status.as_deref(), Some("reproduced_by_citation"));
    }

    #[tokio::test]
    async fn mark_poc_status_refuted_downgrades_status_to_hypothesis() {
        let (_dir, db_path, exec, eid) = fresh_executor();
        insert_poc_candidate(&db_path, eid, "F-1", "env-1");
        let args = json!({"finding_id": "F-1", "status": "refuted"});
        let actions = vec![ProposedAction::ToolCall {
            call_id: "c1".into(),
            name: "mark_poc_status".into(),
            arguments: args.to_string(),
        }];
        let obs = exec
            .execute_actions(
                &actions,
                &LoopConfig::default(),
                &CircuitBreakerRegistry::default(),
            )
            .await;
        assert!(!obs[0].is_error, "got error: {}", obs[0].content);
        assert_eq!(exec.summary().refuted, 1);

        let conn = db::init_db(db_path.to_str().unwrap()).unwrap();
        let (poc, status): (Option<String>, String) = conn
            .query_row(
                "SELECT poc_status, status FROM findings WHERE id = 'F-1'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(poc.as_deref(), Some("refuted"));
        // db::set_poc_status downgrades refuted findings to 'hypothesis'.
        assert_eq!(status, "hypothesis");
    }

    #[tokio::test]
    async fn mark_poc_status_inconclusive_is_accepted_and_does_not_downgrade() {
        let (_dir, db_path, exec, eid) = fresh_executor();
        insert_poc_candidate(&db_path, eid, "F-1", "env-1");
        let args = json!({"finding_id": "F-1", "status": "inconclusive"});
        let actions = vec![ProposedAction::ToolCall {
            call_id: "c1".into(),
            name: "mark_poc_status".into(),
            arguments: args.to_string(),
        }];
        let obs = exec
            .execute_actions(
                &actions,
                &LoopConfig::default(),
                &CircuitBreakerRegistry::default(),
            )
            .await;
        assert!(!obs[0].is_error, "got error: {}", obs[0].content);
        assert_eq!(exec.summary().inconclusive, 1);
        assert_eq!(exec.summary().refuted, 0);

        let conn = db::init_db(db_path.to_str().unwrap()).unwrap();
        let (poc, status): (Option<String>, String) = conn
            .query_row(
                "SELECT poc_status, status FROM findings WHERE id = 'F-1'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(poc.as_deref(), Some("inconclusive"));
        // inconclusive must NOT downgrade — the finding stays in play.
        assert_ne!(status, "hypothesis");
    }

    #[tokio::test]
    async fn refuted_after_env_failure_is_refused() {
        // The anti-masquerade guard: if the last run_reproducer for a finding
        // was an environmental failure, a `refuted` label is refused.
        let (_dir, db_path, exec, eid) = fresh_executor();
        insert_poc_candidate(&db_path, eid, "F-1", "env-1");
        exec.state
            .lock()
            .unwrap()
            .last_run_env_failure
            .insert("F-1".to_string(), true);

        let args = json!({"finding_id": "F-1", "status": "refuted"});
        let actions = vec![ProposedAction::ToolCall {
            call_id: "c1".into(),
            name: "mark_poc_status".into(),
            arguments: args.to_string(),
        }];
        let obs = exec
            .execute_actions(
                &actions,
                &LoopConfig::default(),
                &CircuitBreakerRegistry::default(),
            )
            .await;
        assert!(obs[0].is_error, "refuted after env failure must be refused");
        assert!(obs[0].content.contains("inconclusive"));
        assert_eq!(exec.summary().refuted, 0);

        let conn = db::init_db(db_path.to_str().unwrap()).unwrap();
        let poc: Option<String> = conn
            .query_row(
                "SELECT poc_status FROM findings WHERE id = 'F-1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(poc, None, "no poc_status should be written on refusal");
    }

    #[tokio::test]
    async fn read_context_range_rejects_path_escape() {
        let (dir, _db, exec, _eid) = fresh_executor();
        // Place a sensitive file OUTSIDE the target_repo so we can
        // confirm `..` traversal is refused even if it would resolve to
        // a real file.
        let outside = dir.path().join("secret.txt");
        std::fs::write(&outside, "top-secret").unwrap();

        let args = json!({
            "file_path": "../secret.txt",
            "line_start": 1,
            "line_end": 1,
        });
        let actions = vec![ProposedAction::ToolCall {
            call_id: "c1".into(),
            name: "read_context_range".into(),
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
        assert!(obs[0].is_error, "expected escape to be rejected");
        assert!(
            obs[0].content.contains("escapes target_repo")
                || obs[0].content.contains("canonicalize"),
            "unexpected error: {}",
            obs[0].content,
        );
    }

    #[tokio::test]
    async fn read_context_range_returns_snippet_for_in_repo_file() {
        let (_dir, _db, exec, _eid) = fresh_executor();
        let p = exec.target_repo.join("a.py");
        std::fs::write(&p, "alpha\nbeta\ngamma\ndelta\n").unwrap();

        let args = json!({"file_path": "a.py", "line_start": 2, "line_end": 3});
        let actions = vec![ProposedAction::ToolCall {
            call_id: "c1".into(),
            name: "read_context_range".into(),
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
        let snippet = v.get("snippet").and_then(|x| x.as_str()).unwrap();
        assert!(snippet.contains("2: beta"), "snippet: {snippet}");
        assert!(snippet.contains("3: gamma"), "snippet: {snippet}");
        assert!(!snippet.contains("1: alpha"));
        assert!(!snippet.contains("4: delta"));
    }

    #[tokio::test]
    async fn run_reproducer_requires_non_empty_script() {
        let (_dir, _db, exec, _eid) = fresh_executor();
        let args = json!({"script": ""});
        let actions = vec![ProposedAction::ToolCall {
            call_id: "c1".into(),
            name: "run_reproducer".into(),
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
        assert!(obs[0].content.contains("script required"));
        // scripts_run counter must NOT advance on validation failure
        assert_eq!(exec.summary().scripts_run, 0);
    }

    #[test]
    fn infer_language_maps_extensions() {
        assert_eq!(infer_language("a/b.py").as_deref(), Some("python"));
        assert_eq!(infer_language("a/b.rs").as_deref(), Some("rust"));
        assert_eq!(infer_language("a/b.ts").as_deref(), Some("typescript"));
        assert_eq!(infer_language("a/b.tsx").as_deref(), Some("typescript"));
        assert_eq!(infer_language("a/b.js").as_deref(), Some("javascript"));
        assert_eq!(infer_language("a/b.jsx").as_deref(), Some("javascript"));
        assert_eq!(infer_language("a/b.mjs").as_deref(), Some("javascript"));
        assert_eq!(infer_language("a/b.cjs").as_deref(), Some("javascript"));
        assert_eq!(infer_language("a/b.go").as_deref(), Some("go"));
        assert_eq!(infer_language("a/b.php").as_deref(), Some("php"));
        assert_eq!(infer_language("Makefile"), None);
        assert_eq!(infer_language("a/b.unknown"), None);
        // Case insensitive
        assert_eq!(infer_language("a/B.PY").as_deref(), Some("python"));
        assert_eq!(infer_language("a/B.RS").as_deref(), Some("rust"));
    }

    #[tokio::test]
    async fn run_reproducer_rejects_unsupported_language() {
        let (_dir, _db, exec, _eid) = fresh_executor();
        let args = json!({"script": "print('hi')", "language": "ruby"});
        let actions = vec![ProposedAction::ToolCall {
            call_id: "c1".into(),
            name: "run_reproducer".into(),
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
        assert!(obs[0].is_error, "expected unsupported-language error");
        assert!(
            obs[0].content.contains("unsupported language"),
            "got: {}",
            obs[0].content
        );
        // counter must not advance on validation failure
        assert_eq!(exec.summary().scripts_run, 0);
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
