//! SQLite persistence layer for symbi-codered.

use chrono::{DateTime, Utc};
use rusqlite::Connection;
use rusqlite::params;
use thiserror::Error;
use symbi_evidence_schema::{Engagement, Finding};
use symbi_evidence_schema::{
    Citation, Hypothesis, ThreatModel, TaintChain, AttackChainNode,
};
use uuid::Uuid;

const SCHEMA_SQL: &str = include_str!("../../../db/schema.sql");

#[derive(Debug, Error)]
pub enum DbError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// A cross-field invariant was violated — e.g. attempting to mark a finding
    /// `poc_status=reproduced` with no persisted PoC exhibit to back the claim.
    #[error("integrity: {0}")]
    Integrity(String),
}

pub type Result<T> = std::result::Result<T, DbError>;

/// Open or create a SQLite database, enable WAL + foreign keys, apply schema.
pub fn init_db(path: &str) -> Result<Connection> {
    let conn = Connection::open(path)?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.execute_batch(SCHEMA_SQL)?;
    Ok(conn)
}

// ---------------------------------------------------------------------------
// Engagement
// ---------------------------------------------------------------------------

pub fn insert_engagement(conn: &Connection, e: &Engagement) -> Result<()> {
    conn.execute(
        "INSERT INTO engagements (id, client, scope_hash, start_date, end_date, status, roa_hash, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            e.id.to_string(),
            &e.client,
            &e.scope_hash,
            &e.start_date,
            &e.end_date,
            serde_json::to_string(&e.status)?.trim_matches('"'),
            e.roa_hash.as_deref(),
            e.created_at.to_rfc3339(),
        ],
    )?;
    Ok(())
}

pub fn get_engagement(conn: &Connection, id: Uuid) -> Result<Option<Engagement>> {
    let mut stmt = conn.prepare(
        "SELECT id, client, scope_hash, start_date, end_date, status, roa_hash, created_at
         FROM engagements WHERE id = ?1",
    )?;
    let row = stmt.query_row(params![id.to_string()], |row| {
        let id_str: String = row.get(0)?;
        let status_str: String = row.get(5)?;
        let created_str: String = row.get(7)?;
        Ok(Engagement {
            id: id_str.parse().map_err(|e: uuid::Error| {
                rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
            })?,
            client:     row.get(1)?,
            scope_hash: row.get(2)?,
            start_date: row.get(3)?,
            end_date:   row.get(4)?,
            status:     serde_json::from_str(&format!("\"{status_str}\""))
                .map_err(|e| rusqlite::Error::FromSqlConversionFailure(
                    5, rusqlite::types::Type::Text, Box::new(e)
                ))?,
            roa_hash:   row.get(6)?,
            created_at: chrono::DateTime::parse_from_rfc3339(&created_str)
                .map_err(|e| rusqlite::Error::FromSqlConversionFailure(
                    7, rusqlite::types::Type::Text, Box::new(e)
                ))?.with_timezone(&chrono::Utc),
        })
    });
    match row {
        Ok(e) => Ok(Some(e)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

// ---------------------------------------------------------------------------
// Finding
// ---------------------------------------------------------------------------

pub fn insert_finding(conn: &Connection, f: &Finding) -> Result<()> {
    let phase = serde_json::to_string(&f.phase)?.trim_matches('"').to_string();
    let sev = serde_json::to_string(&f.severity)?.trim_matches('"').to_string();
    let conf = serde_json::to_string(&f.confidence)?.trim_matches('"').to_string();
    let status = serde_json::to_string(&f.status)?.trim_matches('"').to_string();
    let advocate = f.advocate_verdict.as_ref()
        .map(|v| serde_json::to_string(v).map(|s| s.trim_matches('"').to_string()))
        .transpose()?;
    let poc = f.poc_status.as_ref()
        .map(|v| serde_json::to_string(v).map(|s| s.trim_matches('"').to_string()))
        .transpose()?;
    conn.execute(
        "INSERT INTO findings (id, engagement_id, phase, severity, confidence, cwe, owasp,
                               file_path, line_start, line_end, title, description,
                               reachable, exploitable, evidence_envelope_id, status,
                               rank_score, specifier_hash, advocate_verdict,
                               tool_origin, poc_status, created_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,
                 ?18,?19,?20,?21,?22)",
        params![
            &f.id,
            f.engagement_id.to_string(),
            phase, sev, conf,
            f.cwe.as_deref(),
            f.owasp.as_deref(),
            &f.file_path,
            f.line_start,
            f.line_end,
            &f.title,
            &f.description,
            f.reachable.map(i64::from),
            f.exploitable.map(i64::from),
            &f.evidence_envelope_id,
            status,
            f.rank_score,
            f.specifier_hash.as_deref(),
            advocate,
            f.tool_origin.as_deref(),
            poc,
            f.created_at.to_rfc3339(),
        ],
    )?;
    Ok(())
}

/// Read every Finding row for an engagement (no pagination — used by the
/// Plan G reporter, which materialises the full set before templating).
/// Roundtrips the enum string columns back through serde to keep the
/// representation aligned with `insert_finding`.
pub fn list_findings_for(conn: &Connection, engagement_id: Uuid) -> Result<Vec<Finding>> {
    let mut stmt = conn.prepare(
        "SELECT id, engagement_id, phase, severity, confidence, cwe, owasp,
                file_path, line_start, line_end, title, description,
                reachable, exploitable, evidence_envelope_id, status,
                rank_score, specifier_hash, advocate_verdict,
                tool_origin, poc_status, created_at
         FROM findings WHERE engagement_id = ?1 ORDER BY id",
    )?;
    let rows = stmt.query_map(params![engagement_id.to_string()], row_to_finding)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

fn row_to_finding(r: &rusqlite::Row<'_>) -> rusqlite::Result<Finding> {
    use rusqlite::Error::FromSqlConversionFailure;
    use rusqlite::types::Type;

    let id_str: String = r.get(1)?;
    let phase_s: String = r.get(2)?;
    let sev_s: String = r.get(3)?;
    let conf_s: String = r.get(4)?;
    let status_s: String = r.get(15)?;
    let advocate_s: Option<String> = r.get(18)?;
    let poc_s: Option<String> = r.get(20)?;
    let created_s: String = r.get(21)?;

    let phase = serde_json::from_str(&format!("\"{phase_s}\""))
        .map_err(|e| FromSqlConversionFailure(2, Type::Text, Box::new(e)))?;
    let severity = serde_json::from_str(&format!("\"{sev_s}\""))
        .map_err(|e| FromSqlConversionFailure(3, Type::Text, Box::new(e)))?;
    let confidence = serde_json::from_str(&format!("\"{conf_s}\""))
        .map_err(|e| FromSqlConversionFailure(4, Type::Text, Box::new(e)))?;
    let status = serde_json::from_str(&format!("\"{status_s}\""))
        .map_err(|e| FromSqlConversionFailure(15, Type::Text, Box::new(e)))?;
    let advocate_verdict = advocate_s
        .map(|s| serde_json::from_str(&format!("\"{s}\"")))
        .transpose()
        .map_err(|e| FromSqlConversionFailure(18, Type::Text, Box::new(e)))?;
    let poc_status = poc_s
        .map(|s| serde_json::from_str(&format!("\"{s}\"")))
        .transpose()
        .map_err(|e| FromSqlConversionFailure(20, Type::Text, Box::new(e)))?;
    let created_at = DateTime::parse_from_rfc3339(&created_s)
        .map_err(|e| FromSqlConversionFailure(21, Type::Text, Box::new(e)))?
        .with_timezone(&Utc);

    let reachable_i: Option<i64> = r.get(12)?;
    let exploitable_i: Option<i64> = r.get(13)?;
    Ok(Finding {
        id: r.get(0)?,
        engagement_id: id_str.parse().map_err(|e: uuid::Error| {
            FromSqlConversionFailure(1, Type::Text, Box::new(e))
        })?,
        phase,
        severity,
        confidence,
        cwe: r.get(5)?,
        owasp: r.get(6)?,
        file_path: r.get(7)?,
        line_start: r.get::<_, i64>(8)? as u32,
        line_end: r.get::<_, i64>(9)? as u32,
        title: r.get(10)?,
        description: r.get(11)?,
        reachable: reachable_i.map(|v| v != 0),
        exploitable: exploitable_i.map(|v| v != 0),
        evidence_envelope_id: r.get(14)?,
        status,
        rank_score: r.get(16)?,
        specifier_hash: r.get(17)?,
        advocate_verdict,
        tool_origin: r.get(19)?,
        poc_status,
        created_at,
    })
}

/// List every AttackChainNode row for an engagement. Reporter loads the full
/// set; chain volumes are small (one row per kill-chain hop).
pub fn list_attack_chains_for(
    conn: &Connection,
    engagement_id: Uuid,
) -> Result<Vec<AttackChainNode>> {
    let mut stmt = conn.prepare(
        "SELECT id, engagement_id, stage, finding_id, evidence_id, next_chain_id, rationale, created_at
         FROM attack_chains WHERE engagement_id = ?1 ORDER BY id",
    )?;
    let rows = stmt.query_map(params![engagement_id.to_string()], |r| {
        use rusqlite::Error::FromSqlConversionFailure;
        use rusqlite::types::Type;
        let eid_str: String = r.get(1)?;
        let stage_s: String = r.get(2)?;
        let created_s: String = r.get(7)?;
        let stage = serde_json::from_str(&format!("\"{stage_s}\""))
            .map_err(|e| FromSqlConversionFailure(2, Type::Text, Box::new(e)))?;
        let created_at = DateTime::parse_from_rfc3339(&created_s)
            .map_err(|e| FromSqlConversionFailure(7, Type::Text, Box::new(e)))?
            .with_timezone(&Utc);
        Ok(AttackChainNode {
            id: r.get(0)?,
            engagement_id: eid_str.parse().map_err(|e: uuid::Error| {
                FromSqlConversionFailure(1, Type::Text, Box::new(e))
            })?,
            stage,
            finding_id: r.get(3)?,
            evidence_id: r.get(4)?,
            next_chain_id: r.get(5)?,
            rationale: r.get(6)?,
            created_at,
        })
    })?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

pub fn count_findings_for(conn: &Connection, engagement_id: Uuid) -> Result<i64> {
    let n: i64 = conn.query_row(
        "SELECT COUNT(*) FROM findings WHERE engagement_id = ?1",
        params![engagement_id.to_string()],
        |r| r.get(0),
    )?;
    Ok(n)
}

// Plan E: advocate_verdict + poc_status mutators

pub fn set_advocate_verdict(
    conn: &Connection,
    finding_id: &str,
    verdict: &str,
) -> Result<()> {
    conn.execute(
        "UPDATE findings SET advocate_verdict = ?1 WHERE id = ?2",
        params![verdict, finding_id],
    )?;
    Ok(())
}

/// Does `finding_id` have at least one persisted PoC exhibit? A PoC exhibit is
/// a `finding_citations` row of type `poc` written by poc_forge after it ran a
/// reproducer (or deterministically verified source citations). This is the
/// backing required before a finding may be labelled `reproduced`.
pub fn has_poc_artifact(conn: &Connection, finding_id: &str) -> Result<bool> {
    let n: i64 = conn.query_row(
        "SELECT COUNT(*) FROM finding_citations \
         WHERE finding_id = ?1 AND citation_type = 'poc'",
        params![finding_id],
        |r| r.get(0),
    )?;
    Ok(n > 0)
}

/// Persist a PoC exhibit for `finding_id`. `exhibit_json` is an opaque JSON blob
/// (reproducer script + sandbox stdout/stderr + verdict + language, or the set
/// of verified source citations). Stored as a `poc` citation so it travels with
/// the finding and can be re-inspected; its presence is the precondition that
/// [`set_poc_status`] enforces before allowing a `reproduced*` label.
pub fn record_poc_artifact(conn: &Connection, finding_id: &str, exhibit_json: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO finding_citations (finding_id, citation_type, intended_poc) \
         VALUES (?1, 'poc', ?2)",
        params![finding_id, exhibit_json],
    )?;
    Ok(())
}

pub fn set_poc_status(
    conn: &Connection,
    finding_id: &str,
    status: &str,
) -> Result<()> {
    // Integrity guard: a `reproduced*` label is a claim that an exploit was
    // demonstrated. It is only honest if a PoC exhibit was actually persisted.
    // Without this gate the LLM could assert "reproduced" with nothing to show
    // for it (exactly the F-pattern-scout-0001 overstatement).
    //
    // `refuted` means the exploit RAN and did not fire — it downgrades the
    // finding to `hypothesis`. `inconclusive` means the reproducer could NOT run
    // (compile/sandbox error or timeout); it is recorded but does NOT downgrade,
    // so the finding stays in play for a human and is NOT dropped from the seed
    // by handoff.cedar. The poc_forge executor additionally refuses a `refuted`
    // whose last run_reproducer was an environmental failure, so a non-execution
    // can't masquerade as a disproof.
    if status.starts_with("reproduced") && !has_poc_artifact(conn, finding_id)? {
        return Err(DbError::Integrity(format!(
            "refusing to set poc_status={status:?} for {finding_id}: \
             no PoC exhibit persisted (call record_poc_artifact first)"
        )));
    }
    let downgrade = status == "refuted";
    let sql = if downgrade {
        "UPDATE findings SET poc_status = ?1, status = 'hypothesis' WHERE id = ?2"
    } else {
        "UPDATE findings SET poc_status = ?1 WHERE id = ?2"
    };
    conn.execute(sql, params![status, finding_id])?;
    Ok(())
}

/// Total count of candidate findings eligible for poc_forge reproduction.
/// Use alongside `list_poc_candidates` for pagination headers.
pub fn count_poc_candidates(conn: &Connection, engagement_id: Uuid) -> Result<i64> {
    let n: i64 = conn.query_row(
        "SELECT COUNT(*) FROM findings
         WHERE engagement_id = ?1
           AND status = 'open'
           AND cwe IN ('CWE-89','CWE-78','CWE-22','CWE-94','CWE-79')
           AND poc_status IS NULL",
        params![engagement_id.to_string()],
        |r| r.get(0),
    )?;
    Ok(n)
}

/// Paginated PoC-candidate selector. `page` is 0-indexed; `page_size`
/// clamped to [1, 100] (None → 30).
///
/// Ordering puts the chain-aware `triage` (pattern_scout) findings ahead of
/// raw `sast` findings: scout findings are the curated, deduplicated,
/// reachability-reasoned candidates, so they deserve poc_forge's scarce
/// iteration budget before the hundreds of near-duplicate scanner hits.
/// Without this, `F-bandit-*` / `F-semgrep-*` ids sort ahead of
/// `F-pattern-scout-*` and fill page 0, and the high-value scout findings
/// (e.g. a Go SQLi the tracer surfaced) never get a reproduction attempt.
/// Within each tier, ORDER BY id keeps pagination stable.
#[allow(clippy::type_complexity)]
pub fn list_poc_candidates(
    conn: &Connection,
    engagement_id: Uuid,
    page: u32,
    page_size: Option<u32>,
) -> Result<Vec<(String, String, String, String, i64, i64)>> {
    let page_size = page_size.unwrap_or(30).clamp(1, 100) as i64;
    let offset = (page as i64) * page_size;
    let mut stmt = conn.prepare(
        "SELECT id, file_path, title, cwe, line_start, line_end
         FROM findings
         WHERE engagement_id = ?1
           AND status = 'open'
           AND cwe IN ('CWE-89','CWE-78','CWE-22','CWE-94','CWE-79')
           AND poc_status IS NULL
         ORDER BY (CASE WHEN phase = 'triage' THEN 0 ELSE 1 END), id
         LIMIT ?2 OFFSET ?3",
    )?;
    let rows = stmt
        .query_map(params![engagement_id.to_string(), page_size, offset], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, i64>(5)?,
            ))
        })?
        .filter_map(|r| r.ok())
        .collect();
    Ok(rows)
}

// ---------------------------------------------------------------------------
// repo_facts (engagement-scoped key/value of structured facts)
// ---------------------------------------------------------------------------

pub fn insert_repo_fact(
    conn: &Connection,
    engagement_id: Uuid,
    kind: &str,
    json: &str,
) -> Result<()> {
    conn.execute(
        "INSERT INTO repo_facts (engagement_id, kind, json) VALUES (?1, ?2, ?3)",
        params![engagement_id.to_string(), kind, json],
    )?;
    Ok(())
}

pub fn list_repo_facts(
    conn: &Connection,
    engagement_id: Uuid,
    kind: &str,
) -> Result<Vec<String>> {
    let mut stmt = conn.prepare(
        "SELECT json FROM repo_facts WHERE engagement_id = ?1 AND kind = ?2",
    )?;
    let rows = stmt.query_map(params![engagement_id.to_string(), kind], |r| r.get::<_, String>(0))?;
    Ok(rows.filter_map(|r| r.ok()).collect())
}

// ---------------------------------------------------------------------------
// symbol_index
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
pub fn insert_symbol(
    conn: &Connection,
    engagement_id: Uuid,
    file_path: &str,
    line_start: u32,
    line_end: u32,
    kind: &str,
    name: &str,
    language: &str,
) -> Result<()> {
    conn.execute(
        "INSERT INTO symbol_index (engagement_id, file_path, line_start, line_end, kind, name, language)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![engagement_id.to_string(), file_path, line_start, line_end, kind, name, language],
    )?;
    Ok(())
}

#[allow(clippy::type_complexity)]
pub fn find_symbols_by_name(
    conn: &Connection,
    engagement_id: Uuid,
    name: &str,
) -> Result<Vec<(String, u32, u32, String, String)>> {
    let mut stmt = conn.prepare(
        "SELECT file_path, line_start, line_end, kind, language
         FROM symbol_index WHERE engagement_id = ?1 AND name = ?2",
    )?;
    let rows = stmt.query_map(params![engagement_id.to_string(), name], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, u32>(1)?, r.get::<_, u32>(2)?,
            r.get::<_, String>(3)?, r.get::<_, String>(4)?))
    })?;
    Ok(rows.filter_map(|r| r.ok()).collect())
}

/// Return the `(line_start, line_end)` span of the innermost `function`/`method`
/// in `file_path` that encloses `line`, if any. Used by the taint tracer to
/// scope guard detection to the function a sink/source lives in. Only Python
/// symbols are currently indexed by the cartographer, so this returns `None`
/// for Rust/Go/TS sinks — callers fall back to a fixed line window there.
pub fn enclosing_function(
    conn: &Connection,
    engagement_id: Uuid,
    file_path: &str,
    line: u32,
) -> Result<Option<(u32, u32)>> {
    use rusqlite::OptionalExtension;
    let r = conn
        .query_row(
            "SELECT line_start, line_end FROM symbol_index
             WHERE engagement_id = ?1 AND file_path = ?2 AND kind IN ('function', 'method')
               AND line_start <= ?3 AND line_end >= ?3
             ORDER BY line_start DESC LIMIT 1",
            params![engagement_id.to_string(), file_path, line],
            |r| Ok((r.get::<_, u32>(0)?, r.get::<_, u32>(1)?)),
        )
        .optional()?;
    Ok(r)
}

// ---------------------------------------------------------------------------
// routes
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
pub fn insert_route(
    conn: &Connection,
    engagement_id: Uuid,
    method: &str,
    path: &str,
    handler_symbol: &str,
    middleware_json: Option<&str>,
    auth_required: Option<bool>,
    roles_json: Option<&str>,
) -> Result<()> {
    conn.execute(
        "INSERT INTO routes (engagement_id, method, path, handler_symbol, middleware, auth_required, roles)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            engagement_id.to_string(), method, path, handler_symbol,
            middleware_json, auth_required.map(i64::from), roles_json,
        ],
    )?;
    Ok(())
}

pub fn count_routes_for(conn: &Connection, engagement_id: Uuid) -> Result<i64> {
    let n: i64 = conn.query_row(
        "SELECT COUNT(*) FROM routes WHERE engagement_id = ?1",
        params![engagement_id.to_string()],
        |r| r.get(0),
    )?;
    Ok(n)
}

// ---------------------------------------------------------------------------
// threat_models, finding_citations, hypotheses, taint_chains, attack_chains
// ---------------------------------------------------------------------------

pub fn insert_threat_model(conn: &Connection, tm: &ThreatModel) -> Result<()> {
    conn.execute(
        "INSERT INTO threat_models (specifier_hash, engagement_id, json, signed_at, signature)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            &tm.specifier_hash,
            tm.engagement_id.to_string(),
            &tm.canonical_json,
            tm.signed_at.to_rfc3339(),
            &tm.signature,
        ],
    )?;
    Ok(())
}

pub fn insert_finding_citation(
    conn: &Connection,
    finding_id: &str,
    citation: &Citation,
) -> Result<()> {
    match citation {
        Citation::Analyzer { finding_id: cited } => {
            conn.execute(
                "INSERT INTO finding_citations (finding_id, citation_type, analyzer_finding)
                 VALUES (?1, 'analyzer', ?2)",
                params![finding_id, cited],
            )?;
        }
        Citation::Code { file_path, line_start, line_end } => {
            conn.execute(
                "INSERT INTO finding_citations (finding_id, citation_type, code_path, code_line_start, code_line_end)
                 VALUES (?1, 'code', ?2, ?3, ?4)",
                params![finding_id, file_path, line_start, line_end],
            )?;
        }
        Citation::Hypothesis { hypothesis_id, intended_poc } => {
            conn.execute(
                "INSERT INTO finding_citations (finding_id, citation_type, hypothesis_id, intended_poc)
                 VALUES (?1, 'hypothesis', ?2, ?3)",
                params![finding_id, hypothesis_id, intended_poc],
            )?;
        }
    }
    Ok(())
}

pub fn insert_hypothesis(conn: &Connection, h: &Hypothesis) -> Result<()> {
    let status = serde_json::to_string(&h.status)?.trim_matches('"').to_string();
    conn.execute(
        "INSERT INTO hypotheses (id, engagement_id, description, status, created_by_agent, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            &h.id,
            h.engagement_id.to_string(),
            &h.description,
            status,
            &h.created_by_agent,
            h.created_at.to_rfc3339(),
        ],
    )?;
    Ok(())
}

pub fn insert_taint_chain(conn: &Connection, c: &TaintChain) -> Result<()> {
    let chain_json = serde_json::to_string(&c.chain)?;
    let sanitizers_json = serde_json::to_string(&c.sanitizers_seen)?;
    conn.execute(
        "INSERT INTO taint_chains (id, engagement_id, source_file, source_line, sink_file, sink_line, chain_json, sanitizers_seen, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            &c.id,
            c.engagement_id.to_string(),
            &c.source_file,
            c.source_line,
            &c.sink_file,
            c.sink_line,
            chain_json,
            sanitizers_json,
            c.created_at.to_rfc3339(),
        ],
    )?;
    Ok(())
}

pub fn insert_attack_chain_node(conn: &Connection, n: &AttackChainNode) -> Result<()> {
    let stage = serde_json::to_string(&n.stage)?.trim_matches('"').to_string();
    conn.execute(
        "INSERT INTO attack_chains (id, engagement_id, stage, finding_id, evidence_id, next_chain_id, rationale, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            &n.id,
            n.engagement_id.to_string(),
            stage,
            n.finding_id.as_deref(),
            n.evidence_id.as_deref(),
            n.next_chain_id.as_deref(),
            &n.rationale,
            n.created_at.to_rfc3339(),
        ],
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// DataflowEdge — Plan D cartographer extension
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct DataflowEdge {
    pub engagement_id: Uuid,
    pub from_symbol: String,
    pub to_symbol: String,
    pub edge_kind: String,
    pub file_path: String,
    pub line: i64,
}

pub fn insert_dataflow_edge(conn: &Connection, e: &DataflowEdge) -> Result<()> {
    conn.execute(
        "INSERT OR IGNORE INTO dataflow_edges
            (engagement_id, from_symbol, to_symbol, edge_kind, file_path, line)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            e.engagement_id.to_string(),
            &e.from_symbol,
            &e.to_symbol,
            &e.edge_kind,
            &e.file_path,
            e.line,
        ],
    )?;
    Ok(())
}

pub fn list_dataflow_edges_from(
    conn: &Connection,
    engagement_id: Uuid,
    from_symbol: &str,
) -> Result<Vec<DataflowEdge>> {
    let mut stmt = conn.prepare(
        "SELECT from_symbol, to_symbol, edge_kind, file_path, line
         FROM dataflow_edges WHERE engagement_id = ?1 AND from_symbol = ?2",
    )?;
    let rows = stmt
        .query_map(params![engagement_id.to_string(), from_symbol], |r| {
            Ok(DataflowEdge {
                engagement_id,
                from_symbol: r.get(0)?,
                to_symbol: r.get(1)?,
                edge_kind: r.get(2)?,
                file_path: r.get(3)?,
                line: r.get(4)?,
            })
        })?
        .filter_map(|r| r.ok())
        .collect();
    Ok(rows)
}

// ---------------------------------------------------------------------------
// KnowledgeTriple — Plan G reflector cross-engagement learnings
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct KnowledgeTriple {
    pub id: String,
    pub engagement_id: Uuid,
    pub subject: String,
    pub predicate: String,
    pub object: String,
    pub confidence: Option<f64>,
    pub rationale: Option<String>,
    pub source_phase: String,
    pub created_at: DateTime<Utc>,
}

/// Insert one (subject, predicate, object) triple. `id` is the caller's
/// responsibility (e.g. `KT-<eng8>-<idx>`).
pub fn insert_knowledge_triple(conn: &Connection, kt: &KnowledgeTriple) -> Result<()> {
    conn.execute(
        "INSERT INTO knowledge_triples
            (id, engagement_id, subject, predicate, object, confidence, rationale, source_phase, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            &kt.id,
            kt.engagement_id.to_string(),
            &kt.subject,
            &kt.predicate,
            &kt.object,
            kt.confidence,
            kt.rationale.as_deref(),
            &kt.source_phase,
            kt.created_at.to_rfc3339(),
        ],
    )?;
    Ok(())
}

/// Paginated triple lister for one engagement. `page` is 0-indexed;
/// `page_size` clamped to [1, 100] (None → 30). Stable ORDER BY id.
pub fn list_knowledge_triples(
    conn: &Connection,
    engagement_id: Uuid,
    page: u32,
    page_size: Option<u32>,
) -> Result<Vec<KnowledgeTriple>> {
    let page_size = page_size.unwrap_or(30).clamp(1, 100) as i64;
    let offset = (page as i64) * page_size;
    let mut stmt = conn.prepare(
        "SELECT id, engagement_id, subject, predicate, object, confidence, rationale, source_phase, created_at
         FROM knowledge_triples
         WHERE engagement_id = ?1
         ORDER BY id
         LIMIT ?2 OFFSET ?3",
    )?;
    let rows = stmt
        .query_map(params![engagement_id.to_string(), page_size, offset], row_to_kt)?
        .filter_map(|r| r.ok())
        .collect();
    Ok(rows)
}

/// Drain every knowledge_triple row for an engagement (used by the Plan G
/// reporter; volumes are small). Pages through `list_knowledge_triples`
/// in 100-row windows.
pub fn list_all_knowledge_triples_for(
    conn: &Connection,
    engagement_id: Uuid,
) -> Result<Vec<KnowledgeTriple>> {
    let mut out = Vec::new();
    let mut page: u32 = 0;
    loop {
        let batch = list_knowledge_triples(conn, engagement_id, page, Some(100))?;
        if batch.is_empty() {
            break;
        }
        let done = batch.len() < 100;
        out.extend(batch);
        if done {
            break;
        }
        page += 1;
    }
    Ok(out)
}

/// Total triple count for one engagement (paired with `list_knowledge_triples`
/// for pagination headers).
pub fn count_knowledge_triples(conn: &Connection, engagement_id: Uuid) -> Result<i64> {
    let n: i64 = conn.query_row(
        "SELECT COUNT(*) FROM knowledge_triples WHERE engagement_id = ?1",
        params![engagement_id.to_string()],
        |r| r.get(0),
    )?;
    Ok(n)
}

/// CROSS-engagement subject lookup. Matches by `LIKE '%<substr>%'` so future
/// engagements can recall prior knowledge whose subject contains a fragment
/// they care about (e.g. "axum::extract" matches "axum::extract::Query").
/// `limit` clamped to [1, 100].
pub fn recall_knowledge_by_subject(
    conn: &Connection,
    subject_substr: &str,
    limit: u32,
) -> Result<Vec<KnowledgeTriple>> {
    let limit = limit.clamp(1, 100) as i64;
    let pattern = format!("%{subject_substr}%");
    let mut stmt = conn.prepare(
        "SELECT id, engagement_id, subject, predicate, object, confidence, rationale, source_phase, created_at
         FROM knowledge_triples
         WHERE subject LIKE ?1
         ORDER BY created_at DESC
         LIMIT ?2",
    )?;
    let rows = stmt
        .query_map(params![pattern, limit], row_to_kt)?
        .filter_map(|r| r.ok())
        .collect();
    Ok(rows)
}

fn row_to_kt(r: &rusqlite::Row<'_>) -> rusqlite::Result<KnowledgeTriple> {
    let eid_str: String = r.get(1)?;
    let created_str: String = r.get(8)?;
    Ok(KnowledgeTriple {
        id: r.get(0)?,
        engagement_id: eid_str.parse().map_err(|e: uuid::Error| {
            rusqlite::Error::FromSqlConversionFailure(1, rusqlite::types::Type::Text, Box::new(e))
        })?,
        subject: r.get(2)?,
        predicate: r.get(3)?,
        object: r.get(4)?,
        confidence: r.get(5)?,
        rationale: r.get(6)?,
        source_phase: r.get(7)?,
        created_at: DateTime::parse_from_rfc3339(&created_str)
            .map_err(|e| rusqlite::Error::FromSqlConversionFailure(
                8, rusqlite::types::Type::Text, Box::new(e),
            ))?
            .with_timezone(&Utc),
    })
}

impl From<serde_json::Error> for DbError {
    fn from(e: serde_json::Error) -> Self {
        DbError::Sqlite(rusqlite::Error::ToSqlConversionFailure(Box::new(e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn init_db_creates_expected_tables() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.db");
        let conn = init_db(path.to_str().unwrap()).unwrap();

        let mut stmt = conn.prepare(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        ).unwrap();
        let names: Vec<String> = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .filter_map(|r| r.ok())
            .filter(|n| !n.starts_with("sqlite_"))
            .collect();

        let expected = [
            // v1 design tables
            "engagements", "evidence", "findings", "knowledge",
            "repo_facts", "routes", "sboms", "secrets",
            "symbol_index", "tool_runs",
            // AI-perspective amendment tables
            "threat_models", "finding_citations", "hypotheses",
            "taint_chains", "attack_chains",
            // Plan G reflector
            "knowledge_triples",
        ];
        for tbl in expected {
            assert!(names.contains(&tbl.to_string()),
                "missing table {tbl}; got: {names:?}");
        }
    }

    #[test]
    fn init_db_is_idempotent() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.db");
        let _c1 = init_db(path.to_str().unwrap()).unwrap();
        let _c2 = init_db(path.to_str().unwrap()).unwrap();   // must not error
    }

    #[test]
    fn init_db_enables_wal() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.db");
        let conn = init_db(path.to_str().unwrap()).unwrap();
        let mode: String = conn
            .pragma_query_value(None, "journal_mode", |r| r.get(0))
            .unwrap();
        assert_eq!(mode.to_lowercase(), "wal");
    }
}

#[cfg(test)]
mod crud_tests {
    use super::*;
    use symbi_evidence_schema::{Engagement, Finding, finding::{Phase, Severity, Confidence, Status}};
    use tempfile::TempDir;
    use chrono::Utc;
    use uuid::Uuid;

    fn fresh_db() -> (TempDir, Connection) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.db");
        let conn = init_db(path.to_str().unwrap()).unwrap();
        (dir, conn)
    }

    #[test]
    fn engagement_roundtrip() {
        let (_dir, conn) = fresh_db();
        let e = Engagement::new("acme", "deadbeef", "2026-05-22", "2026-05-29");
        let id = e.id;
        insert_engagement(&conn, &e).unwrap();

        let back = get_engagement(&conn, id).unwrap().unwrap();
        assert_eq!(back.client, "acme");
        assert_eq!(back.scope_hash, "deadbeef");
        assert_eq!(back.id, id);
    }

    #[test]
    fn get_unknown_engagement_returns_none() {
        let (_dir, conn) = fresh_db();
        let unknown = Uuid::new_v4();
        assert!(get_engagement(&conn, unknown).unwrap().is_none());
    }

    #[test]
    fn finding_insert_and_count() {
        let (_dir, conn) = fresh_db();
        let e = Engagement::new("acme", "h", "2026-05-22", "2026-05-29");
        insert_engagement(&conn, &e).unwrap();

        for i in 0..3 {
            let f = Finding {
                id: format!("F-{i:04}"),
                engagement_id: e.id,
                phase: Phase::Sast,
                severity: Severity::High,
                confidence: Confidence::High,
                cwe: Some("CWE-89".into()),
                owasp: None,
                file_path: "src/x.py".into(),
                line_start: 10, line_end: 10,
                title: "T".into(), description: "D".into(),
                reachable: Some(true), exploitable: None,
                evidence_envelope_id: format!("S-001-semgrep-{i:012}"),
                status: Status::Open,
                rank_score: Some(0.9),
                specifier_hash: None,
                advocate_verdict: None,
                tool_origin: None,
                poc_status: None,
                created_at: Utc::now(),
            };
            insert_finding(&conn, &f).unwrap();
        }
        assert_eq!(count_findings_for(&conn, e.id).unwrap(), 3);
    }

    // -----------------------------------------------------------------
    // Plan E: advocate_verdict + poc_status mutators
    // -----------------------------------------------------------------

    fn mk_finding(
        engagement_id: Uuid,
        id: &str,
        cwe: &str,
        status: Status,
        poc_status: Option<symbi_evidence_schema::finding::PocStatus>,
    ) -> Finding {
        Finding {
            id: id.into(),
            engagement_id,
            phase: Phase::Sast,
            severity: Severity::High,
            confidence: Confidence::High,
            cwe: Some(cwe.into()),
            owasp: None,
            file_path: "src/x.py".into(),
            line_start: 10,
            line_end: 10,
            title: "T".into(),
            description: "D".into(),
            reachable: Some(true),
            exploitable: None,
            evidence_envelope_id: format!("S-001-semgrep-{id}"),
            status,
            rank_score: Some(0.9),
            specifier_hash: None,
            advocate_verdict: None,
            tool_origin: None,
            poc_status,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn set_advocate_verdict_updates_column() {
        let (_dir, conn) = fresh_db();
        let e = Engagement::new("acme", "h", "2026-05-22", "2026-05-29");
        insert_engagement(&conn, &e).unwrap();
        let f = mk_finding(e.id, "F-0001", "CWE-89", Status::Open, None);
        insert_finding(&conn, &f).unwrap();

        set_advocate_verdict(&conn, "F-0001", "rebutted").unwrap();

        let v: Option<String> = conn
            .query_row(
                "SELECT advocate_verdict FROM findings WHERE id = ?1",
                params!["F-0001"],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(v.as_deref(), Some("rebutted"));
    }

    #[test]
    fn set_poc_status_refuted_also_downgrades_status() {
        let (_dir, conn) = fresh_db();
        let e = Engagement::new("acme", "h", "2026-05-22", "2026-05-29");
        insert_engagement(&conn, &e).unwrap();
        let f = mk_finding(e.id, "F-0002", "CWE-89", Status::Open, None);
        insert_finding(&conn, &f).unwrap();

        set_poc_status(&conn, "F-0002", "refuted").unwrap();

        let (poc, status): (Option<String>, String) = conn
            .query_row(
                "SELECT poc_status, status FROM findings WHERE id = ?1",
                params!["F-0002"],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(poc.as_deref(), Some("refuted"));
        assert_eq!(status, "hypothesis");
    }

    #[test]
    fn list_poc_candidates_filters_correctly() {
        use symbi_evidence_schema::finding::PocStatus;
        let (_dir, conn) = fresh_db();
        let e = Engagement::new("acme", "h", "2026-05-22", "2026-05-29");
        insert_engagement(&conn, &e).unwrap();

        // candidate: CWE-89, open, no poc_status -> returned
        let f1 = mk_finding(e.id, "F-0001", "CWE-89", Status::Open, None);
        // non-candidate: CWE-89 but triaged
        let f2 = mk_finding(e.id, "F-0002", "CWE-89", Status::Triaged, None);
        // non-candidate: CWE-89 open but poc already reproduced
        let f3 = mk_finding(
            e.id,
            "F-0003",
            "CWE-89",
            Status::Open,
            Some(PocStatus::Reproduced),
        );
        insert_finding(&conn, &f1).unwrap();
        insert_finding(&conn, &f2).unwrap();
        insert_finding(&conn, &f3).unwrap();

        let rows = list_poc_candidates(&conn, e.id, 0, None).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, "F-0001");
        assert_eq!(rows[0].3, "CWE-89");
        let total = count_poc_candidates(&conn, e.id).unwrap();
        assert_eq!(total, 1);
    }

    /// A `triage` (pattern_scout) candidate must be listed before a `sast`
    /// candidate even when its id sorts later, so poc_forge attempts the
    /// chain-aware finding before grinding through scanner hits.
    #[test]
    fn list_poc_candidates_orders_triage_before_sast() {
        let (_dir, conn) = fresh_db();
        let e = Engagement::new("acme", "h", "2026-05-22", "2026-05-29");
        insert_engagement(&conn, &e).unwrap();

        // sast id sorts FIRST alphabetically; triage id sorts later.
        let mut sast = mk_finding(e.id, "F-bandit-0001", "CWE-89", Status::Open, None);
        sast.phase = Phase::Sast;
        let mut scout = mk_finding(e.id, "F-pattern-scout-0000", "CWE-89", Status::Open, None);
        scout.phase = Phase::Triage;
        insert_finding(&conn, &sast).unwrap();
        insert_finding(&conn, &scout).unwrap();

        let rows = list_poc_candidates(&conn, e.id, 0, None).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows[0].0, "F-pattern-scout-0000",
            "triage candidate must precede sast despite later id"
        );
        assert_eq!(rows[1].0, "F-bandit-0001");
    }
}

#[cfg(test)]
mod plan_b_crud_tests {
    use super::*;
    use chrono::Utc;
    use symbi_evidence_schema::{
        Engagement, Hypothesis, HypothesisStatus, ThreatModel, TaintChain, TaintHop,
        AttackChainNode, KillChainStage, Citation,
    };
    use tempfile::TempDir;
    use uuid::Uuid;

    fn fresh() -> (TempDir, Connection, Uuid) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.db");
        let conn = init_db(path.to_str().unwrap()).unwrap();
        let e = Engagement::new("acme", "h", "2026-05-22", "2026-05-29");
        let id = e.id;
        insert_engagement(&conn, &e).unwrap();
        (dir, conn, id)
    }

    #[test]
    fn repo_facts_insert_and_list() {
        let (_dir, conn, eng) = fresh();
        insert_repo_fact(&conn, eng, "language", r#"{"name":"python"}"#).unwrap();
        insert_repo_fact(&conn, eng, "language", r#"{"name":"typescript"}"#).unwrap();
        insert_repo_fact(&conn, eng, "framework", r#"{"name":"flask"}"#).unwrap();

        let langs = list_repo_facts(&conn, eng, "language").unwrap();
        assert_eq!(langs.len(), 2);
        let frameworks = list_repo_facts(&conn, eng, "framework").unwrap();
        assert_eq!(frameworks.len(), 1);
    }

    #[test]
    fn symbol_insert_and_find() {
        let (_dir, conn, eng) = fresh();
        insert_symbol(&conn, eng, "app/users.py", 10, 20, "function", "get_users", "python").unwrap();
        insert_symbol(&conn, eng, "app/admin.py", 5, 15, "function", "get_users", "python").unwrap();
        insert_symbol(&conn, eng, "app/users.py", 30, 35, "function", "delete_user", "python").unwrap();

        let hits = find_symbols_by_name(&conn, eng, "get_users").unwrap();
        assert_eq!(hits.len(), 2);
        let hits = find_symbols_by_name(&conn, eng, "delete_user").unwrap();
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn route_insert_and_count() {
        let (_dir, conn, eng) = fresh();
        insert_route(&conn, eng, "GET", "/users", "users.get_users", None, Some(true), None).unwrap();
        insert_route(&conn, eng, "POST", "/users", "users.create", None, Some(true), None).unwrap();
        assert_eq!(count_routes_for(&conn, eng).unwrap(), 2);
    }

    #[test]
    fn threat_model_insert_roundtrips_specifier_hash() {
        let (_dir, conn, eng) = fresh();
        let json = r#"{"scope":["src/**"]}"#;
        let tm = ThreatModel {
            specifier_hash: ThreatModel::hash_for(json),
            engagement_id: eng,
            canonical_json: json.into(),
            signed_at: Utc::now(),
            signature: "ed25519-sig".into(),
        };
        insert_threat_model(&conn, &tm).unwrap();

        let n: i64 = conn.query_row(
            "SELECT COUNT(*) FROM threat_models WHERE engagement_id = ?1",
            params![eng.to_string()],
            |r| r.get(0),
        ).unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn finding_citation_one_of_each_shape() {
        let (_dir, conn, eng) = fresh();
        use symbi_evidence_schema::{Finding, finding::{Phase, Severity, Confidence, Status}};
        let f = Finding {
            id: "F-0001".into(),
            engagement_id: eng,
            phase: Phase::Sast,
            severity: Severity::High,
            confidence: Confidence::High,
            cwe: None, owasp: None,
            file_path: "x.py".into(), line_start: 1, line_end: 1,
            title: "t".into(), description: "d".into(),
            reachable: None, exploitable: None,
            evidence_envelope_id: "env-1".into(),
            status: Status::Open, rank_score: None,
            specifier_hash: None, advocate_verdict: None,
            tool_origin: None, poc_status: None,
            created_at: Utc::now(),
        };
        insert_finding(&conn, &f).unwrap();

        insert_finding_citation(&conn, &f.id, &Citation::Analyzer {
            finding_id: "F-9999".into(),
        }).unwrap();
        insert_finding_citation(&conn, &f.id, &Citation::Code {
            file_path: "x.py".into(), line_start: 10, line_end: 12,
        }).unwrap();
        insert_finding_citation(&conn, &f.id, &Citation::Hypothesis {
            hypothesis_id: "H-1".into(),
            intended_poc: "send malformed input".into(),
        }).unwrap();

        let n: i64 = conn.query_row(
            "SELECT COUNT(*) FROM finding_citations WHERE finding_id = ?1",
            params![&f.id], |r| r.get(0),
        ).unwrap();
        assert_eq!(n, 3);
    }

    #[test]
    fn hypothesis_taint_chain_attack_chain_inserts() {
        let (_dir, conn, eng) = fresh();

        let h = Hypothesis {
            id: "H-0001".into(),
            engagement_id: eng,
            description: "SQLi via sort".into(),
            status: HypothesisStatus::Proposed,
            created_by_agent: "pattern_scout".into(),
            created_at: Utc::now(),
        };
        insert_hypothesis(&conn, &h).unwrap();

        let c = TaintChain {
            id: "T-0001".into(),
            engagement_id: eng,
            source_file: "u.py".into(), source_line: 1,
            sink_file: "u.py".into(), sink_line: 10,
            chain: vec![TaintHop {
                file_path: "u.py".into(), line: 5,
                propagation_reason: "concat".into(),
            }],
            sanitizers_seen: vec![],
            created_at: Utc::now(),
        };
        insert_taint_chain(&conn, &c).unwrap();

        let n = AttackChainNode {
            id: "AC-0001".into(),
            engagement_id: eng,
            stage: KillChainStage::SurfaceMapping,
            finding_id: None, evidence_id: None, next_chain_id: None,
            rationale: "Surface enumerated".into(),
            created_at: Utc::now(),
        };
        insert_attack_chain_node(&conn, &n).unwrap();

        let hyp_count: i64 = conn.query_row("SELECT COUNT(*) FROM hypotheses", [], |r| r.get(0)).unwrap();
        let taint_count: i64 = conn.query_row("SELECT COUNT(*) FROM taint_chains", [], |r| r.get(0)).unwrap();
        let attack_count: i64 = conn.query_row("SELECT COUNT(*) FROM attack_chains", [], |r| r.get(0)).unwrap();
        assert_eq!(hyp_count, 1);
        assert_eq!(taint_count, 1);
        assert_eq!(attack_count, 1);
    }

    // -----------------------------------------------------------------
    // Plan G: knowledge_triples helpers
    // -----------------------------------------------------------------

    fn mk_kt(eng: Uuid, id: &str, subject: &str, predicate: &str, object: &str) -> KnowledgeTriple {
        KnowledgeTriple {
            id: id.into(),
            engagement_id: eng,
            subject: subject.into(),
            predicate: predicate.into(),
            object: object.into(),
            confidence: Some(0.8),
            rationale: Some("rationale".into()),
            source_phase: "reflector".into(),
            created_at: Utc::now(),
        }
    }

    #[test]
    fn knowledge_triple_insert_and_list_roundtrip() {
        let (_dir, conn, eng) = fresh();
        for i in 0..3 {
            let kt = mk_kt(
                eng,
                &format!("KT-{i:04}"),
                "axum::extract::Query",
                "is_taint_source_for",
                "sqlx::query",
            );
            insert_knowledge_triple(&conn, &kt).unwrap();
        }
        assert_eq!(count_knowledge_triples(&conn, eng).unwrap(), 3);

        let page0 = list_knowledge_triples(&conn, eng, 0, Some(2)).unwrap();
        assert_eq!(page0.len(), 2);
        assert_eq!(page0[0].id, "KT-0000");
        assert_eq!(page0[0].subject, "axum::extract::Query");
        assert_eq!(page0[0].predicate, "is_taint_source_for");
        assert_eq!(page0[0].confidence, Some(0.8));
        assert_eq!(page0[0].source_phase, "reflector");

        let page1 = list_knowledge_triples(&conn, eng, 1, Some(2)).unwrap();
        assert_eq!(page1.len(), 1);
        assert_eq!(page1[0].id, "KT-0002");
    }

    #[test]
    fn count_knowledge_triples_returns_zero_for_empty_engagement() {
        let (_dir, conn, eng) = fresh();
        assert_eq!(count_knowledge_triples(&conn, eng).unwrap(), 0);
    }

    #[test]
    fn recall_knowledge_by_subject_pulls_cross_engagement_matches() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.db");
        let conn = init_db(path.to_str().unwrap()).unwrap();

        // Two different engagements, three triples total.
        let e1 = Engagement::new("acme", "h1", "2026-05-22", "2026-05-29");
        let e2 = Engagement::new("acme", "h2", "2026-05-22", "2026-05-29");
        insert_engagement(&conn, &e1).unwrap();
        insert_engagement(&conn, &e2).unwrap();

        let mut a = mk_kt(e1.id, "KT-a", "axum::extract::Query", "is_taint_source_for", "sqlx::query");
        a.created_at = chrono::DateTime::parse_from_rfc3339("2026-05-23T10:00:00+00:00")
            .unwrap()
            .with_timezone(&Utc);
        let mut b = mk_kt(e2.id, "KT-b", "axum::extract::Path", "is_taint_source_for", "std::process::Command");
        b.created_at = chrono::DateTime::parse_from_rfc3339("2026-05-24T10:00:00+00:00")
            .unwrap()
            .with_timezone(&Utc);
        let mut c = mk_kt(e2.id, "KT-c", "flask.request.args", "is_taint_source_for", "subprocess.Popen");
        c.created_at = chrono::DateTime::parse_from_rfc3339("2026-05-25T10:00:00+00:00")
            .unwrap()
            .with_timezone(&Utc);
        insert_knowledge_triple(&conn, &a).unwrap();
        insert_knowledge_triple(&conn, &b).unwrap();
        insert_knowledge_triple(&conn, &c).unwrap();

        // Substring "axum::extract" matches the two axum rows (cross-engagement).
        let hits = recall_knowledge_by_subject(&conn, "axum::extract", 10).unwrap();
        assert_eq!(hits.len(), 2);
        // Ordered created_at DESC → "KT-b" (newer) first.
        assert_eq!(hits[0].id, "KT-b");
        assert_eq!(hits[1].id, "KT-a");

        // limit honoured.
        let one = recall_knowledge_by_subject(&conn, "axum::extract", 1).unwrap();
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].id, "KT-b");

        // No-match returns empty.
        let none = recall_knowledge_by_subject(&conn, "no::such::subject", 10).unwrap();
        assert!(none.is_empty());
    }

    #[test]
    fn dataflow_edge_insert_and_query_roundtrip() {
        let dir = TempDir::new().unwrap();
        let conn = init_db(dir.path().join("test.db").to_str().unwrap()).unwrap();
        let e = symbi_evidence_schema::Engagement::new("acme", "h", "2026-05-24", "2026-05-31");
        let eng = e.id;
        insert_engagement(&conn, &e).unwrap();

        let edge = DataflowEdge {
            engagement_id: eng,
            from_symbol: "users.py:list_users:request.args".into(),
            to_symbol: "users.py:list_users:name".into(),
            edge_kind: "subscript".into(),
            file_path: "users.py".into(),
            line: 12,
        };
        insert_dataflow_edge(&conn, &edge).unwrap();
        let out = list_dataflow_edges_from(&conn, eng, "users.py:list_users:request.args").unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].to_symbol, "users.py:list_users:name");
    }

    // --- PoC-status integrity: "reproduced" requires a persisted exhibit -----

    fn mkfinding(conn: &Connection, eng: Uuid, id: &str) {
        use symbi_evidence_schema::{Finding, finding::{Phase, Severity, Confidence, Status}};
        let f = Finding {
            id: id.into(),
            engagement_id: eng,
            phase: Phase::Triage,
            severity: Severity::High,
            confidence: Confidence::Medium,
            cwe: Some("CWE-89".into()), owasp: None,
            file_path: "x.go".into(), line_start: 1, line_end: 1,
            title: "t".into(), description: "d".into(),
            reachable: None, exploitable: None,
            evidence_envelope_id: "env-1".into(),
            status: Status::Open, rank_score: None,
            specifier_hash: None, advocate_verdict: None,
            tool_origin: Some("pattern_scout".into()), poc_status: None,
            created_at: Utc::now(),
        };
        insert_finding(conn, &f).unwrap();
    }

    fn poc_status_of(conn: &Connection, id: &str) -> Option<String> {
        conn.query_row(
            "SELECT poc_status FROM findings WHERE id = ?1",
            params![id], |r| r.get::<_, Option<String>>(0),
        ).unwrap()
    }

    #[test]
    fn reproduced_without_artifact_is_rejected() {
        let (_dir, conn, eng) = fresh();
        mkfinding(&conn, eng, "F-1");
        // No PoC exhibit recorded → marking "reproduced" must fail and leave the
        // finding's poc_status untouched.
        let err = set_poc_status(&conn, "F-1", "reproduced");
        assert!(matches!(err, Err(DbError::Integrity(_))), "got {err:?}");
        assert_eq!(poc_status_of(&conn, "F-1"), None);
        assert!(!has_poc_artifact(&conn, "F-1").unwrap());
    }

    #[test]
    fn reproduced_with_artifact_succeeds() {
        let (_dir, conn, eng) = fresh();
        mkfinding(&conn, eng, "F-2");
        record_poc_artifact(
            &conn, "F-2",
            r#"{"verdict":"reproduced","language":"go","script":"package main //...","stdout":"REPRODUCED"}"#,
        ).unwrap();
        assert!(has_poc_artifact(&conn, "F-2").unwrap());
        set_poc_status(&conn, "F-2", "reproduced").unwrap();
        assert_eq!(poc_status_of(&conn, "F-2").as_deref(), Some("reproduced"));
    }

    #[test]
    fn reproduced_by_citation_also_requires_artifact() {
        let (_dir, conn, eng) = fresh();
        mkfinding(&conn, eng, "F-3");
        let err = set_poc_status(&conn, "F-3", "reproduced_by_citation");
        assert!(matches!(err, Err(DbError::Integrity(_))), "got {err:?}");
        record_poc_artifact(&conn, "F-3", r#"{"verdict":"reproduced_by_citation"}"#).unwrap();
        set_poc_status(&conn, "F-3", "reproduced_by_citation").unwrap();
        assert_eq!(poc_status_of(&conn, "F-3").as_deref(), Some("reproduced_by_citation"));
    }

    #[test]
    fn refuted_needs_no_artifact() {
        let (_dir, conn, eng) = fresh();
        mkfinding(&conn, eng, "F-4");
        // A conservative downgrade must never be blocked by the artifact guard.
        set_poc_status(&conn, "F-4", "refuted").unwrap();
        assert_eq!(poc_status_of(&conn, "F-4").as_deref(), Some("refuted"));
    }
}
