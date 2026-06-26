//! Pure-data dispatchers for the read-only tools that pattern_scout calls
//! through the ORGA loop.
//!
//! Each function returns a `serde_json::Value` that the ORGA executor will
//! ship straight back to the agent (envelope = false in the manifests).
//!
//! Schema notes (adapted from the actual SQLite schema,
//! crates/symbi-codered-core/src/schema.sql):
//!   - `threat_models` column is `json` (not `canonical_json`)
//!   - `taint_chains` columns are
//!     `(id, engagement_id, source_file, source_line, sink_file, sink_line,
//!       chain_json, sanitizers_seen, created_at)`
//!     — not `(source_symbol, sink_symbol, steps_json)` as the plan drafted.
//!   - `findings.tool_origin` is nullable; `findings.cwe` is nullable.
//!
//! `read_context_range` is exposed as a sibling of the existing `read_context`
//! tool (which returns enclosing function + imports). The range slicer
//! returns the raw `[line_start..line_end]` slice, which is what
//! `pattern_scout` needs when attaching `Citation::Code` snippets.

use rusqlite::Connection;
use serde_json::{json, Value};
use std::path::Path;
use uuid::Uuid;

/// Return the most-recently pinned threat model for `engagement_id`, or
/// `Ok(None)` if no row exists.
pub fn query_threat_model(conn: &Connection, engagement_id: Uuid) -> rusqlite::Result<Option<Value>> {
    let mut stmt = conn.prepare(
        "SELECT specifier_hash, json, signed_at, signature
         FROM threat_models WHERE engagement_id = ?1
         ORDER BY signed_at DESC LIMIT 1",
    )?;
    let mut rows = stmt.query(rusqlite::params![engagement_id.to_string()])?;
    if let Some(r) = rows.next()? {
        Ok(Some(json!({
            "specifier_hash": r.get::<_, String>(0)?,
            "canonical_json": r.get::<_, String>(1)?,
            "signed_at":      r.get::<_, String>(2)?,
            "signature":      r.get::<_, String>(3)?,
        })))
    } else {
        Ok(None)
    }
}

/// Maximum findings returned per page. Calibrated so 30 compact rows fit
/// comfortably under ~10K tokens after JSON envelope overhead, leaving the
/// agent room to reason and make tool calls without triggering Symbiont's
/// context compaction (which kicks in around ~85K tokens by default).
pub const DEFAULT_PAGE_SIZE: u32 = 30;
pub const MAX_PAGE_SIZE: u32 = 100;

/// Per-row description trim threshold for findings whose descriptions
/// exceed this character count. Engineering reality: scanner-emitted
/// descriptions (especially semgrep + checkov) routinely run to 5-10KB
/// per row. With 30 rows per page that's 150-300KB of context per
/// query_findings response, and a single oversized tool_result blows
/// the reasoning loop's context budget. Cap each description to this
/// length with a "[…truncated…]" suffix; the agent can fetch the full
/// description on-demand via query_finding_detail when it needs more.
pub const MAX_DESCRIPTION_CHARS: usize = 600;

/// Paginated findings query. Returns `{findings: [...], page, page_size,
/// total, has_more}` so the agent knows when to fetch the next page.
///
/// `page` is 0-indexed. `page_size` is clamped to `[1, MAX_PAGE_SIZE]`;
/// `None` uses `DEFAULT_PAGE_SIZE`.
///
/// `compact=true` drops the `description` field (often the longest column)
/// — useful for index/triage passes where the agent just needs to know
/// what exists. Per-row token cost drops by roughly 50%, letting the LLM
/// see ~2x more findings per page.
pub fn query_findings(
    conn: &Connection,
    engagement_id: Uuid,
    tool_origin: Option<&str>,
    page: u32,
    page_size: Option<u32>,
    compact: bool,
) -> rusqlite::Result<Value> {
    let eid = engagement_id.to_string();
    let page_size = page_size.unwrap_or(DEFAULT_PAGE_SIZE).clamp(1, MAX_PAGE_SIZE);
    let offset = (page as i64) * (page_size as i64);
    let limit = page_size as i64;

    // Count total so the agent can size its work upfront.
    let total: i64 = match tool_origin {
        Some(t) => conn.query_row(
            "SELECT COUNT(*) FROM findings WHERE engagement_id = ?1 AND tool_origin = ?2",
            rusqlite::params![eid, t],
            |r| r.get(0),
        )?,
        None => conn.query_row(
            "SELECT COUNT(*) FROM findings WHERE engagement_id = ?1",
            rusqlite::params![eid],
            |r| r.get(0),
        )?,
    };

    let mapper: fn(&rusqlite::Row<'_>) -> rusqlite::Result<Value> =
        if compact { row_to_finding_compact } else { row_to_finding };

    let rows: Vec<Value> = match tool_origin {
        Some(t) => {
            let mut stmt = conn.prepare(
                "SELECT id, file_path, line_start, line_end, cwe, severity, title, description, tool_origin
                 FROM findings WHERE engagement_id = ?1 AND tool_origin = ?2
                 ORDER BY id LIMIT ?3 OFFSET ?4",
            )?;
            let it = stmt
                .query_map(rusqlite::params![eid, t, limit, offset], mapper)?
                .filter_map(|r| r.ok())
                .collect();
            it
        }
        None => {
            let mut stmt = conn.prepare(
                "SELECT id, file_path, line_start, line_end, cwe, severity, title, description, tool_origin
                 FROM findings WHERE engagement_id = ?1
                 ORDER BY id LIMIT ?2 OFFSET ?3",
            )?;
            let it = stmt
                .query_map(rusqlite::params![eid, limit, offset], mapper)?
                .filter_map(|r| r.ok())
                .collect();
            it
        }
    };

    let returned = rows.len() as i64;
    let has_more = offset + returned < total;
    Ok(json!({
        "findings": rows,
        "page":      page,
        "page_size": page_size,
        "total":     total,
        "returned":  returned,
        "has_more":  has_more,
        "compact":   compact,
    }))
}

/// Same shape as [`query_findings`] but tuned for triage agents
/// (devils_advocate): skip path prefixes that are almost always CI/ops
/// noise on a polyglot codebase, and surface highest-severity findings
/// first so the agent's iteration budget is spent where signal density
/// is greatest. Schema-compatible with [`query_findings`] — same response
/// envelope so the agent doesn't need to know about the reordering.
///
/// Path-prefix skip list assumes the in-container scan root mounts as
/// `/repo/`. Findings whose file_path starts with one of these prefixes
/// are dropped at the SQL layer (not just deprioritized):
///   - `/repo/.github/` — CI workflows
///   - `/repo/ops/`     — operational scripts
///   - `/repo/scripts/` — build / utility scripts
///   - `/repo/internal-docs/` — documentation
///
/// Ordering: severity rank DESC (critical → high → medium → low → info),
/// then finding id ASC for determinism inside a severity bucket.
/// Map a severity label to a numeric rank. Unknown labels return 0
/// (matching the SQL ORDER BY).
fn severity_rank(s: &str) -> i64 {
    match s {
        "critical" => 4,
        "high"     => 3,
        "medium"   => 2,
        "low"      => 1,
        _          => 0,
    }
}

pub fn query_findings_prioritized(
    conn: &Connection,
    engagement_id: Uuid,
    tool_origin: Option<&str>,
    page: u32,
    page_size: Option<u32>,
    compact: bool,
    severity_floor: Option<&str>,
) -> rusqlite::Result<Value> {
    let eid = engagement_id.to_string();
    let page_size = page_size.unwrap_or(DEFAULT_PAGE_SIZE).clamp(1, MAX_PAGE_SIZE);
    let offset = (page as i64) * (page_size as i64);
    let limit = page_size as i64;

    // Match both rooted (e.g. /repo/.github/...) and relative (e.g.
    // .github/...) path shapes — scanner-emitted findings carry the
    // sidecar mount prefix while pattern_scout's composed findings use
    // relative paths from target_repo.
    //
    // Conservative skip list: only directories where findings are
    // almost certainly CI/docs metadata. `scripts/` and `ops/` LOOK
    // generic but in real codebases (azimuth, for one) they hold real
    // tooling with legitimate command-execution and file-I/O sinks
    // worth scrutinizing. Better to surface them to the advocate and
    // let it rebut than to silently filter.
    const SKIP_PREFIXES_CLAUSE: &str = "
        AND file_path NOT LIKE '%/.github/%'
        AND file_path NOT LIKE '.github/%'
        AND file_path NOT LIKE '%/internal-docs/%'
        AND file_path NOT LIKE 'internal-docs/%'
    ";
    const ORDER_CLAUSE: &str = "
        ORDER BY
          CASE severity
            WHEN 'critical' THEN 4
            WHEN 'high'     THEN 3
            WHEN 'medium'   THEN 2
            WHEN 'low'      THEN 1
            ELSE 0
          END DESC,
          id ASC
    ";

    // Optional severity floor — when supplied, drop findings ranked below it.
    // The SQL CASE re-encodes the same rank so we can compare against the
    // numeric threshold without trusting the on-disk text values to sort
    // lexicographically.
    let floor_rank = severity_floor.map(severity_rank).unwrap_or(0);
    let severity_floor_clause: String = if floor_rank > 0 {
        format!(
            " AND (CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 \
             WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END) >= {floor_rank}"
        )
    } else {
        String::new()
    };

    let total: i64 = match tool_origin {
        Some(t) => conn.query_row(
            &format!(
                "SELECT COUNT(*) FROM findings WHERE engagement_id = ?1 AND tool_origin = ?2 {SKIP_PREFIXES_CLAUSE} {severity_floor_clause}"
            ),
            rusqlite::params![eid, t],
            |r| r.get(0),
        )?,
        None => conn.query_row(
            &format!(
                "SELECT COUNT(*) FROM findings WHERE engagement_id = ?1 {SKIP_PREFIXES_CLAUSE} {severity_floor_clause}"
            ),
            rusqlite::params![eid],
            |r| r.get(0),
        )?,
    };

    let mapper: fn(&rusqlite::Row<'_>) -> rusqlite::Result<Value> =
        if compact { row_to_finding_compact } else { row_to_finding };

    let rows: Vec<Value> = match tool_origin {
        Some(t) => {
            let sql = format!(
                "SELECT id, file_path, line_start, line_end, cwe, severity, title, description, tool_origin
                 FROM findings WHERE engagement_id = ?1 AND tool_origin = ?2 {SKIP_PREFIXES_CLAUSE} {severity_floor_clause} {ORDER_CLAUSE}
                 LIMIT ?3 OFFSET ?4"
            );
            let mut stmt = conn.prepare(&sql)?;
            let it = stmt
                .query_map(rusqlite::params![eid, t, limit, offset], mapper)?
                .filter_map(|r| r.ok())
                .collect();
            it
        }
        None => {
            let sql = format!(
                "SELECT id, file_path, line_start, line_end, cwe, severity, title, description, tool_origin
                 FROM findings WHERE engagement_id = ?1 {SKIP_PREFIXES_CLAUSE} {severity_floor_clause} {ORDER_CLAUSE}
                 LIMIT ?2 OFFSET ?3"
            );
            let mut stmt = conn.prepare(&sql)?;
            let it = stmt
                .query_map(rusqlite::params![eid, limit, offset], mapper)?
                .filter_map(|r| r.ok())
                .collect();
            it
        }
    };

    let returned = rows.len() as i64;
    let has_more = offset + returned < total;
    Ok(json!({
        "findings": rows,
        "page":      page,
        "page_size": page_size,
        "total":     total,
        "returned":  returned,
        "has_more":  has_more,
        "compact":   compact,
        "prioritized": true,
        "severity_floor": severity_floor,
    }))
}

fn row_to_finding(r: &rusqlite::Row<'_>) -> rusqlite::Result<Value> {
    let description: String = r.get(7)?;
    let description = if description.chars().count() > MAX_DESCRIPTION_CHARS {
        // Trim on a char boundary, not a byte index, so multi-byte
        // codepoints don't get sliced. Use chars().take().collect().
        let trimmed: String = description.chars().take(MAX_DESCRIPTION_CHARS).collect();
        format!("{trimmed} […truncated; call query_finding_detail(id) for full text…]")
    } else {
        description
    };
    Ok(json!({
        "id":          r.get::<_, String>(0)?,
        "file_path":   r.get::<_, String>(1)?,
        "line_start":  r.get::<_, i64>(2)?,
        "line_end":    r.get::<_, i64>(3)?,
        "cwe":         r.get::<_, Option<String>>(4)?,
        "severity":    r.get::<_, String>(5)?,
        "title":       r.get::<_, String>(6)?,
        "description": description,
        "tool_origin": r.get::<_, Option<String>>(8)?,
    }))
}

/// Compact projection: drops description (often the longest column) and
/// keeps the headline metadata. Saves roughly half the per-row tokens.
fn row_to_finding_compact(r: &rusqlite::Row<'_>) -> rusqlite::Result<Value> {
    Ok(json!({
        "id":          r.get::<_, String>(0)?,
        "file_path":   r.get::<_, String>(1)?,
        "line_start":  r.get::<_, i64>(2)?,
        "line_end":    r.get::<_, i64>(3)?,
        "cwe":         r.get::<_, Option<String>>(4)?,
        "severity":    r.get::<_, String>(5)?,
        "title":       r.get::<_, String>(6)?,
        "tool_origin": r.get::<_, Option<String>>(8)?,
    }))
}

/// Fetch a single finding's FULL details (incl. description). Used by
/// agents that fetched a compact page and want to dig into one row.
pub fn query_finding_detail(
    conn: &Connection,
    engagement_id: Uuid,
    finding_id: &str,
) -> rusqlite::Result<Option<Value>> {
    let mut stmt = conn.prepare(
        "SELECT id, file_path, line_start, line_end, cwe, severity, title, description, tool_origin
         FROM findings WHERE engagement_id = ?1 AND id = ?2",
    )?;
    let mut rows = stmt.query(rusqlite::params![engagement_id.to_string(), finding_id])?;
    if let Some(r) = rows.next()? {
        Ok(Some(row_to_finding(r)?))
    } else {
        Ok(None)
    }
}

/// Return all taint chains for an engagement.
///
/// `chain` is the deserialized `chain_json` array of hops. `sanitizers_seen`
/// is the deserialized JSON array.
pub fn query_taint_chains(conn: &Connection, engagement_id: Uuid) -> rusqlite::Result<Value> {
    query_taint_chains_paged(conn, engagement_id, 0, None)
}

/// Paginated taint-chain query. Critical for large engagements: a single
/// `query_taint_chains` that returns all rows (azimuth produced 1063)
/// with each row's full hop-by-hop `chain_json` blows the reasoning
/// loop's context budget, forcing truncation that makes the agent
/// "forget" it already queried and re-loop forever.
///
/// Three mitigations:
///   1. Paginate (default page_size 30, clamped to MAX_PAGE_SIZE).
///   2. UNGUARDED chains first — those carrying sanitizers_seen
///      containing "unguarded" are the missing-auth candidates the
///      agent most needs to see; surface them at the top.
///   3. The list view OMITS the full hop chain (the biggest column);
///      it returns source/sink locations + hop_count + unguarded flag.
///      The agent reads actual code via read_context_range.
pub fn query_taint_chains_paged(
    conn: &Connection,
    engagement_id: Uuid,
    page: u32,
    page_size: Option<u32>,
) -> rusqlite::Result<Value> {
    let eid = engagement_id.to_string();
    let page_size = page_size.unwrap_or(DEFAULT_PAGE_SIZE).clamp(1, MAX_PAGE_SIZE);
    let offset = (page as i64) * (page_size as i64);
    let limit = page_size as i64;

    let total: i64 = conn.query_row(
        "SELECT COUNT(*) FROM taint_chains WHERE engagement_id = ?1",
        rusqlite::params![eid],
        |r| r.get(0),
    )?;

    // Ordering, most-valuable first:
    //   1. unguarded (missing-auth candidate) before guarded
    //   2. within that, PRODUCTION-path sinks before dev-tooling sinks.
    //      Prior engagements (and reflector triples) consistently show
    //      that taint chains whose sink lives in scripts/ / notebooks/ /
    //      test / fixtures / mocks are CLI-argv-driven operator tooling or
    //      generated test scaffolding — a false-positive class. (Go
    //      especially emits many `*_mock.go` / `*_test.go` siblings that
    //      flow request-shaped params into sinks but are never reachable in
    //      production.) Pushing them below production-path chains means the
    //      scout's iteration budget lands on the web-service / services /
    //      jobs / cmd sinks that actually matter, instead of burning reads
    //      on dev scripts and mocks.
    //   3. id for determinism.
    let mut stmt = conn.prepare(
        "SELECT id, source_file, source_line, sink_file, sink_line, chain_json, sanitizers_seen
         FROM taint_chains WHERE engagement_id = ?1
         ORDER BY
           (CASE WHEN sanitizers_seen LIKE '%unguarded%' THEN 0 ELSE 1 END),
           (CASE WHEN sink_file LIKE '%/scripts/%' OR sink_file LIKE 'scripts/%'
                   OR sink_file LIKE '%/notebooks/%' OR sink_file LIKE 'notebooks/%'
                   OR sink_file LIKE '%/test/%' OR sink_file LIKE '%/tests/%'
                   OR sink_file LIKE '%_test.%' OR sink_file LIKE '%/fixtures/%'
                   OR sink_file LIKE '%_mock.%' OR sink_file LIKE '%/mocks/%'
                   OR sink_file LIKE '%/mock/%'
                 THEN 1 ELSE 0 END),
           id
         LIMIT ?2 OFFSET ?3",
    )?;
    let rows: Vec<Value> = stmt
        .query_map(rusqlite::params![eid, limit, offset], |r| {
            let chain_json: String = r.get(5)?;
            let sanitizers_json: Option<String> = r.get(6)?;
            // Count hops without serializing the whole chain into the
            // response — keeps the per-row payload tiny.
            let hop_count = serde_json::from_str::<Value>(&chain_json)
                .ok()
                .and_then(|v| v.as_array().map(|a| a.len()))
                .unwrap_or(0);
            let unguarded = sanitizers_json
                .as_deref()
                .map(|s| s.contains("unguarded"))
                .unwrap_or(false);
            Ok(json!({
                "id":          r.get::<_, String>(0)?,
                "source_file": r.get::<_, String>(1)?,
                "source_line": r.get::<_, i64>(2)?,
                "sink_file":   r.get::<_, String>(3)?,
                "sink_line":   r.get::<_, i64>(4)?,
                "hop_count":   hop_count,
                "unguarded":   unguarded,
            }))
        })?
        .filter_map(|r| r.ok())
        .collect();

    let returned = rows.len() as i64;
    let has_more = offset + returned < total;
    Ok(json!({
        "chains":    rows,
        "page":      page,
        "page_size": page_size,
        "total":     total,
        "returned":  returned,
        "has_more":  has_more,
    }))
}

/// Read `[line_start..=line_end]` (1-indexed, inclusive) from `file_path`
/// and return a numbered snippet. Used by pattern_scout when attaching
/// `Citation::Code` to a finding.
pub fn read_context_range(
    file_path: &Path,
    line_start: i64,
    line_end: i64,
) -> std::io::Result<Value> {
    let body = std::fs::read_to_string(file_path)?;
    let mut snippet = String::new();
    for (i, line) in body.lines().enumerate() {
        let n = (i + 1) as i64;
        if n >= line_start && n <= line_end {
            snippet.push_str(&format!("{n}: {line}\n"));
        }
        if n > line_end {
            break;
        }
    }
    Ok(json!({
        "file":       file_path.display().to_string(),
        "line_start": line_start,
        "line_end":   line_end,
        "snippet":    snippet,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use symbi_codered_core::db;
    use symbi_evidence_schema::{
        Engagement, TaintChain, TaintHop, ThreatModel,
    };
    use tempfile::TempDir;

    fn fresh_db() -> (TempDir, Connection) {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("t.db");
        let conn = db::init_db(p.to_str().unwrap()).unwrap();
        (dir, conn)
    }

    #[test]
    fn read_context_range_returns_requested_lines() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("x.py");
        std::fs::write(&p, "a\nb\nc\nd\n").unwrap();
        let v = read_context_range(&p, 2, 3).unwrap();
        let s = v.get("snippet").unwrap().as_str().unwrap();
        assert!(s.contains("2: b"), "snippet missing line 2: {s}");
        assert!(s.contains("3: c"), "snippet missing line 3: {s}");
        assert!(!s.contains("1: a"), "snippet leaked line 1: {s}");
        assert!(!s.contains("4: d"), "snippet leaked line 4: {s}");
        assert_eq!(v.get("line_start").unwrap().as_i64().unwrap(), 2);
        assert_eq!(v.get("line_end").unwrap().as_i64().unwrap(), 3);
    }

    #[test]
    fn query_threat_model_returns_pinned_row() {
        let (_dir, conn) = fresh_db();
        let e = Engagement::new("acme", "h", "2026-05-24", "2026-05-31");
        let eng = e.id;
        db::insert_engagement(&conn, &e).unwrap();

        let canonical = r#"{"scope":["src/**"]}"#;
        let tm = ThreatModel {
            specifier_hash: ThreatModel::hash_for(canonical),
            engagement_id: eng,
            canonical_json: canonical.into(),
            signed_at: Utc::now(),
            signature: "00".repeat(64),
        };
        db::insert_threat_model(&conn, &tm).unwrap();

        let v = query_threat_model(&conn, eng).unwrap().expect("row");
        assert_eq!(v.get("specifier_hash").unwrap().as_str().unwrap().len(), 64);
        assert_eq!(v.get("canonical_json").unwrap().as_str().unwrap(), canonical);
        assert_eq!(v.get("signature").unwrap().as_str().unwrap().len(), 128);
    }

    #[test]
    fn query_threat_model_returns_none_when_missing() {
        let (_dir, conn) = fresh_db();
        let e = Engagement::new("acme", "h", "2026-05-24", "2026-05-31");
        let eng = e.id;
        db::insert_engagement(&conn, &e).unwrap();
        assert!(query_threat_model(&conn, eng).unwrap().is_none());
    }

    #[test]
    fn query_taint_chains_round_trips_chain_json() {
        let (_dir, conn) = fresh_db();
        let e = Engagement::new("acme", "h", "2026-05-24", "2026-05-31");
        let eng = e.id;
        db::insert_engagement(&conn, &e).unwrap();

        let c = TaintChain {
            id: "T-0001".into(),
            engagement_id: eng,
            source_file: "users.py".into(),
            source_line: 31,
            sink_file: "users.py".into(),
            sink_line: 88,
            chain: vec![
                TaintHop {
                    file_path: "users.py".into(),
                    line: 44,
                    propagation_reason: "param read".into(),
                },
                TaintHop {
                    file_path: "users.py".into(),
                    line: 88,
                    propagation_reason: "cursor.execute".into(),
                },
            ],
            sanitizers_seen: vec!["escape_string".into()],
            created_at: Utc::now(),
        };
        db::insert_taint_chain(&conn, &c).unwrap();

        // query_taint_chains now returns a paginated envelope with a
        // compact per-row projection: source/sink + hop_count + unguarded
        // flag (the full hop chain is omitted to keep the response small).
        let v = query_taint_chains(&conn, eng).unwrap();
        assert_eq!(v.get("total").unwrap().as_i64().unwrap(), 1);
        assert_eq!(v.get("returned").unwrap().as_i64().unwrap(), 1);
        assert!(!v.get("has_more").unwrap().as_bool().unwrap());
        let arr = v.get("chains").unwrap().as_array().unwrap();
        assert_eq!(arr.len(), 1);
        let row = &arr[0];
        assert_eq!(row.get("id").unwrap().as_str().unwrap(), "T-0001");
        assert_eq!(row.get("source_line").unwrap().as_i64().unwrap(), 31);
        assert_eq!(row.get("sink_line").unwrap().as_i64().unwrap(), 88);
        // hop_count replaces the full chain array in the list view.
        assert_eq!(row.get("hop_count").unwrap().as_i64().unwrap(), 2);
        // This chain has a real sanitizer (not "unguarded").
        assert!(!row.get("unguarded").unwrap().as_bool().unwrap());
    }

    /// Unguarded chains sort before guarded ones in the paginated view.
    #[test]
    fn query_taint_chains_surfaces_unguarded_first() {
        let (_dir, conn) = fresh_db();
        let e = Engagement::new("acme", "h", "2026-05-24", "2026-05-31");
        let eng = e.id;
        db::insert_engagement(&conn, &e).unwrap();

        // Guarded chain (id sorts first, but should appear AFTER unguarded).
        let guarded = TaintChain {
            id: "T-0001".into(),
            engagement_id: eng,
            source_file: "a.py".into(),
            source_line: 1,
            sink_file: "a.py".into(),
            sink_line: 2,
            chain: vec![TaintHop {
                file_path: "a.py".into(),
                line: 1,
                propagation_reason: "x".into(),
            }],
            sanitizers_seen: vec!["escape".into()],
            created_at: Utc::now(),
        };
        let unguarded = TaintChain {
            id: "T-0002".into(),
            engagement_id: eng,
            source_file: "b.py".into(),
            source_line: 1,
            sink_file: "b.py".into(),
            sink_line: 2,
            chain: vec![TaintHop {
                file_path: "b.py".into(),
                line: 1,
                propagation_reason: "x".into(),
            }],
            sanitizers_seen: vec!["unguarded".into()],
            created_at: Utc::now(),
        };
        db::insert_taint_chain(&conn, &guarded).unwrap();
        db::insert_taint_chain(&conn, &unguarded).unwrap();

        let v = query_taint_chains(&conn, eng).unwrap();
        let arr = v.get("chains").unwrap().as_array().unwrap();
        assert_eq!(arr.len(), 2);
        // Unguarded T-0002 must come first despite its higher id.
        assert_eq!(arr[0].get("id").unwrap().as_str().unwrap(), "T-0002");
        assert!(arr[0].get("unguarded").unwrap().as_bool().unwrap());
        assert!(!arr[1].get("unguarded").unwrap().as_bool().unwrap());
    }

    /// Two equally-unguarded chains: the one whose sink lives in a generated
    /// `*_mock.go` must sort AFTER the production-path sink, so the scout
    /// spends its budget on the real handler first.
    #[test]
    fn query_taint_chains_deprioritizes_mock_sinks() {
        let (_dir, conn) = fresh_db();
        let e = Engagement::new("acme", "h", "2026-05-24", "2026-05-31");
        let eng = e.id;
        db::insert_engagement(&conn, &e).unwrap();

        let mk = |id: &str, sink: &str| TaintChain {
            id: id.into(),
            engagement_id: eng,
            source_file: sink.into(),
            source_line: 1,
            sink_file: sink.into(),
            sink_line: 2,
            chain: vec![TaintHop {
                file_path: sink.into(),
                line: 1,
                propagation_reason: "x".into(),
            }],
            sanitizers_seen: vec!["unguarded".into()],
            created_at: Utc::now(),
        };
        // Mock chain has the lower id, so only the dev-tooling rank can
        // demote it below the production handler.
        db::insert_taint_chain(&conn, &mk("T-0001", "read/connections/svc_mock.go")).unwrap();
        db::insert_taint_chain(&conn, &mk("T-0002", "web-service/query_tags.go")).unwrap();

        let v = query_taint_chains(&conn, eng).unwrap();
        let arr = v.get("chains").unwrap().as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(
            arr[0].get("sink_file").unwrap().as_str().unwrap(),
            "web-service/query_tags.go",
            "production sink must precede the *_mock.go sink"
        );
    }

    #[test]
    fn query_findings_filters_by_tool_origin_when_supplied() {
        use symbi_evidence_schema::{Confidence, Finding, Phase, Severity, Status};
        let (_dir, conn) = fresh_db();
        let e = Engagement::new("acme", "h", "2026-05-24", "2026-05-31");
        let eng = e.id;
        db::insert_engagement(&conn, &e).unwrap();

        let mk = |id: &str, tool: &str, title: &str| Finding {
            id: id.to_string(),
            engagement_id: eng,
            phase: Phase::Sast,
            severity: Severity::High,
            confidence: Confidence::Medium,
            cwe: Some("CWE-89".into()),
            owasp: None,
            file_path: "x.py".into(),
            line_start: 1,
            line_end: 2,
            title: title.into(),
            description: "desc".into(),
            reachable: None,
            exploitable: None,
            evidence_envelope_id: format!("EV-{id}"),
            status: Status::Open,
            rank_score: None,
            specifier_hash: None,
            advocate_verdict: None,
            tool_origin: Some(tool.into()),
            poc_status: None,
            created_at: Utc::now(),
        };

        let f1 = mk("F-0001", "semgrep", "sql-injection");
        let f2 = mk("F-0002", "bandit", "weak-hash");
        db::insert_finding(&conn, &f1).unwrap();
        db::insert_finding(&conn, &f2).unwrap();

        let all = query_findings(&conn, eng, None, 0, None, false).unwrap();
        assert_eq!(all.get("total").unwrap().as_i64().unwrap(), 2);
        assert_eq!(all.get("returned").unwrap().as_i64().unwrap(), 2);
        assert!(!all.get("has_more").unwrap().as_bool().unwrap());
        assert_eq!(all.get("findings").unwrap().as_array().unwrap().len(), 2);

        let semgrep_only = query_findings(&conn, eng, Some("semgrep"), 0, None, false).unwrap();
        let arr = semgrep_only.get("findings").unwrap().as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0].get("tool_origin").unwrap().as_str().unwrap(), "semgrep");
        assert_eq!(arr[0].get("title").unwrap().as_str().unwrap(), "sql-injection");
    }

    #[test]
    fn query_findings_paginates() {
        use db::DataflowEdge;
        use symbi_evidence_schema::Engagement;
        let dir = TempDir::new().unwrap();
        let conn = db::init_db(dir.path().join("t.db").to_str().unwrap()).unwrap();
        let e = Engagement::new("acme", "h", "2026-05-25", "2026-06-01");
        let eng = e.id;
        db::insert_engagement(&conn, &e).unwrap();
        // Insert 75 findings so page_size=30 → 3 pages.
        for i in 0..75 {
            let f = symbi_evidence_schema::Finding {
                id: format!("F-{i:04}"),
                engagement_id: eng,
                phase: symbi_evidence_schema::finding::Phase::Sast,
                severity: symbi_evidence_schema::finding::Severity::Low,
                confidence: symbi_evidence_schema::finding::Confidence::Low,
                cwe: None, owasp: None,
                file_path: "x.py".into(),
                line_start: 1, line_end: 1,
                title: format!("t{i}"), description: "d".into(),
                reachable: None, exploitable: None,
                evidence_envelope_id: "e".into(),
                status: symbi_evidence_schema::finding::Status::Open,
                rank_score: None, specifier_hash: None, advocate_verdict: None,
                tool_origin: Some("semgrep".into()),
                poc_status: None, created_at: chrono::Utc::now(),
            };
            db::insert_finding(&conn, &f).unwrap();
        }
        let p0 = query_findings(&conn, eng, None, 0, Some(30), false).unwrap();
        assert_eq!(p0.get("total").unwrap().as_i64().unwrap(), 75);
        assert_eq!(p0.get("returned").unwrap().as_i64().unwrap(), 30);
        assert!(p0.get("has_more").unwrap().as_bool().unwrap());
        let p2 = query_findings(&conn, eng, None, 2, Some(30), false).unwrap();
        assert_eq!(p2.get("returned").unwrap().as_i64().unwrap(), 15); // 75 - 60
        assert!(!p2.get("has_more").unwrap().as_bool().unwrap());
        // Quiet the unused-import warning from the test
        let _ = DataflowEdge {
            engagement_id: eng, from_symbol: "a".into(), to_symbol: "b".into(),
            edge_kind: "assign".into(), file_path: "x".into(), line: 1,
        };
    }
}
