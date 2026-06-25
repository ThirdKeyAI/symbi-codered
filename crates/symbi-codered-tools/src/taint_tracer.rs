//! taint_tracer — mechanical BFS over `dataflow_edges`.
//!
//! Given (sources, sinks) drawn from the specifier's pinned threat model and
//! the `dataflow_edges` populated by the cartographer (see
//! `crate::dataflow`), this module emits one `TaintChain` row per
//! source→sink path discovered.
//!
//! The tracer is deliberately mechanical — there is no LLM in the loop. Given
//! a fixed dataflow graph and a fixed (sources, sinks) pair, every run yields
//! the same set of chains; mechanical reproducibility is a deliberate design
//! property of the taint result.
//!
//! ## Algorithm
//!
//! 1. For each `source` substring, look up every `from_symbol` in
//!    `dataflow_edges` that contains it. These are the BFS seeds — the
//!    qualified symbol form (e.g. `users.py:list_users:request.args`) means
//!    we substring-match against the bare source name (`request.args`).
//! 2. From each seed, BFS forward over `dataflow_edges` (capped at
//!    `MAX_PATH_LEN` hops). Whenever the current symbol contains any sink
//!    substring, emit a `TaintChain` and stop expanding that branch.
//! 3. A visited set keyed on `to_symbol` prevents cycles.

use chrono::Utc;
use rusqlite::Connection;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use thiserror::Error;
use uuid::Uuid;

use symbi_codered_core::audit;
use symbi_codered_core::db::{self, DataflowEdge};
use symbi_evidence_schema::{TaintChain, TaintHop};

/// Hard cap on path length. Without this, pathological dataflow graphs (deep
/// chains of pure assignments) could let the queue grow unboundedly even with
/// cycle detection, because BFS records each *path*, not each node.
const MAX_PATH_LEN: usize = 12;

/// Lines scanned above a function's `line_start` to catch decorators
/// (`@login_required`) and attribute macros that sit just before the
/// signature.
const DECORATOR_LOOKBACK: u32 = 5;

/// Fallback scope window (lines above/below a hop) used when no enclosing
/// function is indexed — i.e. every non-Python sink, since the cartographer
/// only emits Python symbols today. Guards (decorators, early-return auth
/// checks) almost always precede the operation, so the back window is wide
/// and the forward window narrow to avoid bleeding into the next function.
const WINDOW_BACK: u32 = 40;
const WINDOW_FWD: u32 = 8;

/// Skip source files larger than this when scanning for guards; a vendored
/// minified bundle has no meaningful function scope and would just waste
/// memory in the line cache.
const MAX_SCAN_FILE_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum TaintTracerError {
    #[error("db: {0}")]
    Db(#[from] db::DbError),
    #[error("rusqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("audit: {0}")]
    Audit(#[from] audit::AuditError),
}

pub struct TraceInput<'a> {
    pub engagement_id: Uuid,
    pub sources: &'a [String],
    pub sinks: &'a [String],
    /// Function-name patterns that count as authorization / sanitization
    /// guards. A chain is classified `guarded` when a guard appears either
    /// on the dataflow path itself OR textually within the enclosing scope
    /// of the chain's source or sink hop (see [`GuardScanner`]). Empty slice
    /// = classify everything as `unguarded` (legacy behavior).
    pub guards: &'a [String],
    /// Host-side root the chain's repo-relative `file_path`s resolve against,
    /// used for scope-based guard scanning. Callers run `codered hunt` from
    /// the target repo root, so this is typically `Path::new(".")`.
    pub source_root: &'a Path,
    pub journal_path: &'a str,
}

pub struct TraceSummary {
    pub chains_emitted: usize,
    /// Chains whose path did NOT cross a guard call. These are the
    /// "missing-auth" signal — source data reaches a sensitive sink
    /// without going through any of the threat-model's named guards.
    pub unguarded_chains: usize,
}

/// Run the BFS for every (source, sink) pair and persist each discovered
/// chain via `db::insert_taint_chain`.
pub fn trace(conn: &Connection, input: &TraceInput) -> Result<TraceSummary, TaintTracerError> {
    let mut chains = 0;
    let mut unguarded = 0;
    let scanner = GuardScanner::new(input.source_root, input.guards);

    // Expand sinks the same way we expand sources: full pattern + last
    // identifier segment. bfs_emit uses substring matching, so we add the
    // bare leaf identifier as an additional candidate. De-duplicated to
    // avoid double matching when a sink has no qualifier.
    let mut expanded_sinks: Vec<String> = Vec::new();
    let mut seen_sinks = std::collections::HashSet::new();
    for s in input.sinks {
        if seen_sinks.insert(s.clone()) {
            expanded_sinks.push(s.clone());
        }
        if let Some(leaf) = s.rsplit(['.', ':']).next() {
            if !leaf.is_empty() && leaf != s && seen_sinks.insert(leaf.to_string()) {
                expanded_sinks.push(leaf.to_string());
            }
        }
    }

    for source in input.sources {
        // Threat-model sources are usually qualified (e.g. "request.args",
        // "axum::extract::Query", "req.body"), but the chunker stores
        // dataflow edges with bare identifiers — Python's "request.args"
        // ends up split, Rust's "axum::extract::Query" lands as just
        // "Query". A pure LIKE '%source%' substring match catches
        // identical-form symbols only; we'd miss every cross-language
        // pattern. Build a set of patterns to try:
        //
        //   1. The full source as a substring (anywhere in from_symbol).
        //   2. The last `.` or `::` segment, anchored to the var-name
        //      position (`:<seg>` — last colon-separated chunk of the
        //      `file:fn:var` symbol). This is the high-precision shot.
        //
        // Patterns are de-duplicated so a bare-identifier source doesn't
        // trigger two identical queries.
        let mut patterns: Vec<String> = vec![format!("%{source}%")];
        let last_seg = source
            .rsplit(['.', ':'])
            .next()
            .unwrap_or(source);
        if !last_seg.is_empty() && last_seg != source {
            patterns.push(format!("%:{last_seg}"));
        }

        let mut seen_candidates: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        for pattern in &patterns {
            let mut stmt = conn.prepare(
                "SELECT DISTINCT from_symbol FROM dataflow_edges
                 WHERE engagement_id = ?1 AND from_symbol LIKE ?2",
            )?;
            let rows = stmt
                .query_map(
                    rusqlite::params![input.engagement_id.to_string(), pattern],
                    |r| r.get::<_, String>(0),
                )?
                .filter_map(|r| r.ok())
                .collect::<Vec<_>>();
            for sym in rows {
                seen_candidates.insert(sym);
            }
        }

        for seed in seen_candidates {
            let r = bfs_emit(conn, input.engagement_id, &seed, &expanded_sinks, &scanner)?;
            chains += r.emitted;
            unguarded += r.unguarded;
        }
    }

    audit::append_entry(
        input.journal_path,
        "taint_tracer",
        "execute_tool",
        "Audit::TaintTracer",
        "permit",
        None,
    )?;

    Ok(TraceSummary {
        chains_emitted: chains,
        unguarded_chains: unguarded,
    })
}

/// Result of a single seed's BFS: total chains emitted + how many of
/// them were unguarded (path never passed through a guard call).
struct BfsResult {
    emitted: usize,
    unguarded: usize,
}

/// BFS from a single seed symbol. Each queued state carries the full path of
/// `DataflowEdge`s walked so far so that, on a sink match, we can synthesize
/// the structured `TaintChain` (TaintHops with per-edge file/line/reason).
///
/// When emitting a chain we also check whether ANY symbol on the path
/// matches one of the `guards` patterns. If not, the chain is recorded
/// with `sanitizers_seen=["unguarded"]` so downstream stages can find it
/// quickly. Guard match is by substring against both `from_symbol` and
/// `to_symbol` of every edge — same matcher semantics as sources/sinks.
fn bfs_emit(
    conn: &Connection,
    engagement_id: Uuid,
    seed: &str,
    sinks: &[String],
    scanner: &GuardScanner,
) -> Result<BfsResult, TaintTracerError> {
    // A seed alone with no outgoing edges contributes nothing — handle that
    // before allocating the queue.
    let mut visited: HashSet<String> = HashSet::new();
    visited.insert(seed.to_string());

    // Each queue entry is the chain of edges traversed so far. The current
    // BFS frontier symbol is the last edge's `to_symbol`. We seed the queue
    // with one entry per outgoing edge from the seed.
    let mut queue: Vec<Vec<DataflowEdge>> = Vec::new();
    for e in db::list_dataflow_edges_from(conn, engagement_id, seed)? {
        if visited.insert(e.to_symbol.clone()) {
            queue.push(vec![e]);
        }
    }

    let mut emitted = 0usize;
    let mut unguarded = 0usize;
    let mut emit_counter = next_taint_id_seq(conn, engagement_id)?;

    while let Some(path) = queue.pop() {
        let last_to = path.last().expect("non-empty path").to_symbol.clone();

        if sinks.iter().any(|s| last_to.contains(s.as_str())) {
            let guarded = scanner.path_is_guarded(conn, engagement_id, &path)?;
            let mut tc = build_taint_chain(engagement_id, &path, &mut emit_counter);
            if !guarded {
                // Reuse the sanitizers_seen field to carry the unguarded
                // marker — saves a schema change. Downstream queries can
                // filter on sanitizers_seen containing "unguarded".
                tc.sanitizers_seen = vec!["unguarded".to_string()];
                unguarded += 1;
            }
            db::insert_taint_chain(conn, &tc)?;
            emitted += 1;
            continue;
        }
        if path.len() >= MAX_PATH_LEN {
            continue;
        }
        let next = db::list_dataflow_edges_from(conn, engagement_id, &last_to)?;
        for e in next {
            if visited.insert(e.to_symbol.clone()) {
                let mut p = path.clone();
                p.push(e);
                queue.push(p);
            }
        }
    }
    Ok(BfsResult { emitted, unguarded })
}

/// Returns true if any edge on the path involves a symbol that
/// substring-matches one of the guard patterns. An empty guard list
/// trivially returns false (so every chain is unguarded — legacy
/// behavior for callers that don't supply guards).
fn path_crosses_guard(path: &[DataflowEdge], guards: &[String]) -> bool {
    if guards.is_empty() {
        return false;
    }
    for edge in path {
        for g in guards {
            if edge.from_symbol.contains(g.as_str()) || edge.to_symbol.contains(g.as_str()) {
                return true;
            }
        }
    }
    false
}

/// Decides whether a discovered chain is guarded.
///
/// Guards are overwhelmingly *control-flow* gates (`if Authorize(user)`,
/// `@login_required`) that never transform the tainted value, so they do
/// not appear as nodes on the dataflow path the BFS walks — a pure
/// connectivity check ([`path_crosses_guard`]) misses essentially all of
/// them (measured: 11 of ~183k edges on one real engagement). This scanner
/// adds a second, textual test: does a guard pattern appear within the
/// enclosing scope of the chain's source or sink hop?
///
/// Scope bounds come from the cartographer's `symbol_index` when available
/// (precise, Python-only today); otherwise a fixed line window around the
/// hop is used. Read files are cached by path for the lifetime of the run.
struct GuardScanner<'a> {
    source_root: &'a Path,
    guards: &'a [String],
    /// path → file lines, or `None` when missing / non-UTF-8 / oversized.
    cache: RefCell<HashMap<String, Option<Vec<String>>>>,
}

impl<'a> GuardScanner<'a> {
    fn new(source_root: &'a Path, guards: &'a [String]) -> Self {
        Self {
            source_root,
            guards,
            cache: RefCell::new(HashMap::new()),
        }
    }

    /// A chain is guarded if a guard sits on the dataflow path itself, or
    /// within the enclosing scope of either its source (entry handler) or
    /// sink (the sensitive operation) hop.
    fn path_is_guarded(
        &self,
        conn: &Connection,
        engagement_id: Uuid,
        path: &[DataflowEdge],
    ) -> Result<bool, TaintTracerError> {
        if self.guards.is_empty() {
            return Ok(false);
        }
        if path_crosses_guard(path, self.guards) {
            return Ok(true);
        }
        let endpoints = [path.first(), path.last()];
        for edge in endpoints.into_iter().flatten() {
            if self.scope_has_guard(conn, engagement_id, &edge.file_path, edge.line as u32)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// True if any guard pattern appears in the source scope enclosing
    /// `(file, line)`. Scope is the indexed function span (plus a decorator
    /// look-back) when known, else a fixed window around the line.
    fn scope_has_guard(
        &self,
        conn: &Connection,
        engagement_id: Uuid,
        file: &str,
        line: u32,
    ) -> Result<bool, TaintTracerError> {
        let (lo, hi) = match db::enclosing_function(conn, engagement_id, file, line)? {
            Some((start, end)) => (start.saturating_sub(DECORATOR_LOOKBACK).max(1), end),
            None => (
                line.saturating_sub(WINDOW_BACK).max(1),
                line.saturating_add(WINDOW_FWD),
            ),
        };
        let cache = self.cache.borrow();
        let cached = cache.get(file);
        if let Some(entry) = cached {
            return Ok(self.lines_contain_guard(entry.as_deref(), lo, hi));
        }
        drop(cache);
        let lines = self.read_lines(file);
        let hit = self.lines_contain_guard(lines.as_deref(), lo, hi);
        self.cache.borrow_mut().insert(file.to_string(), lines);
        Ok(hit)
    }

    /// Substring-match every guard against each source line in the 1-based,
    /// inclusive `[lo, hi]` range.
    fn lines_contain_guard(&self, lines: Option<&[String]>, lo: u32, hi: u32) -> bool {
        let Some(lines) = lines else {
            return false;
        };
        let lo = lo.saturating_sub(1) as usize; // to 0-based start
        let hi = (hi as usize).min(lines.len()); // exclusive end, clamped
        if lo >= hi {
            return false;
        }
        lines[lo..hi]
            .iter()
            .any(|l| self.guards.iter().any(|g| l.contains(g.as_str())))
    }

    /// Read `file` (resolved under `source_root`) into lines, or `None` if it
    /// is missing, oversized, or not valid UTF-8.
    fn read_lines(&self, file: &str) -> Option<Vec<String>> {
        let path = self.source_root.join(file);
        match std::fs::metadata(&path) {
            Ok(m) if m.len() > MAX_SCAN_FILE_BYTES => return None,
            Ok(_) => {}
            Err(_) => return None,
        }
        std::fs::read_to_string(&path)
            .ok()
            .map(|s| s.lines().map(str::to_string).collect())
    }
}

/// Build a `TaintChain` row from the traversed edges. Each edge becomes one
/// `TaintHop`; the source location is the first edge's location and the sink
/// location is the last edge's location.
fn build_taint_chain(
    engagement_id: Uuid,
    path: &[DataflowEdge],
    counter: &mut u64,
) -> TaintChain {
    let first = path.first().expect("non-empty path");
    let last = path.last().expect("non-empty path");
    let chain: Vec<TaintHop> = path
        .iter()
        .map(|e| TaintHop {
            file_path: e.file_path.clone(),
            line: e.line as u32,
            propagation_reason: format!(
                "{}: {} -> {}",
                e.edge_kind, e.from_symbol, e.to_symbol
            ),
        })
        .collect();

    let id = format!("T-{}-{:04}", short_engagement(engagement_id), counter);
    *counter += 1;

    TaintChain {
        id,
        engagement_id,
        source_file: first.file_path.clone(),
        source_line: first.line as u32,
        sink_file: last.file_path.clone(),
        sink_line: last.line as u32,
        chain,
        sanitizers_seen: Vec::new(),
        created_at: Utc::now(),
    }
}

fn short_engagement(id: Uuid) -> String {
    id.simple().to_string()[..8].to_string()
}

/// Compute a starting sequence number based on how many `taint_chains` rows
/// already exist for this engagement, so re-running the tracer doesn't
/// collide on the `id` primary key.
fn next_taint_id_seq(conn: &Connection, engagement_id: Uuid) -> Result<u64, TaintTracerError> {
    let n: i64 = conn.query_row(
        "SELECT COUNT(*) FROM taint_chains WHERE engagement_id = ?1",
        rusqlite::params![engagement_id.to_string()],
        |r| r.get(0),
    )?;
    Ok(n as u64 + 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use symbi_codered_core::db::DataflowEdge;
    use symbi_evidence_schema::Engagement;
    use tempfile::TempDir;

    fn fresh() -> (TempDir, Connection, Uuid) {
        let dir = TempDir::new().unwrap();
        let conn = db::init_db(dir.path().join("t.db").to_str().unwrap()).unwrap();
        let e = Engagement::new("acme", "h", "2026-05-24", "2026-05-31");
        let id = e.id;
        db::insert_engagement(&conn, &e).unwrap();
        (dir, conn, id)
    }

    #[test]
    fn bfs_finds_two_hop_chain_from_source_to_sink() {
        let (dir, conn, eng) = fresh();
        let mk = |from: &str, to: &str, kind: &str, line: i64| DataflowEdge {
            engagement_id: eng,
            from_symbol: from.into(),
            to_symbol: to.into(),
            edge_kind: kind.into(),
            file_path: "u.py".into(),
            line,
        };
        db::insert_dataflow_edge(
            &conn,
            &mk("u.py:f:request.args", "u.py:f:name", "subscript", 10),
        )
        .unwrap();
        db::insert_dataflow_edge(
            &conn,
            &mk("u.py:f:name", "u.py:f:cursor.execute", "call_arg", 20),
        )
        .unwrap();

        let journal = dir.path().join("audit.jsonl");
        let input = TraceInput {
            engagement_id: eng,
            sources: &["request.args".to_string()],
            sinks: &["cursor.execute".to_string()],
            guards: &[],
            source_root: dir.path(),
            journal_path: journal.to_str().unwrap(),
        };
        let s = trace(&conn, &input).unwrap();
        assert_eq!(s.chains_emitted, 1, "expected 1 chain");
        // No guards passed → every chain is unguarded.
        assert_eq!(s.unguarded_chains, 1);

        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM taint_chains WHERE engagement_id = ?1",
                rusqlite::params![eng.to_string()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1);

        // Verify the persisted row carries structured hops with reasons.
        let (source_line, sink_line, chain_json): (i64, i64, String) = conn
            .query_row(
                "SELECT source_line, sink_line, chain_json FROM taint_chains
                 WHERE engagement_id = ?1",
                rusqlite::params![eng.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(source_line, 10);
        assert_eq!(sink_line, 20);
        let hops: Vec<TaintHop> = serde_json::from_str(&chain_json).unwrap();
        assert_eq!(hops.len(), 2);
        assert!(hops[0].propagation_reason.starts_with("subscript:"));
        assert!(hops[1].propagation_reason.starts_with("call_arg:"));
    }

    #[test]
    fn bfs_terminates_on_cycle() {
        let (dir, conn, eng) = fresh();
        let mk = |from: &str, to: &str| DataflowEdge {
            engagement_id: eng,
            from_symbol: from.into(),
            to_symbol: to.into(),
            edge_kind: "assign".into(),
            file_path: "u.py".into(),
            line: 1,
        };
        // a -> b -> a (cycle), with sink "z" absent from the graph so the BFS
        // must terminate without emitting any chains.
        db::insert_dataflow_edge(&conn, &mk("u.py:f:a", "u.py:f:b")).unwrap();
        db::insert_dataflow_edge(&conn, &mk("u.py:f:b", "u.py:f:a")).unwrap();

        let journal = dir.path().join("audit.jsonl");
        let input = TraceInput {
            engagement_id: eng,
            sources: &["a".to_string()],
            sinks: &["z".to_string()],
            guards: &[],
            source_root: dir.path(),
            journal_path: journal.to_str().unwrap(),
        };
        let s = trace(&conn, &input).unwrap();
        assert_eq!(s.chains_emitted, 0);
    }

    /// Source→sink chain that crosses a guard call should be classified
    /// as guarded (unguarded_chains stays 0); same chain with no matching
    /// guard pattern goes to unguarded_chains.
    #[test]
    fn chain_classified_guarded_when_path_crosses_guard_symbol() {
        let (dir, conn, eng) = fresh();
        let mk = |from: &str, to: &str| DataflowEdge {
            engagement_id: eng,
            from_symbol: from.into(),
            to_symbol: to.into(),
            edge_kind: "call_arg".into(),
            file_path: "h.py".into(),
            line: 1,
        };
        // source `req.body` → CheckAccess → SelectFoo (sink)
        db::insert_dataflow_edge(&conn, &mk("h.py:handle:req.body", "h.py:handle:CheckAccess")).unwrap();
        db::insert_dataflow_edge(&conn, &mk("h.py:handle:CheckAccess", "h.py:handle:SelectFoo")).unwrap();

        let journal = dir.path().join("audit.jsonl");
        let input = TraceInput {
            engagement_id: eng,
            sources: &["req.body".to_string()],
            sinks: &["SelectFoo".to_string()],
            guards: &["CheckAccess".to_string()],
            source_root: dir.path(),
            journal_path: journal.to_str().unwrap(),
        };
        let s = trace(&conn, &input).unwrap();
        assert_eq!(s.chains_emitted, 1);
        assert_eq!(s.unguarded_chains, 0, "path crossed CheckAccess → guarded");
    }

    /// Same shape, but no guard pattern matches anything on the path.
    #[test]
    fn chain_classified_unguarded_when_no_guard_on_path() {
        let (dir, conn, eng) = fresh();
        let mk = |from: &str, to: &str| DataflowEdge {
            engagement_id: eng,
            from_symbol: from.into(),
            to_symbol: to.into(),
            edge_kind: "call_arg".into(),
            file_path: "h.py".into(),
            line: 1,
        };
        db::insert_dataflow_edge(&conn, &mk("h.py:handle:req.body", "h.py:handle:SelectFoo")).unwrap();

        let journal = dir.path().join("audit.jsonl");
        let input = TraceInput {
            engagement_id: eng,
            sources: &["req.body".to_string()],
            sinks: &["SelectFoo".to_string()],
            guards: &["CheckAccess".to_string()],
            source_root: dir.path(),
            journal_path: journal.to_str().unwrap(),
        };
        let s = trace(&conn, &input).unwrap();
        assert_eq!(s.chains_emitted, 1);
        assert_eq!(s.unguarded_chains, 1, "no guard on path → unguarded");
    }

    fn edge(eng: Uuid, from: &str, to: &str, file: &str, line: i64) -> DataflowEdge {
        DataflowEdge {
            engagement_id: eng,
            from_symbol: from.into(),
            to_symbol: to.into(),
            edge_kind: "call_arg".into(),
            file_path: file.into(),
            line,
        }
    }

    /// Write a file of `n` numbered lines, overriding specific 1-based lines
    /// with provided content (used to place a guard call at a known line).
    fn write_lines(path: &std::path::Path, n: usize, overrides: &[(usize, &str)]) {
        let mut v: Vec<String> = (1..=n).map(|i| format!("// line {i}")).collect();
        for (ln, content) in overrides {
            v[*ln - 1] = (*content).to_string();
        }
        std::fs::write(path, v.join("\n")).unwrap();
    }

    /// Core sibling-inconsistency signal. Two functions in one file: one
    /// calls a guard, one does not. A sink in the guarded function is
    /// classified guarded; the identically-shaped sink in the unguarded
    /// sibling is NOT — even though the guard token exists elsewhere in the
    /// file. The guard is control-flow only (never a dataflow node), so this
    /// exercises the scope scan, not `path_crosses_guard`.
    #[test]
    fn scope_scan_discriminates_sibling_functions() {
        let (dir, conn, eng) = fresh();
        let root = dir.path();
        write_lines(&root.join("svc.py"), 40, &[(12, "    CheckAccess(req.user)")]);
        db::insert_symbol(&conn, eng, "svc.py", 10, 19, "function", "guarded", "python").unwrap();
        db::insert_symbol(&conn, eng, "svc.py", 25, 32, "function", "sibling", "python").unwrap();

        let guards = vec!["CheckAccess".to_string()];
        let scanner = GuardScanner::new(root, &guards);

        let guarded_sink = vec![edge(eng, "svc.py:guarded:p", "svc.py:guarded:read", "svc.py", 18)];
        let unguarded_sink = vec![edge(eng, "svc.py:sibling:p", "svc.py:sibling:read", "svc.py", 30)];

        assert!(
            scanner.path_is_guarded(&conn, eng, &guarded_sink).unwrap(),
            "sink inside guarded() must see CheckAccess in scope"
        );
        assert!(
            !scanner.path_is_guarded(&conn, eng, &unguarded_sink).unwrap(),
            "sink inside unguarded sibling() must not inherit the guard"
        );
    }

    /// No `symbol_index` entry (the case for every non-Python sink today):
    /// scope falls back to a fixed line window. A guard inside the back
    /// window is found; one beyond it is not.
    #[test]
    fn scope_scan_window_fallback_for_unindexed_languages() {
        let (dir, conn, eng) = fresh();
        let root = dir.path();
        write_lines(&root.join("svc.rs"), 80, &[(30, "    Authorize(&ctx)?;")]);
        let guards = vec!["Authorize".to_string()];
        let scanner = GuardScanner::new(root, &guards);

        // sink at 60 → window [20, 68] contains the guard at 30.
        let near = vec![edge(eng, "svc.rs:h:p", "svc.rs:h:read", "svc.rs", 60)];
        // sink at 120 → window [80, 128] (clamped to file) excludes line 30.
        let far = vec![edge(eng, "svc.rs:h:p", "svc.rs:h:read", "svc.rs", 120)];

        assert!(scanner.path_is_guarded(&conn, eng, &near).unwrap());
        assert!(!scanner.path_is_guarded(&conn, eng, &far).unwrap());
    }

    /// A missing/unreadable source file yields no scope guard (and must not
    /// error) — preserves legacy behavior when the repo root is wrong.
    #[test]
    fn scope_scan_missing_file_is_unguarded() {
        let (dir, conn, eng) = fresh();
        let guards = vec!["Authorize".to_string()];
        let scanner = GuardScanner::new(dir.path(), &guards);
        let p = vec![edge(eng, "gone.rs:h:p", "gone.rs:h:read", "gone.rs", 5)];
        assert!(!scanner.path_is_guarded(&conn, eng, &p).unwrap());
    }
}
