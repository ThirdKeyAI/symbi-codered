//! Re-run the mechanical taint stage on an existing engagement DB and print the
//! guarded/unguarded split + per-language chain counts. Costs $0 and calls no
//! LLM — the cheap codered revalidation loop (carto → specifier → this), handy
//! for tuning source/sink guards or checking a new language's dataflow coverage
//! without paying for a full `hunt`.
//!
//! Usage:
//!   cargo run -p symbi-codered-tools --example guard_check --release -- \
//!     --db <codered.db> --engagement <uuid> \
//!     --journal <audit.jsonl> --target <repo-root>

use std::collections::BTreeMap;
use std::path::Path;

use rusqlite::Connection;
use symbi_codered_tools::taint_tracer::{self, TraceInput};
use uuid::Uuid;

fn arg(flag: &str) -> Option<String> {
    let a: Vec<String> = std::env::args().collect();
    a.iter().position(|x| x == flag).and_then(|i| a.get(i + 1).cloned())
}

fn main() -> anyhow::Result<()> {
    let db = arg("--db").expect("--db <path>");
    let eng = arg("--engagement").expect("--engagement <uuid>");
    let journal = arg("--journal").unwrap_or_else(|| "/tmp/guard_check_audit.jsonl".into());
    let target = arg("--target").unwrap_or_else(|| ".".into());
    let engagement_id = Uuid::parse_str(&eng)?;

    let conn = Connection::open(&db)?;

    // Load sources/sinks/guards exactly as `codered hunt` does.
    let canonical: String = conn.query_row(
        "SELECT json FROM threat_models WHERE engagement_id = ?1 \
         ORDER BY signed_at DESC LIMIT 1",
        rusqlite::params![engagement_id.to_string()],
        |r| r.get(0),
    )?;
    let v: serde_json::Value = serde_json::from_str(&canonical)?;
    let pull = |k: &str| -> Vec<String> {
        v.get(k)
            .and_then(|s| s.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
            .unwrap_or_default()
    };
    let sources = pull("sources");
    let sinks = pull("sinks");
    let guards = pull("guards");
    println!(
        "threat model: {} sources, {} sinks, {} guards",
        sources.len(),
        sinks.len(),
        guards.len()
    );

    let input = TraceInput {
        engagement_id,
        sources: &sources,
        sinks: &sinks,
        guards: &guards,
        source_root: Path::new(&target),
        journal_path: &journal,
    };
    let summary = taint_tracer::trace(&conn, &input)?;
    let guarded = summary.chains_emitted.saturating_sub(summary.unguarded_chains);
    println!(
        "chains_emitted={} guarded={} unguarded={}",
        summary.chains_emitted, guarded, summary.unguarded_chains
    );

    // Per-language breakdown by source_file extension.
    let mut by_lang: BTreeMap<String, usize> = BTreeMap::new();
    let mut stmt =
        conn.prepare("SELECT source_file FROM taint_chains WHERE engagement_id = ?1")?;
    let rows = stmt
        .query_map(rusqlite::params![engagement_id.to_string()], |r| {
            r.get::<_, String>(0)
        })?;
    for f in rows.flatten() {
        let ext = Path::new(&f).extension().and_then(|e| e.to_str()).unwrap_or("");
        let lang = match ext {
            "go" => "go",
            "py" => "python",
            "rs" => "rust",
            "ts" | "tsx" => "typescript",
            "js" | "jsx" | "mjs" | "cjs" => "javascript",
            "php" | "phtml" => "php",
            "java" => "java",
            other => other,
        };
        *by_lang.entry(lang.to_string()).or_default() += 1;
    }
    println!("per-language chains (by source_file ext):");
    for (lang, n) in &by_lang {
        println!("  {lang}: {n}");
    }
    Ok(())
}
