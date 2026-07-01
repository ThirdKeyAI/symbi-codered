//! `codered hunt --engagement <uuid>` — runs static_hunter, then the Plan D
//! chain-aware stages (taint_tracer → pattern_scout → chain_builder), and
//! finally the Plan E confirmation-bias stages (poc_forge → devils_advocate).
//!
//! Stages run in sequence inside a private Tokio runtime so the public
//! `run` entrypoint stays sync (matching the other subcommands in
//! `main.rs`). pattern_scout / chain_builder / poc_forge / devils_advocate
//! are async because they drive ORGA loops; static_hunter and taint_tracer
//! are mechanical/sync.

use anyhow::{Context, Result};
use clap::Args;
use std::path::PathBuf;
use std::sync::Arc;
use symbi_codered_core::db;
use symbi_codered_core::policy::PolicyEngine;
use symbi_codered_tools::static_hunter::HuntInput;
use symbi_codered_tools::{
    chain_builder, devils_advocate, pattern_scout, poc_forge, reflector, static_hunter,
    taint_tracer,
};
use uuid::Uuid;

#[derive(Args, Debug)]
pub struct HuntArgs {
    /// Engagement id (created by `codered carto`, pinned by `codered specifier`)
    #[arg(long)]
    engagement: Uuid,

    /// Path INSIDE the python-scanner sidecar where the target repo is mounted.
    #[arg(long, default_value = "/repo")]
    target_in_container: String,

    /// Host-side path to the target repo root that the LLM stages
    /// (taint_tracer, pattern_scout, poc_forge, devils_advocate) resolve
    /// repo-relative file paths against for `read_context_range` and the
    /// file-existence gate. OPTIONAL: when omitted, it defaults to the target
    /// recorded in this engagement's signed threat model (the path passed to
    /// `codered specifier --target`), so the scan always reads the exact tree
    /// it cartographed and can never drift onto the auditor's own source.
    /// Pass it only to override that recorded target.
    #[arg(long)]
    target: Option<PathBuf>,

    /// Name of the python-scanner sidecar container.
    #[arg(long, default_value = "symbi-codered-scanner-python")]
    scanner_container: String,

    /// Name of the python-sandbox sidecar container used by poc_forge
    /// for `run_reproducer` calls. The sidecar is expected to expose a
    /// read-only `/repo` mount with no network and a default 30s timeout.
    #[arg(long, default_value = "symbi-codered-sandbox-python")]
    sandbox_container: String,

    /// Name of the rust-sandbox sidecar container (Plan F).
    #[arg(long, default_value = "symbi-codered-sandbox-rust")]
    rust_sandbox_container: String,

    /// Name of the typescript-sandbox sidecar container (Plan F).
    #[arg(long, default_value = "symbi-codered-sandbox-typescript")]
    typescript_sandbox_container: String,

    /// Name of the go-sandbox sidecar container (Plan F).
    #[arg(long, default_value = "symbi-codered-sandbox-go")]
    go_sandbox_container: String,

    /// Name of the php-sandbox sidecar container.
    #[arg(long, default_value = "symbi-codered-sandbox-php")]
    php_sandbox_container: String,

    /// Name of the java-sandbox sidecar container.
    #[arg(long, default_value = "symbi-codered-sandbox-java")]
    java_sandbox_container: String,

    #[arg(long, default_value = "data/codered.db")]
    db: PathBuf,

    #[arg(long, default_value = "evidence")]
    evidence_dir: PathBuf,

    #[arg(long, default_value = ".symbiont/audit/audit.jsonl")]
    journal: PathBuf,

    /// Directory containing Cedar policy files. Defaults to "policies"
    /// (relative to cwd) for production use from the codered repo root;
    /// tests that change cwd pass an absolute path.
    #[arg(long, default_value = "policies")]
    policies: PathBuf,

    /// Skip the preflight that refreshes jaschadub/compromised-packages-check
    /// into each scanner sidecar. Use when offline, or when the sidecars
    /// haven't yet been rebooted with the new image baseline.
    #[arg(long)]
    skip_compromised_refresh: bool,

    /// Provider for the devils_advocate's own model (anthropic|openai|openrouter),
    /// for an independent, non-mirroring review. See `codered advocate --help`.
    #[arg(long)]
    advocate_provider: Option<String>,

    /// Model id for the devils_advocate primary tier (with --advocate-provider).
    #[arg(long)]
    advocate_model: Option<String>,

    /// Comma-separated provider:model fallback tiers for the advocate.
    #[arg(long)]
    advocate_fallback: Option<String>,
}

/// Best-effort preflight: pull (or clone) the upstream
/// compromised-packages-check repo, then `docker cp` the latest
/// `check_compromised_packages.py` into each running scanner sidecar.
/// Logs warnings on failure; the hunt always proceeds.
fn refresh_compromised_packages(containers: &[&str]) {
    use std::process::Command;

    let cache_dir = match dirs_cache() {
        Some(p) => p,
        None => {
            tracing::warn!("cannot resolve cache dir; skipping compromised-packages refresh");
            return;
        }
    };
    let repo_dir = cache_dir.join("compromised-packages-check");
    let upstream = "https://github.com/jaschadub/compromised-packages-check.git";

    let _ = std::fs::create_dir_all(&cache_dir);

    if repo_dir.join(".git").exists() {
        let out = Command::new("git")
            .args(["-C", repo_dir.to_str().unwrap_or(""), "pull", "--ff-only"])
            .output();
        match out {
            Ok(o) if o.status.success() => {}
            Ok(o) => {
                tracing::warn!(
                    "git pull on {} failed: {}",
                    repo_dir.display(),
                    String::from_utf8_lossy(&o.stderr).trim()
                );
                return;
            }
            Err(e) => {
                tracing::warn!("git pull failed to spawn: {e}");
                return;
            }
        }
    } else {
        let out = Command::new("git")
            .args(["clone", "--depth=1", upstream, repo_dir.to_str().unwrap_or("")])
            .output();
        match out {
            Ok(o) if o.status.success() => {}
            Ok(o) => {
                tracing::warn!(
                    "git clone of {} failed: {}",
                    upstream,
                    String::from_utf8_lossy(&o.stderr).trim()
                );
                return;
            }
            Err(e) => {
                tracing::warn!("git clone failed to spawn: {e}");
                return;
            }
        }
    }

    let host_script = repo_dir.join("check_compromised_packages.py");
    if !host_script.exists() {
        tracing::warn!("expected {} after refresh; skipping docker cp", host_script.display());
        return;
    }

    for container in containers {
        let target = format!("{container}:/opt/compromised-packages-check/check_compromised_packages.py");
        let out = Command::new("docker")
            .args(["cp", host_script.to_str().unwrap_or(""), &target])
            .output();
        match out {
            Ok(o) if o.status.success() => {
                tracing::info!("refreshed compromised-packages-check in {container}");
            }
            Ok(o) => {
                tracing::warn!(
                    "docker cp into {container} failed (sidecar may not be running): {}",
                    String::from_utf8_lossy(&o.stderr).trim()
                );
            }
            Err(e) => {
                tracing::warn!("docker cp into {container} failed to spawn: {e}");
            }
        }
    }
}

fn dirs_cache() -> Option<PathBuf> {
    if let Ok(home) = std::env::var("XDG_CACHE_HOME") {
        return Some(PathBuf::from(home).join("symbi-codered"));
    }
    std::env::var("HOME").ok().map(|h| PathBuf::from(h).join(".cache/symbi-codered"))
}

pub fn run(args: HuntArgs) -> Result<()> {
    let rt = tokio::runtime::Runtime::new().context("building tokio runtime for hunt")?;
    rt.block_on(run_async(args))
}

async fn run_async(args: HuntArgs) -> Result<()> {
    if let Some(p) = args.db.parent() { std::fs::create_dir_all(p).ok(); }
    if let Some(p) = args.journal.parent() { std::fs::create_dir_all(p).ok(); }
    std::fs::create_dir_all(&args.evidence_dir).ok();

    let conn = db::init_db(args.db.to_str().unwrap())
        .with_context(|| format!("opening {}", args.db.display()))?;
    let _ = db::get_engagement(&conn, args.engagement)?
        .with_context(|| format!("engagement {} not found", args.engagement))?;

    let policy = Arc::new(
        PolicyEngine::from_dir(args.policies.to_str().unwrap())
            .with_context(|| format!("loading Cedar policies from {}", args.policies.display()))?,
    );

    // --- Preflight: refresh compromised-packages-check across all sidecars --
    // The jaschadub/compromised-packages-check repo updates 4× daily. The
    // image-baked copy is stale within ~6 hours; this preflight pulls a
    // host-side clone (~/.cache/symbi-codered/compromised-packages-check)
    // and docker-cp's the latest check_compromised_packages.py into each
    // scanner container. Sidecars retain network_mode: none at scan time.
    // Best-effort: a failure here logs a warning and falls back to the
    // baked-in copy; the hunt proceeds either way.
    if !args.skip_compromised_refresh {
        refresh_compromised_packages(&[
            "symbi-codered-scanner-python",
            "symbi-codered-scanner-rust",
            "symbi-codered-scanner-typescript",
            "symbi-codered-scanner-java",
            "symbi-codered-scanner-php",
        ]);
    }

    // --- Stage 1: static_hunter (mechanical, sync) -------------------------
    let input = HuntInput {
        engagement_id: args.engagement,
        target_in_container: args.target_in_container.clone(),
        scanner_container: args.scanner_container.clone(),
        evidence_dir: args.evidence_dir.to_string_lossy().into_owned(),
        journal_path: args.journal.to_string_lossy().into_owned(),
        policy: policy.clone(),
    };
    let summary = static_hunter::hunt(&conn, &input).context("running static_hunter")?;

    // --- Stage 2: taint_tracer (mechanical, sync) --------------------------
    // Pull sources/sinks from the threat model's canonical JSON. The
    // specifier writes them as top-level string arrays; column name is
    // `json` (Task 15).
    let canonical: String = conn
        .query_row(
            "SELECT json FROM threat_models WHERE engagement_id = ?1 \
             ORDER BY signed_at DESC LIMIT 1",
            rusqlite::params![args.engagement.to_string()],
            |r| r.get(0),
        )
        .context("loading threat_model canonical JSON")?;
    let v: serde_json::Value =
        serde_json::from_str(&canonical).context("parsing threat_model canonical JSON")?;
    let sources: Vec<String> = v
        .get("sources")
        .and_then(|s| s.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default();
    let sinks: Vec<String> = v
        .get("sinks")
        .and_then(|s| s.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default();
    let guards: Vec<String> = v
        .get("guards")
        .and_then(|s| s.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default();

    // Host-side tree the LLM stages read. Prefer explicit --target; otherwise
    // the target recorded in the signed threat model, so the scan reads the
    // exact tree it cartographed and never the cwd / the auditor's own source.
    let effective_target = resolve_target(
        args.target.clone(),
        v.get("target").and_then(|t| t.as_str()),
    );

    let taint_input = taint_tracer::TraceInput {
        engagement_id: args.engagement,
        sources: &sources,
        sinks: &sinks,
        guards: &guards,
        // Repo-relative chain file_paths resolve against the engagement's target
        // root, matching the root the scout/poc/advocate executors use (below).
        source_root: effective_target.as_path(),
        journal_path: args.journal.to_str().unwrap(),
    };
    let taint_summary =
        taint_tracer::trace(&conn, &taint_input).context("running taint_tracer")?;

    // taint_tracer holds the rusqlite Connection; release it before handing
    // control to pattern_scout / chain_builder, which open their own pooled
    // connections via the executor.
    drop(conn);

    // --- Stage 3: pattern_scout (ORGA loop, async) -------------------------
    // `--target` is the host-side path the executor walks for
    // `read_context_range` and the file-existence gate.
    let scout_input = pattern_scout::ScoutInput {
        engagement_id: args.engagement,
        db_path: args.db.clone(),
        journal_path: args.journal.clone(),
        target_repo: effective_target.clone(),
        policy: policy.clone(),
    };
    let scout_summary = pattern_scout::run(scout_input)
        .await
        .context("running pattern_scout")?;

    // --- Stage 4: chain_builder (ORGA loop, async) -------------------------
    let chain_input = chain_builder::ChainInput {
        engagement_id: args.engagement,
        db_path: args.db.clone(),
        journal_path: args.journal.clone(),
    };
    let chain_summary = chain_builder::run(chain_input)
        .await
        .context("running chain_builder")?;

    // --- Stage 5: poc_forge (ORGA loop, async) -----------------------------
    // Attempts minimal reproducers for the easily-reproducible CWE classes
    // against the python-sandbox sidecar. Same `.` host-side root as the
    // scout/chain stages — the executor's path-traversal guard re-anchors
    // any `read_context_range` calls relative to this root.
    let poc_summary = poc_forge::run(poc_forge::PocInput {
        engagement_id: args.engagement,
        db_path: args.db.clone(),
        journal_path: args.journal.clone(),
        target_repo: effective_target.clone(),
        sandbox_container: args.sandbox_container.clone(),
        rust_sandbox_container: args.rust_sandbox_container.clone(),
        typescript_sandbox_container: args.typescript_sandbox_container.clone(),
        go_sandbox_container: args.go_sandbox_container.clone(),
        php_sandbox_container: args.php_sandbox_container.clone(),
        java_sandbox_container: args.java_sandbox_container.clone(),
    })
    .await
    .context("running poc_forge")?;

    // --- Stage 6: devils_advocate (ORGA loop, async) -----------------------
    // Inverted-prompt rebuttal pass over the engagement's findings. Writes
    // `confirmed` / `rebutted` / `uncertain` verdicts via the executor;
    // store_finding is denied for this principal by Cedar policy.
    use crate::commands::advocate_model::{resolve_and_warn_advocate_chain, AdvModelInput};
    let model_chain = resolve_and_warn_advocate_chain(
        AdvModelInput {
            provider: args.advocate_provider.clone(),
            model: args.advocate_model.clone(),
            fallback: args.advocate_fallback.clone(),
        },
        AdvModelInput {
            provider: std::env::var("CODERED_ADVOCATE_PROVIDER").ok(),
            model: std::env::var("CODERED_ADVOCATE_MODEL").ok(),
            fallback: std::env::var("CODERED_ADVOCATE_FALLBACK").ok(),
        },
    )?;

    let advocate_summary = devils_advocate::run(devils_advocate::AdvocateInput {
        engagement_id: args.engagement,
        db_path: args.db.clone(),
        journal_path: args.journal.clone(),
        // The advocate reads source (under --target) to verify caller context.
        target_repo: effective_target.clone(),
        model_chain,
        severity_min: None,
        max_iterations: None,
        max_total_tokens: None,
        policy: policy.clone(),
    })
    .await
    .context("running devils_advocate")?;

    // --- Stage 7: reflector (ORGA loop, async; Plan G) ---------------------
    // End-of-engagement cross-phase distillation. Reflector is read-only on
    // findings + chains and may ONLY write `knowledge_triples`. Failure here
    // is NOT a hard error — the engagement summary is still useful without
    // distilled triples; we warn + emit zero counters per spec §7.
    let reflect_summary = reflector::run(reflector::ReflectInput {
        engagement_id: args.engagement,
        db_path: args.db.clone(),
        journal_path: args.journal.clone(),
    })
    .await
    .unwrap_or_else(|e| {
        tracing::warn!("reflector failed: {e}");
        reflector::ReflectSummary {
            triples_written: 0,
            tool_calls: 0,
            tokens_in: 0,
            tokens_out: 0,
            iterations: 0,
        }
    });

    println!("engagement_id:       {}", args.engagement);
    println!("scanner_runs:        {}", summary.scanner_runs);
    println!("scanner_errors:      {}", summary.scanner_errors);
    println!("findings_inserted:   {}", summary.findings_inserted);
    println!("findings_deduped:    {}", summary.deduped);
    println!("denied_by_cedar:     {}", summary.denied_by_cedar);
    println!("taint_chains:        {}", taint_summary.chains_emitted);
    println!("unguarded_chains:    {}", taint_summary.unguarded_chains);
    println!("scout_findings:      {}", scout_summary.findings_inserted);
    println!("scout_denied:        {}", scout_summary.denied_by_cedar);
    println!("attack_chains:       {}", chain_summary.chains_built);
    println!("poc_reproduced:      {}", poc_summary.reproduced);
    println!("poc_refuted:         {}", poc_summary.refuted);
    println!("poc_inconclusive:    {}", poc_summary.inconclusive);
    println!("advocate_confirmed:  {}", advocate_summary.confirmed);
    println!("advocate_rebutted:   {}", advocate_summary.rebutted);
    println!("advocate_uncertain:  {}", advocate_summary.uncertain);
    println!("knowledge_triples:   {}", reflect_summary.triples_written);

    // ---- LLM token accounting ----------------------------------------
    let total_in = scout_summary.tokens_in
        + chain_summary.tokens_in
        + poc_summary.tokens_in
        + advocate_summary.tokens_in
        + reflect_summary.tokens_in;
    let total_out = scout_summary.tokens_out
        + chain_summary.tokens_out
        + poc_summary.tokens_out
        + advocate_summary.tokens_out
        + reflect_summary.tokens_out;
    // Anthropic Sonnet 4.6 list price (USD per million tokens) as of 2026-05.
    // Operators can recompute downstream; this is a rough cost signal, not a bill.
    const SONNET_IN_PER_MTOK: f64 = 3.0;
    const SONNET_OUT_PER_MTOK: f64 = 15.0;
    let est_cost = (total_in as f64) * SONNET_IN_PER_MTOK / 1_000_000.0
        + (total_out as f64) * SONNET_OUT_PER_MTOK / 1_000_000.0;
    println!();
    println!("--- LLM token usage (Sonnet 4.6 list pricing) ---");
    println!(
        "pattern_scout:   in={:>8}  out={:>6}  iters={}",
        scout_summary.tokens_in, scout_summary.tokens_out, scout_summary.iterations
    );
    println!(
        "chain_builder:   in={:>8}  out={:>6}  iters={}",
        chain_summary.tokens_in, chain_summary.tokens_out, chain_summary.iterations
    );
    println!(
        "poc_forge:       in={:>8}  out={:>6}  iters={}",
        poc_summary.tokens_in, poc_summary.tokens_out, poc_summary.iterations
    );
    println!(
        "devils_advocate: in={:>8}  out={:>6}  iters={}",
        advocate_summary.tokens_in, advocate_summary.tokens_out, advocate_summary.iterations
    );
    println!(
        "reflector:       in={:>8}  out={:>6}  iters={}",
        reflect_summary.tokens_in, reflect_summary.tokens_out, reflect_summary.iterations
    );
    println!("TOTAL:           in={total_in:>8}  out={total_out:>6}");
    println!("est_cost_usd:    ${est_cost:.4}");
    Ok(())
}

/// Resolve the host-side target tree the LLM stages read. Precedence:
/// 1. an explicit `--target` (override);
/// 2. the `target` recorded in the engagement's signed threat model — so the
///    scan reads the exact tree it cartographed and can never drift onto the
///    auditor's own source when run from the wrong cwd;
/// 3. `.` as a last resort, with a loud warning (no recorded target — e.g. an
///    old engagement predating target persistence).
fn resolve_target(explicit: Option<PathBuf>, recorded: Option<&str>) -> PathBuf {
    if let Some(t) = explicit {
        return t;
    }
    if let Some(t) = recorded.filter(|s| !s.is_empty()) {
        return PathBuf::from(t);
    }
    tracing::warn!(
        "no --target given and no target recorded in the threat model; \
         defaulting to '.' — findings may reference the wrong tree. Pass \
         --target <repo>, or re-run `codered specifier --target <repo>`."
    );
    PathBuf::from(".")
}

#[cfg(test)]
mod tests {
    use super::resolve_target;
    use std::path::PathBuf;

    #[test]
    fn explicit_target_wins_over_recorded() {
        assert_eq!(resolve_target(Some(PathBuf::from("/explicit")), Some("/recorded")), PathBuf::from("/explicit"));
    }

    #[test]
    fn recorded_target_used_when_no_explicit() {
        // This is the hardening: a normal carto -> specifier -> hunt sequence
        // reads the cartographed tree even with no --target, so it never falls
        // back to cwd / the auditor's own source.
        assert_eq!(resolve_target(None, Some("/tmp/target-repo")), PathBuf::from("/tmp/target-repo"));
    }

    #[test]
    fn empty_recorded_target_is_ignored() {
        assert_eq!(resolve_target(None, Some("")), PathBuf::from("."));
    }

    #[test]
    fn falls_back_to_cwd_when_nothing_recorded() {
        assert_eq!(resolve_target(None, None), PathBuf::from("."));
    }
}
