//! `codered advocate --engagement <uuid>` — run only the devils_advocate
//! stage against an existing engagement.
//!
//! Lets an operator re-adjudicate findings after tweaking advocate's
//! prompt, query ordering, or model — without re-running scanners or the
//! earlier LLM stages. The findings, taint chains, attack chains and
//! poc_status fields are read in-place; only `advocate_verdict` is written.

use anyhow::{Context, Result};
use clap::Args;
use std::path::PathBuf;
use std::sync::Arc;
use symbi_codered_core::db;
use symbi_codered_core::policy::PolicyEngine;
use symbi_codered_tools::devils_advocate;
use uuid::Uuid;

#[derive(Args, Debug)]
pub struct AdvocateArgs {
    /// Engagement id (must already exist with findings populated).
    #[arg(long)]
    engagement: Uuid,

    #[arg(long, default_value = "data/codered.db")]
    db: PathBuf,

    #[arg(long, default_value = ".symbiont/audit/audit.jsonl")]
    journal: PathBuf,

    /// Target repo root the advocate may read source from (path-escape
    /// guarded) to verify caller/sink context before confirming. Defaults to
    /// the current directory; point it at the scanned repo when re-adjudicating
    /// out-of-tree.
    #[arg(long, default_value = ".")]
    target: PathBuf,

    /// Provider for the devils_advocate's own model (anthropic|openai|openrouter).
    /// Set together with --advocate-model to run an INDEPENDENT, non-mirroring
    /// reviewer. If unset, the advocate uses the env-default model (and warns if
    /// that mirrors the generation model).
    #[arg(long)]
    advocate_provider: Option<String>,

    /// Model id for the devils_advocate's primary tier (with --advocate-provider).
    #[arg(long)]
    advocate_model: Option<String>,

    /// Comma-separated provider:model fallback tiers for the advocate, tried in
    /// order after the primary, e.g. "openrouter:google/gemini-2.5-pro,anthropic:claude-opus-4-7".
    #[arg(long)]
    advocate_fallback: Option<String>,

    /// Generation model preset used for this engagement — the mirror-detection
    /// reference: fable5 (default) | opus | sonnet | ollama-qwen. Also honors
    /// CODERED_MODEL_PROFILE / CODERED_GENERATION_* env.
    #[arg(long)]
    model_profile: Option<String>,

    /// Lowest severity to adjudicate. The advocate skips anything ranked
    /// below this floor entirely. Values: critical, high, medium, low.
    /// Omitted = adjudicate all severities (default 60-iter budget will
    /// only get through ~50 findings, mostly the lowest-id ones).
    #[arg(long, value_parser = ["critical", "high", "medium", "low"])]
    severity_min: Option<String>,

    /// ORGA iteration cap. Bump alongside `--max-tokens` when running a
    /// thorough pass over many findings. Default 60.
    #[arg(long)]
    max_iterations: Option<u32>,

    /// ORGA total-token cap. Bump alongside `--max-iterations` so the
    /// loop doesn't get terminated for token reasons. Default 400000.
    #[arg(long)]
    max_tokens: Option<u32>,

    /// Directory containing Cedar policy files. The advocate gates each
    /// `rebutted` verdict through `advocate.cedar`'s witness rule. Defaults to
    /// "policies" (relative to cwd), matching `codered hunt`.
    #[arg(long, default_value = "policies")]
    policies: PathBuf,
}

pub fn run(args: AdvocateArgs) -> Result<()> {
    let rt = tokio::runtime::Runtime::new().context("building tokio runtime for advocate")?;
    rt.block_on(run_async(args))
}

async fn run_async(args: AdvocateArgs) -> Result<()> {
    let conn = db::init_db(args.db.to_str().unwrap())
        .with_context(|| format!("opening {}", args.db.display()))?;
    let _ = db::get_engagement(&conn, args.engagement)?
        .with_context(|| format!("engagement {} not found", args.engagement))?;
    drop(conn);

    let generation = symbi_codered_core::orga::resolve_generation(args.model_profile.as_deref())?;
    let gen_ref_model = generation
        .chain
        .first()
        .map(|(_, m)| m.clone())
        .unwrap_or_default();

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
        &gen_ref_model,
    )?;

    let policy = Arc::new(
        PolicyEngine::from_dir(args.policies.to_str().unwrap())
            .with_context(|| format!("loading Cedar policies from {}", args.policies.display()))?,
    );

    let summary = devils_advocate::run(devils_advocate::AdvocateInput {
        engagement_id: args.engagement,
        db_path: args.db.clone(),
        journal_path: args.journal.clone(),
        target_repo: args.target.clone(),
        model_chain,
        severity_min: args.severity_min.clone(),
        max_iterations: args.max_iterations,
        max_total_tokens: args.max_tokens,
        policy,
    })
    .await
    .context("running devils_advocate")?;

    println!("engagement_id:       {}", args.engagement);
    println!("advocate_confirmed:  {}", summary.confirmed);
    println!("advocate_rebutted:   {}", summary.rebutted);
    println!("advocate_uncertain:  {}", summary.uncertain);
    println!("iterations:          {}", summary.iterations);
    println!("tokens_in:           {}", summary.tokens_in);
    println!("tokens_out:          {}", summary.tokens_out);

    // The advocate typically runs on an independent model (default
    // gemini-2.5-pro); the selected generation profile's list pricing is used
    // as a rough upper-bound signal, not a bill.
    let est_cost = (summary.tokens_in as f64) * generation.cost_in_per_mtok / 1_000_000.0
        + (summary.tokens_out as f64) * generation.cost_out_per_mtok / 1_000_000.0;
    println!("est_cost_usd:        ${est_cost:.4}");

    Ok(())
}
