//! `codered report --engagement <id>` — Plan G reporter subcommand.
//!
//! Writes three deliverables under `<output_dir>/<engagement_id>/`:
//!   - `findings.sarif`        — SARIF 2.1.0 JSON
//!   - `report.md`             — Markdown engagement report
//!   - `engagement-seed.json`  — Cedar-filtered handoff envelope, Ed25519-signed
//!
//! Loads policies + the engagement's signing key, then calls
//! `symbi_codered_tools::reporter::generate_all` (the deterministic Rust
//! pipeline — no LLM is invoked).

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Args;
use uuid::Uuid;

use symbi_codered_core::policy::PolicyEngine;
use symbi_codered_tools::reporter::{generate_all, ReportInput};

#[derive(Args, Debug)]
pub struct ReportArgs {
    /// Engagement id (must have been pinned by `codered specifier` first).
    #[arg(long)]
    pub engagement: Uuid,

    #[arg(long, default_value = "data/codered.db")]
    pub db: PathBuf,

    #[arg(long, default_value = ".symbiont/audit/audit.jsonl")]
    pub journal: PathBuf,

    /// Directory containing Cedar policy files. Defaults to "policies"
    /// (relative to cwd) for production use from the codered repo root.
    #[arg(long, default_value = "policies")]
    pub policies: PathBuf,

    /// Root output directory. The reporter writes its three files to
    /// `<output_dir>/<engagement>/`.
    #[arg(long, default_value = "reports")]
    pub output_dir: PathBuf,

    /// Directory holding the engagement's Ed25519 keypair (written by
    /// `codered specifier`). Defaults to `.symbiont/keys` resolved against
    /// the current working directory. Pass an absolute path when running
    /// `codered report` from a different cwd than `codered specifier`.
    #[arg(long)]
    pub keys_dir: Option<PathBuf>,
}

pub fn run(args: ReportArgs) -> Result<()> {
    let policy = Arc::new(
        PolicyEngine::from_dir(
            args.policies
                .to_str()
                .context("policies path is not valid UTF-8")?,
        )
        .with_context(|| format!("loading Cedar policies from {}", args.policies.display()))?,
    );

    let input = ReportInput {
        engagement_id: args.engagement,
        db_path: args.db,
        policy,
        output_dir: args.output_dir,
        journal_path: args.journal,
        signing_keys_dir: args.keys_dir,
    };

    let summary = generate_all(input).context("generating engagement report")?;

    println!("engagement_id:        {}", args.engagement);
    println!("sarif:                {}", summary.sarif_path.display());
    println!("markdown:             {}", summary.markdown_path.display());
    println!("engagement_seed:      {}", summary.seed_path.display());
    println!("findings_in_seed:     {}", summary.findings_in_seed);
    println!("findings_filtered:    {}", summary.findings_filtered);
    Ok(())
}
