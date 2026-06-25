//! `codered specifier --engagement <uuid> --target <path>` — Plan C specifier.

use anyhow::{Context, Result};
use clap::Args;
use std::path::PathBuf;
use symbi_codered_core::{audit, db};
use symbi_codered_tools::specifier::{self, ScopeOverrides};
use uuid::Uuid;

#[derive(Args, Debug)]
pub struct SpecifierArgs {
    /// Engagement id (must already exist; e.g. produced by `codered carto`)
    #[arg(long)]
    engagement: Uuid,

    /// Target repository root
    #[arg(long)]
    target: PathBuf,

    /// Optional TOML file with scope overrides
    #[arg(long)]
    scope: Option<PathBuf>,

    #[arg(long, default_value = "data/codered.db")]
    db: PathBuf,

    #[arg(long, default_value = ".symbiont/audit/audit.jsonl")]
    journal: PathBuf,

    /// Directory to write the engagement's Ed25519 keypair to.
    /// Defaults to `.symbiont/keys` resolved against the current working
    /// directory. Pass an absolute path when the pipeline runs from a
    /// different cwd than `codered report`.
    #[arg(long)]
    keys_dir: Option<PathBuf>,
}

pub fn run(args: SpecifierArgs) -> Result<()> {
    let conn = db::init_db(args.db.to_str().unwrap())
        .with_context(|| format!("opening {}", args.db.display()))?;
    let _ = db::get_engagement(&conn, args.engagement)?
        .with_context(|| format!("engagement {} not found", args.engagement))?;

    let overrides = match &args.scope {
        Some(p) => ScopeOverrides::load_from_toml(p)
            .with_context(|| format!("loading scope file {}", p.display()))?,
        None => ScopeOverrides::default(),
    };

    let tm = specifier::pin_threat_model(
        &conn,
        args.engagement,
        &args.target,
        overrides,
        args.keys_dir.as_deref(),
    )
    .context("pinning threat model")?;

    audit::append_entry(&args.journal, "specifier", "pin_threat_model",
        format!("ThreatModel::{}", tm.specifier_hash), "permit", None)?;

    println!("specifier_hash:    {}", tm.specifier_hash);
    println!("signed_at:         {}", tm.signed_at);
    println!("canonical_json:    {}", tm.canonical_json);
    println!("signature_hex_len: {}", tm.signature.len());
    Ok(())
}
