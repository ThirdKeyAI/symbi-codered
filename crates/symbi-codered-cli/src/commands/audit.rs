use anyhow::{Context, Result};
use clap::Args;
use std::path::PathBuf;
use symbi_codered_core::{audit, db};
use symbi_evidence_schema::Engagement;

#[derive(Args, Debug)]
pub struct AuditArgs {
    /// Path to the target repository
    target: PathBuf,

    /// Client name attributed to this engagement
    #[arg(long, default_value = "internal")]
    client: String,

    /// SQLite path; created if missing
    #[arg(long, default_value = "data/codered.db")]
    db: PathBuf,

    /// Audit journal path
    #[arg(long, default_value = ".symbiont/audit/audit.jsonl")]
    journal: PathBuf,

    /// Skip auto-handoff (no-op for Plan A; honored in Plan D)
    #[arg(long)]
    no_handoff: bool,
}

pub fn run(args: AuditArgs) -> Result<()> {
    if !args.target.is_dir() {
        anyhow::bail!("target must be an existing directory: {}", args.target.display());
    }

    if let Some(parent) = args.db.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    if let Some(parent) = args.journal.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }

    let conn = db::init_db(args.db.to_str().unwrap())
        .with_context(|| format!("opening {}", args.db.display()))?;

    let scope_hash = symbi_evidence_schema::evidence::hex_sha256(
        args.target.to_string_lossy().as_bytes(),
    );
    let today = chrono::Utc::now().date_naive().to_string();
    let e = Engagement::new(&args.client, scope_hash, &today, &today);
    let engagement_id = e.id;
    db::insert_engagement(&conn, &e)?;

    audit::append_entry(
        &args.journal,
        "audit-controller",
        "create_engagement",
        format!("Engagement::{engagement_id}"),
        "permit",
        None,
    )?;

    println!("engagement_id: {engagement_id}");
    println!("target:        {}", args.target.display());
    println!("db:            {}", args.db.display());
    println!("journal:       {}", args.journal.display());
    if args.no_handoff {
        println!("handoff:       skipped (--no-handoff)");
    } else {
        println!("handoff:       deferred to Plan D");
    }
    Ok(())
}
