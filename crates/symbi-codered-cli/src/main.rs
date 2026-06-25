use anyhow::Result;
use clap::{Parser, Subcommand};

mod commands;

#[derive(Parser, Debug)]
#[command(name = "codered", about = "symbi-codered governed code auditor")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Cmd>,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// ToolClad manifest utilities
    Tools(commands::tools::ToolsArgs),
    /// Run an audit (Plan A stub)
    Audit(commands::audit::AuditArgs),
    /// Run the cartographer pure-fact phase
    Carto(commands::carto::CartoArgs),
    /// Pin and sign the engagement's threat model
    Specifier(commands::specifier::SpecifierArgs),
    /// Run static_hunter (scanners + citation-gated findings)
    Hunt(commands::hunt::HuntArgs),
    /// Re-run only the devils_advocate stage against an existing engagement
    Advocate(commands::advocate::AdvocateArgs),
    /// Generate engagement report (SARIF + Markdown + signed engagement-seed)
    Report(commands::report::ReportArgs),
    /// Push a signed engagement seed to a GRC platform (gapps/comp) as mapped risks
    ExportGrc(commands::grc::ExportGrcArgs),
    /// Serve a local, read-only web viewer for an engagement DB (enterprise)
    #[cfg(feature = "portal")]
    Serve(commands::serve::ServeArgs),
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    match cli.command {
        None => commands::version::print(),
        Some(Cmd::Tools(args)) => commands::tools::run(args),
        Some(Cmd::Audit(args)) => commands::audit::run(args),
        Some(Cmd::Carto(args)) => commands::carto::run(args),
        Some(Cmd::Specifier(args)) => commands::specifier::run(args),
        Some(Cmd::Hunt(args)) => commands::hunt::run(args),
        Some(Cmd::Advocate(args)) => commands::advocate::run(args),
        Some(Cmd::Report(args)) => commands::report::run(args),
        Some(Cmd::ExportGrc(args)) => commands::grc::run(args),
        #[cfg(feature = "portal")]
        Some(Cmd::Serve(args)) => commands::serve::run(args),
    }
}
