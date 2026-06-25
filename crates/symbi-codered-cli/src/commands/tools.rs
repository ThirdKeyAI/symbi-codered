use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use std::path::PathBuf;
use symbi_codered_core::toolclad;
use symbi_codered_tools::{
    chunker, dependency_graph, read_context, repo_overview,
    route_map_python, symbols,
};

#[derive(Args, Debug)]
pub struct ToolsArgs {
    #[command(subcommand)]
    cmd: ToolsCmd,
}

#[derive(Subcommand, Debug)]
enum ToolsCmd {
    /// List all discovered ToolClad manifests under tools/
    List {
        #[arg(long, default_value = "tools")]
        dir: PathBuf,
    },
    /// Parse and validate all manifests; exit non-zero on first failure
    Validate {
        #[arg(long, default_value = "tools")]
        dir: PathBuf,
    },
    /// Run the repo_overview tool directly
    RepoOverview {
        #[arg(long)]
        dir: PathBuf,
    },
    /// Run the dependency_graph tool directly (Python)
    DependencyGraph {
        #[arg(long)]
        dir: PathBuf,
    },
    /// Extract HTTP routes from Python sources
    RouteMap {
        #[arg(long)]
        dir: PathBuf,
    },
    /// Extract all symbols from every Python file under <dir>
    ExtractSymbols {
        #[arg(long)]
        dir: PathBuf,
    },
    /// Print imports + enclosing symbol for a (file, line) pair
    ReadContext {
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        line: u32,
    },
    /// Produce text chunks for embedding
    Chunk {
        #[arg(long)]
        dir: PathBuf,
    },
}

pub fn run(args: ToolsArgs) -> Result<()> {
    match args.cmd {
        ToolsCmd::List { dir } => {
            let manifests = toolclad::parse_dir(&dir)
                .with_context(|| format!("loading {}", dir.display()))?;
            for (path, m) in manifests {
                println!("{:<28}  ({})  risk={}  cedar={}",
                    m.tool.name, path, m.tool.risk_tier, m.tool.cedar.resource);
            }
            Ok(())
        }
        ToolsCmd::Validate { dir } => {
            let manifests = toolclad::parse_dir(&dir)
                .with_context(|| format!("validating {}", dir.display()))?;
            println!("validated {} manifest(s) in {}", manifests.len(), dir.display());
            Ok(())
        }
        ToolsCmd::RepoOverview { dir } => {
            let ov = repo_overview::analyze(&dir)?;
            println!("{}", serde_json::to_string_pretty(&ov)?);
            Ok(())
        }
        ToolsCmd::DependencyGraph { dir } => {
            let g = dependency_graph::analyze_python(&dir)?;
            println!("{}", serde_json::to_string_pretty(&g)?);
            Ok(())
        }
        ToolsCmd::RouteMap { dir } => {
            let routes = route_map_python::extract_routes(&dir)?;
            println!("{}", serde_json::to_string_pretty(&routes)?);
            Ok(())
        }
        ToolsCmd::ExtractSymbols { dir } => {
            let mut out = Vec::new();
            for entry in walkdir::WalkDir::new(&dir).into_iter().filter_map(|e| e.ok()) {
                if entry.file_type().is_file() {
                    let syms = symbols::extract_symbols(entry.path())?;
                    for s in syms {
                        out.push(serde_json::json!({
                            "file": entry.path().strip_prefix(&dir).unwrap_or(entry.path()).to_string_lossy(),
                            "symbol": s,
                        }));
                    }
                }
            }
            println!("{}", serde_json::to_string_pretty(&out)?);
            Ok(())
        }
        ToolsCmd::ReadContext { file, line } => {
            let ctx = read_context::read_context(&file, line)?;
            println!("{}", serde_json::to_string_pretty(&ctx)?);
            Ok(())
        }
        ToolsCmd::Chunk { dir } => {
            let chunks = chunker::chunk_repo(&dir)?;
            println!("{} chunks", chunks.len());
            for c in chunks.iter().take(5) {
                println!("  {} ({}:{}-{})", c.symbol_name.clone().unwrap_or_default(),
                    c.file_path, c.line_start, c.line_end);
            }
            Ok(())
        }
    }
}
