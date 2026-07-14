//! `codered carto <path>` — runs the cartographer pure-fact phase end-to-end.

use anyhow::{Context, Result};
use clap::Args;
use std::path::PathBuf;
use symbi_codered_core::{audit, db};
use symbi_codered_core::embeddings::LocalEmbedder;
use symbi_codered_tools::{
    dataflow, dependency_graph, grep_semantic, recall_journal,
    repo_git_meta, repo_overview, route_map_python, symbols,
    tree_sitter_loader::{parse, SupportedLanguage},
};
use symbi_evidence_schema::Engagement;
use walkdir::WalkDir;

#[derive(Args, Debug)]
pub struct CartoArgs {
    /// Path to the target repository
    target: PathBuf,

    #[arg(long, default_value = "internal")]
    client: String,

    #[arg(long, default_value = "data/codered.db")]
    db: PathBuf,

    #[arg(long, default_value = "data/lance")]
    lance: PathBuf,

    #[arg(long, default_value = ".symbiont/audit/audit.jsonl")]
    journal: PathBuf,
}

pub fn run(args: CartoArgs) -> Result<()> {
    if !args.target.is_dir() {
        anyhow::bail!("target must be a directory: {}", args.target.display());
    }
    if let Some(p) = args.db.parent() { std::fs::create_dir_all(p).ok(); }
    if let Some(p) = args.journal.parent() { std::fs::create_dir_all(p).ok(); }
    std::fs::create_dir_all(&args.lance).ok();

    let conn = db::init_db(args.db.to_str().unwrap())
        .with_context(|| format!("opening {}", args.db.display()))?;

    let scope_hash = symbi_evidence_schema::evidence::hex_sha256(
        args.target.to_string_lossy().as_bytes(),
    );
    let today = chrono::Utc::now().date_naive().to_string();
    let e = Engagement::new(&args.client, scope_hash, &today, &today);
    let engagement_id = e.id;
    db::insert_engagement(&conn, &e)?;
    audit::append_entry(&args.journal, "cartographer", "create_engagement",
        format!("Engagement::{engagement_id}"), "permit", None)?;

    // 0) git provenance — capture origin remote + HEAD commit so the viewer can
    //    deep-link finding locations to source. Best-effort: non-git targets
    //    leave these unset and no rows are written.
    repo_git_meta::capture_and_store(&conn, engagement_id, &args.target)?;

    // 1) repo_overview
    let ov = repo_overview::analyze(&args.target)?;
    for l in &ov.languages {
        db::insert_repo_fact(&conn, engagement_id, "language",
            &serde_json::json!({"name": l}).to_string())?;
    }
    for f in &ov.frameworks {
        db::insert_repo_fact(&conn, engagement_id, "framework",
            &serde_json::json!({"name": f}).to_string())?;
    }
    for pm in &ov.package_managers {
        db::insert_repo_fact(&conn, engagement_id, "package_manager",
            &serde_json::json!({"name": pm}).to_string())?;
    }
    for ep in &ov.entrypoints {
        db::insert_repo_fact(&conn, engagement_id, "entrypoint",
            &serde_json::json!({"path": ep}).to_string())?;
    }
    audit::append_entry(&args.journal, "cartographer", "repo_overview",
        "Audit::RepoIntel", "permit", None)?;

    // 2) dependency_graph (Python only in Plan B)
    if ov.languages.contains("python") {
        let g = dependency_graph::analyze_python(&args.target)?;
        for d in &g.dependencies {
            db::insert_repo_fact(&conn, engagement_id, "dependency",
                &serde_json::to_string(d)?)?;
        }
        audit::append_entry(&args.journal, "cartographer", "dependency_graph",
            "Audit::RepoIntel", "permit", None)?;
    }

    // 3) symbol_index + dataflow_edges (Python)
    let mut sym_count = 0_usize;
    let mut n_edges = 0_usize;
    for entry in WalkDir::new(&args.target)
        .into_iter()
        .filter_entry(|e| !symbi_codered_tools::walk::is_ignored_dir(e.path()))
        .filter_map(|r| r.ok())
    {
        if !entry.file_type().is_file() { continue; }
        let path = entry.path();
        let rel = path.strip_prefix(&args.target).unwrap_or(path);
        let rel_str = rel.to_string_lossy();
        let syms = symbols::extract_symbols(path)?;
        for s in syms {
            db::insert_symbol(
                &conn, engagement_id,
                &rel_str,
                s.line_start, s.line_end,
                &s.kind, &s.name, &s.language,
            )?;
            sym_count += 1;
        }

        // Dataflow extraction — dispatch on detected language.
        if let Some(lang) = SupportedLanguage::from_path(path) {
            if let Ok(src) = std::fs::read(path) {
                let edges = match lang {
                    SupportedLanguage::Python => parse(lang, &src).ok().map(|tree| {
                        dataflow::extract_python_edges(&tree, &src, engagement_id, &rel_str)
                    }),
                    SupportedLanguage::Rust => parse(lang, &src).ok().map(|tree| {
                        dataflow::extract_rust_edges(&tree, &src, engagement_id, &rel_str)
                    }),
                    SupportedLanguage::Go => parse(lang, &src).ok().map(|tree| {
                        dataflow::extract_go_edges(&tree, &src, engagement_id, &rel_str)
                    }),
                    SupportedLanguage::Java => parse(lang, &src).ok().map(|tree| {
                        dataflow::extract_java_edges(&tree, &src, engagement_id, &rel_str)
                    }),
                    SupportedLanguage::Php => parse(lang, &src).ok().map(|tree| {
                        dataflow::extract_php_edges(&tree, &src, engagement_id, &rel_str)
                    }),
                    SupportedLanguage::TypeScript
                    | SupportedLanguage::Tsx
                    | SupportedLanguage::JavaScript => parse(lang, &src).ok().map(|tree| {
                        dataflow::extract_typescript_edges(
                            &tree,
                            &src,
                            engagement_id,
                            &rel_str,
                        )
                    }),
                    // No dataflow extractor for the non-code languages.
                    SupportedLanguage::Toml
                    | SupportedLanguage::Yaml
                    | SupportedLanguage::Json
                    | SupportedLanguage::Dockerfile => None,
                };
                if let Some(edges) = edges {
                    for e in &edges {
                        db::insert_dataflow_edge(&conn, e)?;
                    }
                    n_edges += edges.len();
                }
            }
        }
    }
    audit::append_entry(&args.journal, "cartographer", "symbol_index",
        "Audit::RepoIntel", "permit", None)?;

    // 4) routes
    let routes = route_map_python::extract_routes(&args.target)?;
    for r in &routes {
        db::insert_route(
            &conn, engagement_id,
            &r.method, &r.path, &r.handler_symbol,
            None, None, None,
        )?;
    }
    audit::append_entry(&args.journal, "cartographer", "route_map",
        "Audit::RepoIntel", "permit", None)?;

    // 5) grep_semantic index + recall_journal index (downloads bge model on first run)
    let lance_uri = args.lance.to_string_lossy().into_owned();
    let runtime = tokio::runtime::Runtime::new()?;
    let chunk_count = runtime.block_on(async {
        let embedder = LocalEmbedder::new()
            .with_context(|| "initializing LocalEmbedder (bge-small-en-v1.5)")?;
        let n = grep_semantic::index_repo(
            &lance_uri, engagement_id, &args.target, &embedder,
        ).await?;
        recall_journal::index_journal(
            &lance_uri, engagement_id, &args.journal, &embedder,
        ).await?;
        anyhow::Ok(n)
    })?;
    audit::append_entry(&args.journal, "cartographer", "grep_semantic_index",
        "Audit::RepoIntel", "permit", None)?;

    println!("engagement_id:    {engagement_id}");
    println!("languages:        {:?}", ov.languages);
    println!("frameworks:       {:?}", ov.frameworks);
    println!("package_managers: {:?}", ov.package_managers);
    println!("entrypoints:      {:?}", ov.entrypoints);
    println!("symbols:          {sym_count}");
    println!("dataflow_edges:   {n_edges}");
    println!("routes:           {}", routes.len());
    println!("chunks_indexed:   {chunk_count}");
    println!("lance_uri:        {lance_uri}");

    Ok(())
}
