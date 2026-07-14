//! Native MCP tools used by the cartographer phase of symbi-codered.
//!
//! All tools in this crate are deterministic and read-only on the target
//! repo. They produce structured artifacts that downstream agents
//! (specifier, static_hunter, taint_tracer, pattern_scout, etc.) consume
//! through the SQLite + LanceDB persistence layer.
//!
//! No tool in this crate exercises LLM judgment — that's by design.

pub mod tree_sitter_loader;
pub mod walk;
pub mod repo_overview;
pub mod repo_git_meta;
pub mod dependency_graph;
pub mod symbols;
pub mod read_context;
pub mod route_map_python;
pub mod chunker;
pub mod grep_semantic;
pub mod recall_journal;
pub mod specifier;
pub mod scanner_client;
pub mod scanner_parsers;
pub mod static_hunter;
pub mod dataflow;
pub mod taint_tracer;
pub mod pattern_scout_tools;
pub mod pattern_scout;
pub mod hypothesis_repl;
pub mod chain_builder;
pub mod devils_advocate;
pub mod sandbox_client;
pub mod poc_forge;
pub mod reflector;
pub mod reporter;
pub mod tool_defs;

#[cfg(test)]
mod smoke {
    #[test]
    fn crate_compiles() {
        // Plan B Task 3 sentinel — proves the crate skeleton + dependency
        // tree resolves before any module bodies exist.
    }
}
