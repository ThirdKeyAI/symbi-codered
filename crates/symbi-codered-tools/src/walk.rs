//! Shared directory-walk filtering.
//!
//! The cartographer, chunker, and repo_overview all walk the target tree.
//! Without pruning they descend into `node_modules`, Rust `target/`, and the
//! `.terraform` provider cache — which on a real repo is gigabytes of vendored
//! and build output. Indexing that is slow, pollutes symbols/chunks with
//! third-party code, and inflates downstream LLM token cost. This module is the
//! single source of truth for which directories every walk skips.

use std::path::Path;

/// Directory basenames pruned from every codered repo walk.
// ponytail: a name-based skip list, not a `.gitignore` parser. Covers the
// common vendored/build dirs across ecosystems; if per-repo ignore rules
// (custom `.gitignore` entries) start to matter, swap this for the `ignore`
// crate's `WalkBuilder`, which reads `.gitignore` natively.
pub const IGNORED_DIRS: &[&str] = &[
    // VCS
    ".git",
    // Rust
    "target",
    // Node / web
    "node_modules",
    "dist",
    "build",
    ".next",
    ".svelte-kit",
    ".cache",
    "coverage",
    // Python
    "__pycache__",
    ".venv",
    "venv",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    // IaC / JVM
    ".terraform",
    ".gradle",
];

/// True if `path`'s final component is a directory codered never descends into.
/// Use as a negated [`walkdir::WalkDir::filter_entry`] predicate:
/// `.filter_entry(|e| !is_ignored_dir(e.path()))`. `filter_entry` prunes the
/// whole subtree, so the walk never reads inside these directories at all.
pub fn is_ignored_dir(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .map(|n| IGNORED_DIRS.contains(&n))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prunes_vendored_and_build_dirs() {
        for d in ["node_modules", "target", ".terraform", ".git", "__pycache__"] {
            assert!(is_ignored_dir(Path::new(&format!("/repo/{d}"))), "{d}");
        }
    }

    #[test]
    fn keeps_source_dirs() {
        for d in ["src", "crates", "infra", "web", "lib.rs"] {
            assert!(!is_ignored_dir(Path::new(&format!("/repo/{d}"))), "{d}");
        }
    }
}
