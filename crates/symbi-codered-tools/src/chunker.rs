//! Text chunker for `grep_semantic`.
//!
//! Python files: one chunk per function/class/method.
//! Other supported files: one chunk per file.
//! Each chunk carries enough metadata for the consumer to materialize
//! a LanceDB row.

use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;
use walkdir::WalkDir;

use crate::symbols::{extract_symbols, read_symbol_body, SymbolError};
use crate::tree_sitter_loader::SupportedLanguage;

#[derive(Debug, Error)]
pub enum ChunkerError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("walk: {0}")]
    Walk(#[from] walkdir::Error),
    #[error("symbol: {0}")]
    Symbol(#[from] SymbolError),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Chunk {
    pub id: String,
    pub file_path: String,
    pub line_start: u32,
    pub line_end: u32,
    pub symbol_name: Option<String>,
    pub language: String,
    pub text: String,
}

const IGNORED_DIRS: &[&str] = &[
    ".git", "target", "node_modules", "__pycache__", ".venv", "venv",
];

const MAX_CHUNK_BYTES: usize = 4096;

pub fn chunk_repo(root: &Path) -> Result<Vec<Chunk>, ChunkerError> {
    let mut chunks = Vec::new();
    for entry in WalkDir::new(root)
        .into_iter()
        .filter_entry(|e| !is_ignored(e.path()))
    {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let rel = path
            .strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");

        match SupportedLanguage::from_path(path) {
            Some(SupportedLanguage::Python) => {
                let symbols = extract_symbols(path)?;
                if symbols.is_empty() {
                    if let Some(c) = whole_file_chunk(path, &rel, "python")? {
                        chunks.push(c);
                    }
                } else {
                    for sym in symbols {
                        // Same UTF-8 tolerance as whole_file_chunk: skip the
                        // chunk if we can't decode the file (mixed-encoding
                        // python files do exist in the wild).
                        let body = match read_symbol_body(path, sym.line_start, sym.line_end) {
                            Ok(b) => b,
                            Err(SymbolError::Io(e))
                                if e.kind() == std::io::ErrorKind::InvalidData =>
                            {
                                continue
                            }
                            Err(e) => return Err(e.into()),
                        };
                        chunks.push(Chunk {
                            id: format!("{rel}:{}-{}", sym.line_start, sym.line_end),
                            file_path: rel.clone(),
                            line_start: sym.line_start,
                            line_end: sym.line_end,
                            symbol_name: Some(sym.name),
                            language: sym.language,
                            text: truncate(body),
                        });
                    }
                }
            }
            Some(lang) => {
                if let Some(c) = whole_file_chunk(path, &rel, lang.name())? {
                    chunks.push(c);
                }
            }
            None => continue,
        }
    }
    Ok(chunks)
}

fn whole_file_chunk(path: &Path, rel: &str, language: &str) -> Result<Option<Chunk>, ChunkerError> {
    // Files with non-UTF-8 bytes (binaries misnamed with a tracked extension,
    // legacy latin-1 text, etc.) used to fail the whole carto stage. Skip
    // them instead — they're not useful as embedding chunks anyway.
    let body = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::InvalidData => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    if body.trim().is_empty() {
        return Ok(None);
    }
    let line_count = u32::try_from(body.lines().count().max(1)).unwrap_or(1);
    Ok(Some(Chunk {
        id: format!("{rel}:1-{line_count}"),
        file_path: rel.to_string(),
        line_start: 1,
        line_end: line_count,
        symbol_name: None,
        language: language.to_string(),
        text: truncate(body),
    }))
}

/// Truncate a string to at most `MAX_CHUNK_BYTES` bytes WITHOUT splitting
/// a UTF-8 codepoint. `String::truncate` panics if the byte offset isn't
/// a char boundary (e.g. mid-emoji, mid-accented-char); we walk backwards
/// to the previous boundary instead.
fn truncate(s: String) -> String {
    if s.len() <= MAX_CHUNK_BYTES {
        return s;
    }
    let mut cut = MAX_CHUNK_BYTES;
    while cut > 0 && !s.is_char_boundary(cut) {
        cut -= 1;
    }
    let mut t = s;
    t.truncate(cut);
    t
}

fn is_ignored(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .map(|n| IGNORED_DIRS.contains(&n))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write(dir: &TempDir, rel: &str, body: &str) {
        let p = dir.path().join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
    }

    #[test]
    fn chunks_python_by_symbol() {
        let dir = TempDir::new().unwrap();
        write(&dir, "app/users.py", r#"
def list_users():
    return []

def delete_user(uid):
    pass
"#);
        let chunks = chunk_repo(dir.path()).unwrap();
        let names: Vec<_> = chunks.iter().filter_map(|c| c.symbol_name.clone()).collect();
        assert!(names.iter().any(|n| n == "list_users"));
        assert!(names.iter().any(|n| n == "delete_user"));
    }

    #[test]
    fn skips_ignored_dirs() {
        let dir = TempDir::new().unwrap();
        write(&dir, ".venv/lib/whatever.py", "def x():\n    pass\n");
        write(&dir, "src/keep.py", "def keep():\n    pass\n");
        let chunks = chunk_repo(dir.path()).unwrap();
        assert!(chunks.iter().any(|c| c.symbol_name.as_deref() == Some("keep")));
        assert!(chunks.iter().all(|c| !c.file_path.contains(".venv")));
    }

    #[test]
    fn truncate_does_not_panic_on_multibyte_codepoint_boundary() {
        // Build a body of mostly ASCII but with a 4-byte UTF-8 codepoint
        // (an emoji, 4 bytes) straddling MAX_CHUNK_BYTES so naive truncation
        // would split it.
        let padding = "a".repeat(MAX_CHUNK_BYTES - 2);
        let body = format!("{padding}🦀aaa"); // 🦀 is 4 bytes; padding ends 2 bytes before the limit
        assert!(body.len() > MAX_CHUNK_BYTES);
        let t = truncate(body);
        // Must not panic; result must be valid UTF-8 (String is by construction).
        assert!(t.len() <= MAX_CHUNK_BYTES);
        // The crab emoji should NOT be partially included — we either keep
        // it whole or drop it entirely. We keep at least the padding.
        assert!(t.starts_with(&"a".repeat(MAX_CHUNK_BYTES - 2)));
    }

    #[test]
    fn whole_file_chunk_for_non_python() {
        let dir = TempDir::new().unwrap();
        write(&dir, "config.toml", "[deps]\nflask = \"3.0\"\n");
        let chunks = chunk_repo(dir.path()).unwrap();
        let toml_chunk = chunks.iter().find(|c| c.file_path == "config.toml").unwrap();
        assert!(toml_chunk.symbol_name.is_none());
        assert_eq!(toml_chunk.language, "toml");
    }

    #[test]
    fn empty_file_produces_no_chunk() {
        let dir = TempDir::new().unwrap();
        write(&dir, "empty.toml", "\n");
        let chunks = chunk_repo(dir.path()).unwrap();
        assert!(chunks.iter().all(|c| c.file_path != "empty.toml"));
    }
}
