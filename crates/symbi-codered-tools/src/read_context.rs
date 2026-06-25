//! read_context — for a `(file_path, line)` pair, return:
//!   1. The file's import block (Python: `import` and `from ... import` lines)
//!   2. The body of the enclosing function or method, if any

use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;

use crate::symbols::{extract_symbols, read_symbol_body, Symbol, SymbolError};

#[derive(Debug, Error)]
pub enum ContextError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("symbol: {0}")]
    Symbol(#[from] SymbolError),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CodeContext {
    pub file_path: String,
    pub target_line: u32,
    pub imports: Vec<String>,
    pub enclosing_symbol: Option<Symbol>,
    pub enclosing_body: Option<String>,
}

pub fn read_context(path: &Path, line: u32) -> Result<CodeContext, ContextError> {
    let body = std::fs::read_to_string(path)?;
    let imports = python_imports(&body);

    let symbols = extract_symbols(path)?;
    let enclosing = symbols
        .iter()
        .filter(|s| line >= s.line_start && line <= s.line_end)
        .min_by_key(|s| s.line_end - s.line_start)
        .cloned();

    let enclosing_body = match &enclosing {
        Some(sym) => Some(read_symbol_body(path, sym.line_start, sym.line_end)?),
        None => None,
    };

    Ok(CodeContext {
        file_path: path.to_string_lossy().into_owned(),
        target_line: line,
        imports,
        enclosing_symbol: enclosing,
        enclosing_body,
    })
}

fn python_imports(body: &str) -> Vec<String> {
    body.lines()
        .map(|l| l.trim_end())
        .filter(|l| {
            let t = l.trim_start();
            t.starts_with("import ") || t.starts_with("from ")
        })
        .map(|l| l.to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn enclosing_method_wins_over_class() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("x.py");
        std::fs::write(&p, r#"
from flask import Flask

class Foo:
    def bar(self):
        return 1     # line 6

def top():
    return 2
"#).unwrap();
        let ctx = read_context(&p, 6).unwrap();
        let sym = ctx.enclosing_symbol.unwrap();
        assert_eq!(sym.name, "bar");
        assert_eq!(sym.kind, "method");
        assert!(ctx.imports.iter().any(|i| i.contains("from flask")));
    }

    #[test]
    fn no_enclosing_for_module_level_line() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("x.py");
        std::fs::write(&p, "import os\n\nx = 1\n").unwrap();
        let ctx = read_context(&p, 3).unwrap();
        assert!(ctx.enclosing_symbol.is_none());
        assert!(ctx.enclosing_body.is_none());
        assert_eq!(ctx.imports.len(), 1);
    }
}
