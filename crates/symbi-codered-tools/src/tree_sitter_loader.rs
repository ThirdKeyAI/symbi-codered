//! Tree-sitter parser bootstrap for the language set Plan B needs.
//!
//! Each `SupportedLanguage` variant maps a file path to a tree-sitter
//! grammar and exposes a `parse` helper. Plan F extends this with
//! TypeScript/JavaScript/Rust/Go.
//!
//! # Grammar crate notes
//!
//! `tree-sitter-dockerfile` 0.2 pins `tree-sitter` 0.20 and is therefore
//! incompatible with the workspace's `tree-sitter` 0.26. Dockerfile/Containerfile
//! support is provided via `tree-sitter-containerfile` 0.8 instead, which
//! exposes the modern `LANGUAGE: LanguageFn` API.

use std::path::Path;
use thiserror::Error;
use tree_sitter::{Language, Parser, Tree};

#[derive(Debug, Error)]
pub enum TreeSitterError {
    #[error("language not supported for {0}")]
    Unsupported(String),
    #[error("parser init: {0}")]
    Init(String),
    #[error("parse failed (empty tree returned)")]
    Parse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupportedLanguage {
    Python,
    Toml,
    Yaml,
    Json,
    Dockerfile,
    Rust,
    Go,
    TypeScript,
    Tsx,
    JavaScript,
    Java,
    Php,
}

impl SupportedLanguage {
    /// Map a filesystem path to a supported language by extension / basename.
    pub fn from_path(path: &Path) -> Option<Self> {
        let basename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if basename.eq_ignore_ascii_case("Dockerfile")
            || basename.to_ascii_lowercase().ends_with(".dockerfile")
        {
            return Some(Self::Dockerfile);
        }
        let ext = path.extension().and_then(|e| e.to_str())?.to_ascii_lowercase();
        match ext.as_str() {
            "py" | "pyi" => Some(Self::Python),
            "toml" => Some(Self::Toml),
            "yaml" | "yml" => Some(Self::Yaml),
            "json" => Some(Self::Json),
            "rs" => Some(Self::Rust),
            "go" => Some(Self::Go),
            "ts" => Some(Self::TypeScript),
            "tsx" => Some(Self::Tsx),
            "js" | "jsx" | "mjs" | "cjs" => Some(Self::JavaScript),
            "java" => Some(Self::Java),
            "php" | "phtml" => Some(Self::Php),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Python => "python",
            Self::Toml => "toml",
            Self::Yaml => "yaml",
            Self::Json => "json",
            // Provided by tree-sitter-containerfile; variant kept as Dockerfile
            // for API stability.
            Self::Dockerfile => "dockerfile",
            Self::Rust => "rust",
            Self::Go => "go",
            Self::TypeScript => "typescript",
            Self::Tsx => "tsx",
            Self::JavaScript => "javascript",
            Self::Java => "java",
            Self::Php => "php",
        }
    }

    pub fn language(&self) -> Language {
        match self {
            Self::Python => tree_sitter_python::LANGUAGE.into(),
            Self::Toml => tree_sitter_toml_ng::LANGUAGE.into(),
            Self::Yaml => tree_sitter_yaml::LANGUAGE.into(),
            Self::Json => tree_sitter_json::LANGUAGE.into(),
            // tree-sitter-containerfile 0.8 parses Dockerfiles and Containerfiles.
            Self::Dockerfile => tree_sitter_containerfile::LANGUAGE.into(),
            Self::Rust => tree_sitter_rust::LANGUAGE.into(),
            Self::Go => tree_sitter_go::LANGUAGE.into(),
            Self::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
            Self::Tsx => tree_sitter_typescript::LANGUAGE_TSX.into(),
            Self::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
            Self::Java => tree_sitter_java::LANGUAGE.into(),
            Self::Php => tree_sitter_php::LANGUAGE_PHP.into(),
        }
    }
}

/// Parse `source` for the given language.
pub fn parse(lang: SupportedLanguage, source: &[u8]) -> Result<Tree, TreeSitterError> {
    let mut parser = Parser::new();
    parser
        .set_language(&lang.language())
        .map_err(|e| TreeSitterError::Init(e.to_string()))?;
    parser.parse(source, None).ok_or(TreeSitterError::Parse)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn from_path_recognizes_python_and_dockerfile() {
        assert_eq!(
            SupportedLanguage::from_path(&PathBuf::from("app/users.py")),
            Some(SupportedLanguage::Python)
        );
        assert_eq!(
            SupportedLanguage::from_path(&PathBuf::from("Dockerfile")),
            Some(SupportedLanguage::Dockerfile)
        );
        assert_eq!(
            SupportedLanguage::from_path(&PathBuf::from("infra/build.dockerfile")),
            Some(SupportedLanguage::Dockerfile)
        );
        assert_eq!(
            SupportedLanguage::from_path(&PathBuf::from("config.yml")),
            Some(SupportedLanguage::Yaml)
        );
        assert_eq!(
            SupportedLanguage::from_path(&PathBuf::from("README.md")),
            None
        );
    }

    #[test]
    fn parse_python_returns_module_root() {
        let tree = parse(SupportedLanguage::Python, b"def f():\n    return 1\n").unwrap();
        let root = tree.root_node();
        assert_eq!(root.kind(), "module");
        let first = root.child(0).unwrap();
        assert_eq!(first.kind(), "function_definition");
    }

    #[test]
    fn parse_toml_returns_document() {
        let tree = parse(SupportedLanguage::Toml, b"[deps]\nflask = \"3.0\"\n").unwrap();
        assert_eq!(tree.root_node().kind(), "document");
    }

    #[test]
    fn parse_json_returns_document() {
        let tree = parse(SupportedLanguage::Json, b"{\"a\": 1}").unwrap();
        assert_eq!(tree.root_node().kind(), "document");
    }

    #[test]
    fn from_path_recognizes_java() {
        assert_eq!(
            SupportedLanguage::from_path(&PathBuf::from("src/main/java/com/acme/App.java")),
            Some(SupportedLanguage::Java)
        );
    }

    #[test]
    fn parse_java_returns_program_root() {
        let tree = parse(
            SupportedLanguage::Java,
            b"class A { int f() { return 1; } }",
        )
        .unwrap();
        assert_eq!(tree.root_node().kind(), "program");
    }

    #[test]
    fn from_path_recognizes_php() {
        assert_eq!(
            SupportedLanguage::from_path(&PathBuf::from("public/index.php")),
            Some(SupportedLanguage::Php)
        );
        assert_eq!(
            SupportedLanguage::from_path(&PathBuf::from("tpl/page.phtml")),
            Some(SupportedLanguage::Php)
        );
    }

    #[test]
    fn parse_php_returns_program_root() {
        let tree = parse(
            SupportedLanguage::Php,
            b"<?php class A { function f() { return 1; } }",
        )
        .unwrap();
        assert_eq!(tree.root_node().kind(), "program");
    }
}
