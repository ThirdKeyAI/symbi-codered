//! Symbol extraction + lookup.
//!
//! `extract_symbols(path)` parses a source file with tree-sitter and
//! returns the function/class symbols inside it. `read_symbol_body`
//! returns the source slice for a known symbol location.

use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;
use tree_sitter::Node;

use crate::tree_sitter_loader::{parse, SupportedLanguage};

#[derive(Debug, Error)]
pub enum SymbolError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("tree-sitter: {0}")]
    TreeSitter(#[from] crate::tree_sitter_loader::TreeSitterError),
    #[error("unsupported file: {0}")]
    Unsupported(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Symbol {
    pub name: String,
    pub kind: String,             // "function" | "class" | "method"
    pub line_start: u32,          // 1-indexed
    pub line_end: u32,            // 1-indexed (inclusive)
    pub language: String,
}

/// Extract symbols from `path`. Returns empty Vec for unsupported file types.
pub fn extract_symbols(path: &Path) -> Result<Vec<Symbol>, SymbolError> {
    let lang = match SupportedLanguage::from_path(path) {
        Some(l) => l,
        None => return Ok(Vec::new()),
    };
    let source = std::fs::read(path)?;
    let mut out = Vec::new();
    match lang {
        SupportedLanguage::Python => {
            let tree = parse(lang, &source)?;
            walk_python(tree.root_node(), &source, &mut out, false);
        }
        SupportedLanguage::Go => {
            let tree = parse(lang, &source)?;
            walk_go_symbols(tree.root_node(), &source, &mut out);
        }
        SupportedLanguage::Java => {
            let tree = parse(lang, &source)?;
            walk_java_symbols(tree.root_node(), &source, &mut out);
        }
        SupportedLanguage::Php => {
            let tree = parse(lang, &source)?;
            walk_php_symbols(tree.root_node(), &source, &mut out);
        }
        SupportedLanguage::Rust => {
            let tree = parse(lang, &source)?;
            walk_rust_symbols(tree.root_node(), &source, &mut out);
        }
        SupportedLanguage::TypeScript | SupportedLanguage::Tsx => {
            let tree = parse(lang, &source)?;
            walk_ts_symbols(tree.root_node(), &source, &mut out, "typescript");
        }
        SupportedLanguage::JavaScript => {
            let tree = parse(lang, &source)?;
            walk_ts_symbols(tree.root_node(), &source, &mut out, "javascript");
        }
        // Remaining languages (config/markup): no function-span symbols.
        _ => {}
    }
    Ok(out)
}

/// Extract Go `func`/method declarations as `function`/`method` symbols.
/// A `method_declaration` (has a receiver) is recorded as `method`; a plain
/// `function_declaration` as `function`.
fn walk_go_symbols(node: Node, source: &[u8], out: &mut Vec<Symbol>) {
    let kind = node.kind();
    if kind == "function_declaration" || kind == "method_declaration" {
        if let Some(name_node) = node.child_by_field_name("name") {
            if let Ok(name) = name_node.utf8_text(source) {
                let sym_kind = if kind == "method_declaration" {
                    "method"
                } else {
                    "function"
                };
                out.push(Symbol {
                    name: name.to_string(),
                    kind: sym_kind.into(),
                    line_start: u32::try_from(node.start_position().row + 1).unwrap_or(0),
                    line_end: u32::try_from(node.end_position().row + 1).unwrap_or(0),
                    language: "go".into(),
                });
            }
        }
    }
    for child in node.children(&mut node.walk()) {
        walk_go_symbols(child, source, out);
    }
}

/// Extract Java type and method declarations. `class`/`interface`/`enum`/
/// `record` declarations are recorded as `class`; `method_declaration` and
/// `constructor_declaration` as `method`.
fn walk_java_symbols(node: Node, source: &[u8], out: &mut Vec<Symbol>) {
    let kind = node.kind();
    let sym_kind = match kind {
        "class_declaration"
        | "interface_declaration"
        | "enum_declaration"
        | "record_declaration" => Some("class"),
        "method_declaration" | "constructor_declaration" => Some("method"),
        _ => None,
    };
    if let Some(sym_kind) = sym_kind {
        if let Some(name_node) = node.child_by_field_name("name") {
            if let Ok(name) = name_node.utf8_text(source) {
                out.push(Symbol {
                    name: name.to_string(),
                    kind: sym_kind.into(),
                    line_start: u32::try_from(node.start_position().row + 1).unwrap_or(0),
                    line_end: u32::try_from(node.end_position().row + 1).unwrap_or(0),
                    language: "java".into(),
                });
            }
        }
    }
    for child in node.children(&mut node.walk()) {
        walk_java_symbols(child, source, out);
    }
}

/// Extract PHP type and function declarations. `class`/`interface`/`trait`/
/// `enum` declarations are recorded as `class`; `method_declaration` and
/// top-level `function_definition` as `method`.
fn walk_php_symbols(node: Node, source: &[u8], out: &mut Vec<Symbol>) {
    let kind = node.kind();
    let sym_kind = match kind {
        "class_declaration"
        | "interface_declaration"
        | "trait_declaration"
        | "enum_declaration" => Some("class"),
        "method_declaration" | "function_definition" => Some("method"),
        _ => None,
    };
    if let Some(sym_kind) = sym_kind {
        if let Some(name_node) = node.child_by_field_name("name") {
            if let Ok(name) = name_node.utf8_text(source) {
                out.push(Symbol {
                    name: name.to_string(),
                    kind: sym_kind.into(),
                    line_start: u32::try_from(node.start_position().row + 1).unwrap_or(0),
                    line_end: u32::try_from(node.end_position().row + 1).unwrap_or(0),
                    language: "php".into(),
                });
            }
        }
    }
    for child in node.children(&mut node.walk()) {
        walk_php_symbols(child, source, out);
    }
}

/// Extract Rust items. `struct`/`enum`/`trait`/`union` declarations are
/// recorded as `class`; `function_item` (including methods inside `impl`
/// blocks, which tree-sitter-rust also models as `function_item`) as `function`.
fn walk_rust_symbols(node: Node, source: &[u8], out: &mut Vec<Symbol>) {
    let sym_kind = match node.kind() {
        "struct_item" | "enum_item" | "trait_item" | "union_item" => Some("class"),
        "function_item" => Some("function"),
        _ => None,
    };
    if let Some(sym_kind) = sym_kind {
        if let Some(name_node) = node.child_by_field_name("name") {
            if let Ok(name) = name_node.utf8_text(source) {
                out.push(Symbol {
                    name: name.to_string(),
                    kind: sym_kind.into(),
                    line_start: u32::try_from(node.start_position().row + 1).unwrap_or(0),
                    line_end: u32::try_from(node.end_position().row + 1).unwrap_or(0),
                    language: "rust".into(),
                });
            }
        }
    }
    for child in node.children(&mut node.walk()) {
        walk_rust_symbols(child, source, out);
    }
}

/// Extract TypeScript / JavaScript declarations. `class`/`abstract class`/
/// `interface`/`enum` declarations are recorded as `class`; `function`/
/// generator declarations as `function`; `method_definition` as `method`.
/// `lang` is `"typescript"` or `"javascript"`.
fn walk_ts_symbols(node: Node, source: &[u8], out: &mut Vec<Symbol>, lang: &'static str) {
    let sym_kind = match node.kind() {
        "class_declaration"
        | "abstract_class_declaration"
        | "interface_declaration"
        | "enum_declaration" => Some("class"),
        "function_declaration" | "generator_function_declaration" => Some("function"),
        "method_definition" => Some("method"),
        _ => None,
    };
    if let Some(sym_kind) = sym_kind {
        if let Some(name_node) = node.child_by_field_name("name") {
            if let Ok(name) = name_node.utf8_text(source) {
                out.push(Symbol {
                    name: name.to_string(),
                    kind: sym_kind.into(),
                    line_start: u32::try_from(node.start_position().row + 1).unwrap_or(0),
                    line_end: u32::try_from(node.end_position().row + 1).unwrap_or(0),
                    language: lang.into(),
                });
            }
        }
    }
    for child in node.children(&mut node.walk()) {
        walk_ts_symbols(child, source, out, lang);
    }
}

fn walk_python(node: Node, source: &[u8], out: &mut Vec<Symbol>, inside_class: bool) {
    let kind = node.kind();
    match kind {
        "function_definition" => {
            if let Some(sym) = function_symbol(node, source, inside_class) {
                out.push(sym);
            }
            for child in node.children(&mut node.walk()) {
                walk_python(child, source, out, inside_class);
            }
        }
        "class_definition" => {
            if let Some(sym) = class_symbol(node, source) {
                out.push(sym);
            }
            for child in node.children(&mut node.walk()) {
                walk_python(child, source, out, true);
            }
        }
        _ => {
            for child in node.children(&mut node.walk()) {
                walk_python(child, source, out, inside_class);
            }
        }
    }
}

fn function_symbol(node: Node, source: &[u8], inside_class: bool) -> Option<Symbol> {
    let name_node = node.child_by_field_name("name")?;
    let name = name_node.utf8_text(source).ok()?.to_string();
    let kind = if inside_class { "method" } else { "function" };
    Some(Symbol {
        name,
        kind: kind.into(),
        line_start: u32::try_from(node.start_position().row + 1).unwrap_or(0),
        line_end:   u32::try_from(node.end_position().row + 1).unwrap_or(0),
        language: "python".into(),
    })
}

fn class_symbol(node: Node, source: &[u8]) -> Option<Symbol> {
    let name_node = node.child_by_field_name("name")?;
    let name = name_node.utf8_text(source).ok()?.to_string();
    Some(Symbol {
        name,
        kind: "class".into(),
        line_start: u32::try_from(node.start_position().row + 1).unwrap_or(0),
        line_end:   u32::try_from(node.end_position().row + 1).unwrap_or(0),
        language: "python".into(),
    })
}

/// Read the body of a known symbol location.
pub fn read_symbol_body(
    file_path: &Path,
    line_start: u32,
    line_end: u32,
) -> Result<String, SymbolError> {
    let body = std::fs::read_to_string(file_path)?;
    let lines: Vec<&str> = body.lines().collect();
    let start = (line_start as usize).saturating_sub(1).min(lines.len());
    let end = (line_end as usize).min(lines.len());
    if start >= end {
        return Ok(String::new());
    }
    Ok(lines[start..end].join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write_py(dir: &TempDir, name: &str, body: &str) -> std::path::PathBuf {
        let p = dir.path().join(name);
        std::fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn extracts_module_functions_and_classes() {
        let dir = TempDir::new().unwrap();
        let p = write_py(&dir, "x.py", r#"
def alpha():
    return 1

class Beta:
    def gamma(self):
        return 2

def delta():
    return 3
"#);
        let syms = extract_symbols(&p).unwrap();
        let names: Vec<_> = syms.iter().map(|s| (s.name.as_str(), s.kind.as_str())).collect();
        assert!(names.contains(&("alpha", "function")));
        assert!(names.contains(&("Beta", "class")));
        assert!(names.contains(&("gamma", "method")));
        assert!(names.contains(&("delta", "function")));
    }

    #[test]
    fn extracts_java_types_and_methods() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("App.java");
        std::fs::write(
            &p,
            r#"
package com.acme;
class App {
    App() {}
    int alpha() { return 1; }
}
interface Svc {
    void beta();
}
"#,
        )
        .unwrap();
        let syms = extract_symbols(&p).unwrap();
        let names: Vec<_> = syms
            .iter()
            .map(|s| (s.name.as_str(), s.kind.as_str()))
            .collect();
        assert!(names.contains(&("App", "class")));
        assert!(names.contains(&("alpha", "method")));
        assert!(names.contains(&("Svc", "class")));
        assert!(syms.iter().all(|s| s.language == "java"));
    }

    #[test]
    fn line_numbers_are_one_indexed() {
        let dir = TempDir::new().unwrap();
        let p = write_py(&dir, "x.py", "\ndef f():\n    return 1\n");
        let syms = extract_symbols(&p).unwrap();
        let f = syms.iter().find(|s| s.name == "f").unwrap();
        assert_eq!(f.line_start, 2);
        assert!(f.line_end >= 3);
    }

    #[test]
    fn read_symbol_body_returns_slice() {
        let dir = TempDir::new().unwrap();
        let p = write_py(&dir, "x.py", "def f():\n    return 1\n\ndef g():\n    return 2\n");
        let body = read_symbol_body(&p, 1, 2).unwrap();
        assert!(body.contains("def f"));
        assert!(body.contains("return 1"));
        assert!(!body.contains("def g"));
    }

    #[test]
    fn non_python_files_return_empty() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("x.txt");
        std::fs::write(&p, "not code").unwrap();
        let syms = extract_symbols(&p).unwrap();
        assert!(syms.is_empty());
    }

    #[test]
    fn extracts_php_types_and_methods() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("App.php");
        std::fs::write(
            &p,
            r#"<?php
class App {
    function alpha() { return 1; }
}
interface Svc { public function beta(); }
trait T { function gamma() {} }
function topLevel() { return 2; }
"#,
        )
        .unwrap();
        let syms = extract_symbols(&p).unwrap();
        let names: Vec<_> = syms
            .iter()
            .map(|s| (s.name.as_str(), s.kind.as_str()))
            .collect();
        assert!(names.contains(&("App", "class")));
        assert!(names.contains(&("alpha", "method")));
        assert!(names.contains(&("Svc", "class")));
        assert!(names.contains(&("T", "class")));
        assert!(names.contains(&("topLevel", "method")));
        assert!(syms.iter().all(|s| s.language == "php"));
    }

    #[test]
    fn extracts_rust_items_and_functions() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("lib.rs");
        std::fs::write(
            &p,
            r#"
pub struct Widget { n: u32 }
pub enum Color { Red, Blue }
pub trait Draw { fn draw(&self); }
pub fn build() -> Widget { Widget { n: 0 } }
impl Widget {
    pub fn render(&self) -> u32 { self.n }
}
"#,
        )
        .unwrap();
        let syms = extract_symbols(&p).unwrap();
        let names: Vec<_> = syms
            .iter()
            .map(|s| (s.name.as_str(), s.kind.as_str()))
            .collect();
        assert!(names.contains(&("Widget", "class")));
        assert!(names.contains(&("Color", "class")));
        assert!(names.contains(&("Draw", "class")));
        assert!(names.contains(&("build", "function")));
        assert!(names.contains(&("render", "function"))); // method in impl
        assert!(syms.iter().all(|s| s.language == "rust"));
    }

    #[test]
    fn extracts_typescript_classes_and_functions() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("app.ts");
        std::fs::write(
            &p,
            r#"
export function alpha(x: number): number { return x; }
export class Beta {
    gamma(): void {}
}
interface Svc { delta(): void; }
"#,
        )
        .unwrap();
        let syms = extract_symbols(&p).unwrap();
        let names: Vec<_> = syms
            .iter()
            .map(|s| (s.name.as_str(), s.kind.as_str()))
            .collect();
        assert!(names.contains(&("alpha", "function")));
        assert!(names.contains(&("Beta", "class")));
        assert!(names.contains(&("gamma", "method")));
        assert!(names.contains(&("Svc", "class")));
        assert!(syms.iter().all(|s| s.language == "typescript"));
    }
}
