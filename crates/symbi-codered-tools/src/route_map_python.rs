//! Python route extractor — Flask + FastAPI + Django (basic).

use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;
use tree_sitter::Node;
use walkdir::WalkDir;

use crate::tree_sitter_loader::{parse, SupportedLanguage};

#[derive(Debug, Error)]
pub enum RouteMapError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("walk: {0}")]
    Walk(#[from] walkdir::Error),
    #[error("tree-sitter: {0}")]
    TreeSitter(#[from] crate::tree_sitter_loader::TreeSitterError),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Route {
    pub method: String,
    pub path: String,
    pub handler_symbol: String,
    pub framework: String,        // flask | fastapi | django
    pub file_path: String,
    pub line: u32,
}

pub fn extract_routes(root: &Path) -> Result<Vec<Route>, RouteMapError> {
    let mut routes = Vec::new();
    for entry in WalkDir::new(root) {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        if SupportedLanguage::from_path(path) != Some(SupportedLanguage::Python) {
            continue;
        }
        let source = std::fs::read(path)?;
        let Ok(tree) = parse(SupportedLanguage::Python, &source) else { continue; };
        let rel = path.strip_prefix(root).unwrap_or(path).to_string_lossy().into_owned();
        walk_python_routes(tree.root_node(), &source, &rel, &mut routes);
    }
    Ok(routes)
}

fn walk_python_routes(node: Node, source: &[u8], rel: &str, out: &mut Vec<Route>) {
    if node.kind() == "decorated_definition" {
        if let Some(route) = extract_flask_or_fastapi(node, source, rel) {
            out.push(route);
        }
    }
    if node.kind() == "assignment" {
        extract_django_urlpatterns(node, source, rel, out);
    }
    for child in node.children(&mut node.walk()) {
        walk_python_routes(child, source, rel, out);
    }
}

fn extract_flask_or_fastapi(node: Node, source: &[u8], rel: &str) -> Option<Route> {
    let mut decorator_text = None;
    let mut handler_name = None;
    let mut handler_line = 0;
    for child in node.children(&mut node.walk()) {
        match child.kind() {
            "decorator" => {
                decorator_text = Some(child.utf8_text(source).ok()?.to_string());
            }
            "function_definition" => {
                let name = child.child_by_field_name("name")?;
                handler_name = Some(name.utf8_text(source).ok()?.to_string());
                handler_line = u32::try_from(child.start_position().row + 1).unwrap_or(0);
            }
            _ => {}
        }
    }
    let dec = decorator_text?;
    let handler = handler_name?;

    let dec_norm = dec.trim_start_matches('@');
    let dot = dec_norm.find('.')?;
    let paren = dec_norm.find('(')?;
    if dot >= paren {
        return None;
    }
    let method_token = dec_norm[dot + 1..paren].trim();
    let path = extract_first_string_arg(&dec_norm[paren..])?;

    let (framework, method) = match method_token {
        "get" => ("fastapi", "GET"),
        "post" => ("fastapi", "POST"),
        "put" => ("fastapi", "PUT"),
        "delete" => ("fastapi", "DELETE"),
        "patch" => ("fastapi", "PATCH"),
        "head" => ("fastapi", "HEAD"),
        "options" => ("fastapi", "OPTIONS"),
        "route" => {
            let m = extract_methods_kwarg(&dec_norm[paren..]).unwrap_or_else(|| "GET".into());
            return Some(Route {
                method: m,
                path,
                handler_symbol: format!("{}.{}", rel.trim_end_matches(".py").replace('/', "."), handler),
                framework: "flask".into(),
                file_path: rel.into(),
                line: handler_line,
            });
        }
        _ => return None,
    };

    Some(Route {
        method: method.into(),
        path,
        handler_symbol: format!("{}.{}", rel.trim_end_matches(".py").replace('/', "."), handler),
        framework: framework.into(),
        file_path: rel.into(),
        line: handler_line,
    })
}

fn extract_django_urlpatterns(node: Node, source: &[u8], rel: &str, out: &mut Vec<Route>) {
    let text = node.utf8_text(source).unwrap_or("");
    if !text.trim_start().starts_with("urlpatterns") {
        return;
    }
    let mut idx = 0;
    while let Some(found) = text[idx..].find("path(") {
        let start = idx + found + 5;
        if let Some(path_arg) = extract_first_string_arg(&text[start..]) {
            if let Some(after) = text[start..].split_once(',') {
                let view = after.1.trim().trim_end_matches(',').trim_matches([')', ' ', ',']).to_string();
                let view_token: String = view
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '.')
                    .collect();
                if !view_token.is_empty() {
                    out.push(Route {
                        method: "ANY".into(),
                        path: path_arg,
                        handler_symbol: view_token,
                        framework: "django".into(),
                        file_path: rel.into(),
                        line: u32::try_from(node.start_position().row + 1).unwrap_or(0),
                    });
                }
            }
        }
        idx = start;
    }
}

fn extract_first_string_arg(after_open_paren: &str) -> Option<String> {
    let s = after_open_paren;
    let first = s.find(['\'', '"'])?;
    let quote = s.as_bytes()[first] as char;
    let rest = &s[first + 1..];
    let end = rest.find(quote)?;
    Some(rest[..end].to_string())
}

fn extract_methods_kwarg(after_open_paren: &str) -> Option<String> {
    let idx = after_open_paren.find("methods")?;
    let after = &after_open_paren[idx..];
    let lb = after.find('[')?;
    let rb = after.find(']')?;
    if rb <= lb { return None; }
    let body = &after[lb + 1..rb];
    let methods: Vec<String> = body
        .split(',')
        .filter_map(|p| {
            let trimmed = p.trim().trim_matches(['\'', '"', ' ']);
            if trimmed.is_empty() { None } else { Some(trimmed.to_uppercase()) }
        })
        .collect();
    if methods.is_empty() { None } else { Some(methods.join(",")) }
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
    fn extracts_flask_routes_with_methods_kwarg() {
        let dir = TempDir::new().unwrap();
        write(&dir, "app/routes/users.py", r#"
from flask import Blueprint
bp = Blueprint("users", __name__)

@bp.route("/users", methods=["GET", "POST"])
def list_users():
    return []
"#);
        let routes = extract_routes(dir.path()).unwrap();
        assert_eq!(routes.len(), 1, "expected 1 route; got: {routes:?}");
        let r = &routes[0];
        assert_eq!(r.framework, "flask");
        assert_eq!(r.path, "/users");
        assert!(r.method.contains("GET") && r.method.contains("POST"));
        assert!(r.handler_symbol.ends_with("list_users"));
    }

    #[test]
    fn extracts_fastapi_get_route() {
        let dir = TempDir::new().unwrap();
        write(&dir, "main.py", r#"
from fastapi import FastAPI
app = FastAPI()

@app.get("/items/{item_id}")
def read_item(item_id: int):
    return {"id": item_id}
"#);
        let routes = extract_routes(dir.path()).unwrap();
        assert_eq!(routes.len(), 1);
        let r = &routes[0];
        assert_eq!(r.framework, "fastapi");
        assert_eq!(r.method, "GET");
        assert_eq!(r.path, "/items/{item_id}");
    }

    #[test]
    fn extracts_django_path_assignments() {
        let dir = TempDir::new().unwrap();
        write(&dir, "urls.py", r#"
from django.urls import path
from . import views

urlpatterns = [
    path("users/", views.user_list),
    path("admin/", views.admin_panel),
]
"#);
        let routes = extract_routes(dir.path()).unwrap();
        let paths: Vec<_> = routes.iter().map(|r| r.path.as_str()).collect();
        assert!(paths.contains(&"users/"));
        assert!(paths.contains(&"admin/"));
        assert!(routes.iter().all(|r| r.framework == "django"));
    }

    #[test]
    fn flask_default_method_is_get() {
        let dir = TempDir::new().unwrap();
        write(&dir, "app.py", r#"
from flask import Flask
app = Flask(__name__)

@app.route("/")
def index():
    return ""
"#);
        let routes = extract_routes(dir.path()).unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].method, "GET");
    }
}
