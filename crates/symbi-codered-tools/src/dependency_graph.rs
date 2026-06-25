//! dependency_graph — parse Python project files into a normalized
//! dependency graph. Supports requirements.txt, pyproject.toml,
//! Pipfile, poetry.lock. TS/Rust/Go arrive in Plan F.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use thiserror::Error;
use toml::Value as TomlValue;

#[derive(Debug, Error)]
pub enum DepGraphError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("toml: {0}")]
    Toml(#[from] toml::de::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Dependency {
    pub name: String,
    pub version_spec: String,
    pub resolved_version: Option<String>,
    pub source_file: String,
    pub kind: String,   // direct | transitive
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DependencyGraph {
    pub language: String,
    pub dependencies: Vec<Dependency>,
}

pub fn analyze_python(root: &Path) -> Result<DependencyGraph, DepGraphError> {
    let mut deps: BTreeMap<String, Dependency> = BTreeMap::new();

    // requirements.txt
    let req = root.join("requirements.txt");
    if req.is_file() {
        for (name, spec) in parse_requirements_txt(&std::fs::read_to_string(&req)?) {
            deps.entry(name.clone()).or_insert(Dependency {
                name: name.clone(),
                version_spec: spec,
                resolved_version: None,
                source_file: "requirements.txt".into(),
                kind: "direct".into(),
            });
        }
    }

    // pyproject.toml ([project.dependencies] or [tool.poetry.dependencies])
    let pyproj = root.join("pyproject.toml");
    if pyproj.is_file() {
        let body = std::fs::read_to_string(&pyproj)?;
        let v: TomlValue = toml::from_str(&body)?;
        for (name, spec) in parse_pyproject_deps(&v) {
            deps.entry(name.clone()).or_insert(Dependency {
                name: name.clone(),
                version_spec: spec,
                resolved_version: None,
                source_file: "pyproject.toml".into(),
                kind: "direct".into(),
            });
        }
    }

    // Pipfile
    let pipfile = root.join("Pipfile");
    if pipfile.is_file() {
        let body = std::fs::read_to_string(&pipfile)?;
        let v: TomlValue = toml::from_str(&body)?;
        if let Some(packages) = v.get("packages").and_then(|t| t.as_table()) {
            for (name, spec_val) in packages {
                let spec = match spec_val {
                    TomlValue::String(s) => s.clone(),
                    other => other.to_string(),
                };
                deps.entry(name.clone()).or_insert(Dependency {
                    name: name.clone(),
                    version_spec: spec,
                    resolved_version: None,
                    source_file: "Pipfile".into(),
                    kind: "direct".into(),
                });
            }
        }
    }

    // poetry.lock — pins resolved versions, including transitive
    let poetry = root.join("poetry.lock");
    if poetry.is_file() {
        let body = std::fs::read_to_string(&poetry)?;
        let v: TomlValue = toml::from_str(&body)?;
        if let Some(packages) = v.get("package").and_then(|t| t.as_array()) {
            for pkg in packages {
                let name = pkg.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string();
                let version = pkg.get("version").and_then(|n| n.as_str()).unwrap_or("").to_string();
                if name.is_empty() {
                    continue;
                }
                deps.entry(name.clone())
                    .and_modify(|d| d.resolved_version = Some(version.clone()))
                    .or_insert(Dependency {
                        name: name.clone(),
                        version_spec: String::new(),
                        resolved_version: Some(version),
                        source_file: "poetry.lock".into(),
                        kind: "transitive".into(),
                    });
            }
        }
    }

    Ok(DependencyGraph {
        language: "python".into(),
        dependencies: deps.into_values().collect(),
    })
}

fn parse_requirements_txt(body: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
            continue;
        }
        let ops = ["==", ">=", "<=", "~=", "!=", ">", "<"];
        let mut found = None;
        for op in ops {
            if let Some(idx) = line.find(op) {
                found = Some(idx);
                break;
            }
        }
        match found {
            Some(idx) => {
                let name = line[..idx].trim().to_string();
                let spec = line[idx..].trim().to_string();
                out.push((name, spec));
            }
            None => out.push((line.to_string(), String::new())),
        }
    }
    out
}

fn parse_pyproject_deps(v: &TomlValue) -> Vec<(String, String)> {
    let mut out = Vec::new();

    // PEP 621
    if let Some(arr) = v
        .get("project")
        .and_then(|p| p.get("dependencies"))
        .and_then(|d| d.as_array())
    {
        for entry in arr {
            if let Some(s) = entry.as_str() {
                let (name, spec) = split_dep_spec(s);
                out.push((name, spec));
            }
        }
    }

    // Poetry
    if let Some(tbl) = v
        .get("tool")
        .and_then(|t| t.get("poetry"))
        .and_then(|p| p.get("dependencies"))
        .and_then(|d| d.as_table())
    {
        for (name, spec_val) in tbl {
            if name == "python" {
                continue;
            }
            let spec = match spec_val {
                TomlValue::String(s) => s.clone(),
                TomlValue::Table(t) => t.get("version")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                other => other.to_string(),
            };
            out.push((name.clone(), spec));
        }
    }

    out
}

fn split_dep_spec(s: &str) -> (String, String) {
    let ops = ["==", ">=", "<=", "~=", "!=", ">", "<"];
    for op in ops {
        if let Some(idx) = s.find(op) {
            return (s[..idx].trim().to_string(), s[idx..].trim().to_string());
        }
    }
    (s.trim().to_string(), String::new())
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
    fn parses_requirements_txt_with_specs() {
        let dir = TempDir::new().unwrap();
        write(&dir, "requirements.txt", "flask>=3.0\nsqlalchemy\nrequests==2.31.0\n# comment\n");
        let g = analyze_python(dir.path()).unwrap();
        let names: Vec<_> = g.dependencies.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"flask"));
        assert!(names.contains(&"sqlalchemy"));
        assert!(names.contains(&"requests"));
        let flask = g.dependencies.iter().find(|d| d.name == "flask").unwrap();
        assert_eq!(flask.version_spec, ">=3.0");
        assert_eq!(flask.source_file, "requirements.txt");
    }

    #[test]
    fn parses_pep621_pyproject() {
        let dir = TempDir::new().unwrap();
        write(&dir, "pyproject.toml", r#"
[project]
name = "x"
dependencies = ["flask>=3.0", "click<9"]
"#);
        let g = analyze_python(dir.path()).unwrap();
        assert_eq!(g.dependencies.len(), 2);
        let click = g.dependencies.iter().find(|d| d.name == "click").unwrap();
        assert_eq!(click.version_spec, "<9");
    }

    #[test]
    fn poetry_lock_marks_transitive_and_resolves() {
        let dir = TempDir::new().unwrap();
        write(&dir, "poetry.lock", r#"
[[package]]
name = "flask"
version = "3.0.2"
description = "..."
"#);
        let g = analyze_python(dir.path()).unwrap();
        let flask = g.dependencies.iter().find(|d| d.name == "flask").unwrap();
        assert_eq!(flask.kind, "transitive");
        assert_eq!(flask.resolved_version.as_deref(), Some("3.0.2"));
    }

    #[test]
    fn lock_resolves_declared_dep() {
        let dir = TempDir::new().unwrap();
        write(&dir, "pyproject.toml", r#"
[project]
name = "x"
dependencies = ["flask>=3.0"]
"#);
        write(&dir, "poetry.lock", r#"
[[package]]
name = "flask"
version = "3.0.2"
"#);
        let g = analyze_python(dir.path()).unwrap();
        let flask = g.dependencies.iter().find(|d| d.name == "flask").unwrap();
        assert_eq!(flask.kind, "direct");
        assert_eq!(flask.resolved_version.as_deref(), Some("3.0.2"));
    }
}
