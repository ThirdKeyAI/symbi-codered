//! repo_overview — detect languages, frameworks, package managers, and
//! entrypoints. Pure file-system traversal; no LLM judgment.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;
use thiserror::Error;
use walkdir::WalkDir;

use crate::tree_sitter_loader::SupportedLanguage;

#[derive(Debug, Error)]
pub enum RepoOverviewError {
    #[error("walk: {0}")]
    Walk(#[from] walkdir::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RepoOverview {
    pub languages: BTreeSet<String>,
    pub frameworks: BTreeSet<String>,
    pub package_managers: BTreeSet<String>,
    pub entrypoints: BTreeSet<String>,
}

const IGNORED_DIRS: &[&str] = &[
    ".git", "target", "node_modules", "__pycache__", ".venv", "venv",
    "dist", "build", ".tox", ".mypy_cache", ".pytest_cache",
];

/// Walk `root` and detect overview facts. Skips common build/dep dirs.
pub fn analyze(root: &Path) -> Result<RepoOverview, RepoOverviewError> {
    let mut out = RepoOverview {
        languages: BTreeSet::new(),
        frameworks: BTreeSet::new(),
        package_managers: BTreeSet::new(),
        entrypoints: BTreeSet::new(),
    };

    for entry in WalkDir::new(root)
        .into_iter()
        .filter_entry(|e| !is_ignored(e.path()))
    {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let rel = path.strip_prefix(root).unwrap_or(path);

        if let Some(lang) = SupportedLanguage::from_path(path) {
            out.languages.insert(lang.name().to_string());
        }
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            let lower = name.to_ascii_lowercase();
            if lower.ends_with(".ts") || lower.ends_with(".tsx") {
                out.languages.insert("typescript".into());
            } else if lower.ends_with(".js") || lower.ends_with(".jsx") {
                out.languages.insert("javascript".into());
            } else if lower.ends_with(".rs") {
                out.languages.insert("rust".into());
            } else if lower.ends_with(".go") {
                out.languages.insert("go".into());
            }
        }

        // IaC language detection. A repo gets the "iac" language fact as
        // soon as ANY of these signals fire — the iac sidecar then runs
        // checkov / tfsec / trivy against the whole tree (each walks
        // independently looking for its own manifests).
        if is_iac_path(rel) {
            out.languages.insert("iac".into());
        }

        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            match name {
                "pyproject.toml" | "setup.py" | "setup.cfg" =>
                    { out.package_managers.insert("pip".into()); }
                "Pipfile" => { out.package_managers.insert("pipenv".into()); }
                "poetry.lock" => { out.package_managers.insert("poetry".into()); }
                "requirements.txt" => { out.package_managers.insert("pip".into()); }
                "package.json" => { out.package_managers.insert("npm".into()); }
                "pnpm-lock.yaml" => { out.package_managers.insert("pnpm".into()); }
                "yarn.lock" => { out.package_managers.insert("yarn".into()); }
                "Cargo.toml" => { out.package_managers.insert("cargo".into()); }
                "go.mod" => { out.package_managers.insert("go".into()); }
                "composer.json" | "composer.lock" =>
                    { out.package_managers.insert("composer".into()); }
                _ => {}
            }
        }

        // Framework detection via cheap content heuristics
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if matches!(name, "pyproject.toml" | "requirements.txt" | "setup.py" | "Pipfile") {
                if let Ok(text) = std::fs::read_to_string(path) {
                    let lower = text.to_ascii_lowercase();
                    if lower.contains("flask")    { out.frameworks.insert("flask".into()); }
                    if lower.contains("django")   { out.frameworks.insert("django".into()); }
                    if lower.contains("fastapi")  { out.frameworks.insert("fastapi".into()); }
                }
            }
            if name == "package.json" {
                if let Ok(text) = std::fs::read_to_string(path) {
                    let lower = text.to_ascii_lowercase();
                    if lower.contains("\"express\"") { out.frameworks.insert("express".into()); }
                    if lower.contains("\"next\"")    { out.frameworks.insert("nextjs".into()); }
                }
            }
            if name == "Cargo.toml" {
                if let Ok(text) = std::fs::read_to_string(path) {
                    let lower = text.to_ascii_lowercase();
                    if lower.contains("axum")  { out.frameworks.insert("axum".into()); }
                    if lower.contains("actix") { out.frameworks.insert("actix".into()); }
                }
            }
            if name == "go.mod" {
                if let Ok(text) = std::fs::read_to_string(path) {
                    let lower = text.to_ascii_lowercase();
                    if lower.contains("github.com/gin-gonic/gin") {
                        out.frameworks.insert("gin".into());
                    }
                }
            }
            if name == "composer.json" {
                if let Ok(text) = std::fs::read_to_string(path) {
                    let lower = text.to_ascii_lowercase();
                    if lower.contains("laravel/framework") { out.frameworks.insert("laravel".into()); }
                    if lower.contains("symfony/")          { out.frameworks.insert("symfony".into()); }
                    if lower.contains("drupal/")           { out.frameworks.insert("drupal".into()); }
                }
            }
            if matches!(name, "wp-config.php" | "wp-load.php") {
                out.frameworks.insert("wordpress".into());
            }
        }

        // Entrypoint detection: common filenames.
        if let Some(
            "main.py" | "app.py" | "__main__.py" | "wsgi.py" | "asgi.py"
            | "main.rs" | "server.rs"
            | "main.go" | "server.go"
            | "server.ts" | "server.js" | "index.ts" | "index.js"
            | "index.php",
        ) = path.file_name().and_then(|n| n.to_str())
        {
            out.entrypoints.insert(rel_str(rel));
        }
    }

    // app/__init__.py is also a common Flask/Django entrypoint signal.
    let init = root.join("app").join("__init__.py");
    if init.is_file() {
        out.entrypoints.insert("app/__init__.py".into());
    }

    Ok(out)
}

fn rel_str(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

/// Heuristic match for files that signal the iac language. Conservative
/// on names, generous on directory location.
fn is_iac_path(rel: &Path) -> bool {
    let Some(name) = rel.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let lower = name.to_ascii_lowercase();

    // Terraform — definitive
    if lower.ends_with(".tf") || lower.ends_with(".tfvars") || lower == "terraform.lock.hcl" {
        return true;
    }
    // CloudFormation / SAM templates
    if lower == "template.yaml" || lower == "template.yml" || lower == "samconfig.toml" {
        return true;
    }
    // Helm
    if lower == "chart.yaml" || lower == "values.yaml" || lower == "values.yml" {
        return true;
    }
    // Dockerfile
    if lower == "dockerfile" || lower.starts_with("dockerfile.") || lower.ends_with(".dockerfile") {
        return true;
    }
    // docker-compose
    if matches!(lower.as_str(),
        "docker-compose.yaml" | "docker-compose.yml"
        | "compose.yaml" | "compose.yml"
        | "docker-compose.override.yaml" | "docker-compose.override.yml"
    ) {
        return true;
    }
    // Kubernetes / Argo / GH Actions workflows — only when in a tell-tale
    // directory. YAML in arbitrary places is too noisy to claim as iac.
    if lower.ends_with(".yaml") || lower.ends_with(".yml") {
        let p = rel.to_string_lossy().replace('\\', "/");
        if p.starts_with("k8s/")
            || p.starts_with("kubernetes/")
            || p.starts_with("helm/")
            || p.starts_with("manifests/")
            || p.starts_with(".github/workflows/")
            || p.contains("/k8s/")
            || p.contains("/kubernetes/")
            || p.contains("/helm/")
        {
            return true;
        }
    }
    false
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
        std::fs::write(&p, body).unwrap();
    }

    #[test]
    fn detects_python_flask_pip_with_entrypoint() {
        let dir = TempDir::new().unwrap();
        write(&dir, "pyproject.toml", r#"
[project]
name = "demo"
dependencies = ["flask>=3.0"]
"#);
        write(&dir, "app/__init__.py", "from flask import Flask\napp = Flask(__name__)\n");
        write(&dir, "app/routes.py", "from app import app\n");

        let ov = analyze(dir.path()).unwrap();
        assert!(ov.languages.contains("python"));
        assert!(ov.languages.contains("toml"));
        assert!(ov.frameworks.contains("flask"));
        assert!(ov.package_managers.contains("pip"));
        assert!(ov.entrypoints.contains("app/__init__.py"));
    }

    #[test]
    fn ignores_target_and_node_modules() {
        let dir = TempDir::new().unwrap();
        write(&dir, "target/debug/main.py", "");
        write(&dir, "node_modules/x/index.js", "");
        write(&dir, "src/keep.py", "");

        let ov = analyze(dir.path()).unwrap();
        assert!(ov.languages.contains("python"));
        // No entrypoints — src/keep.py isn't named like one.
        assert!(ov.entrypoints.is_empty(),
            "expected no entrypoint, got: {:?}", ov.entrypoints);
    }

    #[test]
    fn detects_iac_language_from_terraform_and_dockerfile() {
        let dir = TempDir::new().unwrap();
        write(&dir, "main.tf", "resource \"aws_s3_bucket\" \"b\" {}\n");
        write(&dir, "Dockerfile", "FROM alpine\n");

        let ov = analyze(dir.path()).unwrap();
        assert!(ov.languages.contains("iac"));
    }

    #[test]
    fn yaml_outside_iac_dirs_does_not_trigger() {
        let dir = TempDir::new().unwrap();
        write(&dir, "config/app.yaml", "key: value\n");

        let ov = analyze(dir.path()).unwrap();
        assert!(!ov.languages.contains("iac"));
    }

    #[test]
    fn yaml_in_k8s_dir_triggers() {
        let dir = TempDir::new().unwrap();
        write(&dir, "k8s/deployment.yaml", "kind: Deployment\n");

        let ov = analyze(dir.path()).unwrap();
        assert!(ov.languages.contains("iac"));
    }

    #[test]
    fn detects_php_language_composer_and_framework() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("index.php"), "<?php echo 1;").unwrap();
        std::fs::write(
            dir.path().join("composer.json"),
            r#"{"require":{"laravel/framework":"^11.0"}}"#,
        )
        .unwrap();
        let ov = analyze(dir.path()).unwrap();
        assert!(ov.languages.contains("php"));
        assert!(ov.package_managers.contains("composer"));
        assert!(ov.frameworks.contains("laravel"));
        assert!(ov.entrypoints.iter().any(|e| e.ends_with("index.php")));
    }

    #[test]
    fn detects_multiple_package_managers_and_frameworks() {
        let dir = TempDir::new().unwrap();
        write(&dir, "Cargo.toml", "[dependencies]\naxum = \"0.7\"\n");
        write(&dir, "go.mod", "module x\nrequire github.com/gin-gonic/gin v1.9\n");
        write(&dir, "package.json", r#"{"dependencies": {"express": "^4.18"}}"#);

        let ov = analyze(dir.path()).unwrap();
        assert!(ov.package_managers.contains("cargo"));
        assert!(ov.package_managers.contains("go"));
        assert!(ov.package_managers.contains("npm"));
        assert!(ov.frameworks.contains("axum"));
        assert!(ov.frameworks.contains("gin"));
        assert!(ov.frameworks.contains("express"));
    }
}
