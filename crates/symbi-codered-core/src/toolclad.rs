//! Minimal ToolClad manifest validator (Plan A scope).
//!
//! Parses `.clad.toml` into structured types and runs a small set of
//! structural checks. Full custom-type validation against
//! `toolclad.toml` lands in Plan B.

use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ToolCladError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("toml: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("manifest invalid: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolManifest {
    pub tool: ToolMeta,
    pub command: CommandTemplate,
    #[serde(default)]
    pub output: OutputSpec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolMeta {
    pub name: String,
    pub version: String,
    pub binary: String,
    pub description: String,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
    pub risk_tier: String,
    pub cedar: CedarMeta,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CedarMeta {
    pub resource: String,
    pub action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandTemplate {
    pub template: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OutputSpec {
    #[serde(default)]
    pub format: Option<String>,
    #[serde(default)]
    pub parser: Option<String>,
    #[serde(default)]
    pub envelope: bool,
}

fn default_timeout() -> u64 {
    300
}

pub fn parse(path: impl AsRef<Path>) -> Result<ToolManifest, ToolCladError> {
    let bytes = std::fs::read_to_string(path.as_ref())?;
    let m: ToolManifest = toml::from_str(&bytes)?;
    validate(&m)?;
    Ok(m)
}

pub fn parse_dir(dir: impl AsRef<Path>) -> Result<Vec<(String, ToolManifest)>, ToolCladError> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir.as_ref())? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("toml") {
            continue;
        }
        if !path
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n.ends_with(".clad.toml"))
            .unwrap_or(false)
        {
            continue;
        }
        let manifest = parse(&path)?;
        out.push((path.display().to_string(), manifest));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

fn validate(m: &ToolManifest) -> Result<(), ToolCladError> {
    if m.tool.name.is_empty() {
        return Err(ToolCladError::Invalid("tool.name is empty".into()));
    }
    if !["low", "medium", "high", "critical"].contains(&m.tool.risk_tier.as_str()) {
        return Err(ToolCladError::Invalid(format!(
            "tool.risk_tier must be low/medium/high/critical; got {}",
            m.tool.risk_tier
        )));
    }
    if m.command.template.is_empty() {
        return Err(ToolCladError::Invalid("command.template is empty".into()));
    }
    if m.tool.cedar.resource.is_empty() || m.tool.cedar.action.is_empty() {
        return Err(ToolCladError::Invalid(
            "tool.cedar.resource/action required".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write(dir: &TempDir, name: &str, body: &str) -> std::path::PathBuf {
        let p = dir.path().join(name);
        std::fs::write(&p, body).unwrap();
        p
    }

    const VALID_BODY: &str = r#"
[tool]
name = "repo_overview"
version = "1.0.0"
binary = "codered"
description = "Repo intelligence overview"
timeout_seconds = 60
risk_tier = "low"

[tool.cedar]
resource = "Audit::RepoIntel"
action   = "execute_tool"

[command]
template = "codered tools repo_overview"

[output]
format = "json"
parser = "builtin:json"
envelope = true
"#;

    #[test]
    fn parses_valid_manifest() {
        let dir = TempDir::new().unwrap();
        let p = write(&dir, "x.clad.toml", VALID_BODY);
        let m = parse(&p).unwrap();
        assert_eq!(m.tool.name, "repo_overview");
        assert_eq!(m.tool.risk_tier, "low");
        assert!(m.output.envelope);
    }

    #[test]
    fn rejects_invalid_risk_tier() {
        let dir = TempDir::new().unwrap();
        let body = VALID_BODY.replace(r#"risk_tier = "low""#, r#"risk_tier = "EXTREME""#);
        let p = write(&dir, "x.clad.toml", &body);
        match parse(&p) {
            Err(ToolCladError::Invalid(msg)) => assert!(msg.contains("risk_tier")),
            other => panic!("expected Invalid err, got {other:?}"),
        }
    }

    #[test]
    fn parse_dir_only_picks_clad_toml() {
        let dir = TempDir::new().unwrap();
        write(&dir, "a.clad.toml", VALID_BODY);
        write(&dir, "b.clad.toml", VALID_BODY);
        write(&dir, "ignore.toml", VALID_BODY);
        write(&dir, "notes.md", "");
        let out = parse_dir(dir.path()).unwrap();
        assert_eq!(out.len(), 2);
    }
}
