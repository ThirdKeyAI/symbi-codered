//! Per-scanner output parsers. Each module normalizes a scanner's native
//! JSON to a RawFinding shape that static_hunter converts into `Finding`
//! rows with citations.

use serde::{Deserialize, Serialize};

pub mod semgrep;
pub mod bandit;
pub mod pip_audit;
pub mod ruff;
pub mod cargo_audit;
pub mod clippy;
pub mod semgrep_rust;
pub mod eslint;
pub mod npm_audit;
pub mod semgrep_ts;
pub mod gosec;
pub mod govulncheck;
pub mod staticcheck;
pub mod compromised_packages;
pub mod checkov;
pub mod tfsec;
pub mod trivy;
pub mod progpilot;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RawFinding {
    pub tool: String,
    pub rule_id: String,
    pub file_path: String,
    pub line_start: u32,
    pub line_end: u32,
    pub severity: String,
    pub confidence: String,
    pub cwe: Option<String>,
    pub owasp: Option<String>,
    pub title: String,
    pub description: String,
}
