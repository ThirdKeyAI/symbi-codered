use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Finding {
    pub id: String,                   // e.g. "F-0124" (engagement-scoped sequence)
    pub engagement_id: Uuid,
    pub phase: Phase,
    pub severity: Severity,
    pub confidence: Confidence,
    pub cwe: Option<String>,          // "CWE-89"
    pub owasp: Option<String>,        // "A03:2021"
    pub file_path: String,
    pub line_start: u32,
    pub line_end: u32,
    pub title: String,
    pub description: String,
    pub reachable: Option<bool>,
    pub exploitable: Option<bool>,
    pub evidence_envelope_id: String, // required — Cedar evidence.cedar enforces non-empty
    pub status: Status,
    pub rank_score: Option<f64>,
    #[serde(default)]
    pub specifier_hash: Option<String>,
    #[serde(default)]
    pub advocate_verdict: Option<AdvocateVerdict>,
    #[serde(default)]
    pub tool_origin: Option<String>,
    #[serde(default)]
    pub poc_status: Option<PocStatus>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Phase { RepoIntel, Sast, Deps, Secrets, Config, Triage }

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity { Info, Low, Medium, High, Critical }

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Confidence { Low, Medium, High }

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Open,
    /// Downgraded when a poc_forge reproducer attempt failed. The finding
    /// is preserved as a hypothesis to be retried (e.g., by a future
    /// reproducer with better prompting or new context), but is excluded
    /// from the redteam handoff.
    Hypothesis,
    Duplicate,
    FalsePositive,
    Triaged,
    HandedOff,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AdvocateVerdict {
    Confirmed,
    Rebutted,
    Uncertain,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PocStatus {
    Hypothesis,
    PocAttempted,
    Reproduced,
    Refuted,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Finding {
        Finding {
            id: "F-0001".into(),
            engagement_id: Uuid::nil(),
            phase: Phase::Sast,
            severity: Severity::High,
            confidence: Confidence::High,
            cwe: Some("CWE-89".into()),
            owasp: Some("A03:2021".into()),
            file_path: "src/users.py".into(),
            line_start: 88,
            line_end: 88,
            title: "SQL injection via sort parameter".into(),
            description: "Untrusted sort value reaches cursor.execute".into(),
            reachable: Some(true),
            exploitable: None,
            evidence_envelope_id: "S-001-semgrep-deadbeef0000".into(),
            status: Status::Open,
            rank_score: Some(0.92),
            specifier_hash: None,
            advocate_verdict: None,
            tool_origin: None,
            poc_status: None,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn finding_serde_roundtrip() {
        let f = sample();
        let s = serde_json::to_string(&f).unwrap();
        let back: Finding = serde_json::from_str(&s).unwrap();
        assert_eq!(f, back);
    }

    #[test]
    fn severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn enum_variants_serialize_as_documented() {
        assert_eq!(serde_json::to_string(&Severity::Critical).unwrap(), "\"critical\"");
        assert_eq!(serde_json::to_string(&Confidence::High).unwrap(), "\"high\"");
        assert_eq!(serde_json::to_string(&Status::FalsePositive).unwrap(), "\"false_positive\"");
        assert_eq!(serde_json::to_string(&Phase::RepoIntel).unwrap(), "\"repo_intel\"");
    }
}
