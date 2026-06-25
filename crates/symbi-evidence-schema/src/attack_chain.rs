use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KillChainStage {
    SurfaceMapping,
    ToolSubversion,
    InstructionInjection,
    ReasoningCapture,
    GateEvasion,
    PrivilegedAction,
    AuditEvasion,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttackChainNode {
    pub id: String,
    pub engagement_id: Uuid,
    pub stage: KillChainStage,
    pub finding_id: Option<String>,
    pub evidence_id: Option<String>,
    pub next_chain_id: Option<String>,
    pub rationale: String,
    pub created_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&KillChainStage::InstructionInjection).unwrap(),
            "\"instruction_injection\""
        );
    }

    #[test]
    fn attack_chain_node_roundtrip() {
        let n = AttackChainNode {
            id: "AC-0001".into(),
            engagement_id: Uuid::nil(),
            stage: KillChainStage::SurfaceMapping,
            finding_id: Some("F-0001".into()),
            evidence_id: None,
            next_chain_id: Some("AC-0002".into()),
            rationale: "External /users endpoint enumerable".into(),
            created_at: Utc::now(),
        };
        let s = serde_json::to_string(&n).unwrap();
        let back: AttackChainNode = serde_json::from_str(&s).unwrap();
        assert_eq!(n, back);
    }
}
