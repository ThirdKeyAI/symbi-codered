use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HypothesisStatus {
    Proposed,
    PocAttempted,
    Reproduced,
    Refuted,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Hypothesis {
    pub id: String,
    pub engagement_id: Uuid,
    pub description: String,
    pub status: HypothesisStatus,
    pub created_by_agent: String,
    pub created_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hypothesis_serde_roundtrip() {
        let h = Hypothesis {
            id: "H-0001".into(),
            engagement_id: Uuid::nil(),
            description: "SQLi via sort param".into(),
            status: HypothesisStatus::Proposed,
            created_by_agent: "pattern_scout".into(),
            created_at: Utc::now(),
        };
        let s = serde_json::to_string(&h).unwrap();
        let back: Hypothesis = serde_json::from_str(&s).unwrap();
        assert_eq!(h, back);
        assert!(s.contains(r#""status":"proposed""#));
    }

    #[test]
    fn status_variants_serialize_snake_case() {
        assert_eq!(
            serde_json::to_string(&HypothesisStatus::PocAttempted).unwrap(),
            "\"poc_attempted\""
        );
    }
}
