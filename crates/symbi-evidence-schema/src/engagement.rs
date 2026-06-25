use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Engagement {
    pub id: Uuid,
    pub client: String,
    pub scope_hash: String,
    pub start_date: String,
    pub end_date: String,
    pub status: EngagementStatus,
    pub roa_hash: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EngagementStatus {
    Planning,
    Running,
    Complete,
    Failed,
}

impl Engagement {
    /// Create a fresh engagement with a new UUID and `created_at = now`.
    pub fn new(
        client: impl Into<String>,
        scope_hash: impl Into<String>,
        start_date: impl Into<String>,
        end_date: impl Into<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            client: client.into(),
            scope_hash: scope_hash.into(),
            start_date: start_date.into(),
            end_date: end_date.into(),
            status: EngagementStatus::Planning,
            roa_hash: None,
            created_at: Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engagement_serde_roundtrip() {
        let e = Engagement::new("acme", "deadbeef", "2026-05-22", "2026-05-29");
        let s = serde_json::to_string(&e).unwrap();
        let back: Engagement = serde_json::from_str(&s).unwrap();
        assert_eq!(e, back);
        assert_eq!(back.status, EngagementStatus::Planning);
    }

    #[test]
    fn status_serializes_snake_case() {
        let s = serde_json::to_string(&EngagementStatus::Complete).unwrap();
        assert_eq!(s, "\"complete\"");
    }
}
