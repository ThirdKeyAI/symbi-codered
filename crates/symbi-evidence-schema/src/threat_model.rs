use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Output of the specifier agent. Pinned + signed; every downstream finding
/// references this by `specifier_hash`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ThreatModel {
    pub specifier_hash: String,
    pub engagement_id: Uuid,
    pub canonical_json: String,
    pub signed_at: DateTime<Utc>,
    pub signature: String,
}

impl ThreatModel {
    /// Compute the canonical hash of a JSON payload.
    pub fn hash_for(canonical_json: &str) -> String {
        let mut h = Sha256::new();
        h.update(canonical_json.as_bytes());
        format!("{:x}", h.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_deterministic() {
        let a = ThreatModel::hash_for(r#"{"scope":["src/**"]}"#);
        let b = ThreatModel::hash_for(r#"{"scope":["src/**"]}"#);
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn threat_model_serde_roundtrip() {
        let json = r#"{"scope":["src/**"]}"#;
        let tm = ThreatModel {
            specifier_hash: ThreatModel::hash_for(json),
            engagement_id: Uuid::nil(),
            canonical_json: json.into(),
            signed_at: Utc::now(),
            signature: "ed25519-placeholder".into(),
        };
        let s = serde_json::to_string(&tm).unwrap();
        let back: ThreatModel = serde_json::from_str(&s).unwrap();
        assert_eq!(tm, back);
    }
}
