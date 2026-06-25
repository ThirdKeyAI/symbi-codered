use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// One row in the `evidence` table — the canonical record of a tool's output.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Evidence {
    pub envelope_id: String,
    pub sha256: String,
    pub path: String,           // filesystem path relative to evidence_dir
    pub content_type: String,   // "application/json", "application/sarif+json", etc.
    pub created_at: DateTime<Utc>,
}

/// In-memory carrier for a tool's raw bytes BEFORE persistence.
#[derive(Debug, Clone)]
pub struct EvidenceEnvelope {
    pub scan_id: String,        // engagement-scoped scan sequence (e.g. "S-001")
    pub tool: String,           // "semgrep", "bandit", ...
    pub content_type: String,
    pub bytes: Vec<u8>,
}

impl EvidenceEnvelope {
    /// Compute the canonical envelope_id: `<scan_id>-<tool>-<sha256[:12]>`.
    pub fn envelope_id(&self) -> String {
        let hash = hex_sha256(&self.bytes);
        format!("{}-{}-{}", self.scan_id, self.tool, &hash[..12])
    }

    /// Full SHA-256 of the payload bytes, lowercase hex.
    pub fn sha256(&self) -> String {
        hex_sha256(&self.bytes)
    }
}

/// Lowercase hex-encoded SHA-256.
pub fn hex_sha256(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    format!("{:x}", h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_id_is_deterministic_and_truncated() {
        let env = EvidenceEnvelope {
            scan_id: "S-001".into(),
            tool: "semgrep".into(),
            content_type: "application/json".into(),
            bytes: br#"{"findings": []}"#.to_vec(),
        };
        let id = env.envelope_id();
        assert!(id.starts_with("S-001-semgrep-"));
        // Total prefix "S-001-semgrep-" is 14 chars; expected total = 14 + 12 = 26.
        assert_eq!(id.len(), "S-001-semgrep-".len() + 12);

        // Stable across calls
        assert_eq!(id, env.envelope_id());
    }

    #[test]
    fn sha256_matches_known_value() {
        // sha256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        assert_eq!(hex_sha256(b"hello"),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    }

    #[test]
    fn evidence_serde_roundtrip() {
        let e = Evidence {
            envelope_id: "S-001-bandit-abc123abc123".into(),
            sha256: "ff".repeat(32),
            path: "evidence/S-001-bandit-abc123abc123.json".into(),
            content_type: "application/json".into(),
            created_at: Utc::now(),
        };
        let s = serde_json::to_string(&e).unwrap();
        let back: Evidence = serde_json::from_str(&s).unwrap();
        assert_eq!(e, back);
    }
}
