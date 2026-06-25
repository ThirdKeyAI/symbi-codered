use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaintHop {
    pub file_path: String,
    pub line: u32,
    pub propagation_reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaintChain {
    pub id: String,
    pub engagement_id: Uuid,
    pub source_file: String,
    pub source_line: u32,
    pub sink_file: String,
    pub sink_line: u32,
    pub chain: Vec<TaintHop>,
    pub sanitizers_seen: Vec<String>,
    pub created_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn taint_chain_serde_roundtrip() {
        let c = TaintChain {
            id: "T-0001".into(),
            engagement_id: Uuid::nil(),
            source_file: "users.py".into(),
            source_line: 31,
            sink_file: "users.py".into(),
            sink_line: 88,
            chain: vec![
                TaintHop { file_path: "users.py".into(), line: 44, propagation_reason: "param read".into() },
                TaintHop { file_path: "users.py".into(), line: 71, propagation_reason: "string concat".into() },
                TaintHop { file_path: "users.py".into(), line: 88, propagation_reason: "cursor.execute".into() },
            ],
            sanitizers_seen: vec![],
            created_at: Utc::now(),
        };
        let s = serde_json::to_string(&c).unwrap();
        let back: TaintChain = serde_json::from_str(&s).unwrap();
        assert_eq!(c, back);
        assert_eq!(back.chain.len(), 3);
    }
}
