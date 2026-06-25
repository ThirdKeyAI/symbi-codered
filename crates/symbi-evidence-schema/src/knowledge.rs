use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Subject-predicate-object triple written only by the `reflector` agent.
///
/// Example: `("flask_app", "uses_orm", "sqlalchemy", confidence=0.95)`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KnowledgeTriple {
    pub id: Uuid,
    pub engagement_id: Uuid,
    pub subject: String,
    pub predicate: String,
    pub object: String,
    pub confidence: f64,           // [0.0, 1.0]
    pub created_at: DateTime<Utc>,
}

impl KnowledgeTriple {
    pub fn new(
        engagement_id: Uuid,
        subject: impl Into<String>,
        predicate: impl Into<String>,
        object: impl Into<String>,
        confidence: f64,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            engagement_id,
            subject: subject.into(),
            predicate: predicate.into(),
            object: object.into(),
            confidence: confidence.clamp(0.0, 1.0),
            created_at: Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn knowledge_clamps_confidence() {
        let t = KnowledgeTriple::new(Uuid::nil(), "a", "b", "c", 2.5);
        assert!((t.confidence - 1.0).abs() < f64::EPSILON);

        let t = KnowledgeTriple::new(Uuid::nil(), "a", "b", "c", -0.5);
        assert!(t.confidence.abs() < f64::EPSILON);
    }

    #[test]
    fn knowledge_serde_roundtrip() {
        let t = KnowledgeTriple::new(Uuid::nil(), "subj", "pred", "obj", 0.75);
        let s = serde_json::to_string(&t).unwrap();
        let back: KnowledgeTriple = serde_json::from_str(&s).unwrap();
        assert_eq!(t.subject,    back.subject);
        assert_eq!(t.predicate,  back.predicate);
        assert_eq!(t.object,     back.object);
        assert!((t.confidence - back.confidence).abs() < f64::EPSILON);
    }
}
