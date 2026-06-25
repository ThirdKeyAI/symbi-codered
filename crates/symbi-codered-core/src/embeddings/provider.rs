use thiserror::Error;

pub type Embedding = Vec<f32>;

#[derive(Debug, Error)]
pub enum EmbeddingError {
    #[error("embedding backend: {0}")]
    Backend(String),
    #[error("dimension mismatch: expected {expected}, got {got}")]
    Dimension { expected: usize, got: usize },
}

pub trait EmbeddingProvider: Send + Sync {
    /// Length of each returned embedding vector.
    fn dim(&self) -> usize;

    /// Identifier (e.g. "local:bge-small-en-v1.5", "ollama:nomic-embed-text").
    fn id(&self) -> &str;

    /// Encode a batch of texts. Output length MUST equal `texts.len()`,
    /// and each embedding MUST have `self.dim()` elements.
    fn encode(&self, texts: &[String]) -> Result<Vec<Embedding>, EmbeddingError>;
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    pub struct FixedProvider {
        pub dim: usize,
        pub id: String,
    }
    impl EmbeddingProvider for FixedProvider {
        fn dim(&self) -> usize { self.dim }
        fn id(&self)  -> &str  { &self.id }
        fn encode(&self, texts: &[String]) -> Result<Vec<Embedding>, EmbeddingError> {
            Ok(texts.iter().map(|_| vec![0.42; self.dim]).collect())
        }
    }

    #[test]
    fn fixed_provider_satisfies_contract() {
        let p = FixedProvider { dim: 4, id: "fixed:4".into() };
        let v = p.encode(&["a".into(), "b".into()]).unwrap();
        assert_eq!(v.len(), 2);
        assert!(v.iter().all(|e| e.len() == 4));
        assert_eq!(p.id(), "fixed:4");
    }
}
