//! Local CPU embeddings via fastembed (bge-small-en-v1.5).
//!
//! First use downloads the ONNX model (~130 MB) to the cache dir. This
//! cache is bind-mounted from the host in production to avoid repeated
//! downloads.

use super::provider::{Embedding, EmbeddingError, EmbeddingProvider};
use fastembed::{EmbeddingModel, InitOptions, TextEmbedding};
use std::sync::Mutex;

pub struct LocalEmbedder {
    inner: Mutex<TextEmbedding>,
    dim: usize,
    id: String,
}

impl LocalEmbedder {
    /// Initialize with bge-small-en-v1.5 (384 dims).
    pub fn new() -> Result<Self, EmbeddingError> {
        let model = TextEmbedding::try_new(
            InitOptions::new(EmbeddingModel::BGESmallENV15),
        ).map_err(|e| EmbeddingError::Backend(e.to_string()))?;
        Ok(Self {
            inner: Mutex::new(model),
            dim: 384,
            id: "local:bge-small-en-v1.5".to_string(),
        })
    }
}

impl EmbeddingProvider for LocalEmbedder {
    fn dim(&self) -> usize { self.dim }
    fn id(&self) -> &str { &self.id }
    fn encode(&self, texts: &[String]) -> Result<Vec<Embedding>, EmbeddingError> {
        let guard = self.inner.lock().unwrap();
        let out = guard.embed(texts.to_vec(), None)
            .map_err(|e| EmbeddingError::Backend(e.to_string()))?;
        for v in &out {
            if v.len() != self.dim {
                return Err(EmbeddingError::Dimension { expected: self.dim, got: v.len() });
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Downloads ~130 MB on first run. Ignored by default; run with:
    ///   cargo test -p symbi-codered-core -- --ignored
    #[test]
    #[ignore]
    fn bge_small_returns_384_dim_vectors() {
        let p = LocalEmbedder::new().expect("model init");
        let out = p.encode(&["hello world".into(), "second".into()]).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].len(), 384);
        assert_eq!(p.id(), "local:bge-small-en-v1.5");
    }
}
