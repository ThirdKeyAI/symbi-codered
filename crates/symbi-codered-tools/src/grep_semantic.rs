//! grep_semantic — semantic code search.
//!
//! Embeds chunks (Task 10) with the configured EmbeddingProvider and
//! inserts them into the shared LanceDB collection with kind="code_chunk".
//! Queries embed the natural-language query the same way and return the
//! top-K most similar chunks.

use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;
use uuid::Uuid;

use symbi_codered_core::embeddings::EmbeddingProvider;
use symbi_codered_core::lance::{self, LanceError};

use crate::chunker::{chunk_repo, Chunk, ChunkerError};

#[derive(Debug, Error)]
pub enum GrepSemanticError {
    #[error("chunker: {0}")]
    Chunker(#[from] ChunkerError),
    #[error("lance: {0}")]
    Lance(#[from] LanceError),
    #[error("embedding: {0}")]
    Embedding(#[from] symbi_codered_core::embeddings::EmbeddingError),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GrepHit {
    pub chunk_id: String,
    pub file_path: String,
    pub line_start: u32,
    pub line_end: u32,
    pub symbol_name: Option<String>,
    pub text: String,
}

pub async fn index_repo(
    lance_uri: &str,
    engagement_id: Uuid,
    root: &Path,
    embedder: &dyn EmbeddingProvider,
) -> Result<usize, GrepSemanticError> {
    let chunks = chunk_repo(root)?;
    if chunks.is_empty() {
        return Ok(0);
    }

    let dim = embedder.dim();
    let (_conn, tbl) = lance::open(lance_uri, dim).await?;

    let texts: Vec<String> = chunks.iter().map(|c| c.text.clone()).collect();
    let vectors = embedder.encode(&texts)?;

    let ids: Vec<String> = chunks.iter().map(|c| c.id.clone()).collect();
    let kinds: Vec<String> = chunks.iter().map(|_| "code_chunk".to_string()).collect();
    let eng_ids: Vec<String> = chunks.iter().map(|_| engagement_id.to_string()).collect();
    let texts_for_insert: Vec<String> = chunks
        .iter()
        .map(|c| serde_json::to_string(&ChunkMeta::from(c)).unwrap_or_default())
        .collect();

    lance::insert(&tbl, &ids, &kinds, &eng_ids, &texts_for_insert, &vectors, dim).await?;
    Ok(chunks.len())
}

pub async fn query(
    lance_uri: &str,
    engagement_id: Uuid,
    query: &str,
    k: usize,
    embedder: &dyn EmbeddingProvider,
) -> Result<Vec<GrepHit>, GrepSemanticError> {
    let dim = embedder.dim();
    let (_conn, tbl) = lance::open(lance_uri, dim).await?;
    let q_vec = embedder
        .encode(&[query.to_string()])?
        .into_iter()
        .next()
        .unwrap_or_default();

    use futures::TryStreamExt;
    use lancedb::query::{ExecutableQuery, QueryBase};

    let mut stream = tbl
        .query()
        .nearest_to(q_vec)
        .map_err(LanceError::from)?
        .only_if(format!(
            "kind = 'code_chunk' AND engagement_id = '{}'",
            engagement_id
        ))
        .limit(k)
        .execute()
        .await
        .map_err(LanceError::from)?;

    let mut hits = Vec::new();
    while let Some(batch) = stream.try_next().await.map_err(LanceError::from)? {
        let id_col = batch.column_by_name("id").unwrap();
        let text_col = batch.column_by_name("text").unwrap();
        let id_arr = id_col
            .as_any()
            .downcast_ref::<arrow_array::StringArray>()
            .expect("id is utf8");
        let text_arr = text_col
            .as_any()
            .downcast_ref::<arrow_array::StringArray>()
            .expect("text is utf8");
        for i in 0..batch.num_rows() {
            let id = id_arr.value(i).to_string();
            let meta_json = text_arr.value(i);
            let meta: ChunkMeta = serde_json::from_str(meta_json).unwrap_or_default();
            hits.push(GrepHit {
                chunk_id: id,
                file_path: meta.file_path,
                line_start: meta.line_start,
                line_end: meta.line_end,
                symbol_name: meta.symbol_name,
                text: meta.text,
            });
        }
    }
    Ok(hits)
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ChunkMeta {
    file_path: String,
    line_start: u32,
    line_end: u32,
    symbol_name: Option<String>,
    text: String,
}

impl From<&Chunk> for ChunkMeta {
    fn from(c: &Chunk) -> Self {
        Self {
            file_path: c.file_path.clone(),
            line_start: c.line_start,
            line_end: c.line_end,
            symbol_name: c.symbol_name.clone(),
            text: c.text.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use symbi_codered_core::embeddings::{Embedding, EmbeddingError, EmbeddingProvider};
    use tempfile::TempDir;

    struct HashEmbedder {
        dim: usize,
    }
    impl EmbeddingProvider for HashEmbedder {
        fn dim(&self) -> usize {
            self.dim
        }
        fn id(&self) -> &str {
            "test:hash"
        }
        fn encode(&self, texts: &[String]) -> Result<Vec<Embedding>, EmbeddingError> {
            Ok(texts
                .iter()
                .map(|t| {
                    let mut v = vec![0.0_f32; self.dim];
                    for (i, b) in t.bytes().enumerate().take(self.dim) {
                        v[i] = f32::from(b) / 255.0;
                    }
                    v
                })
                .collect())
        }
    }

    fn write(dir: &TempDir, rel: &str, body: &str) {
        let p = dir.path().join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
    }

    #[tokio::test]
    async fn index_and_query_roundtrip() {
        let repo = TempDir::new().unwrap();
        write(&repo, "app/users.py", "def delete_user(uid):\n    pass\n");
        write(&repo, "app/render.py", "def render_markdown(s):\n    pass\n");

        let lance_dir = TempDir::new().unwrap();
        let embedder = HashEmbedder { dim: 16 };
        let eng = Uuid::new_v4();
        let n = index_repo(
            lance_dir.path().to_str().unwrap(),
            eng,
            repo.path(),
            &embedder,
        )
        .await
        .unwrap();
        assert_eq!(n, 2);

        let hits = query(
            lance_dir.path().to_str().unwrap(),
            eng,
            "delete_user(uid)",
            2,
            &embedder,
        )
        .await
        .unwrap();
        assert!(!hits.is_empty(), "expected at least 1 hit");
        let top = &hits[0];
        assert!(
            top.text.contains("delete_user"),
            "top hit should mention delete_user; got: {top:?}"
        );
    }

    #[tokio::test]
    async fn index_empty_repo_returns_zero() {
        let repo = TempDir::new().unwrap();
        let lance_dir = TempDir::new().unwrap();
        let embedder = HashEmbedder { dim: 16 };
        let n = index_repo(
            lance_dir.path().to_str().unwrap(),
            Uuid::new_v4(),
            repo.path(),
            &embedder,
        )
        .await
        .unwrap();
        assert_eq!(n, 0);
    }
}
