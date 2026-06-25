//! recall_journal — episodic-memory substrate for the cartographer +
//! later agents. Indexes the JSONL audit journal into LanceDB, then
//! answers natural-language queries with the most relevant past entries.

use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;
use uuid::Uuid;

use symbi_codered_core::audit::AuditEntry;
use symbi_codered_core::embeddings::EmbeddingProvider;
use symbi_codered_core::lance::{self, LanceError};

#[derive(Debug, Error)]
pub enum RecallError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("lance: {0}")]
    Lance(#[from] LanceError),
    #[error("embedding: {0}")]
    Embedding(#[from] symbi_codered_core::embeddings::EmbeddingError),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JournalHit {
    pub entry_hash: String,
    pub principal: String,
    pub action: String,
    pub resource: String,
    pub cedar_decision: String,
    pub envelope_id: Option<String>,
    pub timestamp: String,
}

pub async fn index_journal(
    lance_uri: &str,
    engagement_id: Uuid,
    journal_path: &Path,
    embedder: &dyn EmbeddingProvider,
) -> Result<usize, RecallError> {
    if !journal_path.exists() {
        return Ok(0);
    }
    let body = std::fs::read_to_string(journal_path)?;
    let entries: Vec<AuditEntry> = body
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    if entries.is_empty() {
        return Ok(0);
    }

    let dim = embedder.dim();
    let (_conn, tbl) = lance::open(lance_uri, dim).await?;

    let texts: Vec<String> = entries
        .iter()
        .map(|e| format!("{} {} {} {}", e.principal, e.action, e.resource, e.cedar_decision))
        .collect();
    let vectors = embedder.encode(&texts)?;

    let ids: Vec<String> = entries.iter().map(|e| e.entry_hash.clone()).collect();
    let kinds: Vec<String> = entries.iter().map(|_| "journal".to_string()).collect();
    let eng_ids: Vec<String> = entries.iter().map(|_| engagement_id.to_string()).collect();
    let payload_texts: Vec<String> = entries
        .iter()
        .map(|e| serde_json::to_string(e).unwrap_or_default())
        .collect();

    lance::insert(&tbl, &ids, &kinds, &eng_ids, &payload_texts, &vectors, dim).await?;
    Ok(entries.len())
}

pub async fn recall(
    lance_uri: &str,
    engagement_id: Uuid,
    query: &str,
    k: usize,
    embedder: &dyn EmbeddingProvider,
) -> Result<Vec<JournalHit>, RecallError> {
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
            "kind = 'journal' AND engagement_id = '{}'",
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
            let payload = text_arr.value(i);
            let entry: AuditEntry = serde_json::from_str(payload)?;
            hits.push(JournalHit {
                entry_hash: id_arr.value(i).to_string(),
                principal: entry.principal,
                action: entry.action,
                resource: entry.resource,
                cedar_decision: entry.cedar_decision,
                envelope_id: entry.envelope_id,
                timestamp: entry.timestamp.to_rfc3339(),
            });
        }
    }
    Ok(hits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use symbi_codered_core::audit::append_entry;
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

    #[tokio::test]
    async fn empty_journal_path_returns_zero() {
        let lance_dir = TempDir::new().unwrap();
        let n = index_journal(
            lance_dir.path().to_str().unwrap(),
            Uuid::new_v4(),
            Path::new("/nonexistent"),
            &HashEmbedder { dim: 16 },
        )
        .await
        .unwrap();
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn index_then_recall_returns_relevant_entry() {
        let dir = TempDir::new().unwrap();
        let journal = dir.path().join("audit.jsonl");
        append_entry(
            &journal,
            "cartographer",
            "list_routes",
            "Audit::RepoIntel",
            "permit",
            None,
        )
        .unwrap();
        append_entry(
            &journal,
            "cartographer",
            "extract_symbols",
            "Audit::RepoIntel",
            "permit",
            None,
        )
        .unwrap();
        append_entry(
            &journal,
            "cartographer",
            "scan_dependencies",
            "Audit::RepoIntel",
            "permit",
            None,
        )
        .unwrap();

        let lance_dir = TempDir::new().unwrap();
        let embedder = HashEmbedder { dim: 16 };
        let eng = Uuid::new_v4();
        let n = index_journal(
            lance_dir.path().to_str().unwrap(),
            eng,
            &journal,
            &embedder,
        )
        .await
        .unwrap();
        assert_eq!(n, 3);

        let hits = recall(
            lance_dir.path().to_str().unwrap(),
            eng,
            "scan_dependencies",
            3,
            &embedder,
        )
        .await
        .unwrap();
        assert!(!hits.is_empty());
        assert!(hits.iter().any(|h| h.action == "scan_dependencies"));
    }
}
