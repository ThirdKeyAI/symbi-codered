//! LanceDB integration for code-chunk / finding / knowledge embeddings.
//!
//! Single collection (`codered_embeddings`) with a `kind` discriminator
//! avoids schema migrations across phases.

use arrow_array::{FixedSizeListArray, RecordBatch, RecordBatchIterator, StringArray};
use arrow_array::types::Float32Type;
use lancedb::{Connection, Table};
use std::sync::Arc;
use thiserror::Error;

pub const COLLECTION: &str = "codered_embeddings";

#[derive(Debug, Error)]
pub enum LanceError {
    #[error("lance: {0}")]
    Lance(String),
    #[error("arrow: {0}")]
    Arrow(String),
}

impl From<lancedb::Error> for LanceError {
    fn from(e: lancedb::Error) -> Self {
        LanceError::Lance(e.to_string())
    }
}
impl From<arrow_schema::ArrowError> for LanceError {
    fn from(e: arrow_schema::ArrowError) -> Self {
        LanceError::Arrow(e.to_string())
    }
}

/// Open or create the LanceDB collection.
pub async fn open(uri: &str, dim: usize) -> Result<(Connection, Table), LanceError> {
    let conn = lancedb::connect(uri).execute().await?;

    let names = conn.table_names().execute().await?;
    if names.contains(&COLLECTION.to_string()) {
        let tbl = conn.open_table(COLLECTION).execute().await?;
        return Ok((conn, tbl));
    }

    let schema = arrow_schema::Schema::new(vec![
        arrow_schema::Field::new("id", arrow_schema::DataType::Utf8, false),
        arrow_schema::Field::new("kind", arrow_schema::DataType::Utf8, false),
        arrow_schema::Field::new("engagement_id", arrow_schema::DataType::Utf8, false),
        arrow_schema::Field::new("text", arrow_schema::DataType::Utf8, false),
        arrow_schema::Field::new(
            "vector",
            arrow_schema::DataType::FixedSizeList(
                Arc::new(arrow_schema::Field::new(
                    "item",
                    arrow_schema::DataType::Float32,
                    true,
                )),
                dim as i32,
            ),
            false,
        ),
    ]);

    let empty = RecordBatch::new_empty(Arc::new(schema.clone()));
    let reader = RecordBatchIterator::new(vec![Ok(empty)].into_iter(), Arc::new(schema));
    let tbl = conn
        .create_table(COLLECTION, Box::new(reader))
        .execute()
        .await?;
    Ok((conn, tbl))
}

pub async fn insert(
    tbl: &Table,
    ids: &[String],
    kinds: &[String],
    engagement_ids: &[String],
    texts: &[String],
    vectors: &[Vec<f32>],
    dim: usize,
) -> Result<(), LanceError> {
    assert_eq!(ids.len(), vectors.len(), "ids/vectors length mismatch");
    let schema = tbl.schema().await?;

    let id_arr = StringArray::from(ids.to_vec());
    let knd_arr = StringArray::from(kinds.to_vec());
    let eng_arr = StringArray::from(engagement_ids.to_vec());
    let txt_arr = StringArray::from(texts.to_vec());

    let vec_arr = FixedSizeListArray::from_iter_primitive::<Float32Type, _, _>(
        vectors
            .iter()
            .map(|v| Some(v.iter().map(|x| Some(*x)).collect::<Vec<_>>())),
        dim as i32,
    );

    let batch = RecordBatch::try_new(
        schema,
        vec![
            Arc::new(id_arr),
            Arc::new(knd_arr),
            Arc::new(eng_arr),
            Arc::new(txt_arr),
            Arc::new(vec_arr),
        ],
    )?;
    let reader =
        RecordBatchIterator::new(vec![Ok(batch.clone())].into_iter(), batch.schema());
    tbl.add(Box::new(reader)).execute().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn open_creates_collection_when_missing() {
        let dir = TempDir::new().unwrap();
        let uri = dir.path().to_str().unwrap();
        let (_c, tbl) = open(uri, 4).await.unwrap();
        // Opening again should reuse, not error.
        let (_c2, _tbl2) = open(uri, 4).await.unwrap();
        assert_eq!(tbl.name(), COLLECTION);
    }

    #[tokio::test]
    async fn insert_two_rows_succeeds() {
        let dir = TempDir::new().unwrap();
        let uri = dir.path().to_str().unwrap();
        let (_c, tbl) = open(uri, 4).await.unwrap();

        insert(
            &tbl,
            &["row-1".into(), "row-2".into()],
            &["code_chunk".into(), "code_chunk".into()],
            &["eng-a".into(), "eng-a".into()],
            &["hello".into(), "world".into()],
            &[vec![1.0, 0.0, 0.0, 0.0], vec![0.0, 1.0, 0.0, 0.0]],
            4,
        )
        .await
        .unwrap();

        let cnt = tbl.count_rows(None).await.unwrap();
        assert_eq!(cnt, 2);
    }
}
