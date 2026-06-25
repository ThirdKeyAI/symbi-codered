pub mod provider;
pub mod local;

pub use provider::{EmbeddingProvider, EmbeddingError, Embedding};
pub use local::LocalEmbedder;
