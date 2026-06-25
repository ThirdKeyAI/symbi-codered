//! Rust-specific semgrep parser. Currently delegates to the language-agnostic
//! `semgrep` parser (semgrep's JSON output shape is identical across
//! languages). Kept as a separate module so Plan F's static_hunter dispatch
//! can wire it independently — if Rust-specific CWE post-processing is
//! needed later, it lands here.

pub use super::semgrep::SemgrepParseError;
pub use super::semgrep::parse;
