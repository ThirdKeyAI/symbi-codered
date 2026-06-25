//! Hash-chained JSONL audit journal — every Cedar decision and tool
//! invocation is appended with the previous entry's hash, producing a
//! tamper-evident chain.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("chain broken at entry {0}")]
    Broken(usize),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEntry {
    pub timestamp: DateTime<Utc>,
    pub principal: String,         // agent name (e.g., "audit-controller")
    pub action: String,            // "execute_tool" | "store_finding" | ...
    pub resource: String,          // tool name | path | resource id
    pub cedar_decision: String,    // "permit" | "deny" | "error" (scanner/tool errored after permit)
    pub envelope_id: Option<String>,
    pub prev_hash: String,         // 64 hex chars; "0".repeat(64) for genesis
    pub entry_hash: String,        // sha256(prev_hash || canonical_json_of_this_entry_minus_hash)
}

/// Compute the hash for a `next` entry whose `prev_hash` is already set.
fn compute_entry_hash(prev_hash: &str, entry_without_hash: &AuditEntry) -> String {
    let mut clone = entry_without_hash.clone();
    clone.entry_hash = String::new();
    let body = serde_json::to_string(&clone).unwrap();
    let mut h = Sha256::new();
    h.update(prev_hash.as_bytes());
    h.update(b"|");
    h.update(body.as_bytes());
    format!("{:x}", h.finalize())
}

/// Append one entry to the journal file at `path`. Reads the last line to
/// chain on top of it. Returns the newly-written entry.
pub fn append_entry(
    path: impl AsRef<Path>,
    principal: impl Into<String>,
    action: impl Into<String>,
    resource: impl Into<String>,
    cedar_decision: impl Into<String>,
    envelope_id: Option<String>,
) -> Result<AuditEntry, AuditError> {
    let prev_hash = read_last_hash(path.as_ref())?;
    let mut entry = AuditEntry {
        timestamp: Utc::now(),
        principal: principal.into(),
        action: action.into(),
        resource: resource.into(),
        cedar_decision: cedar_decision.into(),
        envelope_id,
        prev_hash: prev_hash.clone(),
        entry_hash: String::new(),
    };
    entry.entry_hash = compute_entry_hash(&prev_hash, &entry);

    let f = OpenOptions::new().create(true).append(true).open(path)?;
    let mut w = BufWriter::new(f);
    serde_json::to_writer(&mut w, &entry)?;
    w.write_all(b"\n")?;
    w.flush()?;
    Ok(entry)
}

fn read_last_hash(path: &Path) -> Result<String, AuditError> {
    if !path.exists() {
        return Ok("0".repeat(64));
    }
    let bytes = std::fs::read(path)?;
    if bytes.is_empty() {
        return Ok("0".repeat(64));
    }
    let s = String::from_utf8_lossy(&bytes);
    let last = s.lines().rfind(|l| !l.trim().is_empty());
    match last {
        None => Ok("0".repeat(64)),
        Some(line) => {
            let e: AuditEntry = serde_json::from_str(line)?;
            Ok(e.entry_hash)
        }
    }
}

/// Verify the chain integrity of a journal file. Returns Ok(n) where
/// n is the number of validated entries.
pub fn verify_chain(path: impl AsRef<Path>) -> Result<usize, AuditError> {
    let bytes = std::fs::read(path.as_ref())?;
    if bytes.is_empty() {
        return Ok(0);
    }
    let s = String::from_utf8_lossy(&bytes);
    let mut prev = "0".repeat(64);
    let mut n = 0;
    for (i, line) in s.lines().enumerate() {
        if line.trim().is_empty() { continue; }
        let entry: AuditEntry = serde_json::from_str(line)?;
        if entry.prev_hash != prev {
            return Err(AuditError::Broken(i));
        }
        let expected = compute_entry_hash(&entry.prev_hash, &entry);
        if entry.entry_hash != expected {
            return Err(AuditError::Broken(i));
        }
        prev = entry.entry_hash;
        n += 1;
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn first_entry_uses_genesis_prev_hash() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let e = append_entry(&path, "audit-controller", "execute_tool",
                             "repo_overview", "permit", None).unwrap();
        assert_eq!(e.prev_hash, "0".repeat(64));
    }

    #[test]
    fn chain_links_across_entries() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let a = append_entry(&path, "a", "x", "r", "permit", None).unwrap();
        let b = append_entry(&path, "a", "y", "r", "permit", None).unwrap();
        assert_eq!(b.prev_hash, a.entry_hash);
    }

    #[test]
    fn verify_validates_three_entries() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        append_entry(&path, "p", "a", "r1", "permit", None).unwrap();
        append_entry(&path, "p", "a", "r2", "permit", None).unwrap();
        append_entry(&path, "p", "a", "r3", "deny", None).unwrap();
        assert_eq!(verify_chain(&path).unwrap(), 3);
    }

    #[test]
    fn tampering_breaks_chain() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        append_entry(&path, "p", "a", "r1", "permit", None).unwrap();
        append_entry(&path, "p", "a", "r2", "permit", None).unwrap();

        let s = std::fs::read_to_string(&path).unwrap();
        let tampered = s.replace("permit", "PERMIT"); // changes hash input
        std::fs::write(&path, tampered).unwrap();

        assert!(matches!(verify_chain(&path), Err(AuditError::Broken(_))));
    }
}
