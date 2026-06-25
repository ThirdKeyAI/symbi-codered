//! Ed25519 per-engagement signing (AgentPin substrate).
//!
//! Each engagement gets its own keypair, persisted under `.symbiont/keys/`.
//! The threat-model produced by the specifier agent carries a signature
//! over its canonical JSON; downstream agents verify before referencing
//! `specifier_hash`.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum SigningError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("hex: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("ed25519: {0}")]
    Ed25519(String),
    #[error("key file shape: {0}")]
    Shape(String),
}

pub struct EngagementKeypair {
    pub engagement_id: Uuid,
    pub signing: SigningKey,
    pub verifying: VerifyingKey,
}

impl EngagementKeypair {
    pub fn sign_hex(&self, bytes: &[u8]) -> String {
        let sig: Signature = self.signing.sign(bytes);
        hex::encode(sig.to_bytes())
    }

    pub fn verify_hex(&self, bytes: &[u8], hex_sig: &str) -> Result<(), SigningError> {
        let sig_bytes = hex::decode(hex_sig)?;
        let arr: [u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| SigningError::Shape("signature must be 64 bytes".into()))?;
        let sig = Signature::from_bytes(&arr);
        self.verifying
            .verify(bytes, &sig)
            .map_err(|e| SigningError::Ed25519(e.to_string()))
    }
}

fn keys_dir() -> PathBuf {
    PathBuf::from(".symbiont/keys")
}

pub fn generate_and_persist(engagement_id: Uuid) -> Result<EngagementKeypair, SigningError> {
    let dir = keys_dir();
    generate_and_persist_in(&dir, engagement_id)
}

pub fn load(engagement_id: Uuid) -> Result<EngagementKeypair, SigningError> {
    load_from(&keys_dir(), engagement_id)
}

pub fn load_from(dir: &Path, engagement_id: Uuid) -> Result<EngagementKeypair, SigningError> {
    let priv_hex = fs::read_to_string(dir.join(format!("{engagement_id}.priv")))?;
    let pub_hex  = fs::read_to_string(dir.join(format!("{engagement_id}.pub")))?;
    let priv_bytes = hex::decode(priv_hex.trim())?;
    let pub_bytes  = hex::decode(pub_hex.trim())?;

    let priv_arr: [u8; 32] = priv_bytes
        .as_slice()
        .try_into()
        .map_err(|_| SigningError::Shape("signing key must be 32 bytes".into()))?;
    let pub_arr: [u8; 32] = pub_bytes
        .as_slice()
        .try_into()
        .map_err(|_| SigningError::Shape("verifying key must be 32 bytes".into()))?;

    let signing = SigningKey::from_bytes(&priv_arr);
    let verifying = VerifyingKey::from_bytes(&pub_arr)
        .map_err(|e| SigningError::Ed25519(e.to_string()))?;
    Ok(EngagementKeypair { engagement_id, signing, verifying })
}

pub fn generate_and_persist_in(
    dir: &Path,
    engagement_id: Uuid,
) -> Result<EngagementKeypair, SigningError> {
    fs::create_dir_all(dir)?;

    let mut rng = OsRng;
    let signing = SigningKey::generate(&mut rng);
    let verifying = signing.verifying_key();

    let priv_path = dir.join(format!("{engagement_id}.priv"));
    let pub_path  = dir.join(format!("{engagement_id}.pub"));
    fs::write(&priv_path, hex::encode(signing.to_bytes()))?;
    fs::write(&pub_path, hex::encode(verifying.to_bytes()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&priv_path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&priv_path, perms)?;
    }

    Ok(EngagementKeypair { engagement_id, signing, verifying })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn generate_then_load_yields_identical_keys() {
        let dir = TempDir::new().unwrap();
        let eng = Uuid::new_v4();
        let a = generate_and_persist_in(dir.path(), eng).unwrap();
        let b = load_from(dir.path(), eng).unwrap();
        assert_eq!(a.signing.to_bytes(), b.signing.to_bytes());
        assert_eq!(a.verifying.to_bytes(), b.verifying.to_bytes());
    }

    #[test]
    fn sign_then_verify_succeeds_for_matching_bytes() {
        let dir = TempDir::new().unwrap();
        let eng = Uuid::new_v4();
        let kp = generate_and_persist_in(dir.path(), eng).unwrap();
        let msg = b"canonical threat model JSON";
        let sig = kp.sign_hex(msg);
        kp.verify_hex(msg, &sig).expect("signature must verify");
    }

    #[test]
    fn verify_fails_for_tampered_bytes() {
        let dir = TempDir::new().unwrap();
        let eng = Uuid::new_v4();
        let kp = generate_and_persist_in(dir.path(), eng).unwrap();
        let sig = kp.sign_hex(b"original");
        assert!(kp.verify_hex(b"tampered", &sig).is_err());
    }
}
