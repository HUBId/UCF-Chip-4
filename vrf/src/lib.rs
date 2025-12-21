#![forbid(unsafe_code)]

use blake3::Hasher;
use ed25519_dalek::{Signer, SigningKey};
use rand_core::OsRng;
use sha2::{Digest, Sha512};
use thiserror::Error;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Domain separation tag for experience record VRF preimages.
const RECORD_VRF_DOMAIN: &[u8] = b"UCF:VRF:EXPERIENCE_RECORD";

/// Marker for the beta VRF scheme used until a full ECVRF is available.
pub const TEMPORARY_VRF_SCHEME: &str = "TEMPORARY_VRF_ED25519_SHA512_TAI";

/// VRF keypair bound to a specific epoch.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VrfKeypair {
    pub key_id: String,
    pub epoch_id: u64,
    pub vrf_pk: Vec<u8>,
    pub vrf_sk: Vec<u8>,
}

/// VRF engine responsible for evaluating record VRFs.
///
/// This beta implementation uses `TEMPORARY_VRF_SCHEME`: an Ed25519 signature
/// over the domain-separated message, hashed with SHA-512 and then BLAKE3-256.
/// It is **not** a cryptographic ECVRF and must be replaced once a mature
/// library becomes available.
#[derive(Debug, Clone)]
pub struct VrfEngine {
    pub current: VrfKeypair,
    signing_key: SigningKey,
}

impl VrfEngine {
    /// Create a development VRF engine with a freshly generated keypair.
    pub fn new_dev(epoch_id: u64) -> Self {
        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();
        let key_id = format!("vrf-epoch-{epoch_id}");

        let current = VrfKeypair {
            key_id,
            epoch_id,
            vrf_pk: verifying_key.to_bytes().to_vec(),
            vrf_sk: signing_key.to_bytes().to_vec(),
        };

        Self {
            current,
            signing_key,
        }
    }

    /// Return the current VRF epoch identifier.
    pub fn current_epoch(&self) -> u64 {
        self.current.epoch_id
    }

    /// Return the current VRF public key bytes.
    pub fn vrf_public_key(&self) -> &[u8] {
        &self.current.vrf_pk
    }

    /// Evaluate the experience record VRF digest.
    pub fn eval_record_vrf(
        &self,
        prev_record_digest: [u8; 32],
        record_digest: [u8; 32],
        charter_digest: &str,
        profile_digest: [u8; 32],
        epoch_id: u64,
    ) -> [u8; 32] {
        let message = record_vrf_message(
            prev_record_digest,
            record_digest,
            charter_digest,
            profile_digest,
            epoch_id,
        );
        temporary_vrf_digest(&self.signing_key, &message)
    }

    /// Rotate the VRF keypair to a new epoch identifier.
    pub fn rotate(&mut self, new_epoch_id: u64) {
        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();

        self.current = VrfKeypair {
            key_id: format!("vrf-epoch-{new_epoch_id}"),
            epoch_id: new_epoch_id,
            vrf_pk: verifying_key.to_bytes().to_vec(),
            vrf_sk: signing_key.to_bytes().to_vec(),
        };
        self.signing_key = signing_key;
    }
}

fn record_vrf_message(
    prev_record_digest: [u8; 32],
    record_digest: [u8; 32],
    charter_digest: &str,
    profile_digest: [u8; 32],
    epoch_id: u64,
) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(RECORD_VRF_DOMAIN);
    message.extend_from_slice(&prev_record_digest);
    message.extend_from_slice(&record_digest);
    message.extend_from_slice(charter_digest.as_bytes());
    message.extend_from_slice(&profile_digest);
    message.extend_from_slice(&epoch_id.to_le_bytes());
    message
}

fn temporary_vrf_digest(signing_key: &SigningKey, message: &[u8]) -> [u8; 32] {
    let signature = signing_key.sign(message);
    let signature_hash = Sha512::digest(signature.to_bytes());

    let mut hasher = Hasher::new();
    hasher.update(signature_hash.as_slice());
    *hasher.finalize().as_bytes()
}

#[derive(Debug, Error)]
pub enum VrfError {
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("verification failed")]
    VerificationFailed,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_inputs() -> ([u8; 32], [u8; 32], String, [u8; 32], u64) {
        (
            [1u8; 32],
            [2u8; 32],
            "charter-digest".to_string(),
            [3u8; 32],
            9,
        )
    }

    #[test]
    fn vrf_digest_is_deterministic() {
        let engine = VrfEngine::new_dev(7);
        let (prev_record, record, charter, profile, epoch_id) = sample_inputs();

        let digest1 = engine.eval_record_vrf(prev_record, record, &charter, profile, epoch_id);
        let digest2 = engine.eval_record_vrf(prev_record, record, &charter, profile, epoch_id);

        assert_eq!(digest1, digest2);
    }

    #[test]
    fn vrf_digest_changes_with_record_digest() {
        let engine = VrfEngine::new_dev(11);
        let (prev_record, record, charter, profile, epoch_id) = sample_inputs();

        let digest1 = engine.eval_record_vrf(prev_record, record, &charter, profile, epoch_id);
        let mut modified_record = record;
        modified_record[0] ^= 0xFF;
        let digest2 =
            engine.eval_record_vrf(prev_record, modified_record, &charter, profile, epoch_id);

        assert_ne!(digest1, digest2);
    }

    #[test]
    fn temporary_vrf_digest_matches_signature_hash() {
        let engine = VrfEngine::new_dev(3);
        let (prev_record, record, charter, profile, epoch_id) = sample_inputs();
        let message = record_vrf_message(prev_record, record, &charter, profile, epoch_id);

        let digest = engine.eval_record_vrf(prev_record, record, &charter, profile, epoch_id);

        let signature = engine.signing_key.sign(&message);
        let signature_hash = Sha512::digest(signature.to_bytes());
        let mut hasher = Hasher::new();
        hasher.update(signature_hash.as_slice());
        let expected: [u8; 32] = *hasher.finalize().as_bytes();

        assert_eq!(digest, expected);
    }
}
