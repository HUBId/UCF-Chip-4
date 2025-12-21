#![forbid(unsafe_code)]

use blake3::Hasher;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use sep::{SepError, SepEventType, SepLog};
use thiserror::Error;
use ucf_protocol::ucf::v1::{Digest32, PVGSKeyEpoch, ReasonCodes};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

const KEY_EPOCH_HASH_DOMAIN: &[u8] = b"UCF:HASH:PVGS_KEY_EPOCH";
const KEY_EPOCH_SIGN_DOMAIN: &[u8] = b"UCF:SIGN:PVGS_KEY_EPOCH";

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyEpoch {
    pub epoch_id: u64,
    pub key_id: String,
    pub public_key: [u8; 32],
    pub vrf_public_key: Option<Vec<u8>>,
}

/// Append-only history of published key epochs.
#[derive(Debug, Default, Clone)]
pub struct KeyEpochHistory {
    pub epochs: Vec<PVGSKeyEpoch>,
}

/// Errors raised when managing key epoch history.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum KeyEpochHistoryError {
    #[error("key epoch ids must increase (last {last}, next {next})")]
    NonMonotonic { last: u64, next: u64 },
    #[error("previous digest required for chained history")]
    MissingPreviousDigest,
    #[error("previous digest does not match latest announcement")]
    PreviousDigestMismatch,
    #[error("sep error: {0}")]
    Sep(#[from] SepError),
}

/// In-memory keystore tracking the current signing key and historical epochs.
#[derive(Debug, Clone)]
pub struct KeyStore {
    pub current_epoch: u64,
    pub current_key_id: String,
    pub secret_key: SigningKey,
    pub epochs: Vec<KeyEpoch>,
}

impl KeyStore {
    /// Construct a new developer keystore with a freshly generated signing key.
    pub fn new_dev_keystore(epoch_id: u64) -> Self {
        let mut rng = OsRng;
        let secret_key = SigningKey::generate(&mut rng);
        let current_key_id = format!("epoch-{}", epoch_id);

        Self {
            current_epoch: epoch_id,
            current_key_id,
            secret_key,
            epochs: Vec::new(),
        }
    }

    /// Return the current epoch identifier.
    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    /// Return the identifier for the current signing key.
    pub fn current_key_id(&self) -> &str {
        &self.current_key_id
    }

    /// Get the public key for a given epoch if present.
    pub fn public_key_for_epoch(&self, epoch_id: u64) -> Option<[u8; 32]> {
        if epoch_id == self.current_epoch {
            Some(self.secret_key.verifying_key().to_bytes())
        } else {
            self.epochs
                .iter()
                .find(|epoch| epoch.epoch_id == epoch_id)
                .map(|epoch| epoch.public_key)
        }
    }

    /// Build a signed PVGSKeyEpoch announcement for the current attestation key.
    pub fn make_key_epoch_proto(
        &self,
        key_epoch_id: u64,
        created_at_ms: u64,
        vrf_public_key: Vec<u8>,
        prev_digest: Option<[u8; 32]>,
    ) -> PVGSKeyEpoch {
        let attestation_public_key = self.verifying_key().to_bytes().to_vec();
        let attestation_key_id = self.current_key_id.clone();
        let vrf_key_id = attestation_key_id.clone();

        let mut proto = PVGSKeyEpoch {
            key_epoch_id,
            attestation_key_id,
            attestation_public_key,
            vrf_key_id,
            vrf_public_key,
            created_at_ms,
            prev_key_epoch_digest: prev_digest.map(Digest32),
            announcement_digest: Digest32::zero(),
            announcement_signature: Vec::new(),
        };

        let digest = compute_key_epoch_digest(
            proto.key_epoch_id,
            &proto.attestation_key_id,
            &proto.attestation_public_key,
            &proto.vrf_key_id,
            &proto.vrf_public_key,
            proto.created_at_ms,
            proto.prev_key_epoch_digest.as_ref(),
        );
        proto.announcement_digest = Digest32(digest);

        let signature = self
            .signing_key()
            .sign(&key_epoch_signature_preimage(&proto));
        proto.announcement_signature = signature.to_bytes().to_vec();

        proto
    }

    /// Rotate to a new epoch, retaining the previous public key for verification.
    pub fn rotate(&mut self, new_epoch_id: u64) -> KeyEpoch {
        let current_public = self.secret_key.verifying_key().to_bytes();
        let archived = KeyEpoch {
            epoch_id: self.current_epoch,
            key_id: self.current_key_id.clone(),
            public_key: current_public,
            vrf_public_key: None,
        };
        self.epochs.push(archived);

        let mut rng = OsRng;
        let secret_key = SigningKey::generate(&mut rng);
        let current_key_id = format!("epoch-{}", new_epoch_id);

        self.current_epoch = new_epoch_id;
        self.current_key_id = current_key_id.clone();
        self.secret_key = secret_key;

        KeyEpoch {
            epoch_id: new_epoch_id,
            key_id: current_key_id,
            public_key: self.secret_key.verifying_key().to_bytes(),
            vrf_public_key: None,
        }
    }

    /// Rotate, publish a PVGSKeyEpoch, push history, and emit a SEP event.
    pub fn rotate_and_publish(
        &mut self,
        new_epoch_id: u64,
        created_at_ms: u64,
        vrf_public_key: Vec<u8>,
        history: &mut KeyEpochHistory,
        sep_log: &mut SepLog,
    ) -> Result<PVGSKeyEpoch, KeyEpochHistoryError> {
        if let Some(last) = history.current() {
            if new_epoch_id <= last.key_epoch_id {
                return Err(KeyEpochHistoryError::NonMonotonic {
                    last: last.key_epoch_id,
                    next: new_epoch_id,
                });
            }
        }

        let prev_digest = history.current().map(|epoch| epoch.announcement_digest.0);

        self.rotate(new_epoch_id);
        let proto =
            self.make_key_epoch_proto(new_epoch_id, created_at_ms, vrf_public_key, prev_digest);

        history.push(proto.clone())?;
        sep_log.append_event(
            format!("key-epoch-{}", proto.key_epoch_id),
            SepEventType::EvRecoveryGov,
            proto.announcement_digest.0,
            vec![ReasonCodes::GV_KEY_EPOCH_ROTATED.to_string()],
        )?;

        Ok(proto)
    }

    /// Expose the current signing key for attestation routines.
    pub fn signing_key(&self) -> &SigningKey {
        &self.secret_key
    }

    /// Expose the verifying key for the current epoch.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.secret_key.verifying_key()
    }
}

impl KeyEpochHistory {
    /// Return the current (latest) key epoch if present.
    pub fn current(&self) -> Option<&PVGSKeyEpoch> {
        self.epochs.last()
    }

    /// List all known key epochs in insertion order.
    pub fn list(&self) -> &[PVGSKeyEpoch] {
        &self.epochs
    }

    /// Append a new key epoch, enforcing monotonic ids and optional digest chaining.
    pub fn push(&mut self, ke: PVGSKeyEpoch) -> Result<(), KeyEpochHistoryError> {
        if let Some(last) = self.epochs.last() {
            if ke.key_epoch_id <= last.key_epoch_id {
                return Err(KeyEpochHistoryError::NonMonotonic {
                    last: last.key_epoch_id,
                    next: ke.key_epoch_id,
                });
            }

            if let Some(prev_digest) = ke.prev_key_epoch_digest.as_ref() {
                if prev_digest.0 != last.announcement_digest.0 {
                    return Err(KeyEpochHistoryError::PreviousDigestMismatch);
                }
            }
        } else if ke.prev_key_epoch_digest.is_some() {
            return Err(KeyEpochHistoryError::MissingPreviousDigest);
        }

        self.epochs.push(ke);
        Ok(())
    }
}

/// Verify a PVGSKeyEpoch announcement signature and digest.
pub fn verify_key_epoch_signature(epoch: &PVGSKeyEpoch) -> bool {
    let Ok(attestation_pk_bytes): Result<[u8; 32], _> =
        epoch.attestation_public_key.as_slice().try_into()
    else {
        return false;
    };

    let Ok(signature_bytes): Result<[u8; 64], _> =
        epoch.announcement_signature.as_slice().try_into()
    else {
        return false;
    };

    let expected_digest = compute_key_epoch_digest(
        epoch.key_epoch_id,
        &epoch.attestation_key_id,
        &epoch.attestation_public_key,
        &epoch.vrf_key_id,
        &epoch.vrf_public_key,
        epoch.created_at_ms,
        epoch.prev_key_epoch_digest.as_ref(),
    );

    if epoch.announcement_digest.0 != expected_digest {
        return false;
    }

    let Ok(verifying_key) = VerifyingKey::from_bytes(&attestation_pk_bytes) else {
        return false;
    };
    let signature = Signature::from_bytes(&signature_bytes);

    verifying_key
        .verify(&key_epoch_signature_preimage(epoch), &signature)
        .is_ok()
}

fn compute_key_epoch_digest(
    key_epoch_id: u64,
    attestation_key_id: &str,
    attestation_public_key: &[u8],
    vrf_key_id: &str,
    vrf_public_key: &[u8],
    created_at_ms: u64,
    prev_key_epoch_digest: Option<&Digest32>,
) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(KEY_EPOCH_HASH_DOMAIN);
    hasher.update(&key_epoch_id.to_le_bytes());
    hasher.update(attestation_key_id.as_bytes());
    hasher.update(attestation_public_key);
    hasher.update(vrf_key_id.as_bytes());
    hasher.update(vrf_public_key);
    hasher.update(&created_at_ms.to_le_bytes());
    update_optional_digest_hasher(&mut hasher, prev_key_epoch_digest);
    *hasher.finalize().as_bytes()
}

fn key_epoch_signature_preimage(epoch: &PVGSKeyEpoch) -> Vec<u8> {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(KEY_EPOCH_SIGN_DOMAIN);
    preimage.extend_from_slice(&epoch.key_epoch_id.to_le_bytes());
    preimage.extend_from_slice(epoch.attestation_key_id.as_bytes());
    preimage.extend_from_slice(&epoch.attestation_public_key);
    preimage.extend_from_slice(epoch.vrf_key_id.as_bytes());
    preimage.extend_from_slice(&epoch.vrf_public_key);
    preimage.extend_from_slice(&epoch.created_at_ms.to_le_bytes());
    preimage.extend_from_slice(&epoch.announcement_digest.0);
    match epoch.prev_key_epoch_digest.as_ref() {
        Some(prev) => {
            preimage.push(1u8);
            preimage.extend_from_slice(&prev.0);
        }
        None => preimage.push(0u8),
    }
    preimage
}

fn update_optional_digest_hasher(hasher: &mut Hasher, digest: Option<&Digest32>) {
    match digest {
        Some(d) => {
            hasher.update(&[1u8]);
            hasher.update(&d.0);
        }
        None => {
            hasher.update(&[0u8]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_epoch_digest_is_deterministic() {
        let keystore = KeyStore::new_dev_keystore(7);
        let vrf_pk = vec![9u8; 32];

        let epoch_one = keystore.make_key_epoch_proto(7, 123, vrf_pk.clone(), None);
        let epoch_two = keystore.make_key_epoch_proto(7, 123, vrf_pk, None);

        assert_eq!(epoch_one.announcement_digest, epoch_two.announcement_digest);
        assert_eq!(
            epoch_one.announcement_signature,
            epoch_two.announcement_signature
        );
    }

    #[test]
    fn key_epoch_signature_verifies_and_detects_mutation() {
        let keystore = KeyStore::new_dev_keystore(3);
        let vrf_pk = vec![1u8; 32];
        let mut epoch = keystore.make_key_epoch_proto(3, 99, vrf_pk, None);

        assert!(verify_key_epoch_signature(&epoch));

        epoch.vrf_public_key[0] ^= 0xFF;
        assert!(!verify_key_epoch_signature(&epoch));

        let mut epoch = keystore.make_key_epoch_proto(3, 99, vec![1u8; 32], None);
        epoch.announcement_digest.0[0] ^= 0xAA;
        assert!(!verify_key_epoch_signature(&epoch));
    }

    #[test]
    fn history_rejects_non_monotonic() {
        let keystore = KeyStore::new_dev_keystore(1);
        let mut history = KeyEpochHistory::default();

        let first = keystore.make_key_epoch_proto(1, 10, vec![2u8; 32], None);
        history.push(first).unwrap();

        let second = keystore.make_key_epoch_proto(0, 11, vec![2u8; 32], None);
        let err = history.push(second).unwrap_err();
        assert!(matches!(err, KeyEpochHistoryError::NonMonotonic { .. }));
    }

    #[test]
    fn history_enforces_prev_digest_chain_when_present() {
        let keystore = KeyStore::new_dev_keystore(4);
        let mut history = KeyEpochHistory::default();

        let first = keystore.make_key_epoch_proto(4, 10, vec![4u8; 32], None);
        history.push(first.clone()).unwrap();

        // Wrong digest should be rejected
        let mut wrong_prev = first.clone();
        wrong_prev.announcement_digest.0[0] ^= 0x11;
        let bad_next = keystore.make_key_epoch_proto(
            5,
            11,
            vec![4u8; 32],
            Some(wrong_prev.announcement_digest.0),
        );
        let err = history.push(bad_next).unwrap_err();
        assert_eq!(err, KeyEpochHistoryError::PreviousDigestMismatch);

        // Correct digest should succeed
        let good_next =
            keystore.make_key_epoch_proto(5, 11, vec![4u8; 32], Some(first.announcement_digest.0));
        history.push(good_next).unwrap();
    }

    #[test]
    fn history_rejects_prev_digest_on_first_entry() {
        let keystore = KeyStore::new_dev_keystore(6);
        let mut history = KeyEpochHistory::default();

        let first = keystore.make_key_epoch_proto(6, 20, vec![5u8; 32], Some([0u8; 32]));
        let err = history.push(first).unwrap_err();
        assert_eq!(err, KeyEpochHistoryError::MissingPreviousDigest);
    }

    #[test]
    fn rotation_hook_publishes_and_logs() {
        let mut keystore = KeyStore::new_dev_keystore(8);
        let mut history = KeyEpochHistory::default();
        let mut sep_log = SepLog::default();

        let initial = keystore.make_key_epoch_proto(8, 50, vec![6u8; 32], None);
        history.push(initial.clone()).unwrap();

        let rotated = keystore
            .rotate_and_publish(9, 60, vec![7u8; 32], &mut history, &mut sep_log)
            .unwrap();

        assert_eq!(history.current().unwrap().key_epoch_id, 9);
        assert_eq!(
            sep_log.events.last().unwrap().object_digest,
            rotated.announcement_digest.0
        );
        assert_eq!(
            sep_log.events.last().unwrap().reason_codes,
            vec![ReasonCodes::GV_KEY_EPOCH_ROTATED.to_string()]
        );
    }
}
