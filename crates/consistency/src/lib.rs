#![forbid(unsafe_code)]

use std::collections::HashMap;

use blake3::Hasher;
use prost::Message;
use thiserror::Error;
use ucf_protocol::ucf::v1::ConsistencyFeedback;

const MAX_FLAGS: usize = 16;

#[derive(Debug, Clone, Default)]
pub struct ConsistencyStore {
    pub map: HashMap<[u8; 32], ConsistencyFeedback>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConsistencyStoreError {
    #[error("missing consistency feedback digest")]
    MissingDigest,
    #[error("invalid consistency feedback digest length")]
    InvalidDigestLength,
    #[error("missing consistency class")]
    MissingConsistencyClass,
    #[error("too many consistency flags")]
    FlagsTooLong,
}

impl ConsistencyStore {
    pub fn insert(
        &mut self,
        feedback: ConsistencyFeedback,
    ) -> Result<[u8; 32], ConsistencyStoreError> {
        let (sanitized, digest) = validate_feedback(feedback)?;

        self.map.insert(digest, sanitized);
        Ok(digest)
    }

    pub fn get(&self, digest: [u8; 32]) -> Option<&ConsistencyFeedback> {
        self.map.get(&digest)
    }
}

pub fn validate_feedback(
    mut feedback: ConsistencyFeedback,
) -> Result<(ConsistencyFeedback, [u8; 32]), ConsistencyStoreError> {
    let digest = extract_or_compute_digest(&mut feedback)?;

    if feedback.consistency_class.is_empty() {
        return Err(ConsistencyStoreError::MissingConsistencyClass);
    }

    if feedback.flags.len() > MAX_FLAGS {
        return Err(ConsistencyStoreError::FlagsTooLong);
    }

    feedback.flags.sort();

    Ok((feedback, digest))
}

fn extract_or_compute_digest(
    feedback: &mut ConsistencyFeedback,
) -> Result<[u8; 32], ConsistencyStoreError> {
    if let Some(bytes) = feedback.cf_digest.as_deref() {
        return digest_from_bytes(bytes).ok_or(ConsistencyStoreError::InvalidDigestLength);
    }

    let mut canonical = feedback.clone();
    canonical.cf_digest = None;
    let digest = compute_digest(&canonical);
    feedback.cf_digest = Some(digest.to_vec());
    Ok(digest)
}

fn compute_digest(feedback: &ConsistencyFeedback) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(b"UCF:HASH:CONSISTENCY_FEEDBACK");
    hasher.update(&feedback.encode_to_vec());
    *hasher.finalize().as_bytes()
}

fn digest_from_bytes(bytes: &[u8]) -> Option<[u8; 32]> {
    if bytes.len() != 32 {
        return None;
    }

    let mut digest = [0u8; 32];
    digest.copy_from_slice(bytes);
    Some(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feedback(consistency_class: &str) -> ConsistencyFeedback {
        ConsistencyFeedback {
            cf_digest: Some([7u8; 32].to_vec()),
            consistency_class: consistency_class.to_string(),
            flags: vec!["b".to_string(), "a".to_string()],
            proof_receipt_ref: None,
        }
    }

    #[test]
    fn inserts_with_digest() {
        let mut store = ConsistencyStore::default();
        store.insert(feedback("CONSISTENCY_HIGH")).unwrap();

        assert!(store.get([7u8; 32]).is_some());
        assert_eq!(
            store.get([7u8; 32]).unwrap().flags,
            vec!["a".to_string(), "b".to_string()]
        );
    }

    #[test]
    fn computes_digest_when_missing() {
        let mut store = ConsistencyStore::default();
        let mut feedback = feedback("CONSISTENCY_LOW");
        feedback.cf_digest = None;

        let digest = store.insert(feedback.clone()).unwrap();
        assert_eq!(
            store.get(digest).unwrap().cf_digest.as_deref(),
            Some(digest.as_slice())
        );
    }

    #[test]
    fn rejects_missing_class() {
        let mut store = ConsistencyStore::default();
        let mut feedback = feedback("");
        feedback.cf_digest = None;

        let err = store.insert(feedback).unwrap_err();
        assert_eq!(err, ConsistencyStoreError::MissingConsistencyClass);
    }

    #[test]
    fn rejects_long_flags() {
        let mut store = ConsistencyStore::default();
        let feedback = ConsistencyFeedback {
            cf_digest: Some([1u8; 32].to_vec()),
            consistency_class: "CONSISTENCY_HIGH".to_string(),
            flags: vec!["f".to_string(); MAX_FLAGS + 1],
            proof_receipt_ref: None,
        };

        let err = store.insert(feedback).unwrap_err();
        assert_eq!(err, ConsistencyStoreError::FlagsTooLong);
    }

    #[test]
    fn rejects_invalid_digest() {
        let mut store = ConsistencyStore::default();
        let feedback = ConsistencyFeedback {
            cf_digest: Some(vec![0u8; 31]),
            consistency_class: "CONSISTENCY_HIGH".to_string(),
            flags: Vec::new(),
            proof_receipt_ref: None,
        };

        let err = store.insert(feedback).unwrap_err();
        assert_eq!(err, ConsistencyStoreError::InvalidDigestLength);
    }
}
