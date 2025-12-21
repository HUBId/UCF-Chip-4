#![forbid(unsafe_code)]

use limits::StoreLimits;
use std::collections::HashMap;
use std::collections::VecDeque;

use blake3::Hasher;
use prost::Message;
use thiserror::Error;
use ucf_protocol::ucf::v1::ConsistencyFeedback;

const MAX_FLAGS: usize = 16;

#[derive(Debug, Clone)]
pub struct ConsistencyStore {
    pub map: HashMap<[u8; 32], ConsistencyFeedback>,
    order: VecDeque<[u8; 32]>,
    limits: StoreLimits,
}

impl Default for ConsistencyStore {
    fn default() -> Self {
        Self::with_limits(StoreLimits::default())
    }
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
    pub fn with_limits(limits: StoreLimits) -> Self {
        Self {
            map: HashMap::new(),
            order: VecDeque::new(),
            limits,
        }
    }

    pub fn insert(
        &mut self,
        feedback: ConsistencyFeedback,
    ) -> Result<([u8; 32], Vec<[u8; 32]>), ConsistencyStoreError> {
        let (sanitized, digest) = validate_feedback(feedback)?;

        let mut evicted = Vec::new();
        let limit = self.limits.max_consistency_feedbacks;

        if limit == 0 {
            self.map.clear();
            self.order.clear();
            evicted.push(digest);
            return Ok((digest, evicted));
        }

        if let Some(pos) = self.order.iter().position(|d| *d == digest) {
            self.order.remove(pos);
        }

        while self.order.len() >= limit {
            if let Some(removed) = self.order.pop_front() {
                self.map.remove(&removed);
                evicted.push(removed);
            }
        }

        self.order.push_back(digest);
        self.map.insert(digest, sanitized);
        Ok((digest, evicted))
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
        let (digest, evicted) = store.insert(feedback("CONSISTENCY_HIGH")).unwrap();

        assert!(evicted.is_empty());
        assert!(store.get([7u8; 32]).is_some());
        assert_eq!(
            store.get([7u8; 32]).unwrap().flags,
            vec!["a".to_string(), "b".to_string()]
        );
        assert_eq!(digest, [7u8; 32]);
    }

    #[test]
    fn computes_digest_when_missing() {
        let mut store = ConsistencyStore::default();
        let mut feedback = feedback("CONSISTENCY_LOW");
        feedback.cf_digest = None;

        let (digest, evicted) = store.insert(feedback.clone()).unwrap();
        assert!(evicted.is_empty());
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

    #[test]
    fn evicts_oldest_feedback_in_fifo_order() {
        let mut store = ConsistencyStore::with_limits(StoreLimits {
            max_consistency_feedbacks: 1,
            ..StoreLimits::default()
        });

        let first = feedback("CONSISTENCY_HIGH");
        let mut second = feedback("CONSISTENCY_HIGH");
        second.cf_digest = Some([8u8; 32].to_vec());

        let (_, evicted_first) = store.insert(first.clone()).unwrap();
        assert!(evicted_first.is_empty());

        let (_, evicted_second) = store.insert(second.clone()).unwrap();
        assert_eq!(evicted_second, vec![[7u8; 32]]);
        assert!(store.get([7u8; 32]).is_none());
        let mut expected = second.clone();
        expected.flags.sort();
        assert_eq!(store.get([8u8; 32]), Some(&expected));
    }

    #[test]
    fn reinserting_feedback_updates_order_for_fifo_eviction() {
        let mut store = ConsistencyStore::with_limits(StoreLimits {
            max_consistency_feedbacks: 2,
            ..StoreLimits::default()
        });

        let mut first = feedback("CONSISTENCY_HIGH");
        first.cf_digest = Some([1u8; 32].to_vec());
        let mut second = feedback("CONSISTENCY_HIGH");
        second.cf_digest = Some([2u8; 32].to_vec());
        let mut third = feedback("CONSISTENCY_HIGH");
        third.cf_digest = Some([3u8; 32].to_vec());

        store.insert(first.clone()).unwrap();
        store.insert(second.clone()).unwrap();
        store.insert(first.clone()).unwrap();
        let (_, evicted) = store.insert(third.clone()).unwrap();

        assert_eq!(evicted, vec![[2u8; 32]]);
        assert!(store.get([2u8; 32]).is_none());
        assert_eq!(store.order.back(), Some(&[3u8; 32]));
    }
}
