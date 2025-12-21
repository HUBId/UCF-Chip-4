#![forbid(unsafe_code)]

use std::collections::HashSet;

use limits::StoreLimits;
use thiserror::Error;
pub use ucf_protocol::ucf::v1::{PolicyEcologyDimension, PolicyEcologyVector};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PevError {
    #[error("policy ecology vector missing digest")]
    MissingDigest,
    #[error("policy ecology vector digest must be 32 bytes")]
    InvalidDigestLength,
    #[error("policy ecology vector dimension '{0}' is not allowed")]
    UnknownDimension(String),
    #[error("policy ecology vector epoch must be monotonic")]
    NonMonotonicEpoch,
    #[error("policy ecology vector value {0} exceeds quantized range")]
    ValueOutOfRange(u32),
}

/// Append-only Policy Ecology Vector store with validation.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PevStore {
    pevs: Vec<PolicyEcologyVector>,
    limits: StoreLimits,
}

impl Default for PevStore {
    fn default() -> Self {
        Self::with_limits(StoreLimits::default())
    }
}

impl PevStore {
    pub fn with_limits(limits: StoreLimits) -> Self {
        Self {
            pevs: Vec::new(),
            limits,
        }
    }

    pub fn push(&mut self, pev: PolicyEcologyVector) -> Result<Vec<PolicyEcologyVector>, PevError> {
        self.validate(&pev)?;
        let mut evicted = Vec::new();
        let limit = self.limits.max_pevs;

        if limit == 0 {
            evicted.append(&mut self.pevs);
            evicted.push(pev);
            return Ok(evicted);
        }

        while self.pevs.len() >= limit {
            evicted.push(self.pevs.remove(0));
        }

        self.pevs.push(pev);
        Ok(evicted)
    }

    pub fn latest(&self) -> Option<&PolicyEcologyVector> {
        self.pevs.last()
    }

    pub fn get_by_version(&self, pev_version_digest: &[u8; 32]) -> Option<&PolicyEcologyVector> {
        self.pevs
            .iter()
            .find(|pev| pev_digest(pev).as_ref() == Some(pev_version_digest))
    }

    pub fn list(&self) -> &[PolicyEcologyVector] {
        &self.pevs
    }

    pub fn validate_pev(&self, pev: &PolicyEcologyVector) -> Result<(), PevError> {
        self.validate(pev)
    }

    fn validate(&self, pev: &PolicyEcologyVector) -> Result<(), PevError> {
        let digest_bytes = pev
            .pev_version_digest
            .as_deref()
            .or(pev.pev_digest.as_deref())
            .ok_or(PevError::MissingDigest)?;

        if digest_bytes.len() != 32 {
            return Err(PevError::InvalidDigestLength);
        }

        pev_digest(pev).ok_or(PevError::MissingDigest)?;

        if let (Some(prev_epoch), Some(next_epoch)) =
            (self.latest().and_then(|p| p.pev_epoch), pev.pev_epoch)
        {
            if next_epoch <= prev_epoch {
                return Err(PevError::NonMonotonicEpoch);
            }
        }

        let allowed = allowed_dimensions();
        for dim in &pev.dimensions {
            if !allowed.contains(dim.name.as_str()) {
                return Err(PevError::UnknownDimension(dim.name.clone()));
            }

            if dim.value > u16::MAX as u32 {
                return Err(PevError::ValueOutOfRange(dim.value));
            }
        }

        Ok(())
    }
}

/// Extract a 32-byte digest from a PEV, preferring the explicit version digest.
pub fn pev_digest(pev: &PolicyEcologyVector) -> Option<[u8; 32]> {
    if let Some(version) = pev.pev_version_digest.as_deref() {
        return digest_from_bytes(version);
    }

    pev.pev_digest.as_deref().and_then(digest_from_bytes)
}

fn digest_from_bytes(bytes: &[u8]) -> Option<[u8; 32]> {
    if bytes.len() != 32 {
        return None;
    }

    let mut digest = [0u8; 32];
    digest.copy_from_slice(bytes);
    Some(digest)
}

fn allowed_dimensions() -> HashSet<&'static str> {
    HashSet::from([
        "conservatism_bias",
        "novelty_penalty_bias",
        "manipulation_aversion_bias",
        "data_minimization_bias",
        "reversibility_bias",
        "consistency_bias",
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pev(digest: [u8; 32], epoch: Option<u64>) -> PolicyEcologyVector {
        PolicyEcologyVector {
            dimensions: vec![PolicyEcologyDimension {
                name: "conservatism_bias".to_string(),
                value: 1,
            }],
            pev_digest: Some(digest.to_vec()),
            pev_version_digest: None,
            pev_epoch: epoch,
        }
    }

    #[test]
    fn push_and_latest_returns_last() {
        let mut store = PevStore::default();
        let first = pev([1u8; 32], Some(1));
        let second = pev([2u8; 32], Some(2));

        assert!(store.push(first.clone()).expect("first push").is_empty());
        assert!(store.push(second.clone()).expect("second push").is_empty());

        assert_eq!(store.latest(), Some(&second));
        assert_eq!(
            store.get_by_version(&[1u8; 32]).map(pev_digest),
            Some(Some([1u8; 32]))
        );
    }

    #[test]
    fn rejects_unknown_dimension() {
        let mut store = PevStore::default();
        let bad_pev = PolicyEcologyVector {
            dimensions: vec![PolicyEcologyDimension {
                name: "bad_dimension".to_string(),
                value: 1,
            }],
            pev_digest: Some([9u8; 32].to_vec()),
            pev_version_digest: None,
            pev_epoch: None,
        };

        let err = store.push(bad_pev).expect_err("push should fail");
        assert!(matches!(err, PevError::UnknownDimension(name) if name == "bad_dimension"));
    }

    #[test]
    fn rejects_non_monotonic_epoch() {
        let mut store = PevStore::default();
        assert!(store
            .push(pev([1u8; 32], Some(5)))
            .expect("first push")
            .is_empty());

        let err = store
            .push(pev([2u8; 32], Some(4)))
            .expect_err("push should fail");
        assert_eq!(err, PevError::NonMonotonicEpoch);
    }

    #[test]
    fn rejects_invalid_digest_length() {
        let mut store = PevStore::default();
        let pev = PolicyEcologyVector {
            dimensions: vec![PolicyEcologyDimension {
                name: "conservatism_bias".to_string(),
                value: 1,
            }],
            pev_digest: Some(vec![1u8; 16]),
            pev_version_digest: None,
            pev_epoch: None,
        };

        let err = store.push(pev).expect_err("push should fail");
        assert_eq!(err, PevError::InvalidDigestLength);
    }

    #[test]
    fn evicts_oldest_pev_when_limit_exceeded() {
        let mut store = PevStore::with_limits(StoreLimits {
            max_pevs: 1,
            ..StoreLimits::default()
        });

        let first = pev([1u8; 32], Some(1));
        let second = pev([2u8; 32], Some(2));

        assert!(store.push(first.clone()).expect("first push").is_empty());
        let evicted = store.push(second.clone()).expect("second push");

        assert_eq!(evicted, vec![first]);
        assert_eq!(store.latest(), Some(&second));
    }

    #[test]
    fn pev_store_zero_limit_evicts_every_insert() {
        let mut store = PevStore::with_limits(StoreLimits {
            max_pevs: 0,
            ..StoreLimits::default()
        });

        let first = pev([1u8; 32], Some(1));
        let evicted_first = store.push(first.clone()).expect("first push");
        assert_eq!(evicted_first, vec![first]);
        assert!(store.latest().is_none());

        let second = pev([2u8; 32], Some(2));
        let evicted_second = store.push(second.clone()).expect("second push");
        assert_eq!(evicted_second, vec![second]);
        assert!(store.latest().is_none());
    }
}
