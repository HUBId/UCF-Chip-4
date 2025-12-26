#![forbid(unsafe_code)]

use std::collections::HashMap;
use thiserror::Error;
use ucf_protocol::ucf::v1::{Digest32, Ref, ReplayRunEvidence};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

const MAX_STEPS: u64 = 1_000_000;
const MAX_MICRO_CONFIGS: usize = 8;

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ReplayRunStoreError {
    #[error("run digest missing")]
    MissingRunDigest,
    #[error("asset manifest ref missing")]
    MissingAssetManifestRef,
    #[error("asset manifest digest invalid")]
    InvalidAssetManifestDigest,
    #[error("invalid step count")]
    InvalidStepCount,
    #[error("too many micro configs")]
    TooManyMicroConfigs,
    #[error("summary digests missing")]
    MissingSummaryDigests,
    #[error("summary digest invalid")]
    InvalidSummaryDigest,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Default)]
pub struct ReplayRunStore {
    pub runs: Vec<ReplayRunEvidence>,
    pub by_run_digest: HashMap<[u8; 32], usize>,
}

impl ReplayRunStore {
    pub fn insert(&mut self, evidence: ReplayRunEvidence) -> Result<bool, ReplayRunStoreError> {
        let run_digest =
            digest_from_bytes(&evidence.run_digest).ok_or(ReplayRunStoreError::MissingRunDigest)?;
        if self.by_run_digest.contains_key(&run_digest) {
            return Ok(false);
        }

        let asset_manifest_ref = evidence
            .asset_manifest_ref
            .as_ref()
            .ok_or(ReplayRunStoreError::MissingAssetManifestRef)?;
        if digest_from_ref(asset_manifest_ref).is_none() {
            return Err(ReplayRunStoreError::InvalidAssetManifestDigest);
        }

        if evidence.steps == 0 || evidence.steps > MAX_STEPS {
            return Err(ReplayRunStoreError::InvalidStepCount);
        }

        if evidence.micro_config_refs.len() > MAX_MICRO_CONFIGS {
            return Err(ReplayRunStoreError::TooManyMicroConfigs);
        }

        if evidence.summary_digests.is_empty() {
            return Err(ReplayRunStoreError::MissingSummaryDigests);
        }

        if evidence
            .summary_digests
            .iter()
            .any(|digest| digest_from_bytes(digest).is_none())
        {
            return Err(ReplayRunStoreError::InvalidSummaryDigest);
        }

        self.by_run_digest.insert(run_digest, self.runs.len());
        self.runs.push(evidence);
        Ok(true)
    }

    pub fn get(&self, run_digest: [u8; 32]) -> Option<&ReplayRunEvidence> {
        self.by_run_digest
            .get(&run_digest)
            .and_then(|idx| self.runs.get(*idx))
    }

    pub fn len(&self) -> usize {
        self.runs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.runs.is_empty()
    }
}

fn digest_from_ref(reference: &Ref) -> Option<[u8; 32]> {
    reference
        .digest
        .as_ref()
        .and_then(|digest| digest_from_bytes(digest))
}

fn digest_from_bytes(bytes: &[u8]) -> Option<[u8; 32]> {
    Digest32::from_slice(bytes).map(|digest| digest.0)
}
