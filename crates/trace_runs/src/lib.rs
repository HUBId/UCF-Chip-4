#![forbid(unsafe_code)]

use std::collections::HashMap;

use prost::Message;
use thiserror::Error;
pub use ucf_protocol::ucf::v1::{TraceRunEvidence, TraceVerdict};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub const TRACE_RUN_EVIDENCE_DOMAIN: &str = "UCF:TRACE_RUN_EVIDENCE";
const MAX_TRACE_ID_LEN: usize = 64;
const MAX_REASON_CODES: usize = 32;
const MAX_REASON_CODE_LEN: usize = 64;

pub fn validate_trace_run_evidence(
    evidence: &TraceRunEvidence,
) -> Result<(), TraceRunEvidenceError> {
    validate_internal(evidence, true)
}

fn validate_internal(
    evidence: &TraceRunEvidence,
    check_trace_digest: bool,
) -> Result<(), TraceRunEvidenceError> {
    if evidence.trace_id.is_empty() {
        return Err(TraceRunEvidenceError::MissingTraceId);
    }
    if evidence.trace_id.len() > MAX_TRACE_ID_LEN {
        return Err(TraceRunEvidenceError::TraceIdTooLong);
    }
    let trace_digest = digest_from_bytes(&evidence.trace_digest)
        .ok_or(TraceRunEvidenceError::InvalidTraceDigest)?;
    if check_trace_digest && trace_digest == [0u8; 32] {
        return Err(TraceRunEvidenceError::InvalidTraceDigest);
    }
    if digest_from_bytes(&evidence.active_cfg_digest).is_none()
        || digest_from_bytes(&evidence.shadow_cfg_digest).is_none()
        || digest_from_bytes(&evidence.active_feedback_digest).is_none()
        || digest_from_bytes(&evidence.shadow_feedback_digest).is_none()
    {
        return Err(TraceRunEvidenceError::InvalidTraceDigest);
    }
    let verdict = TraceVerdict::try_from(evidence.verdict).unwrap_or(TraceVerdict::Unspecified);
    if matches!(verdict, TraceVerdict::Unspecified) {
        return Err(TraceRunEvidenceError::InvalidVerdict);
    }
    if evidence.reason_codes.len() > MAX_REASON_CODES {
        return Err(TraceRunEvidenceError::TooManyReasonCodes);
    }
    if evidence
        .reason_codes
        .iter()
        .any(|code| code.len() > MAX_REASON_CODE_LEN)
    {
        return Err(TraceRunEvidenceError::ReasonCodeTooLong);
    }
    if !is_sorted_unique(&evidence.reason_codes) {
        return Err(TraceRunEvidenceError::ReasonCodesNotSorted);
    }
    Ok(())
}

pub fn compute_trace_run_digest(
    evidence: &TraceRunEvidence,
) -> Result<[u8; 32], TraceRunEvidenceError> {
    validate_internal(evidence, false)?;
    let mut canonical = evidence.clone();
    canonical.trace_digest = vec![0u8; 32];
    let payload = canonical.encode_to_vec();
    let mut input = Vec::with_capacity(TRACE_RUN_EVIDENCE_DOMAIN.len() + payload.len());
    input.extend_from_slice(TRACE_RUN_EVIDENCE_DOMAIN.as_bytes());
    input.extend_from_slice(&payload);
    Ok(*blake3::hash(&input).as_bytes())
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TraceRunEvidenceError {
    #[error("trace id missing")]
    MissingTraceId,
    #[error("trace id too long")]
    TraceIdTooLong,
    #[error("invalid trace digest")]
    InvalidTraceDigest,
    #[error("invalid verdict")]
    InvalidVerdict,
    #[error("too many reason codes")]
    TooManyReasonCodes,
    #[error("reason code too long")]
    ReasonCodeTooLong,
    #[error("reason codes not sorted")]
    ReasonCodesNotSorted,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TraceRunStoreError {
    #[error(transparent)]
    InvalidEvidence(#[from] TraceRunEvidenceError),
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Default)]
pub struct TraceRunStore {
    pub runs: Vec<TraceRunEvidence>,
    pub by_trace_digest: HashMap<[u8; 32], usize>,
}

impl TraceRunStore {
    pub fn insert(&mut self, evidence: TraceRunEvidence) -> Result<bool, TraceRunStoreError> {
        validate_trace_run_evidence(&evidence)?;
        let trace_digest = digest_from_bytes(&evidence.trace_digest)
            .ok_or(TraceRunEvidenceError::InvalidTraceDigest)?;
        if self.by_trace_digest.contains_key(&trace_digest) {
            return Ok(false);
        }
        self.by_trace_digest.insert(trace_digest, self.runs.len());
        self.runs.push(evidence);
        Ok(true)
    }

    pub fn get(&self, trace_digest: [u8; 32]) -> Option<&TraceRunEvidence> {
        self.by_trace_digest
            .get(&trace_digest)
            .and_then(|idx| self.runs.get(*idx))
    }

    pub fn len(&self) -> usize {
        self.runs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.runs.is_empty()
    }
}

fn is_sorted_unique(values: &[String]) -> bool {
    values
        .windows(2)
        .all(|pair| pair[0].as_str() < pair[1].as_str())
}

fn digest_from_bytes(bytes: &[u8]) -> Option<[u8; 32]> {
    if bytes.len() != 32 {
        return None;
    }

    let mut digest = [0u8; 32];
    digest.copy_from_slice(bytes);
    Some(digest)
}
