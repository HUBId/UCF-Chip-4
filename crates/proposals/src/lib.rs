#![forbid(unsafe_code)]

use std::collections::HashMap;

use prost::Message;
use thiserror::Error;
pub use ucf_protocol::ucf::v1::{ProposalEvidence, ProposalKind};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub const PROPOSAL_EVIDENCE_DOMAIN: &str = "UCF:PROPOSAL_EVIDENCE";
const MAX_PROPOSAL_ID_LEN: usize = 64;
const MAX_REASON_CODES: usize = 32;
const MAX_REASON_CODE_LEN: usize = 64;

pub fn validate_proposal_evidence(
    evidence: &ProposalEvidence,
) -> Result<(), ProposalEvidenceError> {
    validate_internal(evidence, true)
}

fn validate_internal(
    evidence: &ProposalEvidence,
    check_proposal_digest: bool,
) -> Result<(), ProposalEvidenceError> {
    if evidence.proposal_id.is_empty() {
        return Err(ProposalEvidenceError::MissingProposalId);
    }
    if evidence.proposal_id.len() > MAX_PROPOSAL_ID_LEN {
        return Err(ProposalEvidenceError::ProposalIdTooLong);
    }
    let kind = ProposalKind::try_from(evidence.kind).unwrap_or(ProposalKind::Unspecified);
    if matches!(kind, ProposalKind::Unspecified) {
        return Err(ProposalEvidenceError::InvalidKind);
    }
    let proposal_digest = digest_from_bytes(&evidence.proposal_digest)
        .ok_or(ProposalEvidenceError::InvalidProposalDigest)?;
    if check_proposal_digest && proposal_digest == [0u8; 32] {
        return Err(ProposalEvidenceError::InvalidProposalDigest);
    }
    let base_evidence_digest = digest_from_bytes(&evidence.base_evidence_digest)
        .ok_or(ProposalEvidenceError::InvalidBaseEvidenceDigest)?;
    if base_evidence_digest == [0u8; 32] {
        return Err(ProposalEvidenceError::InvalidBaseEvidenceDigest);
    }
    let payload_digest = digest_from_bytes(&evidence.payload_digest)
        .ok_or(ProposalEvidenceError::InvalidPayloadDigest)?;
    if payload_digest == [0u8; 32] {
        return Err(ProposalEvidenceError::InvalidPayloadDigest);
    }
    if !(0..=2).contains(&evidence.verdict) {
        return Err(ProposalEvidenceError::InvalidVerdict);
    }
    if evidence.reason_codes.len() > MAX_REASON_CODES {
        return Err(ProposalEvidenceError::TooManyReasonCodes);
    }
    if evidence
        .reason_codes
        .iter()
        .any(|code| code.len() > MAX_REASON_CODE_LEN)
    {
        return Err(ProposalEvidenceError::ReasonCodeTooLong);
    }
    if !is_sorted_unique(&evidence.reason_codes) {
        return Err(ProposalEvidenceError::ReasonCodesNotSorted);
    }
    Ok(())
}

pub fn compute_proposal_evidence_digest(
    evidence: &ProposalEvidence,
) -> Result<[u8; 32], ProposalEvidenceError> {
    validate_internal(evidence, false)?;
    let mut canonical = evidence.clone();
    canonical.proposal_digest = vec![0u8; 32];
    let payload = canonical.encode_to_vec();
    let mut input = Vec::with_capacity(PROPOSAL_EVIDENCE_DOMAIN.len() + payload.len());
    input.extend_from_slice(PROPOSAL_EVIDENCE_DOMAIN.as_bytes());
    input.extend_from_slice(&payload);
    Ok(*blake3::hash(&input).as_bytes())
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProposalEvidenceError {
    #[error("proposal id missing")]
    MissingProposalId,
    #[error("proposal id too long")]
    ProposalIdTooLong,
    #[error("invalid proposal digest")]
    InvalidProposalDigest,
    #[error("invalid kind")]
    InvalidKind,
    #[error("invalid base evidence digest")]
    InvalidBaseEvidenceDigest,
    #[error("invalid payload digest")]
    InvalidPayloadDigest,
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
pub enum ProposalStoreError {
    #[error(transparent)]
    Evidence(#[from] ProposalEvidenceError),
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Default)]
pub struct ProposalStore {
    pub by_digest: HashMap<[u8; 32], ProposalEvidence>,
    pub order: Vec<[u8; 32]>,
}

impl ProposalStore {
    pub fn insert(&mut self, evidence: ProposalEvidence) -> Result<bool, ProposalStoreError> {
        validate_proposal_evidence(&evidence)?;
        let digest = digest_from_bytes(&evidence.proposal_digest)
            .ok_or(ProposalEvidenceError::InvalidProposalDigest)?;
        if self.by_digest.contains_key(&digest) {
            return Ok(false);
        }
        self.order.push(digest);
        self.by_digest.insert(digest, evidence);
        Ok(true)
    }

    pub fn get(&self, digest: [u8; 32]) -> Option<&ProposalEvidence> {
        self.by_digest.get(&digest)
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
