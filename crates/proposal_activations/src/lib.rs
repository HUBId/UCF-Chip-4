#![forbid(unsafe_code)]

use std::collections::HashMap;

use prost::Message;
use thiserror::Error;
pub use ucf_protocol::ucf::v1::{ActivationStatus, ProposalActivationEvidence};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub const ACTIVATION_EVIDENCE_DOMAIN: &str = "UCF:ACTIVATION_EVIDENCE";
const MAX_ACTIVATION_ID_LEN: usize = 64;
const MAX_REASON_CODES: usize = 32;
const MAX_REASON_CODE_LEN: usize = 64;

pub fn validate_proposal_activation_evidence(
    evidence: &ProposalActivationEvidence,
) -> Result<(), ProposalActivationEvidenceError> {
    validate_internal(evidence, true)
}

fn validate_internal(
    evidence: &ProposalActivationEvidence,
    check_activation_digest: bool,
) -> Result<(), ProposalActivationEvidenceError> {
    if evidence.activation_id.is_empty() {
        return Err(ProposalActivationEvidenceError::MissingActivationId);
    }
    if evidence.activation_id.len() > MAX_ACTIVATION_ID_LEN {
        return Err(ProposalActivationEvidenceError::ActivationIdTooLong);
    }
    let activation_digest = digest_from_bytes(&evidence.activation_digest)
        .ok_or(ProposalActivationEvidenceError::InvalidActivationDigest)?;
    if check_activation_digest && activation_digest == [0u8; 32] {
        return Err(ProposalActivationEvidenceError::InvalidActivationDigest);
    }
    let proposal_digest = digest_from_bytes(&evidence.proposal_digest)
        .ok_or(ProposalActivationEvidenceError::InvalidProposalDigest)?;
    if proposal_digest == [0u8; 32] {
        return Err(ProposalActivationEvidenceError::InvalidProposalDigest);
    }
    let approval_digest = digest_from_bytes(&evidence.approval_digest)
        .ok_or(ProposalActivationEvidenceError::InvalidApprovalDigest)?;
    if approval_digest == [0u8; 32] {
        return Err(ProposalActivationEvidenceError::InvalidApprovalDigest);
    }
    let status =
        ActivationStatus::try_from(evidence.status).unwrap_or(ActivationStatus::Unspecified);
    if matches!(status, ActivationStatus::Unspecified) {
        return Err(ProposalActivationEvidenceError::InvalidStatus);
    }
    if evidence
        .active_mapping_digest
        .as_ref()
        .is_some_and(|digest| digest_from_bytes(digest).is_none_or(|value| value == [0u8; 32]))
    {
        return Err(ProposalActivationEvidenceError::InvalidActiveMappingDigest);
    }
    if evidence
        .active_sae_pack_digest
        .as_ref()
        .is_some_and(|digest| digest_from_bytes(digest).is_none_or(|value| value == [0u8; 32]))
    {
        return Err(ProposalActivationEvidenceError::InvalidActiveSaePackDigest);
    }
    if evidence
        .active_liquid_params_digest
        .as_ref()
        .is_some_and(|digest| digest_from_bytes(digest).is_none_or(|value| value == [0u8; 32]))
    {
        return Err(ProposalActivationEvidenceError::InvalidActiveLiquidParamsDigest);
    }
    if evidence
        .active_limits_digest
        .as_ref()
        .is_some_and(|digest| digest_from_bytes(digest).is_none_or(|value| value == [0u8; 32]))
    {
        return Err(ProposalActivationEvidenceError::InvalidActiveLimitsDigest);
    }
    if evidence.reason_codes.len() > MAX_REASON_CODES {
        return Err(ProposalActivationEvidenceError::TooManyReasonCodes);
    }
    if evidence
        .reason_codes
        .iter()
        .any(|code| code.len() > MAX_REASON_CODE_LEN)
    {
        return Err(ProposalActivationEvidenceError::ReasonCodeTooLong);
    }
    if !is_sorted_unique(&evidence.reason_codes) {
        return Err(ProposalActivationEvidenceError::ReasonCodesNotSorted);
    }
    Ok(())
}

pub fn compute_proposal_activation_digest(
    evidence: &ProposalActivationEvidence,
) -> Result<[u8; 32], ProposalActivationEvidenceError> {
    validate_internal(evidence, false)?;
    let mut canonical = evidence.clone();
    canonical.activation_digest = vec![0u8; 32];
    let payload = canonical.encode_to_vec();
    let mut input = Vec::with_capacity(ACTIVATION_EVIDENCE_DOMAIN.len() + payload.len());
    input.extend_from_slice(ACTIVATION_EVIDENCE_DOMAIN.as_bytes());
    input.extend_from_slice(&payload);
    Ok(*blake3::hash(&input).as_bytes())
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProposalActivationEvidenceError {
    #[error("activation id missing")]
    MissingActivationId,
    #[error("activation id too long")]
    ActivationIdTooLong,
    #[error("invalid activation digest")]
    InvalidActivationDigest,
    #[error("invalid proposal digest")]
    InvalidProposalDigest,
    #[error("invalid approval digest")]
    InvalidApprovalDigest,
    #[error("invalid status")]
    InvalidStatus,
    #[error("invalid active mapping digest")]
    InvalidActiveMappingDigest,
    #[error("invalid active sae pack digest")]
    InvalidActiveSaePackDigest,
    #[error("invalid active liquid params digest")]
    InvalidActiveLiquidParamsDigest,
    #[error("invalid active limits digest")]
    InvalidActiveLimitsDigest,
    #[error("too many reason codes")]
    TooManyReasonCodes,
    #[error("reason code too long")]
    ReasonCodeTooLong,
    #[error("reason codes not sorted")]
    ReasonCodesNotSorted,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProposalActivationStoreError {
    #[error(transparent)]
    Evidence(#[from] ProposalActivationEvidenceError),
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Default)]
pub struct ProposalActivationStore {
    pub by_digest: HashMap<[u8; 32], ProposalActivationEvidence>,
}

impl ProposalActivationStore {
    pub fn insert(
        &mut self,
        evidence: ProposalActivationEvidence,
    ) -> Result<bool, ProposalActivationStoreError> {
        validate_proposal_activation_evidence(&evidence)?;
        let digest = digest_from_bytes(&evidence.activation_digest)
            .ok_or(ProposalActivationEvidenceError::InvalidActivationDigest)?;
        if self.by_digest.contains_key(&digest) {
            return Ok(false);
        }
        self.by_digest.insert(digest, evidence);
        Ok(true)
    }

    pub fn get(&self, digest: [u8; 32]) -> Option<&ProposalActivationEvidence> {
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
