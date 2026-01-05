#![forbid(unsafe_code)]

use std::collections::HashMap;
use thiserror::Error;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub const ACTIVATION_EVIDENCE_DOMAIN: &str = "UCF:LNSS:ACTIVATION";
const MAX_ACTIVATION_ID_LEN: usize = 128;
const MAX_REASON_CODES: usize = 16;
const MAX_REASON_CODE_LEN: usize = 64;

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationStatus {
    Applied,
    Rejected,
}

impl ActivationStatus {
    fn to_u8(self) -> u8 {
        match self {
            ActivationStatus::Applied => 1,
            ActivationStatus::Rejected => 2,
        }
    }

    fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(ActivationStatus::Applied),
            2 => Some(ActivationStatus::Rejected),
            _ => None,
        }
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposalActivationEvidence {
    pub activation_id: String,
    pub activation_digest: [u8; 32],
    pub proposal_digest: [u8; 32],
    pub approval_digest: [u8; 32],
    pub status: ActivationStatus,
    pub active_mapping_digest: Option<[u8; 32]>,
    pub active_sae_pack_digest: Option<[u8; 32]>,
    pub active_liquid_params_digest: Option<[u8; 32]>,
    pub active_limits_digest: Option<[u8; 32]>,
    pub created_at_ms: u64,
    pub reason_codes: Vec<String>,
}

impl ProposalActivationEvidence {
    pub fn normalize(&mut self) {
        self.reason_codes.sort();
        self.reason_codes.dedup();
    }

    pub fn validate(&self) -> Result<(), ProposalActivationEvidenceError> {
        self.validate_internal(true)
    }

    fn validate_internal(
        &self,
        check_activation_digest: bool,
    ) -> Result<(), ProposalActivationEvidenceError> {
        if self.activation_id.is_empty() {
            return Err(ProposalActivationEvidenceError::MissingActivationId);
        }
        if self.activation_id.len() > MAX_ACTIVATION_ID_LEN {
            return Err(ProposalActivationEvidenceError::ActivationIdTooLong);
        }
        if check_activation_digest && self.activation_digest == [0u8; 32] {
            return Err(ProposalActivationEvidenceError::InvalidActivationDigest);
        }
        if self.proposal_digest == [0u8; 32] {
            return Err(ProposalActivationEvidenceError::InvalidProposalDigest);
        }
        if self.approval_digest == [0u8; 32] {
            return Err(ProposalActivationEvidenceError::InvalidApprovalDigest);
        }
        if self
            .active_mapping_digest
            .is_some_and(|digest| digest == [0u8; 32])
        {
            return Err(ProposalActivationEvidenceError::InvalidActiveMappingDigest);
        }
        if self
            .active_sae_pack_digest
            .is_some_and(|digest| digest == [0u8; 32])
        {
            return Err(ProposalActivationEvidenceError::InvalidActiveSaePackDigest);
        }
        if self
            .active_liquid_params_digest
            .is_some_and(|digest| digest == [0u8; 32])
        {
            return Err(ProposalActivationEvidenceError::InvalidActiveLiquidParamsDigest);
        }
        if self
            .active_limits_digest
            .is_some_and(|digest| digest == [0u8; 32])
        {
            return Err(ProposalActivationEvidenceError::InvalidActiveLimitsDigest);
        }
        if self.reason_codes.len() > MAX_REASON_CODES {
            return Err(ProposalActivationEvidenceError::TooManyReasonCodes);
        }
        if self
            .reason_codes
            .iter()
            .any(|code| code.len() > MAX_REASON_CODE_LEN)
        {
            return Err(ProposalActivationEvidenceError::ReasonCodeTooLong);
        }
        if !is_sorted_unique(&self.reason_codes) {
            return Err(ProposalActivationEvidenceError::ReasonCodesNotSorted);
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, ProposalActivationEvidenceError> {
        self.encode_internal(true)
    }

    fn encode_internal(
        &self,
        check_activation_digest: bool,
    ) -> Result<Vec<u8>, ProposalActivationEvidenceError> {
        self.validate_internal(check_activation_digest)?;
        let mut out = Vec::new();
        write_len_prefixed_string(&mut out, &self.activation_id)?;
        out.extend_from_slice(&self.activation_digest);
        out.extend_from_slice(&self.proposal_digest);
        out.extend_from_slice(&self.approval_digest);
        out.push(self.status.to_u8());
        write_optional_digest(&mut out, self.active_mapping_digest);
        write_optional_digest(&mut out, self.active_sae_pack_digest);
        write_optional_digest(&mut out, self.active_liquid_params_digest);
        write_optional_digest(&mut out, self.active_limits_digest);
        out.extend_from_slice(&self.created_at_ms.to_be_bytes());
        write_u16(&mut out, self.reason_codes.len() as u16);
        for reason in &self.reason_codes {
            write_len_prefixed_string(&mut out, reason)?;
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProposalActivationEvidenceError> {
        let mut cursor = 0usize;
        let activation_id = read_len_prefixed_string(bytes, &mut cursor)?;
        let activation_digest = read_digest(bytes, &mut cursor)?;
        let proposal_digest = read_digest(bytes, &mut cursor)?;
        let approval_digest = read_digest(bytes, &mut cursor)?;
        let status_byte = read_u8(bytes, &mut cursor)?;
        let status = ActivationStatus::from_u8(status_byte)
            .ok_or(ProposalActivationEvidenceError::InvalidStatus)?;
        let active_mapping_digest = read_optional_digest(bytes, &mut cursor)?;
        let active_sae_pack_digest = read_optional_digest(bytes, &mut cursor)?;
        let active_liquid_params_digest = read_optional_digest(bytes, &mut cursor)?;
        let active_limits_digest = read_optional_digest(bytes, &mut cursor)?;
        let created_at_ms = read_u64(bytes, &mut cursor)?;
        let reason_count = read_u16(bytes, &mut cursor)? as usize;
        if reason_count > MAX_REASON_CODES {
            return Err(ProposalActivationEvidenceError::TooManyReasonCodes);
        }
        let mut reason_codes = Vec::with_capacity(reason_count);
        for _ in 0..reason_count {
            reason_codes.push(read_len_prefixed_string(bytes, &mut cursor)?);
        }
        if cursor != bytes.len() {
            return Err(ProposalActivationEvidenceError::PayloadTrailingBytes);
        }
        let evidence = Self {
            activation_id,
            activation_digest,
            proposal_digest,
            approval_digest,
            status,
            active_mapping_digest,
            active_sae_pack_digest,
            active_liquid_params_digest,
            active_limits_digest,
            created_at_ms,
            reason_codes,
        };
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn compute_digest(&self) -> Result<[u8; 32], ProposalActivationEvidenceError> {
        let mut canonical = self.clone();
        canonical.activation_digest = [0u8; 32];
        canonical.normalize();
        let mut payload = canonical.encode_internal(false)?;
        let mut input = Vec::with_capacity(ACTIVATION_EVIDENCE_DOMAIN.len() + payload.len());
        input.extend_from_slice(ACTIVATION_EVIDENCE_DOMAIN.as_bytes());
        input.append(&mut payload);
        Ok(*blake3::hash(&input).as_bytes())
    }
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
    #[error("payload truncated")]
    PayloadTruncated,
    #[error("payload trailing bytes")]
    PayloadTrailingBytes,
    #[error("invalid optional digest flag")]
    InvalidOptionalDigestFlag,
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
    pub order: Vec<[u8; 32]>,
}

impl ProposalActivationStore {
    pub fn insert(
        &mut self,
        mut evidence: ProposalActivationEvidence,
    ) -> Result<bool, ProposalActivationStoreError> {
        evidence.normalize();
        evidence.validate()?;
        if self.by_digest.contains_key(&evidence.activation_digest) {
            return Ok(false);
        }
        self.order.push(evidence.activation_digest);
        self.by_digest.insert(evidence.activation_digest, evidence);
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

fn write_len_prefixed_string(
    out: &mut Vec<u8>,
    value: &str,
) -> Result<(), ProposalActivationEvidenceError> {
    let bytes = value.as_bytes();
    if bytes.len() > u16::MAX as usize {
        return Err(ProposalActivationEvidenceError::ActivationIdTooLong);
    }
    write_u16(out, bytes.len() as u16);
    out.extend_from_slice(bytes);
    Ok(())
}

fn write_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn write_optional_digest(out: &mut Vec<u8>, value: Option<[u8; 32]>) {
    match value {
        Some(digest) => {
            out.push(1u8);
            out.extend_from_slice(&digest);
        }
        None => out.push(0u8),
    }
}

fn read_u8(bytes: &[u8], cursor: &mut usize) -> Result<u8, ProposalActivationEvidenceError> {
    if *cursor >= bytes.len() {
        return Err(ProposalActivationEvidenceError::PayloadTruncated);
    }
    let value = bytes[*cursor];
    *cursor += 1;
    Ok(value)
}

fn read_u16(bytes: &[u8], cursor: &mut usize) -> Result<u16, ProposalActivationEvidenceError> {
    if *cursor + 2 > bytes.len() {
        return Err(ProposalActivationEvidenceError::PayloadTruncated);
    }
    let value = u16::from_be_bytes([bytes[*cursor], bytes[*cursor + 1]]);
    *cursor += 2;
    Ok(value)
}

fn read_u64(bytes: &[u8], cursor: &mut usize) -> Result<u64, ProposalActivationEvidenceError> {
    if *cursor + 8 > bytes.len() {
        return Err(ProposalActivationEvidenceError::PayloadTruncated);
    }
    let mut data = [0u8; 8];
    data.copy_from_slice(&bytes[*cursor..*cursor + 8]);
    *cursor += 8;
    Ok(u64::from_be_bytes(data))
}

fn read_digest(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<[u8; 32], ProposalActivationEvidenceError> {
    if *cursor + 32 > bytes.len() {
        return Err(ProposalActivationEvidenceError::PayloadTruncated);
    }
    let mut data = [0u8; 32];
    data.copy_from_slice(&bytes[*cursor..*cursor + 32]);
    *cursor += 32;
    Ok(data)
}

fn read_optional_digest(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<Option<[u8; 32]>, ProposalActivationEvidenceError> {
    let flag = read_u8(bytes, cursor)?;
    match flag {
        0 => Ok(None),
        1 => Ok(Some(read_digest(bytes, cursor)?)),
        _ => Err(ProposalActivationEvidenceError::InvalidOptionalDigestFlag),
    }
}

fn read_len_prefixed_string(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<String, ProposalActivationEvidenceError> {
    let len = read_u16(bytes, cursor)? as usize;
    if *cursor + len > bytes.len() {
        return Err(ProposalActivationEvidenceError::PayloadTruncated);
    }
    let value = std::str::from_utf8(&bytes[*cursor..*cursor + len])
        .map_err(|_| ProposalActivationEvidenceError::PayloadTruncated)?;
    *cursor += len;
    Ok(value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_evidence(status: ActivationStatus) -> ProposalActivationEvidence {
        ProposalActivationEvidence {
            activation_id: "act-1".to_string(),
            activation_digest: [1u8; 32],
            proposal_digest: [2u8; 32],
            approval_digest: [3u8; 32],
            status,
            active_mapping_digest: Some([4u8; 32]),
            active_sae_pack_digest: None,
            active_liquid_params_digest: Some([5u8; 32]),
            active_limits_digest: None,
            created_at_ms: 10,
            reason_codes: vec!["b".to_string(), "a".to_string()],
        }
    }

    #[test]
    fn encode_decode_roundtrip() {
        let mut evidence = sample_evidence(ActivationStatus::Applied);
        evidence.normalize();
        let payload = evidence.encode().expect("encode");
        let decoded = ProposalActivationEvidence::decode(&payload).expect("decode");
        assert_eq!(decoded.activation_id, "act-1");
        assert_eq!(decoded.status, ActivationStatus::Applied);
        assert_eq!(decoded.reason_codes, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn digest_is_deterministic() {
        let mut evidence = sample_evidence(ActivationStatus::Rejected);
        evidence.normalize();
        let digest_one = evidence.compute_digest().expect("digest");
        let digest_two = evidence.compute_digest().expect("digest");
        assert_eq!(digest_one, digest_two);
    }
}
