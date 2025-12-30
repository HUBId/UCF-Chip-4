#![forbid(unsafe_code)]

use std::collections::HashMap;
use thiserror::Error;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

const MAX_PROPOSAL_ID_LEN: usize = 128;
const MAX_REASON_CODES: usize = 16;
const MAX_REASON_CODE_LEN: usize = 64;

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProposalKind {
    MappingUpdate,
    SaePackUpdate,
    LiquidParamsUpdate,
    InjectionLimitsUpdate,
}

impl ProposalKind {
    fn to_u8(self) -> u8 {
        match self {
            ProposalKind::MappingUpdate => 1,
            ProposalKind::SaePackUpdate => 2,
            ProposalKind::LiquidParamsUpdate => 3,
            ProposalKind::InjectionLimitsUpdate => 4,
        }
    }

    fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(ProposalKind::MappingUpdate),
            2 => Some(ProposalKind::SaePackUpdate),
            3 => Some(ProposalKind::LiquidParamsUpdate),
            4 => Some(ProposalKind::InjectionLimitsUpdate),
            _ => None,
        }
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposalEvidence {
    pub proposal_id: String,
    pub proposal_digest: [u8; 32],
    pub kind: ProposalKind,
    pub base_evidence_digest: [u8; 32],
    pub payload_digest: [u8; 32],
    pub created_at_ms: u64,
    pub score: i32,
    pub verdict: u8,
    pub reason_codes: Vec<String>,
}

impl ProposalEvidence {
    pub fn normalize(&mut self) {
        self.reason_codes.sort();
        self.reason_codes.dedup();
    }

    pub fn validate(&self) -> Result<(), ProposalEvidenceError> {
        if self.proposal_id.is_empty() {
            return Err(ProposalEvidenceError::MissingProposalId);
        }
        if self.proposal_id.len() > MAX_PROPOSAL_ID_LEN {
            return Err(ProposalEvidenceError::ProposalIdTooLong);
        }
        if self.proposal_digest == [0u8; 32] {
            return Err(ProposalEvidenceError::InvalidProposalDigest);
        }
        if self.base_evidence_digest == [0u8; 32] {
            return Err(ProposalEvidenceError::InvalidBaseEvidenceDigest);
        }
        if self.payload_digest == [0u8; 32] {
            return Err(ProposalEvidenceError::InvalidPayloadDigest);
        }
        if self.verdict > 2 {
            return Err(ProposalEvidenceError::InvalidVerdict);
        }
        if self.reason_codes.len() > MAX_REASON_CODES {
            return Err(ProposalEvidenceError::TooManyReasonCodes);
        }
        if self
            .reason_codes
            .iter()
            .any(|code| code.len() > MAX_REASON_CODE_LEN)
        {
            return Err(ProposalEvidenceError::ReasonCodeTooLong);
        }
        if !is_sorted_unique(&self.reason_codes) {
            return Err(ProposalEvidenceError::ReasonCodesNotSorted);
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, ProposalEvidenceError> {
        self.validate()?;
        let mut out = Vec::new();
        write_len_prefixed_string(&mut out, &self.proposal_id)?;
        out.extend_from_slice(&self.proposal_digest);
        out.push(self.kind.to_u8());
        out.extend_from_slice(&self.base_evidence_digest);
        out.extend_from_slice(&self.payload_digest);
        out.extend_from_slice(&self.created_at_ms.to_be_bytes());
        out.extend_from_slice(&self.score.to_be_bytes());
        out.push(self.verdict);
        write_u16(&mut out, self.reason_codes.len() as u16);
        for reason in &self.reason_codes {
            write_len_prefixed_string(&mut out, reason)?;
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProposalEvidenceError> {
        let mut cursor = 0usize;
        let proposal_id = read_len_prefixed_string(bytes, &mut cursor)?;
        let proposal_digest = read_digest(bytes, &mut cursor)?;
        let kind_byte = read_u8(bytes, &mut cursor)?;
        let kind = ProposalKind::from_u8(kind_byte).ok_or(ProposalEvidenceError::InvalidKind)?;
        let base_evidence_digest = read_digest(bytes, &mut cursor)?;
        let payload_digest = read_digest(bytes, &mut cursor)?;
        let created_at_ms = read_u64(bytes, &mut cursor)?;
        let score = read_i32(bytes, &mut cursor)?;
        let verdict = read_u8(bytes, &mut cursor)?;
        let reason_count = read_u16(bytes, &mut cursor)? as usize;
        if reason_count > MAX_REASON_CODES {
            return Err(ProposalEvidenceError::TooManyReasonCodes);
        }
        let mut reason_codes = Vec::with_capacity(reason_count);
        for _ in 0..reason_count {
            reason_codes.push(read_len_prefixed_string(bytes, &mut cursor)?);
        }
        if cursor != bytes.len() {
            return Err(ProposalEvidenceError::PayloadTrailingBytes);
        }
        let evidence = Self {
            proposal_id,
            proposal_digest,
            kind,
            base_evidence_digest,
            payload_digest,
            created_at_ms,
            score,
            verdict,
            reason_codes,
        };
        evidence.validate()?;
        Ok(evidence)
    }
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
    #[error("payload truncated")]
    PayloadTruncated,
    #[error("payload trailing bytes")]
    PayloadTrailingBytes,
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
    pub fn insert(&mut self, mut evidence: ProposalEvidence) -> Result<bool, ProposalStoreError> {
        evidence.normalize();
        evidence.validate()?;
        if self.by_digest.contains_key(&evidence.proposal_digest) {
            return Ok(false);
        }
        self.order.push(evidence.proposal_digest);
        self.by_digest.insert(evidence.proposal_digest, evidence);
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

fn write_len_prefixed_string(out: &mut Vec<u8>, value: &str) -> Result<(), ProposalEvidenceError> {
    let bytes = value.as_bytes();
    if bytes.len() > u16::MAX as usize {
        return Err(ProposalEvidenceError::ProposalIdTooLong);
    }
    write_u16(out, bytes.len() as u16);
    out.extend_from_slice(bytes);
    Ok(())
}

fn write_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn read_u8(bytes: &[u8], cursor: &mut usize) -> Result<u8, ProposalEvidenceError> {
    if *cursor >= bytes.len() {
        return Err(ProposalEvidenceError::PayloadTruncated);
    }
    let value = bytes[*cursor];
    *cursor += 1;
    Ok(value)
}

fn read_u16(bytes: &[u8], cursor: &mut usize) -> Result<u16, ProposalEvidenceError> {
    if *cursor + 2 > bytes.len() {
        return Err(ProposalEvidenceError::PayloadTruncated);
    }
    let value = u16::from_be_bytes([bytes[*cursor], bytes[*cursor + 1]]);
    *cursor += 2;
    Ok(value)
}

fn read_u64(bytes: &[u8], cursor: &mut usize) -> Result<u64, ProposalEvidenceError> {
    if *cursor + 8 > bytes.len() {
        return Err(ProposalEvidenceError::PayloadTruncated);
    }
    let mut data = [0u8; 8];
    data.copy_from_slice(&bytes[*cursor..*cursor + 8]);
    *cursor += 8;
    Ok(u64::from_be_bytes(data))
}

fn read_i32(bytes: &[u8], cursor: &mut usize) -> Result<i32, ProposalEvidenceError> {
    if *cursor + 4 > bytes.len() {
        return Err(ProposalEvidenceError::PayloadTruncated);
    }
    let mut data = [0u8; 4];
    data.copy_from_slice(&bytes[*cursor..*cursor + 4]);
    *cursor += 4;
    Ok(i32::from_be_bytes(data))
}

fn read_digest(bytes: &[u8], cursor: &mut usize) -> Result<[u8; 32], ProposalEvidenceError> {
    if *cursor + 32 > bytes.len() {
        return Err(ProposalEvidenceError::PayloadTruncated);
    }
    let mut data = [0u8; 32];
    data.copy_from_slice(&bytes[*cursor..*cursor + 32]);
    *cursor += 32;
    Ok(data)
}

fn read_len_prefixed_string(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<String, ProposalEvidenceError> {
    let len = read_u16(bytes, cursor)? as usize;
    if *cursor + len > bytes.len() {
        return Err(ProposalEvidenceError::PayloadTruncated);
    }
    let value = std::str::from_utf8(&bytes[*cursor..*cursor + len])
        .map_err(|_| ProposalEvidenceError::PayloadTruncated)?;
    *cursor += len;
    Ok(value.to_string())
}
