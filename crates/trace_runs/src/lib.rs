#![forbid(unsafe_code)]

use std::collections::HashMap;
use thiserror::Error;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub const TRACE_RUN_EVIDENCE_DOMAIN: &str = "UCF:TRACE:RUN_EVIDENCE";
const MAX_TRACE_ID_LEN: usize = 128;
const MAX_REASON_CODES: usize = 16;
const MAX_REASON_CODE_LEN: usize = 64;
const MAX_STEPS: u32 = 1_000_000;

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceStatus {
    Pass,
    Fail,
}

impl TraceStatus {
    fn to_u8(self) -> u8 {
        match self {
            TraceStatus::Pass => 1,
            TraceStatus::Fail => 2,
        }
    }

    fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(TraceStatus::Pass),
            2 => Some(TraceStatus::Fail),
            _ => None,
        }
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceRunEvidence {
    pub trace_id: String,
    pub trace_run_digest: [u8; 32],
    pub asset_manifest_digest: [u8; 32],
    pub circuit_config_digest: [u8; 32],
    pub steps: u32,
    pub created_at_ms: u64,
    pub status: TraceStatus,
    pub reason_codes: Vec<String>,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TraceRunEvidenceError {
    #[error("trace id missing")]
    MissingTraceId,
    #[error("trace id too long")]
    TraceIdTooLong,
    #[error("invalid steps")]
    InvalidSteps,
    #[error("too many reason codes")]
    TooManyReasonCodes,
    #[error("reason code too long")]
    ReasonCodeTooLong,
    #[error("invalid status")]
    InvalidStatus,
    #[error("payload truncated")]
    PayloadTruncated,
    #[error("payload trailing bytes")]
    PayloadTrailingBytes,
}

impl TraceRunEvidence {
    pub fn validate(&self) -> Result<(), TraceRunEvidenceError> {
        if self.trace_id.is_empty() {
            return Err(TraceRunEvidenceError::MissingTraceId);
        }
        if self.trace_id.len() > MAX_TRACE_ID_LEN {
            return Err(TraceRunEvidenceError::TraceIdTooLong);
        }
        if self.steps == 0 || self.steps > MAX_STEPS {
            return Err(TraceRunEvidenceError::InvalidSteps);
        }
        if self.reason_codes.len() > MAX_REASON_CODES {
            return Err(TraceRunEvidenceError::TooManyReasonCodes);
        }
        if self
            .reason_codes
            .iter()
            .any(|code| code.len() > MAX_REASON_CODE_LEN)
        {
            return Err(TraceRunEvidenceError::ReasonCodeTooLong);
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, TraceRunEvidenceError> {
        self.validate()?;
        let mut out = Vec::new();
        write_len_prefixed_string(&mut out, &self.trace_id)?;
        out.extend_from_slice(&self.trace_run_digest);
        out.extend_from_slice(&self.asset_manifest_digest);
        out.extend_from_slice(&self.circuit_config_digest);
        out.extend_from_slice(&self.steps.to_be_bytes());
        out.extend_from_slice(&self.created_at_ms.to_be_bytes());
        out.push(self.status.to_u8());
        write_u16(&mut out, self.reason_codes.len() as u16);
        for reason in &self.reason_codes {
            write_len_prefixed_string(&mut out, reason)?;
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, TraceRunEvidenceError> {
        let mut cursor = 0usize;
        let trace_id = read_len_prefixed_string(bytes, &mut cursor)?;
        let trace_run_digest = read_digest(bytes, &mut cursor)?;
        let asset_manifest_digest = read_digest(bytes, &mut cursor)?;
        let circuit_config_digest = read_digest(bytes, &mut cursor)?;
        let steps = read_u32(bytes, &mut cursor)?;
        let created_at_ms = read_u64(bytes, &mut cursor)?;
        let status = read_u8(bytes, &mut cursor)?;
        let status = TraceStatus::from_u8(status).ok_or(TraceRunEvidenceError::InvalidStatus)?;
        let reason_count = read_u16(bytes, &mut cursor)? as usize;
        if reason_count > MAX_REASON_CODES {
            return Err(TraceRunEvidenceError::TooManyReasonCodes);
        }
        let mut reason_codes = Vec::with_capacity(reason_count);
        for _ in 0..reason_count {
            reason_codes.push(read_len_prefixed_string(bytes, &mut cursor)?);
        }
        if cursor != bytes.len() {
            return Err(TraceRunEvidenceError::PayloadTrailingBytes);
        }
        let evidence = Self {
            trace_id,
            trace_run_digest,
            asset_manifest_digest,
            circuit_config_digest,
            steps,
            created_at_ms,
            status,
            reason_codes,
        };
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn compute_digest(&self) -> Result<[u8; 32], TraceRunEvidenceError> {
        let mut payload = self.encode()?;
        let mut input = Vec::with_capacity(TRACE_RUN_EVIDENCE_DOMAIN.len() + payload.len());
        input.extend_from_slice(TRACE_RUN_EVIDENCE_DOMAIN.as_bytes());
        input.append(&mut payload);
        Ok(*blake3::hash(&input).as_bytes())
    }
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
    pub by_run_digest: HashMap<[u8; 32], usize>,
}

impl TraceRunStore {
    pub fn insert(&mut self, evidence: TraceRunEvidence) -> Result<bool, TraceRunStoreError> {
        evidence.validate()?;
        if self.by_run_digest.contains_key(&evidence.trace_run_digest) {
            return Ok(false);
        }
        self.by_run_digest
            .insert(evidence.trace_run_digest, self.runs.len());
        self.runs.push(evidence);
        Ok(true)
    }

    pub fn get(&self, run_digest: [u8; 32]) -> Option<&TraceRunEvidence> {
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

fn write_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn read_u16(bytes: &[u8], cursor: &mut usize) -> Result<u16, TraceRunEvidenceError> {
    if *cursor + 2 > bytes.len() {
        return Err(TraceRunEvidenceError::PayloadTruncated);
    }
    let mut buf = [0u8; 2];
    buf.copy_from_slice(&bytes[*cursor..*cursor + 2]);
    *cursor += 2;
    Ok(u16::from_be_bytes(buf))
}

fn read_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32, TraceRunEvidenceError> {
    if *cursor + 4 > bytes.len() {
        return Err(TraceRunEvidenceError::PayloadTruncated);
    }
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&bytes[*cursor..*cursor + 4]);
    *cursor += 4;
    Ok(u32::from_be_bytes(buf))
}

fn read_u64(bytes: &[u8], cursor: &mut usize) -> Result<u64, TraceRunEvidenceError> {
    if *cursor + 8 > bytes.len() {
        return Err(TraceRunEvidenceError::PayloadTruncated);
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[*cursor..*cursor + 8]);
    *cursor += 8;
    Ok(u64::from_be_bytes(buf))
}

fn read_u8(bytes: &[u8], cursor: &mut usize) -> Result<u8, TraceRunEvidenceError> {
    if *cursor + 1 > bytes.len() {
        return Err(TraceRunEvidenceError::PayloadTruncated);
    }
    let value = bytes[*cursor];
    *cursor += 1;
    Ok(value)
}

fn read_digest(bytes: &[u8], cursor: &mut usize) -> Result<[u8; 32], TraceRunEvidenceError> {
    if *cursor + 32 > bytes.len() {
        return Err(TraceRunEvidenceError::PayloadTruncated);
    }
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&bytes[*cursor..*cursor + 32]);
    *cursor += 32;
    Ok(digest)
}

fn write_len_prefixed_string(out: &mut Vec<u8>, value: &str) -> Result<(), TraceRunEvidenceError> {
    write_u16(out, value.len() as u16);
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

fn read_len_prefixed_string(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<String, TraceRunEvidenceError> {
    let len = read_u16(bytes, cursor)? as usize;
    if *cursor + len > bytes.len() {
        return Err(TraceRunEvidenceError::PayloadTruncated);
    }
    let value = String::from_utf8(bytes[*cursor..*cursor + len].to_vec())
        .map_err(|_| TraceRunEvidenceError::PayloadTruncated)?;
    *cursor += len;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_trace_run_evidence() {
        let evidence = TraceRunEvidence {
            trace_id: "trace-1".to_string(),
            trace_run_digest: [1u8; 32],
            asset_manifest_digest: [2u8; 32],
            circuit_config_digest: [3u8; 32],
            steps: 12,
            created_at_ms: 999,
            status: TraceStatus::Pass,
            reason_codes: vec!["RC.GV.OK".to_string()],
        };
        let encoded = evidence.encode().expect("encode");
        let decoded = TraceRunEvidence::decode(&encoded).expect("decode");
        assert_eq!(decoded, evidence);
    }
}
