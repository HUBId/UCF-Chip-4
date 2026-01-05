#![forbid(unsafe_code)]

use std::collections::HashMap;
use thiserror::Error;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub const TRACE_RUN_EVIDENCE_DOMAIN: &str = "UCF:LNSS:TRACE_RUN";
const MAX_TRACE_ID_LEN: usize = 64;
const MAX_REASON_CODES: usize = 32;
const MAX_REASON_CODE_LEN: usize = 64;

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceVerdict {
    Promising = 1,
    Neutral = 2,
    Risky = 3,
}

impl TraceVerdict {
    fn to_u8(self) -> u8 {
        match self {
            TraceVerdict::Promising => 1,
            TraceVerdict::Neutral => 2,
            TraceVerdict::Risky => 3,
        }
    }

    fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(TraceVerdict::Promising),
            2 => Some(TraceVerdict::Neutral),
            3 => Some(TraceVerdict::Risky),
            _ => None,
        }
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceRunEvidence {
    pub trace_id: String,
    pub trace_digest: [u8; 32],
    pub active_cfg_digest: [u8; 32],
    pub shadow_cfg_digest: [u8; 32],
    pub active_feedback_digest: [u8; 32],
    pub shadow_feedback_digest: [u8; 32],
    pub score_active: i32,
    pub score_shadow: i32,
    pub delta: i32,
    pub verdict: TraceVerdict,
    pub created_at_ms: u64,
    pub reason_codes: Vec<String>,
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
    #[error("too many reason codes")]
    TooManyReasonCodes,
    #[error("reason code too long")]
    ReasonCodeTooLong,
    #[error("reason codes not sorted")]
    ReasonCodesNotSorted,
    #[error("invalid verdict")]
    InvalidVerdict,
    #[error("payload truncated")]
    PayloadTruncated,
    #[error("payload trailing bytes")]
    PayloadTrailingBytes,
}

impl TraceRunEvidence {
    pub fn normalize(&mut self) {
        self.reason_codes.sort();
        self.reason_codes.dedup();
    }

    pub fn validate(&self) -> Result<(), TraceRunEvidenceError> {
        self.validate_internal(true)
    }

    fn validate_internal(&self, check_trace_digest: bool) -> Result<(), TraceRunEvidenceError> {
        if self.trace_id.is_empty() {
            return Err(TraceRunEvidenceError::MissingTraceId);
        }
        if self.trace_id.len() > MAX_TRACE_ID_LEN {
            return Err(TraceRunEvidenceError::TraceIdTooLong);
        }
        if check_trace_digest && self.trace_digest == [0u8; 32] {
            return Err(TraceRunEvidenceError::InvalidTraceDigest);
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
        if !is_sorted_unique(&self.reason_codes) {
            return Err(TraceRunEvidenceError::ReasonCodesNotSorted);
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, TraceRunEvidenceError> {
        self.encode_internal(true)
    }

    fn encode_internal(&self, check_trace_digest: bool) -> Result<Vec<u8>, TraceRunEvidenceError> {
        self.validate_internal(check_trace_digest)?;
        let mut out = Vec::new();
        write_len_prefixed_string(&mut out, &self.trace_id)?;
        out.extend_from_slice(&self.trace_digest);
        out.extend_from_slice(&self.active_cfg_digest);
        out.extend_from_slice(&self.shadow_cfg_digest);
        out.extend_from_slice(&self.active_feedback_digest);
        out.extend_from_slice(&self.shadow_feedback_digest);
        out.extend_from_slice(&self.score_active.to_be_bytes());
        out.extend_from_slice(&self.score_shadow.to_be_bytes());
        out.extend_from_slice(&self.delta.to_be_bytes());
        out.push(self.verdict.to_u8());
        out.extend_from_slice(&self.created_at_ms.to_be_bytes());
        write_u16(&mut out, self.reason_codes.len() as u16);
        for reason in &self.reason_codes {
            write_len_prefixed_string(&mut out, reason)?;
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, TraceRunEvidenceError> {
        let mut cursor = 0usize;
        let trace_id = read_len_prefixed_string(bytes, &mut cursor)?;
        let trace_digest = read_digest(bytes, &mut cursor)?;
        let active_cfg_digest = read_digest(bytes, &mut cursor)?;
        let shadow_cfg_digest = read_digest(bytes, &mut cursor)?;
        let active_feedback_digest = read_digest(bytes, &mut cursor)?;
        let shadow_feedback_digest = read_digest(bytes, &mut cursor)?;
        let score_active = read_i32(bytes, &mut cursor)?;
        let score_shadow = read_i32(bytes, &mut cursor)?;
        let delta = read_i32(bytes, &mut cursor)?;
        let verdict = read_u8(bytes, &mut cursor)?;
        let verdict =
            TraceVerdict::from_u8(verdict).ok_or(TraceRunEvidenceError::InvalidVerdict)?;
        let created_at_ms = read_u64(bytes, &mut cursor)?;
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
            trace_digest,
            active_cfg_digest,
            shadow_cfg_digest,
            active_feedback_digest,
            shadow_feedback_digest,
            score_active,
            score_shadow,
            delta,
            verdict,
            created_at_ms,
            reason_codes,
        };
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn compute_digest(&self) -> Result<[u8; 32], TraceRunEvidenceError> {
        let mut canonical = self.clone();
        canonical.trace_digest = [0u8; 32];
        canonical.normalize();
        let mut payload = canonical.encode_internal(false)?;
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
    pub by_trace_digest: HashMap<[u8; 32], usize>,
}

impl TraceRunStore {
    pub fn insert(&mut self, evidence: TraceRunEvidence) -> Result<bool, TraceRunStoreError> {
        evidence.validate()?;
        if self.by_trace_digest.contains_key(&evidence.trace_digest) {
            return Ok(false);
        }
        self.by_trace_digest
            .insert(evidence.trace_digest, self.runs.len());
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

fn read_i32(bytes: &[u8], cursor: &mut usize) -> Result<i32, TraceRunEvidenceError> {
    if *cursor + 4 > bytes.len() {
        return Err(TraceRunEvidenceError::PayloadTruncated);
    }
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&bytes[*cursor..*cursor + 4]);
    *cursor += 4;
    Ok(i32::from_be_bytes(buf))
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

fn is_sorted_unique(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_trace_run_evidence() {
        let mut evidence = TraceRunEvidence {
            trace_id: "trace-1".to_string(),
            trace_digest: [0u8; 32],
            active_cfg_digest: [1u8; 32],
            shadow_cfg_digest: [2u8; 32],
            active_feedback_digest: [3u8; 32],
            shadow_feedback_digest: [4u8; 32],
            score_active: 10,
            score_shadow: 12,
            delta: 2,
            verdict: TraceVerdict::Promising,
            created_at_ms: 999,
            reason_codes: vec!["RC.GV.OK".to_string(), "RC.GV.OK.2".to_string()],
        };
        let digest = evidence.compute_digest().expect("digest");
        evidence.trace_digest = digest;
        let encoded = evidence.encode().expect("encode");
        let decoded = TraceRunEvidence::decode(&encoded).expect("decode");
        assert_eq!(decoded, evidence);
    }
}
