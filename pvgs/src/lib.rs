#![forbid(unsafe_code)]

use thiserror::Error;
use wire::Envelope;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PvgsCommitRequest {
    pub envelope: Envelope,
    pub correlation_id: String,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PvgsCommitResponse {
    pub accepted: bool,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PvgsVerificationRequest {
    pub commitment_id: String,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PvgsVerificationResult {
    pub verified: bool,
    pub notes: Vec<String>,
}

pub trait PvgsCommitService {
    fn commit(&self, request: PvgsCommitRequest) -> Result<PvgsCommitResponse, PvgsError>;
}

pub trait PvgsVerificationService {
    fn verify(&self, request: PvgsVerificationRequest)
        -> Result<PvgsVerificationResult, PvgsError>;
}

#[derive(Debug, Error)]
pub enum PvgsError {
    #[error("validation failed: {0}")]
    Validation(String),
    #[error("internal error: {0}")]
    Internal(String),
}
