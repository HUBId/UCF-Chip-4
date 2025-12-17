#![forbid(unsafe_code)]

use pvgs::{PvgsCommitResponse, PvgsVerificationResult};
use thiserror::Error;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PvgsReceipt {
    pub request_id: String,
    pub commit: PvgsCommitResponse,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofReceipt {
    pub receipt_id: String,
    pub verification: PvgsVerificationResult,
}

pub trait ReceiptStore {
    fn record_pvgs_receipt(&self, receipt: PvgsReceipt) -> Result<(), ReceiptError>;
    fn record_proof_receipt(&self, receipt: ProofReceipt) -> Result<(), ReceiptError>;
}

#[derive(Debug, Error)]
pub enum ReceiptError {
    #[error("persistence failed: {0}")]
    Persistence(String),
    #[error("not found: {0}")]
    NotFound(String),
}
