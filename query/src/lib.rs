#![forbid(unsafe_code)]

use cbv::CharacterBaselineVector;
use keys::KeyEpoch;
use pvgs::{PvgsCommitRequest, PvgsVerificationResult};
use receipts::{ProofReceipt, PvgsReceipt};
use sep::SepEvent;
use thiserror::Error;
use vrf::{VrfInput, VrfOutput};
use wire::{AuthContext, Envelope};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryRequest {
    pub subject: String,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryResult {
    pub auth: Option<AuthContext>,
    pub baseline: Option<CharacterBaselineVector>,
    pub last_commit: Option<PvgsReceipt>,
    pub last_verification: Option<ProofReceipt>,
    pub current_epoch: Option<KeyEpoch>,
    pub latest_event: Option<SepEvent>,
    pub recent_vrf: Option<(VrfInput, VrfOutput)>,
}

pub trait QueryInspector {
    fn fetch(&self, request: QueryRequest) -> Result<QueryResult, QueryError>;
    fn prepare_commit(&self, envelope: Envelope) -> Result<PvgsCommitRequest, QueryError>;
    fn summarize_verification(
        &self,
        verification: PvgsVerificationResult,
    ) -> Result<ProofReceipt, QueryError>;
}

#[derive(Debug, Error)]
pub enum QueryError {
    #[error("lookup failed: {0}")]
    Lookup(String),
    #[error("construction failed: {0}")]
    Construction(String),
}
