#![forbid(unsafe_code)]

use cbv::CharacterBaselineVector;
use pvgs::PvgsCommitRequest;
use sep::SepEventInternal;
use thiserror::Error;
use ucf_protocol::ucf::v1::{PVGSKeyEpoch, PVGSReceipt, ProofReceipt};
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
    pub last_commit: Option<PVGSReceipt>,
    pub last_verification: Option<ProofReceipt>,
    pub current_epoch: Option<PVGSKeyEpoch>,
    pub latest_event: Option<SepEventInternal>,
    pub recent_vrf_digest: Option<[u8; 32]>,
}

pub trait QueryInspector {
    fn fetch(&self, request: QueryRequest) -> Result<QueryResult, QueryError>;
    fn prepare_commit(&self, envelope: Envelope) -> Result<PvgsCommitRequest, QueryError>;
    fn summarize_verification(
        &self,
        verification: ProofReceipt,
    ) -> Result<ProofReceipt, QueryError>;
}

#[derive(Debug, Error)]
pub enum QueryError {
    #[error("lookup failed: {0}")]
    Lookup(String),
    #[error("construction failed: {0}")]
    Construction(String),
}
