#![forbid(unsafe_code)]

use blake3::Hasher;
use sep::{SepEventType, SepLog};
use std::collections::HashSet;
use ucf_protocol::ucf::v1::{self as protocol, Digest32, PVGSReceipt, ReceiptStatus};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Commit type supported by PVGS.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitType {
    ReceiptRequest,
    RecordAppend,
    MilestoneAppend,
    CharterUpdate,
    ToolRegistryUpdate,
    RecoveryUpdate,
    PevUpdate,
    CbvUpdate,
}

/// Required checks requested by the caller.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequiredCheck {
    SchemaOk,
    BindingOk,
    TightenOnly,
    IntegrityOk,
}

/// Commit binding data that feeds into receipts.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitBindings {
    pub action_digest: Option<[u8; 32]>,
    pub decision_digest: Option<[u8; 32]>,
    pub grant_id: Option<String>,
    pub charter_version_digest: String,
    pub policy_version_digest: String,
    pub prev_record_digest: [u8; 32],
    pub profile_digest: [u8; 32],
    pub tool_profile_digest: Option<[u8; 32]>,
}

/// A PVGS commit request encompassing bindings and payload digests.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PvgsCommitRequest {
    pub commit_id: String,
    pub commit_type: CommitType,
    pub bindings: CommitBindings,
    pub required_checks: Vec<RequiredCheck>,
    pub payload_digests: Vec<[u8; 32]>,
    pub epoch_id: u64,
}

/// In-memory store tracking PVGS state and SEP event log.
#[derive(Debug, Clone)]
pub struct PvgsStore {
    pub current_head_record_digest: [u8; 32],
    pub known_charter_versions: HashSet<String>,
    pub known_policy_versions: HashSet<String>,
    pub known_profiles: HashSet<[u8; 32]>,
    pub epoch_id_current: u64,
    pub sep_log: SepLog,
}

impl PvgsStore {
    pub fn new(
        current_head_record_digest: [u8; 32],
        known_charter_versions: HashSet<String>,
        known_policy_versions: HashSet<String>,
        known_profiles: HashSet<[u8; 32]>,
        epoch_id_current: u64,
    ) -> Self {
        Self {
            current_head_record_digest,
            known_charter_versions,
            known_policy_versions,
            known_profiles,
            epoch_id_current,
            sep_log: SepLog::default(),
        }
    }
}

/// Compute the receipt digest for a given request, status, and reason codes.
pub fn compute_receipt_digest(
    req: &PvgsCommitRequest,
    status: ReceiptStatus,
    reject_reason_codes: &[String],
) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(b"UCF:PVGS:RECEIPT");
    hasher.update(req.commit_id.as_bytes());
    hasher.update(commit_type_label(req.commit_type).as_bytes());

    // Bindings in fixed order.
    update_optional_digest(&mut hasher, &req.bindings.action_digest);
    update_optional_digest(&mut hasher, &req.bindings.decision_digest);
    update_optional_string(&mut hasher, &req.bindings.grant_id);
    hasher.update(req.bindings.charter_version_digest.as_bytes());
    hasher.update(req.bindings.policy_version_digest.as_bytes());
    hasher.update(&req.bindings.prev_record_digest);
    hasher.update(&req.bindings.profile_digest);
    update_optional_digest(&mut hasher, &req.bindings.tool_profile_digest);

    // Required checks and payloads.
    for check in &req.required_checks {
        hasher.update(required_check_label(*check).as_bytes());
    }

    for digest in &req.payload_digests {
        hasher.update(digest);
    }

    hasher.update(status_label(status).as_bytes());
    for rc in reject_reason_codes {
        hasher.update(rc.as_bytes());
    }
    hasher.update(&req.epoch_id.to_le_bytes());

    *hasher.finalize().as_bytes()
}

/// Verify a commit request and emit a PVGS receipt.
pub fn verify_and_commit(req: PvgsCommitRequest, store: &mut PvgsStore) -> PVGSReceipt {
    let mut reject_reason_codes = Vec::new();

    if req.epoch_id != store.epoch_id_current {
        reject_reason_codes.push(protocol::ReasonCodes::RE_INTEGRITY_DEGRADED.to_string());
        return make_receipt(req, ReceiptStatus::Rejected, reject_reason_codes);
    }

    if req.bindings.prev_record_digest != store.current_head_record_digest {
        reject_reason_codes.push(protocol::ReasonCodes::GE_EXEC_DISPATCH_BLOCKED.to_string());
        return make_receipt(req, ReceiptStatus::Rejected, reject_reason_codes);
    }

    if !store
        .known_charter_versions
        .contains(&req.bindings.charter_version_digest)
    {
        reject_reason_codes.push(protocol::ReasonCodes::PB_DENY_CHARTER_SCOPE.to_string());
        return make_receipt(req, ReceiptStatus::Rejected, reject_reason_codes);
    }

    if !store
        .known_policy_versions
        .contains(&req.bindings.policy_version_digest)
    {
        reject_reason_codes.push(protocol::ReasonCodes::PB_DENY_INTEGRITY_REQUIRED.to_string());
        return make_receipt(req, ReceiptStatus::Rejected, reject_reason_codes);
    }

    if req.commit_type == CommitType::ReceiptRequest
        && (req.bindings.action_digest.is_none()
            || req.bindings.decision_digest.is_none()
            || req.bindings.grant_id.is_none())
    {
        reject_reason_codes.push(protocol::ReasonCodes::GE_GRANT_MISSING.to_string());
        return make_receipt(req, ReceiptStatus::Rejected, reject_reason_codes);
    }

    let receipt = make_receipt(req.clone(), ReceiptStatus::Accepted, reject_reason_codes);
    let event_type = match req.commit_type {
        CommitType::ReceiptRequest => SepEventType::EvDecision,
        _ => SepEventType::EvRecoveryGov,
    };
    store.sep_log.append_event(
        req.commit_id.clone(),
        event_type,
        receipt.receipt_digest.0,
        Vec::new(),
    );
    receipt
}

fn make_receipt(
    req: PvgsCommitRequest,
    status: ReceiptStatus,
    mut reject_reason_codes: Vec<String>,
) -> PVGSReceipt {
    if matches!(status, ReceiptStatus::Rejected) && reject_reason_codes.is_empty() {
        reject_reason_codes.push(protocol::ReasonCodes::GE_GRANT_MISSING.to_string());
    }

    if matches!(status, ReceiptStatus::Accepted) {
        reject_reason_codes.clear();
    }

    let digest = compute_receipt_digest(&req, status, &reject_reason_codes);

    PVGSReceipt {
        commit_id: req.commit_id,
        commit_type: req.commit_type.into(),
        bindings: (&req.bindings).into(),
        required_checks: req.required_checks.into_iter().map(Into::into).collect(),
        payload_digests: req.payload_digests.into_iter().map(Digest32).collect(),
        epoch_id: req.epoch_id,
        status,
        reject_reason_codes,
        receipt_digest: Digest32(digest),
    }
}

fn commit_type_label(commit_type: CommitType) -> &'static str {
    match commit_type {
        CommitType::ReceiptRequest => "ReceiptRequest",
        CommitType::RecordAppend => "RecordAppend",
        CommitType::MilestoneAppend => "MilestoneAppend",
        CommitType::CharterUpdate => "CharterUpdate",
        CommitType::ToolRegistryUpdate => "ToolRegistryUpdate",
        CommitType::RecoveryUpdate => "RecoveryUpdate",
        CommitType::PevUpdate => "PevUpdate",
        CommitType::CbvUpdate => "CbvUpdate",
    }
}

fn required_check_label(check: RequiredCheck) -> &'static str {
    match check {
        RequiredCheck::SchemaOk => "SchemaOk",
        RequiredCheck::BindingOk => "BindingOk",
        RequiredCheck::TightenOnly => "TightenOnly",
        RequiredCheck::IntegrityOk => "IntegrityOk",
    }
}

fn status_label(status: ReceiptStatus) -> &'static str {
    match status {
        ReceiptStatus::Accepted => "ACCEPTED",
        ReceiptStatus::Rejected => "REJECTED",
    }
}

fn update_optional_digest(hasher: &mut Hasher, digest: &Option<[u8; 32]>) {
    match digest {
        Some(d) => {
            hasher.update(&[1u8]);
            hasher.update(d);
        }
        None => {
            hasher.update(&[0u8]);
        }
    }
}

fn update_optional_string(hasher: &mut Hasher, value: &Option<String>) {
    match value {
        Some(v) => {
            hasher.update(&[1u8]);
            hasher.update(v.as_bytes());
        }
        None => {
            hasher.update(&[0u8]);
        }
    }
}

impl From<CommitType> for protocol::CommitType {
    fn from(value: CommitType) -> Self {
        match value {
            CommitType::ReceiptRequest => protocol::CommitType::ReceiptRequest,
            CommitType::RecordAppend => protocol::CommitType::RecordAppend,
            CommitType::MilestoneAppend => protocol::CommitType::MilestoneAppend,
            CommitType::CharterUpdate => protocol::CommitType::CharterUpdate,
            CommitType::ToolRegistryUpdate => protocol::CommitType::ToolRegistryUpdate,
            CommitType::RecoveryUpdate => protocol::CommitType::RecoveryUpdate,
            CommitType::PevUpdate => protocol::CommitType::PevUpdate,
            CommitType::CbvUpdate => protocol::CommitType::CbvUpdate,
        }
    }
}

impl From<RequiredCheck> for protocol::RequiredCheck {
    fn from(value: RequiredCheck) -> Self {
        match value {
            RequiredCheck::SchemaOk => protocol::RequiredCheck::SchemaOk,
            RequiredCheck::BindingOk => protocol::RequiredCheck::BindingOk,
            RequiredCheck::TightenOnly => protocol::RequiredCheck::TightenOnly,
            RequiredCheck::IntegrityOk => protocol::RequiredCheck::IntegrityOk,
        }
    }
}

impl From<&CommitBindings> for protocol::CommitBindings {
    fn from(value: &CommitBindings) -> Self {
        protocol::CommitBindings {
            action_digest: value.action_digest.map(Digest32),
            decision_digest: value.decision_digest.map(Digest32),
            grant_id: value.grant_id.clone(),
            charter_version_digest: value.charter_version_digest.clone(),
            policy_version_digest: value.policy_version_digest.clone(),
            prev_record_digest: Digest32(value.prev_record_digest),
            profile_digest: Digest32(value.profile_digest),
            tool_profile_digest: value.tool_profile_digest.map(Digest32),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol::ReasonCodes;

    fn base_store(prev_digest: [u8; 32]) -> PvgsStore {
        let mut known_charter_versions = HashSet::new();
        known_charter_versions.insert("charter".to_string());
        let mut known_policy_versions = HashSet::new();
        known_policy_versions.insert("policy".to_string());
        let mut known_profiles = HashSet::new();
        known_profiles.insert([9u8; 32]);

        PvgsStore::new(
            prev_digest,
            known_charter_versions,
            known_policy_versions,
            known_profiles,
            1,
        )
    }

    fn make_request(prev: [u8; 32]) -> PvgsCommitRequest {
        PvgsCommitRequest {
            commit_id: "commit-1".to_string(),
            commit_type: CommitType::ReceiptRequest,
            bindings: CommitBindings {
                action_digest: Some([1u8; 32]),
                decision_digest: Some([2u8; 32]),
                grant_id: Some("grant".to_string()),
                charter_version_digest: "charter".to_string(),
                policy_version_digest: "policy".to_string(),
                prev_record_digest: prev,
                profile_digest: [9u8; 32],
                tool_profile_digest: Some([3u8; 32]),
            },
            required_checks: vec![RequiredCheck::BindingOk],
            payload_digests: vec![[4u8; 32]],
            epoch_id: 1,
        }
    }

    #[test]
    fn receipt_accepted() {
        let prev = [8u8; 32];
        let mut store = base_store(prev);
        let req = make_request(prev);

        let receipt = verify_and_commit(req, &mut store);
        assert_eq!(receipt.status, ReceiptStatus::Accepted);
        assert!(receipt.reject_reason_codes.is_empty());
        assert_eq!(store.sep_log.events.len(), 1);
    }

    #[test]
    fn receipt_rejected_wrong_prev() {
        let mut store = base_store([7u8; 32]);
        let req = make_request([6u8; 32]);

        let receipt = verify_and_commit(req, &mut store);
        assert_eq!(receipt.status, ReceiptStatus::Rejected);
        assert_eq!(
            receipt.reject_reason_codes,
            vec![ReasonCodes::GE_EXEC_DISPATCH_BLOCKED.to_string()]
        );
        assert!(store.sep_log.events.is_empty());
    }

    #[test]
    fn receipt_rejected_unknown_charter() {
        let prev = [8u8; 32];
        let mut store = base_store(prev);
        let mut req = make_request(prev);
        req.bindings.charter_version_digest = "unknown".to_string();

        let receipt = verify_and_commit(req, &mut store);
        assert_eq!(receipt.status, ReceiptStatus::Rejected);
        assert_eq!(
            receipt.reject_reason_codes,
            vec![ReasonCodes::PB_DENY_CHARTER_SCOPE.to_string()]
        );
    }
}
