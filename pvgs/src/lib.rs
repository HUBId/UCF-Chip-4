#![forbid(unsafe_code)]

use blake3::Hasher;
use keys::{verify_key_epoch_signature, KeyEpochHistory, KeyStore};
use receipts::{issue_proof_receipt, issue_receipt, ReceiptInput};
use sep::{SepEventType, SepLog};
use std::collections::HashSet;
use ucf_protocol::ucf::v1::{
    self as protocol, Digest32, PVGSKeyEpoch, PVGSReceipt, ProofReceipt, ReceiptStatus,
};
use vrf::VrfEngine;

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
    KeyEpochUpdate,
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
    pub profile_digest: Option<[u8; 32]>,
    pub tool_profile_digest: Option<[u8; 32]>,
}

/// Receipt kinds indicating the action class required by the caller.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequiredReceiptKind {
    Read,
    Transform,
    Write,
    Execute,
    Export,
    Persist,
}

/// A PVGS commit request encompassing bindings and payload digests.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PvgsCommitRequest {
    pub commit_id: String,
    pub commit_type: CommitType,
    pub bindings: CommitBindings,
    pub required_receipt_kind: RequiredReceiptKind,
    pub required_checks: Vec<RequiredCheck>,
    pub payload_digests: Vec<[u8; 32]>,
    pub epoch_id: u64,
    pub key_epoch: Option<PVGSKeyEpoch>,
}

/// In-memory store tracking PVGS state and SEP event log.
#[derive(Debug, Clone)]
pub struct PvgsStore {
    pub current_head_record_digest: [u8; 32],
    pub known_charter_versions: HashSet<String>,
    pub known_policy_versions: HashSet<String>,
    pub known_profiles: HashSet<[u8; 32]>,
    pub key_epoch_history: KeyEpochHistory,
    pub committed_payload_digests: HashSet<[u8; 32]>,
    pub sep_log: SepLog,
}

impl PvgsStore {
    pub fn new(
        current_head_record_digest: [u8; 32],
        known_charter_versions: HashSet<String>,
        known_policy_versions: HashSet<String>,
        known_profiles: HashSet<[u8; 32]>,
    ) -> Self {
        Self {
            current_head_record_digest,
            known_charter_versions,
            known_policy_versions,
            known_profiles,
            key_epoch_history: KeyEpochHistory::default(),
            committed_payload_digests: HashSet::new(),
            sep_log: SepLog::default(),
        }
    }
}

/// Compute a digest over the ruleset inputs (charter + policy).
pub fn compute_ruleset_digest(charter_digest: &[u8], policy_digest: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(b"UCF:HASH:RULESET");
    hasher.update(charter_digest);
    hasher.update(policy_digest);
    *hasher.finalize().as_bytes()
}

/// Compute the digest of fields verified during PVGS evaluation.
pub fn compute_verified_fields_digest(
    bindings: &CommitBindings,
    required_receipt_kind: RequiredReceiptKind,
) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(b"UCF:PVGS:VERIFIED_FIELDS");

    update_optional_digest(&mut hasher, &bindings.action_digest);
    update_optional_digest(&mut hasher, &bindings.decision_digest);
    update_optional_string(&mut hasher, &bindings.grant_id);
    hasher.update(bindings.charter_version_digest.as_bytes());
    hasher.update(bindings.policy_version_digest.as_bytes());
    hasher.update(&bindings.prev_record_digest);
    update_optional_digest(&mut hasher, &bindings.profile_digest);
    update_optional_digest(&mut hasher, &bindings.tool_profile_digest);
    hasher.update(required_receipt_kind_label(&required_receipt_kind).as_bytes());

    *hasher.finalize().as_bytes()
}

/// Compute a deterministic record digest suitable for VRF input.
pub fn compute_record_digest(
    verified_fields_digest: [u8; 32],
    prev_record_digest: [u8; 32],
    commit_id: &str,
) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(b"UCF:PVGS:RECORD_DIGEST");
    hasher.update(&verified_fields_digest);
    hasher.update(&prev_record_digest);
    hasher.update(commit_id.as_bytes());
    *hasher.finalize().as_bytes()
}

/// Compute the verified fields digest for key epoch updates.
pub fn compute_key_epoch_verified_fields_digest(
    payload_digest: [u8; 32],
    key_epoch_id: u64,
) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(b"UCF:PVGS:KEY_EPOCH_VERIFIED_FIELDS");
    hasher.update(&payload_digest);
    hasher.update(&key_epoch_id.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Compute a deterministic record digest for key epoch updates.
pub fn compute_key_epoch_record_digest(
    prev_record_digest: [u8; 32],
    payload_digest: [u8; 32],
    commit_id: &str,
) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(b"UCF:PVGS:KEY_EPOCH_RECORD_DIGEST");
    hasher.update(&prev_record_digest);
    hasher.update(&payload_digest);
    hasher.update(commit_id.as_bytes());
    *hasher.finalize().as_bytes()
}

fn event_type_for_commit(commit_type: CommitType) -> SepEventType {
    match commit_type {
        CommitType::ReceiptRequest => SepEventType::EvDecision,
        CommitType::KeyEpochUpdate => SepEventType::EvKeyEpoch,
        _ => SepEventType::EvRecoveryGov,
    }
}

fn to_receipt_input(req: &PvgsCommitRequest) -> ReceiptInput {
    ReceiptInput {
        commit_id: req.commit_id.clone(),
        commit_type: req.commit_type.into(),
        bindings: (&req.bindings).into(),
        required_checks: req
            .required_checks
            .iter()
            .copied()
            .map(Into::into)
            .collect(),
        payload_digests: req.payload_digests.clone(),
        epoch_id: req.epoch_id,
    }
}

/// Verify a commit request and emit attested receipts.
pub fn verify_and_commit(
    req: PvgsCommitRequest,
    store: &mut PvgsStore,
    keystore: &KeyStore,
    vrf_engine: &VrfEngine,
) -> (PVGSReceipt, Option<ProofReceipt>) {
    let receipt_input = to_receipt_input(&req);
    let mut reject_reason_codes = Vec::new();
    let key_epoch_event_digest = if req.commit_type == CommitType::KeyEpochUpdate {
        key_epoch_payload_digest(&req)
    } else {
        None
    };

    if req.epoch_id != keystore.current_epoch() {
        reject_reason_codes.push(protocol::ReasonCodes::RE_INTEGRITY_DEGRADED.to_string());
        return finalize_receipt(
            &req,
            &receipt_input,
            ReceiptStatus::Rejected,
            reject_reason_codes,
            store,
            keystore,
            key_epoch_event_digest,
        );
    }

    if req.bindings.prev_record_digest != store.current_head_record_digest {
        reject_reason_codes.push(protocol::ReasonCodes::GE_EXEC_DISPATCH_BLOCKED.to_string());
        return finalize_receipt(
            &req,
            &receipt_input,
            ReceiptStatus::Rejected,
            reject_reason_codes,
            store,
            keystore,
            key_epoch_event_digest,
        );
    }

    if !store
        .known_charter_versions
        .contains(&req.bindings.charter_version_digest)
    {
        reject_reason_codes.push(protocol::ReasonCodes::PB_DENY_CHARTER_SCOPE.to_string());
        return finalize_receipt(
            &req,
            &receipt_input,
            ReceiptStatus::Rejected,
            reject_reason_codes,
            store,
            keystore,
            key_epoch_event_digest,
        );
    }

    if !store
        .known_policy_versions
        .contains(&req.bindings.policy_version_digest)
    {
        reject_reason_codes.push(protocol::ReasonCodes::PB_DENY_INTEGRITY_REQUIRED.to_string());
        return finalize_receipt(
            &req,
            &receipt_input,
            ReceiptStatus::Rejected,
            reject_reason_codes,
            store,
            keystore,
            key_epoch_event_digest,
        );
    }

    if req.commit_type == CommitType::ReceiptRequest
        && (req.bindings.action_digest.is_none()
            || req.bindings.decision_digest.is_none()
            || req.bindings.grant_id.is_none())
    {
        reject_reason_codes.push(protocol::ReasonCodes::GE_GRANT_MISSING.to_string());
        return finalize_receipt(
            &req,
            &receipt_input,
            ReceiptStatus::Rejected,
            reject_reason_codes,
            store,
            keystore,
            key_epoch_event_digest,
        );
    }

    if req.commit_type == CommitType::ReceiptRequest
        && matches!(
            req.required_receipt_kind,
            RequiredReceiptKind::Write
                | RequiredReceiptKind::Execute
                | RequiredReceiptKind::Export
                | RequiredReceiptKind::Persist
        )
    {
        if req.bindings.tool_profile_digest.is_none() {
            reject_reason_codes.push(protocol::ReasonCodes::GE_EXEC_DISPATCH_BLOCKED.to_string());
        }

        if req.bindings.profile_digest.is_none() {
            reject_reason_codes.push(protocol::ReasonCodes::GE_EXEC_DISPATCH_BLOCKED.to_string());
        }

        if !reject_reason_codes.is_empty() {
            return finalize_receipt(
                &req,
                &receipt_input,
                ReceiptStatus::Rejected,
                reject_reason_codes,
                store,
                keystore,
                key_epoch_event_digest,
            );
        }
    }

    let mut key_epoch_context: Option<(PVGSKeyEpoch, [u8; 32])> = None;

    if req.commit_type == CommitType::KeyEpochUpdate {
        match validate_key_epoch_update(&req, store) {
            Ok(ctx) => key_epoch_context = Some(ctx),
            Err(reasons) => {
                reject_reason_codes = reasons;
                return finalize_receipt(
                    &req,
                    &receipt_input,
                    ReceiptStatus::Rejected,
                    reject_reason_codes,
                    store,
                    keystore,
                    key_epoch_payload_digest(&req),
                );
            }
        }
    }

    let (verified_fields_digest, record_digest) =
        match (req.commit_type, key_epoch_context.as_ref()) {
            (CommitType::KeyEpochUpdate, Some((key_epoch, payload_digest))) => (
                compute_key_epoch_verified_fields_digest(*payload_digest, key_epoch.key_epoch_id),
                compute_key_epoch_record_digest(
                    req.bindings.prev_record_digest,
                    *payload_digest,
                    &req.commit_id,
                ),
            ),
            _ => {
                let verified_fields_digest =
                    compute_verified_fields_digest(&req.bindings, req.required_receipt_kind);
                (
                    verified_fields_digest,
                    compute_record_digest(
                        verified_fields_digest,
                        req.bindings.prev_record_digest,
                        &req.commit_id,
                    ),
                )
            }
        };

    let receipt = issue_receipt(
        &receipt_input,
        ReceiptStatus::Accepted,
        reject_reason_codes.clone(),
        keystore,
    );

    let vrf_digest = vrf_engine.eval_record_vrf(
        req.bindings.prev_record_digest,
        record_digest,
        &req.bindings.charter_version_digest,
        req.bindings.profile_digest.unwrap_or([0u8; 32]),
        req.epoch_id,
    );

    let mut proof_receipt = issue_proof_receipt(
        compute_ruleset_digest(
            req.bindings.charter_version_digest.as_bytes(),
            req.bindings.policy_version_digest.as_bytes(),
        ),
        verified_fields_digest,
        vrf_digest,
        keystore,
    );
    proof_receipt.receipt_digest = receipt.receipt_digest.clone();

    if let Some((ref key_epoch, payload_digest)) = key_epoch_context {
        store
            .key_epoch_history
            .push(key_epoch.clone())
            .expect("validation enforces monotonic key epochs");
        store.committed_payload_digests.insert(payload_digest);
    }

    let event_object_digest = if let Some((_, payload_digest)) = key_epoch_context.as_ref() {
        *payload_digest
    } else {
        receipt.receipt_digest.0
    };
    let event_type = event_type_for_commit(req.commit_type);

    store.sep_log.append_event(
        req.commit_id.clone(),
        event_type,
        event_object_digest,
        receipt.reject_reason_codes.clone(),
    );

    (receipt, Some(proof_receipt))
}

fn key_epoch_payload_digest(req: &PvgsCommitRequest) -> Option<[u8; 32]> {
    req.payload_digests.first().copied()
}

fn validate_key_epoch_update(
    req: &PvgsCommitRequest,
    store: &PvgsStore,
) -> Result<(PVGSKeyEpoch, [u8; 32]), Vec<String>> {
    if !req.required_checks.contains(&RequiredCheck::SchemaOk)
        || !req.required_checks.contains(&RequiredCheck::BindingOk)
    {
        return Err(vec![
            protocol::ReasonCodes::GV_KEY_EPOCH_REQUIRED_CHECK.to_string()
        ]);
    }

    let Some(key_epoch) = req.key_epoch.as_ref() else {
        return Err(vec![
            protocol::ReasonCodes::GV_KEY_EPOCH_PAYLOAD_INVALID.to_string()
        ]);
    };

    if req.payload_digests.len() != 1 {
        return Err(vec![
            protocol::ReasonCodes::GV_KEY_EPOCH_PAYLOAD_INVALID.to_string()
        ]);
    }

    let payload_digest = req.payload_digests[0];

    if payload_digest != key_epoch.announcement_digest.0 {
        return Err(vec![
            protocol::ReasonCodes::GV_KEY_EPOCH_PAYLOAD_INVALID.to_string()
        ]);
    }

    if store.committed_payload_digests.contains(&payload_digest) {
        return Err(vec![
            protocol::ReasonCodes::GV_KEY_EPOCH_DUPLICATE.to_string()
        ]);
    }

    if !verify_key_epoch_signature(key_epoch) {
        return Err(vec![
            protocol::ReasonCodes::GV_KEY_EPOCH_SIGNATURE_INVALID.to_string()
        ]);
    }

    let mut reject_reason_codes = Vec::new();
    if let Some(latest) = store.key_epoch_history.current() {
        if key_epoch.key_epoch_id != latest.key_epoch_id + 1 {
            reject_reason_codes.push(protocol::ReasonCodes::GV_KEY_EPOCH_NON_MONOTONIC.to_string());
        }

        match key_epoch.prev_key_epoch_digest.as_ref() {
            Some(prev) if prev.0 == latest.announcement_digest.0 => {}
            _ => reject_reason_codes.push(protocol::ReasonCodes::GV_KEY_EPOCH_UNKNOWN.to_string()),
        }
    } else if key_epoch.prev_key_epoch_digest.is_some() {
        reject_reason_codes.push(protocol::ReasonCodes::GV_KEY_EPOCH_UNKNOWN.to_string());
    }

    if reject_reason_codes.is_empty() {
        Ok((key_epoch.clone(), payload_digest))
    } else {
        Err(reject_reason_codes)
    }
}

fn finalize_receipt(
    req: &PvgsCommitRequest,
    receipt_input: &ReceiptInput,
    status: ReceiptStatus,
    mut reject_reason_codes: Vec<String>,
    store: &mut PvgsStore,
    keystore: &KeyStore,
    event_object_digest: Option<[u8; 32]>,
) -> (PVGSReceipt, Option<ProofReceipt>) {
    if matches!(status, ReceiptStatus::Rejected) && reject_reason_codes.is_empty() {
        reject_reason_codes.push(protocol::ReasonCodes::GE_GRANT_MISSING.to_string());
    }

    if matches!(status, ReceiptStatus::Accepted) {
        reject_reason_codes.clear();
    }

    let receipt = issue_receipt(receipt_input, status, reject_reason_codes, keystore);
    let event_type = event_type_for_commit(req.commit_type);

    let object_digest = event_object_digest.unwrap_or(receipt.receipt_digest.0);

    store.sep_log.append_event(
        req.commit_id.clone(),
        event_type,
        object_digest,
        receipt.reject_reason_codes.clone(),
    );

    (receipt, None)
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

fn required_receipt_kind_label(kind: &RequiredReceiptKind) -> &'static str {
    match kind {
        RequiredReceiptKind::Read => "READ",
        RequiredReceiptKind::Transform => "TRANSFORM",
        RequiredReceiptKind::Write => "WRITE",
        RequiredReceiptKind::Execute => "EXECUTE",
        RequiredReceiptKind::Export => "EXPORT",
        RequiredReceiptKind::Persist => "PERSIST",
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
            CommitType::KeyEpochUpdate => protocol::CommitType::KeyEpochUpdate,
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
            profile_digest: value.profile_digest.map(Digest32),
            tool_profile_digest: value.tool_profile_digest.map(Digest32),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol::ReasonCodes;
    use receipts::verify_pvgs_receipt_attestation;
    use vrf::VrfEngine;

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
                profile_digest: Some([9u8; 32]),
                tool_profile_digest: Some([3u8; 32]),
            },
            required_receipt_kind: RequiredReceiptKind::Read,
            required_checks: vec![RequiredCheck::BindingOk],
            payload_digests: vec![[4u8; 32]],
            epoch_id: 1,
            key_epoch: None,
        }
    }

    fn make_key_epoch_request(
        keystore: &KeyStore,
        vrf_engine: &VrfEngine,
        store: &PvgsStore,
        key_epoch_id: u64,
        prev_digest: Option<[u8; 32]>,
        commit_id: &str,
    ) -> (PvgsCommitRequest, PVGSKeyEpoch) {
        let epoch = keystore.make_key_epoch_proto(
            key_epoch_id,
            100 * key_epoch_id,
            vrf_engine.vrf_public_key().to_vec(),
            prev_digest,
        );

        (
            PvgsCommitRequest {
                commit_id: commit_id.to_string(),
                commit_type: CommitType::KeyEpochUpdate,
                bindings: CommitBindings {
                    action_digest: None,
                    decision_digest: None,
                    grant_id: None,
                    charter_version_digest: "charter".to_string(),
                    policy_version_digest: "policy".to_string(),
                    prev_record_digest: store.current_head_record_digest,
                    profile_digest: Some([9u8; 32]),
                    tool_profile_digest: None,
                },
                required_receipt_kind: RequiredReceiptKind::Read,
                required_checks: vec![RequiredCheck::SchemaOk, RequiredCheck::BindingOk],
                payload_digests: vec![epoch.announcement_digest.0],
                epoch_id: keystore.current_epoch(),
                key_epoch: Some(epoch.clone()),
            },
            epoch,
        )
    }

    #[test]
    fn receipt_accepted() {
        let prev = [8u8; 32];
        let mut store = base_store(prev);
        let req = make_request(prev);
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);

        let (receipt, proof) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);
        assert_eq!(receipt.status, ReceiptStatus::Accepted);
        assert!(receipt.reject_reason_codes.is_empty());
        let proof = proof.expect("proof receipt missing");
        assert_ne!(proof.vrf_digest, Digest32::zero());
        assert_eq!(store.sep_log.events.len(), 1);
    }

    #[test]
    fn side_effect_requires_tool_profile_digest() {
        let prev = [8u8; 32];
        let mut store = base_store(prev);
        let mut req = make_request(prev);
        req.required_receipt_kind = RequiredReceiptKind::Export;
        req.bindings.tool_profile_digest = None;
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);

        let (receipt, proof) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);
        assert_eq!(receipt.status, ReceiptStatus::Rejected);
        assert_eq!(
            receipt.reject_reason_codes,
            vec![ReasonCodes::GE_EXEC_DISPATCH_BLOCKED.to_string()]
        );
        assert!(proof.is_none());
    }

    #[test]
    fn side_effect_requires_profile_digest() {
        let prev = [8u8; 32];
        let mut store = base_store(prev);
        let mut req = make_request(prev);
        req.required_receipt_kind = RequiredReceiptKind::Write;
        req.bindings.profile_digest = None;
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);

        let (receipt, proof) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);
        assert_eq!(receipt.status, ReceiptStatus::Rejected);
        assert_eq!(
            receipt.reject_reason_codes,
            vec![ReasonCodes::GE_EXEC_DISPATCH_BLOCKED.to_string()]
        );
        assert!(proof.is_none());
    }

    #[test]
    fn side_effect_accepts_when_all_digests_present() {
        let prev = [8u8; 32];
        let mut store = base_store(prev);
        let mut req = make_request(prev);
        req.required_receipt_kind = RequiredReceiptKind::Export;
        req.bindings.tool_profile_digest = Some([5u8; 32]);
        req.bindings.profile_digest = Some([6u8; 32]);
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);

        let (receipt, proof) = verify_and_commit(req.clone(), &mut store, &keystore, &vrf_engine);
        assert_eq!(receipt.status, ReceiptStatus::Accepted);
        assert!(receipt.reject_reason_codes.is_empty());
        assert_eq!(
            receipt.bindings.profile_digest,
            req.bindings.profile_digest.map(Digest32)
        );
        assert_eq!(
            receipt.bindings.tool_profile_digest,
            req.bindings.tool_profile_digest.map(Digest32)
        );
        let pubkey = keystore
            .public_key_for_epoch(keystore.current_epoch())
            .unwrap();
        assert!(verify_pvgs_receipt_attestation(&receipt, pubkey));

        let proof = proof.expect("missing proof receipt");
        assert_ne!(proof.vrf_digest, Digest32::zero());
        let expected_verified_fields =
            compute_verified_fields_digest(&req.bindings, req.required_receipt_kind);
        assert_eq!(
            proof.verified_fields_digest,
            Digest32(expected_verified_fields)
        );
    }

    #[test]
    fn receipts_remain_deterministic_with_new_bindings() {
        let prev = [8u8; 32];
        let mut req = make_request(prev);
        req.required_receipt_kind = RequiredReceiptKind::Export;
        let keystore = KeyStore::new_dev_keystore(1);

        let mut store_one = base_store(prev);
        let vrf_one = VrfEngine::new_dev(1);
        let (receipt_one, _) = verify_and_commit(req.clone(), &mut store_one, &keystore, &vrf_one);

        let mut store_two = base_store(prev);
        let vrf_two = VrfEngine::new_dev(1);
        let (receipt_two, _) = verify_and_commit(req, &mut store_two, &keystore, &vrf_two);

        assert_eq!(receipt_one.receipt_digest, receipt_two.receipt_digest);
        assert_eq!(
            receipt_one.pvgs_attestation_sig,
            receipt_two.pvgs_attestation_sig
        );
    }

    #[test]
    fn receipt_rejected_wrong_prev() {
        let mut store = base_store([7u8; 32]);
        let req = make_request([6u8; 32]);
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);

        let (receipt, proof) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);
        assert_eq!(receipt.status, ReceiptStatus::Rejected);
        assert_eq!(
            receipt.reject_reason_codes,
            vec![ReasonCodes::GE_EXEC_DISPATCH_BLOCKED.to_string()]
        );
        assert!(proof.is_none());
        assert_eq!(store.sep_log.events.len(), 1);
    }

    #[test]
    fn receipt_rejected_unknown_charter() {
        let prev = [8u8; 32];
        let mut store = base_store(prev);
        let mut req = make_request(prev);
        req.bindings.charter_version_digest = "unknown".to_string();
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);

        let (receipt, proof) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);
        assert_eq!(receipt.status, ReceiptStatus::Rejected);
        assert_eq!(
            receipt.reject_reason_codes,
            vec![ReasonCodes::PB_DENY_CHARTER_SCOPE.to_string()]
        );
        assert!(proof.is_none());
    }

    #[test]
    fn epoch_mismatch_rejects() {
        let prev = [1u8; 32];
        let mut store = base_store(prev);
        let mut req = make_request(prev);
        req.epoch_id = 2;
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);

        let (receipt, proof) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);
        assert_eq!(receipt.status, ReceiptStatus::Rejected);
        assert_eq!(
            receipt.reject_reason_codes,
            vec![ReasonCodes::RE_INTEGRITY_DEGRADED.to_string()]
        );
        assert!(proof.is_none());
    }

    #[test]
    fn key_epoch_commit_accepted() {
        let prev = [8u8; 32];
        let mut store = base_store(prev);
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);
        let (req, epoch) = make_key_epoch_request(&keystore, &vrf_engine, &store, 1, None, "ke-1");

        let (receipt, proof) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);
        assert_eq!(receipt.status, ReceiptStatus::Accepted);
        assert!(proof.is_some());
        let latest = store
            .key_epoch_history
            .current()
            .expect("missing key epoch");
        assert_eq!(latest.key_epoch_id, 1);
        assert_eq!(latest.announcement_digest, epoch.announcement_digest);
        assert!(store
            .committed_payload_digests
            .contains(&epoch.announcement_digest.0));

        let last_event = store.sep_log.events.last().expect("missing event");
        assert_eq!(last_event.event_type, SepEventType::EvKeyEpoch);
        assert_eq!(last_event.object_digest, epoch.announcement_digest.0);
    }

    #[test]
    fn key_epoch_rejects_non_monotonic() {
        let prev = [7u8; 32];
        let mut store = base_store(prev);
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);

        let (req1, epoch1) =
            make_key_epoch_request(&keystore, &vrf_engine, &store, 1, None, "ke-1");
        let _ = verify_and_commit(req1, &mut store, &keystore, &vrf_engine);

        let (req2, _) = make_key_epoch_request(
            &keystore,
            &vrf_engine,
            &store,
            2,
            Some(epoch1.announcement_digest.0),
            "ke-2",
        );
        let _ = verify_and_commit(req2, &mut store, &keystore, &vrf_engine);

        let backward_epoch =
            keystore.make_key_epoch_proto(1, 999, vrf_engine.vrf_public_key().to_vec(), None);
        let backward_req = PvgsCommitRequest {
            commit_id: "ke-backwards".to_string(),
            commit_type: CommitType::KeyEpochUpdate,
            bindings: CommitBindings {
                action_digest: None,
                decision_digest: None,
                grant_id: None,
                charter_version_digest: "charter".to_string(),
                policy_version_digest: "policy".to_string(),
                prev_record_digest: store.current_head_record_digest,
                profile_digest: Some([9u8; 32]),
                tool_profile_digest: None,
            },
            required_receipt_kind: RequiredReceiptKind::Read,
            required_checks: vec![RequiredCheck::SchemaOk, RequiredCheck::BindingOk],
            payload_digests: vec![backward_epoch.announcement_digest.0],
            epoch_id: keystore.current_epoch(),
            key_epoch: Some(backward_epoch),
        };

        let (receipt, proof) = verify_and_commit(backward_req, &mut store, &keystore, &vrf_engine);
        assert_eq!(receipt.status, ReceiptStatus::Rejected);
        assert!(proof.is_none());
        assert!(receipt
            .reject_reason_codes
            .contains(&ReasonCodes::GV_KEY_EPOCH_NON_MONOTONIC.to_string()));
    }

    #[test]
    fn key_epoch_rejects_invalid_signature() {
        let prev = [5u8; 32];
        let mut store = base_store(prev);
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);
        let (mut req, mut epoch) =
            make_key_epoch_request(&keystore, &vrf_engine, &store, 1, None, "ke-1");
        epoch.announcement_signature[0] ^= 0xFF;
        req.key_epoch = Some(epoch);

        let (receipt, proof) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);
        assert_eq!(receipt.status, ReceiptStatus::Rejected);
        assert!(proof.is_none());
        assert_eq!(
            receipt.reject_reason_codes,
            vec![ReasonCodes::GV_KEY_EPOCH_SIGNATURE_INVALID.to_string()]
        );
    }

    #[test]
    fn key_epoch_rejects_duplicate_payload() {
        let prev = [4u8; 32];
        let mut store = base_store(prev);
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);
        let (req, epoch) = make_key_epoch_request(&keystore, &vrf_engine, &store, 1, None, "ke-1");
        let _ = verify_and_commit(req, &mut store, &keystore, &vrf_engine);

        let dup_req = PvgsCommitRequest {
            commit_id: "ke-dup".to_string(),
            commit_type: CommitType::KeyEpochUpdate,
            bindings: CommitBindings {
                action_digest: None,
                decision_digest: None,
                grant_id: None,
                charter_version_digest: "charter".to_string(),
                policy_version_digest: "policy".to_string(),
                prev_record_digest: store.current_head_record_digest,
                profile_digest: Some([9u8; 32]),
                tool_profile_digest: None,
            },
            required_receipt_kind: RequiredReceiptKind::Read,
            required_checks: vec![RequiredCheck::SchemaOk, RequiredCheck::BindingOk],
            payload_digests: vec![epoch.announcement_digest.0],
            epoch_id: keystore.current_epoch(),
            key_epoch: Some(epoch),
        };

        let (receipt, proof) = verify_and_commit(dup_req, &mut store, &keystore, &vrf_engine);
        assert_eq!(receipt.status, ReceiptStatus::Rejected);
        assert!(proof.is_none());
        assert_eq!(
            receipt.reject_reason_codes,
            vec![ReasonCodes::GV_KEY_EPOCH_DUPLICATE.to_string()]
        );
    }
}
