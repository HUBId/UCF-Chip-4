#![forbid(unsafe_code)]

use common::digest::{blake3_digest, encode_deterministic};
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use keys::KeyStore;
use std::convert::TryInto;
use ucf_protocol::ucf::v1::{self as protocol, Digest32, PVGSReceipt, ProofReceipt, ReceiptStatus};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptInput {
    pub commit_id: String,
    pub commit_type: protocol::CommitType,
    pub bindings: protocol::CommitBindings,
    pub required_checks: Vec<protocol::RequiredCheck>,
    pub required_receipt_kind: protocol::RequiredReceiptKind,
    pub payload_digests: Vec<[u8; 32]>,
    pub epoch_id: u64,
}

/// Compute the receipt digest for a given request, status, and reason codes.
pub fn compute_receipt_digest(
    req: &ReceiptInput,
    status: ReceiptStatus,
    reject_reason_codes: &[String],
) -> [u8; 32] {
    let preimage = receipt_digest_preimage(req, status, reject_reason_codes);
    blake3_digest("UCF", "PVGS:RECEIPT", "v1", &preimage)
}

fn receipt_digest_preimage(
    req: &ReceiptInput,
    status: ReceiptStatus,
    reject_reason_codes: &[String],
) -> Vec<u8> {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(req.commit_id.as_bytes());
    preimage.extend_from_slice(commit_type_label(&req.commit_type).as_bytes());

    update_optional_digest(
        &mut preimage,
        &req.bindings.action_digest.as_ref().map(|d| d.0),
    );
    update_optional_digest(
        &mut preimage,
        &req.bindings.decision_digest.as_ref().map(|d| d.0),
    );
    update_optional_string(&mut preimage, &req.bindings.grant_id);
    preimage.extend_from_slice(req.bindings.charter_version_digest.as_bytes());
    preimage.extend_from_slice(req.bindings.policy_version_digest.as_bytes());
    preimage.extend_from_slice(&req.bindings.prev_record_digest.0);
    update_optional_digest(
        &mut preimage,
        &req.bindings.profile_digest.as_ref().map(|d| d.0),
    );
    update_optional_digest(
        &mut preimage,
        &req.bindings.tool_profile_digest.as_ref().map(|d| d.0),
    );
    update_optional_digest(
        &mut preimage,
        &req.bindings.pev_digest.as_ref().map(|d| d.0),
    );

    preimage.extend_from_slice(required_receipt_kind_label(&req.required_receipt_kind).as_bytes());

    for check in &req.required_checks {
        preimage.extend_from_slice(required_check_label(check).as_bytes());
    }

    for digest in &req.payload_digests {
        preimage.extend_from_slice(digest);
    }

    preimage.extend_from_slice(status_label(status).as_bytes());
    for rc in reject_reason_codes {
        preimage.extend_from_slice(rc.as_bytes());
    }
    preimage.extend_from_slice(&req.epoch_id.to_le_bytes());

    preimage
}

#[derive(Clone, PartialEq, ::prost::Message)]
struct ReceiptSignaturePreimage {
    #[prost(string, tag = "1")]
    commit_id: String,
    #[prost(string, tag = "2")]
    commit_type: String,
    #[prost(bytes = "vec", optional, tag = "3")]
    action_digest: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "4")]
    decision_digest: Option<Vec<u8>>,
    #[prost(string, optional, tag = "5")]
    grant_id: Option<String>,
    #[prost(string, tag = "6")]
    charter_version_digest: String,
    #[prost(string, tag = "7")]
    policy_version_digest: String,
    #[prost(bytes = "vec", tag = "8")]
    prev_record_digest: Vec<u8>,
    #[prost(bytes = "vec", optional, tag = "9")]
    profile_digest: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "10")]
    tool_profile_digest: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "11")]
    pev_digest: Option<Vec<u8>>,
    #[prost(string, tag = "12")]
    required_receipt_kind: String,
    #[prost(string, repeated, tag = "13")]
    required_checks: Vec<String>,
    #[prost(bytes = "vec", repeated, tag = "14")]
    payload_digests: Vec<Vec<u8>>,
    #[prost(string, tag = "15")]
    status: String,
    #[prost(string, repeated, tag = "16")]
    reject_reason_codes: Vec<String>,
    #[prost(uint64, tag = "17")]
    epoch_id: u64,
    #[prost(bytes = "vec", tag = "18")]
    receipt_digest: Vec<u8>,
    #[prost(string, tag = "19")]
    receipt_id: String,
}

#[derive(Clone, PartialEq, ::prost::Message)]
struct ProofReceiptSignaturePreimage {
    #[prost(bytes = "vec", tag = "1")]
    ruleset_digest: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    verified_fields_digest: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    vrf_digest: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    receipt_digest: Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    proof_receipt_digest: Vec<u8>,
    #[prost(string, tag = "6")]
    proof_receipt_id: String,
    #[prost(uint64, tag = "7")]
    timestamp_ms: u64,
    #[prost(uint64, tag = "8")]
    epoch_id: u64,
}

/// Issue a PVGS receipt for a given commit request and status.
///
/// `rcs` must contain at least one entry when the receipt is rejected.
pub fn issue_receipt(
    req: &ReceiptInput,
    status: ReceiptStatus,
    rcs: Vec<String>,
    keystore: &KeyStore,
) -> PVGSReceipt {
    let mut reject_reason_codes = rcs;

    if matches!(status, ReceiptStatus::Rejected) && reject_reason_codes.is_empty() {
        panic!("rejected receipt must include at least one reason code");
    }

    if matches!(status, ReceiptStatus::Accepted) {
        reject_reason_codes.clear();
    }

    reject_reason_codes.sort();

    let digest = compute_receipt_digest(req, status, &reject_reason_codes);

    let mut receipt = PVGSReceipt {
        commit_id: req.commit_id.clone(),
        commit_type: req.commit_type.clone(),
        bindings: req.bindings.clone(),
        required_checks: req.required_checks.clone(),
        required_receipt_kind: req.required_receipt_kind,
        payload_digests: req.payload_digests.iter().copied().map(Digest32).collect(),
        epoch_id: req.epoch_id,
        status,
        reject_reason_codes,
        receipt_digest: Digest32(digest),
        receipt_id: req.commit_id.clone(),
        pvgs_attestation_key_id: keystore.current_key_id().to_string(),
        pvgs_attestation_sig: Vec::new(),
    };

    let sig = keystore
        .signing_key()
        .sign(&pvgs_attestation_preimage(&receipt));
    receipt.pvgs_attestation_sig = sig.to_bytes().to_vec();

    receipt
}

/// Issue a proof receipt binding verification output to key epochs.
pub fn issue_proof_receipt(
    ruleset_digest: [u8; 32],
    verified_fields_digest: [u8; 32],
    maybe_vrf_digest: [u8; 32],
    keystore: &KeyStore,
) -> ProofReceipt {
    let timestamp_ms = current_timestamp_ms();
    let proof_receipt_id = format!("proof-{}", timestamp_ms);
    let proof_receipt_digest = compute_proof_receipt_digest(
        &proof_receipt_id,
        ruleset_digest,
        verified_fields_digest,
        maybe_vrf_digest,
        timestamp_ms,
        keystore.current_epoch(),
    );

    let mut proof = ProofReceipt {
        proof_receipt_id,
        receipt_digest: Digest32::zero(),
        ruleset_digest: Digest32(ruleset_digest),
        verified_fields_digest: Digest32(verified_fields_digest),
        vrf_digest: Digest32(maybe_vrf_digest),
        timestamp_ms,
        epoch_id: keystore.current_epoch(),
        proof_receipt_digest: Digest32(proof_receipt_digest),
        proof_attestation_key_id: keystore.current_key_id().to_string(),
        proof_attestation_sig: Vec::new(),
    };

    let signature = keystore
        .signing_key()
        .sign(&proof_attestation_preimage(&proof));
    proof.proof_attestation_sig = signature.to_bytes().to_vec();

    proof
}

/// Verify a PVGS receipt attestation signature against the supplied public key.
pub fn verify_pvgs_receipt_attestation(receipt: &PVGSReceipt, pubkey: [u8; 32]) -> bool {
    let Ok(verifying_key) = VerifyingKey::from_bytes(&pubkey) else {
        return false;
    };
    let Ok(signature_bytes) = receipt.pvgs_attestation_sig.as_slice().try_into() else {
        return false;
    };
    let signature = Signature::from_bytes(&signature_bytes);

    verifying_key
        .verify(&pvgs_attestation_preimage(receipt), &signature)
        .is_ok()
}

/// Verify a proof receipt attestation signature against the supplied public key.
pub fn verify_proof_receipt_attestation(proof: &ProofReceipt, pubkey: [u8; 32]) -> bool {
    let Ok(verifying_key) = VerifyingKey::from_bytes(&pubkey) else {
        return false;
    };
    let Ok(signature_bytes) = proof.proof_attestation_sig.as_slice().try_into() else {
        return false;
    };
    let signature = Signature::from_bytes(&signature_bytes);

    verifying_key
        .verify(&proof_attestation_preimage(proof), &signature)
        .is_ok()
}

fn pvgs_attestation_preimage(receipt: &PVGSReceipt) -> Vec<u8> {
    let mut reject_reason_codes = receipt.reject_reason_codes.clone();
    reject_reason_codes.sort();

    let payload = ReceiptSignaturePreimage {
        commit_id: receipt.commit_id.clone(),
        commit_type: commit_type_label(&receipt.commit_type).to_string(),
        action_digest: receipt
            .bindings
            .action_digest
            .as_ref()
            .map(|d| d.0.to_vec()),
        decision_digest: receipt
            .bindings
            .decision_digest
            .as_ref()
            .map(|d| d.0.to_vec()),
        grant_id: receipt.bindings.grant_id.clone(),
        charter_version_digest: receipt.bindings.charter_version_digest.clone(),
        policy_version_digest: receipt.bindings.policy_version_digest.clone(),
        prev_record_digest: receipt.bindings.prev_record_digest.0.to_vec(),
        profile_digest: receipt
            .bindings
            .profile_digest
            .as_ref()
            .map(|d| d.0.to_vec()),
        tool_profile_digest: receipt
            .bindings
            .tool_profile_digest
            .as_ref()
            .map(|d| d.0.to_vec()),
        pev_digest: receipt.bindings.pev_digest.as_ref().map(|d| d.0.to_vec()),
        required_receipt_kind: required_receipt_kind_label(&receipt.required_receipt_kind)
            .to_string(),
        required_checks: receipt
            .required_checks
            .iter()
            .map(|c| required_check_label(c).to_string())
            .collect(),
        payload_digests: receipt
            .payload_digests
            .iter()
            .map(|d| d.0.to_vec())
            .collect(),
        status: status_label(receipt.status).to_string(),
        reject_reason_codes,
        epoch_id: receipt.epoch_id,
        receipt_digest: receipt.receipt_digest.0.to_vec(),
        receipt_id: receipt.receipt_id.clone(),
    };

    let encoded = encode_deterministic(&payload);

    let mut preimage = Vec::with_capacity(b"UCF:SIGN:PVGS_RECEIPT".len() + encoded.len());
    preimage.extend_from_slice(b"UCF:SIGN:PVGS_RECEIPT");
    preimage.extend_from_slice(&encoded);
    preimage
}

fn proof_attestation_preimage(proof: &ProofReceipt) -> Vec<u8> {
    let payload = ProofReceiptSignaturePreimage {
        ruleset_digest: proof.ruleset_digest.0.to_vec(),
        verified_fields_digest: proof.verified_fields_digest.0.to_vec(),
        vrf_digest: proof.vrf_digest.0.to_vec(),
        timestamp_ms: proof.timestamp_ms,
        epoch_id: proof.epoch_id,
        proof_receipt_id: proof.proof_receipt_id.clone(),
        proof_receipt_digest: proof.proof_receipt_digest.0.to_vec(),
        receipt_digest: proof.receipt_digest.0.to_vec(),
    };

    let encoded = encode_deterministic(&payload);

    let mut preimage = Vec::with_capacity(b"UCF:SIGN:PROOF_RECEIPT".len() + encoded.len());
    preimage.extend_from_slice(b"UCF:SIGN:PROOF_RECEIPT");
    preimage.extend_from_slice(&encoded);
    preimage
}

fn compute_proof_receipt_digest(
    proof_receipt_id: &str,
    ruleset_digest: [u8; 32],
    verified_fields_digest: [u8; 32],
    maybe_vrf_digest: [u8; 32],
    timestamp_ms: u64,
    epoch_id: u64,
) -> [u8; 32] {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(proof_receipt_id.as_bytes());
    preimage.extend_from_slice(&ruleset_digest);
    preimage.extend_from_slice(&verified_fields_digest);
    preimage.extend_from_slice(&maybe_vrf_digest);
    preimage.extend_from_slice(&timestamp_ms.to_le_bytes());
    preimage.extend_from_slice(&epoch_id.to_le_bytes());
    blake3_digest("UCF", "PVGS:PROOF_RECEIPT", "v1", &preimage)
}

fn commit_type_label(commit_type: &protocol::CommitType) -> &'static str {
    match commit_type {
        protocol::CommitType::ReceiptRequest => "ReceiptRequest",
        protocol::CommitType::RecordAppend => "RecordAppend",
        protocol::CommitType::ExperienceRecordAppend => "ExperienceRecordAppend",
        protocol::CommitType::MilestoneAppend => "MilestoneAppend",
        protocol::CommitType::MacroMilestonePropose => "MacroMilestonePropose",
        protocol::CommitType::MacroMilestoneFinalize => "MacroMilestoneFinalize",
        protocol::CommitType::CharterUpdate => "CharterUpdate",
        protocol::CommitType::ToolRegistryUpdate => "ToolRegistryUpdate",
        protocol::CommitType::ToolOnboardingEventAppend => "ToolOnboardingEventAppend",
        protocol::CommitType::RecoveryCaseCreate => "RecoveryCaseCreate",
        protocol::CommitType::RecoveryCaseAdvance => "RecoveryCaseAdvance",
        protocol::CommitType::RecoveryApproval => "RecoveryApproval",
        protocol::CommitType::RecoveryUpdate => "RecoveryUpdate",
        protocol::CommitType::PevUpdate => "PevUpdate",
        protocol::CommitType::CbvUpdate => "CbvUpdate",
        protocol::CommitType::KeyEpochUpdate => "KeyEpochUpdate",
        protocol::CommitType::FrameEvidenceAppend => "FrameEvidenceAppend",
        protocol::CommitType::DlpDecisionAppend => "DlpDecisionAppend",
        protocol::CommitType::ReplayPlanAppend => "ReplayPlanAppend",
        protocol::CommitType::ReplayRunEvidenceAppend => "ReplayRunEvidenceAppend",
        protocol::CommitType::TraceRunEvidenceAppend => "TraceRunEvidenceAppend",
        protocol::CommitType::ConsistencyFeedbackAppend => "ConsistencyFeedbackAppend",
        protocol::CommitType::MicrocircuitConfigAppend => "MicrocircuitConfigAppend",
        protocol::CommitType::AssetManifestAppend => "AssetManifestAppend",
        protocol::CommitType::AssetBundleAppend => "AssetBundleAppend",
        protocol::CommitType::ProposalEvidenceAppend => "ProposalEvidenceAppend",
        protocol::CommitType::ProposalActivationAppend => "ProposalActivationAppend",
    }
}

fn required_check_label(check: &protocol::RequiredCheck) -> &'static str {
    match check {
        protocol::RequiredCheck::SchemaOk => "SchemaOk",
        protocol::RequiredCheck::BindingOk => "BindingOk",
        protocol::RequiredCheck::TightenOnly => "TightenOnly",
        protocol::RequiredCheck::IntegrityOk => "IntegrityOk",
    }
}

fn required_receipt_kind_label(kind: &protocol::RequiredReceiptKind) -> &'static str {
    match kind {
        protocol::RequiredReceiptKind::Read => "READ",
        protocol::RequiredReceiptKind::Transform => "TRANSFORM",
        protocol::RequiredReceiptKind::Write => "WRITE",
        protocol::RequiredReceiptKind::Execute => "EXECUTE",
        protocol::RequiredReceiptKind::Export => "EXPORT",
        protocol::RequiredReceiptKind::Persist => "PERSIST",
    }
}

fn status_label(status: ReceiptStatus) -> &'static str {
    match status {
        ReceiptStatus::Accepted => "ACCEPTED",
        ReceiptStatus::Rejected => "REJECTED",
    }
}

fn update_optional_digest(buf: &mut Vec<u8>, digest: &Option<[u8; 32]>) {
    match digest {
        Some(d) => {
            buf.push(1u8);
            buf.extend_from_slice(d);
        }
        None => buf.push(0u8),
    }
}

fn update_optional_string(buf: &mut Vec<u8>, value: &Option<String>) {
    match value {
        Some(v) => {
            buf.push(1u8);
            buf.extend_from_slice(v.as_bytes());
        }
        None => buf.push(0u8),
    }
}

fn current_timestamp_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use keys::KeyStore;
    use ucf_protocol::ucf::v1::{
        CommitBindings, CommitType, Digest32, ReasonCodes, RequiredCheck, RequiredReceiptKind,
    };

    fn sample_request() -> ReceiptInput {
        ReceiptInput {
            commit_id: "req-1".to_string(),
            commit_type: CommitType::ReceiptRequest,
            bindings: CommitBindings {
                action_digest: Some(Digest32([1u8; 32])),
                decision_digest: Some(Digest32([2u8; 32])),
                grant_id: Some("grant".to_string()),
                charter_version_digest: "charter".to_string(),
                policy_version_digest: "policy".to_string(),
                prev_record_digest: Digest32([3u8; 32]),
                profile_digest: Some(Digest32([4u8; 32])),
                tool_profile_digest: None,
                pev_digest: None,
            },
            required_receipt_kind: RequiredReceiptKind::Read,
            required_checks: vec![RequiredCheck::SchemaOk],
            payload_digests: vec![[5u8; 32]],
            epoch_id: 1,
        }
    }

    #[test]
    fn accepted_receipt_has_empty_reasons_and_verifies() {
        let req = sample_request();
        let keystore = KeyStore::new_dev_keystore(1);
        let receipt = issue_receipt(&req, ReceiptStatus::Accepted, Vec::new(), &keystore);
        assert!(receipt.reject_reason_codes.is_empty());
        let pubkey = keystore.public_key_for_epoch(1).unwrap();
        assert!(verify_pvgs_receipt_attestation(&receipt, pubkey));
    }

    #[test]
    fn rejected_receipt_requires_reason() {
        let req = sample_request();
        let reason = ReasonCodes::GE_GRANT_MISSING;
        let keystore = KeyStore::new_dev_keystore(1);
        let receipt = issue_receipt(
            &req,
            ReceiptStatus::Rejected,
            vec![
                reason.to_string(),
                ReasonCodes::GE_GRANT_MISSING.to_string(),
            ],
            &keystore,
        );
        assert_eq!(receipt.status, ReceiptStatus::Rejected);
        assert_eq!(
            receipt.reject_reason_codes,
            vec![reason.to_string(), reason.to_string()]
        );
        let pubkey = keystore.public_key_for_epoch(1).unwrap();
        assert!(verify_pvgs_receipt_attestation(&receipt, pubkey));
    }

    #[test]
    #[should_panic(expected = "rejected receipt must include at least one reason code")]
    fn rejected_without_reason_panics() {
        let req = sample_request();
        let keystore = KeyStore::new_dev_keystore(1);
        let _ = issue_receipt(&req, ReceiptStatus::Rejected, Vec::new(), &keystore);
    }

    #[test]
    fn receipt_signature_detects_mutation() {
        let req = sample_request();
        let keystore = KeyStore::new_dev_keystore(5);
        let mut receipt = issue_receipt(&req, ReceiptStatus::Accepted, Vec::new(), &keystore);
        let pubkey = keystore.public_key_for_epoch(5).unwrap();
        assert!(verify_pvgs_receipt_attestation(&receipt, pubkey));

        receipt.bindings.charter_version_digest.push_str("tamper");
        assert!(!verify_pvgs_receipt_attestation(&receipt, pubkey));

        let mut receipt2 = issue_receipt(&req, ReceiptStatus::Accepted, Vec::new(), &keystore);
        receipt2.receipt_digest.0[0] ^= 0xFF;
        assert!(!verify_pvgs_receipt_attestation(&receipt2, pubkey));
    }

    #[test]
    fn rotation_retains_previous_public_key() {
        let req = sample_request();
        let mut keystore = KeyStore::new_dev_keystore(7);
        let receipt = issue_receipt(&req, ReceiptStatus::Accepted, Vec::new(), &keystore);
        let epoch_one_key = keystore.public_key_for_epoch(7).unwrap();
        assert!(verify_pvgs_receipt_attestation(&receipt, epoch_one_key));

        keystore.rotate(9);
        assert_eq!(keystore.current_epoch(), 9);
        assert_eq!(keystore.public_key_for_epoch(7).unwrap(), epoch_one_key);
        assert!(verify_pvgs_receipt_attestation(&receipt, epoch_one_key));
    }

    #[test]
    fn proof_receipt_signature_verifies_and_detects_mutation() {
        let keystore = KeyStore::new_dev_keystore(11);
        let proof = issue_proof_receipt([1u8; 32], [2u8; 32], [0u8; 32], &keystore);
        let pubkey = keystore.public_key_for_epoch(11).unwrap();
        assert!(verify_proof_receipt_attestation(&proof, pubkey));

        let mut tampered = proof.clone();
        tampered.verified_fields_digest.0[0] ^= 0xAA;
        assert!(!verify_proof_receipt_attestation(&tampered, pubkey));
    }
}
