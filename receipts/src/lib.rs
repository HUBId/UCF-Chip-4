#![forbid(unsafe_code)]

use blake3::Hasher;
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
    let mut hasher = Hasher::new();
    hasher.update(b"UCF:PVGS:RECEIPT");
    hasher.update(req.commit_id.as_bytes());
    hasher.update(commit_type_label(&req.commit_type).as_bytes());

    update_optional_digest_hasher(&mut hasher, &req.bindings.action_digest);
    update_optional_digest_hasher(&mut hasher, &req.bindings.decision_digest);
    update_optional_string_hasher(&mut hasher, &req.bindings.grant_id);
    hasher.update(req.bindings.charter_version_digest.as_bytes());
    hasher.update(req.bindings.policy_version_digest.as_bytes());
    hasher.update(&req.bindings.prev_record_digest.0);
    update_optional_digest_hasher(&mut hasher, &req.bindings.profile_digest);
    update_optional_digest_hasher(&mut hasher, &req.bindings.tool_profile_digest);

    hasher.update(required_receipt_kind_label(&req.required_receipt_kind).as_bytes());

    for check in &req.required_checks {
        hasher.update(required_check_label(check).as_bytes());
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
    let mut preimage = Vec::new();
    preimage.extend_from_slice(b"UCF:SIGN:PVGS_RECEIPT");
    preimage.extend_from_slice(&receipt.epoch_id.to_le_bytes());
    preimage.extend_from_slice(receipt.receipt_id.as_bytes());
    preimage.extend_from_slice(&receipt.receipt_digest.0);
    preimage.extend_from_slice(status_label(receipt.status).as_bytes());

    update_optional_digest(
        &mut preimage,
        &receipt.bindings.action_digest.as_ref().map(|d| d.0),
    );
    update_optional_digest(
        &mut preimage,
        &receipt.bindings.decision_digest.as_ref().map(|d| d.0),
    );
    update_optional_string(&mut preimage, &receipt.bindings.grant_id);
    preimage.extend_from_slice(receipt.bindings.charter_version_digest.as_bytes());
    preimage.extend_from_slice(receipt.bindings.policy_version_digest.as_bytes());
    preimage.extend_from_slice(&receipt.bindings.prev_record_digest.0);
    update_optional_digest(
        &mut preimage,
        &receipt.bindings.profile_digest.as_ref().map(|d| d.0),
    );
    update_optional_digest(
        &mut preimage,
        &receipt.bindings.tool_profile_digest.as_ref().map(|d| d.0),
    );

    let mut reason_codes = receipt.reject_reason_codes.clone();
    reason_codes.sort();
    for rc in reason_codes {
        preimage.extend_from_slice(rc.as_bytes());
    }

    preimage
}

fn proof_attestation_preimage(proof: &ProofReceipt) -> Vec<u8> {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(b"UCF:SIGN:PROOF_RECEIPT");
    preimage.extend_from_slice(&proof.ruleset_digest.0);
    preimage.extend_from_slice(&proof.verified_fields_digest.0);
    preimage.extend_from_slice(&proof.vrf_digest.0);
    preimage.extend_from_slice(&proof.timestamp_ms.to_le_bytes());
    preimage.extend_from_slice(&proof.epoch_id.to_le_bytes());
    preimage.extend_from_slice(proof.proof_receipt_id.as_bytes());
    preimage.extend_from_slice(&proof.proof_receipt_digest.0);
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
    let mut hasher = Hasher::new();
    hasher.update(b"UCF:PVGS:PROOF_RECEIPT");
    hasher.update(proof_receipt_id.as_bytes());
    hasher.update(&ruleset_digest);
    hasher.update(&verified_fields_digest);
    hasher.update(&maybe_vrf_digest);
    hasher.update(&timestamp_ms.to_le_bytes());
    hasher.update(&epoch_id.to_le_bytes());
    *hasher.finalize().as_bytes()
}

fn commit_type_label(commit_type: &protocol::CommitType) -> &'static str {
    match commit_type {
        protocol::CommitType::ReceiptRequest => "ReceiptRequest",
        protocol::CommitType::RecordAppend => "RecordAppend",
        protocol::CommitType::MilestoneAppend => "MilestoneAppend",
        protocol::CommitType::CharterUpdate => "CharterUpdate",
        protocol::CommitType::ToolRegistryUpdate => "ToolRegistryUpdate",
        protocol::CommitType::RecoveryUpdate => "RecoveryUpdate",
        protocol::CommitType::PevUpdate => "PevUpdate",
        protocol::CommitType::CbvUpdate => "CbvUpdate",
        protocol::CommitType::KeyEpochUpdate => "KeyEpochUpdate",
        protocol::CommitType::FrameEvidenceAppend => "FrameEvidenceAppend",
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

fn update_optional_digest_hasher(hasher: &mut Hasher, digest: &Option<Digest32>) {
    match digest {
        Some(d) => {
            hasher.update(&[1u8]);
            hasher.update(&d.0);
        }
        None => {
            hasher.update(&[0u8]);
        }
    }
}

fn update_optional_string_hasher(hasher: &mut Hasher, value: &Option<String>) {
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
