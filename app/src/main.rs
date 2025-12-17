#![forbid(unsafe_code)]

use cbv::CharacterBaselineVector;
use keys::KeyEpoch;
use pvgs::{CommitBindings, CommitType, PvgsCommitRequest, RequiredCheck};
use query::{QueryRequest, QueryResult};
use receipts::issue_receipt;
use sep::{SepEventInternal, SepEventType, SepLog};
use ucf_protocol::ucf::v1::{Digest32, ProofReceipt, ReceiptStatus};
use vrf::{VrfInput, VrfOutput};
use wire::{AuthContext, Envelope};

fn main() {
    let envelope = Envelope {
        payload: b"boot".to_vec(),
        signature: None,
    };

    let commit_request = PvgsCommitRequest {
        commit_id: "boot-seed".into(),
        commit_type: CommitType::ReceiptRequest,
        bindings: CommitBindings {
            action_digest: Some([1u8; 32]),
            decision_digest: Some([2u8; 32]),
            grant_id: Some("grant".into()),
            charter_version_digest: "charter".into(),
            policy_version_digest: "policy".into(),
            prev_record_digest: [0u8; 32],
            profile_digest: [0u8; 32],
            tool_profile_digest: None,
        },
        required_checks: vec![RequiredCheck::IntegrityOk],
        payload_digests: vec![[3u8; 32]],
        epoch_id: 0,
    };

    let pvgs_receipt = issue_receipt(&commit_request, ReceiptStatus::Accepted, Vec::new());

    let proof_receipt = ProofReceipt {
        receipt_digest: pvgs_receipt.receipt_digest.clone(),
        proof_digest: Digest32([0u8; 32]),
    };

    let baseline = CharacterBaselineVector {
        dimensions: vec!["baseline".into()],
    };

    let current_epoch = KeyEpoch {
        epoch: 0,
        public_key: Vec::new(),
    };

    let mut sep_log = SepLog::default();
    let sep_event: SepEventInternal = sep_log.append_event(
        "boot-session".into(),
        SepEventType::EvDecision,
        pvgs_receipt.receipt_digest.0,
        Vec::new(),
    );

    let vrf_input = VrfInput {
        message: envelope.payload.clone(),
        epoch: current_epoch.epoch,
    };

    let vrf_output = VrfOutput {
        proof: Vec::new(),
        public: current_epoch.public_key.clone(),
    };

    let auth = AuthContext {
        subject: "bootstrap".into(),
        scopes: vec!["init".into()],
    };

    let query_request = QueryRequest {
        subject: auth.subject.clone(),
    };

    let _query_result = QueryResult {
        auth: Some(auth),
        baseline: Some(baseline),
        last_commit: Some(pvgs_receipt.clone()),
        last_verification: Some(proof_receipt),
        current_epoch: Some(current_epoch),
        latest_event: Some(sep_event),
        recent_vrf: Some((vrf_input, vrf_output)),
    };

    println!("boot ok: {}", query_request.subject);
    println!("next receipt digest: {:?}", pvgs_receipt.receipt_digest.0);
}
