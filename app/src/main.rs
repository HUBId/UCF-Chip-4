#![forbid(unsafe_code)]

use cbv::CharacterBaselineVector;
use keys::KeyEpoch;
use pvgs::{
    PvgsCommitRequest, PvgsCommitResponse, PvgsVerificationRequest, PvgsVerificationResult,
};
use query::{QueryRequest, QueryResult};
use receipts::{ProofReceipt, PvgsReceipt};
use sep::SepEvent;
use vrf::{VrfInput, VrfOutput};
use wire::{AuthContext, Envelope};

fn main() {
    let envelope = Envelope {
        payload: b"boot".to_vec(),
        signature: None,
    };

    let commit_request = PvgsCommitRequest {
        envelope: envelope.clone(),
        correlation_id: "boot-seed".into(),
    };

    let commit_response = PvgsCommitResponse { accepted: true };

    let verification_request = PvgsVerificationRequest {
        commitment_id: commit_request.correlation_id.clone(),
    };

    let verification_result = PvgsVerificationResult {
        verified: true,
        notes: vec![format!("Processed {}", verification_request.commitment_id)],
    };

    let pvgs_receipt = PvgsReceipt {
        request_id: commit_request.correlation_id.clone(),
        commit: commit_response,
    };

    let proof_receipt = ProofReceipt {
        receipt_id: verification_request.commitment_id.clone(),
        verification: verification_result.clone(),
    };

    let baseline = CharacterBaselineVector {
        dimensions: vec!["baseline".into()],
    };

    let current_epoch = KeyEpoch {
        epoch: 0,
        public_key: Vec::new(),
    };

    let sep_event = SepEvent {
        id: "event-0".into(),
        kind: "boot".into(),
        payload: "boot event".into(),
    };

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
        last_commit: Some(pvgs_receipt),
        last_verification: Some(proof_receipt),
        current_epoch: Some(current_epoch),
        latest_event: Some(sep_event),
        recent_vrf: Some((vrf_input, vrf_output)),
    };

    println!("boot ok: {}", query_request.subject);
    println!("next: {:?}", verification_result.notes);
}
