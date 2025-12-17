#![forbid(unsafe_code)]

use cbv::CharacterBaselineVector;
use keys::{KeyEpoch, KeyStore};
use pvgs::{
    compute_ruleset_digest, compute_verified_fields_digest, CommitBindings, CommitType,
    PvgsCommitRequest, RequiredCheck,
};
use query::{QueryRequest, QueryResult};
use receipts::{issue_proof_receipt, issue_receipt, ReceiptInput};
use sep::{SepEventInternal, SepEventType, SepLog};
use ucf_protocol::ucf::v1::ReceiptStatus;
use vrf::VrfEngine;
use wire::AuthContext;

fn main() {
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

    let keystore = KeyStore::new_dev_keystore(0);
    let vrf_engine = VrfEngine::new_dev(keystore.current_epoch());
    let receipt_input = ReceiptInput {
        commit_id: commit_request.commit_id.clone(),
        commit_type: commit_request.commit_type.into(),
        bindings: (&commit_request.bindings).into(),
        required_checks: commit_request
            .required_checks
            .iter()
            .copied()
            .map(Into::into)
            .collect(),
        payload_digests: commit_request.payload_digests.clone(),
        epoch_id: commit_request.epoch_id,
    };

    let pvgs_receipt = issue_receipt(
        &receipt_input,
        ReceiptStatus::Accepted,
        Vec::new(),
        &keystore,
    );

    let verified_fields_digest = compute_verified_fields_digest(&commit_request.bindings);
    let record_digest = pvgs::compute_record_digest(
        verified_fields_digest,
        commit_request.bindings.prev_record_digest,
        &commit_request.commit_id,
    );
    let vrf_digest = vrf_engine.eval_record_vrf(
        commit_request.bindings.prev_record_digest,
        record_digest,
        &commit_request.bindings.charter_version_digest,
        commit_request.bindings.profile_digest,
        commit_request.epoch_id,
    );

    let proof_receipt = issue_proof_receipt(
        compute_ruleset_digest(
            commit_request.bindings.charter_version_digest.as_bytes(),
            commit_request.bindings.policy_version_digest.as_bytes(),
        ),
        verified_fields_digest,
        vrf_digest,
        &keystore,
    );

    let baseline = CharacterBaselineVector {
        dimensions: vec!["baseline".into()],
    };

    let current_epoch = KeyEpoch {
        epoch_id: keystore.current_epoch(),
        key_id: keystore.current_key_id().to_string(),
        public_key: keystore.verifying_key().to_bytes(),
        vrf_public_key: Some(vrf_engine.vrf_public_key().to_vec()),
    };

    let mut sep_log = SepLog::default();
    let sep_event: SepEventInternal = sep_log.append_event(
        "boot-session".into(),
        SepEventType::EvDecision,
        pvgs_receipt.receipt_digest.0,
        Vec::new(),
    );

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
        recent_vrf_digest: Some(vrf_digest),
    };

    println!("boot ok: {}", query_request.subject);
    println!("next receipt digest: {:?}", pvgs_receipt.receipt_digest.0);
}
