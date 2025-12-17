#![forbid(unsafe_code)]

use cbv::CharacterBaselineVector;
use keys::{KeyEpochHistory, KeyStore};
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
            profile_digest: Some([0u8; 32]),
            tool_profile_digest: None,
        },
        required_receipt_kind: pvgs::RequiredReceiptKind::Read,
        required_checks: vec![RequiredCheck::IntegrityOk],
        payload_digests: vec![[3u8; 32]],
        epoch_id: 0,
        key_epoch: None,
    };

    let keystore = KeyStore::new_dev_keystore(0);
    let vrf_engine = VrfEngine::new_dev(keystore.current_epoch());
    let mut history = KeyEpochHistory::default();
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

    let verified_fields_digest = compute_verified_fields_digest(
        &commit_request.bindings,
        commit_request.required_receipt_kind,
    );
    let record_digest = pvgs::compute_record_digest(
        verified_fields_digest,
        commit_request.bindings.prev_record_digest,
        &commit_request.commit_id,
    );
    let vrf_digest = vrf_engine.eval_record_vrf(
        commit_request.bindings.prev_record_digest,
        record_digest,
        &commit_request.bindings.charter_version_digest,
        commit_request.bindings.profile_digest.unwrap_or([0u8; 32]),
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

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let current_epoch = keystore.make_key_epoch_proto(
        keystore.current_epoch(),
        now_ms,
        vrf_engine.vrf_public_key().to_vec(),
        None,
    );
    history.push(current_epoch.clone()).expect("history push");

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
