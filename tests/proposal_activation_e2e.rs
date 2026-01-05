use keys::KeyStore;
use proposal_activations::{
    compute_proposal_activation_digest, ActivationStatus, ProposalActivationEvidence,
};
use proposals::{compute_proposal_evidence_digest, ProposalEvidence, ProposalKind};
use prost::Message;
use pvgs::{
    verify_and_commit, CommitBindings, CommitType, PvgsCommitRequest, PvgsStore, RequiredCheck,
    RequiredReceiptKind,
};
use query::{
    latest_activation_for_proposal, latest_proposal, snapshot, ActivationStatusCounts,
    ProposalVerdictCounts, ProposalsCard,
};
use std::collections::HashSet;
use ucf_protocol::ucf::v1::ReasonCodes;
use vrf::VrfEngine;

const MAX_REASON_CODES: usize = 32;

fn base_store(prev_digest: [u8; 32]) -> PvgsStore {
    let mut known_charter_versions = HashSet::new();
    known_charter_versions.insert("charter".to_string());
    let mut known_policy_versions = HashSet::new();
    known_policy_versions.insert("policy".to_string());
    let mut known_profiles = HashSet::new();
    known_profiles.insert([9u8; 32]);

    PvgsStore::new(
        prev_digest,
        "charter".to_string(),
        "policy".to_string(),
        known_charter_versions,
        known_policy_versions,
        known_profiles,
    )
}

fn bounded_reason_codes(mut codes: Vec<String>) -> Vec<String> {
    codes.sort();
    codes.dedup();
    codes.truncate(MAX_REASON_CODES);
    codes
}

fn proposal_evidence_payload(
    base_evidence_digest: [u8; 32],
    payload_digest: [u8; 32],
    created_at_ms: u64,
) -> ([u8; 32], Vec<u8>) {
    let reason_codes = bounded_reason_codes(vec![
        ReasonCodes::GV_PROPOSAL_APPENDED.to_string(),
        "RC.GV.OK".to_string(),
    ]);
    let mut evidence = ProposalEvidence {
        proposal_id: "proposal-1".to_string(),
        proposal_digest: vec![0u8; 32],
        kind: ProposalKind::MappingUpdate as i32,
        base_evidence_digest: base_evidence_digest.to_vec(),
        payload_digest: payload_digest.to_vec(),
        created_at_ms,
        score: 0,
        verdict: 1,
        reason_codes,
    };
    let digest = compute_proposal_evidence_digest(&evidence).expect("proposal digest");
    evidence.proposal_digest = digest.to_vec();
    (digest, evidence.encode_to_vec())
}

fn proposal_activation_payload(
    activation_id: &str,
    proposal_digest: [u8; 32],
    approval_digest: [u8; 32],
    created_at_ms: u64,
) -> (ProposalActivationEvidence, Vec<u8>) {
    let mut raw_reason_codes = (0..20)
        .map(|idx| format!("RC.TEST.{idx:02}"))
        .collect::<Vec<_>>();
    raw_reason_codes.push("RC.GV.OK".to_string());
    raw_reason_codes.push(ReasonCodes::GV_PROPOSAL_ACTIVATED.to_string());
    raw_reason_codes.push("RC.GV.OK".to_string());
    let reason_codes = bounded_reason_codes(raw_reason_codes);

    let mut evidence = ProposalActivationEvidence {
        activation_id: activation_id.to_string(),
        activation_digest: vec![0u8; 32],
        proposal_digest: proposal_digest.to_vec(),
        approval_digest: approval_digest.to_vec(),
        status: ActivationStatus::Applied as i32,
        active_mapping_digest: Some([7u8; 32].to_vec()),
        active_sae_pack_digest: None,
        active_liquid_params_digest: None,
        active_limits_digest: Some([8u8; 32].to_vec()),
        created_at_ms,
        reason_codes,
    };

    let activation_digest = compute_proposal_activation_digest(&evidence).expect("activation");
    evidence.activation_digest = activation_digest.to_vec();
    let payload = evidence.encode_to_vec();

    (evidence, payload)
}

fn proposal_evidence_request(store: &PvgsStore, payload: Vec<u8>) -> PvgsCommitRequest {
    PvgsCommitRequest {
        commit_id: "proposal-commit".to_string(),
        commit_type: CommitType::ProposalEvidenceAppend,
        bindings: CommitBindings {
            action_digest: None,
            decision_digest: None,
            grant_id: None,
            charter_version_digest: "charter".to_string(),
            policy_version_digest: "policy".to_string(),
            prev_record_digest: store.current_head_record_digest,
            profile_digest: None,
            tool_profile_digest: None,
            pev_digest: None,
        },
        required_receipt_kind: RequiredReceiptKind::Read,
        required_checks: vec![RequiredCheck::SchemaOk, RequiredCheck::BindingOk],
        payload_digests: Vec::new(),
        epoch_id: 1,
        key_epoch: None,
        experience_record_payload: None,
        replay_run_evidence_payload: None,
        trace_run_evidence_payload: None,
        proposal_evidence_payload: Some(payload),
        proposal_activation_payload: None,
        macro_milestone: None,
        meso_milestone: None,
        dlp_decision_payload: None,
        tool_registry_container: None,
        pev: None,
        consistency_feedback_payload: None,
        macro_consistency_digest: None,
        recovery_case: None,
        unlock_permit: None,
        tool_onboarding_event: None,
        microcircuit_config_payload: None,
        asset_manifest_payload: None,
        asset_bundle_payload: None,
    }
}

fn proposal_activation_request(store: &PvgsStore, payload: Vec<u8>) -> PvgsCommitRequest {
    PvgsCommitRequest {
        commit_id: "activation-commit".to_string(),
        commit_type: CommitType::ProposalActivationAppend,
        bindings: CommitBindings {
            action_digest: None,
            decision_digest: None,
            grant_id: None,
            charter_version_digest: "charter".to_string(),
            policy_version_digest: "policy".to_string(),
            prev_record_digest: store.current_head_record_digest,
            profile_digest: None,
            tool_profile_digest: None,
            pev_digest: None,
        },
        required_receipt_kind: RequiredReceiptKind::Read,
        required_checks: vec![RequiredCheck::SchemaOk, RequiredCheck::BindingOk],
        payload_digests: Vec::new(),
        epoch_id: 1,
        key_epoch: None,
        experience_record_payload: None,
        replay_run_evidence_payload: None,
        trace_run_evidence_payload: None,
        proposal_evidence_payload: None,
        proposal_activation_payload: Some(payload),
        macro_milestone: None,
        meso_milestone: None,
        dlp_decision_payload: None,
        tool_registry_container: None,
        pev: None,
        consistency_feedback_payload: None,
        macro_consistency_digest: None,
        recovery_case: None,
        unlock_permit: None,
        tool_onboarding_event: None,
        microcircuit_config_payload: None,
        asset_manifest_payload: None,
        asset_bundle_payload: None,
    }
}

fn run_sequence() -> (String, Vec<String>) {
    let mut store = base_store([9u8; 32]);
    let keystore = KeyStore::new_dev_keystore(1);
    let vrf_engine = VrfEngine::new_dev(1);

    let base_evidence_digest = [5u8; 32];
    let payload_digest = [6u8; 32];
    let (proposal_digest, proposal_payload) =
        proposal_evidence_payload(base_evidence_digest, payload_digest, 10);
    let proposal_req = proposal_evidence_request(&store, proposal_payload);
    let (proposal_receipt, _) = verify_and_commit(proposal_req, &mut store, &keystore, &vrf_engine);
    assert_eq!(
        proposal_receipt.status,
        ucf_protocol::ucf::v1::ReceiptStatus::Accepted
    );

    let approval_digest = [11u8; 32];
    let (activation_evidence, activation_payload) =
        proposal_activation_payload("activation-1", proposal_digest, approval_digest, 12);
    let activation_req = proposal_activation_request(&store, activation_payload);
    let (activation_receipt, _) =
        verify_and_commit(activation_req, &mut store, &keystore, &vrf_engine);
    assert_eq!(
        activation_receipt.status,
        ucf_protocol::ucf::v1::ReceiptStatus::Accepted
    );

    assert!(store.proposal_store.get(proposal_digest).is_some());
    let activation_digest = activation_evidence
        .activation_digest
        .as_slice()
        .try_into()
        .expect("activation digest");
    assert!(store
        .proposal_activation_store
        .get(activation_digest)
        .is_some());

    let latest_proposal = latest_proposal(&store).expect("latest proposal");
    assert_eq!(
        latest_proposal.proposal_digest.as_slice(),
        proposal_digest.as_slice()
    );

    let latest_activation =
        latest_activation_for_proposal(&store, proposal_digest).expect("latest activation");
    assert_eq!(
        ActivationStatus::try_from(latest_activation.status).ok(),
        Some(ActivationStatus::Applied)
    );

    let snapshot = snapshot(&store, None);
    let proposals_card = snapshot.proposals_card.clone();
    assert_eq!(
        proposals_card.latest_activation_status,
        Some(ActivationStatus::Applied)
    );
    assert_eq!(proposals_card.activation_counts_last_n.applied, 1);
    assert_eq!(proposals_card.activation_counts_last_n.rejected, 0);

    let expected_reason_codes = vec![
        "RC.GV.OK".to_string(),
        "RC.GV.PROPOSAL.ACTIVATED".to_string(),
        "RC.TEST.00".to_string(),
        "RC.TEST.01".to_string(),
        "RC.TEST.02".to_string(),
        "RC.TEST.03".to_string(),
        "RC.TEST.04".to_string(),
        "RC.TEST.05".to_string(),
        "RC.TEST.06".to_string(),
        "RC.TEST.07".to_string(),
        "RC.TEST.08".to_string(),
        "RC.TEST.09".to_string(),
        "RC.TEST.10".to_string(),
        "RC.TEST.11".to_string(),
        "RC.TEST.12".to_string(),
        "RC.TEST.13".to_string(),
        "RC.TEST.14".to_string(),
        "RC.TEST.15".to_string(),
        "RC.TEST.16".to_string(),
        "RC.TEST.17".to_string(),
        "RC.TEST.18".to_string(),
        "RC.TEST.19".to_string(),
    ];
    assert_eq!(activation_evidence.reason_codes, expected_reason_codes);

    let scorecard_output = format!(
        "{:?} | activation_reason_codes={:?}",
        proposals_card, activation_evidence.reason_codes
    );

    let expected_card = ProposalsCard {
        latest_proposal_digest: Some(proposal_digest),
        latest_proposal_kind: Some(ProposalKind::MappingUpdate),
        latest_proposal_verdict: Some(1),
        latest_activation_status: Some(ActivationStatus::Applied),
        activation_counts_last_n: ActivationStatusCounts {
            applied: 1,
            rejected: 0,
        },
        activation_rejects_present: false,
        risky_activations_present: false,
        counts_last_n: ProposalVerdictCounts {
            promising: 1,
            neutral: 0,
            risky: 0,
        },
        risky_present: false,
    };
    let expected_output = format!(
        "{:?} | activation_reason_codes={:?}",
        expected_card, expected_reason_codes
    );
    assert_eq!(scorecard_output, expected_output);

    (scorecard_output, activation_evidence.reason_codes)
}

#[test]
fn proposal_activation_e2e_smoke_is_deterministic() {
    let (first_output, first_reason_codes) = run_sequence();
    let (second_output, second_reason_codes) = run_sequence();

    assert_eq!(first_output, second_output);
    assert_eq!(first_reason_codes, second_reason_codes);
    assert!(first_reason_codes.len() <= MAX_REASON_CODES);
}
