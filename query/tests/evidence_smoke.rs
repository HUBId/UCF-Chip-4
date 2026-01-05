use assets::{
    compute_asset_bundle_digest, compute_asset_chunk_digest, compute_asset_manifest_digest,
};
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
use replay_plan::{build_replay_plan, BuildReplayPlanArgs};
use std::collections::HashSet;
use trace_runs::{compute_trace_run_digest, TraceRunEvidence, TraceVerdict};
use ucf_protocol::ucf::v1::{
    AssetBundle, AssetChunk, AssetDigest, AssetKind, AssetManifest, CompressionMode, ReasonCodes,
    ReceiptStatus, Ref, ReplayFidelity, ReplayRunEvidence, ReplayTargetKind,
};
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
        "charter".to_string(),
        "policy".to_string(),
        known_charter_versions,
        known_policy_versions,
        known_profiles,
    )
}

fn asset_manifest_payload(created_at_ms: u64, asset_seed: u8) -> (AssetManifest, [u8; 32]) {
    let asset_digest = [asset_seed; 32];
    let mut manifest = AssetManifest {
        manifest_digest: Vec::new(),
        created_at_ms,
        asset_digests: vec![AssetDigest {
            kind: AssetKind::Morphology as i32,
            digest: asset_digest.to_vec(),
            version: 1,
        }],
    };
    let manifest_digest = compute_asset_manifest_digest(&manifest);
    manifest.manifest_digest = manifest_digest.to_vec();
    (manifest, manifest_digest)
}

fn asset_bundle_payload(manifest: AssetManifest) -> AssetBundle {
    let asset_digest = manifest
        .asset_digests
        .first()
        .expect("asset digest")
        .digest
        .clone();

    let chunk_payload_one = b"evidence-bundle-one".to_vec();
    let chunk_payload_two = b"evidence-bundle-two".to_vec();
    let chunk_one = AssetChunk {
        asset_digest: asset_digest.to_vec(),
        chunk_index: 0,
        chunk_count: 2,
        payload: chunk_payload_one.clone(),
        chunk_digest: compute_asset_chunk_digest(&chunk_payload_one).to_vec(),
        compression_mode: CompressionMode::None as i32,
    };
    let chunk_two = AssetChunk {
        asset_digest: asset_digest.to_vec(),
        chunk_index: 1,
        chunk_count: 2,
        payload: chunk_payload_two.clone(),
        chunk_digest: compute_asset_chunk_digest(&chunk_payload_two).to_vec(),
        compression_mode: CompressionMode::Zstd as i32,
    };

    let mut bundle = AssetBundle {
        bundle_digest: Vec::new(),
        created_at_ms: manifest.created_at_ms,
        manifest: Some(manifest),
        chunks: vec![chunk_one, chunk_two],
    };
    let bundle_digest =
        compute_asset_bundle_digest(bundle.manifest.as_ref().unwrap(), &bundle.chunks)
            .expect("bundle digest computed");
    bundle.bundle_digest = bundle_digest.to_vec();

    bundle
}

fn asset_manifest_request(store: &PvgsStore, manifest: &AssetManifest) -> PvgsCommitRequest {
    let payload = manifest.encode_to_vec();
    PvgsCommitRequest {
        commit_id: "asset-manifest-commit".to_string(),
        commit_type: CommitType::AssetManifestAppend,
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
        asset_manifest_payload: Some(payload),
        asset_bundle_payload: None,
    }
}

fn asset_bundle_request(store: &PvgsStore, bundle: &AssetBundle) -> PvgsCommitRequest {
    let payload = bundle.encode_to_vec();
    PvgsCommitRequest {
        commit_id: "asset-bundle-commit".to_string(),
        commit_type: CommitType::AssetBundleAppend,
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
        asset_bundle_payload: Some(payload),
    }
}

fn replay_run_evidence(
    run_digest: [u8; 32],
    asset_manifest_digest: [u8; 32],
    micro_config_digest: [u8; 32],
    created_at_ms: u64,
) -> ReplayRunEvidence {
    ReplayRunEvidence {
        run_digest: run_digest.to_vec(),
        replay_plan_ref: None,
        asset_manifest_ref: Some(Ref {
            id: "asset_manifest".to_string(),
            digest: Some(asset_manifest_digest.to_vec()),
        }),
        steps: 10,
        dt_us: 5,
        created_at_ms,
        micro_config_refs: vec![Ref {
            id: "mc_cfg:lc".to_string(),
            digest: Some(micro_config_digest.to_vec()),
        }],
        summary_digests: vec![vec![4u8; 32]],
    }
}

fn trace_run_evidence(
    run_digest: [u8; 32],
    active_cfg_digest: [u8; 32],
    shadow_cfg_digest: [u8; 32],
    active_feedback_digest: [u8; 32],
    shadow_feedback_digest: [u8; 32],
    created_at_ms: u64,
    verdict: TraceVerdict,
) -> TraceRunEvidence {
    let mut evidence = TraceRunEvidence {
        trace_id: "trace-1".to_string(),
        trace_digest: run_digest.to_vec(),
        active_cfg_digest: active_cfg_digest.to_vec(),
        shadow_cfg_digest: shadow_cfg_digest.to_vec(),
        active_feedback_digest: active_feedback_digest.to_vec(),
        shadow_feedback_digest: shadow_feedback_digest.to_vec(),
        score_active: 10,
        score_shadow: 12,
        delta: 2,
        verdict: verdict.into(),
        created_at_ms,
        reason_codes: vec!["RC.GV.OK".to_string()],
    };
    let digest = compute_trace_run_digest(&evidence).expect("digest");
    evidence.trace_digest = digest.to_vec();
    evidence
}

fn proposal_evidence(
    base_evidence_digest: [u8; 32],
    payload_digest: [u8; 32],
    created_at_ms: u64,
    verdict: i32,
) -> ProposalEvidence {
    let mut evidence = ProposalEvidence {
        proposal_id: "proposal-1".to_string(),
        proposal_digest: vec![0u8; 32],
        kind: ProposalKind::MappingUpdate as i32,
        base_evidence_digest: base_evidence_digest.to_vec(),
        payload_digest: payload_digest.to_vec(),
        created_at_ms,
        score: 0,
        verdict,
        reason_codes: vec![
            "RC.GV.OK".to_string(),
            ReasonCodes::GV_PROPOSAL_APPENDED.to_string(),
        ],
    };
    let digest = compute_proposal_evidence_digest(&evidence).expect("proposal digest");
    evidence.proposal_digest = digest.to_vec();
    evidence
}

fn proposal_activation_evidence(
    proposal_digest: [u8; 32],
    approval_digest: [u8; 32],
    created_at_ms: u64,
    status: ActivationStatus,
) -> ProposalActivationEvidence {
    let reason_code = match status {
        ActivationStatus::Applied => ReasonCodes::GV_PROPOSAL_ACTIVATED,
        ActivationStatus::Rejected => ReasonCodes::GV_PROPOSAL_REJECTED,
        ActivationStatus::Unspecified => ReasonCodes::GE_VALIDATION_SCHEMA_INVALID,
    };
    let mut evidence = ProposalActivationEvidence {
        activation_id: "activation-1".to_string(),
        activation_digest: vec![0u8; 32],
        proposal_digest: proposal_digest.to_vec(),
        approval_digest: approval_digest.to_vec(),
        status: status as i32,
        active_mapping_digest: Some([7u8; 32].to_vec()),
        active_sae_pack_digest: None,
        active_liquid_params_digest: None,
        active_limits_digest: Some([8u8; 32].to_vec()),
        created_at_ms,
        reason_codes: vec!["RC.GV.OK".to_string(), reason_code.to_string()],
    };
    let digest = compute_proposal_activation_digest(&evidence).expect("activation digest");
    evidence.activation_digest = digest.to_vec();
    evidence
}

fn proposal_evidence_request(
    store: &PvgsStore,
    payload: Vec<u8>,
    commit_id: &str,
) -> PvgsCommitRequest {
    PvgsCommitRequest {
        commit_id: commit_id.to_string(),
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

fn proposal_activation_request(
    store: &PvgsStore,
    payload: Vec<u8>,
    commit_id: &str,
) -> PvgsCommitRequest {
    PvgsCommitRequest {
        commit_id: commit_id.to_string(),
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

#[test]
fn evidence_smoke_snapshot_is_deterministic() {
    let mut store = base_store([7u8; 32]);
    let keystore = KeyStore::new_dev_keystore(1);
    let vrf_engine = VrfEngine::new_dev(1);

    let (manifest, manifest_digest) = asset_manifest_payload(100, 5);
    let manifest_req = asset_manifest_request(&store, &manifest);
    let (manifest_receipt, _) = verify_and_commit(manifest_req, &mut store, &keystore, &vrf_engine);
    assert_eq!(manifest_receipt.status, ReceiptStatus::Accepted);

    let bundle = asset_bundle_payload(manifest.clone());
    let req = asset_bundle_request(&store, &bundle);
    let (receipt, _) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);
    assert_eq!(receipt.status, ReceiptStatus::Accepted);

    let asset_manifest_ref = Some(Ref {
        id: "asset_manifest".to_string(),
        digest: Some(manifest_digest.to_vec()),
    });
    let plan_two = build_replay_plan(BuildReplayPlanArgs {
        session_id: "session-1".to_string(),
        head_experience_id: store.experience_store.head_id,
        head_record_digest: store.current_head_record_digest,
        target_kind: ReplayTargetKind::Macro,
        target_refs: vec![
            Ref {
                id: "target-b".to_string(),
                digest: None,
            },
            Ref {
                id: "target-a".to_string(),
                digest: None,
            },
        ],
        fidelity: ReplayFidelity::Low,
        counter: 2,
        trigger_reason_codes: vec!["RC.GV.TRIGGER".to_string()],
        asset_manifest_ref: asset_manifest_ref.clone(),
    });
    store.replay_plans.push(plan_two.clone()).expect("plan two");

    let plan_one = build_replay_plan(BuildReplayPlanArgs {
        session_id: "session-1".to_string(),
        head_experience_id: store.experience_store.head_id,
        head_record_digest: store.current_head_record_digest,
        target_kind: ReplayTargetKind::Macro,
        target_refs: vec![Ref {
            id: "target-a".to_string(),
            digest: None,
        }],
        fidelity: ReplayFidelity::Low,
        counter: 1,
        trigger_reason_codes: vec!["RC.GV.TRIGGER".to_string()],
        asset_manifest_ref: asset_manifest_ref.clone(),
    });
    store.replay_plans.push(plan_one.clone()).expect("plan one");

    let replay_run_digest = [9u8; 32];
    let micro_config_digest = [10u8; 32];
    let replay_evidence = replay_run_evidence(
        replay_run_digest,
        manifest_digest,
        micro_config_digest,
        1234,
    );
    let replay_req = PvgsCommitRequest {
        commit_id: "replay-run-evidence".to_string(),
        commit_type: CommitType::ReplayRunEvidenceAppend,
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
        required_receipt_kind: RequiredReceiptKind::Write,
        required_checks: vec![RequiredCheck::SchemaOk, RequiredCheck::BindingOk],
        payload_digests: Vec::new(),
        epoch_id: keystore.current_epoch(),
        key_epoch: None,
        experience_record_payload: None,
        replay_run_evidence_payload: Some(replay_evidence.encode_to_vec()),
        trace_run_evidence_payload: None,
        proposal_evidence_payload: None,
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
    };

    let (replay_receipt, _) = verify_and_commit(replay_req, &mut store, &keystore, &vrf_engine);
    assert_eq!(replay_receipt.status, ReceiptStatus::Accepted);

    let trace_run_digest = [11u8; 32];
    let active_cfg_digest = [12u8; 32];
    let shadow_cfg_digest = [13u8; 32];
    let active_feedback_digest = [14u8; 32];
    let shadow_feedback_digest = [15u8; 32];
    let trace_evidence = trace_run_evidence(
        trace_run_digest,
        active_cfg_digest,
        shadow_cfg_digest,
        active_feedback_digest,
        shadow_feedback_digest,
        2345,
        TraceVerdict::Promising,
    );
    let trace_run_digest: [u8; 32] = trace_evidence
        .trace_digest
        .as_slice()
        .try_into()
        .expect("trace digest");
    let trace_req = PvgsCommitRequest {
        commit_id: "trace-run-evidence".to_string(),
        commit_type: CommitType::TraceRunEvidenceAppend,
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
        required_receipt_kind: RequiredReceiptKind::Write,
        required_checks: vec![RequiredCheck::SchemaOk, RequiredCheck::BindingOk],
        payload_digests: Vec::new(),
        epoch_id: keystore.current_epoch(),
        key_epoch: None,
        experience_record_payload: None,
        replay_run_evidence_payload: None,
        trace_run_evidence_payload: Some(trace_evidence.encode_to_vec()),
        proposal_evidence_payload: None,
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
    };

    let (trace_receipt, _) = verify_and_commit(trace_req, &mut store, &keystore, &vrf_engine);
    assert_eq!(trace_receipt.status, ReceiptStatus::Accepted);

    let snapshot_one = query::snapshot(&store, None);
    let snapshot_two = query::snapshot(&store, None);

    let digest_one = blake3::hash(format!("{snapshot_one:?}").as_bytes());
    let digest_two = blake3::hash(format!("{snapshot_two:?}").as_bytes());
    assert_eq!(digest_one, digest_two);
    assert_eq!(snapshot_one, snapshot_two);

    let mut expected_pending = vec![plan_one.replay_id.clone(), plan_two.replay_id.clone()];
    expected_pending.sort();
    assert_eq!(snapshot_one.pending_replay_ids, expected_pending);

    assert_eq!(
        snapshot_one.assets_card.latest_manifest_digest,
        Some(manifest_digest)
    );
    assert_eq!(
        snapshot_one.replay_card.latest_replay_run_evidence_digest,
        Some(replay_run_digest)
    );
    assert_eq!(snapshot_one.replay_card.replay_run_evidence_count_last_n, 1);
    assert_eq!(
        snapshot_one.trace_card.latest_trace_run_digest,
        Some(trace_run_digest)
    );
    assert_eq!(
        snapshot_one.trace_card.latest_trace_verdict,
        Some(TraceVerdict::Promising)
    );
    assert_eq!(snapshot_one.trace_card.latest_trace_delta, Some(2));
}

#[test]
fn proposal_evidence_append_is_accepted_and_idempotent() {
    let mut store = base_store([2u8; 32]);
    let keystore = KeyStore::new_dev_keystore(1);
    let vrf_engine = VrfEngine::new_dev(1);

    let evidence = proposal_evidence([3u8; 32], [4u8; 32], 12, 1);
    let proposal_digest: [u8; 32] = evidence
        .proposal_digest
        .as_slice()
        .try_into()
        .expect("proposal digest");
    let payload = evidence.encode_to_vec();
    let req = proposal_evidence_request(&store, payload, "proposal-evidence-1");

    let (receipt, proof) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);
    assert_eq!(receipt.status, ReceiptStatus::Accepted);
    assert!(proof.is_some());
    assert_eq!(store.proposal_store.by_digest.len(), 1);

    let second_payload = evidence.encode_to_vec();
    let second_req = proposal_evidence_request(&store, second_payload, "proposal-evidence-2");
    let (second_receipt, _) = verify_and_commit(second_req, &mut store, &keystore, &vrf_engine);
    assert_eq!(second_receipt.status, ReceiptStatus::Accepted);
    assert_eq!(store.proposal_store.by_digest.len(), 1);

    let sep_event = store
        .sep_log
        .events
        .iter()
        .find(|event| event.object_digest == proposal_digest)
        .expect("sep event present");
    assert!(sep_event
        .reason_codes
        .iter()
        .any(|code| code == ReasonCodes::GV_PROPOSAL_APPENDED));
}

#[test]
fn proposal_activation_append_is_accepted_and_idempotent() {
    let mut store = base_store([2u8; 32]);
    let keystore = KeyStore::new_dev_keystore(1);
    let vrf_engine = VrfEngine::new_dev(1);

    let evidence =
        proposal_activation_evidence([11u8; 32], [12u8; 32], 22, ActivationStatus::Applied);
    let activation_digest: [u8; 32] = evidence
        .activation_digest
        .as_slice()
        .try_into()
        .expect("activation digest");
    let payload = evidence.encode_to_vec();
    let req = proposal_activation_request(&store, payload, "proposal-activation-1");

    let (receipt, proof) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);
    assert_eq!(receipt.status, ReceiptStatus::Accepted);
    assert!(proof.is_some());
    assert_eq!(store.proposal_activation_store.by_digest.len(), 1);

    let second_payload = evidence.encode_to_vec();
    let second_req = proposal_activation_request(&store, second_payload, "proposal-activation-2");
    let (second_receipt, _) = verify_and_commit(second_req, &mut store, &keystore, &vrf_engine);
    assert_eq!(second_receipt.status, ReceiptStatus::Accepted);
    assert_eq!(store.proposal_activation_store.by_digest.len(), 1);

    let sep_event = store
        .sep_log
        .events
        .iter()
        .find(|event| event.object_digest == activation_digest)
        .expect("sep event present");
    assert!(sep_event
        .reason_codes
        .iter()
        .any(|code| code == ReasonCodes::GV_PROPOSAL_ACTIVATED));
}

#[test]
fn list_proposals_is_deterministic() {
    let mut store = base_store([3u8; 32]);
    let first = proposal_evidence([5u8; 32], [6u8; 32], 10, 0);
    let second = proposal_evidence([6u8; 32], [7u8; 32], 9, 2);
    let third = proposal_evidence([7u8; 32], [8u8; 32], 10, 1);

    let first_digest: [u8; 32] = first.proposal_digest.as_slice().try_into().expect("digest");
    let second_digest: [u8; 32] = second
        .proposal_digest
        .as_slice()
        .try_into()
        .expect("digest");
    let third_digest: [u8; 32] = third.proposal_digest.as_slice().try_into().expect("digest");

    store.proposal_store.insert(first).expect("insert proposal");
    store
        .proposal_store
        .insert(second)
        .expect("insert proposal");
    store.proposal_store.insert(third).expect("insert proposal");

    let ordered = query::list_proposals(&store, 10);
    let ordered_digests: Vec<[u8; 32]> = ordered
        .iter()
        .map(|proposal| {
            proposal
                .proposal_digest
                .as_slice()
                .try_into()
                .expect("digest")
        })
        .collect();
    let mut same_time = [first_digest, third_digest];
    same_time.sort();
    assert_eq!(
        ordered_digests,
        vec![second_digest, same_time[0], same_time[1]]
    );
}

#[test]
fn list_proposal_activations_is_deterministic() {
    let mut store = base_store([3u8; 32]);
    let first = proposal_activation_evidence([5u8; 32], [6u8; 32], 10, ActivationStatus::Applied);
    let second = proposal_activation_evidence([5u8; 32], [7u8; 32], 9, ActivationStatus::Rejected);
    let third = proposal_activation_evidence([5u8; 32], [8u8; 32], 10, ActivationStatus::Applied);

    let first_digest: [u8; 32] = first
        .activation_digest
        .as_slice()
        .try_into()
        .expect("digest");
    let second_digest: [u8; 32] = second
        .activation_digest
        .as_slice()
        .try_into()
        .expect("digest");
    let third_digest: [u8; 32] = third
        .activation_digest
        .as_slice()
        .try_into()
        .expect("digest");

    store
        .proposal_activation_store
        .insert(first)
        .expect("insert activation");
    store
        .proposal_activation_store
        .insert(second)
        .expect("insert activation");
    store
        .proposal_activation_store
        .insert(third)
        .expect("insert activation");

    let ordered = query::list_proposal_activations(&store, 10);
    let ordered_digests: Vec<[u8; 32]> = ordered
        .iter()
        .map(|activation| {
            activation
                .activation_digest
                .as_slice()
                .try_into()
                .expect("digest")
        })
        .collect();
    let mut same_time = [first_digest, third_digest];
    same_time.sort();
    assert_eq!(
        ordered_digests,
        vec![second_digest, same_time[0], same_time[1]]
    );
}

#[test]
fn latest_activation_for_proposal_is_deterministic() {
    let mut store = base_store([3u8; 32]);
    let proposal_digest = [7u8; 32];
    let first =
        proposal_activation_evidence(proposal_digest, [6u8; 32], 10, ActivationStatus::Applied);
    let second =
        proposal_activation_evidence(proposal_digest, [6u8; 32], 10, ActivationStatus::Rejected);
    let other = proposal_activation_evidence([8u8; 32], [9u8; 32], 11, ActivationStatus::Applied);
    let first_digest: [u8; 32] = first
        .activation_digest
        .as_slice()
        .try_into()
        .expect("digest");
    let second_digest: [u8; 32] = second
        .activation_digest
        .as_slice()
        .try_into()
        .expect("digest");

    store
        .proposal_activation_store
        .insert(first)
        .expect("insert activation");
    store
        .proposal_activation_store
        .insert(second.clone())
        .expect("insert activation");
    store
        .proposal_activation_store
        .insert(other)
        .expect("insert activation");

    let latest =
        query::latest_activation_for_proposal(&store, proposal_digest).expect("latest activation");
    let expected = if second_digest > first_digest {
        second_digest
    } else {
        first_digest
    };
    let latest_digest: [u8; 32] = latest
        .activation_digest
        .as_slice()
        .try_into()
        .expect("digest");
    assert_eq!(latest_digest, expected);
}

#[test]
fn proposals_scorecard_includes_latest() {
    let mut store = base_store([4u8; 32]);
    let older = proposal_evidence([5u8; 32], [6u8; 32], 3, 0);
    let latest = proposal_evidence([7u8; 32], [8u8; 32], 7, 2);
    let latest_digest: [u8; 32] = latest
        .proposal_digest
        .as_slice()
        .try_into()
        .expect("latest digest");

    store.proposal_store.insert(older).expect("insert proposal");
    store
        .proposal_store
        .insert(latest)
        .expect("insert proposal");

    let activation =
        proposal_activation_evidence([9u8; 32], [11u8; 32], 12, ActivationStatus::Rejected);
    store
        .proposal_activation_store
        .insert(activation)
        .expect("insert activation");

    let snapshot = query::snapshot(&store, None);
    assert_eq!(
        snapshot.proposals_card.latest_proposal_digest,
        Some(latest_digest)
    );
    assert!(snapshot.proposals_card.risky_present);
    assert_eq!(
        snapshot.proposals_card.latest_activation_status,
        Some(ActivationStatus::Rejected)
    );
    assert!(snapshot.proposals_card.activation_rejects_present);
}
