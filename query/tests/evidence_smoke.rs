use assets::{compute_asset_bundle_digest, compute_asset_chunk_digest, compute_asset_manifest_digest};
use blake3;
use keys::KeyStore;
use prost::Message;
use pvgs::{
    verify_and_commit, CommitBindings, CommitType, PvgsCommitRequest, PvgsStore, RequiredCheck,
    RequiredReceiptKind,
};
use replay_plan::{build_replay_plan, BuildReplayPlanArgs};
use std::collections::HashSet;
use trace_runs::{TraceRunEvidence, TraceStatus};
use ucf_protocol::ucf::v1::{
    AssetBundle, AssetChunk, AssetDigest, AssetKind, AssetManifest, CompressionMode, ReceiptStatus,
    Ref, ReplayFidelity, ReplayRunEvidence, ReplayTargetKind,
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

fn asset_bundle_payload(created_at_ms: u64, asset_seed: u8) -> (AssetBundle, [u8; 32]) {
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
        created_at_ms,
        manifest: Some(manifest),
        chunks: vec![chunk_one, chunk_two],
    };
    let bundle_digest =
        compute_asset_bundle_digest(bundle.manifest.as_ref().unwrap(), &bundle.chunks)
            .expect("bundle digest computed");
    bundle.bundle_digest = bundle_digest.to_vec();

    (bundle, manifest_digest)
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
    asset_manifest_digest: [u8; 32],
    circuit_config_digest: [u8; 32],
    created_at_ms: u64,
    status: TraceStatus,
) -> TraceRunEvidence {
    TraceRunEvidence {
        trace_id: "trace-1".to_string(),
        trace_run_digest: run_digest,
        asset_manifest_digest,
        circuit_config_digest,
        steps: 42,
        created_at_ms,
        status,
        reason_codes: vec!["RC.GV.OK".to_string()],
    }
}

#[test]
fn evidence_smoke_snapshot_is_deterministic() {
    let mut store = base_store([7u8; 32]);
    let keystore = KeyStore::new_dev_keystore(1);
    let vrf_engine = VrfEngine::new_dev(1);

    let (bundle, manifest_digest) = asset_bundle_payload(100, 5);
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
    store
        .replay_plans
        .push(plan_two.clone())
        .expect("plan two");

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
    store
        .replay_plans
        .push(plan_one.clone())
        .expect("plan one");

    let replay_run_digest = [9u8; 32];
    let micro_config_digest = [10u8; 32];
    let replay_evidence = replay_run_evidence(replay_run_digest, manifest_digest, micro_config_digest, 1234);
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

    let (replay_receipt, _) =
        verify_and_commit(replay_req, &mut store, &keystore, &vrf_engine);
    assert_eq!(replay_receipt.status, ReceiptStatus::Accepted);

    let trace_run_digest = [11u8; 32];
    let circuit_config_digest = [12u8; 32];
    let trace_evidence = trace_run_evidence(
        trace_run_digest,
        manifest_digest,
        circuit_config_digest,
        2345,
        TraceStatus::Pass,
    );
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
        trace_run_evidence_payload: Some(trace_evidence.encode().expect("encode trace run")),
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

    assert_eq!(snapshot_one.assets_card.latest_manifest_digest, Some(manifest_digest));
    assert_eq!(
        snapshot_one.replay_card.latest_replay_run_evidence_digest,
        Some(replay_run_digest)
    );
    assert_eq!(snapshot_one.replay_card.replay_run_evidence_count_last_n, 1);
    assert_eq!(
        snapshot_one.trace_card.latest_trace_run_digest,
        Some(trace_run_digest)
    );
    assert_eq!(snapshot_one.trace_card.latest_trace_run_status, Some(TraceStatus::Pass));
}
