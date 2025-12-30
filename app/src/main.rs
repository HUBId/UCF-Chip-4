#![forbid(unsafe_code)]

use std::collections::HashSet;

use clap::{Parser, Subcommand};
use hex::encode;
use pvgs::PvgsStore;
use query::{snapshot, PvgsSnapshot};
use ucf_protocol::ucf::v1::AssetKind;

#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    #[command(name = "pvgs-dump")]
    PvgsDump {
        #[arg(long)]
        session: Option<String>,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::PvgsDump { session } => {
            let store = PvgsStore::new(
                [0u8; 32],
                "charter:bootstrap".into(),
                "policy:bootstrap".into(),
                HashSet::new(),
                HashSet::new(),
                HashSet::new(),
            );

            let snapshot = snapshot(&store, session.as_deref());
            println!("{}", format_snapshot(&snapshot));
        }
    }
}

fn format_snapshot(snapshot: &PvgsSnapshot) -> String {
    let mut lines = Vec::new();

    lines.push(format!(
        "head: id={} digest={}",
        snapshot.head_experience_id,
        encode(snapshot.head_record_digest)
    ));

    lines.push(format!(
        "ruleset: current={} prev={}",
        hex_or_none(snapshot.ruleset_digest),
        hex_or_none(snapshot.prev_ruleset_digest),
    ));

    lines.push(format!(
        "cbv: epoch={} digest={}",
        snapshot
            .latest_cbv_epoch
            .map_or_else(|| "NONE".to_string(), |epoch| epoch.to_string()),
        hex_or_none(snapshot.latest_cbv_digest),
    ));

    lines.push(format!(
        "pev_digest: {}",
        hex_or_none(snapshot.latest_pev_digest)
    ));

    lines.push(format!(
        "micro_config_lc: version={} digest={}",
        version_or_none(snapshot.micro_card.lc_config_version),
        hex_or_none(snapshot.micro_card.lc_config_digest),
    ));
    lines.push(format!(
        "micro_config_sn: version={} digest={}",
        version_or_none(snapshot.micro_card.sn_config_version),
        hex_or_none(snapshot.micro_card.sn_config_digest),
    ));
    lines.push(format!(
        "micro_config_hpa: version={} digest={}",
        version_or_none(snapshot.micro_card.hpa_config_version),
        hex_or_none(snapshot.micro_card.hpa_config_digest),
    ));

    lines.push(format!(
        "asset_manifest: {}",
        hex_or_none(snapshot.assets_card.latest_manifest_digest)
    ));
    lines.push(format!(
        "asset_morphology: {}",
        hex_or_none(snapshot.assets_card.morphology_digest)
    ));
    lines.push(format!(
        "asset_channel: {}",
        hex_or_none(snapshot.assets_card.channel_digest)
    ));
    lines.push(format!(
        "asset_synapse: {}",
        hex_or_none(snapshot.assets_card.synapse_digest)
    ));
    lines.push(format!(
        "asset_connectivity: {}",
        hex_or_none(snapshot.assets_card.connectivity_digest)
    ));
    lines.push(format!(
        "asset_payload_summaries: {}",
        snapshot.assets_card.asset_payload_summaries.len()
    ));
    lines.push(format!(
        "replay_assets: bound={} missing={} missing_ids={}",
        snapshot.replay_card.pending_replay_plans_asset_bound_count,
        snapshot
            .replay_card
            .pending_replay_plans_asset_missing_count,
        if snapshot
            .replay_card
            .pending_replay_plans_asset_missing_ids
            .is_empty()
        {
            "NONE".to_string()
        } else {
            snapshot
                .replay_card
                .pending_replay_plans_asset_missing_ids
                .join(",")
        }
    ));
    for summary in &snapshot.assets_card.asset_payload_summaries {
        lines.push(format!(
            "- asset_summary:{} version={} digest={} bytes_len={} neuron_count={} edge_count={} syn_param_count={} channel_param_count={} labels:pool={} role={}",
            asset_kind_label(summary.kind),
            summary.version,
            encode(summary.digest),
            summary.bytes_len,
            count_or_none(summary.neuron_count),
            count_or_none(summary.edge_count),
            count_or_none(summary.syn_param_count),
            count_or_none(summary.channel_param_count),
            summary.has_pool_labels,
            summary.has_role_labels,
        ));
    }

    lines.push(format!(
        "proposals: latest={} kind={:?} verdict={:?} risky_present={} counts_last_n={{promising={}, neutral={}, risky={}}}",
        hex_or_none(snapshot.proposals_card.latest_proposal_digest),
        snapshot.proposals_card.latest_proposal_kind,
        snapshot.proposals_card.latest_proposal_verdict,
        snapshot.proposals_card.risky_present,
        snapshot.proposals_card.counts_last_n.promising,
        snapshot.proposals_card.counts_last_n.neutral,
        snapshot.proposals_card.counts_last_n.risky,
    ));

    lines.push(format!(
        "pending_replay_plans: {}",
        snapshot.pending_replay_ids.len()
    ));

    for replay_id in &snapshot.pending_replay_ids {
        lines.push(format!("- {}", replay_id));
    }

    lines.push(format!(
        "completeness: {}",
        snapshot
            .completeness_status
            .clone()
            .unwrap_or_else(|| "NONE".to_string())
    ));

    lines.push(format!(
        "last_seal: {}",
        hex_or_none(snapshot.last_seal_digest)
    ));

    let (recovery_state, recovery_checks, recovery_id) = snapshot
        .recovery_case
        .as_ref()
        .map(|case| {
            let state = format!("{:?}", case.state);
            let checks = format!(
                "{}/{}",
                case.completed_checks.len(),
                case.required_checks.len()
            );
            (state, checks, case.recovery_id.clone())
        })
        .unwrap_or_else(|| ("NONE".to_string(), "0/0".to_string(), "NONE".to_string()));

    lines.push(format!(
        "recovery: state={} checks={} id={}",
        recovery_state, recovery_checks, recovery_id
    ));

    let unlock_present = snapshot.unlock_permit_digest.is_some();
    lines.push(format!(
        "unlock_permit: present={} digest={}",
        unlock_present,
        hex_or_none(snapshot.unlock_permit_digest)
    ));

    lines.push(format!(
        "unlock_hint: {}",
        snapshot
            .unlock_readiness_hint
            .clone()
            .unwrap_or_else(|| "NONE".to_string())
    ));

    lines.join("\n")
}

fn hex_or_none(value: Option<[u8; 32]>) -> String {
    value.map(encode).unwrap_or_else(|| "NONE".to_string())
}

fn version_or_none(value: Option<u32>) -> String {
    value
        .map(|version| version.to_string())
        .unwrap_or_else(|| "NONE".to_string())
}

fn count_or_none(value: Option<u32>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "NONE".to_string())
}

fn asset_kind_label(kind: AssetKind) -> &'static str {
    match kind {
        AssetKind::Unspecified => "UNSPECIFIED",
        AssetKind::Morphology => "MORPHOLOGY",
        AssetKind::Channel => "CHANNEL",
        AssetKind::Synapse => "SYNAPSE",
        AssetKind::Connectivity => "CONNECTIVITY",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assets::compute_asset_manifest_digest;
    use cbv::compute_cbv_digest;
    use cbv::CharacterBaselineVector;
    use micro_evidence::compute_config_digest;
    use pev::{pev_digest, PolicyEcologyDimension, PolicyEcologyVector};
    use query::{get_current_ruleset_digest, get_previous_ruleset_digest};
    use recovery::{RecoveryCase, RecoveryCheck, RecoveryState};
    use replay_plan::{build_replay_plan, BuildReplayPlanArgs};
    use sep::SepEventType;
    use ucf_protocol::ucf::v1::{
        AssetDigest, AssetKind, AssetManifest, MicroModule, MicrocircuitConfigEvidence,
        ReplayFidelity, ReplayTargetKind,
    };

    #[test]
    fn pvgs_dump_formats_snapshot() {
        let head_digest = [1u8; 32];
        let mut store = PvgsStore::new(
            head_digest,
            "charter:v1".into(),
            "policy:v1".into(),
            HashSet::new(),
            HashSet::new(),
            HashSet::new(),
        );

        store.experience_store.head_id = 7;
        store.experience_store.head_record_digest = head_digest;
        store.current_head_record_digest = head_digest;
        store.ruleset_state.prev_ruleset_digest = Some([9u8; 32]);

        let mut cbv = CharacterBaselineVector {
            cbv_epoch: 5,
            baseline_caution_offset: 1,
            baseline_novelty_dampening_offset: 2,
            baseline_approval_strictness_offset: 3,
            baseline_export_strictness_offset: 4,
            baseline_chain_conservatism_offset: 5,
            baseline_cooldown_multiplier_class: 6,
            cbv_digest: None,
            source_milestone_refs: Vec::new(),
            source_event_refs: Vec::new(),
            proof_receipt_ref: None,
            pvgs_attestation_key_id: String::new(),
            pvgs_attestation_sig: Vec::new(),
        };
        let cbv_digest = compute_cbv_digest(&cbv);
        cbv.cbv_digest = Some(cbv_digest.to_vec());
        store.cbv_store.push(cbv);

        let pev = PolicyEcologyVector {
            dimensions: vec![PolicyEcologyDimension {
                name: "consistency_bias".into(),
                value: 10,
            }],
            pev_digest: Some([3u8; 32].to_vec()),
            pev_version_digest: None,
            pev_epoch: Some(1),
        };
        store.pev_store.push(pev).unwrap();
        store.update_pev_digest(pev_digest(store.pev_store.latest().unwrap()));

        let lc_config_digest = compute_config_digest("LC", 1, b"lc-config");
        let sn_config_digest = compute_config_digest("SN", 2, b"sn-config");
        let hpa_config_digest = compute_config_digest("HPA", 3, b"hpa-config");

        store
            .micro_config_store
            .insert(MicrocircuitConfigEvidence {
                module: MicroModule::Lc as i32,
                config_version: 1,
                config_digest: lc_config_digest.to_vec(),
                created_at_ms: 1,
                attested_by_key_id: None,
                signature: None,
            })
            .unwrap();
        store
            .micro_config_store
            .insert(MicrocircuitConfigEvidence {
                module: MicroModule::Sn as i32,
                config_version: 2,
                config_digest: sn_config_digest.to_vec(),
                created_at_ms: 2,
                attested_by_key_id: None,
                signature: None,
            })
            .unwrap();
        store
            .micro_config_store
            .insert(MicrocircuitConfigEvidence {
                module: MicroModule::Hpa as i32,
                config_version: 3,
                config_digest: hpa_config_digest.to_vec(),
                created_at_ms: 3,
                attested_by_key_id: None,
                signature: None,
            })
            .unwrap();

        let mut manifest = AssetManifest {
            manifest_digest: Vec::new(),
            created_at_ms: 10,
            asset_digests: vec![
                AssetDigest {
                    kind: AssetKind::Morphology as i32,
                    digest: [4u8; 32].to_vec(),
                    version: 1,
                },
                AssetDigest {
                    kind: AssetKind::Channel as i32,
                    digest: [5u8; 32].to_vec(),
                    version: 1,
                },
                AssetDigest {
                    kind: AssetKind::Synapse as i32,
                    digest: [6u8; 32].to_vec(),
                    version: 1,
                },
                AssetDigest {
                    kind: AssetKind::Connectivity as i32,
                    digest: [7u8; 32].to_vec(),
                    version: 1,
                },
            ],
        };
        let manifest_digest = compute_asset_manifest_digest(&manifest);
        manifest.manifest_digest = manifest_digest.to_vec();
        store.asset_manifest_store.insert(manifest).unwrap();

        let plan_a = build_replay_plan(BuildReplayPlanArgs {
            session_id: "sess-1".into(),
            head_experience_id: store.experience_store.head_id,
            head_record_digest: head_digest,
            target_kind: ReplayTargetKind::Micro,
            target_refs: vec![ucf_protocol::ucf::v1::Ref {
                id: "micro:a".into(),
                digest: None,
            }],
            fidelity: ReplayFidelity::Low,
            counter: 1,
            trigger_reason_codes: vec!["reason-a".into()],
            asset_manifest_ref: None,
        });
        let plan_b = build_replay_plan(BuildReplayPlanArgs {
            session_id: "sess-1".into(),
            head_experience_id: store.experience_store.head_id,
            head_record_digest: head_digest,
            target_kind: ReplayTargetKind::Micro,
            target_refs: vec![ucf_protocol::ucf::v1::Ref {
                id: "micro:b".into(),
                digest: None,
            }],
            fidelity: ReplayFidelity::Low,
            counter: 2,
            trigger_reason_codes: vec!["reason-b".into()],
            asset_manifest_ref: None,
        });

        store.replay_plans.push(plan_a.clone()).unwrap();
        store.replay_plans.push(plan_b.clone()).unwrap();

        store
            .recovery_store
            .insert_new(RecoveryCase {
                recovery_id: "recovery:test".into(),
                session_id: "sess-1".into(),
                state: RecoveryState::R0Captured,
                required_checks: vec![RecoveryCheck::IntegrityOk],
                completed_checks: Vec::new(),
                trigger_refs: vec!["trigger".into()],
                created_at_ms: Some(42),
            })
            .unwrap();

        let permit = pvgs::UnlockPermit::new("sess-1".into(), 99, [8u8; 32]);
        store.unlock_permits.insert("sess-1".into(), permit.clone());

        let decision_event = store
            .sep_log
            .append_event(
                "sess-1".into(),
                SepEventType::EvDecision,
                [7u8; 32],
                Vec::new(),
            )
            .unwrap();

        let snapshot = snapshot(&store, Some("sess-1"));

        assert_eq!(snapshot.head_experience_id, 7);
        assert_eq!(snapshot.head_record_digest, head_digest);
        assert_eq!(snapshot.ruleset_digest, get_current_ruleset_digest(&store));
        assert_eq!(
            snapshot.prev_ruleset_digest,
            get_previous_ruleset_digest(&store)
        );
        assert_eq!(snapshot.latest_cbv_epoch, Some(5));
        assert_eq!(snapshot.latest_cbv_digest, Some(cbv_digest));
        assert_eq!(snapshot.latest_pev_digest, Some([3u8; 32]));
        assert_eq!(snapshot.micro_card.lc_config_digest, Some(lc_config_digest));
        assert_eq!(snapshot.micro_card.lc_config_version, Some(1));
        assert_eq!(snapshot.micro_card.sn_config_digest, Some(sn_config_digest));
        assert_eq!(snapshot.micro_card.sn_config_version, Some(2));
        assert_eq!(
            snapshot.micro_card.hpa_config_digest,
            Some(hpa_config_digest)
        );
        assert_eq!(snapshot.micro_card.hpa_config_version, Some(3));
        assert_eq!(
            snapshot.assets_card.latest_manifest_digest,
            Some(manifest_digest)
        );
        assert_eq!(snapshot.assets_card.morphology_digest, Some([4u8; 32]));
        assert_eq!(snapshot.assets_card.channel_digest, Some([5u8; 32]));
        assert_eq!(snapshot.assets_card.synapse_digest, Some([6u8; 32]));
        assert_eq!(snapshot.assets_card.connectivity_digest, Some([7u8; 32]));
        assert_eq!(
            snapshot.pending_replay_ids,
            vec![plan_a.replay_id, plan_b.replay_id]
        );
        assert_eq!(snapshot.last_seal_digest, Some(decision_event.event_digest));

        let expected = format!(
            "head: id=7 digest={}\nruleset: current={} prev={}\ncbv: epoch=5 digest={}\npev_digest: {}\nmicro_config_lc: version=1 digest={}\nmicro_config_sn: version=2 digest={}\nmicro_config_hpa: version=3 digest={}\nasset_manifest: {}\nasset_morphology: {}\nasset_channel: {}\nasset_synapse: {}\nasset_connectivity: {}\nasset_payload_summaries: 0\nreplay_assets: bound=0 missing=2 missing_ids=replay:sess-1:7:1,replay:sess-1:7:2\nproposals: latest=NONE kind=None verdict=None risky_present=false counts_last_n={{promising=0, neutral=0, risky=0}}\npending_replay_plans: 2\n- replay:sess-1:7:1\n- replay:sess-1:7:2\ncompleteness: {}\nlast_seal: {}\nrecovery: state=R0Captured checks=0/1 id=recovery:test\nunlock_permit: present=true digest={}\nunlock_hint: UNLOCKED_READONLY",
            encode(head_digest),
            encode(snapshot.ruleset_digest.unwrap()),
            encode(snapshot.prev_ruleset_digest.unwrap()),
            encode(cbv_digest),
            encode(snapshot.latest_pev_digest.unwrap()),
            encode(lc_config_digest),
            encode(sn_config_digest),
            encode(hpa_config_digest),
            encode(manifest_digest),
            encode([4u8; 32]),
            encode([5u8; 32]),
            encode([6u8; 32]),
            encode([7u8; 32]),
            snapshot
                .completeness_status
                .clone()
                .unwrap_or_else(|| "NONE".to_string()),
            encode(decision_event.event_digest),
            encode(permit.permit_digest),
        );

        let output = format_snapshot(&snapshot);
        assert_eq!(output, expected);
    }
}
