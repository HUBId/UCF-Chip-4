#![forbid(unsafe_code)]

use std::collections::HashSet;

use clap::{Parser, Subcommand};
use hex::encode;
use pvgs::PvgsStore;
use query::{snapshot, PvgsSnapshot};

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

#[cfg(test)]
mod tests {
    use super::*;
    use cbv::compute_cbv_digest;
    use cbv::CharacterBaselineVector;
    use pev::{pev_digest, PolicyEcologyDimension, PolicyEcologyVector};
    use query::{get_current_ruleset_digest, get_previous_ruleset_digest};
    use recovery::{RecoveryCase, RecoveryCheck, RecoveryState};
    use replay_plan::{build_replay_plan, BuildReplayPlanArgs};
    use sep::SepEventType;
    use ucf_protocol::ucf::v1::{ReplayFidelity, ReplayTargetKind};

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

        let plan_a = build_replay_plan(BuildReplayPlanArgs {
            session_id: "sess-1".into(),
            head_experience_id: store.experience_store.head_id,
            head_record_digest: head_digest,
            target_kind: ReplayTargetKind::Micro,
            target_refs: vec![ucf_protocol::ucf::v1::Ref {
                id: "micro:a".into(),
            }],
            fidelity: ReplayFidelity::Low,
            counter: 1,
            trigger_reason_codes: vec!["reason-a".into()],
        });
        let plan_b = build_replay_plan(BuildReplayPlanArgs {
            session_id: "sess-1".into(),
            head_experience_id: store.experience_store.head_id,
            head_record_digest: head_digest,
            target_kind: ReplayTargetKind::Micro,
            target_refs: vec![ucf_protocol::ucf::v1::Ref {
                id: "micro:b".into(),
            }],
            fidelity: ReplayFidelity::Low,
            counter: 2,
            trigger_reason_codes: vec!["reason-b".into()],
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
        assert_eq!(
            snapshot.pending_replay_ids,
            vec![plan_a.replay_id, plan_b.replay_id]
        );
        assert_eq!(snapshot.last_seal_digest, Some(decision_event.event_digest));

        let expected = format!(
            "head: id=7 digest={}\nruleset: current={} prev={}\ncbv: epoch=5 digest={}\npev_digest: {}\npending_replay_plans: 2\n- replay:sess-1:7:1\n- replay:sess-1:7:2\ncompleteness: {}\nlast_seal: {}\nrecovery: state=R0Captured checks=0/1 id=recovery:test\nunlock_permit: present=true digest={}\nunlock_hint: UNLOCKED_READONLY",
            encode(head_digest),
            encode(snapshot.ruleset_digest.unwrap()),
            encode(snapshot.prev_ruleset_digest.unwrap()),
            encode(cbv_digest),
            encode(snapshot.latest_pev_digest.unwrap()),
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
