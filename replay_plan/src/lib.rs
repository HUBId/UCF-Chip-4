#![forbid(unsafe_code)]

use blake3::Hasher;
use hex::encode;
use prost::Message;
use thiserror::Error;
use ucf_protocol::ucf::v1::{
    Digest32, MagnitudeClass, ReasonCodes, Ref, ReplayFidelity, ReplayInjectMode, ReplayPlan,
    ReplayTargetKind,
};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

const REPLAY_PLAN_DOMAIN: &[u8] = b"UCF:HASH:REPLAY_PLAN";
const MAX_TARGET_REFS: usize = 16;
const MAX_PENDING_PLANS: usize = 128;

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplaySignals {
    pub deny_count_last256: usize,
    pub integrity_degraded_present: bool,
    pub latest_consistency_class: Option<ConsistencyClass>,
    pub recent_consistency_counts: ConsistencyCounts,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsistencyClass {
    Low,
    Med,
    High,
}

impl ConsistencyClass {
    pub fn from_str(value: &str) -> Option<Self> {
        if value.eq_ignore_ascii_case("consistency_low") {
            return Some(Self::Low);
        }

        if value.eq_ignore_ascii_case("consistency_med") {
            return Some(Self::Med);
        }

        if value.eq_ignore_ascii_case("consistency_high") {
            return Some(Self::High);
        }

        None
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ConsistencyCounts {
    pub low_count: usize,
    pub med_count: usize,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ReplayPlanError {
    #[error("replay id missing")]
    MissingReplayId,
    #[error("replay digest missing")]
    MissingReplayDigest,
    #[error("target refs required")]
    MissingTargetRefs,
    #[error("too many target refs")]
    TooManyTargetRefs,
}

#[derive(Debug, Default, Clone)]
pub struct ReplayPlanStore {
    pub plans: Vec<ReplayPlan>,
}

impl ReplayPlanStore {
    pub fn push(&mut self, mut plan: ReplayPlan) -> Result<(), ReplayPlanError> {
        sort_plan_components(&mut plan);

        if plan.replay_id.is_empty() {
            return Err(ReplayPlanError::MissingReplayId);
        }

        if plan.target_refs.is_empty() {
            return Err(ReplayPlanError::MissingTargetRefs);
        }

        if plan.target_refs.len() > MAX_TARGET_REFS {
            return Err(ReplayPlanError::TooManyTargetRefs);
        }

        if plan.replay_digest.is_empty() {
            let digest = compute_replay_plan_digest(&plan);
            plan.replay_digest = digest.0.to_vec();
        }

        if plan.replay_digest.len() != 32 {
            return Err(ReplayPlanError::MissingReplayDigest);
        }

        self.plans.push(plan);
        Ok(())
    }

    pub fn list_pending(&self) -> Vec<ReplayPlan> {
        let mut pending: Vec<_> = self.plans.iter().filter(|p| !p.consumed).cloned().collect();
        pending.sort_by(|a, b| a.replay_id.cmp(&b.replay_id));
        pending.truncate(MAX_PENDING_PLANS);
        pending
    }

    pub fn mark_consumed(&mut self, replay_id: &str) -> Result<(), ReplayPlanError> {
        if let Some(plan) = self.plans.iter_mut().find(|p| p.replay_id == replay_id) {
            plan.consumed = true;
            return Ok(());
        }

        Err(ReplayPlanError::MissingReplayId)
    }

    pub fn latest(&self) -> Option<&ReplayPlan> {
        self.plans.last()
    }
}

pub fn should_generate_replay(_session_id: &str, signals: ReplaySignals) -> bool {
    !replay_trigger_reasons(&signals).is_empty()
}

pub fn replay_trigger_reasons(signals: &ReplaySignals) -> Vec<String> {
    let mut reason_codes = Vec::new();

    if signals.latest_consistency_class == Some(ConsistencyClass::Low)
        || signals.recent_consistency_counts.low_count > 0
    {
        reason_codes.push(ReasonCodes::GV_CONSISTENCY_LOW.to_string());
    }

    if signals.recent_consistency_counts.med_count >= 3 {
        reason_codes.push(ReasonCodes::GV_CONSISTENCY_MED_CLUSTER.to_string());
    }

    if signals.deny_count_last256 >= 20 {
        reason_codes.push(ReasonCodes::GV_REPLAY_DENY_CLUSTER.to_string());
    }

    if signals.integrity_degraded_present {
        reason_codes.push(ReasonCodes::RE_INTEGRITY_DEGRADED.to_string());
    }

    reason_codes.sort();
    reason_codes.dedup();
    reason_codes
}

pub fn build_replay_plan(
    session_id: &str,
    head_experience_id: u64,
    head_record_digest: [u8; 32],
    target_kind: ReplayTargetKind,
    target_refs: Vec<Ref>,
    fidelity: ReplayFidelity,
    counter: usize,
    trigger_reason_codes: Vec<String>,
) -> ReplayPlan {
    let mut plan = ReplayPlan {
        replay_id: format!("replay:{session_id}:{head_experience_id}:{counter}"),
        replay_digest: Vec::new(),
        session_id: session_id.to_string(),
        head_record_digest: head_record_digest.to_vec(),
        target_kind: target_kind as i32,
        target_refs,
        fidelity: fidelity as i32,
        inject_mode: ReplayInjectMode::InjectDmnSimulate as i32,
        max_steps_class: MagnitudeClass::Low as i32,
        max_budget_class: MagnitudeClass::Low as i32,
        stop_on_dlp_flag: true,
        proof_receipt_ref: None,
        consumed: false,
        trigger_reason_codes,
    };

    sort_plan_components(&mut plan);
    plan.replay_digest = compute_replay_plan_digest(&plan).0.to_vec();
    plan
}

pub fn compute_replay_plan_digest(plan: &ReplayPlan) -> Digest32 {
    let canonical = canonical_plan(plan);

    let bytes = canonical.encode_to_vec();
    let mut hasher = Hasher::new();
    hasher.update(REPLAY_PLAN_DOMAIN);
    hasher.update(&bytes);
    Digest32(*hasher.finalize().as_bytes())
}

fn canonical_plan(plan: &ReplayPlan) -> ReplayPlan {
    let mut canonical = plan.clone();
    canonical.proof_receipt_ref = None;
    canonical.replay_digest.clear();
    canonical.trigger_reason_codes.sort();
    canonical.trigger_reason_codes.dedup();
    canonical.target_refs.sort_by(|a, b| a.id.cmp(&b.id));
    canonical
}

fn sort_plan_components(plan: &mut ReplayPlan) {
    plan.trigger_reason_codes.sort();
    plan.trigger_reason_codes.dedup();
    plan.target_refs.sort_by(|a, b| a.id.cmp(&b.id));
}

pub fn ref_from_digest(digest: [u8; 32]) -> Ref {
    Ref { id: encode(digest) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_plan_digest_sorts_components() {
        let plan_one = build_replay_plan(
            "session",
            42,
            [1u8; 32],
            ReplayTargetKind::Macro,
            vec![
                Ref {
                    id: "target-b".to_string(),
                },
                Ref {
                    id: "target-a".to_string(),
                },
            ],
            ReplayFidelity::Low,
            1,
            vec![
                ReasonCodes::GV_CONSISTENCY_MED_CLUSTER.to_string(),
                ReasonCodes::GV_CONSISTENCY_LOW.to_string(),
            ],
        );

        let plan_two = build_replay_plan(
            "session",
            42,
            [1u8; 32],
            ReplayTargetKind::Macro,
            vec![
                Ref {
                    id: "target-a".to_string(),
                },
                Ref {
                    id: "target-b".to_string(),
                },
            ],
            ReplayFidelity::Low,
            1,
            vec![
                ReasonCodes::GV_CONSISTENCY_LOW.to_string(),
                ReasonCodes::GV_CONSISTENCY_MED_CLUSTER.to_string(),
            ],
        );

        assert_eq!(plan_one.replay_digest, plan_two.replay_digest);
        assert_eq!(plan_one.target_refs[0].id, "target-a");
        assert_eq!(plan_one.trigger_reason_codes, plan_two.trigger_reason_codes);
    }
}
