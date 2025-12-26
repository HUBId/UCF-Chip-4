#![forbid(unsafe_code)]

use blake3::Hasher;
use hex::encode;
use limits::{StoreLimits, DEFAULT_LIMITS};
use prost::Message;
use std::str::FromStr;
use thiserror::Error;
use ucf_protocol::ucf::v1::{
    Digest32, MagnitudeClass, ReasonCodes, Ref, ReplayFidelity, ReplayInjectMode, ReplayPlan,
    ReplayTargetKind,
};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

const REPLAY_PLAN_DOMAIN: &[u8] = b"UCF:HASH:REPLAY_PLAN";
const MAX_TARGET_REFS: usize = DEFAULT_LIMITS.max_replay_target_refs;

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

impl FromStr for ConsistencyClass {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.eq_ignore_ascii_case("consistency_low") {
            return Ok(Self::Low);
        }

        if value.eq_ignore_ascii_case("consistency_med") {
            return Ok(Self::Med);
        }

        if value.eq_ignore_ascii_case("consistency_high") {
            return Ok(Self::High);
        }

        Err(())
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
    pub limits: StoreLimits,
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
        self.enforce_limits();
        Ok(())
    }

    pub fn list_pending(&self) -> Vec<ReplayPlan> {
        let mut pending: Vec<_> = self.plans.iter().filter(|p| !p.consumed).cloned().collect();
        pending.sort_by(|a, b| a.replay_id.cmp(&b.replay_id));
        pending.truncate(
            self.limits
                .max_pending_replay_plans
                .min(self.limits.max_replay_plans),
        );
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

    fn enforce_limits(&mut self) {
        let max_plans = self.limits.max_replay_plans;

        while self.plans.len() > max_plans {
            if let Some((index, _)) = self
                .plans
                .iter()
                .enumerate()
                .filter(|(_, plan)| plan.consumed)
                .min_by(|(_, a), (_, b)| a.replay_id.cmp(&b.replay_id))
            {
                self.plans.remove(index);
                continue;
            }

            if let Some((index, _)) = self
                .plans
                .iter()
                .enumerate()
                .min_by(|(_, a), (_, b)| a.replay_id.cmp(&b.replay_id))
            {
                self.plans.remove(index);
            } else {
                break;
            }
        }
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

pub struct BuildReplayPlanArgs {
    pub session_id: String,
    pub head_experience_id: u64,
    pub head_record_digest: [u8; 32],
    pub target_kind: ReplayTargetKind,
    pub target_refs: Vec<Ref>,
    pub fidelity: ReplayFidelity,
    pub counter: usize,
    pub trigger_reason_codes: Vec<String>,
    pub asset_manifest_ref: Option<Ref>,
}

pub fn build_replay_plan(args: BuildReplayPlanArgs) -> ReplayPlan {
    let mut plan = ReplayPlan {
        replay_id: format!(
            "replay:{}:{}:{}",
            args.session_id, args.head_experience_id, args.counter
        ),
        replay_digest: Vec::new(),
        session_id: args.session_id,
        head_record_digest: args.head_record_digest.to_vec(),
        target_kind: args.target_kind as i32,
        target_refs: args.target_refs,
        fidelity: args.fidelity as i32,
        inject_mode: ReplayInjectMode::InjectDmnSimulate as i32,
        max_steps_class: MagnitudeClass::Low as i32,
        max_budget_class: MagnitudeClass::Low as i32,
        stop_on_dlp_flag: true,
        proof_receipt_ref: None,
        consumed: false,
        trigger_reason_codes: args.trigger_reason_codes,
        asset_manifest_ref: args.asset_manifest_ref,
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
    Ref {
        id: encode(digest),
        digest: Some(digest.to_vec()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_plan_digest_sorts_components() {
        let plan_one = build_replay_plan(BuildReplayPlanArgs {
            session_id: "session".to_string(),
            head_experience_id: 42,
            head_record_digest: [1u8; 32],
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
            counter: 1,
            trigger_reason_codes: vec![
                ReasonCodes::GV_CONSISTENCY_MED_CLUSTER.to_string(),
                ReasonCodes::GV_CONSISTENCY_LOW.to_string(),
            ],
            asset_manifest_ref: None,
        });

        let plan_two = build_replay_plan(BuildReplayPlanArgs {
            session_id: "session".to_string(),
            head_experience_id: 42,
            head_record_digest: [1u8; 32],
            target_kind: ReplayTargetKind::Macro,
            target_refs: vec![
                Ref {
                    id: "target-a".to_string(),
                    digest: None,
                },
                Ref {
                    id: "target-b".to_string(),
                    digest: None,
                },
            ],
            fidelity: ReplayFidelity::Low,
            counter: 1,
            trigger_reason_codes: vec![
                ReasonCodes::GV_CONSISTENCY_LOW.to_string(),
                ReasonCodes::GV_CONSISTENCY_MED_CLUSTER.to_string(),
            ],
            asset_manifest_ref: None,
        });

        assert_eq!(plan_one.replay_digest, plan_two.replay_digest);
        assert_eq!(plan_one.target_refs[0].id, "target-a");
        assert_eq!(plan_one.trigger_reason_codes, plan_two.trigger_reason_codes);
    }

    #[test]
    fn evicts_consumed_plans_first() {
        let mut store = ReplayPlanStore::default();
        store.limits.max_replay_plans = 2;

        let mut plan_a = build_replay_plan(BuildReplayPlanArgs {
            session_id: "session".to_string(),
            head_experience_id: 1,
            head_record_digest: [1u8; 32],
            target_kind: ReplayTargetKind::Macro,
            target_refs: vec![Ref {
                id: "target-a".to_string(),
                digest: None,
            }],
            fidelity: ReplayFidelity::Low,
            counter: 0,
            trigger_reason_codes: vec![],
            asset_manifest_ref: None,
        });
        plan_a.replay_id = "a".to_string();
        plan_a.consumed = true;
        plan_a.replay_digest.clear();

        let mut plan_b = plan_a.clone();
        plan_b.replay_id = "b".to_string();
        plan_b.consumed = false;

        let mut plan_c = plan_a.clone();
        plan_c.replay_id = "c".to_string();
        plan_c.consumed = false;

        store.push(plan_a).unwrap();
        store.push(plan_b.clone()).unwrap();
        store.push(plan_c.clone()).unwrap();

        assert_eq!(store.plans.len(), 2);
        assert!(store.plans.iter().any(|p| p.replay_id == "b"));
        assert!(store.plans.iter().any(|p| p.replay_id == "c"));
    }

    #[test]
    fn evicts_oldest_replay_id_when_no_consumed() {
        let mut store = ReplayPlanStore::default();
        store.limits.max_replay_plans = 2;

        let mut base_plan = build_replay_plan(BuildReplayPlanArgs {
            session_id: "session".to_string(),
            head_experience_id: 1,
            head_record_digest: [1u8; 32],
            target_kind: ReplayTargetKind::Macro,
            target_refs: vec![Ref {
                id: "target-a".to_string(),
                digest: None,
            }],
            fidelity: ReplayFidelity::Low,
            counter: 0,
            trigger_reason_codes: vec![],
            asset_manifest_ref: None,
        });
        base_plan.replay_digest.clear();

        for id in ["b", "a", "c"] {
            let mut plan = base_plan.clone();
            plan.replay_id = id.to_string();
            store.push(plan).unwrap();
        }

        assert_eq!(store.plans.len(), 2);
        assert!(store.plans.iter().any(|p| p.replay_id == "b"));
        assert!(store.plans.iter().any(|p| p.replay_id == "c"));
        assert!(!store.plans.iter().any(|p| p.replay_id == "a"));
    }

    #[test]
    fn list_pending_respects_replay_limit() {
        let mut store = ReplayPlanStore::default();
        store.limits.max_replay_plans = 2;
        store.limits.max_pending_replay_plans = 3;

        let mut base_plan = build_replay_plan(BuildReplayPlanArgs {
            session_id: "session".to_string(),
            head_experience_id: 1,
            head_record_digest: [1u8; 32],
            target_kind: ReplayTargetKind::Macro,
            target_refs: vec![Ref {
                id: "target-a".to_string(),
                digest: None,
            }],
            fidelity: ReplayFidelity::Low,
            counter: 0,
            trigger_reason_codes: vec![],
            asset_manifest_ref: None,
        });
        base_plan.replay_digest.clear();

        for id in ["b", "a", "c"] {
            let mut plan = base_plan.clone();
            plan.replay_id = id.to_string();
            store.push(plan).unwrap();
        }

        let pending = store.list_pending();
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0].replay_id, "b");
        assert_eq!(pending[1].replay_id, "c");
    }

    #[test]
    fn eviction_prefers_consumed_before_pending_and_is_deterministic() {
        let mut store = ReplayPlanStore::default();
        store.limits.max_replay_plans = 2;

        let mut base_plan = build_replay_plan(BuildReplayPlanArgs {
            session_id: "session".to_string(),
            head_experience_id: 1,
            head_record_digest: [1u8; 32],
            target_kind: ReplayTargetKind::Macro,
            target_refs: vec![Ref {
                id: "target-a".to_string(),
                digest: None,
            }],
            fidelity: ReplayFidelity::Low,
            counter: 0,
            trigger_reason_codes: vec![],
            asset_manifest_ref: None,
        });
        base_plan.replay_digest.clear();

        let mut consumed_one = base_plan.clone();
        consumed_one.replay_id = "b".to_string();
        consumed_one.consumed = true;

        let mut consumed_two = base_plan.clone();
        consumed_two.replay_id = "a".to_string();
        consumed_two.consumed = true;

        let mut pending_one = base_plan.clone();
        pending_one.replay_id = "c".to_string();
        pending_one.consumed = false;

        let mut pending_two = base_plan.clone();
        pending_two.replay_id = "d".to_string();
        pending_two.consumed = false;

        store.push(consumed_one).unwrap();
        store.push(consumed_two).unwrap();
        store.push(pending_one.clone()).unwrap();
        store.push(pending_two.clone()).unwrap();

        let remaining_ids: Vec<_> = store.plans.iter().map(|p| p.replay_id.clone()).collect();
        assert_eq!(remaining_ids, vec!["c".to_string(), "d".to_string()]);
        assert!(store.plans.iter().all(|p| p.replay_digest.len() == 32));
    }
}
