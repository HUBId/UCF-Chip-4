#![forbid(unsafe_code)]

use blake3::Hasher;
use hex::encode;
use prost::Message;
use thiserror::Error;
use ucf_protocol::ucf::v1::{
    Digest32, MagnitudeClass, Ref, ReplayFidelity, ReplayInjectMode, ReplayPlan, ReplayTargetKind,
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
    signals.deny_count_last256 >= 20 || signals.integrity_degraded_present
}

pub fn build_replay_plan(
    session_id: &str,
    head_experience_id: u64,
    head_record_digest: [u8; 32],
    target_kind: ReplayTargetKind,
    target_refs: Vec<Ref>,
    fidelity: ReplayFidelity,
    counter: usize,
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
    };

    plan.replay_digest = compute_replay_plan_digest(&plan).0.to_vec();
    plan
}

pub fn compute_replay_plan_digest(plan: &ReplayPlan) -> Digest32 {
    let mut canonical = plan.clone();
    canonical.proof_receipt_ref = None;
    canonical.replay_digest.clear();

    let bytes = canonical.encode_to_vec();
    let mut hasher = Hasher::new();
    hasher.update(REPLAY_PLAN_DOMAIN);
    hasher.update(&bytes);
    Digest32(*hasher.finalize().as_bytes())
}

pub fn ref_from_digest(digest: [u8; 32]) -> Ref {
    Ref { id: encode(digest) }
}
