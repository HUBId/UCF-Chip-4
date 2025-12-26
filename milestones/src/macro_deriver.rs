use std::collections::{BTreeMap, HashMap, HashSet};

use prost::Message;
use ucf_protocol::ucf::v1::{
    Digest32, MacroMilestone, MacroMilestoneState, MagnitudeClass, Ref, TraitDirection, TraitUpdate,
};

use crate::{new_domain_hasher, MesoMilestone, MicroMilestone, PriorityClass};

#[derive(Debug, Clone, Default)]
pub struct MacroDeriverConfig {
    pub macro_group_size: usize,
    pub max_trait_updates: usize,
}

impl MacroDeriverConfig {
    pub fn beta() -> Self {
        Self {
            macro_group_size: 2,
            max_trait_updates: 16,
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct MacroDeriver {
    config: MacroDeriverConfig,
    seen_macro_ids: HashSet<String>,
    seen_macro_digests: HashSet<[u8; 32]>,
}

impl MacroDeriver {
    pub fn new_beta() -> Self {
        Self {
            config: MacroDeriverConfig::beta(),
            ..Default::default()
        }
    }

    pub fn register_committed(&mut self, macro_milestone: &MacroMilestone) {
        if let Ok(digest) = macro_milestone.macro_digest.clone().try_into() {
            self.seen_macro_digests.insert(digest);
        }
        self.seen_macro_ids.insert(macro_milestone.macro_id.clone());
    }

    pub fn register_all(&mut self, macros: &[MacroMilestone]) {
        for macro_milestone in macros {
            self.register_committed(macro_milestone);
        }
    }

    pub fn derive_candidates(
        &self,
        mesos: &[MesoMilestone],
        micros: &[MicroMilestone],
    ) -> Vec<MacroMilestone> {
        let mut mesos_by_session: BTreeMap<String, Vec<&MesoMilestone>> = BTreeMap::new();
        for meso in mesos {
            let session_id = session_from_meso_id(&meso.meso_id);
            mesos_by_session.entry(session_id).or_default().push(meso);
        }

        let mut micro_by_digest: HashMap<String, &MicroMilestone> = HashMap::new();
        for micro in micros {
            micro_by_digest.insert(hex::encode(&micro.micro_digest), micro);
        }

        let mut candidates = Vec::new();
        for (session_id, mesos) in mesos_by_session {
            let mut ordered = mesos.clone();
            ordered.sort_by(|a, b| a.meso_id.cmp(&b.meso_id));

            for chunk in ordered.chunks(self.config.macro_group_size) {
                if chunk.len() < self.config.macro_group_size {
                    break;
                }

                if let Some(macro_milestone) =
                    propose_macro_for_chunk(&session_id, chunk, &micro_by_digest, &self.config)
                {
                    candidates.push(macro_milestone);
                }
            }
        }

        candidates.sort_by(|a, b| a.macro_id.cmp(&b.macro_id));

        candidates
            .into_iter()
            .filter(|candidate| {
                let Ok(digest): Result<[u8; 32], _> = candidate.macro_digest.clone().try_into()
                else {
                    return false;
                };

                if self.seen_macro_ids.contains(&candidate.macro_id)
                    || self.seen_macro_digests.contains(&digest)
                {
                    return false;
                }

                true
            })
            .collect()
    }
}

pub fn propose_macro_for_chunk(
    session_id: &str,
    chunk: &[&MesoMilestone],
    micro_by_digest: &HashMap<String, &MicroMilestone>,
    config: &MacroDeriverConfig,
) -> Option<MacroMilestone> {
    let first_id = chunk.first()?.meso_id.clone();
    let last_id = chunk.get(1)?.meso_id.clone();

    let meso_refs: Vec<Ref> = chunk
        .iter()
        .filter_map(|meso| {
            let digest: [u8; 32] = meso.meso_digest.clone().try_into().ok()?;
            Some(Ref {
                id: hex::encode(digest),
                digest: None,
            })
        })
        .collect();

    if meso_refs.len() != chunk.len() {
        return None;
    }

    let macro_id = format!("macro:{session_id}:{first_id}:{last_id}");

    let mut macro_milestone = MacroMilestone {
        macro_id,
        macro_digest: Vec::new(),
        state: MacroMilestoneState::Proposed as i32,
        trait_updates: trait_updates_for_chunk(chunk, micro_by_digest, config.max_trait_updates),
        meso_refs,
        consistency_class: "CONSISTENCY_DEFAULT".to_string(),
        identity_anchor_flag: false,
        proof_receipt_ref: None,
        consistency_digest: None,
        consistency_feedback_ref: None,
    };

    let digest = compute_macro_digest(&macro_milestone);
    macro_milestone.macro_digest = digest.0.to_vec();

    Some(macro_milestone)
}

fn trait_updates_for_chunk(
    chunk: &[&MesoMilestone],
    micro_by_digest: &HashMap<String, &MicroMilestone>,
    max_updates: usize,
) -> Vec<TraitUpdate> {
    let mut updates = Vec::new();

    if chunk
        .iter()
        .any(|meso| meso.stability_class.eq_ignore_ascii_case("low"))
    {
        updates.push(TraitUpdate {
            trait_name: "approval_strictness".to_string(),
            direction: TraitDirection::IncreaseStrictness as i32,
            magnitude_class: MagnitudeClass::Med as i32,
        });
    }

    let has_high_priority_micro = chunk.iter().any(|meso| {
        meso.micro_refs.iter().any(|digest| {
            micro_by_digest
                .get(digest)
                .is_some_and(|micro| micro.priority_class == PriorityClass::High as i32)
        })
    });

    if has_high_priority_micro {
        updates.push(TraitUpdate {
            trait_name: "baseline_caution".to_string(),
            direction: TraitDirection::IncreaseStrictness as i32,
            magnitude_class: MagnitudeClass::High as i32,
        });
    }

    if updates.is_empty() {
        updates.push(TraitUpdate {
            trait_name: "novelty_dampening".to_string(),
            direction: TraitDirection::IncreaseStrictness as i32,
            magnitude_class: MagnitudeClass::Low as i32,
        });
    }

    updates.sort_by(|a, b| {
        a.trait_name
            .cmp(&b.trait_name)
            .then_with(|| a.magnitude_class.cmp(&b.magnitude_class))
            .then_with(|| a.direction.cmp(&b.direction))
    });

    updates.truncate(max_updates);
    updates
}

fn session_from_meso_id(meso_id: &str) -> String {
    meso_id
        .split(':')
        .nth(1)
        .map(str::to_string)
        .unwrap_or_default()
}

pub fn compute_macro_digest(macro_milestone: &MacroMilestone) -> Digest32 {
    let mut canonical = macro_milestone.clone();
    canonical.state = MacroMilestoneState::Proposed as i32;
    canonical.identity_anchor_flag = false;
    canonical.macro_digest.clear();
    canonical.proof_receipt_ref = None;
    canonical.consistency_digest = None;
    canonical.consistency_feedback_ref = None;
    let mut hasher = new_domain_hasher("UCF:HASH:MACRO_MILESTONE");
    let mut buf = Vec::new();
    canonical
        .encode(&mut buf)
        .expect("macro milestone encoding");
    hasher.update(&buf);
    Digest32(*hasher.finalize().as_bytes())
}

pub fn compute_macro_finalization_digest(macro_milestone: &MacroMilestone) -> Digest32 {
    let mut finalized = macro_milestone.clone();
    finalized.state = MacroMilestoneState::Finalized as i32;
    finalized.identity_anchor_flag = true;
    compute_macro_digest(&finalized)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ExperienceRange, HormoneProfile, MicroMilestoneState};

    fn sample_micro(id: u8, priority: PriorityClass) -> MicroMilestone {
        let range = ExperienceRange {
            start_experience_id: id as u64,
            end_experience_id: id as u64,
            head_record_digest: vec![1u8; 32],
        };

        MicroMilestone {
            micro_id: format!("micro:s:{id}:{id}"),
            experience_range: Some(range),
            summary_digest: vec![2u8; 32],
            hormone_profile: Some(HormoneProfile {
                profile_digest: Some([id; 32].to_vec()),
            }),
            priority_class: priority as i32,
            state: MicroMilestoneState::Sealed as i32,
            micro_digest: vec![id; 32],
            proof_receipt_ref: None,
        }
    }

    fn sample_meso(id_suffix: u8, micro_refs: Vec<String>, stability_class: &str) -> MesoMilestone {
        let mut meso = MesoMilestone {
            meso_id: format!("meso:s:{id_suffix}:{}", id_suffix + 5),
            micro_refs,
            meso_digest: vec![id_suffix; 32],
            stability_class: stability_class.to_string(),
            state: MicroMilestoneState::Sealed as i32,
            proof_receipt_ref: None,
            hormone_profile: None,
            theme_tags: Vec::new(),
        };

        let digest = crate::compute_meso_digest(&meso);
        meso.meso_digest = digest.0.to_vec();
        meso
    }

    #[test]
    fn macro_derivation_is_deterministic() {
        let micro_a = sample_micro(1, PriorityClass::Med);
        let micro_b = sample_micro(2, PriorityClass::High);

        let meso_one = sample_meso(10, vec![hex::encode(&micro_a.micro_digest)], "MED");
        let meso_two = sample_meso(20, vec![hex::encode(&micro_b.micro_digest)], "MED");

        let deriver = MacroDeriver::new_beta();

        let expected_macro_id = format!("macro:s:{}:{}", meso_one.meso_id, meso_two.meso_id);

        let first = deriver.derive_candidates(
            &[meso_one.clone(), meso_two.clone()],
            &[micro_a.clone(), micro_b.clone()],
        );
        let second =
            deriver.derive_candidates(&[meso_two.clone(), meso_one.clone()], &[micro_a, micro_b]);

        assert_eq!(first.len(), 1);
        assert_eq!(first, second);
        assert_eq!(first[0].macro_id, expected_macro_id);
    }
}
