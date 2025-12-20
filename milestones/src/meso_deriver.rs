use std::collections::{BTreeMap, HashSet};

use prost::Message;
use ucf_protocol::ucf::v1::Digest32;

use crate::{
    new_domain_hasher, HormoneProfile, MesoMilestone, MicroMilestone, MicroMilestoneState,
    PriorityClass,
};

#[derive(Debug, Clone, Default)]
pub struct MesoDeriverConfig {
    pub meso_group_size: usize,
    pub require_same_session: bool,
    pub max_pending_meso: usize,
}

impl MesoDeriverConfig {
    pub fn beta() -> Self {
        Self {
            meso_group_size: 4,
            require_same_session: true,
            max_pending_meso: 1024,
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct MesoDeriver {
    config: MesoDeriverConfig,
    seen_meso_ids: HashSet<String>,
    seen_meso_digests: HashSet<[u8; 32]>,
}

impl MesoDeriver {
    pub fn new_beta() -> Self {
        Self {
            config: MesoDeriverConfig::beta(),
            ..Default::default()
        }
    }

    pub fn register_committed(&mut self, meso: &MesoMilestone) {
        if let Ok(digest) = meso.meso_digest.clone().try_into() {
            self.seen_meso_digests.insert(digest);
        }
        self.seen_meso_ids.insert(meso.meso_id.clone());
    }

    pub fn register_all(&mut self, mesos: &[MesoMilestone]) {
        for meso in mesos {
            self.register_committed(meso);
        }
    }

    pub fn derive_candidates(&self, micros: &[MicroMilestone]) -> Vec<MesoMilestone> {
        let mut by_session: BTreeMap<String, Vec<&MicroMilestone>> = BTreeMap::new();

        let mut micros_with_ranges: Vec<_> = micros
            .iter()
            .filter_map(|m| {
                m.experience_range
                    .as_ref()
                    .map(|r| (r.start_experience_id, m))
            })
            .collect();

        micros_with_ranges
            .sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.micro_id.cmp(&b.1.micro_id)));

        for (_, micro) in micros_with_ranges {
            let session_id = session_from_micro_id(&micro.micro_id);
            if self.config.require_same_session && session_id.is_empty() {
                continue;
            }

            by_session.entry(session_id).or_default().push(micro);
        }

        let mut candidates = Vec::new();

        for (session_id, micros) in by_session {
            for chunk in micros.chunks(self.config.meso_group_size) {
                if chunk.len() < self.config.meso_group_size {
                    break;
                }

                if let Some(meso) = derive_meso_for_chunk(&session_id, chunk) {
                    candidates.push(meso);
                }
            }
        }

        candidates.sort_by(|a, b| a.meso_id.cmp(&b.meso_id));

        let mut unseen = Vec::new();
        for candidate in candidates {
            let Ok(digest): Result<[u8; 32], _> = candidate.meso_digest.clone().try_into() else {
                continue;
            };

            if self.seen_meso_ids.contains(&candidate.meso_id)
                || self.seen_meso_digests.contains(&digest)
            {
                continue;
            }

            unseen.push(candidate);
            if unseen.len() >= self.config.max_pending_meso {
                break;
            }
        }

        unseen
    }
}

fn derive_meso_for_chunk(session_id: &str, chunk: &[&MicroMilestone]) -> Option<MesoMilestone> {
    let first_range = chunk.first()?.experience_range.as_ref()?;
    let last_range = chunk.last()?.experience_range.as_ref()?;

    let meso_id = format!(
        "meso:{session_id}:{}:{}",
        first_range.start_experience_id, last_range.end_experience_id
    );

    let micro_refs = chunk.iter().map(|m| hex::encode(&m.micro_digest)).collect();

    let stability_class = if chunk
        .iter()
        .all(|m| m.priority_class == PriorityClass::Low as i32)
    {
        "HIGH"
    } else {
        "MED"
    }
    .to_string();

    let hormone_profile = aggregate_hormones(chunk);
    let mut meso = MesoMilestone {
        meso_id,
        micro_refs,
        meso_digest: Vec::new(),
        stability_class,
        state: MicroMilestoneState::Sealed as i32,
        proof_receipt_ref: None,
        hormone_profile,
        theme_tags: vec!["theme:generic".to_string()],
    };

    let digest = compute_meso_digest(&meso);
    meso.meso_digest = digest.0.to_vec();

    Some(meso)
}

fn aggregate_hormones(chunk: &[&MicroMilestone]) -> Option<HormoneProfile> {
    let mut selected = chunk
        .iter()
        .filter_map(|m| m.hormone_profile.as_ref())
        .filter_map(|p| p.profile_digest.as_ref())
        .cloned()
        .collect::<Vec<_>>();

    if selected.is_empty() {
        return Some(HormoneProfile {
            profile_digest: Some([0u8; 32].to_vec()),
        });
    }

    selected.sort();
    selected.last().cloned().map(|digest| HormoneProfile {
        profile_digest: Some(digest),
    })
}

pub fn compute_meso_digest(meso: &MesoMilestone) -> Digest32 {
    let mut meso_clean = meso.clone();
    meso_clean.proof_receipt_ref = None;
    meso_clean.meso_digest.clear();
    let mut hasher = new_domain_hasher("UCF:HASH:MESO_MILESTONE");
    let mut buf = Vec::new();
    meso_clean
        .encode(&mut buf)
        .expect("meso milestone encoding");
    hasher.update(&buf);
    Digest32(hasher.finalize().into())
}

fn session_from_micro_id(micro_id: &str) -> String {
    micro_id
        .split(':')
        .nth(1)
        .map(str::to_string)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use rand::seq::SliceRandom;

    use super::*;
    use crate::{ExperienceRange, MicroMilestone};

    fn sample_micro(id_suffix: u64, priority: PriorityClass) -> MicroMilestone {
        let range = ExperienceRange {
            start_experience_id: id_suffix,
            end_experience_id: id_suffix + 9,
            head_record_digest: vec![1u8; 32],
        };

        MicroMilestone {
            micro_id: format!("micro:s:{id_suffix}:{}", id_suffix + 9),
            experience_range: Some(range),
            summary_digest: vec![2u8; 32],
            hormone_profile: Some(HormoneProfile {
                profile_digest: Some([id_suffix as u8; 32].to_vec()),
            }),
            priority_class: priority as i32,
            state: MicroMilestoneState::Sealed as i32,
            micro_digest: vec![(id_suffix % 255) as u8; 32],
            proof_receipt_ref: None,
        }
    }

    #[test]
    fn derives_deterministic_mesos() {
        let micros: Vec<_> = (0..4)
            .map(|i| sample_micro(i + 1, PriorityClass::Med))
            .collect();
        let deriver = MesoDeriver::new_beta();

        let first = deriver.derive_candidates(&micros);
        let second = deriver.derive_candidates(&micros);

        assert_eq!(first.len(), 1);
        assert_eq!(second, first);
    }

    #[test]
    fn ordering_ignores_input_shuffle() {
        let micros: Vec<_> = (0..4)
            .map(|i| sample_micro(i + 1, PriorityClass::Med))
            .collect();
        let mut shuffled = micros.clone();
        shuffled.shuffle(&mut rand::thread_rng());

        let deriver = MesoDeriver::new_beta();
        let ordered = deriver.derive_candidates(&micros);
        let from_shuffle = deriver.derive_candidates(&shuffled);

        assert_eq!(ordered, from_shuffle);
    }
}
