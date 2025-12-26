#![forbid(unsafe_code)]

use blake3::Hasher;
use limits::StoreLimits;
use prost::Message;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::convert::TryFrom;
use thiserror::Error;
pub use ucf_protocol::ucf::v1::{
    CharacterBaselineVector, MacroMilestone, MacroMilestoneState, MagnitudeClass, Ref,
    TraitDirection, TraitUpdate,
};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CbvDeriverConfig {
    pub max_trait_updates_per_macro: u32,
    pub tighten_only: bool,
    pub epoch_increment: u64,
}

impl Default for CbvDeriverConfig {
    fn default() -> Self {
        Self {
            max_trait_updates_per_macro: 32,
            tighten_only: true,
            epoch_increment: 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeriveOutcome {
    pub cbv: CharacterBaselineVector,
    pub applied_updates: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DeriveError {
    #[error("cbv epoch overflow")]
    EpochOverflow,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TraitField {
    Caution,
    NoveltyDampening,
    ApprovalStrictness,
    ExportStrictness,
    ChainConservatism,
    CooldownMultiplier,
}

/// Append-only CBV store.
#[derive(Debug, Clone)]
pub struct CbvStore {
    entries: Vec<CharacterBaselineVector>,
    limits: StoreLimits,
}

impl Default for CbvStore {
    fn default() -> Self {
        Self::with_limits(StoreLimits::default())
    }
}

impl CbvStore {
    pub fn with_limits(limits: StoreLimits) -> Self {
        Self {
            entries: Vec::new(),
            limits,
        }
    }

    pub fn push(&mut self, cbv: CharacterBaselineVector) -> Vec<CharacterBaselineVector> {
        let mut evicted = Vec::new();
        let limit = self.limits.max_cbvs;

        if limit == 0 {
            evicted.append(&mut self.entries);
            evicted.push(cbv);
            return evicted;
        }

        while self.entries.len() >= limit {
            evicted.push(self.entries.remove(0));
        }

        self.entries.push(cbv);
        evicted
    }

    pub fn latest(&self) -> Option<&CharacterBaselineVector> {
        self.entries.last()
    }

    /// Return a bounded list of the most recent CBVs in chronological order.
    pub fn list_latest(&self, limit: usize) -> Vec<CharacterBaselineVector> {
        let start = self.entries.len().saturating_sub(limit);
        self.entries[start..].to_vec()
    }

    pub fn latest_digest(&self) -> Option<[u8; 32]> {
        self.latest()
            .and_then(|cbv| cbv.cbv_digest.as_deref())
            .map(vec_to_digest)
    }

    pub fn latest_epoch_and_source(&self) -> Option<(u64, Option<[u8; 32]>)> {
        let latest = self.latest()?;
        let source = latest
            .source_milestone_refs
            .first()
            .and_then(|r| r.id.split(':').nth(1))
            .and_then(|hex| hex::decode(hex).ok())
            .and_then(|bytes| bytes.try_into().ok());

        Some((latest.cbv_epoch, source))
    }
}

pub fn get_latest_cbv_epoch_and_source(store: &CbvStore) -> Option<(u64, Option<[u8; 32]>)> {
    store.latest_epoch_and_source()
}

/// Compute the canonical CBV digest excluding proof references and signatures.
pub fn compute_cbv_digest(cbv: &CharacterBaselineVector) -> [u8; 32] {
    let mut canonical = cbv.clone();
    canonical.cbv_digest = None;
    canonical.proof_receipt_ref = None;
    canonical.pvgs_attestation_sig.clear();
    canonical.pvgs_attestation_key_id.clear();
    let bytes = canonical.encode_to_vec();

    let mut hasher = Hasher::new();
    hasher.update(b"UCF:HASH:CBV");
    hasher.update(&bytes);
    *hasher.finalize().as_bytes()
}

/// Compute a verified fields digest for CBV updates.
pub fn compute_cbv_verified_fields_digest(
    prev_cbv_digest: [u8; 32],
    macro_digest: [u8; 32],
    next_cbv_digest: [u8; 32],
    epoch: u64,
) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(b"UCF:CBV:VERIFIED_FIELDS");
    hasher.update(&prev_cbv_digest);
    hasher.update(&macro_digest);
    hasher.update(&next_cbv_digest);
    hasher.update(&epoch.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Deterministically derive the next CBV from the previous value and macro milestone.
pub fn derive_next_cbv(
    prev: Option<&CharacterBaselineVector>,
    macro_milestone: &MacroMilestone,
    config: &CbvDeriverConfig,
) -> Result<DeriveOutcome, DeriveError> {
    let prev_epoch = prev.map(|cbv| cbv.cbv_epoch).unwrap_or(0);
    let next_epoch = prev_epoch
        .checked_add(config.epoch_increment)
        .ok_or(DeriveError::EpochOverflow)?;

    let mut cbv = CharacterBaselineVector {
        cbv_epoch: next_epoch,
        baseline_caution_offset: prev.map(|c| c.baseline_caution_offset).unwrap_or(0),
        baseline_novelty_dampening_offset: prev
            .map(|c| c.baseline_novelty_dampening_offset)
            .unwrap_or(0),
        baseline_approval_strictness_offset: prev
            .map(|c| c.baseline_approval_strictness_offset)
            .unwrap_or(0),
        baseline_export_strictness_offset: prev
            .map(|c| c.baseline_export_strictness_offset)
            .unwrap_or(0),
        baseline_chain_conservatism_offset: prev
            .map(|c| c.baseline_chain_conservatism_offset)
            .unwrap_or(0),
        baseline_cooldown_multiplier_class: prev
            .map(|c| c.baseline_cooldown_multiplier_class)
            .unwrap_or(0),
        cbv_digest: None,
        source_milestone_refs: vec![macro_source_ref(macro_milestone)],
        source_event_refs: Vec::new(),
        proof_receipt_ref: None,
        pvgs_attestation_key_id: String::new(),
        pvgs_attestation_sig: Vec::new(),
    };

    let mut applied_updates = false;
    let trait_map = default_trait_map();
    let mut sorted_updates = macro_milestone.trait_updates.clone();
    sort_trait_updates(&mut sorted_updates);

    for update in sorted_updates
        .into_iter()
        .take(config.max_trait_updates_per_macro as usize)
    {
        if config.tighten_only
            && matches!(direction_of(&update), TraitDirection::DecreaseStrictness)
        {
            continue;
        }

        let Some(field) = trait_map.get(update.trait_name.as_str()) else {
            continue;
        };

        let magnitude = magnitude_value(&update);
        let direction = direction_of(&update);

        match field {
            TraitField::CooldownMultiplier => {
                let magnitude_class = magnitude as u32;
                let new_value = match direction {
                    TraitDirection::IncreaseStrictness => {
                        cbv.baseline_cooldown_multiplier_class.max(magnitude_class)
                    }
                    TraitDirection::DecreaseStrictness => cbv
                        .baseline_cooldown_multiplier_class
                        .saturating_sub(magnitude_class),
                };
                applied_updates |= new_value != cbv.baseline_cooldown_multiplier_class;
                cbv.baseline_cooldown_multiplier_class = new_value;
            }
            _ => {
                let delta = match direction {
                    TraitDirection::IncreaseStrictness => magnitude,
                    TraitDirection::DecreaseStrictness => -magnitude,
                };

                let target = match field {
                    TraitField::Caution => &mut cbv.baseline_caution_offset,
                    TraitField::NoveltyDampening => &mut cbv.baseline_novelty_dampening_offset,
                    TraitField::ApprovalStrictness => &mut cbv.baseline_approval_strictness_offset,
                    TraitField::ExportStrictness => &mut cbv.baseline_export_strictness_offset,
                    TraitField::ChainConservatism => &mut cbv.baseline_chain_conservatism_offset,
                    TraitField::CooldownMultiplier => unreachable!(),
                };

                let new_value = target.saturating_add(delta);
                applied_updates |= new_value != *target;
                *target = new_value;
            }
        }
    }

    let digest = compute_cbv_digest(&cbv);
    cbv.cbv_digest = Some(digest.to_vec());

    Ok(DeriveOutcome {
        cbv,
        applied_updates,
    })
}

fn default_trait_map() -> HashMap<String, TraitField> {
    HashMap::from([
        ("baseline_caution".to_string(), TraitField::Caution),
        (
            "novelty_dampening".to_string(),
            TraitField::NoveltyDampening,
        ),
        (
            "approval_strictness".to_string(),
            TraitField::ApprovalStrictness,
        ),
        (
            "export_strictness".to_string(),
            TraitField::ExportStrictness,
        ),
        (
            "chain_conservatism".to_string(),
            TraitField::ChainConservatism,
        ),
        (
            "cooldown_multiplier".to_string(),
            TraitField::CooldownMultiplier,
        ),
    ])
}

fn sort_trait_updates(updates: &mut [TraitUpdate]) {
    updates.sort_by(|a, b| match a.trait_name.cmp(&b.trait_name) {
        Ordering::Equal => magnitude_rank(b).cmp(&magnitude_rank(a)),
        other => other,
    });
}

fn magnitude_value(update: &TraitUpdate) -> i32 {
    match MagnitudeClass::try_from(update.magnitude_class).unwrap_or(MagnitudeClass::Low) {
        MagnitudeClass::Low => 1,
        MagnitudeClass::Med => 2,
        MagnitudeClass::High => 3,
    }
}

fn magnitude_rank(update: &TraitUpdate) -> i32 {
    match MagnitudeClass::try_from(update.magnitude_class).unwrap_or(MagnitudeClass::Low) {
        MagnitudeClass::Low => 0,
        MagnitudeClass::Med => 1,
        MagnitudeClass::High => 2,
    }
}

fn direction_of(update: &TraitUpdate) -> TraitDirection {
    TraitDirection::try_from(update.direction).unwrap_or(TraitDirection::IncreaseStrictness)
}

fn macro_source_ref(macro_milestone: &MacroMilestone) -> Ref {
    let digest_hex: String = macro_milestone
        .macro_digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    Ref {
        id: format!("{}:{}", macro_milestone.macro_id, digest_hex),
        digest: None,
    }
}

fn vec_to_digest(bytes: &[u8]) -> [u8; 32] {
    let mut digest = [0u8; 32];
    let len = bytes.len().min(32);
    digest[..len].copy_from_slice(&bytes[..len]);
    digest
}

/// Build a deterministic preimage for CBV attestations.
pub fn cbv_attestation_preimage(cbv: &CharacterBaselineVector) -> Vec<u8> {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(b"UCF:SIGN:CBV");
    preimage.extend_from_slice(&cbv.cbv_epoch.to_le_bytes());
    if let Some(digest) = &cbv.cbv_digest {
        preimage.extend_from_slice(digest);
    }

    preimage.extend_from_slice(&cbv.baseline_caution_offset.to_le_bytes());
    preimage.extend_from_slice(&cbv.baseline_novelty_dampening_offset.to_le_bytes());
    preimage.extend_from_slice(&cbv.baseline_approval_strictness_offset.to_le_bytes());
    preimage.extend_from_slice(&cbv.baseline_export_strictness_offset.to_le_bytes());
    preimage.extend_from_slice(&cbv.baseline_chain_conservatism_offset.to_le_bytes());
    preimage.extend_from_slice(&cbv.baseline_cooldown_multiplier_class.to_le_bytes());

    for r in &cbv.source_milestone_refs {
        preimage.extend_from_slice(r.id.as_bytes());
    }

    for r in &cbv.source_event_refs {
        preimage.extend_from_slice(r.id.as_bytes());
    }

    if let Some(proof) = &cbv.proof_receipt_ref {
        preimage.extend_from_slice(proof.id.as_bytes());
    }

    preimage
}

#[cfg(test)]
mod tests {
    use super::*;
    use ucf_protocol::ucf::v1::{MacroMilestoneState, MagnitudeClass, TraitDirection};

    fn sample_macro_with_updates(updates: Vec<TraitUpdate>) -> MacroMilestone {
        MacroMilestone {
            macro_id: "macro-1".to_string(),
            macro_digest: vec![0xAA; 32],
            state: MacroMilestoneState::Finalized as i32,
            trait_updates: updates,
            meso_refs: Vec::new(),
            consistency_class: "CONSISTENCY_HIGH".to_string(),
            identity_anchor_flag: true,
            proof_receipt_ref: None,
            consistency_digest: None,
            consistency_feedback_ref: None,
        }
    }

    fn update(name: &str, direction: TraitDirection, magnitude: MagnitudeClass) -> TraitUpdate {
        TraitUpdate {
            trait_name: name.to_string(),
            direction: direction as i32,
            magnitude_class: magnitude as i32,
        }
    }

    fn cbv_with_epoch(epoch: u64) -> CharacterBaselineVector {
        CharacterBaselineVector {
            cbv_epoch: epoch,
            baseline_caution_offset: 0,
            baseline_novelty_dampening_offset: 0,
            baseline_approval_strictness_offset: 0,
            baseline_export_strictness_offset: 0,
            baseline_chain_conservatism_offset: 0,
            baseline_cooldown_multiplier_class: 0,
            cbv_digest: Some([epoch as u8; 32].to_vec()),
            source_milestone_refs: Vec::new(),
            source_event_refs: Vec::new(),
            proof_receipt_ref: None,
            pvgs_attestation_key_id: String::new(),
            pvgs_attestation_sig: Vec::new(),
        }
    }

    #[test]
    fn derivation_is_deterministic() {
        let updates = vec![update(
            "baseline_caution",
            TraitDirection::IncreaseStrictness,
            MagnitudeClass::Med,
        )];
        let macro_milestone = sample_macro_with_updates(updates);
        let config = CbvDeriverConfig::default();

        let first = derive_next_cbv(None, &macro_milestone, &config).unwrap();
        let second = derive_next_cbv(None, &macro_milestone, &config).unwrap();

        assert_eq!(first.cbv.cbv_digest, second.cbv.cbv_digest);
    }

    #[test]
    fn trait_updates_sort_deterministically() {
        let unordered = vec![
            update(
                "baseline_caution",
                TraitDirection::IncreaseStrictness,
                MagnitudeClass::Low,
            ),
            update(
                "baseline_caution",
                TraitDirection::IncreaseStrictness,
                MagnitudeClass::High,
            ),
            update(
                "novelty_dampening",
                TraitDirection::IncreaseStrictness,
                MagnitudeClass::Med,
            ),
        ];

        let mut shuffled = unordered.clone();
        shuffled.reverse();

        let macro_a = sample_macro_with_updates(unordered);
        let macro_b = sample_macro_with_updates(shuffled);
        let config = CbvDeriverConfig::default();

        let derived_a = derive_next_cbv(None, &macro_a, &config).unwrap();
        let derived_b = derive_next_cbv(None, &macro_b, &config).unwrap();

        assert_eq!(derived_a.cbv.cbv_digest, derived_b.cbv.cbv_digest);
    }

    #[test]
    fn tighten_only_ignores_decreases() {
        let updates = vec![update(
            "baseline_caution",
            TraitDirection::DecreaseStrictness,
            MagnitudeClass::High,
        )];
        let macro_milestone = sample_macro_with_updates(updates);
        let config = CbvDeriverConfig::default();

        let derived = derive_next_cbv(None, &macro_milestone, &config).unwrap();

        assert_eq!(derived.cbv.baseline_caution_offset, 0);
        assert!(!derived.applied_updates);
    }

    #[test]
    fn cooldown_multiplier_uses_max() {
        let updates = vec![
            update(
                "cooldown_multiplier",
                TraitDirection::IncreaseStrictness,
                MagnitudeClass::Low,
            ),
            update(
                "cooldown_multiplier",
                TraitDirection::IncreaseStrictness,
                MagnitudeClass::High,
            ),
        ];
        let macro_milestone = sample_macro_with_updates(updates);
        let config = CbvDeriverConfig::default();

        let derived = derive_next_cbv(None, &macro_milestone, &config).unwrap();

        assert_eq!(derived.cbv.baseline_cooldown_multiplier_class, 3);
        assert!(derived.applied_updates);
    }

    #[test]
    fn cbv_store_evicts_fifo() {
        let mut store = CbvStore::with_limits(StoreLimits {
            max_cbvs: 2,
            ..StoreLimits::default()
        });

        let first = cbv_with_epoch(1);
        let second = cbv_with_epoch(2);
        let third = cbv_with_epoch(3);

        assert!(store.push(first.clone()).is_empty());
        assert!(store.push(second.clone()).is_empty());

        let evicted = store.push(third.clone());
        assert_eq!(evicted, vec![first]);
        assert_eq!(store.latest(), Some(&third));
        assert_eq!(store.list_latest(5), vec![second, third]);
    }

    #[test]
    fn cbv_store_with_zero_limit_always_evicts() {
        let mut store = CbvStore::with_limits(StoreLimits {
            max_cbvs: 0,
            ..StoreLimits::default()
        });

        let first = cbv_with_epoch(1);
        let second = cbv_with_epoch(2);

        let evicted_first = store.push(first.clone());
        assert_eq!(evicted_first, vec![first.clone()]);
        assert!(store.latest().is_none());

        let evicted_second = store.push(second.clone());
        assert_eq!(evicted_second, vec![second]);
        assert!(store.latest().is_none());
    }
}
