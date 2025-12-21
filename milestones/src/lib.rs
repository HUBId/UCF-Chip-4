#![forbid(unsafe_code)]

use blake3::Hasher;
use prost::Message;
use thiserror::Error;
use ucf_protocol::ucf::v1::{Digest32, ExperienceRecord, RecordType, Ref};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub mod meso_deriver;
pub use meso_deriver::{compute_meso_digest, MesoDeriver, MesoDeriverConfig};
pub mod macro_deriver;
pub use macro_deriver::{
    compute_macro_digest, compute_macro_finalization_digest, propose_macro_for_chunk, MacroDeriver,
    MacroDeriverConfig,
};

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, PartialEq, Eq, Message)]
pub struct ExperienceRange {
    #[prost(uint64, tag = "1")]
    pub start_experience_id: u64,
    #[prost(uint64, tag = "2")]
    pub end_experience_id: u64,
    #[prost(bytes = "vec", tag = "3")]
    pub head_record_digest: Vec<u8>,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub enum MicroMilestoneState {
    Open = 0,
    Sealed = 1,
    Finalized = 2,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub enum PriorityClass {
    Low = 0,
    Med = 1,
    High = 2,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, PartialEq, Eq, Message)]
pub struct HormoneProfile {
    #[prost(bytes = "vec", optional, tag = "1")]
    pub profile_digest: Option<Vec<u8>>,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, PartialEq, Eq, Message)]
pub struct MicroMilestone {
    #[prost(string, tag = "1")]
    pub micro_id: String,
    #[prost(message, optional, tag = "2")]
    pub experience_range: Option<ExperienceRange>,
    #[prost(bytes = "vec", tag = "3")]
    pub summary_digest: Vec<u8>,
    #[prost(message, optional, tag = "4")]
    pub hormone_profile: Option<HormoneProfile>,
    #[prost(enumeration = "PriorityClass", tag = "5")]
    pub priority_class: i32,
    #[prost(enumeration = "MicroMilestoneState", tag = "6")]
    pub state: i32,
    #[prost(bytes = "vec", tag = "7")]
    pub micro_digest: Vec<u8>,
    #[prost(message, optional, tag = "8")]
    pub proof_receipt_ref: Option<Ref>,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, PartialEq, Eq, Message)]
pub struct MesoMilestone {
    #[prost(string, tag = "1")]
    pub meso_id: String,
    #[prost(string, repeated, tag = "2")]
    pub micro_refs: Vec<String>,
    #[prost(bytes = "vec", tag = "3")]
    pub meso_digest: Vec<u8>,
    #[prost(string, tag = "4")]
    pub stability_class: String,
    #[prost(enumeration = "MicroMilestoneState", tag = "5")]
    pub state: i32,
    #[prost(message, optional, tag = "6")]
    pub proof_receipt_ref: Option<Ref>,
    #[prost(message, optional, tag = "7")]
    pub hormone_profile: Option<HormoneProfile>,
    #[prost(string, repeated, tag = "8")]
    pub theme_tags: Vec<String>,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, PartialEq, Eq, Message)]
pub struct MacroMilestone {
    #[prost(string, tag = "1")]
    pub macro_id: String,
    #[prost(string, repeated, tag = "2")]
    pub meso_refs: Vec<String>,
    #[prost(bytes = "vec", tag = "3")]
    pub macro_digest: Vec<u8>,
    #[prost(string, tag = "4")]
    pub consistency_class: String,
    #[prost(enumeration = "MicroMilestoneState", tag = "5")]
    pub state: i32,
    #[prost(message, optional, tag = "6")]
    pub proof_receipt_ref: Option<Ref>,
}

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("digest missing")]
    MissingDigest,
    #[error("experience range invalid")]
    InvalidRange,
    #[error("invalid state")]
    InvalidState,
    #[error("proof receipt required")]
    MissingProofReceipt,
    #[error("consistency class too low")]
    LowConsistencyClass,
}

#[derive(Debug, Default, Clone)]
pub struct MicroMilestoneStore {
    items: Vec<MicroMilestone>,
}

impl MicroMilestoneStore {
    pub fn push(&mut self, micro: MicroMilestone) -> Result<(), ValidationError> {
        validate_micro(&micro)?;
        self.items.push(micro);
        Ok(())
    }

    pub fn latest(&self) -> Option<&MicroMilestone> {
        self.items.last()
    }

    pub fn get_by_id(&self, micro_id: &str) -> Option<&MicroMilestone> {
        self.items.iter().find(|m| m.micro_id == micro_id)
    }

    pub fn list(&self) -> &[MicroMilestone] {
        &self.items
    }
}

#[derive(Debug, Default, Clone)]
pub struct MesoMilestoneStore {
    items: Vec<MesoMilestone>,
}

impl MesoMilestoneStore {
    pub fn push(&mut self, meso: MesoMilestone) -> Result<(), ValidationError> {
        validate_meso(&meso)?;
        self.items.push(meso);
        Ok(())
    }

    pub fn latest(&self) -> Option<&MesoMilestone> {
        self.items.last()
    }

    pub fn list(&self) -> &[MesoMilestone] {
        &self.items
    }
}

#[derive(Debug, Default)]
pub struct MacroMilestoneStore {
    items: Vec<MacroMilestone>,
}

impl MacroMilestoneStore {
    pub fn push(&mut self, macro_milestone: MacroMilestone) -> Result<(), ValidationError> {
        validate_macro(&macro_milestone)?;
        self.items.push(macro_milestone);
        Ok(())
    }

    pub fn latest(&self) -> Option<&MacroMilestone> {
        self.items.last()
    }
}

fn validate_micro(micro: &MicroMilestone) -> Result<(), ValidationError> {
    if micro.micro_digest.len() != 32 {
        return Err(ValidationError::MissingDigest);
    }
    if micro.summary_digest.len() != 32 {
        return Err(ValidationError::MissingDigest);
    }
    let range = micro
        .experience_range
        .as_ref()
        .ok_or(ValidationError::InvalidRange)?;
    if range.start_experience_id > range.end_experience_id {
        return Err(ValidationError::InvalidRange);
    }

    match MicroMilestoneState::try_from(micro.state) {
        Ok(MicroMilestoneState::Open | MicroMilestoneState::Sealed) => {}
        Ok(MicroMilestoneState::Finalized) => {
            if micro.proof_receipt_ref.is_none() {
                return Err(ValidationError::MissingProofReceipt);
            }
        }
        _ => return Err(ValidationError::InvalidState),
    }

    Ok(())
}

fn validate_meso(meso: &MesoMilestone) -> Result<(), ValidationError> {
    if meso.meso_digest.len() != 32 {
        return Err(ValidationError::MissingDigest);
    }
    if meso.micro_refs.is_empty() {
        return Err(ValidationError::InvalidRange);
    }
    match MicroMilestoneState::try_from(meso.state) {
        Ok(MicroMilestoneState::Finalized) => {
            if meso.proof_receipt_ref.is_none() {
                return Err(ValidationError::MissingProofReceipt);
            }
        }
        Ok(MicroMilestoneState::Open | MicroMilestoneState::Sealed) => {}
        _ => return Err(ValidationError::InvalidState),
    }
    Ok(())
}

fn validate_macro(macro_milestone: &MacroMilestone) -> Result<(), ValidationError> {
    match MicroMilestoneState::try_from(macro_milestone.state) {
        Ok(MicroMilestoneState::Finalized) => {}
        _ => return Err(ValidationError::InvalidState),
    }
    if macro_milestone
        .consistency_class
        .eq_ignore_ascii_case("low")
    {
        return Err(ValidationError::LowConsistencyClass);
    }
    if macro_milestone.proof_receipt_ref.is_none() {
        return Err(ValidationError::MissingProofReceipt);
    }
    if macro_milestone.macro_digest.len() != 32 {
        return Err(ValidationError::MissingDigest);
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum DerivationError {
    #[error("start greater than end")]
    InvalidRange,
    #[error("missing experience entries")]
    MissingEntries,
    #[error("validation failure: {0}")]
    Validation(#[from] ValidationError),
}

pub fn derive_micro_from_experience_window(
    session_id: &str,
    start_experience_id: u64,
    end_experience_id: u64,
    head_record_digest: [u8; 32],
    records: &[(u64, [u8; 32], ExperienceRecord)],
) -> Result<MicroMilestone, DerivationError> {
    if start_experience_id > end_experience_id {
        return Err(DerivationError::InvalidRange);
    }

    let mut digest_pairs: Vec<_> = records
        .iter()
        .filter(|(id, _, _)| *id >= start_experience_id && *id <= end_experience_id)
        .cloned()
        .collect();

    if digest_pairs.is_empty() {
        return Err(DerivationError::MissingEntries);
    }

    digest_pairs.sort_by_key(|(id, _, _)| *id);

    let mut summary_hasher = new_domain_hasher("UCF:HASH:MICRO_SUMMARY");
    for (_, digest, _) in &digest_pairs {
        summary_hasher.update(digest);
    }
    let summary_digest = Digest32(summary_hasher.finalize().into());

    let hormone_profile = digest_pairs
        .iter()
        .rev()
        .find_map(|(_, _, record)| record.metabolic_frame.as_ref())
        .and_then(|m| m.profile_digest.as_ref())
        .map(|d| HormoneProfile {
            profile_digest: Some(d.clone()),
        });

    let priority_class = if digest_pairs
        .iter()
        .any(|(_, _, record)| record.record_type == RecordType::RtActionExec as i32)
    {
        PriorityClass::High
    } else {
        PriorityClass::Med
    } as i32;

    let experience_range = ExperienceRange {
        start_experience_id,
        end_experience_id,
        head_record_digest: head_record_digest.to_vec(),
    };

    let micro_id = format!("micro:{session_id}:{start_experience_id}:{end_experience_id}");

    let mut micro = MicroMilestone {
        micro_id,
        experience_range: Some(experience_range),
        summary_digest: summary_digest.0.to_vec(),
        hormone_profile,
        priority_class,
        state: MicroMilestoneState::Sealed as i32,
        micro_digest: Vec::new(),
        proof_receipt_ref: None,
    };

    let digest = compute_micro_digest(&micro);
    micro.micro_digest = digest.0.to_vec();

    validate_micro(&micro)?;

    Ok(micro)
}

fn compute_micro_digest(micro: &MicroMilestone) -> Digest32 {
    let mut micro_clean = micro.clone();
    micro_clean.proof_receipt_ref = None;
    let mut hasher = new_domain_hasher("UCF:HASH:MICRO_MILESTONE");
    let mut buf = Vec::new();
    micro_clean
        .encode(&mut buf)
        .expect("micro milestone encoding");
    hasher.update(&buf);
    Digest32(hasher.finalize().into())
}

pub(crate) fn new_domain_hasher(domain: &str) -> Hasher {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain.as_bytes());
    hasher
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_record(
        record_type: RecordType,
        profile_digest: Option<[u8; 32]>,
    ) -> ExperienceRecord {
        ExperienceRecord {
            record_type: record_type as i32,
            core_frame: None,
            metabolic_frame: profile_digest.map(|d| ucf_protocol::ucf::v1::MetabolicFrame {
                profile_digest: Some(d.to_vec()),
                outcome_refs: Vec::new(),
            }),
            governance_frame: None,
            core_frame_ref: None,
            metabolic_frame_ref: None,
            governance_frame_ref: None,
            dlp_refs: Vec::new(),
            finalization_header: None,
        }
    }

    #[test]
    fn micro_derivation_is_deterministic() {
        let head = [9u8; 32];
        let records = vec![
            (1, [1u8; 32], sample_record(RecordType::RtOutput, None)),
            (2, [2u8; 32], sample_record(RecordType::RtActionExec, None)),
            (
                3,
                [3u8; 32],
                sample_record(RecordType::RtOutput, Some([8u8; 32])),
            ),
        ];

        let a = derive_micro_from_experience_window("s", 1, 3, head, &records).unwrap();
        let b = derive_micro_from_experience_window("s", 1, 3, head, &records).unwrap();

        assert_eq!(a.micro_id, b.micro_id);
        assert_eq!(a.micro_digest, b.micro_digest);
        assert_eq!(a.summary_digest, b.summary_digest);
        assert_eq!(a.priority_class, PriorityClass::High as i32);
    }

    #[test]
    fn micro_store_rejects_invalid_range() {
        let head = [0u8; 32];
        let records = vec![(1, [1u8; 32], sample_record(RecordType::RtOutput, None))];
        let result = derive_micro_from_experience_window("s", 2, 1, head, &records);
        assert!(matches!(result, Err(DerivationError::InvalidRange)));
    }

    #[test]
    fn macro_store_requires_high_consistency() {
        let macro_milestone = MacroMilestone {
            macro_id: "macro".into(),
            meso_refs: vec!["m1".into()],
            macro_digest: vec![1u8; 32],
            consistency_class: "LOW".into(),
            state: MicroMilestoneState::Finalized as i32,
            proof_receipt_ref: Some(Ref::default()),
        };
        let mut store = MacroMilestoneStore::default();
        let err = store.push(macro_milestone).unwrap_err();
        assert!(matches!(err, ValidationError::LowConsistencyClass));
    }
}
