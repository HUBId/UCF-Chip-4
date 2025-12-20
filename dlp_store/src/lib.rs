#![forbid(unsafe_code)]

use std::collections::HashMap;

use thiserror::Error;
use ucf_protocol::ucf::v1::DlpDecision;

#[derive(Debug, Clone, Default)]
pub struct DlpDecisionStore {
    pub map: HashMap<[u8; 32], DlpDecision>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DlpStoreError {
    #[error("missing dlp decision digest")]
    MissingDigest,
    #[error("invalid dlp decision digest length")]
    InvalidDigestLength,
}

impl DlpDecisionStore {
    pub fn insert(&mut self, mut decision: DlpDecision) -> Result<(), DlpStoreError> {
        let digest = extract_digest(&decision)?;
        decision.reason_codes.sort();
        self.map.insert(digest, decision);
        Ok(())
    }

    pub fn get(&self, digest: [u8; 32]) -> Option<&DlpDecision> {
        self.map.get(&digest)
    }
}

fn extract_digest(dlp: &DlpDecision) -> Result<[u8; 32], DlpStoreError> {
    let bytes = dlp
        .dlp_decision_digest
        .as_ref()
        .ok_or(DlpStoreError::MissingDigest)?;

    if bytes.len() != 32 {
        return Err(DlpStoreError::InvalidDigestLength);
    }

    let mut digest = [0u8; 32];
    digest.copy_from_slice(bytes);
    Ok(digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ucf_protocol::ucf::v1::DlpDecisionForm;

    fn decision(form: DlpDecisionForm) -> DlpDecision {
        DlpDecision {
            dlp_decision_digest: Some([7u8; 32].to_vec()),
            decision_form: form as i32,
            reason_codes: vec!["b".to_string(), "a".to_string()],
        }
    }

    #[test]
    fn rejects_missing_digest() {
        let mut store = DlpDecisionStore::default();
        let decision = DlpDecision {
            dlp_decision_digest: None,
            decision_form: DlpDecisionForm::Block as i32,
            reason_codes: Vec::new(),
        };

        let err = store.insert(decision).unwrap_err();
        assert_eq!(err, DlpStoreError::MissingDigest);
    }

    #[test]
    fn sorts_reason_codes_on_insert() {
        let mut store = DlpDecisionStore::default();
        let decision = decision(DlpDecisionForm::Allow);

        store.insert(decision).unwrap();
        let stored = store.get([7u8; 32]).unwrap();
        assert_eq!(stored.reason_codes, vec!["a".to_string(), "b".to_string()]);
    }
}
