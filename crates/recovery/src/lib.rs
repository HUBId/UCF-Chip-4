#![forbid(unsafe_code)]

use std::collections::HashMap;

use thiserror::Error;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RecoveryCheck {
    IntegrityOk,
    ValidationPassed,
}

impl RecoveryCheck {
    pub fn all_checks() -> &'static [RecoveryCheck] {
        &[RecoveryCheck::IntegrityOk, RecoveryCheck::ValidationPassed]
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RecoveryState {
    R0Captured = 0,
    R1Triaged = 1,
    R2Validated = 2,
    R3Mitigated = 3,
    R4Remediated = 4,
    R5Approved = 5,
    R6Unlocked = 6,
    R7Closed = 7,
}

impl RecoveryState {
    pub fn next(self) -> Option<Self> {
        match self {
            RecoveryState::R0Captured => Some(RecoveryState::R1Triaged),
            RecoveryState::R1Triaged => Some(RecoveryState::R2Validated),
            RecoveryState::R2Validated => Some(RecoveryState::R3Mitigated),
            RecoveryState::R3Mitigated => Some(RecoveryState::R4Remediated),
            RecoveryState::R4Remediated => Some(RecoveryState::R5Approved),
            RecoveryState::R5Approved => Some(RecoveryState::R6Unlocked),
            RecoveryState::R6Unlocked => Some(RecoveryState::R7Closed),
            RecoveryState::R7Closed => None,
        }
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryCase {
    pub recovery_id: String,
    pub session_id: String,
    pub state: RecoveryState,
    pub required_checks: Vec<RecoveryCheck>,
    pub completed_checks: Vec<RecoveryCheck>,
    pub trigger_refs: Vec<String>,
    pub created_at_ms: Option<u64>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RecoveryStoreError {
    #[error("recovery case already exists")]
    Duplicate,
    #[error("recovery case not found")]
    NotFound,
    #[error("invalid initial state")]
    InvalidInitialState,
    #[error("invalid state transition")]
    InvalidStateTransition,
    #[error("invalid required checks")]
    InvalidRequiredChecks,
    #[error("completed checks not monotonic")]
    NonMonotonicChecks,
    #[error("recovery session mismatch")]
    SessionMismatch,
}

#[derive(Debug, Default, Clone)]
pub struct RecoveryStore {
    cases: HashMap<String, RecoveryCase>,
}

impl RecoveryStore {
    pub fn insert_new(&mut self, mut case: RecoveryCase) -> Result<(), RecoveryStoreError> {
        if self.cases.contains_key(&case.recovery_id) {
            return Err(RecoveryStoreError::Duplicate);
        }

        if !self.valid_required_checks(&case.required_checks) {
            return Err(RecoveryStoreError::InvalidRequiredChecks);
        }

        if case.state != RecoveryState::R0Captured {
            return Err(RecoveryStoreError::InvalidInitialState);
        }

        Self::sanitize_checks(&mut case);
        self.cases.insert(case.recovery_id.clone(), case);
        Ok(())
    }

    pub fn update(&mut self, mut case: RecoveryCase) -> Result<(), RecoveryStoreError> {
        let Some(existing) = self.cases.get(&case.recovery_id) else {
            return Err(RecoveryStoreError::NotFound);
        };

        if existing.session_id != case.session_id {
            return Err(RecoveryStoreError::SessionMismatch);
        }

        if existing.state.next() != Some(case.state) {
            return Err(RecoveryStoreError::InvalidStateTransition);
        }

        if case.required_checks != existing.required_checks {
            return Err(RecoveryStoreError::InvalidRequiredChecks);
        }

        if !self.valid_required_checks(&case.required_checks) {
            return Err(RecoveryStoreError::InvalidRequiredChecks);
        }

        if !Self::is_superset(&case.completed_checks, &existing.completed_checks) {
            return Err(RecoveryStoreError::NonMonotonicChecks);
        }

        if !Self::is_superset(&case.required_checks, &case.completed_checks) {
            return Err(RecoveryStoreError::InvalidRequiredChecks);
        }

        Self::sanitize_checks(&mut case);
        self.cases.insert(case.recovery_id.clone(), case);
        Ok(())
    }

    pub fn get(&self, recovery_id: &str) -> Option<RecoveryCase> {
        self.cases.get(recovery_id).cloned()
    }

    pub fn get_active_for_session(&self, session_id: &str) -> Option<RecoveryCase> {
        self.cases
            .values()
            .filter(|case| case.session_id == session_id && case.state != RecoveryState::R7Closed)
            .cloned()
            .max_by(RecoveryStore::case_ordering)
    }

    pub fn list_for_session(&self, session_id: &str) -> Vec<RecoveryCase> {
        let mut cases: Vec<_> = self
            .cases
            .values()
            .filter(|case| case.session_id == session_id)
            .cloned()
            .collect();

        cases.sort_by(RecoveryStore::case_ordering);
        cases
    }

    fn valid_required_checks(&self, checks: &[RecoveryCheck]) -> bool {
        checks
            .iter()
            .all(|c| RecoveryCheck::all_checks().contains(c))
    }

    fn sanitize_checks(case: &mut RecoveryCase) {
        case.required_checks.sort();
        case.required_checks.dedup();
        case.completed_checks.sort();
        case.completed_checks.dedup();
    }

    fn is_superset(full: &[RecoveryCheck], subset: &[RecoveryCheck]) -> bool {
        let mut required_set = full.to_vec();
        required_set.sort();
        required_set.dedup();

        subset.iter().all(|chk| required_set.contains(chk))
    }

    fn case_ordering(a: &RecoveryCase, b: &RecoveryCase) -> std::cmp::Ordering {
        let created_a = a.created_at_ms.unwrap_or_default();
        let created_b = b.created_at_ms.unwrap_or_default();

        created_a
            .cmp(&created_b)
            .then_with(|| a.recovery_id.cmp(&b.recovery_id))
            .then_with(|| a.state.cmp(&b.state))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_case(state: RecoveryState) -> RecoveryCase {
        RecoveryCase {
            recovery_id: "rec-1".to_string(),
            session_id: "session".to_string(),
            state,
            required_checks: vec![RecoveryCheck::IntegrityOk, RecoveryCheck::ValidationPassed],
            completed_checks: Vec::new(),
            trigger_refs: vec!["trigger".to_string()],
            created_at_ms: None,
        }
    }

    #[test]
    fn insert_requires_initial_state() {
        let mut store = RecoveryStore::default();
        let case = base_case(RecoveryState::R1Triaged);
        let err = store.insert_new(case).unwrap_err();
        assert_eq!(err, RecoveryStoreError::InvalidInitialState);
    }

    #[test]
    fn enforce_sequential_transition_and_monotonic_checks() {
        let mut store = RecoveryStore::default();
        let mut case = base_case(RecoveryState::R0Captured);
        store.insert_new(case.clone()).unwrap();

        case.state = RecoveryState::R2Validated;
        assert_eq!(
            store.update(case.clone()).unwrap_err(),
            RecoveryStoreError::InvalidStateTransition
        );

        case.state = RecoveryState::R1Triaged;
        case.completed_checks.push(RecoveryCheck::ValidationPassed);
        store.update(case.clone()).unwrap();

        let mut regress = case.clone();
        regress.state = RecoveryState::R2Validated;
        regress.completed_checks = vec![RecoveryCheck::IntegrityOk];
        assert_eq!(
            store.update(regress).unwrap_err(),
            RecoveryStoreError::NonMonotonicChecks
        );
    }
}
