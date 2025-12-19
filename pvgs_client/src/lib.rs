#![forbid(unsafe_code)]

use std::cell::RefCell;

use thiserror::Error;
use ucf_protocol::ucf::v1::ExperienceRecord;

/// Convenience alias for 32-byte digests exposed by PVGS queries.
pub type Digest32 = [u8; 32];

/// Minimal interface for reading digests from PVGS.
pub trait PvgsReader {
    fn get_latest_cbv_digest(&self) -> Option<Digest32>;
    fn get_latest_pev_digest(&self) -> Option<Digest32> {
        None
    }
    fn get_latest_ruleset_digest(&self) -> Option<Digest32> {
        None
    }
}

/// Optional PVGS writer hook for committing control frame evidence.
pub trait PvgsWriter {
    fn commit_control_frame_evidence(
        &mut self,
        session_id: &str,
        control_frame_digest: Digest32,
    ) -> Result<(), PvgsClientError>;

    fn commit_experience_record(
        &mut self,
        _record: &ExperienceRecord,
    ) -> Result<(), PvgsClientError> {
        Err(PvgsClientError::Commit(
            "experience commit unsupported".into(),
        ))
    }
}

#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum PvgsClientError {
    #[error("commit failed: {0}")]
    Commit(String),
}

/// Mock PVGS reader returning fixed digests for testing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MockPvgsReader {
    cbv_digest: Option<Digest32>,
    pev_digest: Option<Digest32>,
    ruleset_digest: Option<Digest32>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MockPvgsWriter {
    pub control_frame_commits: RefCell<Vec<(String, Digest32)>>,
    pub experience_records: RefCell<Vec<ExperienceRecord>>,
    pub fail_experience: RefCell<Option<PvgsClientError>>,
}

impl MockPvgsWriter {
    pub fn with_experience_error(err: PvgsClientError) -> Self {
        Self {
            control_frame_commits: RefCell::new(Vec::new()),
            experience_records: RefCell::new(Vec::new()),
            fail_experience: RefCell::new(Some(err)),
        }
    }
}

impl PvgsWriter for MockPvgsWriter {
    fn commit_control_frame_evidence(
        &mut self,
        session_id: &str,
        control_frame_digest: Digest32,
    ) -> Result<(), PvgsClientError> {
        self.control_frame_commits
            .borrow_mut()
            .push((session_id.to_string(), control_frame_digest));
        Ok(())
    }

    fn commit_experience_record(
        &mut self,
        record: &ExperienceRecord,
    ) -> Result<(), PvgsClientError> {
        if let Some(err) = self.fail_experience.borrow_mut().take() {
            return Err(err);
        }

        self.experience_records.borrow_mut().push(record.clone());
        Ok(())
    }
}

impl MockPvgsReader {
    pub fn new(
        cbv_digest: Option<Digest32>,
        pev_digest: Option<Digest32>,
        ruleset_digest: Option<Digest32>,
    ) -> Self {
        Self {
            cbv_digest,
            pev_digest,
            ruleset_digest,
        }
    }
}

impl Default for MockPvgsReader {
    fn default() -> Self {
        Self {
            cbv_digest: Some([0xCB; 32]),
            pev_digest: Some([0xCE; 32]),
            ruleset_digest: Some([0xAA; 32]),
        }
    }
}

impl PvgsReader for MockPvgsReader {
    fn get_latest_cbv_digest(&self) -> Option<Digest32> {
        self.cbv_digest
    }

    fn get_latest_pev_digest(&self) -> Option<Digest32> {
        self.pev_digest
    }

    fn get_latest_ruleset_digest(&self) -> Option<Digest32> {
        self.ruleset_digest
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_returns_defaults() {
        let reader = MockPvgsReader::default();

        assert_eq!(reader.get_latest_cbv_digest(), Some([0xCB; 32]));
        assert_eq!(reader.get_latest_pev_digest(), Some([0xCE; 32]));
        assert_eq!(reader.get_latest_ruleset_digest(), Some([0xAA; 32]));
    }

    #[test]
    fn mock_can_be_empty() {
        let reader = MockPvgsReader::new(None, None, None);

        assert_eq!(reader.get_latest_cbv_digest(), None);
        assert_eq!(reader.get_latest_pev_digest(), None);
        assert_eq!(reader.get_latest_ruleset_digest(), None);
    }
}
