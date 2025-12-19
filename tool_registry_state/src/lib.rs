#![forbid(unsafe_code)]

use thiserror::Error;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Errors returned by the tool registry state store.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ToolRegistryError {
    #[error("tool registry digest already recorded")]
    DuplicateDigest,
}

/// Append-only tool registry digest tracker.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ToolRegistryState {
    pub current_digest: Option<[u8; 32]>,
    pub history: Vec<[u8; 32]>,
}

impl ToolRegistryState {
    /// Set the current registry digest and append it to history.
    pub fn set_current(&mut self, digest: [u8; 32]) -> Result<(), ToolRegistryError> {
        if self.history.contains(&digest) {
            return Err(ToolRegistryError::DuplicateDigest);
        }

        self.current_digest = Some(digest);
        self.history.push(digest);
        Ok(())
    }

    /// Return the latest registry digest if present.
    pub fn current(&self) -> Option<[u8; 32]> {
        self.current_digest
    }

    /// Return the complete append-only digest history.
    pub fn history(&self) -> &[[u8; 32]] {
        &self.history
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sets_and_tracks_history() {
        let mut state = ToolRegistryState::default();
        assert!(state.current().is_none());
        assert!(state.history().is_empty());

        let digest = [1u8; 32];
        state.set_current(digest).expect("first insert");
        assert_eq!(state.current(), Some(digest));
        assert_eq!(state.history(), &[digest]);
    }

    #[test]
    fn rejects_duplicate_digests() {
        let mut state = ToolRegistryState::default();
        let digest = [2u8; 32];
        state.set_current(digest).expect("insert");

        let err = state
            .set_current(digest)
            .expect_err("duplicate should fail");
        assert_eq!(err, ToolRegistryError::DuplicateDigest);
        assert_eq!(state.history(), &[digest]);
        assert_eq!(state.current(), Some(digest));
    }
}
