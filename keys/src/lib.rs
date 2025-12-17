#![forbid(unsafe_code)]

use thiserror::Error;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyEpoch {
    pub epoch: u64,
    pub public_key: Vec<u8>,
}

pub trait KeyEpochProvider {
    fn current(&self) -> Result<KeyEpoch, KeyError>;
    fn rotate(&self) -> Result<KeyEpoch, KeyError>;
}

#[derive(Debug, Error)]
pub enum KeyError {
    #[error("rotation failed: {0}")]
    Rotation(String),
    #[error("uninitialized")]
    Uninitialized,
}
