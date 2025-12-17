#![forbid(unsafe_code)]

use thiserror::Error;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CharacterBaselineVector {
    pub dimensions: Vec<String>,
}

pub trait BaselineCalculator {
    fn calculate(&self, subject: &str) -> Result<CharacterBaselineVector, BaselineError>;
}

#[derive(Debug, Error)]
pub enum BaselineError {
    #[error("calculation error: {0}")]
    Calculation(String),
}
