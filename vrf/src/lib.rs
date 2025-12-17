#![forbid(unsafe_code)]

use thiserror::Error;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VrfInput {
    pub message: Vec<u8>,
    pub epoch: u64,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VrfOutput {
    pub proof: Vec<u8>,
    pub public: Vec<u8>,
}

pub trait VrfProver {
    fn prove(&self, input: &VrfInput) -> Result<VrfOutput, VrfError>;
}

pub trait VrfVerifier {
    fn verify(&self, input: &VrfInput, output: &VrfOutput) -> Result<(), VrfError>;
}

#[derive(Debug, Error)]
pub enum VrfError {
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("verification failed")]
    VerificationFailed,
}
