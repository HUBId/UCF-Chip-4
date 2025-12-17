#![forbid(unsafe_code)]

use thiserror::Error;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub payload: Vec<u8>,
    pub signature: Option<Vec<u8>>,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthContext {
    pub subject: String,
    pub scopes: Vec<String>,
}

pub trait Authenticator {
    fn authenticate(&self, envelope: &Envelope) -> Result<AuthContext, AuthError>;
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("invalid envelope")]
    InvalidEnvelope,
    #[error("unauthorized: {0}")]
    Unauthorized(String),
}
