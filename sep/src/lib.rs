#![forbid(unsafe_code)]

use thiserror::Error;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SepEvent {
    pub id: String,
    pub kind: String,
    pub payload: String,
}

pub trait SepEventLog {
    fn append(&self, event: SepEvent) -> Result<(), SepError>;
    fn events(&self) -> Result<Vec<SepEvent>, SepError>;
}

pub trait SepGraphIndex {
    fn connect(&self, parent: &SepEvent, child: &SepEvent) -> Result<(), SepError>;
}

#[derive(Debug, Error)]
pub enum SepError {
    #[error("io error: {0}")]
    Io(String),
    #[error("graph error: {0}")]
    Graph(String),
}
