use crate::state::StateRoot;

/// High-level state update submitted through the public API layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateUpdate {
    /// Logical schema identifier targeted by the update.
    pub schema: String,
    /// Raw key payload in schema-specific format.
    pub key: Vec<u8>,
    /// Presence or absence of a value represents insert/update vs. delete.
    pub value: Option<Vec<u8>>,
}

/// Public interface exposed by the Firewood storage backend to other subsystems.
pub trait StateApi {
    /// Error type surfaced through the API.
    type Error;
    /// Proof object returned when querying membership or non-membership.
    type Proof;

    /// Query the latest state for a schema/key pair.
    fn query(&self, schema: &str, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error>;

    /// Apply a batch of state updates and return the resulting root hash.
    fn apply_updates(&self, updates: Vec<StateUpdate>) -> Result<StateRoot, Self::Error>;

    /// Produce a proof of inclusion or exclusion for the supplied key.
    fn prove(&self, schema: &str, key: &[u8]) -> Result<Option<Self::Proof>, Self::Error>;
}
