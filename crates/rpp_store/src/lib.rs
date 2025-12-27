#![forbid(unsafe_code)]

use std::cmp::Ordering;
use std::collections::BTreeMap;

use thiserror::Error;

pub const MAX_KEY_SIZE: usize = 1024;
pub const MAX_VALUE_SIZE: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeltaOp {
    Put { key: Vec<u8>, value: Vec<u8> },
    Del { key: Vec<u8> },
}

impl DeltaOp {
    #[must_use]
    pub fn key(&self) -> &[u8] {
        match self {
            Self::Put { key, .. } | Self::Del { key } => key,
        }
    }

    #[allow(clippy::missing_const_for_fn)]
    fn validate(&self) -> Result<(), Error> {
        match self {
            Self::Put { key, value } => {
                if key.len() > MAX_KEY_SIZE {
                    return Err(Error::KeyTooLarge {
                        len: key.len(),
                        max: MAX_KEY_SIZE,
                    });
                }
                if value.len() > MAX_VALUE_SIZE {
                    return Err(Error::ValueTooLarge {
                        len: value.len(),
                        max: MAX_VALUE_SIZE,
                    });
                }
            }
            Self::Del { key } => {
                if key.len() > MAX_KEY_SIZE {
                    return Err(Error::KeyTooLarge {
                        len: key.len(),
                        max: MAX_KEY_SIZE,
                    });
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("key size {len} exceeds max {max}")]
    KeyTooLarge { len: usize, max: usize },
    #[error("value size {len} exceeds max {max}")]
    ValueTooLarge { len: usize, max: usize },
    #[cfg(feature = "rpp-firewood")]
    #[error("firewood kv error: {0}")]
    FirewoodKv(#[from] storage_firewood::kv::KvError),
}

pub trait RppStateStore {
    fn current_root(&self) -> [u8; 32];

    /// Apply a batch of operations to the state store.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyTooLarge`] or [`Error::ValueTooLarge`] if an op exceeds
    /// the maximum key/value sizes. Implementations may return backend-specific
    /// errors as well.
    fn apply_ops(&mut self, ops: &[DeltaOp]) -> Result<[u8; 32], Error>;
    fn get(&self, key: &[u8]) -> Option<Vec<u8>>;
}

#[derive(Debug, Default)]
pub struct InMemoryStateStore {
    state: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl InMemoryStateStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl RppStateStore for InMemoryStateStore {
    fn current_root(&self) -> [u8; 32] {
        hash_state(&self.state)
    }

    fn apply_ops(&mut self, ops: &[DeltaOp]) -> Result<[u8; 32], Error> {
        let ordered = sort_ops(ops)?;
        for op in ordered {
            match op {
                DeltaOp::Put { key, value } => {
                    self.state.insert(key, value);
                }
                DeltaOp::Del { key } => {
                    self.state.remove(&key);
                }
            }
        }
        Ok(self.current_root())
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.state.get(key).cloned()
    }
}

#[cfg(feature = "rpp-firewood")]
#[derive(Debug)]
pub struct FirewoodStateStore {
    kv: storage_firewood::kv::FirewoodKv,
}

#[cfg(feature = "rpp-firewood")]
impl FirewoodStateStore {
    /// Open or create a Firewood-backed store at the given path.
    ///
    /// # Errors
    ///
    /// Returns [`Error::FirewoodKv`] if the underlying Firewood KV store fails
    /// to open.
    pub fn open<P: AsRef<std::path::Path>>(path: P) -> Result<Self, Error> {
        let kv = storage_firewood::kv::FirewoodKv::open(path)?;
        Ok(Self { kv })
    }

    fn trie_root(&self) -> [u8; 32] {
        firewood_triehash::trie_root::<keccak_hasher::KeccakHasher, _, _, _>(
            self.kv.scan_prefix(b""),
        )
    }
}

#[cfg(feature = "rpp-firewood")]
impl RppStateStore for FirewoodStateStore {
    fn current_root(&self) -> [u8; 32] {
        self.trie_root()
    }

    fn apply_ops(&mut self, ops: &[DeltaOp]) -> Result<[u8; 32], Error> {
        let ordered = sort_ops(ops)?;
        if ordered.is_empty() {
            return Ok(self.current_root());
        }

        for op in ordered {
            match op {
                DeltaOp::Put { key, value } => {
                    self.kv.put(key, value);
                }
                DeltaOp::Del { key } => {
                    self.kv.delete(&key);
                }
            }
        }

        self.kv.commit()?;
        Ok(self.current_root())
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.kv.get(key)
    }
}

fn sort_ops(ops: &[DeltaOp]) -> Result<Vec<DeltaOp>, Error> {
    let mut ordered = Vec::with_capacity(ops.len());
    for op in ops {
        op.validate()?;
        ordered.push(op.clone());
    }

    ordered.sort_by(|left, right| {
        let key_cmp = left.key().cmp(right.key());
        if key_cmp != Ordering::Equal {
            return key_cmp;
        }
        match (left, right) {
            (DeltaOp::Del { .. }, DeltaOp::Put { .. }) => Ordering::Less,
            (DeltaOp::Put { .. }, DeltaOp::Del { .. }) => Ordering::Greater,
            _ => Ordering::Equal,
        }
    });

    Ok(ordered)
}

fn hash_state(state: &BTreeMap<Vec<u8>, Vec<u8>>) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    for (key, value) in state {
        hasher.update(&(key.len() as u32).to_le_bytes());
        hasher.update(key);
        hasher.update(&(value.len() as u32).to_le_bytes());
        hasher.update(value);
    }
    hasher.finalize().into()
}
