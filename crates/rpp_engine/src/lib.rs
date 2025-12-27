#![forbid(unsafe_code)]

use blake3::Hasher;
use rpp_store::{DeltaOp, Error as RppStoreError, InMemoryStateStore};
use std::cmp::Ordering;
use std::sync::{Arc, Mutex};
use thiserror::Error;

#[cfg(feature = "rpp-firewood")]
use rpp_store::FirewoodStateStore;

const PAYLOAD_DOMAIN: &[u8] = b"UCF:RPP:PAYLOAD";
const DELTA_OPS_DOMAIN: &[u8] = b"UCF:RPP:DELTA_OPS";
const PAYLOAD_KEY_PREFIX: &[u8] = b"rpp:payload:";

#[derive(Debug, Error)]
pub enum RppEngineError {
    #[error(transparent)]
    Store(#[from] RppStoreError),
    #[error("rpp engine mutex poisoned")]
    Poisoned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RppAccumulatorStatus {
    pub acc_digest: [u8; 32],
}

impl Default for RppAccumulatorStatus {
    fn default() -> Self {
        Self {
            acc_digest: [0u8; 32],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RppHeadMeta {
    pub head_id: u64,
    pub head_record_digest: [u8; 32],
    pub prev_acc_digest: [u8; 32],
    pub acc_digest: [u8; 32],
    pub prev_root: [u8; 32],
    pub new_root: [u8; 32],
    pub payload_digest: [u8; 32],
    pub delta_ops_digest: [u8; 32],
}

#[derive(Debug, Clone, Default)]
pub struct RppHeadMetaStore {
    entries: Vec<RppHeadMeta>,
}

impl RppHeadMetaStore {
    pub fn push(&mut self, meta: RppHeadMeta) {
        self.entries.push(meta);
    }

    pub fn latest(&self) -> Option<&RppHeadMeta> {
        self.entries.last()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

#[derive(Debug)]
enum RppStateBackend {
    InMemory(InMemoryStateStore),
    #[cfg(feature = "rpp-firewood")]
    Firewood(FirewoodStateStore),
}

impl RppStateBackend {
    fn current_root(&self) -> [u8; 32] {
        match self {
            Self::InMemory(store) => store.current_root(),
            #[cfg(feature = "rpp-firewood")]
            Self::Firewood(store) => store.current_root(),
        }
    }

    fn apply_ops(&mut self, ops: &[DeltaOp]) -> Result<[u8; 32], RppStoreError> {
        match self {
            Self::InMemory(store) => store.apply_ops(ops),
            #[cfg(feature = "rpp-firewood")]
            Self::Firewood(store) => store.apply_ops(ops),
        }
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        match self {
            Self::InMemory(store) => store.get(key),
            #[cfg(feature = "rpp-firewood")]
            Self::Firewood(store) => store.get(key),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RppEngine {
    state: Arc<Mutex<RppStateBackend>>,
    acc_status: Arc<Mutex<RppAccumulatorStatus>>,
    head_meta_store: Arc<Mutex<RppHeadMetaStore>>,
}

impl Default for RppEngine {
    fn default() -> Self {
        Self::new_in_memory()
    }
}

impl RppEngine {
    #[must_use]
    pub fn new_in_memory() -> Self {
        Self {
            state: Arc::new(Mutex::new(RppStateBackend::InMemory(
                InMemoryStateStore::new(),
            ))),
            acc_status: Arc::new(Mutex::new(RppAccumulatorStatus::default())),
            head_meta_store: Arc::new(Mutex::new(RppHeadMetaStore::default())),
        }
    }

    #[cfg(feature = "rpp-firewood")]
    pub fn new_firewood<P: AsRef<std::path::Path>>(path: P) -> Result<Self, RppEngineError> {
        Ok(Self {
            state: Arc::new(Mutex::new(RppStateBackend::Firewood(
                FirewoodStateStore::open(path)?,
            ))),
            acc_status: Arc::new(Mutex::new(RppAccumulatorStatus::default())),
            head_meta_store: Arc::new(Mutex::new(RppHeadMetaStore::default())),
        })
    }

    pub fn current_root(&self) -> Result<[u8; 32], RppEngineError> {
        self.state
            .lock()
            .map_err(|_| RppEngineError::Poisoned)
            .map(|state| state.current_root())
    }

    pub fn apply_ops(&self, ops: &[DeltaOp]) -> Result<[u8; 32], RppEngineError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| RppEngineError::Poisoned)?;
        Ok(state.apply_ops(ops)?)
    }

    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, RppEngineError> {
        self.state
            .lock()
            .map_err(|_| RppEngineError::Poisoned)
            .map(|state| state.get(key))
    }

    pub fn acc_status(&self) -> Result<RppAccumulatorStatus, RppEngineError> {
        self.acc_status
            .lock()
            .map_err(|_| RppEngineError::Poisoned)
            .map(|status| *status)
    }

    pub fn set_acc_digest(&self, acc_digest: [u8; 32]) -> Result<(), RppEngineError> {
        let mut status = self
            .acc_status
            .lock()
            .map_err(|_| RppEngineError::Poisoned)?;
        status.acc_digest = acc_digest;
        Ok(())
    }

    pub fn record_head_meta(&self, meta: RppHeadMeta) -> Result<(), RppEngineError> {
        let mut store = self
            .head_meta_store
            .lock()
            .map_err(|_| RppEngineError::Poisoned)?;
        store.push(meta);
        Ok(())
    }

    pub fn head_meta_store(&self) -> Result<RppHeadMetaStore, RppEngineError> {
        self.head_meta_store
            .lock()
            .map_err(|_| RppEngineError::Poisoned)
            .map(|store| store.clone())
    }
}

#[must_use]
pub fn compute_payload_digest(payload: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(PAYLOAD_DOMAIN);
    hasher.update(payload);
    *hasher.finalize().as_bytes()
}

pub fn ordered_ops(ops: &[DeltaOp]) -> Result<Vec<DeltaOp>, RppStoreError> {
    let mut ordered = Vec::with_capacity(ops.len());
    for op in ops {
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

#[must_use]
pub fn compute_delta_ops_digest(ops: &[DeltaOp]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(DELTA_OPS_DOMAIN);
    hasher.update(&(ops.len() as u32).to_be_bytes());

    for op in ops {
        match op {
            DeltaOp::Put { key, value } => {
                hasher.update(&[1u8]);
                hasher.update(&(key.len() as u32).to_be_bytes());
                hasher.update(key);
                hasher.update(&(value.len() as u32).to_be_bytes());
                hasher.update(value);
            }
            DeltaOp::Del { key } => {
                hasher.update(&[0u8]);
                hasher.update(&(key.len() as u32).to_be_bytes());
                hasher.update(key);
            }
        }
    }

    *hasher.finalize().as_bytes()
}

#[must_use]
pub fn build_payload_ops(payload_digest: [u8; 32], payload_bytes: &[u8]) -> Vec<DeltaOp> {
    let mut key = Vec::with_capacity(PAYLOAD_KEY_PREFIX.len() + payload_digest.len());
    key.extend_from_slice(PAYLOAD_KEY_PREFIX);
    key.extend_from_slice(&payload_digest);

    vec![DeltaOp::Put {
        key,
        value: payload_bytes.to_vec(),
    }]
}
