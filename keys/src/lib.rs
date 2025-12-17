#![forbid(unsafe_code)]

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::OsRng;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyEpoch {
    pub epoch_id: u64,
    pub key_id: String,
    pub public_key: [u8; 32],
}

/// In-memory keystore tracking the current signing key and historical epochs.
#[derive(Debug, Clone)]
pub struct KeyStore {
    pub current_epoch: u64,
    pub current_key_id: String,
    pub secret_key: SigningKey,
    pub epochs: Vec<KeyEpoch>,
}

impl KeyStore {
    /// Construct a new developer keystore with a freshly generated signing key.
    pub fn new_dev_keystore(epoch_id: u64) -> Self {
        let mut rng = OsRng;
        let secret_key = SigningKey::generate(&mut rng);
        let current_key_id = format!("epoch-{}", epoch_id);

        Self {
            current_epoch: epoch_id,
            current_key_id,
            secret_key,
            epochs: Vec::new(),
        }
    }

    /// Return the current epoch identifier.
    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    /// Return the identifier for the current signing key.
    pub fn current_key_id(&self) -> &str {
        &self.current_key_id
    }

    /// Get the public key for a given epoch if present.
    pub fn public_key_for_epoch(&self, epoch_id: u64) -> Option<[u8; 32]> {
        if epoch_id == self.current_epoch {
            Some(self.secret_key.verifying_key().to_bytes())
        } else {
            self.epochs
                .iter()
                .find(|epoch| epoch.epoch_id == epoch_id)
                .map(|epoch| epoch.public_key)
        }
    }

    /// Rotate to a new epoch, retaining the previous public key for verification.
    pub fn rotate(&mut self, new_epoch_id: u64) -> KeyEpoch {
        let current_public = self.secret_key.verifying_key().to_bytes();
        let archived = KeyEpoch {
            epoch_id: self.current_epoch,
            key_id: self.current_key_id.clone(),
            public_key: current_public,
        };
        self.epochs.push(archived);

        let mut rng = OsRng;
        let secret_key = SigningKey::generate(&mut rng);
        let current_key_id = format!("epoch-{}", new_epoch_id);

        self.current_epoch = new_epoch_id;
        self.current_key_id = current_key_id.clone();
        self.secret_key = secret_key;

        KeyEpoch {
            epoch_id: new_epoch_id,
            key_id: current_key_id,
            public_key: self.secret_key.verifying_key().to_bytes(),
        }
    }

    /// Expose the current signing key for attestation routines.
    pub fn signing_key(&self) -> &SigningKey {
        &self.secret_key
    }

    /// Expose the verifying key for the current epoch.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.secret_key.verifying_key()
    }
}
