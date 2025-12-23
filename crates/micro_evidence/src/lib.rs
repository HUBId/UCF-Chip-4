#![forbid(unsafe_code)]

use blake3::Hasher;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub const MAX_MODULE_LEN: usize = 8;
const CONFIG_DIGEST_DOMAIN: &[u8] = b"UCF:HASH:MC_CONFIG";

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MicrocircuitConfigEvidence {
    pub module: String,
    pub config_version: u32,
    pub config_digest: [u8; 32],
    pub created_at_ms: u64,
    pub attested_by_key_id: Option<String>,
    pub signature: Option<Vec<u8>>,
}

impl MicrocircuitConfigEvidence {
    pub fn new(
        module: impl Into<String>,
        config_version: u32,
        canonical_config_bytes: &[u8],
        created_at_ms: u64,
    ) -> Self {
        let module = module.into();
        let config_digest = compute_config_digest(&module, config_version, canonical_config_bytes);
        Self {
            module,
            config_version,
            config_digest,
            created_at_ms,
            attested_by_key_id: None,
            signature: None,
        }
    }
}

pub fn compute_config_digest(
    module: &str,
    config_version: u32,
    canonical_config_bytes: &[u8],
) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(CONFIG_DIGEST_DOMAIN);
    hasher.update(module.as_bytes());
    hasher.update(&config_version.to_be_bytes());
    hasher.update(canonical_config_bytes);
    *hasher.finalize().as_bytes()
}

pub fn module_is_bounded(module: &str) -> bool {
    !module.is_empty() && module.len() <= MAX_MODULE_LEN
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_digest_is_deterministic() {
        let module = "LC";
        let bytes = br#"{"alpha":true,"beta":3}"#;
        let digest_a = compute_config_digest(module, 1, bytes);
        let digest_b = compute_config_digest(module, 1, bytes);

        assert_eq!(digest_a, digest_b);
    }
}
