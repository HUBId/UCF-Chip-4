#![forbid(unsafe_code)]

use blake3::Hasher;

const CONFIG_DIGEST_DOMAIN: &[u8] = b"UCF:HASH:MC_CONFIG";

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
