#![forbid(unsafe_code)]

use blake3::Hasher;
use prost::Message;
use std::collections::HashMap;
use thiserror::Error;
use ucf_protocol::ucf::v1::{AssetDigest, AssetKind, AssetManifest};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Default)]
pub struct AssetManifestStore {
    manifests: Vec<AssetManifest>,
    by_digest: HashMap<[u8; 32], usize>,
}

impl AssetManifestStore {
    pub fn insert(&mut self, manifest: AssetManifest) -> Result<bool, AssetManifestStoreError> {
        let manifest_digest = validate_manifest(&manifest)?;

        if self.by_digest.contains_key(&manifest_digest) {
            return Ok(false);
        }

        let index = self.manifests.len();
        self.manifests.push(manifest);
        self.by_digest.insert(manifest_digest, index);
        Ok(true)
    }

    pub fn get(&self, digest: [u8; 32]) -> Option<&AssetManifest> {
        self.by_digest
            .get(&digest)
            .and_then(|index| self.manifests.get(*index))
    }

    pub fn latest(&self) -> Option<&AssetManifest> {
        self.manifests.last()
    }

    pub fn list(&self) -> &[AssetManifest] {
        &self.manifests
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AssetManifestStoreError {
    #[error("manifest digest missing or invalid")]
    InvalidManifestDigest,
    #[error("asset kind must be specified")]
    InvalidAssetKind,
    #[error("asset digest must be 32 bytes")]
    InvalidAssetDigest,
    #[error("asset version must be > 0")]
    InvalidAssetVersion,
}

pub fn compute_asset_manifest_digest(manifest: &AssetManifest) -> [u8; 32] {
    let mut canonical = manifest.clone();
    canonical.manifest_digest = vec![0u8; 32];
    let bytes = canonical.encode_to_vec();
    let mut hasher = Hasher::new();
    hasher.update(b"UCF:ASSET:MANIFEST");
    hasher.update(&bytes);
    *hasher.finalize().as_bytes()
}

pub fn validate_manifest(manifest: &AssetManifest) -> Result<[u8; 32], AssetManifestStoreError> {
    let manifest_digest = digest_from_bytes(&manifest.manifest_digest)
        .ok_or(AssetManifestStoreError::InvalidManifestDigest)?;

    for asset in &manifest.asset_digests {
        validate_asset_digest(asset)?;
    }

    Ok(manifest_digest)
}

fn validate_asset_digest(asset: &AssetDigest) -> Result<(), AssetManifestStoreError> {
    let kind = AssetKind::try_from(asset.kind).unwrap_or(AssetKind::Unspecified);
    if kind == AssetKind::Unspecified {
        return Err(AssetManifestStoreError::InvalidAssetKind);
    }
    if asset.digest.len() != 32 {
        return Err(AssetManifestStoreError::InvalidAssetDigest);
    }
    if asset.version == 0 {
        return Err(AssetManifestStoreError::InvalidAssetVersion);
    }

    Ok(())
}

fn digest_from_bytes(bytes: &[u8]) -> Option<[u8; 32]> {
    if bytes.len() != 32 {
        return None;
    }

    let mut digest = [0u8; 32];
    digest.copy_from_slice(bytes);
    Some(digest)
}
