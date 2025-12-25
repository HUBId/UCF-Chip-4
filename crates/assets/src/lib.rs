#![forbid(unsafe_code)]

use blake3::Hasher;
use prost::Message;
use std::collections::HashMap;
use thiserror::Error;
use ucf_protocol::ucf::v1::{AssetBundle, AssetChunk, AssetDigest, AssetKind, AssetManifest};

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
    let bytes = canonical_manifest_bytes(manifest);
    let mut hasher = Hasher::new();
    hasher.update(b"UCF:ASSET:MANIFEST");
    hasher.update(&bytes);
    *hasher.finalize().as_bytes()
}

pub fn compute_asset_chunk_digest(payload: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(b"UCF:ASSET:CHUNK");
    hasher.update(payload);
    *hasher.finalize().as_bytes()
}

pub fn compute_asset_bundle_digest(
    manifest: &AssetManifest,
    chunks: &[AssetChunk],
) -> Option<[u8; 32]> {
    let mut ordered: Vec<([u8; 32], u32, [u8; 32])> = Vec::with_capacity(chunks.len());
    for chunk in chunks {
        let asset_digest = digest_from_bytes(&chunk.asset_digest)?;
        let chunk_digest = digest_from_bytes(&chunk.chunk_digest)?;
        ordered.push((asset_digest, chunk.chunk_index, chunk_digest));
    }
    ordered.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

    let mut hasher = Hasher::new();
    hasher.update(b"UCF:ASSET:BUNDLE");
    hasher.update(&canonical_manifest_bytes(manifest));
    for (_, _, chunk_digest) in ordered {
        hasher.update(&chunk_digest);
    }
    Some(*hasher.finalize().as_bytes())
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

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct AssetBundleStoreConfig {
    pub max_bundles: usize,
    pub max_chunks_per_asset: usize,
}

impl Default for AssetBundleStoreConfig {
    fn default() -> Self {
        Self {
            max_bundles: 100,
            max_chunks_per_asset: 2048,
        }
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct AssetBundleStore {
    bundles: Vec<AssetBundle>,
    by_digest: HashMap<[u8; 32], usize>,
    chunks_by_asset_digest: HashMap<[u8; 32], Vec<AssetChunk>>,
    config: AssetBundleStoreConfig,
}

impl Default for AssetBundleStore {
    fn default() -> Self {
        Self::with_config(AssetBundleStoreConfig::default())
    }
}

impl AssetBundleStore {
    pub fn with_config(config: AssetBundleStoreConfig) -> Self {
        Self {
            bundles: Vec::new(),
            by_digest: HashMap::new(),
            chunks_by_asset_digest: HashMap::new(),
            config,
        }
    }

    pub fn insert(&mut self, bundle: AssetBundle) -> Result<bool, AssetBundleStoreError> {
        let bundle_digest = digest_from_bytes(&bundle.bundle_digest)
            .ok_or(AssetBundleStoreError::InvalidBundleDigest)?;

        if self.by_digest.contains_key(&bundle_digest) {
            return Ok(false);
        }

        if self.bundles.len() >= self.config.max_bundles {
            return Err(AssetBundleStoreError::TooManyBundles);
        }

        let mut incoming: HashMap<[u8; 32], Vec<AssetChunk>> = HashMap::new();
        for chunk in &bundle.chunks {
            let asset_digest = digest_from_bytes(&chunk.asset_digest)
                .ok_or(AssetBundleStoreError::InvalidAssetDigest)?;
            incoming
                .entry(asset_digest)
                .or_default()
                .push(chunk.clone());
        }

        for (asset_digest, chunks) in &incoming {
            let existing_count = self
                .chunks_by_asset_digest
                .get(asset_digest)
                .map_or(0, |stored| stored.len());
            if existing_count + chunks.len() > self.config.max_chunks_per_asset {
                return Err(AssetBundleStoreError::TooManyChunks);
            }
        }

        let index = self.bundles.len();
        self.bundles.push(bundle);
        self.by_digest.insert(bundle_digest, index);

        for (asset_digest, mut chunks) in incoming {
            let entry = self.chunks_by_asset_digest.entry(asset_digest).or_default();
            entry.append(&mut chunks);
            entry.sort_by_key(|chunk| chunk.chunk_index);
        }

        Ok(true)
    }

    pub fn get(&self, digest: [u8; 32]) -> Option<&AssetBundle> {
        self.by_digest
            .get(&digest)
            .and_then(|index| self.bundles.get(*index))
    }

    pub fn latest(&self) -> Option<&AssetBundle> {
        self.bundles.last()
    }

    pub fn list(&self) -> &[AssetBundle] {
        &self.bundles
    }

    pub fn chunks_for_asset(&self, digest: [u8; 32]) -> Option<&[AssetChunk]> {
        self.chunks_by_asset_digest.get(&digest).map(Vec::as_slice)
    }

    pub fn max_bundles(&self) -> usize {
        self.config.max_bundles
    }

    pub fn max_chunks_per_asset(&self) -> usize {
        self.config.max_chunks_per_asset
    }

    pub fn total_chunks(&self) -> usize {
        self.chunks_by_asset_digest
            .values()
            .map(|chunks| chunks.len())
            .sum()
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AssetBundleStoreError {
    #[error("bundle digest missing or invalid")]
    InvalidBundleDigest,
    #[error("asset digest missing or invalid")]
    InvalidAssetDigest,
    #[error("bundle storage limit exceeded")]
    TooManyBundles,
    #[error("asset chunk storage limit exceeded")]
    TooManyChunks,
}

fn canonical_manifest_bytes(manifest: &AssetManifest) -> Vec<u8> {
    let mut canonical = manifest.clone();
    canonical.manifest_digest = vec![0u8; 32];
    canonical.encode_to_vec()
}

fn digest_from_bytes(bytes: &[u8]) -> Option<[u8; 32]> {
    if bytes.len() != 32 {
        return None;
    }

    let mut digest = [0u8; 32];
    digest.copy_from_slice(bytes);
    Some(digest)
}
