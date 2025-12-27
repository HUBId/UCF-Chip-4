#[cfg(feature = "rpp-firewood")]
pub mod api;
#[cfg(feature = "rpp-firewood")]
pub mod column_family;
#[cfg(feature = "rpp-firewood")]
pub mod kv;
#[cfg(all(feature = "rpp-firewood", feature = "rpp-proof-envelope"))]
pub mod lifecycle;
#[cfg(all(feature = "rpp-firewood", feature = "rpp-proof-envelope"))]
pub mod pruning;
#[cfg(feature = "rpp-firewood")]
pub mod schema;
#[cfg(all(feature = "rpp-firewood", feature = "rpp-proof-envelope"))]
pub mod state;
#[cfg(feature = "rpp-firewood")]
pub mod tree;
#[cfg(feature = "rpp-firewood")]
pub mod wal;

#[cfg(all(feature = "rpp-firewood", feature = "rpp-proof-envelope"))]
pub use crate::pruning::SnapshotManifest;
#[cfg(all(feature = "rpp-firewood", feature = "rpp-proof-envelope"))]
pub use crate::state::{
    FirewoodState as Storage, StorageOptions, SyncPolicy, STORAGE_LAYOUT_VERSION,
};
#[cfg(all(feature = "rpp-firewood", feature = "rpp-proof-envelope"))]
pub use lifecycle::{FirewoodLifecycle, LifecycleError, LifecycleReceipt, LifecycleStatus};

#[cfg(all(test, feature = "rpp-firewood", feature = "rpp-proof-envelope"))]
mod tests {
    use std::env;

    use std::fs;
    use std::path::Path;

    use super::{kv::FirewoodKv, pruning::FirewoodPruner, tree::FirewoodTree};
    use rpp_pruning::{TaggedDigest, ENVELOPE_TAG, SNAPSHOT_STATE_TAG};
    use sha2::{Digest, Sha256};

    fn temp_dir(name: &str) -> String {
        let mut dir = env::temp_dir();
        dir.push(format!("firewood-{}", name));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir.to_string_lossy().into_owned()
    }

    #[test]
    fn kv_roundtrip_and_commit() {
        let dir = temp_dir("kv");
        let mut kv = FirewoodKv::open(&dir).expect("open kv");
        kv.put(b"alpha".to_vec(), b"one".to_vec());
        kv.put(b"beta".to_vec(), b"two".to_vec());
        let root = kv.commit().expect("commit");
        assert_eq!(kv.get(b"alpha"), Some(b"one".to_vec()));
        assert_eq!(kv.get(b"beta"), Some(b"two".to_vec()));
        assert_eq!(root.len(), 32);
    }

    #[test]
    fn tree_proof_verifies() {
        let mut tree = FirewoodTree::new();
        let root = tree.update(b"key", b"value".to_vec());
        let proof = tree.get_proof(b"key");
        assert!(super::tree::FirewoodTree::verify_proof(&root, &proof));
    }

    #[test]
    fn pruner_retains_recent_snapshots() {
        let mut pruner = FirewoodPruner::new(2);
        pruner.prune_block(1, [0u8; 32]);
        pruner.prune_block(2, [1u8; 32]);
        pruner.prune_block(3, [2u8; 32]);
        let proof = pruner.prune_block(4, [2u8; 32]);
        assert!(pruner.verify_with_config([2u8; 32], &proof));
    }

    #[test]
    fn pruning_proof_rejects_tampering() {
        let mut pruner = FirewoodPruner::new(4);
        let root = [1u8; 32];
        let proof = pruner.prune_block(1, root);
        assert!(pruner.verify_with_config(root, &proof));
        assert!(!pruner.verify_with_config([0u8; 32], &proof));

        let mut digest = *proof.snapshot().state_commitment().digest();
        digest[0] ^= 0xFF;
        let corrupted_snapshot = rpp_pruning::Snapshot::new(
            proof.snapshot().schema_version(),
            proof.snapshot().parameter_version(),
            proof.snapshot().block_height(),
            TaggedDigest::new(SNAPSHOT_STATE_TAG, digest),
        )
        .expect("tag preserved");
        let segments = proof.segments().to_vec();
        let commitment = proof.commitment().clone();
        let mut binding_bytes = *proof.binding_digest().digest();
        binding_bytes[0] ^= 0xFF;
        let corrupted = rpp_pruning::Envelope::new(
            proof.schema_version(),
            proof.parameter_version(),
            corrupted_snapshot,
            segments,
            commitment,
            TaggedDigest::new(ENVELOPE_TAG, binding_bytes),
        )
        .expect("tag preserved");

        assert!(!pruner.verify_with_config(root, &corrupted));
    }

    #[test]
    fn commit_rejects_manifest_mismatch() {
        let dir = temp_dir("manifest-mismatch");
        let state = super::state::FirewoodState::open(&dir).expect("open state");
        state.put(b"account".to_vec(), vec![1, 2, 3]);

        let proof_bytes = vec![7u8; 16];
        let checksum = {
            let mut hasher = Sha256::new();
            hasher.update(&proof_bytes);
            hex::encode(hasher.finalize())
        };

        let pruner = FirewoodPruner::new(2);
        let manifest = super::pruning::SnapshotManifest {
            layout_version: super::STORAGE_LAYOUT_VERSION,
            block_height: 1,
            state_root: hex::encode([9u8; 32]),
            schema_digest: hex::encode(pruner.schema_digest()),
            parameter_digest: hex::encode(pruner.parameter_digest()),
            schema_version: pruner.schema_version().get(),
            parameter_version: pruner.parameter_version().get(),
            proof_file: "00000000000000000001.bin".to_string(),
            proof_checksum: checksum,
        };

        let base = Path::new(&dir);
        let manifest_dir = base.join("cf_pruning_snapshots");
        let proof_dir = base.join("cf_pruning_proofs");
        fs::create_dir_all(&manifest_dir).expect("manifest dir");
        fs::create_dir_all(&proof_dir).expect("proof dir");
        fs::write(
            manifest_dir.join("00000000000000000001.json"),
            serde_json::to_vec_pretty(&manifest).expect("encode manifest"),
        )
        .expect("write manifest");
        fs::write(proof_dir.join(&manifest.proof_file), &proof_bytes).expect("write proof");

        let err = state
            .commit_block(1)
            .expect_err("commit should detect manifest drift");
        match err {
            super::state::StateError::PruningInvariantViolation { height, .. } => {
                assert_eq!(height, 1);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn state_commit_flow() {
        let dir = temp_dir("state");
        let state = super::state::FirewoodState::open(&dir).expect("open state");
        state.put(b"account".to_vec(), vec![1, 2, 3]);
        let (root, proof) = state.commit_block(1).expect("commit block");
        assert_eq!(root.len(), 32);
        assert!(FirewoodPruner::verify_pruned_state(root, proof.as_ref()));
    }
}
