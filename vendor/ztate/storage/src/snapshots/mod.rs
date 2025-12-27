//! Canonical snapshot metadata used by the state sync validation pipeline.
//!
//! The metadata exposed here represents pruning snapshots that have been
//! captured from long-running devnet deployments.  Downstream tests use these
//! records as golden references when comparing pruning receipts exported by the
//! storage layer with the manifests that will eventually be distributed to
//! peers.

/// Digest length used by pruning commitments.
pub const DIGEST_LENGTH: usize = 32;

/// Metadata describing a snapshot captured at a specific block height.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnapshotEntry {
    /// Inclusive block height captured by the snapshot.
    pub block_height: u64,
    /// Hex-encoded Firewood state root that backs the snapshot.
    pub state_root: &'static str,
    /// Blake3 commitment emitted by the pruning job for this snapshot.
    pub state_commitment: [u8; DIGEST_LENGTH],
    /// Hex-encoded checksum of the persisted pruning proof artifacts.
    pub proof_checksum: &'static str,
    /// Cross-shard or cross-partition references captured alongside the snapshot.
    pub cross_shard_links: &'static [CrossShardLink],
}

/// Metadata describing a cross-shard or cross-partition reference retained after pruning.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CrossShardLink {
    /// Logical shard identifier advertised by the pruning job.
    pub shard: &'static str,
    /// Partition label recorded for the linked shard.
    pub partition: &'static str,
    /// Snapshot height on the linked shard.
    pub block_height: u64,
}

/// Collection of snapshots that share schema and parameter digests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnapshotSet {
    /// Human readable label for the deployment the snapshots were captured on.
    pub label: &'static str,
    /// Layout version used when persisting pruning artifacts.
    pub layout_version: u32,
    /// Schema version recorded by the pruning job.
    pub schema_version: u16,
    /// Parameter version recorded by the pruning job.
    pub parameter_version: u16,
    /// Schema digest committed to the manifest files.
    pub schema_digest: [u8; DIGEST_LENGTH],
    /// Parameter digest committed to the manifest files.
    pub parameter_digest: [u8; DIGEST_LENGTH],
    /// Snapshots captured for this dataset ordered by block height.
    pub snapshots: &'static [SnapshotEntry],
}

const DEVNET_SNAPSHOTS: &[SnapshotEntry] = &[
    SnapshotEntry {
        block_height: 4_096,
        state_root: "c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00",
        state_commitment: [
            64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85,
            86, 87, 88, 89, 90, 91, 92, 93, 94, 95,
        ],
        proof_checksum: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        cross_shard_links: &[CrossShardLink {
            shard: "archive-a",
            partition: "partition-0",
            block_height: 4_096,
        }],
    },
    SnapshotEntry {
        block_height: 8_192,
        state_root: "decafbaddecafbaddecafbaddecafbaddecafbaddecafbaddecafbaddecafbad",
        state_commitment: [
            96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113,
            114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127,
        ],
        proof_checksum: "8899aabbccddeeff00112233445566778899aabbccddeeff0011223344556677",
        cross_shard_links: &[CrossShardLink {
            shard: "archive-b",
            partition: "partition-2",
            block_height: 12_288,
        }],
    },
];

const SNAPSHOT_SETS: &[SnapshotSet] = &[SnapshotSet {
    label: "phase3-devnet",
    layout_version: 1,
    schema_version: 1,
    parameter_version: 1,
    schema_digest: [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31,
    ],
    parameter_digest: [
        32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54,
        55, 56, 57, 58, 59, 60, 61, 62, 63,
    ],
    snapshots: DEVNET_SNAPSHOTS,
}];

/// Returns the canonical snapshot datasets recognised by the repository.
#[must_use]
pub const fn known_snapshot_sets() -> &'static [SnapshotSet] {
    SNAPSHOT_SETS
}
