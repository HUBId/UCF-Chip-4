#![deny(unsafe_code)]
#![doc = "Canonical pruning data structures shared across pruning-aware components."]

//! This crate defines canonical serialization formats for pruning snapshots and
//! associated commitments.  The goal is to ensure that pruning data exchanged
//! between nodes is stable across implementations, schema upgrades, and
//! serialization backends.  The types exposed here enforce the following
//! guarantees:
//!
//! * Schema and parameter versions are carried explicitly as big-endian byte
//!   sequences.  The conversion helpers guarantee that the canonical byte order
//!   is preserved independently from the platform endianness.
//! * Hashes are wrapped in [`TaggedDigest`] so that every digest is paired with a
//!   domain-separation tag.  When serialized, the tag is emitted before the raw
//!   digest bytes, making the prefixed representation unambiguous.
//! * Helper constructors perform validation so callers cannot accidentally mix
//!   and match domain tags.  This makes round-tripping through
//!   [`serde`]/[`bincode`] deterministic when combined with
//!   [`canonical_bincode_options`].
//! * Conversion helpers validate that schema and parameter digests encode the
//!   same versions as the structured documents, preventing stale or
//!   cross-wired pruning artifacts from entering gossip or storage.
//!
//! The domain tags are ASCII identifiers padded to sixteen bytes.  They are
//!   chosen to describe the semantic context of the digest:
//!
//! * [`SNAPSHOT_STATE_TAG`] – commitments to the prunable state itself.
//! * [`PROOF_SEGMENT_TAG`] – merkle segments that prove inclusion of snapshot
//!   chunks.
//! * [`COMMITMENT_TAG`] – aggregate commitments that bind a snapshot and its
//!   segments together.
//! * [`ENVELOPE_TAG`] – outer envelope bindings that authenticate the entire
//!   payload when transported over the network.
//!
//! Downstream crates should treat these definitions as the source of truth when
//! exchanging pruning data.  Doing so avoids divergence in serialization logic
//! and keeps pruning proofs fully deterministic.

use bincode::Options;
use core::fmt;
use serde::{Deserialize, Serialize};

/// Canonical configuration for `bincode` consumers of this crate.
///
/// The returned options enforce fixed-width integer encoding while retaining
/// the default behaviour of rejecting trailing bytes, which keeps the
/// serialized stream deterministic.
#[must_use]
pub fn canonical_bincode_options() -> impl Options {
    bincode::DefaultOptions::new().with_fixint_encoding()
}

/// Errors reported when validating tagged digests and structured documents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationError {
    /// Raised when a [`TaggedDigest`] does not carry the expected domain tag.
    UnexpectedDomainTag {
        /// Domain tag that was expected by the caller.
        expected: DomainTag,
        /// Domain tag actually stored in the digest.
        actual: DomainTag,
    },
    /// Raised when a proof segment range is malformed.
    InvalidSegmentRange {
        /// Inclusive lower bound of the range that failed validation.
        start: BlockHeight,
        /// Inclusive upper bound of the range that failed validation.
        end: BlockHeight,
    },
    /// Raised when a schema or parameter digest encodes an unexpected version.
    VersionDigestMismatch {
        /// Component whose digest prefix encoded the wrong version.
        component: &'static str,
        /// Version expected by the structured document.
        expected: u16,
        /// Version encoded inside the digest prefix.
        found: u16,
    },
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationError::UnexpectedDomainTag { expected, actual } => {
                write!(
                    f,
                    "domain tag mismatch (expected {:x?}, found {:x?})",
                    expected.as_bytes(),
                    actual.as_bytes()
                )
            }
            ValidationError::InvalidSegmentRange { start, end } => {
                write!(
                    f,
                    "invalid proof segment range: {} > {}",
                    start.as_u64(),
                    end.as_u64()
                )
            }
            ValidationError::VersionDigestMismatch {
                component,
                expected,
                found,
            } => {
                write!(
                    f,
                    "{component} digest encodes version {found}, expected {expected}"
                )
            }
        }
    }
}

/// Sixteen byte domain-separation tags used by the pruning structures.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct DomainTag {
    bytes: [u8; DOMAIN_TAG_LENGTH],
}

impl DomainTag {
    /// Creates a new domain tag from a fixed-length byte array.
    #[must_use]
    pub const fn new(bytes: [u8; DOMAIN_TAG_LENGTH]) -> Self {
        Self { bytes }
    }

    /// Returns the raw tag bytes.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; DOMAIN_TAG_LENGTH] {
        self.bytes
    }
}

/// Domain tag for [`Snapshot::state_commitment`].
pub const SNAPSHOT_STATE_TAG: DomainTag = DomainTag::new(*b"rpp:prune:state\0");
/// Domain tag for [`ProofSegment::segment_commitment`].
pub const PROOF_SEGMENT_TAG: DomainTag = DomainTag::new(*b"rpp:prune:proof\0");
/// Domain tag for [`Commitment::aggregate_commitment`].
pub const COMMITMENT_TAG: DomainTag = DomainTag::new(*b"rpp:prune:commit");
/// Domain tag for [`Envelope::binding_digest`].
pub const ENVELOPE_TAG: DomainTag = DomainTag::new(*b"rpp:prune:envlp\0");

/// Number of bytes used by every domain tag.
pub const DOMAIN_TAG_LENGTH: usize = 16;
/// Number of bytes used by hashing algorithms referenced by this module.
pub const DIGEST_LENGTH: usize = 32;

/// Digest that is prefixed with a [`DomainTag`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TaggedDigest {
    tag: DomainTag,
    digest: [u8; DIGEST_LENGTH],
}

impl TaggedDigest {
    /// Builds a new tagged digest with the provided domain tag and raw digest bytes.
    #[must_use]
    pub const fn new(tag: DomainTag, digest: [u8; DIGEST_LENGTH]) -> Self {
        Self { tag, digest }
    }

    /// Accessor for the domain tag.
    #[must_use]
    pub const fn tag(self) -> DomainTag {
        self.tag
    }

    /// Accessor for the raw digest bytes.
    #[must_use]
    pub const fn digest(&self) -> &[u8; DIGEST_LENGTH] {
        &self.digest
    }

    /// Returns the concatenation `tag || digest`, which is useful when hashing
    /// higher-level structures.
    #[must_use]
    pub fn prefixed_bytes(&self) -> [u8; DOMAIN_TAG_LENGTH + DIGEST_LENGTH] {
        let mut bytes = [0u8; DOMAIN_TAG_LENGTH + DIGEST_LENGTH];
        bytes[..DOMAIN_TAG_LENGTH].copy_from_slice(&self.tag.as_bytes());
        bytes[DOMAIN_TAG_LENGTH..].copy_from_slice(&self.digest);
        bytes
    }

    /// Ensures that this digest carries the expected domain tag.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError::UnexpectedDomainTag`] if the digest tag does not
    /// match `expected`.
    pub fn ensure_tag(&self, expected: DomainTag) -> Result<(), ValidationError> {
        if self.tag == expected {
            Ok(())
        } else {
            Err(ValidationError::UnexpectedDomainTag {
                expected,
                actual: self.tag,
            })
        }
    }
}

macro_rules! be_bytes_newtype {
    ($(#[$meta:meta])* $vis:vis struct $name:ident([$len:expr]); $int:ty) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        $vis struct $name {
            bytes: [u8; $len],
        }

        impl $name {
            /// Creates a new value from its native integer representation.
            pub const fn new(value: $int) -> Self {
                Self { bytes: value.to_be_bytes() }
            }

            /// Returns the native integer represented by this value.
            pub const fn get(self) -> $int {
                <$int>::from_be_bytes(self.bytes)
            }
        }

        impl From<$int> for $name {
            fn from(value: $int) -> Self {
                Self::new(value)
            }
        }

        impl From<$name> for $int {
            fn from(value: $name) -> Self {
                value.get()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.get())
            }
        }
    };
}

be_bytes_newtype!(/// Schema version identifier stored using two big-endian bytes.
pub struct SchemaVersion([2]); u16);
be_bytes_newtype!(/// Parameter version identifier stored using two big-endian bytes.
pub struct ParameterVersion([2]); u16);
be_bytes_newtype!(/// Inclusive block height stored using eight big-endian bytes.
pub struct BlockHeight([8]); u64);
be_bytes_newtype!(/// Segment index stored using four big-endian bytes.
pub struct SegmentIndex([4]); u32);

impl BlockHeight {
    /// Returns the block height as a `u64`.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.get()
    }
}

impl SegmentIndex {
    /// Returns the underlying index as a `u32`.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.get()
    }
}

impl SchemaVersion {
    /// Returns the canonical Firewood digest associated with this version.
    #[must_use]
    pub fn canonical_digest(self) -> [u8; DIGEST_LENGTH] {
        canonical_version_digest(self.get())
    }
}

impl ParameterVersion {
    /// Returns the canonical Firewood digest associated with this version.
    #[must_use]
    pub fn canonical_digest(self) -> [u8; DIGEST_LENGTH] {
        canonical_version_digest(self.get())
    }
}

/// Canonical pruning snapshot that binds schema/parameter versions to a state commitment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    schema_version: SchemaVersion,
    parameter_version: ParameterVersion,
    block_height: BlockHeight,
    state_commitment: TaggedDigest,
}

impl Snapshot {
    /// Constructs a snapshot after verifying that the commitment uses the
    /// [`SNAPSHOT_STATE_TAG`].
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError::UnexpectedDomainTag`] if the state commitment
    /// is tagged with a different domain.
    pub fn new(
        schema_version: SchemaVersion,
        parameter_version: ParameterVersion,
        block_height: BlockHeight,
        state_commitment: TaggedDigest,
    ) -> Result<Self, ValidationError> {
        state_commitment.ensure_tag(SNAPSHOT_STATE_TAG)?;
        Ok(Self {
            schema_version,
            parameter_version,
            block_height,
            state_commitment,
        })
    }

    /// Returns the schema version identifier.
    #[must_use]
    pub const fn schema_version(&self) -> SchemaVersion {
        self.schema_version
    }

    /// Returns the parameter version identifier.
    #[must_use]
    pub const fn parameter_version(&self) -> ParameterVersion {
        self.parameter_version
    }

    /// Returns the height of the block used to generate the snapshot.
    #[must_use]
    pub const fn block_height(&self) -> BlockHeight {
        self.block_height
    }

    /// Returns the state commitment.
    #[must_use]
    pub const fn state_commitment(&self) -> TaggedDigest {
        self.state_commitment
    }
}

/// A segment that proves inclusion of a pruning snapshot chunk.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofSegment {
    schema_version: SchemaVersion,
    parameter_version: ParameterVersion,
    segment_index: SegmentIndex,
    start_height: BlockHeight,
    end_height: BlockHeight,
    segment_commitment: TaggedDigest,
}

impl ProofSegment {
    /// Constructs a proof segment after validating the commitment tag and the
    /// height range ordering.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError::InvalidSegmentRange`] if `start_height` is
    /// greater than `end_height`, or [`ValidationError::UnexpectedDomainTag`]
    /// if the commitment tag does not match [`PROOF_SEGMENT_TAG`].
    pub fn new(
        schema_version: SchemaVersion,
        parameter_version: ParameterVersion,
        segment_index: SegmentIndex,
        start_height: BlockHeight,
        end_height: BlockHeight,
        segment_commitment: TaggedDigest,
    ) -> Result<Self, ValidationError> {
        if start_height.as_u64() > end_height.as_u64() {
            return Err(ValidationError::InvalidSegmentRange {
                start: start_height,
                end: end_height,
            });
        }
        segment_commitment.ensure_tag(PROOF_SEGMENT_TAG)?;
        Ok(Self {
            schema_version,
            parameter_version,
            segment_index,
            start_height,
            end_height,
            segment_commitment,
        })
    }

    /// Returns the schema version identifier.
    #[must_use]
    pub const fn schema_version(&self) -> SchemaVersion {
        self.schema_version
    }

    /// Returns the parameter version identifier.
    #[must_use]
    pub const fn parameter_version(&self) -> ParameterVersion {
        self.parameter_version
    }

    /// Returns the segment index.
    #[must_use]
    pub const fn segment_index(&self) -> SegmentIndex {
        self.segment_index
    }

    /// Returns the inclusive starting block height for the segment.
    #[must_use]
    pub const fn start_height(&self) -> BlockHeight {
        self.start_height
    }

    /// Returns the inclusive ending block height for the segment.
    #[must_use]
    pub const fn end_height(&self) -> BlockHeight {
        self.end_height
    }

    /// Returns the commitment that authenticates the segment contents.
    #[must_use]
    pub const fn segment_commitment(&self) -> TaggedDigest {
        self.segment_commitment
    }
}

/// Aggregate commitment that binds snapshots and segments.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::struct_field_names)]
pub struct Commitment {
    schema_version: SchemaVersion,
    parameter_version: ParameterVersion,
    aggregate_commitment: TaggedDigest,
}

impl Commitment {
    /// Builds a commitment validated against the [`COMMITMENT_TAG`].
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError::UnexpectedDomainTag`] if the commitment tag
    /// does not match [`COMMITMENT_TAG`].
    pub fn new(
        schema_version: SchemaVersion,
        parameter_version: ParameterVersion,
        aggregate_commitment: TaggedDigest,
    ) -> Result<Self, ValidationError> {
        aggregate_commitment.ensure_tag(COMMITMENT_TAG)?;
        Ok(Self {
            schema_version,
            parameter_version,
            aggregate_commitment,
        })
    }

    /// Returns the schema version identifier.
    #[must_use]
    pub const fn schema_version(&self) -> SchemaVersion {
        self.schema_version
    }

    /// Returns the parameter version identifier.
    #[must_use]
    pub const fn parameter_version(&self) -> ParameterVersion {
        self.parameter_version
    }

    /// Returns the aggregate commitment digest.
    #[must_use]
    pub const fn aggregate_commitment(&self) -> TaggedDigest {
        self.aggregate_commitment
    }
}

/// Outer envelope that wraps snapshots, proof segments, and the aggregate commitment.
#[cfg(feature = "rpp-proof-envelope")]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    schema_version: SchemaVersion,
    parameter_version: ParameterVersion,
    snapshot: Snapshot,
    segments: Vec<ProofSegment>,
    commitment: Commitment,
    binding_digest: TaggedDigest,
}

#[cfg(feature = "rpp-proof-envelope")]
impl Envelope {
    /// Builds an envelope validated against the [`ENVELOPE_TAG`].
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError::UnexpectedDomainTag`] if the binding digest
    /// does not match [`ENVELOPE_TAG`].
    pub fn new(
        schema_version: SchemaVersion,
        parameter_version: ParameterVersion,
        snapshot: Snapshot,
        segments: Vec<ProofSegment>,
        commitment: Commitment,
        binding_digest: TaggedDigest,
    ) -> Result<Self, ValidationError> {
        binding_digest.ensure_tag(ENVELOPE_TAG)?;
        Ok(Self {
            schema_version,
            parameter_version,
            snapshot,
            segments,
            commitment,
            binding_digest,
        })
    }

    /// Returns the schema version identifier.
    #[must_use]
    pub const fn schema_version(&self) -> SchemaVersion {
        self.schema_version
    }

    /// Returns the parameter version identifier.
    #[must_use]
    pub const fn parameter_version(&self) -> ParameterVersion {
        self.parameter_version
    }

    /// Returns the snapshot carried by this envelope.
    #[must_use]
    pub const fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }

    /// Returns the proof segments carried by this envelope.
    #[must_use]
    pub fn segments(&self) -> &[ProofSegment] {
        &self.segments
    }

    /// Returns the aggregate commitment for the envelope.
    #[must_use]
    pub const fn commitment(&self) -> &Commitment {
        &self.commitment
    }

    /// Returns the binding digest that authenticates the envelope.
    #[must_use]
    pub const fn binding_digest(&self) -> TaggedDigest {
        self.binding_digest
    }
}

fn canonical_version_digest(version: u16) -> [u8; DIGEST_LENGTH] {
    let mut digest = [0u8; DIGEST_LENGTH];
    digest[..2].copy_from_slice(&version.to_be_bytes());
    digest
}

#[cfg(feature = "rpp-proof-envelope")]
const fn version_from_digest(digest: &[u8; DIGEST_LENGTH]) -> u16 {
    u16::from_be_bytes([digest[0], digest[1]])
}

#[cfg(feature = "rpp-proof-envelope")]
const fn ensure_version_matches(
    component: &'static str,
    digest: &[u8; DIGEST_LENGTH],
    version: u16,
) -> Result<(), ValidationError> {
    let found = version_from_digest(digest);
    if found == version {
        Ok(())
    } else {
        Err(ValidationError::VersionDigestMismatch {
            component,
            expected: version,
            found,
        })
    }
}

/// Firewood-specific wrapper that pairs canonical envelopes with schema and parameter digests.
#[cfg(feature = "rpp-proof-envelope")]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewoodEnvelope {
    schema_digest: [u8; DIGEST_LENGTH],
    parameter_digest: [u8; DIGEST_LENGTH],
    schema_version: SchemaVersion,
    parameter_version: ParameterVersion,
    snapshot: Snapshot,
    #[serde(default)]
    segments: Vec<ProofSegment>,
    commitment: Commitment,
    binding_digest: TaggedDigest,
}

#[cfg(feature = "rpp-proof-envelope")]
impl FirewoodEnvelope {
    /// Builds a Firewood envelope after ensuring the digests encode the supplied versions.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError::VersionDigestMismatch`] if any digest prefix
    /// disagrees with the corresponding version values.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        schema_digest: [u8; DIGEST_LENGTH],
        parameter_digest: [u8; DIGEST_LENGTH],
        schema_version: SchemaVersion,
        parameter_version: ParameterVersion,
        snapshot: Snapshot,
        segments: Vec<ProofSegment>,
        commitment: Commitment,
        binding_digest: TaggedDigest,
    ) -> Result<Self, ValidationError> {
        ensure_version_matches(
            "envelope.schema_version",
            &schema_digest,
            schema_version.get(),
        )?;
        ensure_version_matches(
            "envelope.parameter_version",
            &parameter_digest,
            parameter_version.get(),
        )?;
        ensure_version_matches(
            "snapshot.schema_version",
            &schema_digest,
            snapshot.schema_version().get(),
        )?;
        ensure_version_matches(
            "snapshot.parameter_version",
            &parameter_digest,
            snapshot.parameter_version().get(),
        )?;
        ensure_version_matches(
            "commitment.schema_version",
            &schema_digest,
            commitment.schema_version().get(),
        )?;
        ensure_version_matches(
            "commitment.parameter_version",
            &parameter_digest,
            commitment.parameter_version().get(),
        )?;
        for segment in &segments {
            ensure_version_matches(
                "segment.schema_version",
                &schema_digest,
                segment.schema_version().get(),
            )?;
            ensure_version_matches(
                "segment.parameter_version",
                &parameter_digest,
                segment.parameter_version().get(),
            )?;
        }

        Ok(Self {
            schema_digest,
            parameter_digest,
            schema_version,
            parameter_version,
            snapshot,
            segments,
            commitment,
            binding_digest,
        })
    }

    /// Returns the schema digest carried by the Firewood envelope.
    #[must_use]
    pub const fn schema_digest(&self) -> &[u8; DIGEST_LENGTH] {
        &self.schema_digest
    }

    /// Returns the parameter digest carried by the Firewood envelope.
    #[must_use]
    pub const fn parameter_digest(&self) -> &[u8; DIGEST_LENGTH] {
        &self.parameter_digest
    }

    /// Converts this Firewood wrapper back into the canonical [`Envelope`].
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError::UnexpectedDomainTag`] if the binding digest
    /// is not tagged with [`ENVELOPE_TAG`].
    pub fn into_envelope(self) -> Result<Envelope, ValidationError> {
        Envelope::new(
            self.schema_version,
            self.parameter_version,
            self.snapshot,
            self.segments,
            self.commitment,
            self.binding_digest,
        )
    }
}

#[cfg(feature = "rpp-proof-envelope")]
#[allow(clippy::expect_used)]
impl From<&Envelope> for FirewoodEnvelope {
    fn from(envelope: &Envelope) -> Self {
        FirewoodEnvelope::new(
            envelope.schema_version().canonical_digest(),
            envelope.parameter_version().canonical_digest(),
            envelope.schema_version(),
            envelope.parameter_version(),
            envelope.snapshot().clone(),
            envelope.segments().to_vec(),
            envelope.commitment().clone(),
            envelope.binding_digest(),
        )
        .expect("envelope must be internally consistent")
    }
}

#[cfg(feature = "rpp-proof-envelope")]
impl TryFrom<FirewoodEnvelope> for Envelope {
    type Error = ValidationError;

    fn try_from(value: FirewoodEnvelope) -> Result<Self, Self::Error> {
        value.into_envelope()
    }
}

#[cfg(all(test, feature = "rpp-proof-envelope"))]
#[allow(clippy::expect_used, clippy::indexing_slicing, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_roundtrip_is_canonical() {
        let snapshot = Snapshot::new(
            SchemaVersion::new(1),
            ParameterVersion::new(2),
            BlockHeight::new(3),
            TaggedDigest::new(SNAPSHOT_STATE_TAG, [0x11; DIGEST_LENGTH]),
        )
        .unwrap();
        let bytes = canonical_bincode_options()
            .serialize(&snapshot)
            .expect("serialization must succeed");
        // Schema version (0,1), parameter version (0,2), block height (0..0,3), tag, digest.
        assert_eq!(bytes[0..2], [0, 1]);
        assert_eq!(bytes[2..4], [0, 2]);
        assert_eq!(bytes[4..12], [0, 0, 0, 0, 0, 0, 0, 3]);
        assert_eq!(bytes[12..28], SNAPSHOT_STATE_TAG.as_bytes());
        assert_eq!(bytes[28..], vec![0x11; DIGEST_LENGTH]);
    }

    #[test]
    fn envelope_rejects_wrong_tag() {
        let snapshot = Snapshot::new(
            SchemaVersion::new(1),
            ParameterVersion::new(2),
            BlockHeight::new(3),
            TaggedDigest::new(SNAPSHOT_STATE_TAG, [0x22; DIGEST_LENGTH]),
        )
        .unwrap();
        let commitment = Commitment::new(
            SchemaVersion::new(1),
            ParameterVersion::new(2),
            TaggedDigest::new(COMMITMENT_TAG, [0x33; DIGEST_LENGTH]),
        )
        .unwrap();
        let segments = vec![ProofSegment::new(
            SchemaVersion::new(1),
            ParameterVersion::new(2),
            SegmentIndex::new(0),
            BlockHeight::new(3),
            BlockHeight::new(4),
            TaggedDigest::new(PROOF_SEGMENT_TAG, [0x44; DIGEST_LENGTH]),
        )
        .unwrap()];

        let wrong_tag_result = Envelope::new(
            SchemaVersion::new(1),
            ParameterVersion::new(2),
            snapshot,
            segments,
            commitment,
            TaggedDigest::new(COMMITMENT_TAG, [0x55; DIGEST_LENGTH]),
        );
        assert!(matches!(
            wrong_tag_result,
            Err(ValidationError::UnexpectedDomainTag { .. })
        ));
    }

    #[test]
    fn firewood_envelope_roundtrip_serializes_identically() {
        let snapshot = Snapshot::new(
            SchemaVersion::new(1),
            ParameterVersion::new(2),
            BlockHeight::new(3),
            TaggedDigest::new(SNAPSHOT_STATE_TAG, [0x22; DIGEST_LENGTH]),
        )
        .unwrap();
        let segment = ProofSegment::new(
            SchemaVersion::new(1),
            ParameterVersion::new(2),
            SegmentIndex::new(0),
            BlockHeight::new(3),
            BlockHeight::new(3),
            TaggedDigest::new(PROOF_SEGMENT_TAG, [0x33; DIGEST_LENGTH]),
        )
        .unwrap();
        let commitment = Commitment::new(
            SchemaVersion::new(1),
            ParameterVersion::new(2),
            TaggedDigest::new(COMMITMENT_TAG, [0x44; DIGEST_LENGTH]),
        )
        .unwrap();
        let envelope = Envelope::new(
            SchemaVersion::new(1),
            ParameterVersion::new(2),
            snapshot,
            vec![segment],
            commitment,
            TaggedDigest::new(ENVELOPE_TAG, [0x55; DIGEST_LENGTH]),
        )
        .unwrap();

        let firewood = FirewoodEnvelope::from(&envelope);
        let encoded_a = canonical_bincode_options()
            .serialize(&firewood)
            .expect("serialize firewood");
        let encoded_b = canonical_bincode_options()
            .serialize(&firewood)
            .expect("serialize firewood");
        assert_eq!(encoded_a, encoded_b);

        let json_a = serde_json::to_string(&firewood).expect("json firewood");
        let json_b = serde_json::to_string(&firewood).expect("json firewood");
        assert_eq!(json_a, json_b);

        let decoded: FirewoodEnvelope = canonical_bincode_options()
            .deserialize(&encoded_a)
            .expect("decode firewood");
        let restored: Envelope = decoded.try_into().expect("firewood converts");
        assert_eq!(restored, envelope);
    }

    #[test]
    fn firewood_envelope_rejects_swapped_digests() {
        let snapshot = Snapshot::new(
            SchemaVersion::new(1),
            ParameterVersion::new(2),
            BlockHeight::new(3),
            TaggedDigest::new(SNAPSHOT_STATE_TAG, [0x22; DIGEST_LENGTH]),
        )
        .unwrap();
        let segment = ProofSegment::new(
            SchemaVersion::new(1),
            ParameterVersion::new(2),
            SegmentIndex::new(0),
            BlockHeight::new(3),
            BlockHeight::new(3),
            TaggedDigest::new(PROOF_SEGMENT_TAG, [0x33; DIGEST_LENGTH]),
        )
        .unwrap();
        let commitment = Commitment::new(
            SchemaVersion::new(1),
            ParameterVersion::new(2),
            TaggedDigest::new(COMMITMENT_TAG, [0x44; DIGEST_LENGTH]),
        )
        .unwrap();
        let envelope = Envelope::new(
            SchemaVersion::new(1),
            ParameterVersion::new(2),
            snapshot,
            vec![segment],
            commitment,
            TaggedDigest::new(ENVELOPE_TAG, [0x55; DIGEST_LENGTH]),
        )
        .unwrap();

        let schema_digest = envelope.schema_version().canonical_digest();
        let parameter_digest = envelope.parameter_version().canonical_digest();
        let swapped = FirewoodEnvelope::new(
            parameter_digest,
            schema_digest,
            envelope.schema_version(),
            envelope.parameter_version(),
            envelope.snapshot().clone(),
            envelope.segments().to_vec(),
            envelope.commitment().clone(),
            envelope.binding_digest(),
        );
        assert!(matches!(
            swapped,
            Err(ValidationError::VersionDigestMismatch { component, .. })
                if component.contains("schema")
        ));
    }
}
