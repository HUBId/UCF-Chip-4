// Copyright (C) 2023, Ava Labs, Inc. All rights reserved.
// See the file LICENSE.md for licensing terms.

#![expect(
    clippy::match_same_arms,
    reason = "Found 1 occurrences after enabling the lint."
)]
#![expect(
    clippy::missing_panics_doc,
    reason = "Found 2 occurrences after enabling the lint."
)]
#![allow(clippy::expect_used)] // Branch node helpers rely on expect to assert persistence invariants for corrupted tries.

use crate::{LeafNode, LinearAddress, MaybePersistedNode, Node, Path, SharedNode};
use std::fmt::Write as _;
use std::fmt::{Debug, Formatter};
use std::io::Read;

/// The type of a hash. For ethereum compatible hashes, this might be a RLP encoded
/// value if it's small enough to fit in less than 32 bytes. For merkledb compatible
/// hashes, it's always a `TrieHash`.
#[cfg(feature = "ethhash")]
pub type HashType = ethhash::HashOrRlp;

#[cfg(not(feature = "ethhash"))]
/// The type of a hash. For non-ethereum compatible hashes, this is always a `TrieHash`.
pub type HashType = crate::TrieHash;

/// A trait to convert a value into a [`HashType`].
///
/// This is used to allow different hash types to be conditionally used, e.g., when the
/// `ethhash` feature is enabled. When not enabled, this suppresses the clippy warnings
/// about useless `.into()` calls.
pub trait IntoHashType {
    /// Converts the value into a `HashType`.
    #[must_use]
    fn into_hash_type(self) -> HashType;
}

#[cfg(feature = "ethhash")]
impl IntoHashType for crate::TrieHash {
    #[inline]
    fn into_hash_type(self) -> HashType {
        self.into()
    }
}

#[cfg(not(feature = "ethhash"))]
impl IntoHashType for crate::TrieHash {
    #[inline]
    fn into_hash_type(self) -> HashType {
        self
    }
}

pub(crate) trait Serializable {
    fn write_to_vec(&self, vec: &mut Vec<u8>);

    fn from_reader<R: Read>(reader: R) -> Result<Self, std::io::Error>
    where
        Self: Sized;
}

/// An extension trait for [`Read`] for convenience methods when
/// reading serialized data.
pub(crate) trait ReadSerializable: Read {
    /// Read a single byte from the reader.
    fn read_byte(&mut self) -> Result<u8, std::io::Error> {
        let mut this = 0;
        self.read_exact(std::slice::from_mut(&mut this))?;
        Ok(this)
    }

    /// Reads a fixed amount of bytes from the reader into a vector
    fn read_fixed_len(&mut self, len: usize) -> Result<Vec<u8>, std::io::Error> {
        let mut buf = Vec::with_capacity(len);
        self.take(len as u64).read_to_end(&mut buf)?;
        if buf.len() != len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "not enough bytes read",
            ));
        }
        Ok(buf)
    }

    /// Read a value of type `T` from the reader.
    fn next_value<T: Serializable>(&mut self) -> Result<T, std::io::Error> {
        T::from_reader(self)
    }
}

impl<T: Read> ReadSerializable for T {}

#[derive(PartialEq, Eq, Clone, Debug)]
#[repr(C)]
/// A child of a branch node.
pub enum Child {
    /// There is a child at this index, but we haven't hashed it
    /// or allocated space in storage for it yet.
    Node(Node),

    /// We know the child's persisted address and hash.
    AddressWithHash(LinearAddress, HashType),

    /// A `MaybePersisted` child
    MaybePersisted(MaybePersistedNode, HashType),
}

const DEBUG_CHILD_PATH_PREVIEW_NIBBLES: usize = 16;
const DEBUG_CHILD_VALUE_PREVIEW_BYTES: usize = 8;

fn format_path_preview(path: &Path) -> String {
    if path.is_empty() {
        return "[]".to_string();
    }

    let mut buf = String::from("0x");
    for nibble in path.iter().take(DEBUG_CHILD_PATH_PREVIEW_NIBBLES) {
        let _ = write!(&mut buf, "{nibble:x}");
    }
    if path.len() > DEBUG_CHILD_PATH_PREVIEW_NIBBLES {
        buf.push('…');
    }
    buf
}

fn hex_preview(bytes: &[u8], max_bytes: usize) -> String {
    let limit = bytes.len().min(max_bytes);
    let mut buf = String::new();
    for byte in bytes.iter().take(limit) {
        let _ = write!(&mut buf, "{byte:02x}");
    }
    if bytes.len() > limit {
        buf.push('…');
    }
    buf
}

fn format_value_preview(bytes: &[u8]) -> String {
    format!(
        "0x{} (len={})",
        hex_preview(bytes, DEBUG_CHILD_VALUE_PREVIEW_BYTES),
        bytes.len()
    )
}

fn summarize_child_node(node: &Node) -> String {
    match node {
        Node::Branch(branch) => {
            let path_preview = format_path_preview(&branch.partial_path);
            let child_count = branch
                .children
                .iter()
                .filter(|child| child.is_some())
                .count();
            let value_preview = branch
                .value
                .as_deref()
                .map_or_else(|| "nil".to_string(), format_value_preview);
            format!("branch path={path_preview} children={child_count} value={value_preview}")
        }
        Node::Leaf(leaf) => {
            let path_preview = format_path_preview(&leaf.partial_path);
            let value_preview = format_value_preview(&leaf.value);
            format!("leaf path={path_preview} value={value_preview}")
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
/// Errors that occur when accessing children of a [`BranchNode`].
pub enum BranchChildError {
    /// Encountered a child that has not been hashed yet.
    #[error("branch child at index {child_index} is not hashed")]
    NotHashed {
        /// Index of the offending child.
        child_index: usize,
    },
    /// Encountered a child whose address has not been assigned yet.
    #[error("branch child at index {child_index} does not have a persisted address")]
    AddressUnavailable {
        /// Index of the offending child.
        child_index: usize,
    },
}

impl BranchChildError {
    #[must_use]
    /// Returns the index of the child that triggered this error.
    pub const fn child_index(self) -> usize {
        match self {
            Self::NotHashed { child_index } | Self::AddressUnavailable { child_index } => {
                child_index
            }
        }
    }

    #[must_use]
    /// Creates a [`BranchChildError::NotHashed`] for `child_index`.
    pub const fn child_not_hashed(child_index: usize) -> Self {
        Self::NotHashed { child_index }
    }

    #[must_use]
    /// Creates a [`BranchChildError::AddressUnavailable`] for `child_index`.
    pub const fn address_unavailable(child_index: usize) -> Self {
        Self::AddressUnavailable { child_index }
    }
}

impl Child {
    /// Return a mutable reference to the underlying Node if the child
    /// is a [`Child::Node`] variant, otherwise None.
    #[must_use]
    pub const fn as_mut_node(&mut self) -> Option<&mut Node> {
        match self {
            Child::Node(node) => Some(node),
            _ => None,
        }
    }

    /// Return the persisted address of the child if it is a [`Child::AddressWithHash`] or [`Child::MaybePersisted`] variant, otherwise None.
    #[must_use]
    pub fn persisted_address(&self) -> Option<LinearAddress> {
        match self {
            Child::AddressWithHash(addr, _) => Some(*addr),
            Child::MaybePersisted(maybe_persisted, _) => maybe_persisted.as_linear_address(),
            Child::Node(_) => None,
        }
    }

    /// Return the unpersisted node if the child is an unpersisted [`Child::MaybePersisted`]
    /// variant, otherwise None.
    #[must_use]
    pub fn unpersisted(&self) -> Option<&MaybePersistedNode> {
        if let Child::MaybePersisted(maybe_persisted, _) = self {
            maybe_persisted.unpersisted()
        } else {
            None
        }
    }

    /// Return the hash of the child if it is a [`Child::AddressWithHash`] or [`Child::MaybePersisted`] variant, otherwise None.
    #[must_use]
    pub const fn hash(&self) -> Option<&HashType> {
        match self {
            Child::AddressWithHash(_, hash) => Some(hash),
            Child::MaybePersisted(_, hash) => Some(hash),
            Child::Node(_) => None,
        }
    }

    /// Return the persistence information (address and hash) of the child if it is persisted.
    ///
    /// This method returns `Some((address, hash))` for:
    /// - [`Child::AddressWithHash`] variants (already persisted)
    /// - [`Child::MaybePersisted`] variants that have been persisted
    ///
    /// Returns `None` for:
    /// - [`Child::Node`] variants (unpersisted nodes)
    /// - [`Child::MaybePersisted`] variants that are not yet persisted
    #[must_use]
    pub fn persist_info(&self) -> Option<(LinearAddress, &HashType)> {
        match self {
            Child::AddressWithHash(addr, hash) => Some((*addr, hash)),
            Child::MaybePersisted(maybe_persisted, hash) => {
                maybe_persisted.as_linear_address().map(|addr| (addr, hash))
            }
            Child::Node(_) => None,
        }
    }

    /// Return a `MaybePersistedNode` from a child
    ///
    /// This is used in the dump utility, but otherwise should be avoided,
    /// as it may create an unnecessary `MaybePersistedNode`
    #[must_use]
    pub fn as_maybe_persisted_node(&self) -> MaybePersistedNode {
        match self {
            Child::Node(node) => MaybePersistedNode::from(SharedNode::from(node.clone())),
            Child::AddressWithHash(addr, _) => MaybePersistedNode::from(*addr),
            Child::MaybePersisted(maybe_persisted, _) => maybe_persisted.clone(),
        }
    }
}

#[cfg(feature = "ethhash")]
pub mod ethhash {
    use sha2::Digest as _;
    use sha3::Keccak256;
    use smallvec::SmallVec;
    use std::{
        fmt::{Display, Formatter},
        io::Read,
    };

    use crate::TrieHash;

    use super::Serializable;

    #[derive(Clone, Debug)]
    pub enum HashOrRlp {
        Hash(TrieHash),
        // TODO: this slice is never larger than 32 bytes so smallvec is probably not our best container
        // the length is stored in a `usize` but it could be in a `u8` and it will never overflow
        Rlp(RlpBytes),
    }

    #[derive(Clone)]
    pub struct RlpBytes {
        bytes: [u8; 32],
        len: u8,
    }

    impl RlpBytes {
        pub const fn new(bytes: [u8; 32], len: u8) -> Self {
            debug_assert!(len < 32, "RLP payloads must be shorter than 32 bytes");
            Self { bytes, len }
        }

        pub fn copy_from_slice(slice: &[u8]) -> Result<Self, InvalidRlpLength> {
            let len: u8 = slice
                .len()
                .try_into()
                .map_err(|_| InvalidRlpLength(slice.len()))?;
            if len >= 32 {
                return Err(InvalidRlpLength(slice.len()));
            }
            let mut bytes = [0u8; 32];
            bytes[..slice.len()].copy_from_slice(slice);
            Ok(Self { bytes, len })
        }

        #[allow(clippy::missing_const_for_fn)]
        pub fn len(&self) -> usize {
            usize::from(self.len)
        }

        pub fn is_empty(&self) -> bool {
            self.len == 0
        }

        pub fn as_slice(&self) -> &[u8] {
            &self.bytes[..self.len()]
        }
    }

    impl std::fmt::Debug for RlpBytes {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            f.debug_tuple("RlpBytes")
                .field(&hex::encode(self.as_slice()))
                .finish()
        }
    }

    impl PartialEq for RlpBytes {
        fn eq(&self, other: &Self) -> bool {
            self.as_slice() == other.as_slice()
        }
    }

    impl Eq for RlpBytes {}

    #[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
    #[error("invalid RLP payload length {0}; expected < 32 bytes")]
    pub struct InvalidRlpLength(pub usize);

    impl TryFrom<&[u8]> for RlpBytes {
        type Error = InvalidRlpLength;

        fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
            Self::copy_from_slice(slice)
        }
    }

    impl From<SmallVec<[u8; 32]>> for RlpBytes {
        fn from(value: SmallVec<[u8; 32]>) -> Self {
            debug_assert!(
                value.len() < 32,
                "RLP payloads must be shorter than 32 bytes"
            );
            let len = value.len();
            let mut bytes = [0u8; 32];
            bytes[..len].copy_from_slice(value.as_slice());
            // SAFETY: `len` was just computed from the slice length, so it fits in u8 and < 32.
            let len = len as u8;
            Self { bytes, len }
        }
    }

    impl From<RlpBytes> for Box<[u8]> {
        fn from(value: RlpBytes) -> Self {
            value.as_slice().into()
        }
    }

    impl AsRef<[u8]> for RlpBytes {
        fn as_ref(&self) -> &[u8] {
            self.as_slice()
        }
    }

    impl std::ops::Deref for RlpBytes {
        type Target = [u8];

        fn deref(&self) -> &Self::Target {
            self.as_slice()
        }
    }

    impl HashOrRlp {
        /// Creates a new `TrieHash` from the default value, which is the all zeros.
        ///
        /// ```
        /// assert_eq!(
        ///     firewood_storage::HashType::empty(),
        ///     firewood_storage::HashType::from([0; 32]),
        /// )
        /// ```
        #[must_use]
        pub fn empty() -> Self {
            TrieHash::empty().into()
        }

        pub fn as_slice(&self) -> &[u8] {
            self
        }

        pub(crate) fn into_triehash(self) -> TrieHash {
            self.into()
        }
    }

    impl PartialEq<TrieHash> for HashOrRlp {
        fn eq(&self, other: &TrieHash) -> bool {
            match self {
                HashOrRlp::Hash(h) => h == other,
                HashOrRlp::Rlp(r) => Keccak256::digest(r.as_ref()).as_slice() == other.as_ref(),
            }
        }
    }

    impl PartialEq<HashOrRlp> for TrieHash {
        fn eq(&self, other: &HashOrRlp) -> bool {
            match other {
                HashOrRlp::Hash(h) => h == self,
                HashOrRlp::Rlp(r) => Keccak256::digest(r.as_ref()).as_slice() == self.as_ref(),
            }
        }
    }

    impl PartialEq for HashOrRlp {
        fn eq(&self, other: &Self) -> bool {
            match (self, other) {
                (HashOrRlp::Hash(h1), HashOrRlp::Hash(h2)) => h1 == h2,
                (HashOrRlp::Rlp(r1), HashOrRlp::Rlp(r2)) => r1.as_slice() == r2.as_slice(),
                (HashOrRlp::Hash(h), HashOrRlp::Rlp(r))
                | (HashOrRlp::Rlp(r), HashOrRlp::Hash(h)) => {
                    Keccak256::digest(r.as_ref()).as_slice() == h.as_ref()
                }
            }
        }
    }

    impl Eq for HashOrRlp {}

    impl Serializable for HashOrRlp {
        fn write_to_vec(&self, vec: &mut Vec<u8>) {
            match self {
                HashOrRlp::Hash(h) => {
                    vec.push(0);
                    vec.extend_from_slice(h.as_ref());
                }
                HashOrRlp::Rlp(r) => {
                    debug_assert!(!r.is_empty());
                    debug_assert!(r.len() < 32);
                    vec.push(r.len() as u8);
                    vec.extend_from_slice(r.as_ref());
                }
            }
        }

        fn from_reader<R: Read>(mut reader: R) -> Result<Self, std::io::Error> {
            let mut bytes = [0; 32];
            reader.read_exact(&mut bytes[0..1])?;
            match bytes[0] {
                0 => {
                    reader.read_exact(&mut bytes)?;
                    Ok(HashOrRlp::Hash(TrieHash::from(bytes)))
                }
                len if len < 32 => {
                    reader.read_exact(&mut bytes[0..len as usize])?;
                    Ok(HashOrRlp::Rlp(RlpBytes::new(bytes, len)))
                }
                _ => Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid RLP length",
                )),
            }
        }
    }

    impl From<HashOrRlp> for TrieHash {
        fn from(val: HashOrRlp) -> Self {
            match val {
                HashOrRlp::Hash(h) => h,
                HashOrRlp::Rlp(r) => Keccak256::digest(r.as_ref()).into(),
            }
        }
    }

    impl From<TrieHash> for HashOrRlp {
        fn from(val: TrieHash) -> Self {
            HashOrRlp::Hash(val)
        }
    }

    impl From<[u8; 32]> for HashOrRlp {
        fn from(value: [u8; 32]) -> Self {
            HashOrRlp::Hash(TrieHash::into(value.into()))
        }
    }

    impl TryFrom<&[u8]> for HashOrRlp {
        type Error = crate::InvalidTrieHashLength;

        fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
            value.try_into().map(HashOrRlp::Hash)
        }
    }

    impl AsRef<[u8]> for HashOrRlp {
        fn as_ref(&self) -> &[u8] {
            match self {
                HashOrRlp::Hash(h) => h.as_ref(),
                HashOrRlp::Rlp(r) => r.as_ref(),
            }
        }
    }

    impl std::ops::Deref for HashOrRlp {
        type Target = [u8];
        fn deref(&self) -> &Self::Target {
            match self {
                HashOrRlp::Hash(h) => h,
                HashOrRlp::Rlp(r) => r,
            }
        }
    }

    impl Display for HashOrRlp {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            match self {
                HashOrRlp::Hash(h) => write!(f, "{h}"),
                HashOrRlp::Rlp(r) => {
                    let width = f.precision().unwrap_or(32);
                    write!(f, "{:.*}", width, hex::encode(r.as_slice()))
                }
            }
        }
    }
}

/// Type alias for a collection of children in a branch node.
pub type Children<T> = [Option<T>; BranchNode::MAX_CHILDREN];

#[derive(PartialEq, Eq, Clone)]
/// A branch node
pub struct BranchNode {
    /// The partial path for this branch
    pub partial_path: Path,

    /// The value of the data for this branch, if any
    pub value: Option<Box<[u8]>>,

    /// The children of this branch.
    /// Element i is the child at index i, or None if there is no child at that index.
    /// Each element is (`child_hash`, `child_address`).
    /// `child_address` is None if we don't know the child's hash.
    pub children: Children<Child>,
}

impl Debug for BranchNode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "[BranchNode")?;
        write!(f, r#" path="{:?}""#, self.partial_path)?;

        for (i, c) in self.children.iter().enumerate() {
            match c {
                None => {}
                Some(Child::Node(node)) => {
                    write!(f, "({i:?}: node={})", summarize_child_node(node))?;
                }
                Some(Child::AddressWithHash(addr, hash)) => {
                    write!(f, "({i:?}: address={addr:?} hash={hash})")?;
                }
                Some(Child::MaybePersisted(maybe_persisted, hash)) => {
                    // For MaybePersisted, show the address if persisted, otherwise show as unpersisted
                    match maybe_persisted.as_linear_address() {
                        Some(addr) => write!(f, "({i:?}: address={addr:?} hash={hash})")?,
                        None => write!(f, "({i:?}: unpersisted hash={hash})")?,
                    }
                }
            }
        }

        write!(
            f,
            " v={}]",
            match &self.value {
                Some(v) => hex::encode(&**v),
                None => "nil".to_string(),
            }
        )
    }
}

impl BranchNode {
    /// The maximum number of children in a [`BranchNode`]
    #[cfg(feature = "branch_factor_256")]
    pub const MAX_CHILDREN: usize = 256;

    /// The maximum number of children in a [`BranchNode`]
    #[cfg(not(feature = "branch_factor_256"))]
    pub const MAX_CHILDREN: usize = 16;

    /// Convenience function to create a new array of empty children.
    #[must_use]
    pub const fn empty_children<T>() -> Children<T> {
        [const { None }; Self::MAX_CHILDREN]
    }

    /// Returns the address of the child at the given index.
    /// Panics if `child_index` >= [`BranchNode::MAX_CHILDREN`].
    #[must_use]
    pub fn child(&self, child_index: u8) -> &Option<Child> {
        self.children
            .get(child_index as usize)
            .expect("child_index is in bounds")
    }

    /// Update the child at `child_index` to be `new_child_addr`.
    /// If `new_child_addr` is None, the child is removed.
    pub fn update_child(
        &mut self,
        child_index: u8,
        new_child: Option<Child>,
    ) -> Result<(), BranchChildError> {
        let child = self
            .children
            .get_mut(child_index as usize)
            .expect("child_index is in bounds");

        *child = new_child;
        Ok(())
    }

    /// Helper to iterate over only valid children
    ///
    /// # Errors
    ///
    /// Returns [`BranchChildError::NotHashed`] if any child remains a
    /// [`Child::Node`], meaning it has not been hashed yet. Unlike
    /// [`BranchNode::children_addresses`], this does _not_ error on
    /// unpersisted [`Child::MaybePersisted`] children.
    #[track_caller]
    pub(crate) fn children_iter(
        &self,
    ) -> Result<impl Iterator<Item = (usize, (LinearAddress, &HashType))> + Clone, BranchChildError>
    {
        if let Some((index, _)) = self
            .children
            .iter()
            .enumerate()
            .find(|(_, child)| matches!(child, Some(Child::Node(_))))
        {
            return Err(BranchChildError::child_not_hashed(index));
        }

        Ok(self
            .children
            .iter()
            .enumerate()
            .filter_map(|(i, child)| match child {
                None => None,
                Some(Child::Node(_)) => None,
                Some(Child::AddressWithHash(address, hash)) => Some((i, (*address, hash))),
                Some(Child::MaybePersisted(maybe_persisted, hash)) => {
                    // For MaybePersisted, we need the address if it's persisted
                    maybe_persisted
                        .as_linear_address()
                        .map(|addr| (i, (addr, hash)))
                }
            }))
    }

    /// Returns a set of hashes for each child that has a hash set.
    ///
    /// The index of the hash in the returned array corresponds to the index of the child
    /// in the branch node.
    ///
    /// # Errors
    ///
    /// Returns [`BranchChildError::NotHashed`] if any child is still stored as
    /// an in-memory [`Child::Node`] that has not been hashed yet.
    #[must_use]
    #[track_caller]
    pub fn children_hashes(&self) -> Result<Children<HashType>, BranchChildError> {
        let mut hashes = Self::empty_children();
        for (index, (child, slot)) in self.children.iter().zip(hashes.iter_mut()).enumerate() {
            match child {
                None => {}
                Some(Child::Node(_)) => {
                    return Err(BranchChildError::child_not_hashed(index));
                }
                Some(Child::AddressWithHash(_, hash)) => _ = slot.replace(hash.clone()),
                Some(Child::MaybePersisted(_, hash)) => _ = slot.replace(hash.clone()),
            }
        }
        Ok(hashes)
    }

    /// Returns a set of addresses for each child that has an address set.
    ///
    /// The index of the address in the returned array corresponds to the index of the child
    /// in the branch node.
    ///
    /// # Errors
    ///
    /// Returns [`BranchChildError::NotHashed`] if any child remains a
    /// [`Child::Node`] and [`BranchChildError::AddressUnavailable`] when a
    /// [`Child::MaybePersisted`] child has not been persisted yet and therefore
    /// lacks an address.
    #[must_use]
    #[track_caller]
    pub fn children_addresses(&self) -> Result<Children<LinearAddress>, BranchChildError> {
        let mut addrs = Self::empty_children();
        for (index, (child, slot)) in self.children.iter().zip(addrs.iter_mut()).enumerate() {
            match child {
                None => {}
                Some(Child::Node(_)) => {
                    return Err(BranchChildError::child_not_hashed(index));
                }
                Some(Child::AddressWithHash(address, _)) => _ = slot.replace(*address),
                Some(Child::MaybePersisted(maybe_persisted, _)) => {
                    // For MaybePersisted, we need the address if it's persisted
                    if let Some(addr) = maybe_persisted.as_linear_address() {
                        slot.replace(addr);
                    } else {
                        return Err(BranchChildError::address_unavailable(index));
                    }
                }
            }
        }
        Ok(addrs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_includes_child_node_summaries() {
        let mut parent = BranchNode {
            partial_path: Path::new(),
            value: None,
            children: BranchNode::empty_children(),
        };

        parent
            .update_child(
                0,
                Some(Child::Node(Node::Leaf(LeafNode {
                    partial_path: Path::from([0x1, 0x2, 0x3]),
                    value: vec![0xaa, 0xbb, 0xcc].into_boxed_slice(),
                }))),
            )
            .unwrap();

        let child_branch = BranchNode {
            partial_path: Path::from([0x0a]),
            value: Some(vec![0xde, 0xad, 0xbe, 0xef].into_boxed_slice()),
            children: BranchNode::empty_children(),
        };
        parent
            .update_child(1, Some(Child::Node(Node::from(child_branch))))
            .unwrap();

        let debug_output = format!("{:?}", parent);

        assert!(
            debug_output.contains("leaf path=0x123"),
            "expected leaf summary in {debug_output}"
        );
        assert!(
            debug_output.contains("branch path=0xa"),
            "expected branch summary in {debug_output}"
        );
    }

    #[test]
    fn children_iter_errors_on_unhashed_child() {
        let mut branch = BranchNode {
            partial_path: Path::new(),
            value: None,
            children: BranchNode::empty_children(),
        };

        branch
            .update_child(
                0,
                Some(Child::Node(Node::Leaf(LeafNode {
                    partial_path: Path::new(),
                    value: Box::from([]),
                }))),
            )
            .unwrap();

        let result = branch.children_iter();
        match result {
            Err(BranchChildError::NotHashed { child_index }) => assert_eq!(child_index, 0),
            Err(other) => panic!("unexpected error {other:?}"),
            Ok(_) => panic!("expected error"),
        }
    }

    #[test]
    fn children_hashes_errors_on_unhashed_child() {
        let mut branch = BranchNode {
            partial_path: Path::new(),
            value: None,
            children: BranchNode::empty_children(),
        };

        branch
            .update_child(
                1,
                Some(Child::Node(Node::Leaf(LeafNode {
                    partial_path: Path::new(),
                    value: Box::from([]),
                }))),
            )
            .unwrap();

        let result = branch.children_hashes();
        match result {
            Err(BranchChildError::NotHashed { child_index }) => assert_eq!(child_index, 1),
            Err(other) => panic!("unexpected error {other:?}"),
            Ok(_) => panic!("expected error"),
        }
    }

    #[test]
    fn children_addresses_errors_on_unpersisted_child() {
        let mut branch = BranchNode {
            partial_path: Path::new(),
            value: None,
            children: BranchNode::empty_children(),
        };

        let child = Child::MaybePersisted(
            MaybePersistedNode::from(SharedNode::new(Node::Leaf(LeafNode {
                partial_path: Path::new(),
                value: Box::from([0u8]),
            }))),
            HashType::empty(),
        );

        branch.update_child(2, Some(child)).unwrap();

        let result = branch.children_addresses();
        match result {
            Err(BranchChildError::AddressUnavailable { child_index }) => assert_eq!(child_index, 2),
            Err(other) => panic!("unexpected error {other:?}"),
            Ok(_) => panic!("expected error"),
        }
    }
}

impl From<&LeafNode> for BranchNode {
    fn from(leaf: &LeafNode) -> Self {
        BranchNode {
            partial_path: leaf.partial_path.clone(),
            value: Some(Box::from(&leaf.value[..])),
            children: BranchNode::empty_children(),
        }
    }
}
