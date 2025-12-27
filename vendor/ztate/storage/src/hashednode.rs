// Copyright (C) 2023, Ava Labs, Inc. All rights reserved.
// See the file LICENSE.md for licensing terms.

use crate::{BranchNode, Children, HashType, LeafNode, Node, Path};
use smallvec::SmallVec;
use std::convert::TryFrom;
use std::fmt;

/// Error returned when a [`BranchNode`] contains a [`Child`] without an exposed hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MissingChildHashError {
    child_index: usize,
}

impl MissingChildHashError {
    /// Creates a new [`MissingChildHashError`] for the given child index.
    #[must_use]
    pub const fn new(child_index: usize) -> Self {
        Self { child_index }
    }

    /// Index of the child without an exposed hash.
    #[must_use]
    pub const fn child_index(self) -> usize {
        self.child_index
    }
}

impl fmt::Display for MissingChildHashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "branch child at index {} is missing a hash",
            self.child_index
        )
    }
}

impl std::error::Error for MissingChildHashError {}

/// Wrapper guaranteeing that every [`Child`] of the branch exposes a hash.
#[derive(Clone, Copy, Debug)]
pub struct HashedBranchChildren<'a> {
    branch: &'a BranchNode,
}

impl<'a> HashedBranchChildren<'a> {
    /// Attempts to wrap the given branch, returning an error when any child lacks a hash.
    pub fn try_new(branch: &'a BranchNode) -> Result<Self, MissingChildHashError> {
        if let Err(err) = branch.children_hashes() {
            let child_index = err.child_index();
            #[cfg(debug_assertions)]
            panic!(
                "branch child at index {child_index} is missing a hash: {:?}",
                branch.children[child_index].as_ref()
            );

            #[cfg(not(debug_assertions))]
            return Err(MissingChildHashError::new(child_index));
        }

        for (index, child) in branch.children.iter().enumerate() {
            if let Some(child) = child {
                if child.hash().is_none() {
                    #[cfg(debug_assertions)]
                    panic!("branch child at index {index} is missing a hash: {child:?}");

                    #[cfg(not(debug_assertions))]
                    return Err(MissingChildHashError::new(index));
                }
            }
        }
        Ok(Self { branch })
    }

    /// Returns the wrapped branch.
    #[must_use]
    pub const fn as_ref(&self) -> &'a BranchNode {
        self.branch
    }
}

/// Reference to a node that is safe to hash.
#[derive(Clone, Copy, Debug)]
pub enum HashedNodeRef<'a> {
    /// Branch with guaranteed child hashes.
    Branch(HashedBranchChildren<'a>),
    /// Leaf node.
    Leaf(&'a LeafNode),
}

impl<'a> TryFrom<&'a Node> for HashedNodeRef<'a> {
    type Error = MissingChildHashError;

    fn try_from(node: &'a Node) -> Result<Self, Self::Error> {
        Ok(match node {
            Node::Branch(branch) => HashedNodeRef::Branch(HashedBranchChildren::try_new(branch)?),
            Node::Leaf(leaf) => HashedNodeRef::Leaf(leaf),
        })
    }
}

/// Returns the hash of `node`, which is at the given `path_prefix`.
#[must_use]
pub fn hash_node(node: HashedNodeRef<'_>, path_prefix: &Path) -> HashType {
    NodeAndPrefix {
        node,
        prefix: path_prefix,
    }
    .into()
}

/// Returns the serialized representation of `node` used as the pre-image
/// when hashing the node. The node is at the given `path_prefix`.
#[must_use]
pub fn hash_preimage(node: HashedNodeRef<'_>, path_prefix: &Path) -> Box<[u8]> {
    // Key, 3 options, value digest
    #[expect(clippy::arithmetic_side_effects)]
    let est_len = node.partial_path().count() + path_prefix.len() + 3 + HashType::empty().len();
    let mut buf = Vec::with_capacity(est_len);
    NodeAndPrefix {
        node,
        prefix: path_prefix,
    }
    .write(&mut buf);
    buf.into_boxed_slice()
}

pub trait HasUpdate {
    fn update<T: AsRef<[u8]>>(&mut self, data: T);

    #[cfg(feature = "ethhash")]
    fn record_error(&mut self, _error: crate::TrieError) {}
}

impl HasUpdate for Vec<u8> {
    fn update<T: AsRef<[u8]>>(&mut self, data: T) {
        self.extend(data.as_ref().iter().copied());
    }
}

impl<A> HasUpdate for SmallVec<A>
where
    A: smallvec::Array<Item = u8>,
{
    fn update<T: AsRef<[u8]>>(&mut self, data: T) {
        self.extend_from_slice(data.as_ref());
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// A `ValueDigest` is either a node's value or the hash of its value.
pub enum ValueDigest<T> {
    /// The node's value.
    Value(T),
    #[cfg(not(feature = "ethhash"))]
    /// For MerkleDB hashing, the digest is the hash of the value if it is 32
    /// bytes or longer.
    Hash(HashType),
}

impl<T: AsRef<[u8]>> ValueDigest<T> {
    /// Verifies that the value or hash matches the expected value.
    pub fn verify(&self, expected: impl AsRef<[u8]>) -> bool {
        match self {
            Self::Value(got_value) => {
                // This proof proves that `key` maps to `got_value`.
                got_value.as_ref() == expected.as_ref()
            }
            #[cfg(not(feature = "ethhash"))]
            Self::Hash(got_hash) => {
                use sha2::{Digest, Sha256};
                // This proof proves that `key` maps to a value
                // whose hash is `got_hash`.
                *got_hash == HashType::from(Sha256::digest(expected.as_ref()))
            }
        }
    }

    /// Returns a `ValueDigest` that borrows from this one.
    pub fn as_ref(&self) -> ValueDigest<&[u8]> {
        match self {
            Self::Value(v) => ValueDigest::Value(v.as_ref()),
            #[cfg(not(feature = "ethhash"))]
            Self::Hash(h) => ValueDigest::Hash(h.clone()),
        }
    }

    /// Convert the value to a hash if it is not already a hash.
    ///
    /// If the value is less than 32 bytes, it will be passed through as is
    /// instead of hashing.
    ///
    /// If etherum hashing is enabled, this will always return the value as is.
    pub fn make_hash(&self) -> ValueDigest<&[u8]> {
        match self.as_ref() {
            #[cfg(not(feature = "ethhash"))]
            ValueDigest::Value(v) if v.len() >= 32 => {
                use sha2::{Digest, Sha256};
                ValueDigest::Hash(HashType::from(Sha256::digest(v)))
            }

            ValueDigest::Value(v) => ValueDigest::Value(v),

            #[cfg(not(feature = "ethhash"))]
            ValueDigest::Hash(v) => ValueDigest::Hash(v),
        }
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for ValueDigest<T> {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Value(v) => v.as_ref(),
            #[cfg(not(feature = "ethhash"))]
            Self::Hash(h) => h.as_ref(),
        }
    }
}

/// A node in the trie that can be hashed.
pub trait Hashable: std::fmt::Debug {
    /// The full path of this node's parent where each byte is a nibble.
    fn parent_prefix_path(&self) -> impl Iterator<Item = u8> + Clone;
    /// The partial path of this node where each byte is a nibble.
    fn partial_path(&self) -> impl Iterator<Item = u8> + Clone;
    /// The node's value or hash.
    fn value_digest(&self) -> Option<ValueDigest<&[u8]>>;
    /// Each element is a child's index and hash.
    /// Yields 0 elements if the node is a leaf.
    fn children(&self) -> Children<HashType>;

    /// The full path of this node including the parent's prefix where each byte is a nibble.
    fn full_path(&self) -> impl Iterator<Item = u8> + Clone {
        self.parent_prefix_path().chain(self.partial_path())
    }
}

/// A preimage of a hash.
pub trait Preimage: std::fmt::Debug {
    /// Returns the hash of this preimage.
    fn to_hash(&self) -> HashType;
    /// Write this hash preimage to `buf`.
    fn write(&self, buf: &mut impl HasUpdate);
}

trait HashableNode: std::fmt::Debug {
    fn partial_path(&self) -> impl Iterator<Item = u8> + Clone;
    fn value(&self) -> Option<&[u8]>;
    fn child_hashes(&self) -> Children<HashType>;
}

impl<'a> HashableNode for HashedNodeRef<'a> {
    fn partial_path(&self) -> impl Iterator<Item = u8> + Clone {
        match self {
            HashedNodeRef::Branch(branch) => branch.as_ref().partial_path.0.iter().copied(),
            HashedNodeRef::Leaf(leaf) => leaf.partial_path.0.iter().copied(),
        }
    }

    fn value(&self) -> Option<&[u8]> {
        match self {
            HashedNodeRef::Branch(branch) => branch.as_ref().value.as_deref(),
            HashedNodeRef::Leaf(leaf) => Some(&leaf.value),
        }
    }

    fn child_hashes(&self) -> Children<HashType> {
        match self {
            HashedNodeRef::Branch(branch) => branch
                .as_ref()
                .children_hashes()
                .expect("branch children hashes validated during construction"),
            HashedNodeRef::Leaf(_) => BranchNode::empty_children(),
        }
    }
}

#[derive(Debug)]
struct NodeAndPrefix<'a, N: HashableNode> {
    node: N,
    prefix: &'a Path,
}

impl<'a, N: HashableNode> From<NodeAndPrefix<'a, N>> for HashType {
    fn from(node: NodeAndPrefix<'a, N>) -> Self {
        node.to_hash()
    }
}

impl<'a, N: HashableNode> Hashable for NodeAndPrefix<'a, N> {
    fn parent_prefix_path(&self) -> impl Iterator<Item = u8> + Clone {
        self.prefix.0.iter().copied()
    }

    fn partial_path(&self) -> impl Iterator<Item = u8> + Clone {
        self.node.partial_path()
    }

    fn value_digest(&self) -> Option<ValueDigest<&[u8]>> {
        self.node.value().map(ValueDigest::Value)
    }

    fn children(&self) -> Children<HashType> {
        self.node.child_hashes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Child;

    fn branch_with_unhashed_child() -> BranchNode {
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
        branch
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "branch child at index 0 is missing a hash")]
    fn hashed_branch_children_panics_when_missing_hash_in_debug() {
        let branch = branch_with_unhashed_child();
        let _ = HashedBranchChildren::try_new(&branch);
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn hashed_branch_children_errors_when_missing_hash_in_release() {
        let branch = branch_with_unhashed_child();
        let err = HashedBranchChildren::try_new(&branch).expect_err("missing hash must error");
        assert_eq!(err.child_index(), 0);
    }

    #[test]
    fn smallvec_has_update_supports_capacity_4() {
        let mut buf: SmallVec<[u8; 4]> = SmallVec::new();
        HasUpdate::update(&mut buf, [1u8, 2, 3]);
        HasUpdate::update(&mut buf, [4u8, 5]);

        assert_eq!(buf.as_slice(), &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn smallvec_has_update_supports_capacity_8() {
        let mut buf: SmallVec<[u8; 8]> = SmallVec::new();
        HasUpdate::update(&mut buf, [0xAA, 0xBB]);
        HasUpdate::update(&mut buf, [0xCC; 4]);

        assert_eq!(buf.as_slice(), &[0xAA, 0xBB, 0xCC, 0xCC, 0xCC, 0xCC]);
    }
}
