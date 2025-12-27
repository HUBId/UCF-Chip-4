// Copyright (C) 2023, Ava Labs, Inc. All rights reserved.
// See the file LICENSE.md for licensing terms.

#![allow(clippy::expect_used)] // Merkle operations rely on expect to guard structural invariants and surface corruption early.

#[cfg(test)]
pub(crate) mod tests;

use crate::iter::{MerkleKeyValueIter, MerkleNodeIter, PathIterator, TryExtend};
use crate::proof::{Proof, ProofCollection, ProofError, ProofNode, RangeProof};
use crate::v2::api::{self, FrozenProof, FrozenRangeProof, KeyType, ValueType};
use firewood_storage::{
    BranchNode, Child, FileIoError, HashType, HashedNodeReader, ImmutableProposal, IntoHashType,
    LeafNode, MaybePersistedNode, MutableProposal, NibblesIterator, Node, NodeStore, Parentable,
    Path, ReadableStorage, SharedNode, TrieHash, TrieReader,
};
use metrics::counter;
use std::collections::HashSet;
use std::fmt::Debug;
use std::io::{Error, ErrorKind};
use std::iter::once;
use std::num::NonZeroUsize;
use std::sync::Arc;

/// Keys are boxed u8 slices
pub type Key = Box<[u8]>;

/// Values are boxed u8 slices
pub type Value = Box<[u8]>;

fn corrupt_child_slot_error(
    partial_path: &Path,
    child_index: usize,
    context: &'static str,
) -> FileIoError {
    let detail = format!(
        "corrupt trie: branch at partial path {:?} missing child slot {child_index}",
        partial_path
    );
    FileIoError::from_generic_no_file(Error::new(ErrorKind::InvalidData, detail), context)
}

fn branch_child_slot<'a>(
    branch: &'a BranchNode,
    child_index: usize,
    context: &'static str,
) -> Result<&'a Option<Child>, FileIoError> {
    branch
        .children
        .get(child_index)
        .ok_or_else(|| corrupt_child_slot_error(&branch.partial_path, child_index, context))
}

fn branch_child_slot_mut<'a>(
    branch: &'a mut BranchNode,
    child_index: usize,
    context: &'static str,
) -> Result<&'a mut Option<Child>, FileIoError> {
    if child_index < branch.children.len() {
        Ok(&mut branch.children[child_index])
    } else {
        let partial_path = branch.partial_path.clone();
        Err(corrupt_child_slot_error(
            &partial_path,
            child_index,
            context,
        ))
    }
}

pub(crate) fn branch_child_ref<'a>(
    branch: &'a BranchNode,
    child_index: usize,
    context: &'static str,
) -> Result<Option<&'a Child>, FileIoError> {
    Ok(branch_child_slot(branch, child_index, context)?.as_ref())
}

fn take_branch_child(
    branch: &mut BranchNode,
    child_index: usize,
    context: &'static str,
) -> Result<Option<Child>, FileIoError> {
    Ok(branch_child_slot_mut(branch, child_index, context)?.take())
}

fn set_branch_child(
    branch: &mut BranchNode,
    child_index: usize,
    child: Option<Child>,
    context: &'static str,
) -> Result<(), FileIoError> {
    *branch_child_slot_mut(branch, child_index, context)? = child;
    Ok(())
}

macro_rules! write_attributes {
    ($writer:ident, $node:expr, $value:expr) => {
        if !$node.partial_path.0.is_empty() {
            write!($writer, " pp={:x}", $node.partial_path)
                .map_err(|e| FileIoError::from_generic_no_file(e, "write attributes"))?;
        }
        if !$value.is_empty() {
            match std::str::from_utf8($value) {
                Ok(string) if string.chars().all(char::is_alphanumeric) => {
                    write!($writer, " val={:.6}", string)
                        .map_err(|e| FileIoError::from_generic_no_file(e, "write attributes"))?;
                    if string.len() > 6 {
                        $writer.write_all(b"...").map_err(|e| {
                            FileIoError::from_generic_no_file(e, "write attributes")
                        })?;
                    }
                }
                _ => {
                    let hex = hex::encode($value);
                    write!($writer, " val={:.6}", hex)
                        .map_err(|e| FileIoError::from_generic_no_file(e, "write attributes"))?;
                    if hex.len() > 6 {
                        $writer.write_all(b"...").map_err(|e| {
                            FileIoError::from_generic_no_file(e, "write attributes")
                        })?;
                    }
                }
            }
        }
    };
}

/// Returns the value mapped to by `key` in the subtrie rooted at `node`.
fn get_helper<T: TrieReader>(
    nodestore: &T,
    node: &Node,
    key: &[u8],
) -> Result<Option<SharedNode>, FileIoError> {
    // 4 possibilities for the position of the `key` relative to `node`:
    // 1. The node is at `key`
    // 2. The key is above the node (i.e. its ancestor)
    // 3. The key is below the node (i.e. its descendant)
    // 4. Neither is an ancestor of the other
    let path_overlap = PrefixOverlap::from(key, node.partial_path());
    let unique_key = path_overlap.unique_a;
    let unique_node = path_overlap.unique_b;

    match (
        unique_key.split_first().map(|(index, path)| (*index, path)),
        unique_node.split_first(),
    ) {
        (_, Some(_)) => {
            // Case (2) or (4)
            Ok(None)
        }
        (None, None) => Ok(Some(node.clone().into())), // 1. The node is at `key`
        (Some((child_index, remaining_key)), None) => {
            // 3. The key is below the node (i.e. its descendant)
            match node {
                Node::Leaf(_) => Ok(None),
                Node::Branch(node) => match node
                    .children
                    .get(child_index as usize)
                    .expect("index is in bounds")
                {
                    None => Ok(None),
                    Some(Child::Node(child)) => get_helper(nodestore, child, remaining_key),
                    Some(Child::AddressWithHash(addr, _)) => {
                        let child = nodestore.read_node(*addr)?;
                        get_helper(nodestore, &child, remaining_key)
                    }
                    Some(Child::MaybePersisted(maybe_persisted, _)) => {
                        let child = maybe_persisted.as_shared_node(nodestore)?;
                        get_helper(nodestore, &child, remaining_key)
                    }
                },
            }
        }
    }
}

#[derive(Debug)]
/// Merkle operations against a nodestore
pub struct Merkle<T> {
    nodestore: T,
}

impl<T> Merkle<T> {
    pub(crate) fn into_inner(self) -> T {
        self.nodestore
    }
}

#[cfg(feature = "debug-tools")]
impl<T> Merkle<T> {
    /// Expose the underlying nodestore for debugging utilities.
    pub fn into_inner_for_debug(self) -> T {
        Self::into_inner(self)
    }

    /// Borrow the underlying nodestore for debugging utilities.
    pub fn nodestore_for_debug(&self) -> &T {
        &self.nodestore
    }
}

impl<T> From<T> for Merkle<T> {
    fn from(nodestore: T) -> Self {
        Merkle { nodestore }
    }
}

impl<T: TrieReader> Merkle<T> {
    pub(crate) fn try_root(&self) -> Result<Option<SharedNode>, FileIoError> {
        self.nodestore
            .root_as_maybe_persisted_node()
            .map(|root| root.as_shared_node(&self.nodestore))
            .transpose()
    }

    #[cfg(test)]
    pub(crate) const fn nodestore(&self) -> &T {
        &self.nodestore
    }

    /// Returns a proof that the given key has a certain value,
    /// or that the key isn't in the trie.
    ///
    /// ## Errors
    ///
    /// Returns an error if the trie is empty or an error occurs while reading from storage.
    pub fn prove(&self, key: &[u8]) -> Result<FrozenProof, ProofError> {
        let Some(root) = self.try_root().map_err(ProofError::from)? else {
            return Err(ProofError::Empty);
        };

        // Get the path to the key
        let path_iter = self.path_iter(key)?;
        let mut proof = Vec::new();
        for node in path_iter {
            let node = node?;
            proof.push(ProofNode::from(node));
        }

        if proof.is_empty() {
            // No nodes, even the root, are before `key`.
            // The root alone proves the non-existence of `key`.
            proof.push(ProofNode::from_root(&root));
        }

        Ok(Proof::new(proof.into_boxed_slice()))
    }

    /// Verify that a range proof is valid for the specified key range and root hash.
    ///
    /// This method validates a range proof by constructing a partial trie from the proof data
    /// and verifying that it produces the expected root hash. The proof may contain fewer
    /// key-value pairs than requested if the peer chose to limit the response size.
    ///
    /// # Parameters
    ///
    /// * `first_key` - The requested start of the range (inclusive).
    ///   - If `Some(key)`, verifies the proof covers keys >= this key
    ///   - If `None`, verifies the proof starts from the beginning of the trie
    ///
    /// * `last_key` - The requested end of the range (inclusive).
    ///   - If `Some(key)`, represents the upper bound that was requested
    ///   - If `None`, indicates no upper bound was specified
    ///   - Note: The proof may contain fewer keys than requested if the peer limited the response
    ///
    /// * `root_hash` - The expected root hash of the trie. The constructed partial trie
    ///   from the proof must produce this exact hash for the proof to be valid.
    ///
    /// * `proof` - The range proof to verify, containing:
    ///   - Start proof: Merkle proof for the lower boundary
    ///   - End proof: Merkle proof for the upper boundary
    ///   - Key-value pairs: The actual entries within the range
    ///
    /// # Returns
    ///
    /// Returns the constructed [`Merkle<Arc<ImmutableProposal>, _>`] that was built and
    /// verified from the proof data, if the proof is valid.
    ///
    /// # Verification Process
    ///
    /// The verification follows these steps:
    /// 1. **Structural validation**: Verify the proof structure is well-formed
    ///    - Check that start/end proofs are consistent with the key range
    ///    - Ensure key-value pairs are in the correct order
    ///    - Validate that boundary proofs correctly bound the key-value pairs
    ///
    /// 2. **Proposal construction**: Build a proposal trie containing the proof data
    ///    - Insert all key-value pairs from the proof
    ///    - Incorporate nodes from the start and end proofs
    ///    - Handle edge cases for empty ranges or partial proofs
    ///
    /// 3. **Hash verification**: Compute the root hash of the constructed proposal
    ///    - The computed hash must match the provided `root_hash` exactly
    ///    - Any mismatch indicates an invalid or tampered proof
    ///
    /// # Errors
    ///
    /// * [`api::Error::ProofError`] - The proof structure is malformed or inconsistent
    /// * [`api::Error::InvalidRange`] - The proof boundaries don't match the requested range
    /// * [`api::Error::ParentNotLatest`] - The computed root hash doesn't match the expected hash
    /// * [`api::Error`] - Other errors during proposal construction or verification
    ///
    /// # Examples
    ///
    /// ```ignore
    /// // Verify a range proof received from a peer
    /// let verified_proposal = merkle.verify_range_proof(
    ///     Some(b"alice"),
    ///     Some(b"charlie"),
    ///     &expected_root_hash,
    ///     &range_proof
    /// )?;
    /// ```
    ///
    /// # Implementation Notes
    ///
    /// - Structural validation is performed first to avoid expensive proposal construction
    ///   for obviously invalid proofs
    /// - The method is designed to handle partial proofs where the peer provides less
    ///   data than requested, which is common for large ranges
    /// - Future optimization: Consider caching partial verification results for
    ///   incremental range proof verification
    pub fn verify_range_proof(
        &self,
        _first_key: Option<impl KeyType>,
        _last_key: Option<impl KeyType>,
        _root_hash: &TrieHash,
        _proof: &RangeProof<impl KeyType, impl ValueType, impl ProofCollection>,
    ) -> Result<(), api::Error> {
        todo!()
    }

    pub(crate) fn path_iter<'a>(
        &self,
        key: &'a [u8],
    ) -> Result<PathIterator<'_, 'a, T>, FileIoError> {
        PathIterator::new(&self.nodestore, key)
    }

    /// Returns an iterator that visits every node in the trie in order starting from the root.
    pub fn node_iter(&self) -> MerkleNodeIter<'_, T> {
        MerkleNodeIter::from(&self.nodestore)
    }

    pub fn key_value_iter(&self) -> MerkleKeyValueIter<'_, T> {
        MerkleKeyValueIter::from(&self.nodestore)
    }

    pub(super) fn key_value_iter_from_key<'a>(
        &'a self,
        key: &'a [u8],
    ) -> MerkleKeyValueIter<'a, T> {
        MerkleKeyValueIter::from_slice(&self.nodestore, key)
    }

    /// Generate a cryptographic proof for a range of key-value pairs in the Merkle trie.
    ///
    /// This method creates a range proof that can be used to verify the existence (or absence)
    /// of a contiguous set of keys within the trie. The proof includes boundary proofs and
    /// the actual key-value pairs within the specified range.
    ///
    /// # Parameters
    ///
    /// * `start_key` - The optional lower bound of the range (inclusive).
    ///   - If `Some(key)`, the proof will include all keys >= this key
    ///   - If `None`, the proof starts from the beginning of the trie
    ///
    /// * `end_key` - The optional upper bound of the range (inclusive).
    ///   - If `Some(key)`, the proof will include all keys <= this key
    ///   - If `None`, the proof extends to the end of the trie
    ///
    /// * `limit` - Optional maximum number of key-value pairs to include in the proof.
    ///   - If `Some(n)`, at most n key-value pairs will be included
    ///   - If `None`, all key-value pairs in the range will be included
    ///   - Useful for paginating through large ranges
    ///   - **NOTE**: avalanchego's limit is based on the entire packet size and not the
    ///     number of key-value pairs. Currently, we only limit by the number of pairs.
    ///
    /// # Returns
    ///
    /// A `FrozenRangeProof` containing:
    /// - Start proof: Merkle proof for the first key in the range
    /// - End proof: Merkle proof for the last key in the range
    /// - Key-value pairs: All entries within the specified bounds (up to the limit)
    ///
    /// # Errors
    ///
    /// * `api::Error::InvalidRange` - If `start_key` > `end_key` when both are provided.
    ///   This ensures the range bounds are logically consistent.
    ///
    /// * `api::Error::RangeProofOnEmptyTrie` - If the trie is empty and the caller
    ///   requests a proof for the entire trie (both `start_key` and `end_key` are `None`).
    ///   This prevents generating meaningless proofs for non-existent data.
    ///
    /// * `api::Error` - Various other errors can occur during proof generation, such as:
    ///   - I/O errors when reading nodes from storage
    ///   - Corrupted trie structure
    ///   - Invalid node references
    ///
    /// # Examples
    ///
    /// ```ignore
    /// // Prove all keys between "alice" and "charlie"
    /// let proof = merkle.range_proof(
    ///     Some(b"alice"),
    ///     Some(b"charlie"),
    ///     None
    /// ).await?;
    ///
    /// // Prove the first 100 keys starting from "alice"
    /// let proof = merkle.range_proof(
    ///     Some(b"alice"),
    ///     None,
    ///     Some(NonZeroUsize::new(100).unwrap())
    /// ).await?;
    ///
    /// // Prove that no keys exist in a range
    /// let proof = merkle.range_proof(
    ///     Some(b"aardvark"),
    ///     Some(b"aaron"),
    ///     None
    /// ).await?;
    /// ```
    pub(super) fn range_proof(
        &self,
        start_key: Option<&[u8]>,
        end_key: Option<&[u8]>,
        limit: Option<NonZeroUsize>,
    ) -> Result<FrozenRangeProof, api::Error> {
        if let (Some(k1), Some(k2)) = (&start_key, &end_key) {
            if k1 > k2 {
                return Err(api::Error::InvalidRange {
                    start_key: k1.to_vec().into(),
                    end_key: k2.to_vec().into(),
                });
            }
        }

        let mut iter = match start_key {
            Some(key) => self.key_value_iter_from_key(key),
            None => self.key_value_iter(),
        };

        // fetch the first key from the stream
        let first_result = iter.next();

        // transpose the Option<Result<T, E>> to Result<Option<T>, E>
        // If this is an error, the ? operator will return it
        let Some((first_key, first_value)) = first_result.transpose()? else {
            // The trie is empty.
            if start_key.is_none() && end_key.is_none() {
                // The caller requested a range proof over an empty trie.
                return Err(api::Error::RangeProofOnEmptyTrie);
            }

            let start_proof = start_key
                .map(|start_key| self.prove(start_key))
                .transpose()?
                .unwrap_or_default();

            let end_proof = end_key
                .map(|end_key| self.prove(end_key))
                .transpose()?
                .unwrap_or_default();

            return Ok(RangeProof::new(start_proof, end_proof, Box::new([])));
        };

        let start_proof = self.prove(&first_key)?;
        let limit = limit.map(|old_limit| old_limit.get().saturating_sub(1));

        let mut key_values = vec![(first_key, first_value)];

        // we stop iterating if either we hit the limit or the key returned was larger
        // than the largest key requested
        key_values.try_extend(iter.take(limit.unwrap_or(usize::MAX)).take_while(|kv| {
            // no last key asked for, so keep going
            let Some(last_key) = end_key else {
                return true;
            };

            // return the error if there was one
            let Ok(kv) = kv else {
                return true;
            };

            // keep going if the key returned is less than the last key requested
            *kv.0 <= *last_key
        }))?;

        let end_proof = key_values
            .last()
            .map(|(largest_key, _)| self.prove(largest_key))
            .transpose()?
            .unwrap_or_default();

        Ok(RangeProof::new(
            start_proof,
            end_proof,
            key_values.into_boxed_slice(),
        ))
    }

    pub(crate) fn get_value(&self, key: &[u8]) -> Result<Option<Value>, FileIoError> {
        let Some(node) = self.get_node(key)? else {
            return Ok(None);
        };
        Ok(node.value().map(|v| v.to_vec().into_boxed_slice()))
    }

    pub(crate) fn get_node(&self, key: &[u8]) -> Result<Option<SharedNode>, FileIoError> {
        let Some(root) = self.try_root()? else {
            return Ok(None);
        };

        let key = Path::from_nibbles_iterator(NibblesIterator::new(key));
        get_helper(&self.nodestore, &root, &key)
    }
}

impl<T: HashedNodeReader> Merkle<T> {
    /// Dump a node, recursively, to a dot file
    pub(crate) fn dump_node<W: std::io::Write + ?Sized>(
        &self,
        node: &MaybePersistedNode,
        hash: Option<&HashType>,
        seen: &mut HashSet<String>,
        writer: &mut W,
    ) -> Result<(), FileIoError> {
        writeln!(writer, "  {node}[label=\"{node}")
            .map_err(Error::other)
            .map_err(|e| FileIoError::new(e, None, 0, None))?;
        if let Some(hash) = hash {
            write!(writer, " H={hash:.6?}")
                .map_err(Error::other)
                .map_err(|e| FileIoError::new(e, None, 0, None))?;
        }

        match &*node.as_shared_node(&self.nodestore)? {
            Node::Branch(b) => {
                write_attributes!(writer, b, &b.value.clone().unwrap_or(Box::from([])));
                writeln!(writer, "\"]")
                    .map_err(|e| FileIoError::from_generic_no_file(e, "write branch"))?;
                for (childidx, child) in b.children.iter().enumerate() {
                    let (child, child_hash) = match child {
                        None => continue,
                        Some(node) => (node.as_maybe_persisted_node(), node.hash()),
                    };

                    let inserted = seen.insert(format!("{child}"));
                    if inserted {
                        writeln!(writer, "  {node} -> {child}[label=\"{childidx:x}\"]")
                            .map_err(|e| FileIoError::from_generic_no_file(e, "write branch"))?;
                        self.dump_node(&child, child_hash, seen, writer)?;
                    } else {
                        // We have already seen this child, which shouldn't happen.
                        // Indicate this with a red edge.
                        writeln!(
                            writer,
                            "  {node} -> {child}[label=\"{childidx:x} (dup)\" color=red]"
                        )
                        .map_err(|e| FileIoError::from_generic_no_file(e, "write branch"))?;
                    }
                }
            }
            Node::Leaf(l) => {
                write_attributes!(writer, l, &l.value);
                writeln!(writer, "\" shape=rect]")
                    .map_err(|e| FileIoError::from_generic_no_file(e, "write leaf"))?;
            }
        }
        Ok(())
    }

    /// Dump the trie to a dot file.
    ///
    /// This function is primarily used in testing, but also has an API implementation
    ///
    /// Dot files can be rendered using `dot -Tpng -o output.png input.dot`
    /// or online at <https://dreampuf.github.io/GraphvizOnline>
    ///
    /// # Errors
    ///
    /// Returns an error if writing to the output writer fails.
    pub(crate) fn dump<W: std::io::Write + ?Sized>(&self, writer: &mut W) -> Result<(), Error> {
        let root = self.nodestore.root_as_maybe_persisted_node();

        writeln!(writer, "digraph Merkle {{\n  rankdir=LR;").map_err(Error::other)?;
        if let (Some(root), Some(root_hash)) = (root, self.nodestore.root_hash()) {
            writeln!(writer, " root -> {root}")
                .map_err(Error::other)
                .map_err(|e| FileIoError::new(e, None, 0, None))
                .map_err(Error::other)?;
            let mut seen = HashSet::new();
            self.dump_node(&root, Some(&root_hash.into_hash_type()), &mut seen, writer)
                .map_err(Error::other)?;
        }
        writeln!(writer, "}}")
            .map_err(Error::other)
            .map_err(|e| FileIoError::new(e, None, 0, None))
            .map_err(Error::other)?;

        Ok(())
    }
    /// Dump the trie to a string (for testing or logging).
    ///
    /// This is a convenience function for tests that need the dot output as a string.
    ///
    /// # Errors
    ///
    /// Returns an error if writing to the string fails.
    pub(crate) fn dump_to_string(&self) -> Result<String, Error> {
        let mut buffer = Vec::new();
        self.dump(&mut buffer)?;
        String::from_utf8(buffer).map_err(Error::other)
    }
}

impl<F: Parentable, S: ReadableStorage> Merkle<NodeStore<F, S>> {
    /// Forks the current Merkle trie into a new mutable proposal.
    ///
    /// ## Errors
    ///
    /// Returns an error if the nodestore cannot be created. See [`NodeStore::new`].
    pub fn fork(&self) -> Result<Merkle<NodeStore<MutableProposal, S>>, FileIoError> {
        NodeStore::new(&self.nodestore).map(Into::into)
    }
}

impl<S: ReadableStorage> TryFrom<Merkle<NodeStore<MutableProposal, S>>>
    for Merkle<NodeStore<Arc<ImmutableProposal>, S>>
{
    type Error = FileIoError;
    fn try_from(m: Merkle<NodeStore<MutableProposal, S>>) -> Result<Self, Self::Error> {
        Ok(Merkle {
            nodestore: m.nodestore.try_into()?,
        })
    }
}

#[expect(clippy::missing_errors_doc)]
impl<S: ReadableStorage> Merkle<NodeStore<MutableProposal, S>> {
    /// Convert a merkle backed by an `MutableProposal` into an `ImmutableProposal`
    ///
    /// This function is only used in benchmarks and tests
    ///
    /// ## Panics
    ///
    /// Panics if the conversion fails. This should only be used in tests or benchmarks.
    #[must_use]
    pub fn hash(self) -> Merkle<NodeStore<Arc<ImmutableProposal>, S>> {
        self.try_into().expect("failed to convert")
    }

    /// Map `key` to `value` in the trie.
    /// Each element of key is 2 nibbles.
    pub fn insert(&mut self, key: &[u8], value: Value) -> Result<(), FileIoError> {
        let key = Path::from_nibbles_iterator(NibblesIterator::new(key));

        let root = self.nodestore.root_mut();

        let Some(root_node) = std::mem::take(root) else {
            // The trie is empty. Create a new leaf node with `value` and set
            // it as the root.
            let root_node = Node::Leaf(LeafNode {
                partial_path: key,
                value,
            });
            *root = root_node.into();
            return Ok(());
        };

        let root_node = self.insert_helper(root_node, key.as_ref(), value)?;
        *self.nodestore.root_mut() = root_node.into();
        Ok(())
    }

    /// Map `key` to `value` into the subtrie rooted at `node`.
    /// Each element of `key` is 1 nibble.
    /// Returns the new root of the subtrie.
    pub fn insert_helper(
        &mut self,
        mut node: Node,
        key: &[u8],
        value: Value,
    ) -> Result<Node, FileIoError> {
        // 4 possibilities for the position of the `key` relative to `node`:
        // 1. The node is at `key`
        // 2. The key is above the node (i.e. its ancestor)
        // 3. The key is below the node (i.e. its descendant)
        // 4. Neither is an ancestor of the other
        let path_overlap = PrefixOverlap::from(key, node.partial_path().as_ref());

        let unique_key = path_overlap.unique_a;
        let unique_node = path_overlap.unique_b;

        match (
            unique_key
                .split_first()
                .map(|(index, path)| (*index, path.into())),
            unique_node
                .split_first()
                .map(|(index, path)| (*index, path.into())),
        ) {
            (None, None) => {
                // 1. The node is at `key`
                node.update_value(value);
                counter!("firewood.insert", "merkle" => "update").increment(1);
                Ok(node)
            }
            (None, Some((child_index, partial_path))) => {
                // 2. The key is above the node (i.e. its ancestor)
                // Make a new branch node and insert the current node as a child.
                //    ...                ...
                //     |     -->          |
                //    node               key
                //                        |
                //                       node
                let mut branch = BranchNode {
                    partial_path: path_overlap.shared.into(),
                    value: Some(value),
                    children: BranchNode::empty_children(),
                };

                // Shorten the node's partial path since it has a new parent.
                node.update_partial_path(partial_path);
                set_branch_child(
                    &mut branch,
                    child_index as usize,
                    Some(Child::Node(node)),
                    "merkle::insert_helper",
                )?;
                counter!("firewood.insert", "merkle"=>"above").increment(1);

                Ok(Node::Branch(Box::new(branch)))
            }
            (Some((child_index, partial_path)), None) => {
                // 3. The key is below the node (i.e. its descendant)
                //    ...                         ...
                //     |                           |
                //    node         -->            node
                //     |                           |
                //    ... (key may be below)       ... (key is below)
                match node {
                    Node::Branch(ref mut branch) => {
                        let child = match take_branch_child(
                            branch,
                            child_index as usize,
                            "merkle::insert_helper",
                        )? {
                            None => {
                                // There is no child at this index.
                                // Create a new leaf and put it here.
                                let new_leaf = Node::Leaf(LeafNode {
                                    value,
                                    partial_path,
                                });
                                set_branch_child(
                                    branch,
                                    child_index as usize,
                                    Some(Child::Node(new_leaf)),
                                    "merkle::insert_helper",
                                )?;
                                counter!("firewood.insert", "merkle"=>"below").increment(1);
                                return Ok(node);
                            }
                            Some(Child::Node(child)) => child,
                            Some(Child::AddressWithHash(addr, _)) => {
                                self.nodestore.read_for_update(addr.into())?
                            }
                            Some(Child::MaybePersisted(maybe_persisted, _)) => {
                                self.nodestore.read_for_update(maybe_persisted.clone())?
                            }
                        };

                        let child = self.insert_helper(child, partial_path.as_ref(), value)?;
                        set_branch_child(
                            branch,
                            child_index as usize,
                            Some(Child::Node(child)),
                            "merkle::insert_helper",
                        )?;
                        Ok(node)
                    }
                    Node::Leaf(ref mut leaf) => {
                        // Turn this node into a branch node and put a new leaf as a child.
                        let mut branch = BranchNode {
                            partial_path: std::mem::replace(&mut leaf.partial_path, Path::new()),
                            value: Some(std::mem::take(&mut leaf.value)),
                            children: BranchNode::empty_children(),
                        };

                        let new_leaf = Node::Leaf(LeafNode {
                            value,
                            partial_path,
                        });

                        set_branch_child(
                            &mut branch,
                            child_index as usize,
                            Some(Child::Node(new_leaf)),
                            "merkle::insert_helper",
                        )?;

                        counter!("firewood.insert", "merkle"=>"split").increment(1);
                        Ok(Node::Branch(Box::new(branch)))
                    }
                }
            }
            (Some((key_index, key_partial_path)), Some((node_index, node_partial_path))) => {
                // 4. Neither is an ancestor of the other
                //    ...                         ...
                //     |                           |
                //    node         -->            branch
                //     |                           |    \
                //                               node   key
                // Make a branch node that has both the current node and a new leaf node as children.
                let mut branch = BranchNode {
                    partial_path: path_overlap.shared.into(),
                    value: None,
                    children: BranchNode::empty_children(),
                };

                node.update_partial_path(node_partial_path);
                set_branch_child(
                    &mut branch,
                    node_index as usize,
                    Some(Child::Node(node)),
                    "merkle::insert_helper",
                )?;

                let new_leaf = Node::Leaf(LeafNode {
                    value,
                    partial_path: key_partial_path,
                });
                set_branch_child(
                    &mut branch,
                    key_index as usize,
                    Some(Child::Node(new_leaf)),
                    "merkle::insert_helper",
                )?;

                counter!("firewood.insert", "merkle" => "split").increment(1);
                Ok(Node::Branch(Box::new(branch)))
            }
        }
    }

    /// Removes the value associated with the given `key`.
    /// Returns the value that was removed, if any.
    /// Otherwise returns `None`.
    /// Each element of `key` is 2 nibbles.
    pub fn remove(&mut self, key: &[u8]) -> Result<Option<Value>, FileIoError> {
        let key = Path::from_nibbles_iterator(NibblesIterator::new(key));

        let root = self.nodestore.root_mut();
        let Some(root_node) = std::mem::take(root) else {
            // The trie is empty. There is nothing to remove.
            counter!("firewood.remove", "prefix" => "false", "result" => "nonexistent")
                .increment(1);
            return Ok(None);
        };

        let (root_node, removed_value) = self.remove_helper(root_node, &key)?;
        *self.nodestore.root_mut() = root_node;
        if removed_value.is_some() {
            counter!("firewood.remove", "prefix" => "false", "result" => "success").increment(1);
        } else {
            counter!("firewood.remove", "prefix" => "false", "result" => "nonexistent")
                .increment(1);
        }
        Ok(removed_value)
    }

    /// Removes the value associated with the given `key` from the subtrie rooted at `node`.
    /// Returns the new root of the subtrie and the value that was removed, if any.
    /// Each element of `key` is 1 nibble.
    #[expect(clippy::too_many_lines)]
    fn remove_helper(
        &mut self,
        mut node: Node,
        key: &[u8],
    ) -> Result<(Option<Node>, Option<Value>), FileIoError> {
        // 4 possibilities for the position of the `key` relative to `node`:
        // 1. The node is at `key`
        // 2. The key is above the node (i.e. its ancestor)
        // 3. The key is below the node (i.e. its descendant)
        // 4. Neither is an ancestor of the other
        let path_overlap = PrefixOverlap::from(key, node.partial_path().as_ref());

        let unique_key = path_overlap.unique_a;
        let unique_node = path_overlap.unique_b;

        match (
            unique_key
                .split_first()
                .map(|(index, path)| (*index, Path::from(path))),
            unique_node.split_first(),
        ) {
            (_, Some(_)) => {
                // Case (2) or (4)
                Ok((Some(node), None))
            }
            (None, None) => {
                // 1. The node is at `key`
                match &mut node {
                    Node::Branch(branch) => {
                        let Some(removed_value) = branch.value.take() else {
                            // The branch has no value. Return the node as is.
                            return Ok((Some(node), None));
                        };

                        // This branch node has a value.
                        // If it has multiple children, return the node as is.
                        // Otherwise, its only child becomes the root of this subtrie.
                        let mut children_iter =
                            branch
                                .children
                                .iter_mut()
                                .enumerate()
                                .filter_map(|(index, child)| {
                                    child.as_mut().map(|child| (index, child))
                                });

                        let (child_index, child) = children_iter
                            .next()
                            .expect("branch node must have children");

                        if children_iter.next().is_some() {
                            // The branch has more than 1 child so it can't be removed.
                            Ok((Some(node), Some(removed_value)))
                        } else {
                            // The branch's only child becomes the root of this subtrie.
                            let mut child = match child {
                                Child::Node(child_node) => std::mem::take(child_node),
                                Child::AddressWithHash(addr, _) => {
                                    self.nodestore.read_for_update((*addr).into())?
                                }
                                Child::MaybePersisted(maybe_persisted, _) => {
                                    self.nodestore.read_for_update(maybe_persisted.clone())?
                                }
                            };

                            // The child's partial path is the concatenation of its (now removed) parent,
                            // its (former) child index, and its partial path.
                            match child {
                                Node::Branch(ref mut child_branch) => {
                                    let partial_path = Path::from_nibbles_iterator(
                                        branch
                                            .partial_path
                                            .iter()
                                            .copied()
                                            .chain(once(child_index as u8))
                                            .chain(child_branch.partial_path.iter().copied()),
                                    );
                                    child_branch.partial_path = partial_path;
                                }
                                Node::Leaf(ref mut leaf) => {
                                    let partial_path = Path::from_nibbles_iterator(
                                        branch
                                            .partial_path
                                            .iter()
                                            .copied()
                                            .chain(once(child_index as u8))
                                            .chain(leaf.partial_path.iter().copied()),
                                    );
                                    leaf.partial_path = partial_path;
                                }
                            }

                            let node_partial_path =
                                std::mem::replace(&mut branch.partial_path, Path::new());

                            let partial_path = Path::from_nibbles_iterator(
                                branch
                                    .partial_path
                                    .iter()
                                    .chain(once(&(child_index as u8)))
                                    .chain(node_partial_path.iter())
                                    .copied(),
                            );

                            node.update_partial_path(partial_path);

                            Ok((Some(child), Some(removed_value)))
                        }
                    }
                    Node::Leaf(leaf) => {
                        let removed_value = std::mem::take(&mut leaf.value);
                        Ok((None, Some(removed_value)))
                    }
                }
            }
            (Some((child_index, child_partial_path)), None) => {
                // 3. The key is below the node (i.e. its descendant)
                match node {
                    // we found a non-matching leaf node, so the value does not exist
                    Node::Leaf(_) => Ok((Some(node), None)),
                    Node::Branch(ref mut branch) => {
                        let child = match take_branch_child(
                            branch,
                            child_index as usize,
                            "merkle::remove_helper",
                        )? {
                            None => {
                                return Ok((Some(node), None));
                            }
                            Some(Child::Node(node)) => node,
                            Some(Child::AddressWithHash(addr, _)) => {
                                self.nodestore.read_for_update(addr.into())?
                            }
                            Some(Child::MaybePersisted(maybe_persisted, _)) => {
                                self.nodestore.read_for_update(maybe_persisted.clone())?
                            }
                        };

                        let (child, removed_value) =
                            self.remove_helper(child, child_partial_path.as_ref())?;

                        if let Some(child) = child {
                            set_branch_child(
                                branch,
                                child_index as usize,
                                Some(Child::Node(child)),
                                "merkle::remove_helper",
                            )?;
                        } else {
                            set_branch_child(
                                branch,
                                child_index as usize,
                                None,
                                "merkle::remove_helper",
                            )?;
                        }

                        let mut children_iter =
                            branch
                                .children
                                .iter_mut()
                                .enumerate()
                                .filter_map(|(index, child)| {
                                    child.as_mut().map(|child| (index, child))
                                });

                        let Some((child_index, child)) = children_iter.next() else {
                            // The branch has no children. Turn it into a leaf.
                            let leaf = Node::Leaf(LeafNode {
                                    value: branch.value.take().expect(
                                        "branch node must have a value if it previously had only 1 child",
                                    ),
                                    partial_path: std::mem::take(&mut branch.partial_path),
                                });
                            return Ok((Some(leaf), removed_value));
                        };

                        // if there is more than one child or the branch has a value, return it
                        if branch.value.is_some() || children_iter.next().is_some() {
                            return Ok((Some(node), removed_value));
                        }

                        // The branch has only 1 child. Remove the branch and return the child.
                        let mut child = match child {
                            Child::Node(child_node) => std::mem::replace(
                                child_node,
                                Node::Leaf(LeafNode {
                                    value: Box::default(),
                                    partial_path: Path::new(),
                                }),
                            ),
                            Child::AddressWithHash(addr, _) => {
                                self.nodestore.read_for_update((*addr).into())?
                            }
                            Child::MaybePersisted(maybe_persisted, _) => {
                                self.nodestore.read_for_update(maybe_persisted.clone())?
                            }
                        };

                        // The child's partial path is the concatenation of its (now removed) parent,
                        // its (former) child index, and its partial path.
                        let child_partial_path = branch
                            .partial_path
                            .with_appended_nibble(child_index as u8)
                            .with_appended_iter(child.partial_path().iter().copied());
                        child.update_partial_path(child_partial_path);

                        Ok((Some(child), removed_value))
                    }
                }
            }
        }
    }

    /// Removes any key-value pairs with keys that have the given `prefix`.
    /// Returns the number of key-value pairs removed.
    pub fn remove_prefix(&mut self, prefix: &[u8]) -> Result<usize, FileIoError> {
        let prefix = Path::from_nibbles_iterator(NibblesIterator::new(prefix));

        let root = self.nodestore.root_mut();
        let Some(root_node) = std::mem::take(root) else {
            // The trie is empty. There is nothing to remove.
            counter!("firewood.remove", "prefix" => "true", "result" => "nonexistent").increment(1);
            return Ok(0);
        };

        let mut deleted = 0;
        let root_node = self.remove_prefix_helper(root_node, &prefix, &mut deleted)?;
        counter!("firewood.remove", "prefix" => "true", "result" => "success")
            .increment(deleted as u64);
        *self.nodestore.root_mut() = root_node;
        Ok(deleted)
    }

    fn remove_prefix_helper(
        &mut self,
        mut node: Node,
        key: &[u8],
        deleted: &mut usize,
    ) -> Result<Option<Node>, FileIoError> {
        // 4 possibilities for the position of the `key` relative to `node`:
        // 1. The node is at `key`, in which case we need to delete this node and all its children.
        // 2. The key is above the node (i.e. its ancestor), so the parent needs to be restructured (TODO).
        // 3. The key is below the node (i.e. its descendant), so continue traversing the trie.
        // 4. Neither is an ancestor of the other, in which case there's no work to do.
        let path_overlap = PrefixOverlap::from(key, node.partial_path().as_ref());

        let unique_key = path_overlap.unique_a;
        let unique_node = path_overlap.unique_b;

        let key_split = unique_key
            .split_first()
            .map(|(index, path)| (*index, Path::from(path)));
        let node_split = unique_node
            .split_first()
            .map(|(index, path)| (*index, Path::from(path)));

        match (key_split, node_split) {
            (None, None) => {
                // 1. The node is at `key`
                match &mut node {
                    Node::Branch(branch) => {
                        if branch.value.is_some() {
                            // a KV pair was in the branch itself
                            *deleted = deleted.saturating_add(1);
                        }
                        self.delete_children(branch, deleted)?;
                    }
                    Node::Leaf(_) => {
                        // the prefix matched only a leaf, so we remove it and indicate only one item was removed
                        *deleted = deleted.saturating_add(1);
                    }
                }
                Ok(None)
            }
            (None, Some((_node_index, _node_partial_path))) => {
                // 2. The key is above the node (i.e. its ancestor)
                match node {
                    Node::Leaf(_) => {
                        *deleted = deleted.saturating_add(1);
                        Ok(None)
                    }
                    Node::Branch(mut branch) => {
                        if branch.value.is_some() {
                            *deleted = deleted.saturating_add(1);
                        }

                        for child in branch.children.iter_mut() {
                            if let Some(child) = child.take() {
                                let child_node = match child {
                                    Child::Node(node) => node,
                                    Child::AddressWithHash(addr, _) => {
                                        self.nodestore.read_for_update(addr.into())?
                                    }
                                    Child::MaybePersisted(maybe_persisted, _) => {
                                        self.nodestore.read_for_update(maybe_persisted)?
                                    }
                                };

                                let _ = self.remove_prefix_helper(child_node, &[], deleted)?;
                            }
                        }

                        Ok(None)
                    }
                }
            }
            (Some((child_index, child_partial_path)), None) => {
                // 3. The key is below the node (i.e. its descendant)
                match node {
                    Node::Leaf(_) => Ok(Some(node)),
                    Node::Branch(ref mut branch) => {
                        let child = match take_branch_child(
                            branch,
                            child_index as usize,
                            "merkle::remove_prefix_helper",
                        )? {
                            None => {
                                return Ok(Some(node));
                            }
                            Some(Child::Node(node)) => node,
                            Some(Child::AddressWithHash(addr, _)) => {
                                self.nodestore.read_for_update(addr.into())?
                            }
                            Some(Child::MaybePersisted(maybe_persisted, _)) => {
                                self.nodestore.read_for_update(maybe_persisted.clone())?
                            }
                        };

                        let child =
                            self.remove_prefix_helper(child, child_partial_path.as_ref(), deleted)?;

                        if let Some(child) = child {
                            set_branch_child(
                                branch,
                                child_index as usize,
                                Some(Child::Node(child)),
                                "merkle::remove_prefix_helper",
                            )?;
                        } else {
                            set_branch_child(
                                branch,
                                child_index as usize,
                                None,
                                "merkle::remove_prefix_helper",
                            )?;
                        }

                        let mut children_iter =
                            branch
                                .children
                                .iter_mut()
                                .enumerate()
                                .filter_map(|(index, child)| {
                                    child.as_mut().map(|child| (index, child))
                                });

                        let Some((child_index, child)) = children_iter.next() else {
                            // The branch has no children. Turn it into a leaf.
                            let leaf = Node::Leaf(LeafNode {
                                    value: branch.value.take().expect(
                                        "branch node must have a value if it previously had only 1 child",
                                    ),
                                    partial_path: std::mem::take(&mut branch.partial_path),
                                });
                            return Ok(Some(leaf));
                        };

                        // if there is more than one child or the branch has a value, return it
                        if branch.value.is_some() || children_iter.next().is_some() {
                            return Ok(Some(node));
                        }

                        // The branch has only 1 child. Remove the branch and return the child.
                        let mut child = match child {
                            Child::Node(child_node) => std::mem::replace(
                                child_node,
                                Node::Leaf(LeafNode {
                                    value: Box::default(),
                                    partial_path: Path::new(),
                                }),
                            ),
                            Child::AddressWithHash(addr, _) => {
                                self.nodestore.read_for_update((*addr).into())?
                            }
                            Child::MaybePersisted(maybe_persisted, _) => {
                                self.nodestore.read_for_update(maybe_persisted.clone())?
                            }
                        };

                        // The child's partial path is the concatenation of its (now removed) parent,
                        // its (former) child index, and its partial path.
                        let child_partial_path = branch
                            .partial_path
                            .with_appended_nibble(child_index as u8)
                            .with_appended_iter(child.partial_path().iter().copied());
                        child.update_partial_path(child_partial_path);

                        Ok(Some(child))
                    }
                }
            }
            (Some(_), Some(_)) => {
                // Case (4). Neither is an ancestor of the other.
                Ok(Some(node))
            }
        }
    }

    /// Recursively deletes all children of a branch node.
    fn delete_children(
        &mut self,
        branch: &mut BranchNode,
        deleted: &mut usize,
    ) -> Result<(), FileIoError> {
        if branch.value.is_some() {
            // a KV pair was in the branch itself
            *deleted = deleted.saturating_add(1);
        }
        for children in &mut branch.children {
            // read the child node
            let child_node = match children.take() {
                Some(Child::Node(node)) => Some(node),
                Some(Child::AddressWithHash(addr, _)) => {
                    Some(self.nodestore.read_for_update(addr.into())?)
                }
                Some(Child::MaybePersisted(maybe_persisted, _)) => {
                    Some(self.nodestore.read_for_update(maybe_persisted)?)
                }
                None => None,
            };

            let Some(child_node) = child_node else {
                continue;
            };

            match child_node {
                Node::Branch(mut child_branch) => {
                    self.delete_children(child_branch.as_mut(), deleted)?;
                }
                Node::Leaf(_) => {
                    *deleted = deleted.saturating_add(1);
                }
            }
        }
        Ok(())
    }
}

/// Returns an iterator where each element is the result of combining
/// 2 nibbles of `nibbles`. If `nibbles` is odd length, panics in
/// debug mode and drops the final nibble in release mode.
pub fn nibbles_to_bytes_iter(nibbles: &[u8]) -> impl Iterator<Item = u8> + '_ {
    debug_assert_eq!(nibbles.len() & 1, 0);
    #[expect(clippy::indexing_slicing)]
    nibbles.chunks_exact(2).map(|p| (p[0] << 4) | p[1])
}

/// The [`PrefixOverlap`] type represents the _shared_ and _unique_ parts of two potentially overlapping slices.
/// As the type-name implies, the `shared` property only constitues a shared *prefix*.
/// The `unique_*` properties, [`unique_a`][`PrefixOverlap::unique_a`] and [`unique_b`][`PrefixOverlap::unique_b`]
/// are set based on the argument order passed into the [`from`][`PrefixOverlap::from`] constructor.
#[derive(Debug)]
struct PrefixOverlap<'a, T> {
    shared: &'a [T],
    unique_a: &'a [T],
    unique_b: &'a [T],
}

impl<'a, T: PartialEq> PrefixOverlap<'a, T> {
    fn from(a: &'a [T], b: &'a [T]) -> Self {
        let split_index = a
            .iter()
            .zip(b)
            .position(|(a, b)| *a != *b)
            .unwrap_or_else(|| std::cmp::min(a.len(), b.len()));

        let (shared, unique_a) = a.split_at(split_index);
        let unique_b = b.get(split_index..).expect("");

        Self {
            shared,
            unique_a,
            unique_b,
        }
    }
}
