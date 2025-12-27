// Copyright (C) 2023, Ava Labs, Inc. All rights reserved.
// See the file LICENSE.md for licensing terms.

#![allow(clippy::expect_used)] // Hash walkers expect valid persisted state and bail loudly on corruption.

//! # Hash Module
//!
//! This module contains all node hashing functionality for the nodestore, including
//! specialized support for Ethereum-compatible hash processing.

#[cfg(feature = "ethhash")]
use crate::hashednode::MissingChildHashError;
use crate::hashednode::{hash_node, HashedNodeRef};
use crate::linear::FileIoError;
use crate::logger::trace;
use crate::node::Node;
#[cfg(feature = "ethhash")]
use crate::Children;
#[cfg(feature = "ethhash")]
use crate::{firewood_counter, TrieError};
use crate::{
    AreaIndex, Child, HashType, MaybePersistedNode, NodeStore, Path, ReadableStorage, SharedNode,
};

use super::NodeReader;

use std::convert::TryFrom;
use std::ops::{Deref, DerefMut};

/// Wrapper around a path that makes sure we truncate what gets extended to the path after it goes out of scope
/// This allows the same memory space to be reused for different path prefixes
#[derive(Debug)]
struct PathGuard<'a> {
    path: &'a mut Path,
    original_length: usize,
}

impl<'a> PathGuard<'a> {
    fn new(path: &'a mut PathGuard<'_>) -> Self {
        Self {
            original_length: path.0.len(),
            path: &mut path.path,
        }
    }

    fn from_path(path: &'a mut Path) -> Self {
        Self {
            original_length: path.0.len(),
            path,
        }
    }
}

impl Drop for PathGuard<'_> {
    fn drop(&mut self) {
        self.path.0.truncate(self.original_length);
    }
}

impl Deref for PathGuard<'_> {
    type Target = Path;
    fn deref(&self) -> &Self::Target {
        self.path
    }
}

impl DerefMut for PathGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.path
    }
}

fn hash_node_checked(
    node: &Node,
    path_prefix: &Path,
    context: &str,
) -> Result<HashType, FileIoError> {
    let node = HashedNodeRef::try_from(node)
        .map_err(|err| FileIoError::from_generic_no_file(err, context))?;
    Ok(hash_node(node, path_prefix))
}

/// Classified children for ethereum hash processing
#[cfg(feature = "ethhash")]
pub(super) struct ClassifiedChildren<'a> {
    pub(super) unhashed: Vec<(usize, Node)>,
    pub(super) hashed: Vec<(usize, (MaybePersistedNode, &'a mut HashType))>,
}

impl<T, S: ReadableStorage> NodeStore<T, S>
where
    NodeStore<T, S>: NodeReader,
{
    /// Helper function to classify children for ethereum hash processing
    /// We have some special cases based on the number of children
    /// and whether they are hashed or unhashed, so we need to classify them.
    #[cfg(feature = "ethhash")]
    pub(super) fn ethhash_classify_children<'a>(
        &self,
        children: &'a mut Children<Child>,
    ) -> ClassifiedChildren<'a> {
        children.iter_mut().enumerate().fold(
            ClassifiedChildren {
                unhashed: Vec::new(),
                hashed: Vec::new(),
            },
            |mut acc, (idx, child)| {
                match child {
                    None => {}
                    Some(Child::AddressWithHash(a, h)) => {
                        // Convert address to MaybePersistedNode
                        let maybe_persisted_node = MaybePersistedNode::from(*a);
                        acc.hashed.push((idx, (maybe_persisted_node, h)));
                    }
                    Some(Child::Node(node)) => acc.unhashed.push((idx, node.clone())),
                    Some(Child::MaybePersisted(maybe_persisted, h)) => {
                        // For MaybePersisted, we need to get the address if it's persisted
                        if let Some(addr) = maybe_persisted.as_linear_address() {
                            let maybe_persisted_node = MaybePersistedNode::from(addr);
                            acc.hashed.push((idx, (maybe_persisted_node, h)));
                        } else {
                            // If not persisted, we need to get the node to hash it
                            let node = maybe_persisted
                                .as_shared_node(&self)
                                .expect("will never fail for unpersisted nodes");
                            acc.unhashed.push((idx, node.deref().clone()));
                        }
                    }
                }
                acc
            },
        )
    }

    /// Hashes the given `node` and the subtree rooted at it.
    /// Returns the hashed node and its hash.
    pub(super) fn hash_helper(
        #[cfg(feature = "ethhash")] &self,
        node: Node,
    ) -> Result<(MaybePersistedNode, HashType, usize), FileIoError> {
        let mut root_path = Path::new();
        #[cfg(not(feature = "ethhash"))]
        let res = Self::hash_helper_inner(node, PathGuard::from_path(&mut root_path))?;
        #[cfg(feature = "ethhash")]
        let res = self.hash_helper_inner(node, PathGuard::from_path(&mut root_path), None)?;
        Ok(res)
    }

    /// Recursive helper that hashes the given `node` and the subtree rooted at it.
    /// This function takes a mut `node` to update the hash in place.
    /// The `path_prefix` is also mut because we will extend it to the path of the child we are hashing in recursive calls - it will be restored after the recursive call returns.
    /// The `num_siblings` is the number of children of the parent node, which includes this node.
    fn hash_helper_inner(
        #[cfg(feature = "ethhash")] &self,
        mut node: Node,
        mut path_prefix: PathGuard<'_>,
        #[cfg(feature = "ethhash")] fake_root_extra_nibble: Option<u8>,
    ) -> Result<(MaybePersistedNode, HashType, usize), FileIoError> {
        // If this is a branch, find all unhashed children and recursively hash them.
        trace!("hashing {node:?} at {path_prefix:?}");
        let mut nodes_processed = 1usize; // Count this node
        if let Node::Branch(ref mut b) = node {
            // special case code for ethereum hashes at the account level
            #[cfg(feature = "ethhash")]
            let make_fake_root = if path_prefix.0.len().saturating_add(b.partial_path.0.len()) == 64
            {
                // looks like we're at an account branch
                // tally up how many hashes we need to deal with
                let mut account_path = path_prefix.deref().clone();
                account_path.0.extend(b.partial_path.0.iter().copied());
                if let Some((child_idx, _)) = b.children.iter().enumerate().find(|(_, child)| {
                    matches!(
                        child,
                        Some(Child::MaybePersisted(maybe_child, _))
                            if maybe_child.as_linear_address().is_none()
                    )
                }) {
                    firewood_counter!(
                        "firewood.nodestore.ethhash.corrupt_proof",
                        "count of ethhash hashing failures detected during proof validation",
                        "reason" => "missing_address"
                    )
                    .increment(1);
                    return Err(FileIoError::from_generic_no_file(
                        TrieError::CorruptProof(format!(
                            "account branch child {child_idx} missing persisted address at path {account_path:?}"
                        )),
                        "hash_helper_inner ethhash missing address",
                    ));
                }
                let ClassifiedChildren {
                    unhashed,
                    mut hashed,
                } = self.ethhash_classify_children(&mut b.children);
                trace!("hashed {hashed:?} unhashed {unhashed:?}");
                // we were left with one hashed node that must be rehashed
                if let [(child_idx, (child_node, child_hash))] = &mut hashed[..] {
                    let Some(addr) = child_node.as_linear_address() else {
                        firewood_counter!(
                            "firewood.nodestore.ethhash.corrupt_proof",
                            "count of ethhash hashing failures detected during proof validation",
                            "reason" => "missing_address"
                        )
                        .increment(1);
                        return Err(FileIoError::from_generic_no_file(
                            TrieError::CorruptProof(format!(
                                "account branch child {child_idx} missing persisted address at path {account_path:?}"
                            )),
                            "hash_helper_inner ethhash rehash missing address",
                        ));
                    };
                    let mut hashable_node = self.read_node(addr)?.deref().clone();
                    let hash = {
                        let mut path_guard = PathGuard::new(&mut path_prefix);
                        path_guard.0.extend(b.partial_path.0.iter().copied());
                        if unhashed.is_empty() {
                            hashable_node.update_partial_path(Path::from_nibbles_iterator(
                                std::iter::once(*child_idx as u8)
                                    .chain(hashable_node.partial_path().0.iter().copied()),
                            ));
                        } else {
                            path_guard.0.push(*child_idx as u8);
                        }
                        hash_node_checked(
                            &hashable_node,
                            &path_guard,
                            "hash_helper_inner ethhash rehash",
                        )?
                    };
                    **child_hash = hash;
                }
                // handle the single-child case for an account special below
                if hashed.is_empty() {
                    match unhashed.as_slice() {
                        [] => None,
                        [single] => {
                            let Ok(nibble) = u8::try_from(single.0) else {
                                firewood_counter!(
                                    "firewood.nodestore.ethhash.corrupt_proof",
                                    "count of ethhash hashing failures detected during proof validation",
                                    "reason" => "invalid_child_index"
                                )
                                .increment(1);
                                return Err(FileIoError::from_generic_no_file(
                                    TrieError::CorruptProof(format!(
                                        "account branch child index {} out of range at path {account_path:?}",
                                        single.0
                                    )),
                                    "hash_helper_inner ethhash child index",
                                ));
                            };
                            Some(nibble)
                        }
                        multiple => {
                            firewood_counter!(
                                "firewood.nodestore.ethhash.corrupt_proof",
                                "count of ethhash hashing failures detected during proof validation",
                                "reason" => "multiple_unhashed"
                            )
                            .increment(1);
                            return Err(FileIoError::from_generic_no_file(
                                TrieError::CorruptProof(format!(
                                    "account branch at path {account_path:?} retains {} unhashed children",
                                    multiple.len()
                                )),
                                "hash_helper_inner ethhash multiple unhashed",
                            ));
                        }
                    }
                } else {
                    None
                }
            } else {
                // not a single child
                None
            };

            // branch children cases:
            // 1. 1 child, already hashed
            // 2. >1 child, already hashed,
            // 3. 1 hashed child, 1 unhashed child
            // 4. 0 hashed, 1 unhashed <-- handle child special
            // 5. 1 hashed, >0 unhashed <-- rehash case
            // 6. everything already hashed

            for (nibble, child) in b.children.iter_mut().enumerate() {
                // If this is empty or already hashed, we're done
                // Empty matches None, and non-Node types match Some(None) here, so we want
                // Some(Some(node))
                let Some(child_node) = child.as_mut().and_then(|child| child.as_mut_node()) else {
                    continue;
                };

                // remove the child from the children array, we will replace it with a hashed variant
                let child_node = std::mem::take(child_node);

                // Hash this child and update
                let (child_node, child_hash, child_count) = {
                    // we extend and truncate path_prefix to reduce memory allocations]
                    let mut child_path_prefix = PathGuard::new(&mut path_prefix);
                    child_path_prefix.0.extend(b.partial_path.0.iter().copied());
                    #[cfg(feature = "ethhash")]
                    if make_fake_root.is_none() {
                        // we don't push the nibble there is only one unhashed child and
                        // we're on an account
                        child_path_prefix.0.push(nibble as u8);
                    }
                    #[cfg(not(feature = "ethhash"))]
                    child_path_prefix.0.push(nibble as u8);
                    #[cfg(feature = "ethhash")]
                    let (child_node, child_hash, child_count) =
                        self.hash_helper_inner(child_node, child_path_prefix, make_fake_root)?;
                    #[cfg(not(feature = "ethhash"))]
                    let (child_node, child_hash, child_count) =
                        Self::hash_helper_inner(child_node, child_path_prefix)?;

                    (child_node, child_hash, child_count)
                };

                nodes_processed = nodes_processed.saturating_add(child_count);
                *child = Some(Child::MaybePersisted(child_node, child_hash));
                trace!("child now {child:?}");
            }
        }
        // At this point, we either have a leaf or a branch with all children hashed.
        // if the encoded child hash <32 bytes then we use that RLP

        #[cfg(feature = "ethhash")]
        // if we have a child that is the only child of an account branch, we will hash this child as if it
        // is a root node. This means we have to take the nibble from the parent and prefix it to the partial path
        let hash = if let Some(nibble) = fake_root_extra_nibble {
            let mut fake_root = node.clone();
            trace!("old node: {fake_root:?}");
            fake_root.update_partial_path(Path::from_nibbles_iterator(
                std::iter::once(nibble).chain(fake_root.partial_path().0.iter().copied()),
            ));
            trace!("new node: {fake_root:?}");
            hash_node_checked(&fake_root, &path_prefix, "hash_helper_inner fake root")?
        } else {
            hash_node_checked(&node, &path_prefix, "hash_helper_inner")?
        };

        #[cfg(not(feature = "ethhash"))]
        let hash = hash_node_checked(&node, &path_prefix, "hash_helper_inner")?;

        let serialized_len = node.serialized_length() as u64;
        AreaIndex::from_size(serialized_len)
            .map_err(|e| FileIoError::from_generic_no_file(e, "hash_helper_inner"))?;

        Ok((SharedNode::new(node).into(), hash, nodes_processed))
    }

    #[cfg(feature = "ethhash")]
    pub(crate) fn compute_node_ethhash(
        node: &Node,
        path_prefix: &Path,
        have_peers: bool,
    ) -> Result<HashType, MissingChildHashError> {
        if path_prefix.0.len() == 65 && !have_peers {
            // This is the special case when this node is the only child of an account
            //  - 64 nibbles for account + 1 nibble for its position in account branch node
            let mut fake_root = node.clone();
            fake_root.update_partial_path(Path::from_nibbles_iterator(
                path_prefix
                    .0
                    .last()
                    .into_iter()
                    .chain(fake_root.partial_path().0.iter())
                    .copied(),
            ));
            let node = HashedNodeRef::try_from(&fake_root)?;
            Ok(hash_node(node, path_prefix))
        } else {
            let node = HashedNodeRef::try_from(node)?;
            Ok(hash_node(node, path_prefix))
        }
    }
}
