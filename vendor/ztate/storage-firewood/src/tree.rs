use std::fmt;

use crate::kv::Hash;
use serde::{Deserialize, Serialize};

const TREE_HEIGHT: usize = 256;

#[inline]
fn poseidon_hash(data: &[u8]) -> Hash {
    blake3::hash(data).into()
}

fn poseidon_combine(left: &Hash, right: &Hash) -> Hash {
    let mut bytes = Vec::with_capacity(64);
    bytes.extend_from_slice(left);
    bytes.extend_from_slice(right);
    poseidon_hash(&bytes)
}

fn key_bit(key: &[u8; 32], depth: usize) -> u8 {
    let byte_index = depth / 8;
    let bit_index = 7 - (depth % 8);
    (key[byte_index] >> bit_index) & 1
}

fn default_hashes() -> [Hash; TREE_HEIGHT + 1] {
    let mut defaults = [[0u8; 32]; TREE_HEIGHT + 1];
    for level in (0..=TREE_HEIGHT).rev() {
        if level == TREE_HEIGHT {
            defaults[level] = poseidon_hash(&[]);
        } else {
            defaults[level] = poseidon_combine(&defaults[level + 1], &defaults[level + 1]);
        }
    }
    defaults
}

/// Representation of a Merkle proof along a 256 level sparse tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProof {
    pub siblings: Vec<Hash>,
    pub value: Option<Vec<u8>>,
    pub key: [u8; 32],
}

impl MerkleProof {
    pub fn new(siblings: Vec<Hash>, key: [u8; 32], value: Option<Vec<u8>>) -> Self {
        MerkleProof {
            siblings,
            value,
            key,
        }
    }
}

#[derive(Clone)]
enum NodeKind {
    Empty,
    Leaf { key: [u8; 32], value: Vec<u8> },
    Branch { left: Box<Node>, right: Box<Node> },
}

#[derive(Clone)]
struct Node {
    hash: Hash,
    kind: NodeKind,
}

impl Node {
    fn empty(default: Hash) -> Self {
        Node {
            hash: default,
            kind: NodeKind::Empty,
        }
    }

    fn leaf(key: [u8; 32], value: Vec<u8>) -> Self {
        let mut data = Vec::with_capacity(64 + value.len());
        data.extend_from_slice(&key);
        data.extend_from_slice(&value);
        Node {
            hash: poseidon_hash(&data),
            kind: NodeKind::Leaf { key, value },
        }
    }

    fn branch(left: Node, right: Node) -> Self {
        let hash = poseidon_combine(&left.hash, &right.hash);
        Node {
            hash,
            kind: NodeKind::Branch {
                left: Box::new(left),
                right: Box::new(right),
            },
        }
    }
    fn is_empty(&self) -> bool {
        matches!(self.kind, NodeKind::Empty)
    }
}

/// Sparse Merkle tree that stores values keyed by 32 byte identifiers and
/// computes Poseidon commitments over 256 levels.
#[derive(Clone)]
pub struct FirewoodTree {
    root: Node,
    defaults: [Hash; TREE_HEIGHT + 1],
}

impl fmt::Debug for FirewoodTree {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FirewoodTree")
            .field("root", &"<node>")
            .finish()
    }
}

impl FirewoodTree {
    pub fn new() -> Self {
        let defaults = default_hashes();
        FirewoodTree {
            root: Node::empty(defaults[0]),
            defaults,
        }
    }

    pub fn root(&self) -> Hash {
        self.root.hash
    }

    pub fn update(&mut self, key: &[u8], value: Vec<u8>) -> Hash {
        let key = Self::normalize_key(key);
        self.root = Self::insert(self.root.clone(), &self.defaults, 0, key, value);
        self.root.hash
    }

    pub fn delete(&mut self, key: &[u8]) -> Hash {
        let key = Self::normalize_key(key);
        self.root = Self::remove(self.root.clone(), &self.defaults, 0, key);
        self.root.hash
    }

    pub fn batch_update(&mut self, entries: &[(Vec<u8>, Vec<u8>)]) -> Hash {
        for (key, value) in entries {
            self.update(key, value.clone());
        }
        self.root.hash
    }

    pub fn get_proof(&self, key: &[u8]) -> MerkleProof {
        let key = Self::normalize_key(key);
        let mut siblings = Vec::with_capacity(TREE_HEIGHT);
        let mut node = &self.root;
        for depth in 0..TREE_HEIGHT {
            let bit = key_bit(&key, depth);
            match &node.kind {
                NodeKind::Branch { left, right } => {
                    if bit == 0 {
                        siblings.push(right.hash);
                        node = left;
                    } else {
                        siblings.push(left.hash);
                        node = right;
                    }
                }
                NodeKind::Leaf { .. } | NodeKind::Empty => {
                    siblings.extend(self.defaults[depth + 1..].iter().cloned());
                    break;
                }
            }
        }

        let value = match &node.kind {
            NodeKind::Leaf {
                key: existing_key,
                value,
            } if existing_key == &key => Some(value.clone()),
            _ => None,
        };

        MerkleProof::new(siblings, key, value)
    }

    pub fn verify_proof(root: &Hash, proof: &MerkleProof) -> bool {
        let defaults = default_hashes();
        let mut current_hash = match &proof.value {
            Some(value) => {
                let mut data = Vec::with_capacity(64 + value.len());
                data.extend_from_slice(&proof.key);
                data.extend_from_slice(value);
                poseidon_hash(&data)
            }
            None => defaults[TREE_HEIGHT],
        };

        for (idx, sibling) in proof.siblings.iter().rev().enumerate() {
            let depth = TREE_HEIGHT - 1 - idx;
            let bit = key_bit(&proof.key, depth);
            if bit == 0 {
                current_hash = poseidon_combine(&current_hash, sibling);
            } else {
                current_hash = poseidon_combine(sibling, &current_hash);
            }
        }

        current_hash == *root
    }

    fn normalize_key(key: &[u8]) -> [u8; 32] {
        if key.len() == 32 {
            let mut buf = [0u8; 32];
            buf.copy_from_slice(key);
            buf
        } else {
            poseidon_hash(key)
        }
    }

    fn insert(
        node: Node,
        defaults: &[Hash; TREE_HEIGHT + 1],
        depth: usize,
        key: [u8; 32],
        value: Vec<u8>,
    ) -> Node {
        if depth == TREE_HEIGHT {
            return Node::leaf(key, value);
        }

        match node.kind {
            NodeKind::Empty => {
                let branch = Node::branch(
                    Node::empty(defaults[depth + 1]),
                    Node::empty(defaults[depth + 1]),
                );
                FirewoodTree::insert(branch, defaults, depth, key, value)
            }
            NodeKind::Leaf {
                key: existing_key,
                value: existing_value,
            } => {
                if existing_key == key {
                    Node::leaf(key, value)
                } else {
                    FirewoodTree::split_leaf(
                        existing_key,
                        existing_value,
                        key,
                        value,
                        defaults,
                        depth,
                    )
                }
            }
            NodeKind::Branch {
                mut left,
                mut right,
            } => {
                let bit = key_bit(&key, depth);
                if bit == 0 {
                    *left = FirewoodTree::insert((*left).clone(), defaults, depth + 1, key, value);
                } else {
                    *right =
                        FirewoodTree::insert((*right).clone(), defaults, depth + 1, key, value);
                }
                Node::branch((*left).clone(), (*right).clone())
            }
        }
    }

    fn remove(node: Node, defaults: &[Hash; TREE_HEIGHT + 1], depth: usize, key: [u8; 32]) -> Node {
        match node.kind {
            NodeKind::Empty => Node::empty(defaults[depth]),
            NodeKind::Leaf {
                key: existing_key,
                value,
            } => {
                if existing_key == key {
                    Node::empty(defaults[depth])
                } else {
                    Node {
                        hash: node.hash,
                        kind: NodeKind::Leaf {
                            key: existing_key,
                            value,
                        },
                    }
                }
            }
            NodeKind::Branch {
                mut left,
                mut right,
            } => {
                let bit = key_bit(&key, depth);
                if bit == 0 {
                    *left = FirewoodTree::remove((*left).clone(), defaults, depth + 1, key);
                } else {
                    *right = FirewoodTree::remove((*right).clone(), defaults, depth + 1, key);
                }
                if left.is_empty() && right.is_empty() {
                    Node::empty(defaults[depth])
                } else {
                    Node::branch((*left).clone(), (*right).clone())
                }
            }
        }
    }

    fn split_leaf(
        existing_key: [u8; 32],
        existing_value: Vec<u8>,
        new_key: [u8; 32],
        new_value: Vec<u8>,
        defaults: &[Hash; TREE_HEIGHT + 1],
        depth: usize,
    ) -> Node {
        let mut left = Node::empty(defaults[depth + 1]);
        let mut right = Node::empty(defaults[depth + 1]);

        let existing_bit = key_bit(&existing_key, depth);
        if existing_bit == 0 {
            left = FirewoodTree::insert(left, defaults, depth + 1, existing_key, existing_value);
        } else {
            right = FirewoodTree::insert(right, defaults, depth + 1, existing_key, existing_value);
        }

        let new_bit = key_bit(&new_key, depth);
        if new_bit == 0 {
            left = FirewoodTree::insert(left, defaults, depth + 1, new_key, new_value);
        } else {
            right = FirewoodTree::insert(right, defaults, depth + 1, new_key, new_value);
        }

        Node::branch(left, right)
    }
}

impl Default for FirewoodTree {
    fn default() -> Self {
        Self::new()
    }
}
