// Copyright (C) 2025, Ava Labs, Inc. All rights reserved.
// See the file LICENSE.md for licensing terms.

#![allow(clippy::indexing_slicing)] // Tests index fixture data to validate trie boundaries.
#![allow(clippy::unwrap_used)] // Tests unwrap to fail fast when invariants are broken.
#![allow(clippy::expect_used)] // Tests call expect to surface decode regressions immediately.

#[cfg(feature = "ethhash")]
mod ethhash;
// TODO: get the hashes from merkledb and verify compatibility with branch factor 256
#[cfg(feature = "branch_factor_256")]
mod branch_factor_256;
mod proof;
mod range;
mod remove;
#[cfg(not(any(feature = "ethhash", feature = "branch_factor_256")))]
mod triehash;

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write;
use std::ops::Deref;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

use super::*;
use firewood_storage::{
    noop_storage_metrics, BranchNode, Child, Committed, FileIoError, LeafNode, LinearAddress,
    MaybePersistedNode, MemStore, MutableProposal, NodeReader, NodeStore, Path, PathIterItem,
    RootReader, SharedNode, TrieHash, TrieReader,
};
use hash_db::Hasher;
use plain_hasher::PlainHasher;
use sha2::{Digest, Sha256};

static DEBUG_ITERATION: AtomicUsize = AtomicUsize::new(usize::MAX);

#[derive(Default, Debug, Clone, PartialEq, Eq, Hash)]
struct MerkleDbSha256Hasher;

impl Hasher for MerkleDbSha256Hasher {
    type Out = [u8; 32];
    type StdHasher = PlainHasher;
    const LENGTH: usize = 32;

    #[inline]
    fn hash(x: &[u8]) -> Self::Out {
        let mut hasher = Sha256::new();
        hasher.update(x);
        hasher.finalize().into()
    }
}

fn compute_expected_root(items: &[(Vec<u8>, Vec<u8>)]) -> TrieHash {
    let mut deduped: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
    for (key, value) in items {
        deduped.insert(key.clone(), value.clone());
    }

    let merkle = init_merkle(deduped);
    merkle
        .nodestore()
        .root_hash()
        .unwrap_or_else(TrieHash::empty)
}

fn nibbles_to_key(nibbles: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity((nibbles.len() + 1) / 2);
    for chunk in nibbles.chunks(2) {
        let hi = chunk[0] & 0x0f;
        let lo = chunk.get(1).copied().unwrap_or(0) & 0x0f;
        bytes.push((hi << 4) | lo);
    }
    bytes
}

fn child_partial_path(store: &NodeStore<MutableProposal, MemStore>, child: &Child) -> Path {
    match child {
        Child::Node(node) => Path::from_iter(node.partial_path().iter().copied()),
        Child::AddressWithHash(addr, _) => {
            let shared = store
                .read_node((*addr).into())
                .expect("read persisted child");
            match shared.deref() {
                Node::Branch(branch) => Path::from_iter(branch.partial_path.iter().copied()),
                Node::Leaf(leaf) => Path::from_iter(leaf.partial_path.iter().copied()),
            }
        }
        Child::MaybePersisted(maybe, _) => {
            let shared = maybe
                .as_shared_node(store)
                .expect("load maybe persisted child");
            match shared.deref() {
                Node::Branch(branch) => Path::from_iter(branch.partial_path.iter().copied()),
                Node::Leaf(leaf) => Path::from_iter(leaf.partial_path.iter().copied()),
            }
        }
    }
}

// Returns n random key-value pairs.
fn generate_random_kvs(rng: &firewood_storage::SeededRng, n: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut kvs: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    for _ in 0..n {
        let key_len = rng.random_range(1..=4096);
        let key: Vec<u8> = (0..key_len).map(|_| rng.random()).collect();

        let val_len = rng.random_range(1..=4096);
        let val: Vec<u8> = (0..val_len).map(|_| rng.random()).collect();

        kvs.push((key, val));
    }

    kvs
}

fn into_committed(
    merkle: Merkle<NodeStore<Arc<ImmutableProposal>, MemStore>>,
    parent: &NodeStore<Committed, MemStore>,
) -> Merkle<NodeStore<Committed, MemStore>> {
    let ns = merkle.into_inner();
    ns.flush_freelist().unwrap();
    ns.flush_header().unwrap();
    let mut ns = ns.as_committed(parent);
    ns.flush_nodes().unwrap();
    ns.into()
}

pub(crate) fn init_merkle<I, K, V>(iter: I) -> Merkle<NodeStore<Committed, MemStore>>
where
    I: Clone + IntoIterator<Item = (K, V)>,
    K: AsRef<[u8]>,
    V: AsRef<[u8]>,
{
    let debug_iteration = match DEBUG_ITERATION.load(Ordering::Relaxed) {
        usize::MAX => None,
        value => Some(value),
    };
    let env_debug = std::env::var("FIREWOOD_MERKLE_DEBUG")
        .ok()
        .map(|value| matches!(value.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false);
    let debug_enabled = env_debug || debug_iteration.is_some();
    let debug_prefix = debug_iteration
        .map(|iter| format!("debug(iter={iter})"))
        .unwrap_or_else(|| "debug".to_string());
    let debug_log = |message: &str| {
        if debug_enabled {
            println!("{debug_prefix}: {message}");
        }
    };

    let format_bytes = |bytes: &[u8]| {
        const LIMIT: usize = 16;
        let mut output = String::new();
        for (index, byte) in bytes.iter().take(LIMIT).enumerate() {
            let _ = write!(output, "{byte:02x}");
            if index % 2 == 1 {
                output.push(' ');
            }
        }
        if bytes.len() > LIMIT {
            output.push_str("...");
        }
        output
    };

    let format_hash = |hash: &TrieHash| format_bytes(hash.as_ref());

    let mut expected_values: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();

    debug_log("init_merkle start");

    let memstore = Arc::new(MemStore::new(Vec::with_capacity(64 * 1024)));
    let base = Merkle::from(
        NodeStore::new_empty_committed(memstore.clone(), noop_storage_metrics()).unwrap(),
    );
    let mut merkle = base.fork().unwrap();

    for (index, (k, v)) in iter.clone().into_iter().enumerate() {
        let key = k.as_ref();
        let value = v.as_ref();

        let previous = expected_values.insert(key.to_vec(), value.to_vec());
        if debug_iteration.is_some() {
            if let Some(prev) = previous.as_ref() {
                debug_log(&format!(
                    "insert[{index}] duplicate key={} new_len={} prev_len={} prev_head={} new_head={}",
                    format_bytes(key),
                    value.len(),
                    prev.len(),
                    format_bytes(prev),
                    format_bytes(value),
                ));
            } else {
                debug_log(&format!(
                    "insert[{index}] key={} value_len={} head={}",
                    format_bytes(key),
                    value.len(),
                    format_bytes(value),
                ));
            }
        }

        merkle.insert(key, value.into()).unwrap();

        let stored = merkle.get_value(key).unwrap();
        if debug_iteration.is_some() {
            if let Some(stored) = stored.as_deref() {
                if stored != value {
                    debug_log(&format!(
                        "insert[{index}] mismatch key={} expected_head={} actual_head={} expected_len={} actual_len={}",
                        format_bytes(key),
                        format_bytes(value),
                        format_bytes(stored),
                        value.len(),
                        stored.len(),
                    ));
                    if let Some(recorded) = expected_values.get(key) {
                        debug_log(&format!(
                            "insert[{index}] recorded_value_head={} recorded_len={}",
                            format_bytes(recorded),
                            recorded.len(),
                        ));
                    }
                }
            }
        }

        assert_eq!(
            stored.as_deref(),
            Some(value),
            "Failed to insert key: {key:?}"
        );
    }
    debug_log("inserts complete");

    let mut expected_keys: Vec<&Vec<u8>> = expected_values.keys().collect();
    expected_keys.sort();

    for (index, key) in expected_keys.iter().enumerate() {
        let key_bytes = key.as_slice();
        let value = expected_values
            .get(*key)
            .expect("expected value for inserted key");

        if debug_iteration.is_some() {
            debug_log(&format!(
                "verify-pre-hash[{index}] key={}",
                format_bytes(key_bytes),
            ));
        }
        assert_eq!(
            merkle.get_value(key_bytes).unwrap().as_deref(),
            Some(value.as_slice()),
            "Failed to get key after insert: {:?}",
            key_bytes,
        );
    }

    debug_log("hashing start");
    let merkle = merkle.hash();
    debug_log("hashing complete");
    if debug_enabled {
        match merkle.nodestore.root_hash() {
            Some(root) => debug_log(&format!("hash root={}", format_hash(&root))),
            None => debug_log("hash root=<empty>"),
        }
    }

    for (index, key) in expected_keys.iter().enumerate() {
        let key_bytes = key.as_slice();
        let value = expected_values
            .get(*key)
            .expect("expected value for inserted key");

        if debug_iteration.is_some() {
            debug_log(&format!(
                "verify-post-hash[{index}] key={}",
                format_bytes(key_bytes),
            ));
        }
        assert_eq!(
            merkle.get_value(key_bytes).unwrap().as_deref(),
            Some(value.as_slice()),
            "Failed to get key after hashing: {:?}",
            key_bytes,
        );
    }

    debug_log("committing");
    let merkle = into_committed(merkle, base.nodestore());

    if debug_enabled {
        match merkle.nodestore().root_hash() {
            Some(root) => debug_log(&format!("committed root={}", format_hash(&root))),
            None => debug_log("committed root=<empty>"),
        }
    }

    for (index, key) in expected_keys.iter().enumerate() {
        let key_bytes = key.as_slice();
        let value = expected_values
            .get(*key)
            .expect("expected value for inserted key");

        if debug_iteration.is_some() {
            debug_log(&format!(
                "verify-committed[{index}] key={}",
                format_bytes(key_bytes),
            ));
        }
        assert_eq!(
            merkle.get_value(key_bytes).unwrap().as_deref(),
            Some(value.as_slice()),
            "Failed to get key after committing: {:?}",
            key_bytes,
        );
    }

    debug_log("init_merkle done");
    merkle
}

#[derive(Debug)]
struct FailingRootReader {
    root: MaybePersistedNode,
}

impl FailingRootReader {
    fn new() -> Self {
        Self {
            root: MaybePersistedNode::from(
                LinearAddress::new(1).expect("failing reader requires non-zero address"),
            ),
        }
    }

    fn io_error(&self) -> FileIoError {
        FileIoError::from_generic_no_file(
            std::io::Error::new(std::io::ErrorKind::Other, "failing root read"),
            "failing root read",
        )
    }
}

impl NodeReader for FailingRootReader {
    fn read_node(&self, _: LinearAddress) -> Result<SharedNode, FileIoError> {
        Err(self.io_error())
    }
}

impl RootReader for FailingRootReader {
    fn root_node(&self) -> Result<Option<SharedNode>, FileIoError> {
        panic!("root_node should not be called for failing reader");
    }

    fn root_as_maybe_persisted_node(&self) -> Option<MaybePersistedNode> {
        Some(self.root.clone())
    }
}

// generate pseudorandom data, but prefix it with some known data
// The number of fixed data points is 100; you specify how much random data you want
#[expect(clippy::arithmetic_side_effects)]
fn fixed_and_pseudorandom_data(
    rng: &firewood_storage::SeededRng,
    random_count: u32,
) -> HashMap<[u8; 32], [u8; 20]> {
    let mut items = HashMap::new();
    for i in 0..100_u32 {
        let mut key: [u8; 32] = [0; 32];
        let mut value: [u8; 20] = [0; 20];
        for (index, d) in i.to_be_bytes().iter().enumerate() {
            key[index] = *d;
            value[index] = *d;
        }
        items.insert(key, value);

        let mut more_key: [u8; 32] = [0; 32];
        for (index, d) in (i + 10).to_be_bytes().iter().enumerate() {
            more_key[index] = *d;
        }
        items.insert(more_key, value);
    }

    for _ in 0..random_count {
        let key = rng.random::<[u8; 32]>();
        let val = rng.random::<[u8; 20]>();
        items.insert(key, val);
    }
    items
}

fn increase_key(key: &[u8; 32]) -> [u8; 32] {
    let mut new_key = *key;
    for ch in new_key.iter_mut().rev() {
        let overflow;
        (*ch, overflow) = ch.overflowing_add(1);
        if !overflow {
            break;
        }
    }
    new_key
}

fn key_nibbles(key: &[u8]) -> Vec<u8> {
    match BranchNode::MAX_CHILDREN {
        16 => key
            .iter()
            .flat_map(|byte| [byte >> 4, byte & 0x0F])
            .collect(),
        256 => key.to_vec(),
        other => panic!("unsupported branch factor {other}"),
    }
}

fn expect_branch(item: &PathIterItem) -> &BranchNode {
    item.node
        .as_branch()
        .expect("expected path iterator item to reference a branch node")
}

fn expect_leaf(item: &PathIterItem) -> &LeafNode {
    item.node
        .as_leaf()
        .expect("expected path iterator item to reference a leaf node")
}

fn assert_branch_child_is_leaf<T: TrieReader>(
    merkle: &Merkle<T>,
    parent_key: &[u8],
    child_key: &[u8],
) {
    let parent_nibbles = key_nibbles(parent_key);
    let child_nibbles = key_nibbles(child_key);

    assert!(
        child_nibbles.starts_with(&parent_nibbles),
        "child key {child_key:?} does not extend parent key {parent_key:?}"
    );

    let expected_child_nibble = child_nibbles
        .get(parent_nibbles.len())
        .copied()
        .expect("child key must extend parent key by at least one nibble");

    let mut iter = merkle
        .path_iter(child_key)
        .expect("failed to iterate path for child key");

    while let Some(item) = iter.next() {
        let item = item.expect("failed to read node while iterating path");
        if item.key_nibbles.as_ref() != parent_nibbles.as_slice() {
            continue;
        }

        expect_branch(&item);
        assert_eq!(
            item.next_nibble,
            Some(expected_child_nibble),
            "branch should direct traversal to child nibble {expected_child_nibble:#x}"
        );

        let mut child_item = iter
            .next()
            .expect("branch child missing from path iterator")
            .expect("failed to read child node while iterating path");

        while child_item.key_nibbles.as_ref() != child_nibbles.as_slice() {
            expect_branch(&child_item);
            let next_expected_index = child_item.key_nibbles.len();
            let next_expected_nibble = child_nibbles
                .get(next_expected_index)
                .copied()
                .expect("child key must extend through intermediate branch");
            assert_eq!(
                child_item.next_nibble,
                Some(next_expected_nibble),
                "intermediate branch should direct traversal to child nibble {next_expected_nibble:#x}"
            );

            child_item = iter
                .next()
                .expect("intermediate branch missing expected child")
                .expect("failed to read intermediate child while iterating path");
        }

        expect_leaf(&child_item);
        return;
    }

    panic!("branch for key {parent_key:?} not encountered in path to child key {child_key:?}");
}

fn decrease_key(key: &[u8; 32]) -> [u8; 32] {
    let mut new_key = *key;
    for ch in new_key.iter_mut().rev() {
        let overflow;
        (*ch, overflow) = ch.overflowing_sub(1);
        if !overflow {
            break;
        }
    }
    new_key
}

#[test]
fn test_get_regression() {
    let mut merkle = create_in_memory_merkle();

    merkle.insert(&[0], Box::new([0])).unwrap();
    assert_eq!(merkle.get_value(&[0]).unwrap(), Some(Box::from([0])));

    merkle.insert(&[1], Box::new([1])).unwrap();
    assert_eq!(merkle.get_value(&[1]).unwrap(), Some(Box::from([1])));

    merkle.insert(&[2], Box::new([2])).unwrap();
    assert_eq!(merkle.get_value(&[2]).unwrap(), Some(Box::from([2])));

    let merkle = merkle.hash();

    assert_eq!(merkle.get_value(&[0]).unwrap(), Some(Box::from([0])));
    assert_eq!(merkle.get_value(&[1]).unwrap(), Some(Box::from([1])));
    assert_eq!(merkle.get_value(&[2]).unwrap(), Some(Box::from([2])));

    for result in merkle.path_iter(&[2]).unwrap() {
        result.unwrap();
    }
}

#[test]
fn insert_one() {
    let mut merkle = create_in_memory_merkle();
    merkle.insert(b"abc", Box::new([])).unwrap();
}

fn create_in_memory_merkle() -> Merkle<NodeStore<MutableProposal, MemStore>> {
    let memstore = MemStore::new(vec![]);

    let nodestore = NodeStore::new_empty_proposal(memstore.into(), noop_storage_metrics());

    Merkle { nodestore }
}

fn invalid_child_key() -> Option<Vec<u8>> {
    u8::try_from(BranchNode::MAX_CHILDREN)
        .ok()
        .map(|idx| vec![idx])
}

fn assert_missing_slot_error(err: &FileIoError) {
    let message = err.to_string();
    assert!(
        message.contains("missing child slot"),
        "error message should mention missing child slot, got: {message}"
    );
}

#[test]
fn insert_helper_detects_out_of_bounds_child_slot() {
    let mut merkle = create_in_memory_merkle();

    if let Some(invalid_key) = invalid_child_key() {
        let branch = BranchNode {
            partial_path: Path::new(),
            value: None,
            children: BranchNode::empty_children(),
        };
        let node = Node::Branch(Box::new(branch));
        let err = merkle
            .insert_helper(node, &invalid_key, Box::<[u8]>::default())
            .expect_err("malformed child index should return an error");
        assert_missing_slot_error(&err);
    } else {
        let mut branch = BranchNode {
            partial_path: Path::new(),
            value: None,
            children: BranchNode::empty_children(),
        };
        let err = set_branch_child(
            &mut branch,
            BranchNode::MAX_CHILDREN,
            Some(Child::Node(Node::Leaf(LeafNode {
                partial_path: Path::new(),
                value: Box::default(),
            }))),
            "tests::insert_helper_detects_out_of_bounds_child_slot",
        )
        .expect_err("setting an out-of-bounds child slot should error");
        assert_missing_slot_error(&err);
    }
}

#[test]
fn remove_helper_detects_out_of_bounds_child_slot() {
    let mut merkle = create_in_memory_merkle();

    if let Some(invalid_key) = invalid_child_key() {
        let branch = BranchNode {
            partial_path: Path::new(),
            value: None,
            children: BranchNode::empty_children(),
        };
        let node = Node::Branch(Box::new(branch));
        let err = merkle
            .remove_helper(node, &invalid_key)
            .expect_err("malformed child index should return an error");
        assert_missing_slot_error(&err);
    } else {
        let mut branch = BranchNode {
            partial_path: Path::new(),
            value: None,
            children: BranchNode::empty_children(),
        };
        let err = take_branch_child(
            &mut branch,
            BranchNode::MAX_CHILDREN,
            "tests::remove_helper_detects_out_of_bounds_child_slot",
        )
        .expect_err("taking an out-of-bounds child slot should error");
        assert_missing_slot_error(&err);
    }
}

#[test]
fn remove_prefix_helper_detects_out_of_bounds_child_slot() {
    let mut merkle = create_in_memory_merkle();

    if let Some(invalid_key) = invalid_child_key() {
        let branch = BranchNode {
            partial_path: Path::new(),
            value: None,
            children: BranchNode::empty_children(),
        };
        let node = Node::Branch(Box::new(branch));
        let err = merkle
            .remove_prefix_helper(node, &invalid_key, &mut 0)
            .expect_err("malformed child index should return an error");
        assert_missing_slot_error(&err);
    } else {
        let mut branch = BranchNode {
            partial_path: Path::new(),
            value: None,
            children: BranchNode::empty_children(),
        };
        let err = take_branch_child(
            &mut branch,
            BranchNode::MAX_CHILDREN,
            "tests::remove_prefix_helper_detects_out_of_bounds_child_slot",
        )
        .expect_err("taking an out-of-bounds child slot should error");
        assert_missing_slot_error(&err);
    }
}

#[test]
fn path_iter_returns_error_for_corrupt_child_slot() {
    let mut merkle = create_in_memory_merkle();

    if let Some(invalid_key) = invalid_child_key() {
        let branch = BranchNode {
            partial_path: Path::new(),
            value: None,
            children: BranchNode::empty_children(),
        };
        *merkle.nodestore.root_mut() = Some(Node::Branch(Box::new(branch.clone())));

        let mut iter = merkle.path_iter(&invalid_key).unwrap();
        match iter.next() {
            Some(Err(err)) => assert_missing_slot_error(&err),
            _ => {
                let err = branch_child_ref(
                    &branch,
                    BranchNode::MAX_CHILDREN,
                    "tests::path_iter_returns_error_for_corrupt_child_slot",
                )
                .expect_err("reading an out-of-bounds child slot should error");
                assert_missing_slot_error(&err);
            }
        }
    } else {
        let branch = BranchNode {
            partial_path: Path::new(),
            value: None,
            children: BranchNode::empty_children(),
        };
        let err = branch_child_ref(
            &branch,
            BranchNode::MAX_CHILDREN,
            "tests::path_iter_returns_error_for_corrupt_child_slot",
        )
        .expect_err("reading an out-of-bounds child slot should error");
        assert_missing_slot_error(&err);
    }
}

#[test]
fn test_insert_and_get() {
    let mut merkle = create_in_memory_merkle();

    // insert values
    for key_val in u8::MIN..=u8::MAX {
        let key = vec![key_val];
        let val = Box::new([key_val]);

        merkle.insert(&key, val.clone()).unwrap();

        let fetched_val = merkle.get_value(&key).unwrap();

        // make sure the value was inserted
        assert_eq!(fetched_val.as_deref(), val.as_slice().into());
    }

    // make sure none of the previous values were forgotten after initial insert
    for key_val in u8::MIN..=u8::MAX {
        let key = vec![key_val];
        let val = vec![key_val];

        let fetched_val = merkle.get_value(&key).unwrap();

        assert_eq!(fetched_val.as_deref(), val.as_slice().into());
    }
}

#[test]
fn overwrite_leaf() {
    let key = &[0x00];
    let val = &[1];
    let overwrite = &[2];

    let mut merkle = create_in_memory_merkle();

    merkle.insert(key, val[..].into()).unwrap();

    assert_eq!(
        merkle.get_value(key).unwrap().as_deref(),
        Some(val.as_slice())
    );

    merkle.insert(key, overwrite[..].into()).unwrap();

    assert_eq!(
        merkle.get_value(key).unwrap().as_deref(),
        Some(overwrite.as_slice())
    );
}

#[test]
fn remove_root() {
    let key0 = vec![0];
    let val0 = [0];
    let key1 = vec![0, 1];
    let val1 = [0, 1];
    let key2 = vec![0, 1, 2];
    let val2 = [0, 1, 2];
    let key3 = vec![0, 1, 15];
    let val3 = [0, 1, 15];

    let mut merkle = create_in_memory_merkle();

    merkle.insert(&key0, Box::from(val0)).unwrap();
    merkle.insert(&key1, Box::from(val1)).unwrap();
    merkle.insert(&key2, Box::from(val2)).unwrap();
    merkle.insert(&key3, Box::from(val3)).unwrap();
    // Trie is:
    //   key0
    //    |
    //   key1
    //  /    \
    // key2  key3

    // Test removal of root when it's a branch with 1 branch child
    let removed_val = merkle.remove(&key0).unwrap();
    assert_eq!(removed_val, Some(Box::from(val0)));
    assert!(merkle.get_value(&key0).unwrap().is_none());
    // Removing an already removed key is a no-op
    assert!(merkle.remove(&key0).unwrap().is_none());

    // Trie is:
    //   key1
    //  /    \
    // key2  key3
    // Test removal of root when it's a branch with multiple children
    assert_eq!(merkle.remove(&key1).unwrap(), Some(Box::from(val1)));
    assert!(merkle.get_value(&key1).unwrap().is_none());
    assert!(merkle.remove(&key1).unwrap().is_none());

    // Trie is:
    //   key1 (now has no value)
    //  /    \
    // key2  key3
    let removed_val = merkle.remove(&key2).unwrap();
    assert_eq!(removed_val, Some(Box::from(val2)));
    assert!(merkle.get_value(&key2).unwrap().is_none());
    assert!(merkle.remove(&key2).unwrap().is_none());

    // Trie is:
    // key3
    let removed_val = merkle.remove(&key3).unwrap();
    assert_eq!(removed_val, Some(Box::from(val3)));
    assert!(merkle.get_value(&key3).unwrap().is_none());
    assert!(merkle.remove(&key3).unwrap().is_none());

    assert!(merkle.nodestore.root_node().unwrap().is_none());
}

#[test]
fn remove_prefix_exact() {
    let mut merkle = two_byte_all_keys();
    for key_val in u8::MIN..=u8::MAX {
        let key = [key_val];
        let got = merkle.remove_prefix(&key).unwrap();
        assert_eq!(got, 1);
        let got = merkle.get_value(&key).unwrap();
        assert!(got.is_none());
    }
}

fn two_byte_all_keys() -> Merkle<NodeStore<MutableProposal, MemStore>> {
    let mut merkle = create_in_memory_merkle();
    for key_val in u8::MIN..=u8::MAX {
        let key = [key_val, key_val];
        let val = [key_val];

        merkle.insert(&key, Box::new(val)).unwrap();
        let got = merkle.get_value(&key).unwrap().unwrap();
        assert_eq!(&*got, val);
    }
    merkle
}

#[test]
fn remove_prefix_all() {
    let mut merkle = two_byte_all_keys();
    let got = merkle.remove_prefix(&[]).unwrap();
    assert_eq!(got, 256);
}

#[test]
fn remove_prefix_partial() {
    let mut merkle = create_in_memory_merkle();
    merkle
        .insert(b"abc", Box::from(b"value".as_slice()))
        .unwrap();
    merkle
        .insert(b"abd", Box::from(b"value".as_slice()))
        .unwrap();
    let got = merkle.remove_prefix(b"ab").unwrap();
    assert_eq!(got, 2);
}

#[test]
fn remove_many() {
    let mut merkle = create_in_memory_merkle();

    // insert key-value pairs
    for key_val in u8::MIN..=u8::MAX {
        let key = [key_val];
        let val = [key_val];

        merkle.insert(&key, Box::new(val)).unwrap();
        let got = merkle.get_value(&key).unwrap().unwrap();
        assert_eq!(&*got, val);
    }

    // remove key-value pairs
    for key_val in u8::MIN..=u8::MAX {
        let key = [key_val];
        let val = [key_val];

        let got = merkle.remove(&key).unwrap().unwrap();
        assert_eq!(&*got, val);

        // Removing an already removed key is a no-op
        assert!(merkle.remove(&key).unwrap().is_none());

        let got = merkle.get_value(&key).unwrap();
        assert!(got.is_none());
    }
    assert!(merkle.nodestore.root_node().unwrap().is_none());
}

#[test]
fn prove_surfaces_io_error_when_root_read_fails() {
    let merkle = Merkle::from(FailingRootReader::new());

    let err = merkle.prove(b"any-key").unwrap_err();
    assert!(
        matches!(err, ProofError::IO(_)),
        "unexpected error: {err:?}"
    );
}

#[test]
fn get_node_surfaces_io_error_when_root_read_fails() {
    let merkle = Merkle::from(FailingRootReader::new());

    let err = merkle.get_node(b"any-key").unwrap_err();
    assert!(err.to_string().contains("failing root read"), "{err}");
}

#[test]
fn remove_prefix() {
    let mut merkle = create_in_memory_merkle();

    // insert key-value pairs
    for key_val in u8::MIN..=u8::MAX {
        let key = [key_val, key_val];
        let val = [key_val];

        merkle.insert(&key, Box::new(val)).unwrap();
        let got = merkle.get_value(&key).unwrap().unwrap();
        assert_eq!(&*got, val);
    }

    // remove key-value pairs with prefix [0]
    let prefix = [0];
    assert_eq!(merkle.remove_prefix(&[0]).unwrap(), 1);

    // make sure all keys with prefix [0] were removed
    for key_val in u8::MIN..=u8::MAX {
        let key = [key_val, key_val];
        let got = merkle.get_value(&key).unwrap();
        if key[0] == prefix[0] {
            assert!(got.is_none());
        } else {
            assert!(got.is_some());
        }
    }
}

#[test]
fn get_empty_proof() {
    let merkle = create_in_memory_merkle().hash();
    let proof = merkle.prove(b"any-key");
    assert!(matches!(proof.unwrap_err(), ProofError::Empty));
}

#[test]
fn single_key_proof() {
    const TEST_SIZE: usize = 1;

    let mut merkle = create_in_memory_merkle();

    let rng = firewood_storage::SeededRng::from_env_or_random();

    let kvs = generate_random_kvs(&rng, TEST_SIZE);

    for (key, val) in &kvs {
        merkle.insert(key, val.clone().into_boxed_slice()).unwrap();
    }

    let merkle = merkle.hash();

    let root_hash = merkle.nodestore.root_hash().unwrap();

    for (key, value) in kvs {
        let proof = merkle.prove(&key).unwrap();

        proof
            .verify(key.clone(), Some(value.clone()), &root_hash)
            .unwrap();

        {
            // Test that the proof is invalid when the value is different
            let mut value = value.clone();
            value[0] = value[0].wrapping_add(1);
            assert!(proof.verify(key.clone(), Some(value), &root_hash).is_err());
        }

        {
            // Test that the proof is invalid when the hash is different
            assert!(proof.verify(key, Some(value), &TrieHash::empty()).is_err());
        }
    }
}

#[test]
fn empty_range_proof() {
    let merkle = create_in_memory_merkle();

    assert!(matches!(
        merkle.range_proof(None, None, None).unwrap_err(),
        api::Error::RangeProofOnEmptyTrie
    ));
}

#[test]
fn test_insert_leaf_suffix() {
    // key_2 is a suffix of key, which is a leaf
    let key = vec![0xff];
    let val = [1];
    let key_2 = vec![0xff, 0x00];
    let val_2 = [2];

    let mut merkle = create_in_memory_merkle();

    merkle.insert(&key, Box::new(val)).unwrap();
    merkle.insert(&key_2, Box::new(val_2)).unwrap();

    let got = merkle.get_value(&key).unwrap().unwrap();

    assert_eq!(*got, val);

    let got = merkle.get_value(&key_2).unwrap().unwrap();
    assert_eq!(*got, val_2);
}

#[test]
fn test_insert_leaf_prefix() {
    // key_2 is a prefix of key, which is a leaf
    let key = vec![0xff, 0x00];
    let val = [1];
    let key_2 = vec![0xff];
    let val_2 = [2];

    let mut merkle = create_in_memory_merkle();

    merkle.insert(&key, Box::new(val)).unwrap();
    merkle.insert(&key_2, Box::new(val_2)).unwrap();

    let got = merkle.get_value(&key).unwrap().unwrap();
    assert_eq!(*got, val);

    let got = merkle.get_value(&key_2).unwrap().unwrap();
    assert_eq!(*got, val_2);
}

#[test]
fn test_insert_sibling_leaf() {
    // The node at key is a branch node with children key_2 and key_3.
    let key = vec![0xff];
    let val = [1];
    let key_2 = vec![0xff, 0x00];
    let val_2 = [2];
    let key_3 = vec![0xff, 0x0f];
    let val_3 = [3];

    let mut merkle = create_in_memory_merkle();

    merkle.insert(&key, Box::new(val)).unwrap();
    merkle.insert(&key_2, Box::new(val_2)).unwrap();
    merkle.insert(&key_3, Box::new(val_3)).unwrap();

    let got = merkle.get_value(&key).unwrap().unwrap();
    assert_eq!(*got, val);

    let got = merkle.get_value(&key_2).unwrap().unwrap();
    assert_eq!(*got, val_2);

    let got = merkle.get_value(&key_3).unwrap().unwrap();
    assert_eq!(*got, val_3);

    let path: Vec<_> = merkle
        .path_iter(&key)
        .expect("failed to iterate path for branch key")
        .map(|item| item.expect("failed to load node while iterating path"))
        .collect();

    assert!(!path.is_empty(), "path iterator did not yield branch node");

    let branch_item = path.last().expect("branch node missing from path");
    let expected_nibbles = key_nibbles(&key);
    assert_eq!(
        branch_item.key_nibbles.as_ref(),
        expected_nibbles.as_slice(),
        "branch node path did not match expected key"
    );
    assert!(
        branch_item.next_nibble.is_none(),
        "branch path should terminate at the requested key"
    );

    let branch = expect_branch(branch_item);
    assert_eq!(
        branch.value.as_deref(),
        Some(val.as_slice()),
        "branch node should retain original value"
    );

    assert_branch_child_is_leaf(&merkle, &key, &key_2);
    assert_branch_child_is_leaf(&merkle, &key, &key_3);
}

#[test]
fn test_insert_branch_as_branch_parent() {
    let key = vec![0xff, 0xf0];
    let val = [1];
    let key_2 = vec![0xff, 0xf0, 0x00];
    let val_2 = [2];
    let key_3 = vec![0xff];
    let val_3 = [3];

    let mut merkle = create_in_memory_merkle();

    merkle.insert(&key, Box::new(val)).unwrap();
    // key is a leaf

    merkle.insert(&key_2, Box::new(val_2)).unwrap();
    // key is branch with child key_2

    merkle.insert(&key_3, Box::new(val_3)).unwrap();
    // key_3 is a branch with child key
    // key is a branch with child key_3

    let got = merkle.get_value(&key).unwrap().unwrap();
    assert_eq!(&*got, val);

    let got = merkle.get_value(&key_2).unwrap().unwrap();
    assert_eq!(&*got, val_2);

    let got = merkle.get_value(&key_3).unwrap().unwrap();
    assert_eq!(&*got, val_3);
}

#[test]
fn test_insert_overwrite_branch_value() {
    let key = vec![0xff];
    let val = [1];
    let key_2 = vec![0xff, 0x00];
    let val_2 = [2];
    let overwrite = [3];

    let mut merkle = create_in_memory_merkle();

    merkle.insert(&key, Box::new(val)).unwrap();
    merkle.insert(&key_2, Box::new(val_2)).unwrap();

    let got = merkle.get_value(&key).unwrap().unwrap();
    assert_eq!(*got, val);

    let got = merkle.get_value(&key_2).unwrap().unwrap();
    assert_eq!(*got, val_2);

    merkle.insert(&key, Box::new(overwrite)).unwrap();

    let got = merkle.get_value(&key).unwrap().unwrap();
    assert_eq!(*got, overwrite);

    let got = merkle.get_value(&key_2).unwrap().unwrap();
    assert_eq!(*got, val_2);
}

#[test]
fn test_delete_one_child_with_branch_value() {
    let mut merkle = create_in_memory_merkle();
    // insert a parent with a value
    merkle.insert(&[0], Box::new([42u8])).unwrap();
    // insert child1 with a value
    merkle.insert(&[0, 1], Box::new([43u8])).unwrap();
    // insert child2 with a value
    merkle.insert(&[0, 2], Box::new([44u8])).unwrap();

    // now delete one of the children
    let deleted = merkle.remove(&[0, 1]).unwrap();
    assert_eq!(deleted, Some([43u8].to_vec().into_boxed_slice()));

    // make sure the parent still has the correct value
    let got = merkle.get_value(&[0]).unwrap().unwrap();
    assert_eq!(*got, [42u8]);

    // and check the remaining child
    let other_child = merkle.get_value(&[0, 2]).unwrap().unwrap();
    assert_eq!(*other_child, [44u8]);
}

#[test]
fn test_root_hash_simple_insertions() -> Result<(), Error> {
    let kvs = vec![
        (b"do".to_vec(), b"verb".to_vec()),
        (b"doe".to_vec(), b"reindeer".to_vec()),
        (b"dog".to_vec(), b"puppy".to_vec()),
        (b"doge".to_vec(), b"coin".to_vec()),
        (b"horse".to_vec(), b"stallion".to_vec()),
        (b"ddd".to_vec(), b"ok".to_vec()),
    ];

    let merkle = init_merkle(kvs.clone());
    let firewood_hash = merkle
        .nodestore()
        .root_hash()
        .unwrap_or_else(TrieHash::empty);
    let expected_hash = compute_expected_root(&kvs);
    assert_eq!(firewood_hash, expected_hash);
    Ok(())
}

#[test]
fn test_root_hash_fuzz_insertions() -> Result<(), FileIoError> {
    thread::Builder::new()
        .name("merkle-fuzz-insertions".into())
        .stack_size(32 * 1024 * 1024)
        .spawn(|| -> Result<(), FileIoError> {
            let rng = firewood_storage::SeededRng::from_option(Some(42));
            let max_len0 = 8;
            let max_len1 = 4;
            let keygen = || {
                let (len0, len1): (usize, usize) = {
                    (
                        rng.random_range(1..=max_len0),
                        rng.random_range(1..=max_len1),
                    )
                };
                let key: Vec<u8> = (0..len0)
                    .map(|_| rng.random_range(0..2))
                    .chain((0..len1).map(|_| rng.random()))
                    .collect();
                key
            };

            let debug_env = std::env::var("FIREWOOD_MERKLE_DEBUG")
                .ok()
                .map(|value| matches!(value.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
                .unwrap_or(false);
            let debug_target = std::env::var("FIREWOOD_MERKLE_DEBUG_ITER")
                .ok()
                .and_then(|value| value.parse::<usize>().ok());

            for iter in 0..200 {
                if debug_env {
                    println!("debug: fuzz iteration {iter} start");
                }
                let mut items = Vec::new();

                for _ in 0..100 {
                    let val: Vec<u8> = (0..256).map(|_| rng.random()).collect();
                    items.push((keygen(), val));
                }

                if let Some(target) = debug_target {
                    if target == iter {
                        DEBUG_ITERATION.store(iter, Ordering::Relaxed);
                    } else {
                        DEBUG_ITERATION.store(usize::MAX, Ordering::Relaxed);
                    }
                }
                let expected_root = compute_expected_root(&items);
                let merkle = init_merkle(items.clone());
                let actual_root = merkle
                    .nodestore()
                    .root_hash()
                    .unwrap_or_else(TrieHash::empty);
                assert_eq!(
                    actual_root, expected_root,
                    "root hash mismatch at iteration {iter}"
                );
            }

            if debug_target.is_some() {
                DEBUG_ITERATION.store(usize::MAX, Ordering::Relaxed);
            }

            Ok(())
        })
        .expect("failed to spawn merkle fuzz thread")
        .join()
        .expect("merkle fuzz thread panicked")
}

#[cfg(debug_assertions)]
fn iteration_106_dataset() -> Vec<(Vec<u8>, Vec<u8>)> {
    let rng = firewood_storage::SeededRng::from_option(Some(42));
    let max_len0 = 8;
    let max_len1 = 4;
    let keygen = || {
        let (len0, len1): (usize, usize) = {
            (
                rng.random_range(1..=max_len0),
                rng.random_range(1..=max_len1),
            )
        };
        (0..len0)
            .map(|_| rng.random_range(0..2))
            .chain((0..len1).map(|_| rng.random()))
            .collect::<Vec<u8>>()
    };

    for iter in 0..=106 {
        let mut items = Vec::with_capacity(100);
        for _ in 0..100 {
            let val: Vec<u8> = (0..256).map(|_| rng.random()).collect();
            items.push((keygen(), val));
        }
        if iter == 106 {
            return items;
        }
    }

    unreachable!("iteration 106 dataset generation must return");
}

#[cfg(debug_assertions)]
#[test]
fn iteration_106_roots_match_after_deduplication() {
    let items = iteration_106_dataset();
    let actual_merkle = init_merkle(items.clone());

    let mut deduped: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
    for (key, value) in items {
        deduped.insert(key, value);
    }
    let expected_merkle = init_merkle(deduped);

    let actual_hash = actual_merkle
        .nodestore()
        .root_hash()
        .expect("actual root hash");
    let expected_hash = expected_merkle
        .nodestore()
        .root_hash()
        .expect("expected root hash");

    assert_eq!(
        actual_hash, expected_hash,
        "iteration 106 dataset should match deduplicated root"
    );
}

#[test]
fn remove_branch_with_value_promotes_partial_path() {
    let branch_key = nibbles_to_key(&[0x1, 0x0]);
    let child_key = nibbles_to_key(&[0x1, 0x0, 0x2, 0x0]);
    let items = vec![
        (branch_key.clone(), b"root".to_vec()),
        (child_key.clone(), b"child".to_vec()),
    ];

    let mut merkle = init_merkle(items).fork().unwrap();

    let root_before = merkle
        .nodestore()
        .root_as_maybe_persisted_node()
        .and_then(|node| node.as_shared_node(merkle.nodestore()).ok())
        .expect("root before removal");

    let expected_partial_path = match root_before.deref() {
        Node::Branch(branch) => {
            assert!(branch.value.is_some(), "branch must store root value");
            Path::from_iter(branch.partial_path.iter().copied())
        }
        other => panic!("expected branch before removal, got {other:?}"),
    };

    assert_eq!(
        merkle.remove(&child_key).unwrap().as_deref(),
        Some(&b"child"[..])
    );

    let root_after = merkle
        .nodestore()
        .root_as_maybe_persisted_node()
        .and_then(|node| node.as_shared_node(merkle.nodestore()).ok())
        .expect("root after removal");

    match root_after.deref() {
        Node::Leaf(leaf) => {
            assert_eq!(leaf.partial_path.as_ref(), expected_partial_path.as_ref());
            assert_eq!(leaf.value.as_ref(), b"root");
        }
        other => panic!("expected leaf after removal, got {other:?}"),
    }
}

#[test]
fn remove_branch_with_single_child_merges_partial_paths() {
    let kept_nibbles = [0x1, 0x0, 0x2, 0x0];
    let removed_nibbles = [0x1, 0x0, 0x3, 0x0];
    let kept_key = nibbles_to_key(&kept_nibbles);
    let removed_key = nibbles_to_key(&removed_nibbles);

    let mut merkle = init_merkle(vec![
        (kept_key.clone(), b"keep".to_vec()),
        (removed_key.clone(), b"discard".to_vec()),
    ])
    .fork()
    .unwrap();

    let root_before = merkle
        .nodestore()
        .root_as_maybe_persisted_node()
        .and_then(|node| node.as_shared_node(merkle.nodestore()).ok())
        .expect("root before removal");

    let expected_partial_path = match root_before.deref() {
        Node::Branch(branch) => {
            assert!(branch.value.is_none(), "branch should not store a value");
            let branch_partial = Path::from_iter(branch.partial_path.iter().copied());
            let surviving_child_index = kept_nibbles[branch_partial.len()];
            let surviving_child = branch
                .child(surviving_child_index as u8)
                .as_ref()
                .expect("branch must contain surviving child");
            let surviving_suffix = child_partial_path(merkle.nodestore(), surviving_child);

            branch
                .partial_path
                .with_appended_nibble(surviving_child_index as u8)
                .with_appended_iter(surviving_suffix.iter().copied())
        }
        other => panic!("expected branch before removal, got {other:?}"),
    };

    merkle.remove(&removed_key).unwrap();

    let root_after = merkle
        .nodestore()
        .root_as_maybe_persisted_node()
        .and_then(|node| node.as_shared_node(merkle.nodestore()).ok())
        .expect("root after removal");

    match root_after.deref() {
        Node::Leaf(leaf) => {
            let expected_key_path = Path::from_iter(kept_nibbles.iter().copied());
            assert_eq!(leaf.partial_path.as_ref(), expected_partial_path.as_ref());
            assert_eq!(leaf.partial_path.as_ref(), expected_key_path.as_ref());
        }
        other => panic!("expected promoted leaf, got {other:?}"),
    }
}

#[test]
fn test_delete_child() {
    let items = vec![("do", "verb")];
    let merkle = init_merkle(items);
    let mut merkle = merkle.fork().unwrap();

    assert_eq!(merkle.remove(b"does_not_exist").unwrap(), None);
    assert_eq!(&*merkle.get_value(b"do").unwrap().unwrap(), b"verb");
}

#[test]
fn test_delete_some() {
    let items = (0..100)
        .map(|n| {
            let key = format!("key{n}");
            let val = format!("value{n}");
            (key.as_bytes().to_vec(), val.as_bytes().to_vec())
        })
        .collect::<Vec<(Vec<u8>, Vec<u8>)>>();
    let mut merkle = init_merkle(items.clone()).fork().unwrap();
    merkle.remove_prefix(b"key1").unwrap();
    for item in items {
        let (key, val) = item;
        if key.starts_with(b"key1") {
            assert!(merkle.get_value(&key).unwrap().is_none());
        } else {
            assert_eq!(&*merkle.get_value(&key).unwrap().unwrap(), val.as_slice());
        }
    }
}

#[test]
fn test_root_hash_reversed_deletions() -> Result<(), FileIoError> {
    let rng = firewood_storage::SeededRng::from_env_or_random();

    let max_len0 = 8;
    let max_len1 = 4;
    let keygen = || {
        let (len0, len1): (usize, usize) = {
            (
                rng.random_range(1..=max_len0),
                rng.random_range(1..=max_len1),
            )
        };
        (0..len0)
            .map(|_| rng.random_range(0..2))
            .chain((0..len1).map(|_| rng.random()))
            .collect()
    };

    for _ in 0..10 {
        let mut items: Vec<(Key, Value)> = (0..10)
            .map(|_| keygen())
            .map(|key| {
                let val = (0..8).map(|_| rng.random()).collect();
                (key, val)
            })
            .collect();

        items.sort_unstable();
        items.dedup_by_key(|(k, _)| k.clone());

        let init_merkle = create_in_memory_merkle();
        let init_immutable_merkle = init_merkle.hash();

        let (hashes, complete_immutable_merkle) = items.iter().fold(
            (vec![], init_immutable_merkle),
            |(mut hashes, immutable_merkle), (k, v)| {
                let root_hash = immutable_merkle.nodestore.root_hash();
                hashes.push(root_hash);
                let mut merkle = immutable_merkle.fork().unwrap();
                merkle.insert(k, v.clone()).unwrap();
                (hashes, merkle.hash())
            },
        );

        let (new_hashes, _) = items.iter().rev().fold(
            (vec![], complete_immutable_merkle),
            |(mut new_hashes, immutable_merkle_before_removal), (k, _)| {
                let before = immutable_merkle_before_removal.dump_to_string().unwrap();
                let mut merkle = Merkle::from(
                    NodeStore::new(immutable_merkle_before_removal.nodestore()).unwrap(),
                );
                merkle.remove(k).unwrap();
                let immutable_merkle_after_removal: Merkle<NodeStore<Arc<ImmutableProposal>, _>> =
                    merkle.try_into().unwrap();
                new_hashes.push((
                    immutable_merkle_after_removal.nodestore.root_hash(),
                    k,
                    before,
                    immutable_merkle_after_removal.dump_to_string().unwrap(),
                ));
                (new_hashes, immutable_merkle_after_removal)
            },
        );

        for (expected_hash, (actual_hash, key, before_removal, after_removal)) in
            hashes.into_iter().rev().zip(new_hashes)
        {
            let key = key.iter().fold(String::new(), |mut s, b| {
                let _ = write!(s, "{b:02x}");
                s
            });
            assert_eq!(
                actual_hash, expected_hash,
                "\n\nkey: {key}\nbefore:\n{before_removal}\nafter:\n{after_removal}\n\nexpected:\n{expected_hash:?}\nactual:\n{actual_hash:?}\n",
            );
        }
    }

    Ok(())
}

#[test]
fn remove_nonexistent_with_one() {
    let items = [("do", "verb")];
    let mut merkle = init_merkle(items).fork().unwrap();

    assert_eq!(merkle.remove(b"does_not_exist").unwrap(), None);
    assert_eq!(&*merkle.get_value(b"do").unwrap().unwrap(), b"verb");
}
