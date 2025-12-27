// Copyright (C) 2025, Ava Labs, Inc. All rights reserved.
// See the file LICENSE.md for licensing terms.

use crate::proof::{Proof, ProofError, ProofNode};
use crate::v2::api::OptionalHashKeyExt;

use super::*;
use ethereum_types::H256;
use std::convert::TryFrom;
use std::sync::Arc;

use firewood_storage::{
    noop_storage_metrics, BranchNode, Child, HashType, ImmutableProposal, LeafNode,
    MaybePersistedNode, MemStore, NibblesIterator, Node, NodeStore, Path, RlpBytes, SharedNode,
    TrieHash, ValueDigest,
};
use hash_db::Hasher;
use plain_hasher::PlainHasher;
use rlp::RlpStream;
use sha3::{Digest, Keccak256};
use test_case::test_case;

#[derive(Default, Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeccakHasher;

impl KeccakHasher {
    fn trie_root<I, K, V>(items: I) -> H256
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<[u8]> + Ord,
        V: AsRef<[u8]>,
    {
        firewood_triehash::trie_root::<Self, _, _, _>(items)
    }
}

impl Hasher for KeccakHasher {
    type Out = H256;
    type StdHasher = PlainHasher;
    const LENGTH: usize = 32;

    #[inline]
    fn hash(x: &[u8]) -> Self::Out {
        let mut hasher = Keccak256::new();
        hasher.update(x);
        let result = hasher.finalize();
        H256::from_slice(result.as_slice())
    }
}

#[test_case([("doe", "reindeer")])]
#[test_case([("doe", "reindeer"),("dog", "puppy"),("dogglesworth", "cat")])]
#[test_case([("doe", "reindeer"),("dog", "puppy"),("dogglesworth", "cacatcatcatcatcatcatcatcatcatcatcatcatcatcatcatcatcatcatcatcatcatcatcatcatcatcatcatcatcatcatcatcatt")])]
#[test_case([("dogglesworth", "cacatcatcatcatcatcatcatcatcatcatcatcatcatcatcatcatcatcatcatcatcatcatcatcatcatcatcatcatcatcatcatcatt")])]
fn test_root_hash_eth_compatible<I, K, V>(kvs: I)
where
    I: Clone + IntoIterator<Item = (K, V)>,
    K: AsRef<[u8]> + Ord,
    V: AsRef<[u8]>,
{
    let merkle = init_merkle(kvs.clone());
    let firewood_hash = merkle.nodestore.root_hash().unwrap_or_else(TrieHash::empty);
    let eth_hash: TrieHash = KeccakHasher::trie_root(kvs).to_fixed_bytes().into();
    assert_eq!(firewood_hash, eth_hash);
}

#[test_case(
            "0000000000000000000000000000000000000002",
            "f844802ca00000000000000000000000000000000000000000000000000000000000000000a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
            &[],
            "c00ca9b8e6a74b03f6b1ae2db4a65ead348e61b74b339fe4b117e860d79c7821"
    )]
#[test_case(
            "0000000000000000000000000000000000000002",
            "f844802ca00000000000000000000000000000000000000000000000000000000000000000a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
            &[
                    ("48078cfed56339ea54962e72c37c7f588fc4f8e5bc173827ba75cb10a63a96a5", "a00200000000000000000000000000000000000000000000000000000000000000")
            ],
            "91336bf4e6756f68e1af0ad092f4a551c52b4a66860dc31adbd736f0acbadaf6"
    )]
#[test_case(
            "0000000000000000000000000000000000000002",
            "f844802ca00000000000000000000000000000000000000000000000000000000000000000a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
            &[
                    ("48078cfed56339ea54962e72c37c7f588fc4f8e5bc173827ba75cb10a63a96a5", "a00200000000000000000000000000000000000000000000000000000000000000"),
                    ("0e81f83a84964b811dd1b8328262a9f57e6bc3e5e7eb53627d10437c73c4b8da", "a02800000000000000000000000000000000000000000000000000000000000000"),
            ],
            "c267104830880c966c2cc8c669659e4bfaf3126558dbbd6216123b457944001b"
    )]
fn test_eth_compatible_accounts(
    account: &str,
    account_value: &str,
    key_suffixes_and_values: &[(&str, &str)],
    expected_root: &str,
) {
    use sha3::Digest as _;
    use sha3::Keccak256;

    let account = make_key(account);
    let expected_key_hash = Keccak256::digest(&account);

    let items = once((
        Box::from(expected_key_hash.as_slice()),
        make_key(account_value),
    ))
    .chain(key_suffixes_and_values.iter().map(|(key_suffix, value)| {
        let key = expected_key_hash
            .iter()
            .copied()
            .chain(make_key(key_suffix).iter().copied())
            .collect();
        let value = make_key(value);
        (key, value)
    }))
    .collect::<Vec<(Box<_>, Box<_>)>>();

    let merkle = init_merkle(items);
    let firewood_hash = merkle.nodestore.root_hash();

    assert_eq!(
        firewood_hash,
        TrieHash::try_from(&*make_key(expected_root)).ok()
    );
}

/// helper method to convert a hex encoded string into a boxed slice
fn make_key(hex_str: &str) -> Key {
    hex::decode(hex_str).unwrap().into_boxed_slice()
}

fn account_proof_with_children<F>(rlp_bytes: &[u8], configure_children: F) -> Proof<Vec<ProofNode>>
where
    F: FnOnce(&mut [Option<HashType>; BranchNode::MAX_CHILDREN]),
{
    let mut child_hashes = BranchNode::empty_children();
    configure_children(&mut child_hashes);

    let node = ProofNode {
        key: vec![0; 64].into_boxed_slice(),
        partial_len: 0,
        value_digest: Some(ValueDigest::Value(rlp_bytes.to_vec().into_boxed_slice())),
        child_hashes,
    };

    Proof::new(vec![node])
}

fn truncated_account_rlp() -> Vec<u8> {
    let mut stream = RlpStream::new_list(2);
    stream.append_empty_data();
    stream.append_empty_data();
    stream.out().to_vec()
}

fn invalid_account_rlp() -> Vec<u8> {
    vec![0x01]
}

fn expect_corrupt_proof(proof: Proof<Vec<ProofNode>>) {
    let err = proof
        .value_digest([0u8; 32], &TrieHash::empty())
        .expect_err("corrupt proof should fail");
    assert!(matches!(err, ProofError::CorruptProof(_)));
}

#[test]
fn proof_rejects_corrupt_account_leaf_rlp() {
    expect_corrupt_proof(account_proof_with_children(&invalid_account_rlp(), |_| {}));
}

#[test]
fn proof_rejects_corrupt_account_branch_single_child() {
    expect_corrupt_proof(account_proof_with_children(
        &truncated_account_rlp(),
        |children| {
            children[0] = Some(HashType::Hash(TrieHash::empty()));
        },
    ));
}

#[test]
fn proof_rejects_corrupt_account_branch_multi_child() {
    expect_corrupt_proof(account_proof_with_children(
        &truncated_account_rlp(),
        |children| {
            children[0] = Some(HashType::Hash(TrieHash::empty()));
            children[1] = Some(HashType::Hash(TrieHash::empty()));
        },
    ));
}

#[test]
fn proof_accepts_account_branch_with_hashed_child() {
    let key_bytes = vec![0u8; 32];
    let key_nibbles: Vec<u8> = NibblesIterator::new(&key_bytes).collect();

    let account_nonce: u64 = 0;
    let account_balance: u64 = 44;
    let placeholder_storage_root = [0u8; 32];
    let account_code_hash = [0x22u8; 32];

    let account_placeholder = encode_account(
        account_nonce,
        account_balance,
        &placeholder_storage_root,
        &account_code_hash,
    );

    let child_hash = TrieHash::from([0x11u8; 32]);
    let expected_root = compute_account_branch_root(
        &key_nibbles,
        account_nonce,
        account_balance,
        &account_code_hash,
        child_hash.as_ref(),
    );

    let mut child_hashes = BranchNode::empty_children();
    child_hashes[0] = Some(HashType::Hash(child_hash));

    let proof = Proof::new(vec![ProofNode {
        key: key_nibbles.clone().into_boxed_slice(),
        partial_len: 0,
        value_digest: Some(ValueDigest::Value(
            account_placeholder.clone().into_boxed_slice(),
        )),
        child_hashes,
    }]);

    let result = proof
        .value_digest(&key_bytes, &expected_root)
        .expect("valid proof");

    assert_eq!(
        result,
        Some(ValueDigest::Value(account_placeholder.as_slice()))
    );
}

#[test]
fn proof_accepts_account_branch_with_inline_child() {
    let key_bytes = vec![0u8; 32];
    let key_nibbles: Vec<u8> = NibblesIterator::new(&key_bytes).collect();

    let account_nonce: u64 = 1;
    let account_balance: u64 = 99;
    let placeholder_storage_root = [0u8; 32];
    let account_code_hash = [0x33u8; 32];

    let account_placeholder = encode_account(
        account_nonce,
        account_balance,
        &placeholder_storage_root,
        &account_code_hash,
    );

    let encoded_path = encode_nibbles_to_eth_compact(&key_nibbles, true);
    let inline_child_rlp = {
        let mut stream = RlpStream::new_list(2);
        stream.append(&encode_nibbles_to_eth_compact(&[], true));
        stream.append(&b"v".as_slice());
        stream.out().to_vec()
    };
    let inline_child_bytes = RlpBytes::try_from(inline_child_rlp.as_slice())
        .expect("inline child payload fits into RlpBytes");

    let replacement_hash = {
        let mut stream = RlpStream::new_list(2);
        stream.append(&encoded_path);
        stream.append_raw(inline_child_rlp.as_slice(), 1);
        TrieHash::from(Keccak256::digest(stream.out().as_ref()))
    };

    let expected_root = compute_account_branch_root(
        &key_nibbles,
        account_nonce,
        account_balance,
        &account_code_hash,
        replacement_hash.as_ref(),
    );

    let mut child_hashes = BranchNode::empty_children();
    child_hashes[0] = Some(HashType::Rlp(inline_child_bytes));

    let proof = Proof::new(vec![ProofNode {
        key: key_nibbles.clone().into_boxed_slice(),
        partial_len: 0,
        value_digest: Some(ValueDigest::Value(
            account_placeholder.clone().into_boxed_slice(),
        )),
        child_hashes,
    }]);

    let result = proof
        .value_digest(&key_bytes, &expected_root)
        .expect("valid proof");

    assert_eq!(
        result,
        Some(ValueDigest::Value(account_placeholder.as_slice()))
    );
}

#[test]
fn account_branch_with_missing_persisted_child_address_is_rejected() {
    let storage = Arc::new(MemStore::new(Vec::new()));
    let mut proposal = NodeStore::new_empty_proposal(storage, noop_storage_metrics());

    let mut account_branch = BranchNode {
        partial_path: Path::from(vec![0u8; 64]),
        value: None,
        children: BranchNode::empty_children(),
    };

    let unpersisted_leaf = Node::Leaf(LeafNode {
        partial_path: Path::new(),
        value: vec![0u8].into_boxed_slice(),
    });
    let maybe_child = MaybePersistedNode::from(SharedNode::new(unpersisted_leaf));

    account_branch.children[0] = Some(Child::MaybePersisted(
        maybe_child,
        HashType::from(TrieHash::empty()),
    ));

    proposal
        .root_mut()
        .replace(Node::Branch(Box::new(account_branch)));

    let err = NodeStore::<Arc<ImmutableProposal>, MemStore>::try_from(proposal)
        .expect_err("corrupt account branch should fail hashing");

    let message = err.to_string();
    assert!(
        message.contains("corrupt proof"),
        "expected corrupt proof error, got: {message}"
    );
    assert!(
        message.contains("missing persisted address"),
        "error message should mention missing address, got: {message}"
    );
}

#[test]
fn account_branch_with_multiple_unhashed_children_is_rejected() {
    let storage = Arc::new(MemStore::new(Vec::new()));
    let mut proposal = NodeStore::new_empty_proposal(storage, noop_storage_metrics());

    let mut account_branch = BranchNode {
        partial_path: Path::from(vec![0u8; 64]),
        value: None,
        children: BranchNode::empty_children(),
    };

    let leaf_a = Node::Leaf(LeafNode {
        partial_path: Path::from(vec![0u8]),
        value: vec![1u8].into_boxed_slice(),
    });
    let leaf_b = Node::Leaf(LeafNode {
        partial_path: Path::from(vec![1u8]),
        value: vec![2u8].into_boxed_slice(),
    });

    account_branch.children[0] = Some(Child::Node(leaf_a));
    account_branch.children[1] = Some(Child::Node(leaf_b));

    proposal
        .root_mut()
        .replace(Node::Branch(Box::new(account_branch)));

    let err = NodeStore::<Arc<ImmutableProposal>, MemStore>::try_from(proposal)
        .expect_err("corrupt account branch should fail hashing");

    let message = err.to_string();
    assert!(
        message.contains("corrupt proof"),
        "expected corrupt proof error, got: {message}"
    );
    assert!(
        message.contains("unhashed children"),
        "error message should mention multiple unhashed children, got: {message}"
    );
}

fn encode_account(nonce: u64, balance: u64, storage_root: &[u8], code_hash: &[u8]) -> Vec<u8> {
    let mut stream = RlpStream::new_list(4);
    stream.append(&nonce);
    stream.append(&balance);
    stream.append(&storage_root);
    stream.append(&code_hash);
    stream.out().to_vec()
}

fn compute_account_branch_root(
    partial_path: &[u8],
    nonce: u64,
    balance: u64,
    code_hash: &[u8],
    replacement_hash: &[u8],
) -> TrieHash {
    let encoded_path = encode_nibbles_to_eth_compact(partial_path, true);
    let account_with_replacement = encode_account(nonce, balance, replacement_hash, code_hash);
    let mut stream = RlpStream::new_list(2);
    stream.append(&encoded_path);
    stream.append(&account_with_replacement.as_slice());
    TrieHash::from(Keccak256::digest(stream.out().as_ref()))
}

fn encode_nibbles_to_eth_compact(nibbles: &[u8], is_leaf: bool) -> Vec<u8> {
    debug_assert!(nibbles.iter().all(|n| *n < 16));

    let mut first = if is_leaf { 0x20 } else { 0x00 };
    let mut result = Vec::with_capacity(1 + (nibbles.len() + 1) / 2);

    let mut index = 0;
    if nibbles.len() % 2 == 1 {
        first |= 0x10 | nibbles[0];
        index = 1;
    }
    result.push(first);

    while index < nibbles.len() {
        let hi = nibbles[index];
        let lo = nibbles[index + 1];
        result.push((hi << 4) | lo);
        index += 2;
    }

    result
}

#[test]
fn test_root_hash_random_deletions() {
    use rand::seq::SliceRandom;
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
            .collect()
    };

    for i in 0..10 {
        let mut items = std::collections::HashMap::<Key, Value>::new();

        for _ in 0..10 {
            let val = (0..8).map(|_| rng.random()).collect();
            items.insert(keygen(), val);
        }

        let mut items_ordered: Vec<_> = items.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        items_ordered.sort_unstable();
        items_ordered.shuffle(&mut &rng);

        let mut committed_merkle = init_merkle(&items);

        for (k, v) in items_ordered {
            let mut merkle = committed_merkle.fork().unwrap();
            assert_eq!(merkle.get_value(&k).unwrap().as_deref(), Some(v.as_ref()));

            merkle.remove(&k).unwrap();

            // assert_eq(None) and not assert(is_none) for better error messages
            assert_eq!(merkle.get_value(&k).unwrap().as_deref(), None);

            items.remove(&k);

            for (k, v) in &items {
                assert_eq!(merkle.get_value(k).unwrap().as_deref(), Some(v.as_ref()));
            }

            committed_merkle = into_committed(merkle.hash(), committed_merkle.nodestore());

            let h: TrieHash = KeccakHasher::trie_root(&items).to_fixed_bytes().into();

            let h0 = committed_merkle
                .nodestore()
                .root_hash()
                .or_default_root_hash()
                .unwrap();

            assert_eq!(h, h0);
        }

        println!("i = {i}");
    }
}
