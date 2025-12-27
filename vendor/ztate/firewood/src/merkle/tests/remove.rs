// Copyright (C) 2025, Ava Labs, Inc. All rights reserved.
// See the file LICENSE.md for licensing terms.

use super::*;

fn value_bytes(input: &str) -> Box<[u8]> {
    Box::<[u8]>::from(input.as_bytes())
}

#[test]
fn remove_prefix_removes_leaf_descendant_when_prefix_is_ancestor() {
    let mut merkle = create_in_memory_merkle();

    let prefix = nibbles_to_key(&[0x1, 0x2]);
    let leaf_key = nibbles_to_key(&[0x1, 0x2, 0x3, 0x4]);
    let sibling_key = nibbles_to_key(&[0x1, 0x0, 0x5, 0x6]);
    let other_key = nibbles_to_key(&[0x4, 0x4, 0x0, 0x0]);

    merkle.insert(&leaf_key, value_bytes("leaf")).unwrap();
    merkle.insert(&sibling_key, value_bytes("sibling")).unwrap();
    merkle.insert(&other_key, value_bytes("other")).unwrap();

    let removed = merkle.remove_prefix(&prefix).unwrap();
    assert_eq!(
        removed, 1,
        "expected the leaf under the ancestor prefix to be removed"
    );

    assert!(
        merkle.get_value(&leaf_key).unwrap().is_none(),
        "leaf should be removed"
    );
    assert!(
        merkle.get_value(&sibling_key).unwrap().is_some(),
        "sibling without the prefix should remain",
    );
    assert!(
        merkle.get_value(&other_key).unwrap().is_some(),
        "unrelated keys must remain",
    );
}

#[test]
fn remove_prefix_removes_branch_descendant_when_prefix_is_ancestor() {
    let mut merkle = create_in_memory_merkle();

    let prefix = nibbles_to_key(&[0x3, 0x3]);
    let branch_key_a = nibbles_to_key(&[0x3, 0x3, 0x1, 0x0]);
    let branch_key_b = nibbles_to_key(&[0x3, 0x3, 0x1, 0x1]);
    let other_key = nibbles_to_key(&[0x3, 0x4, 0x0, 0x0]);

    merkle
        .insert(&branch_key_a, value_bytes("branch-a"))
        .unwrap();
    merkle
        .insert(&branch_key_b, value_bytes("branch-b"))
        .unwrap();
    merkle.insert(&other_key, value_bytes("other")).unwrap();

    let removed = merkle.remove_prefix(&prefix).unwrap();
    assert_eq!(removed, 2, "expected both branch descendants to be removed");

    assert!(
        merkle.get_value(&branch_key_a).unwrap().is_none(),
        "first branch descendant should be removed",
    );
    assert!(
        merkle.get_value(&branch_key_b).unwrap().is_none(),
        "second branch descendant should be removed",
    );
    assert!(
        merkle.get_value(&other_key).unwrap().is_some(),
        "keys outside the prefix should remain",
    );
}

#[test]
fn remove_prefix_removes_ancestor_subtrie_for_persisted_nodes() {
    let prefix = nibbles_to_key(&[0x5, 0x5]);
    let leaf_key = nibbles_to_key(&[0x5, 0x5, 0x0, 0x1]);
    let branch_key_a = nibbles_to_key(&[0x5, 0x5, 0x2, 0x0]);
    let branch_key_b = nibbles_to_key(&[0x5, 0x5, 0x2, 0x1]);
    let keep_key = nibbles_to_key(&[0x5, 0x7, 0x0, 0x0]);

    let items: Vec<(Vec<u8>, Vec<u8>)> = vec![
        (leaf_key.clone(), b"leaf".to_vec()),
        (branch_key_a.clone(), b"branch-a".to_vec()),
        (branch_key_b.clone(), b"branch-b".to_vec()),
        (keep_key.clone(), b"keep".to_vec()),
    ];

    let committed = init_merkle(items.clone());
    let nodestore = NodeStore::new(committed.nodestore()).unwrap();
    let mut merkle = Merkle::from(nodestore);
    let removed = merkle.remove_prefix(&prefix).unwrap();
    assert_eq!(
        removed, 3,
        "all descendants under the persisted prefix should be removed"
    );

    for key in [&leaf_key, &branch_key_a, &branch_key_b] {
        assert!(
            merkle.get_value(key).unwrap().is_none(),
            "persisted descendant {key:?} should be removed",
        );
    }
    assert_eq!(
        merkle.get_value(&keep_key).unwrap().as_deref(),
        Some(b"keep".as_slice()),
        "unrelated persisted key should remain",
    );
}
