use super::*;

use hex::FromHex;
use serde::Deserialize;
use std::sync::Arc;

const FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../tests/storage/fixtures/branch_factor_256/hashlists.json",
));

#[derive(Debug, Deserialize)]
struct FixtureFile {
    branch_factor: u32,
    fixtures: Vec<Fixture>,
}

#[derive(Debug, Deserialize)]
struct Fixture {
    name: String,
    #[allow(dead_code)]
    description: String,
    operations: Vec<Operation>,
}

#[derive(Debug, Deserialize)]
struct Operation {
    #[serde(rename = "type")]
    kind: OperationKind,
    key: String,
    value: Option<String>,
    root: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum OperationKind {
    Put,
    Delete,
}

#[test]
fn merkledb_branch_factor_256_hashlists_match() {
    let fixtures: FixtureFile =
        serde_json::from_str(FIXTURE).expect("failed to parse merkledb hash fixtures");

    assert_eq!(
        fixtures.branch_factor, 256,
        "unexpected branch factor in fixture"
    );

    for fixture in fixtures.fixtures {
        assert_fixture_matches(&fixture);
    }
}

fn assert_fixture_matches(fixture: &Fixture) {
    let memstore = Arc::new(MemStore::new(Vec::with_capacity(64 * 1024)));
    let base = Merkle::from(
        NodeStore::new_empty_committed(memstore.clone(), noop_storage_metrics()).unwrap(),
    );
    let mut committed = base;

    for (index, operation) in fixture.operations.iter().enumerate() {
        let key = decode_key_bytes(&operation.key);

        let mut proposal = committed.fork().unwrap_or_else(|err| {
            panic!("failed to fork committed state for {}: {err}", fixture.name)
        });

        match operation.kind {
            OperationKind::Put => {
                let value_hex = operation
                    .value
                    .as_ref()
                    .unwrap_or_else(|| panic!("missing value for put in fixture {}", fixture.name));
                let value = Vec::from_hex(value_hex).unwrap_or_else(|err| {
                    panic!("invalid hex value in fixture {}: {err}", fixture.name)
                });
                proposal
                    .insert(&key, value.into_boxed_slice())
                    .unwrap_or_else(|err| {
                        panic!(
                            "insert failed for fixture {} at step {index}: {err}",
                            fixture.name
                        )
                    });
            }
            OperationKind::Delete => {
                proposal.remove(&key).unwrap_or_else(|err| {
                    panic!(
                        "remove failed for fixture {} at step {index}: {err}",
                        fixture.name
                    )
                });
            }
        }

        let hashed = proposal.hash();
        let actual_root = hashed.nodestore.root_hash();
        let next_committed = into_committed(hashed, committed.nodestore());
        let expected_root = decode_expected_root(&operation.root);

        match (expected_root, actual_root) {
            (ExpectedRoot::Empty, None) => {}
            (ExpectedRoot::Empty, Some(root)) => panic!(
                "expected empty root for fixture {} at step {index}, got {root:?}",
                fixture.name
            ),
            (ExpectedRoot::Hash(expected), None) => panic!(
                "expected root {expected:?} for fixture {} at step {index}, got None",
                fixture.name
            ),
            (ExpectedRoot::Hash(expected), Some(actual)) => {
                assert_eq!(
                    actual, expected,
                    "root hash mismatch for fixture {} at step {index}",
                    fixture.name
                );
            }
        }

        committed = next_committed;
    }
}

enum ExpectedRoot {
    Empty,
    Hash(TrieHash),
}

fn decode_key_bytes(hex_key: &str) -> Vec<u8> {
    Vec::from_hex(hex_key).unwrap_or_else(|err| panic!("invalid hex key {hex_key}: {err}"))
}

fn decode_expected_root(root_hex: &str) -> ExpectedRoot {
    if root_hex.chars().all(|c| c == '0') {
        return ExpectedRoot::Empty;
    }

    let mut bytes = [0u8; 32];
    hex::decode_to_slice(root_hex, &mut bytes)
        .unwrap_or_else(|err| panic!("invalid root hash {root_hex}: {err}"));
    ExpectedRoot::Hash(TrieHash::from(bytes))
}
