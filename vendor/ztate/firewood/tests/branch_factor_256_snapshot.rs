#![cfg(feature = "branch_factor_256")]

use std::fs;
use std::path::PathBuf;

use firewood::db::{Db, DbConfig};
use firewood::manager::RevisionManagerConfig;
use firewood::v2::api::{Db as _, DbView as _};
use firewood_storage::noop_storage_metrics;
use tempfile::tempdir;

fn fixture_path() -> PathBuf {
    // Store the fixture as hex so it stays text-friendly for code review tooling.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../tests/storage/fixtures/branch_factor_256/snapshot.firewood.hex")
}

fn write_fixture(temp: &tempfile::TempDir) -> PathBuf {
    let fixture = fixture_path();
    let encoded = fs::read_to_string(&fixture).expect("read hex snapshot fixture");
    let decoded = hex::decode(encoded.split_whitespace().collect::<String>())
        .expect("decode hex snapshot fixture");

    let snapshot_path = temp.path().join("snapshot.firewood");
    fs::write(&snapshot_path, decoded).expect("materialize snapshot fixture");
    snapshot_path
}

#[test]
fn branch_factor_256_snapshot_roundtrip() {
    let temp = tempdir().expect("create scratch directory");
    let snapshot_path = write_fixture(&temp);

    let manager_cfg = RevisionManagerConfig::builder().max_revisions(4).build();
    let db_cfg = DbConfig::builder().manager(manager_cfg).build();
    let db = Db::new(&snapshot_path, db_cfg, noop_storage_metrics()).expect("open fixture db");

    let root = db
        .root_hash()
        .expect("root lookup")
        .expect("non-empty root");
    assert_eq!(
        hex::encode(root.as_ref()),
        "bfe9062561ae077a339ce49786f7287bc54711e4a50129bd8fb31daea5a66ac9",
        "fixture root hash should remain stable",
    );

    let committed = db.revision(root).expect("committed view");
    assert_eq!(committed.val(b"a").expect("query a"), None);
    assert_eq!(committed.val(b"b").expect("query b"), None);

    let carol = committed
        .val(b"c")
        .expect("query c")
        .expect("carol entry must exist");
    assert_eq!(&*carol, b"carol-0001");

    let dan = committed
        .val(b"d")
        .expect("query d")
        .expect("dan entry must exist");
    assert_eq!(&*dan, b"dan-0001");
}
