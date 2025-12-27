use std::{env, fs, path::PathBuf};

use firewood::db::{BatchOp, Db, DbConfig};
use firewood::manager::RevisionManagerConfig;
use firewood::v2::api::{Db as _, Proposal as _};
use firewood_storage::noop_storage_metrics;

fn main() {
    let out_path = env::args().nth(1).map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from("tests/storage/fixtures/branch_factor_256/snapshot.firewood")
    });

    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent).expect("create fixture directory");
    }
    if out_path.exists() {
        fs::remove_file(&out_path).expect("remove existing snapshot");
    }

    let manager_cfg = RevisionManagerConfig::builder().max_revisions(4).build();
    let db_cfg = DbConfig::builder().manager(manager_cfg).build();
    let db = Db::new(&out_path, db_cfg, noop_storage_metrics()).expect("create fixture db");

    db.propose(vec![
        BatchOp::Put {
            key: b"a".to_vec(),
            value: b"alice-0001".to_vec(),
        },
        BatchOp::Put {
            key: b"b".to_vec(),
            value: b"bob-0001".to_vec(),
        },
    ])
    .expect("stage genesis accounts")
    .commit()
    .expect("commit block 1");

    db.propose(vec![
        BatchOp::Put {
            key: b"a".to_vec(),
            value: b"alice-0002".to_vec(),
        },
        BatchOp::Put {
            key: b"c".to_vec(),
            value: b"carol-0001".to_vec(),
        },
        BatchOp::Delete { key: b"b".to_vec() },
    ])
    .expect("stage second block")
    .commit()
    .expect("commit block 2");

    db.propose(vec![
        BatchOp::Put {
            key: b"d".to_vec(),
            value: b"dan-0001".to_vec(),
        },
        BatchOp::Delete { key: b"a".to_vec() },
    ])
    .expect("stage third block")
    .commit()
    .expect("commit block 3");
}
