use std::{env, fs, path::PathBuf};

use firewood_storage::{Storage, StorageOptions, SyncPolicy};

fn main() {
    let out_dir = env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("tests/storage/fixtures/branch_factor_256/snapshot"));

    if out_dir.exists() {
        fs::remove_dir_all(&out_dir).expect("clean existing snapshot");
    }
    fs::create_dir_all(&out_dir).expect("create snapshot directory");

    let mut options = StorageOptions::default();
    options.retain_snapshots = 3;
    options.sync_policy = SyncPolicy::Always;

    let storage = Storage::open_with_options(
        out_dir.to_str().expect("fixture path must be valid UTF-8"),
        options,
    )
    .expect("open fixture storage");

    storage.put(b"accounts/alice".to_vec(), b"alice-0001".to_vec());
    storage.put(b"accounts/bob".to_vec(), b"bob-0001".to_vec());
    storage
        .commit_block(1)
        .expect("commit initial snapshot block");

    storage.put(b"accounts/alice".to_vec(), b"alice-0002".to_vec());
    storage.put(b"accounts/carol".to_vec(), b"carol-0001".to_vec());
    storage.delete(b"accounts/bob");
    storage
        .commit_block(2)
        .expect("commit second snapshot block");

    storage.put(b"accounts/dan".to_vec(), b"dan-0001".to_vec());
    storage.delete(b"accounts/alice");
    storage
        .commit_block(3)
        .expect("commit final snapshot block");
}
