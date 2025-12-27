use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};

use bytemuck::bytes_of;
use firewood::db::{BatchOp, Db, DbConfig};
use firewood::manager::RevisionManagerConfig;
use firewood::v2::api::{Db as _, DbView as _, Proposal as _};
use firewood_storage::{noop_storage_metrics, AreaIndex, NodeStoreHeader};

#[test]
fn commit_skips_corrupt_free_list_entry() {
    let tmpdir = tempfile::tempdir().expect("create tempdir");
    let db_path = tmpdir.path().join("freelist_corruption.firewood");

    let manager_cfg = RevisionManagerConfig::builder().max_revisions(1).build();
    let db_cfg = DbConfig::builder().manager(manager_cfg).build();
    let db = Db::new(&db_path, db_cfg, noop_storage_metrics()).expect("create db");

    db.propose(vec![BatchOp::Put {
        key: b"key",
        value: b"value-0",
    }])
    .expect("create proposal")
    .commit()
    .expect("commit revision");

    let mut header_block = vec![0u8; firewood_storage::NodeStoreHeader::SIZE as usize];
    File::open(&db_path)
        .expect("open db file")
        .read_exact(&mut header_block)
        .expect("read header");
    let header_slice = &mut header_block[..std::mem::size_of::<NodeStoreHeader>()];
    let mut header = *NodeStoreHeader::from_bytes(header_slice);
    let size_before = header.size();
    let root_addr = header
        .root_address()
        .expect("expected committed root address");

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&db_path)
        .expect("open db for corruption");

    let mut area_index_byte = [0u8; 1];
    file.seek(SeekFrom::Start(root_addr.get()))
        .expect("seek to stored area");
    file.read_exact(&mut area_index_byte)
        .expect("read area index");
    let area_index = AreaIndex::try_from(area_index_byte[0]).expect("valid area index");

    file.seek(SeekFrom::Start(root_addr.get() + 1))
        .expect("seek to stored marker");
    file.write_all(&[0x01u8])
        .expect("overwrite stored area marker");

    header.free_lists_mut()[area_index.as_usize()] = Some(root_addr);
    header_slice.copy_from_slice(bytes_of(&header));
    file.seek(SeekFrom::Start(0)).expect("seek to header start");
    file.write_all(&header_block)
        .expect("write corrupted header");
    file.sync_data().expect("flush corruption");
    drop(file);

    db.propose(vec![BatchOp::Put {
        key: b"key",
        value: b"value-1",
    }])
    .expect("create proposal after corruption")
    .commit()
    .expect("commit recovery revision");

    let (size_after, head_after) = {
        let mut header_block = vec![0u8; firewood_storage::NodeStoreHeader::SIZE as usize];
        File::open(&db_path)
            .expect("reopen db file")
            .read_exact(&mut header_block)
            .expect("read header");
        let header_slice = &header_block[..std::mem::size_of::<NodeStoreHeader>()];
        let header = *NodeStoreHeader::from_bytes(header_slice);
        let head = header.free_lists()[area_index.as_usize()]
            .map(|addr: firewood_storage::LinearAddress| addr.get());
        (header.size(), head)
    };

    assert!(
        size_after > size_before,
        "expected allocator to grow the store instead of reusing corrupted block",
    );
    assert_ne!(
        head_after,
        Some(root_addr.get()),
        "corrupted free list entry should not remain the head",
    );

    let latest_root = db
        .root_hash()
        .expect("get root hash")
        .expect("non-empty root");
    let committed = db.revision(latest_root).expect("get committed view");
    assert_eq!(
        &*committed
            .val(b"key")
            .expect("query committed value")
            .expect("value must exist"),
        b"value-1",
    );
}

#[test]
fn commit_rejects_leaked_allocator_after_pruning() {
    let tmpdir = tempfile::tempdir().expect("create tempdir");
    let db_path = tmpdir.path().join("allocator_leak.firewood");

    let manager_cfg = RevisionManagerConfig::builder().max_revisions(1).build();
    let db_cfg = DbConfig::builder().manager(manager_cfg).build();
    let db = Db::new(&db_path, db_cfg, noop_storage_metrics()).expect("create db");

    db.propose(vec![BatchOp::Put {
        key: b"key-0",
        value: b"value-0",
    }])
    .expect("create proposal")
    .commit()
    .expect("commit baseline revision");

    let mut header_block = vec![0u8; firewood_storage::NodeStoreHeader::SIZE as usize];
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&db_path)
        .expect("open db for leak injection");
    file.read_exact(&mut header_block)
        .expect("read existing header");
    let header_slice = &mut header_block[..std::mem::size_of::<NodeStoreHeader>()];
    let mut header = *NodeStoreHeader::from_bytes(header_slice);
    header.set_size(header.size() + AreaIndex::MIN.size());
    header_slice.copy_from_slice(bytes_of(&header));
    file.seek(SeekFrom::Start(0)).expect("rewind header");
    file.write_all(&header_block).expect("persist leaked size");
    file.sync_data().expect("flush leaked size");

    let err = db
        .propose(vec![BatchOp::Put {
            key: b"key-1",
            value: b"value-1",
        }])
        .expect("create proposal after leak")
        .commit()
        .expect_err("allocator check should reject leaked space");

    assert!(
        err.to_string().contains("allocator integrity check failed"),
        "unexpected error: {err}"
    );
}
