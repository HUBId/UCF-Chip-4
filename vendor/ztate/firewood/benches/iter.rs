//! Criterion benchmark verifying allocation behaviour of Merkle iterators.
//!
//! Run with `cargo bench --manifest-path firewood/Cargo.toml --bench iter`.

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use firewood::merkle::Merkle;
use firewood_storage::{
    noop_storage_metrics, ImmutableProposal, MemStore, MutableProposal, NodeStore, TrieReader,
};
use std::alloc::System;
use std::hint::black_box;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use tracking_allocator::{
    AllocationGroupId, AllocationGroupToken, AllocationRegistry, AllocationTracker, Allocator,
};

const EXPECTED_NODE_ALLOCATIONS: usize = 67;
const EXPECTED_KEY_VALUE_ALLOCATIONS: usize = 72;

#[global_allocator]
static GLOBAL: Allocator<System> = Allocator::system();

struct CountingTracker;

static TRACKING_INIT: OnceLock<()> = OnceLock::new();
static ALLOCATION_COUNT: AtomicUsize = AtomicUsize::new(0);

impl AllocationTracker for CountingTracker {
    fn allocated(
        &self,
        _addr: usize,
        _object_size: usize,
        _wrapped_size: usize,
        _group_id: AllocationGroupId,
    ) {
        ALLOCATION_COUNT.fetch_add(1, Ordering::SeqCst);
    }

    fn deallocated(
        &self,
        _addr: usize,
        _object_size: usize,
        _wrapped_size: usize,
        _source_group_id: AllocationGroupId,
        _current_group_id: AllocationGroupId,
    ) {
        // We only track allocations for this benchmark.
    }
}

fn initialize_tracking() {
    TRACKING_INIT.get_or_init(|| {
        AllocationRegistry::set_global_tracker(CountingTracker)
            .expect("global allocation tracker should only be set once");
    });
}

fn count_allocs<F: FnOnce()>(f: F) -> usize {
    initialize_tracking();

    let mut token = AllocationGroupToken::register().expect("failed to register allocation group");
    let guard = token.enter();

    ALLOCATION_COUNT.store(0, Ordering::SeqCst);
    AllocationRegistry::enable_tracking();

    let result = catch_unwind(AssertUnwindSafe(f));

    AllocationRegistry::disable_tracking();
    drop(guard);
    drop(token);

    let allocations = ALLOCATION_COUNT.load(Ordering::SeqCst);

    if let Err(payload) = result {
        std::panic::resume_unwind(payload);
    }

    allocations
}

fn sample_pairs() -> Vec<(Vec<u8>, Vec<u8>)> {
    vec![
        (vec![0x00, 0x00], vec![0xAA, 0x00]),
        (vec![0x00, 0x10], vec![0xAA, 0x10]),
        (vec![0x10, 0x00], vec![0xBB, 0x00]),
        (vec![0x10, 0x10], vec![0xBB, 0x10]),
        (vec![0x20, 0x00], vec![0xCC, 0x00]),
        (vec![0xFF, 0x00], vec![0xDD, 0x00]),
    ]
}

fn populate_merkle(merkle: &mut Merkle<NodeStore<MutableProposal, MemStore>>) {
    for (key, value) in sample_pairs() {
        merkle
            .insert(&key, value.into_boxed_slice())
            .expect("sample inserts should succeed");
    }
}

fn create_unpersisted_merkle() -> Merkle<NodeStore<MutableProposal, MemStore>> {
    let storage = Arc::new(MemStore::new(vec![]));
    let mut merkle = Merkle::from(NodeStore::new_empty_proposal(
        storage,
        noop_storage_metrics(),
    ));
    populate_merkle(&mut merkle);
    merkle
}

fn create_persisted_merkle() -> Merkle<NodeStore<Arc<ImmutableProposal>, MemStore>> {
    let storage = Arc::new(MemStore::new(vec![]));
    let mut merkle = Merkle::from(NodeStore::new_empty_proposal(
        storage,
        noop_storage_metrics(),
    ));
    populate_merkle(&mut merkle);
    merkle.hash()
}

fn iterate_nodes<T: TrieReader>(merkle: &Merkle<T>) -> usize {
    let mut iter = merkle.node_iter();
    let mut visited = 0usize;
    while let Some(result) = iter.next() {
        let (key, node) = result.expect("node iteration should succeed");
        black_box(key);
        black_box(node);
        visited += 1;
    }
    visited
}

fn iterate_key_values<T: TrieReader>(merkle: &Merkle<T>) -> usize {
    let mut iter = merkle.key_value_iter();
    let mut visited = 0usize;
    while let Some(result) = iter.next() {
        let (key, value) = result.expect("key-value iteration should succeed");
        black_box(key);
        black_box(value);
        visited += 1;
    }
    visited
}

fn bench_merkle_iter_allocations(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("merkle_iterator_allocations");
    group.sample_size(10);

    group.bench_function("node_iter_unpersisted", |b| {
        b.iter_batched(
            create_unpersisted_merkle,
            |merkle| {
                let allocations = count_allocs(|| {
                    let visited = iterate_nodes(&merkle);
                    assert!(visited > 0, "iterator should visit nodes");
                    black_box(visited);
                });
                assert!(
                    allocations <= EXPECTED_NODE_ALLOCATIONS,
                    "MerkleNodeIter allocated {allocations} times for in-memory children (expected ≤ {EXPECTED_NODE_ALLOCATIONS})"
                );
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("node_iter_persisted", |b| {
        b.iter_batched(
            create_persisted_merkle,
            |merkle| {
                let allocations = count_allocs(|| {
                    let visited = iterate_nodes(&merkle);
                    assert!(visited > 0, "iterator should visit nodes");
                    black_box(visited);
                });
                assert!(
                    allocations <= EXPECTED_NODE_ALLOCATIONS,
                    "MerkleNodeIter allocated {allocations} times when reading persisted children (expected ≤ {EXPECTED_NODE_ALLOCATIONS})"
                );
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("key_value_iter_unpersisted", |b| {
        b.iter_batched(
            create_unpersisted_merkle,
            |merkle| {
                let allocations = count_allocs(|| {
                    let visited = iterate_key_values(&merkle);
                    assert!(visited > 0, "iterator should visit entries");
                    black_box(visited);
                });
                assert!(
                    allocations <= EXPECTED_KEY_VALUE_ALLOCATIONS,
                    "MerkleKeyValueIter allocated {allocations} times for in-memory children (expected ≤ {EXPECTED_KEY_VALUE_ALLOCATIONS})"
                );
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("key_value_iter_persisted", |b| {
        b.iter_batched(
            create_persisted_merkle,
            |merkle| {
                let allocations = count_allocs(|| {
                    let visited = iterate_key_values(&merkle);
                    assert!(visited > 0, "iterator should visit entries");
                    black_box(visited);
                });
                assert!(
                    allocations <= EXPECTED_KEY_VALUE_ALLOCATIONS,
                    "MerkleKeyValueIter allocated {allocations} times when reading persisted children (expected ≤ {EXPECTED_KEY_VALUE_ALLOCATIONS})"
                );
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(benches, bench_merkle_iter_allocations);
criterion_main!(benches);
