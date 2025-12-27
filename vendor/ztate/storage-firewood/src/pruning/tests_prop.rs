use super::*;
use bincode::Options;
use proptest::prelude::*;
use rpp_pruning::{
    Envelope, FirewoodEnvelope, Snapshot, TaggedDigest, ValidationError, SNAPSHOT_STATE_TAG,
};
use std::collections::BTreeMap;

#[allow(dead_code)]
fn proptest_config() -> ProptestConfig {
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(48);
    ProptestConfig {
        cases,
        ..ProptestConfig::default()
    }
}

prop_compose! {
    fn arb_hash()(bytes in prop::array::uniform32(any::<u8>())) -> Hash {
        bytes
    }
}

prop_compose! {
    fn arb_pruning_sequence()(retain in 1usize..6usize,
                              entries in prop::collection::vec((any::<u64>(), arb_hash()), 1..6))
        -> (usize, Vec<(u64, Hash)>)
    {
        let mut unique = BTreeMap::new();
        for (id, root) in entries {
            unique.insert(id, root);
        }
        let mut ordered: Vec<_> = unique.into_iter().collect();
        ordered.sort_by_key(|(id, _)| *id);
        (retain, ordered)
    }
}

proptest! {
    #![proptest_config(proptest_config())]
    fn pruning_proofs_roundtrip((retain, entries) in arb_pruning_sequence()) {
        let mut pruner = FirewoodPruner::new(retain);
        for (id, root) in entries.iter().cloned() {
            let proof = pruner.prune_block(id, root);
            let firewood = FirewoodEnvelope::from(&proof);
            let encoded = rpp_pruning::canonical_bincode_options()
                .serialize(&firewood)
                .expect("serialize pruning envelope");
            let decoded: FirewoodEnvelope = rpp_pruning::canonical_bincode_options()
                .deserialize(&encoded)
                .expect("deserialize pruning envelope");
            let restored: Envelope = decoded.try_into().expect("firewood envelope");
            assert_eq!(restored, proof);
            let json_a = serde_json::to_string(&firewood).expect("serialize firewood envelope");
            let json_b = serde_json::to_string(&firewood).expect("serialize firewood envelope");
            assert_eq!(json_a, json_b);
            assert!(FirewoodPruner::verify_pruned_state(root, &restored));
        }
    }
}

proptest! {
    #![proptest_config(proptest_config())]
    fn pruning_proof_detects_mutation((retain, entries) in arb_pruning_sequence()) {
        let mut pruner = FirewoodPruner::new(retain);
        for (id, root) in entries.iter().cloned() {
            let proof = pruner.prune_block(id, root);
            let mut digest = *proof.snapshot().state_commitment().digest();
            digest[0] ^= 0xFF;
            let corrupted_snapshot = Snapshot::new(
                proof.snapshot().schema_version(),
                proof.snapshot().parameter_version(),
                proof.snapshot().block_height(),
                TaggedDigest::new(SNAPSHOT_STATE_TAG, digest),
            )
            .expect("tag preserved");
            let corrupted = Envelope::new(
                proof.schema_version(),
                proof.parameter_version(),
                corrupted_snapshot,
                proof.segments().to_vec(),
                proof.commitment().clone(),
                proof.binding_digest(),
            )
            .expect("tag preserved");
            assert!(!FirewoodPruner::verify_pruned_state(root, &corrupted));
        }
    }
}

proptest! {
    #![proptest_config(proptest_config())]
    fn firewood_helpers_reject_swapped_digests((retain, entries) in arb_pruning_sequence()) {
        let mut pruner = FirewoodPruner::new(retain);
        for (id, root) in entries.iter().cloned() {
            let proof = pruner.prune_block(id, root);
            let firewood = FirewoodEnvelope::from(&proof);
            let schema_digest = *firewood.schema_digest();
            let parameter_digest = *firewood.parameter_digest();
            let swapped = FirewoodEnvelope::new(
                parameter_digest,
                schema_digest,
                proof.schema_version(),
                proof.parameter_version(),
                proof.snapshot().clone(),
                proof.segments().to_vec(),
                proof.commitment().clone(),
                proof.binding_digest(),
            );
            assert!(matches!(
                swapped,
                Err(ValidationError::VersionDigestMismatch { .. })
            ));
        }
    }
}
