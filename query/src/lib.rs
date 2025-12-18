#![forbid(unsafe_code)]

use cbv::CharacterBaselineVector;
use pev::{pev_digest, PolicyEcologyVector};
use pvgs::{PvgsCommitRequest, PvgsStore};
use sep::{SepEventInternal, SepEventType, SepLog};
use thiserror::Error;
use ucf_protocol::ucf::v1::{PVGSKeyEpoch, PVGSReceipt, ProofReceipt};
use wire::{AuthContext, Envelope};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryRequest {
    pub subject: String,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryResult {
    pub auth: Option<AuthContext>,
    pub baseline: Option<CharacterBaselineVector>,
    pub last_commit: Option<PVGSReceipt>,
    pub last_verification: Option<ProofReceipt>,
    pub current_epoch: Option<PVGSKeyEpoch>,
    pub latest_event: Option<SepEventInternal>,
    pub recent_vrf_digest: Option<[u8; 32]>,
}

pub trait QueryInspector {
    fn fetch(&self, request: QueryRequest) -> Result<QueryResult, QueryError>;
    fn prepare_commit(&self, envelope: Envelope) -> Result<PvgsCommitRequest, QueryError>;
    fn summarize_verification(
        &self,
        verification: ProofReceipt,
    ) -> Result<ProofReceipt, QueryError>;
}

#[derive(Debug, Error)]
pub enum QueryError {
    #[error("lookup failed: {0}")]
    Lookup(String),
    #[error("construction failed: {0}")]
    Construction(String),
}

/// Return the latest committed key epoch if present.
pub fn get_current_key_epoch(store: &PvgsStore) -> Option<PVGSKeyEpoch> {
    store.key_epoch_history.current().cloned()
}

/// List all key epochs in insertion order.
pub fn list_key_epochs(store: &PvgsStore) -> Vec<PVGSKeyEpoch> {
    store.key_epoch_history.list().to_vec()
}

/// Retrieve a specific key epoch by id.
pub fn get_key_epoch(store: &PvgsStore, epoch_id: u64) -> Option<PVGSKeyEpoch> {
    store
        .key_epoch_history
        .list()
        .iter()
        .find(|epoch| epoch.key_epoch_id == epoch_id)
        .cloned()
}

/// Return the most recent Policy Ecology Vector if present.
pub fn get_latest_pev(store: &PvgsStore) -> Option<PolicyEcologyVector> {
    store.pev_store.latest().cloned()
}

/// Return the latest PEV digest if stored.
pub fn get_latest_pev_digest(store: &PvgsStore) -> Option<[u8; 32]> {
    store.pev_store.latest().and_then(pev_digest)
}

/// List all known PEV version digests in insertion order.
pub fn list_pev_versions(store: &PvgsStore) -> Vec<[u8; 32]> {
    store
        .pev_store
        .list()
        .iter()
        .filter_map(pev_digest)
        .collect()
}

/// Return true if the SEP log contains a control frame event with the digest in the session.
pub fn has_control_frame_digest(log: &SepLog, session_id: &str, digest: [u8; 32]) -> bool {
    log.events.iter().any(|event| {
        event.session_id == session_id
            && matches!(event.event_type, SepEventType::EvControlFrame)
            && event.object_digest == digest
    })
}

/// List all control frame digests for the provided session.
pub fn list_control_frames(log: &SepLog, session_id: &str) -> Vec<[u8; 32]> {
    log.events
        .iter()
        .filter(|event| {
            event.session_id == session_id
                && matches!(event.event_type, SepEventType::EvControlFrame)
        })
        .map(|event| event.object_digest)
        .collect()
}

/// List all signal frame digests for the provided session.
pub fn list_signal_frames(log: &SepLog, session_id: &str) -> Vec<[u8; 32]> {
    log.events
        .iter()
        .filter(|event| {
            event.session_id == session_id
                && matches!(event.event_type, SepEventType::EvSignalFrame)
        })
        .map(|event| event.object_digest)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use keys::KeyStore;
    use pev::PolicyEcologyDimension;
    use sep::{FrameEventKind, SepLog};
    use std::collections::HashSet;
    use vrf::VrfEngine;

    fn store_with_epochs() -> (PvgsStore, PVGSKeyEpoch, PVGSKeyEpoch) {
        let mut known_charter_versions = HashSet::new();
        known_charter_versions.insert("charter".to_string());
        let mut known_policy_versions = HashSet::new();
        known_policy_versions.insert("policy".to_string());
        let mut known_profiles = HashSet::new();
        known_profiles.insert([1u8; 32]);

        let mut store = PvgsStore::new(
            [0u8; 32],
            known_charter_versions,
            known_policy_versions,
            known_profiles,
        );
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);

        let first =
            keystore.make_key_epoch_proto(1, 10, vrf_engine.vrf_public_key().to_vec(), None);
        let second = keystore.make_key_epoch_proto(
            2,
            20,
            vrf_engine.vrf_public_key().to_vec(),
            Some(first.announcement_digest.0),
        );

        store.key_epoch_history.push(first.clone()).unwrap();
        store.key_epoch_history.push(second.clone()).unwrap();
        store
            .committed_payload_digests
            .insert(first.announcement_digest.0);
        store
            .committed_payload_digests
            .insert(second.announcement_digest.0);

        (store, first, second)
    }

    #[test]
    fn queries_return_clones() {
        let (store, first, second) = store_with_epochs();
        let current = get_current_key_epoch(&store).expect("missing current");
        assert_eq!(current.key_epoch_id, second.key_epoch_id);

        let listed = list_key_epochs(&store);
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].announcement_digest, first.announcement_digest);

        let fetched = get_key_epoch(&store, first.key_epoch_id).expect("missing epoch one");
        assert_eq!(fetched.announcement_digest, first.announcement_digest);

        let mut mutated = fetched;
        mutated.attestation_key_id.push_str("-mut");
        assert_ne!(
            mutated.attestation_key_id,
            store.key_epoch_history.list()[0].attestation_key_id
        );
    }

    #[test]
    fn pev_queries_return_clones_and_digests() {
        let (mut store, _, _) = store_with_epochs();
        let pev = PolicyEcologyVector {
            dimensions: vec![PolicyEcologyDimension {
                name: "conservatism_bias".to_string(),
                value: 1,
            }],
            pev_digest: Some([0xAB; 32].to_vec()),
            pev_version_digest: None,
            pev_epoch: Some(1),
        };
        store.pev_store.push(pev.clone()).expect("push pev");

        let latest = get_latest_pev(&store).expect("missing pev");
        assert_eq!(pev_digest(&latest), Some([0xAB; 32]));

        let mut mutated = latest;
        mutated.dimensions[0].value = 2;
        assert_eq!(pev.dimensions[0].value, 1);
        assert_eq!(
            store.pev_store.latest().unwrap().dimensions[0].value,
            pev.dimensions[0].value
        );

        assert_eq!(get_latest_pev_digest(&store), Some([0xAB; 32]));
        assert_eq!(list_pev_versions(&store), vec![[0xAB; 32]]);
    }

    #[test]
    fn frame_queries_return_digests() {
        let mut log = SepLog::default();
        let control_digest = [7u8; 32];
        let signal_digest = [8u8; 32];

        log.append_frame_event(
            "session-1".to_string(),
            FrameEventKind::ControlFrame,
            control_digest,
            vec![],
        );
        log.append_frame_event(
            "session-1".to_string(),
            FrameEventKind::SignalFrame,
            signal_digest,
            vec![],
        );

        assert!(has_control_frame_digest(&log, "session-1", control_digest));
        assert!(!has_control_frame_digest(&log, "session-1", signal_digest));

        let controls = list_control_frames(&log, "session-1");
        assert_eq!(controls, vec![control_digest]);

        let signals = list_signal_frames(&log, "session-1");
        assert_eq!(signals, vec![signal_digest]);
    }
}
