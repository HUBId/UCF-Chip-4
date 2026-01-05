#![forbid(unsafe_code)]

use blake3::Hasher;
use pvgs::{compute_experience_record_digest, PvgsStore};
use sep::{EdgeType, SepEventType};
use std::collections::HashSet;
use thiserror::Error;
use ucf_protocol::ucf::v1::{ExperienceRecord, ReasonCodes, RecordType, Ref};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

const POLICY_QUERY_STUB_DOMAIN: &[u8] = b"UCF:HASH:POLICY_QUERY_STUB";
const POLICY_BUNDLE_DOMAIN: &[u8] = b"UCF:HASH:POLICY_REPLAY_BUNDLE";
const ACTION_MANIFEST_DOMAIN: &[u8] = b"UCF:HASH:ACTION_MANIFEST";
const DEFAULT_MAX_ACTION_ENTRIES: usize = 256;
const DEFAULT_MAX_POLICY_ENTRIES: usize = 256;
const SEED_WINDOW: usize = 8;

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyReplayBundle {
    pub bundle_id: String,
    pub bundle_digest: [u8; 32],
    pub policy_version_digest: String,
    pub charter_version_digest: String,
    pub ruleset_digest: [u8; 32],
    pub policy_query_digests: Vec<[u8; 32]>,
    pub expected_decision_digests: Vec<[u8; 32]>,
    pub created_at_ms: u64,
}

impl PolicyReplayBundle {
    fn recompute_digest(&self) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(POLICY_BUNDLE_DOMAIN);
        hasher.update(self.bundle_id.as_bytes());
        hasher.update(self.policy_version_digest.as_bytes());
        hasher.update(self.charter_version_digest.as_bytes());
        hasher.update(&self.ruleset_digest);
        for digest in &self.policy_query_digests {
            hasher.update(digest);
        }
        for digest in &self.expected_decision_digests {
            hasher.update(digest);
        }
        hasher.update(&self.created_at_ms.to_le_bytes());
        *hasher.finalize().as_bytes()
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionManifest {
    pub manifest_id: String,
    pub manifest_digest: [u8; 32],
    pub ruleset_digest: [u8; 32],
    pub entries: Vec<ActionEntry>,
}

impl ActionManifest {
    fn recompute_digest(&self) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(ACTION_MANIFEST_DOMAIN);
        hasher.update(self.manifest_id.as_bytes());
        hasher.update(&self.ruleset_digest);
        for entry in &self.entries {
            hasher.update(&entry.action_digest);
            hasher.update(&entry.decision_digest);
            hasher.update(&entry.receipt_digest);
            hasher.update(&entry.record_digest);
            hasher.update(&entry.created_at_ms.to_le_bytes());
        }
        *hasher.finalize().as_bytes()
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionEntry {
    pub action_digest: [u8; 32],
    pub decision_digest: [u8; 32],
    pub receipt_digest: [u8; 32],
    pub record_digest: [u8; 32],
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayStatus {
    Match,
    Mismatch,
    Partial,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayResult {
    pub status: ReplayStatus,
    pub mismatches: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpotCheckReport {
    pub status: ReplayStatus,
    pub mismatches: Vec<String>,
    pub reason_codes: Vec<String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ReplayError {
    #[error("mismatched bundle lengths")]
    LengthMismatch,
}

pub fn generate_policy_replay_bundle(session_id: &str, store: &PvgsStore) -> PolicyReplayBundle {
    let mut decision_pairs: Vec<([u8; 32], [u8; 32])> = collect_policy_decisions(session_id, store)
        .into_iter()
        .take(DEFAULT_MAX_POLICY_ENTRIES)
        .map(|decision_digest| (policy_query_stub(&decision_digest), decision_digest))
        .collect();

    decision_pairs.sort_by(|(a_query, _), (b_query, _)| a_query.cmp(b_query));

    let (policy_query_digests, expected_decision_digests): (Vec<_>, Vec<_>) =
        decision_pairs.into_iter().unzip();

    let created_at_ms = latest_record_timestamp(session_id, store).unwrap_or(0);

    let mut bundle = PolicyReplayBundle {
        bundle_id: format!("{session_id}-policy-replay"),
        bundle_digest: [0u8; 32],
        policy_version_digest: store.ruleset_state.policy_version_digest.clone(),
        charter_version_digest: store.ruleset_state.charter_version_digest.clone(),
        ruleset_digest: store.ruleset_state.ruleset_digest,
        policy_query_digests,
        expected_decision_digests,
        created_at_ms,
    };

    bundle.bundle_digest = bundle.recompute_digest();
    bundle
}

pub fn generate_action_manifest(session_id: &str, store: &PvgsStore) -> ActionManifest {
    let entries = collect_action_entries(session_id, store);
    let manifest_id = format!("{session_id}-action-manifest");

    let mut manifest = ActionManifest {
        manifest_id,
        manifest_digest: [0u8; 32],
        ruleset_digest: store.ruleset_state.ruleset_digest,
        entries,
    };

    manifest
        .entries
        .sort_by(|a, b| match a.action_digest.cmp(&b.action_digest) {
            std::cmp::Ordering::Equal => a.record_digest.cmp(&b.record_digest),
            other => other,
        });
    manifest.entries.truncate(DEFAULT_MAX_ACTION_ENTRIES);
    manifest.manifest_digest = manifest.recompute_digest();
    manifest
}

pub fn verify_policy_replay(
    session_id: &str,
    bundle: &PolicyReplayBundle,
    store: &mut PvgsStore,
) -> Result<ReplayResult, ReplayError> {
    if bundle.policy_query_digests.len() != bundle.expected_decision_digests.len() {
        return Err(ReplayError::LengthMismatch);
    }

    let status = ReplayStatus::Partial;
    let mismatches = Vec::new();

    log_replay_event(
        session_id,
        bundle.bundle_digest,
        &mut store.sep_log,
        status,
        &mismatches,
        &[],
    );

    Ok(ReplayResult { status, mismatches })
}

pub fn verify_action_manifest(
    session_id: &str,
    manifest: &ActionManifest,
    store: &mut PvgsStore,
) -> ReplayResult {
    let mut mismatches = Vec::new();
    let mut status = ReplayStatus::Match;

    for entry in &manifest.entries {
        let mut entry_ok = true;

        match store.receipts.get(&entry.receipt_digest) {
            Some(receipt) => {
                let action_binding = receipt
                    .bindings
                    .action_digest
                    .as_ref()
                    .map(|d| d.0)
                    .unwrap_or([0u8; 32]);
                let decision_binding = receipt
                    .bindings
                    .decision_digest
                    .as_ref()
                    .map(|d| d.0)
                    .unwrap_or([0u8; 32]);

                if action_binding != entry.action_digest
                    || decision_binding != entry.decision_digest
                {
                    entry_ok = false;
                }
            }
            None => {
                entry_ok = false;
            }
        }

        match lookup_record(&entry.record_digest, &store.experience_store.records) {
            Some(record) => {
                if let Some(gov) = &record.governance_frame {
                    let receipt_matches = gov.pvgs_receipt_ref.as_ref().and_then(digest_from_ref)
                        == Some(entry.receipt_digest);
                    let mut decisions: Vec<[u8; 32]> = gov
                        .policy_decision_refs
                        .iter()
                        .filter_map(digest_from_ref)
                        .collect();
                    decisions.sort();

                    if !receipt_matches
                        || decisions.first().copied().unwrap_or([0u8; 32]) != entry.decision_digest
                    {
                        entry_ok = false;
                    }
                } else {
                    entry_ok = false;
                }
            }
            None => {
                entry_ok = false;
            }
        }

        let neighbors = store.causal_graph.neighbors(entry.action_digest);
        if !neighbors.iter().any(|(edge, digest)| {
            matches!(edge, EdgeType::Authorizes) && digest == &entry.receipt_digest
        }) {
            entry_ok = false;
        }

        if !entry_ok {
            status = ReplayStatus::Mismatch;
            mismatches.push(format!(
                "mismatch for action {} record {}",
                hex::encode(entry.action_digest),
                hex::encode(entry.record_digest)
            ));
        }
    }

    log_replay_event(
        session_id,
        manifest.manifest_digest,
        &mut store.sep_log,
        status,
        &mismatches,
        &[],
    );

    ReplayResult { status, mismatches }
}

pub fn daily_spot_check(
    session_id: &str,
    manifest: &ActionManifest,
    seed_digest: [u8; 32],
    sample_size: usize,
    store: &mut PvgsStore,
) -> SpotCheckReport {
    let mut sorted_entries = manifest.entries.clone();
    sorted_entries.sort_by(|a, b| a.action_digest.cmp(&b.action_digest));

    let total_entries = sorted_entries.len();
    let target_samples = sample_size.max(1);

    let seed_bytes: [u8; SEED_WINDOW] = seed_digest[..SEED_WINDOW]
        .try_into()
        .expect("slice matches SEED_WINDOW");
    let seed_value = u64::from_le_bytes(seed_bytes);

    let step = if total_entries == 0 {
        1
    } else {
        std::cmp::max(1, total_entries.div_ceil(target_samples))
    };
    let offset = if total_entries == 0 {
        0
    } else {
        (seed_value as usize) % total_entries
    };

    let mut sampled_entries = Vec::new();
    let mut seen = HashSet::new();
    let mut index = offset;

    while sampled_entries.len() < total_entries.min(target_samples) {
        if !seen.insert(index) {
            break;
        }

        if let Some(entry) = sorted_entries.get(index) {
            sampled_entries.push(entry.clone());
        }

        if total_entries == 0 {
            break;
        }

        index = (index + step) % total_entries;
    }

    let mut sampled_manifest = ActionManifest {
        manifest_id: manifest.manifest_id.clone(),
        manifest_digest: [0u8; 32],
        ruleset_digest: manifest.ruleset_digest,
        entries: sampled_entries,
    };
    sampled_manifest.manifest_digest = sampled_manifest.recompute_digest();

    let replay_result = verify_action_manifest(session_id, &sampled_manifest, store);

    let mut reason_codes = vec![ReasonCodes::GV_REPLAY_SPOTCHECK.to_string()];
    match replay_result.status {
        ReplayStatus::Mismatch => {
            reason_codes.push(ReasonCodes::RE_REPLAY_MISMATCH.to_string());
            reason_codes.extend(replay_result.mismatches.iter().cloned());
        }
        _ => reason_codes.push(ReasonCodes::RE_INTEGRITY_OK.to_string()),
    }

    log_replay_event(
        session_id,
        sampled_manifest.manifest_digest,
        &mut store.sep_log,
        replay_result.status,
        &replay_result.mismatches,
        &reason_codes,
    );

    SpotCheckReport {
        status: replay_result.status,
        mismatches: replay_result.mismatches,
        reason_codes,
    }
}

fn log_replay_event(
    session_id: &str,
    object_digest: [u8; 32],
    log: &mut sep::SepLog,
    status: ReplayStatus,
    mismatches: &[String],
    base_reasons: &[String],
) {
    let mut reasons: Vec<String> = base_reasons.to_vec();
    match status {
        ReplayStatus::Mismatch => reasons.push(ReasonCodes::RE_REPLAY_MISMATCH.to_string()),
        _ => reasons.push(ReasonCodes::RE_INTEGRITY_OK.to_string()),
    }

    for mismatch in mismatches {
        if !reasons.contains(mismatch) {
            reasons.push(mismatch.clone());
        }
    }

    let _ = log.append_event(
        session_id.to_string(),
        SepEventType::EvReplay,
        object_digest,
        reasons,
    );
}

fn collect_policy_decisions(session_id: &str, store: &PvgsStore) -> Vec<[u8; 32]> {
    let record_digests = records_for_session(session_id, store);
    let mut decisions = Vec::new();

    for digest in record_digests {
        if let Some(record) = lookup_record(&digest, &store.experience_store.records) {
            if matches!(
                RecordType::try_from(record.record_type),
                Ok(RecordType::RtActionExec)
            ) {
                if let Some(gov) = &record.governance_frame {
                    let mut refs: Vec<[u8; 32]> = gov
                        .policy_decision_refs
                        .iter()
                        .filter_map(digest_from_ref)
                        .collect();
                    refs.sort();
                    decisions.extend(refs);
                }
            }
        }
    }

    decisions
}

fn collect_action_entries(session_id: &str, store: &PvgsStore) -> Vec<ActionEntry> {
    let mut entries = Vec::new();

    for record_digest in records_for_session(session_id, store) {
        if let Some(record) = lookup_record(&record_digest, &store.experience_store.records) {
            if !matches!(
                RecordType::try_from(record.record_type),
                Ok(RecordType::RtActionExec)
            ) {
                continue;
            }

            let Some(gov) = &record.governance_frame else {
                continue;
            };
            let receipt_digest = gov
                .pvgs_receipt_ref
                .as_ref()
                .and_then(digest_from_ref)
                .unwrap_or([0u8; 32]);

            let mut decision_digests: Vec<[u8; 32]> = gov
                .policy_decision_refs
                .iter()
                .filter_map(digest_from_ref)
                .collect();
            decision_digests.sort();
            let decision_digest = decision_digests.first().copied().unwrap_or([0u8; 32]);

            let action_digest = action_digest_from_record(record);
            let created_at_ms = record
                .finalization_header
                .as_ref()
                .map(|f| f.timestamp_ms)
                .unwrap_or(0);

            entries.push(ActionEntry {
                action_digest,
                decision_digest,
                receipt_digest,
                record_digest,
                created_at_ms,
            });
        }
    }

    entries
}

fn action_digest_from_record(record: &ExperienceRecord) -> [u8; 32] {
    if let Some(core_ref) = &record.core_frame_ref {
        if let Some(digest) = digest_from_ref(core_ref) {
            return digest;
        }
    }

    if let Some(core) = &record.core_frame {
        if let Some(digest) = core.evidence_refs.iter().filter_map(digest_from_ref).min() {
            return digest;
        }
    }

    [0u8; 32]
}

fn policy_query_stub(decision_digest: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(POLICY_QUERY_STUB_DOMAIN);
    hasher.update(decision_digest);
    *hasher.finalize().as_bytes()
}

fn records_for_session(session_id: &str, store: &PvgsStore) -> Vec<[u8; 32]> {
    store
        .sep_log
        .events
        .iter()
        .filter(|event| {
            event.session_id == session_id && matches!(event.event_type, SepEventType::EvAgentStep)
        })
        .map(|event| event.object_digest)
        .collect()
}

fn lookup_record<'a>(
    record_digest: &[u8; 32],
    records: &'a [ExperienceRecord],
) -> Option<&'a ExperienceRecord> {
    records
        .iter()
        .find(|record| compute_experience_record_digest(record) == *record_digest)
}

fn digest_from_ref(reference: &Ref) -> Option<[u8; 32]> {
    if let Some(digest) = reference
        .digest
        .as_ref()
        .and_then(|digest| <[u8; 32]>::try_from(digest.as_slice()).ok())
    {
        return Some(digest);
    }

    if reference.id.len() == 64 {
        if let Ok(decoded) = hex::decode(&reference.id) {
            if let Ok(array) = <[u8; 32]>::try_from(decoded.as_slice()) {
                return Some(array);
            }
        }
    }

    if reference.id.len() == 32 {
        if let Ok(array) = <[u8; 32]>::try_from(reference.id.as_bytes()) {
            return Some(array);
        }
    }

    None
}

fn latest_record_timestamp(session_id: &str, store: &PvgsStore) -> Option<u64> {
    records_for_session(session_id, store)
        .iter()
        .filter_map(|digest| lookup_record(digest, &store.experience_store.records))
        .filter_map(|record| record.finalization_header.as_ref())
        .map(|header| header.timestamp_ms)
        .max()
}

#[cfg(test)]
mod tests {
    use super::*;
    use keys::KeyStore;
    use prost::Message;
    use pvgs::{
        verify_and_commit, CommitBindings, CommitType, PvgsCommitRequest, RequiredCheck,
        RequiredReceiptKind,
    };
    use std::collections::HashSet;
    use ucf_protocol::ucf::v1::{CoreFrame, GovernanceFrame};
    use vrf::VrfEngine;

    fn base_store(head_digest: [u8; 32]) -> PvgsStore {
        let mut known_charter_versions = HashSet::new();
        known_charter_versions.insert("charter-v1".to_string());
        let mut known_policy_versions = HashSet::new();
        known_policy_versions.insert("policy-v1".to_string());
        PvgsStore::new(
            head_digest,
            "charter-v1".to_string(),
            "policy-v1".to_string(),
            known_charter_versions,
            known_policy_versions,
            HashSet::new(),
        )
    }

    fn make_receipt_request(
        head_digest: [u8; 32],
        action: [u8; 32],
        decision: [u8; 32],
        epoch_id: u64,
    ) -> PvgsCommitRequest {
        PvgsCommitRequest {
            commit_id: "session-1".to_string(),
            commit_type: CommitType::ReceiptRequest,
            bindings: CommitBindings {
                action_digest: Some(action),
                decision_digest: Some(decision),
                grant_id: Some("grant-1".to_string()),
                charter_version_digest: "charter-v1".to_string(),
                policy_version_digest: "policy-v1".to_string(),
                prev_record_digest: head_digest,
                profile_digest: None,
                tool_profile_digest: None,
                pev_digest: None,
            },
            required_receipt_kind: RequiredReceiptKind::Read,
            required_checks: vec![RequiredCheck::SchemaOk, RequiredCheck::BindingOk],
            payload_digests: Vec::new(),
            epoch_id,
            key_epoch: None,
            experience_record_payload: None,
            replay_run_evidence_payload: None,
            trace_run_evidence_payload: None,
            proposal_evidence_payload: None,
            proposal_activation_payload: None,
            macro_milestone: None,
            meso_milestone: None,
            dlp_decision_payload: None,
            tool_registry_container: None,
            pev: None,
            consistency_feedback_payload: None,
            macro_consistency_digest: None,
            recovery_case: None,
            unlock_permit: None,
            tool_onboarding_event: None,
            microcircuit_config_payload: None,
            asset_manifest_payload: None,
            asset_bundle_payload: None,
        }
    }

    fn make_experience_record(
        action: [u8; 32],
        decision: [u8; 32],
        receipt: [u8; 32],
    ) -> ExperienceRecord {
        ExperienceRecord {
            record_type: RecordType::RtActionExec as i32,
            core_frame: Some(CoreFrame {
                evidence_refs: vec![Ref {
                    id: hex::encode(action),
                    digest: None,
                }],
            }),
            metabolic_frame: None,
            governance_frame: Some(GovernanceFrame {
                policy_decision_refs: vec![Ref {
                    id: hex::encode(decision),
                    digest: None,
                }],
                pvgs_receipt_ref: Some(Ref {
                    id: hex::encode(receipt),
                    digest: None,
                }),
                dlp_refs: Vec::new(),
            }),
            core_frame_ref: Some(Ref {
                id: hex::encode(action),
                digest: None,
            }),
            metabolic_frame_ref: None,
            governance_frame_ref: Some(Ref {
                id: hex::encode([9u8; 32]),
                digest: None,
            }),
            dlp_refs: Vec::new(),
            finalization_header: None,
        }
    }

    fn make_record_request(
        head_digest: [u8; 32],
        action: [u8; 32],
        decision: [u8; 32],
        epoch_id: u64,
        payload: Vec<u8>,
    ) -> PvgsCommitRequest {
        PvgsCommitRequest {
            commit_id: "session-1".to_string(),
            commit_type: CommitType::ExperienceRecordAppend,
            bindings: CommitBindings {
                action_digest: Some(action),
                decision_digest: Some(decision),
                grant_id: Some("grant-1".to_string()),
                charter_version_digest: "charter-v1".to_string(),
                policy_version_digest: "policy-v1".to_string(),
                prev_record_digest: head_digest,
                profile_digest: None,
                tool_profile_digest: None,
                pev_digest: None,
            },
            required_receipt_kind: RequiredReceiptKind::Read,
            required_checks: vec![RequiredCheck::SchemaOk, RequiredCheck::BindingOk],
            payload_digests: Vec::new(),
            epoch_id,
            key_epoch: None,
            experience_record_payload: Some(payload),
            replay_run_evidence_payload: None,
            trace_run_evidence_payload: None,
            proposal_evidence_payload: None,
            proposal_activation_payload: None,
            macro_milestone: None,
            meso_milestone: None,
            dlp_decision_payload: None,
            tool_registry_container: None,
            pev: None,
            consistency_feedback_payload: None,
            macro_consistency_digest: None,
            recovery_case: None,
            unlock_permit: None,
            tool_onboarding_event: None,
            microcircuit_config_payload: None,
            asset_manifest_payload: None,
            asset_bundle_payload: None,
        }
    }

    fn create_session_state() -> (PvgsStore, [u8; 32], [u8; 32], [u8; 32]) {
        let head_digest = [0u8; 32];
        let action = [1u8; 32];
        let decision = [2u8; 32];
        let mut store = base_store(head_digest);
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);

        let receipt_req =
            make_receipt_request(head_digest, action, decision, keystore.current_epoch());
        let (receipt, _) = verify_and_commit(receipt_req, &mut store, &keystore, &vrf_engine);

        let record = make_experience_record(action, decision, receipt.receipt_digest.0);
        let payload = record.encode_to_vec();
        let record_req = make_record_request(
            head_digest,
            action,
            decision,
            keystore.current_epoch(),
            payload,
        );
        let (record_receipt, _) = verify_and_commit(record_req, &mut store, &keystore, &vrf_engine);
        assert_eq!(
            record_receipt.status,
            ucf_protocol::ucf::v1::ReceiptStatus::Accepted
        );

        (store, action, decision, receipt.receipt_digest.0)
    }

    #[test]
    fn action_manifest_is_deterministic() {
        let (store, _, _, _) = create_session_state();
        let manifest_one = generate_action_manifest("session-1", &store);
        let manifest_two = generate_action_manifest("session-1", &store);
        assert_eq!(manifest_one.manifest_digest, manifest_two.manifest_digest);
        assert_eq!(manifest_one.entries, manifest_two.entries);
    }

    #[test]
    fn verify_action_manifest_match_logs_event() {
        let (mut store, _, _, _) = create_session_state();
        let manifest = generate_action_manifest("session-1", &store);
        let result = verify_action_manifest("session-1", &manifest, &mut store);
        assert!(result.mismatches.is_empty());
        assert_eq!(result.status, ReplayStatus::Match);

        let replay_event = store
            .sep_log
            .events
            .iter()
            .rev()
            .find(|event| matches!(event.event_type, SepEventType::EvReplay))
            .cloned()
            .expect("replay event logged");
        assert_eq!(replay_event.object_digest, manifest.manifest_digest);
        assert!(replay_event
            .reason_codes
            .contains(&ReasonCodes::RE_INTEGRITY_OK.to_string()));
    }

    #[test]
    fn verify_action_manifest_mismatch_detected_and_logged() {
        let (mut store, _action, _decision, receipt_digest) = create_session_state();
        let manifest = generate_action_manifest("session-1", &store);

        if let Some(receipt) = store.receipts.get_mut(&receipt_digest) {
            receipt.bindings.action_digest = Some(ucf_protocol::ucf::v1::Digest32([9u8; 32]));
        }

        let result = verify_action_manifest("session-1", &manifest, &mut store);
        assert_eq!(result.status, ReplayStatus::Mismatch);
        assert!(!result.mismatches.is_empty());

        let replay_event = store
            .sep_log
            .events
            .iter()
            .rev()
            .find(|event| matches!(event.event_type, SepEventType::EvReplay))
            .cloned()
            .expect("replay event logged");
        assert!(replay_event
            .reason_codes
            .contains(&ReasonCodes::RE_REPLAY_MISMATCH.to_string()));
    }

    #[test]
    fn daily_spot_check_logs_spotcheck_reason() {
        let (mut store, _, _, _) = create_session_state();
        let manifest = generate_action_manifest("session-1", &store);
        let report = daily_spot_check("session-1", &manifest, [7u8; 32], 1, &mut store);

        assert_eq!(report.status, ReplayStatus::Match);
        assert!(report
            .reason_codes
            .contains(&ReasonCodes::GV_REPLAY_SPOTCHECK.to_string()));

        let replay_event = store
            .sep_log
            .events
            .iter()
            .rev()
            .find(|event| matches!(event.event_type, SepEventType::EvReplay))
            .cloned()
            .expect("replay event logged");
        assert!(replay_event
            .reason_codes
            .contains(&ReasonCodes::GV_REPLAY_SPOTCHECK.to_string()));
    }

    #[test]
    fn daily_spot_check_reports_mismatches() {
        let (mut store, _action, _decision, receipt_digest) = create_session_state();
        let manifest = generate_action_manifest("session-1", &store);

        if let Some(receipt) = store.receipts.get_mut(&receipt_digest) {
            receipt.bindings.action_digest = Some(ucf_protocol::ucf::v1::Digest32([9u8; 32]));
        }

        let report = daily_spot_check("session-1", &manifest, [5u8; 32], 1, &mut store);

        assert_eq!(report.status, ReplayStatus::Mismatch);
        assert!(report
            .reason_codes
            .contains(&ReasonCodes::RE_REPLAY_MISMATCH.to_string()));
        assert!(report
            .reason_codes
            .contains(&ReasonCodes::GV_REPLAY_SPOTCHECK.to_string()));
        assert!(!report.mismatches.is_empty());

        let replay_event = store
            .sep_log
            .events
            .iter()
            .rev()
            .find(|event| matches!(event.event_type, SepEventType::EvReplay))
            .cloned()
            .expect("replay event logged");
        assert!(replay_event
            .reason_codes
            .contains(&ReasonCodes::RE_REPLAY_MISMATCH.to_string()));
        assert!(replay_event
            .reason_codes
            .contains(&ReasonCodes::GV_REPLAY_SPOTCHECK.to_string()));
    }

    #[test]
    fn daily_spot_check_is_deterministic_and_marks_mismatches() {
        let (mut store, _action, _decision, _receipt_digest) = create_session_state();
        let mut manifest = generate_action_manifest("session-1", &store);

        manifest.entries.push(ActionEntry {
            action_digest: [2u8; 32],
            decision_digest: [3u8; 32],
            receipt_digest: [4u8; 32],
            record_digest: [5u8; 32],
            created_at_ms: 1,
        });
        manifest.entries.push(ActionEntry {
            action_digest: [0x11u8; 32],
            decision_digest: [0x12u8; 32],
            receipt_digest: [0x13u8; 32],
            record_digest: [0x14u8; 32],
            created_at_ms: 2,
        });
        manifest.manifest_digest = manifest.recompute_digest();

        let seed = [1u8; 32];
        let report_one = daily_spot_check("session-1", &manifest, seed, 2, &mut store);
        let report_two = daily_spot_check("session-1", &manifest, seed, 2, &mut store);

        assert_eq!(report_one.status, ReplayStatus::Mismatch);
        assert_eq!(report_one.mismatches, report_two.mismatches);
        assert!(report_one
            .reason_codes
            .contains(&ReasonCodes::GV_REPLAY_SPOTCHECK.to_string()));
        assert!(report_one
            .reason_codes
            .contains(&ReasonCodes::RE_REPLAY_MISMATCH.to_string()));
        assert!(report_one
            .reason_codes
            .iter()
            .any(|rc| rc.contains("mismatch for action")));

        let replay_event = store
            .sep_log
            .events
            .iter()
            .rev()
            .find(|event| matches!(event.event_type, SepEventType::EvReplay))
            .cloned()
            .expect("replay event logged");
        assert!(replay_event
            .reason_codes
            .iter()
            .any(|rc| rc.contains("mismatch for action")));
    }
}
