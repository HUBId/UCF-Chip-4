#![forbid(unsafe_code)]

use cbv::{
    compute_cbv_digest, CbvStore, CharacterBaselineVector, MacroMilestone, MacroMilestoneState,
};
use dlp_store::DlpDecisionStore;
use milestones::{MesoMilestone, MicroMilestone};
use pev::{pev_digest, PolicyEcologyVector};
use pvgs::{
    compute_experience_record_digest, CompletenessChecker, CompletenessStatus, PvgsCommitRequest,
    PvgsStore,
};
use sep::{EdgeType, NodeKey, SepEventInternal, SepEventType, SepLog};
use std::collections::{BTreeSet, VecDeque};
use std::convert::TryFrom;
use thiserror::Error;
use ucf_protocol::ucf::v1::{
    ConsistencyFeedback, DlpDecisionForm, ExperienceRecord, PVGSKeyEpoch, PVGSReceipt,
    ProofReceipt, ReasonCodes, ReplayPlan,
};
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

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceResult {
    pub receipts: Vec<NodeKey>,
    pub decisions: Vec<NodeKey>,
    pub records: Vec<NodeKey>,
    pub profiles: Vec<NodeKey>,
    pub path: Vec<NodeKey>,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordTrace {
    pub references: Vec<NodeKey>,
    pub referenced_by: Vec<NodeKey>,
    pub dlp_decisions: Vec<NodeKey>,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportAttempt {
    pub record_digest: NodeKey,
    pub dlp_decision_digest: Option<NodeKey>,
    pub reason_codes: Vec<String>,
    pub timestamp_ms: Option<u64>,
    pub blocked: bool,
    pub decision_present: bool,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportAudit {
    pub record_digest: [u8; 32],
    pub experience_id: Option<u64>,
    pub output_artifact_digest: Option<[u8; 32]>,
    pub dlp_decision_digest: [u8; 32],
    pub dlp_form: DlpDecisionForm,
    pub dlp_reason_codes: Vec<String>,
    pub blocked: bool,
    pub decision_present: bool,
    pub ruleset_digest: Option<[u8; 32]>,
    pub policy_decision_digest: Option<[u8; 32]>,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacroStatusView {
    pub macro_id: String,
    pub macro_digest: [u8; 32],
    pub state: String,
    pub meso_digests: Vec<[u8; 32]>,
    pub trait_update_names: Vec<String>,
    pub consistency_digest: Option<[u8; 32]>,
    pub consistency_feedback: Option<ConsistencyFeedback>,
    pub proof_receipt_digest: Option<[u8; 32]>,
    pub cbv_epoch_after: Option<u64>,
    pub cbv_digest_after: Option<[u8; 32]>,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PvgsSnapshot {
    pub head_experience_id: u64,
    pub head_record_digest: [u8; 32],
    pub ruleset_digest: Option<[u8; 32]>,
    pub prev_ruleset_digest: Option<[u8; 32]>,
    pub latest_cbv_epoch: Option<u64>,
    pub latest_cbv_digest: Option<[u8; 32]>,
    pub latest_pev_digest: Option<[u8; 32]>,
    pub pending_replay_ids: Vec<String>,
    pub completeness_status: Option<String>,
    pub last_seal_digest: Option<[u8; 32]>,
}

const MAX_MACRO_VECTOR_ITEMS: usize = 64;
const MAX_CBV_SCAN: usize = 32;

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

/// Return the current tool registry digest if set.
pub fn get_current_tool_registry_digest(store: &PvgsStore) -> Option<[u8; 32]> {
    store.tool_registry_state.current()
}

/// List all committed tool registry digests in insertion order.
pub fn list_tool_registry_digests(store: &PvgsStore) -> Vec<[u8; 32]> {
    store.tool_registry_state.history.clone()
}

/// Build a deterministic snapshot of key PVGS state for operational inspection.
pub fn snapshot(store: &PvgsStore, session_id: Option<&str>) -> PvgsSnapshot {
    let latest_cbv = store.get_latest_cbv();

    let latest_cbv_epoch = latest_cbv.as_ref().map(|cbv| cbv.cbv_epoch);
    let latest_cbv_digest = latest_cbv.as_ref().map(|cbv| {
        cbv.cbv_digest
            .as_deref()
            .and_then(digest_from_bytes)
            .unwrap_or_else(|| compute_cbv_digest(cbv))
    });

    let mut pending_replay_ids: Vec<_> = match session_id {
        Some(session) => get_pending_replay_plans(store, session),
        None => store.replay_plans.list_pending(),
    }
    .into_iter()
    .map(|plan| plan.replay_id)
    .collect();

    pending_replay_ids.sort();
    pending_replay_ids.dedup();
    pending_replay_ids.truncate(128);

    let completeness_status = session_id.and_then(|session| {
        let action_digests: Vec<_> = store
            .sep_log
            .events
            .iter()
            .filter(|event| event.session_id == session)
            .filter(|event| matches!(event.event_type, SepEventType::EvDecision))
            .map(|event| event.object_digest)
            .collect();

        if action_digests.is_empty() {
            return None;
        }

        let mut sep_log = store.sep_log.clone();
        let mut checker = CompletenessChecker::new(
            &store.causal_graph,
            &mut sep_log,
            &store.dlp_store,
            &store.replay_plans,
            &store.experience_store.records,
        );
        let status = checker.check_actions(session, action_digests).status;

        match status {
            CompletenessStatus::Ok => Some("OK".to_string()),
            CompletenessStatus::Degraded => Some("DEGRADED".to_string()),
            CompletenessStatus::Fail => Some("FAIL".to_string()),
        }
    });

    let last_seal_digest = session_id.and_then(|session| {
        store
            .sep_log
            .events
            .iter()
            .rev()
            .find(|event| event.session_id == session)
            .map(|event| event.event_digest)
    });

    PvgsSnapshot {
        head_experience_id: store.experience_store.head_id,
        head_record_digest: store.experience_store.head_record_digest,
        ruleset_digest: get_current_ruleset_digest(store),
        prev_ruleset_digest: get_previous_ruleset_digest(store),
        latest_cbv_epoch,
        latest_cbv_digest,
        latest_pev_digest: get_latest_pev_digest(store),
        pending_replay_ids,
        completeness_status,
        last_seal_digest,
    }
}

fn macro_consistency_feedback(
    store: &PvgsStore,
    macro_milestone: &MacroMilestone,
) -> Option<ConsistencyFeedback> {
    macro_milestone
        .consistency_digest
        .as_deref()
        .and_then(digest_from_bytes)
        .and_then(|digest| store.consistency_store.get(digest).cloned())
}

/// List all micro milestones in deterministic order.
pub fn list_micros(store: &PvgsStore) -> Vec<MicroMilestone> {
    let mut micros = store.micro_milestones.list().to_vec();
    micros.sort_by(|a, b| a.micro_id.cmp(&b.micro_id));
    micros
}

/// List all meso milestones in deterministic order.
pub fn list_mesos(store: &PvgsStore) -> Vec<MesoMilestone> {
    let mut mesos = store.meso_milestones.list().to_vec();
    mesos.sort_by(|a, b| a.meso_id.cmp(&b.meso_id));
    mesos
}

/// Return the current ruleset digest if available.
pub fn get_current_ruleset_digest(store: &PvgsStore) -> Option<[u8; 32]> {
    Some(store.ruleset_state.ruleset_digest)
}

/// Return the previous ruleset digest if tracked.
pub fn get_previous_ruleset_digest(store: &PvgsStore) -> Option<[u8; 32]> {
    store.ruleset_state.prev_ruleset_digest
}

/// List all ruleset change digests observed in the SEP log.
pub fn list_ruleset_changes(log: &SepLog, session_id: Option<&str>) -> Vec<[u8; 32]> {
    log.events
        .iter()
        .filter(|event| {
            event
                .reason_codes
                .iter()
                .any(|reason| reason == ReasonCodes::GV_RULESET_CHANGED)
                && session_id.is_none_or(|sid| sid == event.session_id)
        })
        .map(|event| event.object_digest)
        .collect()
}

/// List proposed macro milestones in deterministic order.
pub fn list_proposed_macros(store: &PvgsStore) -> Vec<MacroStatusView> {
    let mut macros: Vec<_> = store
        .macro_milestones
        .list_proposed()
        .into_iter()
        .map(|milestone| macro_status_from(&milestone, &store.cbv_store, false, None))
        .collect();

    macros.sort_by(|a, b| a.macro_id.cmp(&b.macro_id));
    macros
}

/// List finalized macro milestones in deterministic order.
pub fn list_finalized_macros(store: &PvgsStore) -> Vec<MacroStatusView> {
    let mut macros: Vec<_> = store
        .macro_milestones
        .list_finalized()
        .into_iter()
        .map(|milestone| {
            let consistency_feedback = macro_consistency_feedback(store, &milestone);

            macro_status_from(&milestone, &store.cbv_store, true, consistency_feedback)
        })
        .collect();

    macros.sort_by(|a, b| a.macro_id.cmp(&b.macro_id));
    macros
}

/// Retrieve the latest known status for a macro id.
pub fn get_macro_status(store: &PvgsStore, macro_id: &str) -> Option<MacroStatusView> {
    if let Some(macro_milestone) = store.macro_milestones.get_proposed(macro_id) {
        return Some(macro_status_from(
            macro_milestone,
            &store.cbv_store,
            false,
            None,
        ));
    }

    store
        .macro_milestones
        .get_finalized(macro_id)
        .map(|macro_milestone| {
            let consistency_feedback = macro_consistency_feedback(store, macro_milestone);

            macro_status_from(
                macro_milestone,
                &store.cbv_store,
                true,
                consistency_feedback,
            )
        })
}

/// Retrieve the stored consistency feedback for a finalized macro if available.
pub fn get_consistency_for_macro(store: &PvgsStore, macro_id: &str) -> Option<ConsistencyFeedback> {
    let macro_milestone = store.macro_milestones.get_finalized(macro_id)?;

    macro_consistency_feedback(store, macro_milestone)
}

pub fn get_pending_replay_plans(store: &PvgsStore, session_id: &str) -> Vec<ReplayPlan> {
    let mut plans: Vec<_> = store
        .replay_plans
        .list_pending()
        .into_iter()
        .filter(|plan| plan.session_id == session_id)
        .collect();
    plans.sort_by(|a, b| a.replay_id.cmp(&b.replay_id));
    plans.truncate(64);
    plans
}

pub fn consume_replay_plan(store: &mut PvgsStore, replay_id: &str) -> Result<(), QueryError> {
    store
        .replay_plans
        .mark_consumed(replay_id)
        .map_err(|err| QueryError::Lookup(err.to_string()))
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

fn macro_status_from(
    macro_milestone: &MacroMilestone,
    cbv_store: &CbvStore,
    include_cbv: bool,
    consistency_feedback: Option<ConsistencyFeedback>,
) -> MacroStatusView {
    let macro_digest = digest_from_bytes(&macro_milestone.macro_digest).unwrap_or([0u8; 32]);

    let mut meso_digests: Vec<[u8; 32]> = macro_milestone
        .meso_refs
        .iter()
        .filter_map(digest_from_ref)
        .collect();
    meso_digests.sort();
    meso_digests.dedup();
    meso_digests.truncate(MAX_MACRO_VECTOR_ITEMS);

    let mut trait_update_names: Vec<String> = macro_milestone
        .trait_updates
        .iter()
        .map(|update| update.trait_name.clone())
        .collect();
    trait_update_names.sort();
    trait_update_names.dedup();
    trait_update_names.truncate(MAX_MACRO_VECTOR_ITEMS);

    let (cbv_epoch_after, cbv_digest_after) = if include_cbv {
        cbv_link_for_macro(cbv_store, macro_digest)
    } else {
        (None, None)
    };

    let state = match MacroMilestoneState::try_from(macro_milestone.state)
        .unwrap_or(MacroMilestoneState::Unknown)
    {
        MacroMilestoneState::Finalized => "FINALIZED".to_string(),
        _ => "PROPOSED".to_string(),
    };

    MacroStatusView {
        macro_id: macro_milestone.macro_id.clone(),
        macro_digest,
        state,
        meso_digests,
        trait_update_names,
        consistency_digest: macro_milestone
            .consistency_digest
            .as_deref()
            .and_then(digest_from_bytes),
        consistency_feedback,
        proof_receipt_digest: macro_milestone
            .proof_receipt_ref
            .as_ref()
            .and_then(digest_from_ref),
        cbv_epoch_after,
        cbv_digest_after,
    }
}

fn cbv_link_for_macro(
    cbv_store: &CbvStore,
    macro_digest: [u8; 32],
) -> (Option<u64>, Option<[u8; 32]>) {
    let mut epoch_after = None;
    let mut cbv_digest_after = None;

    for cbv in cbv_store.list_latest(MAX_CBV_SCAN).into_iter().rev() {
        let references_macro = cbv
            .source_milestone_refs
            .iter()
            .any(|reference| macro_ref_matches(reference, macro_digest));

        if references_macro {
            epoch_after = Some(cbv.cbv_epoch);
            cbv_digest_after = cbv
                .cbv_digest
                .as_deref()
                .and_then(digest_from_bytes)
                .or_else(|| Some(compute_cbv_digest(&cbv)));
            break;
        }
    }

    (epoch_after, cbv_digest_after)
}

fn macro_ref_matches(reference: &ucf_protocol::ucf::v1::Ref, macro_digest: [u8; 32]) -> bool {
    (reference
        .id
        .split_once(':')
        .and_then(|(_, value)| hex::decode(value).ok())
        .and_then(|bytes| digest_from_bytes(&bytes))
        == Some(macro_digest))
        || digest_from_labeled_ref(reference, "macro") == Some(macro_digest)
}

const MAX_TRACE_NODES: usize = 256;

/// Traverse the causal graph starting from an action digest to collect receipts,
/// related decisions, records, and profiles.
pub fn trace_action(store: &PvgsStore, action_digest: [u8; 32]) -> TraceResult {
    let mut receipts = BTreeSet::new();
    let mut decisions = BTreeSet::new();
    let mut records = BTreeSet::new();
    let mut profiles = BTreeSet::new();
    let mut visited = BTreeSet::new();
    let mut path = Vec::new();

    visited.insert(action_digest);
    path.push(action_digest);

    for (edge, neighbor) in sorted_edges(store.causal_graph.neighbors(action_digest)) {
        if visited.len() >= MAX_TRACE_NODES {
            break;
        }

        match edge {
            EdgeType::Authorizes => {
                if receipts.insert(neighbor) && visited.insert(neighbor) {
                    path.push(neighbor);
                }
            }
            EdgeType::References if is_record_node(store, &neighbor) => {
                if records.insert(neighbor) && visited.insert(neighbor) {
                    path.push(neighbor);
                }
            }
            _ => {}
        }
    }

    let mut queue = VecDeque::from(receipts.iter().copied().collect::<Vec<_>>());
    while let Some(receipt) = queue.pop_front() {
        if visited.len() >= MAX_TRACE_NODES {
            break;
        }

        for (edge, neighbor) in sorted_edges(store.causal_graph.reverse_neighbors(receipt)) {
            if visited.len() >= MAX_TRACE_NODES {
                break;
            }

            match edge {
                EdgeType::Authorizes => {
                    if neighbor == action_digest {
                        continue;
                    }

                    if decisions.insert(neighbor) && visited.insert(neighbor) {
                        path.push(neighbor);
                    }
                }
                EdgeType::References => {
                    let is_record = is_record_node(store, &neighbor);
                    let is_profile = is_profile_node(store, &neighbor);

                    let inserted = (is_record && records.insert(neighbor))
                        || (is_profile && profiles.insert(neighbor));

                    if inserted && visited.insert(neighbor) {
                        path.push(neighbor);
                    }
                }
                _ => {}
            }
        }
    }

    for (edge, neighbor) in sorted_edges(store.causal_graph.reverse_neighbors(action_digest)) {
        if visited.len() >= MAX_TRACE_NODES {
            break;
        }

        if matches!(edge, EdgeType::References)
            && is_record_node(store, &neighbor)
            && records.insert(neighbor)
            && visited.insert(neighbor)
        {
            path.push(neighbor);
        }
    }

    TraceResult {
        receipts: receipts.into_iter().collect(),
        decisions: decisions.into_iter().collect(),
        records: records.into_iter().collect(),
        profiles: profiles.into_iter().collect(),
        path,
    }
}

/// Trace record references and related DLP decisions.
pub fn trace_record(store: &PvgsStore, record_digest: [u8; 32]) -> RecordTrace {
    let mut references = BTreeSet::new();
    let mut referenced_by = BTreeSet::new();
    let mut dlp_decisions = BTreeSet::new();

    for (edge, neighbor) in sorted_edges(store.causal_graph.neighbors(record_digest)) {
        if matches!(edge, EdgeType::References) {
            references.insert(neighbor);
        }
    }

    for (edge, neighbor) in sorted_edges(store.causal_graph.reverse_neighbors(record_digest)) {
        if matches!(edge, EdgeType::References | EdgeType::Causes) {
            referenced_by.insert(neighbor);
        }
    }

    if let Some(record) = find_record(store, record_digest) {
        for digest in dlp_digests_from_record(record) {
            dlp_decisions.insert(digest);
        }
    }

    RecordTrace {
        references: references.into_iter().collect(),
        referenced_by: referenced_by.into_iter().collect(),
        dlp_decisions: dlp_decisions.into_iter().collect(),
    }
}

/// List export attempts for a session in deterministic order.
pub fn list_export_attempts(store: &PvgsStore, session_id: &str) -> Vec<ExportAttempt> {
    let mut attempts = Vec::new();

    for event in store.sep_log.events.iter().filter(|event| {
        event.session_id == session_id && matches!(event.event_type, SepEventType::EvOutput)
    }) {
        let record = find_record(store, event.object_digest);
        let dlp_digests = record.map(dlp_digests_from_record).unwrap_or_default();
        let decision_digest = dlp_digests.first().copied();

        let timestamp_ms = record.and_then(record_timestamp_ms);
        let (blocked, decision_present, reason_codes) =
            classify_dlp_decision(&store.dlp_store, decision_digest);

        attempts.push(ExportAttempt {
            record_digest: event.object_digest,
            dlp_decision_digest: decision_digest,
            reason_codes,
            timestamp_ms,
            blocked,
            decision_present,
        });
    }

    attempts.sort_by(|a, b| a.record_digest.cmp(&b.record_digest));
    attempts
}

const RC_RE_DLP_DECISION_MISSING: &str = "RC.RE.DLP_DECISION.MISSING";

/// Return detailed export audits for RT_OUTPUT records in a deterministic order.
pub fn trace_exports(store: &PvgsStore, session_id: &str) -> Vec<ExportAudit> {
    let mut audits = Vec::new();

    let mut output_records: Vec<[u8; 32]> = store
        .sep_log
        .events
        .iter()
        .filter(|event| {
            event.session_id == session_id && matches!(event.event_type, SepEventType::EvOutput)
        })
        .map(|event| event.object_digest)
        .collect();

    output_records.sort();
    output_records.dedup();

    for record_digest in output_records {
        let Some(record) = find_record(store, record_digest) else {
            continue;
        };

        let mut dlp_digests = dlp_digests_from_record(record);
        dlp_digests.sort();

        for dlp_digest in dlp_digests {
            let (blocked, decision_present, dlp_form, mut dlp_reason_codes) =
                classify_export_dlp_decision(&store.dlp_store, dlp_digest);

            dlp_reason_codes.sort();

            let output_artifact_digest = related_digest(record, "output_artifact");
            let ruleset_digest = related_digest(record, "ruleset");
            let policy_decision_digest = related_digest(record, "decision");
            let experience_id = record
                .finalization_header
                .as_ref()
                .map(|header| header.experience_id);

            audits.push(ExportAudit {
                record_digest,
                experience_id,
                output_artifact_digest,
                dlp_decision_digest: dlp_digest,
                dlp_form,
                dlp_reason_codes,
                blocked,
                decision_present,
                ruleset_digest,
                policy_decision_digest,
            });
        }
    }

    audits.sort_by(|a, b| {
        a.record_digest
            .cmp(&b.record_digest)
            .then_with(|| a.dlp_decision_digest.cmp(&b.dlp_decision_digest))
    });
    audits
}

fn find_record(store: &PvgsStore, record_digest: [u8; 32]) -> Option<&ExperienceRecord> {
    store
        .experience_store
        .records
        .iter()
        .find(|record| compute_experience_record_digest(record) == record_digest)
}

fn related_digest(record: &ExperienceRecord, target_id: &str) -> Option<[u8; 32]> {
    let mut refs: Vec<&ucf_protocol::ucf::v1::Ref> = Vec::new();

    if let Some(gov) = &record.governance_frame {
        refs.extend(gov.policy_decision_refs.iter());
    }

    if let Some(meta) = &record.metabolic_frame {
        refs.extend(meta.outcome_refs.iter());
    }

    refs.into_iter()
        .find_map(|reference| digest_from_labeled_ref(reference, target_id))
}

fn dlp_digests_from_record(record: &ExperienceRecord) -> Vec<NodeKey> {
    let mut digests = BTreeSet::new();

    if let Some(gov) = &record.governance_frame {
        for reference in &gov.dlp_refs {
            if let Some(digest) = digest_from_ref(reference) {
                digests.insert(digest);
            }
        }
    }

    for reference in &record.dlp_refs {
        if let Some(digest) = digest_from_ref(reference) {
            digests.insert(digest);
        }
    }

    digests.into_iter().collect()
}

fn digest_from_labeled_ref(
    reference: &ucf_protocol::ucf::v1::Ref,
    target_id: &str,
) -> Option<[u8; 32]> {
    let prefix = format!("{target_id}:");

    if let Some(value) = reference.id.strip_prefix(&prefix) {
        return digest_from_labeled_value(value);
    }

    None
}

fn digest_from_labeled_value(value: &str) -> Option<[u8; 32]> {
    if value.len() == 64 {
        let bytes = hex::decode(value).ok()?;
        return digest_from_bytes(&bytes);
    }

    digest_from_bytes(value.as_bytes())
}

fn digest_from_ref(reference: &ucf_protocol::ucf::v1::Ref) -> Option<[u8; 32]> {
    if reference.id.len() == 64 {
        let bytes = hex::decode(&reference.id).ok()?;
        return digest_from_bytes(&bytes);
    }

    digest_from_bytes(reference.id.as_bytes())
}

fn digest_from_bytes(bytes: &[u8]) -> Option<[u8; 32]> {
    if bytes.len() != 32 {
        return None;
    }

    let mut digest = [0u8; 32];
    digest.copy_from_slice(bytes);
    Some(digest)
}

fn record_timestamp_ms(record: &ExperienceRecord) -> Option<u64> {
    record
        .finalization_header
        .as_ref()
        .map(|header| header.timestamp_ms)
}

fn classify_dlp_decision(
    store: &DlpDecisionStore,
    digest: Option<NodeKey>,
) -> (bool, bool, Vec<String>) {
    let Some(dlp_digest) = digest else {
        return (false, false, Vec::new());
    };

    match store.get(dlp_digest) {
        Some(decision) => {
            let form = DlpDecisionForm::try_from(decision.decision_form)
                .unwrap_or(DlpDecisionForm::Unspecified);
            let blocked = matches!(form, DlpDecisionForm::Block | DlpDecisionForm::Hold);
            (blocked, true, decision.reason_codes.clone())
        }
        None => (
            true,
            false,
            vec![ReasonCodes::RE_INTEGRITY_DEGRADED.to_string()],
        ),
    }
}

fn classify_export_dlp_decision(
    store: &DlpDecisionStore,
    digest: [u8; 32],
) -> (bool, bool, DlpDecisionForm, Vec<String>) {
    match store.get(digest) {
        Some(decision) => {
            let form = DlpDecisionForm::try_from(decision.decision_form)
                .unwrap_or(DlpDecisionForm::Unspecified);
            let blocked = matches!(form, DlpDecisionForm::Block | DlpDecisionForm::Hold);
            (blocked, true, form, decision.reason_codes.clone())
        }
        None => (
            true,
            false,
            DlpDecisionForm::Unspecified,
            vec![RC_RE_DLP_DECISION_MISSING.to_string()],
        ),
    }
}

fn sorted_edges(edges: &[(EdgeType, NodeKey)]) -> Vec<(EdgeType, NodeKey)> {
    let mut ordered = edges.to_vec();
    ordered.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    ordered
}

fn is_record_node(store: &PvgsStore, digest: &NodeKey) -> bool {
    store.experience_store.proof_receipts.contains_key(digest)
        || store.experience_store.head_record_digest == *digest
}

fn is_profile_node(store: &PvgsStore, digest: &NodeKey) -> bool {
    store.known_profiles.contains(digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use keys::KeyStore;
    use pev::PolicyEcologyDimension;
    use prost::Message;
    use pvgs::{
        compute_ruleset_digest, verify_and_commit, CommitBindings, CommitType, RequiredCheck,
        RequiredReceiptKind,
    };
    use replay_plan::{build_replay_plan, BuildReplayPlanArgs};
    use sep::{EdgeType, FrameEventKind, SepLog};
    use std::collections::HashSet;
    use ucf_protocol::ucf::v1::{
        ConsistencyFeedback, Digest32, DlpDecision, GovernanceFrame, MacroMilestone,
        MacroMilestoneState, MagnitudeClass, MetabolicFrame, ReceiptStatus, RecordType, Ref,
        ReplayFidelity, ReplayTargetKind, TraitDirection, TraitUpdate,
    };
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
            "charter".to_string(),
            "policy".to_string(),
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

    fn minimal_store() -> PvgsStore {
        let mut known_charter_versions = HashSet::new();
        known_charter_versions.insert("charter".to_string());
        let mut known_policy_versions = HashSet::new();
        known_policy_versions.insert("policy".to_string());
        let known_profiles = HashSet::new();

        PvgsStore::new(
            [1u8; 32],
            "charter".to_string(),
            "policy".to_string(),
            known_charter_versions,
            known_policy_versions,
            known_profiles,
        )
    }

    fn trace_store(profile_digest: [u8; 32]) -> PvgsStore {
        let mut known_charter_versions = HashSet::new();
        known_charter_versions.insert("charter".to_string());
        let mut known_policy_versions = HashSet::new();
        known_policy_versions.insert("policy".to_string());
        let mut known_profiles = HashSet::new();
        known_profiles.insert(profile_digest);

        PvgsStore::new(
            [0u8; 32],
            "charter".to_string(),
            "policy".to_string(),
            known_charter_versions,
            known_policy_versions,
            known_profiles,
        )
    }

    fn dummy_proof_receipt(record_digest: [u8; 32]) -> ProofReceipt {
        ProofReceipt {
            proof_receipt_id: "proof".to_string(),
            receipt_digest: Digest32(record_digest),
            ruleset_digest: Digest32([0u8; 32]),
            verified_fields_digest: Digest32([0u8; 32]),
            vrf_digest: Digest32([0u8; 32]),
            timestamp_ms: 0,
            epoch_id: 0,
            proof_receipt_digest: Digest32([0u8; 32]),
            proof_attestation_key_id: String::new(),
            proof_attestation_sig: Vec::new(),
        }
    }

    fn macro_proposal(id: &str, digest: [u8; 32]) -> MacroMilestone {
        MacroMilestone {
            macro_id: id.to_string(),
            macro_digest: digest.to_vec(),
            state: MacroMilestoneState::Proposed as i32,
            trait_updates: vec![TraitUpdate {
                trait_name: "baseline_caution".to_string(),
                direction: TraitDirection::IncreaseStrictness as i32,
                magnitude_class: MagnitudeClass::Low as i32,
            }],
            meso_refs: vec![Ref {
                id: hex::encode(digest),
            }],
            consistency_class: String::new(),
            identity_anchor_flag: false,
            proof_receipt_ref: None,
            consistency_digest: None,
            consistency_feedback_ref: None,
        }
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
    fn tool_registry_queries_return_current_and_history() {
        let (mut store, _, _) = store_with_epochs();
        let digest = [0xAAu8; 32];
        store
            .tool_registry_state
            .set_current(digest)
            .expect("insert digest");
        store.update_tool_registry_digest(store.tool_registry_state.current());

        assert_eq!(get_current_tool_registry_digest(&store), Some(digest));
        assert_eq!(list_tool_registry_digests(&store), vec![digest]);
    }

    #[test]
    fn ruleset_queries_return_current_and_previous() {
        let (mut store, _, _) = store_with_epochs();
        let expected = compute_ruleset_digest(b"charter", b"policy", None, None);

        let current = get_current_ruleset_digest(&store).expect("missing ruleset");
        assert_eq!(current, expected);
        assert_eq!(get_previous_ruleset_digest(&store), Some([0u8; 32]));

        let updated_tool_registry = [0x44u8; 32];
        store
            .tool_registry_state
            .set_current(updated_tool_registry)
            .expect("tool registry digest");
        store.update_tool_registry_digest(store.tool_registry_state.current());

        let updated = get_current_ruleset_digest(&store).expect("missing updated ruleset");
        assert_ne!(updated, expected);
        assert_eq!(get_previous_ruleset_digest(&store), Some(expected));
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
        )
        .unwrap();
        log.append_frame_event(
            "session-1".to_string(),
            FrameEventKind::SignalFrame,
            signal_digest,
            vec![],
        )
        .unwrap();

        assert!(has_control_frame_digest(&log, "session-1", control_digest));
        assert!(!has_control_frame_digest(&log, "session-1", signal_digest));

        let controls = list_control_frames(&log, "session-1");
        assert_eq!(controls, vec![control_digest]);

        let signals = list_signal_frames(&log, "session-1");
        assert_eq!(signals, vec![signal_digest]);
    }

    #[test]
    fn ruleset_change_queries_list_digests() {
        let mut log = SepLog::default();
        let digest_one = [1u8; 32];
        let digest_two = [2u8; 32];

        log.append_event(
            "session-a".to_string(),
            SepEventType::EvPevUpdate,
            digest_one,
            vec![ReasonCodes::GV_RULESET_CHANGED.to_string()],
        )
        .unwrap();
        log.append_event(
            "session-b".to_string(),
            SepEventType::EvToolOnboarding,
            digest_two,
            vec![ReasonCodes::GV_RULESET_CHANGED.to_string()],
        )
        .unwrap();

        let all_changes = list_ruleset_changes(&log, None);
        assert_eq!(all_changes, vec![digest_one, digest_two]);

        let filtered = list_ruleset_changes(&log, Some("session-b"));
        assert_eq!(filtered, vec![digest_two]);
    }

    #[test]
    fn proposed_macro_list_includes_entries() {
        let mut store = minimal_store();
        let proposal = macro_proposal("macro-alpha", [1u8; 32]);
        store
            .macro_milestones
            .insert_proposal(proposal)
            .expect("proposal stored");

        let proposed = list_proposed_macros(&store);
        assert_eq!(proposed.len(), 1);
        assert_eq!(proposed[0].macro_id, "macro-alpha");
        assert_eq!(proposed[0].macro_digest, [1u8; 32]);
        assert!(proposed[0].consistency_feedback.is_none());
        assert!(list_finalized_macros(&store).is_empty());
    }

    #[test]
    fn macro_lists_reflect_finalization_and_cbv_linkage() {
        let (mut store, _, _) = store_with_epochs();
        let keystore = KeyStore::new_dev_keystore(3);
        let vrf_engine = VrfEngine::new_dev(3);
        let proposal = macro_proposal("macro-high", [2u8; 32]);

        store
            .macro_milestones
            .insert_proposal(proposal)
            .expect("proposal stored");

        let feedback = ConsistencyFeedback {
            cf_digest: Some([9u8; 32].to_vec()),
            consistency_class: "CONSISTENCY_HIGH".to_string(),
            flags: Vec::new(),
            proof_receipt_ref: None,
        };
        let consistency_digest = store
            .consistency_store
            .insert(feedback)
            .expect("feedback stored");

        let receipt = store
            .finalize_macro("macro-high", consistency_digest, &keystore, &vrf_engine)
            .expect("macro finalized")
            .expect("finalization receipt");
        assert_eq!(receipt.status, ReceiptStatus::Accepted);

        assert!(list_proposed_macros(&store).is_empty());

        let finalized = list_finalized_macros(&store);
        assert_eq!(finalized.len(), 1);
        let status = &finalized[0];
        assert_eq!(status.macro_id, "macro-high");
        assert_eq!(status.state, "FINALIZED");
        assert_eq!(status.consistency_digest, Some(consistency_digest));
        assert!(status.cbv_epoch_after.is_some());
        assert!(status.cbv_digest_after.is_some());

        let consistency_feedback = status
            .consistency_feedback
            .as_ref()
            .expect("consistency feedback present");
        assert_eq!(
            consistency_feedback.cf_digest.as_deref(),
            Some(consistency_digest.as_slice())
        );
        assert_eq!(
            consistency_feedback.consistency_class,
            "CONSISTENCY_HIGH".to_string()
        );

        let stored = get_consistency_for_macro(&store, "macro-high").expect("consistency");
        assert_eq!(stored.consistency_class, "CONSISTENCY_HIGH");

        let status = get_macro_status(&store, "macro-high").expect("macro status");
        assert!(status.cbv_epoch_after.is_some());
        assert!(status.cbv_digest_after.is_some());
        assert!(status.consistency_feedback.is_some());
    }

    #[test]
    fn macro_lists_are_sorted_by_macro_id() {
        let mut store = minimal_store();
        let later = macro_proposal("macro-z", [3u8; 32]);
        let earlier = macro_proposal("macro-a", [4u8; 32]);

        store
            .macro_milestones
            .insert_proposal(later)
            .expect("later stored");
        store
            .macro_milestones
            .insert_proposal(earlier)
            .expect("earlier stored");

        let ids: Vec<_> = list_proposed_macros(&store)
            .into_iter()
            .map(|entry| entry.macro_id)
            .collect();

        assert_eq!(ids, vec!["macro-a".to_string(), "macro-z".to_string()]);
    }

    #[test]
    fn trace_action_collects_related_nodes() {
        let action = [1u8; 32];
        let receipt = [2u8; 32];
        let decision = [3u8; 32];
        let record = [4u8; 32];
        let profile = [5u8; 32];

        let mut store = trace_store(profile);
        store
            .experience_store
            .proof_receipts
            .insert(record, dummy_proof_receipt(record));

        store
            .causal_graph
            .add_edge(action, EdgeType::Authorizes, receipt);
        store
            .causal_graph
            .add_edge(decision, EdgeType::Authorizes, receipt);
        store
            .causal_graph
            .add_edge(profile, EdgeType::References, receipt);
        store
            .causal_graph
            .add_edge(record, EdgeType::References, receipt);
        store
            .causal_graph
            .add_edge(record, EdgeType::References, action);

        let result = trace_action(&store, action);
        assert_eq!(result.receipts, vec![receipt]);
        assert_eq!(result.decisions, vec![decision]);
        assert_eq!(result.records, vec![record]);
        assert_eq!(result.profiles, vec![profile]);
        assert_eq!(
            result.path,
            vec![action, receipt, decision, record, profile]
        );
    }

    #[test]
    fn trace_action_is_deterministic() {
        let action = [9u8; 32];
        let receipt = [8u8; 32];
        let decision_a = [7u8; 32];
        let decision_b = [6u8; 32];
        let profile = [5u8; 32];
        let record = [4u8; 32];

        let mut store_one = trace_store(profile);
        store_one
            .experience_store
            .proof_receipts
            .insert(record, dummy_proof_receipt(record));
        store_one
            .causal_graph
            .add_edge(action, EdgeType::Authorizes, receipt);
        store_one
            .causal_graph
            .add_edge(decision_b, EdgeType::Authorizes, receipt);
        store_one
            .causal_graph
            .add_edge(decision_a, EdgeType::Authorizes, receipt);
        store_one
            .causal_graph
            .add_edge(record, EdgeType::References, receipt);
        store_one
            .causal_graph
            .add_edge(profile, EdgeType::References, receipt);

        let mut store_two = trace_store(profile);
        store_two
            .experience_store
            .proof_receipts
            .insert(record, dummy_proof_receipt(record));
        store_two
            .causal_graph
            .add_edge(decision_a, EdgeType::Authorizes, receipt);
        store_two
            .causal_graph
            .add_edge(action, EdgeType::Authorizes, receipt);
        store_two
            .causal_graph
            .add_edge(profile, EdgeType::References, receipt);
        store_two
            .causal_graph
            .add_edge(record, EdgeType::References, receipt);
        store_two
            .causal_graph
            .add_edge(decision_b, EdgeType::Authorizes, receipt);

        let result_one = trace_action(&store_one, action);
        let result_two = trace_action(&store_two, action);

        assert_eq!(result_one.receipts, result_two.receipts);
        assert_eq!(result_one.decisions, result_two.decisions);
        assert_eq!(result_one.records, result_two.records);
        assert_eq!(result_one.profiles, result_two.profiles);
        assert_eq!(result_one.path, result_two.path);
    }

    #[test]
    fn trace_record_includes_dlp_decisions() {
        let mut known_charter_versions = HashSet::new();
        known_charter_versions.insert("charter".to_string());
        let mut known_policy_versions = HashSet::new();
        known_policy_versions.insert("policy".to_string());

        let mut store = PvgsStore::new(
            [0u8; 32],
            "charter".to_string(),
            "policy".to_string(),
            known_charter_versions,
            known_policy_versions,
            HashSet::new(),
        );
        let keystore = KeyStore::new_dev_keystore(2);
        let vrf_engine = VrfEngine::new_dev(2);

        let dlp_digest = [7u8; 32];
        let governance_frame = GovernanceFrame {
            policy_decision_refs: Vec::new(),
            pvgs_receipt_ref: None,
            dlp_refs: vec![Ref {
                id: hex::encode(dlp_digest),
            }],
        };

        let record = ExperienceRecord {
            record_type: RecordType::RtOutput as i32,
            core_frame: None,
            metabolic_frame: None,
            governance_frame: Some(governance_frame),
            core_frame_ref: None,
            metabolic_frame_ref: None,
            governance_frame_ref: Some(Ref {
                id: hex::encode([3u8; 32]),
            }),
            dlp_refs: Vec::new(),
            finalization_header: None,
        };

        let req = PvgsCommitRequest {
            commit_id: "session-export".to_string(),
            commit_type: CommitType::ExperienceRecordAppend,
            bindings: CommitBindings {
                action_digest: None,
                decision_digest: None,
                grant_id: None,
                charter_version_digest: "charter".to_string(),
                policy_version_digest: "policy".to_string(),
                prev_record_digest: store.current_head_record_digest,
                profile_digest: None,
                tool_profile_digest: None,
                pev_digest: None,
            },
            required_receipt_kind: RequiredReceiptKind::Read,
            required_checks: vec![RequiredCheck::SchemaOk],
            payload_digests: Vec::new(),
            epoch_id: keystore.current_epoch(),
            key_epoch: None,
            experience_record_payload: Some(record.encode_to_vec()),
            macro_milestone: None,
            meso_milestone: None,
            dlp_decision_payload: None,
            tool_registry_container: None,
            pev: None,
            consistency_feedback_payload: None,
            macro_consistency_digest: None,
        };

        let (receipt, _) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);
        assert_eq!(receipt.status, ReceiptStatus::Accepted);

        let record_digest = store.experience_store.head_record_digest;
        let trace = trace_record(&store, record_digest);

        assert_eq!(trace.dlp_decisions, vec![dlp_digest]);
    }

    fn store_dlp_decision(
        store: &mut PvgsStore,
        digest: [u8; 32],
        form: DlpDecisionForm,
        reasons: Vec<&str>,
    ) {
        let decision = DlpDecision {
            dlp_decision_digest: Some(digest.to_vec()),
            decision_form: form as i32,
            reason_codes: reasons.into_iter().map(String::from).collect(),
        };

        store.dlp_store.insert(decision).unwrap();
    }

    fn append_output_record(
        store: &mut PvgsStore,
        keystore: &KeyStore,
        vrf_engine: &VrfEngine,
        commit_id: &str,
        dlp_digest: [u8; 32],
    ) -> [u8; 32] {
        append_output_record_with_refs(
            store,
            keystore,
            vrf_engine,
            commit_id,
            dlp_digest,
            Vec::new(),
            Vec::new(),
        )
    }

    fn append_output_record_with_refs(
        store: &mut PvgsStore,
        keystore: &KeyStore,
        vrf_engine: &VrfEngine,
        commit_id: &str,
        dlp_digest: [u8; 32],
        related_refs: Vec<Ref>,
        outcome_refs: Vec<Ref>,
    ) -> [u8; 32] {
        let governance_frame = GovernanceFrame {
            policy_decision_refs: related_refs,
            pvgs_receipt_ref: None,
            dlp_refs: vec![Ref {
                id: hex::encode(dlp_digest),
            }],
        };

        let metabolic_frame = if outcome_refs.is_empty() {
            None
        } else {
            Some(MetabolicFrame {
                profile_digest: None,
                outcome_refs,
            })
        };

        let record = ExperienceRecord {
            record_type: RecordType::RtOutput as i32,
            core_frame: None,
            metabolic_frame,
            governance_frame: Some(governance_frame),
            core_frame_ref: None,
            metabolic_frame_ref: None,
            governance_frame_ref: Some(Ref {
                id: hex::encode([9u8; 32]),
            }),
            dlp_refs: Vec::new(),
            finalization_header: None,
        };

        let req = PvgsCommitRequest {
            commit_id: commit_id.to_string(),
            commit_type: CommitType::ExperienceRecordAppend,
            bindings: CommitBindings {
                action_digest: None,
                decision_digest: None,
                grant_id: None,
                charter_version_digest: "charter".to_string(),
                policy_version_digest: "policy".to_string(),
                prev_record_digest: store.current_head_record_digest,
                profile_digest: None,
                tool_profile_digest: None,
                pev_digest: None,
            },
            required_receipt_kind: RequiredReceiptKind::Read,
            required_checks: vec![RequiredCheck::SchemaOk],
            payload_digests: Vec::new(),
            epoch_id: keystore.current_epoch(),
            key_epoch: None,
            experience_record_payload: Some(record.encode_to_vec()),
            macro_milestone: None,
            meso_milestone: None,
            dlp_decision_payload: None,
            tool_registry_container: None,
            pev: None,
            consistency_feedback_payload: None,
            macro_consistency_digest: None,
        };

        let (receipt, _) = verify_and_commit(req, store, keystore, vrf_engine);
        assert_eq!(receipt.status, ReceiptStatus::Accepted);

        store.experience_store.head_record_digest
    }

    #[test]
    fn list_export_attempts_returns_output() {
        let mut known_charter_versions = HashSet::new();
        known_charter_versions.insert("charter".to_string());
        let mut known_policy_versions = HashSet::new();
        known_policy_versions.insert("policy".to_string());

        let mut store = PvgsStore::new(
            [0u8; 32],
            "charter".to_string(),
            "policy".to_string(),
            known_charter_versions,
            known_policy_versions,
            HashSet::new(),
        );
        let keystore = KeyStore::new_dev_keystore(3);
        let vrf_engine = VrfEngine::new_dev(3);
        let dlp_digest = [5u8; 32];
        let commit_id = "export-list";
        append_output_record(&mut store, &keystore, &vrf_engine, commit_id, dlp_digest);

        let attempts = list_export_attempts(&store, commit_id);
        assert_eq!(attempts.len(), 1);
        assert_eq!(
            attempts[0].record_digest,
            store.experience_store.head_record_digest
        );
        assert_eq!(attempts[0].dlp_decision_digest, Some(dlp_digest));
        assert_eq!(
            attempts[0].reason_codes,
            vec![ReasonCodes::RE_INTEGRITY_DEGRADED.to_string()]
        );
        assert!(attempts[0].timestamp_ms.is_some());
        assert!(attempts[0].blocked);
        assert!(!attempts[0].decision_present);
    }

    #[test]
    fn list_export_attempts_reflects_block_decision() {
        let mut known_charter_versions = HashSet::new();
        known_charter_versions.insert("charter".to_string());
        let mut known_policy_versions = HashSet::new();
        known_policy_versions.insert("policy".to_string());

        let mut store = PvgsStore::new(
            [0u8; 32],
            "charter".to_string(),
            "policy".to_string(),
            known_charter_versions,
            known_policy_versions,
            HashSet::new(),
        );
        let keystore = KeyStore::new_dev_keystore(3);
        let vrf_engine = VrfEngine::new_dev(3);
        let dlp_digest = [6u8; 32];

        store_dlp_decision(
            &mut store,
            dlp_digest,
            DlpDecisionForm::Block,
            vec![
                ReasonCodes::CD_DLP_SECRET_PATTERN,
                ReasonCodes::CD_DLP_EXPORT_BLOCKED,
            ],
        );

        let commit_id = "export-blocked";
        append_output_record(&mut store, &keystore, &vrf_engine, commit_id, dlp_digest);

        let attempts = list_export_attempts(&store, commit_id);
        assert_eq!(attempts.len(), 1);
        assert_eq!(attempts[0].dlp_decision_digest, Some(dlp_digest));
        assert!(attempts[0].blocked);
        assert!(attempts[0].decision_present);
        assert_eq!(
            attempts[0].reason_codes,
            vec![
                ReasonCodes::CD_DLP_EXPORT_BLOCKED.to_string(),
                ReasonCodes::CD_DLP_SECRET_PATTERN.to_string(),
            ]
        );
    }

    #[test]
    fn list_export_attempts_reflects_allow_decision() {
        let mut known_charter_versions = HashSet::new();
        known_charter_versions.insert("charter".to_string());
        let mut known_policy_versions = HashSet::new();
        known_policy_versions.insert("policy".to_string());

        let mut store = PvgsStore::new(
            [0u8; 32],
            "charter".to_string(),
            "policy".to_string(),
            known_charter_versions,
            known_policy_versions,
            HashSet::new(),
        );
        let keystore = KeyStore::new_dev_keystore(3);
        let vrf_engine = VrfEngine::new_dev(3);
        let dlp_digest = [7u8; 32];

        store_dlp_decision(
            &mut store,
            dlp_digest,
            DlpDecisionForm::Allow,
            vec![ReasonCodes::RE_INTEGRITY_OK],
        );

        let commit_id = "export-allowed";
        append_output_record(&mut store, &keystore, &vrf_engine, commit_id, dlp_digest);

        let attempts = list_export_attempts(&store, commit_id);
        assert_eq!(attempts.len(), 1);
        assert_eq!(attempts[0].dlp_decision_digest, Some(dlp_digest));
        assert!(!attempts[0].blocked);
        assert!(attempts[0].decision_present);
        assert_eq!(
            attempts[0].reason_codes,
            vec![ReasonCodes::RE_INTEGRITY_OK.to_string()]
        );
    }

    #[test]
    fn list_export_attempts_are_sorted_by_record_digest() {
        let mut known_charter_versions = HashSet::new();
        known_charter_versions.insert("charter".to_string());
        let mut known_policy_versions = HashSet::new();
        known_policy_versions.insert("policy".to_string());

        let mut store = PvgsStore::new(
            [0u8; 32],
            "charter".to_string(),
            "policy".to_string(),
            known_charter_versions,
            known_policy_versions,
            HashSet::new(),
        );
        let keystore = KeyStore::new_dev_keystore(3);
        let vrf_engine = VrfEngine::new_dev(3);

        let digest_a = [1u8; 32];
        let digest_b = [2u8; 32];
        store_dlp_decision(
            &mut store,
            digest_a,
            DlpDecisionForm::Allow,
            vec![ReasonCodes::RE_INTEGRITY_OK],
        );
        store_dlp_decision(
            &mut store,
            digest_b,
            DlpDecisionForm::Block,
            vec![ReasonCodes::CD_DLP_EXPORT_BLOCKED],
        );

        let commit_id = "export-order";
        let first_record =
            append_output_record(&mut store, &keystore, &vrf_engine, commit_id, digest_b);
        let second_record =
            append_output_record(&mut store, &keystore, &vrf_engine, commit_id, digest_a);

        let mut expected = vec![first_record, second_record];
        expected.sort();

        let attempts = list_export_attempts(&store, commit_id);
        assert_eq!(attempts.len(), 2);
        assert_eq!(
            attempts
                .iter()
                .map(|attempt| attempt.record_digest)
                .collect::<Vec<_>>(),
            expected
        );
    }

    #[test]
    fn trace_exports_blocks_on_dlp_decision() {
        let mut known_charter_versions = HashSet::new();
        known_charter_versions.insert("charter".to_string());
        let mut known_policy_versions = HashSet::new();
        known_policy_versions.insert("policy".to_string());

        let mut store = PvgsStore::new(
            [0u8; 32],
            "charter".to_string(),
            "policy".to_string(),
            known_charter_versions,
            known_policy_versions,
            HashSet::new(),
        );
        let keystore = KeyStore::new_dev_keystore(3);
        let vrf_engine = VrfEngine::new_dev(3);
        let dlp_digest = [11u8; 32];
        let output_artifact_digest = [12u8; 32];
        let ruleset_digest = [13u8; 32];
        let policy_decision_digest = [14u8; 32];

        store_dlp_decision(
            &mut store,
            dlp_digest,
            DlpDecisionForm::Block,
            vec![ReasonCodes::CD_DLP_SECRET_PATTERN],
        );

        let commit_id = "trace-blocked";
        append_output_record_with_refs(
            &mut store,
            &keystore,
            &vrf_engine,
            commit_id,
            dlp_digest,
            vec![
                Ref {
                    id: format!("output_artifact:{}", hex::encode(output_artifact_digest)),
                },
                Ref {
                    id: format!("ruleset:{}", hex::encode(ruleset_digest)),
                },
                Ref {
                    id: format!("decision:{}", hex::encode(policy_decision_digest)),
                },
            ],
            Vec::new(),
        );

        let audits = trace_exports(&store, commit_id);
        assert_eq!(audits.len(), 1);
        let audit = &audits[0];
        assert!(audit.blocked);
        assert!(audit.decision_present);
        assert_eq!(audit.dlp_decision_digest, dlp_digest);
        assert_eq!(audit.dlp_form, DlpDecisionForm::Block);
        assert_eq!(
            audit.dlp_reason_codes,
            vec![ReasonCodes::CD_DLP_SECRET_PATTERN.to_string()]
        );
        assert_eq!(audit.output_artifact_digest, Some(output_artifact_digest));
        assert_eq!(audit.ruleset_digest, Some(ruleset_digest));
        assert_eq!(audit.policy_decision_digest, Some(policy_decision_digest));
    }

    #[test]
    fn trace_exports_allows_on_allow_decision() {
        let mut known_charter_versions = HashSet::new();
        known_charter_versions.insert("charter".to_string());
        let mut known_policy_versions = HashSet::new();
        known_policy_versions.insert("policy".to_string());

        let mut store = PvgsStore::new(
            [0u8; 32],
            "charter".to_string(),
            "policy".to_string(),
            known_charter_versions,
            known_policy_versions,
            HashSet::new(),
        );
        let keystore = KeyStore::new_dev_keystore(3);
        let vrf_engine = VrfEngine::new_dev(3);
        let dlp_digest = [15u8; 32];

        store_dlp_decision(
            &mut store,
            dlp_digest,
            DlpDecisionForm::Allow,
            vec![ReasonCodes::RE_INTEGRITY_OK],
        );

        let commit_id = "trace-allow";
        append_output_record_with_refs(
            &mut store,
            &keystore,
            &vrf_engine,
            commit_id,
            dlp_digest,
            Vec::new(),
            Vec::new(),
        );

        let audits = trace_exports(&store, commit_id);
        assert_eq!(audits.len(), 1);
        let audit = &audits[0];
        assert!(!audit.blocked);
        assert!(audit.decision_present);
        assert_eq!(audit.dlp_form, DlpDecisionForm::Allow);
        assert_eq!(
            audit.dlp_reason_codes,
            vec![ReasonCodes::RE_INTEGRITY_OK.to_string()]
        );
    }

    #[test]
    fn trace_exports_blocks_when_decision_missing() {
        let mut known_charter_versions = HashSet::new();
        known_charter_versions.insert("charter".to_string());
        let mut known_policy_versions = HashSet::new();
        known_policy_versions.insert("policy".to_string());

        let mut store = PvgsStore::new(
            [0u8; 32],
            "charter".to_string(),
            "policy".to_string(),
            known_charter_versions,
            known_policy_versions,
            HashSet::new(),
        );
        let keystore = KeyStore::new_dev_keystore(3);
        let vrf_engine = VrfEngine::new_dev(3);
        let missing_digest = [21u8; 32];

        let commit_id = "trace-missing";
        append_output_record_with_refs(
            &mut store,
            &keystore,
            &vrf_engine,
            commit_id,
            missing_digest,
            Vec::new(),
            Vec::new(),
        );

        let audits = trace_exports(&store, commit_id);
        assert_eq!(audits.len(), 1);
        let audit = &audits[0];
        assert!(audit.blocked);
        assert!(!audit.decision_present);
        assert_eq!(audit.dlp_form, DlpDecisionForm::Unspecified);
        assert_eq!(
            audit.dlp_reason_codes,
            vec![RC_RE_DLP_DECISION_MISSING.to_string()]
        );
    }

    #[test]
    fn trace_exports_is_deterministic() {
        let mut known_charter_versions = HashSet::new();
        known_charter_versions.insert("charter".to_string());
        let mut known_policy_versions = HashSet::new();
        known_policy_versions.insert("policy".to_string());

        let mut store = PvgsStore::new(
            [0u8; 32],
            "charter".to_string(),
            "policy".to_string(),
            known_charter_versions,
            known_policy_versions,
            HashSet::new(),
        );
        let keystore = KeyStore::new_dev_keystore(3);
        let vrf_engine = VrfEngine::new_dev(3);

        let first_dlp = [31u8; 32];
        let second_dlp = [32u8; 32];

        store_dlp_decision(
            &mut store,
            first_dlp,
            DlpDecisionForm::Allow,
            vec![ReasonCodes::RE_INTEGRITY_OK],
        );
        store_dlp_decision(
            &mut store,
            second_dlp,
            DlpDecisionForm::Allow,
            vec![ReasonCodes::RE_INTEGRITY_OK],
        );

        let commit_id = "trace-ordering";
        let first_record = append_output_record_with_refs(
            &mut store,
            &keystore,
            &vrf_engine,
            commit_id,
            second_dlp,
            Vec::new(),
            Vec::new(),
        );
        let second_record = append_output_record_with_refs(
            &mut store,
            &keystore,
            &vrf_engine,
            commit_id,
            first_dlp,
            Vec::new(),
            Vec::new(),
        );

        let mut expected_records = vec![first_record, second_record];
        expected_records.sort();

        let audits = trace_exports(&store, commit_id);
        assert_eq!(
            audits
                .iter()
                .map(|audit| audit.record_digest)
                .collect::<Vec<_>>(),
            expected_records
        );
    }

    #[test]
    fn pending_replay_plans_sorted_and_consumed() {
        let mut store = minimal_store();
        let target_ref = Ref {
            id: "target".to_string(),
        };

        let plan_two = build_replay_plan(BuildReplayPlanArgs {
            session_id: "sess".to_string(),
            head_experience_id: 1,
            head_record_digest: [1u8; 32],
            target_kind: ReplayTargetKind::Macro,
            target_refs: vec![target_ref.clone()],
            fidelity: ReplayFidelity::Low,
            counter: 2,
            trigger_reason_codes: Vec::new(),
        });
        let plan_one = build_replay_plan(BuildReplayPlanArgs {
            session_id: "sess".to_string(),
            head_experience_id: 1,
            head_record_digest: [1u8; 32],
            target_kind: ReplayTargetKind::Macro,
            target_refs: vec![target_ref],
            fidelity: ReplayFidelity::Low,
            counter: 1,
            trigger_reason_codes: Vec::new(),
        });

        store.replay_plans.push(plan_two).unwrap();
        store.replay_plans.push(plan_one).unwrap();

        let plans = get_pending_replay_plans(&store, "sess");
        assert_eq!(plans.len(), 2);
        assert!(plans[0].replay_id < plans[1].replay_id);

        consume_replay_plan(&mut store, &plans[0].replay_id).expect("consume first");
        let remaining = get_pending_replay_plans(&store, "sess");
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].replay_id, plans[1].replay_id);
    }
}
