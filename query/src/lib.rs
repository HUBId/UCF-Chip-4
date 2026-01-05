#![forbid(unsafe_code)]

use cbv::{
    compute_cbv_digest, CbvStore, CharacterBaselineVector, MacroMilestone, MacroMilestoneState,
};
use dlp_store::DlpDecisionStore;
use milestones::{MesoMilestone, MicroMilestone};
use pev::{pev_digest, PolicyEcologyVector};
use proposal_activations::{ActivationStatus, ProposalActivationEvidence};
use proposals::{ProposalEvidence, ProposalKind};
use prost::Message;
use pvgs::{compute_experience_record_digest, CompletenessStatus, PvgsCommitRequest, PvgsStore};
use recovery::{
    RecoveryCase as InternalRecoveryCase, RecoveryCheck as InternalRecoveryCheck,
    RecoveryState as InternalRecoveryState,
};
use sep::{EdgeType, NodeKey, SepEventInternal, SepEventType, SepLog};
use std::collections::{BTreeSet, VecDeque};
use std::convert::TryFrom;
use thiserror::Error;
use trace_runs::{TraceRunEvidence, TraceVerdict};
use ucf_protocol::ucf::v1::{
    AssetBundle, AssetChunk, AssetKind, AssetManifest, ChannelParamsSetPayload, CompressionMode,
    ConnectivityGraphPayload, ConsistencyFeedback, DlpDecisionForm, ExperienceRecord, MicroModule,
    MicrocircuitConfigEvidence, MorphologySetPayload, PVGSKeyEpoch, PVGSReceipt, ProofReceipt,
    ReasonCodes, RecordType, RecoveryCase as ProtoRecoveryCase,
    RecoveryCheck as ProtoRecoveryCheck, RecoveryState as ProtoRecoveryState, ReplayPlan,
    ReplayRunEvidence, SynapseParamsSetPayload, ToolOnboardingEvent, ToolOnboardingStage,
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
    pub micro_snapshots_lc: Vec<[u8; 32]>,
    pub micro_snapshots_sn: Vec<[u8; 32]>,
    pub plasticity_snapshots: Vec<[u8; 32]>,
    pub micro_configs_lc: Vec<[u8; 32]>,
    pub micro_configs_sn: Vec<[u8; 32]>,
    pub replay_run_digests: Vec<[u8; 32]>,
    pub micro_evidence: MicroEvidenceSummary,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MicroEvidenceSummary {
    pub lc_snapshots: Vec<[u8; 32]>,
    pub sn_snapshots: Vec<[u8; 32]>,
    pub lc_configs: Vec<[u8; 32]>,
    pub sn_configs: Vec<[u8; 32]>,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordTrace {
    pub references: Vec<NodeKey>,
    pub referenced_by: Vec<NodeKey>,
    pub dlp_decisions: Vec<NodeKey>,
    pub micro_evidence: MicroEvidenceSummary,
    pub plasticity_snapshots: Vec<[u8; 32]>,
    pub replay_run_digests: Vec<[u8; 32]>,
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
pub struct ToolSuspensionExplanation {
    pub tool_id: String,
    pub action_id: String,
    pub suspended: bool,
    pub latest_event_digest: Option<[u8; 32]>,
    pub latest_reason_codes: Vec<String>,
    pub event_ruleset_digest: Option<[u8; 32]>,
    pub event_tool_registry_digest: Option<[u8; 32]>,
    pub event_timestamp_ms: Option<u64>,
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
    pub recovery_case: Option<ProtoRecoveryCase>,
    pub unlock_permit_digest: Option<[u8; 32]>,
    pub unlock_readiness_hint: Option<String>,
    pub micro_card: MicroCard,
    pub plasticity_card: PlasticityCard,
    pub assets_card: AssetsCard,
    pub replay_card: ReplayCard,
    pub trace_card: TraceCard,
    pub proposals_card: ProposalsCard,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingReplayPlanView {
    pub replay_id: String,
    pub asset_manifest_digest: Option<[u8; 32]>,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MicroCard {
    pub lc_config_digest: Option<[u8; 32]>,
    pub lc_config_version: Option<u32>,
    pub sn_config_digest: Option<[u8; 32]>,
    pub sn_config_version: Option<u32>,
    pub hpa_config_digest: Option<[u8; 32]>,
    pub hpa_config_version: Option<u32>,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AssetsCard {
    pub latest_manifest_digest: Option<[u8; 32]>,
    pub latest_bundle_digest: Option<[u8; 32]>,
    pub morphology_digest: Option<[u8; 32]>,
    pub channel_digest: Option<[u8; 32]>,
    pub synapse_digest: Option<[u8; 32]>,
    pub connectivity_digest: Option<[u8; 32]>,
    pub total_asset_chunks: u64,
    pub compression_none_count: u64,
    pub compression_zstd_count: u64,
    pub asset_digest_mismatch_count: u64,
    pub asset_payload_summaries: Vec<AssetPayloadSummary>,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReplayCard {
    pub pending_replay_plans_asset_bound_count: u64,
    pub pending_replay_plans_asset_missing_count: u64,
    pub pending_replay_plans_asset_missing_ids: Vec<String>,
    pub replay_run_count_last_n: u64,
    pub latest_replay_run_digest: Option<[u8; 32]>,
    pub unique_replay_run_count_last_n: u64,
    pub last_replay_run_digests: Vec<[u8; 32]>,
    pub replay_run_evidence_count_last_n: u64,
    pub latest_replay_run_evidence_digest: Option<[u8; 32]>,
    pub asset_bound_run_count: u64,
    pub top_micro_modules_in_runs: Vec<MicroModuleCount>,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TraceCard {
    pub latest_trace_run_digest: Option<[u8; 32]>,
    pub latest_trace_verdict: Option<TraceVerdict>,
    pub latest_trace_delta: Option<i32>,
    pub counts_last_n: TraceVerdictCounts,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProposalsCard {
    pub latest_proposal_digest: Option<[u8; 32]>,
    pub latest_proposal_kind: Option<ProposalKind>,
    pub latest_proposal_verdict: Option<i32>,
    pub latest_activation_status: Option<ActivationStatus>,
    pub activation_counts_last_n: ActivationStatusCounts,
    pub activation_rejects_present: bool,
    pub risky_activations_present: bool,
    pub counts_last_n: ProposalVerdictCounts,
    pub risky_present: bool,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ActivationStatusCounts {
    pub applied: u64,
    pub rejected: u64,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProposalVerdictCounts {
    pub promising: u64,
    pub neutral: u64,
    pub risky: u64,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TraceVerdictCounts {
    pub promising: u64,
    pub neutral: u64,
    pub risky: u64,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TraceRunSummaryCounts {
    pub promising: u64,
    pub neutral: u64,
    pub risky: u64,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MicroModuleCount {
    pub module: MicroModule,
    pub count: u64,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayRunSummary {
    pub run_digest: [u8; 32],
    pub replay_plan_digest: Option<[u8; 32]>,
    pub asset_manifest_digest: Option<[u8; 32]>,
    pub steps: u64,
    pub dt_us: u64,
    pub created_at_ms: u64,
    pub micro_config_digests: Vec<[u8; 32]>,
    pub summary_digests: Vec<[u8; 32]>,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetPayloadSummary {
    pub kind: AssetKind,
    pub version: u32,
    pub digest: [u8; 32],
    pub bytes_len: u32,
    pub neuron_count: Option<u32>,
    pub edge_count: Option<u32>,
    pub syn_param_count: Option<u32>,
    pub channel_param_count: Option<u32>,
    pub has_pool_labels: bool,
    pub has_role_labels: bool,
}

const MAX_MACRO_VECTOR_ITEMS: usize = 64;
const MAX_CBV_SCAN: usize = 32;
const MAX_ASSET_MANIFESTS: usize = 128;
const MAX_ASSET_BUNDLES: usize = 128;
const MAX_ASSET_PAYLOAD_SUMMARIES: usize = 4;
const MAX_ASSET_PAYLOAD_DECODE_BYTES: usize = 2 * 1024 * 1024;
const MAX_REPLAY_RUN_DIGESTS: usize = 64;
const MAX_REPLAY_SCORECARD_DIGESTS: usize = 128;
const MAX_REPLAY_SCORECARD_LIST: usize = 5;
const REPLAY_SCORECARD_WINDOW: usize = 1000;
const REPLAY_RUN_EVIDENCE_WINDOW: usize = 1000;
const TRACE_RUN_EVIDENCE_WINDOW: usize = 1000;
const MAX_TRACE_RUNS: usize = 128;
const TRACE_DELTA_BOUND: i32 = 1_000_000;
const MAX_PLASTICITY_EVIDENCE: usize = 128;
const MAX_PLASTICITY_SCORECARD_DIGESTS: usize = 128;
const MAX_PLASTICITY_SCORECARD_LIST: usize = 5;
const PLASTICITY_SCORECARD_WINDOW: usize = 1000;
const PROPOSAL_SCORECARD_WINDOW: usize = 128;
const PROPOSAL_ACTIVATION_SCORECARD_WINDOW: usize = 128;

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
pub fn is_session_sealed(store: &PvgsStore, session_id: &str) -> bool {
    store.forensic_mode
        && store.sep_log.events.iter().any(|event| {
            event.session_id == session_id && event.event_type == SepEventType::EvRecovery
        })
}

pub fn has_unlock_permit(store: &PvgsStore, session_id: &str) -> bool {
    store.unlock_permits.contains_key(session_id)
}

pub fn get_unlock_permit_digest(store: &PvgsStore, session_id: &str) -> Option<[u8; 32]> {
    store
        .unlock_permits
        .get(session_id)
        .map(|permit| permit.permit_digest)
}

pub fn list_tool_events(
    store: &PvgsStore,
    tool_id: &str,
    action_id: &str,
) -> Vec<ToolOnboardingEvent> {
    store.tool_event_store.list_for(tool_id, action_id)
}

pub fn explain_tool_suspension(
    store: &PvgsStore,
    tool_id: &str,
    action_id: &str,
) -> ToolSuspensionExplanation {
    let mut latest: Option<(&ToolOnboardingEvent, usize)> = None;

    for (idx, event) in store.tool_event_store.iter().enumerate() {
        if event.tool_id != tool_id || event.action_id != action_id {
            continue;
        }

        if !matches!(
            ToolOnboardingStage::try_from(event.stage).ok(),
            Some(ToolOnboardingStage::To6Suspended)
        ) {
            continue;
        }

        if let Some((prev, prev_idx)) = latest {
            if is_newer_tool_event(event, idx, prev, prev_idx) {
                latest = Some((event, idx));
            }
        } else {
            latest = Some((event, idx));
        }
    }

    let mut explanation = ToolSuspensionExplanation {
        tool_id: tool_id.to_string(),
        action_id: action_id.to_string(),
        suspended: latest.is_some(),
        latest_event_digest: None,
        latest_reason_codes: Vec::new(),
        event_ruleset_digest: None,
        event_tool_registry_digest: None,
        event_timestamp_ms: None,
    };

    if let Some((event, _)) = latest {
        explanation.event_timestamp_ms = event.created_at_ms;
        explanation.latest_reason_codes = event.reason_codes.clone();

        if let Some(digest) = event.event_digest.as_deref().and_then(digest_from_bytes) {
            explanation.latest_event_digest = Some(digest);

            if let Some(correlation) = store.tool_event_correlations.get(&digest) {
                explanation.event_ruleset_digest = Some(correlation.ruleset_digest);
                explanation.event_tool_registry_digest = correlation.tool_registry_digest;
            }
        }
    }

    explanation
}

pub fn list_suspended_tools_with_reasons(store: &PvgsStore) -> Vec<ToolSuspensionExplanation> {
    let mut explanations: Vec<_> = store
        .suspended_tools
        .iter()
        .map(|(tool_id, action_id)| explain_tool_suspension(store, tool_id, action_id))
        .collect();

    explanations.sort_by(|a, b| {
        a.tool_id
            .cmp(&b.tool_id)
            .then(a.action_id.cmp(&b.action_id))
    });

    explanations
}

pub fn is_tool_suspended(store: &PvgsStore, tool_id: &str, action_id: &str) -> bool {
    let Some((event, _)) = store.tool_event_store.latest_for(tool_id, action_id) else {
        return false;
    };

    matches!(
        ToolOnboardingStage::try_from(event.stage).ok(),
        Some(ToolOnboardingStage::To6Suspended)
    )
}

pub fn list_suspended_tools(store: &PvgsStore) -> Vec<(String, String)> {
    store.suspended_tools.iter().cloned().collect()
}

pub fn get_recovery_case_for_session(
    store: &PvgsStore,
    session_id: &str,
) -> Option<ProtoRecoveryCase> {
    let mut cases: Vec<_> = store
        .recovery_store
        .list_for_session(session_id)
        .into_iter()
        .filter(|case| case.state != InternalRecoveryState::R7Closed)
        .collect();

    if cases.is_empty() {
        return None;
    }

    cases.sort_by(|a, b| {
        let created_a = a.created_at_ms.unwrap_or_default();
        let created_b = b.created_at_ms.unwrap_or_default();

        created_a
            .cmp(&created_b)
            .then_with(|| a.recovery_id.cmp(&b.recovery_id))
    });

    cases.last().cloned().map(recovery_case_to_proto)
}

pub fn unlock_readiness_hint(store: &PvgsStore, session_id: &str) -> String {
    if has_unlock_permit(store, session_id) {
        "UNLOCKED_READONLY".to_string()
    } else if is_session_sealed(store, session_id) {
        "LOCKED".to_string()
    } else {
        "NONE".to_string()
    }
}

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

/// Return the latest asset manifest if present.
pub fn get_latest_asset_manifest(store: &PvgsStore) -> Option<AssetManifest> {
    list_asset_manifests(store).into_iter().last()
}

/// Return the latest asset manifest digest if present.
pub fn get_latest_asset_manifest_digest(store: &PvgsStore) -> Option<[u8; 32]> {
    get_latest_asset_manifest(store)
        .as_ref()
        .and_then(|manifest| digest_from_bytes(&manifest.manifest_digest))
}

/// Retrieve a specific asset manifest by digest.
pub fn get_asset_manifest(store: &PvgsStore, digest: [u8; 32]) -> Option<AssetManifest> {
    store.asset_manifest_store.get(digest).cloned()
}

pub fn get_asset_manifest_for_replay(store: &PvgsStore, replay_id: &str) -> Option<AssetManifest> {
    let plan = store
        .replay_plans
        .plans
        .iter()
        .find(|plan| plan.replay_id == replay_id)?;
    let digest = plan.asset_manifest_ref.as_ref().and_then(digest_from_ref)?;
    get_asset_manifest(store, digest)
}

/// List asset manifests sorted by created_at_ms then manifest digest.
pub fn list_asset_manifests(store: &PvgsStore) -> Vec<AssetManifest> {
    let mut manifests: Vec<AssetManifest> = store.asset_manifest_store.list().to_vec();
    manifests.sort_by(|a, b| {
        a.created_at_ms
            .cmp(&b.created_at_ms)
            .then_with(|| a.manifest_digest.cmp(&b.manifest_digest))
    });
    manifests.truncate(MAX_ASSET_MANIFESTS);
    manifests
}

/// Return the latest asset bundle if present.
pub fn get_latest_asset_bundle(store: &PvgsStore) -> Option<AssetBundle> {
    list_asset_bundles(store).into_iter().last()
}

/// Retrieve a specific asset bundle by digest.
pub fn get_asset_bundle(store: &PvgsStore, digest: [u8; 32]) -> Option<AssetBundle> {
    store.asset_bundle_store.get(digest).cloned()
}

/// List asset bundles sorted by created_at_ms then bundle digest.
pub fn list_asset_bundles(store: &PvgsStore) -> Vec<AssetBundle> {
    let mut bundles: Vec<AssetBundle> = store.asset_bundle_store.list().to_vec();
    bundles.sort_by(|a, b| {
        a.created_at_ms
            .cmp(&b.created_at_ms)
            .then_with(|| a.bundle_digest.cmp(&b.bundle_digest))
    });
    bundles.truncate(MAX_ASSET_BUNDLES);
    bundles
}

/// Retrieve stored chunks for an asset digest, sorted by chunk_index.
pub fn get_asset_chunks(store: &PvgsStore, asset_digest: [u8; 32]) -> Vec<AssetChunk> {
    let mut chunks = store
        .asset_bundle_store
        .chunks_for_asset(asset_digest)
        .map(|chunks| chunks.to_vec())
        .unwrap_or_default();
    chunks.sort_by_key(|chunk| chunk.chunk_index);
    chunks.truncate(store.asset_bundle_store.max_chunks_per_asset());
    chunks
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

        let mut store = store.clone();
        let status = store.check_completeness(session, action_digests).status;

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
        recovery_case: session_id.and_then(|session| get_recovery_case_for_session(store, session)),
        unlock_permit_digest: session_id
            .and_then(|session| get_unlock_permit_digest(store, session)),
        unlock_readiness_hint: session_id
            .map(|session| unlock_readiness_hint(store, session))
            .filter(|hint| hint != "NONE"),
        micro_card: micro_card_from_store(store),
        plasticity_card: plasticity_card_from_store(store),
        assets_card: assets_card_from_store(store),
        replay_card: replay_card_from_store(store, session_id),
        trace_card: trace_card_from_store(store),
        proposals_card: proposals_card_from_store(store),
    }
}

fn micro_card_from_store(store: &PvgsStore) -> MicroCard {
    let (lc_config_digest, lc_config_version) = latest_micro_config(store, MicroModule::Lc);
    let (sn_config_digest, sn_config_version) = latest_micro_config(store, MicroModule::Sn);
    let (hpa_config_digest, hpa_config_version) = latest_micro_config(store, MicroModule::Hpa);

    MicroCard {
        lc_config_digest,
        lc_config_version,
        sn_config_digest,
        sn_config_version,
        hpa_config_digest,
        hpa_config_version,
    }
}

fn assets_card_from_store(store: &PvgsStore) -> AssetsCard {
    let latest_manifest = get_latest_asset_manifest(store);
    let latest_manifest_digest = latest_manifest
        .as_ref()
        .and_then(|manifest| digest_from_bytes(&manifest.manifest_digest));
    let latest_bundle_digest = store
        .asset_bundle_store
        .latest()
        .and_then(|bundle| digest_from_bytes(&bundle.bundle_digest));
    let morphology_digest = latest_manifest
        .as_ref()
        .and_then(|manifest| select_asset_digest(manifest, AssetKind::Morphology));
    let channel_digest = latest_manifest
        .as_ref()
        .and_then(|manifest| select_asset_digest(manifest, AssetKind::Channel));
    let synapse_digest = latest_manifest
        .as_ref()
        .and_then(|manifest| select_asset_digest(manifest, AssetKind::Synapse));
    let connectivity_digest = latest_manifest
        .as_ref()
        .and_then(|manifest| select_asset_digest(manifest, AssetKind::Connectivity));

    let mut compression_none_count = 0u64;
    let mut compression_zstd_count = 0u64;
    for bundle in store.asset_bundle_store.list() {
        for chunk in &bundle.chunks {
            match CompressionMode::try_from(chunk.compression_mode)
                .unwrap_or(CompressionMode::Unspecified)
            {
                CompressionMode::None => compression_none_count += 1,
                CompressionMode::Zstd => compression_zstd_count += 1,
                CompressionMode::Unspecified => {}
            }
        }
    }

    let asset_digest_mismatch_count = store
        .sep_log
        .events
        .iter()
        .filter(|event| {
            event
                .reason_codes
                .iter()
                .any(|code| code == ReasonCodes::GV_ASSET_DIGEST_MISMATCH)
        })
        .count() as u64;

    let mut asset_payload_summaries = get_latest_asset_payload_summaries(store);
    asset_payload_summaries.truncate(MAX_ASSET_PAYLOAD_SUMMARIES);

    AssetsCard {
        latest_manifest_digest,
        latest_bundle_digest,
        morphology_digest,
        channel_digest,
        synapse_digest,
        connectivity_digest,
        total_asset_chunks: store.asset_bundle_store.total_chunks() as u64,
        compression_none_count,
        compression_zstd_count,
        asset_digest_mismatch_count,
        asset_payload_summaries,
    }
}

fn replay_card_from_store(store: &PvgsStore, session_id: Option<&str>) -> ReplayCard {
    let mut pending_plans = match session_id {
        Some(session) => get_pending_replay_plans(store, session),
        None => store.replay_plans.list_pending(),
    };
    pending_plans.sort_by(|a, b| a.replay_id.cmp(&b.replay_id));

    let mut asset_bound = 0u64;
    let mut asset_missing = 0u64;
    let mut missing_ids = Vec::new();

    for plan in pending_plans {
        let manifest_digest = plan.asset_manifest_ref.as_ref().and_then(digest_from_ref);
        let manifest_exists = manifest_digest
            .and_then(|digest| get_asset_manifest(store, digest))
            .is_some();

        if manifest_exists {
            asset_bound += 1;
        } else {
            asset_missing += 1;
            if missing_ids.len() < 3 {
                missing_ids.push(plan.replay_id.clone());
            }
        }
    }

    let start = store
        .experience_store
        .records
        .len()
        .saturating_sub(REPLAY_SCORECARD_WINDOW);
    let mut replay_run_count = 0u64;
    let mut latest_replay_run_digest = None;
    let mut unique_replay_runs = BTreeSet::new();
    let mut last_replay_run_digests = VecDeque::new();

    for record in store.experience_store.records.iter().skip(start) {
        let record_type =
            RecordType::try_from(record.record_type).unwrap_or(RecordType::Unspecified);
        if !matches!(record_type, RecordType::RtReplay) {
            continue;
        }

        let digests = replay_run_digests_from_record(record);
        if digests.is_empty() {
            continue;
        }

        replay_run_count = replay_run_count.saturating_add(1);

        for digest in digests {
            latest_replay_run_digest = Some(digest);
            unique_replay_runs.insert(digest);

            if let Some(pos) = last_replay_run_digests
                .iter()
                .position(|existing| existing == &digest)
            {
                last_replay_run_digests.remove(pos);
            }
            last_replay_run_digests.push_back(digest);
            if last_replay_run_digests.len() > MAX_REPLAY_SCORECARD_LIST {
                last_replay_run_digests.pop_front();
            }
        }
    }

    let mut unique_replay_run_digests: Vec<[u8; 32]> = unique_replay_runs.into_iter().collect();
    unique_replay_run_digests.truncate(MAX_REPLAY_SCORECARD_DIGESTS);
    let unique_replay_run_count = unique_replay_run_digests.len() as u64;

    let run_start = store
        .replay_run_store
        .runs
        .len()
        .saturating_sub(REPLAY_RUN_EVIDENCE_WINDOW);
    let recent_runs = store.replay_run_store.runs.iter().skip(run_start);
    let mut replay_run_evidence_count_last_n = 0u64;
    let mut latest_replay_run_evidence_digest = None;
    let mut latest_replay_run_created_at = 0u64;
    let mut asset_bound_run_count = 0u64;
    let mut module_count_map = std::collections::BTreeMap::new();

    for run in recent_runs {
        replay_run_evidence_count_last_n = replay_run_evidence_count_last_n.saturating_add(1);
        if let Some(digest) = digest_from_bytes(&run.run_digest) {
            let is_newer = match latest_replay_run_evidence_digest {
                Some(latest_digest) => {
                    run.created_at_ms > latest_replay_run_created_at
                        || (run.created_at_ms == latest_replay_run_created_at
                            && digest > latest_digest)
                }
                None => true,
            };
            if is_newer {
                latest_replay_run_created_at = run.created_at_ms;
                latest_replay_run_evidence_digest = Some(digest);
            }
        }

        if run
            .asset_manifest_ref
            .as_ref()
            .and_then(digest_from_ref)
            .is_some()
        {
            asset_bound_run_count = asset_bound_run_count.saturating_add(1);
        }

        for reference in &run.micro_config_refs {
            if let Some(module) = micro_module_from_config_ref(reference) {
                let entry = module_count_map.entry(module).or_insert(0u64);
                *entry = (*entry).saturating_add(1);
            }
        }
    }

    let mut top_micro_modules_in_runs: Vec<MicroModuleCount> = module_count_map
        .into_iter()
        .map(|(module, count)| MicroModuleCount { module, count })
        .collect();
    top_micro_modules_in_runs
        .sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.module.cmp(&b.module)));

    ReplayCard {
        pending_replay_plans_asset_bound_count: asset_bound,
        pending_replay_plans_asset_missing_count: asset_missing,
        pending_replay_plans_asset_missing_ids: missing_ids,
        replay_run_count_last_n: replay_run_count,
        latest_replay_run_digest,
        unique_replay_run_count_last_n: unique_replay_run_count,
        last_replay_run_digests: last_replay_run_digests.into_iter().collect(),
        replay_run_evidence_count_last_n,
        latest_replay_run_evidence_digest,
        asset_bound_run_count,
        top_micro_modules_in_runs,
    }
}

fn trace_card_from_store(store: &PvgsStore) -> TraceCard {
    let run_start = store
        .trace_run_store
        .runs
        .len()
        .saturating_sub(TRACE_RUN_EVIDENCE_WINDOW);
    let recent_runs = store.trace_run_store.runs.iter().skip(run_start);
    let mut counts = TraceVerdictCounts::default();
    let mut latest_digest = None;
    let mut latest_verdict = None;
    let mut latest_delta = None;
    let mut latest_created_at = 0u64;

    for run in recent_runs {
        let verdict = TraceVerdict::try_from(run.verdict).unwrap_or(TraceVerdict::Unspecified);
        match verdict {
            TraceVerdict::Promising => counts.promising = counts.promising.saturating_add(1),
            TraceVerdict::Neutral => counts.neutral = counts.neutral.saturating_add(1),
            TraceVerdict::Risky => counts.risky = counts.risky.saturating_add(1),
            TraceVerdict::Unspecified => {}
        }

        let run_digest = digest_from_bytes(&run.trace_digest).unwrap_or([0u8; 32]);
        let is_newer = match latest_digest {
            Some(digest) => {
                run.created_at_ms > latest_created_at
                    || (run.created_at_ms == latest_created_at && run_digest > digest)
            }
            None => true,
        };
        if is_newer {
            latest_created_at = run.created_at_ms;
            latest_digest = Some(run_digest);
            latest_verdict = Some(verdict);
            latest_delta = Some(run.delta.clamp(-TRACE_DELTA_BOUND, TRACE_DELTA_BOUND));
        }
    }

    TraceCard {
        latest_trace_run_digest: latest_digest,
        latest_trace_verdict: latest_verdict,
        latest_trace_delta: latest_delta,
        counts_last_n: counts,
    }
}

fn proposals_card_from_store(store: &PvgsStore) -> ProposalsCard {
    let latest = latest_proposal(store);
    let counts = proposal_counts_last_n(store, PROPOSAL_SCORECARD_WINDOW);
    let activation_counts = activation_counts_last_n(store, PROPOSAL_ACTIVATION_SCORECARD_WINDOW);
    let activation_rejects_present = activation_counts.rejected > 0;
    let risky_activations =
        risky_activation_count_last_n(store, PROPOSAL_ACTIVATION_SCORECARD_WINDOW);
    let latest_activation = latest_proposal_activation(store);
    ProposalsCard {
        latest_proposal_digest: latest
            .as_ref()
            .and_then(|proposal| digest_from_bytes(&proposal.proposal_digest)),
        latest_proposal_kind: latest
            .as_ref()
            .and_then(|proposal| ProposalKind::try_from(proposal.kind).ok()),
        latest_proposal_verdict: latest.as_ref().map(|proposal| proposal.verdict),
        latest_activation_status: latest_activation
            .and_then(|activation| ActivationStatus::try_from(activation.status).ok()),
        activation_counts_last_n: activation_counts,
        activation_rejects_present,
        risky_activations_present: risky_activations > 0,
        risky_present: counts.risky > 0,
        counts_last_n: counts,
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PlasticityCard {
    pub learning_evidence_record_count: u64,
    pub latest_plasticity_snapshot_digest: Option<[u8; 32]>,
    pub unique_plasticity_snapshot_count: u64,
    pub last_plasticity_digests: Vec<[u8; 32]>,
}

fn plasticity_card_from_store(store: &PvgsStore) -> PlasticityCard {
    let start = store
        .experience_store
        .records
        .len()
        .saturating_sub(PLASTICITY_SCORECARD_WINDOW);
    let mut evidence_records = 0u64;
    let mut latest_digest = None;
    let mut unique_digests = BTreeSet::new();

    for record in store.experience_store.records.iter().skip(start) {
        let mut record_has_evidence = false;
        if let Some(gov) = &record.governance_frame {
            for reference in &gov.policy_decision_refs {
                if let Some(digest) = digest_from_labeled_ref(reference, "mc_snap:plasticity") {
                    record_has_evidence = true;
                    latest_digest = Some(digest);
                    unique_digests.insert(digest);
                }
            }
        }

        if record_has_evidence {
            evidence_records = evidence_records.saturating_add(1);
        }
    }

    let mut digests: Vec<[u8; 32]> = unique_digests.into_iter().collect();
    digests.truncate(MAX_PLASTICITY_SCORECARD_DIGESTS);
    let unique_count = digests.len() as u64;
    let last_plasticity_digests = digests
        .iter()
        .copied()
        .take(MAX_PLASTICITY_SCORECARD_LIST)
        .collect();

    PlasticityCard {
        learning_evidence_record_count: evidence_records,
        latest_plasticity_snapshot_digest: latest_digest,
        unique_plasticity_snapshot_count: unique_count,
        last_plasticity_digests,
    }
}

fn latest_micro_config(store: &PvgsStore, module: MicroModule) -> (Option<[u8; 32]>, Option<u32>) {
    store
        .micro_config_store
        .latest_for_module(module)
        .map(|config| {
            (
                digest_from_bytes(&config.config_digest),
                Some(config.config_version),
            )
        })
        .unwrap_or((None, None))
}

fn select_asset_digest(manifest: &AssetManifest, kind: AssetKind) -> Option<[u8; 32]> {
    manifest
        .asset_digests
        .iter()
        .filter(|asset| AssetKind::try_from(asset.kind).ok() == Some(kind))
        .filter_map(|asset| digest_from_bytes(&asset.digest).map(|digest| (asset.version, digest)))
        .max_by(|(version_a, digest_a), (version_b, digest_b)| {
            version_a
                .cmp(version_b)
                .then_with(|| digest_a.cmp(digest_b))
        })
        .map(|(_, digest)| digest)
}

fn select_asset_digest_with_version(
    manifest: &AssetManifest,
    kind: AssetKind,
) -> Option<(u32, [u8; 32])> {
    manifest
        .asset_digests
        .iter()
        .filter(|asset| AssetKind::try_from(asset.kind).ok() == Some(kind))
        .filter_map(|asset| digest_from_bytes(&asset.digest).map(|digest| (asset.version, digest)))
        .max_by(|(version_a, digest_a), (version_b, digest_b)| {
            version_a
                .cmp(version_b)
                .then_with(|| digest_a.cmp(digest_b))
        })
}

fn reassemble_asset_payload(chunks: &[AssetChunk]) -> Option<Vec<u8>> {
    if chunks.is_empty() {
        return None;
    }
    let mut ordered = chunks.to_vec();
    ordered.sort_by_key(|chunk| chunk.chunk_index);
    let expected_count = ordered[0].chunk_count;
    if expected_count as usize != ordered.len() {
        return None;
    }
    for (idx, chunk) in ordered.iter().enumerate() {
        if chunk.chunk_index != idx as u32 || chunk.chunk_count != expected_count {
            return None;
        }
    }
    let mut payload = Vec::new();
    for chunk in ordered {
        payload.extend_from_slice(&chunk.payload);
    }
    Some(payload)
}

pub fn get_latest_asset_payload_summaries(store: &PvgsStore) -> Vec<AssetPayloadSummary> {
    let manifest = get_latest_asset_manifest(store).or_else(|| {
        store
            .asset_bundle_store
            .latest()
            .and_then(|bundle| bundle.manifest.clone())
    });
    let Some(manifest) = manifest else {
        return Vec::new();
    };

    let mut summaries = Vec::new();
    for kind in [
        AssetKind::Morphology,
        AssetKind::Channel,
        AssetKind::Synapse,
        AssetKind::Connectivity,
    ] {
        let Some((version, digest)) = select_asset_digest_with_version(&manifest, kind) else {
            continue;
        };
        let Some(chunks) = store.asset_bundle_store.chunks_for_asset(digest) else {
            continue;
        };
        let Some(payload) = reassemble_asset_payload(chunks) else {
            continue;
        };
        let bytes_len = payload.len() as u32;

        let mut summary = AssetPayloadSummary {
            kind,
            version,
            digest,
            bytes_len,
            neuron_count: None,
            edge_count: None,
            syn_param_count: None,
            channel_param_count: None,
            has_pool_labels: false,
            has_role_labels: false,
        };

        if payload.len() <= MAX_ASSET_PAYLOAD_DECODE_BYTES {
            match kind {
                AssetKind::Morphology => {
                    if let Ok(decoded) = MorphologySetPayload::decode(payload.as_slice()) {
                        summary.neuron_count = Some(decoded.morphologies.len() as u32);
                        summary.has_pool_labels = decoded
                            .morphologies
                            .iter()
                            .any(|entry| !entry.pool_label.is_empty());
                        summary.has_role_labels = decoded
                            .morphologies
                            .iter()
                            .any(|entry| !entry.role_label.is_empty());
                    }
                }
                AssetKind::Channel => {
                    if let Ok(decoded) = ChannelParamsSetPayload::decode(payload.as_slice()) {
                        summary.channel_param_count = Some(decoded.channel_params.len() as u32);
                    }
                }
                AssetKind::Synapse => {
                    if let Ok(decoded) = SynapseParamsSetPayload::decode(payload.as_slice()) {
                        summary.syn_param_count = Some(decoded.synapse_params.len() as u32);
                    }
                }
                AssetKind::Connectivity => {
                    if let Ok(decoded) = ConnectivityGraphPayload::decode(payload.as_slice()) {
                        summary.edge_count = Some(decoded.edges.len() as u32);
                        summary.has_pool_labels = decoded
                            .edges
                            .iter()
                            .any(|entry| !entry.pool_label.is_empty());
                        summary.has_role_labels = decoded
                            .edges
                            .iter()
                            .any(|entry| !entry.role_label.is_empty());
                    }
                }
                AssetKind::Unspecified => {}
            }
        }

        summaries.push(summary);
    }

    summaries
}

fn recovery_case_to_proto(case: InternalRecoveryCase) -> ProtoRecoveryCase {
    ProtoRecoveryCase {
        recovery_id: case.recovery_id,
        session_id: case.session_id,
        state: recovery_state_to_proto(case.state),
        required_checks: case
            .required_checks
            .into_iter()
            .map(recovery_check_to_proto)
            .collect(),
        completed_checks: case
            .completed_checks
            .into_iter()
            .map(recovery_check_to_proto)
            .collect(),
        trigger_refs: case.trigger_refs,
        created_at_ms: case.created_at_ms,
    }
}

fn recovery_state_to_proto(state: InternalRecoveryState) -> ProtoRecoveryState {
    match state {
        InternalRecoveryState::R0Captured => ProtoRecoveryState::R0Captured,
        InternalRecoveryState::R1Triaged => ProtoRecoveryState::R1Triaged,
        InternalRecoveryState::R2Validated => ProtoRecoveryState::R2Validated,
        InternalRecoveryState::R3Mitigated => ProtoRecoveryState::R3Mitigated,
        InternalRecoveryState::R4Remediated => ProtoRecoveryState::R4Remediated,
        InternalRecoveryState::R5Approved => ProtoRecoveryState::R5Approved,
        InternalRecoveryState::R6Unlocked => ProtoRecoveryState::R6Unlocked,
        InternalRecoveryState::R7Closed => ProtoRecoveryState::R7Closed,
    }
}

fn recovery_check_to_proto(check: InternalRecoveryCheck) -> ProtoRecoveryCheck {
    match check {
        InternalRecoveryCheck::IntegrityOk => ProtoRecoveryCheck::IntegrityOk,
        InternalRecoveryCheck::ValidationPassed => ProtoRecoveryCheck::ValidationPassed,
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

/// Return the latest microcircuit config for a module, if present.
pub fn get_microcircuit_config(
    store: &PvgsStore,
    module: MicroModule,
) -> Option<MicrocircuitConfigEvidence> {
    store.micro_config_store.latest_for_module(module).cloned()
}

/// Return the latest microcircuit config digest for a module, if present.
pub fn get_microcircuit_config_digest(store: &PvgsStore, module: MicroModule) -> Option<[u8; 32]> {
    get_microcircuit_config(store, module).and_then(|entry| digest_from_bytes(&entry.config_digest))
}

/// List current microcircuit configs in deterministic module order.
pub fn list_microcircuit_configs(store: &PvgsStore) -> Vec<MicrocircuitConfigEvidence> {
    store.micro_config_store.list_all()
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
pub fn list_ruleset_changes(store: &PvgsStore, session_id: Option<&str>) -> Vec<[u8; 32]> {
    store
        .sep_log
        .events
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

/// List all committed tool registry digests in deterministic order.
pub fn list_tool_registry_history(store: &PvgsStore) -> Vec<[u8; 32]> {
    store.tool_registry_state.history.clone()
}

/// Correlate tool registry digests to the ruleset digest they produced.
pub fn correlate_registry_to_ruleset(store: &PvgsStore) -> Vec<([u8; 32], [u8; 32])> {
    let mut pairs: Vec<_> = store
        .registry_ruleset_correlation
        .iter()
        .map(|(registry, ruleset)| (*registry, *ruleset))
        .collect();

    pairs.sort_by(|a, b| a.0.cmp(&b.0));

    pairs
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

pub fn get_pending_replay_plan_views(
    store: &PvgsStore,
    session_id: &str,
) -> Vec<PendingReplayPlanView> {
    get_pending_replay_plans(store, session_id)
        .into_iter()
        .map(|plan| PendingReplayPlanView {
            replay_id: plan.replay_id,
            asset_manifest_digest: plan.asset_manifest_ref.as_ref().and_then(digest_from_ref),
        })
        .collect()
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
const MAX_MICRO_EVIDENCE: usize = 32;

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

    let micro_evidence = collect_micro_evidence_from_records(store, &records);
    let plasticity_snapshots = collect_plasticity_snapshots_from_records(store, &records);
    let replay_run_digests = collect_replay_run_digests_from_records(store, &records);

    TraceResult {
        receipts: receipts.into_iter().collect(),
        decisions: decisions.into_iter().collect(),
        records: records.into_iter().collect(),
        profiles: profiles.into_iter().collect(),
        path,
        micro_snapshots_lc: micro_evidence.lc_snapshots.clone(),
        micro_snapshots_sn: micro_evidence.sn_snapshots.clone(),
        plasticity_snapshots,
        micro_configs_lc: micro_evidence.lc_configs.clone(),
        micro_configs_sn: micro_evidence.sn_configs.clone(),
        replay_run_digests,
        micro_evidence,
    }
}

/// Trace record references and related DLP decisions.
pub fn trace_record(store: &PvgsStore, record_digest: [u8; 32]) -> RecordTrace {
    let mut references = BTreeSet::new();
    let mut referenced_by = BTreeSet::new();
    let mut dlp_decisions = BTreeSet::new();
    let mut micro_evidence = MicroEvidenceSummary::default();
    let mut plasticity_snapshots = Vec::new();
    let mut replay_run_digests = Vec::new();

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
        micro_evidence = micro_evidence_from_record(record);
        plasticity_snapshots = plasticity_snapshots_from_record(record);
        replay_run_digests = replay_run_digests_from_record(record);
    }

    RecordTrace {
        references: references.into_iter().collect(),
        referenced_by: referenced_by.into_iter().collect(),
        dlp_decisions: dlp_decisions.into_iter().collect(),
        micro_evidence,
        plasticity_snapshots,
        replay_run_digests,
    }
}

/// List microcircuit evidence digests for a session in deterministic order.
pub fn list_microcircuit_evidence(store: &PvgsStore, session_id: &str) -> MicroEvidenceSummary {
    let mut record_digests: Vec<[u8; 32]> = store
        .sep_log
        .events
        .iter()
        .filter(|event| event.session_id == session_id)
        .filter(|event| matches!(event.event_type, SepEventType::EvAgentStep))
        .map(|event| event.object_digest)
        .collect();

    record_digests.sort();
    record_digests.dedup();

    let mut lc_snapshots = BTreeSet::new();
    let mut sn_snapshots = BTreeSet::new();
    let mut lc_configs = BTreeSet::new();
    let mut sn_configs = BTreeSet::new();

    for digest in record_digests {
        if let Some(record) = find_record(store, digest) {
            if let Some(gov) = &record.governance_frame {
                for reference in &gov.policy_decision_refs {
                    if let Some(micro_digest) = digest_from_labeled_ref(reference, "mc:lc") {
                        lc_snapshots.insert(micro_digest);
                    }
                    if let Some(micro_digest) = digest_from_labeled_ref(reference, "mc:sn") {
                        sn_snapshots.insert(micro_digest);
                    }
                    if let Some(micro_digest) = digest_from_labeled_ref(reference, "mc_cfg:lc") {
                        lc_configs.insert(micro_digest);
                    }
                    if let Some(micro_digest) = digest_from_labeled_ref(reference, "mc_cfg:sn") {
                        sn_configs.insert(micro_digest);
                    }
                }
            }
        }
    }

    micro_evidence_from_sets(lc_snapshots, sn_snapshots, lc_configs, sn_configs)
}

/// List plasticity evidence digests for a session in deterministic order.
pub fn list_plasticity_evidence(store: &PvgsStore, session_id: &str) -> Vec<[u8; 32]> {
    let mut record_digests: Vec<[u8; 32]> = store
        .sep_log
        .events
        .iter()
        .filter(|event| event.session_id == session_id)
        .filter(|event| matches!(event.event_type, SepEventType::EvAgentStep))
        .map(|event| event.object_digest)
        .collect();

    record_digests.sort();
    record_digests.dedup();

    let mut digests = BTreeSet::new();

    for digest in record_digests {
        if let Some(record) = find_record(store, digest) {
            let record_type =
                RecordType::try_from(record.record_type).unwrap_or(RecordType::Unspecified);
            if !matches!(record_type, RecordType::RtReplay | RecordType::RtActionExec) {
                continue;
            }
            if let Some(gov) = &record.governance_frame {
                for reference in &gov.policy_decision_refs {
                    if let Some(snapshot) = digest_from_labeled_ref(reference, "mc_snap:plasticity")
                    {
                        digests.insert(snapshot);
                    }
                }
            }
        }
    }

    let mut snapshots: Vec<[u8; 32]> = digests.into_iter().collect();
    snapshots.truncate(MAX_PLASTICITY_EVIDENCE);
    snapshots
}

/// List replay run digests for a session in deterministic order.
pub fn list_replay_run_digests(store: &PvgsStore, session_id: &str) -> Vec<[u8; 32]> {
    let mut record_digests: Vec<[u8; 32]> = store
        .sep_log
        .events
        .iter()
        .filter(|event| {
            event.session_id == session_id && matches!(event.event_type, SepEventType::EvAgentStep)
        })
        .map(|event| event.object_digest)
        .collect();

    record_digests.sort();
    record_digests.dedup();

    let mut digests = BTreeSet::new();

    for digest in record_digests {
        if let Some(record) = find_record(store, digest) {
            let record_type =
                RecordType::try_from(record.record_type).unwrap_or(RecordType::Unspecified);
            if !matches!(record_type, RecordType::RtReplay) {
                continue;
            }
            for replay_run_digest in replay_run_digests_from_record(record) {
                digests.insert(replay_run_digest);
            }
        }
    }

    let mut replay_runs: Vec<[u8; 32]> = digests.into_iter().collect();
    replay_runs.truncate(MAX_REPLAY_RUN_DIGESTS);
    replay_runs
}

/// Fetch a replay run evidence record by digest.
pub fn get_replay_run(store: &PvgsStore, run_digest: [u8; 32]) -> Option<ReplayRunEvidence> {
    store.replay_run_store.get(run_digest).cloned()
}

/// List replay run evidence entries in deterministic order.
pub fn list_replay_runs(store: &PvgsStore, limit: usize) -> Vec<ReplayRunEvidence> {
    let mut runs: Vec<ReplayRunEvidence> = store.replay_run_store.runs.clone();
    runs.sort_by(|a, b| {
        let digest_a = digest_from_bytes(&a.run_digest).unwrap_or([0u8; 32]);
        let digest_b = digest_from_bytes(&b.run_digest).unwrap_or([0u8; 32]);
        a.created_at_ms
            .cmp(&b.created_at_ms)
            .then_with(|| digest_a.cmp(&digest_b))
    });
    runs.truncate(limit);
    runs
}

/// List trace run evidence entries in deterministic order.
pub fn list_trace_runs(store: &PvgsStore, limit: usize) -> Vec<TraceRunEvidence> {
    let mut runs: Vec<TraceRunEvidence> = store.trace_run_store.runs.clone();
    runs.sort_by(|a, b| {
        let digest_a = digest_from_bytes(&a.trace_digest).unwrap_or([0u8; 32]);
        let digest_b = digest_from_bytes(&b.trace_digest).unwrap_or([0u8; 32]);
        a.created_at_ms
            .cmp(&b.created_at_ms)
            .then_with(|| digest_a.cmp(&digest_b))
    });
    runs.truncate(limit.min(MAX_TRACE_RUNS));
    runs
}

/// List proposal evidence entries in deterministic order.
pub fn list_proposals(store: &PvgsStore, limit: usize) -> Vec<ProposalEvidence> {
    let mut proposals: Vec<ProposalEvidence> =
        store.proposal_store.by_digest.values().cloned().collect();
    proposals.sort_by(|a, b| {
        let digest_a = digest_from_bytes(&a.proposal_digest).unwrap_or([0u8; 32]);
        let digest_b = digest_from_bytes(&b.proposal_digest).unwrap_or([0u8; 32]);
        a.created_at_ms
            .cmp(&b.created_at_ms)
            .then_with(|| digest_a.cmp(&digest_b))
    });
    proposals.truncate(limit);
    proposals
}

/// List proposal activation evidence entries in deterministic order.
pub fn list_proposal_activations(
    store: &PvgsStore,
    limit: usize,
) -> Vec<ProposalActivationEvidence> {
    let mut activations: Vec<ProposalActivationEvidence> = store
        .proposal_activation_store
        .by_digest
        .values()
        .cloned()
        .collect();
    activations.sort_by(|a, b| {
        let digest_a = digest_from_bytes(&a.activation_digest).unwrap_or([0u8; 32]);
        let digest_b = digest_from_bytes(&b.activation_digest).unwrap_or([0u8; 32]);
        a.created_at_ms
            .cmp(&b.created_at_ms)
            .then_with(|| digest_a.cmp(&digest_b))
    });
    activations.truncate(limit);
    activations
}

/// Fetch a proposal evidence record by digest.
pub fn get_proposal(store: &PvgsStore, digest: [u8; 32]) -> Option<ProposalEvidence> {
    store.proposal_store.get(digest).cloned()
}

/// Fetch the latest proposal activation evidence record in deterministic order.
pub fn latest_proposal_activation(store: &PvgsStore) -> Option<ProposalActivationEvidence> {
    store
        .proposal_activation_store
        .by_digest
        .values()
        .cloned()
        .max_by(|a, b| {
            let digest_a = digest_from_bytes(&a.activation_digest).unwrap_or([0u8; 32]);
            let digest_b = digest_from_bytes(&b.activation_digest).unwrap_or([0u8; 32]);
            a.created_at_ms
                .cmp(&b.created_at_ms)
                .then_with(|| digest_a.cmp(&digest_b))
        })
}

/// Fetch the latest activation for a proposal digest.
pub fn latest_activation_for_proposal(
    store: &PvgsStore,
    proposal_digest: [u8; 32],
) -> Option<ProposalActivationEvidence> {
    store
        .proposal_activation_store
        .by_digest
        .values()
        .filter(|activation| {
            digest_from_bytes(&activation.proposal_digest) == Some(proposal_digest)
        })
        .cloned()
        .max_by(|a, b| {
            let digest_a = digest_from_bytes(&a.activation_digest).unwrap_or([0u8; 32]);
            let digest_b = digest_from_bytes(&b.activation_digest).unwrap_or([0u8; 32]);
            a.created_at_ms
                .cmp(&b.created_at_ms)
                .then_with(|| digest_a.cmp(&digest_b))
        })
}

/// Fetch the latest proposal evidence record in deterministic order.
pub fn latest_proposal(store: &PvgsStore) -> Option<ProposalEvidence> {
    store
        .proposal_store
        .by_digest
        .values()
        .cloned()
        .max_by(|a, b| {
            let digest_a = digest_from_bytes(&a.proposal_digest).unwrap_or([0u8; 32]);
            let digest_b = digest_from_bytes(&b.proposal_digest).unwrap_or([0u8; 32]);
            a.created_at_ms
                .cmp(&b.created_at_ms)
                .then_with(|| digest_a.cmp(&digest_b))
        })
}

/// Count proposal verdicts within the last N proposals.
pub fn proposal_counts_last_n(store: &PvgsStore, n: usize) -> ProposalVerdictCounts {
    if n == 0 {
        return ProposalVerdictCounts::default();
    }
    let mut proposals = list_proposals(store, usize::MAX);
    if proposals.len() > n {
        proposals = proposals.split_off(proposals.len() - n);
    }
    let mut counts = ProposalVerdictCounts::default();
    for proposal in proposals {
        match proposal.verdict {
            1 => counts.promising = counts.promising.saturating_add(1),
            2 => counts.risky = counts.risky.saturating_add(1),
            _ => counts.neutral = counts.neutral.saturating_add(1),
        }
    }
    counts
}

/// Count activation statuses within the last N activations.
pub fn activation_counts_last_n(store: &PvgsStore, n: usize) -> ActivationStatusCounts {
    if n == 0 {
        return ActivationStatusCounts::default();
    }
    let mut activations = list_proposal_activations(store, usize::MAX);
    if activations.len() > n {
        activations = activations.split_off(activations.len() - n);
    }
    let mut counts = ActivationStatusCounts::default();
    for activation in activations {
        match ActivationStatus::try_from(activation.status).unwrap_or(ActivationStatus::Unspecified)
        {
            ActivationStatus::Applied => counts.applied = counts.applied.saturating_add(1),
            ActivationStatus::Rejected => counts.rejected = counts.rejected.saturating_add(1),
            ActivationStatus::Unspecified => {}
        }
    }
    counts
}

fn risky_activation_count_last_n(store: &PvgsStore, n: usize) -> u64 {
    if n == 0 {
        return 0;
    }
    let mut activations = list_proposal_activations(store, usize::MAX);
    if activations.len() > n {
        activations = activations.split_off(activations.len() - n);
    }
    let mut count = 0u64;
    for activation in activations {
        let status =
            ActivationStatus::try_from(activation.status).unwrap_or(ActivationStatus::Unspecified);
        if !matches!(status, ActivationStatus::Applied) {
            continue;
        }
        if let Some(proposal_digest) = digest_from_bytes(&activation.proposal_digest) {
            if let Some(proposal) = store.proposal_store.get(proposal_digest) {
                if proposal.verdict == 2 {
                    count = count.saturating_add(1);
                }
            }
        }
    }
    count
}

/// Return the latest trace run evidence by created time.
pub fn latest_trace_run(store: &PvgsStore) -> Option<TraceRunEvidence> {
    store
        .trace_run_store
        .runs
        .iter()
        .max_by(|a, b| {
            let digest_a = digest_from_bytes(&a.trace_digest).unwrap_or([0u8; 32]);
            let digest_b = digest_from_bytes(&b.trace_digest).unwrap_or([0u8; 32]);
            a.created_at_ms
                .cmp(&b.created_at_ms)
                .then_with(|| digest_a.cmp(&digest_b))
        })
        .cloned()
}

/// Summarize verdict counts for the last N trace runs.
pub fn trace_run_summary_counts(store: &PvgsStore, last_n: usize) -> TraceRunSummaryCounts {
    let mut counts = TraceRunSummaryCounts::default();
    let start = store.trace_run_store.runs.len().saturating_sub(last_n);
    for run in store.trace_run_store.runs.iter().skip(start) {
        match TraceVerdict::try_from(run.verdict).unwrap_or(TraceVerdict::Unspecified) {
            TraceVerdict::Promising => counts.promising = counts.promising.saturating_add(1),
            TraceVerdict::Neutral => counts.neutral = counts.neutral.saturating_add(1),
            TraceVerdict::Risky => counts.risky = counts.risky.saturating_add(1),
            TraceVerdict::Unspecified => {}
        }
    }
    counts
}

/// Fetch the latest trace run evidence for a configuration pair.
pub fn latest_trace_run_for_configs(
    store: &PvgsStore,
    active_cfg_digest: [u8; 32],
    shadow_cfg_digest: [u8; 32],
) -> Option<TraceRunEvidence> {
    store
        .trace_run_store
        .runs
        .iter()
        .filter(|run| {
            digest_from_bytes(&run.active_cfg_digest) == Some(active_cfg_digest)
                && digest_from_bytes(&run.shadow_cfg_digest) == Some(shadow_cfg_digest)
        })
        .max_by(|a, b| {
            let digest_a = digest_from_bytes(&a.trace_digest).unwrap_or([0u8; 32]);
            let digest_b = digest_from_bytes(&b.trace_digest).unwrap_or([0u8; 32]);
            a.created_at_ms
                .cmp(&b.created_at_ms)
                .then_with(|| digest_a.cmp(&digest_b))
        })
        .cloned()
}

/// Return the latest replay run digest by created time.
pub fn latest_replay_run_digest(store: &PvgsStore) -> Option<[u8; 32]> {
    store
        .replay_run_store
        .runs
        .iter()
        .filter_map(|run| digest_from_bytes(&run.run_digest).map(|digest| (digest, run)))
        .max_by(|(digest_a, run_a), (digest_b, run_b)| {
            run_a
                .created_at_ms
                .cmp(&run_b.created_at_ms)
                .then_with(|| digest_a.cmp(digest_b))
        })
        .map(|(digest, _)| digest)
}

pub fn replay_run_summary(store: &PvgsStore, run_digest: [u8; 32]) -> ReplayRunSummary {
    let Some(run) = store.replay_run_store.get(run_digest) else {
        return ReplayRunSummary {
            run_digest,
            replay_plan_digest: None,
            asset_manifest_digest: None,
            steps: 0,
            dt_us: 0,
            created_at_ms: 0,
            micro_config_digests: Vec::new(),
            summary_digests: Vec::new(),
        };
    };

    let replay_plan_digest = run.replay_plan_ref.as_ref().and_then(digest_from_ref);
    let asset_manifest_digest = run.asset_manifest_ref.as_ref().and_then(digest_from_ref);
    let mut micro_config_digests: Vec<[u8; 32]> = run
        .micro_config_refs
        .iter()
        .filter_map(digest_from_ref)
        .collect();
    micro_config_digests.sort();
    micro_config_digests.dedup();
    let mut summary_digests: Vec<[u8; 32]> = run
        .summary_digests
        .iter()
        .filter_map(|digest| digest_from_bytes(digest))
        .collect();
    summary_digests.sort();
    summary_digests.dedup();

    ReplayRunSummary {
        run_digest,
        replay_plan_digest,
        asset_manifest_digest,
        steps: run.steps,
        dt_us: run.dt_us,
        created_at_ms: run.created_at_ms,
        micro_config_digests,
        summary_digests,
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

#[cfg(test)]
mod recovery_views_tests {
    use super::*;
    use pvgs::UnlockPermit;
    use recovery::{RecoveryCheck, RecoveryState};
    use std::collections::HashSet;

    fn base_store() -> PvgsStore {
        PvgsStore::new(
            [0u8; 32],
            "charter".to_string(),
            "policy".to_string(),
            HashSet::new(),
            HashSet::new(),
            HashSet::new(),
        )
    }

    #[test]
    fn recovery_query_returns_latest_case() {
        let mut store = base_store();

        let case_old = InternalRecoveryCase {
            recovery_id: "recovery:a".into(),
            session_id: "session-1".into(),
            state: RecoveryState::R0Captured,
            required_checks: vec![RecoveryCheck::IntegrityOk, RecoveryCheck::ValidationPassed],
            completed_checks: Vec::new(),
            trigger_refs: vec!["trigger-a".into()],
            created_at_ms: Some(10),
        };

        let mut case_newer = case_old.clone();
        case_newer.recovery_id = "recovery:b".into();
        case_newer.created_at_ms = Some(20);

        store.recovery_store.insert_new(case_old).unwrap();
        store.recovery_store.insert_new(case_newer.clone()).unwrap();

        let result = get_recovery_case_for_session(&store, "session-1").unwrap();
        assert_eq!(result.recovery_id, case_newer.recovery_id);
        assert_eq!(result.state, ProtoRecoveryState::R0Captured);
    }

    #[test]
    fn unlock_permit_view_returns_digest() {
        let mut store = base_store();

        let permit = UnlockPermit::new("sess".into(), 1, [9u8; 32]);
        store.unlock_permits.insert("sess".into(), permit.clone());

        assert!(has_unlock_permit(&store, "sess"));
        assert_eq!(
            get_unlock_permit_digest(&store, "sess"),
            Some(permit.permit_digest)
        );
    }
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

fn micro_evidence_from_record(record: &ExperienceRecord) -> MicroEvidenceSummary {
    let mut lc_snapshots = BTreeSet::new();
    let mut sn_snapshots = BTreeSet::new();
    let mut lc_configs = BTreeSet::new();
    let mut sn_configs = BTreeSet::new();

    if let Some(gov) = &record.governance_frame {
        for reference in &gov.policy_decision_refs {
            if let Some(digest) = digest_from_labeled_ref(reference, "mc:lc") {
                lc_snapshots.insert(digest);
            }
            if let Some(digest) = digest_from_labeled_ref(reference, "mc:sn") {
                sn_snapshots.insert(digest);
            }
            if let Some(digest) = digest_from_labeled_ref(reference, "mc_cfg:lc") {
                lc_configs.insert(digest);
            }
            if let Some(digest) = digest_from_labeled_ref(reference, "mc_cfg:sn") {
                sn_configs.insert(digest);
            }
        }
    }

    micro_evidence_from_sets(lc_snapshots, sn_snapshots, lc_configs, sn_configs)
}

fn plasticity_snapshots_from_record(record: &ExperienceRecord) -> Vec<[u8; 32]> {
    let mut digests = BTreeSet::new();

    if let Some(gov) = &record.governance_frame {
        for reference in &gov.policy_decision_refs {
            if let Some(digest) = digest_from_labeled_ref(reference, "mc_snap:plasticity") {
                digests.insert(digest);
            }
        }
    }

    plasticity_snapshots_from_sets(digests)
}

fn replay_run_digest_from_ref(reference: &ucf_protocol::ucf::v1::Ref) -> Option<[u8; 32]> {
    if reference.id == "replay_run"
        || reference.id.starts_with("replay_run:")
        || reference.id == "replay_run_evidence"
        || reference.id.starts_with("replay_run_evidence:")
    {
        return digest_from_ref(reference);
    }

    None
}

fn replay_run_digests_from_record(record: &ExperienceRecord) -> Vec<[u8; 32]> {
    let mut digests = BTreeSet::new();

    if let Some(gov) = &record.governance_frame {
        for reference in &gov.policy_decision_refs {
            if let Some(digest) = replay_run_digest_from_ref(reference) {
                digests.insert(digest);
            }
        }
    }

    let mut replay_runs: Vec<[u8; 32]> = digests.into_iter().collect();
    replay_runs.truncate(MAX_REPLAY_RUN_DIGESTS);
    replay_runs
}

fn collect_micro_evidence_from_records(
    store: &PvgsStore,
    records: &BTreeSet<[u8; 32]>,
) -> MicroEvidenceSummary {
    let mut lc_snapshots = BTreeSet::new();
    let mut sn_snapshots = BTreeSet::new();
    let mut lc_configs = BTreeSet::new();
    let mut sn_configs = BTreeSet::new();

    for record_digest in records {
        if let Some(record) = find_record(store, *record_digest) {
            if let Some(gov) = &record.governance_frame {
                for reference in &gov.policy_decision_refs {
                    if let Some(digest) = digest_from_labeled_ref(reference, "mc:lc") {
                        lc_snapshots.insert(digest);
                    }
                    if let Some(digest) = digest_from_labeled_ref(reference, "mc:sn") {
                        sn_snapshots.insert(digest);
                    }
                    if let Some(digest) = digest_from_labeled_ref(reference, "mc_cfg:lc") {
                        lc_configs.insert(digest);
                    }
                    if let Some(digest) = digest_from_labeled_ref(reference, "mc_cfg:sn") {
                        sn_configs.insert(digest);
                    }
                }
            }
        }
    }

    micro_evidence_from_sets(lc_snapshots, sn_snapshots, lc_configs, sn_configs)
}

fn collect_plasticity_snapshots_from_records(
    store: &PvgsStore,
    records: &BTreeSet<[u8; 32]>,
) -> Vec<[u8; 32]> {
    let mut digests = BTreeSet::new();

    for record_digest in records {
        if let Some(record) = find_record(store, *record_digest) {
            if let Some(gov) = &record.governance_frame {
                for reference in &gov.policy_decision_refs {
                    if let Some(digest) = digest_from_labeled_ref(reference, "mc_snap:plasticity") {
                        digests.insert(digest);
                    }
                }
            }
        }
    }

    plasticity_snapshots_from_sets(digests)
}

fn collect_replay_run_digests_from_records(
    store: &PvgsStore,
    records: &BTreeSet<[u8; 32]>,
) -> Vec<[u8; 32]> {
    let mut digests = BTreeSet::new();

    for record_digest in records {
        if let Some(record) = find_record(store, *record_digest) {
            for digest in replay_run_digests_from_record(record) {
                digests.insert(digest);
            }
        }
    }

    let mut replay_runs: Vec<[u8; 32]> = digests.into_iter().collect();
    replay_runs.truncate(MAX_REPLAY_RUN_DIGESTS);
    replay_runs
}

fn micro_evidence_from_sets(
    lc_snapshots: BTreeSet<[u8; 32]>,
    sn_snapshots: BTreeSet<[u8; 32]>,
    lc_configs: BTreeSet<[u8; 32]>,
    sn_configs: BTreeSet<[u8; 32]>,
) -> MicroEvidenceSummary {
    let mut lc_snapshots: Vec<[u8; 32]> = lc_snapshots.into_iter().collect();
    let mut sn_snapshots: Vec<[u8; 32]> = sn_snapshots.into_iter().collect();
    let mut lc_configs: Vec<[u8; 32]> = lc_configs.into_iter().collect();
    let mut sn_configs: Vec<[u8; 32]> = sn_configs.into_iter().collect();

    lc_snapshots.truncate(MAX_MICRO_EVIDENCE);
    sn_snapshots.truncate(MAX_MICRO_EVIDENCE);
    lc_configs.truncate(MAX_MICRO_EVIDENCE);
    sn_configs.truncate(MAX_MICRO_EVIDENCE);

    MicroEvidenceSummary {
        lc_snapshots,
        sn_snapshots,
        lc_configs,
        sn_configs,
    }
}

fn plasticity_snapshots_from_sets(digests: BTreeSet<[u8; 32]>) -> Vec<[u8; 32]> {
    let mut snapshots: Vec<[u8; 32]> = digests.into_iter().collect();
    snapshots.truncate(MAX_PLASTICITY_EVIDENCE);
    snapshots
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

fn micro_module_from_config_ref(reference: &ucf_protocol::ucf::v1::Ref) -> Option<MicroModule> {
    digest_from_ref(reference)?;

    if reference.id == "mc_cfg:lc" || reference.id.starts_with("mc_cfg:lc:") {
        return Some(MicroModule::Lc);
    }
    if reference.id == "mc_cfg:sn" || reference.id.starts_with("mc_cfg:sn:") {
        return Some(MicroModule::Sn);
    }
    if reference.id == "mc_cfg:hpa" || reference.id.starts_with("mc_cfg:hpa:") {
        return Some(MicroModule::Hpa);
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
    reference
        .digest
        .as_ref()
        .and_then(|digest| digest_from_bytes(digest))
        .or_else(|| {
            if reference.id.len() == 64 {
                let bytes = hex::decode(&reference.id).ok()?;
                return digest_from_bytes(&bytes);
            }

            digest_from_bytes(reference.id.as_bytes())
        })
}

fn digest_from_bytes(bytes: &[u8]) -> Option<[u8; 32]> {
    if bytes.len() != 32 {
        return None;
    }

    let mut digest = [0u8; 32];
    digest.copy_from_slice(bytes);
    Some(digest)
}

fn is_newer_tool_event(
    current: &ToolOnboardingEvent,
    current_idx: usize,
    prev: &ToolOnboardingEvent,
    prev_idx: usize,
) -> bool {
    match (current.created_at_ms, prev.created_at_ms) {
        (Some(a), Some(b)) => a > b || (a == b && current_idx > prev_idx),
        (Some(_), None) => true,
        (None, Some(_)) => false,
        (None, None) => current_idx > prev_idx,
    }
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
    use assets::{
        compute_asset_bundle_digest, compute_asset_chunk_digest, compute_asset_manifest_digest,
    };
    use keys::KeyStore;
    use micro_evidence::compute_config_digest;
    use pev::PolicyEcologyDimension;
    use prost::Message;
    use pvgs::{
        compute_ruleset_digest, verify_and_commit, CommitBindings, CommitType, RequiredCheck,
        RequiredReceiptKind,
    };
    use replay_plan::{build_replay_plan, BuildReplayPlanArgs};
    use sep::{EdgeType, FrameEventKind, SepLog};
    use std::collections::HashSet;
    use trace_runs::{compute_trace_run_digest, TraceRunEvidence, TraceVerdict};
    use ucf_protocol::ucf::v1::{
        AssetBundle, AssetChunk, AssetDigest, AssetKind, AssetManifest, CompressionMode,
        ConnectivityEdge, ConnectivityGraphPayload, ConsistencyFeedback, Digest32, DlpDecision,
        GovernanceFrame, MacroMilestone, MacroMilestoneState, MagnitudeClass, MetabolicFrame,
        MicroModule, MicrocircuitConfigEvidence, MorphologyEntry, MorphologySetPayload,
        ReceiptStatus, RecordType, Ref, ReplayFidelity, ReplayRunEvidence, ReplayTargetKind,
        TraitDirection, TraitUpdate,
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

    fn trace_run_evidence(
        run_digest: [u8; 32],
        created_at_ms: u64,
        verdict: TraceVerdict,
    ) -> TraceRunEvidence {
        let mut evidence = TraceRunEvidence {
            trace_id: "trace-1".to_string(),
            trace_digest: run_digest.to_vec(),
            active_cfg_digest: [2u8; 32].to_vec(),
            shadow_cfg_digest: [3u8; 32].to_vec(),
            active_feedback_digest: [4u8; 32].to_vec(),
            shadow_feedback_digest: [5u8; 32].to_vec(),
            score_active: 10,
            score_shadow: 12,
            delta: 2,
            verdict: verdict as i32,
            created_at_ms,
            reason_codes: vec!["RC.GV.OK".to_string()],
        };
        let digest = compute_trace_run_digest(&evidence).expect("digest");
        evidence.trace_digest = digest.to_vec();
        evidence
    }

    fn asset_bundle_payload(
        created_at_ms: u64,
        asset_seed: u8,
    ) -> (AssetBundle, [u8; 32], [u8; 32]) {
        let asset_digest = [asset_seed; 32];
        let mut manifest = AssetManifest {
            manifest_digest: Vec::new(),
            created_at_ms,
            asset_digests: vec![AssetDigest {
                kind: AssetKind::Morphology as i32,
                digest: asset_digest.to_vec(),
                version: 1,
            }],
        };
        let manifest_digest = compute_asset_manifest_digest(&manifest);
        manifest.manifest_digest = manifest_digest.to_vec();

        let chunk_payload_one = b"bundle-one".to_vec();
        let chunk_payload_two = b"bundle-two".to_vec();
        let chunk_one = AssetChunk {
            asset_digest: asset_digest.to_vec(),
            chunk_index: 0,
            chunk_count: 2,
            payload: chunk_payload_one.clone(),
            chunk_digest: compute_asset_chunk_digest(&chunk_payload_one).to_vec(),
            compression_mode: CompressionMode::None as i32,
        };
        let chunk_two = AssetChunk {
            asset_digest: asset_digest.to_vec(),
            chunk_index: 1,
            chunk_count: 2,
            payload: chunk_payload_two.clone(),
            chunk_digest: compute_asset_chunk_digest(&chunk_payload_two).to_vec(),
            compression_mode: CompressionMode::Zstd as i32,
        };

        let mut bundle = AssetBundle {
            bundle_digest: Vec::new(),
            created_at_ms,
            manifest: Some(manifest),
            chunks: vec![chunk_one, chunk_two],
        };
        let bundle_digest =
            compute_asset_bundle_digest(bundle.manifest.as_ref().unwrap(), &bundle.chunks)
                .expect("bundle digest computed");
        bundle.bundle_digest = bundle_digest.to_vec();

        (bundle, bundle_digest, asset_digest)
    }

    fn asset_bundle_payload_with_assets(
        created_at_ms: u64,
        asset_seed: u8,
        morph_payload: Vec<u8>,
        connectivity_payload: Vec<u8>,
    ) -> (AssetBundle, [u8; 32], [u8; 32], [u8; 32]) {
        let morph_digest = [asset_seed; 32];
        let connectivity_digest = [asset_seed.wrapping_add(1); 32];
        let mut manifest = AssetManifest {
            manifest_digest: Vec::new(),
            created_at_ms,
            asset_digests: vec![
                AssetDigest {
                    kind: AssetKind::Morphology as i32,
                    digest: morph_digest.to_vec(),
                    version: 1,
                },
                AssetDigest {
                    kind: AssetKind::Connectivity as i32,
                    digest: connectivity_digest.to_vec(),
                    version: 2,
                },
            ],
        };
        let manifest_digest = compute_asset_manifest_digest(&manifest);
        manifest.manifest_digest = manifest_digest.to_vec();

        let chunks = vec![
            AssetChunk {
                asset_digest: morph_digest.to_vec(),
                chunk_index: 0,
                chunk_count: 1,
                payload: morph_payload.clone(),
                chunk_digest: compute_asset_chunk_digest(&morph_payload).to_vec(),
                compression_mode: CompressionMode::None as i32,
            },
            AssetChunk {
                asset_digest: connectivity_digest.to_vec(),
                chunk_index: 0,
                chunk_count: 1,
                payload: connectivity_payload.clone(),
                chunk_digest: compute_asset_chunk_digest(&connectivity_payload).to_vec(),
                compression_mode: CompressionMode::None as i32,
            },
        ];

        let mut bundle = AssetBundle {
            bundle_digest: Vec::new(),
            created_at_ms,
            manifest: Some(manifest),
            chunks,
        };
        let bundle_digest =
            compute_asset_bundle_digest(bundle.manifest.as_ref().unwrap(), &bundle.chunks)
                .expect("bundle digest computed");
        bundle.bundle_digest = bundle_digest.to_vec();

        (bundle, bundle_digest, morph_digest, connectivity_digest)
    }

    fn asset_bundle_request(store: &PvgsStore, bundle: &AssetBundle) -> PvgsCommitRequest {
        PvgsCommitRequest {
            commit_id: "asset-bundle-commit".to_string(),
            commit_type: CommitType::AssetBundleAppend,
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
            epoch_id: 1,
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
            asset_bundle_payload: Some(bundle.encode_to_vec()),
        }
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

    #[test]
    fn microcircuit_config_queries_return_latest() {
        let mut store = minimal_store();
        let lc_digest = compute_config_digest("LC", 1, b"lc-config");
        let sn_digest = compute_config_digest("SN", 2, b"sn-config");
        let hpa_digest = compute_config_digest("HPA", 3, b"hpa-config");

        store
            .micro_config_store
            .insert(MicrocircuitConfigEvidence {
                module: MicroModule::Lc as i32,
                config_version: 1,
                config_digest: lc_digest.to_vec(),
                created_at_ms: 10,
                attested_by_key_id: None,
                signature: None,
            })
            .expect("insert lc");
        store
            .micro_config_store
            .insert(MicrocircuitConfigEvidence {
                module: MicroModule::Sn as i32,
                config_version: 2,
                config_digest: sn_digest.to_vec(),
                created_at_ms: 20,
                attested_by_key_id: None,
                signature: None,
            })
            .expect("insert sn");
        store
            .micro_config_store
            .insert(MicrocircuitConfigEvidence {
                module: MicroModule::Hpa as i32,
                config_version: 3,
                config_digest: hpa_digest.to_vec(),
                created_at_ms: 30,
                attested_by_key_id: None,
                signature: None,
            })
            .expect("insert hpa");

        assert_eq!(
            get_microcircuit_config_digest(&store, MicroModule::Lc),
            Some(lc_digest)
        );
        assert_eq!(
            get_microcircuit_config_digest(&store, MicroModule::Sn),
            Some(sn_digest)
        );
        assert_eq!(
            get_microcircuit_config_digest(&store, MicroModule::Hpa),
            Some(hpa_digest)
        );

        let configs = list_microcircuit_configs(&store);
        assert_eq!(
            configs,
            vec![
                MicrocircuitConfigEvidence {
                    module: MicroModule::Lc as i32,
                    config_version: 1,
                    config_digest: lc_digest.to_vec(),
                    created_at_ms: 10,
                    attested_by_key_id: None,
                    signature: None,
                },
                MicrocircuitConfigEvidence {
                    module: MicroModule::Sn as i32,
                    config_version: 2,
                    config_digest: sn_digest.to_vec(),
                    created_at_ms: 20,
                    attested_by_key_id: None,
                    signature: None,
                },
                MicrocircuitConfigEvidence {
                    module: MicroModule::Hpa as i32,
                    config_version: 3,
                    config_digest: hpa_digest.to_vec(),
                    created_at_ms: 30,
                    attested_by_key_id: None,
                    signature: None,
                },
            ]
        );
    }

    #[test]
    fn microcircuit_config_commit_queries_return_config() {
        let mut store = minimal_store();
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);
        let config_bytes = br#"{\"enabled\":true}"#;
        let digest = compute_config_digest("LC", 1, config_bytes);
        let evidence = MicrocircuitConfigEvidence {
            module: MicroModule::Lc as i32,
            config_version: 1,
            config_digest: digest.to_vec(),
            created_at_ms: 42,
            attested_by_key_id: None,
            signature: None,
        };

        let req = PvgsCommitRequest {
            commit_id: "micro-config-commit".to_string(),
            commit_type: CommitType::MicrocircuitConfigAppend,
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
            microcircuit_config_payload: Some(evidence.encode_to_vec()),
            asset_manifest_payload: None,
            asset_bundle_payload: None,
        };

        let (receipt, _) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);
        assert_eq!(receipt.status, ReceiptStatus::Accepted);

        let stored = get_microcircuit_config(&store, MicroModule::Lc);
        assert_eq!(stored, Some(evidence));
    }

    #[test]
    fn microcircuit_config_commit_queries_return_hpa() {
        let mut store = minimal_store();
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);
        let config_bytes = br#"{\"enabled\":true}"#;
        let digest = compute_config_digest("HPA", 2, config_bytes);
        let evidence = MicrocircuitConfigEvidence {
            module: MicroModule::Hpa as i32,
            config_version: 2,
            config_digest: digest.to_vec(),
            created_at_ms: 42,
            attested_by_key_id: None,
            signature: None,
        };

        let req = PvgsCommitRequest {
            commit_id: "micro-config-commit".to_string(),
            commit_type: CommitType::MicrocircuitConfigAppend,
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
            microcircuit_config_payload: Some(evidence.encode_to_vec()),
            asset_manifest_payload: None,
            asset_bundle_payload: None,
        };

        let (receipt, _) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);
        assert_eq!(receipt.status, ReceiptStatus::Accepted);

        let stored = get_microcircuit_config(&store, MicroModule::Hpa);
        assert_eq!(stored, Some(evidence));
    }

    #[test]
    fn asset_manifest_commit_queries_return_latest() {
        let mut store = minimal_store();
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);
        let mut manifest = AssetManifest {
            manifest_digest: Vec::new(),
            created_at_ms: 42,
            asset_digests: vec![
                AssetDigest {
                    kind: AssetKind::Morphology as i32,
                    digest: [10u8; 32].to_vec(),
                    version: 1,
                },
                AssetDigest {
                    kind: AssetKind::Channel as i32,
                    digest: [11u8; 32].to_vec(),
                    version: 1,
                },
            ],
        };
        let manifest_digest = compute_asset_manifest_digest(&manifest);
        manifest.manifest_digest = manifest_digest.to_vec();

        let req = PvgsCommitRequest {
            commit_id: "asset-manifest-commit".to_string(),
            commit_type: CommitType::AssetManifestAppend,
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
            asset_manifest_payload: Some(manifest.encode_to_vec()),
            asset_bundle_payload: None,
        };

        let (receipt, proof_receipt) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);
        assert_eq!(receipt.status, ReceiptStatus::Accepted);
        assert!(proof_receipt.is_some());

        let latest = get_latest_asset_manifest(&store).expect("latest manifest");
        assert_eq!(latest.manifest_digest, manifest_digest.to_vec());
    }

    #[test]
    fn asset_bundle_commit_updates_scorecard_and_queries() {
        let mut store = minimal_store();
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);
        let (bundle, digest, asset_digest) = asset_bundle_payload(55, 9);

        let req = asset_bundle_request(&store, &bundle);
        let (receipt, proof_receipt) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);
        assert_eq!(receipt.status, ReceiptStatus::Accepted);
        assert!(proof_receipt.is_some());

        let latest = get_latest_asset_bundle(&store).expect("latest bundle");
        assert_eq!(latest.bundle_digest, digest.to_vec());
        assert_eq!(
            get_asset_bundle(&store, digest).unwrap().bundle_digest,
            digest.to_vec()
        );

        let chunks = get_asset_chunks(&store, asset_digest);
        assert_eq!(chunks.len(), 2);
        assert!(chunks[0].chunk_index < chunks[1].chunk_index);

        let card = snapshot(&store, None).assets_card;
        assert_eq!(card.latest_bundle_digest, Some(digest));
        assert_eq!(card.total_asset_chunks, 2);
        assert_eq!(card.compression_none_count, 1);
        assert_eq!(card.compression_zstd_count, 1);
        assert_eq!(card.asset_payload_summaries.len(), 1);
        let summary = &card.asset_payload_summaries[0];
        assert_eq!(summary.kind, AssetKind::Morphology);
        assert_eq!(summary.version, 1);
        assert_eq!(summary.digest, asset_digest);
        assert_eq!(summary.bytes_len, 20);
        assert_eq!(summary.neuron_count, None);
        assert_eq!(summary.edge_count, None);
        assert_eq!(summary.syn_param_count, None);
        assert_eq!(summary.channel_param_count, None);
        assert!(!summary.has_pool_labels);
        assert!(!summary.has_role_labels);

        let mut tampered = bundle.clone();
        tampered.chunks[0].payload = b"tampered".to_vec();
        let bad_req = asset_bundle_request(&store, &tampered);
        let (bad_receipt, _) = verify_and_commit(bad_req, &mut store, &keystore, &vrf_engine);
        assert_eq!(bad_receipt.status, ReceiptStatus::Rejected);

        let card = snapshot(&store, None).assets_card;
        assert_eq!(card.asset_digest_mismatch_count, 1);
    }

    #[test]
    fn asset_payload_summaries_include_counts_and_labels() {
        let mut store = minimal_store();
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);
        let morph_payload = MorphologySetPayload {
            morphologies: vec![
                MorphologyEntry {
                    neuron_id: 1,
                    pool_label: "pool-a".to_string(),
                    role_label: "".to_string(),
                    payload: vec![1u8],
                },
                MorphologyEntry {
                    neuron_id: 2,
                    pool_label: "".to_string(),
                    role_label: "role-b".to_string(),
                    payload: vec![2u8],
                },
            ],
        }
        .encode_to_vec();
        let connectivity_payload = ConnectivityGraphPayload {
            edges: vec![ConnectivityEdge {
                source_id: 1,
                target_id: 2,
                pool_label: "pool-c".to_string(),
                role_label: "role-c".to_string(),
            }],
        }
        .encode_to_vec();

        let (bundle, _digest, morph_digest, connectivity_digest) = asset_bundle_payload_with_assets(
            55,
            9,
            morph_payload.clone(),
            connectivity_payload.clone(),
        );

        let req = asset_bundle_request(&store, &bundle);
        let (receipt, proof_receipt) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);
        assert_eq!(receipt.status, ReceiptStatus::Accepted);
        assert!(proof_receipt.is_some());

        let card = snapshot(&store, None).assets_card;
        assert_eq!(card.asset_payload_summaries.len(), 2);
        assert_eq!(card.asset_payload_summaries[0].kind, AssetKind::Morphology);
        assert_eq!(card.asset_payload_summaries[0].digest, morph_digest);
        assert_eq!(
            card.asset_payload_summaries[0].bytes_len,
            morph_payload.len() as u32
        );
        assert_eq!(card.asset_payload_summaries[0].neuron_count, Some(2));
        assert!(card.asset_payload_summaries[0].has_pool_labels);
        assert!(card.asset_payload_summaries[0].has_role_labels);

        assert_eq!(
            card.asset_payload_summaries[1].kind,
            AssetKind::Connectivity
        );
        assert_eq!(card.asset_payload_summaries[1].digest, connectivity_digest);
        assert_eq!(
            card.asset_payload_summaries[1].bytes_len,
            connectivity_payload.len() as u32
        );
        assert_eq!(card.asset_payload_summaries[1].edge_count, Some(1));
        assert!(card.asset_payload_summaries[1].has_pool_labels);
        assert!(card.asset_payload_summaries[1].has_role_labels);
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

    fn micro_ref(prefix: &str, digest: [u8; 32]) -> Ref {
        Ref {
            id: format!("{prefix}:{}", hex::encode(digest)),
            digest: None,
        }
    }

    fn replay_run_ref(digest: [u8; 32]) -> Ref {
        Ref {
            id: "replay_run".to_string(),
            digest: Some(digest.to_vec()),
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
                digest: None,
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

        let mut store = minimal_store();
        store.sep_log = log.clone();

        let all_changes = list_ruleset_changes(&store, None);
        assert_eq!(all_changes, vec![digest_one, digest_two]);

        let filtered = list_ruleset_changes(&store, Some("session-b"));
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
        let (consistency_digest, evicted) = store
            .consistency_store
            .insert(feedback)
            .expect("feedback stored");
        assert!(evicted.is_empty());

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
            .add_edge(action, EdgeType::Authorizes, receipt, None);
        store
            .causal_graph
            .add_edge(decision, EdgeType::Authorizes, receipt, None);
        store
            .causal_graph
            .add_edge(profile, EdgeType::References, receipt, None);
        store
            .causal_graph
            .add_edge(record, EdgeType::References, receipt, None);
        store
            .causal_graph
            .add_edge(record, EdgeType::References, action, None);

        let result = trace_action(&store, action);
        assert_eq!(result.receipts, vec![receipt]);
        assert_eq!(result.decisions, vec![decision]);
        assert_eq!(result.records, vec![record]);
        assert_eq!(result.profiles, vec![profile]);
        assert_eq!(
            result.path,
            vec![action, receipt, decision, record, profile]
        );
        assert_eq!(result.micro_evidence, MicroEvidenceSummary::default());
        assert!(result.plasticity_snapshots.is_empty());
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
            .add_edge(action, EdgeType::Authorizes, receipt, None);
        store_one
            .causal_graph
            .add_edge(decision_b, EdgeType::Authorizes, receipt, None);
        store_one
            .causal_graph
            .add_edge(decision_a, EdgeType::Authorizes, receipt, None);
        store_one
            .causal_graph
            .add_edge(record, EdgeType::References, receipt, None);
        store_one
            .causal_graph
            .add_edge(profile, EdgeType::References, receipt, None);

        let mut store_two = trace_store(profile);
        store_two
            .experience_store
            .proof_receipts
            .insert(record, dummy_proof_receipt(record));
        store_two
            .causal_graph
            .add_edge(decision_a, EdgeType::Authorizes, receipt, None);
        store_two
            .causal_graph
            .add_edge(action, EdgeType::Authorizes, receipt, None);
        store_two
            .causal_graph
            .add_edge(profile, EdgeType::References, receipt, None);
        store_two
            .causal_graph
            .add_edge(record, EdgeType::References, receipt, None);
        store_two
            .causal_graph
            .add_edge(decision_b, EdgeType::Authorizes, receipt, None);

        let result_one = trace_action(&store_one, action);
        let result_two = trace_action(&store_two, action);

        assert_eq!(result_one.receipts, result_two.receipts);
        assert_eq!(result_one.decisions, result_two.decisions);
        assert_eq!(result_one.records, result_two.records);
        assert_eq!(result_one.profiles, result_two.profiles);
        assert_eq!(result_one.path, result_two.path);
        assert_eq!(result_one.micro_evidence, result_two.micro_evidence);
        assert_eq!(
            result_one.plasticity_snapshots,
            result_two.plasticity_snapshots
        );
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
                digest: None,
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
                digest: None,
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
        };

        let (receipt, _) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);
        assert_eq!(receipt.status, ReceiptStatus::Accepted);

        let record_digest = store.experience_store.head_record_digest;
        let trace = trace_record(&store, record_digest);

        assert_eq!(trace.dlp_decisions, vec![dlp_digest]);
        assert_eq!(trace.micro_evidence, MicroEvidenceSummary::default());
        assert!(trace.plasticity_snapshots.is_empty());
    }

    #[test]
    fn trace_record_includes_micro_evidence() {
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

        let lc_digest = [1u8; 32];
        let sn_digest = [2u8; 32];
        let lc_config_digest = [3u8; 32];
        let sn_config_digest = [4u8; 32];
        let refs = vec![
            micro_ref("mc:lc", lc_digest),
            micro_ref("mc:sn", sn_digest),
            micro_ref("mc_cfg:lc", lc_config_digest),
            micro_ref("mc_cfg:sn", sn_config_digest),
        ];

        let record_digest =
            append_decision_record_with_refs(&mut store, &keystore, &vrf_engine, "session", refs);

        let references: Vec<_> = store
            .causal_graph
            .neighbors(record_digest)
            .iter()
            .filter(|(edge, _)| matches!(edge, EdgeType::References))
            .map(|(_, digest)| *digest)
            .collect();

        assert!(references.contains(&lc_digest));
        assert!(references.contains(&sn_digest));
        assert!(references.contains(&lc_config_digest));
        assert!(references.contains(&sn_config_digest));

        let trace = trace_record(&store, record_digest);
        assert_eq!(trace.micro_evidence.lc_snapshots, vec![lc_digest]);
        assert_eq!(trace.micro_evidence.sn_snapshots, vec![sn_digest]);
        assert_eq!(trace.micro_evidence.lc_configs, vec![lc_config_digest]);
        assert_eq!(trace.micro_evidence.sn_configs, vec![sn_config_digest]);
        assert!(trace.plasticity_snapshots.is_empty());
    }

    #[test]
    fn trace_record_includes_plasticity_snapshot() {
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

        let plasticity_digest = [5u8; 32];
        let refs = vec![micro_ref("mc_snap:plasticity", plasticity_digest)];

        let record_digest =
            append_decision_record_with_refs(&mut store, &keystore, &vrf_engine, "session", refs);

        let trace = trace_record(&store, record_digest);
        assert_eq!(trace.plasticity_snapshots, vec![plasticity_digest]);
    }

    #[test]
    fn trace_record_includes_replay_run_digest() {
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

        let replay_run_digest = [6u8; 32];
        let record_digest = append_record_with_refs_and_type(
            &mut store,
            &keystore,
            &vrf_engine,
            "session-replay-run",
            RecordType::RtReplay,
            vec![replay_run_ref(replay_run_digest)],
        );

        let trace = trace_record(&store, record_digest);
        assert_eq!(trace.replay_run_digests, vec![replay_run_digest]);
    }

    #[test]
    fn trace_action_collects_micro_evidence() {
        let action = [11u8; 32];
        let receipt = [12u8; 32];
        let profile = [13u8; 32];
        let lc_first = [1u8; 32];
        let lc_second = [3u8; 32];
        let sn_first = [2u8; 32];
        let sn_second = [4u8; 32];
        let lc_config_first = [5u8; 32];
        let lc_config_second = [7u8; 32];
        let sn_config_first = [6u8; 32];
        let sn_config_second = [8u8; 32];

        let mut store = trace_store(profile);

        let record_one = ExperienceRecord {
            record_type: RecordType::RtActionExec as i32,
            core_frame: None,
            metabolic_frame: None,
            governance_frame: Some(GovernanceFrame {
                policy_decision_refs: vec![
                    micro_ref("mc:lc", lc_first),
                    micro_ref("mc:sn", sn_first),
                    micro_ref("mc_cfg:lc", lc_config_first),
                    micro_ref("mc_cfg:sn", sn_config_first),
                ],
                pvgs_receipt_ref: None,
                dlp_refs: Vec::new(),
            }),
            core_frame_ref: None,
            metabolic_frame_ref: None,
            governance_frame_ref: Some(Ref {
                id: hex::encode([8u8; 32]),
                digest: None,
            }),
            dlp_refs: Vec::new(),
            finalization_header: None,
        };

        let record_two = ExperienceRecord {
            record_type: RecordType::RtActionExec as i32,
            core_frame: None,
            metabolic_frame: None,
            governance_frame: Some(GovernanceFrame {
                policy_decision_refs: vec![
                    micro_ref("mc:lc", lc_second),
                    micro_ref("mc:sn", sn_second),
                    micro_ref("mc_cfg:lc", lc_config_second),
                    micro_ref("mc_cfg:sn", sn_config_second),
                ],
                pvgs_receipt_ref: None,
                dlp_refs: Vec::new(),
            }),
            core_frame_ref: None,
            metabolic_frame_ref: None,
            governance_frame_ref: Some(Ref {
                id: hex::encode([9u8; 32]),
                digest: None,
            }),
            dlp_refs: Vec::new(),
            finalization_header: None,
        };

        let record_one_digest = compute_experience_record_digest(&record_one);
        let record_two_digest = compute_experience_record_digest(&record_two);

        store.experience_store.records.push(record_one);
        store.experience_store.records.push(record_two);
        store
            .experience_store
            .proof_receipts
            .insert(record_one_digest, dummy_proof_receipt(record_one_digest));
        store
            .experience_store
            .proof_receipts
            .insert(record_two_digest, dummy_proof_receipt(record_two_digest));

        store
            .causal_graph
            .add_edge(action, EdgeType::Authorizes, receipt, None);
        store
            .causal_graph
            .add_edge(record_one_digest, EdgeType::References, action, None);
        store
            .causal_graph
            .add_edge(record_two_digest, EdgeType::References, action, None);

        let trace = trace_action(&store, action);
        assert_eq!(trace.micro_evidence.lc_snapshots, vec![lc_first, lc_second]);
        assert_eq!(trace.micro_evidence.sn_snapshots, vec![sn_first, sn_second]);
        assert_eq!(
            trace.micro_evidence.lc_configs,
            vec![lc_config_first, lc_config_second]
        );
        assert_eq!(
            trace.micro_evidence.sn_configs,
            vec![sn_config_first, sn_config_second]
        );
        assert!(trace.plasticity_snapshots.is_empty());
    }

    #[test]
    fn trace_action_collects_plasticity_snapshots() {
        let action = [21u8; 32];
        let receipt = [22u8; 32];
        let profile = [23u8; 32];
        let plasticity_first = [3u8; 32];
        let plasticity_second = [2u8; 32];

        let mut store = trace_store(profile);

        let record_one = ExperienceRecord {
            record_type: RecordType::RtActionExec as i32,
            core_frame: None,
            metabolic_frame: None,
            governance_frame: Some(GovernanceFrame {
                policy_decision_refs: vec![micro_ref("mc_snap:plasticity", plasticity_first)],
                pvgs_receipt_ref: None,
                dlp_refs: Vec::new(),
            }),
            core_frame_ref: None,
            metabolic_frame_ref: None,
            governance_frame_ref: Some(Ref {
                id: hex::encode([11u8; 32]),
                digest: None,
            }),
            dlp_refs: Vec::new(),
            finalization_header: None,
        };

        let record_two = ExperienceRecord {
            record_type: RecordType::RtActionExec as i32,
            core_frame: None,
            metabolic_frame: None,
            governance_frame: Some(GovernanceFrame {
                policy_decision_refs: vec![micro_ref("mc_snap:plasticity", plasticity_second)],
                pvgs_receipt_ref: None,
                dlp_refs: Vec::new(),
            }),
            core_frame_ref: None,
            metabolic_frame_ref: None,
            governance_frame_ref: Some(Ref {
                id: hex::encode([12u8; 32]),
                digest: None,
            }),
            dlp_refs: Vec::new(),
            finalization_header: None,
        };

        let record_one_digest = compute_experience_record_digest(&record_one);
        let record_two_digest = compute_experience_record_digest(&record_two);

        store.experience_store.records.push(record_one);
        store.experience_store.records.push(record_two);
        store
            .experience_store
            .proof_receipts
            .insert(record_one_digest, dummy_proof_receipt(record_one_digest));
        store
            .experience_store
            .proof_receipts
            .insert(record_two_digest, dummy_proof_receipt(record_two_digest));

        store
            .causal_graph
            .add_edge(action, EdgeType::Authorizes, receipt, None);
        store
            .causal_graph
            .add_edge(record_one_digest, EdgeType::References, action, None);
        store
            .causal_graph
            .add_edge(record_two_digest, EdgeType::References, action, None);

        let trace = trace_action(&store, action);
        assert_eq!(
            trace.plasticity_snapshots,
            vec![plasticity_second, plasticity_first]
        );
    }

    #[test]
    fn list_microcircuit_evidence_is_bounded() {
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

        for idx in 0..(MAX_MICRO_EVIDENCE + 8) {
            let digest = [idx as u8; 32];
            let refs = vec![micro_ref("mc:lc", digest), micro_ref("mc_cfg:lc", digest)];
            append_decision_record_with_refs(
                &mut store,
                &keystore,
                &vrf_engine,
                "session-bounded",
                refs,
            );
        }

        let summary = list_microcircuit_evidence(&store, "session-bounded");
        assert_eq!(summary.lc_snapshots.len(), MAX_MICRO_EVIDENCE);
        assert_eq!(summary.lc_snapshots.first().copied(), Some([0u8; 32]));
        assert_eq!(summary.lc_snapshots.last().copied(), Some([31u8; 32]));
        assert_eq!(summary.lc_configs.len(), MAX_MICRO_EVIDENCE);
        assert_eq!(summary.lc_configs.first().copied(), Some([0u8; 32]));
        assert_eq!(summary.lc_configs.last().copied(), Some([31u8; 32]));
        assert!(summary.sn_snapshots.is_empty());
        assert!(summary.sn_configs.is_empty());
    }

    #[test]
    fn list_plasticity_evidence_filters_record_types() {
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

        let plasticity_first = [2u8; 32];
        let plasticity_second = [1u8; 32];
        let session_id = "session-plasticity";

        append_record_with_refs_and_type(
            &mut store,
            &keystore,
            &vrf_engine,
            session_id,
            RecordType::RtReplay,
            vec![micro_ref("mc_snap:plasticity", plasticity_first)],
        );
        append_record_with_refs_and_type(
            &mut store,
            &keystore,
            &vrf_engine,
            session_id,
            RecordType::RtActionExec,
            vec![micro_ref("mc_snap:plasticity", plasticity_second)],
        );
        append_record_with_refs_and_type(
            &mut store,
            &keystore,
            &vrf_engine,
            session_id,
            RecordType::RtDecision,
            vec![micro_ref("mc_snap:plasticity", [9u8; 32])],
        );

        let snapshots = list_plasticity_evidence(&store, session_id);
        assert_eq!(snapshots, vec![plasticity_second, plasticity_first]);
    }

    #[test]
    fn list_replay_run_digests_returns_sorted_unique_digests() {
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
        let session_id = "session-replay-list";

        let replay_run_first = [3u8; 32];
        let replay_run_second = [1u8; 32];

        append_record_with_refs_and_type(
            &mut store,
            &keystore,
            &vrf_engine,
            session_id,
            RecordType::RtReplay,
            vec![replay_run_ref(replay_run_first)],
        );
        append_record_with_refs_and_type(
            &mut store,
            &keystore,
            &vrf_engine,
            session_id,
            RecordType::RtReplay,
            vec![replay_run_ref(replay_run_second)],
        );
        append_record_with_refs_and_type(
            &mut store,
            &keystore,
            &vrf_engine,
            session_id,
            RecordType::RtReplay,
            vec![replay_run_ref(replay_run_first)],
        );

        let replay_runs = list_replay_run_digests(&store, session_id);
        assert_eq!(replay_runs, vec![replay_run_second, replay_run_first]);
    }

    #[test]
    fn list_replay_runs_returns_sorted_evidence() {
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

        let first_digest = [2u8; 32];
        let second_digest = [1u8; 32];
        let asset_digest = [3u8; 32];

        store
            .replay_run_store
            .insert(ReplayRunEvidence {
                run_digest: first_digest.to_vec(),
                replay_plan_ref: None,
                asset_manifest_ref: Some(Ref {
                    id: "asset_manifest".to_string(),
                    digest: Some(asset_digest.to_vec()),
                }),
                steps: 10,
                dt_us: 5,
                created_at_ms: 20,
                micro_config_refs: Vec::new(),
                summary_digests: vec![vec![5u8; 32]],
            })
            .expect("valid run evidence");
        store
            .replay_run_store
            .insert(ReplayRunEvidence {
                run_digest: second_digest.to_vec(),
                replay_plan_ref: None,
                asset_manifest_ref: Some(Ref {
                    id: "asset_manifest".to_string(),
                    digest: Some(asset_digest.to_vec()),
                }),
                steps: 12,
                dt_us: 6,
                created_at_ms: 10,
                micro_config_refs: Vec::new(),
                summary_digests: vec![vec![6u8; 32]],
            })
            .expect("valid run evidence");

        let runs = list_replay_runs(&store, 10);
        assert_eq!(runs.len(), 2);
        assert_eq!(runs[0].run_digest, second_digest.to_vec());
        assert_eq!(runs[1].run_digest, first_digest.to_vec());

        let fetched = get_replay_run(&store, first_digest);
        assert!(fetched.is_some());
        let summary = replay_run_summary(&store, first_digest);
        assert_eq!(summary.run_digest, first_digest);
        assert_eq!(summary.asset_manifest_digest, Some(asset_digest));
    }

    #[test]
    fn plasticity_scorecard_tracks_latest_digest() {
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

        let first = [4u8; 32];
        let second = [8u8; 32];

        append_record_with_refs_and_type(
            &mut store,
            &keystore,
            &vrf_engine,
            "plasticity-1",
            RecordType::RtDecision,
            vec![micro_ref("mc_snap:plasticity", first)],
        );
        append_record_with_refs_and_type(
            &mut store,
            &keystore,
            &vrf_engine,
            "plasticity-2",
            RecordType::RtReplay,
            Vec::new(),
        );
        append_record_with_refs_and_type(
            &mut store,
            &keystore,
            &vrf_engine,
            "plasticity-3",
            RecordType::RtDecision,
            vec![micro_ref("mc_snap:plasticity", second)],
        );

        let snapshot = snapshot(&store, Some("plasticity-3"));
        let card = snapshot.plasticity_card;

        assert_eq!(card.learning_evidence_record_count, 2);
        assert_eq!(card.latest_plasticity_snapshot_digest, Some(second));
        assert_eq!(card.unique_plasticity_snapshot_count, 2);
        assert_eq!(card.last_plasticity_digests, vec![first, second]);
    }

    #[test]
    fn replay_scorecard_tracks_latest_replay_run_digest() {
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

        let first = [4u8; 32];
        let second = [8u8; 32];
        let asset_manifest_first = [5u8; 32];
        let asset_manifest_second = [6u8; 32];
        let micro_config_lc = [7u8; 32];
        let micro_config_sn = [9u8; 32];

        append_record_with_refs_and_type(
            &mut store,
            &keystore,
            &vrf_engine,
            "replay-1",
            RecordType::RtReplay,
            vec![replay_run_ref(first)],
        );
        append_record_with_refs_and_type(
            &mut store,
            &keystore,
            &vrf_engine,
            "replay-2",
            RecordType::RtReplay,
            vec![replay_run_ref(second)],
        );

        store
            .replay_run_store
            .insert(ReplayRunEvidence {
                run_digest: first.to_vec(),
                replay_plan_ref: None,
                asset_manifest_ref: Some(Ref {
                    id: "asset_manifest".to_string(),
                    digest: Some(asset_manifest_first.to_vec()),
                }),
                steps: 12,
                dt_us: 5,
                created_at_ms: 10,
                micro_config_refs: vec![Ref {
                    id: "mc_cfg:lc".to_string(),
                    digest: Some(micro_config_lc.to_vec()),
                }],
                summary_digests: vec![vec![1u8; 32]],
            })
            .expect("valid replay run evidence");
        store
            .replay_run_store
            .insert(ReplayRunEvidence {
                run_digest: second.to_vec(),
                replay_plan_ref: None,
                asset_manifest_ref: Some(Ref {
                    id: "asset_manifest".to_string(),
                    digest: Some(asset_manifest_second.to_vec()),
                }),
                steps: 14,
                dt_us: 6,
                created_at_ms: 12,
                micro_config_refs: vec![Ref {
                    id: "mc_cfg:sn".to_string(),
                    digest: Some(micro_config_sn.to_vec()),
                }],
                summary_digests: vec![vec![2u8; 32]],
            })
            .expect("valid replay run evidence");

        let snapshot = snapshot(&store, Some("replay-2"));
        let card = snapshot.replay_card;

        assert_eq!(card.replay_run_count_last_n, 2);
        assert_eq!(card.latest_replay_run_digest, Some(second));
        assert_eq!(card.unique_replay_run_count_last_n, 2);
        assert_eq!(card.last_replay_run_digests, vec![first, second]);
        assert_eq!(card.replay_run_evidence_count_last_n, 2);
        assert_eq!(card.latest_replay_run_evidence_digest, Some(second));
        assert_eq!(card.asset_bound_run_count, 2);
        assert_eq!(
            card.top_micro_modules_in_runs,
            vec![
                MicroModuleCount {
                    module: MicroModule::Lc,
                    count: 1
                },
                MicroModuleCount {
                    module: MicroModule::Sn,
                    count: 1
                },
            ]
        );
    }

    #[test]
    fn trace_scorecard_tracks_latest_and_counts() {
        let mut store = minimal_store();
        let first = trace_run_evidence([4u8; 32], 10, TraceVerdict::Promising);
        let second = trace_run_evidence([6u8; 32], 12, TraceVerdict::Risky);
        let third = trace_run_evidence([5u8; 32], 12, TraceVerdict::Neutral);
        store
            .trace_run_store
            .insert(first.clone())
            .expect("valid trace run");
        store
            .trace_run_store
            .insert(second.clone())
            .expect("valid trace run");
        store
            .trace_run_store
            .insert(third.clone())
            .expect("valid trace run");

        let runs = list_trace_runs(&store, 10);
        assert_eq!(runs.len(), 3);
        assert_eq!(runs[0].created_at_ms, 10);
        let mut expected = [
            digest_from_bytes(&second.trace_digest).unwrap(),
            digest_from_bytes(&third.trace_digest).unwrap(),
        ];
        expected.sort();
        assert_eq!(digest_from_bytes(&runs[1].trace_digest), Some(expected[0]));
        assert_eq!(digest_from_bytes(&runs[2].trace_digest), Some(expected[1]));

        let latest = latest_trace_run(&store).expect("latest trace run");
        assert_eq!(digest_from_bytes(&latest.trace_digest), Some(expected[1]));
        let expected_verdict = if digest_from_bytes(&second.trace_digest) == Some(expected[1]) {
            TraceVerdict::Risky
        } else {
            TraceVerdict::Neutral
        };
        assert_eq!(latest.verdict, expected_verdict as i32);

        let snapshot = snapshot(&store, None);
        let card = snapshot.trace_card;
        assert_eq!(card.latest_trace_run_digest, Some(expected[1]));
        assert_eq!(card.latest_trace_verdict, Some(expected_verdict));
        assert_eq!(card.counts_last_n.promising, 1);
        assert_eq!(card.counts_last_n.neutral, 1);
        assert_eq!(card.counts_last_n.risky, 1);
    }

    #[test]
    fn latest_trace_run_for_configs_is_deterministic() {
        let mut store = minimal_store();
        let mut first = trace_run_evidence([2u8; 32], 10, TraceVerdict::Promising);
        first.active_cfg_digest = [9u8; 32].to_vec();
        first.shadow_cfg_digest = [8u8; 32].to_vec();
        let digest = compute_trace_run_digest(&first).expect("digest");
        first.trace_digest = digest.to_vec();

        let mut second = trace_run_evidence([3u8; 32], 12, TraceVerdict::Risky);
        second.active_cfg_digest = [9u8; 32].to_vec();
        second.shadow_cfg_digest = [8u8; 32].to_vec();
        let digest = compute_trace_run_digest(&second).expect("digest");
        second.trace_digest = digest.to_vec();

        store
            .trace_run_store
            .insert(first.clone())
            .expect("valid trace run");
        store
            .trace_run_store
            .insert(second.clone())
            .expect("valid trace run");

        let latest =
            latest_trace_run_for_configs(&store, [9u8; 32], [8u8; 32]).expect("latest trace run");
        assert_eq!(
            digest_from_bytes(&latest.trace_digest),
            digest_from_bytes(&second.trace_digest)
        );
    }

    #[test]
    fn list_microcircuit_evidence_includes_configs() {
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

        let lc_snapshot = [10u8; 32];
        let sn_snapshot = [11u8; 32];
        let lc_config = [12u8; 32];
        let sn_config = [13u8; 32];
        let refs = vec![
            micro_ref("mc:lc", lc_snapshot),
            micro_ref("mc:sn", sn_snapshot),
            micro_ref("mc_cfg:lc", lc_config),
            micro_ref("mc_cfg:sn", sn_config),
        ];
        append_decision_record_with_refs(
            &mut store,
            &keystore,
            &vrf_engine,
            "session-configs",
            refs,
        );

        let summary = list_microcircuit_evidence(&store, "session-configs");
        assert_eq!(summary.lc_snapshots, vec![lc_snapshot]);
        assert_eq!(summary.sn_snapshots, vec![sn_snapshot]);
        assert_eq!(summary.lc_configs, vec![lc_config]);
        assert_eq!(summary.sn_configs, vec![sn_config]);
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
                digest: None,
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
                digest: None,
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
        };

        let (receipt, _) = verify_and_commit(req, store, keystore, vrf_engine);
        assert_eq!(receipt.status, ReceiptStatus::Accepted);

        store.experience_store.head_record_digest
    }

    fn append_decision_record_with_refs(
        store: &mut PvgsStore,
        keystore: &KeyStore,
        vrf_engine: &VrfEngine,
        commit_id: &str,
        related_refs: Vec<Ref>,
    ) -> [u8; 32] {
        append_record_with_refs_and_type(
            store,
            keystore,
            vrf_engine,
            commit_id,
            RecordType::RtDecision,
            related_refs,
        )
    }

    fn append_record_with_refs_and_type(
        store: &mut PvgsStore,
        keystore: &KeyStore,
        vrf_engine: &VrfEngine,
        commit_id: &str,
        record_type: RecordType,
        related_refs: Vec<Ref>,
    ) -> [u8; 32] {
        let governance_frame = GovernanceFrame {
            policy_decision_refs: related_refs,
            pvgs_receipt_ref: None,
            dlp_refs: Vec::new(),
        };

        let record = ExperienceRecord {
            record_type: record_type as i32,
            core_frame: None,
            metabolic_frame: None,
            governance_frame: Some(governance_frame),
            core_frame_ref: None,
            metabolic_frame_ref: None,
            governance_frame_ref: Some(Ref {
                id: hex::encode([9u8; 32]),
                digest: None,
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
                    digest: None,
                },
                Ref {
                    id: format!("ruleset:{}", hex::encode(ruleset_digest)),
                    digest: None,
                },
                Ref {
                    id: format!("decision:{}", hex::encode(policy_decision_digest)),
                    digest: None,
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
    fn tool_event_queries_reflect_suspension() {
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

        let first = ToolOnboardingEvent {
            event_id: "evt-b".to_string(),
            stage: ToolOnboardingStage::To1Validated as i32,
            tool_id: "tool-q".to_string(),
            action_id: "action-q".to_string(),
            reason_codes: vec!["z".to_string()],
            signatures: Vec::new(),
            event_digest: None,
            created_at_ms: Some(5),
        };

        let mut second = first.clone();
        second.event_id = "evt-a".to_string();
        second.stage = ToolOnboardingStage::To6Suspended as i32;
        second.created_at_ms = Some(6);

        store.tool_event_store.insert(first).unwrap();
        store.tool_event_store.insert(second.clone()).unwrap();
        store
            .suspended_tools
            .insert((second.tool_id.clone(), second.action_id.clone()));

        let events = list_tool_events(&store, "tool-q", "action-q");
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event_id, "evt-a".to_string());
        assert!(is_tool_suspended(&store, "tool-q", "action-q"));

        let suspended = list_suspended_tools(&store);
        assert_eq!(
            suspended,
            vec![("tool-q".to_string(), "action-q".to_string())]
        );
    }

    #[test]
    fn explain_suspension_returns_correlation_and_reasons() {
        let mut store = minimal_store();
        store.ruleset_state.ruleset_digest = [9u8; 32];
        store.ruleset_state.tool_registry_digest = Some([7u8; 32]);

        let mut event = ToolOnboardingEvent {
            event_id: "evt-1".to_string(),
            stage: ToolOnboardingStage::To6Suspended as i32,
            tool_id: "tool-1".to_string(),
            action_id: "action-1".to_string(),
            reason_codes: vec!["b".to_string(), "a".to_string()],
            signatures: Vec::new(),
            event_digest: None,
            created_at_ms: Some(2),
        };

        let digest = store
            .tool_event_store
            .insert(event.clone())
            .expect("event inserted");
        store
            .suspended_tools
            .insert((event.tool_id.clone(), event.action_id.clone()));
        store.correlate_tool_event(digest);

        event.reason_codes.sort();
        let explanation = explain_tool_suspension(&store, "tool-1", "action-1");

        assert!(explanation.suspended);
        assert_eq!(explanation.latest_event_digest, Some(digest));
        assert_eq!(explanation.event_ruleset_digest, Some([9u8; 32]));
        assert_eq!(explanation.event_tool_registry_digest, Some([7u8; 32]));
        assert_eq!(explanation.latest_reason_codes, event.reason_codes);
        assert_eq!(explanation.event_timestamp_ms, event.created_at_ms);
    }

    #[test]
    fn list_suspended_tools_is_deterministic() {
        let mut store = minimal_store();
        store.ruleset_state.ruleset_digest = [3u8; 32];

        let first = ToolOnboardingEvent {
            event_id: "evt-1".to_string(),
            stage: ToolOnboardingStage::To6Suspended as i32,
            tool_id: "tool-a".to_string(),
            action_id: "action-b".to_string(),
            reason_codes: vec!["r1".to_string()],
            signatures: Vec::new(),
            event_digest: None,
            created_at_ms: None,
        };

        let mut second = first.clone();
        second.tool_id = "tool-a".to_string();
        second.action_id = "action-a".to_string();
        second.reason_codes = vec!["r2".to_string(), "r0".to_string()];
        second.created_at_ms = Some(5);

        let first_digest = store.tool_event_store.insert(first).unwrap();
        store.correlate_tool_event(first_digest);
        let second_digest = store.tool_event_store.insert(second.clone()).unwrap();
        store.ruleset_state.ruleset_digest = [4u8; 32];
        store.correlate_tool_event(second_digest);

        store
            .suspended_tools
            .insert(("tool-a".to_string(), "action-a".to_string()));
        store
            .suspended_tools
            .insert(("tool-a".to_string(), "action-b".to_string()));

        let explanations = list_suspended_tools_with_reasons(&store);
        assert_eq!(explanations.len(), 2);
        assert_eq!(explanations[0].action_id, "action-a");
        assert_eq!(explanations[0].latest_event_digest, Some(second_digest));
        assert_eq!(explanations[1].action_id, "action-b");
        assert!(explanations[1].latest_event_digest.is_some());
    }

    #[test]
    fn registry_ruleset_correlation_tracks_history() {
        let mut store = minimal_store();
        let registry_one = [1u8; 32];
        let registry_two = [2u8; 32];

        store.tool_registry_state.set_current(registry_one).unwrap();
        store.ruleset_state.ruleset_digest = [5u8; 32];
        store.ruleset_state.tool_registry_digest = Some(registry_one);
        store.correlate_registry_ruleset(registry_one);

        store.tool_registry_state.set_current(registry_two).unwrap();
        store.ruleset_state.ruleset_digest = [6u8; 32];
        store.ruleset_state.tool_registry_digest = Some(registry_two);
        store.correlate_registry_ruleset(registry_two);

        assert_eq!(
            list_tool_registry_history(&store),
            vec![registry_one, registry_two]
        );

        let correlations = correlate_registry_to_ruleset(&store);
        assert_eq!(correlations.len(), 2);
        assert!(correlations.contains(&(registry_one, [5u8; 32])));
        assert!(correlations.contains(&(registry_two, [6u8; 32])));
    }

    #[test]
    fn pending_replay_plans_sorted_and_consumed() {
        let mut store = minimal_store();
        let target_ref = Ref {
            id: "target".to_string(),
            digest: None,
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
            asset_manifest_ref: None,
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
            asset_manifest_ref: None,
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

    #[test]
    fn replay_card_tracks_pending_asset_bindings() {
        let mut store = minimal_store();
        let mut manifest = AssetManifest {
            manifest_digest: Vec::new(),
            created_at_ms: 1,
            asset_digests: vec![AssetDigest {
                kind: AssetKind::Morphology as i32,
                digest: [0x11u8; 32].to_vec(),
                version: 1,
            }],
        };
        let digest = compute_asset_manifest_digest(&manifest);
        manifest.manifest_digest = digest.to_vec();
        store.asset_manifest_store.insert(manifest).unwrap();

        let target_ref = Ref {
            id: "target".to_string(),
            digest: None,
        };
        let plan_bound = build_replay_plan(BuildReplayPlanArgs {
            session_id: "sess".to_string(),
            head_experience_id: 1,
            head_record_digest: [1u8; 32],
            target_kind: ReplayTargetKind::Macro,
            target_refs: vec![target_ref.clone()],
            fidelity: ReplayFidelity::Low,
            counter: 1,
            trigger_reason_codes: Vec::new(),
            asset_manifest_ref: Some(Ref {
                id: "asset_manifest".to_string(),
                digest: Some(digest.to_vec()),
            }),
        });
        let plan_missing = build_replay_plan(BuildReplayPlanArgs {
            session_id: "sess".to_string(),
            head_experience_id: 1,
            head_record_digest: [1u8; 32],
            target_kind: ReplayTargetKind::Macro,
            target_refs: vec![target_ref],
            fidelity: ReplayFidelity::Low,
            counter: 2,
            trigger_reason_codes: Vec::new(),
            asset_manifest_ref: Some(Ref {
                id: "asset_manifest".to_string(),
                digest: Some([0x22u8; 32].to_vec()),
            }),
        });

        store.replay_plans.push(plan_bound).unwrap();
        store.replay_plans.push(plan_missing.clone()).unwrap();

        let snapshot = snapshot(&store, Some("sess"));
        assert_eq!(
            snapshot.replay_card.pending_replay_plans_asset_bound_count,
            1
        );
        assert_eq!(
            snapshot
                .replay_card
                .pending_replay_plans_asset_missing_count,
            1
        );
        assert_eq!(
            snapshot.replay_card.pending_replay_plans_asset_missing_ids,
            vec![plan_missing.replay_id]
        );
    }
}
