#![forbid(unsafe_code)]

use assets::{
    compute_asset_bundle_digest, compute_asset_chunk_digest, compute_asset_manifest_digest,
    validate_manifest, AssetBundleStore, AssetBundleStoreError, AssetManifestStore,
};
use bincode::Options;
use blake3::Hasher;
use cbv::{
    cbv_attestation_preimage, compute_cbv_digest, compute_cbv_verified_fields_digest,
    derive_next_cbv, CbvDeriverConfig, CbvStore,
};
use consistency::{validate_feedback, ConsistencyStore};
use dlp_store::DlpDecisionStore;
use ed25519_dalek::Signer;
use keys::{verify_key_epoch_signature, KeyEpochHistory, KeyStore};
use limits::{StoreLimits, DEFAULT_LIMITS};
use milestones::{
    compute_meso_digest, MacroDeriver, MesoDeriver, MesoMilestone, MesoMilestoneStore,
    MicroMilestoneStore,
};
use pev::{pev_digest as extract_pev_digest, PevStore, PolicyEcologyVector};
use proposal_activations::{
    compute_proposal_activation_digest, validate_proposal_activation_evidence, ActivationStatus,
    ProposalActivationEvidence, ProposalActivationStore,
};
use proposals::{
    compute_proposal_evidence_digest, validate_proposal_evidence, ProposalEvidence, ProposalStore,
};
use prost::Message;
use receipts::{issue_proof_receipt, issue_receipt, ReceiptInput};
use recovery::{RecoveryCase, RecoveryCheck, RecoveryState, RecoveryStore, RecoveryStoreError};
use replay_plan::{
    build_replay_plan, ref_from_digest, replay_trigger_reasons, should_generate_replay,
    BuildReplayPlanArgs, ConsistencyClass, ConsistencyCounts, ReplayPlanStore, ReplaySignals,
};
use replay_runs::ReplayRunStore;
use rpp_pruning::{canonical_bincode_options, TaggedDigest, COMMITMENT_TAG};
use sep::{
    CausalGraph, EdgeType, FrameEventKind, NodeKey, SepError, SepEventInternal, SepEventType,
    SepLog, SessionSeal,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::convert::TryFrom;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tool_events::{
    compute_event_digest as compute_tool_event_digest, ToolEventError, ToolEventStore,
};
use tool_registry_state::{ToolRegistryError, ToolRegistryState};
use trace_runs::{
    compute_trace_run_digest, validate_trace_run_evidence, TraceRunEvidence, TraceRunStore,
    TraceVerdict,
};
use ucf_protocol::ucf::v1::{
    self as protocol, AssetBundle, AssetChunk, AssetKind, AssetManifest, ChannelParamsSetPayload,
    CharacterBaselineVector, ConnectivityGraphPayload, ConsistencyFeedback, Digest32, DlpDecision,
    DlpDecisionForm, ExperienceRecord, FinalizationHeader, MacroMilestone, MacroMilestoneState,
    MicroModule, MicrocircuitConfigEvidence, MorphologySetPayload, PVGSKeyEpoch, PVGSReceipt,
    ProofReceipt, ReasonCodes, ReceiptStatus, RecordType, Ref, ReplayFidelity, ReplayPlan,
    ReplayRunEvidence, ReplayTargetKind, SynapseParamsSetPayload, ToolOnboardingEvent,
    ToolOnboardingStage, ToolRegistryContainer,
};
use vrf::VrfEngine;

const CONSISTENCY_SIGNAL_WINDOW: usize = DEFAULT_LIMITS.consistency_signal_window;
const CONSISTENCY_HISTORY_MAX: usize = DEFAULT_LIMITS.consistency_history_max;
const GRAPH_TRIM_SESSION_ID: &str = "graph-trim";
const MAX_ASSET_PAYLOAD_DECODE_BYTES: usize = 2 * 1024 * 1024;
const PRUNE_MANIFEST_PREFIX: &str = "pvgs/prune";

/// Commit type supported by PVGS.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitType {
    ReceiptRequest,
    RecordAppend,
    ExperienceRecordAppend,
    MilestoneAppend,
    MacroMilestonePropose,
    MacroMilestoneFinalize,
    ConsistencyFeedbackAppend,
    CharterUpdate,
    ToolRegistryUpdate,
    ToolOnboardingEventAppend,
    RecoveryCaseCreate,
    RecoveryCaseAdvance,
    RecoveryApproval,
    RecoveryUpdate,
    PevUpdate,
    CbvUpdate,
    KeyEpochUpdate,
    FrameEvidenceAppend,
    DlpDecisionAppend,
    ReplayPlanAppend,
    ReplayRunEvidenceAppend,
    TraceRunEvidenceAppend,
    MicrocircuitConfigAppend,
    AssetManifestAppend,
    AssetBundleAppend,
    ProposalEvidenceAppend,
    ProposalActivationAppend,
}

/// Required checks requested by the caller.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequiredCheck {
    SchemaOk,
    BindingOk,
    TightenOnly,
    IntegrityOk,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CriticalTrigger {
    SepOverflow,
    IntegrityFail,
    ReplayMismatch,
    UnauthorizedPath,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CriticalTriggerConfig {
    pub replay_mismatch: bool,
}

impl Default for CriticalTriggerConfig {
    fn default() -> Self {
        Self {
            replay_mismatch: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PvgsConfig {
    pub auto_seal_on_replay_mismatch: bool,
}

impl PvgsConfig {
    pub fn beta() -> Self {
        Self {
            auto_seal_on_replay_mismatch: false,
        }
    }

    pub fn production() -> Self {
        Self {
            auto_seal_on_replay_mismatch: true,
        }
    }
}

impl Default for PvgsConfig {
    fn default() -> Self {
        Self::beta()
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnlockPermit {
    pub session_id: String,
    pub permit_digest: [u8; 32],
    pub issued_at_ms: u64,
    pub ruleset_digest: [u8; 32],
}

impl UnlockPermit {
    pub fn new(session_id: String, issued_at_ms: u64, ruleset_digest: [u8; 32]) -> Self {
        let mut hasher = Hasher::new();
        hasher.update(b"UCF:PVGS:UNLOCK_PERMIT");
        hasher.update(session_id.as_bytes());
        hasher.update(&issued_at_ms.to_le_bytes());
        hasher.update(&ruleset_digest);

        let permit_digest = *hasher.finalize().as_bytes();
        Self {
            session_id,
            permit_digest,
            issued_at_ms,
            ruleset_digest,
        }
    }
}

fn critical_trigger_reason_code(trig: CriticalTrigger) -> String {
    match trig {
        CriticalTrigger::ReplayMismatch => protocol::ReasonCodes::RE_REPLAY_MISMATCH.to_string(),
        CriticalTrigger::UnauthorizedPath => {
            protocol::ReasonCodes::RX_REQ_UNAUTHORIZED_PATH.to_string()
        }
        CriticalTrigger::SepOverflow | CriticalTrigger::IntegrityFail => {
            protocol::ReasonCodes::RE_INTEGRITY_FAIL.to_string()
        }
    }
}

fn critical_trigger_digest(session_id: &str, trig: CriticalTrigger) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(b"UCF:PVGS:CRITICAL_TRIGGER");
    hasher.update(session_id.as_bytes());
    hasher.update(match trig {
        CriticalTrigger::SepOverflow => b"SEP_OVERFLOW".as_slice(),
        CriticalTrigger::IntegrityFail => b"INTEGRITY_FAIL".as_slice(),
        CriticalTrigger::ReplayMismatch => b"REPLAY_MISMATCH".as_slice(),
        CriticalTrigger::UnauthorizedPath => b"UNAUTHORIZED_PATH".as_slice(),
    });

    *hasher.finalize().as_bytes()
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CbvCommitError {
    #[error("macro milestone not finalized")]
    MacroNotFinalized,
    #[error("cbv epoch is not monotonic")]
    NonMonotonicEpoch,
    #[error("cbv derivation failed: {0}")]
    Derivation(String),
    #[error("sep error: {0}")]
    Sep(#[from] SepError),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MacroValidationError {
    #[error("macro milestone already stored")]
    Duplicate,
    #[error("macro milestone not proposed")]
    MissingProposal,
    #[error("macro milestone invalid state")]
    InvalidState,
    #[error("macro milestone missing digest")]
    MissingDigest,
    #[error("macro milestone missing proof receipt")]
    MissingProofReceipt,
    #[error("macro milestone missing consistency feedback")]
    MissingConsistencyFeedback,
    #[error("macro milestone consistency too low")]
    LowConsistencyClass,
    #[error("sep error: {0}")]
    Sep(#[from] SepError),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AutoCommitError {
    #[error("meso commit rejected: {0:?}")]
    Rejected(Vec<String>),
    #[error("sep error: {0}")]
    Sep(#[from] SepError),
}

/// Commit binding data that feeds into receipts.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitBindings {
    pub action_digest: Option<[u8; 32]>,
    pub decision_digest: Option<[u8; 32]>,
    pub grant_id: Option<String>,
    pub charter_version_digest: String,
    pub policy_version_digest: String,
    pub prev_record_digest: [u8; 32],
    pub profile_digest: Option<[u8; 32]>,
    pub tool_profile_digest: Option<[u8; 32]>,
    pub pev_digest: Option<[u8; 32]>,
}

/// Current digest state of governance ruleset inputs.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RulesetState {
    pub charter_version_digest: String,
    pub policy_version_digest: String,
    pub tool_registry_digest: Option<[u8; 32]>,
    pub pev_digest: Option<[u8; 32]>,
    pub ruleset_digest: [u8; 32],
    pub prev_ruleset_digest: Option<[u8; 32]>,
}

impl RulesetState {
    pub fn new(charter_version_digest: String, policy_version_digest: String) -> Self {
        let mut state = Self {
            charter_version_digest,
            policy_version_digest,
            tool_registry_digest: None,
            pev_digest: None,
            ruleset_digest: [0u8; 32],
            prev_ruleset_digest: None,
        };
        state.recompute_ruleset_digest();
        state
    }

    pub fn recompute_ruleset_digest(&mut self) -> bool {
        let old_ruleset_digest = self.ruleset_digest;
        let new_ruleset_digest = compute_ruleset_digest(
            self.charter_version_digest.as_bytes(),
            self.policy_version_digest.as_bytes(),
            self.pev_digest.as_ref().map(|d| d.as_slice()),
            self.tool_registry_digest.as_ref().map(|d| d.as_slice()),
        );

        if new_ruleset_digest != old_ruleset_digest {
            self.prev_ruleset_digest = Some(old_ruleset_digest);
            self.ruleset_digest = new_ruleset_digest;
            return true;
        }

        false
    }
}

pub use protocol::RequiredReceiptKind;

/// A PVGS commit request encompassing bindings and payload digests.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PvgsCommitRequest {
    pub commit_id: String,
    pub commit_type: CommitType,
    pub bindings: CommitBindings,
    pub required_receipt_kind: RequiredReceiptKind,
    pub required_checks: Vec<RequiredCheck>,
    pub payload_digests: Vec<[u8; 32]>,
    pub epoch_id: u64,
    pub key_epoch: Option<PVGSKeyEpoch>,
    pub experience_record_payload: Option<Vec<u8>>,
    pub replay_run_evidence_payload: Option<Vec<u8>>,
    pub trace_run_evidence_payload: Option<Vec<u8>>,
    pub proposal_evidence_payload: Option<Vec<u8>>,
    pub proposal_activation_payload: Option<Vec<u8>>,
    pub macro_milestone: Option<MacroMilestone>,
    pub meso_milestone: Option<MesoMilestone>,
    pub dlp_decision_payload: Option<Vec<u8>>,
    pub tool_registry_container: Option<Vec<u8>>,
    pub pev: Option<PolicyEcologyVector>,
    pub consistency_feedback_payload: Option<Vec<u8>>,
    pub macro_consistency_digest: Option<[u8; 32]>,
    pub recovery_case: Option<RecoveryCase>,
    pub unlock_permit: Option<UnlockPermit>,
    pub tool_onboarding_event: Option<Vec<u8>>,
    pub microcircuit_config_payload: Option<Vec<u8>>,
    pub asset_manifest_payload: Option<Vec<u8>>,
    pub asset_bundle_payload: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CbvCommitOutcome {
    pub cbv: CharacterBaselineVector,
    pub receipt: PVGSReceipt,
    pub proof_receipt: ProofReceipt,
    pub applied_updates: bool,
}

#[derive(Debug, Clone)]
pub struct ReplayPlanOutcome {
    pub plan: ReplayPlan,
    pub receipt: PVGSReceipt,
    pub proof_receipt: ProofReceipt,
}

/// In-memory store tracking experience records and proof receipts.
#[derive(Debug, Clone, Default)]
pub struct ExperienceStore {
    pub records: Vec<ExperienceRecord>,
    pub head_record_digest: [u8; 32],
    pub head_id: u64,
    pub proof_receipts: HashMap<[u8; 32], ProofReceipt>,
    pub limits: StoreLimits,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PruneManifest {
    head_id: u64,
    prune_ops_digest: TaggedDigest,
    pruned_record_digests: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, Default)]
pub struct ConsistencyHistory {
    entries: Vec<(String, [u8; 32])>,
}

impl ConsistencyHistory {
    pub fn push(&mut self, session_id: String, digest: [u8; 32]) {
        self.entries.push((session_id, digest));

        if self.entries.len() > CONSISTENCY_HISTORY_MAX {
            let remove_count = self.entries.len() - CONSISTENCY_HISTORY_MAX;
            self.entries.drain(0..remove_count);
        }
    }

    pub fn recent_for_session(&self, session_id: &str, limit: usize) -> Vec<[u8; 32]> {
        let mut digests = Vec::new();

        for (entry_session, digest) in self.entries.iter().rev() {
            if entry_session == session_id {
                digests.push(*digest);

                if digests.len() >= limit {
                    break;
                }
            }
        }

        digests.reverse();
        digests
    }
}

#[derive(Debug, Clone, Default)]
pub struct MacroMilestoneStore {
    proposed: HashMap<String, MacroMilestone>,
    finalized: HashMap<String, MacroMilestone>,
    finalized_order: Vec<String>,
}

impl MacroMilestoneStore {
    pub fn insert_proposal(
        &mut self,
        macro_milestone: MacroMilestone,
    ) -> Result<(), MacroValidationError> {
        validate_macro_proposal(&macro_milestone)?;

        if self.proposed.contains_key(&macro_milestone.macro_id)
            || self.finalized.contains_key(&macro_milestone.macro_id)
        {
            return Err(MacroValidationError::Duplicate);
        }

        self.proposed
            .insert(macro_milestone.macro_id.clone(), macro_milestone);
        Ok(())
    }

    pub fn finalize(
        &mut self,
        macro_milestone: MacroMilestone,
        feedback: &ConsistencyFeedback,
    ) -> Result<(), MacroValidationError> {
        validate_macro_finalization(&macro_milestone, feedback)?;

        if self.finalized.contains_key(&macro_milestone.macro_id) {
            return Err(MacroValidationError::Duplicate);
        }

        if !self.proposed.contains_key(&macro_milestone.macro_id) {
            return Err(MacroValidationError::MissingProposal);
        }

        self.proposed.remove(&macro_milestone.macro_id);
        self.finalized
            .insert(macro_milestone.macro_id.clone(), macro_milestone.clone());
        self.finalized_order.push(macro_milestone.macro_id);
        Ok(())
    }

    pub fn latest_finalized(&self) -> Option<&MacroMilestone> {
        self.finalized_order
            .last()
            .and_then(|id| self.finalized.get(id))
    }

    pub fn last(&self) -> Option<&MacroMilestone> {
        self.latest_finalized()
    }

    pub fn len(&self) -> usize {
        self.finalized_order.len()
    }

    pub fn get_proposed(&self, macro_id: &str) -> Option<&MacroMilestone> {
        self.proposed.get(macro_id)
    }

    pub fn get_finalized(&self, macro_id: &str) -> Option<&MacroMilestone> {
        self.finalized.get(macro_id)
    }

    pub fn proposed_ids(&self) -> Vec<String> {
        self.proposed.keys().cloned().collect()
    }

    pub fn list_proposed(&self) -> Vec<MacroMilestone> {
        self.proposed.values().cloned().collect()
    }

    pub fn list_finalized(&self) -> Vec<MacroMilestone> {
        self.finalized_order
            .iter()
            .filter_map(|id| self.finalized.get(id))
            .cloned()
            .collect()
    }

    pub fn is_empty(&self) -> bool {
        self.finalized_order.is_empty() && self.proposed.is_empty()
    }
}

#[derive(Debug, Clone, Default)]
pub struct MicroConfigStore {
    entries: BTreeMap<(MicroModule, [u8; 32]), MicrocircuitConfigEvidence>,
}

impl MicroConfigStore {
    pub fn insert(
        &mut self,
        evidence: MicrocircuitConfigEvidence,
    ) -> Result<bool, MicroConfigStoreError> {
        let module = MicroModule::try_from(evidence.module)
            .map_err(|_| MicroConfigStoreError::InvalidModule)?;
        if module == MicroModule::Unspecified {
            return Err(MicroConfigStoreError::InvalidModule);
        }
        if evidence.config_version == 0 {
            return Err(MicroConfigStoreError::InvalidVersion);
        }
        let digest = digest_from_bytes(&evidence.config_digest)
            .ok_or(MicroConfigStoreError::InvalidDigest)?;
        let key = (module, digest);
        if self.entries.contains_key(&key) {
            return Ok(false);
        }
        self.entries.insert(key, evidence);
        Ok(true)
    }

    pub fn latest_for_module(&self, module: MicroModule) -> Option<&MicrocircuitConfigEvidence> {
        self.entries
            .iter()
            .filter_map(|((stored_module, _), entry)| (stored_module == &module).then_some(entry))
            .max_by(|a, b| {
                a.created_at_ms
                    .cmp(&b.created_at_ms)
                    .then_with(|| a.config_version.cmp(&b.config_version))
                    .then_with(|| a.config_digest.cmp(&b.config_digest))
            })
    }

    pub fn list_all(&self) -> Vec<MicrocircuitConfigEvidence> {
        let mut configs: Vec<MicrocircuitConfigEvidence> = self.entries.values().cloned().collect();
        configs.sort_by(|a, b| {
            a.module
                .cmp(&b.module)
                .then_with(|| a.config_version.cmp(&b.config_version))
                .then_with(|| a.created_at_ms.cmp(&b.created_at_ms))
        });
        configs
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MicroConfigStoreError {
    InvalidModule,
    InvalidVersion,
    InvalidDigest,
}

fn validate_macro_proposal(macro_milestone: &MacroMilestone) -> Result<(), MacroValidationError> {
    if macro_milestone.macro_digest.len() != 32 {
        return Err(MacroValidationError::MissingDigest);
    }

    let state = MacroMilestoneState::try_from(macro_milestone.state)
        .unwrap_or(MacroMilestoneState::Unknown);
    if !matches!(state, MacroMilestoneState::Proposed) {
        return Err(MacroValidationError::InvalidState);
    }

    Ok(())
}

fn validate_macro_finalization(
    macro_milestone: &MacroMilestone,
    feedback: &ConsistencyFeedback,
) -> Result<(), MacroValidationError> {
    if macro_milestone.macro_digest.len() != 32 {
        return Err(MacroValidationError::MissingDigest);
    }

    if macro_milestone.proof_receipt_ref.is_none() {
        return Err(MacroValidationError::MissingProofReceipt);
    }

    if macro_milestone.consistency_feedback_ref.is_none() {
        return Err(MacroValidationError::MissingConsistencyFeedback);
    }

    if !macro_milestone
        .consistency_class
        .eq_ignore_ascii_case("consistency_high")
        || feedback.consistency_class != "CONSISTENCY_HIGH"
    {
        return Err(MacroValidationError::LowConsistencyClass);
    }

    Ok(())
}

fn reason_code_for_macro_error(err: MacroValidationError) -> String {
    match err {
        MacroValidationError::LowConsistencyClass => {
            protocol::ReasonCodes::GV_CONSISTENCY_LOW.to_string()
        }
        MacroValidationError::MissingProposal | MacroValidationError::Duplicate => {
            protocol::ReasonCodes::GE_EXEC_DISPATCH_BLOCKED.to_string()
        }
        MacroValidationError::MissingConsistencyFeedback
        | MacroValidationError::MissingDigest
        | MacroValidationError::InvalidState
        | MacroValidationError::MissingProofReceipt => {
            protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string()
        }
        MacroValidationError::Sep(_) => protocol::ReasonCodes::RE_INTEGRITY_FAIL.to_string(),
    }
}

fn macro_proposal_from(macro_milestone: &MacroMilestone) -> MacroMilestone {
    let mut proposal = macro_milestone.clone();
    proposal.state = MacroMilestoneState::Proposed as i32;
    proposal.proof_receipt_ref = None;
    proposal.consistency_feedback_ref = None;
    proposal
}

/// In-memory store tracking PVGS state and SEP event log.
#[derive(Debug, Clone)]
pub struct PvgsStore {
    pub current_head_record_digest: [u8; 32],
    pub experience_store: ExperienceStore,
    pub limits: StoreLimits,
    pub config: PvgsConfig,
    pub critical_triggers: CriticalTriggerConfig,
    pub receipts: HashMap<[u8; 32], PVGSReceipt>,
    pub known_charter_versions: HashSet<String>,
    pub known_policy_versions: HashSet<String>,
    pub known_profiles: HashSet<[u8; 32]>,
    pub key_epoch_history: KeyEpochHistory,
    pub cbv_store: CbvStore,
    pub pev_store: PevStore,
    pub dlp_store: DlpDecisionStore,
    pub tool_event_store: ToolEventStore,
    pub consistency_store: ConsistencyStore,
    pub consistency_history: ConsistencyHistory,
    pub tool_registry_state: ToolRegistryState,
    pub micro_config_store: MicroConfigStore,
    pub asset_manifest_store: AssetManifestStore,
    pub asset_bundle_store: AssetBundleStore,
    pub micro_milestones: MicroMilestoneStore,
    pub meso_milestones: MesoMilestoneStore,
    pub meso_deriver: MesoDeriver,
    pub macro_deriver: MacroDeriver,
    pub macro_milestones: MacroMilestoneStore,
    pub replay_plans: ReplayPlanStore,
    pub replay_run_store: ReplayRunStore,
    pub trace_run_store: TraceRunStore,
    pub proposal_store: ProposalStore,
    pub proposal_activation_store: ProposalActivationStore,
    pub committed_payload_digests: HashSet<[u8; 32]>,
    pub recovery_store: RecoveryStore,
    pub unlock_permits: HashMap<String, UnlockPermit>,
    pub sep_log: SepLog,
    pub causal_graph: CausalGraph,
    pub receipt_gate_enabled: bool,
    pub forensic_mode: bool,
    pub ruleset_state: RulesetState,
    pub suspended_tools: BTreeSet<(String, String)>,
    pub tool_event_correlations: BTreeMap<[u8; 32], ToolEventCorrelation>,
    pub registry_ruleset_correlation: BTreeMap<[u8; 32], [u8; 32]>,
    pub prune_manifests: BTreeMap<String, Vec<u8>>,
    prune_manifest_order: VecDeque<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolEventCorrelation {
    pub ruleset_digest: [u8; 32],
    pub tool_registry_digest: Option<[u8; 32]>,
}

/// Helper for planned commits that require mutable access to the PVGS store and cryptographic
/// material.
pub struct PvgsPlanner<'a> {
    store: &'a mut PvgsStore,
    keystore: &'a mut KeyStore,
    vrf_engine: &'a mut VrfEngine,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("key epoch ids must increase (last {last}, next {next})")]
    NonMonotonic { last: u64, next: u64 },
    #[error("key epoch commit rejected: {0:?}")]
    Rejected(Vec<String>),
    #[error(transparent)]
    Sep(#[from] SepError),
}

impl<'a> PvgsPlanner<'a> {
    pub fn new(
        store: &'a mut PvgsStore,
        keystore: &'a mut KeyStore,
        vrf_engine: &'a mut VrfEngine,
    ) -> Self {
        Self {
            store,
            keystore,
            vrf_engine,
        }
    }

    /// Rotate the attestation and VRF keys, announce them via the KeyEpochUpdate flow, and log
    /// SEP evidence for the rotation.
    pub fn planned_rotate_keys(
        &mut self,
        new_epoch_id: u64,
        created_at_ms: u64,
    ) -> Result<PVGSKeyEpoch, Error> {
        let last_committed = self
            .store
            .key_epoch_history
            .current()
            .map(|epoch| epoch.key_epoch_id)
            .unwrap_or(0);
        let last_epoch = last_committed.max(self.keystore.current_epoch());

        if new_epoch_id <= last_epoch {
            return Err(Error::NonMonotonic {
                last: last_epoch,
                next: new_epoch_id,
            });
        }

        let prev_digest = self
            .store
            .key_epoch_history
            .current()
            .map(|epoch| epoch.announcement_digest.0);

        self.vrf_engine.rotate(new_epoch_id);
        self.keystore.rotate(new_epoch_id);
        let epoch = self.keystore.make_key_epoch_proto(
            new_epoch_id,
            created_at_ms,
            self.vrf_engine.vrf_public_key().to_vec(),
            prev_digest,
        );

        let commit_id = format!("key-epoch-{new_epoch_id}");
        let req = PvgsCommitRequest {
            commit_id: commit_id.clone(),
            commit_type: CommitType::KeyEpochUpdate,
            bindings: CommitBindings {
                action_digest: None,
                decision_digest: None,
                grant_id: None,
                charter_version_digest: self.store.ruleset_state.charter_version_digest.clone(),
                policy_version_digest: self.store.ruleset_state.policy_version_digest.clone(),
                prev_record_digest: self.store.current_head_record_digest,
                profile_digest: None,
                tool_profile_digest: None,
                pev_digest: None,
            },
            required_receipt_kind: RequiredReceiptKind::Read,
            required_checks: vec![RequiredCheck::SchemaOk, RequiredCheck::BindingOk],
            payload_digests: vec![epoch.announcement_digest.0],
            epoch_id: self.keystore.current_epoch(),
            key_epoch: Some(epoch.clone()),
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
        };

        let (receipt, _) = verify_and_commit(req, self.store, self.keystore, self.vrf_engine);

        if !matches!(receipt.status, ReceiptStatus::Accepted) {
            return Err(Error::Rejected(receipt.reject_reason_codes));
        }

        self.store.record_sep_event(
            &commit_id,
            SepEventType::EvKeyEpoch,
            epoch.announcement_digest.0,
            vec![ReasonCodes::GV_KEY_EPOCH_ROTATED.to_string()],
        )?;

        Ok(self
            .store
            .key_epoch_history
            .current()
            .cloned()
            .unwrap_or(epoch))
    }
}

impl PvgsStore {
    pub fn new(
        current_head_record_digest: [u8; 32],
        charter_version_digest: String,
        policy_version_digest: String,
        known_charter_versions: HashSet<String>,
        known_policy_versions: HashSet<String>,
        known_profiles: HashSet<[u8; 32]>,
    ) -> Self {
        Self::new_with_config(
            current_head_record_digest,
            charter_version_digest,
            policy_version_digest,
            known_charter_versions,
            known_policy_versions,
            known_profiles,
            PvgsConfig::default(),
        )
    }

    pub fn new_production(
        current_head_record_digest: [u8; 32],
        charter_version_digest: String,
        policy_version_digest: String,
        known_charter_versions: HashSet<String>,
        known_policy_versions: HashSet<String>,
        known_profiles: HashSet<[u8; 32]>,
    ) -> Self {
        Self::new_with_config(
            current_head_record_digest,
            charter_version_digest,
            policy_version_digest,
            known_charter_versions,
            known_policy_versions,
            known_profiles,
            PvgsConfig::production(),
        )
    }

    pub fn new_with_config(
        current_head_record_digest: [u8; 32],
        charter_version_digest: String,
        policy_version_digest: String,
        known_charter_versions: HashSet<String>,
        known_policy_versions: HashSet<String>,
        known_profiles: HashSet<[u8; 32]>,
        config: PvgsConfig,
    ) -> Self {
        let limits = StoreLimits::default();
        let experience_store = ExperienceStore {
            head_record_digest: current_head_record_digest,
            limits,
            ..Default::default()
        };
        Self {
            current_head_record_digest,
            experience_store,
            limits,
            config,
            critical_triggers: CriticalTriggerConfig::default(),
            receipts: HashMap::new(),
            known_charter_versions,
            known_policy_versions,
            known_profiles,
            key_epoch_history: KeyEpochHistory::default(),
            cbv_store: CbvStore::with_limits(limits),
            pev_store: PevStore::with_limits(limits),
            dlp_store: DlpDecisionStore::default(),
            tool_event_store: ToolEventStore::with_limits(limits),
            consistency_store: ConsistencyStore::with_limits(limits),
            consistency_history: ConsistencyHistory::default(),
            tool_registry_state: ToolRegistryState::default(),
            micro_config_store: MicroConfigStore::default(),
            asset_manifest_store: AssetManifestStore::default(),
            asset_bundle_store: AssetBundleStore::default(),
            micro_milestones: MicroMilestoneStore::default(),
            meso_milestones: MesoMilestoneStore::default(),
            meso_deriver: MesoDeriver::new_beta(),
            macro_deriver: MacroDeriver::new_beta(),
            macro_milestones: MacroMilestoneStore::default(),
            replay_plans: ReplayPlanStore::default(),
            replay_run_store: ReplayRunStore::default(),
            trace_run_store: TraceRunStore::default(),
            proposal_store: ProposalStore::default(),
            proposal_activation_store: ProposalActivationStore::default(),
            committed_payload_digests: HashSet::new(),
            recovery_store: RecoveryStore::default(),
            unlock_permits: HashMap::new(),
            sep_log: SepLog::default(),
            causal_graph: CausalGraph::with_limits(limits),
            receipt_gate_enabled: false,
            forensic_mode: false,
            ruleset_state: RulesetState::new(charter_version_digest, policy_version_digest),
            suspended_tools: BTreeSet::new(),
            tool_event_correlations: BTreeMap::new(),
            registry_ruleset_correlation: BTreeMap::new(),
            prune_manifests: BTreeMap::new(),
            prune_manifest_order: VecDeque::new(),
        }
    }

    pub fn get_latest_cbv(&self) -> Option<CharacterBaselineVector> {
        self.cbv_store.latest().cloned()
    }

    pub fn refresh_ruleset_state(
        &mut self,
        charter_version_digest: &str,
        policy_version_digest: &str,
    ) -> (bool, bool) {
        let charter_changed = self.ruleset_state.charter_version_digest != charter_version_digest;
        let policy_changed = self.ruleset_state.policy_version_digest != policy_version_digest;
        self.ruleset_state.charter_version_digest = charter_version_digest.to_string();
        self.ruleset_state.policy_version_digest = policy_version_digest.to_string();
        self.ruleset_state.pev_digest = self.pev_store.latest().and_then(extract_pev_digest);
        self.ruleset_state.tool_registry_digest = self.tool_registry_state.current();
        (
            self.ruleset_state.recompute_ruleset_digest(),
            charter_changed || policy_changed,
        )
    }

    pub fn update_pev_digest(&mut self, pev_digest: Option<[u8; 32]>) -> bool {
        self.ruleset_state.pev_digest = pev_digest;
        self.ruleset_state.recompute_ruleset_digest()
    }

    pub fn update_tool_registry_digest(&mut self, tool_registry_digest: Option<[u8; 32]>) -> bool {
        self.ruleset_state.tool_registry_digest = tool_registry_digest;
        self.ruleset_state.recompute_ruleset_digest()
    }

    pub fn correlate_tool_event(&mut self, event_digest: [u8; 32]) {
        self.tool_event_correlations.insert(
            event_digest,
            ToolEventCorrelation {
                ruleset_digest: self.ruleset_state.ruleset_digest,
                tool_registry_digest: self.ruleset_state.tool_registry_digest,
            },
        );
    }

    pub fn correlate_registry_ruleset(&mut self, registry_digest: [u8; 32]) {
        self.registry_ruleset_correlation
            .insert(registry_digest, self.ruleset_state.ruleset_digest);
    }

    pub fn collect_replay_signals(&self, session_id: &str) -> ReplaySignals {
        let deny_count_last256 = self
            .experience_store
            .records
            .iter()
            .rev()
            .take(256)
            .filter(|record| record.record_type == RecordType::RtDecision as i32)
            .count();

        let integrity_degraded_present = self.sep_log.events.iter().any(|event| {
            event.session_id == session_id
                && event
                    .reason_codes
                    .iter()
                    .any(|rc| rc == protocol::ReasonCodes::RE_INTEGRITY_DEGRADED)
        });

        let mut latest_consistency_class = None;
        let mut consistency_counts = ConsistencyCounts::default();

        for digest in self
            .consistency_history
            .recent_for_session(session_id, CONSISTENCY_SIGNAL_WINDOW)
        {
            if let Some(feedback) = self.consistency_store.get(digest) {
                if let Ok(class) = feedback.consistency_class.parse::<ConsistencyClass>() {
                    latest_consistency_class = Some(class.clone());
                    match class {
                        ConsistencyClass::Low => consistency_counts.low_count += 1,
                        ConsistencyClass::Med => consistency_counts.med_count += 1,
                        ConsistencyClass::High => {}
                    }
                }
            }
        }

        ReplaySignals {
            deny_count_last256,
            integrity_degraded_present,
            latest_consistency_class,
            recent_consistency_counts: consistency_counts,
        }
    }

    pub fn maybe_plan_replay(
        &mut self,
        session_id: &str,
        keystore: &KeyStore,
    ) -> Result<Option<ReplayPlanOutcome>, SepError> {
        let signals = self.collect_replay_signals(session_id);
        if !should_generate_replay(session_id, signals.clone()) {
            return Ok(None);
        }

        let mut trigger_reason_codes = replay_trigger_reasons(&signals);

        if trigger_reason_codes.is_empty() {
            return Ok(None);
        }

        if let Some(latest) = self.replay_plans.latest() {
            if digest_from_bytes(&latest.head_record_digest)
                .is_some_and(|digest| digest == self.current_head_record_digest)
            {
                return Ok(None);
            }
        }

        let prefer_macro_targets = trigger_reason_codes.iter().any(|reason| {
            reason == protocol::ReasonCodes::GV_CONSISTENCY_LOW
                || reason == protocol::ReasonCodes::GV_CONSISTENCY_MED_CLUSTER
        });

        let (target_kind, target_refs) = select_replay_targets(self, prefer_macro_targets);
        if target_refs.is_empty() {
            return Ok(None);
        }

        let asset_manifest_ref = latest_asset_manifest_digest(self).map(|digest| Ref {
            id: "asset_manifest".to_string(),
            digest: Some(digest.to_vec()),
        });
        if asset_manifest_ref.is_none() {
            trigger_reason_codes.push(protocol::ReasonCodes::GV_ASSET_MISSING.to_string());
        }

        let fidelity = if signals.integrity_degraded_present {
            ReplayFidelity::Med
        } else {
            ReplayFidelity::Low
        };

        let counter = self.replay_plans.plans.len() + 1;
        let plan = build_replay_plan(BuildReplayPlanArgs {
            session_id: session_id.to_string(),
            head_experience_id: self.experience_store.head_id,
            head_record_digest: self.current_head_record_digest,
            target_kind,
            target_refs,
            fidelity,
            counter,
            trigger_reason_codes: trigger_reason_codes.clone(),
            asset_manifest_ref,
        });

        if self.replay_plans.push(plan.clone()).is_err() {
            return Ok(None);
        }

        let Some(plan_digest) = digest_from_bytes(&plan.replay_digest) else {
            return Ok(None);
        };
        self.committed_payload_digests.insert(plan_digest);

        let (receipt, proof_receipt) = issue_replay_plan_receipts(&plan, self, keystore);
        self.add_receipt_edges(&receipt);
        self.experience_store
            .proof_receipts
            .insert(plan_digest, proof_receipt.clone());

        self.record_sep_event(
            session_id,
            SepEventType::EvReplay,
            plan_digest,
            vec![protocol::ReasonCodes::GV_REPLAY_PLANNED.to_string()],
        )?;

        Ok(Some(ReplayPlanOutcome {
            plan,
            receipt,
            proof_receipt,
        }))
    }

    pub fn handle_critical_trigger(
        &mut self,
        session_id: &str,
        trig: CriticalTrigger,
    ) -> Result<SessionSeal, SepError> {
        if self.limits.max_sep_events > 0 {
            self.forensic_mode = true;
        }

        let trigger_reason = critical_trigger_reason_code(trig);
        let trigger_digest = critical_trigger_digest(session_id, trig);

        self.sep_log.append_event(
            session_id.to_string(),
            SepEventType::EvIncident,
            trigger_digest,
            vec![trigger_reason.clone()],
        )?;

        self.sep_log.append_event(
            session_id.to_string(),
            SepEventType::EvRecovery,
            trigger_digest,
            vec![
                protocol::ReasonCodes::RX_ACTION_FORENSIC.to_string(),
                trigger_reason,
            ],
        )?;

        let seal = sep::seal(session_id, &self.sep_log);
        self.auto_create_recovery_case(session_id, &seal);

        Ok(seal)
    }

    fn auto_create_recovery_case(&mut self, session_id: &str, seal: &SessionSeal) {
        let prefix: String = seal
            .final_event_digest
            .iter()
            .take(4)
            .map(|b| format!("{:02x}", b))
            .collect();

        let recovery_id = format!("recovery:{session_id}:{prefix}");
        if self.recovery_store.get(&recovery_id).is_some() {
            return;
        }

        let case = RecoveryCase {
            recovery_id,
            session_id: session_id.to_string(),
            state: RecoveryState::R0Captured,
            required_checks: vec![RecoveryCheck::IntegrityOk, RecoveryCheck::ValidationPassed],
            completed_checks: Vec::new(),
            trigger_refs: vec![seal.seal_id.clone()],
            created_at_ms: None,
        };

        let _ = self.recovery_store.insert_new(case);
    }

    fn record_sep_overflow_incident(&mut self, session_id: &str) -> Result<(), SepError> {
        let _ = self.handle_critical_trigger(session_id, CriticalTrigger::SepOverflow)?;
        Ok(())
    }

    fn maybe_trigger_replay_mismatch(
        &mut self,
        session_id: &str,
        replay_mismatch: bool,
    ) -> Result<(), SepError> {
        if self.config.auto_seal_on_replay_mismatch
            && replay_mismatch
            && self.critical_triggers.replay_mismatch
        {
            let _ = self.handle_critical_trigger(session_id, CriticalTrigger::ReplayMismatch)?;
        }

        Ok(())
    }

    fn record_sep_event(
        &mut self,
        session_id: &str,
        event_type: SepEventType,
        object_digest: [u8; 32],
        reason_codes: Vec<String>,
    ) -> Result<(), SepError> {
        let replay_mismatch = reason_codes
            .iter()
            .any(|rc| rc == protocol::ReasonCodes::RE_REPLAY_MISMATCH);

        match self.sep_log.append_event(
            session_id.to_string(),
            event_type,
            object_digest,
            reason_codes,
        ) {
            Ok(_) => self.maybe_trigger_replay_mismatch(session_id, replay_mismatch),
            Err(SepError::Overflow) => {
                self.record_sep_overflow_incident(session_id)?;
                Err(SepError::Overflow)
            }
            Err(err) => Err(err),
        }
    }

    fn record_sep_frame_event(
        &mut self,
        session_id: &str,
        kind: FrameEventKind,
        frame_digest: [u8; 32],
        reason_codes: Vec<String>,
    ) -> Result<(), SepError> {
        match self.sep_log.append_frame_event(
            session_id.to_string(),
            kind,
            frame_digest,
            reason_codes,
        ) {
            Ok(_) => Ok(()),
            Err(SepError::Overflow) => {
                self.record_sep_overflow_incident(session_id)?;
                Err(SepError::Overflow)
            }
            Err(err) => Err(err),
        }
    }

    fn log_ruleset_change(
        &mut self,
        session_id: &str,
        event_type: SepEventType,
        mut reason_codes: Vec<String>,
    ) {
        reason_codes.push(protocol::ReasonCodes::GV_RULESET_CHANGED.to_string());
        self.record_sep_event(
            session_id,
            event_type,
            self.ruleset_state.ruleset_digest,
            reason_codes,
        )
        .expect("sep log append failed");
    }

    fn log_retention_evictions(
        &mut self,
        session_id: &str,
        evicted: impl IntoIterator<Item = [u8; 32]>,
    ) {
        for digest in evicted {
            let _ = self.record_sep_event(
                session_id,
                SepEventType::EvOutcome,
                digest,
                vec!["RC.GV.RETENTION.EVICTED".to_string()],
            );
        }
    }

    fn store_prune_manifest(&mut self, head_id: u64, pruned_record_digests: Vec<[u8; 32]>) {
        let limit = self.limits.max_experience_records;
        if limit == 0 {
            return;
        }

        let prune_ops_digest = compute_prune_ops_digest(head_id, &pruned_record_digests);
        let manifest = PruneManifest {
            head_id,
            prune_ops_digest,
            pruned_record_digests,
        };
        let bytes = canonical_bincode_options()
            .serialize(&manifest)
            .expect("serialize prune manifest");
        let key = prune_manifest_key(head_id);
        self.prune_manifests.insert(key.clone(), bytes);
        self.prune_manifest_order.push_back(key.clone());

        while self.prune_manifest_order.len() > limit {
            if let Some(evicted_key) = self.prune_manifest_order.pop_front() {
                self.prune_manifests.remove(&evicted_key);
            }
        }
    }

    pub fn check_completeness(
        &mut self,
        session_id: &str,
        action_digests: Vec<[u8; 32]>,
    ) -> CompletenessReport {
        let report = {
            let mut checker = CompletenessChecker::new(
                &self.causal_graph,
                &mut self.sep_log,
                &self.dlp_store,
                &self.replay_plans,
                &self.asset_manifest_store,
                &self.asset_bundle_store,
                &self.experience_store.records,
            );
            checker.check_actions(session_id, action_digests)
        };

        for trigger in &report.critical_triggers {
            match trigger {
                CriticalTrigger::IntegrityFail => {
                    let _ =
                        self.handle_critical_trigger(session_id, CriticalTrigger::IntegrityFail);
                }
                CriticalTrigger::SepOverflow => {
                    let _ = self.handle_critical_trigger(session_id, CriticalTrigger::SepOverflow);
                }
                _ => {}
            }
        }

        report
    }

    fn add_graph_edge(
        &mut self,
        from: NodeKey,
        et: EdgeType,
        to: NodeKey,
        session_id: Option<&str>,
    ) {
        let session_id = session_id.unwrap_or(GRAPH_TRIM_SESSION_ID);
        self.causal_graph
            .add_edge(from, et, to, Some((&mut self.sep_log, session_id)));
    }

    fn add_receipt_edges(&mut self, receipt: &PVGSReceipt) {
        let receipt_digest = receipt.receipt_digest.0;
        self.receipts.insert(receipt_digest, receipt.clone());

        if !matches!(receipt.status, ReceiptStatus::Accepted) {
            return;
        }
        if let Some(decision) = optional_proto_digest(&receipt.bindings.decision_digest) {
            self.add_graph_edge(decision, EdgeType::Authorizes, receipt_digest, None);
        }

        if let Some(action) = optional_proto_digest(&receipt.bindings.action_digest) {
            self.add_graph_edge(action, EdgeType::Authorizes, receipt_digest, None);
        }

        if let Some(profile) = optional_proto_digest(&receipt.bindings.profile_digest) {
            self.add_graph_edge(profile, EdgeType::References, receipt_digest, None);
        }

        if let Some(tool_profile) = optional_proto_digest(&receipt.bindings.tool_profile_digest) {
            self.add_graph_edge(tool_profile, EdgeType::References, receipt_digest, None);
        }
    }

    fn add_record_edges(
        &mut self,
        session_id: &str,
        record_digest: [u8; 32],
        prev_record_digest: [u8; 32],
        record: &ExperienceRecord,
    ) {
        if prev_record_digest != [0u8; 32] {
            self.add_graph_edge(
                prev_record_digest,
                EdgeType::Causes,
                record_digest,
                Some(session_id),
            );
        }

        let record_type =
            RecordType::try_from(record.record_type).unwrap_or(RecordType::Unspecified);

        if matches!(record_type, RecordType::RtReplay) {
            self.add_replay_reference_edges(session_id, record_digest, record);
            self.add_frame_reference_edges(session_id, record_digest, record);
            self.add_micro_reference_edges(session_id, record_digest, record);
        } else {
            self.add_frame_reference_edges(session_id, record_digest, record);
            self.add_micro_reference_edges(session_id, record_digest, record);
        }

        match record_type {
            RecordType::RtActionExec => {
                self.add_action_exec_edges(session_id, record_digest, record)
            }
            RecordType::RtOutput => self.add_output_edges(session_id, record_digest, record),
            RecordType::RtDecision | RecordType::RtReplay => {}
            _ => {}
        }
    }

    fn add_frame_reference_edges(
        &mut self,
        session_id: &str,
        record_digest: NodeKey,
        record: &ExperienceRecord,
    ) {
        if let Some(core_ref) = &record.core_frame_ref {
            self.add_reference_edges_from_refs(
                session_id,
                record_digest,
                std::slice::from_ref(core_ref),
            );
        }

        if let Some(meta_ref) = &record.metabolic_frame_ref {
            self.add_reference_edges_from_refs(
                session_id,
                record_digest,
                std::slice::from_ref(meta_ref),
            );
        }

        if let Some(gov_ref) = &record.governance_frame_ref {
            self.add_reference_edges_from_refs(
                session_id,
                record_digest,
                std::slice::from_ref(gov_ref),
            );
        }
    }

    fn add_action_exec_edges(
        &mut self,
        session_id: &str,
        record_digest: NodeKey,
        record: &ExperienceRecord,
    ) {
        if let Some(core) = &record.core_frame {
            self.add_reference_edges_from_refs(session_id, record_digest, &core.evidence_refs);
        }

        if let Some(gov) = &record.governance_frame {
            self.add_reference_edges_from_refs(
                session_id,
                record_digest,
                &gov.policy_decision_refs,
            );

            if let Some(receipt_ref) = &gov.pvgs_receipt_ref {
                self.add_reference_edges_from_refs(
                    session_id,
                    record_digest,
                    std::slice::from_ref(receipt_ref),
                );
            }
        }

        if let Some(core_ref) = &record.core_frame_ref {
            self.add_reference_edges_from_refs(
                session_id,
                record_digest,
                std::slice::from_ref(core_ref),
            );
        }
    }

    fn add_output_edges(
        &mut self,
        session_id: &str,
        record_digest: NodeKey,
        record: &ExperienceRecord,
    ) {
        let mut dlp_refs: Vec<Ref> = Vec::new();

        if let Some(gov) = &record.governance_frame {
            dlp_refs.extend(gov.dlp_refs.clone());
        }

        if !record.dlp_refs.is_empty() {
            dlp_refs.extend(record.dlp_refs.clone());
        }

        if !dlp_refs.is_empty() {
            self.add_reference_edges_from_refs(session_id, record_digest, &dlp_refs);
        }
    }

    fn add_reference_edges_from_refs(&mut self, session_id: &str, from: NodeKey, refs: &[Ref]) {
        for reference in refs {
            if let Some(target) = digest_from_ref(reference) {
                self.add_graph_edge(from, EdgeType::References, target, Some(session_id));
            }
        }
    }

    fn add_micro_reference_edges(
        &mut self,
        session_id: &str,
        record_digest: NodeKey,
        record: &ExperienceRecord,
    ) {
        let Some(gov) = &record.governance_frame else {
            return;
        };

        let mut lc_digests = Vec::new();
        let mut sn_digests = Vec::new();
        let mut plasticity_digests = Vec::new();
        let mut lc_config_digests = Vec::new();
        let mut sn_config_digests = Vec::new();

        for reference in &gov.policy_decision_refs {
            if let Some(digest) = micro_digest_from_ref(reference, "mc:lc") {
                lc_digests.push(digest);
            }
            if let Some(digest) = micro_digest_from_ref(reference, "mc:sn") {
                sn_digests.push(digest);
            }
            if let Some(digest) = micro_digest_from_ref(reference, "mc_snap:plasticity") {
                plasticity_digests.push(digest);
            }
            if let Some(digest) = micro_digest_from_ref(reference, "mc_cfg:lc") {
                lc_config_digests.push(digest);
            }
            if let Some(digest) = micro_digest_from_ref(reference, "mc_cfg:sn") {
                sn_config_digests.push(digest);
            }
        }

        for digest in lc_digests
            .into_iter()
            .chain(sn_digests)
            .chain(plasticity_digests)
            .chain(lc_config_digests)
            .chain(sn_config_digests)
        {
            self.add_graph_edge(
                record_digest,
                EdgeType::References,
                digest,
                Some(session_id),
            );
        }
    }

    fn add_replay_reference_edges(
        &mut self,
        session_id: &str,
        record_digest: NodeKey,
        record: &ExperienceRecord,
    ) {
        let (replay_plan_digest, _) = replay_plan_digest_from_record(record);
        if let Some(digest) = replay_plan_digest {
            self.add_graph_edge(
                record_digest,
                EdgeType::References,
                digest,
                Some(session_id),
            );
        }

        if let Some(digest) = replay_run_digest_from_record(record) {
            self.add_graph_edge(
                record_digest,
                EdgeType::References,
                digest,
                Some(session_id),
            );
        }
    }

    pub fn append_record(
        &mut self,
        session_id: &str,
        record: ExperienceRecord,
        record_digest: [u8; 32],
        proof_receipt: ProofReceipt,
    ) {
        self.current_head_record_digest = record_digest;
        let evicted = self
            .experience_store
            .append(
                record,
                record_digest,
                proof_receipt,
                &mut self.sep_log,
                session_id,
            )
            .expect("sep log append failed");
        self.store_prune_manifest(self.experience_store.head_id, evicted);
    }

    #[allow(clippy::too_many_arguments)]
    pub fn commit_cbv_from_macro(
        &mut self,
        macro_milestone: &MacroMilestone,
        keystore: &KeyStore,
        vrf_engine: &VrfEngine,
        charter_version_digest: &str,
        policy_version_digest: &str,
        pev_digest: Option<[u8; 32]>,
        config: CbvDeriverConfig,
    ) -> Result<CbvCommitOutcome, CbvCommitError> {
        let state = MacroMilestoneState::try_from(macro_milestone.state)
            .unwrap_or(MacroMilestoneState::Unknown);
        if !matches!(state, MacroMilestoneState::Finalized) {
            return Err(CbvCommitError::MacroNotFinalized);
        }

        let prev_cbv = self.cbv_store.latest().cloned();
        let derived = derive_next_cbv(prev_cbv.as_ref(), macro_milestone, &config)
            .map_err(|e| CbvCommitError::Derivation(e.to_string()))?;
        let mut cbv = derived.cbv;

        if let Some(prev) = prev_cbv.as_ref() {
            if cbv.cbv_epoch <= prev.cbv_epoch {
                return Err(CbvCommitError::NonMonotonicEpoch);
            }
        }

        let prev_cbv_digest = prev_cbv
            .as_ref()
            .and_then(|c| c.cbv_digest.as_ref())
            .and_then(|d| digest_from_bytes(d))
            .unwrap_or([0u8; 32]);
        let next_cbv_digest = cbv
            .cbv_digest
            .as_ref()
            .and_then(|d| digest_from_bytes(d))
            .unwrap_or([0u8; 32]);
        let macro_digest = digest_from_bytes(&macro_milestone.macro_digest).unwrap_or([0u8; 32]);

        let verified_fields_digest = compute_cbv_verified_fields_digest(
            prev_cbv_digest,
            macro_digest,
            next_cbv_digest,
            cbv.cbv_epoch,
        );

        let (ruleset_changed, charter_or_policy_changed) =
            self.refresh_ruleset_state(charter_version_digest, policy_version_digest);
        if ruleset_changed && charter_or_policy_changed {
            self.log_ruleset_change(
                &macro_milestone.macro_id,
                SepEventType::EvCharterUpdate,
                Vec::new(),
            );
        }
        self.update_pev_digest(pev_digest);
        let ruleset_digest = self.ruleset_state.ruleset_digest;

        let vrf_digest = vrf_engine.eval_record_vrf(
            prev_cbv_digest,
            next_cbv_digest,
            charter_version_digest,
            [0u8; 32],
            keystore.current_epoch(),
        );

        let proof_receipt =
            issue_proof_receipt(ruleset_digest, verified_fields_digest, vrf_digest, keystore);

        let bindings = CommitBindings {
            action_digest: None,
            decision_digest: None,
            grant_id: None,
            charter_version_digest: charter_version_digest.to_string(),
            policy_version_digest: policy_version_digest.to_string(),
            prev_record_digest: self.current_head_record_digest,
            profile_digest: None,
            tool_profile_digest: None,
            pev_digest,
        };

        let receipt_input = ReceiptInput {
            commit_id: macro_milestone.macro_id.clone(),
            commit_type: CommitType::CbvUpdate.into(),
            bindings: (&bindings).into(),
            required_checks: vec![
                RequiredCheck::TightenOnly.into(),
                RequiredCheck::IntegrityOk.into(),
            ],
            required_receipt_kind: protocol::RequiredReceiptKind::Read,
            payload_digests: vec![next_cbv_digest, macro_digest],
            epoch_id: keystore.current_epoch(),
        };

        let receipt = issue_receipt(
            &receipt_input,
            ReceiptStatus::Accepted,
            Vec::new(),
            keystore,
        );

        self.add_receipt_edges(&receipt);

        cbv.proof_receipt_ref = Some(Ref {
            id: proof_receipt.proof_receipt_id.clone(),
            digest: None,
        });
        cbv.pvgs_attestation_key_id = keystore.current_key_id().to_string();
        let signature = keystore.signing_key().sign(&cbv_attestation_preimage(&cbv));
        cbv.pvgs_attestation_sig = signature.to_bytes().to_vec();

        let evicted = self.cbv_store.push(cbv.clone());
        if !evicted.is_empty() {
            let evicted_digests = evicted.iter().map(compute_cbv_digest).collect::<Vec<_>>();
            self.log_retention_evictions(&macro_milestone.macro_id, evicted_digests);
        }

        let mut reason_codes = vec![protocol::ReasonCodes::GV_CBV_UPDATED.to_string()];
        if !derived.applied_updates {
            reason_codes.push(protocol::ReasonCodes::GV_CBV_NO_CHANGE.to_string());
        }

        self.record_sep_event(
            &macro_milestone.macro_id,
            SepEventType::EvRecoveryGov,
            next_cbv_digest,
            reason_codes,
        )?;

        Ok(CbvCommitOutcome {
            cbv,
            receipt,
            proof_receipt,
            applied_updates: derived.applied_updates,
        })
    }

    pub fn auto_commit_next_meso(
        &mut self,
        keystore: &KeyStore,
        vrf_engine: &VrfEngine,
    ) -> Result<Option<PVGSReceipt>, AutoCommitError> {
        let mut candidates = self
            .meso_deriver
            .derive_candidates(self.micro_milestones.list());

        candidates.sort_by(|a, b| a.meso_id.cmp(&b.meso_id));
        let Some(meso) = candidates.into_iter().next() else {
            return Ok(None);
        };

        let meso_digest = digest_from_bytes(&meso.meso_digest).unwrap_or([0u8; 32]);

        let req = PvgsCommitRequest {
            commit_id: meso.meso_id.clone(),
            commit_type: CommitType::MilestoneAppend,
            bindings: CommitBindings {
                action_digest: None,
                decision_digest: None,
                grant_id: None,
                charter_version_digest: self.ruleset_state.charter_version_digest.clone(),
                policy_version_digest: self.ruleset_state.policy_version_digest.clone(),
                prev_record_digest: self.current_head_record_digest,
                profile_digest: None,
                tool_profile_digest: None,
                pev_digest: self.ruleset_state.pev_digest,
            },
            required_receipt_kind: RequiredReceiptKind::Read,
            required_checks: vec![RequiredCheck::SchemaOk],
            payload_digests: vec![meso_digest],
            epoch_id: keystore.current_epoch(),
            key_epoch: None,
            experience_record_payload: None,
            replay_run_evidence_payload: None,
            trace_run_evidence_payload: None,
            proposal_evidence_payload: None,
            proposal_activation_payload: None,
            macro_milestone: None,
            meso_milestone: Some(meso),
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

        let (receipt, _proof) = verify_meso_milestone_append(req, self, keystore, vrf_engine);
        if receipt.status == ReceiptStatus::Rejected {
            return Err(AutoCommitError::Rejected(receipt.reject_reason_codes));
        }

        Ok(Some(receipt))
    }

    pub fn auto_propose_next_macro(
        &mut self,
        keystore: &KeyStore,
        vrf_engine: &VrfEngine,
    ) -> Result<Option<PVGSReceipt>, AutoCommitError> {
        let mut candidates = self
            .macro_deriver
            .derive_candidates(self.meso_milestones.list(), self.micro_milestones.list());

        candidates.sort_by(|a, b| a.macro_id.cmp(&b.macro_id));
        let Some(macro_milestone) = candidates.into_iter().next() else {
            return Ok(None);
        };

        let macro_digest = digest_from_bytes(&macro_milestone.macro_digest).unwrap_or([0u8; 32]);
        let payload_digests = vec![macro_digest];
        let proposal = macro_proposal_from(&macro_milestone);

        let proposal_req = PvgsCommitRequest {
            commit_id: proposal.macro_id.clone(),
            commit_type: CommitType::MacroMilestonePropose,
            bindings: CommitBindings {
                action_digest: None,
                decision_digest: None,
                grant_id: None,
                charter_version_digest: self.ruleset_state.charter_version_digest.clone(),
                policy_version_digest: self.ruleset_state.policy_version_digest.clone(),
                prev_record_digest: self.current_head_record_digest,
                profile_digest: None,
                tool_profile_digest: None,
                pev_digest: self.ruleset_state.pev_digest,
            },
            required_receipt_kind: RequiredReceiptKind::Read,
            required_checks: vec![RequiredCheck::SchemaOk],
            payload_digests,
            epoch_id: keystore.current_epoch(),
            key_epoch: None,
            experience_record_payload: None,
            replay_run_evidence_payload: None,
            trace_run_evidence_payload: None,
            proposal_evidence_payload: None,
            proposal_activation_payload: None,
            macro_milestone: Some(proposal.clone()),
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

        let (proposal_receipt, _) =
            verify_macro_milestone_proposal(proposal_req, self, keystore, vrf_engine);
        if proposal_receipt.status == ReceiptStatus::Rejected {
            return Err(AutoCommitError::Rejected(
                proposal_receipt.reject_reason_codes,
            ));
        }

        self.macro_deriver.register_committed(&proposal);

        Ok(Some(proposal_receipt))
    }

    pub fn finalize_macro(
        &mut self,
        macro_id: &str,
        consistency_digest: [u8; 32],
        keystore: &KeyStore,
        vrf_engine: &VrfEngine,
    ) -> Result<Option<PVGSReceipt>, AutoCommitError> {
        let Some(mut macro_milestone) = self.macro_milestones.get_proposed(macro_id).cloned()
        else {
            return Ok(None);
        };

        let Some(feedback) = self.consistency_store.get(consistency_digest) else {
            return Err(AutoCommitError::Rejected(vec![
                protocol::ReasonCodes::RE_INTEGRITY_DEGRADED.to_string(),
            ]));
        };

        macro_milestone.state = MacroMilestoneState::Finalized as i32;
        macro_milestone.identity_anchor_flag = true;
        macro_milestone.consistency_class = feedback.consistency_class.clone();
        macro_milestone.consistency_digest = Some(consistency_digest.to_vec());
        macro_milestone
            .proof_receipt_ref
            .get_or_insert_with(Ref::default);
        macro_milestone
            .consistency_feedback_ref
            .get_or_insert_with(Ref::default);

        let macro_digest = digest_from_bytes(&macro_milestone.macro_digest).unwrap_or([0u8; 32]);
        let finalize_req = PvgsCommitRequest {
            commit_id: macro_milestone.macro_id.clone(),
            commit_type: CommitType::MacroMilestoneFinalize,
            bindings: CommitBindings {
                action_digest: None,
                decision_digest: None,
                grant_id: None,
                charter_version_digest: self.ruleset_state.charter_version_digest.clone(),
                policy_version_digest: self.ruleset_state.policy_version_digest.clone(),
                prev_record_digest: self.current_head_record_digest,
                profile_digest: None,
                tool_profile_digest: None,
                pev_digest: self.ruleset_state.pev_digest,
            },
            required_receipt_kind: RequiredReceiptKind::Read,
            required_checks: vec![RequiredCheck::SchemaOk],
            payload_digests: vec![macro_digest, consistency_digest],
            epoch_id: keystore.current_epoch(),
            key_epoch: None,
            experience_record_payload: None,
            replay_run_evidence_payload: None,
            trace_run_evidence_payload: None,
            proposal_evidence_payload: None,
            proposal_activation_payload: None,
            macro_milestone: Some(macro_milestone),
            meso_milestone: None,
            dlp_decision_payload: None,
            tool_registry_container: None,
            pev: None,
            consistency_feedback_payload: None,
            macro_consistency_digest: Some(consistency_digest),
            recovery_case: None,
            unlock_permit: None,
            tool_onboarding_event: None,
            microcircuit_config_payload: None,
            asset_manifest_payload: None,
            asset_bundle_payload: None,
        };

        let (receipt, _) =
            verify_macro_milestone_finalization(finalize_req, self, keystore, vrf_engine);
        if receipt.status == ReceiptStatus::Rejected {
            if receipt
                .reject_reason_codes
                .contains(&protocol::ReasonCodes::GE_EXEC_DISPATCH_BLOCKED.to_string())
                && self.macro_milestones.get_finalized(macro_id).is_some()
            {
                return Ok(None);
            }

            return Err(AutoCommitError::Rejected(receipt.reject_reason_codes));
        }

        Ok(Some(receipt))
    }
}

impl ExperienceStore {
    pub fn append(
        &mut self,
        record: ExperienceRecord,
        record_digest: [u8; 32],
        proof_receipt: ProofReceipt,
        sep_log: &mut SepLog,
        session_id: &str,
    ) -> Result<Vec<[u8; 32]>, SepError> {
        let limit = self.limits.max_experience_records;
        let mut evicted_digests = Vec::new();

        if limit == 0 {
            return Ok(evicted_digests);
        }

        while self.records.len() >= limit {
            if let Some(evicted) = self.records.first() {
                if let Some(evicted_digest) = evicted
                    .finalization_header
                    .as_ref()
                    .and_then(|header| digest_from_bytes(&header.record_digest))
                {
                    self.proof_receipts.remove(&evicted_digest);
                    sep_log.append_event(
                        session_id.to_string(),
                        SepEventType::EvOutcome,
                        evicted_digest,
                        vec!["RC.GV.RETENTION.EVICTED".to_string()],
                    )?;
                    evicted_digests.push(evicted_digest);
                }
            }

            self.records.remove(0);

            if let Some(latest) = self.records.last() {
                self.head_record_digest = latest
                    .finalization_header
                    .as_ref()
                    .and_then(|header| digest_from_bytes(&header.record_digest))
                    .unwrap_or([0u8; 32]);
            } else {
                self.head_record_digest = [0u8; 32];
            }
        }

        self.records.push(record);
        self.head_record_digest = record_digest;
        self.head_id = self.head_id.saturating_add(1);
        self.proof_receipts.insert(record_digest, proof_receipt);

        Ok(evicted_digests)
    }
}

/// Compute a digest over the ruleset inputs (charter + policy + optional PEV).
pub fn compute_ruleset_digest(
    charter_digest: &[u8],
    policy_digest: &[u8],
    pev_digest: Option<&[u8]>,
    tool_registry_digest: Option<&[u8]>,
) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(b"UCF:HASH:RULESET");
    hasher.update(charter_digest);
    hasher.update(policy_digest);
    hasher.update(pev_digest.unwrap_or([0u8; 32].as_slice()));
    hasher.update(tool_registry_digest.unwrap_or([0u8; 32].as_slice()));
    *hasher.finalize().as_bytes()
}

fn prune_manifest_key(head_id: u64) -> String {
    format!("{PRUNE_MANIFEST_PREFIX}/{head_id}")
}

fn compute_prune_ops_digest(head_id: u64, pruned_records: &[[u8; 32]]) -> TaggedDigest {
    let mut hasher = Hasher::new();
    hasher.update(b"UCF:PVGS:PRUNE_OPS");
    hasher.update(&head_id.to_be_bytes());
    for digest in pruned_records {
        hasher.update(digest);
    }
    TaggedDigest::new(COMMITMENT_TAG, hasher.finalize().into())
}

/// Compute the digest of fields verified during PVGS evaluation.
pub fn compute_verified_fields_digest(
    bindings: &CommitBindings,
    required_receipt_kind: RequiredReceiptKind,
) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(b"UCF:PVGS:VERIFIED_FIELDS");

    update_optional_digest(&mut hasher, &bindings.action_digest);
    update_optional_digest(&mut hasher, &bindings.decision_digest);
    update_optional_string(&mut hasher, &bindings.grant_id);
    hasher.update(bindings.charter_version_digest.as_bytes());
    hasher.update(bindings.policy_version_digest.as_bytes());
    hasher.update(&bindings.prev_record_digest);
    update_optional_digest(&mut hasher, &bindings.profile_digest);
    update_optional_digest(&mut hasher, &bindings.tool_profile_digest);
    update_optional_digest(&mut hasher, &bindings.pev_digest);
    hasher.update(required_receipt_kind_label(&required_receipt_kind).as_bytes());

    *hasher.finalize().as_bytes()
}

/// Compute the canonical digest of an experience record.
pub fn compute_experience_record_digest(record: &ExperienceRecord) -> [u8; 32] {
    let mut canonical = record.clone();
    canonical.finalization_header = None;
    let bytes = canonical.encode_to_vec();
    let mut hasher = Hasher::new();
    hasher.update(b"UCF:HASH:EXPERIENCE_RECORD");
    hasher.update(&bytes);
    *hasher.finalize().as_bytes()
}

/// Compute the verified fields digest for experience record appends.
pub fn compute_experience_verified_fields_digest(
    prev_record_digest: [u8; 32],
    record_digest: [u8; 32],
    experience_id: u64,
) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(b"UCF:HASH:VERIFIED_FIELDS");
    hasher.update(&prev_record_digest);
    hasher.update(&record_digest);
    hasher.update(&experience_id.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Compute a deterministic record digest suitable for VRF input.
pub fn compute_record_digest(
    verified_fields_digest: [u8; 32],
    prev_record_digest: [u8; 32],
    commit_id: &str,
) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(b"UCF:PVGS:RECORD_DIGEST");
    hasher.update(&verified_fields_digest);
    hasher.update(&prev_record_digest);
    hasher.update(commit_id.as_bytes());
    *hasher.finalize().as_bytes()
}

/// Compute the verified fields digest for key epoch updates.
pub fn compute_key_epoch_verified_fields_digest(
    payload_digest: [u8; 32],
    key_epoch_id: u64,
) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(b"UCF:PVGS:KEY_EPOCH_VERIFIED_FIELDS");
    hasher.update(&payload_digest);
    hasher.update(&key_epoch_id.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Compute a deterministic record digest for key epoch updates.
pub fn compute_key_epoch_record_digest(
    prev_record_digest: [u8; 32],
    payload_digest: [u8; 32],
    commit_id: &str,
) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(b"UCF:PVGS:KEY_EPOCH_RECORD_DIGEST");
    hasher.update(&prev_record_digest);
    hasher.update(&payload_digest);
    hasher.update(commit_id.as_bytes());
    *hasher.finalize().as_bytes()
}

/// Compute the verified fields digest for PEV updates.
pub fn compute_pev_verified_fields_digest(
    prev_record_digest: [u8; 32],
    pev_digest: [u8; 32],
    pev_version_digest: Option<[u8; 32]>,
    epoch_id: u64,
) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(b"UCF:PVGS:PEV_VERIFIED_FIELDS");
    hasher.update(&prev_record_digest);
    hasher.update(&pev_digest);
    update_optional_digest(&mut hasher, &pev_version_digest);
    hasher.update(&epoch_id.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Compute the verified fields digest for tool registry updates.
pub fn compute_tool_registry_verified_fields_digest(
    prev_record_digest: [u8; 32],
    registry_digest: [u8; 32],
    registry_version: &str,
) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(b"UCF:PVGS:TOOL_REGISTRY_VERIFIED_FIELDS");
    hasher.update(&prev_record_digest);
    hasher.update(&registry_digest);
    hasher.update(registry_version.as_bytes());
    *hasher.finalize().as_bytes()
}

fn compute_macro_verified_fields_digest(
    prev_record_digest: [u8; 32],
    macro_digest: [u8; 32],
    epoch_id: u64,
) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(b"UCF:PVGS:MACRO_VERIFIED_FIELDS");
    hasher.update(&prev_record_digest);
    hasher.update(&macro_digest);
    hasher.update(&epoch_id.to_le_bytes());
    *hasher.finalize().as_bytes()
}

fn compute_meso_verified_fields_digest(
    prev_record_digest: [u8; 32],
    meso_digest: [u8; 32],
    epoch_id: u64,
) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(b"UCF:PVGS:MESO_VERIFIED_FIELDS");
    hasher.update(&prev_record_digest);
    hasher.update(&meso_digest);
    hasher.update(&epoch_id.to_le_bytes());
    *hasher.finalize().as_bytes()
}

fn recovery_reason_for_error(err: RecoveryStoreError) -> String {
    match err {
        RecoveryStoreError::Duplicate | RecoveryStoreError::InvalidInitialState => {
            protocol::ReasonCodes::GV_RECOVERY_INVALID_STATE.to_string()
        }
        RecoveryStoreError::InvalidRequiredChecks | RecoveryStoreError::NonMonotonicChecks => {
            protocol::ReasonCodes::GV_RECOVERY_INVALID_CHECKS.to_string()
        }
        RecoveryStoreError::NotFound => protocol::ReasonCodes::GV_RECOVERY_UNKNOWN_CASE.to_string(),
        RecoveryStoreError::InvalidStateTransition => {
            protocol::ReasonCodes::GV_RECOVERY_INVALID_STATE.to_string()
        }
        RecoveryStoreError::SessionMismatch => {
            protocol::ReasonCodes::GV_RECOVERY_INVALID_STATE.to_string()
        }
    }
}

fn verify_recovery_case_create(
    mut req: PvgsCommitRequest,
    store: &mut PvgsStore,
    keystore: &KeyStore,
) -> (PVGSReceipt, Option<ProofReceipt>) {
    let receipt_input = to_receipt_input(&req);
    let mut reject_reason_codes = Vec::new();

    let Some(case) = req.recovery_case.take() else {
        reject_reason_codes.push(protocol::ReasonCodes::GV_RECOVERY_INVALID_STATE.to_string());
        return finalize_receipt(FinalizeReceiptArgs {
            req: &req,
            receipt_input: &receipt_input,
            status: ReceiptStatus::Rejected,
            reject_reason_codes,
            store,
            keystore,
            frame_kind: None,
            event_object_digest: None,
            event_reason_codes: None,
        });
    };

    if case.trigger_refs.is_empty() {
        reject_reason_codes.push(protocol::ReasonCodes::GV_RECOVERY_INVALID_STATE.to_string());
    }

    if reject_reason_codes.is_empty() {
        if let Err(err) = store.recovery_store.insert_new(case) {
            reject_reason_codes.push(recovery_reason_for_error(err));
        }
    }

    let status = if reject_reason_codes.is_empty() {
        ReceiptStatus::Accepted
    } else {
        ReceiptStatus::Rejected
    };

    let event_reason_codes = if matches!(status, ReceiptStatus::Accepted) {
        Some(vec![protocol::ReasonCodes::GV_RECOVERY_CREATED.to_string()])
    } else {
        None
    };

    finalize_receipt(FinalizeReceiptArgs {
        req: &req,
        receipt_input: &receipt_input,
        status,
        reject_reason_codes,
        store,
        keystore,
        frame_kind: None,
        event_object_digest: None,
        event_reason_codes,
    })
}

fn verify_recovery_case_advance(
    mut req: PvgsCommitRequest,
    store: &mut PvgsStore,
    keystore: &KeyStore,
) -> (PVGSReceipt, Option<ProofReceipt>) {
    let receipt_input = to_receipt_input(&req);
    let mut reject_reason_codes = Vec::new();

    let Some(case) = req.recovery_case.take() else {
        reject_reason_codes.push(protocol::ReasonCodes::GV_RECOVERY_INVALID_STATE.to_string());
        return finalize_receipt(FinalizeReceiptArgs {
            req: &req,
            receipt_input: &receipt_input,
            status: ReceiptStatus::Rejected,
            reject_reason_codes,
            store,
            keystore,
            frame_kind: None,
            event_object_digest: None,
            event_reason_codes: None,
        });
    };

    if let Err(err) = store.recovery_store.update(case) {
        reject_reason_codes.push(recovery_reason_for_error(err));
    }

    let status = if reject_reason_codes.is_empty() {
        ReceiptStatus::Accepted
    } else {
        ReceiptStatus::Rejected
    };

    let event_reason_codes = if matches!(status, ReceiptStatus::Accepted) {
        Some(vec![protocol::ReasonCodes::GV_RECOVERY_ADVANCED.to_string()])
    } else {
        None
    };

    finalize_receipt(FinalizeReceiptArgs {
        req: &req,
        receipt_input: &receipt_input,
        status,
        reject_reason_codes,
        store,
        keystore,
        frame_kind: None,
        event_object_digest: None,
        event_reason_codes,
    })
}

fn verify_recovery_approval(
    mut req: PvgsCommitRequest,
    store: &mut PvgsStore,
    keystore: &KeyStore,
) -> (PVGSReceipt, Option<ProofReceipt>) {
    let receipt_input = to_receipt_input(&req);
    let mut reject_reason_codes = Vec::new();

    let Some(mut permit_payload) = req.unlock_permit.take() else {
        reject_reason_codes.push(protocol::ReasonCodes::GV_RECOVERY_INVALID_STATE.to_string());
        return finalize_receipt(FinalizeReceiptArgs {
            req: &req,
            receipt_input: &receipt_input,
            status: ReceiptStatus::Rejected,
            reject_reason_codes,
            store,
            keystore,
            frame_kind: None,
            event_object_digest: None,
            event_reason_codes: None,
        });
    };

    let Some(case) = store
        .recovery_store
        .get_active_for_session(&permit_payload.session_id)
    else {
        reject_reason_codes.push(protocol::ReasonCodes::GV_RECOVERY_UNKNOWN_CASE.to_string());
        return finalize_receipt(FinalizeReceiptArgs {
            req: &req,
            receipt_input: &receipt_input,
            status: ReceiptStatus::Rejected,
            reject_reason_codes,
            store,
            keystore,
            frame_kind: None,
            event_object_digest: None,
            event_reason_codes: None,
        });
    };

    if case.state < RecoveryState::R5Approved {
        reject_reason_codes.push(protocol::ReasonCodes::GV_RECOVERY_INVALID_STATE.to_string());
    }

    if permit_payload.permit_digest == [0u8; 32] {
        permit_payload = UnlockPermit::new(
            permit_payload.session_id.clone(),
            permit_payload.issued_at_ms,
            store.ruleset_state.ruleset_digest,
        );
    } else {
        permit_payload.ruleset_digest = store.ruleset_state.ruleset_digest;
    }

    let required_checks = [RecoveryCheck::IntegrityOk, RecoveryCheck::ValidationPassed];
    let has_required_checks = required_checks
        .iter()
        .all(|chk| case.completed_checks.contains(chk));

    if !has_required_checks {
        reject_reason_codes.push(protocol::ReasonCodes::GV_RECOVERY_INVALID_CHECKS.to_string());
    }

    let status = if reject_reason_codes.is_empty() {
        store
            .unlock_permits
            .insert(permit_payload.session_id.clone(), permit_payload.clone());
        ReceiptStatus::Accepted
    } else {
        ReceiptStatus::Rejected
    };

    let event_reason_codes = if matches!(status, ReceiptStatus::Accepted) {
        Some(vec![
            protocol::ReasonCodes::GV_RECOVERY_UNLOCK_GRANTED.to_string()
        ])
    } else {
        None
    };

    finalize_receipt(FinalizeReceiptArgs {
        req: &req,
        receipt_input: &receipt_input,
        status,
        reject_reason_codes,
        store,
        keystore,
        frame_kind: None,
        event_object_digest: None,
        event_reason_codes,
    })
}

fn event_type_for_commit(
    commit_type: CommitType,
    frame_kind: Option<FrameEventKind>,
) -> SepEventType {
    match commit_type {
        CommitType::ReceiptRequest => SepEventType::EvDecision,
        CommitType::KeyEpochUpdate => SepEventType::EvKeyEpoch,
        CommitType::PevUpdate => SepEventType::EvPevUpdate,
        CommitType::ToolRegistryUpdate => SepEventType::EvToolOnboarding,
        CommitType::ToolOnboardingEventAppend => SepEventType::EvToolOnboarding,
        CommitType::ExperienceRecordAppend => SepEventType::EvIntent,
        CommitType::DlpDecisionAppend => SepEventType::EvDlpDecision,
        CommitType::ReplayPlanAppend => SepEventType::EvReplay,
        CommitType::ReplayRunEvidenceAppend => SepEventType::EvReplay,
        CommitType::TraceRunEvidenceAppend => SepEventType::EvReplay,
        CommitType::ProposalEvidenceAppend => SepEventType::EvAgentStep,
        CommitType::ProposalActivationAppend => SepEventType::EvAgentStep,
        CommitType::RecoveryCaseCreate => SepEventType::EvRecoveryGov,
        CommitType::RecoveryCaseAdvance => SepEventType::EvRecoveryGov,
        CommitType::RecoveryApproval => SepEventType::EvRecoveryGov,
        CommitType::ConsistencyFeedbackAppend => SepEventType::EvRecoveryGov,
        CommitType::MacroMilestonePropose => SepEventType::EvRecoveryGov,
        CommitType::MacroMilestoneFinalize => SepEventType::EvRecoveryGov,
        CommitType::MicrocircuitConfigAppend => SepEventType::EvRecoveryGov,
        CommitType::AssetManifestAppend => SepEventType::EvRecoveryGov,
        CommitType::AssetBundleAppend => SepEventType::EvRecoveryGov,
        CommitType::FrameEvidenceAppend => match frame_kind {
            Some(FrameEventKind::ControlFrame) => SepEventType::EvControlFrame,
            Some(FrameEventKind::SignalFrame) => SepEventType::EvSignalFrame,
            None => SepEventType::EvRecoveryGov,
        },
        _ => SepEventType::EvRecoveryGov,
    }
}

fn select_replay_targets(store: &PvgsStore, prefer_macro: bool) -> (ReplayTargetKind, Vec<Ref>) {
    let micro_refs = latest_micro_refs(store);
    let meso_ref = latest_meso_ref(store);
    let macro_ref = latest_macro_ref(store);

    if prefer_macro {
        if let Some(reference) = macro_ref {
            return (ReplayTargetKind::Macro, vec![reference]);
        }

        if let Some(reference) = meso_ref {
            return (ReplayTargetKind::Meso, vec![reference]);
        }

        if !micro_refs.is_empty() {
            return (ReplayTargetKind::Micro, micro_refs);
        }
    } else {
        if !micro_refs.is_empty() {
            return (ReplayTargetKind::Micro, micro_refs);
        }

        if let Some(reference) = meso_ref {
            return (ReplayTargetKind::Meso, vec![reference]);
        }

        if let Some(reference) = macro_ref {
            return (ReplayTargetKind::Macro, vec![reference]);
        }
    }

    (ReplayTargetKind::Unspecified, Vec::new())
}

fn latest_asset_manifest_digest(store: &PvgsStore) -> Option<[u8; 32]> {
    let mut manifests: Vec<AssetManifest> = store.asset_manifest_store.list().to_vec();
    manifests.sort_by(|a, b| {
        a.created_at_ms
            .cmp(&b.created_at_ms)
            .then_with(|| a.manifest_digest.cmp(&b.manifest_digest))
    });
    manifests
        .pop()
        .and_then(|manifest| digest_from_bytes(&manifest.manifest_digest))
}

fn latest_micro_refs(store: &PvgsStore) -> Vec<Ref> {
    let mut micro_refs: Vec<Ref> = store
        .micro_milestones
        .list()
        .iter()
        .rev()
        .take(2)
        .filter_map(|micro| digest_from_bytes(&micro.micro_digest))
        .map(ref_from_digest)
        .collect();

    micro_refs.sort_by(|a, b| a.id.cmp(&b.id));
    micro_refs
}

fn latest_meso_ref(store: &PvgsStore) -> Option<Ref> {
    store
        .meso_milestones
        .latest()
        .and_then(|meso| digest_from_bytes(&meso.meso_digest))
        .map(ref_from_digest)
}

fn latest_macro_ref(store: &PvgsStore) -> Option<Ref> {
    if let Some(finalized) = store.macro_milestones.latest_finalized() {
        if let Some(digest) = digest_from_bytes(&finalized.macro_digest) {
            return Some(ref_from_digest(digest));
        }
    }

    let mut proposals = store.macro_milestones.list_proposed();
    proposals.sort_by(|a, b| a.macro_id.cmp(&b.macro_id));

    proposals
        .last()
        .and_then(|proposal| digest_from_bytes(&proposal.macro_digest))
        .map(ref_from_digest)
}

fn issue_replay_plan_receipts(
    plan: &ReplayPlan,
    store: &PvgsStore,
    keystore: &KeyStore,
) -> (PVGSReceipt, ProofReceipt) {
    let bindings = CommitBindings {
        action_digest: None,
        decision_digest: None,
        grant_id: None,
        charter_version_digest: store.ruleset_state.charter_version_digest.clone(),
        policy_version_digest: store.ruleset_state.policy_version_digest.clone(),
        prev_record_digest: store.current_head_record_digest,
        profile_digest: None,
        tool_profile_digest: None,
        pev_digest: store.ruleset_state.pev_digest,
    };

    let payload_digest = digest_from_bytes(&plan.replay_digest).unwrap_or([0u8; 32]);
    let receipt_input = ReceiptInput {
        commit_id: plan.replay_id.clone(),
        commit_type: protocol::CommitType::ReplayPlanAppend,
        bindings: protocol::CommitBindings::from(&bindings),
        required_checks: Vec::new(),
        required_receipt_kind: RequiredReceiptKind::Write,
        payload_digests: vec![payload_digest],
        epoch_id: keystore.current_epoch(),
    };

    let receipt = issue_receipt(
        &receipt_input,
        ReceiptStatus::Accepted,
        Vec::new(),
        keystore,
    );

    let verified_fields_digest =
        compute_verified_fields_digest(&bindings, RequiredReceiptKind::Write);
    let mut proof_receipt = issue_proof_receipt(
        store.ruleset_state.ruleset_digest,
        verified_fields_digest,
        [0u8; 32],
        keystore,
    );
    proof_receipt.receipt_digest = receipt.receipt_digest.clone();

    (receipt, proof_receipt)
}

fn frame_event_kind_for_request(req: &PvgsCommitRequest) -> FrameEventKind {
    if req.bindings.profile_digest.is_some() {
        FrameEventKind::ControlFrame
    } else {
        FrameEventKind::SignalFrame
    }
}

fn to_receipt_input(req: &PvgsCommitRequest) -> ReceiptInput {
    ReceiptInput {
        commit_id: req.commit_id.clone(),
        commit_type: req.commit_type.into(),
        bindings: (&req.bindings).into(),
        required_checks: req
            .required_checks
            .iter()
            .copied()
            .map(Into::into)
            .collect(),
        required_receipt_kind: req.required_receipt_kind,
        payload_digests: req.payload_digests.clone(),
        epoch_id: req.epoch_id,
    }
}

fn macro_source_ref_id(macro_milestone: &MacroMilestone) -> String {
    format!(
        "{}:{}",
        macro_milestone.macro_id,
        hex::encode(&macro_milestone.macro_digest)
    )
}

/// Verify a commit request and emit attested receipts.
pub fn verify_and_commit(
    req: PvgsCommitRequest,
    store: &mut PvgsStore,
    keystore: &KeyStore,
    vrf_engine: &VrfEngine,
) -> (PVGSReceipt, Option<ProofReceipt>) {
    if matches!(
        req.commit_type,
        CommitType::MilestoneAppend
            | CommitType::MacroMilestonePropose
            | CommitType::MacroMilestoneFinalize
    ) {
        if req.meso_milestone.is_some() {
            return verify_meso_milestone_append(req, store, keystore, vrf_engine);
        }

        return match req.commit_type {
            CommitType::MacroMilestoneFinalize => {
                verify_macro_milestone_finalization(req, store, keystore, vrf_engine)
            }
            CommitType::MilestoneAppend => {
                let is_proposal = req
                    .macro_milestone
                    .as_ref()
                    .and_then(|m| MacroMilestoneState::try_from(m.state).ok())
                    .is_some_and(|state| state == MacroMilestoneState::Proposed);

                if is_proposal {
                    verify_macro_milestone_proposal(req, store, keystore, vrf_engine)
                } else {
                    verify_macro_milestone_finalization(req, store, keystore, vrf_engine)
                }
            }
            _ => verify_macro_milestone_proposal(req, store, keystore, vrf_engine),
        };
    }

    if req.commit_type == CommitType::PevUpdate {
        return verify_pev_update(req, store, keystore, vrf_engine);
    }

    if req.commit_type == CommitType::ToolRegistryUpdate {
        return verify_tool_registry_update(req, store, keystore, vrf_engine);
    }

    if req.commit_type == CommitType::ToolOnboardingEventAppend {
        return verify_tool_event_append(req, store, keystore);
    }

    if req.commit_type == CommitType::ExperienceRecordAppend {
        return verify_experience_record_append(req, store, keystore, vrf_engine);
    }

    if req.commit_type == CommitType::ConsistencyFeedbackAppend {
        return verify_consistency_feedback_append(req, store, keystore, vrf_engine);
    }

    if req.commit_type == CommitType::DlpDecisionAppend {
        return verify_dlp_decision_append(req, store, keystore);
    }

    if req.commit_type == CommitType::MicrocircuitConfigAppend {
        return verify_microcircuit_config_append(req, store, keystore);
    }

    if req.commit_type == CommitType::AssetManifestAppend {
        return verify_asset_manifest_append(req, store, keystore);
    }

    if req.commit_type == CommitType::AssetBundleAppend {
        return verify_asset_bundle_append(req, store, keystore);
    }

    if req.commit_type == CommitType::ReplayRunEvidenceAppend {
        return verify_replay_run_evidence_append(req, store, keystore);
    }

    if req.commit_type == CommitType::TraceRunEvidenceAppend {
        return verify_trace_run_evidence_append(req, store, keystore);
    }

    if req.commit_type == CommitType::ProposalEvidenceAppend {
        return verify_proposal_evidence_append(req, store, keystore);
    }

    if req.commit_type == CommitType::ProposalActivationAppend {
        return verify_proposal_activation_append(req, store, keystore);
    }

    if req.commit_type == CommitType::RecoveryCaseCreate {
        return verify_recovery_case_create(req, store, keystore);
    }

    if req.commit_type == CommitType::RecoveryCaseAdvance {
        return verify_recovery_case_advance(req, store, keystore);
    }

    if req.commit_type == CommitType::RecoveryApproval {
        return verify_recovery_approval(req, store, keystore);
    }

    let receipt_input = to_receipt_input(&req);
    let mut reject_reason_codes = Vec::new();
    let key_epoch_event_digest = if req.commit_type == CommitType::KeyEpochUpdate {
        key_epoch_payload_digest(&req)
    } else {
        None
    };
    let frame_event_kind = (req.commit_type == CommitType::FrameEvidenceAppend)
        .then(|| frame_event_kind_for_request(&req));

    if req.epoch_id != keystore.current_epoch() {
        reject_reason_codes.push(protocol::ReasonCodes::RE_INTEGRITY_DEGRADED.to_string());
        return finalize_receipt(FinalizeReceiptArgs {
            req: &req,
            receipt_input: &receipt_input,
            status: ReceiptStatus::Rejected,
            reject_reason_codes,
            store,
            keystore,
            frame_kind: frame_event_kind,
            event_object_digest: key_epoch_event_digest,
            event_reason_codes: None,
        });
    }

    if req.bindings.prev_record_digest != store.current_head_record_digest {
        reject_reason_codes.push(protocol::ReasonCodes::GE_EXEC_DISPATCH_BLOCKED.to_string());
        return finalize_receipt(FinalizeReceiptArgs {
            req: &req,
            receipt_input: &receipt_input,
            status: ReceiptStatus::Rejected,
            reject_reason_codes,
            store,
            keystore,
            frame_kind: frame_event_kind,
            event_object_digest: key_epoch_event_digest,
            event_reason_codes: None,
        });
    }

    if !store
        .known_charter_versions
        .contains(&req.bindings.charter_version_digest)
    {
        reject_reason_codes.push(protocol::ReasonCodes::PB_DENY_CHARTER_SCOPE.to_string());
        return finalize_receipt(FinalizeReceiptArgs {
            req: &req,
            receipt_input: &receipt_input,
            status: ReceiptStatus::Rejected,
            reject_reason_codes,
            store,
            keystore,
            frame_kind: frame_event_kind,
            event_object_digest: key_epoch_event_digest,
            event_reason_codes: None,
        });
    }

    if !store
        .known_policy_versions
        .contains(&req.bindings.policy_version_digest)
    {
        reject_reason_codes.push(protocol::ReasonCodes::PB_DENY_INTEGRITY_REQUIRED.to_string());
        return finalize_receipt(FinalizeReceiptArgs {
            req: &req,
            receipt_input: &receipt_input,
            status: ReceiptStatus::Rejected,
            reject_reason_codes,
            store,
            keystore,
            frame_kind: frame_event_kind,
            event_object_digest: key_epoch_event_digest,
            event_reason_codes: None,
        });
    }

    if req.commit_type == CommitType::FrameEvidenceAppend {
        let mut frame_reject_reason_codes = Vec::new();
        let has_required_checks = req.required_checks.contains(&RequiredCheck::SchemaOk)
            && req.required_checks.contains(&RequiredCheck::BindingOk);

        if !has_required_checks {
            frame_reject_reason_codes
                .push(protocol::ReasonCodes::GV_FRAME_EVIDENCE_REQUIRED_CHECK.to_string());
        }

        if req.payload_digests.len() != 1 {
            frame_reject_reason_codes
                .push(protocol::ReasonCodes::GV_FRAME_EVIDENCE_PAYLOAD_INVALID.to_string());
        }

        if !frame_reject_reason_codes.is_empty() {
            return finalize_receipt(FinalizeReceiptArgs {
                req: &req,
                receipt_input: &receipt_input,
                status: ReceiptStatus::Rejected,
                reject_reason_codes: frame_reject_reason_codes,
                store,
                keystore,
                frame_kind: frame_event_kind,
                event_object_digest: key_epoch_event_digest,
                event_reason_codes: None,
            });
        }
    }

    if req.commit_type == CommitType::ReceiptRequest
        && (req.bindings.action_digest.is_none()
            || req.bindings.decision_digest.is_none()
            || req.bindings.grant_id.is_none())
    {
        reject_reason_codes.push(protocol::ReasonCodes::GE_GRANT_MISSING.to_string());
        return finalize_receipt(FinalizeReceiptArgs {
            req: &req,
            receipt_input: &receipt_input,
            status: ReceiptStatus::Rejected,
            reject_reason_codes,
            store,
            keystore,
            frame_kind: frame_event_kind,
            event_object_digest: key_epoch_event_digest,
            event_reason_codes: None,
        });
    }

    if req.commit_type == CommitType::ReceiptRequest
        && matches!(
            req.required_receipt_kind,
            RequiredReceiptKind::Write
                | RequiredReceiptKind::Execute
                | RequiredReceiptKind::Export
                | RequiredReceiptKind::Persist
        )
    {
        if req.bindings.tool_profile_digest.is_none() {
            reject_reason_codes.push(protocol::ReasonCodes::GE_EXEC_DISPATCH_BLOCKED.to_string());
        }

        if req.bindings.profile_digest.is_none() {
            reject_reason_codes.push(protocol::ReasonCodes::GE_EXEC_DISPATCH_BLOCKED.to_string());
        }

        if !reject_reason_codes.is_empty() {
            return finalize_receipt(FinalizeReceiptArgs {
                req: &req,
                receipt_input: &receipt_input,
                status: ReceiptStatus::Rejected,
                reject_reason_codes,
                store,
                keystore,
                frame_kind: frame_event_kind,
                event_object_digest: key_epoch_event_digest,
                event_reason_codes: None,
            });
        }
    }

    let mut key_epoch_context: Option<(PVGSKeyEpoch, [u8; 32])> = None;

    if req.commit_type == CommitType::KeyEpochUpdate {
        match validate_key_epoch_update(&req, store) {
            Ok(ctx) => key_epoch_context = Some(ctx),
            Err(reasons) => {
                reject_reason_codes = reasons;
                return finalize_receipt(FinalizeReceiptArgs {
                    req: &req,
                    receipt_input: &receipt_input,
                    status: ReceiptStatus::Rejected,
                    reject_reason_codes,
                    store,
                    keystore,
                    frame_kind: frame_event_kind,
                    event_object_digest: key_epoch_payload_digest(&req),
                    event_reason_codes: None,
                });
            }
        }
    }

    let (verified_fields_digest, record_digest) =
        match (req.commit_type, key_epoch_context.as_ref()) {
            (CommitType::KeyEpochUpdate, Some((key_epoch, payload_digest))) => (
                compute_key_epoch_verified_fields_digest(*payload_digest, key_epoch.key_epoch_id),
                compute_key_epoch_record_digest(
                    req.bindings.prev_record_digest,
                    *payload_digest,
                    &req.commit_id,
                ),
            ),
            _ => {
                let verified_fields_digest =
                    compute_verified_fields_digest(&req.bindings, req.required_receipt_kind);
                (
                    verified_fields_digest,
                    compute_record_digest(
                        verified_fields_digest,
                        req.bindings.prev_record_digest,
                        &req.commit_id,
                    ),
                )
            }
        };

    let receipt = issue_receipt(
        &receipt_input,
        ReceiptStatus::Accepted,
        reject_reason_codes.clone(),
        keystore,
    );

    store.add_receipt_edges(&receipt);

    let vrf_digest = vrf_engine.eval_record_vrf(
        req.bindings.prev_record_digest,
        record_digest,
        &req.bindings.charter_version_digest,
        req.bindings.profile_digest.unwrap_or([0u8; 32]),
        req.epoch_id,
    );

    let (ruleset_changed, charter_or_policy_changed) = store.refresh_ruleset_state(
        &req.bindings.charter_version_digest,
        &req.bindings.policy_version_digest,
    );
    if ruleset_changed && charter_or_policy_changed {
        store.log_ruleset_change(&req.commit_id, SepEventType::EvCharterUpdate, Vec::new());
    }
    if req.bindings.pev_digest.is_some() {
        store.update_pev_digest(req.bindings.pev_digest);
    }

    let mut proof_receipt = issue_proof_receipt(
        store.ruleset_state.ruleset_digest,
        verified_fields_digest,
        vrf_digest,
        keystore,
    );
    proof_receipt.receipt_digest = receipt.receipt_digest.clone();

    if let Some((ref key_epoch, payload_digest)) = key_epoch_context {
        store
            .key_epoch_history
            .push(key_epoch.clone())
            .expect("validation enforces monotonic key epochs");
        store.committed_payload_digests.insert(payload_digest);
    }

    let frame_payload_digest = if req.commit_type == CommitType::FrameEvidenceAppend {
        req.payload_digests.first().copied()
    } else {
        None
    };

    let event_object_digest = if let Some((_, payload_digest)) = key_epoch_context.as_ref() {
        *payload_digest
    } else if let Some(frame_digest) = frame_payload_digest {
        frame_digest
    } else {
        receipt.receipt_digest.0
    };
    let event_type = event_type_for_commit(req.commit_type, frame_event_kind);

    if matches!(req.commit_type, CommitType::FrameEvidenceAppend) {
        let kind = frame_event_kind.unwrap_or(FrameEventKind::SignalFrame);
        let _ = store.record_sep_frame_event(
            &req.commit_id,
            kind,
            event_object_digest,
            receipt.reject_reason_codes.clone(),
        );
    } else {
        let _ = store.record_sep_event(
            &req.commit_id,
            event_type,
            event_object_digest,
            receipt.reject_reason_codes.clone(),
        );
    }

    (receipt, Some(proof_receipt))
}

fn verify_macro_milestone_proposal(
    mut req: PvgsCommitRequest,
    store: &mut PvgsStore,
    keystore: &KeyStore,
    vrf_engine: &VrfEngine,
) -> (PVGSReceipt, Option<ProofReceipt>) {
    let mut reject_reason_codes = Vec::new();
    let receipt_input = to_receipt_input(&req);
    if req.epoch_id != keystore.current_epoch() {
        reject_reason_codes.push(protocol::ReasonCodes::RE_INTEGRITY_DEGRADED.to_string());
        return finalize_receipt(FinalizeReceiptArgs {
            req: &req,
            receipt_input: &receipt_input,
            status: ReceiptStatus::Rejected,
            reject_reason_codes,
            store,
            keystore,
            frame_kind: None,
            event_object_digest: None,
            event_reason_codes: None,
        });
    }

    if req.bindings.prev_record_digest != store.current_head_record_digest {
        reject_reason_codes.push(protocol::ReasonCodes::GE_EXEC_DISPATCH_BLOCKED.to_string());
        return finalize_receipt(FinalizeReceiptArgs {
            req: &req,
            receipt_input: &receipt_input,
            status: ReceiptStatus::Rejected,
            reject_reason_codes,
            store,
            keystore,
            frame_kind: None,
            event_object_digest: None,
            event_reason_codes: None,
        });
    }

    if !store
        .known_charter_versions
        .contains(&req.bindings.charter_version_digest)
    {
        reject_reason_codes.push(protocol::ReasonCodes::PB_DENY_CHARTER_SCOPE.to_string());
        return finalize_receipt(FinalizeReceiptArgs {
            req: &req,
            receipt_input: &receipt_input,
            status: ReceiptStatus::Rejected,
            reject_reason_codes,
            store,
            keystore,
            frame_kind: None,
            event_object_digest: None,
            event_reason_codes: None,
        });
    }

    if !store
        .known_policy_versions
        .contains(&req.bindings.policy_version_digest)
    {
        reject_reason_codes.push(protocol::ReasonCodes::PB_DENY_INTEGRITY_REQUIRED.to_string());
        return finalize_receipt(FinalizeReceiptArgs {
            req: &req,
            receipt_input: &receipt_input,
            status: ReceiptStatus::Rejected,
            reject_reason_codes,
            store,
            keystore,
            frame_kind: None,
            event_object_digest: None,
            event_reason_codes: None,
        });
    }

    let Some(mut macro_milestone) = req.macro_milestone.clone() else {
        reject_reason_codes.push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
        return finalize_receipt(FinalizeReceiptArgs {
            req: &req,
            receipt_input: &receipt_input,
            status: ReceiptStatus::Rejected,
            reject_reason_codes,
            store,
            keystore,
            frame_kind: None,
            event_object_digest: None,
            event_reason_codes: None,
        });
    };

    let macro_digest = digest_from_bytes(&macro_milestone.macro_digest).unwrap_or([0u8; 32]);

    if req.payload_digests.is_empty() {
        req.payload_digests = vec![macro_digest];
    } else if req.payload_digests.len() != 1 || req.payload_digests[0] != macro_digest {
        reject_reason_codes.push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
    }

    if let Err(err) = validate_macro_proposal(&macro_milestone) {
        reject_reason_codes.push(reason_code_for_macro_error(err));
    }

    if !reject_reason_codes.is_empty() {
        return finalize_receipt(FinalizeReceiptArgs {
            req: &req,
            receipt_input: &receipt_input,
            status: ReceiptStatus::Rejected,
            reject_reason_codes,
            store,
            keystore,
            frame_kind: None,
            event_object_digest: Some(macro_digest),
            event_reason_codes: None,
        });
    }

    let (ruleset_changed, charter_or_policy_changed) = store.refresh_ruleset_state(
        &req.bindings.charter_version_digest,
        &req.bindings.policy_version_digest,
    );
    if ruleset_changed && charter_or_policy_changed {
        store.log_ruleset_change(&req.commit_id, SepEventType::EvCharterUpdate, Vec::new());
    }

    let verified_fields_digest = compute_macro_verified_fields_digest(
        req.bindings.prev_record_digest,
        macro_digest,
        req.epoch_id,
    );

    let vrf_digest = vrf_engine.eval_record_vrf(
        req.bindings.prev_record_digest,
        macro_digest,
        &req.bindings.charter_version_digest,
        req.bindings.profile_digest.unwrap_or([0u8; 32]),
        req.epoch_id,
    );

    let mut proof_receipt = issue_proof_receipt(
        store.ruleset_state.ruleset_digest,
        verified_fields_digest,
        vrf_digest,
        keystore,
    );

    macro_milestone.proof_receipt_ref = Some(Ref {
        id: proof_receipt.proof_receipt_id.clone(),
        digest: None,
    });

    let receipt = issue_receipt(
        &receipt_input,
        ReceiptStatus::Accepted,
        reject_reason_codes.clone(),
        keystore,
    );

    proof_receipt.receipt_digest = receipt.receipt_digest.clone();

    if let Err(err) = store
        .macro_milestones
        .insert_proposal(macro_milestone.clone())
    {
        reject_reason_codes.push(reason_code_for_macro_error(err));
        return finalize_receipt(FinalizeReceiptArgs {
            req: &req,
            receipt_input: &receipt_input,
            status: ReceiptStatus::Rejected,
            reject_reason_codes,
            store,
            keystore,
            frame_kind: None,
            event_object_digest: Some(macro_digest),
            event_reason_codes: Some(vec![protocol::ReasonCodes::GV_MACRO_PROPOSED.to_string()]),
        });
    }

    store.committed_payload_digests.insert(macro_digest);
    store.add_receipt_edges(&receipt);

    let _ = store.record_sep_event(
        &req.commit_id,
        SepEventType::EvRecoveryGov,
        macro_digest,
        vec![protocol::ReasonCodes::GV_MACRO_PROPOSED.to_string()],
    );

    (receipt, Some(proof_receipt))
}

fn verify_macro_milestone_finalization(
    mut req: PvgsCommitRequest,
    store: &mut PvgsStore,
    keystore: &KeyStore,
    vrf_engine: &VrfEngine,
) -> (PVGSReceipt, Option<ProofReceipt>) {
    let mut reject_reason_codes = Vec::new();
    let receipt_input = to_receipt_input(&req);

    if req.epoch_id != keystore.current_epoch() {
        reject_reason_codes.push(protocol::ReasonCodes::RE_INTEGRITY_DEGRADED.to_string());
        return finalize_receipt(FinalizeReceiptArgs {
            req: &req,
            receipt_input: &receipt_input,
            status: ReceiptStatus::Rejected,
            reject_reason_codes,
            store,
            keystore,
            frame_kind: None,
            event_object_digest: None,
            event_reason_codes: None,
        });
    }

    if req.bindings.prev_record_digest != store.current_head_record_digest {
        reject_reason_codes.push(protocol::ReasonCodes::GE_EXEC_DISPATCH_BLOCKED.to_string());
        return finalize_receipt(FinalizeReceiptArgs {
            req: &req,
            receipt_input: &receipt_input,
            status: ReceiptStatus::Rejected,
            reject_reason_codes,
            store,
            keystore,
            frame_kind: None,
            event_object_digest: None,
            event_reason_codes: None,
        });
    }

    if !store
        .known_charter_versions
        .contains(&req.bindings.charter_version_digest)
    {
        reject_reason_codes.push(protocol::ReasonCodes::PB_DENY_CHARTER_SCOPE.to_string());
        return finalize_receipt(FinalizeReceiptArgs {
            req: &req,
            receipt_input: &receipt_input,
            status: ReceiptStatus::Rejected,
            reject_reason_codes,
            store,
            keystore,
            frame_kind: None,
            event_object_digest: None,
            event_reason_codes: None,
        });
    }

    if !store
        .known_policy_versions
        .contains(&req.bindings.policy_version_digest)
    {
        reject_reason_codes.push(protocol::ReasonCodes::PB_DENY_INTEGRITY_REQUIRED.to_string());
        return finalize_receipt(FinalizeReceiptArgs {
            req: &req,
            receipt_input: &receipt_input,
            status: ReceiptStatus::Rejected,
            reject_reason_codes,
            store,
            keystore,
            frame_kind: None,
            event_object_digest: None,
            event_reason_codes: None,
        });
    }

    let Some(mut macro_milestone) = req.macro_milestone.clone() else {
        reject_reason_codes.push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
        return finalize_receipt(FinalizeReceiptArgs {
            req: &req,
            receipt_input: &receipt_input,
            status: ReceiptStatus::Rejected,
            reject_reason_codes,
            store,
            keystore,
            frame_kind: None,
            event_object_digest: None,
            event_reason_codes: None,
        });
    };

    let macro_digest = digest_from_bytes(&macro_milestone.macro_digest).unwrap_or([0u8; 32]);
    let Some(consistency_digest) = req.macro_consistency_digest else {
        reject_reason_codes.push(protocol::ReasonCodes::RE_INTEGRITY_DEGRADED.to_string());
        return finalize_receipt(FinalizeReceiptArgs {
            req: &req,
            receipt_input: &receipt_input,
            status: ReceiptStatus::Rejected,
            reject_reason_codes,
            store,
            keystore,
            frame_kind: None,
            event_object_digest: Some(macro_digest),
            event_reason_codes: None,
        });
    };

    if req.payload_digests.is_empty() {
        req.payload_digests = vec![macro_digest, consistency_digest];
    } else if req.payload_digests.len() < 2
        || !req.payload_digests.contains(&macro_digest)
        || !req.payload_digests.contains(&consistency_digest)
    {
        reject_reason_codes.push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
    }

    if store
        .macro_milestones
        .get_finalized(&macro_milestone.macro_id)
        .is_some()
    {
        reject_reason_codes.push(protocol::ReasonCodes::RE_INTEGRITY_DEGRADED.to_string());
    }

    let Some(feedback) = store.consistency_store.get(consistency_digest).cloned() else {
        reject_reason_codes.push(protocol::ReasonCodes::RE_INTEGRITY_DEGRADED.to_string());
        return finalize_receipt(FinalizeReceiptArgs {
            req: &req,
            receipt_input: &receipt_input,
            status: ReceiptStatus::Rejected,
            reject_reason_codes,
            store,
            keystore,
            frame_kind: None,
            event_object_digest: Some(macro_digest),
            event_reason_codes: None,
        });
    };

    macro_milestone.state = MacroMilestoneState::Finalized as i32;
    macro_milestone.identity_anchor_flag = true;
    macro_milestone.consistency_class = feedback.consistency_class.clone();
    macro_milestone.macro_digest = macro_digest.to_vec();
    macro_milestone.consistency_digest = Some(consistency_digest.to_vec());
    macro_milestone.consistency_feedback_ref =
        macro_milestone.consistency_feedback_ref.or_else(|| {
            Some(Ref {
                id: hex::encode(consistency_digest),
                digest: None,
            })
        });
    macro_milestone
        .proof_receipt_ref
        .get_or_insert_with(Ref::default);

    let (ruleset_changed, charter_or_policy_changed) = store.refresh_ruleset_state(
        &req.bindings.charter_version_digest,
        &req.bindings.policy_version_digest,
    );
    if ruleset_changed && charter_or_policy_changed {
        store.log_ruleset_change(&req.commit_id, SepEventType::EvCharterUpdate, Vec::new());
    }

    if let Err(err) = validate_macro_finalization(&macro_milestone, &feedback) {
        reject_reason_codes.push(reason_code_for_macro_error(err));
    }

    if !reject_reason_codes.is_empty() {
        return finalize_receipt(FinalizeReceiptArgs {
            req: &req,
            receipt_input: &receipt_input,
            status: ReceiptStatus::Rejected,
            reject_reason_codes,
            store,
            keystore,
            frame_kind: None,
            event_object_digest: Some(macro_digest),
            event_reason_codes: None,
        });
    }

    let verified_fields_digest = compute_macro_verified_fields_digest(
        req.bindings.prev_record_digest,
        macro_digest,
        req.epoch_id,
    );

    let vrf_digest = vrf_engine.eval_record_vrf(
        req.bindings.prev_record_digest,
        macro_digest,
        &req.bindings.charter_version_digest,
        req.bindings.profile_digest.unwrap_or([0u8; 32]),
        req.epoch_id,
    );

    let mut proof_receipt = issue_proof_receipt(
        store.ruleset_state.ruleset_digest,
        verified_fields_digest,
        vrf_digest,
        keystore,
    );

    macro_milestone.proof_receipt_ref = Some(Ref {
        id: proof_receipt.proof_receipt_id.clone(),
        digest: None,
    });

    let receipt = issue_receipt(
        &receipt_input,
        ReceiptStatus::Accepted,
        reject_reason_codes.clone(),
        keystore,
    );

    proof_receipt.receipt_digest = receipt.receipt_digest.clone();

    if let Err(err) = store
        .macro_milestones
        .finalize(macro_milestone.clone(), &feedback)
    {
        reject_reason_codes.push(reason_code_for_macro_error(err));
        return finalize_receipt(FinalizeReceiptArgs {
            req: &req,
            receipt_input: &receipt_input,
            status: ReceiptStatus::Rejected,
            reject_reason_codes,
            store,
            keystore,
            frame_kind: None,
            event_object_digest: Some(macro_digest),
            event_reason_codes: Some(vec![protocol::ReasonCodes::GV_MACRO_FINALIZED.to_string()]),
        });
    }

    store.add_receipt_edges(&receipt);
    store.macro_deriver.register_committed(&macro_milestone);
    store.committed_payload_digests.insert(consistency_digest);
    store.committed_payload_digests.insert(macro_digest);

    add_macro_edges(
        store,
        macro_digest,
        &macro_milestone,
        Some(consistency_digest),
    );

    let _ = store.record_sep_event(
        &req.commit_id,
        SepEventType::EvRecoveryGov,
        macro_digest,
        vec![
            protocol::ReasonCodes::GV_MACRO_FINALIZED.to_string(),
            protocol::ReasonCodes::GV_CONSISTENCY_APPENDED.to_string(),
        ],
    );

    attempt_cbv_update_from_macro(store, keystore, vrf_engine, macro_milestone, macro_digest);

    (receipt, Some(proof_receipt))
}

fn verify_meso_milestone_append(
    mut req: PvgsCommitRequest,
    store: &mut PvgsStore,
    keystore: &KeyStore,
    vrf_engine: &VrfEngine,
) -> (PVGSReceipt, Option<ProofReceipt>) {
    let mut reject_reason_codes = Vec::new();
    let receipt_input = to_receipt_input(&req);

    if req.epoch_id != keystore.current_epoch() {
        reject_reason_codes.push(protocol::ReasonCodes::RE_INTEGRITY_DEGRADED.to_string());
        return finalize_receipt(FinalizeReceiptArgs {
            req: &req,
            receipt_input: &receipt_input,
            status: ReceiptStatus::Rejected,
            reject_reason_codes,
            store,
            keystore,
            frame_kind: None,
            event_object_digest: None,
            event_reason_codes: None,
        });
    }

    if req.bindings.prev_record_digest != store.current_head_record_digest {
        reject_reason_codes.push(protocol::ReasonCodes::GE_EXEC_DISPATCH_BLOCKED.to_string());
        return finalize_receipt(FinalizeReceiptArgs {
            req: &req,
            receipt_input: &receipt_input,
            status: ReceiptStatus::Rejected,
            reject_reason_codes,
            store,
            keystore,
            frame_kind: None,
            event_object_digest: None,
            event_reason_codes: None,
        });
    }

    if !store
        .known_charter_versions
        .contains(&req.bindings.charter_version_digest)
    {
        reject_reason_codes.push(protocol::ReasonCodes::PB_DENY_CHARTER_SCOPE.to_string());
        return finalize_receipt(FinalizeReceiptArgs {
            req: &req,
            receipt_input: &receipt_input,
            status: ReceiptStatus::Rejected,
            reject_reason_codes,
            store,
            keystore,
            frame_kind: None,
            event_object_digest: None,
            event_reason_codes: None,
        });
    }

    if !store
        .known_policy_versions
        .contains(&req.bindings.policy_version_digest)
    {
        reject_reason_codes.push(protocol::ReasonCodes::PB_DENY_INTEGRITY_REQUIRED.to_string());
        return finalize_receipt(FinalizeReceiptArgs {
            req: &req,
            receipt_input: &receipt_input,
            status: ReceiptStatus::Rejected,
            reject_reason_codes,
            store,
            keystore,
            frame_kind: None,
            event_object_digest: None,
            event_reason_codes: None,
        });
    }

    let Some(mut meso_milestone) = req.meso_milestone.clone() else {
        reject_reason_codes.push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
        return finalize_receipt(FinalizeReceiptArgs {
            req: &req,
            receipt_input: &receipt_input,
            status: ReceiptStatus::Rejected,
            reject_reason_codes,
            store,
            keystore,
            frame_kind: None,
            event_object_digest: None,
            event_reason_codes: None,
        });
    };

    let meso_digest = digest_from_bytes(&meso_milestone.meso_digest).unwrap_or([0u8; 32]);
    let recomputed_digest = compute_meso_digest(&meso_milestone).0;

    if meso_digest == [0u8; 32] || meso_digest != recomputed_digest {
        reject_reason_codes.push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
    }

    if req.payload_digests.is_empty() {
        req.payload_digests = vec![meso_digest];
    } else if req.payload_digests.len() != 1 || req.payload_digests[0] != meso_digest {
        reject_reason_codes.push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
    }

    if !reject_reason_codes.is_empty() {
        return finalize_receipt(FinalizeReceiptArgs {
            req: &req,
            receipt_input: &receipt_input,
            status: ReceiptStatus::Rejected,
            reject_reason_codes,
            store,
            keystore,
            frame_kind: None,
            event_object_digest: Some(meso_digest),
            event_reason_codes: None,
        });
    }

    let (ruleset_changed, charter_or_policy_changed) = store.refresh_ruleset_state(
        &req.bindings.charter_version_digest,
        &req.bindings.policy_version_digest,
    );
    if ruleset_changed && charter_or_policy_changed {
        store.log_ruleset_change(&req.commit_id, SepEventType::EvCharterUpdate, Vec::new());
    }

    let verified_fields_digest = compute_meso_verified_fields_digest(
        req.bindings.prev_record_digest,
        meso_digest,
        req.epoch_id,
    );
    let vrf_digest = vrf_engine.eval_record_vrf(
        req.bindings.prev_record_digest,
        meso_digest,
        &req.bindings.charter_version_digest,
        req.bindings.profile_digest.unwrap_or([0u8; 32]),
        req.epoch_id,
    );

    let ruleset_digest = store.ruleset_state.ruleset_digest;
    let proof_receipt =
        issue_proof_receipt(ruleset_digest, verified_fields_digest, vrf_digest, keystore);

    meso_milestone.proof_receipt_ref = Some(Ref {
        id: proof_receipt.proof_receipt_id.clone(),
        digest: None,
    });

    let receipt = issue_receipt(
        &receipt_input,
        ReceiptStatus::Accepted,
        Vec::new(),
        keystore,
    );

    if let Err(err) = store.meso_milestones.push(meso_milestone.clone()) {
        return finalize_receipt(FinalizeReceiptArgs {
            req: &req,
            receipt_input: &receipt_input,
            status: ReceiptStatus::Rejected,
            reject_reason_codes: vec![err.to_string()],
            store,
            keystore,
            frame_kind: None,
            event_object_digest: Some(meso_digest),
            event_reason_codes: None,
        });
    }

    store.add_receipt_edges(&receipt);
    store.meso_deriver.register_committed(&meso_milestone);

    let _ = store.record_sep_event(
        &req.commit_id,
        SepEventType::EvRecoveryGov,
        meso_digest,
        vec!["RC.GV.MILESTONE.MESO_APPENDED".to_string()],
    );

    (receipt, Some(proof_receipt))
}

fn attempt_cbv_update_from_macro(
    store: &mut PvgsStore,
    keystore: &KeyStore,
    vrf_engine: &VrfEngine,
    macro_milestone: MacroMilestone,
    macro_digest: [u8; 32],
) {
    if cbv_update_already_applied(store, &macro_milestone) {
        let _ = store.record_sep_event(
            &macro_milestone.macro_id,
            SepEventType::EvRecoveryGov,
            macro_digest,
            vec![protocol::ReasonCodes::GV_CBV_NO_OP.to_string()],
        );
        return;
    }

    let charter_version = store.ruleset_state.charter_version_digest.clone();
    let policy_version = store.ruleset_state.policy_version_digest.clone();
    let pev_digest = store.ruleset_state.pev_digest;
    let cbv_config = CbvDeriverConfig::default();
    match store.commit_cbv_from_macro(
        &macro_milestone,
        keystore,
        vrf_engine,
        &charter_version,
        &policy_version,
        pev_digest,
        cbv_config,
    ) {
        Ok(outcome) => {
            store.committed_payload_digests.insert(
                outcome
                    .cbv
                    .cbv_digest
                    .as_deref()
                    .and_then(digest_from_bytes)
                    .unwrap_or([0u8; 32]),
            );
        }
        Err(_) => {
            let _ = store.record_sep_event(
                &macro_milestone.macro_id,
                SepEventType::EvRecoveryGov,
                macro_digest,
                vec![
                    protocol::ReasonCodes::RE_INTEGRITY_DEGRADED.to_string(),
                    protocol::ReasonCodes::GV_CBV_UPDATE_FAILED.to_string(),
                ],
            );
        }
    }
}

fn cbv_update_already_applied(store: &PvgsStore, macro_milestone: &MacroMilestone) -> bool {
    let source_id = macro_source_ref_id(macro_milestone);
    store
        .cbv_store
        .latest()
        .is_some_and(|cbv| cbv.source_milestone_refs.iter().any(|r| r.id == source_id))
}

fn verify_pev_update(
    mut req: PvgsCommitRequest,
    store: &mut PvgsStore,
    keystore: &KeyStore,
    vrf_engine: &VrfEngine,
) -> (PVGSReceipt, Option<ProofReceipt>) {
    let Some(pev) = req.pev.clone() else {
        let receipt_input = to_receipt_input(&req);
        return finalize_receipt(FinalizeReceiptArgs {
            req: &req,
            receipt_input: &receipt_input,
            status: ReceiptStatus::Rejected,
            reject_reason_codes: vec![
                protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string()
            ],
            store,
            keystore,
            frame_kind: None,
            event_object_digest: None,
            event_reason_codes: None,
        });
    };

    let mut reject_reason_codes = Vec::new();
    let Some(pev_digest) = extract_pev_digest(&pev) else {
        reject_reason_codes.push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
        let receipt_input = to_receipt_input(&req);
        return finalize_receipt(FinalizeReceiptArgs {
            req: &req,
            receipt_input: &receipt_input,
            status: ReceiptStatus::Rejected,
            reject_reason_codes,
            store,
            keystore,
            frame_kind: None,
            event_object_digest: None,
            event_reason_codes: None,
        });
    };

    if req.payload_digests.is_empty() {
        req.payload_digests = vec![pev_digest];
    } else if req.payload_digests.len() != 1 || req.payload_digests[0] != pev_digest {
        reject_reason_codes.push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
    }

    req.bindings.pev_digest = Some(pev_digest);

    let receipt_input = to_receipt_input(&req);

    let has_required_checks = req.required_checks.contains(&RequiredCheck::SchemaOk)
        && req.required_checks.contains(&RequiredCheck::BindingOk);
    if !has_required_checks {
        reject_reason_codes.push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
    }

    if req.epoch_id != keystore.current_epoch() {
        reject_reason_codes.push(protocol::ReasonCodes::RE_INTEGRITY_DEGRADED.to_string());
    }

    if req.bindings.prev_record_digest != store.current_head_record_digest {
        reject_reason_codes.push(protocol::ReasonCodes::GE_EXEC_DISPATCH_BLOCKED.to_string());
    }

    if store.pev_store.validate_pev(&pev).is_err() {
        reject_reason_codes.push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
    }

    if !reject_reason_codes.is_empty() {
        return finalize_receipt(FinalizeReceiptArgs {
            req: &req,
            receipt_input: &receipt_input,
            status: ReceiptStatus::Rejected,
            reject_reason_codes,
            store,
            keystore,
            frame_kind: None,
            event_object_digest: Some(pev_digest),
            event_reason_codes: None,
        });
    }

    let verified_fields_digest = compute_pev_verified_fields_digest(
        req.bindings.prev_record_digest,
        pev_digest,
        pev.pev_version_digest
            .as_deref()
            .and_then(digest_from_bytes),
        req.epoch_id,
    );

    let receipt = issue_receipt(
        &receipt_input,
        ReceiptStatus::Accepted,
        reject_reason_codes.clone(),
        keystore,
    );

    let vrf_digest = vrf_engine.eval_record_vrf(
        req.bindings.prev_record_digest,
        pev_digest,
        &req.bindings.charter_version_digest,
        req.bindings.profile_digest.unwrap_or([0u8; 32]),
        req.epoch_id,
    );

    let (ruleset_changed, charter_or_policy_changed) = store.refresh_ruleset_state(
        &req.bindings.charter_version_digest,
        &req.bindings.policy_version_digest,
    );
    if ruleset_changed && charter_or_policy_changed {
        store.log_ruleset_change(&req.commit_id, SepEventType::EvCharterUpdate, Vec::new());
    }
    let ruleset_changed = store.update_pev_digest(Some(pev_digest));

    let mut proof_receipt = issue_proof_receipt(
        store.ruleset_state.ruleset_digest,
        verified_fields_digest,
        vrf_digest,
        keystore,
    );
    proof_receipt.receipt_digest = receipt.receipt_digest.clone();

    let evicted_pevs = store
        .pev_store
        .push(pev)
        .expect("validated PEV must be insertable");
    if !evicted_pevs.is_empty() {
        let evicted_digests = evicted_pevs
            .iter()
            .filter_map(extract_pev_digest)
            .collect::<Vec<_>>();
        store.log_retention_evictions(&req.commit_id, evicted_digests);
    }
    store.committed_payload_digests.insert(pev_digest);

    if ruleset_changed {
        store.log_ruleset_change(
            &req.commit_id,
            SepEventType::EvPevUpdate,
            vec![protocol::ReasonCodes::GV_PEV_UPDATED.to_string()],
        );
    }

    (receipt, Some(proof_receipt))
}

fn verify_tool_registry_update(
    mut req: PvgsCommitRequest,
    store: &mut PvgsStore,
    keystore: &KeyStore,
    vrf_engine: &VrfEngine,
) -> (PVGSReceipt, Option<ProofReceipt>) {
    let Some(payload) = req.tool_registry_container.clone() else {
        return finalize_receipt(FinalizeReceiptArgs {
            req: &req,
            receipt_input: &to_receipt_input(&req),
            status: ReceiptStatus::Rejected,
            reject_reason_codes: vec![
                protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string()
            ],
            store,
            keystore,
            frame_kind: None,
            event_object_digest: None,
            event_reason_codes: None,
        });
    };

    let Ok(container) = ToolRegistryContainer::decode(payload.as_slice()) else {
        let receipt_input = to_receipt_input(&req);
        return finalize_receipt(FinalizeReceiptArgs {
            req: &req,
            receipt_input: &receipt_input,
            status: ReceiptStatus::Rejected,
            reject_reason_codes: vec![
                protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string()
            ],
            store,
            keystore,
            frame_kind: None,
            event_object_digest: None,
            event_reason_codes: None,
        });
    };

    let Some(registry_digest) = digest_from_bytes(&container.registry_digest) else {
        let receipt_input = to_receipt_input(&req);
        return finalize_receipt(FinalizeReceiptArgs {
            req: &req,
            receipt_input: &receipt_input,
            status: ReceiptStatus::Rejected,
            reject_reason_codes: vec![
                protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string()
            ],
            store,
            keystore,
            frame_kind: None,
            event_object_digest: None,
            event_reason_codes: None,
        });
    };

    let mut reject_reason_codes = Vec::new();

    if req.payload_digests.is_empty() {
        req.payload_digests = vec![registry_digest];
    } else if req.payload_digests.len() != 1 || req.payload_digests[0] != registry_digest {
        reject_reason_codes.push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
    }

    let receipt_input = to_receipt_input(&req);

    if !req.required_checks.contains(&RequiredCheck::SchemaOk)
        || !req.required_checks.contains(&RequiredCheck::BindingOk)
    {
        reject_reason_codes.push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
    }

    if req.epoch_id != keystore.current_epoch() {
        reject_reason_codes.push(protocol::ReasonCodes::RE_INTEGRITY_DEGRADED.to_string());
    }

    if req.bindings.prev_record_digest != store.current_head_record_digest {
        reject_reason_codes.push(protocol::ReasonCodes::GE_EXEC_DISPATCH_BLOCKED.to_string());
    }

    if container.registry_version.is_empty() {
        reject_reason_codes.push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
    }

    if store.tool_registry_state.history.contains(&registry_digest) {
        reject_reason_codes.push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
    }

    if !reject_reason_codes.is_empty() {
        return finalize_receipt(FinalizeReceiptArgs {
            req: &req,
            receipt_input: &receipt_input,
            status: ReceiptStatus::Rejected,
            reject_reason_codes,
            store,
            keystore,
            frame_kind: None,
            event_object_digest: Some(registry_digest),
            event_reason_codes: None,
        });
    }

    if let Err(err) = store.tool_registry_state.set_current(registry_digest) {
        let reason = match err {
            ToolRegistryError::DuplicateDigest => {
                protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string()
            }
        };

        return finalize_receipt(FinalizeReceiptArgs {
            req: &req,
            receipt_input: &receipt_input,
            status: ReceiptStatus::Rejected,
            reject_reason_codes: vec![reason],
            store,
            keystore,
            frame_kind: None,
            event_object_digest: Some(registry_digest),
            event_reason_codes: None,
        });
    }

    let verified_fields_digest = compute_tool_registry_verified_fields_digest(
        req.bindings.prev_record_digest,
        registry_digest,
        &container.registry_version,
    );
    let record_digest = compute_record_digest(
        verified_fields_digest,
        req.bindings.prev_record_digest,
        &req.commit_id,
    );

    let vrf_digest = vrf_engine.eval_record_vrf(
        req.bindings.prev_record_digest,
        record_digest,
        &req.bindings.charter_version_digest,
        req.bindings.profile_digest.unwrap_or([0u8; 32]),
        req.epoch_id,
    );

    let (ruleset_changed, charter_or_policy_changed) = store.refresh_ruleset_state(
        &req.bindings.charter_version_digest,
        &req.bindings.policy_version_digest,
    );
    if ruleset_changed && charter_or_policy_changed {
        store.log_ruleset_change(&req.commit_id, SepEventType::EvCharterUpdate, Vec::new());
    }
    let tool_ruleset_changed =
        store.update_tool_registry_digest(store.tool_registry_state.current());
    if let Some(digest) = store.tool_registry_state.current() {
        store.correlate_registry_ruleset(digest);
    }
    let effective_tool_change =
        tool_ruleset_changed || (ruleset_changed && !charter_or_policy_changed);

    let receipt = issue_receipt(
        &receipt_input,
        ReceiptStatus::Accepted,
        Vec::new(),
        keystore,
    );

    store.add_receipt_edges(&receipt);

    store.committed_payload_digests.insert(registry_digest);

    let mut proof_receipt = issue_proof_receipt(
        store.ruleset_state.ruleset_digest,
        verified_fields_digest,
        vrf_digest,
        keystore,
    );
    proof_receipt.receipt_digest = receipt.receipt_digest.clone();

    if effective_tool_change {
        store.log_ruleset_change(
            &req.commit_id,
            SepEventType::EvToolOnboarding,
            vec![protocol::ReasonCodes::GV_TOOL_REGISTRY_UPDATED.to_string()],
        );
    }

    (receipt, Some(proof_receipt))
}

fn verify_experience_record_append(
    mut req: PvgsCommitRequest,
    store: &mut PvgsStore,
    keystore: &KeyStore,
    vrf_engine: &VrfEngine,
) -> (PVGSReceipt, Option<ProofReceipt>) {
    let payload_digest = req
        .experience_record_payload
        .as_ref()
        .map(|payload| *blake3::hash(payload).as_bytes());
    if let Some(digest) = payload_digest {
        req.payload_digests = vec![digest];
    }

    let receipt_input = to_receipt_input(&req);
    let mut reject_reason_codes = Vec::new();

    if req.epoch_id != keystore.current_epoch() {
        reject_reason_codes.push(protocol::ReasonCodes::RE_INTEGRITY_DEGRADED.to_string());
        return finalize_receipt(FinalizeReceiptArgs {
            req: &req,
            receipt_input: &receipt_input,
            status: ReceiptStatus::Rejected,
            reject_reason_codes,
            store,
            keystore,
            frame_kind: None,
            event_object_digest: payload_digest,
            event_reason_codes: None,
        });
    }

    if req.bindings.prev_record_digest != store.current_head_record_digest {
        reject_reason_codes.push(protocol::ReasonCodes::GE_EXEC_DISPATCH_BLOCKED.to_string());
        return finalize_receipt(FinalizeReceiptArgs {
            req: &req,
            receipt_input: &receipt_input,
            status: ReceiptStatus::Rejected,
            reject_reason_codes,
            store,
            keystore,
            frame_kind: None,
            event_object_digest: payload_digest,
            event_reason_codes: None,
        });
    }

    if !store
        .known_charter_versions
        .contains(&req.bindings.charter_version_digest)
    {
        reject_reason_codes.push(protocol::ReasonCodes::PB_DENY_CHARTER_SCOPE.to_string());
        return finalize_receipt(FinalizeReceiptArgs {
            req: &req,
            receipt_input: &receipt_input,
            status: ReceiptStatus::Rejected,
            reject_reason_codes,
            store,
            keystore,
            frame_kind: None,
            event_object_digest: payload_digest,
            event_reason_codes: None,
        });
    }

    if !store
        .known_policy_versions
        .contains(&req.bindings.policy_version_digest)
    {
        reject_reason_codes.push(protocol::ReasonCodes::PB_DENY_INTEGRITY_REQUIRED.to_string());
        return finalize_receipt(FinalizeReceiptArgs {
            req: &req,
            receipt_input: &receipt_input,
            status: ReceiptStatus::Rejected,
            reject_reason_codes,
            store,
            keystore,
            frame_kind: None,
            event_object_digest: payload_digest,
            event_reason_codes: None,
        });
    }

    let payload = match req.experience_record_payload.take() {
        Some(p) => p,
        None => {
            reject_reason_codes
                .push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
            return finalize_receipt(FinalizeReceiptArgs {
                req: &req,
                receipt_input: &receipt_input,
                status: ReceiptStatus::Rejected,
                reject_reason_codes,
                store,
                keystore,
                frame_kind: None,
                event_object_digest: payload_digest,
                event_reason_codes: None,
            });
        }
    };

    let mut record = match ExperienceRecord::decode(payload.as_slice()) {
        Ok(record) => record,
        Err(_) => {
            reject_reason_codes
                .push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
            return finalize_receipt(FinalizeReceiptArgs {
                req: &req,
                receipt_input: &receipt_input,
                status: ReceiptStatus::Rejected,
                reject_reason_codes,
                store,
                keystore,
                frame_kind: None,
                event_object_digest: payload_digest,
                event_reason_codes: None,
            });
        }
    };

    if let Err(reasons) = validate_experience_record(&record, store) {
        return finalize_receipt(FinalizeReceiptArgs {
            req: &req,
            receipt_input: &receipt_input,
            status: ReceiptStatus::Rejected,
            reject_reason_codes: reasons,
            store,
            keystore,
            frame_kind: None,
            event_object_digest: payload_digest,
            event_reason_codes: None,
        });
    }

    let record_digest = compute_experience_record_digest(&record);
    let experience_id = store.experience_store.head_id.saturating_add(1);
    let key_epoch_id = keystore.current_epoch();
    let mut finalization_header =
        build_finalization_header(&req, record_digest, experience_id, key_epoch_id);

    let verified_fields_digest = compute_experience_verified_fields_digest(
        store.current_head_record_digest,
        record_digest,
        experience_id,
    );

    let profile_digest = profile_digest_from_record(&record).unwrap_or([0u8; 32]);
    let vrf_digest = vrf_engine.eval_record_vrf(
        store.current_head_record_digest,
        record_digest,
        &finalization_header.charter_version_digest,
        profile_digest,
        key_epoch_id,
    );

    let receipt = issue_receipt(
        &receipt_input,
        ReceiptStatus::Accepted,
        reject_reason_codes.clone(),
        keystore,
    );

    store.add_receipt_edges(&receipt);

    let (ruleset_changed, charter_or_policy_changed) = store.refresh_ruleset_state(
        &finalization_header.charter_version_digest,
        &finalization_header.policy_version_digest,
    );
    if ruleset_changed && charter_or_policy_changed {
        store.log_ruleset_change(&req.commit_id, SepEventType::EvCharterUpdate, Vec::new());
    }
    if req.bindings.pev_digest.is_some() {
        store.update_pev_digest(req.bindings.pev_digest);
    }

    let mut proof_receipt = issue_proof_receipt(
        store.ruleset_state.ruleset_digest,
        verified_fields_digest,
        vrf_digest,
        keystore,
    );
    proof_receipt.receipt_digest = receipt.receipt_digest.clone();

    finalization_header.proof_receipt_ref = Some(Ref {
        id: proof_receipt.proof_receipt_id.clone(),
        digest: None,
    });
    finalization_header.prev_record_digest = digest_to_vec(store.current_head_record_digest);
    finalization_header.record_digest = digest_to_vec(record_digest);
    record.finalization_header = Some(finalization_header);

    store.add_record_edges(
        &req.commit_id,
        record_digest,
        req.bindings.prev_record_digest,
        &record,
    );
    log_experience_events(&req.commit_id, record_digest, &record, store);
    store.append_record(&req.commit_id, record, record_digest, proof_receipt.clone());

    (receipt, Some(proof_receipt))
}

fn verify_consistency_feedback_append(
    mut req: PvgsCommitRequest,
    store: &mut PvgsStore,
    keystore: &KeyStore,
    vrf_engine: &VrfEngine,
) -> (PVGSReceipt, Option<ProofReceipt>) {
    let payload = match req.consistency_feedback_payload.take() {
        Some(payload) => payload,
        None => {
            let receipt_input = to_receipt_input(&req);
            return finalize_receipt(FinalizeReceiptArgs {
                req: &req,
                receipt_input: &receipt_input,
                status: ReceiptStatus::Rejected,
                reject_reason_codes: vec![
                    protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string()
                ],
                store,
                keystore,
                frame_kind: None,
                event_object_digest: None,
                event_reason_codes: None,
            });
        }
    };

    let payload_digest = *blake3::hash(&payload).as_bytes();
    if req.payload_digests.is_empty() {
        req.payload_digests = vec![payload_digest];
    }

    let receipt_input = to_receipt_input(&req);
    let mut reject_reason_codes = Vec::new();

    if req.payload_digests.len() != 1 || req.payload_digests[0] != payload_digest {
        reject_reason_codes.push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
    }

    if req.epoch_id != keystore.current_epoch() {
        reject_reason_codes.push(protocol::ReasonCodes::RE_INTEGRITY_DEGRADED.to_string());
    }

    if req.bindings.prev_record_digest != store.current_head_record_digest {
        reject_reason_codes.push(protocol::ReasonCodes::GE_EXEC_DISPATCH_BLOCKED.to_string());
    }

    if !req
        .required_checks
        .iter()
        .any(|check| matches!(check, RequiredCheck::SchemaOk))
    {
        reject_reason_codes.push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
    }

    if !store
        .known_charter_versions
        .contains(&req.bindings.charter_version_digest)
    {
        reject_reason_codes.push(protocol::ReasonCodes::PB_DENY_CHARTER_SCOPE.to_string());
    }

    if !store
        .known_policy_versions
        .contains(&req.bindings.policy_version_digest)
    {
        reject_reason_codes.push(protocol::ReasonCodes::PB_DENY_INTEGRITY_REQUIRED.to_string());
    }

    let feedback = match ConsistencyFeedback::decode(payload.as_slice()) {
        Ok(feedback) => feedback,
        Err(_) => {
            reject_reason_codes
                .push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
            return finalize_receipt(FinalizeReceiptArgs {
                req: &req,
                receipt_input: &receipt_input,
                status: ReceiptStatus::Rejected,
                reject_reason_codes,
                store,
                keystore,
                frame_kind: None,
                event_object_digest: Some(payload_digest),
                event_reason_codes: None,
            });
        }
    };

    let (sanitized_feedback, cf_digest) = match validate_feedback(feedback) {
        Ok(result) => result,
        Err(_) => {
            reject_reason_codes
                .push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
            return finalize_receipt(FinalizeReceiptArgs {
                req: &req,
                receipt_input: &receipt_input,
                status: ReceiptStatus::Rejected,
                reject_reason_codes,
                store,
                keystore,
                frame_kind: None,
                event_object_digest: Some(payload_digest),
                event_reason_codes: None,
            });
        }
    };

    if store.committed_payload_digests.contains(&payload_digest) {
        reject_reason_codes.push(protocol::ReasonCodes::RE_REPLAY_MISMATCH.to_string());
    }

    if !reject_reason_codes.is_empty() {
        return finalize_receipt(FinalizeReceiptArgs {
            req: &req,
            receipt_input: &receipt_input,
            status: ReceiptStatus::Rejected,
            reject_reason_codes,
            store,
            keystore,
            frame_kind: None,
            event_object_digest: Some(cf_digest),
            event_reason_codes: None,
        });
    }

    store.refresh_ruleset_state(
        &req.bindings.charter_version_digest,
        &req.bindings.policy_version_digest,
    );

    let verified_fields_digest =
        compute_verified_fields_digest(&req.bindings, req.required_receipt_kind);
    let record_digest = compute_record_digest(
        verified_fields_digest,
        req.bindings.prev_record_digest,
        &req.commit_id,
    );
    let vrf_digest = vrf_engine.eval_record_vrf(
        req.bindings.prev_record_digest,
        record_digest,
        &req.bindings.charter_version_digest,
        req.bindings.profile_digest.unwrap_or([0u8; 32]),
        req.epoch_id,
    );

    let mut proof_receipt = issue_proof_receipt(
        store.ruleset_state.ruleset_digest,
        verified_fields_digest,
        vrf_digest,
        keystore,
    );

    let receipt = issue_receipt(
        &receipt_input,
        ReceiptStatus::Accepted,
        Vec::new(),
        keystore,
    );

    proof_receipt.receipt_digest = receipt.receipt_digest.clone();

    store.add_receipt_edges(&receipt);
    store
        .consistency_store
        .insert(sanitized_feedback)
        .expect("validated feedback");
    store
        .consistency_history
        .push(req.commit_id.clone(), cf_digest);
    store.committed_payload_digests.insert(payload_digest);

    let _ = store.record_sep_event(
        &req.commit_id,
        SepEventType::EvRecoveryGov,
        cf_digest,
        vec![protocol::ReasonCodes::GV_CONSISTENCY_APPENDED.to_string()],
    );

    (receipt, Some(proof_receipt))
}

fn verify_dlp_decision_append(
    mut req: PvgsCommitRequest,
    store: &mut PvgsStore,
    keystore: &KeyStore,
) -> (PVGSReceipt, Option<ProofReceipt>) {
    let payload = match req.dlp_decision_payload.take() {
        Some(payload) => payload,
        None => {
            let receipt_input = to_receipt_input(&req);
            return finalize_receipt(FinalizeReceiptArgs {
                req: &req,
                receipt_input: &receipt_input,
                status: ReceiptStatus::Rejected,
                reject_reason_codes: vec![
                    protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string()
                ],
                store,
                keystore,
                frame_kind: None,
                event_object_digest: None,
                event_reason_codes: None,
            });
        }
    };

    let payload_digest = *blake3::hash(&payload).as_bytes();
    if req.payload_digests.is_empty() {
        req.payload_digests = vec![payload_digest];
    }

    let receipt_input = to_receipt_input(&req);
    let mut reject_reason_codes = Vec::new();

    if req.payload_digests.len() != 1 || req.payload_digests[0] != payload_digest {
        reject_reason_codes.push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
    }

    if req.epoch_id != keystore.current_epoch() {
        reject_reason_codes.push(protocol::ReasonCodes::RE_INTEGRITY_DEGRADED.to_string());
    }

    if req.bindings.prev_record_digest != store.current_head_record_digest {
        reject_reason_codes.push(protocol::ReasonCodes::GE_EXEC_DISPATCH_BLOCKED.to_string());
    }

    if !req
        .required_checks
        .iter()
        .any(|check| matches!(check, RequiredCheck::SchemaOk))
    {
        reject_reason_codes.push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
    }

    let decision = match DlpDecision::decode(payload.as_slice()) {
        Ok(decision) => decision,
        Err(_) => {
            reject_reason_codes
                .push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
            return finalize_receipt(FinalizeReceiptArgs {
                req: &req,
                receipt_input: &receipt_input,
                status: ReceiptStatus::Rejected,
                reject_reason_codes,
                store,
                keystore,
                frame_kind: None,
                event_object_digest: Some(payload_digest),
                event_reason_codes: None,
            });
        }
    };

    let Some(digest) = decision
        .dlp_decision_digest
        .as_deref()
        .and_then(digest_from_bytes)
    else {
        reject_reason_codes.push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
        return finalize_receipt(FinalizeReceiptArgs {
            req: &req,
            receipt_input: &receipt_input,
            status: ReceiptStatus::Rejected,
            reject_reason_codes,
            store,
            keystore,
            frame_kind: None,
            event_object_digest: Some(payload_digest),
            event_reason_codes: None,
        });
    };

    if store.committed_payload_digests.contains(&payload_digest) {
        reject_reason_codes.push(protocol::ReasonCodes::RE_REPLAY_MISMATCH.to_string());
    }

    let decision_form =
        DlpDecisionForm::try_from(decision.decision_form).unwrap_or(DlpDecisionForm::Unspecified);
    if matches!(decision_form, DlpDecisionForm::Unspecified) {
        reject_reason_codes.push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
    }

    if store.dlp_store.insert(decision.clone()).is_err() {
        reject_reason_codes.push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
    }

    if !reject_reason_codes.is_empty() {
        return finalize_receipt(FinalizeReceiptArgs {
            req: &req,
            receipt_input: &receipt_input,
            status: ReceiptStatus::Rejected,
            reject_reason_codes,
            store,
            keystore,
            frame_kind: None,
            event_object_digest: Some(digest),
            event_reason_codes: None,
        });
    }

    let event_reason_codes = store
        .dlp_store
        .get(digest)
        .map(|stored| stored.reason_codes.clone())
        .unwrap_or(decision.reason_codes.clone());

    store.committed_payload_digests.insert(payload_digest);

    finalize_receipt(FinalizeReceiptArgs {
        req: &req,
        receipt_input: &receipt_input,
        status: ReceiptStatus::Accepted,
        reject_reason_codes,
        store,
        keystore,
        frame_kind: None,
        event_object_digest: Some(digest),
        event_reason_codes: Some(event_reason_codes),
    })
}

fn verify_microcircuit_config_append(
    mut req: PvgsCommitRequest,
    store: &mut PvgsStore,
    keystore: &KeyStore,
) -> (PVGSReceipt, Option<ProofReceipt>) {
    let payload = match req.microcircuit_config_payload.take() {
        Some(payload) => payload,
        None => {
            let receipt_input = to_receipt_input(&req);
            return finalize_receipt(FinalizeReceiptArgs {
                req: &req,
                receipt_input: &receipt_input,
                status: ReceiptStatus::Rejected,
                reject_reason_codes: vec![
                    protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string()
                ],
                store,
                keystore,
                frame_kind: None,
                event_object_digest: None,
                event_reason_codes: None,
            });
        }
    };

    let evidence = match MicrocircuitConfigEvidence::decode(payload.as_slice()) {
        Ok(evidence) => evidence,
        Err(_) => {
            let receipt_input = to_receipt_input(&req);
            return finalize_receipt(FinalizeReceiptArgs {
                req: &req,
                receipt_input: &receipt_input,
                status: ReceiptStatus::Rejected,
                reject_reason_codes: vec![
                    protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string()
                ],
                store,
                keystore,
                frame_kind: None,
                event_object_digest: None,
                event_reason_codes: None,
            });
        }
    };

    let payload_digest = digest_from_bytes(&evidence.config_digest);
    if req.payload_digests.is_empty() {
        if let Some(digest) = payload_digest {
            req.payload_digests = vec![digest];
        }
    }

    let receipt_input = to_receipt_input(&req);
    let mut reject_reason_codes = Vec::new();

    let module = MicroModule::try_from(evidence.module).unwrap_or(MicroModule::Unspecified);

    if payload_digest.is_none() {
        reject_reason_codes.push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
    }

    if let Some(digest) = payload_digest {
        if req.payload_digests.len() != 1 || req.payload_digests[0] != digest {
            reject_reason_codes
                .push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
        }
    }

    if evidence.config_version == 0 {
        reject_reason_codes.push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
    }

    if module == MicroModule::Unspecified
        || !matches!(module, MicroModule::Lc | MicroModule::Sn | MicroModule::Hpa)
    {
        reject_reason_codes.push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
    }

    if req.epoch_id != keystore.current_epoch() {
        reject_reason_codes.push(protocol::ReasonCodes::RE_INTEGRITY_DEGRADED.to_string());
    }

    if req.bindings.prev_record_digest != store.current_head_record_digest {
        reject_reason_codes.push(protocol::ReasonCodes::GE_EXEC_DISPATCH_BLOCKED.to_string());
    }

    if !req
        .required_checks
        .iter()
        .any(|check| matches!(check, RequiredCheck::SchemaOk))
    {
        reject_reason_codes.push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
    }

    if !store
        .known_charter_versions
        .contains(&req.bindings.charter_version_digest)
    {
        reject_reason_codes.push(protocol::ReasonCodes::PB_DENY_CHARTER_SCOPE.to_string());
    }

    if !store
        .known_policy_versions
        .contains(&req.bindings.policy_version_digest)
    {
        reject_reason_codes.push(protocol::ReasonCodes::PB_DENY_INTEGRITY_REQUIRED.to_string());
    }

    if !reject_reason_codes.is_empty() {
        return finalize_receipt(FinalizeReceiptArgs {
            req: &req,
            receipt_input: &receipt_input,
            status: ReceiptStatus::Rejected,
            reject_reason_codes,
            store,
            keystore,
            frame_kind: None,
            event_object_digest: payload_digest,
            event_reason_codes: None,
        });
    }

    let verified_fields_digest =
        compute_verified_fields_digest(&req.bindings, req.required_receipt_kind);
    let mut proof_receipt = issue_proof_receipt(
        store.ruleset_state.ruleset_digest,
        verified_fields_digest,
        [0u8; 32],
        keystore,
    );
    let receipt = issue_receipt(
        &receipt_input,
        ReceiptStatus::Accepted,
        Vec::new(),
        keystore,
    );
    proof_receipt.receipt_digest = receipt.receipt_digest.clone();

    store.add_receipt_edges(&receipt);
    let payload_digest = payload_digest.expect("validated payload digest");
    let _ = store.micro_config_store.insert(evidence);
    store.committed_payload_digests.insert(payload_digest);

    let _ = store.record_sep_event(
        &req.commit_id,
        SepEventType::EvRecoveryGov,
        payload_digest,
        vec![protocol::ReasonCodes::GV_MICROCIRCUIT_CONFIG_APPENDED.to_string()],
    );

    (receipt, Some(proof_receipt))
}

fn verify_asset_manifest_append(
    mut req: PvgsCommitRequest,
    store: &mut PvgsStore,
    keystore: &KeyStore,
) -> (PVGSReceipt, Option<ProofReceipt>) {
    let payload = match req.asset_manifest_payload.take() {
        Some(payload) => payload,
        None => {
            let receipt_input = to_receipt_input(&req);
            return finalize_receipt(FinalizeReceiptArgs {
                req: &req,
                receipt_input: &receipt_input,
                status: ReceiptStatus::Rejected,
                reject_reason_codes: vec![
                    protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string()
                ],
                store,
                keystore,
                frame_kind: None,
                event_object_digest: None,
                event_reason_codes: None,
            });
        }
    };

    let manifest = match AssetManifest::decode(payload.as_slice()) {
        Ok(manifest) => manifest,
        Err(_) => {
            let receipt_input = to_receipt_input(&req);
            return finalize_receipt(FinalizeReceiptArgs {
                req: &req,
                receipt_input: &receipt_input,
                status: ReceiptStatus::Rejected,
                reject_reason_codes: vec![
                    protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string()
                ],
                store,
                keystore,
                frame_kind: None,
                event_object_digest: None,
                event_reason_codes: None,
            });
        }
    };

    let manifest_digest = digest_from_bytes(&manifest.manifest_digest);
    let recomputed_digest = compute_asset_manifest_digest(&manifest);
    if req.payload_digests.is_empty() {
        if let Some(digest) = manifest_digest {
            req.payload_digests = vec![digest];
        }
    }

    let receipt_input = to_receipt_input(&req);
    let mut reject_reason_codes = Vec::new();

    if manifest_digest.is_none() {
        reject_reason_codes.push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
    }

    if let Some(digest) = manifest_digest {
        if digest != recomputed_digest {
            reject_reason_codes
                .push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
        }

        if req.payload_digests.len() != 1 || req.payload_digests[0] != digest {
            reject_reason_codes
                .push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
        }
    }

    if validate_manifest(&manifest).is_err() {
        reject_reason_codes.push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
    }

    if req.epoch_id != keystore.current_epoch() {
        reject_reason_codes.push(protocol::ReasonCodes::RE_INTEGRITY_DEGRADED.to_string());
    }

    if req.bindings.prev_record_digest != store.current_head_record_digest {
        reject_reason_codes.push(protocol::ReasonCodes::GE_EXEC_DISPATCH_BLOCKED.to_string());
    }

    if !req
        .required_checks
        .iter()
        .any(|check| matches!(check, RequiredCheck::SchemaOk))
    {
        reject_reason_codes.push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
    }

    if !store
        .known_charter_versions
        .contains(&req.bindings.charter_version_digest)
    {
        reject_reason_codes.push(protocol::ReasonCodes::PB_DENY_CHARTER_SCOPE.to_string());
    }

    if !store
        .known_policy_versions
        .contains(&req.bindings.policy_version_digest)
    {
        reject_reason_codes.push(protocol::ReasonCodes::PB_DENY_INTEGRITY_REQUIRED.to_string());
    }

    if !reject_reason_codes.is_empty() {
        return finalize_receipt(FinalizeReceiptArgs {
            req: &req,
            receipt_input: &receipt_input,
            status: ReceiptStatus::Rejected,
            reject_reason_codes,
            store,
            keystore,
            frame_kind: None,
            event_object_digest: manifest_digest,
            event_reason_codes: None,
        });
    }

    let verified_fields_digest =
        compute_verified_fields_digest(&req.bindings, req.required_receipt_kind);
    let mut proof_receipt = issue_proof_receipt(
        store.ruleset_state.ruleset_digest,
        verified_fields_digest,
        [0u8; 32],
        keystore,
    );
    let receipt = issue_receipt(
        &receipt_input,
        ReceiptStatus::Accepted,
        Vec::new(),
        keystore,
    );
    proof_receipt.receipt_digest = receipt.receipt_digest.clone();

    store.add_receipt_edges(&receipt);
    let payload_digest = manifest_digest.expect("validated manifest digest");
    let _ = store.asset_manifest_store.insert(manifest);
    store.committed_payload_digests.insert(payload_digest);

    let _ = store.record_sep_event(
        &req.commit_id,
        SepEventType::EvRecoveryGov,
        payload_digest,
        vec![protocol::ReasonCodes::GV_ASSET_MANIFEST_APPENDED.to_string()],
    );

    (receipt, Some(proof_receipt))
}

fn reassemble_asset_payload(chunks: &[&AssetChunk]) -> Option<Vec<u8>> {
    if chunks.is_empty() {
        return None;
    }
    let mut ordered: Vec<&AssetChunk> = chunks.to_vec();
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

fn canonicalize_asset_payload_bytes(
    kind: AssetKind,
    payload_bytes: &[u8],
) -> Result<Vec<u8>, prost::DecodeError> {
    match kind {
        AssetKind::Morphology => {
            let mut payload = MorphologySetPayload::decode(payload_bytes)?;
            payload
                .morphologies
                .sort_by_key(|entry| entry.encode_to_vec());
            Ok(payload.encode_to_vec())
        }
        AssetKind::Channel => {
            let mut payload = ChannelParamsSetPayload::decode(payload_bytes)?;
            payload
                .channel_params
                .sort_by_key(|entry| entry.encode_to_vec());
            Ok(payload.encode_to_vec())
        }
        AssetKind::Synapse => {
            let mut payload = SynapseParamsSetPayload::decode(payload_bytes)?;
            payload
                .synapse_params
                .sort_by_key(|entry| entry.encode_to_vec());
            Ok(payload.encode_to_vec())
        }
        AssetKind::Connectivity => {
            let mut payload = ConnectivityGraphPayload::decode(payload_bytes)?;
            payload.edges.sort_by_key(|entry| entry.encode_to_vec());
            Ok(payload.encode_to_vec())
        }
        AssetKind::Unspecified => Ok(payload_bytes.to_vec()),
    }
}

fn verify_asset_bundle_append(
    mut req: PvgsCommitRequest,
    store: &mut PvgsStore,
    keystore: &KeyStore,
) -> (PVGSReceipt, Option<ProofReceipt>) {
    let payload = match req.asset_bundle_payload.take() {
        Some(payload) => payload,
        None => {
            let receipt_input = to_receipt_input(&req);
            return finalize_receipt(FinalizeReceiptArgs {
                req: &req,
                receipt_input: &receipt_input,
                status: ReceiptStatus::Rejected,
                reject_reason_codes: vec![
                    protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string()
                ],
                store,
                keystore,
                frame_kind: None,
                event_object_digest: None,
                event_reason_codes: None,
            });
        }
    };

    let bundle = match AssetBundle::decode(payload.as_slice()) {
        Ok(bundle) => bundle,
        Err(_) => {
            let receipt_input = to_receipt_input(&req);
            return finalize_receipt(FinalizeReceiptArgs {
                req: &req,
                receipt_input: &receipt_input,
                status: ReceiptStatus::Rejected,
                reject_reason_codes: vec![
                    protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string()
                ],
                store,
                keystore,
                frame_kind: None,
                event_object_digest: None,
                event_reason_codes: None,
            });
        }
    };

    let bundle_digest = digest_from_bytes(&bundle.bundle_digest);
    if req.payload_digests.is_empty() {
        if let Some(digest) = bundle_digest {
            req.payload_digests = vec![digest];
        }
    }

    let receipt_input = to_receipt_input(&req);
    let mut reject_reason_codes = Vec::new();
    let mut integrity_failed = false;
    let mut schema_failed = false;

    if bundle_digest.is_none() {
        schema_failed = true;
    }

    let manifest = bundle.manifest.as_ref();
    if manifest.is_none() {
        schema_failed = true;
    }

    if let Some(manifest) = manifest {
        if !manifest.manifest_digest.is_empty() {
            if let Some(manifest_digest) = digest_from_bytes(&manifest.manifest_digest) {
                if compute_asset_manifest_digest(manifest) != manifest_digest {
                    integrity_failed = true;
                }
            } else {
                schema_failed = true;
            }
            if validate_manifest(manifest).is_err() {
                schema_failed = true;
            }
        } else {
            for asset in &manifest.asset_digests {
                let kind = AssetKind::try_from(asset.kind).unwrap_or(AssetKind::Unspecified);
                if kind == AssetKind::Unspecified || asset.digest.len() != 32 || asset.version == 0
                {
                    schema_failed = true;
                }
            }
        }
    }

    let mut chunk_counts: HashMap<[u8; 32], u32> = HashMap::new();
    for chunk in &bundle.chunks {
        let asset_digest = match digest_from_bytes(&chunk.asset_digest) {
            Some(digest) => digest,
            None => {
                schema_failed = true;
                continue;
            }
        };
        let chunk_digest = match digest_from_bytes(&chunk.chunk_digest) {
            Some(digest) => digest,
            None => {
                schema_failed = true;
                continue;
            }
        };
        let recomputed_chunk_digest = compute_asset_chunk_digest(&chunk.payload);
        if chunk_digest != recomputed_chunk_digest {
            integrity_failed = true;
        }
        if chunk.chunk_count == 0 || chunk.chunk_index >= chunk.chunk_count {
            integrity_failed = true;
        }
        if let Some(existing) = chunk_counts.insert(asset_digest, chunk.chunk_count) {
            if existing != chunk.chunk_count {
                integrity_failed = true;
            }
        }
    }

    let mut decode_skipped_due_to_size = false;
    let mut canonical_mismatch = false;
    if let Some(manifest) = manifest {
        let mut chunks_by_digest: HashMap<[u8; 32], Vec<&AssetChunk>> = HashMap::new();
        for chunk in &bundle.chunks {
            if let Some(asset_digest) = digest_from_bytes(&chunk.asset_digest) {
                chunks_by_digest
                    .entry(asset_digest)
                    .or_default()
                    .push(chunk);
            }
        }

        for kind in [
            AssetKind::Morphology,
            AssetKind::Channel,
            AssetKind::Synapse,
            AssetKind::Connectivity,
        ] {
            let asset_digest = manifest
                .asset_digests
                .iter()
                .find(|asset| AssetKind::try_from(asset.kind).ok() == Some(kind))
                .and_then(|asset| digest_from_bytes(&asset.digest));
            let Some(asset_digest) = asset_digest else {
                continue;
            };
            let Some(chunks) = chunks_by_digest.get(&asset_digest) else {
                continue;
            };
            let Some(payload_bytes) = reassemble_asset_payload(chunks) else {
                continue;
            };
            if payload_bytes.len() > MAX_ASSET_PAYLOAD_DECODE_BYTES {
                decode_skipped_due_to_size = true;
                continue;
            }
            if let Ok(canonical_bytes) = canonicalize_asset_payload_bytes(kind, &payload_bytes) {
                if canonical_bytes != payload_bytes {
                    canonical_mismatch = true;
                }
            }
        }
    }

    let recomputed_bundle_digest =
        manifest.and_then(|manifest| compute_asset_bundle_digest(manifest, &bundle.chunks));
    if let Some(digest) = bundle_digest {
        if recomputed_bundle_digest != Some(digest) {
            integrity_failed = true;
        }

        if req.payload_digests.len() != 1 || req.payload_digests[0] != digest {
            schema_failed = true;
        }
    } else {
        integrity_failed = true;
    }

    if req.epoch_id != keystore.current_epoch() {
        reject_reason_codes.push(protocol::ReasonCodes::RE_INTEGRITY_DEGRADED.to_string());
    }

    if req.bindings.prev_record_digest != store.current_head_record_digest {
        reject_reason_codes.push(protocol::ReasonCodes::GE_EXEC_DISPATCH_BLOCKED.to_string());
    }

    if !req
        .required_checks
        .iter()
        .any(|check| matches!(check, RequiredCheck::SchemaOk))
    {
        schema_failed = true;
    }

    if !store
        .known_charter_versions
        .contains(&req.bindings.charter_version_digest)
    {
        reject_reason_codes.push(protocol::ReasonCodes::PB_DENY_CHARTER_SCOPE.to_string());
    }

    if !store
        .known_policy_versions
        .contains(&req.bindings.policy_version_digest)
    {
        reject_reason_codes.push(protocol::ReasonCodes::PB_DENY_INTEGRITY_REQUIRED.to_string());
    }

    if schema_failed {
        let schema_code = protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string();
        if !reject_reason_codes.contains(&schema_code) {
            reject_reason_codes.push(schema_code);
        }
    }

    if integrity_failed {
        let integrity_code = protocol::ReasonCodes::RE_INTEGRITY_DEGRADED.to_string();
        if !reject_reason_codes.contains(&integrity_code) {
            reject_reason_codes.push(integrity_code);
        }
        reject_reason_codes.push(protocol::ReasonCodes::GV_ASSET_DIGEST_MISMATCH.to_string());
    }

    if canonical_mismatch {
        reject_reason_codes.push(protocol::ReasonCodes::GV_ASSET_CANONICAL_MISMATCH.to_string());
    }

    if !reject_reason_codes.is_empty() {
        return finalize_receipt(FinalizeReceiptArgs {
            req: &req,
            receipt_input: &receipt_input,
            status: ReceiptStatus::Rejected,
            reject_reason_codes,
            store,
            keystore,
            frame_kind: None,
            event_object_digest: bundle_digest,
            event_reason_codes: None,
        });
    }

    let payload_digest = bundle_digest.expect("validated bundle digest");
    if let Err(err) = store.asset_bundle_store.insert(bundle) {
        let reject_reason_codes = match err {
            AssetBundleStoreError::TooManyBundles | AssetBundleStoreError::TooManyChunks => {
                vec![protocol::ReasonCodes::RE_INTEGRITY_DEGRADED.to_string()]
            }
            AssetBundleStoreError::InvalidBundleDigest
            | AssetBundleStoreError::InvalidAssetDigest => {
                vec![protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string()]
            }
        };
        return finalize_receipt(FinalizeReceiptArgs {
            req: &req,
            receipt_input: &receipt_input,
            status: ReceiptStatus::Rejected,
            reject_reason_codes,
            store,
            keystore,
            frame_kind: None,
            event_object_digest: Some(payload_digest),
            event_reason_codes: None,
        });
    }

    let verified_fields_digest =
        compute_verified_fields_digest(&req.bindings, req.required_receipt_kind);
    let mut proof_receipt = issue_proof_receipt(
        store.ruleset_state.ruleset_digest,
        verified_fields_digest,
        [0u8; 32],
        keystore,
    );
    let receipt = issue_receipt(
        &receipt_input,
        ReceiptStatus::Accepted,
        Vec::new(),
        keystore,
    );
    proof_receipt.receipt_digest = receipt.receipt_digest.clone();

    store.add_receipt_edges(&receipt);
    store.committed_payload_digests.insert(payload_digest);

    let mut event_reason_codes = vec![protocol::ReasonCodes::GV_ASSET_BUNDLE_APPENDED.to_string()];
    if decode_skipped_due_to_size {
        event_reason_codes
            .push(protocol::ReasonCodes::GV_ASSET_DECODE_SKIPPED_DUE_TO_SIZE.to_string());
    }

    let _ = store.record_sep_event(
        &req.commit_id,
        SepEventType::EvRecoveryGov,
        payload_digest,
        event_reason_codes,
    );

    (receipt, Some(proof_receipt))
}

fn verify_replay_run_evidence_append(
    mut req: PvgsCommitRequest,
    store: &mut PvgsStore,
    keystore: &KeyStore,
) -> (PVGSReceipt, Option<ProofReceipt>) {
    let payload = match req.replay_run_evidence_payload.take() {
        Some(payload) => payload,
        None => {
            let receipt_input = to_receipt_input(&req);
            return finalize_receipt(FinalizeReceiptArgs {
                req: &req,
                receipt_input: &receipt_input,
                status: ReceiptStatus::Rejected,
                reject_reason_codes: vec![
                    protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string()
                ],
                store,
                keystore,
                frame_kind: None,
                event_object_digest: None,
                event_reason_codes: None,
            });
        }
    };

    let evidence = match ReplayRunEvidence::decode(payload.as_slice()) {
        Ok(evidence) => evidence,
        Err(_) => {
            let receipt_input = to_receipt_input(&req);
            return finalize_receipt(FinalizeReceiptArgs {
                req: &req,
                receipt_input: &receipt_input,
                status: ReceiptStatus::Rejected,
                reject_reason_codes: vec![
                    protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string()
                ],
                store,
                keystore,
                frame_kind: None,
                event_object_digest: None,
                event_reason_codes: None,
            });
        }
    };

    let run_digest = digest_from_bytes(&evidence.run_digest);
    if req.payload_digests.is_empty() {
        if let Some(digest) = run_digest {
            req.payload_digests = vec![digest];
        }
    }

    let receipt_input = to_receipt_input(&req);
    let mut reject_reason_codes = Vec::new();

    if run_digest.is_none() {
        reject_reason_codes.push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
    }

    if let Some(digest) = run_digest {
        if req.payload_digests.len() != 1 || req.payload_digests[0] != digest {
            reject_reason_codes
                .push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
        }
    }

    let asset_manifest_digest = evidence
        .asset_manifest_ref
        .as_ref()
        .and_then(digest_from_ref);
    if asset_manifest_digest.is_none() {
        reject_reason_codes.push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
    }

    if evidence.steps == 0 || evidence.steps > 1_000_000 {
        reject_reason_codes.push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
    }

    if evidence.micro_config_refs.len() > 8 {
        reject_reason_codes.push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
    }

    if evidence.summary_digests.is_empty()
        || evidence
            .summary_digests
            .iter()
            .any(|digest| digest_from_bytes(digest).is_none())
    {
        reject_reason_codes.push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
    }

    if req.epoch_id != keystore.current_epoch() {
        reject_reason_codes.push(protocol::ReasonCodes::RE_INTEGRITY_DEGRADED.to_string());
    }

    if req.bindings.prev_record_digest != store.current_head_record_digest {
        reject_reason_codes.push(protocol::ReasonCodes::GE_EXEC_DISPATCH_BLOCKED.to_string());
    }

    if !req
        .required_checks
        .iter()
        .any(|check| matches!(check, RequiredCheck::SchemaOk))
    {
        reject_reason_codes.push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
    }

    if !store
        .known_charter_versions
        .contains(&req.bindings.charter_version_digest)
    {
        reject_reason_codes.push(protocol::ReasonCodes::PB_DENY_CHARTER_SCOPE.to_string());
    }

    if !store
        .known_policy_versions
        .contains(&req.bindings.policy_version_digest)
    {
        reject_reason_codes.push(protocol::ReasonCodes::PB_DENY_INTEGRITY_REQUIRED.to_string());
    }

    if !reject_reason_codes.is_empty() {
        return finalize_receipt(FinalizeReceiptArgs {
            req: &req,
            receipt_input: &receipt_input,
            status: ReceiptStatus::Rejected,
            reject_reason_codes,
            store,
            keystore,
            frame_kind: None,
            event_object_digest: run_digest,
            event_reason_codes: None,
        });
    }

    let run_digest = run_digest.expect("validated run digest");

    let verified_fields_digest =
        compute_verified_fields_digest(&req.bindings, req.required_receipt_kind);
    let mut proof_receipt = issue_proof_receipt(
        store.ruleset_state.ruleset_digest,
        verified_fields_digest,
        [0u8; 32],
        keystore,
    );
    let receipt = issue_receipt(
        &receipt_input,
        ReceiptStatus::Accepted,
        Vec::new(),
        keystore,
    );
    proof_receipt.receipt_digest = receipt.receipt_digest.clone();

    store.add_receipt_edges(&receipt);
    if store.replay_run_store.insert(evidence.clone()).is_err() {
        return finalize_receipt(FinalizeReceiptArgs {
            req: &req,
            receipt_input: &receipt_input,
            status: ReceiptStatus::Rejected,
            reject_reason_codes: vec![
                protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string()
            ],
            store,
            keystore,
            frame_kind: None,
            event_object_digest: Some(run_digest),
            event_reason_codes: None,
        });
    }
    store.committed_payload_digests.insert(run_digest);

    if let Some(asset_digest) = asset_manifest_digest {
        store.add_graph_edge(run_digest, EdgeType::References, asset_digest, None);
    }

    for micro_ref in &evidence.micro_config_refs {
        if let Some(micro_digest) = digest_from_ref(micro_ref) {
            store.add_graph_edge(run_digest, EdgeType::References, micro_digest, None);
        }
    }

    let _ = store.record_sep_event(
        &req.commit_id,
        SepEventType::EvReplay,
        run_digest,
        vec![protocol::ReasonCodes::GV_REPLAY_RUN_EVIDENCE_APPENDED.to_string()],
    );

    (receipt, Some(proof_receipt))
}

fn verify_trace_run_evidence_append(
    mut req: PvgsCommitRequest,
    store: &mut PvgsStore,
    keystore: &KeyStore,
) -> (PVGSReceipt, Option<ProofReceipt>) {
    let payload = match req.trace_run_evidence_payload.take() {
        Some(payload) => payload,
        None => {
            let receipt_input = to_receipt_input(&req);
            return finalize_receipt(FinalizeReceiptArgs {
                req: &req,
                receipt_input: &receipt_input,
                status: ReceiptStatus::Rejected,
                reject_reason_codes: vec![
                    protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string()
                ],
                store,
                keystore,
                frame_kind: None,
                event_object_digest: None,
                event_reason_codes: None,
            });
        }
    };

    let evidence = match TraceRunEvidence::decode(payload.as_slice()) {
        Ok(evidence) => evidence,
        Err(_) => {
            let receipt_input = to_receipt_input(&req);
            return finalize_receipt(FinalizeReceiptArgs {
                req: &req,
                receipt_input: &receipt_input,
                status: ReceiptStatus::Rejected,
                reject_reason_codes: vec![
                    protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string()
                ],
                store,
                keystore,
                frame_kind: None,
                event_object_digest: None,
                event_reason_codes: None,
            });
        }
    };

    let run_digest = digest_from_bytes(&evidence.trace_digest);
    if req.payload_digests.is_empty() {
        if let Some(digest) = run_digest {
            req.payload_digests = vec![digest];
        }
    }

    let receipt_input = to_receipt_input(&req);
    let mut reject_reason_codes = Vec::new();

    if run_digest.is_none() {
        reject_reason_codes.push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
    }

    if let Some(digest) = run_digest {
        if req.payload_digests.len() != 1 || req.payload_digests[0] != digest {
            reject_reason_codes
                .push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
        }
    }

    if validate_trace_run_evidence(&evidence).is_err() {
        reject_reason_codes.push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
    }

    if verify_trace_run_evidence_digest(&evidence).is_err() {
        reject_reason_codes.push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
    }

    if req.epoch_id != keystore.current_epoch() {
        reject_reason_codes.push(protocol::ReasonCodes::RE_INTEGRITY_DEGRADED.to_string());
    }

    if req.bindings.prev_record_digest != store.current_head_record_digest {
        reject_reason_codes.push(protocol::ReasonCodes::GE_EXEC_DISPATCH_BLOCKED.to_string());
    }

    if !req
        .required_checks
        .iter()
        .any(|check| matches!(check, RequiredCheck::SchemaOk))
    {
        reject_reason_codes.push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
    }

    if !store
        .known_charter_versions
        .contains(&req.bindings.charter_version_digest)
    {
        reject_reason_codes.push(protocol::ReasonCodes::PB_DENY_CHARTER_SCOPE.to_string());
    }

    if !store
        .known_policy_versions
        .contains(&req.bindings.policy_version_digest)
    {
        reject_reason_codes.push(protocol::ReasonCodes::PB_DENY_INTEGRITY_REQUIRED.to_string());
    }

    if !reject_reason_codes.is_empty() {
        return finalize_receipt(FinalizeReceiptArgs {
            req: &req,
            receipt_input: &receipt_input,
            status: ReceiptStatus::Rejected,
            reject_reason_codes,
            store,
            keystore,
            frame_kind: None,
            event_object_digest: run_digest,
            event_reason_codes: None,
        });
    }

    let run_digest = run_digest.expect("validated run digest");

    let verified_fields_digest =
        compute_verified_fields_digest(&req.bindings, req.required_receipt_kind);
    let mut proof_receipt = issue_proof_receipt(
        store.ruleset_state.ruleset_digest,
        verified_fields_digest,
        [0u8; 32],
        keystore,
    );
    let receipt = issue_receipt(
        &receipt_input,
        ReceiptStatus::Accepted,
        Vec::new(),
        keystore,
    );
    proof_receipt.receipt_digest = receipt.receipt_digest.clone();

    store.add_receipt_edges(&receipt);
    if store.trace_run_store.insert(evidence.clone()).is_err() {
        return finalize_receipt(FinalizeReceiptArgs {
            req: &req,
            receipt_input: &receipt_input,
            status: ReceiptStatus::Rejected,
            reject_reason_codes: vec![
                protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string()
            ],
            store,
            keystore,
            frame_kind: None,
            event_object_digest: Some(run_digest),
            event_reason_codes: None,
        });
    }
    store.committed_payload_digests.insert(run_digest);

    if let Some(active_cfg_digest) = digest_from_bytes(&evidence.active_cfg_digest) {
        store.add_graph_edge(run_digest, EdgeType::References, active_cfg_digest, None);
    }
    if let Some(shadow_cfg_digest) = digest_from_bytes(&evidence.shadow_cfg_digest) {
        store.add_graph_edge(run_digest, EdgeType::References, shadow_cfg_digest, None);
    }
    if let Some(active_feedback_digest) = digest_from_bytes(&evidence.active_feedback_digest) {
        store.add_graph_edge(
            run_digest,
            EdgeType::References,
            active_feedback_digest,
            None,
        );
    }
    if let Some(shadow_feedback_digest) = digest_from_bytes(&evidence.shadow_feedback_digest) {
        store.add_graph_edge(
            run_digest,
            EdgeType::References,
            shadow_feedback_digest,
            None,
        );
    }

    let mut reason_codes = vec![protocol::ReasonCodes::GV_TRACE_APPENDED.to_string()];
    match TraceVerdict::try_from(evidence.verdict).unwrap_or(TraceVerdict::Unspecified) {
        TraceVerdict::Promising => {
            reason_codes.push(protocol::ReasonCodes::GV_TRACE_PROMISING.to_string());
        }
        TraceVerdict::Neutral => {
            reason_codes.push(protocol::ReasonCodes::GV_TRACE_NEUTRAL.to_string());
        }
        TraceVerdict::Risky => {
            reason_codes.push(protocol::ReasonCodes::GV_TRACE_RISKY.to_string());
        }
        TraceVerdict::Unspecified => {}
    }
    let event_type = SepEventType::EvReplay;

    let _ = store.record_sep_event(&req.commit_id, event_type, run_digest, reason_codes);

    (receipt, Some(proof_receipt))
}

fn verify_proposal_evidence_append(
    mut req: PvgsCommitRequest,
    store: &mut PvgsStore,
    keystore: &KeyStore,
) -> (PVGSReceipt, Option<ProofReceipt>) {
    let payload = match req.proposal_evidence_payload.take() {
        Some(payload) => payload,
        None => {
            let receipt_input = to_receipt_input(&req);
            return finalize_receipt(FinalizeReceiptArgs {
                req: &req,
                receipt_input: &receipt_input,
                status: ReceiptStatus::Rejected,
                reject_reason_codes: vec![
                    protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string()
                ],
                store,
                keystore,
                frame_kind: None,
                event_object_digest: None,
                event_reason_codes: None,
            });
        }
    };

    let evidence = match ProposalEvidence::decode(payload.as_slice()) {
        Ok(evidence) => evidence,
        Err(_) => {
            let receipt_input = to_receipt_input(&req);
            return finalize_receipt(FinalizeReceiptArgs {
                req: &req,
                receipt_input: &receipt_input,
                status: ReceiptStatus::Rejected,
                reject_reason_codes: vec![
                    protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string()
                ],
                store,
                keystore,
                frame_kind: None,
                event_object_digest: None,
                event_reason_codes: None,
            });
        }
    };

    let proposal_digest = digest_from_bytes(&evidence.proposal_digest);
    if req.payload_digests.is_empty() {
        if let Some(digest) = proposal_digest {
            req.payload_digests = vec![digest];
        }
    }

    let receipt_input = to_receipt_input(&req);
    let mut reject_reason_codes = Vec::new();

    if proposal_digest.is_none() {
        reject_reason_codes.push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
    }

    if let Some(digest) = proposal_digest {
        if req.payload_digests.len() != 1 || req.payload_digests[0] != digest {
            reject_reason_codes
                .push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
        }
    }

    if validate_proposal_evidence(&evidence).is_err() {
        reject_reason_codes.push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
    }

    if verify_proposal_evidence_digest(&evidence).is_err() {
        reject_reason_codes.push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
    }

    if req.epoch_id != keystore.current_epoch() {
        reject_reason_codes.push(protocol::ReasonCodes::RE_INTEGRITY_DEGRADED.to_string());
    }

    if req.bindings.prev_record_digest != store.current_head_record_digest {
        reject_reason_codes.push(protocol::ReasonCodes::GE_EXEC_DISPATCH_BLOCKED.to_string());
    }

    if !req
        .required_checks
        .iter()
        .any(|check| matches!(check, RequiredCheck::SchemaOk))
    {
        reject_reason_codes.push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
    }

    if !store
        .known_charter_versions
        .contains(&req.bindings.charter_version_digest)
    {
        reject_reason_codes.push(protocol::ReasonCodes::PB_DENY_CHARTER_SCOPE.to_string());
    }

    if !store
        .known_policy_versions
        .contains(&req.bindings.policy_version_digest)
    {
        reject_reason_codes.push(protocol::ReasonCodes::PB_DENY_INTEGRITY_REQUIRED.to_string());
    }

    if !reject_reason_codes.is_empty() {
        return finalize_receipt(FinalizeReceiptArgs {
            req: &req,
            receipt_input: &receipt_input,
            status: ReceiptStatus::Rejected,
            reject_reason_codes,
            store,
            keystore,
            frame_kind: None,
            event_object_digest: proposal_digest,
            event_reason_codes: None,
        });
    }

    let proposal_digest = proposal_digest.expect("validated proposal digest");

    let verified_fields_digest =
        compute_verified_fields_digest(&req.bindings, req.required_receipt_kind);
    let mut proof_receipt = issue_proof_receipt(
        store.ruleset_state.ruleset_digest,
        verified_fields_digest,
        [0u8; 32],
        keystore,
    );
    let receipt = issue_receipt(
        &receipt_input,
        ReceiptStatus::Accepted,
        Vec::new(),
        keystore,
    );
    proof_receipt.receipt_digest = receipt.receipt_digest.clone();

    store.add_receipt_edges(&receipt);
    match store.proposal_store.insert(evidence.clone()) {
        Ok(inserted) => {
            store.committed_payload_digests.insert(proposal_digest);
            if inserted {
                if let Some(base_digest) = digest_from_bytes(&evidence.base_evidence_digest) {
                    store.add_graph_edge(proposal_digest, EdgeType::References, base_digest, None);
                }
                if let Some(payload_digest) = digest_from_bytes(&evidence.payload_digest) {
                    store.add_graph_edge(
                        proposal_digest,
                        EdgeType::References,
                        payload_digest,
                        None,
                    );
                }
                let _ = store.record_sep_event(
                    &req.commit_id,
                    SepEventType::EvAgentStep,
                    proposal_digest,
                    vec![protocol::ReasonCodes::GV_PROPOSAL_APPENDED.to_string()],
                );
            }
        }
        Err(_) => {
            return finalize_receipt(FinalizeReceiptArgs {
                req: &req,
                receipt_input: &receipt_input,
                status: ReceiptStatus::Rejected,
                reject_reason_codes: vec![
                    protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string()
                ],
                store,
                keystore,
                frame_kind: None,
                event_object_digest: Some(proposal_digest),
                event_reason_codes: None,
            });
        }
    }

    (receipt, Some(proof_receipt))
}

fn verify_proposal_activation_append(
    mut req: PvgsCommitRequest,
    store: &mut PvgsStore,
    keystore: &KeyStore,
) -> (PVGSReceipt, Option<ProofReceipt>) {
    let payload = match req.proposal_activation_payload.take() {
        Some(payload) => payload,
        None => {
            let receipt_input = to_receipt_input(&req);
            return finalize_receipt(FinalizeReceiptArgs {
                req: &req,
                receipt_input: &receipt_input,
                status: ReceiptStatus::Rejected,
                reject_reason_codes: vec![
                    protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string()
                ],
                store,
                keystore,
                frame_kind: None,
                event_object_digest: None,
                event_reason_codes: None,
            });
        }
    };

    let evidence = match ProposalActivationEvidence::decode(payload.as_slice()) {
        Ok(evidence) => evidence,
        Err(_) => {
            let receipt_input = to_receipt_input(&req);
            return finalize_receipt(FinalizeReceiptArgs {
                req: &req,
                receipt_input: &receipt_input,
                status: ReceiptStatus::Rejected,
                reject_reason_codes: vec![
                    protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string()
                ],
                store,
                keystore,
                frame_kind: None,
                event_object_digest: None,
                event_reason_codes: None,
            });
        }
    };

    let activation_digest = digest_from_bytes(&evidence.activation_digest);
    if req.payload_digests.is_empty() {
        if let Some(digest) = activation_digest {
            req.payload_digests = vec![digest];
        }
    }

    let receipt_input = to_receipt_input(&req);
    let mut reject_reason_codes = Vec::new();

    if activation_digest.is_none() {
        reject_reason_codes.push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
    }

    if let Some(digest) = activation_digest {
        if req.payload_digests.len() != 1 || req.payload_digests[0] != digest {
            reject_reason_codes
                .push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
        }
    }

    if validate_proposal_activation_evidence(&evidence).is_err() {
        reject_reason_codes.push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
    }

    if verify_proposal_activation_digest(&evidence).is_err() {
        reject_reason_codes.push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
    }

    if req.epoch_id != keystore.current_epoch() {
        reject_reason_codes.push(protocol::ReasonCodes::RE_INTEGRITY_DEGRADED.to_string());
    }

    if req.bindings.prev_record_digest != store.current_head_record_digest {
        reject_reason_codes.push(protocol::ReasonCodes::GE_EXEC_DISPATCH_BLOCKED.to_string());
    }

    if !req
        .required_checks
        .iter()
        .any(|check| matches!(check, RequiredCheck::SchemaOk))
    {
        reject_reason_codes.push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
    }

    if !store
        .known_charter_versions
        .contains(&req.bindings.charter_version_digest)
    {
        reject_reason_codes.push(protocol::ReasonCodes::PB_DENY_CHARTER_SCOPE.to_string());
    }

    if !store
        .known_policy_versions
        .contains(&req.bindings.policy_version_digest)
    {
        reject_reason_codes.push(protocol::ReasonCodes::PB_DENY_INTEGRITY_REQUIRED.to_string());
    }

    if !reject_reason_codes.is_empty() {
        return finalize_receipt(FinalizeReceiptArgs {
            req: &req,
            receipt_input: &receipt_input,
            status: ReceiptStatus::Rejected,
            reject_reason_codes,
            store,
            keystore,
            frame_kind: None,
            event_object_digest: activation_digest,
            event_reason_codes: None,
        });
    }

    let activation_digest = activation_digest.expect("validated activation digest");

    let verified_fields_digest =
        compute_verified_fields_digest(&req.bindings, req.required_receipt_kind);
    let mut proof_receipt = issue_proof_receipt(
        store.ruleset_state.ruleset_digest,
        verified_fields_digest,
        [0u8; 32],
        keystore,
    );
    let receipt = issue_receipt(
        &receipt_input,
        ReceiptStatus::Accepted,
        Vec::new(),
        keystore,
    );
    proof_receipt.receipt_digest = receipt.receipt_digest.clone();

    store.add_receipt_edges(&receipt);
    match store.proposal_activation_store.insert(evidence.clone()) {
        Ok(inserted) => {
            store.committed_payload_digests.insert(activation_digest);
            if inserted {
                if let Some(proposal_digest) = digest_from_bytes(&evidence.proposal_digest) {
                    store.add_graph_edge(
                        activation_digest,
                        EdgeType::References,
                        proposal_digest,
                        None,
                    );
                }
                if let Some(approval_digest) = digest_from_bytes(&evidence.approval_digest) {
                    store.add_graph_edge(
                        activation_digest,
                        EdgeType::References,
                        approval_digest,
                        None,
                    );
                }
                if let Some(digest) = evidence
                    .active_mapping_digest
                    .as_ref()
                    .and_then(|value| digest_from_bytes(value))
                {
                    store.add_graph_edge(activation_digest, EdgeType::References, digest, None);
                }
                if let Some(digest) = evidence
                    .active_sae_pack_digest
                    .as_ref()
                    .and_then(|value| digest_from_bytes(value))
                {
                    store.add_graph_edge(activation_digest, EdgeType::References, digest, None);
                }
                if let Some(digest) = evidence
                    .active_liquid_params_digest
                    .as_ref()
                    .and_then(|value| digest_from_bytes(value))
                {
                    store.add_graph_edge(activation_digest, EdgeType::References, digest, None);
                }
                if let Some(digest) = evidence
                    .active_limits_digest
                    .as_ref()
                    .and_then(|value| digest_from_bytes(value))
                {
                    store.add_graph_edge(activation_digest, EdgeType::References, digest, None);
                }
                let reason_code = match ActivationStatus::try_from(evidence.status)
                    .unwrap_or(ActivationStatus::Unspecified)
                {
                    ActivationStatus::Applied => {
                        protocol::ReasonCodes::GV_PROPOSAL_ACTIVATED.to_string()
                    }
                    ActivationStatus::Rejected => {
                        protocol::ReasonCodes::GV_PROPOSAL_REJECTED.to_string()
                    }
                    ActivationStatus::Unspecified => {
                        protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string()
                    }
                };
                let _ = store.record_sep_event(
                    &req.commit_id,
                    SepEventType::EvAgentStep,
                    activation_digest,
                    vec![reason_code],
                );
            }
        }
        Err(_) => {
            return finalize_receipt(FinalizeReceiptArgs {
                req: &req,
                receipt_input: &receipt_input,
                status: ReceiptStatus::Rejected,
                reject_reason_codes: vec![
                    protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string()
                ],
                store,
                keystore,
                frame_kind: None,
                event_object_digest: Some(activation_digest),
                event_reason_codes: None,
            });
        }
    }

    (receipt, Some(proof_receipt))
}

fn verify_proposal_evidence_digest(evidence: &ProposalEvidence) -> Result<(), ()> {
    let digest = digest_from_bytes(&evidence.proposal_digest).ok_or(())?;
    let expected = compute_proposal_evidence_digest(evidence).map_err(|_| ())?;
    if digest != expected {
        return Err(());
    }
    Ok(())
}

fn verify_proposal_activation_digest(evidence: &ProposalActivationEvidence) -> Result<(), ()> {
    let digest = digest_from_bytes(&evidence.activation_digest).ok_or(())?;
    let expected = compute_proposal_activation_digest(evidence).map_err(|_| ())?;
    if digest != expected {
        return Err(());
    }
    Ok(())
}

fn verify_trace_run_evidence_digest(evidence: &TraceRunEvidence) -> Result<(), ()> {
    let digest = digest_from_bytes(&evidence.trace_digest).ok_or(())?;
    let expected = compute_trace_run_digest(evidence).map_err(|_| ())?;
    if digest != expected {
        return Err(());
    }
    Ok(())
}

fn verify_tool_event_append(
    mut req: PvgsCommitRequest,
    store: &mut PvgsStore,
    keystore: &KeyStore,
) -> (PVGSReceipt, Option<ProofReceipt>) {
    let payload = match req.tool_onboarding_event.take() {
        Some(payload) => payload,
        None => {
            let receipt_input = to_receipt_input(&req);
            return finalize_receipt(FinalizeReceiptArgs {
                req: &req,
                receipt_input: &receipt_input,
                status: ReceiptStatus::Rejected,
                reject_reason_codes: vec![
                    protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string()
                ],
                store,
                keystore,
                frame_kind: None,
                event_object_digest: None,
                event_reason_codes: None,
            });
        }
    };

    let payload_digest = *blake3::hash(&payload).as_bytes();
    if req.payload_digests.is_empty() {
        req.payload_digests = vec![payload_digest];
    }

    let receipt_input = to_receipt_input(&req);
    let mut reject_reason_codes = Vec::new();

    if req.payload_digests.len() != 1 || req.payload_digests[0] != payload_digest {
        reject_reason_codes.push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
    }

    if req.epoch_id != keystore.current_epoch() {
        reject_reason_codes.push(protocol::ReasonCodes::RE_INTEGRITY_DEGRADED.to_string());
    }

    if req.bindings.prev_record_digest != store.current_head_record_digest {
        reject_reason_codes.push(protocol::ReasonCodes::GE_EXEC_DISPATCH_BLOCKED.to_string());
    }

    let event = match ToolOnboardingEvent::decode(payload.as_slice()) {
        Ok(event) => event,
        Err(_) => {
            reject_reason_codes
                .push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
            return finalize_receipt(FinalizeReceiptArgs {
                req: &req,
                receipt_input: &receipt_input,
                status: ReceiptStatus::Rejected,
                reject_reason_codes,
                store,
                keystore,
                frame_kind: None,
                event_object_digest: Some(payload_digest),
                event_reason_codes: None,
            });
        }
    };

    let event_digest = compute_tool_event_digest(&event).ok();

    if store.committed_payload_digests.contains(&payload_digest) {
        reject_reason_codes.push(protocol::ReasonCodes::RE_REPLAY_MISMATCH.to_string());
    }

    let mut stored_digest = None;
    if reject_reason_codes.is_empty() {
        match store.tool_event_store.insert(event.clone()) {
            Ok(digest) => stored_digest = Some(digest),
            Err(err) => reject_reason_codes.push(reason_code_for_tool_event_error(err)),
        }
    }

    if !reject_reason_codes.is_empty() {
        return finalize_receipt(FinalizeReceiptArgs {
            req: &req,
            receipt_input: &receipt_input,
            status: ReceiptStatus::Rejected,
            reject_reason_codes,
            store,
            keystore,
            frame_kind: None,
            event_object_digest: stored_digest.or(event_digest).or(Some(payload_digest)),
            event_reason_codes: None,
        });
    }

    let digest = stored_digest.unwrap_or_else(|| event_digest.unwrap_or([0u8; 32]));
    store.committed_payload_digests.insert(payload_digest);
    update_suspended_tools(store, &event);
    store.correlate_tool_event(digest);

    let mut event_reason_codes =
        vec![protocol::ReasonCodes::GV_TOOL_ONBOARDING_EVENT_APPENDED.to_string()];
    if matches!(
        ToolOnboardingStage::try_from(event.stage).ok(),
        Some(ToolOnboardingStage::To6Suspended)
    ) {
        event_reason_codes.push(protocol::ReasonCodes::GV_TOOL_SUSPENDED.to_string());
    }

    let receipt = issue_receipt(
        &receipt_input,
        ReceiptStatus::Accepted,
        reject_reason_codes,
        keystore,
    );
    store.add_receipt_edges(&receipt);

    let event_type = event_type_for_commit(req.commit_type, None);
    let _ = store.record_sep_event(
        &req.commit_id,
        event_type,
        digest,
        event_reason_codes.clone(),
    );

    let verified_fields_digest =
        compute_verified_fields_digest(&req.bindings, req.required_receipt_kind);
    let mut proof_receipt = issue_proof_receipt(
        store.ruleset_state.ruleset_digest,
        verified_fields_digest,
        [0u8; 32],
        keystore,
    );
    proof_receipt.receipt_digest = receipt.receipt_digest.clone();

    (receipt, Some(proof_receipt))
}

fn reason_code_for_tool_event_error(err: ToolEventError) -> String {
    match err {
        ToolEventError::MissingEventId
        | ToolEventError::MissingToolId
        | ToolEventError::InvalidStage
        | ToolEventError::TooManyReasonCodes
        | ToolEventError::TooManySignatures
        | ToolEventError::InvalidDigestLength
        | ToolEventError::DigestMismatch => {
            protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string()
        }
    }
}

fn update_suspended_tools(store: &mut PvgsStore, event: &ToolOnboardingEvent) {
    let key = (event.tool_id.clone(), event.action_id.clone());
    if matches!(
        ToolOnboardingStage::try_from(event.stage).ok(),
        Some(ToolOnboardingStage::To6Suspended)
    ) {
        store.suspended_tools.insert(key);
    } else {
        store.suspended_tools.remove(&key);
    }
}

fn build_finalization_header(
    req: &PvgsCommitRequest,
    record_digest: [u8; 32],
    experience_id: u64,
    key_epoch_id: u64,
) -> FinalizationHeader {
    FinalizationHeader {
        experience_id,
        timestamp_ms: now_ms(),
        prev_record_digest: digest_to_vec(req.bindings.prev_record_digest),
        record_digest: digest_to_vec(record_digest),
        charter_version_digest: req.bindings.charter_version_digest.clone(),
        policy_version_digest: req.bindings.policy_version_digest.clone(),
        key_epoch_id,
        proof_receipt_ref: None,
    }
}

fn validate_experience_record(
    record: &ExperienceRecord,
    store: &PvgsStore,
) -> Result<(), Vec<String>> {
    let Ok(record_type) = RecordType::try_from(record.record_type) else {
        return Err(vec![
            protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string()
        ]);
    };

    let mut reasons = Vec::new();

    match record_type {
        RecordType::RtActionExec => {
            if record.governance_frame_ref.is_none() {
                reasons.push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
            }

            if let Some(gov) = &record.governance_frame {
                if gov.policy_decision_refs.is_empty() {
                    reasons.push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
                }

                if store.receipt_gate_enabled && gov.pvgs_receipt_ref.is_none() {
                    reasons.push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
                }
            } else if store.receipt_gate_enabled {
                reasons.push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
            }
        }
        RecordType::RtOutput => {
            if record.governance_frame_ref.is_none() {
                reasons.push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
            }

            if record
                .governance_frame
                .as_ref()
                .is_none_or(|gov| gov.dlp_refs.is_empty())
            {
                reasons.push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
            }
        }
        RecordType::RtDecision => {
            if record.governance_frame_ref.is_none() {
                reasons.push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
            }

            if record
                .governance_frame
                .as_ref()
                .is_none_or(|gov| gov.policy_decision_refs.is_empty())
            {
                reasons.push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
            }
        }
        RecordType::RtPerception => {
            if record.core_frame_ref.is_none() {
                reasons.push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
            }

            if record.metabolic_frame_ref.is_none() {
                reasons.push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
            }
        }
        RecordType::RtReplay => {}
        RecordType::Unspecified => {
            reasons.push(protocol::ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string());
        }
    }

    if reasons.is_empty() {
        Ok(())
    } else {
        Err(reasons)
    }
}

fn profile_digest_from_record(record: &ExperienceRecord) -> Option<[u8; 32]> {
    record
        .metabolic_frame
        .as_ref()
        .and_then(|m| m.profile_digest.as_ref())
        .and_then(|bytes| digest_from_bytes(bytes))
}

fn log_experience_events(
    commit_id: &str,
    record_digest: [u8; 32],
    record: &ExperienceRecord,
    store: &mut PvgsStore,
) {
    let record_type = RecordType::try_from(record.record_type).unwrap_or(RecordType::Unspecified);

    let _ = store.record_sep_event(
        commit_id,
        SepEventType::EvAgentStep,
        record_digest,
        Vec::new(),
    );

    if let RecordType::RtOutput = record_type {
        let mut dlp_digests: Vec<[u8; 32]> = Vec::new();
        let mut output_reason_codes: Option<Vec<String>> = None;

        if let Some(gov) = &record.governance_frame {
            for reference in &gov.dlp_refs {
                if let Some(digest) = digest_from_ref(reference) {
                    dlp_digests.push(digest);
                }
            }
        }

        for digest in &record.dlp_refs {
            if let Some(target) = digest_from_ref(digest) {
                dlp_digests.push(target);
            }
        }

        for digest in &dlp_digests {
            let reason_codes = store
                .dlp_store
                .get(*digest)
                .map(|dlp| dlp.reason_codes.clone())
                .unwrap_or_else(|| vec![protocol::ReasonCodes::RE_INTEGRITY_DEGRADED.to_string()]);
            if output_reason_codes.is_none() {
                output_reason_codes = Some(reason_codes.clone());
            }
            let _ = store.record_sep_event(
                commit_id,
                SepEventType::EvDlpDecision,
                *digest,
                reason_codes,
            );
        }

        let output_reason = output_reason_codes
            .unwrap_or_else(|| vec![protocol::ReasonCodes::RE_INTEGRITY_OK.to_string()]);

        let _ = store.record_sep_event(
            commit_id,
            SepEventType::EvOutput,
            record_digest,
            output_reason,
        );
    }

    if let Some(gov) = &record.governance_frame {
        if !gov.policy_decision_refs.is_empty() {
            let _ = store.record_sep_event(
                commit_id,
                SepEventType::EvDecision,
                record_digest,
                Vec::new(),
            );
        }

        if !gov.dlp_refs.is_empty() {
            let _ = store.record_sep_event(
                commit_id,
                SepEventType::EvOutcome,
                record_digest,
                Vec::new(),
            );
        }
    }

    if record.metabolic_frame_ref.is_some() {
        let _ = store.record_sep_event(
            commit_id,
            SepEventType::EvProfileChange,
            record_digest,
            Vec::new(),
        );
    }

    if let Some(meta) = &record.metabolic_frame {
        if meta.profile_digest.is_some() {
            let _ = store.record_sep_event(
                commit_id,
                SepEventType::EvProfileChange,
                record_digest,
                Vec::new(),
            );
        }

        if !meta.outcome_refs.is_empty() {
            let _ = store.record_sep_event(
                commit_id,
                SepEventType::EvOutcome,
                record_digest,
                Vec::new(),
            );
        }
    }

    let _ = store.record_sep_event(
        commit_id,
        SepEventType::EvRecoveryGov,
        record_digest,
        vec!["RECORD_APPEND_OK".to_string()],
    );
}

fn digest_to_vec(digest: [u8; 32]) -> Vec<u8> {
    digest.to_vec()
}

fn digest_from_bytes(bytes: &[u8]) -> Option<[u8; 32]> {
    if bytes.len() != 32 {
        return None;
    }

    let mut digest = [0u8; 32];
    digest.copy_from_slice(bytes);
    Some(digest)
}

fn optional_proto_digest(value: &Option<Digest32>) -> Option<[u8; 32]> {
    value.as_ref().map(|d| d.0)
}

fn digest_from_ref(reference: &Ref) -> Option<[u8; 32]> {
    reference
        .digest
        .as_ref()
        .and_then(|digest| digest_from_bytes(digest))
        .or_else(|| digest_from_hex_str(&reference.id))
        .or_else(|| {
            reference
                .id
                .rsplit(':')
                .next()
                .and_then(digest_from_hex_str)
        })
        .or_else(|| digest_from_bytes(reference.id.as_bytes()))
}

fn micro_digest_from_ref(reference: &Ref, target_id: &str) -> Option<[u8; 32]> {
    let prefix = format!("{target_id}:");
    let value = reference.id.strip_prefix(&prefix)?;
    digest_from_labeled_value(value)
}

fn digest_from_labeled_value(value: &str) -> Option<[u8; 32]> {
    digest_from_hex_str(value).or_else(|| digest_from_bytes(value.as_bytes()))
}

fn add_macro_edges(
    store: &mut PvgsStore,
    macro_digest: [u8; 32],
    macro_milestone: &MacroMilestone,
    consistency_digest: Option<[u8; 32]>,
) {
    for meso_ref in &macro_milestone.meso_refs {
        if let Some(meso_digest) = digest_from_ref(meso_ref) {
            store.add_graph_edge(macro_digest, EdgeType::Finalizes, meso_digest, None);
        }
    }

    if let Some(consistency) = consistency_digest {
        store.add_graph_edge(macro_digest, EdgeType::Finalizes, consistency, None);
    }
}

fn digest_from_hex_str(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }

    let bytes = hex::decode(value).ok()?;
    digest_from_bytes(&bytes)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

const RC_RE_DLP_DECISION_MISSING: &str = "RC.RE.DLP_DECISION.MISSING";
const RC_RE_REPLAY_PLAN_REF_MISSING: &str = "RC.RE.REPLAY.PLAN_REF_MISSING";
const RC_RE_REPLAY_PLAN_MISSING: &str = "RC.RE.REPLAY.PLAN_MISSING";
const RC_RE_REPLAY_INVALID_EMBEDDED_ACTION: &str = "RC.RE.REPLAY.INVALID_EMBEDDED_ACTION";

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompletenessStatus {
    Ok,
    Degraded,
    Fail,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletenessReport {
    pub status: CompletenessStatus,
    pub missing_nodes: Vec<[u8; 32]>,
    pub missing_edges: Vec<String>,
    pub reason_codes: Vec<String>,
    pub critical_triggers: Vec<CriticalTrigger>,
}

#[derive(Debug)]
pub struct CompletenessChecker<'a> {
    graph: &'a CausalGraph,
    sep_log: &'a mut SepLog,
    dlp_store: &'a DlpDecisionStore,
    replay_plans: &'a ReplayPlanStore,
    asset_manifest_store: &'a AssetManifestStore,
    asset_bundle_store: &'a AssetBundleStore,
    records: &'a [ExperienceRecord],
}

impl<'a> CompletenessChecker<'a> {
    pub fn new(
        graph: &'a CausalGraph,
        sep_log: &'a mut SepLog,
        dlp_store: &'a DlpDecisionStore,
        replay_plans: &'a ReplayPlanStore,
        asset_manifest_store: &'a AssetManifestStore,
        asset_bundle_store: &'a AssetBundleStore,
        records: &'a [ExperienceRecord],
    ) -> Self {
        Self {
            graph,
            sep_log,
            dlp_store,
            replay_plans,
            asset_manifest_store,
            asset_bundle_store,
            records,
        }
    }

    /// Evaluate completeness for the provided action digests using graph-based rules.
    pub fn check_actions(
        &mut self,
        session_id: &str,
        action_digests: Vec<[u8; 32]>,
    ) -> CompletenessReport {
        use std::collections::BTreeSet;

        let mut status = CompletenessStatus::Ok;
        let mut missing_nodes: BTreeSet<[u8; 32]> = BTreeSet::new();
        let mut missing_edges: Vec<String> = Vec::new();
        let mut reason_codes: BTreeSet<String> = BTreeSet::new();
        let mut critical_triggers: BTreeSet<CriticalTrigger> = BTreeSet::new();

        let mut record_append_result = |result: Result<SepEventInternal, SepError>| {
            if let Err(SepError::Overflow) = result {
                critical_triggers.insert(CriticalTrigger::SepOverflow);
            }
        };

        let mut actions: BTreeSet<[u8; 32]> = action_digests.into_iter().collect();

        if actions.is_empty() {
            let session_receipts: Vec<[u8; 32]> = self
                .sep_log
                .events
                .iter()
                .filter(|event| {
                    event.session_id == session_id
                        && matches!(event.event_type, SepEventType::EvDecision)
                })
                .map(|event| event.object_digest)
                .collect();

            for receipt in &session_receipts {
                for (edge, action) in self.graph.reverse_neighbors(*receipt) {
                    if matches!(edge, EdgeType::Authorizes) {
                        actions.insert(*action);
                    }
                }
            }
        }

        if actions.is_empty() {
            for event in self
                .sep_log
                .events
                .iter()
                .filter(|event| event.session_id == session_id)
            {
                for (edge, target) in self.graph.neighbors(event.object_digest) {
                    if matches!(edge, EdgeType::References) {
                        actions.insert(*target);
                    }
                }
            }
        }

        let mut receipts_for_session: BTreeSet<[u8; 32]> = BTreeSet::new();

        for action in &actions {
            let receipts: Vec<[u8; 32]> = self
                .graph
                .neighbors(*action)
                .iter()
                .filter_map(|(edge, digest)| {
                    if matches!(edge, EdgeType::Authorizes) {
                        Some(*digest)
                    } else {
                        None
                    }
                })
                .collect();

            if receipts.is_empty() {
                status = CompletenessStatus::Fail;
                missing_nodes.insert(*action);
                missing_edges.push(format!(
                    "AUTHORIZES missing from action {} to receipt",
                    hex::encode(action)
                ));
                reason_codes.insert(protocol::ReasonCodes::RE_INTEGRITY_FAIL.to_string());
            } else {
                receipts_for_session.extend(receipts);
            }
        }

        for receipt in &receipts_for_session {
            let has_decision = self
                .graph
                .reverse_neighbors(*receipt)
                .iter()
                .any(|(edge, _)| matches!(edge, EdgeType::Authorizes));

            let referenced_by_record = self
                .graph
                .reverse_neighbors(*receipt)
                .iter()
                .filter(|(edge, _)| matches!(edge, EdgeType::References))
                .any(|(_, record)| {
                    self.graph
                        .neighbors(*record)
                        .iter()
                        .any(|(edge, _)| matches!(edge, EdgeType::References))
                });

            if !has_decision && !referenced_by_record {
                status = CompletenessStatus::Fail;
                missing_nodes.insert(*receipt);
                missing_edges.push(format!(
                    "decision AUTHORIZES missing for receipt {}",
                    hex::encode(receipt)
                ));
                reason_codes.insert(protocol::ReasonCodes::RE_INTEGRITY_FAIL.to_string());
            }
        }

        for action in &actions {
            let receipts: Vec<[u8; 32]> = self
                .graph
                .neighbors(*action)
                .iter()
                .filter_map(|(edge, digest)| {
                    if matches!(edge, EdgeType::Authorizes) {
                        Some(*digest)
                    } else {
                        None
                    }
                })
                .collect();

            for receipt in receipts {
                if !self.references_both(action, &receipt) {
                    if !matches!(status, CompletenessStatus::Fail) {
                        status = CompletenessStatus::Degraded;
                    }
                    missing_nodes.insert(*action);
                    missing_edges.push(format!(
                        "record missing REFERENCES links for action {} and receipt {}",
                        hex::encode(action),
                        hex::encode(receipt)
                    ));
                    reason_codes.insert(protocol::ReasonCodes::RE_INTEGRITY_DEGRADED.to_string());
                }
            }
        }

        for receipt in &receipts_for_session {
            let profile_digests: Vec<[u8; 32]> = self
                .graph
                .reverse_neighbors(*receipt)
                .iter()
                .filter_map(|(edge, digest)| {
                    if matches!(edge, EdgeType::References) {
                        Some(*digest)
                    } else {
                        None
                    }
                })
                .collect();

            if !profile_digests.is_empty()
                && !profile_digests.iter().any(|digest| {
                    self.sep_log.events.iter().any(|event| {
                        event.session_id == session_id
                            && matches!(event.event_type, SepEventType::EvControlFrame)
                            && event.object_digest == *digest
                    })
                })
            {
                if !matches!(status, CompletenessStatus::Fail) {
                    status = CompletenessStatus::Degraded;
                }
                missing_nodes.extend(profile_digests);
                missing_edges.push("control frame missing for receipt profile_digest".to_string());
                reason_codes.insert(protocol::ReasonCodes::RE_INTEGRITY_DEGRADED.to_string());
            }
        }

        // O-C1: Every RT_OUTPUT governance DLP reference must resolve to a stored decision.
        // TODO: Elevate to FAIL in production.
        let mut missing_dlp_decisions: BTreeSet<[u8; 32]> = BTreeSet::new();

        for output_digest in self.outputs_for_session(session_id) {
            if let Some(record) = self.find_record(output_digest) {
                for digest in dlp_digests_from_gov(record) {
                    if self.dlp_store.get(digest).is_none() && missing_dlp_decisions.insert(digest)
                    {
                        if !matches!(status, CompletenessStatus::Fail) {
                            status = CompletenessStatus::Degraded;
                        }
                        missing_nodes.insert(digest);
                        reason_codes
                            .insert(protocol::ReasonCodes::RE_INTEGRITY_DEGRADED.to_string());
                        reason_codes.insert(RC_RE_DLP_DECISION_MISSING.to_string());
                        record_append_result(self.sep_log.append_event(
                            session_id.to_string(),
                            SepEventType::EvDlpDecision,
                            digest,
                            vec![RC_RE_DLP_DECISION_MISSING.to_string()],
                        ));
                    }
                }
            }
        }

        for (record_digest, record) in self.replay_records_for_session(session_id) {
            let (plan_digest, has_embedded_action) = replay_plan_digest_from_record(&record);

            if has_embedded_action {
                status = CompletenessStatus::Fail;
                reason_codes.insert(protocol::ReasonCodes::RE_INTEGRITY_FAIL.to_string());
                reason_codes.insert(RC_RE_REPLAY_INVALID_EMBEDDED_ACTION.to_string());
                record_append_result(self.sep_log.append_event(
                    session_id.to_string(),
                    SepEventType::EvReplay,
                    record_digest,
                    vec![RC_RE_REPLAY_INVALID_EMBEDDED_ACTION.to_string()],
                ));
            }

            let Some(plan_digest) = plan_digest else {
                if !matches!(status, CompletenessStatus::Fail) {
                    status = CompletenessStatus::Degraded;
                }
                reason_codes.insert(protocol::ReasonCodes::RE_INTEGRITY_DEGRADED.to_string());
                reason_codes.insert(RC_RE_REPLAY_PLAN_REF_MISSING.to_string());
                continue;
            };

            let Some(plan) = self.replay_plan_by_digest(plan_digest) else {
                if !matches!(status, CompletenessStatus::Fail) {
                    status = CompletenessStatus::Degraded;
                }
                if missing_nodes.insert(plan_digest) {
                    record_append_result(self.sep_log.append_event(
                        session_id.to_string(),
                        SepEventType::EvReplay,
                        plan_digest,
                        vec![RC_RE_REPLAY_PLAN_MISSING.to_string()],
                    ));
                }
                reason_codes.insert(protocol::ReasonCodes::RE_INTEGRITY_DEGRADED.to_string());
                reason_codes.insert(RC_RE_REPLAY_PLAN_MISSING.to_string());
                continue;
            };

            if let Some(asset_ref) = &plan.asset_manifest_ref {
                let manifest_digest = digest_from_ref(asset_ref);
                let manifest_exists = manifest_digest
                    .and_then(|digest| self.asset_manifest_store.get(digest).map(|_| digest))
                    .is_some();

                if !manifest_exists {
                    status = CompletenessStatus::Fail;
                    reason_codes.insert(protocol::ReasonCodes::RE_INTEGRITY_FAIL.to_string());
                    reason_codes.insert(protocol::ReasonCodes::RE_REPLAY_MISMATCH.to_string());
                    reason_codes.insert(protocol::ReasonCodes::RE_REPLAY_ASSET_MISSING.to_string());

                    if let Some(missing_digest) = manifest_digest {
                        missing_nodes.insert(missing_digest);
                    }

                    record_append_result(self.sep_log.append_event(
                        session_id.to_string(),
                        SepEventType::EvReplay,
                        plan_digest,
                        vec![
                            protocol::ReasonCodes::RE_REPLAY_MISMATCH.to_string(),
                            protocol::ReasonCodes::RE_REPLAY_ASSET_MISSING.to_string(),
                        ],
                    ));
                    continue;
                }

                let bundle_exists = manifest_digest.is_some_and(|digest| {
                    self.asset_bundle_store.list().iter().any(|bundle| {
                        bundle
                            .manifest
                            .as_ref()
                            .and_then(|manifest| digest_from_bytes(&manifest.manifest_digest))
                            .is_some_and(|bundle_digest| bundle_digest == digest)
                    })
                });

                if !bundle_exists {
                    if !matches!(status, CompletenessStatus::Fail) {
                        status = CompletenessStatus::Degraded;
                    }
                    reason_codes.insert(protocol::ReasonCodes::RE_INTEGRITY_DEGRADED.to_string());
                    reason_codes
                        .insert(protocol::ReasonCodes::RE_REPLAY_ASSET_BUNDLE_MISSING.to_string());
                    record_append_result(self.sep_log.append_event(
                        session_id.to_string(),
                        SepEventType::EvReplay,
                        plan_digest,
                        vec![protocol::ReasonCodes::RE_REPLAY_ASSET_BUNDLE_MISSING.to_string()],
                    ));
                }
            }
        }

        missing_edges.sort();

        if matches!(status, CompletenessStatus::Fail) {
            critical_triggers.insert(CriticalTrigger::IntegrityFail);
        }

        CompletenessReport {
            status,
            missing_nodes: missing_nodes.into_iter().collect(),
            missing_edges,
            reason_codes: reason_codes.into_iter().collect(),
            critical_triggers: critical_triggers.into_iter().collect(),
        }
    }

    fn references_both(&self, action: &[u8; 32], receipt: &[u8; 32]) -> bool {
        let mut nodes: Vec<[u8; 32]> = self
            .graph
            .adj
            .keys()
            .copied()
            .chain(self.graph.rev.keys().copied())
            .collect();
        nodes.sort();
        nodes.dedup();

        nodes.into_iter().any(|node| {
            self.references(node, action) && self.references(node, receipt)
                || self.references(*action, &node) && self.references(*receipt, &node)
        })
    }

    fn outputs_for_session(&self, session_id: &str) -> Vec<[u8; 32]> {
        let mut outputs = std::collections::BTreeSet::new();

        for event in self.sep_log.events.iter().filter(|event| {
            event.session_id == session_id && matches!(event.event_type, SepEventType::EvOutput)
        }) {
            outputs.insert(event.object_digest);
        }

        outputs.into_iter().collect()
    }

    fn replay_records_for_session(&self, session_id: &str) -> Vec<([u8; 32], ExperienceRecord)> {
        self.sep_log
            .events
            .iter()
            .filter(|event| {
                event.session_id == session_id
                    && matches!(event.event_type, SepEventType::EvAgentStep)
            })
            .filter_map(|event| {
                self.find_record(event.object_digest).and_then(|record| {
                    RecordType::try_from(record.record_type)
                        .ok()
                        .filter(|record_type| matches!(record_type, RecordType::RtReplay))
                        .map(|_| (compute_experience_record_digest(record), record.clone()))
                })
            })
            .collect()
    }

    fn replay_plan_by_digest(&self, digest: [u8; 32]) -> Option<&ReplayPlan> {
        self.replay_plans
            .plans
            .iter()
            .find(|plan| digest_from_bytes(&plan.replay_digest) == Some(digest))
    }

    fn find_record(&self, record_digest: [u8; 32]) -> Option<&ExperienceRecord> {
        self.records
            .iter()
            .find(|record| compute_experience_record_digest(record) == record_digest)
    }

    fn references(&self, from: [u8; 32], to: &[u8; 32]) -> bool {
        self.graph
            .neighbors(from)
            .iter()
            .any(|(edge, digest)| matches!(edge, EdgeType::References) && digest == to)
            || self
                .graph
                .reverse_neighbors(from)
                .iter()
                .any(|(edge, digest)| matches!(edge, EdgeType::References) && digest == to)
    }
}

fn replay_plan_digest_from_record(record: &ExperienceRecord) -> (Option<[u8; 32]>, bool) {
    let mut has_embedded_action = false;
    let mut replay_plan_digest = None;

    if let Some(gov) = &record.governance_frame {
        for reference in &gov.policy_decision_refs {
            match reference.id.split(':').next().unwrap_or("") {
                "replay_plan" => {
                    if replay_plan_digest.is_none() {
                        replay_plan_digest = digest_from_ref(reference);
                    }
                }
                "action" | "action_spec" => {
                    has_embedded_action = true;
                }
                _ => {}
            }
        }
    }

    if replay_plan_digest.is_none() {
        if let Some(reference) = &record.governance_frame_ref {
            replay_plan_digest = digest_from_ref(reference);
        }
    }

    (replay_plan_digest, has_embedded_action)
}

fn replay_run_digest_from_record(record: &ExperienceRecord) -> Option<[u8; 32]> {
    let Some(gov) = &record.governance_frame else {
        return None;
    };

    for reference in &gov.policy_decision_refs {
        if reference.id == "replay_run"
            || reference.id.starts_with("replay_run:")
            || reference.id == "replay_run_evidence"
            || reference.id.starts_with("replay_run_evidence:")
        {
            if let Some(digest) = digest_from_ref(reference) {
                return Some(digest);
            }
        }
    }

    None
}

fn key_epoch_payload_digest(req: &PvgsCommitRequest) -> Option<[u8; 32]> {
    req.payload_digests.first().copied()
}

fn dlp_digests_from_gov(record: &ExperienceRecord) -> Vec<[u8; 32]> {
    let mut digests = std::collections::BTreeSet::new();

    if let Some(gov) = &record.governance_frame {
        for reference in &gov.dlp_refs {
            if let Some(digest) = digest_from_ref(reference) {
                digests.insert(digest);
            }
        }
    }

    digests.into_iter().collect()
}

fn validate_key_epoch_update(
    req: &PvgsCommitRequest,
    store: &PvgsStore,
) -> Result<(PVGSKeyEpoch, [u8; 32]), Vec<String>> {
    if !req.required_checks.contains(&RequiredCheck::SchemaOk)
        || !req.required_checks.contains(&RequiredCheck::BindingOk)
    {
        return Err(vec![
            protocol::ReasonCodes::GV_KEY_EPOCH_REQUIRED_CHECK.to_string()
        ]);
    }

    let Some(key_epoch) = req.key_epoch.as_ref() else {
        return Err(vec![
            protocol::ReasonCodes::GV_KEY_EPOCH_PAYLOAD_INVALID.to_string()
        ]);
    };

    if req.payload_digests.len() != 1 {
        return Err(vec![
            protocol::ReasonCodes::GV_KEY_EPOCH_PAYLOAD_INVALID.to_string()
        ]);
    }

    let payload_digest = req.payload_digests[0];

    if payload_digest != key_epoch.announcement_digest.0 {
        return Err(vec![
            protocol::ReasonCodes::GV_KEY_EPOCH_PAYLOAD_INVALID.to_string()
        ]);
    }

    if store.committed_payload_digests.contains(&payload_digest) {
        return Err(vec![
            protocol::ReasonCodes::GV_KEY_EPOCH_DUPLICATE.to_string()
        ]);
    }

    if !verify_key_epoch_signature(key_epoch) {
        return Err(vec![
            protocol::ReasonCodes::GV_KEY_EPOCH_SIGNATURE_INVALID.to_string()
        ]);
    }

    let mut reject_reason_codes = Vec::new();
    if let Some(latest) = store.key_epoch_history.current() {
        if key_epoch.key_epoch_id != latest.key_epoch_id + 1 {
            reject_reason_codes.push(protocol::ReasonCodes::GV_KEY_EPOCH_NON_MONOTONIC.to_string());
        }

        match key_epoch.prev_key_epoch_digest.as_ref() {
            Some(prev) if prev.0 == latest.announcement_digest.0 => {}
            _ => reject_reason_codes.push(protocol::ReasonCodes::GV_KEY_EPOCH_UNKNOWN.to_string()),
        }
    } else if key_epoch.prev_key_epoch_digest.is_some() {
        reject_reason_codes.push(protocol::ReasonCodes::GV_KEY_EPOCH_UNKNOWN.to_string());
    }

    if reject_reason_codes.is_empty() {
        Ok((key_epoch.clone(), payload_digest))
    } else {
        Err(reject_reason_codes)
    }
}

struct FinalizeReceiptArgs<'a> {
    req: &'a PvgsCommitRequest,
    receipt_input: &'a ReceiptInput,
    status: ReceiptStatus,
    reject_reason_codes: Vec<String>,
    store: &'a mut PvgsStore,
    keystore: &'a KeyStore,
    frame_kind: Option<FrameEventKind>,
    event_object_digest: Option<[u8; 32]>,
    event_reason_codes: Option<Vec<String>>,
}

fn finalize_receipt(args: FinalizeReceiptArgs) -> (PVGSReceipt, Option<ProofReceipt>) {
    let FinalizeReceiptArgs {
        req,
        receipt_input,
        status,
        mut reject_reason_codes,
        store,
        keystore,
        frame_kind,
        event_object_digest,
        event_reason_codes,
    } = args;
    if matches!(status, ReceiptStatus::Rejected) && reject_reason_codes.is_empty() {
        reject_reason_codes.push(protocol::ReasonCodes::GE_GRANT_MISSING.to_string());
    }

    if matches!(status, ReceiptStatus::Accepted) {
        reject_reason_codes.clear();
    }

    let receipt = issue_receipt(receipt_input, status, reject_reason_codes, keystore);
    let event_type = event_type_for_commit(req.commit_type, frame_kind);

    if matches!(receipt.status, ReceiptStatus::Accepted) {
        store.add_receipt_edges(&receipt);
    }

    let object_digest = event_object_digest.unwrap_or(receipt.receipt_digest.0);
    let reason_codes = event_reason_codes.unwrap_or_else(|| receipt.reject_reason_codes.clone());

    if matches!(req.commit_type, CommitType::FrameEvidenceAppend) {
        let kind = frame_kind.unwrap_or(FrameEventKind::SignalFrame);
        let _ = store.record_sep_frame_event(&req.commit_id, kind, object_digest, reason_codes);
    } else {
        let _ = store.record_sep_event(&req.commit_id, event_type, object_digest, reason_codes);
    }

    (receipt, None)
}

fn update_optional_digest(hasher: &mut Hasher, digest: &Option<[u8; 32]>) {
    match digest {
        Some(d) => {
            hasher.update(&[1u8]);
            hasher.update(d);
        }
        None => {
            hasher.update(&[0u8]);
        }
    }
}

fn update_optional_string(hasher: &mut Hasher, value: &Option<String>) {
    match value {
        Some(v) => {
            hasher.update(&[1u8]);
            hasher.update(v.as_bytes());
        }
        None => {
            hasher.update(&[0u8]);
        }
    }
}

fn required_receipt_kind_label(kind: &RequiredReceiptKind) -> &'static str {
    match kind {
        RequiredReceiptKind::Read => "READ",
        RequiredReceiptKind::Transform => "TRANSFORM",
        RequiredReceiptKind::Write => "WRITE",
        RequiredReceiptKind::Execute => "EXECUTE",
        RequiredReceiptKind::Export => "EXPORT",
        RequiredReceiptKind::Persist => "PERSIST",
    }
}

impl From<CommitType> for protocol::CommitType {
    fn from(value: CommitType) -> Self {
        match value {
            CommitType::ReceiptRequest => protocol::CommitType::ReceiptRequest,
            CommitType::RecordAppend => protocol::CommitType::RecordAppend,
            CommitType::ExperienceRecordAppend => protocol::CommitType::ExperienceRecordAppend,
            CommitType::MilestoneAppend => protocol::CommitType::MilestoneAppend,
            CommitType::MacroMilestonePropose => protocol::CommitType::MacroMilestonePropose,
            CommitType::MacroMilestoneFinalize => protocol::CommitType::MacroMilestoneFinalize,
            CommitType::ConsistencyFeedbackAppend => {
                protocol::CommitType::ConsistencyFeedbackAppend
            }
            CommitType::CharterUpdate => protocol::CommitType::CharterUpdate,
            CommitType::ToolRegistryUpdate => protocol::CommitType::ToolRegistryUpdate,
            CommitType::ToolOnboardingEventAppend => {
                protocol::CommitType::ToolOnboardingEventAppend
            }
            CommitType::RecoveryCaseCreate => protocol::CommitType::RecoveryCaseCreate,
            CommitType::RecoveryCaseAdvance => protocol::CommitType::RecoveryCaseAdvance,
            CommitType::RecoveryApproval => protocol::CommitType::RecoveryApproval,
            CommitType::RecoveryUpdate => protocol::CommitType::RecoveryUpdate,
            CommitType::PevUpdate => protocol::CommitType::PevUpdate,
            CommitType::CbvUpdate => protocol::CommitType::CbvUpdate,
            CommitType::KeyEpochUpdate => protocol::CommitType::KeyEpochUpdate,
            CommitType::FrameEvidenceAppend => protocol::CommitType::FrameEvidenceAppend,
            CommitType::DlpDecisionAppend => protocol::CommitType::DlpDecisionAppend,
            CommitType::ReplayPlanAppend => protocol::CommitType::ReplayPlanAppend,
            CommitType::ReplayRunEvidenceAppend => protocol::CommitType::ReplayRunEvidenceAppend,
            CommitType::TraceRunEvidenceAppend => protocol::CommitType::TraceRunEvidenceAppend,
            CommitType::MicrocircuitConfigAppend => protocol::CommitType::MicrocircuitConfigAppend,
            CommitType::AssetManifestAppend => protocol::CommitType::AssetManifestAppend,
            CommitType::AssetBundleAppend => protocol::CommitType::AssetBundleAppend,
            CommitType::ProposalEvidenceAppend => protocol::CommitType::ProposalEvidenceAppend,
            CommitType::ProposalActivationAppend => protocol::CommitType::ProposalActivationAppend,
        }
    }
}

impl From<RequiredCheck> for protocol::RequiredCheck {
    fn from(value: RequiredCheck) -> Self {
        match value {
            RequiredCheck::SchemaOk => protocol::RequiredCheck::SchemaOk,
            RequiredCheck::BindingOk => protocol::RequiredCheck::BindingOk,
            RequiredCheck::TightenOnly => protocol::RequiredCheck::TightenOnly,
            RequiredCheck::IntegrityOk => protocol::RequiredCheck::IntegrityOk,
        }
    }
}

impl From<&CommitBindings> for protocol::CommitBindings {
    fn from(value: &CommitBindings) -> Self {
        protocol::CommitBindings {
            action_digest: value.action_digest.map(Digest32),
            decision_digest: value.decision_digest.map(Digest32),
            grant_id: value.grant_id.clone(),
            charter_version_digest: value.charter_version_digest.clone(),
            policy_version_digest: value.policy_version_digest.clone(),
            prev_record_digest: Digest32(value.prev_record_digest),
            profile_digest: value.profile_digest.map(Digest32),
            tool_profile_digest: value.tool_profile_digest.map(Digest32),
            pev_digest: value.pev_digest.map(Digest32),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::UnlockPermit;
    use super::*;
    use assets::{
        compute_asset_bundle_digest, compute_asset_chunk_digest, compute_asset_manifest_digest,
    };
    use micro_evidence::compute_config_digest;
    use milestones::{
        derive_micro_from_experience_window, ExperienceRange, MicroMilestone, MicroMilestoneState,
        PriorityClass,
    };
    use proposals::ProposalKind;
    use prost::Message;
    use protocol::ReasonCodes;
    use receipts::verify_pvgs_receipt_attestation;
    use recovery::{RecoveryCase, RecoveryCheck, RecoveryState};
    use sep::{EdgeType, SepEventType};
    use ucf_protocol::ucf::v1::{
        AssetBundle, AssetChunk, AssetDigest, AssetKind, AssetManifest, CompressionMode,
        ConsistencyFeedback, CoreFrame, GovernanceFrame, MacroMilestone, MacroMilestoneState,
        MagnitudeClass, MetabolicFrame, MicroModule, MicrocircuitConfigEvidence, MorphologyEntry,
        MorphologySetPayload, PolicyEcologyDimension, PolicyEcologyVector, RecordType, Ref,
        ReplayRunEvidence, ReplayTargetKind, ToolOnboardingEvent, ToolOnboardingStage,
        TraitDirection, TraitUpdate,
    };
    use vrf::VrfEngine;

    fn base_store(prev_digest: [u8; 32]) -> PvgsStore {
        let mut known_charter_versions = HashSet::new();
        known_charter_versions.insert("charter".to_string());
        let mut known_policy_versions = HashSet::new();
        known_policy_versions.insert("policy".to_string());
        let mut known_profiles = HashSet::new();
        known_profiles.insert([9u8; 32]);

        PvgsStore::new(
            prev_digest,
            "charter".to_string(),
            "policy".to_string(),
            known_charter_versions,
            known_policy_versions,
            known_profiles,
        )
    }

    fn empty_asset_stores() -> (AssetManifestStore, AssetBundleStore) {
        (AssetManifestStore::default(), AssetBundleStore::default())
    }

    fn make_request(prev: [u8; 32]) -> PvgsCommitRequest {
        PvgsCommitRequest {
            commit_id: "commit-1".to_string(),
            commit_type: CommitType::ReceiptRequest,
            bindings: CommitBindings {
                action_digest: Some([1u8; 32]),
                decision_digest: Some([2u8; 32]),
                grant_id: Some("grant".to_string()),
                charter_version_digest: "charter".to_string(),
                policy_version_digest: "policy".to_string(),
                prev_record_digest: prev,
                profile_digest: Some([9u8; 32]),
                tool_profile_digest: Some([3u8; 32]),
                pev_digest: None,
            },
            required_receipt_kind: RequiredReceiptKind::Read,
            required_checks: vec![RequiredCheck::BindingOk],
            payload_digests: vec![[4u8; 32]],
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
            asset_bundle_payload: None,
        }
    }

    fn recovery_case_for(
        recovery_id: &str,
        session_id: &str,
        state: RecoveryState,
        completed_checks: Vec<RecoveryCheck>,
    ) -> RecoveryCase {
        RecoveryCase {
            recovery_id: recovery_id.to_string(),
            session_id: session_id.to_string(),
            state,
            required_checks: vec![RecoveryCheck::IntegrityOk, RecoveryCheck::ValidationPassed],
            completed_checks,
            trigger_refs: vec!["trigger".to_string()],
            created_at_ms: None,
        }
    }

    fn recovery_request(
        commit_type: CommitType,
        recovery_case: Option<RecoveryCase>,
        prev: [u8; 32],
    ) -> PvgsCommitRequest {
        PvgsCommitRequest {
            commit_id: "recovery-commit".to_string(),
            commit_type,
            bindings: CommitBindings {
                action_digest: None,
                decision_digest: None,
                grant_id: None,
                charter_version_digest: "charter".to_string(),
                policy_version_digest: "policy".to_string(),
                prev_record_digest: prev,
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
            recovery_case,
            unlock_permit: None,
            tool_onboarding_event: None,
            microcircuit_config_payload: None,
            asset_manifest_payload: None,
            asset_bundle_payload: None,
        }
    }

    fn make_key_epoch_request(
        keystore: &KeyStore,
        vrf_engine: &VrfEngine,
        store: &PvgsStore,
        key_epoch_id: u64,
        prev_digest: Option<[u8; 32]>,
        commit_id: &str,
    ) -> (PvgsCommitRequest, PVGSKeyEpoch) {
        let epoch = keystore.make_key_epoch_proto(
            key_epoch_id,
            100 * key_epoch_id,
            vrf_engine.vrf_public_key().to_vec(),
            prev_digest,
        );

        (
            PvgsCommitRequest {
                commit_id: commit_id.to_string(),
                commit_type: CommitType::KeyEpochUpdate,
                bindings: CommitBindings {
                    action_digest: None,
                    decision_digest: None,
                    grant_id: None,
                    charter_version_digest: "charter".to_string(),
                    policy_version_digest: "policy".to_string(),
                    prev_record_digest: store.current_head_record_digest,
                    profile_digest: Some([9u8; 32]),
                    tool_profile_digest: None,
                    pev_digest: None,
                },
                required_receipt_kind: RequiredReceiptKind::Read,
                required_checks: vec![RequiredCheck::SchemaOk, RequiredCheck::BindingOk],
                payload_digests: vec![epoch.announcement_digest.0],
                epoch_id: keystore.current_epoch(),
                key_epoch: Some(epoch.clone()),
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
            },
            epoch,
        )
    }

    fn cbv_update(name: &str, direction: TraitDirection, magnitude: MagnitudeClass) -> TraitUpdate {
        TraitUpdate {
            trait_name: name.to_string(),
            direction: direction as i32,
            magnitude_class: magnitude as i32,
        }
    }

    fn macro_with_updates(id: &str, updates: Vec<TraitUpdate>) -> MacroMilestone {
        let mut milestone = macro_with_state(id, MacroMilestoneState::Finalized);
        milestone.trait_updates = updates;
        milestone.macro_digest = vec![1u8; 32];
        milestone
    }

    fn macro_with_state(id: &str, state: MacroMilestoneState) -> MacroMilestone {
        let (proof_receipt_ref, consistency_feedback_ref) =
            if matches!(state, MacroMilestoneState::Finalized) {
                (Some(Ref::default()), Some(Ref::default()))
            } else {
                (None, None)
            };

        MacroMilestone {
            macro_id: id.to_string(),
            macro_digest: vec![2u8; 32],
            state: state as i32,
            trait_updates: Vec::new(),
            meso_refs: Vec::new(),
            consistency_class: "CONSISTENCY_HIGH".to_string(),
            identity_anchor_flag: true,
            proof_receipt_ref,
            consistency_digest: None,
            consistency_feedback_ref,
        }
    }

    fn macro_proposal_from(finalized: &MacroMilestone) -> MacroMilestone {
        let mut proposal = finalized.clone();
        proposal.state = MacroMilestoneState::Proposed as i32;
        proposal.proof_receipt_ref = None;
        proposal.consistency_feedback_ref = None;
        proposal
    }

    fn store_consistency_feedback(store: &mut PvgsStore, digest: [u8; 32], class: &str) {
        let feedback = ConsistencyFeedback {
            cf_digest: Some(digest.to_vec()),
            consistency_class: class.to_string(),
            flags: Vec::new(),
            proof_receipt_ref: None,
        };

        store
            .consistency_store
            .insert(feedback)
            .expect("valid feedback");
    }

    fn track_consistency_feedback(
        store: &mut PvgsStore,
        session_id: &str,
        digest: [u8; 32],
        class: &str,
    ) {
        store_consistency_feedback(store, digest, class);
        store
            .consistency_history
            .push(session_id.to_string(), digest);
    }

    fn micro_with_priority(id: u64, priority: PriorityClass) -> MicroMilestone {
        let range = ExperienceRange {
            start_experience_id: id * 10,
            end_experience_id: id * 10 + 5,
            head_record_digest: vec![1u8; 32],
        };

        MicroMilestone {
            micro_id: format!("micro:s:{id}:{}", id * 10 + 5),
            experience_range: Some(range),
            summary_digest: vec![2u8; 32],
            hormone_profile: None,
            priority_class: priority as i32,
            state: MicroMilestoneState::Sealed as i32,
            micro_digest: vec![id as u8; 32],
            proof_receipt_ref: None,
        }
    }

    fn sample_micro(id: u64) -> MicroMilestone {
        let range = ExperienceRange {
            start_experience_id: id * 10,
            end_experience_id: id * 10 + 5,
            head_record_digest: vec![1u8; 32],
        };

        MicroMilestone {
            micro_id: format!("micro:s:{id}:{}", id * 10 + 5),
            experience_range: Some(range),
            summary_digest: vec![2u8; 32],
            hormone_profile: None,
            priority_class: PriorityClass::Med as i32,
            state: MicroMilestoneState::Sealed as i32,
            micro_digest: vec![id as u8; 32],
            proof_receipt_ref: None,
        }
    }

    fn make_macro_request(
        macro_milestone: &MacroMilestone,
        store: &PvgsStore,
        epoch_id: u64,
        consistency_digest: Option<[u8; 32]>,
        commit_type: CommitType,
    ) -> PvgsCommitRequest {
        let macro_digest = digest_from_bytes(&macro_milestone.macro_digest).unwrap();

        let mut payload_digests = vec![macro_digest];
        if let Some(consistency) = consistency_digest {
            payload_digests.push(consistency);
        }

        PvgsCommitRequest {
            commit_id: macro_milestone.macro_id.clone(),
            commit_type,
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
            payload_digests,
            epoch_id,
            key_epoch: None,
            experience_record_payload: None,
            replay_run_evidence_payload: None,
            trace_run_evidence_payload: None,
            proposal_evidence_payload: None,
            proposal_activation_payload: None,
            macro_milestone: Some(macro_milestone.clone()),
            meso_milestone: None,
            dlp_decision_payload: None,
            tool_registry_container: None,
            pev: None,
            consistency_feedback_payload: None,
            macro_consistency_digest: consistency_digest,
            recovery_case: None,
            unlock_permit: None,
            tool_onboarding_event: None,
            microcircuit_config_payload: None,
            asset_manifest_payload: None,
            asset_bundle_payload: None,
        }
    }

    fn module_label(module: MicroModule) -> &'static str {
        match module {
            MicroModule::Lc => "LC",
            MicroModule::Sn => "SN",
            MicroModule::Hpa => "HPA",
            MicroModule::Unspecified => "UNSPECIFIED",
        }
    }

    fn micro_config_evidence(
        module: MicroModule,
        version: u32,
        canonical_config_bytes: &[u8],
    ) -> MicrocircuitConfigEvidence {
        MicrocircuitConfigEvidence {
            module: module as i32,
            config_version: version,
            config_digest: compute_config_digest(
                module_label(module),
                version,
                canonical_config_bytes,
            )
            .to_vec(),
            created_at_ms: 123,
            attested_by_key_id: None,
            signature: None,
        }
    }

    fn asset_manifest_payload(created_at_ms: u64, asset_seed: u8) -> (AssetManifest, [u8; 32]) {
        let mut manifest = AssetManifest {
            manifest_digest: Vec::new(),
            created_at_ms,
            asset_digests: vec![
                AssetDigest {
                    kind: AssetKind::Morphology as i32,
                    digest: [asset_seed; 32].to_vec(),
                    version: 1,
                },
                AssetDigest {
                    kind: AssetKind::Channel as i32,
                    digest: [asset_seed.wrapping_add(1); 32].to_vec(),
                    version: 1,
                },
            ],
        };
        let digest = compute_asset_manifest_digest(&manifest);
        manifest.manifest_digest = digest.to_vec();
        (manifest, digest)
    }

    fn asset_manifest_request(store: &PvgsStore, manifest: &AssetManifest) -> PvgsCommitRequest {
        let payload = manifest.encode_to_vec();
        PvgsCommitRequest {
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
            required_checks: vec![RequiredCheck::SchemaOk, RequiredCheck::BindingOk],
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
            asset_manifest_payload: Some(payload),
            asset_bundle_payload: None,
        }
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

        let chunk_payload_one = b"chunk-one".to_vec();
        let chunk_payload_two = b"chunk-two".to_vec();
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

    fn asset_bundle_with_payload(
        created_at_ms: u64,
        asset_seed: u8,
        kind: AssetKind,
        payload: Vec<u8>,
    ) -> (AssetBundle, [u8; 32], [u8; 32]) {
        let asset_digest = [asset_seed; 32];
        let mut manifest = AssetManifest {
            manifest_digest: Vec::new(),
            created_at_ms,
            asset_digests: vec![AssetDigest {
                kind: kind as i32,
                digest: asset_digest.to_vec(),
                version: 1,
            }],
        };
        let manifest_digest = compute_asset_manifest_digest(&manifest);
        manifest.manifest_digest = manifest_digest.to_vec();

        let chunk = AssetChunk {
            asset_digest: asset_digest.to_vec(),
            chunk_index: 0,
            chunk_count: 1,
            payload: payload.clone(),
            chunk_digest: compute_asset_chunk_digest(&payload).to_vec(),
            compression_mode: CompressionMode::None as i32,
        };

        let mut bundle = AssetBundle {
            bundle_digest: Vec::new(),
            created_at_ms,
            manifest: Some(manifest),
            chunks: vec![chunk],
        };
        let bundle_digest =
            compute_asset_bundle_digest(bundle.manifest.as_ref().unwrap(), &bundle.chunks)
                .expect("bundle digest computed");
        bundle.bundle_digest = bundle_digest.to_vec();

        (bundle, bundle_digest, asset_digest)
    }

    fn asset_bundle_request(store: &PvgsStore, bundle: &AssetBundle) -> PvgsCommitRequest {
        let payload = bundle.encode_to_vec();
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
            required_checks: vec![RequiredCheck::SchemaOk, RequiredCheck::BindingOk],
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
            asset_bundle_payload: Some(payload),
        }
    }

    fn micro_config_request(
        store: &PvgsStore,
        module: MicroModule,
        version: u32,
        canonical_config_bytes: &[u8],
    ) -> PvgsCommitRequest {
        let evidence = micro_config_evidence(module, version, canonical_config_bytes);
        let payload = evidence.encode_to_vec();
        PvgsCommitRequest {
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
            required_checks: vec![RequiredCheck::SchemaOk, RequiredCheck::BindingOk],
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
            microcircuit_config_payload: Some(payload),
            asset_manifest_payload: None,
            asset_bundle_payload: None,
        }
    }

    #[test]
    fn microcircuit_config_append_accepts_and_logs() {
        let mut store = base_store([7u8; 32]);
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);
        let config_bytes = br#"{\"enabled\":true}"#;
        let expected_digest = compute_config_digest("LC", 1, config_bytes);

        let req = micro_config_request(&store, MicroModule::Lc, 1, config_bytes);
        let (receipt, proof_receipt) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);

        assert_eq!(receipt.status, ReceiptStatus::Accepted);
        assert!(proof_receipt.is_some());

        let stored = store
            .micro_config_store
            .latest_for_module(MicroModule::Lc)
            .expect("config stored");
        assert_eq!(stored.config_digest, expected_digest.to_vec());
        assert_eq!(stored.config_version, 1);

        let has_event = store.sep_log.events.iter().any(|event| {
            event.event_type == SepEventType::EvRecoveryGov
                && event.object_digest == expected_digest
                && event
                    .reason_codes
                    .contains(&ReasonCodes::GV_MICROCIRCUIT_CONFIG_APPENDED.to_string())
        });
        assert!(has_event);
    }

    #[test]
    fn microcircuit_config_rejects_unspecified_module() {
        let mut store = base_store([7u8; 32]);
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);
        let config_bytes = br#"{\"enabled\":true}"#;

        let req = micro_config_request(&store, MicroModule::Unspecified, 1, config_bytes);
        let (receipt, proof_receipt) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);

        assert_eq!(receipt.status, ReceiptStatus::Rejected);
        assert!(proof_receipt.is_none());
        assert!(store
            .micro_config_store
            .latest_for_module(MicroModule::Unspecified)
            .is_none());
    }

    #[test]
    fn microcircuit_config_append_is_idempotent() {
        let mut store = base_store([7u8; 32]);
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);
        let config_bytes = br#"{\"enabled\":true}"#;
        let expected_digest = compute_config_digest("LC", 1, config_bytes);

        let first_req = micro_config_request(&store, MicroModule::Lc, 1, config_bytes);
        let second_req = micro_config_request(&store, MicroModule::Lc, 1, config_bytes);

        let (first_receipt, first_proof) =
            verify_and_commit(first_req, &mut store, &keystore, &vrf_engine);
        let (second_receipt, second_proof) =
            verify_and_commit(second_req, &mut store, &keystore, &vrf_engine);

        assert_eq!(first_receipt.status, ReceiptStatus::Accepted);
        assert!(first_proof.is_some());
        assert_eq!(second_receipt.status, ReceiptStatus::Accepted);
        assert!(second_proof.is_some());

        let stored = store
            .micro_config_store
            .latest_for_module(MicroModule::Lc)
            .expect("config stored");
        assert_eq!(stored.config_digest, expected_digest.to_vec());
        assert_eq!(store.micro_config_store.list_all().len(), 1);
    }

    #[test]
    fn microcircuit_config_append_accepts_hpa() {
        let mut store = base_store([7u8; 32]);
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);
        let config_bytes = br#"{\"enabled\":true}"#;
        let expected_digest = compute_config_digest("HPA", 2, config_bytes);

        let req = micro_config_request(&store, MicroModule::Hpa, 2, config_bytes);
        let (receipt, proof_receipt) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);

        assert_eq!(receipt.status, ReceiptStatus::Accepted);
        assert!(proof_receipt.is_some());

        let stored = store
            .micro_config_store
            .latest_for_module(MicroModule::Hpa)
            .expect("config stored");
        assert_eq!(stored.config_digest, expected_digest.to_vec());
        assert_eq!(stored.config_version, 2);
    }

    #[test]
    fn asset_manifest_append_accepts_and_logs() {
        let mut store = base_store([7u8; 32]);
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);
        let (manifest, digest) = asset_manifest_payload(42, 10);

        let req = asset_manifest_request(&store, &manifest);
        let (receipt, proof_receipt) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);

        assert_eq!(receipt.status, ReceiptStatus::Accepted);
        assert!(proof_receipt.is_some());

        let stored = store
            .asset_manifest_store
            .get(digest)
            .expect("manifest stored");
        assert_eq!(stored.manifest_digest, manifest.manifest_digest);

        let has_event = store.sep_log.events.iter().any(|event| {
            event.event_type == SepEventType::EvRecoveryGov
                && event.object_digest == digest
                && event
                    .reason_codes
                    .contains(&ReasonCodes::GV_ASSET_MANIFEST_APPENDED.to_string())
        });
        assert!(has_event);
    }

    #[test]
    fn asset_manifest_append_rejects_digest_mismatch() {
        let mut store = base_store([7u8; 32]);
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);
        let (mut manifest, _) = asset_manifest_payload(42, 10);
        manifest.manifest_digest = vec![9u8; 32];

        let req = asset_manifest_request(&store, &manifest);
        let (receipt, proof_receipt) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);

        assert_eq!(receipt.status, ReceiptStatus::Rejected);
        assert!(proof_receipt.is_none());
        assert!(store.asset_manifest_store.list().is_empty());
    }

    #[test]
    fn asset_manifest_append_is_idempotent() {
        let mut store = base_store([7u8; 32]);
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);
        let (manifest, digest) = asset_manifest_payload(42, 10);

        let first_req = asset_manifest_request(&store, &manifest);
        let second_req = asset_manifest_request(&store, &manifest);

        let (first_receipt, first_proof) =
            verify_and_commit(first_req, &mut store, &keystore, &vrf_engine);
        let (second_receipt, second_proof) =
            verify_and_commit(second_req, &mut store, &keystore, &vrf_engine);

        assert_eq!(first_receipt.status, ReceiptStatus::Accepted);
        assert!(first_proof.is_some());
        assert_eq!(second_receipt.status, ReceiptStatus::Accepted);
        assert!(second_proof.is_some());
        assert_eq!(store.asset_manifest_store.list().len(), 1);
        assert!(store.asset_manifest_store.get(digest).is_some());
    }

    #[test]
    fn asset_bundle_append_accepts_and_logs() {
        let mut store = base_store([7u8; 32]);
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);
        let (bundle, digest, asset_digest) = asset_bundle_payload(55, 12);

        let req = asset_bundle_request(&store, &bundle);
        let (receipt, proof_receipt) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);

        assert_eq!(receipt.status, ReceiptStatus::Accepted);
        assert!(proof_receipt.is_some());

        let stored = store.asset_bundle_store.get(digest).expect("bundle stored");
        assert_eq!(stored.bundle_digest, bundle.bundle_digest);
        assert_eq!(
            store
                .asset_bundle_store
                .chunks_for_asset(asset_digest)
                .unwrap()
                .len(),
            2
        );

        let has_event = store.sep_log.events.iter().any(|event| {
            event.event_type == SepEventType::EvRecoveryGov
                && event.object_digest == digest
                && event
                    .reason_codes
                    .contains(&ReasonCodes::GV_ASSET_BUNDLE_APPENDED.to_string())
        });
        assert!(has_event);
    }

    #[test]
    fn asset_bundle_append_accepts_canonical_payload() {
        let mut store = base_store([7u8; 32]);
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);
        let payload = MorphologySetPayload {
            morphologies: vec![
                MorphologyEntry {
                    neuron_id: 1,
                    pool_label: "pool-a".to_string(),
                    role_label: "role-a".to_string(),
                    payload: vec![1u8],
                },
                MorphologyEntry {
                    neuron_id: 2,
                    pool_label: "pool-b".to_string(),
                    role_label: "role-b".to_string(),
                    payload: vec![2u8],
                },
            ],
        };
        let (bundle, _, _) =
            asset_bundle_with_payload(55, 12, AssetKind::Morphology, payload.encode_to_vec());

        let req = asset_bundle_request(&store, &bundle);
        let (receipt, proof_receipt) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);

        assert_eq!(receipt.status, ReceiptStatus::Accepted);
        assert!(proof_receipt.is_some());
    }

    #[test]
    fn asset_bundle_append_rejects_noncanonical_payload() {
        let mut store = base_store([7u8; 32]);
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);
        let payload = MorphologySetPayload {
            morphologies: vec![
                MorphologyEntry {
                    neuron_id: 2,
                    pool_label: "pool-b".to_string(),
                    role_label: "role-b".to_string(),
                    payload: vec![2u8],
                },
                MorphologyEntry {
                    neuron_id: 1,
                    pool_label: "pool-a".to_string(),
                    role_label: "role-a".to_string(),
                    payload: vec![1u8],
                },
            ],
        };
        let (bundle, _, _) =
            asset_bundle_with_payload(55, 12, AssetKind::Morphology, payload.encode_to_vec());

        let req = asset_bundle_request(&store, &bundle);
        let (receipt, proof_receipt) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);

        assert_eq!(receipt.status, ReceiptStatus::Rejected);
        assert!(proof_receipt.is_none());
        assert!(receipt
            .reject_reason_codes
            .contains(&ReasonCodes::GV_ASSET_CANONICAL_MISMATCH.to_string()));
    }

    #[test]
    fn asset_bundle_append_logs_decode_skipped_due_to_size() {
        let mut store = base_store([7u8; 32]);
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);
        let payload = vec![0u8; MAX_ASSET_PAYLOAD_DECODE_BYTES + 1];
        let (bundle, digest, _) = asset_bundle_with_payload(55, 12, AssetKind::Morphology, payload);

        let req = asset_bundle_request(&store, &bundle);
        let (receipt, proof_receipt) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);

        assert_eq!(receipt.status, ReceiptStatus::Accepted);
        assert!(proof_receipt.is_some());

        let has_event = store.sep_log.events.iter().any(|event| {
            event.event_type == SepEventType::EvRecoveryGov
                && event.object_digest == digest
                && event
                    .reason_codes
                    .contains(&ReasonCodes::GV_ASSET_DECODE_SKIPPED_DUE_TO_SIZE.to_string())
        });
        assert!(has_event);
    }

    #[test]
    fn asset_bundle_append_rejects_digest_mismatch() {
        let mut store = base_store([7u8; 32]);
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);
        let (mut bundle, _digest, _asset_digest) = asset_bundle_payload(55, 12);
        bundle.chunks[0].payload = b"tampered".to_vec();

        let req = asset_bundle_request(&store, &bundle);
        let (receipt, proof_receipt) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);

        assert_eq!(receipt.status, ReceiptStatus::Rejected);
        assert!(proof_receipt.is_none());
        assert!(receipt
            .reject_reason_codes
            .contains(&ReasonCodes::RE_INTEGRITY_DEGRADED.to_string()));
        assert!(receipt
            .reject_reason_codes
            .contains(&ReasonCodes::GV_ASSET_DIGEST_MISMATCH.to_string()));
        assert!(store.asset_bundle_store.list().is_empty());
    }

    #[test]
    fn asset_bundle_append_sorts_chunks_for_digest() {
        let mut store = base_store([7u8; 32]);
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);
        let (mut bundle, _digest, _asset_digest) = asset_bundle_payload(55, 12);
        bundle.chunks.reverse();

        let req = asset_bundle_request(&store, &bundle);
        let (receipt, proof_receipt) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);

        assert_eq!(receipt.status, ReceiptStatus::Accepted);
        assert!(proof_receipt.is_some());
    }

    #[test]
    fn asset_bundle_append_rejects_over_max_chunks() {
        let mut store = base_store([7u8; 32]);
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);
        let max_chunks = store.asset_bundle_store.max_chunks_per_asset() as u32;
        let asset_digest = [42u8; 32];
        let mut manifest = AssetManifest {
            manifest_digest: Vec::new(),
            created_at_ms: 99,
            asset_digests: vec![AssetDigest {
                kind: AssetKind::Morphology as i32,
                digest: asset_digest.to_vec(),
                version: 1,
            }],
        };
        let manifest_digest = compute_asset_manifest_digest(&manifest);
        manifest.manifest_digest = manifest_digest.to_vec();

        let mut chunks = Vec::new();
        for idx in 0..=max_chunks {
            let payload = vec![idx as u8; 4];
            chunks.push(AssetChunk {
                asset_digest: asset_digest.to_vec(),
                chunk_index: idx,
                chunk_count: max_chunks + 1,
                payload: payload.clone(),
                chunk_digest: compute_asset_chunk_digest(&payload).to_vec(),
                compression_mode: CompressionMode::None as i32,
            });
        }

        let mut bundle = AssetBundle {
            bundle_digest: Vec::new(),
            created_at_ms: 99,
            manifest: Some(manifest),
            chunks,
        };
        let bundle_digest =
            compute_asset_bundle_digest(bundle.manifest.as_ref().unwrap(), &bundle.chunks)
                .expect("bundle digest computed");
        bundle.bundle_digest = bundle_digest.to_vec();

        let req = asset_bundle_request(&store, &bundle);
        let (receipt, proof_receipt) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);

        assert_eq!(receipt.status, ReceiptStatus::Rejected);
        assert!(proof_receipt.is_none());
        assert!(receipt
            .reject_reason_codes
            .contains(&ReasonCodes::RE_INTEGRITY_DEGRADED.to_string()));
        assert!(store.asset_bundle_store.list().is_empty());
    }

    #[test]
    fn critical_trigger_logs_incident_and_recovery() {
        let mut store = base_store([7u8; 32]);

        let seal = store
            .handle_critical_trigger("session-crit", CriticalTrigger::IntegrityFail)
            .expect("trigger handled");

        assert!(store.forensic_mode);
        assert_eq!(store.sep_log.events.len(), 2);

        let incident = &store.sep_log.events[0];
        assert_eq!(incident.event_type, SepEventType::EvIncident);
        assert_eq!(
            incident.reason_codes,
            vec![ReasonCodes::RE_INTEGRITY_FAIL.to_string()]
        );

        let recovery = &store.sep_log.events[1];
        assert_eq!(recovery.event_type, SepEventType::EvRecovery);
        assert!(recovery
            .reason_codes
            .contains(&ReasonCodes::RX_ACTION_FORENSIC.to_string()));
        assert!(recovery
            .reason_codes
            .contains(&ReasonCodes::RE_INTEGRITY_FAIL.to_string()));

        let prefix: String = seal
            .final_event_digest
            .iter()
            .take(4)
            .map(|b| format!("{:02x}", b))
            .collect();
        assert_eq!(seal.seal_id, format!("seal:session-crit:{prefix}"));

        let recovery_case = store
            .recovery_store
            .get_active_for_session("session-crit")
            .expect("recovery case created");
        assert_eq!(recovery_case.state, RecoveryState::R0Captured);
        assert_eq!(
            recovery_case.recovery_id,
            format!("recovery:session-crit:{prefix}")
        );
    }

    #[test]
    fn recovery_state_advances_sequentially() {
        let mut store = base_store([7u8; 32]);
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);

        let base_case = recovery_case_for(
            "rec-1",
            "session-crit",
            RecoveryState::R0Captured,
            Vec::new(),
        );

        let create_req = recovery_request(
            CommitType::RecoveryCaseCreate,
            Some(base_case.clone()),
            store.current_head_record_digest,
        );
        let (create_receipt, _) = verify_and_commit(create_req, &mut store, &keystore, &vrf_engine);
        assert_eq!(create_receipt.status, ReceiptStatus::Accepted);

        let mut jump_case = recovery_case_for(
            "rec-1",
            "session-crit",
            RecoveryState::R2Validated,
            Vec::new(),
        );
        jump_case.required_checks = base_case.required_checks.clone();

        let bad_advance = recovery_request(
            CommitType::RecoveryCaseAdvance,
            Some(jump_case),
            store.current_head_record_digest,
        );
        let (bad_receipt, _) = verify_and_commit(bad_advance, &mut store, &keystore, &vrf_engine);
        assert_eq!(bad_receipt.status, ReceiptStatus::Rejected);

        let mut r1_case = base_case.clone();
        r1_case.state = RecoveryState::R1Triaged;
        let good_advance = recovery_request(
            CommitType::RecoveryCaseAdvance,
            Some(r1_case),
            store.current_head_record_digest,
        );
        let (advance_receipt, _) =
            verify_and_commit(good_advance, &mut store, &keystore, &vrf_engine);
        assert_eq!(advance_receipt.status, ReceiptStatus::Accepted);
    }

    #[test]
    fn unlock_permit_requires_approved_state() {
        let mut store = base_store([7u8; 32]);
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);

        let base_case = recovery_case_for(
            "rec-approve",
            "session-crit",
            RecoveryState::R0Captured,
            Vec::new(),
        );

        let create_req = recovery_request(
            CommitType::RecoveryCaseCreate,
            Some(base_case.clone()),
            store.current_head_record_digest,
        );
        let (create_receipt, _) = verify_and_commit(create_req, &mut store, &keystore, &vrf_engine);
        assert_eq!(create_receipt.status, ReceiptStatus::Accepted);

        let mut early_permit = UnlockPermit::new(
            "session-crit".to_string(),
            now_ms(),
            store.ruleset_state.ruleset_digest,
        );
        early_permit.permit_digest = [0u8; 32];

        let mut early_unlock = recovery_request(
            CommitType::RecoveryApproval,
            None,
            store.current_head_record_digest,
        );
        early_unlock.unlock_permit = Some(early_permit.clone());
        let (early_receipt, _) =
            verify_and_commit(early_unlock, &mut store, &keystore, &vrf_engine);
        assert_eq!(early_receipt.status, ReceiptStatus::Rejected);

        let mut completed = Vec::new();
        let states = [
            RecoveryState::R1Triaged,
            RecoveryState::R2Validated,
            RecoveryState::R3Mitigated,
            RecoveryState::R4Remediated,
            RecoveryState::R5Approved,
        ];

        for state in states {
            if state >= RecoveryState::R2Validated {
                completed.push(RecoveryCheck::IntegrityOk);
            }
            if state >= RecoveryState::R5Approved {
                completed.push(RecoveryCheck::ValidationPassed);
            }

            let mut case =
                recovery_case_for("rec-approve", "session-crit", state, completed.clone());
            case.required_checks = base_case.required_checks.clone();

            let req = recovery_request(
                CommitType::RecoveryCaseAdvance,
                Some(case),
                store.current_head_record_digest,
            );
            let (receipt, _) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);
            assert_eq!(receipt.status, ReceiptStatus::Accepted);
        }

        let mut approved_permit = UnlockPermit::new(
            "session-crit".to_string(),
            now_ms(),
            store.ruleset_state.ruleset_digest,
        );
        approved_permit.permit_digest = [0u8; 32];
        let mut unlock_req = recovery_request(
            CommitType::RecoveryApproval,
            None,
            store.current_head_record_digest,
        );
        unlock_req.unlock_permit = Some(approved_permit.clone());
        let (unlock_receipt, _) = verify_and_commit(unlock_req, &mut store, &keystore, &vrf_engine);
        assert_eq!(unlock_receipt.status, ReceiptStatus::Accepted);
        assert!(store.unlock_permits.contains_key("session-crit"));
    }

    #[test]
    fn replay_mismatch_does_not_auto_seal_in_beta_profile() {
        let mut store = base_store([7u8; 32]);

        store
            .record_sep_event(
                "session-beta",
                SepEventType::EvDecision,
                [3u8; 32],
                vec![ReasonCodes::RE_REPLAY_MISMATCH.to_string()],
            )
            .expect("event recorded");

        assert_eq!(store.sep_log.events.len(), 1);
        assert!(store
            .sep_log
            .events
            .iter()
            .all(|event| event.event_type != SepEventType::EvIncident));
    }

    #[test]
    fn replay_mismatch_auto_seals_in_production_profile() {
        let mut known_charter_versions = HashSet::new();
        known_charter_versions.insert("charter".to_string());
        let mut known_policy_versions = HashSet::new();
        known_policy_versions.insert("policy".to_string());
        let mut known_profiles = HashSet::new();
        known_profiles.insert([9u8; 32]);

        let mut store = PvgsStore::new_production(
            [7u8; 32],
            "charter".to_string(),
            "policy".to_string(),
            known_charter_versions,
            known_policy_versions,
            known_profiles,
        );

        store
            .record_sep_event(
                "session-prod",
                SepEventType::EvDecision,
                [3u8; 32],
                vec![ReasonCodes::RE_REPLAY_MISMATCH.to_string()],
            )
            .expect("event recorded");

        assert_eq!(store.sep_log.events.len(), 3);
        assert!(store
            .sep_log
            .events
            .iter()
            .any(|event| event.event_type == SepEventType::EvIncident));
    }

    #[test]
    fn consistency_feedback_append_is_stored() {
        let prev = [8u8; 32];
        let mut store = base_store(prev);
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);
        let digest = [0xAAu8; 32];

        let feedback = ConsistencyFeedback {
            cf_digest: Some(digest.to_vec()),
            consistency_class: "CONSISTENCY_HIGH".to_string(),
            flags: vec!["alpha".to_string()],
            proof_receipt_ref: None,
        };

        let req = PvgsCommitRequest {
            commit_id: "cf-append".to_string(),
            commit_type: CommitType::ConsistencyFeedbackAppend,
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
            consistency_feedback_payload: Some(feedback.encode_to_vec()),
            macro_consistency_digest: None,
            recovery_case: None,
            unlock_permit: None,
            tool_onboarding_event: None,
            microcircuit_config_payload: None,
            asset_manifest_payload: None,
            asset_bundle_payload: None,
        };

        let (receipt, proof) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);

        assert_eq!(receipt.status, ReceiptStatus::Accepted);
        assert!(proof.is_some());
        let stored = store
            .consistency_store
            .get(digest)
            .expect("feedback missing");
        assert_eq!(stored.consistency_class, "CONSISTENCY_HIGH");

        let event = store.sep_log.events.last().expect("missing sep event");
        assert!(event
            .reason_codes
            .contains(&ReasonCodes::GV_CONSISTENCY_APPENDED.to_string()));
        assert_eq!(event.object_digest, digest);
    }

    #[test]
    fn macro_append_rejects_without_consistency_ref() {
        let prev = [8u8; 32];
        let mut store = base_store(prev);
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);
        let macro_milestone = macro_with_updates(
            "macro-no-ref",
            vec![cbv_update(
                "baseline_caution_offset",
                TraitDirection::IncreaseStrictness,
                MagnitudeClass::Low,
            )],
        );
        let macro_digest = digest_from_bytes(&macro_milestone.macro_digest).unwrap();
        let payload_digests = vec![macro_digest];

        let req = PvgsCommitRequest {
            commit_id: macro_milestone.macro_id.clone(),
            commit_type: CommitType::MilestoneAppend,
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
            payload_digests,
            epoch_id: keystore.current_epoch(),
            key_epoch: None,
            experience_record_payload: None,
            replay_run_evidence_payload: None,
            trace_run_evidence_payload: None,
            proposal_evidence_payload: None,
            proposal_activation_payload: None,
            macro_milestone: Some(macro_milestone),
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

        let (receipt, proof) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);

        assert_eq!(receipt.status, ReceiptStatus::Rejected);
        assert!(proof.is_none());
        assert!(receipt
            .reject_reason_codes
            .contains(&ReasonCodes::RE_INTEGRITY_DEGRADED.to_string()));
        assert!(store.macro_milestones.is_empty());
        assert!(store.cbv_store.latest().is_none());
    }

    #[test]
    fn macro_proposal_emits_sep_without_cbv_update() {
        let prev = [8u8; 32];
        let mut store = base_store(prev);
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);

        let macro_milestone = macro_with_state("macro-proposed", MacroMilestoneState::Finalized);
        let macro_digest = digest_from_bytes(&macro_milestone.macro_digest).unwrap();

        let req = make_macro_request(
            &macro_proposal_from(&macro_milestone),
            &store,
            1,
            None,
            CommitType::MacroMilestonePropose,
        );

        let (receipt, proof) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);

        assert_eq!(receipt.status, ReceiptStatus::Accepted);
        assert!(proof.is_some());
        assert!(store.cbv_store.latest().is_none());

        let event = store.sep_log.events.last().expect("missing sep event");
        assert_eq!(event.event_type, SepEventType::EvRecoveryGov);
        assert_eq!(event.object_digest, macro_digest);
        assert!(event
            .reason_codes
            .contains(&ReasonCodes::GV_MACRO_PROPOSED.to_string()));
        assert!(!event
            .reason_codes
            .contains(&ReasonCodes::GV_CBV_UPDATED.to_string()));
    }

    #[test]
    fn macro_append_rejects_low_consistency() {
        let prev = [8u8; 32];
        let mut store = base_store(prev);
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);
        let macro_milestone = macro_with_state("macro-low", MacroMilestoneState::Finalized);
        let consistency_digest = [0x21u8; 32];
        store_consistency_feedback(&mut store, consistency_digest, "CONSISTENCY_LOW");

        let proposal_req = make_macro_request(
            &macro_proposal_from(&macro_milestone),
            &store,
            1,
            None,
            CommitType::MacroMilestonePropose,
        );
        let (proposal_receipt, _) =
            verify_and_commit(proposal_req, &mut store, &keystore, &vrf_engine);
        assert_eq!(proposal_receipt.status, ReceiptStatus::Accepted);

        let req = make_macro_request(
            &macro_milestone,
            &store,
            1,
            Some(consistency_digest),
            CommitType::MacroMilestoneFinalize,
        );

        let (receipt, proof) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);

        assert_eq!(receipt.status, ReceiptStatus::Rejected);
        assert!(proof.is_none());
        assert!(receipt
            .reject_reason_codes
            .contains(&ReasonCodes::GV_CONSISTENCY_LOW.to_string()));
        assert!(store.macro_milestones.get_proposed("macro-low").is_some());
        assert!(store.cbv_store.latest().is_none());
    }

    #[test]
    fn macro_finalize_rejects_without_feedback() {
        let prev = [8u8; 32];
        let mut store = base_store(prev);
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);
        let consistency_digest = [0x31u8; 32];

        let macro_milestone = macro_with_state("macro-no-feedback", MacroMilestoneState::Finalized);
        let macro_digest = digest_from_bytes(&macro_milestone.macro_digest).unwrap();

        let proposal_req = make_macro_request(
            &macro_proposal_from(&macro_milestone),
            &store,
            1,
            None,
            CommitType::MacroMilestonePropose,
        );
        let (proposal_receipt, _) =
            verify_and_commit(proposal_req, &mut store, &keystore, &vrf_engine);
        assert_eq!(proposal_receipt.status, ReceiptStatus::Accepted);

        let finalize_req = make_macro_request(
            &macro_milestone,
            &store,
            1,
            Some(consistency_digest),
            CommitType::MacroMilestoneFinalize,
        );

        let (receipt, proof) = verify_and_commit(finalize_req, &mut store, &keystore, &vrf_engine);

        assert_eq!(receipt.status, ReceiptStatus::Rejected);
        assert!(proof.is_none());
        assert!(store.cbv_store.latest().is_none());
        assert!(store
            .macro_milestones
            .get_proposed("macro-no-feedback")
            .is_some());

        let neighbors = store.causal_graph.neighbors(macro_digest);
        assert!(!neighbors.contains(&(EdgeType::Finalizes, consistency_digest)));

        let event = store.sep_log.events.last().expect("missing sep event");
        assert_eq!(event.object_digest, macro_digest);
        assert!(event
            .reason_codes
            .contains(&ReasonCodes::RE_INTEGRITY_DEGRADED.to_string()));
    }

    fn sample_pev(digest: [u8; 32], epoch: u64) -> PolicyEcologyVector {
        PolicyEcologyVector {
            dimensions: vec![PolicyEcologyDimension {
                name: "conservatism_bias".to_string(),
                value: 1,
            }],
            pev_digest: Some(digest.to_vec()),
            pev_version_digest: Some(digest.to_vec()),
            pev_epoch: Some(epoch),
        }
    }

    fn tool_registry_container(digest: [u8; 32], version: &str) -> ToolRegistryContainer {
        ToolRegistryContainer {
            registry_digest: digest.to_vec(),
            registry_version: version.to_string(),
        }
    }

    fn perception_record(profile_digest: [u8; 32]) -> ExperienceRecord {
        ExperienceRecord {
            record_type: RecordType::RtPerception as i32,
            core_frame: None,
            metabolic_frame: Some(MetabolicFrame {
                profile_digest: Some(profile_digest.to_vec()),
                outcome_refs: Vec::new(),
            }),
            governance_frame: None,
            core_frame_ref: Some(Ref {
                id: "core-ref".to_string(),
                digest: None,
            }),
            metabolic_frame_ref: Some(Ref {
                id: "met-ref".to_string(),
                digest: None,
            }),
            governance_frame_ref: None,
            dlp_refs: Vec::new(),
            finalization_header: None,
        }
    }

    fn output_record(dlp_digest: [u8; 32]) -> ExperienceRecord {
        ExperienceRecord {
            record_type: RecordType::RtOutput as i32,
            core_frame: None,
            metabolic_frame: None,
            governance_frame: Some(GovernanceFrame {
                policy_decision_refs: Vec::new(),
                pvgs_receipt_ref: None,
                dlp_refs: vec![Ref {
                    id: hex::encode(dlp_digest),
                    digest: None,
                }],
            }),
            core_frame_ref: None,
            metabolic_frame_ref: None,
            governance_frame_ref: Some(Ref {
                id: hex::encode([7u8; 32]),
                digest: None,
            }),
            dlp_refs: Vec::new(),
            finalization_header: None,
        }
    }

    fn replay_record(related_refs: Vec<Ref>, governance_ref: Option<Ref>) -> ExperienceRecord {
        ExperienceRecord {
            record_type: RecordType::RtReplay as i32,
            core_frame: None,
            metabolic_frame: None,
            governance_frame: Some(GovernanceFrame {
                policy_decision_refs: related_refs,
                pvgs_receipt_ref: None,
                dlp_refs: Vec::new(),
            }),
            core_frame_ref: None,
            metabolic_frame_ref: None,
            governance_frame_ref: governance_ref,
            dlp_refs: Vec::new(),
            finalization_header: None,
        }
    }

    fn replay_run_evidence(
        run_digest: [u8; 32],
        asset_manifest_digest: [u8; 32],
        micro_config_digest: [u8; 32],
        created_at_ms: u64,
    ) -> ReplayRunEvidence {
        ReplayRunEvidence {
            run_digest: run_digest.to_vec(),
            replay_plan_ref: None,
            asset_manifest_ref: Some(Ref {
                id: "asset_manifest".to_string(),
                digest: Some(asset_manifest_digest.to_vec()),
            }),
            steps: 10,
            dt_us: 5,
            created_at_ms,
            micro_config_refs: vec![Ref {
                id: "mc_cfg:lc".to_string(),
                digest: Some(micro_config_digest.to_vec()),
            }],
            summary_digests: vec![vec![4u8; 32]],
        }
    }

    struct TraceRunEvidenceInput {
        run_digest: [u8; 32],
        active_cfg_digest: [u8; 32],
        shadow_cfg_digest: [u8; 32],
        active_feedback_digest: [u8; 32],
        shadow_feedback_digest: [u8; 32],
        created_at_ms: u64,
        verdict: TraceVerdict,
        delta: i32,
    }

    fn trace_run_evidence(input: TraceRunEvidenceInput) -> TraceRunEvidence {
        let mut evidence = TraceRunEvidence {
            trace_id: "trace-1".to_string(),
            trace_digest: input.run_digest.to_vec(),
            active_cfg_digest: input.active_cfg_digest.to_vec(),
            shadow_cfg_digest: input.shadow_cfg_digest.to_vec(),
            active_feedback_digest: input.active_feedback_digest.to_vec(),
            shadow_feedback_digest: input.shadow_feedback_digest.to_vec(),
            score_active: 10,
            score_shadow: 12,
            delta: input.delta,
            verdict: input.verdict as i32,
            created_at_ms: input.created_at_ms,
            reason_codes: vec!["RC.GV.OK".to_string()],
        };
        let digest = compute_trace_run_digest(&evidence).expect("digest");
        evidence.trace_digest = digest.to_vec();
        evidence
    }

    fn make_experience_request_with_id(
        record: &ExperienceRecord,
        store: &PvgsStore,
        epoch_id: u64,
        commit_id: &str,
    ) -> PvgsCommitRequest {
        PvgsCommitRequest {
            commit_id: commit_id.to_string(),
            commit_type: CommitType::ExperienceRecordAppend,
            bindings: CommitBindings {
                action_digest: None,
                decision_digest: None,
                grant_id: None,
                charter_version_digest: "charter".to_string(),
                policy_version_digest: "policy".to_string(),
                prev_record_digest: store.current_head_record_digest,
                profile_digest: profile_digest_from_record(record),
                tool_profile_digest: None,
                pev_digest: None,
            },
            required_receipt_kind: RequiredReceiptKind::Read,
            required_checks: vec![RequiredCheck::SchemaOk],
            payload_digests: Vec::new(),
            epoch_id,
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
        }
    }

    #[test]
    fn experience_record_adds_plasticity_reference_edge() {
        let prev = [2u8; 32];
        let mut store = base_store(prev);
        let keystore = KeyStore::new_dev_keystore(7);
        let vrf_engine = VrfEngine::new_dev(7);
        let plasticity_digest = [11u8; 32];
        let record = replay_record(
            vec![Ref {
                id: format!("mc_snap:plasticity:{}", hex::encode(plasticity_digest)),
                digest: None,
            }],
            None,
        );
        let req = make_experience_request_with_id(
            &record,
            &store,
            keystore.current_epoch(),
            "exp-plasticity",
        );

        let (receipt, _) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);

        assert_eq!(receipt.status, ReceiptStatus::Accepted);
        let record_digest = store.experience_store.head_record_digest;
        let has_edge =
            store
                .causal_graph
                .neighbors(record_digest)
                .iter()
                .any(|(edge, neighbor)| {
                    matches!(edge, EdgeType::References) && *neighbor == plasticity_digest
                });
        assert!(has_edge);
    }

    #[test]
    fn macro_append_triggers_cbv_update() {
        let prev = [8u8; 32];
        let mut store = base_store(prev);
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);
        let consistency_digest = [0x11u8; 32];
        store_consistency_feedback(&mut store, consistency_digest, "CONSISTENCY_HIGH");
        let macro_milestone = macro_with_updates(
            "macro-1",
            vec![cbv_update(
                "baseline_caution_offset",
                TraitDirection::IncreaseStrictness,
                MagnitudeClass::Low,
            )],
        );
        let proposal_req = make_macro_request(
            &macro_proposal_from(&macro_milestone),
            &store,
            1,
            None,
            CommitType::MacroMilestonePropose,
        );
        let (proposal_receipt, _) =
            verify_and_commit(proposal_req, &mut store, &keystore, &vrf_engine);
        assert_eq!(proposal_receipt.status, ReceiptStatus::Accepted);

        let req = make_macro_request(
            &macro_milestone,
            &store,
            1,
            Some(consistency_digest),
            CommitType::MacroMilestoneFinalize,
        );

        let (receipt, proof) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);

        assert_eq!(receipt.status, ReceiptStatus::Accepted);
        assert!(proof.is_some());
        let latest_cbv = store.cbv_store.latest().expect("cbv missing");
        assert_eq!(latest_cbv.cbv_epoch, 1);

        let macro_digest = digest_from_bytes(&macro_milestone.macro_digest).unwrap();
        let neighbors = store.causal_graph.neighbors(macro_digest);
        assert!(neighbors.contains(&(EdgeType::Finalizes, consistency_digest)));

        assert!(store.sep_log.events.iter().any(|e| e
            .reason_codes
            .contains(&ReasonCodes::GV_MACRO_PROPOSED.to_string())));
        assert!(store.sep_log.events.iter().any(|e| e
            .reason_codes
            .contains(&ReasonCodes::GV_MACRO_FINALIZED.to_string())));
        assert!(store.sep_log.events.iter().any(|e| e
            .reason_codes
            .contains(&ReasonCodes::GV_CONSISTENCY_APPENDED.to_string())));
        assert!(store.sep_log.events.iter().any(|e| e
            .reason_codes
            .contains(&ReasonCodes::GV_CBV_UPDATED.to_string())));
    }

    #[test]
    fn macro_append_is_idempotent_for_cbv() {
        let prev = [8u8; 32];
        let mut store = base_store(prev);
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);
        let consistency_digest = [0x12u8; 32];
        store_consistency_feedback(&mut store, consistency_digest, "CONSISTENCY_HIGH");
        let macro_milestone = macro_with_updates(
            "macro-2",
            vec![cbv_update(
                "baseline_approval_strictness_offset",
                TraitDirection::IncreaseStrictness,
                MagnitudeClass::Low,
            )],
        );
        let proposal_req = make_macro_request(
            &macro_proposal_from(&macro_milestone),
            &store,
            1,
            None,
            CommitType::MacroMilestonePropose,
        );
        let (proposal_receipt, _) =
            verify_and_commit(proposal_req, &mut store, &keystore, &vrf_engine);
        assert_eq!(proposal_receipt.status, ReceiptStatus::Accepted);

        let req = make_macro_request(
            &macro_milestone,
            &store,
            1,
            Some(consistency_digest),
            CommitType::MacroMilestoneFinalize,
        );

        let (receipt, _) = verify_and_commit(req.clone(), &mut store, &keystore, &vrf_engine);
        assert_eq!(receipt.status, ReceiptStatus::Accepted);
        let (second, _) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);
        assert_eq!(second.status, ReceiptStatus::Rejected);

        let latest_cbv = store.cbv_store.latest().expect("cbv missing");
        assert_eq!(latest_cbv.cbv_epoch, 1);
        assert!(store.sep_log.events.iter().any(|e| e
            .reason_codes
            .contains(&ReasonCodes::RE_INTEGRITY_DEGRADED.to_string())));
    }

    #[test]
    fn macro_append_logs_degraded_on_cbv_failure() {
        let prev = [8u8; 32];
        let mut store = base_store(prev);
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);
        let consistency_digest = [0x13u8; 32];
        store_consistency_feedback(&mut store, consistency_digest, "CONSISTENCY_HIGH");
        let mut macro_milestone = macro_with_state("macro-3", MacroMilestoneState::Draft);
        macro_milestone.proof_receipt_ref = Some(Ref::default());
        macro_milestone.consistency_feedback_ref = Some(Ref::default());
        let proposal_req = make_macro_request(
            &macro_proposal_from(&macro_milestone),
            &store,
            1,
            None,
            CommitType::MacroMilestonePropose,
        );
        let (proposal_receipt, _) =
            verify_and_commit(proposal_req, &mut store, &keystore, &vrf_engine);
        assert_eq!(proposal_receipt.status, ReceiptStatus::Accepted);

        let req = make_macro_request(
            &macro_milestone,
            &store,
            1,
            Some(consistency_digest),
            CommitType::MacroMilestoneFinalize,
        );

        let (receipt, _proof) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);

        assert_eq!(receipt.status, ReceiptStatus::Accepted);
        assert!(store.cbv_store.latest().is_some());
        assert!(store.sep_log.events.iter().any(|e| {
            e.reason_codes
                .contains(&ReasonCodes::GV_CBV_UPDATED.to_string())
        }));
    }

    #[test]
    fn macro_finalize_accepts_high_feedback_and_updates_cbv_and_graphs() {
        let prev = [9u8; 32];
        let mut store = base_store(prev);
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);
        let consistency_digest = [0x41u8; 32];
        let meso_digest = [0x42u8; 32];
        let meso_ref = Ref {
            id: hex::encode(meso_digest),
            digest: None,
        };

        store_consistency_feedback(&mut store, consistency_digest, "CONSISTENCY_HIGH");

        let mut macro_milestone = macro_with_updates(
            "macro-high",
            vec![cbv_update(
                "baseline_approval_strictness_offset",
                TraitDirection::IncreaseStrictness,
                MagnitudeClass::Low,
            )],
        );
        macro_milestone.meso_refs = vec![meso_ref];
        let macro_digest = digest_from_bytes(&macro_milestone.macro_digest).unwrap();

        let proposal_req = make_macro_request(
            &macro_proposal_from(&macro_milestone),
            &store,
            1,
            None,
            CommitType::MacroMilestonePropose,
        );
        let (proposal_receipt, _) =
            verify_and_commit(proposal_req, &mut store, &keystore, &vrf_engine);
        assert_eq!(proposal_receipt.status, ReceiptStatus::Accepted);
        assert!(store.cbv_store.latest().is_none());

        let finalize_req = make_macro_request(
            &macro_milestone,
            &store,
            1,
            Some(consistency_digest),
            CommitType::MacroMilestoneFinalize,
        );

        let (receipt, proof) =
            verify_and_commit(finalize_req.clone(), &mut store, &keystore, &vrf_engine);

        assert_eq!(receipt.status, ReceiptStatus::Accepted);
        assert!(proof.is_some());
        let cbv_epoch = store.cbv_store.latest().expect("cbv missing").cbv_epoch;
        assert_eq!(cbv_epoch, 1);

        let neighbors = store.causal_graph.neighbors(macro_digest);
        assert!(neighbors.contains(&(EdgeType::Finalizes, meso_digest)));
        assert!(neighbors.contains(&(EdgeType::Finalizes, consistency_digest)));

        assert!(store.sep_log.events.iter().any(|e| {
            e.object_digest == macro_digest
                && e.reason_codes
                    .contains(&ReasonCodes::GV_MACRO_PROPOSED.to_string())
        }));
        assert!(store.sep_log.events.iter().any(|e| {
            e.object_digest == macro_digest
                && e.reason_codes
                    .contains(&ReasonCodes::GV_MACRO_FINALIZED.to_string())
                && e.reason_codes
                    .contains(&ReasonCodes::GV_CONSISTENCY_APPENDED.to_string())
        }));
        assert!(store.sep_log.events.iter().any(|e| {
            e.reason_codes
                .contains(&ReasonCodes::GV_CBV_UPDATED.to_string())
        }));

        let (dup_receipt, dup_proof) =
            verify_and_commit(finalize_req, &mut store, &keystore, &vrf_engine);

        assert_eq!(dup_receipt.status, ReceiptStatus::Rejected);
        assert!(dup_proof.is_none());
        assert_eq!(
            store.cbv_store.latest().expect("cbv missing").cbv_epoch,
            cbv_epoch
        );
        assert_eq!(
            dup_receipt.reject_reason_codes,
            vec![ReasonCodes::RE_INTEGRITY_DEGRADED.to_string()]
        );

        let last_event = store.sep_log.events.last().expect("missing sep event");
        assert_eq!(last_event.object_digest, macro_digest);
        assert_eq!(last_event.reason_codes, dup_receipt.reject_reason_codes);
    }

    #[test]
    fn receipt_accepted() {
        let prev = [8u8; 32];
        let mut store = base_store(prev);
        let req = make_request(prev);
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);

        let (receipt, proof) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);
        assert_eq!(receipt.status, ReceiptStatus::Accepted);
        assert!(receipt.reject_reason_codes.is_empty());
        let proof = proof.expect("proof receipt missing");
        assert_ne!(proof.vrf_digest, Digest32::zero());
        assert_eq!(store.sep_log.events.len(), 1);
    }

    #[test]
    fn graph_updates_on_receipt() {
        let prev = [8u8; 32];
        let mut store = base_store(prev);
        let req = make_request(prev);
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);

        let (receipt, _) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);
        let receipt_digest = receipt.receipt_digest.0;

        let decision_edges = store.causal_graph.neighbors([2u8; 32]);
        assert!(decision_edges.contains(&(EdgeType::Authorizes, receipt_digest)));

        let action_edges = store.causal_graph.neighbors([1u8; 32]);
        assert!(action_edges.contains(&(EdgeType::Authorizes, receipt_digest)));

        let reverse = store.causal_graph.reverse_neighbors(receipt_digest);
        assert!(reverse.contains(&(EdgeType::References, [9u8; 32])));
        assert!(reverse.contains(&(EdgeType::References, [3u8; 32])));
    }

    #[test]
    fn graph_updates_on_record_append() {
        let prev = [7u8; 32];
        let mut store = base_store(prev);
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);

        let receipt_req = make_request(prev);
        let (receipt, _) = verify_and_commit(receipt_req, &mut store, &keystore, &vrf_engine);
        let receipt_digest = receipt.receipt_digest.0;

        let action_digest = [5u8; 32];
        let decision_digest = [6u8; 32];
        let frame_digest = [4u8; 32];

        let record = ExperienceRecord {
            record_type: RecordType::RtActionExec as i32,
            core_frame: Some(CoreFrame {
                evidence_refs: vec![Ref {
                    id: hex::encode(action_digest),
                    digest: None,
                }],
            }),
            metabolic_frame: None,
            governance_frame: Some(GovernanceFrame {
                policy_decision_refs: vec![Ref {
                    id: hex::encode(decision_digest),
                    digest: None,
                }],
                pvgs_receipt_ref: Some(Ref {
                    id: hex::encode(receipt_digest),
                    digest: None,
                }),
                dlp_refs: Vec::new(),
            }),
            core_frame_ref: Some(Ref {
                id: hex::encode(action_digest),
                digest: None,
            }),
            metabolic_frame_ref: None,
            governance_frame_ref: Some(Ref {
                id: hex::encode(frame_digest),
                digest: None,
            }),
            dlp_refs: Vec::new(),
            finalization_header: None,
        };

        let req =
            make_experience_request_with_id(&record, &store, keystore.current_epoch(), "exp-1");
        let (record_receipt, _) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);
        assert_eq!(record_receipt.status, ReceiptStatus::Accepted);

        let record_digest = store.experience_store.head_record_digest;
        let neighbors = store.causal_graph.neighbors(record_digest);
        assert!(neighbors.contains(&(EdgeType::References, decision_digest)));
        assert!(neighbors.contains(&(EdgeType::References, receipt_digest)));
        assert!(neighbors.contains(&(EdgeType::References, action_digest)));

        let prev_edges = store.causal_graph.neighbors(prev);
        assert!(prev_edges.contains(&(EdgeType::Causes, record_digest)));
    }

    #[test]
    fn graph_updates_on_replay_run_record_append() {
        let prev = [11u8; 32];
        let mut store = base_store(prev);
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);

        let replay_run_digest = [9u8; 32];
        let record = replay_record(
            vec![Ref {
                id: "replay_run".to_string(),
                digest: Some(replay_run_digest.to_vec()),
            }],
            None,
        );

        let req = make_experience_request_with_id(
            &record,
            &store,
            keystore.current_epoch(),
            "exp-replay",
        );
        let (record_receipt, _) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);
        assert_eq!(record_receipt.status, ReceiptStatus::Accepted);

        let record_digest = store.experience_store.head_record_digest;
        let neighbors = store.causal_graph.neighbors(record_digest);
        assert!(neighbors.contains(&(EdgeType::References, replay_run_digest)));
    }

    #[test]
    fn graph_updates_on_replay_run_evidence_record_append() {
        let prev = [13u8; 32];
        let mut store = base_store(prev);
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);

        let replay_run_digest = [10u8; 32];
        let record = replay_record(
            vec![Ref {
                id: "replay_run_evidence".to_string(),
                digest: Some(replay_run_digest.to_vec()),
            }],
            None,
        );

        let req = make_experience_request_with_id(
            &record,
            &store,
            keystore.current_epoch(),
            "exp-replay-evidence",
        );
        let (record_receipt, _) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);
        assert_eq!(record_receipt.status, ReceiptStatus::Accepted);

        let record_digest = store.experience_store.head_record_digest;
        let neighbors = store.causal_graph.neighbors(record_digest);
        assert!(neighbors.contains(&(EdgeType::References, replay_run_digest)));
    }

    #[test]
    fn replay_run_evidence_append_is_idempotent() {
        let prev = [19u8; 32];
        let mut store = base_store(prev);
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);

        let run_digest = [7u8; 32];
        let asset_manifest_digest = [8u8; 32];
        let micro_config_digest = [9u8; 32];
        let evidence =
            replay_run_evidence(run_digest, asset_manifest_digest, micro_config_digest, 10);

        let req = PvgsCommitRequest {
            commit_id: "replay-run-evidence-1".to_string(),
            commit_type: CommitType::ReplayRunEvidenceAppend,
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
            required_receipt_kind: RequiredReceiptKind::Write,
            required_checks: vec![RequiredCheck::SchemaOk, RequiredCheck::BindingOk],
            payload_digests: Vec::new(),
            epoch_id: keystore.current_epoch(),
            key_epoch: None,
            experience_record_payload: None,
            replay_run_evidence_payload: Some(evidence.encode_to_vec()),
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

        let (receipt, proof_receipt) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);
        assert_eq!(receipt.status, ReceiptStatus::Accepted);
        assert!(proof_receipt.is_some());
        assert!(store.replay_run_store.get(run_digest).is_some());
        assert_eq!(store.replay_run_store.len(), 1);

        let second_req = PvgsCommitRequest {
            commit_id: "replay-run-evidence-2".to_string(),
            commit_type: CommitType::ReplayRunEvidenceAppend,
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
            required_receipt_kind: RequiredReceiptKind::Write,
            required_checks: vec![RequiredCheck::SchemaOk, RequiredCheck::BindingOk],
            payload_digests: Vec::new(),
            epoch_id: keystore.current_epoch(),
            key_epoch: None,
            experience_record_payload: None,
            replay_run_evidence_payload: Some(
                replay_run_evidence(run_digest, asset_manifest_digest, micro_config_digest, 11)
                    .encode_to_vec(),
            ),
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

        let (second_receipt, _) = verify_and_commit(second_req, &mut store, &keystore, &vrf_engine);
        assert_eq!(second_receipt.status, ReceiptStatus::Accepted);
        assert_eq!(store.replay_run_store.len(), 1);

        let logged = store.sep_log.events.iter().any(|event| {
            event.object_digest == run_digest
                && event
                    .reason_codes
                    .contains(&ReasonCodes::GV_REPLAY_RUN_EVIDENCE_APPENDED.to_string())
        });
        assert!(logged);

        let neighbors = store.causal_graph.neighbors(run_digest);
        assert!(neighbors.contains(&(EdgeType::References, asset_manifest_digest)));
        assert!(neighbors.contains(&(EdgeType::References, micro_config_digest)));
    }

    #[test]
    fn trace_run_evidence_append_is_idempotent() {
        let prev = [29u8; 32];
        let mut store = base_store(prev);
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);

        let active_cfg_digest = [12u8; 32];
        let shadow_cfg_digest = [13u8; 32];
        let active_feedback_digest = [14u8; 32];
        let shadow_feedback_digest = [15u8; 32];
        let evidence = trace_run_evidence(TraceRunEvidenceInput {
            run_digest: [11u8; 32],
            active_cfg_digest,
            shadow_cfg_digest,
            active_feedback_digest,
            shadow_feedback_digest,
            created_at_ms: 10,
            verdict: TraceVerdict::Promising,
            delta: 2,
        });
        let run_digest: [u8; 32] = evidence.trace_digest.as_slice().try_into().expect("digest");

        let req = PvgsCommitRequest {
            commit_id: "trace-run-evidence-1".to_string(),
            commit_type: CommitType::TraceRunEvidenceAppend,
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
            required_receipt_kind: RequiredReceiptKind::Write,
            required_checks: vec![RequiredCheck::SchemaOk, RequiredCheck::BindingOk],
            payload_digests: Vec::new(),
            epoch_id: keystore.current_epoch(),
            key_epoch: None,
            experience_record_payload: None,
            replay_run_evidence_payload: None,
            proposal_evidence_payload: None,
            proposal_activation_payload: None,
            trace_run_evidence_payload: Some(evidence.encode_to_vec()),
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

        let (receipt, proof_receipt) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);
        assert_eq!(receipt.status, ReceiptStatus::Accepted);
        assert!(proof_receipt.is_some());
        assert!(store.trace_run_store.get(run_digest).is_some());
        assert_eq!(store.trace_run_store.len(), 1);

        let second_req = PvgsCommitRequest {
            commit_id: "trace-run-evidence-2".to_string(),
            commit_type: CommitType::TraceRunEvidenceAppend,
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
            required_receipt_kind: RequiredReceiptKind::Write,
            required_checks: vec![RequiredCheck::SchemaOk, RequiredCheck::BindingOk],
            payload_digests: Vec::new(),
            epoch_id: keystore.current_epoch(),
            key_epoch: None,
            experience_record_payload: None,
            replay_run_evidence_payload: None,
            proposal_evidence_payload: None,
            proposal_activation_payload: None,
            trace_run_evidence_payload: Some(
                trace_run_evidence(TraceRunEvidenceInput {
                    run_digest: [22u8; 32],
                    active_cfg_digest,
                    shadow_cfg_digest,
                    active_feedback_digest,
                    shadow_feedback_digest,
                    created_at_ms: 10,
                    verdict: TraceVerdict::Promising,
                    delta: 2,
                })
                .encode_to_vec(),
            ),
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

        let (second_receipt, _) = verify_and_commit(second_req, &mut store, &keystore, &vrf_engine);
        assert_eq!(second_receipt.status, ReceiptStatus::Accepted);
        assert_eq!(store.trace_run_store.len(), 1);

        let logged = store.sep_log.events.iter().any(|event| {
            event.object_digest == run_digest
                && event
                    .reason_codes
                    .contains(&ReasonCodes::GV_TRACE_APPENDED.to_string())
        });
        assert!(logged);

        let neighbors = store.causal_graph.neighbors(run_digest);
        assert!(neighbors.contains(&(EdgeType::References, active_cfg_digest)));
        assert!(neighbors.contains(&(EdgeType::References, shadow_cfg_digest)));
        assert!(neighbors.contains(&(EdgeType::References, active_feedback_digest)));
        assert!(neighbors.contains(&(EdgeType::References, shadow_feedback_digest)));
    }

    #[test]
    fn trace_run_evidence_append_rejects_tampered_digest() {
        let prev = [31u8; 32];
        let mut store = base_store(prev);
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);

        let active_cfg_digest = [12u8; 32];
        let shadow_cfg_digest = [13u8; 32];
        let active_feedback_digest = [14u8; 32];
        let shadow_feedback_digest = [15u8; 32];
        let mut evidence = trace_run_evidence(TraceRunEvidenceInput {
            run_digest: [11u8; 32],
            active_cfg_digest,
            shadow_cfg_digest,
            active_feedback_digest,
            shadow_feedback_digest,
            created_at_ms: 10,
            verdict: TraceVerdict::Promising,
            delta: 2,
        });
        let run_digest: [u8; 32] = evidence.trace_digest.as_slice().try_into().expect("digest");
        evidence.delta = evidence.delta.saturating_add(5);

        let req = PvgsCommitRequest {
            commit_id: "trace-run-evidence-tampered".to_string(),
            commit_type: CommitType::TraceRunEvidenceAppend,
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
            required_receipt_kind: RequiredReceiptKind::Write,
            required_checks: vec![RequiredCheck::SchemaOk, RequiredCheck::BindingOk],
            payload_digests: Vec::new(),
            epoch_id: keystore.current_epoch(),
            key_epoch: None,
            experience_record_payload: None,
            replay_run_evidence_payload: None,
            proposal_evidence_payload: None,
            proposal_activation_payload: None,
            trace_run_evidence_payload: Some(evidence.encode_to_vec()),
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
        assert_eq!(receipt.status, ReceiptStatus::Rejected);
        assert!(store.trace_run_store.get(run_digest).is_none());
    }

    #[test]
    fn proposal_evidence_append_rejects_tampered_digest() {
        let prev = [41u8; 32];
        let mut store = base_store(prev);
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);

        let mut evidence = ProposalEvidence {
            proposal_id: "proposal-1".to_string(),
            proposal_digest: vec![0u8; 32],
            kind: ProposalKind::MappingUpdate as i32,
            base_evidence_digest: [8u8; 32].to_vec(),
            payload_digest: [9u8; 32].to_vec(),
            created_at_ms: 10,
            score: 0,
            verdict: 1,
            reason_codes: vec!["RC.GV.OK".to_string()],
        };
        let digest = compute_proposal_evidence_digest(&evidence).expect("proposal digest");
        evidence.proposal_digest = digest.to_vec();
        evidence.score = 5;

        let req = PvgsCommitRequest {
            commit_id: "proposal-evidence-tampered".to_string(),
            commit_type: CommitType::ProposalEvidenceAppend,
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
            required_checks: vec![RequiredCheck::SchemaOk, RequiredCheck::BindingOk],
            payload_digests: Vec::new(),
            epoch_id: keystore.current_epoch(),
            key_epoch: None,
            experience_record_payload: None,
            replay_run_evidence_payload: None,
            proposal_evidence_payload: Some(evidence.encode_to_vec()),
            proposal_activation_payload: None,
            trace_run_evidence_payload: None,
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
        assert_eq!(receipt.status, ReceiptStatus::Rejected);
    }

    #[test]
    fn proposal_evidence_append_rejects_unsorted_reason_codes() {
        let prev = [42u8; 32];
        let mut store = base_store(prev);
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);

        let mut evidence = ProposalEvidence {
            proposal_id: "proposal-1".to_string(),
            proposal_digest: vec![0u8; 32],
            kind: ProposalKind::MappingUpdate as i32,
            base_evidence_digest: [8u8; 32].to_vec(),
            payload_digest: [9u8; 32].to_vec(),
            created_at_ms: 10,
            score: 0,
            verdict: 1,
            reason_codes: vec!["RC.GV.OK".to_string(), "RC.GV.AA".to_string()],
        };
        let mut canonical = evidence.clone();
        canonical.proposal_digest = vec![0u8; 32];
        let payload = canonical.encode_to_vec();
        let mut input =
            Vec::with_capacity(proposals::PROPOSAL_EVIDENCE_DOMAIN.len() + payload.len());
        input.extend_from_slice(proposals::PROPOSAL_EVIDENCE_DOMAIN.as_bytes());
        input.extend_from_slice(&payload);
        evidence.proposal_digest = blake3::hash(&input).as_bytes().to_vec();

        let req = PvgsCommitRequest {
            commit_id: "proposal-evidence-unsorted".to_string(),
            commit_type: CommitType::ProposalEvidenceAppend,
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
            required_checks: vec![RequiredCheck::SchemaOk, RequiredCheck::BindingOk],
            payload_digests: Vec::new(),
            epoch_id: keystore.current_epoch(),
            key_epoch: None,
            experience_record_payload: None,
            replay_run_evidence_payload: None,
            proposal_evidence_payload: Some(evidence.encode_to_vec()),
            proposal_activation_payload: None,
            trace_run_evidence_payload: None,
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
        assert_eq!(receipt.status, ReceiptStatus::Rejected);
    }

    #[test]
    fn auto_commit_meso_appends_once() {
        let prev = [8u8; 32];
        let mut store = base_store(prev);
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);

        for i in 0..4 {
            store
                .micro_milestones
                .push(sample_micro(i + 1))
                .expect("valid micro");
        }

        let candidates = store
            .meso_deriver
            .derive_candidates(store.micro_milestones.list());
        assert_eq!(candidates.len(), 1);
        let meso_digest: [u8; 32] = candidates[0]
            .meso_digest
            .clone()
            .try_into()
            .expect("meso digest length");
        assert_eq!(compute_meso_digest(&candidates[0]).0, meso_digest);

        let receipt = store
            .auto_commit_next_meso(&keystore, &vrf_engine)
            .expect("auto commit")
            .expect("meso committed");

        assert_eq!(receipt.status, ReceiptStatus::Accepted);
        assert_eq!(store.meso_milestones.list().len(), 1);

        let meso_reason_logged = store.sep_log.events.iter().any(|event| {
            event
                .reason_codes
                .contains(&"RC.GV.MILESTONE.MESO_APPENDED".to_string())
        });
        assert!(meso_reason_logged);

        let second = store
            .auto_commit_next_meso(&keystore, &vrf_engine)
            .expect("second attempt");
        assert!(second.is_none());
    }

    #[test]
    fn auto_commit_macro_appends_and_updates_cbv() {
        let prev = [8u8; 32];
        let mut store = base_store(prev);
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);

        store_consistency_feedback(&mut store, [0x31u8; 32], "CONSISTENCY_HIGH");

        for i in 0..8 {
            let priority = if i == 0 {
                PriorityClass::High
            } else {
                PriorityClass::Med
            };
            store
                .micro_milestones
                .push(micro_with_priority(i + 1, priority))
                .expect("valid micro");
        }

        for _ in 0..2 {
            let receipt = store
                .auto_commit_next_meso(&keystore, &vrf_engine)
                .expect("auto meso")
                .expect("meso receipt");
            assert_eq!(receipt.status, ReceiptStatus::Accepted);
        }

        assert_eq!(store.meso_milestones.list().len(), 2);

        let macro_receipt = store
            .auto_propose_next_macro(&keystore, &vrf_engine)
            .expect("auto macro")
            .expect("macro receipt");

        assert_eq!(macro_receipt.status, ReceiptStatus::Accepted);
        assert_eq!(store.macro_milestones.len(), 0);

        let proposed_macro_id = store
            .macro_milestones
            .proposed_ids()
            .pop()
            .expect("proposal stored");

        assert!(store.cbv_store.latest().is_none());

        store_consistency_feedback(&mut store, [0x31u8; 32], "CONSISTENCY_HIGH");

        let macro_receipt = store
            .finalize_macro(&proposed_macro_id, [0x31u8; 32], &keystore, &vrf_engine)
            .expect("macro finalize")
            .expect("macro receipt");

        assert_eq!(macro_receipt.status, ReceiptStatus::Accepted);
        assert_eq!(store.macro_milestones.len(), 1);

        let macro_digest = digest_from_bytes(
            &store
                .macro_milestones
                .last()
                .expect("macro stored")
                .macro_digest,
        )
        .unwrap();

        let neighbors = store.causal_graph.neighbors(macro_digest);
        for meso in store.meso_milestones.list() {
            let digest = digest_from_bytes(&meso.meso_digest).unwrap();
            assert!(neighbors.contains(&(EdgeType::Finalizes, digest)));
        }

        let latest_cbv = store.cbv_store.latest().expect("cbv updated");
        assert_eq!(latest_cbv.cbv_epoch, 1);
        assert!(latest_cbv
            .source_milestone_refs
            .iter()
            .any(|r| digest_from_ref(r) == Some(macro_digest)));

        let macro_logged = store.sep_log.events.iter().any(|event| {
            event
                .reason_codes
                .contains(&ReasonCodes::GV_MACRO_FINALIZED.to_string())
        });
        assert!(macro_logged);

        let cbv_logged = store.sep_log.events.iter().any(|event| {
            event
                .reason_codes
                .contains(&ReasonCodes::GV_CBV_UPDATED.to_string())
        });
        assert!(cbv_logged);

        let second = store
            .auto_propose_next_macro(&keystore, &vrf_engine)
            .expect("second macro attempt");
        assert!(second.is_none());
    }

    #[test]
    fn side_effect_requires_tool_profile_digest() {
        let prev = [8u8; 32];
        let mut store = base_store(prev);
        let mut req = make_request(prev);
        req.required_receipt_kind = RequiredReceiptKind::Export;
        req.bindings.tool_profile_digest = None;
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);

        let (receipt, proof) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);
        assert_eq!(receipt.status, ReceiptStatus::Rejected);
        assert_eq!(
            receipt.reject_reason_codes,
            vec![ReasonCodes::GE_EXEC_DISPATCH_BLOCKED.to_string()]
        );
        assert!(proof.is_none());
    }

    #[test]
    fn side_effect_requires_profile_digest() {
        let prev = [8u8; 32];
        let mut store = base_store(prev);
        let mut req = make_request(prev);
        req.required_receipt_kind = RequiredReceiptKind::Write;
        req.bindings.profile_digest = None;
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);

        let (receipt, proof) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);
        assert_eq!(receipt.status, ReceiptStatus::Rejected);
        assert_eq!(
            receipt.reject_reason_codes,
            vec![ReasonCodes::GE_EXEC_DISPATCH_BLOCKED.to_string()]
        );
        assert!(proof.is_none());
    }

    #[test]
    fn side_effect_accepts_when_all_digests_present() {
        let prev = [8u8; 32];
        let mut store = base_store(prev);
        let mut req = make_request(prev);
        req.required_receipt_kind = RequiredReceiptKind::Export;
        req.bindings.tool_profile_digest = Some([5u8; 32]);
        req.bindings.profile_digest = Some([6u8; 32]);
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);

        let (receipt, proof) = verify_and_commit(req.clone(), &mut store, &keystore, &vrf_engine);
        assert_eq!(receipt.status, ReceiptStatus::Accepted);
        assert!(receipt.reject_reason_codes.is_empty());
        assert_eq!(
            receipt.bindings.profile_digest,
            req.bindings.profile_digest.map(Digest32)
        );
        assert_eq!(
            receipt.bindings.tool_profile_digest,
            req.bindings.tool_profile_digest.map(Digest32)
        );
        let pubkey = keystore
            .public_key_for_epoch(keystore.current_epoch())
            .unwrap();
        assert!(verify_pvgs_receipt_attestation(&receipt, pubkey));

        let proof = proof.expect("missing proof receipt");
        assert_ne!(proof.vrf_digest, Digest32::zero());
        let expected_verified_fields =
            compute_verified_fields_digest(&req.bindings, req.required_receipt_kind);
        assert_eq!(
            proof.verified_fields_digest,
            Digest32(expected_verified_fields)
        );
    }

    #[test]
    fn receipts_remain_deterministic_with_new_bindings() {
        let prev = [8u8; 32];
        let mut req = make_request(prev);
        req.required_receipt_kind = RequiredReceiptKind::Export;
        let keystore = KeyStore::new_dev_keystore(1);

        let mut store_one = base_store(prev);
        let vrf_one = VrfEngine::new_dev(1);
        let (receipt_one, _) = verify_and_commit(req.clone(), &mut store_one, &keystore, &vrf_one);

        let mut store_two = base_store(prev);
        let vrf_two = VrfEngine::new_dev(1);
        let (receipt_two, _) = verify_and_commit(req, &mut store_two, &keystore, &vrf_two);

        assert_eq!(receipt_one.receipt_digest, receipt_two.receipt_digest);
        assert_eq!(
            receipt_one.pvgs_attestation_sig,
            receipt_two.pvgs_attestation_sig
        );
    }

    #[test]
    fn receipt_rejected_wrong_prev() {
        let mut store = base_store([7u8; 32]);
        let req = make_request([6u8; 32]);
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);

        let (receipt, proof) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);
        assert_eq!(receipt.status, ReceiptStatus::Rejected);
        assert_eq!(
            receipt.reject_reason_codes,
            vec![ReasonCodes::GE_EXEC_DISPATCH_BLOCKED.to_string()]
        );
        assert!(proof.is_none());
        assert_eq!(store.sep_log.events.len(), 1);
    }

    #[test]
    fn receipt_rejected_unknown_charter() {
        let prev = [8u8; 32];
        let mut store = base_store(prev);
        let mut req = make_request(prev);
        req.bindings.charter_version_digest = "unknown".to_string();
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);

        let (receipt, proof) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);
        assert_eq!(receipt.status, ReceiptStatus::Rejected);
        assert_eq!(
            receipt.reject_reason_codes,
            vec![ReasonCodes::PB_DENY_CHARTER_SCOPE.to_string()]
        );
        assert!(proof.is_none());
    }

    #[test]
    fn epoch_mismatch_rejects() {
        let prev = [1u8; 32];
        let mut store = base_store(prev);
        let mut req = make_request(prev);
        req.epoch_id = 2;
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);

        let (receipt, proof) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);
        assert_eq!(receipt.status, ReceiptStatus::Rejected);
        assert_eq!(
            receipt.reject_reason_codes,
            vec![ReasonCodes::RE_INTEGRITY_DEGRADED.to_string()]
        );
        assert!(proof.is_none());
    }

    #[test]
    fn key_epoch_commit_accepted() {
        let prev = [8u8; 32];
        let mut store = base_store(prev);
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);
        let (req, epoch) = make_key_epoch_request(&keystore, &vrf_engine, &store, 1, None, "ke-1");

        let (receipt, proof) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);
        assert_eq!(receipt.status, ReceiptStatus::Accepted);
        assert!(proof.is_some());
        let latest = store
            .key_epoch_history
            .current()
            .expect("missing key epoch");
        assert_eq!(latest.key_epoch_id, 1);
        assert_eq!(latest.announcement_digest, epoch.announcement_digest);
        assert!(store
            .committed_payload_digests
            .contains(&epoch.announcement_digest.0));

        let last_event = store.sep_log.events.last().expect("missing event");
        assert_eq!(last_event.event_type, SepEventType::EvKeyEpoch);
        assert_eq!(last_event.object_digest, epoch.announcement_digest.0);
    }

    #[test]
    fn planned_key_rotation_commits_and_logs() {
        let prev = [8u8; 32];
        let mut store = base_store(prev);
        let mut keystore = KeyStore::new_dev_keystore(0);
        let mut vrf_engine = VrfEngine::new_dev(0);

        let mut planner = PvgsPlanner::new(&mut store, &mut keystore, &mut vrf_engine);
        let epoch = planner
            .planned_rotate_keys(1, 7777)
            .expect("rotation should succeed");

        let latest = store.key_epoch_history.current().expect("missing epoch");
        assert_eq!(latest.key_epoch_id, 1);
        assert_eq!(latest.announcement_digest, epoch.announcement_digest);

        let last_event = store.sep_log.events.last().expect("missing sep event");
        assert_eq!(last_event.event_type, SepEventType::EvKeyEpoch);
        assert_eq!(last_event.object_digest, epoch.announcement_digest.0);
        assert_eq!(
            last_event.reason_codes,
            vec![ReasonCodes::GV_KEY_EPOCH_ROTATED.to_string()]
        );
    }

    #[test]
    fn planned_key_rotation_rejects_regressions() {
        let prev = [8u8; 32];
        let mut store = base_store(prev);
        let mut keystore = KeyStore::new_dev_keystore(0);
        let mut vrf_engine = VrfEngine::new_dev(0);

        let mut planner = PvgsPlanner::new(&mut store, &mut keystore, &mut vrf_engine);
        let _ = planner.planned_rotate_keys(1, 10).expect("first rotation");

        let err = planner
            .planned_rotate_keys(1, 20)
            .expect_err("non-monotonic rotation should fail");

        assert!(matches!(err, Error::NonMonotonic { last: 1, next: 1 }));
    }

    #[test]
    fn planned_rotation_updates_epoch_and_rejects_lower_value() {
        let prev = [8u8; 32];
        let mut store = base_store(prev);
        let mut keystore = KeyStore::new_dev_keystore(0);
        let mut vrf_engine = VrfEngine::new_dev(0);

        {
            let mut planner = PvgsPlanner::new(&mut store, &mut keystore, &mut vrf_engine);
            let epoch = planner
                .planned_rotate_keys(2, 5555)
                .expect("initial rotation should succeed");

            let latest = store.key_epoch_history.current().expect("missing epoch");
            assert_eq!(latest.key_epoch_id, 2);
            assert_eq!(latest.announcement_digest, epoch.announcement_digest);
        }

        assert_eq!(keystore.current_epoch(), 2);

        let mut planner = PvgsPlanner::new(&mut store, &mut keystore, &mut vrf_engine);
        let err = planner
            .planned_rotate_keys(1, 6666)
            .expect_err("non-monotonic rotation should fail");

        assert!(matches!(err, Error::NonMonotonic { last: 2, next: 1 }));
    }

    #[test]
    fn key_epoch_rejects_non_monotonic() {
        let prev = [7u8; 32];
        let mut store = base_store(prev);
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);

        let (req1, epoch1) =
            make_key_epoch_request(&keystore, &vrf_engine, &store, 1, None, "ke-1");
        let _ = verify_and_commit(req1, &mut store, &keystore, &vrf_engine);

        let (req2, _) = make_key_epoch_request(
            &keystore,
            &vrf_engine,
            &store,
            2,
            Some(epoch1.announcement_digest.0),
            "ke-2",
        );
        let _ = verify_and_commit(req2, &mut store, &keystore, &vrf_engine);

        let backward_epoch =
            keystore.make_key_epoch_proto(1, 999, vrf_engine.vrf_public_key().to_vec(), None);
        let backward_req = PvgsCommitRequest {
            commit_id: "ke-backwards".to_string(),
            commit_type: CommitType::KeyEpochUpdate,
            bindings: CommitBindings {
                action_digest: None,
                decision_digest: None,
                grant_id: None,
                charter_version_digest: "charter".to_string(),
                policy_version_digest: "policy".to_string(),
                prev_record_digest: store.current_head_record_digest,
                profile_digest: Some([9u8; 32]),
                tool_profile_digest: None,
                pev_digest: None,
            },
            required_receipt_kind: RequiredReceiptKind::Read,
            required_checks: vec![RequiredCheck::SchemaOk, RequiredCheck::BindingOk],
            payload_digests: vec![backward_epoch.announcement_digest.0],
            epoch_id: keystore.current_epoch(),
            key_epoch: Some(backward_epoch),
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
        };

        let (receipt, proof) = verify_and_commit(backward_req, &mut store, &keystore, &vrf_engine);
        assert_eq!(receipt.status, ReceiptStatus::Rejected);
        assert!(proof.is_none());
        assert!(receipt
            .reject_reason_codes
            .contains(&ReasonCodes::GV_KEY_EPOCH_NON_MONOTONIC.to_string()));
    }

    #[test]
    fn key_epoch_rejects_invalid_signature() {
        let prev = [5u8; 32];
        let mut store = base_store(prev);
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);
        let (mut req, mut epoch) =
            make_key_epoch_request(&keystore, &vrf_engine, &store, 1, None, "ke-1");
        epoch.announcement_signature[0] ^= 0xFF;
        req.key_epoch = Some(epoch);

        let (receipt, proof) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);
        assert_eq!(receipt.status, ReceiptStatus::Rejected);
        assert!(proof.is_none());
        assert_eq!(
            receipt.reject_reason_codes,
            vec![ReasonCodes::GV_KEY_EPOCH_SIGNATURE_INVALID.to_string()]
        );
    }

    #[test]
    fn key_epoch_rejects_duplicate_payload() {
        let prev = [4u8; 32];
        let mut store = base_store(prev);
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);
        let (req, epoch) = make_key_epoch_request(&keystore, &vrf_engine, &store, 1, None, "ke-1");
        let _ = verify_and_commit(req, &mut store, &keystore, &vrf_engine);

        let dup_req = PvgsCommitRequest {
            commit_id: "ke-dup".to_string(),
            commit_type: CommitType::KeyEpochUpdate,
            bindings: CommitBindings {
                action_digest: None,
                decision_digest: None,
                grant_id: None,
                charter_version_digest: "charter".to_string(),
                policy_version_digest: "policy".to_string(),
                prev_record_digest: store.current_head_record_digest,
                profile_digest: Some([9u8; 32]),
                tool_profile_digest: None,
                pev_digest: None,
            },
            required_receipt_kind: RequiredReceiptKind::Read,
            required_checks: vec![RequiredCheck::SchemaOk, RequiredCheck::BindingOk],
            payload_digests: vec![epoch.announcement_digest.0],
            epoch_id: keystore.current_epoch(),
            key_epoch: Some(epoch),
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
        };

        let (receipt, proof) = verify_and_commit(dup_req, &mut store, &keystore, &vrf_engine);
        assert_eq!(receipt.status, ReceiptStatus::Rejected);
        assert!(proof.is_none());
        assert_eq!(
            receipt.reject_reason_codes,
            vec![ReasonCodes::GV_KEY_EPOCH_DUPLICATE.to_string()]
        );
    }

    #[test]
    fn frame_evidence_commit_logs_event() {
        let prev = [8u8; 32];
        let mut store = base_store(prev);
        let req = PvgsCommitRequest {
            commit_id: "frame-commit".to_string(),
            commit_type: CommitType::FrameEvidenceAppend,
            bindings: CommitBindings {
                action_digest: None,
                decision_digest: None,
                grant_id: None,
                charter_version_digest: "charter".to_string(),
                policy_version_digest: "policy".to_string(),
                prev_record_digest: prev,
                profile_digest: Some([1u8; 32]),
                tool_profile_digest: None,
                pev_digest: None,
            },
            required_receipt_kind: RequiredReceiptKind::Write,
            required_checks: vec![RequiredCheck::SchemaOk, RequiredCheck::BindingOk],
            payload_digests: vec![[1u8; 32]],
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
            asset_bundle_payload: None,
        };

        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);

        let (receipt, proof) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);
        assert_eq!(receipt.status, ReceiptStatus::Accepted);
        assert!(proof.is_some());

        let last_event = store.sep_log.events.last().expect("missing frame event");
        assert_eq!(last_event.event_type, SepEventType::EvControlFrame);
        assert_eq!(last_event.object_digest, [1u8; 32]);
    }

    #[test]
    fn dlp_decision_append_stores_and_logs() {
        let prev = [10u8; 32];
        let mut store = base_store(prev);
        let keystore = KeyStore::new_dev_keystore(2);
        let vrf_engine = VrfEngine::new_dev(2);
        let dlp_digest = [0xAAu8; 32];

        let decision = DlpDecision {
            dlp_decision_digest: Some(dlp_digest.to_vec()),
            decision_form: DlpDecisionForm::Block as i32,
            reason_codes: vec![
                ReasonCodes::CD_DLP_SECRET_PATTERN.to_string(),
                ReasonCodes::CD_DLP_EXPORT_BLOCKED.to_string(),
            ],
        };

        let req = PvgsCommitRequest {
            commit_id: "dlp-append".to_string(),
            commit_type: CommitType::DlpDecisionAppend,
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
            dlp_decision_payload: Some(decision.encode_to_vec()),
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

        let (receipt, proof) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);
        assert_eq!(receipt.status, ReceiptStatus::Accepted);
        assert!(proof.is_none());

        let stored = store.dlp_store.get(dlp_digest).expect("missing decision");
        assert_eq!(
            stored.reason_codes,
            vec![
                ReasonCodes::CD_DLP_EXPORT_BLOCKED.to_string(),
                ReasonCodes::CD_DLP_SECRET_PATTERN.to_string(),
            ]
        );

        let event = store.sep_log.events.last().expect("missing sep event");
        assert_eq!(event.event_type, SepEventType::EvDlpDecision);
        assert_eq!(event.object_digest, dlp_digest);
        assert_eq!(event.reason_codes, stored.reason_codes);
    }

    #[test]
    fn pev_update_commit_appends_sep_event() {
        let prev = [2u8; 32];
        let mut store = base_store(prev);
        let initial_ruleset = store.ruleset_state.ruleset_digest;
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);
        let pev_digest = [0x22u8; 32];
        let pev = sample_pev(pev_digest, 1);

        let req = PvgsCommitRequest {
            commit_id: "pev-update".to_string(),
            commit_type: CommitType::PevUpdate,
            bindings: CommitBindings {
                action_digest: None,
                decision_digest: None,
                grant_id: None,
                charter_version_digest: "charter".to_string(),
                policy_version_digest: "policy".to_string(),
                prev_record_digest: prev,
                profile_digest: Some([9u8; 32]),
                tool_profile_digest: None,
                pev_digest: None,
            },
            required_receipt_kind: RequiredReceiptKind::Read,
            required_checks: vec![RequiredCheck::SchemaOk, RequiredCheck::BindingOk],
            payload_digests: vec![pev_digest],
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
            pev: Some(pev.clone()),
            consistency_feedback_payload: None,
            macro_consistency_digest: None,
            recovery_case: None,
            unlock_permit: None,
            tool_onboarding_event: None,
            microcircuit_config_payload: None,
            asset_manifest_payload: None,
            asset_bundle_payload: None,
        };

        let (receipt, proof) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);
        assert_eq!(receipt.status, ReceiptStatus::Accepted);
        let proof = proof.expect("missing proof receipt");
        assert_eq!(
            proof.verified_fields_digest,
            Digest32(compute_pev_verified_fields_digest(
                prev,
                pev_digest,
                pev.pev_version_digest
                    .as_deref()
                    .and_then(digest_from_bytes),
                keystore.current_epoch()
            ))
        );

        let stored_pev = store.pev_store.latest().expect("missing stored pev");
        assert_eq!(extract_pev_digest(stored_pev), Some(pev_digest));

        let sep_event = store.sep_log.events.last().expect("missing sep event");
        assert_eq!(sep_event.event_type, SepEventType::EvPevUpdate);
        assert_eq!(sep_event.object_digest, store.ruleset_state.ruleset_digest);
        assert_eq!(
            sep_event.reason_codes,
            vec![
                ReasonCodes::GV_PEV_UPDATED.to_string(),
                ReasonCodes::GV_RULESET_CHANGED.to_string(),
            ]
        );
        assert_eq!(
            store.ruleset_state.prev_ruleset_digest,
            Some(initial_ruleset)
        );
    }

    #[test]
    fn ruleset_digest_changes_when_pev_updates() {
        let prev = [2u8; 32];
        let mut store = base_store(prev);
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);

        let initial_ruleset = store.ruleset_state.ruleset_digest;

        let (receipt_before, proof_before) =
            verify_and_commit(make_request(prev), &mut store, &keystore, &vrf_engine);
        assert_eq!(receipt_before.status, ReceiptStatus::Accepted);
        let proof_before = proof_before.expect("proof receipt before PEV");
        assert_eq!(
            proof_before.ruleset_digest.0,
            store.ruleset_state.ruleset_digest
        );

        let pev_digest = [0x33u8; 32];
        let pev = sample_pev(pev_digest, 1);
        let pev_req = PvgsCommitRequest {
            commit_id: "pev-update-ruleset".to_string(),
            commit_type: CommitType::PevUpdate,
            bindings: CommitBindings {
                action_digest: None,
                decision_digest: None,
                grant_id: None,
                charter_version_digest: "charter".to_string(),
                policy_version_digest: "policy".to_string(),
                prev_record_digest: prev,
                profile_digest: Some([9u8; 32]),
                tool_profile_digest: None,
                pev_digest: None,
            },
            required_receipt_kind: RequiredReceiptKind::Read,
            required_checks: vec![RequiredCheck::SchemaOk, RequiredCheck::BindingOk],
            payload_digests: vec![pev_digest],
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
            pev: Some(pev),
            consistency_feedback_payload: None,
            macro_consistency_digest: None,
            recovery_case: None,
            unlock_permit: None,
            tool_onboarding_event: None,
            microcircuit_config_payload: None,
            asset_manifest_payload: None,
            asset_bundle_payload: None,
        };

        let (_, pev_proof) = verify_and_commit(pev_req, &mut store, &keystore, &vrf_engine);
        let pev_proof = pev_proof.expect("proof receipt after PEV");
        let updated_ruleset = store.ruleset_state.ruleset_digest;

        assert_ne!(initial_ruleset, updated_ruleset);
        assert_eq!(pev_proof.ruleset_digest.0, updated_ruleset);

        let mut after_req = make_request(prev);
        after_req.commit_id = "after-pev".to_string();
        let (_, proof_after) = verify_and_commit(after_req, &mut store, &keystore, &vrf_engine);
        let proof_after = proof_after.expect("proof receipt after ruleset change");

        assert_ne!(proof_before.ruleset_digest, proof_after.ruleset_digest);
        assert_eq!(
            proof_after.ruleset_digest.0,
            store.ruleset_state.ruleset_digest
        );

        let sep_event = store
            .sep_log
            .events
            .iter()
            .find(|event| event.event_type == SepEventType::EvPevUpdate)
            .expect("missing sep event");
        assert_eq!(sep_event.object_digest, store.ruleset_state.ruleset_digest);
        assert_eq!(
            sep_event.reason_codes,
            vec![
                ReasonCodes::GV_PEV_UPDATED.to_string(),
                ReasonCodes::GV_RULESET_CHANGED.to_string(),
            ]
        );
        assert_eq!(
            store.ruleset_state.prev_ruleset_digest,
            Some(initial_ruleset)
        );
    }

    #[test]
    fn tool_registry_update_changes_ruleset_and_logs_sep() {
        let prev = [3u8; 32];
        let mut store = base_store(prev);
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);

        let initial_ruleset = store.ruleset_state.ruleset_digest;
        let registry_digest = [0x77u8; 32];
        let container = tool_registry_container(registry_digest, "trc-v1");
        let req = PvgsCommitRequest {
            commit_id: "tool-registry".to_string(),
            commit_type: CommitType::ToolRegistryUpdate,
            bindings: CommitBindings {
                action_digest: None,
                decision_digest: None,
                grant_id: None,
                charter_version_digest: "charter".to_string(),
                policy_version_digest: "policy".to_string(),
                prev_record_digest: prev,
                profile_digest: Some([9u8; 32]),
                tool_profile_digest: None,
                pev_digest: None,
            },
            required_receipt_kind: RequiredReceiptKind::Read,
            required_checks: vec![RequiredCheck::SchemaOk, RequiredCheck::BindingOk],
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
            tool_registry_container: Some(container.encode_to_vec()),
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

        let (receipt, proof) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);
        assert_eq!(receipt.status, ReceiptStatus::Accepted);
        let proof = proof.expect("missing proof receipt");

        let updated_ruleset = store.ruleset_state.ruleset_digest;
        assert_ne!(initial_ruleset, updated_ruleset);
        assert_eq!(store.tool_registry_state.current(), Some(registry_digest));
        assert_eq!(
            store.ruleset_state.tool_registry_digest,
            Some(registry_digest)
        );
        assert_eq!(proof.ruleset_digest.0, updated_ruleset);

        let sep_event = store.sep_log.events.last().expect("missing sep event");
        assert_eq!(sep_event.event_type, SepEventType::EvToolOnboarding);
        assert_eq!(sep_event.object_digest, store.ruleset_state.ruleset_digest);
        assert_eq!(
            sep_event.reason_codes,
            vec![
                ReasonCodes::GV_TOOL_REGISTRY_UPDATED.to_string(),
                ReasonCodes::GV_RULESET_CHANGED.to_string(),
            ]
        );
        assert_eq!(
            store.ruleset_state.prev_ruleset_digest,
            Some(initial_ruleset)
        );
    }

    #[test]
    fn tool_onboarding_suspension_is_tracked_and_logged() {
        let prev = [4u8; 32];
        let mut store = base_store(prev);
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);

        let event = ToolOnboardingEvent {
            event_id: "to-event-1".to_string(),
            stage: ToolOnboardingStage::To6Suspended as i32,
            tool_id: "tool-9".to_string(),
            action_id: "action-9".to_string(),
            reason_codes: vec!["b".to_string(), "a".to_string()],
            signatures: Vec::new(),
            event_digest: None,
            created_at_ms: Some(10),
        };

        let req = PvgsCommitRequest {
            commit_id: "tool-event".to_string(),
            commit_type: CommitType::ToolOnboardingEventAppend,
            bindings: CommitBindings {
                action_digest: None,
                decision_digest: None,
                grant_id: None,
                charter_version_digest: "charter".to_string(),
                policy_version_digest: "policy".to_string(),
                prev_record_digest: prev,
                profile_digest: Some([9u8; 32]),
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
            tool_onboarding_event: Some(event.encode_to_vec()),
            microcircuit_config_payload: None,
            asset_manifest_payload: None,
            asset_bundle_payload: None,
        };

        let (receipt, proof) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);
        assert_eq!(receipt.status, ReceiptStatus::Accepted);
        let proof = proof.expect("missing proof receipt");

        let digest = compute_tool_event_digest(&event).expect("event digest");
        assert!(store.tool_event_store.get(digest).is_some());
        assert_eq!(proof.ruleset_digest.0, store.ruleset_state.ruleset_digest);

        let sep_event = store.sep_log.events.last().expect("sep event");
        assert_eq!(sep_event.event_type, SepEventType::EvToolOnboarding);
        assert_eq!(sep_event.object_digest, digest);
        assert!(sep_event
            .reason_codes
            .contains(&ReasonCodes::GV_TOOL_SUSPENDED.to_string()));
        assert!(store
            .suspended_tools
            .contains(&("tool-9".to_string(), "action-9".to_string())));
    }

    #[test]
    fn ruleset_digest_is_stable_without_pev() {
        let mut state = RulesetState::new("charter".to_string(), "policy".to_string());
        let first = state.ruleset_digest;
        let changed = state.recompute_ruleset_digest();

        assert!(!changed);
        assert_eq!(first, state.ruleset_digest);
    }

    #[test]
    fn experience_perception_append_succeeds() {
        let prev = [0u8; 32];
        let mut store = base_store(prev);
        let keystore = KeyStore::new_dev_keystore(2);
        let vrf_engine = VrfEngine::new_dev(2);
        let record = perception_record([5u8; 32]);
        let req =
            make_experience_request_with_id(&record, &store, keystore.current_epoch(), "exp-1");

        let (receipt, proof) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);

        assert_eq!(receipt.status, ReceiptStatus::Accepted);
        assert!(proof.is_some());
        assert_eq!(store.experience_store.head_id, 1);
        assert_ne!(store.current_head_record_digest, prev);
    }

    #[test]
    fn action_exec_missing_governance_ref_rejected() {
        let prev = [0u8; 32];
        let mut store = base_store(prev);
        let keystore = KeyStore::new_dev_keystore(3);
        let vrf_engine = VrfEngine::new_dev(3);

        let mut record = ExperienceRecord {
            record_type: RecordType::RtActionExec as i32,
            governance_frame: Some(GovernanceFrame::default()),
            ..Default::default()
        };
        record.governance_frame_ref = None;

        let req = make_experience_request_with_id(
            &record,
            &store,
            keystore.current_epoch(),
            "exp-missing-gov",
        );

        let (receipt, proof) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);

        assert_eq!(receipt.status, ReceiptStatus::Rejected);
        assert!(proof.is_none());
        assert_eq!(store.current_head_record_digest, prev);
        assert!(store.experience_store.records.is_empty());
        assert!(receipt
            .reject_reason_codes
            .contains(&ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string()));
    }

    #[test]
    fn rt_output_accepts_with_dlp_refs() {
        let prev = [4u8; 32];
        let mut store = base_store(prev);
        let keystore = KeyStore::new_dev_keystore(7);
        let vrf_engine = VrfEngine::new_dev(7);

        let record = output_record([2u8; 32]);
        let req = make_experience_request_with_id(
            &record,
            &store,
            keystore.current_epoch(),
            "exp-output-accept",
        );

        let (receipt, _) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);

        assert_eq!(receipt.status, ReceiptStatus::Accepted);
        assert_eq!(store.experience_store.head_id, 1);
    }

    #[test]
    fn rt_output_rejects_without_dlp_refs() {
        let prev = [5u8; 32];
        let mut store = base_store(prev);
        let keystore = KeyStore::new_dev_keystore(8);
        let vrf_engine = VrfEngine::new_dev(8);

        let mut record = output_record([3u8; 32]);
        if let Some(gov) = record.governance_frame.as_mut() {
            gov.dlp_refs.clear();
        }

        let req = make_experience_request_with_id(
            &record,
            &store,
            keystore.current_epoch(),
            "exp-output-reject",
        );

        let (receipt, _) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);

        assert_eq!(receipt.status, ReceiptStatus::Rejected);
        assert!(receipt
            .reject_reason_codes
            .contains(&ReasonCodes::GE_VALIDATION_SCHEMA_INVALID.to_string()));
    }

    #[test]
    fn rt_output_logs_sep_and_graph_edges() {
        let prev = [6u8; 32];
        let mut store = base_store(prev);
        let keystore = KeyStore::new_dev_keystore(9);
        let vrf_engine = VrfEngine::new_dev(9);

        let dlp_digest = [9u8; 32];
        let record = output_record(dlp_digest);
        let req = make_experience_request_with_id(
            &record,
            &store,
            keystore.current_epoch(),
            "exp-output-sep",
        );

        let (receipt, _) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);
        assert_eq!(receipt.status, ReceiptStatus::Accepted);

        let record_digest = store.experience_store.head_record_digest;
        let neighbors = store.causal_graph.neighbors(record_digest);
        assert!(neighbors.contains(&(EdgeType::References, dlp_digest)));

        let has_dlp_event = store.sep_log.events.iter().any(|event| {
            event.event_type == SepEventType::EvDlpDecision && event.object_digest == dlp_digest
        });
        assert!(has_dlp_event);
        assert!(store.sep_log.validate_chain().is_ok());
    }

    #[test]
    fn experience_record_chain_binds_prev_digest() {
        let prev = [1u8; 32];
        let mut store = base_store(prev);
        let keystore = KeyStore::new_dev_keystore(4);
        let vrf_engine = VrfEngine::new_dev(4);

        let first_record = perception_record([7u8; 32]);
        let req_one = make_experience_request_with_id(
            &first_record,
            &store,
            keystore.current_epoch(),
            "exp-chain-1",
        );
        let _ = verify_and_commit(req_one, &mut store, &keystore, &vrf_engine);
        let first_digest = store.current_head_record_digest;

        let second_record = perception_record([8u8; 32]);
        let req_two = make_experience_request_with_id(
            &second_record,
            &store,
            keystore.current_epoch(),
            "exp-chain-2",
        );
        let (receipt_two, _) = verify_and_commit(req_two, &mut store, &keystore, &vrf_engine);
        assert_eq!(receipt_two.status, ReceiptStatus::Accepted);

        let appended = store
            .experience_store
            .records
            .last()
            .expect("missing appended record");
        let header = appended
            .finalization_header
            .as_ref()
            .expect("finalization header missing");
        let prev_digest =
            digest_from_bytes(&header.prev_record_digest).expect("invalid prev digest");
        let record_digest =
            digest_from_bytes(&header.record_digest).expect("invalid record digest");

        assert_eq!(prev_digest, first_digest);
        assert_eq!(store.current_head_record_digest, record_digest);
        assert_eq!(
            compute_experience_record_digest(&first_record),
            compute_experience_record_digest(&first_record),
        );
    }

    #[test]
    fn experience_store_evicts_oldest_record_and_logs_reason() {
        let mut store = base_store([0u8; 32]);
        store.limits.max_experience_records = 1;
        store.experience_store.limits = store.limits;
        let keystore = KeyStore::new_dev_keystore(8);
        let vrf_engine = VrfEngine::new_dev(8);

        let first = perception_record([5u8; 32]);
        let req_one = make_experience_request_with_id(
            &first,
            &store,
            keystore.current_epoch(),
            "exp-evict-1",
        );
        let (_, proof_one) = verify_and_commit(req_one, &mut store, &keystore, &vrf_engine);
        let first_digest = store.current_head_record_digest;

        let second = perception_record([6u8; 32]);
        let req_two = make_experience_request_with_id(
            &second,
            &store,
            keystore.current_epoch(),
            "exp-evict-2",
        );
        let (_, proof_two) = verify_and_commit(req_two, &mut store, &keystore, &vrf_engine);

        assert!(proof_one.is_some());
        assert!(proof_two.is_some());
        assert_eq!(store.experience_store.records.len(), 1);
        assert!(!store
            .experience_store
            .proof_receipts
            .contains_key(&first_digest));

        let eviction_logged = store.sep_log.events.iter().any(|event| {
            event.event_type == SepEventType::EvOutcome
                && event
                    .reason_codes
                    .contains(&"RC.GV.RETENTION.EVICTED".to_string())
        });
        assert!(eviction_logged);
    }

    #[test]
    fn proof_receipt_vrf_digest_is_non_zero() {
        let prev = [0u8; 32];
        let mut store = base_store(prev);
        let keystore = KeyStore::new_dev_keystore(5);
        let vrf_engine = VrfEngine::new_dev(5);
        let record = perception_record([9u8; 32]);
        let req =
            make_experience_request_with_id(&record, &store, keystore.current_epoch(), "exp-proof");

        let (_, proof) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);
        let proof = proof.expect("missing proof receipt");

        assert_ne!(proof.vrf_digest, Digest32::zero());
    }

    #[test]
    fn sep_log_updates_after_experience_append() {
        let prev = [2u8; 32];
        let mut store = base_store(prev);
        let keystore = KeyStore::new_dev_keystore(6);
        let vrf_engine = VrfEngine::new_dev(6);
        let record = perception_record([6u8; 32]);
        let req =
            make_experience_request_with_id(&record, &store, keystore.current_epoch(), "exp-sep");

        let (receipt, _) = verify_and_commit(req, &mut store, &keystore, &vrf_engine);

        assert_eq!(receipt.status, ReceiptStatus::Accepted);
        assert!(!store.sep_log.events.is_empty());
        assert!(store.sep_log.validate_chain().is_ok());
        let has_append_ok = store.sep_log.events.iter().any(|event| {
            event.event_type == SepEventType::EvRecoveryGov
                && event.reason_codes.contains(&"RECORD_APPEND_OK".to_string())
        });
        assert!(has_append_ok);
    }

    #[test]
    fn completeness_passes_with_action_receipt_decision_and_record() {
        let mut graph = CausalGraph::default();
        let mut sep_log = SepLog::default();
        let action = [1u8; 32];
        let receipt = [2u8; 32];
        let decision = [3u8; 32];
        let record = [4u8; 32];
        let profile = [5u8; 32];

        graph.add_edge(action, EdgeType::Authorizes, receipt, None);
        graph.add_edge(decision, EdgeType::Authorizes, receipt, None);
        graph.add_edge(record, EdgeType::References, action, None);
        graph.add_edge(record, EdgeType::References, receipt, None);
        graph.add_edge(profile, EdgeType::References, receipt, None);

        sep_log
            .append_event(
                "sess-ok".to_string(),
                SepEventType::EvDecision,
                receipt,
                vec![],
            )
            .unwrap();
        sep_log
            .append_frame_event(
                "sess-ok".to_string(),
                FrameEventKind::ControlFrame,
                profile,
                vec![],
            )
            .unwrap();

        let dlp_store = DlpDecisionStore::default();
        let replay_plans = ReplayPlanStore::default();
        let records = Vec::new();
        let (asset_manifest_store, asset_bundle_store) = empty_asset_stores();
        let mut checker = CompletenessChecker::new(
            &graph,
            &mut sep_log,
            &dlp_store,
            &replay_plans,
            &asset_manifest_store,
            &asset_bundle_store,
            &records,
        );
        let report = checker.check_actions("sess-ok", vec![action]);

        assert!(report.missing_edges.is_empty());
        assert!(report.missing_nodes.is_empty());
        assert_eq!(report.status, CompletenessStatus::Ok);
    }

    #[test]
    fn completeness_fails_when_receipt_missing() {
        let graph = CausalGraph::default();
        let mut sep_log = SepLog::default();
        let dlp_store = DlpDecisionStore::default();
        let replay_plans = ReplayPlanStore::default();
        let records = Vec::new();
        let (asset_manifest_store, asset_bundle_store) = empty_asset_stores();
        let mut checker = CompletenessChecker::new(
            &graph,
            &mut sep_log,
            &dlp_store,
            &replay_plans,
            &asset_manifest_store,
            &asset_bundle_store,
            &records,
        );

        let report = checker.check_actions("sess-missing", vec![[9u8; 32]]);

        assert_eq!(report.status, CompletenessStatus::Fail);
        assert!(report
            .reason_codes
            .contains(&ReasonCodes::RE_INTEGRITY_FAIL.to_string()));
    }

    #[test]
    fn completeness_failure_seals_session_and_logs_incident() {
        let prev = [8u8; 32];
        let mut store = base_store(prev);

        let report = store.check_completeness("sess-complete-fail", vec![[9u8; 32]]);

        assert_eq!(report.status, CompletenessStatus::Fail);
        assert!(report
            .reason_codes
            .contains(&ReasonCodes::RE_INTEGRITY_FAIL.to_string()));
        assert!(store.forensic_mode);

        let seal = sep::seal("sess-complete-fail", &store.sep_log);
        assert_ne!(seal.final_event_digest, [0u8; 32]);
        assert!(store
            .sep_log
            .events
            .iter()
            .any(|event| event.event_type == SepEventType::EvIncident));
    }

    #[test]
    fn completeness_degrades_when_record_missing() {
        let mut graph = CausalGraph::default();
        let mut sep_log = SepLog::default();
        let action = [7u8; 32];
        let receipt = [8u8; 32];
        let decision = [6u8; 32];
        let profile = [5u8; 32];

        graph.add_edge(action, EdgeType::Authorizes, receipt, None);
        graph.add_edge(decision, EdgeType::Authorizes, receipt, None);
        graph.add_edge(profile, EdgeType::References, receipt, None);

        sep_log
            .append_event(
                "sess-degraded".to_string(),
                SepEventType::EvDecision,
                receipt,
                vec![],
            )
            .unwrap();
        sep_log
            .append_frame_event(
                "sess-degraded".to_string(),
                FrameEventKind::ControlFrame,
                profile,
                vec![],
            )
            .unwrap();

        let dlp_store = DlpDecisionStore::default();
        let replay_plans = ReplayPlanStore::default();
        let records = Vec::new();
        let (asset_manifest_store, asset_bundle_store) = empty_asset_stores();
        let mut checker = CompletenessChecker::new(
            &graph,
            &mut sep_log,
            &dlp_store,
            &replay_plans,
            &asset_manifest_store,
            &asset_bundle_store,
            &records,
        );
        let report = checker.check_actions("sess-degraded", vec![action]);

        assert_eq!(report.status, CompletenessStatus::Degraded);
        assert!(report
            .reason_codes
            .contains(&ReasonCodes::RE_INTEGRITY_DEGRADED.to_string()));
    }

    #[test]
    fn sep_overflow_triggers_incident_and_seal() {
        let prev = [8u8; 32];
        let mut store = base_store(prev);
        store.limits.max_sep_events = 1;
        store.sep_log.limits.max_sep_events = 1;

        store
            .record_sep_event(
                "sess-overflow",
                SepEventType::EvDecision,
                [1u8; 32],
                vec![ReasonCodes::RE_INTEGRITY_OK.to_string()],
            )
            .expect("first event should fit");
        let err = store
            .record_sep_event(
                "sess-overflow",
                SepEventType::EvDecision,
                [2u8; 32],
                vec![ReasonCodes::RE_INTEGRITY_OK.to_string()],
            )
            .expect_err("overflow should fail");

        assert_eq!(err, SepError::Overflow);
        assert!(store.forensic_mode);

        let seal = sep::seal("sess-overflow", &store.sep_log);
        assert_ne!(seal.final_event_digest, [0u8; 32]);
        assert!(store
            .sep_log
            .events
            .iter()
            .any(|event| event.event_type == SepEventType::EvIncident));
    }

    #[test]
    fn replay_mismatch_auto_seals() {
        let prev = [8u8; 32];
        let mut store = base_store(prev);
        store.config.auto_seal_on_replay_mismatch = true;
        store.critical_triggers.replay_mismatch = true;

        store
            .record_sep_event(
                "sess-replay-mismatch",
                SepEventType::EvDecision,
                [4u8; 32],
                vec![ReasonCodes::RE_REPLAY_MISMATCH.to_string()],
            )
            .expect("replay mismatch should be recorded");

        assert!(store.forensic_mode);
        assert!(store
            .sep_log
            .events
            .iter()
            .any(|event| event.event_type == SepEventType::EvIncident));
        let seal = sep::seal("sess-replay-mismatch", &store.sep_log);
        assert_ne!(seal.final_event_digest, [0u8; 32]);
    }

    #[test]
    fn completeness_accepts_present_dlp_decision_for_output() {
        let graph = CausalGraph::default();
        let mut sep_log = SepLog::default();
        let dlp_digest = [42u8; 32];

        let mut dlp_store = DlpDecisionStore::default();
        let decision = DlpDecision {
            dlp_decision_digest: Some(dlp_digest.to_vec()),
            decision_form: DlpDecisionForm::Allow as i32,
            reason_codes: vec![ReasonCodes::RE_INTEGRITY_OK.to_string()],
        };
        dlp_store.insert(decision).unwrap();

        let record = output_record(dlp_digest);
        let record_digest = compute_experience_record_digest(&record);
        sep_log
            .append_event(
                "sess-o-c1-ok".to_string(),
                SepEventType::EvOutput,
                record_digest,
                Vec::new(),
            )
            .unwrap();

        let records = vec![record];
        let replay_plans = ReplayPlanStore::default();
        let (asset_manifest_store, asset_bundle_store) = empty_asset_stores();
        let mut checker = CompletenessChecker::new(
            &graph,
            &mut sep_log,
            &dlp_store,
            &replay_plans,
            &asset_manifest_store,
            &asset_bundle_store,
            &records,
        );
        let report = checker.check_actions("sess-o-c1-ok", vec![]);

        assert_eq!(report.status, CompletenessStatus::Ok);
        assert!(report.missing_nodes.is_empty());
        assert!(!report
            .reason_codes
            .contains(&RC_RE_DLP_DECISION_MISSING.to_string()));
    }

    #[test]
    fn completeness_degrades_when_dlp_decision_missing() {
        let graph = CausalGraph::default();
        let mut sep_log = SepLog::default();
        let dlp_digest = [43u8; 32];

        let record = output_record(dlp_digest);
        let record_digest = compute_experience_record_digest(&record);
        sep_log
            .append_event(
                "sess-o-c1-missing".to_string(),
                SepEventType::EvOutput,
                record_digest,
                Vec::new(),
            )
            .unwrap();

        let dlp_store = DlpDecisionStore::default();
        let records = vec![record];
        let replay_plans = ReplayPlanStore::default();
        let (asset_manifest_store, asset_bundle_store) = empty_asset_stores();
        let mut checker = CompletenessChecker::new(
            &graph,
            &mut sep_log,
            &dlp_store,
            &replay_plans,
            &asset_manifest_store,
            &asset_bundle_store,
            &records,
        );
        let report = checker.check_actions("sess-o-c1-missing", vec![]);

        assert_eq!(report.status, CompletenessStatus::Degraded);
        assert!(report.missing_nodes.contains(&dlp_digest));
        assert!(report
            .reason_codes
            .contains(&ReasonCodes::RE_INTEGRITY_DEGRADED.to_string()));
        assert!(report
            .reason_codes
            .contains(&RC_RE_DLP_DECISION_MISSING.to_string()));

        let has_sep_event = sep_log.events.iter().any(|event| {
            event.session_id == "sess-o-c1-missing"
                && event.event_type == SepEventType::EvDlpDecision
                && event.object_digest == dlp_digest
                && event
                    .reason_codes
                    .contains(&RC_RE_DLP_DECISION_MISSING.to_string())
        });
        assert!(has_sep_event);
    }

    #[test]
    fn completeness_output_is_deterministic() {
        let mut graph = CausalGraph::default();
        let mut sep_log = SepLog::default();
        let action = [1u8; 32];
        let receipt = [2u8; 32];

        graph.add_edge(action, EdgeType::Authorizes, receipt, None);
        graph.add_edge([3u8; 32], EdgeType::References, receipt, None);

        sep_log
            .append_event(
                "sess-deterministic".to_string(),
                SepEventType::EvDecision,
                receipt,
                vec![],
            )
            .unwrap();

        let dlp_store = DlpDecisionStore::default();
        let replay_plans = ReplayPlanStore::default();
        let records = Vec::new();
        let (asset_manifest_store, asset_bundle_store) = empty_asset_stores();
        let mut checker = CompletenessChecker::new(
            &graph,
            &mut sep_log,
            &dlp_store,
            &replay_plans,
            &asset_manifest_store,
            &asset_bundle_store,
            &records,
        );
        let report_one = checker.check_actions("sess-deterministic", vec![action]);
        let report_two = checker.check_actions("sess-deterministic", vec![action]);

        assert_eq!(report_one.missing_edges, report_two.missing_edges);
        assert_eq!(report_one.missing_nodes, report_two.missing_nodes);
        assert_eq!(report_one.reason_codes, report_two.reason_codes);
        assert_eq!(report_one.status, report_two.status);
    }

    #[test]
    fn completeness_degrades_without_control_frame() {
        let mut graph = CausalGraph::default();
        let mut sep_log = SepLog::default();
        let action = [10u8; 32];
        let receipt = [11u8; 32];
        let decision = [12u8; 32];
        let profile = [13u8; 32];

        graph.add_edge(action, EdgeType::Authorizes, receipt, None);
        graph.add_edge(decision, EdgeType::Authorizes, receipt, None);
        graph.add_edge(profile, EdgeType::References, receipt, None);
        graph.add_edge([14u8; 32], EdgeType::References, action, None);
        graph.add_edge([14u8; 32], EdgeType::References, receipt, None);

        sep_log
            .append_event(
                "sess-cf".to_string(),
                SepEventType::EvDecision,
                receipt,
                vec![],
            )
            .unwrap();

        let dlp_store = DlpDecisionStore::default();
        let replay_plans = ReplayPlanStore::default();
        let records = Vec::new();
        let (asset_manifest_store, asset_bundle_store) = empty_asset_stores();
        let mut checker = CompletenessChecker::new(
            &graph,
            &mut sep_log,
            &dlp_store,
            &replay_plans,
            &asset_manifest_store,
            &asset_bundle_store,
            &records,
        );
        let report = checker.check_actions("sess-cf", vec![action]);

        assert_eq!(report.status, CompletenessStatus::Degraded);
        assert!(report.missing_nodes.iter().any(|digest| digest == &profile));
    }

    #[test]
    fn completeness_accepts_present_replay_plan() {
        let graph = CausalGraph::default();
        let mut sep_log = SepLog::default();
        let plan = build_replay_plan(BuildReplayPlanArgs {
            session_id: "sess-replay-present".to_string(),
            head_experience_id: 1,
            head_record_digest: [1u8; 32],
            target_kind: ReplayTargetKind::Macro,
            target_refs: vec![Ref {
                id: "target".to_string(),
                digest: None,
            }],
            fidelity: ReplayFidelity::Low,
            counter: 1,
            trigger_reason_codes: Vec::new(),
            asset_manifest_ref: None,
        });

        let mut replay_plans = ReplayPlanStore::default();
        replay_plans.push(plan.clone()).unwrap();
        let plan_digest = digest_from_bytes(&plan.replay_digest).unwrap();

        let record = replay_record(
            vec![Ref {
                id: format!("replay_plan:{}", hex::encode(plan_digest)),
                digest: None,
            }],
            None,
        );
        let record_digest = compute_experience_record_digest(&record);
        sep_log
            .append_event(
                "sess-replay-present".to_string(),
                SepEventType::EvAgentStep,
                record_digest,
                Vec::new(),
            )
            .unwrap();

        let dlp_store = DlpDecisionStore::default();
        let records = vec![record];
        let (asset_manifest_store, asset_bundle_store) = empty_asset_stores();
        let mut checker = CompletenessChecker::new(
            &graph,
            &mut sep_log,
            &dlp_store,
            &replay_plans,
            &asset_manifest_store,
            &asset_bundle_store,
            &records,
        );
        let report = checker.check_actions("sess-replay-present", vec![]);

        assert_eq!(report.status, CompletenessStatus::Ok);
        assert!(report.missing_nodes.is_empty());
        assert!(!report
            .reason_codes
            .contains(&RC_RE_REPLAY_PLAN_MISSING.to_string()));
    }

    #[test]
    fn completeness_degrades_when_replay_plan_missing() {
        let graph = CausalGraph::default();
        let mut sep_log = SepLog::default();
        let plan_digest = [9u8; 32];
        let record = replay_record(
            vec![Ref {
                id: format!("replay_plan:{}", hex::encode(plan_digest)),
                digest: None,
            }],
            None,
        );
        let record_digest = compute_experience_record_digest(&record);
        sep_log
            .append_event(
                "sess-replay-missing-plan".to_string(),
                SepEventType::EvAgentStep,
                record_digest,
                Vec::new(),
            )
            .unwrap();

        let dlp_store = DlpDecisionStore::default();
        let replay_plans = ReplayPlanStore::default();
        let records = vec![record];
        let (asset_manifest_store, asset_bundle_store) = empty_asset_stores();
        let mut checker = CompletenessChecker::new(
            &graph,
            &mut sep_log,
            &dlp_store,
            &replay_plans,
            &asset_manifest_store,
            &asset_bundle_store,
            &records,
        );
        let report = checker.check_actions("sess-replay-missing-plan", vec![]);

        assert_eq!(report.status, CompletenessStatus::Degraded);
        assert!(report.missing_nodes.contains(&plan_digest));
        assert!(report
            .reason_codes
            .contains(&ReasonCodes::RE_INTEGRITY_DEGRADED.to_string()));
        assert!(report
            .reason_codes
            .contains(&RC_RE_REPLAY_PLAN_MISSING.to_string()));

        let has_sep_event = sep_log.events.iter().any(|event| {
            event.session_id == "sess-replay-missing-plan"
                && event.event_type == SepEventType::EvReplay
                && event.object_digest == plan_digest
                && event
                    .reason_codes
                    .contains(&RC_RE_REPLAY_PLAN_MISSING.to_string())
        });
        assert!(has_sep_event);
    }

    #[test]
    fn completeness_fails_when_replay_asset_manifest_missing() {
        let graph = CausalGraph::default();
        let mut sep_log = SepLog::default();
        let missing_digest = [0x44u8; 32];
        let plan = build_replay_plan(BuildReplayPlanArgs {
            session_id: "sess-replay-asset-missing".to_string(),
            head_experience_id: 1,
            head_record_digest: [1u8; 32],
            target_kind: ReplayTargetKind::Macro,
            target_refs: vec![Ref {
                id: "target".to_string(),
                digest: None,
            }],
            fidelity: ReplayFidelity::Low,
            counter: 1,
            trigger_reason_codes: Vec::new(),
            asset_manifest_ref: Some(Ref {
                id: "asset_manifest".to_string(),
                digest: Some(missing_digest.to_vec()),
            }),
        });

        let mut replay_plans = ReplayPlanStore::default();
        replay_plans.push(plan.clone()).unwrap();
        let plan_digest = digest_from_bytes(&plan.replay_digest).unwrap();

        let record = replay_record(
            vec![Ref {
                id: format!("replay_plan:{}", hex::encode(plan_digest)),
                digest: None,
            }],
            None,
        );
        let record_digest = compute_experience_record_digest(&record);
        sep_log
            .append_event(
                "sess-replay-asset-missing".to_string(),
                SepEventType::EvAgentStep,
                record_digest,
                Vec::new(),
            )
            .unwrap();

        let dlp_store = DlpDecisionStore::default();
        let records = vec![record];
        let (asset_manifest_store, asset_bundle_store) = empty_asset_stores();
        let mut checker = CompletenessChecker::new(
            &graph,
            &mut sep_log,
            &dlp_store,
            &replay_plans,
            &asset_manifest_store,
            &asset_bundle_store,
            &records,
        );
        let report = checker.check_actions("sess-replay-asset-missing", vec![]);

        assert_eq!(report.status, CompletenessStatus::Fail);
        assert!(report
            .reason_codes
            .contains(&ReasonCodes::RE_REPLAY_MISMATCH.to_string()));
        assert!(report
            .reason_codes
            .contains(&ReasonCodes::RE_REPLAY_ASSET_MISSING.to_string()));

        let has_sep_event = sep_log.events.iter().any(|event| {
            event.session_id == "sess-replay-asset-missing"
                && event.event_type == SepEventType::EvReplay
                && event.object_digest == plan_digest
                && event
                    .reason_codes
                    .contains(&ReasonCodes::RE_REPLAY_ASSET_MISSING.to_string())
        });
        assert!(has_sep_event);
    }

    #[test]
    fn completeness_degrades_when_replay_asset_bundle_missing() {
        let graph = CausalGraph::default();
        let mut sep_log = SepLog::default();
        let (manifest, digest) = asset_manifest_payload(21, 4);
        let plan = build_replay_plan(BuildReplayPlanArgs {
            session_id: "sess-replay-bundle-missing".to_string(),
            head_experience_id: 1,
            head_record_digest: [1u8; 32],
            target_kind: ReplayTargetKind::Macro,
            target_refs: vec![Ref {
                id: "target".to_string(),
                digest: None,
            }],
            fidelity: ReplayFidelity::Low,
            counter: 1,
            trigger_reason_codes: Vec::new(),
            asset_manifest_ref: Some(Ref {
                id: "asset_manifest".to_string(),
                digest: Some(digest.to_vec()),
            }),
        });

        let mut replay_plans = ReplayPlanStore::default();
        replay_plans.push(plan.clone()).unwrap();
        let plan_digest = digest_from_bytes(&plan.replay_digest).unwrap();

        let record = replay_record(
            vec![Ref {
                id: format!("replay_plan:{}", hex::encode(plan_digest)),
                digest: None,
            }],
            None,
        );
        let record_digest = compute_experience_record_digest(&record);
        sep_log
            .append_event(
                "sess-replay-bundle-missing".to_string(),
                SepEventType::EvAgentStep,
                record_digest,
                Vec::new(),
            )
            .unwrap();

        let dlp_store = DlpDecisionStore::default();
        let records = vec![record];
        let mut asset_manifest_store = AssetManifestStore::default();
        asset_manifest_store.insert(manifest).unwrap();
        let (_, asset_bundle_store) = empty_asset_stores();
        let mut checker = CompletenessChecker::new(
            &graph,
            &mut sep_log,
            &dlp_store,
            &replay_plans,
            &asset_manifest_store,
            &asset_bundle_store,
            &records,
        );
        let report = checker.check_actions("sess-replay-bundle-missing", vec![]);

        assert_eq!(report.status, CompletenessStatus::Degraded);
        assert!(report
            .reason_codes
            .contains(&ReasonCodes::RE_REPLAY_ASSET_BUNDLE_MISSING.to_string()));
    }

    #[test]
    fn completeness_degrades_when_replay_plan_ref_missing() {
        let graph = CausalGraph::default();
        let mut sep_log = SepLog::default();
        let record = replay_record(Vec::new(), None);
        let record_digest = compute_experience_record_digest(&record);
        sep_log
            .append_event(
                "sess-replay-missing-ref".to_string(),
                SepEventType::EvAgentStep,
                record_digest,
                Vec::new(),
            )
            .unwrap();

        let dlp_store = DlpDecisionStore::default();
        let replay_plans = ReplayPlanStore::default();
        let records = vec![record];
        let (asset_manifest_store, asset_bundle_store) = empty_asset_stores();
        let mut checker = CompletenessChecker::new(
            &graph,
            &mut sep_log,
            &dlp_store,
            &replay_plans,
            &asset_manifest_store,
            &asset_bundle_store,
            &records,
        );
        let report = checker.check_actions("sess-replay-missing-ref", vec![]);

        assert_eq!(report.status, CompletenessStatus::Degraded);
        assert!(report
            .reason_codes
            .contains(&ReasonCodes::RE_INTEGRITY_DEGRADED.to_string()));
        assert!(report
            .reason_codes
            .contains(&RC_RE_REPLAY_PLAN_REF_MISSING.to_string()));
    }

    #[test]
    fn completeness_fails_on_embedded_action_refs_in_replay_record() {
        let graph = CausalGraph::default();
        let mut sep_log = SepLog::default();
        let plan = build_replay_plan(BuildReplayPlanArgs {
            session_id: "sess-replay-invalid-action".to_string(),
            head_experience_id: 1,
            head_record_digest: [1u8; 32],
            target_kind: ReplayTargetKind::Macro,
            target_refs: vec![Ref {
                id: "target".to_string(),
                digest: None,
            }],
            fidelity: ReplayFidelity::Low,
            counter: 1,
            trigger_reason_codes: Vec::new(),
            asset_manifest_ref: None,
        });

        let mut replay_plans = ReplayPlanStore::default();
        replay_plans.push(plan.clone()).unwrap();
        let plan_digest = digest_from_bytes(&plan.replay_digest).unwrap();

        let record = replay_record(
            vec![
                Ref {
                    id: format!("replay_plan:{}", hex::encode(plan_digest)),
                    digest: None,
                },
                Ref {
                    id: format!("action:{}", hex::encode([2u8; 32])),
                    digest: None,
                },
            ],
            None,
        );
        let record_digest = compute_experience_record_digest(&record);
        sep_log
            .append_event(
                "sess-replay-invalid-action".to_string(),
                SepEventType::EvAgentStep,
                record_digest,
                Vec::new(),
            )
            .unwrap();

        let dlp_store = DlpDecisionStore::default();
        let records = vec![record];
        let (asset_manifest_store, asset_bundle_store) = empty_asset_stores();
        let mut checker = CompletenessChecker::new(
            &graph,
            &mut sep_log,
            &dlp_store,
            &replay_plans,
            &asset_manifest_store,
            &asset_bundle_store,
            &records,
        );
        let report = checker.check_actions("sess-replay-invalid-action", vec![]);

        assert_eq!(report.status, CompletenessStatus::Fail);
        assert!(report
            .reason_codes
            .contains(&RC_RE_REPLAY_INVALID_EMBEDDED_ACTION.to_string()));
        assert!(report
            .reason_codes
            .contains(&ReasonCodes::RE_INTEGRITY_FAIL.to_string()));

        let has_sep_event = sep_log.events.iter().any(|event| {
            event.session_id == "sess-replay-invalid-action"
                && event.event_type == SepEventType::EvReplay
                && event.object_digest == record_digest
                && event
                    .reason_codes
                    .contains(&RC_RE_REPLAY_INVALID_EMBEDDED_ACTION.to_string())
        });
        assert!(has_sep_event);
    }

    #[test]
    fn cbv_commit_is_deterministic() {
        let prev = [2u8; 32];
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);
        let updates = vec![cbv_update(
            "baseline_caution",
            TraitDirection::IncreaseStrictness,
            MagnitudeClass::Med,
        )];

        let macro_one = macro_with_updates("macro-one", updates.clone());
        let macro_two = macro_one.clone();

        let mut store_a = base_store(prev);
        let mut store_b = base_store(prev);

        let outcome_a = store_a
            .commit_cbv_from_macro(
                &macro_one,
                &keystore,
                &vrf_engine,
                "charter",
                "policy",
                None,
                CbvDeriverConfig::default(),
            )
            .expect("cbv commit a");
        let outcome_b = store_b
            .commit_cbv_from_macro(
                &macro_two,
                &keystore,
                &vrf_engine,
                "charter",
                "policy",
                None,
                CbvDeriverConfig::default(),
            )
            .expect("cbv commit b");

        assert_eq!(outcome_a.cbv.cbv_digest, outcome_b.cbv.cbv_digest);
    }

    #[test]
    fn cbv_epoch_is_monotonic_and_queryable() {
        let prev = [3u8; 32];
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);
        let mut store = base_store(prev);

        let first_macro = macro_with_updates(
            "macro-1",
            vec![cbv_update(
                "baseline_caution",
                TraitDirection::IncreaseStrictness,
                MagnitudeClass::Low,
            )],
        );
        let second_macro = macro_with_updates(
            "macro-2",
            vec![cbv_update(
                "baseline_export_strictness",
                TraitDirection::IncreaseStrictness,
                MagnitudeClass::High,
            )],
        );

        let first = store
            .commit_cbv_from_macro(
                &first_macro,
                &keystore,
                &vrf_engine,
                "charter",
                "policy",
                None,
                CbvDeriverConfig::default(),
            )
            .expect("first cbv commit");
        let second = store
            .commit_cbv_from_macro(
                &second_macro,
                &keystore,
                &vrf_engine,
                "charter",
                "policy",
                None,
                CbvDeriverConfig::default(),
            )
            .expect("second cbv commit");

        assert_eq!(first.cbv.cbv_epoch, 1);
        assert_eq!(second.cbv.cbv_epoch, 2);
        let latest = store.get_latest_cbv().expect("missing latest cbv");
        assert_eq!(latest.cbv_epoch, 2);
    }

    #[test]
    fn cbv_commit_logs_sep_event() {
        let prev = [4u8; 32];
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);
        let mut store = base_store(prev);
        let macro_one = macro_with_updates(
            "macro-log",
            vec![cbv_update(
                "chain_conservatism",
                TraitDirection::IncreaseStrictness,
                MagnitudeClass::Med,
            )],
        );

        let outcome = store
            .commit_cbv_from_macro(
                &macro_one,
                &keystore,
                &vrf_engine,
                "charter",
                "policy",
                None,
                CbvDeriverConfig::default(),
            )
            .expect("cbv commit");

        let last_event = store.sep_log.events.last().expect("missing event");
        let cbv_digest = outcome
            .cbv
            .cbv_digest
            .as_ref()
            .and_then(|d| digest_from_bytes(d))
            .expect("cbv digest missing");
        assert_eq!(last_event.object_digest, cbv_digest);
        assert!(last_event
            .reason_codes
            .contains(&ReasonCodes::GV_CBV_UPDATED.to_string()));
    }

    #[test]
    fn cbv_commit_notes_no_change_when_only_decreases() {
        let prev = [5u8; 32];
        let keystore = KeyStore::new_dev_keystore(1);
        let vrf_engine = VrfEngine::new_dev(1);
        let mut store = base_store(prev);
        let macro_one = macro_with_updates(
            "macro-no-change",
            vec![cbv_update(
                "baseline_caution",
                TraitDirection::DecreaseStrictness,
                MagnitudeClass::High,
            )],
        );

        let outcome = store
            .commit_cbv_from_macro(
                &macro_one,
                &keystore,
                &vrf_engine,
                "charter",
                "policy",
                None,
                CbvDeriverConfig::default(),
            )
            .expect("cbv commit");

        assert!(!outcome.applied_updates);
        let last_event = store.sep_log.events.last().expect("missing event");
        assert!(last_event
            .reason_codes
            .contains(&ReasonCodes::GV_CBV_NO_CHANGE.to_string()));
    }

    fn decision_record(idx: usize) -> ExperienceRecord {
        ExperienceRecord {
            record_type: RecordType::RtDecision as i32,
            core_frame: None,
            metabolic_frame: None,
            governance_frame: Some(GovernanceFrame {
                policy_decision_refs: vec![Ref {
                    id: format!("decision-ref-{idx}"),
                    digest: None,
                }],
                pvgs_receipt_ref: None,
                dlp_refs: Vec::new(),
            }),
            core_frame_ref: Some(Ref {
                id: format!("core-{idx}"),
                digest: None,
            }),
            metabolic_frame_ref: None,
            governance_frame_ref: Some(Ref {
                id: format!("gov-{idx}"),
                digest: None,
            }),
            dlp_refs: Vec::new(),
            finalization_header: None,
        }
    }

    fn simple_macro(id: &str, digest: [u8; 32]) -> MacroMilestone {
        MacroMilestone {
            macro_id: id.to_string(),
            macro_digest: digest.to_vec(),
            state: MacroMilestoneState::Finalized as i32,
            trait_updates: Vec::new(),
            meso_refs: Vec::new(),
            consistency_class: "CONSISTENCY_HIGH".to_string(),
            identity_anchor_flag: false,
            proof_receipt_ref: Some(Ref::default()),
            consistency_digest: None,
            consistency_feedback_ref: Some(Ref::default()),
        }
    }

    fn install_macro_target(store: &mut PvgsStore, id: &str, digest: [u8; 32]) {
        let finalized_macro = simple_macro(id, digest);
        let proposal = macro_proposal_from(&finalized_macro);
        let feedback = ConsistencyFeedback {
            cf_digest: Some([0xBBu8; 32].to_vec()),
            consistency_class: "CONSISTENCY_HIGH".to_string(),
            flags: Vec::new(),
            proof_receipt_ref: None,
        };

        store
            .macro_milestones
            .insert_proposal(proposal)
            .expect("proposal stored");
        store
            .macro_milestones
            .finalize(finalized_macro, &feedback)
            .expect("finalized macro stored");
    }

    #[test]
    fn trigger_appends_replay_plan_and_sep_event() {
        let prev = [7u8; 32];
        let keystore = KeyStore::new_dev_keystore(1);
        let mut store = base_store(prev);

        let finalized_macro = simple_macro("macro-1", [1u8; 32]);
        let proposal = macro_proposal_from(&finalized_macro);
        let feedback = ConsistencyFeedback {
            cf_digest: Some([0xAAu8; 32].to_vec()),
            consistency_class: "CONSISTENCY_HIGH".to_string(),
            flags: Vec::new(),
            proof_receipt_ref: None,
        };
        store
            .macro_milestones
            .insert_proposal(proposal)
            .expect("proposal stored");
        store
            .macro_milestones
            .finalize(finalized_macro, &feedback)
            .expect("finalized macro stored");

        for idx in 0..20 {
            store.experience_store.records.push(decision_record(idx));
            store.experience_store.head_id += 1;
        }

        let outcome = store
            .maybe_plan_replay("session-a", &keystore)
            .expect("replay plan created")
            .expect("replay plan outcome");

        assert_eq!(store.replay_plans.plans.len(), 1);
        assert_eq!(outcome.plan.replay_id, "replay:session-a:20:1");
        assert_eq!(outcome.plan.target_kind, ReplayTargetKind::Macro as i32);

        let last_event = store.sep_log.events.last().expect("missing sep event");
        assert_eq!(last_event.event_type, SepEventType::EvReplay);
        assert!(last_event
            .reason_codes
            .contains(&ReasonCodes::GV_REPLAY_PLANNED.to_string()));

        let duplicate = store.maybe_plan_replay("session-a", &keystore);
        assert!(duplicate.expect("duplicate planning result").is_none());
        assert_eq!(store.replay_plans.plans.len(), 1);
    }

    #[test]
    fn selects_micro_targets_deterministically() {
        let prev = [8u8; 32];
        let keystore = KeyStore::new_dev_keystore(1);
        let mut store = base_store(prev);

        let base_record = decision_record(1);
        let digest = compute_experience_record_digest(&base_record);
        let records = vec![(1, digest, base_record.clone()), (2, digest, base_record)];

        let micro_one = derive_micro_from_experience_window("session-b", 1, 1, prev, &records)
            .expect("micro one");
        let micro_two = derive_micro_from_experience_window("session-b", 2, 2, prev, &records)
            .expect("micro two");

        store.micro_milestones.push(micro_one).unwrap();
        store.micro_milestones.push(micro_two).unwrap();

        for idx in 0..20 {
            store.experience_store.records.push(decision_record(idx));
        }

        let outcome = store
            .maybe_plan_replay("session-b", &keystore)
            .expect("replay plan created")
            .expect("replay plan outcome");

        assert_eq!(outcome.plan.target_kind, ReplayTargetKind::Micro as i32);
        assert_eq!(outcome.plan.target_refs.len(), 2);
        let ids: Vec<_> = outcome
            .plan
            .target_refs
            .iter()
            .map(|r| r.id.clone())
            .collect();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted);
    }

    #[test]
    fn consistency_low_triggers_replay_plan() {
        let prev = [5u8; 32];
        let keystore = KeyStore::new_dev_keystore(1);
        let mut store = base_store(prev);

        install_macro_target(&mut store, "macro-low", [3u8; 32]);

        track_consistency_feedback(&mut store, "session-low", [0xA1u8; 32], "CONSISTENCY_LOW");

        let outcome = store
            .maybe_plan_replay("session-low", &keystore)
            .expect("replay plan created")
            .expect("replay plan outcome");

        assert_eq!(
            outcome.plan.trigger_reason_codes,
            vec![
                ReasonCodes::GV_ASSET_MISSING.to_string(),
                ReasonCodes::GV_CONSISTENCY_LOW.to_string(),
            ]
        );
        assert_eq!(outcome.plan.target_kind, ReplayTargetKind::Macro as i32);
    }

    #[test]
    fn replay_plan_binds_latest_asset_manifest() {
        let prev = [12u8; 32];
        let keystore = KeyStore::new_dev_keystore(1);
        let mut store = base_store(prev);

        install_macro_target(&mut store, "macro-assets", [3u8; 32]);

        let (manifest_one, _) = asset_manifest_payload(10, 1);
        store
            .asset_manifest_store
            .insert(manifest_one)
            .expect("manifest one stored");
        let (manifest_two, digest_two) = asset_manifest_payload(11, 2);
        store
            .asset_manifest_store
            .insert(manifest_two)
            .expect("manifest two stored");

        track_consistency_feedback(
            &mut store,
            "session-assets",
            [0xA3u8; 32],
            "CONSISTENCY_LOW",
        );

        let outcome = store
            .maybe_plan_replay("session-assets", &keystore)
            .expect("replay plan created")
            .expect("replay plan outcome");

        let asset_ref = outcome
            .plan
            .asset_manifest_ref
            .as_ref()
            .expect("asset manifest ref");
        assert_eq!(asset_ref.id, "asset_manifest");
        assert_eq!(asset_ref.digest.as_deref(), Some(digest_two.as_slice()));
    }

    #[test]
    fn consistency_med_cluster_triggers_replay_plan() {
        let prev = [6u8; 32];
        let keystore = KeyStore::new_dev_keystore(1);
        let mut store = base_store(prev);

        install_macro_target(&mut store, "macro-med", [4u8; 32]);

        for idx in 0..3 {
            let mut digest = [0u8; 32];
            digest[0] = idx as u8 + 1;
            track_consistency_feedback(&mut store, "session-med", digest, "CONSISTENCY_MED");
        }

        let outcome = store
            .maybe_plan_replay("session-med", &keystore)
            .expect("replay plan created")
            .expect("replay plan outcome");

        assert_eq!(
            outcome.plan.trigger_reason_codes,
            vec![
                ReasonCodes::GV_ASSET_MISSING.to_string(),
                ReasonCodes::GV_CONSISTENCY_MED_CLUSTER.to_string(),
            ]
        );
    }

    #[test]
    fn consistency_high_does_not_trigger_replay() {
        let prev = [9u8; 32];
        let keystore = KeyStore::new_dev_keystore(1);
        let mut store = base_store(prev);

        install_macro_target(&mut store, "macro-high", [5u8; 32]);

        track_consistency_feedback(&mut store, "session-high", [0xC1u8; 32], "CONSISTENCY_HIGH");

        assert!(store
            .maybe_plan_replay("session-high", &keystore)
            .expect("replay planning result")
            .is_none());
    }

    #[test]
    fn consistency_triggers_prefer_macro_targets() {
        let prev = [11u8; 32];
        let keystore = KeyStore::new_dev_keystore(1);
        let mut store = base_store(prev);

        install_macro_target(&mut store, "macro-pref", [0x21u8; 32]);
        store.micro_milestones.push(sample_micro(1)).unwrap();
        store.micro_milestones.push(sample_micro(2)).unwrap();

        track_consistency_feedback(&mut store, "session-pref", [0xD1u8; 32], "CONSISTENCY_LOW");

        let outcome = store
            .maybe_plan_replay("session-pref", &keystore)
            .expect("replay plan created")
            .expect("replay plan outcome");

        assert_eq!(outcome.plan.target_kind, ReplayTargetKind::Macro as i32);
        assert_eq!(outcome.plan.target_refs.len(), 1);
        assert_eq!(
            digest_from_ref(outcome.plan.target_refs.first().expect("target")),
            Some([0x21u8; 32])
        );
    }
}
