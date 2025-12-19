#![forbid(unsafe_code)]

use blake3::Hasher;
use cbv::{
    cbv_attestation_preimage, compute_cbv_verified_fields_digest, derive_next_cbv,
    CbvDeriverConfig, CbvStore,
};
use ed25519_dalek::Signer;
use keys::{verify_key_epoch_signature, KeyEpochHistory, KeyStore};
use pev::{pev_digest as extract_pev_digest, PevStore, PolicyEcologyVector};
use prost::Message;
use receipts::{issue_proof_receipt, issue_receipt, ReceiptInput};
use sep::{CausalGraph, EdgeType, FrameEventKind, NodeKey, SepEventType, SepLog};
use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tool_registry_state::{ToolRegistryError, ToolRegistryState};
use ucf_protocol::ucf::v1::{
    self as protocol, CharacterBaselineVector, Digest32, ExperienceRecord, FinalizationHeader,
    MacroMilestone, MacroMilestoneState, PVGSKeyEpoch, PVGSReceipt, ProofReceipt, ReceiptStatus,
    RecordType, Ref, ToolRegistryContainer,
};
use vrf::VrfEngine;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Commit type supported by PVGS.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitType {
    ReceiptRequest,
    RecordAppend,
    ExperienceRecordAppend,
    MilestoneAppend,
    CharterUpdate,
    ToolRegistryUpdate,
    RecoveryUpdate,
    PevUpdate,
    CbvUpdate,
    KeyEpochUpdate,
    FrameEvidenceAppend,
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

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CbvCommitError {
    #[error("macro milestone not finalized")]
    MacroNotFinalized,
    #[error("cbv epoch is not monotonic")]
    NonMonotonicEpoch,
    #[error("cbv derivation failed: {0}")]
    Derivation(String),
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
    pub tool_registry_container: Option<Vec<u8>>,
    pub pev: Option<PolicyEcologyVector>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CbvCommitOutcome {
    pub cbv: CharacterBaselineVector,
    pub receipt: PVGSReceipt,
    pub proof_receipt: ProofReceipt,
    pub applied_updates: bool,
}

/// In-memory store tracking experience records and proof receipts.
#[derive(Debug, Clone, Default)]
pub struct ExperienceStore {
    pub records: Vec<ExperienceRecord>,
    pub head_record_digest: [u8; 32],
    pub head_id: u64,
    pub proof_receipts: HashMap<[u8; 32], ProofReceipt>,
}

/// In-memory store tracking PVGS state and SEP event log.
#[derive(Debug, Clone)]
pub struct PvgsStore {
    pub current_head_record_digest: [u8; 32],
    pub experience_store: ExperienceStore,
    pub receipts: HashMap<[u8; 32], PVGSReceipt>,
    pub known_charter_versions: HashSet<String>,
    pub known_policy_versions: HashSet<String>,
    pub known_profiles: HashSet<[u8; 32]>,
    pub key_epoch_history: KeyEpochHistory,
    pub cbv_store: CbvStore,
    pub pev_store: PevStore,
    pub tool_registry_state: ToolRegistryState,
    pub committed_payload_digests: HashSet<[u8; 32]>,
    pub sep_log: SepLog,
    pub causal_graph: CausalGraph,
    pub receipt_gate_enabled: bool,
    pub ruleset_state: RulesetState,
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
        let experience_store = ExperienceStore {
            head_record_digest: current_head_record_digest,
            ..Default::default()
        };
        Self {
            current_head_record_digest,
            experience_store,
            receipts: HashMap::new(),
            known_charter_versions,
            known_policy_versions,
            known_profiles,
            key_epoch_history: KeyEpochHistory::default(),
            cbv_store: CbvStore::default(),
            pev_store: PevStore::default(),
            tool_registry_state: ToolRegistryState::default(),
            committed_payload_digests: HashSet::new(),
            sep_log: SepLog::default(),
            causal_graph: CausalGraph::default(),
            receipt_gate_enabled: false,
            ruleset_state: RulesetState::new(charter_version_digest, policy_version_digest),
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

    fn log_ruleset_change(
        &mut self,
        session_id: &str,
        event_type: SepEventType,
        mut reason_codes: Vec<String>,
    ) {
        reason_codes.push(protocol::ReasonCodes::GV_RULESET_CHANGED.to_string());
        self.sep_log.append_event(
            session_id.to_string(),
            event_type,
            self.ruleset_state.ruleset_digest,
            reason_codes,
        );
    }

    fn add_receipt_edges(&mut self, receipt: &PVGSReceipt) {
        let receipt_digest = receipt.receipt_digest.0;
        self.receipts.insert(receipt_digest, receipt.clone());

        if !matches!(receipt.status, ReceiptStatus::Accepted) {
            return;
        }
        if let Some(decision) = optional_proto_digest(&receipt.bindings.decision_digest) {
            self.causal_graph
                .add_edge(decision, EdgeType::Authorizes, receipt_digest);
        }

        if let Some(action) = optional_proto_digest(&receipt.bindings.action_digest) {
            self.causal_graph
                .add_edge(action, EdgeType::Authorizes, receipt_digest);
        }

        if let Some(profile) = optional_proto_digest(&receipt.bindings.profile_digest) {
            self.causal_graph
                .add_edge(profile, EdgeType::References, receipt_digest);
        }

        if let Some(tool_profile) = optional_proto_digest(&receipt.bindings.tool_profile_digest) {
            self.causal_graph
                .add_edge(tool_profile, EdgeType::References, receipt_digest);
        }
    }

    fn add_record_edges(
        &mut self,
        record_digest: [u8; 32],
        prev_record_digest: [u8; 32],
        record: &ExperienceRecord,
    ) {
        if prev_record_digest != [0u8; 32] {
            self.causal_graph
                .add_edge(prev_record_digest, EdgeType::Causes, record_digest);
        }

        self.add_frame_reference_edges(record_digest, record);

        match RecordType::try_from(record.record_type).unwrap_or(RecordType::Unspecified) {
            RecordType::RtActionExec => self.add_action_exec_edges(record_digest, record),
            RecordType::RtOutput => self.add_output_edges(record_digest, record),
            RecordType::RtDecision => {}
            _ => {}
        }
    }

    fn add_frame_reference_edges(&mut self, record_digest: NodeKey, record: &ExperienceRecord) {
        if let Some(core_ref) = &record.core_frame_ref {
            self.add_reference_edges_from_refs(record_digest, std::slice::from_ref(core_ref));
        }

        if let Some(meta_ref) = &record.metabolic_frame_ref {
            self.add_reference_edges_from_refs(record_digest, std::slice::from_ref(meta_ref));
        }

        if let Some(gov_ref) = &record.governance_frame_ref {
            self.add_reference_edges_from_refs(record_digest, std::slice::from_ref(gov_ref));
        }
    }

    fn add_action_exec_edges(&mut self, record_digest: NodeKey, record: &ExperienceRecord) {
        if let Some(core) = &record.core_frame {
            self.add_reference_edges_from_refs(record_digest, &core.evidence_refs);
        }

        if let Some(gov) = &record.governance_frame {
            self.add_reference_edges_from_refs(record_digest, &gov.policy_decision_refs);

            if let Some(receipt_ref) = &gov.pvgs_receipt_ref {
                self.add_reference_edges_from_refs(
                    record_digest,
                    std::slice::from_ref(receipt_ref),
                );
            }
        }

        if let Some(core_ref) = &record.core_frame_ref {
            self.add_reference_edges_from_refs(record_digest, std::slice::from_ref(core_ref));
        }
    }

    fn add_output_edges(&mut self, record_digest: NodeKey, record: &ExperienceRecord) {
        if !record.dlp_refs.is_empty() {
            self.add_reference_edges_from_refs(record_digest, &record.dlp_refs);
        }

        if let Some(gov) = &record.governance_frame {
            if !gov.dlp_refs.is_empty() {
                self.add_reference_edges_from_refs(record_digest, &gov.dlp_refs);
            }
        }
    }

    fn add_reference_edges_from_refs(&mut self, from: NodeKey, refs: &[Ref]) {
        for reference in refs {
            if let Some(target) = digest_from_ref(reference) {
                self.causal_graph
                    .add_edge(from, EdgeType::References, target);
            }
        }
    }

    pub fn append_record(
        &mut self,
        record: ExperienceRecord,
        record_digest: [u8; 32],
        proof_receipt: ProofReceipt,
    ) {
        self.current_head_record_digest = record_digest;
        self.experience_store
            .append(record, record_digest, proof_receipt);
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
        });
        cbv.pvgs_attestation_key_id = keystore.current_key_id().to_string();
        let signature = keystore.signing_key().sign(&cbv_attestation_preimage(&cbv));
        cbv.pvgs_attestation_sig = signature.to_bytes().to_vec();

        self.cbv_store.push(cbv.clone());

        let mut reason_codes = vec![protocol::ReasonCodes::GV_CBV_UPDATED.to_string()];
        if !derived.applied_updates {
            reason_codes.push(protocol::ReasonCodes::GV_CBV_NO_CHANGE.to_string());
        }

        self.sep_log.append_event(
            macro_milestone.macro_id.clone(),
            SepEventType::EvRecoveryGov,
            next_cbv_digest,
            reason_codes,
        );

        Ok(CbvCommitOutcome {
            cbv,
            receipt,
            proof_receipt,
            applied_updates: derived.applied_updates,
        })
    }
}

impl ExperienceStore {
    pub fn append(
        &mut self,
        record: ExperienceRecord,
        record_digest: [u8; 32],
        proof_receipt: ProofReceipt,
    ) {
        self.records.push(record);
        self.head_record_digest = record_digest;
        self.head_id = self.head_id.saturating_add(1);
        self.proof_receipts.insert(record_digest, proof_receipt);
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

fn event_type_for_commit(
    commit_type: CommitType,
    frame_kind: Option<FrameEventKind>,
) -> SepEventType {
    match commit_type {
        CommitType::ReceiptRequest => SepEventType::EvDecision,
        CommitType::KeyEpochUpdate => SepEventType::EvKeyEpoch,
        CommitType::PevUpdate => SepEventType::EvPevUpdate,
        CommitType::ToolRegistryUpdate => SepEventType::EvToolOnboarding,
        CommitType::ExperienceRecordAppend => SepEventType::EvIntent,
        CommitType::FrameEvidenceAppend => match frame_kind {
            Some(FrameEventKind::ControlFrame) => SepEventType::EvControlFrame,
            Some(FrameEventKind::SignalFrame) => SepEventType::EvSignalFrame,
            None => SepEventType::EvRecoveryGov,
        },
        _ => SepEventType::EvRecoveryGov,
    }
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

/// Verify a commit request and emit attested receipts.
pub fn verify_and_commit(
    req: PvgsCommitRequest,
    store: &mut PvgsStore,
    keystore: &KeyStore,
    vrf_engine: &VrfEngine,
) -> (PVGSReceipt, Option<ProofReceipt>) {
    if req.commit_type == CommitType::PevUpdate {
        return verify_pev_update(req, store, keystore, vrf_engine);
    }

    if req.commit_type == CommitType::ToolRegistryUpdate {
        return verify_tool_registry_update(req, store, keystore, vrf_engine);
    }

    if req.commit_type == CommitType::ExperienceRecordAppend {
        return verify_experience_record_append(req, store, keystore, vrf_engine);
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
        store.sep_log.append_frame_event(
            req.commit_id.clone(),
            kind,
            event_object_digest,
            receipt.reject_reason_codes.clone(),
        );
    } else {
        store.sep_log.append_event(
            req.commit_id.clone(),
            event_type,
            event_object_digest,
            receipt.reject_reason_codes.clone(),
        );
    }

    (receipt, Some(proof_receipt))
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

    store
        .pev_store
        .push(pev)
        .expect("validated PEV must be insertable");
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
    });
    finalization_header.prev_record_digest = digest_to_vec(store.current_head_record_digest);
    finalization_header.record_digest = digest_to_vec(record_digest);
    record.finalization_header = Some(finalization_header);

    store.add_record_edges(record_digest, req.bindings.prev_record_digest, &record);
    log_experience_events(&req.commit_id, record_digest, &record, store);
    store.append_record(record, record_digest, proof_receipt.clone());

    (receipt, Some(proof_receipt))
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

            if record.dlp_refs.is_empty() {
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
                .map_or(true, |gov| gov.policy_decision_refs.is_empty())
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
    store.sep_log.append_event(
        commit_id.to_string(),
        SepEventType::EvAgentStep,
        record_digest,
        Vec::new(),
    );

    if let Some(gov) = &record.governance_frame {
        if !gov.policy_decision_refs.is_empty() {
            store.sep_log.append_event(
                commit_id.to_string(),
                SepEventType::EvDecision,
                record_digest,
                Vec::new(),
            );
        }

        if !gov.dlp_refs.is_empty() {
            store.sep_log.append_event(
                commit_id.to_string(),
                SepEventType::EvOutcome,
                record_digest,
                Vec::new(),
            );
        }
    }

    if record.metabolic_frame_ref.is_some() {
        store.sep_log.append_event(
            commit_id.to_string(),
            SepEventType::EvProfileChange,
            record_digest,
            Vec::new(),
        );
    }

    if let Some(meta) = &record.metabolic_frame {
        if meta.profile_digest.is_some() {
            store.sep_log.append_event(
                commit_id.to_string(),
                SepEventType::EvProfileChange,
                record_digest,
                Vec::new(),
            );
        }

        if !meta.outcome_refs.is_empty() {
            store.sep_log.append_event(
                commit_id.to_string(),
                SepEventType::EvOutcome,
                record_digest,
                Vec::new(),
            );
        }
    }

    store.sep_log.append_event(
        commit_id.to_string(),
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
    digest_from_hex_str(&reference.id).or_else(|| digest_from_bytes(reference.id.as_bytes()))
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
}

#[derive(Debug)]
pub struct CompletenessChecker<'a> {
    graph: &'a CausalGraph,
    sep_log: &'a SepLog,
}

impl<'a> CompletenessChecker<'a> {
    pub fn new(graph: &'a CausalGraph, sep_log: &'a SepLog) -> Self {
        Self { graph, sep_log }
    }

    /// Evaluate completeness for the provided action digests using graph-based rules.
    pub fn check_actions(
        &self,
        session_id: &str,
        action_digests: Vec<[u8; 32]>,
    ) -> CompletenessReport {
        use std::collections::BTreeSet;

        let mut status = CompletenessStatus::Ok;
        let mut missing_nodes: BTreeSet<[u8; 32]> = BTreeSet::new();
        let mut missing_edges: Vec<String> = Vec::new();
        let mut reason_codes: BTreeSet<String> = BTreeSet::new();

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

        missing_edges.sort();

        CompletenessReport {
            status,
            missing_nodes: missing_nodes.into_iter().collect(),
            missing_edges,
            reason_codes: reason_codes.into_iter().collect(),
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

fn key_epoch_payload_digest(req: &PvgsCommitRequest) -> Option<[u8; 32]> {
    req.payload_digests.first().copied()
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
        store
            .sep_log
            .append_frame_event(req.commit_id.clone(), kind, object_digest, reason_codes);
    } else {
        store.sep_log.append_event(
            req.commit_id.clone(),
            event_type,
            object_digest,
            reason_codes,
        );
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
            CommitType::CharterUpdate => protocol::CommitType::CharterUpdate,
            CommitType::ToolRegistryUpdate => protocol::CommitType::ToolRegistryUpdate,
            CommitType::RecoveryUpdate => protocol::CommitType::RecoveryUpdate,
            CommitType::PevUpdate => protocol::CommitType::PevUpdate,
            CommitType::CbvUpdate => protocol::CommitType::CbvUpdate,
            CommitType::KeyEpochUpdate => protocol::CommitType::KeyEpochUpdate,
            CommitType::FrameEvidenceAppend => protocol::CommitType::FrameEvidenceAppend,
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
    use super::*;
    use protocol::ReasonCodes;
    use receipts::verify_pvgs_receipt_attestation;
    use sep::EdgeType;
    use ucf_protocol::ucf::v1::{
        CoreFrame, GovernanceFrame, MacroMilestoneState, MagnitudeClass, MetabolicFrame,
        PolicyEcologyDimension, PolicyEcologyVector, Ref, TraitDirection, TraitUpdate,
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
            tool_registry_container: None,
            pev: None,
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
                tool_registry_container: None,
                pev: None,
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
        MacroMilestone {
            macro_id: id.to_string(),
            macro_digest: vec![1u8; 32],
            state: MacroMilestoneState::Finalized as i32,
            trait_updates: updates,
        }
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
            }),
            metabolic_frame_ref: Some(Ref {
                id: "met-ref".to_string(),
            }),
            governance_frame_ref: None,
            dlp_refs: Vec::new(),
            finalization_header: None,
        }
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
            tool_registry_container: None,
            pev: None,
        }
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
                }],
            }),
            metabolic_frame: None,
            governance_frame: Some(GovernanceFrame {
                policy_decision_refs: vec![Ref {
                    id: hex::encode(decision_digest),
                }],
                pvgs_receipt_ref: Some(Ref {
                    id: hex::encode(receipt_digest),
                }),
                dlp_refs: Vec::new(),
            }),
            core_frame_ref: Some(Ref {
                id: hex::encode(action_digest),
            }),
            metabolic_frame_ref: None,
            governance_frame_ref: Some(Ref {
                id: hex::encode(frame_digest),
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
            tool_registry_container: None,
            pev: None,
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
            tool_registry_container: None,
            pev: None,
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
            tool_registry_container: None,
            pev: None,
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
            tool_registry_container: None,
            pev: Some(pev.clone()),
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
            tool_registry_container: None,
            pev: Some(pev),
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
            tool_registry_container: Some(container.encode_to_vec()),
            pev: None,
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

        graph.add_edge(action, EdgeType::Authorizes, receipt);
        graph.add_edge(decision, EdgeType::Authorizes, receipt);
        graph.add_edge(record, EdgeType::References, action);
        graph.add_edge(record, EdgeType::References, receipt);
        graph.add_edge(profile, EdgeType::References, receipt);

        sep_log.append_event(
            "sess-ok".to_string(),
            SepEventType::EvDecision,
            receipt,
            vec![],
        );
        sep_log.append_frame_event(
            "sess-ok".to_string(),
            FrameEventKind::ControlFrame,
            profile,
            vec![],
        );

        let checker = CompletenessChecker::new(&graph, &sep_log);
        let report = checker.check_actions("sess-ok", vec![action]);

        assert!(report.missing_edges.is_empty());
        assert!(report.missing_nodes.is_empty());
        assert_eq!(report.status, CompletenessStatus::Ok);
    }

    #[test]
    fn completeness_fails_when_receipt_missing() {
        let graph = CausalGraph::default();
        let sep_log = SepLog::default();
        let checker = CompletenessChecker::new(&graph, &sep_log);

        let report = checker.check_actions("sess-missing", vec![[9u8; 32]]);

        assert_eq!(report.status, CompletenessStatus::Fail);
        assert!(report
            .reason_codes
            .contains(&ReasonCodes::RE_INTEGRITY_FAIL.to_string()));
    }

    #[test]
    fn completeness_degrades_when_record_missing() {
        let mut graph = CausalGraph::default();
        let mut sep_log = SepLog::default();
        let action = [7u8; 32];
        let receipt = [8u8; 32];
        let decision = [6u8; 32];
        let profile = [5u8; 32];

        graph.add_edge(action, EdgeType::Authorizes, receipt);
        graph.add_edge(decision, EdgeType::Authorizes, receipt);
        graph.add_edge(profile, EdgeType::References, receipt);

        sep_log.append_event(
            "sess-degraded".to_string(),
            SepEventType::EvDecision,
            receipt,
            vec![],
        );
        sep_log.append_frame_event(
            "sess-degraded".to_string(),
            FrameEventKind::ControlFrame,
            profile,
            vec![],
        );

        let checker = CompletenessChecker::new(&graph, &sep_log);
        let report = checker.check_actions("sess-degraded", vec![action]);

        assert_eq!(report.status, CompletenessStatus::Degraded);
        assert!(report
            .reason_codes
            .contains(&ReasonCodes::RE_INTEGRITY_DEGRADED.to_string()));
    }

    #[test]
    fn completeness_output_is_deterministic() {
        let mut graph = CausalGraph::default();
        let mut sep_log = SepLog::default();
        let action = [1u8; 32];
        let receipt = [2u8; 32];

        graph.add_edge(action, EdgeType::Authorizes, receipt);
        graph.add_edge([3u8; 32], EdgeType::References, receipt);

        sep_log.append_event(
            "sess-deterministic".to_string(),
            SepEventType::EvDecision,
            receipt,
            vec![],
        );

        let checker = CompletenessChecker::new(&graph, &sep_log);
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

        graph.add_edge(action, EdgeType::Authorizes, receipt);
        graph.add_edge(decision, EdgeType::Authorizes, receipt);
        graph.add_edge(profile, EdgeType::References, receipt);
        graph.add_edge([14u8; 32], EdgeType::References, action);
        graph.add_edge([14u8; 32], EdgeType::References, receipt);

        sep_log.append_event(
            "sess-cf".to_string(),
            SepEventType::EvDecision,
            receipt,
            vec![],
        );

        let checker = CompletenessChecker::new(&graph, &sep_log);
        let report = checker.check_actions("sess-cf", vec![action]);

        assert_eq!(report.status, CompletenessStatus::Degraded);
        assert!(report.missing_nodes.iter().any(|digest| digest == &profile));
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
}
