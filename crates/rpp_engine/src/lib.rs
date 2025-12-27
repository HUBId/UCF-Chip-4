#![forbid(unsafe_code)]

use blake3::Hasher;
use prost::Message;
use rpp_store::DeltaOp;
use std::cmp::Ordering;
use std::collections::BTreeMap;
use thiserror::Error;
use ucf_protocol::ucf::v1::{
    AssetBundle, AssetManifest, CommitType, ExperienceRecord, Ref, ToolOnboardingEvent,
};

#[cfg(feature = "rpp-proof-envelope")]
use rpp_proofs::{verify_transition, Digest, RppProofEnvelope, RppPublicInputs};

const PAYLOAD_DOMAIN: &[u8] = b"UCF:RPP:PAYLOAD";
const DELTA_OPS_DOMAIN: &[u8] = b"UCF:RPP:DELTA_OPS";
const ACCUMULATOR_DOMAIN: &[u8] = b"UCF:RPP:ACC";
const ROOT_STUB_DOMAIN: &[u8] = b"UCF:RPP:ROOT_STUB";

#[cfg(feature = "rpp-proof-envelope")]
const PROOF_BYTES_CAP: usize = 4096;

#[derive(Debug, Clone, Copy)]
pub struct EngineLimits {
    pub max_ops_per_commit: usize,
    pub max_value_size: usize,
}

impl Default for EngineLimits {
    fn default() -> Self {
        Self {
            max_ops_per_commit: 1024,
            max_value_size: rpp_store::MAX_VALUE_SIZE,
        }
    }
}

#[derive(Debug, Error)]
pub enum RppEngineError {
    #[error("payload decode failed: {0}")]
    PayloadDecode(String),
    #[error("digest length for {name} must be 32 bytes, got {len}")]
    InvalidDigestLength { name: &'static str, len: usize },
    #[error("payload digest must not be zero")]
    ZeroPayloadDigest,
    #[error("delta ops digest must not be zero")]
    ZeroDeltaOpsDigest,
    #[error("op count {count} exceeds limit {limit}")]
    MaxOpsExceeded { count: usize, limit: usize },
    #[error("value size {size} exceeds limit {limit}")]
    MaxValueSizeExceeded { size: usize, limit: usize },
    #[error("proof verification failed")]
    ProofVerificationFailed,
    #[error("state store error: {0}")]
    StateStore(#[from] rpp_store::Error),
    #[error("persistence error: {0}")]
    Persistence(String),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RppHeadMeta {
    pub head_id: u64,
    pub commit_kind: String,
    pub payload_digest: [u8; 32],
    pub delta_ops_digest: [u8; 32],
    pub prev_root: [u8; 32],
    pub new_root: [u8; 32],
    pub prev_acc: [u8; 32],
    pub new_acc: [u8; 32],
    pub ruleset_digest: [u8; 32],
    pub asset_manifest_digest_or_zero: [u8; 32],
}

impl RppHeadMeta {
    pub fn new(
        head_id: u64,
        commit_kind: String,
        payload_digest: [u8; 32],
        delta_ops_digest: [u8; 32],
        prev_root: [u8; 32],
        new_root: [u8; 32],
        prev_acc: [u8; 32],
        new_acc: [u8; 32],
        ruleset_digest: [u8; 32],
        asset_manifest_digest_or_zero: [u8; 32],
    ) -> Result<Self, RppEngineError> {
        if payload_digest == [0u8; 32] {
            return Err(RppEngineError::ZeroPayloadDigest);
        }
        if delta_ops_digest == [0u8; 32] {
            return Err(RppEngineError::ZeroDeltaOpsDigest);
        }

        Ok(Self {
            head_id,
            commit_kind,
            payload_digest,
            delta_ops_digest,
            prev_root,
            new_root,
            prev_acc,
            new_acc,
            ruleset_digest,
            asset_manifest_digest_or_zero,
        })
    }
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct RppHeadMetaStore {
    metas: BTreeMap<u64, RppHeadMeta>,
    latest_head_id: Option<u64>,
}

impl RppHeadMetaStore {
    pub fn insert(&mut self, meta: RppHeadMeta) {
        let head_id = meta.head_id;
        self.metas.insert(head_id, meta);
        if self
            .latest_head_id
            .map_or(true, |current| head_id > current)
        {
            self.latest_head_id = Some(head_id);
        }
    }

    pub fn get(&self, head_id: u64) -> Option<&RppHeadMeta> {
        self.metas.get(&head_id)
    }

    pub fn latest(&self) -> Option<&RppHeadMeta> {
        self.latest_head_id
            .and_then(|head_id| self.metas.get(&head_id))
    }

    pub fn persist_to_bytes(&self) -> Result<Vec<u8>, RppEngineError> {
        serde_json::to_vec(self).map_err(|err| RppEngineError::Persistence(err.to_string()))
    }

    pub fn load_from_bytes(bytes: &[u8]) -> Result<Self, RppEngineError> {
        serde_json::from_slice(bytes).map_err(|err| RppEngineError::Persistence(err.to_string()))
    }
}

pub fn compute_payload_digest(
    commit_kind: &CommitType,
    payload_bytes: &[u8],
    aux_digests: &[[u8; 32]],
) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(PAYLOAD_DOMAIN);
    hasher.update(commit_type_label(commit_kind).as_bytes());
    hasher.update(&(payload_bytes.len() as u64).to_le_bytes());
    hasher.update(payload_bytes);

    let mut ordered = aux_digests.to_vec();
    ordered.sort();
    for digest in ordered {
        hasher.update(&digest);
    }

    *hasher.finalize().as_bytes()
}

pub fn canonical_payload_bytes(
    commit_kind: &CommitType,
    payload_bytes: &[u8],
) -> Result<Vec<u8>, RppEngineError> {
    match commit_kind {
        CommitType::ToolOnboardingEventAppend => {
            let mut event = decode_payload::<ToolOnboardingEvent>(payload_bytes)?;
            event.event_digest = None;
            normalize_tool_event(&mut event);
            Ok(event.encode_to_vec())
        }
        CommitType::ExperienceRecordAppend => {
            let mut record = decode_payload::<ExperienceRecord>(payload_bytes)?;
            record.finalization_header = None;
            normalize_experience_record(&mut record);
            Ok(record.encode_to_vec())
        }
        CommitType::AssetManifestAppend => {
            let mut manifest = decode_payload::<AssetManifest>(payload_bytes)?;
            normalize_asset_manifest(&mut manifest);
            Ok(manifest.encode_to_vec())
        }
        CommitType::AssetBundleAppend => {
            let mut bundle = decode_payload::<AssetBundle>(payload_bytes)?;
            normalize_asset_bundle(&mut bundle);
            Ok(bundle.encode_to_vec())
        }
        _ => Ok(payload_bytes.to_vec()),
    }
}

pub fn build_delta_ops(
    commit_kind: &CommitType,
    payload_bytes: &[u8],
    payload_digest: [u8; 32],
    limits: EngineLimits,
) -> Result<Vec<DeltaOp>, RppEngineError> {
    let canonical = canonical_payload_bytes(commit_kind, payload_bytes)?;
    if canonical.len() > limits.max_value_size {
        return Err(RppEngineError::MaxValueSizeExceeded {
            size: canonical.len(),
            limit: limits.max_value_size,
        });
    }

    let key = commit_key(commit_kind, payload_digest);
    let ops = vec![DeltaOp::Put {
        key,
        value: canonical,
    }];

    if ops.len() > limits.max_ops_per_commit {
        return Err(RppEngineError::MaxOpsExceeded {
            count: ops.len(),
            limit: limits.max_ops_per_commit,
        });
    }

    Ok(ops)
}

pub fn compute_delta_ops_digest(ops: &[DeltaOp]) -> [u8; 32] {
    let ordered = ordered_ops(ops);
    let mut hasher = Hasher::new();
    hasher.update(DELTA_OPS_DOMAIN);
    for op in ordered {
        match op {
            DeltaOp::Put { key, value } => {
                hasher.update(&[b'P']);
                hasher.update(&(key.len() as u32).to_le_bytes());
                hasher.update(&key);
                hasher.update(&(value.len() as u32).to_le_bytes());
                hasher.update(&value);
            }
            DeltaOp::Del { key } => {
                hasher.update(&[b'D']);
                hasher.update(&(key.len() as u32).to_le_bytes());
                hasher.update(&key);
                hasher.update(&0u32.to_le_bytes());
            }
        }
    }
    *hasher.finalize().as_bytes()
}

pub fn compute_accumulator_digest(
    prev_acc: [u8; 32],
    prev_root: [u8; 32],
    new_root: [u8; 32],
    payload_digest: [u8; 32],
    ruleset_digest: [u8; 32],
    asset_manifest_digest_or_zero: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(ACCUMULATOR_DOMAIN);
    hasher.update(&prev_acc);
    hasher.update(&prev_root);
    hasher.update(&new_root);
    hasher.update(&payload_digest);
    hasher.update(&ruleset_digest);
    hasher.update(&asset_manifest_digest_or_zero);
    *hasher.finalize().as_bytes()
}

#[cfg(feature = "rpp-proof-envelope")]
pub fn build_proof_envelope(
    pub_inputs: &RppPublicInputs,
) -> Result<RppProofEnvelope, RppEngineError> {
    let acc_proof_bytes = Vec::with_capacity(PROOF_BYTES_CAP);
    let step_proof_bytes = Vec::new();
    let envelope = RppProofEnvelope {
        prev_acc_digest: pub_inputs.prev_acc_digest,
        acc_digest: pub_inputs.acc_digest,
        prev_root_proof: acc_proof_bytes,
        new_root_proof: step_proof_bytes,
        payload_proof: Vec::new(),
        ruleset_proof: Vec::new(),
        asset_manifest_proof: Vec::new(),
    };

    if !verify_transition(pub_inputs, &envelope) {
        return Err(RppEngineError::ProofVerificationFailed);
    }

    Ok(envelope)
}

#[cfg(feature = "rpp-proof-envelope")]
pub fn build_public_inputs(
    prev_acc: Digest,
    acc: Digest,
    prev_root: Digest,
    new_root: Digest,
    payload_digest: Digest,
    ruleset_digest: Digest,
) -> RppPublicInputs {
    RppPublicInputs {
        prev_acc_digest: prev_acc,
        acc_digest: acc,
        prev_root,
        new_root,
        payload_digest,
        ruleset_digest,
        asset_manifest_digest_or_zero: [0u8; 32],
    }
}

#[cfg(feature = "rpp-firewood")]
pub struct RppState {
    store: rpp_store::FirewoodStateStore,
}

#[cfg(feature = "rpp-firewood")]
impl RppState {
    pub fn open<P: AsRef<std::path::Path>>(path: P) -> Result<Self, RppEngineError> {
        let store = rpp_store::FirewoodStateStore::open(path)?;
        Ok(Self { store })
    }

    pub fn current_root(&self) -> [u8; 32] {
        self.store.current_root()
    }

    pub fn apply_ops(
        &mut self,
        ops: &[DeltaOp],
        limits: EngineLimits,
    ) -> Result<[u8; 32], RppEngineError> {
        enforce_limits(ops, limits)?;
        Ok(self.store.apply_ops(ops)?)
    }

    pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.store.get(key)
    }
}

#[cfg(not(feature = "rpp-firewood"))]
#[derive(Debug, Default)]
pub struct RppState {
    state: BTreeMap<Vec<u8>, Vec<u8>>,
}

#[cfg(not(feature = "rpp-firewood"))]
impl RppState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn current_root(&self) -> [u8; 32] {
        root_stub_hash(&self.state)
    }

    pub fn apply_ops(
        &mut self,
        ops: &[DeltaOp],
        limits: EngineLimits,
    ) -> Result<[u8; 32], RppEngineError> {
        enforce_limits(ops, limits)?;
        let ordered = ordered_ops(ops);
        for op in ordered {
            match op {
                DeltaOp::Put { key, value } => {
                    self.state.insert(key, value);
                }
                DeltaOp::Del { key } => {
                    self.state.remove(&key);
                }
            }
        }
        Ok(self.current_root())
    }

    pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.state.get(key).cloned()
    }
}

fn enforce_limits(ops: &[DeltaOp], limits: EngineLimits) -> Result<(), RppEngineError> {
    if ops.len() > limits.max_ops_per_commit {
        return Err(RppEngineError::MaxOpsExceeded {
            count: ops.len(),
            limit: limits.max_ops_per_commit,
        });
    }
    for op in ops {
        if let DeltaOp::Put { value, .. } = op {
            if value.len() > limits.max_value_size {
                return Err(RppEngineError::MaxValueSizeExceeded {
                    size: value.len(),
                    limit: limits.max_value_size,
                });
            }
        }
    }
    Ok(())
}

fn ordered_ops(ops: &[DeltaOp]) -> Vec<DeltaOp> {
    let mut ordered = ops.to_vec();
    ordered.sort_by(|left, right| {
        let key_cmp = left.key().cmp(right.key());
        if key_cmp != Ordering::Equal {
            return key_cmp;
        }
        match (left, right) {
            (DeltaOp::Del { .. }, DeltaOp::Put { .. }) => Ordering::Less,
            (DeltaOp::Put { .. }, DeltaOp::Del { .. }) => Ordering::Greater,
            _ => Ordering::Equal,
        }
    });
    ordered
}

fn root_stub_hash(state: &BTreeMap<Vec<u8>, Vec<u8>>) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(ROOT_STUB_DOMAIN);
    for (key, value) in state {
        hasher.update(key);
        hasher.update(value);
    }
    *hasher.finalize().as_bytes()
}

fn commit_key(commit_kind: &CommitType, digest: [u8; 32]) -> Vec<u8> {
    let label = commit_type_label(commit_kind);
    let digest_hex = hex::encode(digest);
    format!("pvgs/commit/{label}/{digest_hex}").into_bytes()
}

fn commit_type_label(commit_type: &CommitType) -> &'static str {
    match commit_type {
        CommitType::ReceiptRequest => "ReceiptRequest",
        CommitType::RecordAppend => "RecordAppend",
        CommitType::ExperienceRecordAppend => "ExperienceRecordAppend",
        CommitType::MilestoneAppend => "MilestoneAppend",
        CommitType::MacroMilestonePropose => "MacroMilestonePropose",
        CommitType::MacroMilestoneFinalize => "MacroMilestoneFinalize",
        CommitType::ConsistencyFeedbackAppend => "ConsistencyFeedbackAppend",
        CommitType::CharterUpdate => "CharterUpdate",
        CommitType::ToolRegistryUpdate => "ToolRegistryUpdate",
        CommitType::ToolOnboardingEventAppend => "ToolOnboardingEventAppend",
        CommitType::RecoveryCaseCreate => "RecoveryCaseCreate",
        CommitType::RecoveryCaseAdvance => "RecoveryCaseAdvance",
        CommitType::RecoveryApproval => "RecoveryApproval",
        CommitType::RecoveryUpdate => "RecoveryUpdate",
        CommitType::PevUpdate => "PevUpdate",
        CommitType::CbvUpdate => "CbvUpdate",
        CommitType::KeyEpochUpdate => "KeyEpochUpdate",
        CommitType::FrameEvidenceAppend => "FrameEvidenceAppend",
        CommitType::DlpDecisionAppend => "DlpDecisionAppend",
        CommitType::ReplayPlanAppend => "ReplayPlanAppend",
        CommitType::ReplayRunEvidenceAppend => "ReplayRunEvidenceAppend",
        CommitType::TraceRunEvidenceAppend => "TraceRunEvidenceAppend",
        CommitType::MicrocircuitConfigAppend => "MicrocircuitConfigAppend",
        CommitType::AssetManifestAppend => "AssetManifestAppend",
        CommitType::AssetBundleAppend => "AssetBundleAppend",
    }
}

fn decode_payload<T: Message + Default>(payload: &[u8]) -> Result<T, RppEngineError> {
    T::decode(payload).map_err(|err| RppEngineError::PayloadDecode(err.to_string()))
}

fn normalize_tool_event(event: &mut ToolOnboardingEvent) {
    event.reason_codes.sort();
    event.reason_codes.dedup();
    event.signatures.sort();
    event.signatures.dedup();
}

fn normalize_experience_record(record: &mut ExperienceRecord) {
    normalize_refs(&mut record.dlp_refs);

    if let Some(core_frame) = record.core_frame.as_mut() {
        normalize_refs(&mut core_frame.evidence_refs);
    }
    if let Some(metabolic_frame) = record.metabolic_frame.as_mut() {
        normalize_refs(&mut metabolic_frame.outcome_refs);
    }
    if let Some(governance_frame) = record.governance_frame.as_mut() {
        normalize_refs(&mut governance_frame.policy_decision_refs);
        normalize_refs(&mut governance_frame.dlp_refs);
    }
}

fn normalize_asset_manifest(manifest: &mut AssetManifest) {
    manifest.manifest_digest = vec![0u8; 32];
    manifest.asset_digests.sort_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then_with(|| left.digest.cmp(&right.digest))
            .then_with(|| left.version.cmp(&right.version))
    });
    manifest.asset_digests.dedup_by(|left, right| {
        left.kind == right.kind && left.digest == right.digest && left.version == right.version
    });
}

fn normalize_asset_bundle(bundle: &mut AssetBundle) {
    bundle.bundle_digest = vec![0u8; 32];
    if let Some(manifest) = bundle.manifest.as_mut() {
        normalize_asset_manifest(manifest);
    }
    bundle.chunks.sort_by(|left, right| {
        left.asset_digest
            .cmp(&right.asset_digest)
            .then_with(|| left.chunk_index.cmp(&right.chunk_index))
            .then_with(|| left.chunk_digest.cmp(&right.chunk_digest))
            .then_with(|| left.chunk_count.cmp(&right.chunk_count))
            .then_with(|| left.compression_mode.cmp(&right.compression_mode))
    });
    bundle.chunks.dedup_by(|left, right| {
        left.asset_digest == right.asset_digest
            && left.chunk_index == right.chunk_index
            && left.chunk_digest == right.chunk_digest
            && left.chunk_count == right.chunk_count
            && left.compression_mode == right.compression_mode
            && left.payload == right.payload
    });
}

fn normalize_refs(refs: &mut Vec<Ref>) {
    refs.sort_by(|left, right| {
        left.id
            .cmp(&right.id)
            .then_with(|| left.digest.cmp(&right.digest))
    });
    refs.dedup_by(|left, right| left.id == right.id && left.digest == right.digest);
}
