#![forbid(unsafe_code)]

use blake3::Hasher;
use prost::Message;
use rpp_proofs::{
    compute_accumulator_digest, verify_transition, RppProofEnvelope, RppPublicInputs,
};
use rpp_store::{DeltaOp, MAX_KEY_SIZE, MAX_VALUE_SIZE};
use std::cmp::Ordering;
use std::collections::BTreeMap;
#[cfg(feature = "rpp-firewood")]
use std::sync::{Arc, Mutex};
use thiserror::Error;
use trace_runs::TraceRunEvidence;
use ucf_protocol::ucf::v1::{
    AssetBundle, AssetManifest, ExperienceRecord, Ref, ReplayRunEvidence, ToolOnboardingEvent,
};

pub const PAYLOAD_DOMAIN: &str = "UCF:RPP:PAYLOAD";
pub const DELTA_OPS_DOMAIN: &str = "UCF:RPP:DELTA_OPS";
pub const ACC_DOMAIN: &str = "UCF:RPP:ACC";
pub const ROOT_STUB_DOMAIN: &str = "UCF:RPP:ROOT_STUB";

const ZERO_DIGEST: [u8; 32] = [0u8; 32];
const MAX_DELTA_OPS_PER_COMMIT: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RppHeadMeta {
    pub head_id: u64,
    pub head_record_digest: [u8; 32],
    pub prev_state_root: [u8; 32],
    pub state_root: [u8; 32],
    pub prev_acc_digest: [u8; 32],
    pub acc_digest: [u8; 32],
    pub ruleset_digest: [u8; 32],
    pub asset_manifest_digest: Option<[u8; 32]>,
    pub payload_digest: [u8; 32],
    pub delta_ops_digest: [u8; 32],
    pub created_at_ms: u64,
}

#[derive(Debug, Error)]
pub enum RppEngineError {
    #[error("payload digest is zero")]
    ZeroPayloadDigest,
    #[error("delta ops digest is zero")]
    ZeroDeltaOpsDigest,
    #[error("delta ops count {len} exceeds max {max}")]
    TooManyDeltaOps { len: usize, max: usize },
    #[error("delta op key too large: {len} > {max}")]
    DeltaOpKeyTooLarge { len: usize, max: usize },
    #[error("delta op value too large: {len} > {max}")]
    DeltaOpValueTooLarge { len: usize, max: usize },
    #[error("rpp transition verification failed")]
    VerificationFailed,
    #[cfg(feature = "rpp-firewood")]
    #[error("state store error: {0}")]
    StateStore(#[from] rpp_store::Error),
    #[cfg(feature = "rpp-firewood")]
    #[error("state store mutex poisoned")]
    StateStorePoisoned,
}

pub struct RppTransitionInput {
    pub payload_digest: [u8; 32],
    pub delta_ops: Vec<DeltaOp>,
    pub ruleset_digest: [u8; 32],
    pub asset_manifest_digest: Option<[u8; 32]>,
    pub created_at_ms: u64,
    pub head_record_digest: Option<[u8; 32]>,
    pub advance_head: bool,
}

#[derive(Debug, Clone)]
pub struct RppTransitionOutcome {
    pub prev_state_root: [u8; 32],
    pub state_root: [u8; 32],
    pub prev_acc_digest: [u8; 32],
    pub acc_digest: [u8; 32],
    pub payload_digest: [u8; 32],
    pub delta_ops_digest: [u8; 32],
    pub envelope: RppProofEnvelope,
    pub head_meta: Option<RppHeadMeta>,
}

#[derive(Debug, Clone)]
pub struct RppEngine {
    state_store: RppStateStore,
    acc_digest: [u8; 32],
    head_id: u64,
    head_meta_store: BTreeMap<u64, RppHeadMeta>,
    verifier: fn(&RppPublicInputs, &RppProofEnvelope) -> bool,
}

impl Default for RppEngine {
    fn default() -> Self {
        Self::new_stub()
    }
}

impl RppEngine {
    #[must_use]
    pub fn new_stub() -> Self {
        Self {
            state_store: RppStateStore::Stub(StubStateStore::default()),
            acc_digest: ZERO_DIGEST,
            head_id: 0,
            head_meta_store: BTreeMap::new(),
            verifier: verify_transition,
        }
    }

    #[cfg(feature = "rpp-firewood")]
    pub fn open_firewood<P: AsRef<std::path::Path>>(path: P) -> Result<Self, RppEngineError> {
        Ok(Self {
            state_store: RppStateStore::Firewood(Arc::new(Mutex::new(
                rpp_store::FirewoodStateStore::open(path)?,
            ))),
            acc_digest: ZERO_DIGEST,
            head_id: 0,
            head_meta_store: BTreeMap::new(),
            verifier: verify_transition,
        })
    }

    pub fn set_verifier(&mut self, verifier: fn(&RppPublicInputs, &RppProofEnvelope) -> bool) {
        self.verifier = verifier;
    }

    #[must_use]
    pub fn latest_head_meta(&self) -> Option<&RppHeadMeta> {
        self.head_meta_store.get(&self.head_id)
    }

    #[must_use]
    pub fn head_meta(&self, head_id: u64) -> Option<&RppHeadMeta> {
        self.head_meta_store.get(&head_id)
    }

    #[must_use]
    pub fn head_id(&self) -> u64 {
        self.head_id
    }

    #[must_use]
    pub fn acc_digest(&self) -> [u8; 32] {
        self.acc_digest
    }

    #[must_use]
    pub fn current_root(&self) -> [u8; 32] {
        self.state_store.current_root()
    }

    pub fn apply_transition(
        &mut self,
        input: RppTransitionInput,
    ) -> Result<RppTransitionOutcome, RppEngineError> {
        if input.payload_digest == ZERO_DIGEST {
            return Err(RppEngineError::ZeroPayloadDigest);
        }

        if input.delta_ops.len() > MAX_DELTA_OPS_PER_COMMIT {
            return Err(RppEngineError::TooManyDeltaOps {
                len: input.delta_ops.len(),
                max: MAX_DELTA_OPS_PER_COMMIT,
            });
        }

        let prev_state_root = self.state_store.current_root();
        let prev_acc_digest = self.acc_digest;

        let ordered_ops = sort_ops(&input.delta_ops)?;
        let delta_ops_digest = compute_delta_ops_digest_from_sorted(&ordered_ops);
        if delta_ops_digest == ZERO_DIGEST {
            return Err(RppEngineError::ZeroDeltaOpsDigest);
        }

        let state_root = self.state_store.apply_sorted_ops(&ordered_ops)?;

        let asset_manifest_or_zero = input.asset_manifest_digest.unwrap_or(ZERO_DIGEST);
        let acc_digest = compute_accumulator_digest(
            prev_acc_digest,
            prev_state_root,
            state_root,
            input.payload_digest,
            input.ruleset_digest,
            asset_manifest_or_zero,
        );

        let envelope = RppProofEnvelope {
            prev_acc_digest,
            acc_digest,
            acc_proof_bytes: Vec::new(),
            step_proof_bytes: None,
        };

        let pub_inputs = RppPublicInputs {
            prev_acc_digest,
            acc_digest,
            prev_root: prev_state_root,
            new_root: state_root,
            payload_digest: input.payload_digest,
            ruleset_digest: input.ruleset_digest,
            asset_manifest_digest_or_zero: asset_manifest_or_zero,
        };

        if !(self.verifier)(&pub_inputs, &envelope) {
            return Err(RppEngineError::VerificationFailed);
        }

        self.acc_digest = acc_digest;

        let head_meta = if input.advance_head {
            let head_record_digest = input.head_record_digest.unwrap_or(ZERO_DIGEST);
            self.head_id = self.head_id.saturating_add(1);
            let meta = RppHeadMeta {
                head_id: self.head_id,
                head_record_digest,
                prev_state_root,
                state_root,
                prev_acc_digest,
                acc_digest,
                ruleset_digest: input.ruleset_digest,
                asset_manifest_digest: input.asset_manifest_digest,
                payload_digest: input.payload_digest,
                delta_ops_digest,
                created_at_ms: input.created_at_ms,
            };
            self.head_meta_store.insert(self.head_id, meta.clone());
            Some(meta)
        } else {
            None
        };

        Ok(RppTransitionOutcome {
            prev_state_root,
            state_root,
            prev_acc_digest,
            acc_digest,
            payload_digest: input.payload_digest,
            delta_ops_digest,
            envelope,
            head_meta,
        })
    }
}

#[derive(Debug, Default, Clone)]
struct StubStateStore {
    state: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl StubStateStore {
    fn current_root(&self) -> [u8; 32] {
        compute_stub_root(&self.state)
    }

    fn apply_sorted_ops(&mut self, ops: &[DeltaOp]) -> Result<[u8; 32], RppEngineError> {
        for op in ops {
            match op {
                DeltaOp::Put { key, value } => {
                    self.state.insert(key.clone(), value.clone());
                }
                DeltaOp::Del { key } => {
                    self.state.remove(key);
                }
            }
        }
        Ok(self.current_root())
    }
}

#[derive(Debug, Clone)]
enum RppStateStore {
    Stub(StubStateStore),
    #[cfg(feature = "rpp-firewood")]
    Firewood(Arc<Mutex<rpp_store::FirewoodStateStore>>),
}

impl RppStateStore {
    fn current_root(&self) -> [u8; 32] {
        match self {
            Self::Stub(store) => store.current_root(),
            #[cfg(feature = "rpp-firewood")]
            Self::Firewood(store) => store
                .lock()
                .map(|store| store.current_root())
                .unwrap_or(ZERO_DIGEST),
        }
    }

    fn apply_sorted_ops(&mut self, ops: &[DeltaOp]) -> Result<[u8; 32], RppEngineError> {
        match self {
            Self::Stub(store) => store.apply_sorted_ops(ops),
            #[cfg(feature = "rpp-firewood")]
            Self::Firewood(store) => {
                let mut store = store
                    .lock()
                    .map_err(|_| RppEngineError::StateStorePoisoned)?;
                Ok(store.apply_ops(ops)?)
            }
        }
    }
}

#[must_use]
pub fn compute_payload_digest(
    commit_kind: &str,
    payload_bytes: &[u8],
    aux_digests: &[([u8; 32], &'static str)],
) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(PAYLOAD_DOMAIN.as_bytes());
    hasher.update(commit_kind.as_bytes());
    hasher.update(&(payload_bytes.len() as u64).to_le_bytes());
    hasher.update(payload_bytes);
    for (digest, tag) in aux_digests {
        hasher.update(tag.as_bytes());
        hasher.update(digest);
    }
    *hasher.finalize().as_bytes()
}

pub fn compute_delta_ops_digest(ops: &[DeltaOp]) -> Result<[u8; 32], RppEngineError> {
    let ordered = sort_ops(ops)?;
    Ok(compute_delta_ops_digest_from_sorted(&ordered))
}

#[must_use]
pub fn build_experience_record_delta_ops(
    record_digest: [u8; 32],
    record_bytes: Vec<u8>,
    sep_events: &[([u8; 32], Vec<u8>)],
) -> Vec<DeltaOp> {
    let mut ops = Vec::with_capacity(1 + sep_events.len());
    ops.push(DeltaOp::Put {
        key: key_with_digest("pvgs/records", record_digest),
        value: record_bytes,
    });
    for (digest, bytes) in sep_events {
        ops.push(DeltaOp::Put {
            key: key_with_digest("pvgs/sep", *digest),
            value: bytes.clone(),
        });
    }
    ops
}

#[must_use]
pub fn build_asset_bundle_delta_ops(
    bundle_digest: [u8; 32],
    bundle_bytes: Vec<u8>,
    manifest: Option<([u8; 32], Vec<u8>)>,
) -> Vec<DeltaOp> {
    let mut ops = Vec::new();
    ops.push(DeltaOp::Put {
        key: key_with_digest("pvgs/assets/bundles", bundle_digest),
        value: bundle_bytes,
    });
    if let Some((digest, bytes)) = manifest {
        ops.push(DeltaOp::Put {
            key: key_with_digest("pvgs/assets/manifests", digest),
            value: bytes,
        });
    }
    ops
}

#[must_use]
pub fn build_asset_manifest_delta_ops(
    manifest_digest: [u8; 32],
    manifest_bytes: Vec<u8>,
) -> Vec<DeltaOp> {
    vec![DeltaOp::Put {
        key: key_with_digest("pvgs/assets/manifests", manifest_digest),
        value: manifest_bytes,
    }]
}

#[must_use]
pub fn build_replay_run_delta_ops(run_digest: [u8; 32], run_bytes: Vec<u8>) -> Vec<DeltaOp> {
    vec![DeltaOp::Put {
        key: key_with_digest("pvgs/replay_runs", run_digest),
        value: run_bytes,
    }]
}

#[must_use]
pub fn build_trace_run_delta_ops(run_digest: [u8; 32], run_bytes: Vec<u8>) -> Vec<DeltaOp> {
    vec![DeltaOp::Put {
        key: key_with_digest("pvgs/trace_runs", run_digest),
        value: run_bytes,
    }]
}

#[must_use]
pub fn build_tool_registry_delta_ops(
    registry_digest: [u8; 32],
    registry_bytes: Vec<u8>,
) -> Vec<DeltaOp> {
    vec![DeltaOp::Put {
        key: key_with_digest("pvgs/tool_registry", registry_digest),
        value: registry_bytes,
    }]
}

#[must_use]
pub fn build_tool_event_delta_ops(event_digest: [u8; 32], event_bytes: Vec<u8>) -> Vec<DeltaOp> {
    vec![DeltaOp::Put {
        key: key_with_digest("pvgs/tool_events", event_digest),
        value: event_bytes,
    }]
}

#[must_use]
pub fn canonicalize_experience_record(record: &ExperienceRecord) -> Vec<u8> {
    let mut canonical = record.clone();
    normalize_ref_list(&mut canonical.dlp_refs);
    if let Some(frame) = canonical.core_frame.as_mut() {
        normalize_ref_list(&mut frame.evidence_refs);
    }
    if let Some(frame) = canonical.metabolic_frame.as_mut() {
        normalize_ref_list(&mut frame.outcome_refs);
    }
    if let Some(frame) = canonical.governance_frame.as_mut() {
        normalize_ref_list(&mut frame.policy_decision_refs);
        normalize_ref_list(&mut frame.dlp_refs);
    }
    canonical.encode_to_vec()
}

#[must_use]
pub fn canonicalize_tool_event(event: &ToolOnboardingEvent) -> Vec<u8> {
    let mut canonical = event.clone();
    canonical.reason_codes.sort();
    canonical.reason_codes.dedup();
    canonical.signatures.sort();
    canonical.encode_to_vec()
}

#[must_use]
pub fn canonicalize_replay_run_evidence(evidence: &ReplayRunEvidence) -> Vec<u8> {
    let mut canonical = evidence.clone();
    canonical
        .micro_config_refs
        .sort_by_key(|entry| entry.encode_to_vec());
    canonical.summary_digests.sort();
    canonical.encode_to_vec()
}

#[must_use]
pub fn canonicalize_asset_manifest(manifest: &AssetManifest) -> Vec<u8> {
    let mut canonical = manifest.clone();
    canonical
        .asset_digests
        .sort_by_key(|entry| entry.encode_to_vec());
    canonical.encode_to_vec()
}

#[must_use]
pub fn canonicalize_asset_bundle(bundle: &AssetBundle) -> Vec<u8> {
    let mut canonical = bundle.clone();
    if let Some(manifest) = canonical.manifest.as_mut() {
        let bytes = canonicalize_asset_manifest(manifest);
        if let Ok(decoded) = AssetManifest::decode(bytes.as_slice()) {
            *manifest = decoded;
        }
    }
    canonical.chunks.sort_by_key(|entry| entry.encode_to_vec());
    canonical.encode_to_vec()
}

pub fn canonicalize_trace_run_evidence(evidence: &TraceRunEvidence) -> Vec<u8> {
    let mut canonical = evidence.clone();
    canonical.reason_codes.sort();
    canonical.reason_codes.dedup();
    canonical
        .encode()
        .unwrap_or_else(|_| evidence.encode().unwrap_or_default())
}

fn normalize_ref_list(refs: &mut [Ref]) {
    refs.sort_by_key(|entry| entry.encode_to_vec());
}

fn key_with_digest(prefix: &str, digest: [u8; 32]) -> Vec<u8> {
    let key = format!("{}/{}", prefix, hex::encode(digest));
    key.into_bytes()
}

fn sort_ops(ops: &[DeltaOp]) -> Result<Vec<DeltaOp>, RppEngineError> {
    let mut ordered = Vec::with_capacity(ops.len());
    for op in ops {
        match op {
            DeltaOp::Put { key, value } => {
                if key.len() > MAX_KEY_SIZE {
                    return Err(RppEngineError::DeltaOpKeyTooLarge {
                        len: key.len(),
                        max: MAX_KEY_SIZE,
                    });
                }
                if value.len() > MAX_VALUE_SIZE {
                    return Err(RppEngineError::DeltaOpValueTooLarge {
                        len: value.len(),
                        max: MAX_VALUE_SIZE,
                    });
                }
            }
            DeltaOp::Del { key } => {
                if key.len() > MAX_KEY_SIZE {
                    return Err(RppEngineError::DeltaOpKeyTooLarge {
                        len: key.len(),
                        max: MAX_KEY_SIZE,
                    });
                }
            }
        }
        ordered.push(op.clone());
    }

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

    Ok(ordered)
}

fn compute_delta_ops_digest_from_sorted(ops: &[DeltaOp]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(DELTA_OPS_DOMAIN.as_bytes());
    for op in ops {
        match op {
            DeltaOp::Put { key, value } => {
                hasher.update(b"P");
                hasher.update(&(key.len() as u64).to_le_bytes());
                hasher.update(key);
                hasher.update(&(value.len() as u64).to_le_bytes());
                hasher.update(value);
            }
            DeltaOp::Del { key } => {
                hasher.update(b"D");
                hasher.update(&(key.len() as u64).to_le_bytes());
                hasher.update(key);
                hasher.update(&0u64.to_le_bytes());
            }
        }
    }
    *hasher.finalize().as_bytes()
}

fn compute_stub_root(state: &BTreeMap<Vec<u8>, Vec<u8>>) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(ROOT_STUB_DOMAIN.as_bytes());
    for (key, value) in state {
        hasher.update(key);
        hasher.update(value);
    }
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ucf_protocol::ucf::v1::{ToolOnboardingEvent, ToolOnboardingStage};

    #[test]
    fn payload_digest_is_deterministic_for_reordered_repeats() {
        let mut event = ToolOnboardingEvent {
            event_id: "evt".to_string(),
            stage: ToolOnboardingStage::To6Suspended as i32,
            tool_id: "tool".to_string(),
            action_id: "action".to_string(),
            reason_codes: vec!["b".to_string(), "a".to_string()],
            signatures: vec![vec![2, 1], vec![3]],
            event_digest: None,
            created_at_ms: Some(10),
        };

        let mut shuffled = event.clone();
        shuffled.reason_codes.reverse();
        shuffled.signatures.reverse();

        let bytes = canonicalize_tool_event(&event);
        let shuffled_bytes = canonicalize_tool_event(&shuffled);

        let digest = compute_payload_digest("ToolOnboardingEventAppend", &bytes, &[]);
        let digest_again =
            compute_payload_digest("ToolOnboardingEventAppend", &shuffled_bytes, &[]);

        assert_eq!(digest, digest_again);
    }

    #[test]
    fn delta_ops_digest_is_deterministic() {
        let op_a = DeltaOp::Put {
            key: b"a".to_vec(),
            value: b"1".to_vec(),
        };
        let op_b = DeltaOp::Del { key: b"b".to_vec() };
        let op_c = DeltaOp::Put {
            key: b"b".to_vec(),
            value: b"2".to_vec(),
        };

        let digest_1 =
            compute_delta_ops_digest(&[op_a.clone(), op_b.clone(), op_c.clone()]).expect("digest");
        let digest_2 = compute_delta_ops_digest(&[op_c, op_a, op_b]).expect("digest");

        assert_eq!(digest_1, digest_2);
    }

    #[test]
    fn accumulator_digest_matches_domain_rule() {
        let prev_acc = [1u8; 32];
        let prev_root = [2u8; 32];
        let new_root = [3u8; 32];
        let payload_digest = [4u8; 32];
        let ruleset_digest = [5u8; 32];
        let asset_manifest = [6u8; 32];

        let expected = {
            let mut hasher = Hasher::new();
            hasher.update(ACC_DOMAIN.as_bytes());
            hasher.update(&prev_acc);
            hasher.update(&prev_root);
            hasher.update(&new_root);
            hasher.update(&payload_digest);
            hasher.update(&ruleset_digest);
            hasher.update(&asset_manifest);
            *hasher.finalize().as_bytes()
        };

        let computed = compute_accumulator_digest(
            prev_acc,
            prev_root,
            new_root,
            payload_digest,
            ruleset_digest,
            asset_manifest,
        );

        assert_eq!(expected, computed);
    }
}
