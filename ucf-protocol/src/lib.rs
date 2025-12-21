#![forbid(unsafe_code)]

/// Protocol-level types for UCF interactions.
pub mod ucf {
    pub mod v1 {
        use prost::{Enumeration, Message};
        #[cfg(feature = "serde")]
        use serde::{Deserialize, Serialize};

        /// 32-byte digest wrapper used across protocol structs.
        #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct Digest32(pub [u8; 32]);

        impl Digest32 {
            pub fn zero() -> Self {
                Self([0u8; 32])
            }

            pub fn from_slice(bytes: &[u8]) -> Option<Self> {
                if bytes.len() != 32 {
                    return None;
                }

                let mut digest = [0u8; 32];
                digest.copy_from_slice(bytes);
                Some(Self(digest))
            }

            pub fn to_vec(&self) -> Vec<u8> {
                self.0.to_vec()
            }
        }

        /// Commit categories supported by the PVGS.
        #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
        #[derive(Clone, Debug, PartialEq, Eq)]
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
            RecoveryUpdate,
            PevUpdate,
            CbvUpdate,
            KeyEpochUpdate,
            FrameEvidenceAppend,
            DlpDecisionAppend,
            ReplayPlanAppend,
        }

        /// Required receipt classes for PVGS commits.
        #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum RequiredReceiptKind {
            Read,
            Transform,
            Write,
            Execute,
            Export,
            Persist,
        }

        /// Required checks requested by the caller.
        #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub enum RequiredCheck {
            SchemaOk,
            BindingOk,
            TightenOnly,
            IntegrityOk,
        }

        /// Binding information recorded inside receipts.
        #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct CommitBindings {
            pub action_digest: Option<Digest32>,
            pub decision_digest: Option<Digest32>,
            pub grant_id: Option<String>,
            pub charter_version_digest: String,
            pub policy_version_digest: String,
            pub prev_record_digest: Digest32,
            pub profile_digest: Option<Digest32>,
            pub tool_profile_digest: Option<Digest32>,
            pub pev_digest: Option<Digest32>,
        }

        /// Acceptance status for PVGS receipts.
        #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum ReceiptStatus {
            Accepted,
            Rejected,
        }

        /// PVGS receipt containing verification results and digests.
        #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct PVGSReceipt {
            pub commit_id: String,
            pub commit_type: CommitType,
            pub bindings: CommitBindings,
            pub required_checks: Vec<RequiredCheck>,
            pub required_receipt_kind: RequiredReceiptKind,
            pub payload_digests: Vec<Digest32>,
            pub epoch_id: u64,
            pub status: ReceiptStatus,
            pub reject_reason_codes: Vec<String>,
            pub receipt_digest: Digest32,
            pub receipt_id: String,
            pub pvgs_attestation_key_id: String,
            pub pvgs_attestation_sig: Vec<u8>,
        }

        /// Placeholder ProofReceipt for future use.
        #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct ProofReceipt {
            pub proof_receipt_id: String,
            pub receipt_digest: Digest32,
            pub ruleset_digest: Digest32,
            pub verified_fields_digest: Digest32,
            pub vrf_digest: Digest32,
            pub timestamp_ms: u64,
            pub epoch_id: u64,
            pub proof_receipt_digest: Digest32,
            pub proof_attestation_key_id: String,
            pub proof_attestation_sig: Vec<u8>,
        }

        /// Tool registry container used for PVGS commits.
        #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
        #[derive(Clone, PartialEq, Eq, Message)]
        pub struct ToolRegistryContainer {
            #[prost(bytes = "vec", tag = "1")]
            pub registry_digest: Vec<u8>,
            #[prost(string, tag = "2")]
            pub registry_version: String,
        }

        /// Published key epoch announcement for PVGS attestation and VRF verification.
        #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct PVGSKeyEpoch {
            pub key_epoch_id: u64,
            pub attestation_key_id: String,
            pub attestation_public_key: Vec<u8>,
            pub vrf_key_id: String,
            pub vrf_public_key: Vec<u8>,
            pub created_at_ms: u64,
            pub prev_key_epoch_digest: Option<Digest32>,
            pub announcement_digest: Digest32,
            pub announcement_signature: Vec<u8>,
        }

        /// Control overlays included in control frames.
        #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
        #[derive(Clone, Debug, PartialEq, Eq, Default)]
        pub struct Overlays {
            pub export_lock: bool,
            pub novelty_lock: bool,
            pub simulate_first: bool,
            pub deescalation_lock: bool,
        }

        /// Control profiles that can be commanded by the governance engine.
        #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum Profile {
            M0,
            M1Restricted,
            M2Quarantine,
            M3KillSwitch,
        }

        /// Approval mode describing how conservative the control frame is.
        #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum ApprovalMode {
            Standard,
            Strict,
        }

        #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Enumeration)]
        #[repr(i32)]
        pub enum MacroMilestoneState {
            Unknown = 0,
            Draft = 1,
            Finalized = 2,
            Proposed = 3,
        }

        #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Enumeration)]
        #[repr(i32)]
        pub enum TraitDirection {
            IncreaseStrictness = 0,
            DecreaseStrictness = 1,
        }

        #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Enumeration)]
        #[repr(i32)]
        pub enum MagnitudeClass {
            Low = 0,
            Med = 1,
            High = 2,
        }

        #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
        #[derive(Clone, PartialEq, Eq, Message)]
        pub struct TraitUpdate {
            #[prost(string, tag = "1")]
            pub trait_name: String,
            #[prost(enumeration = "TraitDirection", tag = "2")]
            pub direction: i32,
            #[prost(enumeration = "MagnitudeClass", tag = "3")]
            pub magnitude_class: i32,
        }

        #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
        #[derive(Clone, PartialEq, Eq, Message)]
        pub struct MacroMilestone {
            #[prost(string, tag = "1")]
            pub macro_id: String,
            #[prost(bytes = "vec", tag = "2")]
            pub macro_digest: Vec<u8>,
            #[prost(enumeration = "MacroMilestoneState", tag = "3")]
            pub state: i32,
            #[prost(message, repeated, tag = "4")]
            pub trait_updates: Vec<TraitUpdate>,
            #[prost(message, repeated, tag = "5")]
            pub meso_refs: Vec<Ref>,
            #[prost(string, tag = "6")]
            pub consistency_class: String,
            #[prost(bool, tag = "7")]
            pub identity_anchor_flag: bool,
            #[prost(message, optional, tag = "8")]
            pub proof_receipt_ref: Option<Ref>,
            #[prost(bytes = "vec", optional, tag = "9")]
            pub consistency_digest: Option<Vec<u8>>,
            #[prost(message, optional, tag = "10")]
            pub consistency_feedback_ref: Option<Ref>,
        }

        #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
        #[derive(Clone, PartialEq, Eq, Message)]
        pub struct ConsistencyFeedback {
            #[prost(bytes = "vec", optional, tag = "1")]
            pub cf_digest: Option<Vec<u8>>,
            #[prost(string, tag = "2")]
            pub consistency_class: String,
            #[prost(string, repeated, tag = "3")]
            pub flags: Vec<String>,
            #[prost(message, optional, tag = "4")]
            pub proof_receipt_ref: Option<Ref>,
        }

        #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
        #[derive(Clone, PartialEq, Eq, Message)]
        pub struct CharacterBaselineVector {
            #[prost(uint64, tag = "1")]
            pub cbv_epoch: u64,
            #[prost(int32, tag = "2")]
            pub baseline_caution_offset: i32,
            #[prost(int32, tag = "3")]
            pub baseline_novelty_dampening_offset: i32,
            #[prost(int32, tag = "4")]
            pub baseline_approval_strictness_offset: i32,
            #[prost(int32, tag = "5")]
            pub baseline_export_strictness_offset: i32,
            #[prost(int32, tag = "6")]
            pub baseline_chain_conservatism_offset: i32,
            #[prost(uint32, tag = "7")]
            pub baseline_cooldown_multiplier_class: u32,
            #[prost(bytes = "vec", optional, tag = "8")]
            pub cbv_digest: Option<Vec<u8>>,
            #[prost(message, repeated, tag = "9")]
            pub source_milestone_refs: Vec<Ref>,
            #[prost(message, repeated, tag = "10")]
            pub source_event_refs: Vec<Ref>,
            #[prost(message, optional, tag = "11")]
            pub proof_receipt_ref: Option<Ref>,
            #[prost(string, tag = "12")]
            pub pvgs_attestation_key_id: String,
            #[prost(bytes = "vec", tag = "13")]
            pub pvgs_attestation_sig: Vec<u8>,
        }

        #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
        #[derive(Clone, PartialEq, Eq, Message)]
        pub struct PolicyEcologyDimension {
            #[prost(string, tag = "1")]
            pub name: String,
            #[prost(uint32, tag = "2")]
            pub value: u32,
        }

        #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
        #[derive(Clone, PartialEq, Eq, Message)]
        pub struct PolicyEcologyVector {
            #[prost(message, repeated, tag = "1")]
            pub dimensions: Vec<PolicyEcologyDimension>,
            #[prost(bytes = "vec", optional, tag = "2")]
            pub pev_digest: Option<Vec<u8>>,
            #[prost(bytes = "vec", optional, tag = "3")]
            pub pev_version_digest: Option<Vec<u8>>,
            #[prost(uint64, optional, tag = "4")]
            pub pev_epoch: Option<u64>,
        }

        /// Control frame emitted by the engine with overlays and reasons.
        #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct ControlFrame {
            pub profile: Profile,
            pub overlays: Overlays,
            pub approval_mode: ApprovalMode,
            pub character_epoch_digest: Option<Digest32>,
            pub policy_ecology_digest: Option<Digest32>,
            pub profile_reason_codes: Vec<String>,
            pub created_at_ms: u64,
        }

        /// Alias for PVGSKeyEpoch using Rust-style casing.
        pub type PvgsKeyEpoch = PVGSKeyEpoch;

        /// Reason code constants for PVGS and SEP operations.
        pub struct ReasonCodes;

        impl ReasonCodes {
            pub const RE_INTEGRITY_DEGRADED: &'static str = "RC.RE.INTEGRITY.DEGRADED";
            pub const RE_INTEGRITY_FAIL: &'static str = "RC.RE.INTEGRITY.FAIL";
            pub const GE_EXEC_DISPATCH_BLOCKED: &'static str = "RC.GE.EXEC.DISPATCH_BLOCKED";
            pub const PB_DENY_CHARTER_SCOPE: &'static str = "RC.PB.DENY.CHARTER_SCOPE";
            pub const PB_DENY_INTEGRITY_REQUIRED: &'static str = "RC.PB.DENY.INTEGRITY_REQUIRED";
            pub const GE_GRANT_MISSING: &'static str = "RC.GE.GRANT.MISSING";
            pub const TH_INTEGRITY_COMPROMISE: &'static str = "RC.TH.INTEGRITY.COMPROMISE";
            pub const GV_KEY_EPOCH_ROTATED: &'static str = "RC.GV.KEY_EPOCH.ROTATED";
            pub const GV_KEY_EPOCH_UNKNOWN: &'static str = "RC.GV.KEY_EPOCH.UNKNOWN";
            pub const GV_KEY_EPOCH_SIGNATURE_INVALID: &'static str =
                "RC.GV.KEY_EPOCH.SIGNATURE_INVALID";
            pub const GV_KEY_EPOCH_DUPLICATE: &'static str = "RC.GV.KEY_EPOCH.DUPLICATE";
            pub const GV_KEY_EPOCH_NON_MONOTONIC: &'static str = "RC.GV.KEY_EPOCH.NON_MONOTONIC";
            pub const GV_KEY_EPOCH_REQUIRED_CHECK: &'static str =
                "RC.GV.KEY_EPOCH.REQUIRED_CHECK_MISSING";
            pub const GV_KEY_EPOCH_PAYLOAD_INVALID: &'static str =
                "RC.GV.KEY_EPOCH.PAYLOAD_INVALID";
            pub const GV_FRAME_EVIDENCE_REQUIRED_CHECK: &'static str =
                "RC.GV.FRAME_EVIDENCE.REQUIRED_CHECK";
            pub const GV_FRAME_EVIDENCE_PAYLOAD_INVALID: &'static str =
                "RC.GV.FRAME_EVIDENCE.PAYLOAD_INVALID";
            pub const GE_VALIDATION_SCHEMA_INVALID: &'static str =
                "RC.GE.VALIDATION.SCHEMA_INVALID";
            pub const GV_CBV_UPDATED: &'static str = "RC.GV.CBV.UPDATED";
            pub const GV_CBV_NO_CHANGE: &'static str = "RC.GV.CBV.NO_CHANGE";
            pub const GV_CBV_NO_OP: &'static str = "RC.GV.CBV.NO_OP";
            pub const GV_CBV_UPDATE_FAILED: &'static str = "RC.GV.CBV.UPDATE_FAILED";
            pub const GV_MACRO_PROPOSED: &'static str = "RC.GV.MACRO.PROPOSED";
            pub const GV_MACRO_FINALIZED: &'static str = "RC.GV.MACRO.FINALIZED";
            pub const GV_MILESTONE_MACRO_APPENDED: &'static str = "RC.GV.MILESTONE.MACRO_APPENDED";
            pub const GV_CONSISTENCY_APPENDED: &'static str = "RC.GV.CONSISTENCY.APPENDED";
            pub const GV_CONSISTENCY_LOW: &'static str = "RC.GV.CONSISTENCY.LOW";
            pub const GV_CONSISTENCY_MED_CLUSTER: &'static str = "RC.GV.CONSISTENCY.MED_CLUSTER";
            pub const GV_REPLAY_PLANNED: &'static str = "RC.GV.REPLAY.PLANNED";
            pub const GV_REPLAY_DENY_CLUSTER: &'static str = "RC.GV.REPLAY.DENY_CLUSTER";
            pub const GV_REPLAY_SPOTCHECK: &'static str = "RC.GV.REPLAY.SPOTCHECK";
            pub const GV_PEV_UPDATED: &'static str = "RC.GV.PEV.UPDATED";
            pub const GV_TOOL_REGISTRY_UPDATED: &'static str = "RC.GV.TOOL_REGISTRY.UPDATED";
            pub const GV_RULESET_CHANGED: &'static str = "RC.GV.RULESET.CHANGED";
            pub const GV_GRAPH_TRIMMED: &'static str = "RC.GV.GRAPH.TRIMMED";
            pub const RE_REPLAY_MISMATCH: &'static str = "RC.RE.REPLAY.MISMATCH";
            pub const RE_REPLAY_PLAN_REF_MISSING: &'static str = "RC.RE.REPLAY.PLAN_REF_MISSING";
            pub const RE_REPLAY_PLAN_MISSING: &'static str = "RC.RE.REPLAY.PLAN_MISSING";
            pub const RE_REPLAY_INVALID_EMBEDDED_ACTION: &'static str =
                "RC.RE.REPLAY.INVALID_EMBEDDED_ACTION";
            pub const RE_INTEGRITY_OK: &'static str = "RC.RE.INTEGRITY.OK";
            pub const CD_DLP_EXPORT_BLOCKED: &'static str = "RC.CD.DLP.EXPORT_BLOCKED";
            pub const CD_DLP_SECRET_PATTERN: &'static str = "RC.CD.DLP.SECRET_PATTERN";
        }

        #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Enumeration)]
        #[repr(i32)]
        pub enum DlpDecisionForm {
            Unspecified = 0,
            Allow = 1,
            Redact = 2,
            Block = 3,
            Hold = 4,
        }

        #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
        #[derive(Clone, PartialEq, Eq, Message)]
        pub struct DlpDecision {
            #[prost(bytes = "vec", optional, tag = "1")]
            pub dlp_decision_digest: Option<Vec<u8>>,
            #[prost(enumeration = "DlpDecisionForm", tag = "2")]
            pub decision_form: i32,
            #[prost(string, repeated, tag = "3")]
            pub reason_codes: Vec<String>,
        }

        /// Lightweight reference type for future graph links.
        #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
        #[derive(Clone, PartialEq, Eq, Message)]
        pub struct Ref {
            #[prost(string, tag = "1")]
            pub id: String,
        }

        /// Integrity classifications for RSV state.
        #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum IntegrityState {
            Pass,
            Fail,
        }

        /// Rolling receipt statistics reported by the client.
        #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct ReceiptStats {
            pub receipt_missing_count: u32,
            pub receipt_invalid_count: u32,
        }

        /// A signal frame emitted by the client with optional receipt stats.
        #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct SignalFrame {
            pub integrity: IntegrityState,
            pub receipt_stats: Option<ReceiptStats>,
        }

        #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Enumeration)]
        #[repr(i32)]
        pub enum RecordType {
            Unspecified = 0,
            RtActionExec = 1,
            RtOutput = 2,
            RtPerception = 3,
            RtDecision = 4,
            RtReplay = 5,
        }

        #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
        #[derive(Clone, PartialEq, Eq, Message)]
        pub struct CoreFrame {
            #[prost(message, repeated, tag = "1")]
            pub evidence_refs: Vec<Ref>,
        }

        #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
        #[derive(Clone, PartialEq, Eq, Message)]
        pub struct MetabolicFrame {
            #[prost(bytes = "vec", optional, tag = "1")]
            pub profile_digest: Option<Vec<u8>>,
            #[prost(message, repeated, tag = "2")]
            pub outcome_refs: Vec<Ref>,
        }

        #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
        #[derive(Clone, PartialEq, Eq, Message)]
        pub struct GovernanceFrame {
            #[prost(message, repeated, tag = "1")]
            pub policy_decision_refs: Vec<Ref>,
            #[prost(message, optional, tag = "2")]
            pub pvgs_receipt_ref: Option<Ref>,
            #[prost(message, repeated, tag = "3")]
            pub dlp_refs: Vec<Ref>,
        }

        #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Enumeration)]
        #[repr(i32)]
        pub enum ReplayTargetKind {
            Unspecified = 0,
            Micro = 1,
            Meso = 2,
            Macro = 3,
        }

        #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Enumeration)]
        #[repr(i32)]
        pub enum ReplayFidelity {
            Low = 0,
            Med = 1,
            High = 2,
        }

        #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Enumeration)]
        #[repr(i32)]
        pub enum ReplayInjectMode {
            Unspecified = 0,
            InjectDmnSimulate = 1,
        }

        #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
        #[derive(Clone, PartialEq, Eq, Message)]
        pub struct ReplayPlan {
            #[prost(string, tag = "1")]
            pub replay_id: String,
            #[prost(bytes = "vec", tag = "2")]
            pub replay_digest: Vec<u8>,
            #[prost(string, tag = "3")]
            pub session_id: String,
            #[prost(bytes = "vec", tag = "4")]
            pub head_record_digest: Vec<u8>,
            #[prost(enumeration = "ReplayTargetKind", tag = "5")]
            pub target_kind: i32,
            #[prost(message, repeated, tag = "6")]
            pub target_refs: Vec<Ref>,
            #[prost(enumeration = "ReplayFidelity", tag = "7")]
            pub fidelity: i32,
            #[prost(enumeration = "ReplayInjectMode", tag = "8")]
            pub inject_mode: i32,
            #[prost(enumeration = "MagnitudeClass", tag = "9")]
            pub max_steps_class: i32,
            #[prost(enumeration = "MagnitudeClass", tag = "10")]
            pub max_budget_class: i32,
            #[prost(bool, tag = "11")]
            pub stop_on_dlp_flag: bool,
            #[prost(message, optional, tag = "12")]
            pub proof_receipt_ref: Option<Ref>,
            #[prost(bool, tag = "13")]
            pub consumed: bool,
            #[prost(string, repeated, tag = "14")]
            pub trigger_reason_codes: Vec<String>,
        }

        #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
        #[derive(Clone, PartialEq, Eq, Message)]
        pub struct FinalizationHeader {
            #[prost(uint64, tag = "1")]
            pub experience_id: u64,
            #[prost(uint64, tag = "2")]
            pub timestamp_ms: u64,
            #[prost(bytes = "vec", tag = "3")]
            pub prev_record_digest: Vec<u8>,
            #[prost(bytes = "vec", tag = "4")]
            pub record_digest: Vec<u8>,
            #[prost(string, tag = "5")]
            pub charter_version_digest: String,
            #[prost(string, tag = "6")]
            pub policy_version_digest: String,
            #[prost(uint64, tag = "7")]
            pub key_epoch_id: u64,
            #[prost(message, optional, tag = "8")]
            pub proof_receipt_ref: Option<Ref>,
        }

        #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
        #[derive(Clone, PartialEq, Eq, Message)]
        pub struct ExperienceRecord {
            #[prost(enumeration = "RecordType", tag = "1")]
            pub record_type: i32,
            #[prost(message, optional, tag = "2")]
            pub core_frame: Option<CoreFrame>,
            #[prost(message, optional, tag = "3")]
            pub metabolic_frame: Option<MetabolicFrame>,
            #[prost(message, optional, tag = "4")]
            pub governance_frame: Option<GovernanceFrame>,
            #[prost(message, optional, tag = "5")]
            pub core_frame_ref: Option<Ref>,
            #[prost(message, optional, tag = "6")]
            pub metabolic_frame_ref: Option<Ref>,
            #[prost(message, optional, tag = "7")]
            pub governance_frame_ref: Option<Ref>,
            #[prost(message, repeated, tag = "8")]
            pub dlp_refs: Vec<Ref>,
            #[prost(message, optional, tag = "9")]
            pub finalization_header: Option<FinalizationHeader>,
        }
    }
}
