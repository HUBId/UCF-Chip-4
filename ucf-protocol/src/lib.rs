#![forbid(unsafe_code)]

/// Protocol-level types for UCF interactions.
pub mod ucf {
    pub mod v1 {
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
        }

        /// Commit categories supported by the PVGS.
        #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub enum CommitType {
            ReceiptRequest,
            RecordAppend,
            MilestoneAppend,
            CharterUpdate,
            ToolRegistryUpdate,
            RecoveryUpdate,
            PevUpdate,
            CbvUpdate,
            KeyEpochUpdate,
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
            pub profile_digest: Digest32,
            pub tool_profile_digest: Option<Digest32>,
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

        /// Alias for PVGSKeyEpoch using Rust-style casing.
        pub type PvgsKeyEpoch = PVGSKeyEpoch;

        /// Reason code constants for PVGS and SEP operations.
        pub struct ReasonCodes;

        impl ReasonCodes {
            pub const RE_INTEGRITY_DEGRADED: &'static str = "RC.RE.INTEGRITY.DEGRADED";
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
        }

        /// Lightweight reference type for future graph links.
        #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct Ref {
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
    }
}
