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

        /// Reason code constants for PVGS and SEP operations.
        pub struct ReasonCodes;

        impl ReasonCodes {
            pub const RE_INTEGRITY_DEGRADED: &'static str = "RC.RE.INTEGRITY.DEGRADED";
            pub const GE_EXEC_DISPATCH_BLOCKED: &'static str = "RC.GE.EXEC.DISPATCH_BLOCKED";
            pub const PB_DENY_CHARTER_SCOPE: &'static str = "RC.PB.DENY.CHARTER_SCOPE";
            pub const PB_DENY_INTEGRITY_REQUIRED: &'static str = "RC.PB.DENY.INTEGRITY_REQUIRED";
            pub const GE_GRANT_MISSING: &'static str = "RC.GE.GRANT.MISSING";
        }

        /// Lightweight reference type for future graph links.
        #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct Ref {
            pub id: String,
        }
    }
}
