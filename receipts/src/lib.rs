#![forbid(unsafe_code)]

use pvgs::{compute_receipt_digest, PvgsCommitRequest};
use ucf_protocol::ucf::v1::{
    CommitBindings as ProtoBindings, Digest32, PVGSReceipt, ReceiptStatus,
};

/// Issue a PVGS receipt for a given commit request and status.
///
/// `rcs` must contain at least one entry when the receipt is rejected.
pub fn issue_receipt(
    req: &PvgsCommitRequest,
    status: ReceiptStatus,
    rcs: Vec<&'static str>,
) -> PVGSReceipt {
    let mut reject_reason_codes: Vec<String> = rcs.into_iter().map(|rc| rc.to_string()).collect();

    if matches!(status, ReceiptStatus::Rejected) && reject_reason_codes.is_empty() {
        panic!("rejected receipt must include at least one reason code");
    }

    if matches!(status, ReceiptStatus::Accepted) {
        reject_reason_codes.clear();
    }

    let digest = compute_receipt_digest(req, status, &reject_reason_codes);

    PVGSReceipt {
        commit_id: req.commit_id.clone(),
        commit_type: req.commit_type.into(),
        bindings: ProtoBindings::from(&req.bindings),
        required_checks: req
            .required_checks
            .iter()
            .copied()
            .map(Into::into)
            .collect(),
        payload_digests: req.payload_digests.iter().copied().map(Digest32).collect(),
        epoch_id: req.epoch_id,
        status,
        reject_reason_codes,
        receipt_digest: Digest32(digest),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pvgs::{CommitBindings, CommitType, RequiredCheck};
    use ucf_protocol::ucf::v1::ReasonCodes;

    fn sample_request() -> PvgsCommitRequest {
        PvgsCommitRequest {
            commit_id: "req-1".to_string(),
            commit_type: CommitType::ReceiptRequest,
            bindings: CommitBindings {
                action_digest: Some([1u8; 32]),
                decision_digest: Some([2u8; 32]),
                grant_id: Some("grant".to_string()),
                charter_version_digest: "charter".to_string(),
                policy_version_digest: "policy".to_string(),
                prev_record_digest: [3u8; 32],
                profile_digest: [4u8; 32],
                tool_profile_digest: None,
            },
            required_checks: vec![RequiredCheck::SchemaOk],
            payload_digests: vec![[5u8; 32]],
            epoch_id: 1,
        }
    }

    #[test]
    fn accepted_receipt_has_empty_reasons() {
        let req = sample_request();
        let receipt = issue_receipt(&req, ReceiptStatus::Accepted, Vec::new());
        assert!(receipt.reject_reason_codes.is_empty());
    }

    #[test]
    fn rejected_receipt_requires_reason() {
        let req = sample_request();
        let reason = ReasonCodes::GE_GRANT_MISSING;
        let receipt = issue_receipt(
            &req,
            ReceiptStatus::Rejected,
            vec![reason, ReasonCodes::GE_GRANT_MISSING],
        );
        assert_eq!(receipt.status, ReceiptStatus::Rejected);
        assert_eq!(
            receipt.reject_reason_codes,
            vec![reason.to_string(), reason.to_string()]
        );
    }

    #[test]
    #[should_panic(expected = "rejected receipt must include at least one reason code")]
    fn rejected_without_reason_panics() {
        let req = sample_request();
        let _ = issue_receipt(&req, ReceiptStatus::Rejected, Vec::new());
    }
}
