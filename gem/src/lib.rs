#![forbid(unsafe_code)]

use hex::encode;
use pvgs_client::PvgsWriter;
use std::collections::HashMap;
use ucf_protocol::ucf::v1::{ExperienceRecord, GovernanceFrame, RecordType, Ref};

use prost::Message;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionDisposition {
    Allow,
    Deny,
    ApprovalRequired,
    SimulationRequired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDecision {
    pub decision_id: String,
    pub decision_digest: [u8; 32],
    pub policy_query_digest: [u8; 32],
    pub ruleset_digest: Option<[u8; 32]>,
    pub reason_codes: Vec<String>,
    pub disposition: DecisionDisposition,
}

impl PolicyDecision {
    fn sorted_reasons(&self) -> Vec<String> {
        let mut reasons = self.reason_codes.clone();
        reasons.sort();
        reasons
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionContext<'a> {
    pub session_id: &'a str,
    pub step_id: &'a str,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SignalFrameAggregator {
    pub integrity_degraded_reasons: Vec<String>,
    pub deny_count: u64,
    pub top_reason_codes: Vec<String>,
}

impl SignalFrameAggregator {
    pub fn record_integrity_degraded(&mut self, reason: String) {
        self.integrity_degraded_reasons.push(reason);
    }

    fn update_top_reasons(&mut self, reasons: &[String]) {
        let mut counts: HashMap<String, u64> = self
            .top_reason_codes
            .iter()
            .cloned()
            .map(|code| (code, 1))
            .collect();

        for reason in reasons {
            *counts.entry(reason.clone()).or_default() += 1;
        }

        let mut deduped: Vec<_> = counts.into_iter().collect();
        deduped.sort_by(|(a_code, a_count), (b_code, b_count)| {
            b_count.cmp(a_count).then_with(|| a_code.cmp(b_code))
        });

        self.top_reason_codes = deduped.into_iter().map(|(code, _)| code).collect();
    }

    pub fn record_deny(&mut self, reasons: &[String]) {
        self.deny_count += 1;
        self.update_top_reasons(reasons);
    }
}

pub trait DecisionAdapter {
    fn on_allow(&mut self, decision: &PolicyDecision);
}

pub fn build_decision_record(decision: &PolicyDecision, ctx: &DecisionContext) -> ExperienceRecord {
    let mut related_refs = vec![
        Ref {
            id: encode(decision.policy_query_digest),
            digest: None,
        },
        Ref {
            id: encode(decision.decision_digest),
            digest: None,
        },
    ];

    if let Some(ruleset) = decision.ruleset_digest {
        related_refs.push(Ref {
            id: encode(ruleset),
            digest: None,
        });
    }

    ExperienceRecord {
        record_type: RecordType::RtDecision as i32,
        core_frame: None,
        metabolic_frame: None,
        governance_frame: Some(GovernanceFrame {
            policy_decision_refs: related_refs.clone(),
            pvgs_receipt_ref: None,
            dlp_refs: Vec::new(),
        }),
        core_frame_ref: Some(Ref {
            id: format!("{}:{}", ctx.session_id, ctx.step_id),
            digest: None,
        }),
        metabolic_frame_ref: None,
        governance_frame_ref: Some(Ref {
            id: encode(decision.decision_digest),
            digest: None,
        }),
        dlp_refs: Vec::new(),
        finalization_header: None,
    }
}

pub fn encode_record(record: &ExperienceRecord) -> Vec<u8> {
    let mut buf = Vec::new();
    record
        .encode(&mut buf)
        .expect("failed to encode experience record");
    buf
}

pub fn process_policy_decision<W: PvgsWriter, A: DecisionAdapter>(
    writer: &mut W,
    adapter: &mut A,
    ctx: &DecisionContext,
    decision: &PolicyDecision,
    aggregator: &mut SignalFrameAggregator,
) {
    let record = build_decision_record(decision, ctx);
    if let Err(err) = writer.commit_experience_record(&record) {
        aggregator.record_integrity_degraded(err.to_string());
    }

    if matches!(decision.disposition, DecisionDisposition::Deny) {
        aggregator.record_deny(&decision.sorted_reasons());
        return;
    }

    adapter.on_allow(decision);
}

#[cfg(test)]
mod tests {
    use super::*;
    use once_cell::sync::Lazy;
    use pvgs_client::{MockPvgsWriter, PvgsClientError};

    static DECISION_DIGEST: Lazy<[u8; 32]> = Lazy::new(|| [1u8; 32]);
    static POLICY_QUERY_DIGEST: Lazy<[u8; 32]> = Lazy::new(|| [2u8; 32]);
    static RULESET_DIGEST: Lazy<[u8; 32]> = Lazy::new(|| [3u8; 32]);

    #[derive(Default)]
    struct CountingAdapter {
        pub calls: usize,
    }

    impl DecisionAdapter for CountingAdapter {
        fn on_allow(&mut self, _decision: &PolicyDecision) {
            self.calls += 1;
        }
    }

    fn make_decision(disposition: DecisionDisposition) -> PolicyDecision {
        PolicyDecision {
            decision_id: "d-1".into(),
            decision_digest: *DECISION_DIGEST,
            policy_query_digest: *POLICY_QUERY_DIGEST,
            ruleset_digest: Some(*RULESET_DIGEST),
            reason_codes: vec!["RC_B".into(), "RC_A".into()],
            disposition,
        }
    }

    fn ctx() -> DecisionContext<'static> {
        DecisionContext {
            session_id: "s1",
            step_id: "step-1",
        }
    }

    #[test]
    fn commits_rt_decision_on_allow() {
        let mut writer = MockPvgsWriter::default();
        let mut adapter = CountingAdapter::default();
        let mut aggregator = SignalFrameAggregator::default();
        let decision = make_decision(DecisionDisposition::Allow);

        process_policy_decision(
            &mut writer,
            &mut adapter,
            &ctx(),
            &decision,
            &mut aggregator,
        );

        let records = writer.experience_records.borrow();
        assert_eq!(records.len(), 1);
        assert_eq!(adapter.calls, 1);
        assert_eq!(aggregator.deny_count, 0);

        let record = &records[0];
        assert_eq!(record.record_type, RecordType::RtDecision as i32);
        let gov = record.governance_frame.as_ref().expect("governance frame");
        assert_eq!(gov.policy_decision_refs.len(), 3);
        assert_eq!(gov.policy_decision_refs[0].id, encode(*POLICY_QUERY_DIGEST));
        assert_eq!(gov.policy_decision_refs[1].id, encode(*DECISION_DIGEST));
    }

    #[test]
    fn commits_rt_decision_on_deny_and_skips_adapter() {
        let mut writer = MockPvgsWriter::default();
        let mut adapter = CountingAdapter::default();
        let mut aggregator = SignalFrameAggregator::default();
        let decision = make_decision(DecisionDisposition::Deny);

        process_policy_decision(
            &mut writer,
            &mut adapter,
            &ctx(),
            &decision,
            &mut aggregator,
        );

        let records = writer.experience_records.borrow();
        assert_eq!(records.len(), 1);
        assert_eq!(adapter.calls, 0);
        assert_eq!(aggregator.deny_count, 1);
        assert_eq!(
            aggregator.top_reason_codes,
            vec!["RC_A".to_string(), "RC_B".to_string()]
        );

        let record = &records[0];
        let gov = record.governance_frame.as_ref().expect("governance frame");
        assert_eq!(gov.policy_decision_refs[0].id, encode(*POLICY_QUERY_DIGEST));
    }

    #[test]
    fn decision_record_bytes_are_deterministic() {
        let decision = make_decision(DecisionDisposition::ApprovalRequired);
        let record_a = build_decision_record(&decision, &ctx());
        let record_b = build_decision_record(&decision, &ctx());

        assert_eq!(encode_record(&record_a), encode_record(&record_b));
    }

    #[test]
    fn logs_integrity_when_commit_fails() {
        let mut writer =
            MockPvgsWriter::with_experience_error(PvgsClientError::Commit("nope".into()));
        let mut adapter = CountingAdapter::default();
        let mut aggregator = SignalFrameAggregator::default();
        let decision = make_decision(DecisionDisposition::Allow);

        process_policy_decision(
            &mut writer,
            &mut adapter,
            &ctx(),
            &decision,
            &mut aggregator,
        );

        assert!(writer.experience_records.borrow().is_empty());
        assert_eq!(adapter.calls, 1);
        assert_eq!(
            aggregator.integrity_degraded_reasons,
            vec!["commit failed: nope"]
        );
    }
}
