#![forbid(unsafe_code)]

use engine::{ApprovalMode, ControlFrame, Profile};
use pvgs_client::{PvgsClientError, PvgsReader, PvgsWriter};
use rsv::{LevelClass, RsvState};
use ucf_protocol::ucf::v1::{IntegrityState, ReasonCodes};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BaselineContext {
    pub cbv_digest: Option<[u8; 32]>,
    pub pev_digest: Option<[u8; 32]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProfilesConfig {
    pub cbv_influence_enabled: bool,
}

/// Compute the decision control frame from RSV state.
pub fn decide(
    rsv: &RsvState,
    now_ms: u64,
    baseline: BaselineContext,
    config: ProfilesConfig,
) -> ControlFrame {
    let mut control_frame = ControlFrame {
        created_at_ms: now_ms,
        ..ControlFrame::default()
    };

    control_frame.character_epoch_digest = baseline.cbv_digest;
    control_frame.policy_ecology_digest = baseline.pev_digest;

    if matches!(rsv.integrity, IntegrityState::Fail) {
        apply_cbv_bias(&mut control_frame, baseline.cbv_digest, config);
        control_frame.profile = Profile::M3KillSwitch;
        control_frame
            .profile_reason_codes
            .push(ReasonCodes::RE_INTEGRITY_DEGRADED.to_string());
        return control_frame;
    }

    if matches!(rsv.receipt_failures, LevelClass::Med | LevelClass::High) {
        tighten_for_receipts(&mut control_frame, rsv);
    }

    apply_cbv_bias(&mut control_frame, baseline.cbv_digest, config);

    control_frame
}

fn tighten_for_receipts(control_frame: &mut ControlFrame, rsv: &RsvState) {
    control_frame.profile = Profile::M1Restricted;
    control_frame.overlays.export_lock = true;
    control_frame.overlays.novelty_lock = true;
    control_frame.overlays.simulate_first = true;
    control_frame.overlays.deescalation_lock = true;

    control_frame
        .profile_reason_codes
        .push(ReasonCodes::GE_EXEC_DISPATCH_BLOCKED.to_string());

    if rsv.receipt_invalid_count_window >= 2 {
        control_frame.profile = Profile::M2Quarantine;
    }
}

fn apply_cbv_bias(
    control_frame: &mut ControlFrame,
    cbv_digest: Option<[u8; 32]>,
    config: ProfilesConfig,
) {
    if config.cbv_influence_enabled && cbv_digest.is_some() {
        control_frame.approval_mode = ApprovalMode::Strict;
        control_frame.overlays.novelty_lock = true;
    }
}

/// Produce a control frame and optionally commit evidence via PVGS.
pub fn decide_with_writer<W: PvgsWriter>(
    rsv: &RsvState,
    now_ms: u64,
    baseline: BaselineContext,
    config: ProfilesConfig,
    session_id: &str,
    writer: &mut W,
) -> Result<ControlFrame, PvgsClientError> {
    let control_frame = decide(rsv, now_ms, baseline, config);
    writer.commit_control_frame_evidence(session_id, control_frame.digest())?;
    Ok(control_frame)
}

/// Convenience helper that pulls CBV/PEV digests from a PVGS reader.
pub fn decide_from_reader<R: PvgsReader>(
    rsv: &RsvState,
    now_ms: u64,
    reader: &R,
    config: ProfilesConfig,
) -> ControlFrame {
    let baseline = BaselineContext {
        cbv_digest: reader.get_latest_cbv_digest(),
        pev_digest: reader.get_latest_pev_digest(),
    };

    decide(rsv, now_ms, baseline, config)
}

/// Convenience helper that also commits control frame evidence when a writer is available.
pub fn decide_from_reader_with_writer<R: PvgsReader, W: PvgsWriter>(
    rsv: &RsvState,
    now_ms: u64,
    reader: &R,
    config: ProfilesConfig,
    session_id: &str,
    writer: &mut W,
) -> Result<ControlFrame, PvgsClientError> {
    let baseline = BaselineContext {
        cbv_digest: reader.get_latest_cbv_digest(),
        pev_digest: reader.get_latest_pev_digest(),
    };

    decide_with_writer(rsv, now_ms, baseline, config, session_id, writer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine::Overlays;
    use pvgs_client::MockPvgsReader;
    use rsv::LevelClass;
    use std::cell::RefCell;
    use ucf_protocol::ucf::v1::{ReceiptStats, SignalFrame};

    const BASELINE_DEFAULT: BaselineContext = BaselineContext {
        cbv_digest: None,
        pev_digest: None,
    };
    const CONFIG_DEFAULT: ProfilesConfig = ProfilesConfig {
        cbv_influence_enabled: false,
    };

    fn rsv_from(signal: SignalFrame) -> RsvState {
        let mut rsv = RsvState::default();
        rsv.update_from_signal_frame(&signal);
        rsv
    }

    fn default_signal() -> SignalFrame {
        SignalFrame {
            integrity: IntegrityState::Pass,
            receipt_stats: None,
        }
    }

    #[test]
    fn no_receipt_stats_keeps_m0() {
        let rsv = rsv_from(default_signal());
        let control = decide(&rsv, 100, BASELINE_DEFAULT, CONFIG_DEFAULT);

        assert_eq!(control.profile, Profile::M0);
        assert_eq!(control.overlays, Overlays::default());
        assert!(control.profile_reason_codes.is_empty());
    }

    #[test]
    fn missing_receipt_triggers_tightening() {
        let rsv = rsv_from(SignalFrame {
            integrity: IntegrityState::Pass,
            receipt_stats: Some(ReceiptStats {
                receipt_missing_count: 1,
                receipt_invalid_count: 0,
            }),
        });

        assert_eq!(rsv.receipt_failures, LevelClass::Med);

        let control = decide(&rsv, 5, BASELINE_DEFAULT, CONFIG_DEFAULT);

        assert_eq!(control.profile, Profile::M1Restricted);
        assert!(control.overlays.export_lock);
        assert!(control.overlays.novelty_lock);
        assert!(control.overlays.simulate_first);
        assert!(control.overlays.deescalation_lock);
        assert_eq!(
            control.profile_reason_codes,
            vec![ReasonCodes::GE_EXEC_DISPATCH_BLOCKED.to_string()]
        );
    }

    #[test]
    fn invalid_receipt_triggers_tightening() {
        let rsv = rsv_from(SignalFrame {
            integrity: IntegrityState::Pass,
            receipt_stats: Some(ReceiptStats {
                receipt_missing_count: 0,
                receipt_invalid_count: 1,
            }),
        });

        assert_eq!(rsv.receipt_failures, LevelClass::High);

        let control = decide(&rsv, 10, BASELINE_DEFAULT, CONFIG_DEFAULT);

        assert_eq!(control.profile, Profile::M1Restricted);
        assert!(control.overlays.export_lock);
        assert!(control.overlays.novelty_lock);
        assert!(control.overlays.simulate_first);
        assert!(control.overlays.deescalation_lock);
        assert_eq!(
            control.profile_reason_codes,
            vec![ReasonCodes::GE_EXEC_DISPATCH_BLOCKED.to_string()]
        );
    }

    #[test]
    fn integrity_failure_wins() {
        let rsv = RsvState {
            integrity: IntegrityState::Fail,
            receipt_failures: LevelClass::High,
            ..Default::default()
        };

        let control = decide(&rsv, 1, BASELINE_DEFAULT, CONFIG_DEFAULT);

        assert_eq!(control.profile, Profile::M3KillSwitch);
        assert_eq!(
            control.profile_reason_codes,
            vec![ReasonCodes::RE_INTEGRITY_DEGRADED.to_string()]
        );
    }

    #[test]
    fn invalid_receipts_twice_quarantines() {
        let rsv = rsv_from(SignalFrame {
            integrity: IntegrityState::Pass,
            receipt_stats: Some(ReceiptStats {
                receipt_missing_count: 0,
                receipt_invalid_count: 2,
            }),
        });

        let control = decide(&rsv, 2, BASELINE_DEFAULT, CONFIG_DEFAULT);

        assert_eq!(control.profile, Profile::M2Quarantine);
        assert!(control.overlays.export_lock);
        assert!(control.overlays.novelty_lock);
        assert!(control.overlays.simulate_first);
        assert!(control.overlays.deescalation_lock);
    }

    #[test]
    fn digest_is_stable_for_same_signal() {
        let signal = SignalFrame {
            integrity: IntegrityState::Pass,
            receipt_stats: Some(ReceiptStats {
                receipt_missing_count: 1,
                receipt_invalid_count: 0,
            }),
        };

        let rsv_a = rsv_from(signal.clone());
        let rsv_b = rsv_from(signal);

        let cf_a = decide(&rsv_a, 99, BASELINE_DEFAULT, CONFIG_DEFAULT);
        let cf_b = decide(&rsv_b, 99, BASELINE_DEFAULT, CONFIG_DEFAULT);

        assert_eq!(cf_a.digest(), cf_b.digest());
    }

    #[test]
    fn cbv_digest_is_embedded_and_changes_digest() {
        let rsv = rsv_from(default_signal());
        let cbv_one = BaselineContext {
            cbv_digest: Some([1u8; 32]),
            pev_digest: None,
        };
        let cbv_two = BaselineContext {
            cbv_digest: Some([2u8; 32]),
            pev_digest: None,
        };

        let control_one = decide(&rsv, 1, cbv_one, CONFIG_DEFAULT);
        let control_two = decide(&rsv, 1, cbv_two, CONFIG_DEFAULT);
        assert_eq!(control_one.character_epoch_digest, cbv_one.cbv_digest);
        assert_ne!(control_one.digest(), control_two.digest());
    }

    #[test]
    fn no_cbv_available_does_not_crash() {
        let rsv = rsv_from(default_signal());
        let control = decide(&rsv, 2, BASELINE_DEFAULT, CONFIG_DEFAULT);

        assert!(control.character_epoch_digest.is_none());
    }

    #[test]
    fn cbv_presence_can_enable_strict_mode() {
        let rsv = rsv_from(default_signal());
        let baseline = BaselineContext {
            cbv_digest: Some([9u8; 32]),
            pev_digest: None,
        };
        let cfg = ProfilesConfig {
            cbv_influence_enabled: true,
        };

        let control = decide(&rsv, 3, baseline, cfg);
        assert_eq!(control.approval_mode, ApprovalMode::Strict);
        assert!(control.overlays.novelty_lock);
    }

    #[test]
    fn digest_remains_deterministic_with_same_inputs() {
        let rsv_a = rsv_from(default_signal());
        let rsv_b = rsv_from(default_signal());
        let baseline = BaselineContext {
            cbv_digest: Some([7u8; 32]),
            pev_digest: Some([8u8; 32]),
        };
        let cfg = ProfilesConfig {
            cbv_influence_enabled: true,
        };

        let cf_a = decide(&rsv_a, 77, baseline, cfg);
        let cf_b = decide(&rsv_b, 77, baseline, cfg);

        assert_eq!(cf_a.digest(), cf_b.digest());
    }

    #[test]
    fn pvgs_reader_populates_baseline() {
        let rsv = rsv_from(default_signal());
        let reader = MockPvgsReader::new(Some([3u8; 32]), Some([4u8; 32]), None);

        let control = decide_from_reader(&rsv, 11, &reader, CONFIG_DEFAULT);

        assert_eq!(
            control.character_epoch_digest,
            reader.get_latest_cbv_digest()
        );
        assert_eq!(
            control.policy_ecology_digest,
            reader.get_latest_pev_digest()
        );
    }

    struct RecordingWriter {
        last: RefCell<Vec<(String, [u8; 32])>>,
    }

    impl RecordingWriter {
        fn new() -> Self {
            Self {
                last: RefCell::new(Vec::new()),
            }
        }
    }

    impl PvgsWriter for RecordingWriter {
        fn commit_control_frame_evidence(
            &mut self,
            session_id: &str,
            control_frame_digest: [u8; 32],
        ) -> Result<(), PvgsClientError> {
            self.last
                .borrow_mut()
                .push((session_id.to_string(), control_frame_digest));
            Ok(())
        }
    }

    #[test]
    fn evidence_commit_hook_invoked() {
        let rsv = rsv_from(default_signal());
        let mut writer = RecordingWriter::new();
        let baseline = BaselineContext {
            cbv_digest: Some([5u8; 32]),
            pev_digest: None,
        };
        let cfg = ProfilesConfig {
            cbv_influence_enabled: true,
        };

        let control = decide_with_writer(&rsv, 42, baseline, cfg, "session", &mut writer)
            .expect("commit failed");
        let records = writer.last.borrow();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].0, "session");
        assert_eq!(records[0].1, control.digest());
    }

    #[test]
    fn evidence_commit_works_with_reader_helper() {
        let rsv = rsv_from(default_signal());
        let mut writer = RecordingWriter::new();
        let reader = MockPvgsReader::new(Some([6u8; 32]), None, None);
        let cfg = ProfilesConfig {
            cbv_influence_enabled: true,
        };

        let control =
            decide_from_reader_with_writer(&rsv, 55, &reader, cfg, "session-2", &mut writer)
                .expect("commit failed");

        let records = writer.last.borrow();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].0, "session-2");
        assert_eq!(records[0].1, control.digest());
    }
}
