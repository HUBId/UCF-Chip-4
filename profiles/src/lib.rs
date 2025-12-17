#![forbid(unsafe_code)]

use engine::{ControlFrame, Profile};
use rsv::{LevelClass, RsvState};
use ucf_protocol::ucf::v1::{IntegrityState, ReasonCodes};

/// Compute the decision control frame from RSV state.
pub fn decide(rsv: &RsvState, now_ms: u64) -> ControlFrame {
    let mut control_frame = ControlFrame {
        created_at_ms: now_ms,
        ..ControlFrame::default()
    };

    if matches!(rsv.integrity, IntegrityState::Fail) {
        control_frame.profile = Profile::M3KillSwitch;
        control_frame
            .profile_reason_codes
            .push(ReasonCodes::RE_INTEGRITY_DEGRADED.to_string());
        return control_frame;
    }

    if matches!(rsv.receipt_failures, LevelClass::Med | LevelClass::High) {
        tighten_for_receipts(&mut control_frame, rsv);
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use engine::Overlays;
    use rsv::LevelClass;
    use ucf_protocol::ucf::v1::{ReceiptStats, SignalFrame};

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
        let control = decide(&rsv, 100);

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

        let control = decide(&rsv, 5);

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

        let control = decide(&rsv, 10);

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
        let mut rsv = RsvState::default();
        rsv.integrity = IntegrityState::Fail;
        rsv.receipt_failures = LevelClass::High;

        let control = decide(&rsv, 1);

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

        let control = decide(&rsv, 2);

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

        let cf_a = decide(&rsv_a, 99);
        let cf_b = decide(&rsv_b, 99);

        assert_eq!(cf_a.digest(), cf_b.digest());
    }
}
