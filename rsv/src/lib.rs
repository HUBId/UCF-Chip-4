#![forbid(unsafe_code)]

use ucf_protocol::ucf::v1::{IntegrityState, ReceiptStats, SignalFrame};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// A three-level classification used by RSV.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LevelClass {
    Low,
    Med,
    High,
}

/// Rolling RSV state derived from the latest signal frame.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsvState {
    pub integrity: IntegrityState,
    pub receipt_failures: LevelClass,
    pub receipt_missing_count_window: u32,
    pub receipt_invalid_count_window: u32,
}

impl Default for RsvState {
    fn default() -> Self {
        Self {
            integrity: IntegrityState::Pass,
            receipt_failures: LevelClass::Low,
            receipt_missing_count_window: 0,
            receipt_invalid_count_window: 0,
        }
    }
}

impl RsvState {
    /// Update the RSV state from an incoming signal frame.
    pub fn update_from_signal_frame(&mut self, signal: &SignalFrame) {
        self.integrity = signal.integrity;

        if let Some(receipt_stats) = &signal.receipt_stats {
            self.apply_receipt_stats(receipt_stats);
        } else {
            self.receipt_failures = LevelClass::Low;
            self.receipt_missing_count_window = 0;
            self.receipt_invalid_count_window = 0;
        }
    }

    fn apply_receipt_stats(&mut self, receipt_stats: &ReceiptStats) {
        self.receipt_missing_count_window = receipt_stats.receipt_missing_count;
        self.receipt_invalid_count_window = receipt_stats.receipt_invalid_count;

        self.receipt_failures = if receipt_stats.receipt_invalid_count >= 1
            || receipt_stats.receipt_missing_count >= 2
        {
            LevelClass::High
        } else if receipt_stats.receipt_missing_count == 1 {
            LevelClass::Med
        } else {
            LevelClass::Low
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signal(receipt_stats: Option<ReceiptStats>) -> SignalFrame {
        SignalFrame {
            integrity: IntegrityState::Pass,
            receipt_stats,
        }
    }

    #[test]
    fn defaults_to_low_when_missing() {
        let mut state = RsvState::default();
        state.update_from_signal_frame(&signal(None));

        assert_eq!(state.receipt_failures, LevelClass::Low);
        assert_eq!(state.receipt_missing_count_window, 0);
        assert_eq!(state.receipt_invalid_count_window, 0);
    }

    #[test]
    fn missing_one_sets_med() {
        let mut state = RsvState::default();
        state.update_from_signal_frame(&signal(Some(ReceiptStats {
            receipt_missing_count: 1,
            receipt_invalid_count: 0,
        })));

        assert_eq!(state.receipt_failures, LevelClass::Med);
        assert_eq!(state.receipt_missing_count_window, 1);
        assert_eq!(state.receipt_invalid_count_window, 0);
    }

    #[test]
    fn missing_two_sets_high() {
        let mut state = RsvState::default();
        state.update_from_signal_frame(&signal(Some(ReceiptStats {
            receipt_missing_count: 2,
            receipt_invalid_count: 0,
        })));

        assert_eq!(state.receipt_failures, LevelClass::High);
    }

    #[test]
    fn invalid_any_sets_high() {
        let mut state = RsvState::default();
        state.update_from_signal_frame(&signal(Some(ReceiptStats {
            receipt_missing_count: 0,
            receipt_invalid_count: 1,
        })));

        assert_eq!(state.receipt_failures, LevelClass::High);
        assert_eq!(state.receipt_missing_count_window, 0);
        assert_eq!(state.receipt_invalid_count_window, 1);
    }
}
