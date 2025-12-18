#![forbid(unsafe_code)]

use blake3::Hasher;
use ucf_protocol::ucf::v1::ReasonCodes;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Profiles available to the control engine.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    M0,
    M1Restricted,
    M2Quarantine,
    M3KillSwitch,
}

impl Profile {
    fn as_str(&self) -> &'static str {
        match self {
            Profile::M0 => "M0",
            Profile::M1Restricted => "M1_RESTRICTED",
            Profile::M2Quarantine => "M2_QUARANTINE",
            Profile::M3KillSwitch => "M3_KILL_SWITCH",
        }
    }
}

/// Approval mode describing how permissive the control frame is allowed to be.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ApprovalMode {
    #[default]
    Standard,
    Strict,
}

impl ApprovalMode {
    fn as_str(&self) -> &'static str {
        match self {
            ApprovalMode::Standard => "STANDARD",
            ApprovalMode::Strict => "STRICT",
        }
    }
}

/// Overlay toggles applied to outbound control frames.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Overlays {
    pub export_lock: bool,
    pub novelty_lock: bool,
    pub simulate_first: bool,
    pub deescalation_lock: bool,
}

/// Control frame emitted by the decision engine.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlFrame {
    pub profile: Profile,
    pub overlays: Overlays,
    pub approval_mode: ApprovalMode,
    pub character_epoch_digest: Option<[u8; 32]>,
    pub policy_ecology_digest: Option<[u8; 32]>,
    pub profile_reason_codes: Vec<String>,
    pub created_at_ms: u64,
}

impl Default for ControlFrame {
    fn default() -> Self {
        Self {
            profile: Profile::M0,
            overlays: Overlays::default(),
            approval_mode: ApprovalMode::default(),
            character_epoch_digest: None,
            policy_ecology_digest: None,
            profile_reason_codes: Vec::new(),
            created_at_ms: 0,
        }
    }
}

impl ControlFrame {
    /// Compute a deterministic digest over the control frame.
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(b"UCF:HASH:CONTROL_FRAME");
        hasher.update(self.profile.as_str().as_bytes());
        hasher.update(&[u8::from(self.overlays.export_lock)]);
        hasher.update(&[u8::from(self.overlays.novelty_lock)]);
        hasher.update(&[u8::from(self.overlays.simulate_first)]);
        hasher.update(&[u8::from(self.overlays.deescalation_lock)]);
        hasher.update(self.approval_mode.as_str().as_bytes());

        match self.character_epoch_digest {
            Some(digest) => {
                hasher.update(&[1]);
                hasher.update(&digest);
            }
            None => {
                hasher.update(&[0]);
            }
        }

        match self.policy_ecology_digest {
            Some(digest) => {
                hasher.update(&[1]);
                hasher.update(&digest);
            }
            None => {
                hasher.update(&[0]);
            }
        }
        hasher.update(&self.created_at_ms.to_le_bytes());

        let mut rcs = self.profile_reason_codes.clone();
        rcs.sort();
        for rc in rcs {
            hasher.update(rc.as_bytes());
        }

        *hasher.finalize().as_bytes()
    }

    /// Ensure a preferred reason code is included when dispatch is blocked.
    pub fn with_dispatch_blocked_reason(mut self) -> Self {
        if !self
            .profile_reason_codes
            .iter()
            .any(|rc| rc == ReasonCodes::GE_EXEC_DISPATCH_BLOCKED)
        {
            self.profile_reason_codes
                .push(ReasonCodes::GE_EXEC_DISPATCH_BLOCKED.to_string());
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_is_deterministic() {
        let cf1 = ControlFrame {
            profile: Profile::M1Restricted,
            overlays: Overlays {
                export_lock: true,
                novelty_lock: true,
                simulate_first: true,
                deescalation_lock: true,
            },
            approval_mode: ApprovalMode::Strict,
            character_epoch_digest: Some([1u8; 32]),
            policy_ecology_digest: None,
            profile_reason_codes: vec![
                ReasonCodes::GE_EXEC_DISPATCH_BLOCKED.to_string(),
                ReasonCodes::TH_INTEGRITY_COMPROMISE.to_string(),
            ],
            created_at_ms: 99,
        };

        let mut cf2 = cf1.clone();
        cf2.profile_reason_codes.reverse();
        cf2.policy_ecology_digest = Some([2u8; 32]);

        assert_ne!(cf1.digest(), cf2.digest());

        cf2.policy_ecology_digest = None;
        assert_eq!(cf1.digest(), cf2.digest());

        cf2.character_epoch_digest = Some([9u8; 32]);
        assert_ne!(cf1.digest(), cf2.digest());
    }
}
