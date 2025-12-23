#![forbid(unsafe_code)]

/// Default, shareable size limits for PVGS in-memory stores.
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreLimits {
    /// Number of consistency signals retained per session when deriving replay triggers.
    pub consistency_signal_window: usize,
    /// Maximum consistency history entries kept before older entries are discarded.
    pub consistency_history_max: usize,
    /// Maximum Character Baseline Vectors retained in memory.
    pub max_cbvs: usize,
    /// Maximum Policy Ecology Vectors retained in memory.
    pub max_pevs: usize,
    /// Maximum Consistency Feedback entries retained in memory.
    pub max_consistency_feedbacks: usize,
    /// Maximum number of causal graph edges retained per node.
    pub max_graph_edges_per_node: usize,
    /// Maximum number of replay plans retained (pending + consumed) before eviction.
    pub max_replay_plans: usize,
    /// Maximum number of replay target references allowed on a plan.
    pub max_replay_target_refs: usize,
    /// Maximum number of pending replay plans that are returned.
    pub max_pending_replay_plans: usize,
    /// Maximum number of experience records retained in memory.
    pub max_experience_records: usize,
    /// Maximum number of SEP events retained in memory.
    pub max_sep_events: usize,
    /// Maximum number of tool onboarding events retained per tool/action index entry.
    pub max_tool_events_per_action: usize,
    /// Maximum reason codes retained on a tool onboarding event.
    pub max_tool_event_reason_codes: usize,
    /// Maximum signatures retained on a tool onboarding event.
    pub max_tool_event_signatures: usize,
}

/// Default limits used throughout the PVGS components.
pub const DEFAULT_LIMITS: StoreLimits = StoreLimits {
    consistency_signal_window: 8,
    consistency_history_max: 256,
    max_cbvs: 1024,
    max_pevs: 1024,
    max_consistency_feedbacks: 4096,
    max_graph_edges_per_node: 128,
    max_replay_plans: 128,
    max_replay_target_refs: 16,
    max_pending_replay_plans: 128,
    max_experience_records: 4096,
    max_sep_events: 4096,
    max_tool_events_per_action: 256,
    max_tool_event_reason_codes: 64,
    max_tool_event_signatures: 16,
};

impl Default for StoreLimits {
    fn default() -> Self {
        default_limits()
    }
}

/// Convenience helper returning the default store limits.
pub const fn default_limits() -> StoreLimits {
    DEFAULT_LIMITS
}
