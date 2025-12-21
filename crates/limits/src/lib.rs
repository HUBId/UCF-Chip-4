#![forbid(unsafe_code)]

/// Default, shareable size limits for PVGS in-memory stores.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreLimits {
    /// Number of consistency signals retained per session when deriving replay triggers.
    pub consistency_signal_window: usize,
    /// Maximum consistency history entries kept before older entries are discarded.
    pub consistency_history_max: usize,
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
}

/// Default limits used throughout the PVGS components.
pub const DEFAULT_LIMITS: StoreLimits = StoreLimits {
    consistency_signal_window: 8,
    consistency_history_max: 256,
    max_graph_edges_per_node: 128,
    max_replay_plans: 128,
    max_replay_target_refs: 16,
    max_pending_replay_plans: 128,
    max_experience_records: 4096,
    max_sep_events: 4096,
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
