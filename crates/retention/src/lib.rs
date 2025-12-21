#![forbid(unsafe_code)]

/// Summary statistics about the current state of a store used for retention
/// decisions.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct StoreStats {
    /// Number of items currently held in memory.
    pub in_memory_items: usize,
    /// Number of persisted items on disk or other durable storage.
    pub persisted_items: usize,
}

/// A plan describing which items should be removed from a store.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RetentionPlan {
    /// Identifiers for in-memory entries scheduled for eviction.
    pub in_memory_evictions: Vec<String>,
    /// Identifiers for durable entries scheduled for cleanup.
    ///
    /// TODO: Extend this to support richer persistent retention strategies,
    /// such as size-based pruning or tiered archival.
    pub persistent_evictions: Vec<String>,
}

/// Strategy interface for deriving and applying retention plans.
pub trait RetentionPolicy {
    /// Build a plan for which items should be removed given the current store
    /// statistics.
    fn plan(&self, stats: &StoreStats) -> RetentionPlan;

    /// Apply a retention plan to the underlying store implementation.
    ///
    /// TODO: Provide hooks for durable state updates when implementing
    /// persistent policies.
    fn apply(&self, plan: &RetentionPlan);
}

/// A retention policy that intentionally leaves all entries untouched.
#[derive(Debug, Default)]
pub struct NoOpRetentionPolicy;

impl RetentionPolicy for NoOpRetentionPolicy {
    fn plan(&self, _stats: &StoreStats) -> RetentionPlan {
        RetentionPlan::default()
    }

    fn apply(&self, _plan: &RetentionPlan) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_returns_empty_plan() {
        let policy = NoOpRetentionPolicy;
        let plan = policy.plan(&StoreStats::default());

        assert!(plan.in_memory_evictions.is_empty());
        assert!(plan.persistent_evictions.is_empty());
    }

    #[test]
    fn noop_apply_is_noop() {
        let policy = NoOpRetentionPolicy;
        let plan = RetentionPlan {
            in_memory_evictions: vec!["a".into(), "b".into()],
            persistent_evictions: vec!["c".into()],
        };

        policy.apply(&plan);
    }
}
