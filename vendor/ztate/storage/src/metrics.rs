use std::sync::Arc;
use std::time::Duration;

/// Outcome reported when flushing write-ahead data to storage.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum WalFlushOutcome {
    /// Flush completed successfully without requiring retries.
    Success,
    /// Flush completed successfully but required a retry.
    Retried,
    /// Flush failed.
    Failed,
}

/// Facade used by the storage layer to emit metrics.
pub trait StorageMetrics: Send + Sync {
    /// Record the duration of a header flush attempt.
    fn record_header_flush_duration(&self, _duration: Duration) {}

    /// Record the size of a header flush.
    fn record_header_flush_bytes(&self, _bytes: u64) {}

    /// Increment the counter tracking header flush attempts.
    fn increment_header_flushes(&self) {}

    /// Record the duration of a WAL flush attempt.
    fn record_wal_flush_duration(&self, _outcome: WalFlushOutcome, _duration: Duration) {}

    /// Record the number of bytes flushed to the WAL.
    fn record_wal_flush_bytes(&self, _outcome: WalFlushOutcome, _bytes: u64) {}

    /// Increment the counter tracking WAL flush attempts for the provided outcome.
    fn increment_wal_flushes(&self, _outcome: WalFlushOutcome) {}
}

#[derive(Debug, Default)]
struct NoopStorageMetrics;

impl StorageMetrics for NoopStorageMetrics {}

/// Shared metrics handle used by the storage layer.
pub type StorageMetricsHandle = Arc<dyn StorageMetrics>;

/// Returns a metrics handle that ignores all observations.
pub fn noop() -> StorageMetricsHandle {
    Arc::new(NoopStorageMetrics)
}
