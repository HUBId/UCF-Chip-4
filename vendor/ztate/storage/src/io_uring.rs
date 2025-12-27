use std::num::NonZero;

#[cfg(feature = "io-uring")]
use io_uring::{cqueue, squeue};

/// Environment variable that forces io-uring to be treated as unsupported.
///
/// This is primarily intended for tests and diagnostics so that capability
/// handling paths can be exercised without requiring a kernel downgrade.
pub const IO_URING_FORCE_UNSUPPORTED_ENV: &str = "FIREWOOD_IO_URING_FORCE_UNSUPPORTED";

/// Runtime capability detection result for io-uring.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IoUringCapability {
    /// io-uring is available and may be initialised.
    Supported,
    /// io-uring is unavailable because the binary or platform disables it.
    Disabled {
        /// Explanation describing why io-uring support is disabled.
        reason: String,
    },
    /// io-uring initialisation is expected to fail on this kernel.
    Unsupported {
        /// Kernel or permission error that prevents initialising io-uring.
        reason: String,
    },
}

/// Detect whether io-uring is usable on the current host.
///
/// When compiled with the `io-uring` feature this attempts to build a ring using
/// the same parameters as the storage backend. Failures are reported with a
/// descriptive reason so callers can surface actionable errors. On builds
/// without the feature the detection reports a disabled capability so higher
/// layers can fall back to the synchronous storage backend.
///
/// Set [`IO_URING_FORCE_UNSUPPORTED_ENV`] to force an unsupported result, which
/// is useful for testing warning and error handling on kernels that would
/// normally pass this probe.
pub fn detect_io_uring_capability(entries: NonZero<u32>) -> IoUringCapability {
    if std::env::var_os(IO_URING_FORCE_UNSUPPORTED_ENV).is_some() {
        return IoUringCapability::Unsupported {
            reason: format!("forced via {IO_URING_FORCE_UNSUPPORTED_ENV}"),
        };
    }

    #[cfg(feature = "io-uring")]
    {
        const IDLETIME_MS: u32 = 1000;
        match io_uring::IoUring::<squeue::Entry, cqueue::Entry>::builder()
            .dontfork()
            .setup_single_issuer()
            .setup_cqsize(entries.get() * 2)
            .setup_sqpoll(IDLETIME_MS)
            .build(entries.get())
        {
            Ok(_) => IoUringCapability::Supported,
            Err(error) => IoUringCapability::Unsupported {
                reason: format!("io-uring initialisation failed: {error}"),
            },
        }
    }

    #[cfg(not(feature = "io-uring"))]
    {
        let _ = entries;
        IoUringCapability::Disabled {
            reason:
                "binary compiled without io-uring support; falling back to synchronous file I/O"
                    .to_string(),
        }
    }
}
