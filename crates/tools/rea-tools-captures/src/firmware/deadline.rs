//! One operation-scoped deadline combined with the caller cancellation.
//!
//! Compatibility owner: the `deadline`/`signal` composition in
//! `src/firmware/FirmwareProvider.ts#execute`. The TypeScript provider builds a
//! single `AbortSignal.timeout(FIRMWARE_LIMITS.timeoutMs)` at the start of the
//! operation and combines it with the caller signal via
//! `AbortSignal.any([options.signal, deadline])`. That one composite signal is
//! threaded through command launches, the private snapshot, the output
//! inventory and publication, so the whole operation shares a single deadline
//! rather than restarting the budget for each launched command. When the
//! deadline fires, `firmwareFailure`/`firmwareCancellation` reclassify the
//! resulting cancellation as `AnalysisTimeoutError`.
use super::release::FIRMWARE_LIMITS;
use rea_core::analysis_error::AnalysisError;
use rea_core::cancellation::Cancellation;
use std::time::Instant;

/// A single operation-wide deadline plus the caller cancellation it is combined
/// with. Captured once when the operation begins and shared by every phase.
pub struct OperationDeadline<'a> {
    cancellation: &'a Cancellation,
    deadline: Instant,
}

impl<'a> OperationDeadline<'a> {
    /// Start the operation deadline now (mirrors `AbortSignal.timeout` created
    /// at the top of `#execute`).
    pub fn start(cancellation: &'a Cancellation) -> Self {
        Self {
            cancellation,
            deadline: Instant::now() + std::time::Duration::from_millis(FIRMWARE_LIMITS.timeout_ms),
        }
    }

    /// The caller cancellation this deadline is combined with.
    pub fn cancellation(&self) -> &'a Cancellation {
        self.cancellation
    }

    /// Whether the operation deadline has elapsed.
    pub fn expired(&self) -> bool {
        Instant::now() >= self.deadline
    }

    /// The interruption observed at a phase boundary, if any.
    ///
    /// `AbortSignal.any` resolves to whichever source aborted first. The caller
    /// `Cancellation` carries no timestamp, so an explicitly recorded caller
    /// reason is treated as the winner; only when the caller has not cancelled
    /// does an elapsed deadline surface as a timeout. Both branches match the
    /// observable `AnalysisCancelledError`/`AnalysisTimeoutError` the provider
    /// produces for each source.
    pub fn interruption(&self, operation: &str) -> Option<AnalysisError> {
        if self.cancellation.reason().is_some() {
            return Some(AnalysisError::cancelled(operation));
        }
        if self.expired() {
            return Some(AnalysisError::timeout(
                operation,
                FIRMWARE_LIMITS.timeout_ms,
            ));
        }
        None
    }
}
