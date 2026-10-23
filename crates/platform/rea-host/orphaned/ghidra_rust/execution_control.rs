//! Shared interruption and deadline state for a Rust Ghidra operation.
//!
//! The provider performs the polling itself because the host cancellation
//! primitive deliberately has no background thread or timer ownership.  This
//! type keeps the first interruption source stable while a request moves
//! through several worker phases.

use std::time::{Duration, Instant};

use rea_core::cancellation::Cancellation;

const TIMEOUT_REASON: &str = "Provider startup deadline elapsed";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionInterruption {
    Cancelled,
    Closing,
    Timeout,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionControlError {
    InvalidTimeout,
    Interrupted(ExecutionInterruption),
}

/// Owns the composite cancellation identity for one provider operation.
pub struct GhidraRustExecutionControl {
    timeout: Duration,
    deadline: Instant,
    shutdown: Cancellation,
    caller: Option<Cancellation>,
    signal: Cancellation,
    interruption: Option<ExecutionInterruption>,
}

impl GhidraRustExecutionControl {
    pub fn new(
        timeout: Duration,
        shutdown: Cancellation,
        caller: Option<Cancellation>,
    ) -> Result<Self, ExecutionControlError> {
        if timeout.is_zero() {
            return Err(ExecutionControlError::InvalidTimeout);
        }

        let mut control = Self {
            timeout,
            deadline: Instant::now() + timeout,
            shutdown,
            caller,
            signal: Cancellation::default(),
            interruption: None,
        };

        // Match the TypeScript constructor's eager handling of signals that
        // were already aborted before the control object was created.
        control.refresh();

        Ok(control)
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    pub fn signal(&self) -> Cancellation {
        self.signal.clone()
    }

    /// Return the reason carried by the composite signal after refreshing it.
    ///
    /// The TypeScript control preserves the caller's abort reason (and the
    /// shutdown signal's reason) instead of replacing it with a provider
    /// generated message.  Exposing the same fact keeps failure adapters from
    /// having to reinterpret the interruption enum.
    pub fn signal_reason(&mut self) -> Option<&str> {
        self.refresh();
        self.signal.reason()
    }

    pub fn remaining(&mut self) -> Duration {
        self.refresh();
        self.deadline.saturating_duration_since(Instant::now())
    }

    pub fn interruption(&mut self) -> Option<ExecutionInterruption> {
        self.refresh();
        self.interruption
    }

    pub fn check(&mut self) -> Result<(), ExecutionControlError> {
        match self.interruption() {
            Some(interruption) => Err(ExecutionControlError::Interrupted(interruption)),
            None => Ok(()),
        }
    }

    fn refresh(&mut self) {
        if self.interruption.is_some() {
            return;
        }

        // Caller cancellation has the same precedence as the TypeScript
        // implementation when both signals were already aborted.
        if let Some(reason) = self
            .caller
            .as_ref()
            .and_then(Cancellation::reason)
            .map(str::to_owned)
        {
            self.record(ExecutionInterruption::Cancelled, &reason);
            return;
        }

        if let Some(reason) = self.shutdown.reason().map(str::to_owned) {
            self.record(ExecutionInterruption::Closing, &reason);
            return;
        }

        if Instant::now() >= self.deadline {
            self.record(ExecutionInterruption::Timeout, TIMEOUT_REASON);
        }
    }

    fn record(&mut self, interruption: ExecutionInterruption, reason: &str) {
        self.interruption = Some(interruption);
        self.signal.cancel(reason);
    }
}

