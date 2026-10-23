//! Retryable cleanup state for a supervised Ghidra Rust worker.
//!
//! The worker owns more than the child process: a cancelled lineage observer
//! and protocol/listener streams may still be settling after the caller's
//! deadline.  This type keeps that ownership explicit until every phase has
//! completed successfully, while retaining all independent cleanup failures.

const MAX_FAILURE_REASON_BYTES: usize = 4 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GhidraRustCleanupFailure {
    pub reason: String,
}

impl GhidraRustCleanupFailure {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: truncate_reason(&reason.into()),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GhidraRustCleanupProgress {
    pub process_stopped: bool,
    pub lineage_settled: bool,
    pub protocol_released: bool,
    pub listeners_released: bool,
}

impl GhidraRustCleanupProgress {
    pub fn complete(self) -> bool {
        self.process_stopped
            && self.lineage_settled
            && self.protocol_released
            && self.listeners_released
    }
}

#[derive(Debug, Default)]
pub struct GhidraRustProcessCleanup {
    progress: GhidraRustCleanupProgress,
    failures: Vec<GhidraRustCleanupFailure>,
    owned: bool,
}

impl GhidraRustProcessCleanup {
    /// A newly launched worker remains owned until all cleanup phases settle.
    pub fn owned() -> Self {
        Self {
            owned: true,
            ..Self::default()
        }
    }

    pub fn progress(&self) -> GhidraRustCleanupProgress {
        self.progress
    }

    pub fn failures(&self) -> &[GhidraRustCleanupFailure] {
        &self.failures
    }

    pub fn is_owned(&self) -> bool {
        self.owned
    }

    pub fn is_complete(&self) -> bool {
        self.progress.complete()
    }

    /// Run each independent phase and retain ownership if any phase fails.
    pub fn attempt<Stop, Lineage, Protocol, Listeners>(
        &mut self,
        stop_process: Stop,
        settle_lineage: Lineage,
        release_protocol: Protocol,
        release_listeners: Listeners,
    ) where
        Stop: FnOnce() -> Result<(), String>,
        Lineage: FnOnce() -> Result<(), String>,
        Protocol: FnOnce() -> Result<(), String>,
        Listeners: FnOnce() -> Result<(), String>,
    {
        // A retry can occur after lineage settled but before dependent stream
        // resources were released. Descendants may appear during finalization,
        // so each incomplete release attempt needs a fresh observation.
        let retry_requires_lineage_observation = !self.is_complete();

        if !self.progress.process_stopped {
            self.run_phase("worker stop", stop_process, |progress| {
                progress.process_stopped = true;
            });
        }

        if retry_requires_lineage_observation || !self.progress.lineage_settled {
            self.run_phase("lineage settlement", settle_lineage, |progress| {
                progress.lineage_settled = true;
            });
        }

        if !self.progress.protocol_released {
            self.run_phase("protocol release", release_protocol, |progress| {
                progress.protocol_released = true;
            });
        }

        if !self.progress.listeners_released {
            self.run_phase("listener release", release_listeners, |progress| {
                progress.listeners_released = true;
            });
        }

        self.owned = !self.is_complete();
    }

    fn run_phase<F, Mark>(&mut self, phase: &'static str, operation: F, mark: Mark)
    where
        F: FnOnce() -> Result<(), String>,
        Mark: FnOnce(&mut GhidraRustCleanupProgress),
    {
        match operation() {
            Ok(()) => mark(&mut self.progress),
            Err(reason) => self.record_failure(format!("{phase}: {reason}")),
        }
    }

    fn record_failure(&mut self, reason: String) {
        self.failures.push(GhidraRustCleanupFailure::new(reason));
    }
}

fn truncate_reason(reason: &str) -> String {
    if reason.len() <= MAX_FAILURE_REASON_BYTES {
        return reason.to_owned();
    }

    let mut end = MAX_FAILURE_REASON_BYTES;
    while !reason.is_char_boundary(end) {
        end -= 1;
    }

    reason[..end].to_owned()
}
