//! Bounded aggregation for Ghidra Rust cleanup diagnostics.
//!
//! Cleanup is a separate lifecycle phase.  Each operation is recorded even
//! when another operation has already failed, so the caller can retain the
//! complete failure set alongside the resource owner and retry cleanup later.

use std::error::Error;
use std::fmt;

/// Maximum diagnostic text retained for one cleanup operation.
pub const MAX_CLEANUP_REASON_BYTES: usize = 4_096;

/// One cleanup operation that did not complete successfully.
#[derive(Debug)]
pub struct CleanupFailure {
    reason: String,
    cause: Option<Box<dyn Error + Send + Sync>>,
}

impl CleanupFailure {
    pub fn reason(&self) -> &str {
        &self.reason
    }

    pub fn cause(&self) -> Option<&(dyn Error + Send + Sync + 'static)> {
        self.cause.as_deref()
    }

    fn new(reason: String, cause: Option<Box<dyn Error + Send + Sync>>) -> Self {
        Self { reason, cause }
    }
}

/// Independent cleanup failures retained until the owning lifecycle can retry.
#[derive(Debug, Default)]
pub struct CleanupFailures {
    failures: Vec<CleanupFailure>,
}

impl CleanupFailures {
    pub fn is_empty(&self) -> bool {
        self.failures.is_empty()
    }

    pub fn len(&self) -> usize {
        self.failures.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = &CleanupFailure> {
        self.failures.iter()
    }

    /// Expose the retained records to a retry owner without transferring them.
    pub fn failures(&self) -> &[CleanupFailure] {
        &self.failures
    }

    /// Record one failure without preventing independent cleanup attempts.
    pub fn record(&mut self, reason: impl AsRef<str>) {
        self.record_with_cause(reason, None);
    }

    /// Record one failure and preserve its original error for later reporting.
    pub fn record_error<E>(&mut self, reason: impl AsRef<str>, cause: E)
    where
        E: Error + Send + Sync + 'static,
    {
        self.record_with_cause(reason, Some(Box::new(cause)));
    }

    /// Retain an already-boxed cause when cleanup ownership crosses a helper.
    pub fn record_boxed_error(
        &mut self,
        reason: impl AsRef<str>,
        cause: Box<dyn Error + Send + Sync>,
    ) {
        self.record_with_cause(reason, Some(cause));
    }

    fn record_with_cause(
        &mut self,
        reason: impl AsRef<str>,
        cause: Option<Box<dyn Error + Send + Sync>>,
    ) {
        let bounded_reason = truncate_reason(reason.as_ref());
        self.failures
            .push(CleanupFailure::new(bounded_reason, cause));
    }

    /// Preserve all records for a retry owner while returning a diagnostic cause.
    pub fn cause(&self) -> Option<CleanupCause<'_>> {
        let causes = self
            .failures
            .iter()
            .filter_map(|failure| failure.cause())
            .collect::<Vec<_>>();

        match causes.as_slice() {
            [] => None,
            [cause] => Some(CleanupCause::Single(*cause)),
            _ => Some(CleanupCause::Multiple(causes)),
        }
    }
}

/// A cleanup cause preserving one exact error or every independent cause.
#[derive(Debug)]
pub enum CleanupCause<'a> {
    Single(&'a (dyn Error + Send + Sync + 'static)),
    Multiple(Vec<&'a (dyn Error + Send + Sync + 'static)>),
}

impl fmt::Display for CleanupCause<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Single(cause) => cause.fmt(formatter),
            Self::Multiple(_) => {
                write!(formatter, "Multiple Rust Ghidra cleanup operations failed.")
            }
        }
    }
}

impl Error for CleanupCause<'_> {}

fn truncate_reason(reason: &str) -> String {
    if reason.len() <= MAX_CLEANUP_REASON_BYTES {
        return reason.to_owned();
    }

    let mut end = MAX_CLEANUP_REASON_BYTES;
    while !reason.is_char_boundary(end) {
        end -= 1;
    }
    reason[..end].to_owned()
}
