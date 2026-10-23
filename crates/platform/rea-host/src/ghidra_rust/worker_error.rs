//! TypeScript-compatible classification for Rust Ghidra worker failures.

use serde_json::{Map, Value};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkerErrorCode {
    WorkerFailed,
    CacheIntegrityFailed,
}

impl WorkerErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WorkerFailed => "WORKER_FAILED",
            Self::CacheIntegrityFailed => "CACHE_INTEGRITY_FAILED",
        }
    }

    pub fn failure_kind(self) -> &'static str {
        match self {
            Self::WorkerFailed => "process",
            Self::CacheIntegrityFailed => "cache_integrity",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerFailure {
    pub operation: String,
    pub message: String,
    pub code: WorkerErrorCode,
    pub diagnostics: Map<String, Value>,
    /// The original worker failure retained when cleanup composes a wrapper.
    /// This mirrors `AnalysisError.cleanupPrimary` and keeps cache identity
    /// available after lifecycle cleanup has also failed.
    pub cleanup_primary: Option<Box<WorkerFailure>>,
    /// Cleanup remains retryable while this flag is set.
    pub cleanup_incomplete: bool,
    /// Independent cleanup failures are retained without replacing the
    /// substantive worker failure.
    pub secondary_failures: Vec<WorkerFailure>,
}

impl WorkerFailure {
    pub fn new(
        operation: impl Into<String>,
        message: impl Into<String>,
        code: WorkerErrorCode,
    ) -> Self {
        let mut diagnostics = Map::new();
        diagnostics.insert(
            "failure_kind".into(),
            Value::String(code.failure_kind().into()),
        );
        diagnostics.insert(
            "worker_error_code".into(),
            Value::String(code.as_str().into()),
        );

        Self {
            operation: operation.into(),
            message: message.into(),
            code,
            diagnostics,
            cleanup_primary: None,
            cleanup_incomplete: false,
            secondary_failures: Vec::new(),
        }
    }

    pub fn with_diagnostic(mut self, key: impl Into<String>, value: impl Into<Value>) -> Self {
        self.diagnostics.insert(key.into(), value.into());
        self.restore_classification_diagnostics();
        self
    }

    /// Merge producer-owned facts while keeping the canonical classification
    /// fields authoritative, as the TypeScript error factory does.
    pub fn with_diagnostics(mut self, diagnostics: Map<String, Value>) -> Self {
        self.diagnostics.extend(diagnostics);
        self.restore_classification_diagnostics();
        self
    }

    /// Retain a primary failure while reporting a later cleanup failure.
    pub fn with_cleanup_primary(mut self, primary: WorkerFailure) -> Self {
        self.cleanup_primary = Some(Box::new(primary));
        self.cleanup_incomplete = true;
        self
    }

    /// Add an independent cleanup failure without discarding the first one.
    pub fn with_secondary_failure(mut self, failure: WorkerFailure) -> Self {
        self.secondary_failures.push(failure);
        self.cleanup_incomplete = true;
        self
    }

    fn restore_classification_diagnostics(&mut self) {
        self.diagnostics.insert(
            "failure_kind".into(),
            Value::String(self.code.failure_kind().into()),
        );
        self.diagnostics.insert(
            "worker_error_code".into(),
            Value::String(self.code.as_str().into()),
        );
    }

    pub fn remediation(&self) -> Option<&'static str> {
        (self.code == WorkerErrorCode::CacheIntegrityFailed).then_some(
            "Preserve the existing cache for inspection. Configure REA_GHIDRA_RUST_CACHE_DIR to a new empty directory and reopen the target before retrying.",
        )
    }
}

pub fn cache_integrity_failed(failure: &WorkerFailure) -> bool {
    let mut current = failure;
    while let Some(primary) = current.cleanup_primary.as_deref() {
        current = primary;
    }

    matches!(
        current.diagnostics.get("worker_error_code"),
        Some(Value::String(code)) if code == "CACHE_INTEGRITY_FAILED"
    )
}
