//! Runtime-owned adapter for the host Ghidra batch policy.
//!
//! The host policy owns selector ordering, bounded pages, cache-only retries,
//! and reply validation.  This adapter owns the live provider and keeps the
//! caller's cancellation and target identity at that boundary.

use rea_host::ghidra_rust::batch::{BatchOperation, BatchOptions, GhidraRustBatchSession};
use rea_host::ghidra_rust::batch_plan::SelectedProcedure;
use rea_host::ghidra_rust::protocol::{WorkerFrame, WorkerFunctionResolution, WorkerProtocolError};
use rea_host::ghidra_rust::provider::{GhidraRustProvider, ProviderError};
use serde_json::{Value, json};

/// A live host session bound to one caller-selected target.
pub struct RuntimeGhidraRustBatchSession<'a> {
    provider: GhidraRustProvider,
    cancelled: &'a dyn Fn() -> bool,
    inventory_sha256: Option<String>,
    invalidated: bool,
    retained_partial: Option<Value>,
    rejected_batch: Option<Value>,
    invalidation_error: Option<ProviderError>,
    finalized: bool,
}

impl<'a> RuntimeGhidraRustBatchSession<'a> {
    pub fn new(provider: GhidraRustProvider, cancelled: &'a dyn Fn() -> bool) -> Self {
        Self {
            provider,
            cancelled,
            inventory_sha256: None,
            invalidated: false,
            retained_partial: None,
            rejected_batch: None,
            invalidation_error: None,
            finalized: false,
        }
    }

    pub fn open_target(&mut self, path: &str, target_sha256: &str) -> Result<(), ProviderError> {
        let cancelled = self.cancelled;
        let info = self
            .provider
            .open_with_cancel(path, target_sha256, || cancelled())?;
        self.inventory_sha256 = info.inventory_sha256;
        Ok(())
    }

    pub fn provider_mut(&mut self) -> &mut GhidraRustProvider {
        &mut self.provider
    }

    pub fn take_retained_partial(&mut self) -> Option<Value> {
        self.retained_partial.take()
    }

    pub fn take_rejected_batch(&mut self) -> Option<Value> {
        self.rejected_batch.take()
    }

    pub fn take_invalidation_error(&mut self) -> Option<ProviderError> {
        self.invalidation_error.take()
    }

    /// Close the worker and preserve ownership when final cleanup fails.
    ///
    /// Invalidation is attempted before this method by the host policy. If
    /// invalidation recorded an error and close succeeds, that error is
    /// returned after the worker has been settled. If close fails, the close
    /// failure is returned while the invalidation error remains available via
    /// `take_invalidation_error`; `finalized` stays false so the adapter still
    /// owns a retryable worker lifecycle.
    pub fn finalize(&mut self) -> Result<(), ProviderError> {
        if self.finalized {
            return Err(ProviderError::Transport(
                "Rust Ghidra batch session was already finalized".into(),
            ));
        }

        let cancelled = self.cancelled;
        let close_result = self.provider.close_with_cancel(|| cancelled());
        if let Err(error) = close_result {
            return Err(error);
        }

        self.finalized = true;

        if let Some(error) = self.invalidation_error.take() {
            return Err(error);
        }

        Ok(())
    }

    fn ensure_live(&self) -> Result<(), ProviderError> {
        if self.finalized {
            return Err(ProviderError::Transport(
                "Rust Ghidra batch session was already finalized".into(),
            ));
        }
        if self.invalidated {
            return Err(ProviderError::Transport(
                "Rust Ghidra batch session was invalidated".into(),
            ));
        }
        if (self.cancelled)() {
            return Err(ProviderError::Cancelled);
        }
        Ok(())
    }

    fn frame_value(&mut self, frame: WorkerFrame) -> Result<Value, ProviderError> {
        match frame {
            WorkerFrame::Reply { result, .. } => Ok(result),
            WorkerFrame::Error {
                id,
                code,
                message,
                error_code,
                ..
            } => {
                self.rejected_batch = Some(json!({
                    "worker_error": {
                        "id": id,
                        "code": code,
                        "message": message,
                        "error_code": error_code,
                    }
                }));
                Err(ProviderError::Protocol(
                    WorkerProtocolError::RequestFailed {
                        id,
                        code,
                        message,
                        error_code,
                    },
                ))
            }
            WorkerFrame::Progress {
                label,
                completed,
                total,
            } => {
                self.rejected_batch = Some(json!({
                    "worker_progress": {
                        "label": label,
                        "completed": completed,
                        "total": total,
                    }
                }));
                Err(ProviderError::Protocol(WorkerProtocolError::Malformed(
                    "worker returned progress without a batch reply".into(),
                )))
            }
        }
    }
}

impl GhidraRustBatchSession for RuntimeGhidraRustBatchSession<'_> {
    type Error = ProviderError;

    fn inventory_sha256(&self) -> Option<&str> {
        self.inventory_sha256.as_deref()
    }

    fn resolve_page(
        &mut self,
        selectors: &[String],
        _options: BatchOptions,
    ) -> Result<Vec<WorkerFunctionResolution>, Self::Error> {
        self.ensure_live()?;
        let cancelled = self.cancelled;
        let resolution = self
            .provider
            .resolve_functions_with_cancel(selectors, || cancelled())?;
        Ok(resolution.items)
    }

    fn request_batch(
        &mut self,
        procedures: &[SelectedProcedure],
        options: BatchOptions,
    ) -> Result<Value, Self::Error> {
        self.ensure_live()?;
        let cancelled = self.cancelled;
        let addresses = procedures
            .iter()
            .map(|procedure| procedure.address.clone())
            .collect::<Vec<_>>();
        let frame = match options.operation {
            BatchOperation::BatchDecompile | BatchOperation::ProcedurePseudoCode => {
                if options.cache_only {
                    self.provider
                        .batch_decompile_cache_only_with_cancel(&addresses, || cancelled())?
                } else {
                    self.provider
                        .batch_decompile_with_cancel(&addresses, || cancelled())?
                }
            }
        };
        self.frame_value(frame)
    }

    fn acknowledge_checkpoint(&mut self) -> Result<(), Self::Error> {
        // The TypeScript batch policy acknowledges the validated receipt in
        // memory.  Sending a second checkpoint RPC would create an extra
        // worker side effect and is therefore intentionally omitted.
        self.ensure_live()
    }

    fn invalidate(&mut self) {
        self.invalidated = true;
        if self.invalidation_error.is_none() {
            if let Err(error) = self.provider.cancel() {
                self.invalidation_error = Some(error);
            }
        }
    }

    fn retain_partial_result(&mut self, result: Value) {
        self.retained_partial = Some(result);
    }

    fn retain_rejected_batch(&mut self, reply: Value) {
        self.rejected_batch = Some(reply);
    }
}
