//! Stable session API for composed workflows and adapters.
//!
//! Compatibility owner: `BinarySessionPort` / `AnalysisOperationPort` in
//! `src/application/binary/BinarySessionPort.ts`. The binary session owns the
//! implementation; callers must not reach into its state.
use rea_analysis::{AnalysisExecution, BinaryTarget, ExecutionOptions, ProviderIdentity};
use rea_core::analysis_error::AnalysisError;
use rea_core::cancellation::Cancellation;
use rea_mcp::Session;
use serde_json::{Map, Value};
use std::sync::Arc;

/// Provider-neutral operation port bound to the admitted active target.
pub trait AnalysisPort {
    /// Whether the active provider route declares this operation available.
    fn supports_operation(&self, operation: &str) -> bool;
    /// Execute one provider operation (session snapshot replay applies).
    fn execute(
        &self,
        operation: &str,
        parameters: &Map<String, Value>,
        options: &ExecutionOptions,
    ) -> Result<AnalysisExecution, AnalysisError>;
}

/// One composed workflow result retained for snapshot replay.
#[derive(Clone, Debug)]
pub struct WorkflowSnapshot {
    pub operation: String,
    pub parameters: Value,
    pub evidence: Value,
}

/// Hold the active target binding through one complete composed operation.
///
/// Fails with `NoBinaryOpenError` when no target is open, or a cancellation
/// failure when `cancellation` wins before admission.
pub fn with_admitted_analysis<T>(
    session: &Arc<Session>,
    operation: &str,
    cancellation: &Cancellation,
    work: impl FnOnce(&dyn AnalysisPort) -> T,
) -> Result<T, AnalysisError> {
    crate::session::with_admitted_analysis(session, operation, cancellation, work)
}

/// The active target, if one is open.
pub fn active_target(session: &Arc<Session>) -> Option<BinaryTarget> {
    crate::session::active_target(session)
}

/// Identity of the provider bound to the active target (for `operation`).
pub fn provider_identity(
    session: &Arc<Session>,
    operation: Option<&str>,
) -> Option<ProviderIdentity> {
    crate::session::provider_identity(session, operation)
}

/// Analysis profile commitment of the active binding (for `operation`).
pub fn analysis_profile(session: &Arc<Session>, operation: Option<&str>) -> Option<Value> {
    crate::session::analysis_profile(session, operation)
}

/// Whether `operation` results may be replayed from an analysis snapshot.
pub fn allows_snapshot_replay(session: &Arc<Session>, operation: &str) -> bool {
    crate::session::allows_snapshot_replay(session, operation)
}

/// Retain a composed workflow result for snapshot replay.
pub fn record_workflow_snapshot(
    session: &Arc<Session>,
    snapshot: WorkflowSnapshot,
) -> Result<(), AnalysisError> {
    crate::session::record_workflow_snapshot(session, snapshot)
}
