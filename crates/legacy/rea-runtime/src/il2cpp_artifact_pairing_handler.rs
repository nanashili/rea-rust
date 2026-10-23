//! Runtime adapter for `pair_il2cpp_artifacts`.
//!
//! Pairing consumes caller-supplied artifact manifests or authenticated
//! retained Evidence. It never opens paths, derives identity from filenames,
//! invokes a provider, or mutates a target.

use rea_application::il2cpp;
use rea_core::failure::{Detail, Failure};
use serde_json::Value;

/// Stable public operation name.
pub const OPERATION: &str = il2cpp::artifact_pairing::OPERATION;

/// Pair static or captured IL2CPP artifacts by exact supplied identity.
pub fn dispatch(input: Value) -> Result<Value, Failure> {
    dispatch_typed(&input)
}

/// Pair an already-selected request without opening an artifact.
pub fn dispatch_typed(input: &Value) -> Result<Value, Failure> {
    il2cpp::artifact_pairing::project(input).map_err(tag_failure)
}

/// Keep failures explicit about the captured-only authority of this adapter.
/// The application projection retains the exact field and identity reason.
fn tag_failure(mut failure: Failure) -> Failure {
    failure.detail("operation", Detail::Text(OPERATION.into()));
    failure.detail("authority", Detail::Text("offline_capture_only".into()));
    failure
}
