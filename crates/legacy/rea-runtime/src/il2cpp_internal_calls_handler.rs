//! Runtime adapter for `map_il2cpp_internal_calls`.
//!
//! The application projection owns internal-call correlation and ambiguity
//! handling. This boundary forwards only caller-supplied captured facts; it
//! never resolves symbols, opens a binary, or executes a managed target.

use rea_application::il2cpp;
use rea_core::failure::{Detail, Failure};
use serde_json::Value;

/// Stable public operation name.
pub const OPERATION: &str = il2cpp::internal_call_map::OPERATION;

/// Project captured internal-call registry rows and optional method rows.
pub fn dispatch(input: Value) -> Result<Value, Failure> {
    dispatch_typed(&input)
}

/// Project an already-selected `map_il2cpp_internal_calls` request.
pub fn dispatch_typed(input: &Value) -> Result<Value, Failure> {
    il2cpp::internal_call_map::project(input).map_err(tag_failure)
}

fn tag_failure(mut failure: Failure) -> Failure {
    failure.detail("operation", Detail::Text(OPERATION.into()));
    failure.detail("authority", Detail::Text("offline_capture_only".into()));
    failure
}
