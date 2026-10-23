//! Captured/static boundary for `render_il2cpp_method_signatures`.
//!
//! The caller supplies normalized IL2CPP rows.  The application projection
//! owns signature rendering and unresolved-reason semantics; this adapter does
//! not decode files, acquire a target, or infer missing facts.

use rea_application::il2cpp;
use rea_core::failure::{Detail, Failure};
use serde_json::Value;

/// The exact public operation exposed by this captured/static adapter.
pub const OPERATION: &str = il2cpp::method_signature_metadata::OPERATION;

/// Project caller-supplied normalized IL2CPP metadata into method signatures.
pub fn dispatch(input: Value) -> Result<Value, Failure> {
    dispatch_typed(&input)
}

/// Dispatch an already-selected operation without acquiring a target or provider.
pub fn dispatch_typed(input: &Value) -> Result<Value, Failure> {
    il2cpp::method_signature_metadata::project(input).map_err(tag_failure)
}

fn tag_failure(mut failure: Failure) -> Failure {
    failure.detail("operation", Detail::Text(OPERATION.into()));
    failure.detail("authority", Detail::Text("offline_capture_only".into()));
    failure
}
