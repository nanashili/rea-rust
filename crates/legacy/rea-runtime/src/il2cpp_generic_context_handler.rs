//! Runtime adapter for `project_il2cpp_generic_context`.
//!
//! Metadata readers own decoding and normalization. This boundary only forwards
//! caller-supplied generic-container facts to the application projection; it
//! does not read artifacts, execute a target, or infer owner relationships.

use rea_application::il2cpp;
use rea_core::failure::{Detail, Failure};
use serde_json::Value;

/// Stable public operation name.
pub const OPERATION: &str = il2cpp::generic_context::OPERATION;

/// Project normalized IL2CPP generic containers and parameter constraints.
pub fn dispatch(input: Value) -> Result<Value, Failure> {
    dispatch_typed(&input)
}

/// Project an already-selected `project_il2cpp_generic_context` request.
pub fn dispatch_typed(input: &Value) -> Result<Value, Failure> {
    il2cpp::generic_context::project(input).map_err(tag_failure)
}

fn tag_failure(mut failure: Failure) -> Failure {
    failure.detail("operation", Detail::Text(OPERATION.into()));
    failure.detail("authority", Detail::Text("offline_capture_only".into()));
    failure
}
