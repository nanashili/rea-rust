//! Read-only runtime adapter for `project_il2cpp_type_descriptors`.
//!
//! Metadata readers own decoding and normalization. This adapter forwards
//! caller-supplied captured rows to the application projection and does not
//! reopen artifacts, execute a target, or infer unresolved descriptor facts.

use rea_application::il2cpp;
use rea_core::failure::{Detail, Failure};
use serde_json::Value;

/// Stable public operation name.
pub const OPERATION: &str = il2cpp::type_descriptors::OPERATION;

/// Project normalized, captured IL2CPP type-descriptor rows.
pub fn dispatch(input: Value) -> Result<Value, Failure> {
    dispatch_typed(&input)
}

/// Project an already-selected `project_il2cpp_type_descriptors` request.
pub fn dispatch_typed(input: &Value) -> Result<Value, Failure> {
    il2cpp::type_descriptors::project(input).map_err(tag_failure)
}

fn tag_failure(mut failure: Failure) -> Failure {
    failure.detail("operation", Detail::Text(OPERATION.into()));
    failure.detail("authority", Detail::Text("offline_capture_only".into()));
    failure
}
