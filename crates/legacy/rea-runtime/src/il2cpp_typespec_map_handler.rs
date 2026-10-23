//! Captured/static boundary for `project_il2cpp_typespecs`.
//!
//! Metadata readers own decoding and normalization. This adapter forwards
//! caller-supplied TypeSpec, type-definition, and generic-instantiation rows
//! to the application projection without opening artifacts, executing a
//! target, or resolving unknown references by inference.

use rea_application::il2cpp;
use rea_core::failure::{Detail, Failure};
use serde_json::Value;

/// Stable public operation name.
pub const OPERATION: &str = il2cpp::typespec_map::OPERATION;

/// Project normalized, captured IL2CPP TypeSpec rows.
pub fn dispatch(input: Value) -> Result<Value, Failure> {
    dispatch_typed(&input)
}

/// Dispatch an already-selected operation without acquiring a target or provider.
pub fn dispatch_typed(input: &Value) -> Result<Value, Failure> {
    il2cpp::typespec_map::project(input).map_err(tag_failure)
}

fn tag_failure(mut failure: Failure) -> Failure {
    failure.detail("operation", Detail::Text(OPERATION.into()));
    failure.detail("authority", Detail::Text("offline_capture_only".into()));
    failure
}
