//! Captured/static boundary for `inspect_il2cpp_method_semantics`.
//!
//! The caller supplies normalized metadata rows.  This adapter delegates
//! classification to the application layer and never opens an artifact,
//! acquires a target, executes IL2CPP, or mutates state.

use rea_application::il2cpp;
use rea_core::failure::{Detail, Failure};
use serde_json::Value;

/// Stable public operation name.
pub const OPERATION: &str = il2cpp::method_semantics::OPERATION;

/// Project caller-supplied IL2CPP method-semantics rows.
pub fn dispatch(input: Value) -> Result<Value, Failure> {
    dispatch_typed(&input)
}

/// Dispatch an already-selected operation without provider or target access.
pub fn dispatch_typed(input: &Value) -> Result<Value, Failure> {
    let mut result = il2cpp::method_semantics::project(input).map_err(tag_failure)?;

    // Keep the runtime envelope authoritative at the public boundary. The
    // application projection currently emits this field too, but the adapter
    // owns the operation selected by the runtime dispatcher and must preserve
    // that contract if the projection is reused elsewhere.
    if let Some(object) = result.as_object_mut() {
        object.insert("operation".into(), Value::String(OPERATION.into()));
    }

    Ok(result)
}

fn tag_failure(mut failure: Failure) -> Failure {
    failure.detail("operation", Detail::Text(OPERATION.into()));
    failure.detail("authority", Detail::Text("offline_capture_only".into()));
    failure
}
