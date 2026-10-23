//! Captured/static boundary for `project_il2cpp_parameters`.
//!
//! The caller supplies already-decoded IL2CPP method, parameter, and optional
//! type facts. This adapter delegates range projection to the application
//! layer and has no artifact, provider, process, or target-execution authority.

use rea_application::il2cpp;
use rea_core::failure::{Detail, Failure};
use serde_json::Value;
use std::collections::BTreeMap;

/// The exact public operation exposed by this captured/static adapter.
pub const OPERATION: &str = il2cpp::parameters::OPERATION;

/// Project caller-supplied IL2CPP parameter ranges without live access.
pub fn dispatch(input: Value) -> Result<Value, Failure> {
    dispatch_typed(&input)
}

/// Dispatch an already-selected operation without acquiring a target or provider.
pub fn dispatch_typed(input: &Value) -> Result<Value, Failure> {
    let result = il2cpp::parameters::project(input).map_err(tag_failure)?;
    if !result.is_object() {
        return Err(tag_failure(invalid_projection()));
    }

    Ok(result)
}

fn invalid_projection() -> Failure {
    Failure::new(
        "invalid_result",
        "invalid_output",
        "IL2CPP parameter projection returned a non-object result.".into(),
        false,
        "Retry the offline IL2CPP parameter projection with a supported application result.".into(),
        BTreeMap::new(),
    )
}

fn tag_failure(mut failure: Failure) -> Failure {
    failure.detail("operation", Detail::Text(OPERATION.into()));
    failure.detail("authority", Detail::Text("offline_capture_only".into()));
    failure
}
