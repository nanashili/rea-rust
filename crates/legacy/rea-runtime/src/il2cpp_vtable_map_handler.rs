//! Captured/static boundary for `map_il2cpp_vtables`.
//!
//! Vtable and interface rows are supplied by the caller from an existing
//! capture. This adapter only delegates projection to the application layer;
//! it has no artifact, process, provider, or target-execution authority.

use rea_application::il2cpp;
use rea_core::failure::{Detail, Failure};
use serde_json::Value;

/// The exact public operation exposed by this captured/static adapter.
pub const OPERATION: &str = il2cpp::vtable_map::OPERATION;

/// Project caller-supplied IL2CPP vtable and interface rows without live access.
pub fn dispatch(input: Value) -> Result<Value, Failure> {
    dispatch_typed(&input)
}

/// Dispatch an already-selected operation without acquiring a target or provider.
pub fn dispatch_typed(input: &Value) -> Result<Value, Failure> {
    il2cpp::vtable_map::project(input).map_err(tag_failure)
}

fn tag_failure(mut failure: Failure) -> Failure {
    failure.detail("operation", Detail::Text(OPERATION.into()));
    failure.detail("authority", Detail::Text("offline_capture_only".into()));
    failure
}
