//! Captured/static runtime boundary for IL2CPP RGCTX projections.
//!
//! The application projector owns row interpretation.  This adapter only
//! selects between caller-supplied module rows and a retained normalized
//! result; it never reopens the metadata or native image.

use rea_application::il2cpp;
use rea_core::failure::Failure;
use serde_json::Value;

/// Stable public operation name.
pub const OPERATION: &str = il2cpp::rgctx_map::OPERATION;

/// Dispatch a captured RGCTX request.
pub fn dispatch(input: Value) -> Result<Value, Failure> {
    dispatch_typed(&input)
}

/// Dispatch an already-selected request without provider or target access.
pub fn dispatch_typed(input: &Value) -> Result<Value, Failure> {
    if input
        .as_object()
        .is_some_and(|object| object.contains_key("evidence"))
    {
        il2cpp::rgctx_map::project_captured_evidence(input)
    } else {
        il2cpp::rgctx_map::project_records(input, il2cpp::rgctx_map::DEFAULT_MAX_RECORDS)
    }
}
