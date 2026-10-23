//! Runtime adapter for `project_il2cpp_generic_constraints`.
//!
//! Generic-constraint rows are supplied by a static decoder or retained
//! capture. The application projection owns validation and joins; this
//! boundary does not read files, contact a provider, select a target, or
//! resolve an absent or ambiguous type reference.

use rea_application::il2cpp;
use rea_core::failure::{Detail, Failure};
use serde_json::Value;

/// Stable public operation name.
pub const OPERATION: &str = il2cpp::generic_constraints::OPERATION;

/// Project caller-supplied IL2CPP generic-parameter constraint rows.
pub fn dispatch(input: Value) -> Result<Value, Failure> {
    dispatch_typed(&input)
}

/// Project an already-selected static or captured request.
pub fn dispatch_typed(input: &Value) -> Result<Value, Failure> {
    il2cpp::generic_constraints::project(input).map_err(tag_failure)
}

fn tag_failure(mut failure: Failure) -> Failure {
    failure.detail("operation", Detail::Text(OPERATION.into()));
    failure.detail("authority", Detail::Text("offline_capture_only".into()));
    failure
}
