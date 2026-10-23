//! Captured/static boundary for `project_il2cpp_pointer_tables`.
//!
//! Pointer-table rows are supplied by a caller-owned capture.  This adapter
//! only delegates validation and projection to the application layer.

use rea_application::il2cpp;
use rea_core::failure::{Detail, Failure};
use serde_json::Value;

pub const OPERATION: &str = il2cpp::pointer_table_projection::OPERATION;

/// Project normalized IL2CPP method-pointer tables without live access.
pub fn dispatch(input: Value) -> Result<Value, Failure> {
    dispatch_typed(&input)
}

/// Dispatch an already-selected operation without acquiring a target.
pub fn dispatch_typed(input: &Value) -> Result<Value, Failure> {
    il2cpp::pointer_table_projection::project(input).map_err(tag_failure)
}

fn tag_failure(mut failure: Failure) -> Failure {
    failure.detail("operation", Detail::Text(OPERATION.into()));
    failure.detail("authority", Detail::Text("offline_capture_only".into()));
    failure
}
