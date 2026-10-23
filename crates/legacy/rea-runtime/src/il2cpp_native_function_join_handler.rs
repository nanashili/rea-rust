//! Runtime adapter for `join_il2cpp_native_functions`.
//!
//! The application projection owns exact identity matching and coverage
//! accounting. This boundary only selects the operation and forwards the
//! caller-supplied rows; it never opens artifacts, invokes a provider, or
//! executes a target.

use rea_application::il2cpp;
use rea_core::failure::{Detail, Failure};
use serde_json::Value;
use std::collections::BTreeMap;

/// Stable public operation name.
pub const OPERATION: &str = il2cpp::native_function_join::OPERATION;

/// Dispatch a named captured-only operation.
pub fn dispatch(operation: &str, input: Value) -> Result<Value, Failure> {
    if operation != OPERATION {
        return Err(unknown_operation(operation));
    }

    dispatch_typed(&input)
}

/// Dispatch an already-selected join request.
pub fn dispatch_typed(input: &Value) -> Result<Value, Failure> {
    il2cpp::native_function_join::project(input).map_err(tag_failure)
}

/// Keep failures explicit about the operation's captured-only authority.
fn tag_failure(mut failure: Failure) -> Failure {
    failure.detail("operation", Detail::Text(OPERATION.into()));
    failure.detail("authority", Detail::Text("offline_capture_only".into()));
    failure
}

fn unknown_operation(operation: &str) -> Failure {
    Failure::new_with_details(
        "invalid_request",
        "invalid_input",
        format!("IL2CPP native-function join operation is unknown: {operation}"),
        false,
        "Select join_il2cpp_native_functions and provide captured mappings and native facts."
            .into(),
        BTreeMap::from([(String::from("operation"), Detail::Text(operation.into()))]),
    )
}
