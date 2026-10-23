//! Runtime adapter for joining captured IL2CPP method mappings with native Evidence.
//!
//! The application projection owns Evidence authentication and exact identity
//! matching. This boundary only selects the operation and forwards retained
//! caller data; it never opens artifacts, invokes a provider, or executes a
//! target.

use rea_application::il2cpp;
use rea_core::failure::{Detail, Failure};
use serde_json::Value;
use std::collections::BTreeMap;

/// Stable public operation name.
pub const OPERATION: &str = il2cpp::decompilation_join::OPERATION;

/// Dispatch a named captured-only operation.
pub fn dispatch(operation: &str, input: Value) -> Result<Value, Failure> {
    if operation != OPERATION {
        return Err(unknown_operation(operation));
    }

    dispatch_typed(&input)
}

/// Dispatch an already-selected join request.
pub fn dispatch_typed(input: &Value) -> Result<Value, Failure> {
    il2cpp::decompilation_join::project(input).map_err(tag_failure)
}

fn tag_failure(mut failure: Failure) -> Failure {
    failure.detail("operation", Detail::Text(OPERATION.into()));
    failure.detail("authority", Detail::Text("offline_capture_only".into()));
    failure
}

fn unknown_operation(operation: &str) -> Failure {
    Failure::new_with_details(
        "invalid_request",
        "invalid_input",
        format!("IL2CPP decompilation join operation is unknown: {operation}"),
        false,
        "Select join_il2cpp_decompilation and provide captured mappings and Evidence.".into(),
        BTreeMap::from([(String::from("operation"), Detail::Text(operation.into()))]),
    )
}
