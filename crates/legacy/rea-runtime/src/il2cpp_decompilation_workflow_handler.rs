//! Runtime adapter for captured IL2CPP decompilation correlation.
//!
//! The caller supplies retained metadata, method-address, and native
//! decompilation Evidence. The application workflow owns correlation and
//! validation semantics; this adapter does not read files or contact a
//! provider or target.

use rea_application::il2cpp;
use rea_core::failure::{Detail, Failure};
use serde_json::Value;
use std::collections::BTreeMap;

/// The public operation exposed by this adapter.
pub const OPERATION: &str = il2cpp::decompilation_workflow::OPERATION;

/// Correlate caller-supplied IL2CPP decompilation Evidence.
pub fn dispatch(operation: &str, input: Value) -> Result<Value, Failure> {
    if operation != OPERATION {
        return Err(tag_failure(unknown_operation(operation)));
    }

    dispatch_typed(&input)
}

/// Correlate an already-selected captured-Evidence operation.
pub fn dispatch_typed(input: &Value) -> Result<Value, Failure> {
    il2cpp::decompilation_workflow::correlate(input).map_err(tag_failure)
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
        format!("IL2CPP decompilation operation is unknown: {operation}"),
        false,
        "Select correlate_il2cpp_decompilation and provide captured Evidence.".into(),
        BTreeMap::from([
            (String::from("operation"), Detail::Text(operation.into())),
            (
                String::from("requested_operation"),
                Detail::Text(operation.into()),
            ),
        ]),
    )
}
