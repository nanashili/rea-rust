//! Runtime adapter for captured IL2CPP static-report projections.
//!
//! The caller supplies retained metadata, CodeGenModule, method-address, and
//! member projections. The application workflow owns report composition and
//! identity semantics; this adapter does not read artifacts, invoke a
//! provider, execute a target, or mutate state.

use rea_application::il2cpp;
use rea_core::failure::{Detail, Failure};
use serde_json::Value;
use std::collections::BTreeMap;

/// The public operation exposed by this adapter.
pub const OPERATION: &str = il2cpp::static_report::OPERATION;

/// Build a report from caller-supplied captured IL2CPP projections.
pub fn dispatch(operation: &str, input: Value) -> Result<Value, Failure> {
    if operation != OPERATION {
        return Err(tag_failure(unknown_operation(operation)));
    }

    dispatch_typed(&input)
}

/// Build an already-selected captured IL2CPP static report.
pub fn dispatch_typed(input: &Value) -> Result<Value, Failure> {
    il2cpp::static_report::project(input).map_err(tag_failure)
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
        format!("IL2CPP static-report operation is unknown: {operation}"),
        false,
        "Select build_il2cpp_static_report and provide captured IL2CPP projections.".into(),
        BTreeMap::from([
            (String::from("operation"), Detail::Text(operation.into())),
            (
                String::from("requested_operation"),
                Detail::Text(operation.into()),
            ),
        ]),
    )
}
