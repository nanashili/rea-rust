//! Captured-Evidence-only runtime adapter for trace_native_ui_action.
//!
//! This adapter has no UI, provider, process, or filesystem authority. It
//! delegates the bounded graph projection to the application owner.

use rea_application::native;
use rea_core::failure::{Detail, Failure};
use serde_json::Value;
use std::collections::BTreeMap;

pub const OPERATION: &str = native::trace_ui_action::OPERATION;

/// Dispatch the captured UI-action trace operation.
pub fn dispatch(operation: &str, input: Value) -> Result<Value, Failure> {
    if operation != OPERATION {
        return Err(Failure::new(
            "invalid_request",
            "invalid_input",
            format!("unknown native UI trace operation: {operation}"),
            false,
            "Select trace_native_ui_action.".into(),
            BTreeMap::from([("operation", Detail::Text(operation.into()))]),
        ));
    }

    validate_captured_input(&input)?;
    native::trace_ui_action::trace(&input)
}

fn validate_captured_input(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid_input("trace_native_ui_action input must be an object"))?;
    let graph = object
        .get("graph")
        .ok_or_else(|| invalid_input("captured graph Evidence is required"))?;
    let graph = graph
        .as_object()
        .ok_or_else(|| invalid_input("captured graph Evidence must be an object"))?;

    if graph
        .get("operation")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Err(invalid_input(
            "captured graph Evidence must include operation",
        ));
    }

    graph
        .get("evidence_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid_input("captured graph Evidence must include evidence_id"))?;
    if graph.get("normalized_result").is_none() && graph.get("result").is_none() {
        return Err(invalid_input(
            "captured graph Evidence must include normalized_result or result",
        ));
    }

    Ok(())
}

fn invalid_input(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide retained captured UI graph Evidence and retry.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
