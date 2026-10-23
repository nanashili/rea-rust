//! Runtime boundary for explicit function Evidence comparison.
//!
//! The application layer owns comparison semantics. This adapter only selects
//! the public operation and validates that both inputs belong to the
//! `analyze_function` Evidence family. It never opens a provider database,
//! resolves a function, executes a target, or mutates retained Evidence.

use rea_application::javascript;
use rea_core::failure::{Detail, Failure};
use serde_json::Value;
use std::collections::BTreeMap;

const ANALYZE_FUNCTION_OPERATION: &str = "analyze_function";

/// Dispatch the public `compare_functions` operation using retained Evidence.
pub fn dispatch(operation: &str, input: Value) -> Result<Value, Failure> {
    if operation != javascript::function_comparison::OPERATION {
        return Err(unknown_operation(operation));
    }

    validate_input(&input)?;
    javascript::function_comparison::compare(&input)
}

/// Validate and dispatch an already-selected compare-functions operation.
pub fn dispatch_typed(input: &Value) -> Result<Value, Failure> {
    validate_input(input)?;
    javascript::function_comparison::compare(input)
}

fn validate_input(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid_input("compare_functions input must be an object"))?;

    if object.len() != 2 || !object.contains_key("left") || !object.contains_key("right") {
        return Err(invalid_input(
            "compare_functions input must contain exactly left and right Evidence",
        ));
    }

    let left = object
        .get("left")
        .ok_or_else(|| invalid_input("left Evidence is required"))?;
    let right = object
        .get("right")
        .ok_or_else(|| invalid_input("right Evidence is required"))?;

    validate_evidence(left, "left")?;
    validate_evidence(right, "right")?;
    Ok(())
}

fn validate_evidence(value: &Value, side: &str) -> Result<(), Failure> {
    let evidence = value
        .as_object()
        .ok_or_else(|| invalid_input(format!("{side} Evidence must be an object")))?;

    if evidence.get("operation").and_then(Value::as_str) != Some(ANALYZE_FUNCTION_OPERATION) {
        return Err(invalid_input(format!(
            "{side} Evidence operation must be analyze_function"
        )));
    }

    if evidence.get("predicate_type").and_then(Value::as_str) != Some("rea.analysis") {
        return Err(invalid_input(format!(
            "{side} Evidence predicate_type must be rea.analysis"
        )));
    }

    Ok(())
}

fn unknown_operation(operation: &str) -> Failure {
    Failure::new_with_details(
        "invalid_request",
        "invalid_input",
        format!("Function comparison operation is unknown: {operation}"),
        false,
        "Select compare_functions and provide two analyze_function Evidence records.".into(),
        BTreeMap::from([(String::from("operation"), Detail::Text(operation.into()))]),
    )
}

fn invalid_input(message: impl Into<String>) -> Failure {
    Failure::new_with_details(
        "invalid_request",
        "invalid_input",
        message.into(),
        false,
        "Provide two complete analyze_function Evidence records and retry.".into(),
        BTreeMap::from([(
            String::from("operation"),
            Detail::Text(javascript::function_comparison::OPERATION.into()),
        )]),
    )
}
