//! Runtime adapter for the public Dart AOT inspection contract.
//!
//! The application layer owns APK reading, snapshot parsing, Evidence
//! identity, and producer limitations. This module only enforces the public
//! request shape and converts the producer's retained RawValue for the MCP
//! runtime without reinterpreting its result.

use rea_application::{flutter::dart_aot, flutter::dart_aot_delivery};
use rea_core::{
    cancellation::Cancellation,
    failure::{Detail, Failure},
};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub const OPERATION: &str = "inspect_dart_aot";
const MAX_ABI_LABEL_CHARACTERS: usize = 1_010;

/// Execute the public Dart AOT inspection request through its owning producer.
pub fn inspect(input: &Value, cancellation: &Cancellation) -> Result<Value, Failure> {
    validate_input(input)?;

    let detail = input
        .get("detail")
        .and_then(Value::as_str)
        .unwrap_or("complete");

    let provider_input = remove_delivery_selection(input)?;
    let complete = dart_aot::inspect(&provider_input, cancellation)?;
    let delivered = dart_aot_delivery::select(&complete, Some(detail))?;

    serde_json::from_str(delivered.get()).map_err(|error| {
        Failure::new_with_details(
            "execution_failure",
            "analysis_output",
            error.to_string(),
            false,
            "Review the serialized Dart AOT Evidence.".into(),
            BTreeMap::from([(String::from("operation"), Detail::Text(OPERATION.into()))]),
        )
    })
}

/// The application reader owns analysis inputs; `detail` only selects how the
/// already-retained Evidence is delivered and must not influence the read.
fn remove_delivery_selection(input: &Value) -> Result<Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid_input("input", "Expected an object"))?;

    let mut provider_object = object.clone();
    provider_object.remove("detail");

    Ok(Value::Object(provider_object))
}

fn validate_input(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid_input("input", "Expected an object"))?;

    reject_unknown_fields(object)?;

    let path = object
        .get("path")
        .and_then(Value::as_str)
        .filter(|path| !path.is_empty())
        .ok_or_else(|| invalid_input("path", "Expected a non-empty string"))?;
    if path.contains('\0') {
        return Err(invalid_input(
            "path",
            "Local filesystem paths cannot contain NUL",
        ));
    }

    if let Some(abi) = object.get("abi") {
        let abi = abi
            .as_str()
            .ok_or_else(|| invalid_input("abi", "Expected a string"))?;
        let character_count = abi.chars().count();
        if abi.is_empty() || abi.contains('/') || character_count > MAX_ABI_LABEL_CHARACTERS {
            return Err(invalid_input(
                "abi",
                "ABI must be a non-empty lib directory label without '/'",
            ));
        }
    }

    if let Some(detail) = object.get("detail") {
        let detail = detail
            .as_str()
            .ok_or_else(|| invalid_input("detail", "Expected complete or summary"))?;
        if !matches!(detail, "complete" | "summary") {
            return Err(invalid_input("detail", "Expected complete or summary"));
        }
    }

    Ok(())
}

fn reject_unknown_fields(object: &Map<String, Value>) -> Result<(), Failure> {
    for field in object.keys() {
        if !matches!(field.as_str(), "path" | "abi" | "detail") {
            return Err(invalid_input(field, "Unrecognized key"));
        }
    }

    Ok(())
}

fn invalid_input(field: &str, reason: &str) -> Failure {
    Failure::new_with_details(
        "invalid_request",
        "invalid_input",
        "Analysis input is invalid.".into(),
        false,
        "Correct the input and retry.".into(),
        BTreeMap::from([
            (String::from("operation"), Detail::Text(OPERATION.into())),
            (String::from("field"), Detail::Text(field.into())),
            (String::from("reason"), Detail::Text(reason.into())),
        ]),
    )
}
