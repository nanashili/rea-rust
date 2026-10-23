//! Application-owned projection for captured Apktool resource observations.
//!
//! Apktool execution and workspace ownership belong to the provider adapter.
//! This boundary accepts only a retained report (or Evidence envelope), checks
//! the public decode shape, and preserves the provider's facts for transport
//! adapters to wrap in their own Evidence envelope.

use rea_core::{
    failure::{Detail, Failure},
    json_output,
};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

pub const OPERATION: &str = "decode_android_resources";
const MAX_OUTPUT_BYTES: usize = 8 * 1024 * 1024;

const SOURCE_FIELDS: &[&str] = &["report", "evidence"];

/// Project one caller-supplied Apktool report through the application boundary.
pub fn decode(input: &Value) -> Result<Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("input must be an object"))?;
    reject_unknown_input_fields(object)?;

    let source = exclusive_source(object)?;
    let result = resolve_result(source)?;
    validate_result(result)?;
    json_output::admitted_length(result, MAX_OUTPUT_BYTES).map_err(|error| {
        invalid(&format!(
            "decoded Apktool result exceeds output limit: {error}"
        ))
    })?;

    Ok(json!({ "result": result.clone() }))
}

fn reject_unknown_input_fields(object: &Map<String, Value>) -> Result<(), Failure> {
    if object
        .keys()
        .any(|key| !SOURCE_FIELDS.contains(&key.as_str()))
    {
        return Err(invalid("input contains an unknown field"));
    }
    Ok(())
}

fn exclusive_source<'a>(object: &'a Map<String, Value>) -> Result<&'a Value, Failure> {
    let sources = SOURCE_FIELDS
        .iter()
        .filter_map(|field| object.get(*field).map(|value| (*field, value)))
        .collect::<Vec<_>>();
    match sources.as_slice() {
        [(_, source)] => Ok(source),
        [] => Err(invalid("captured Apktool report is required")),
        _ => Err(invalid("provide exactly one captured source field")),
    }
}

fn resolve_result(source: &Value) -> Result<&Value, Failure> {
    let result = source
        .get("normalized_result")
        .or_else(|| source.get("result"))
        .unwrap_or(source);
    if result.is_object() {
        Ok(result)
    } else {
        Err(invalid(
            "captured Apktool report must contain an object result",
        ))
    }
}

fn validate_result(result: &Value) -> Result<(), Failure> {
    let object = result
        .as_object()
        .ok_or_else(|| invalid("captured Apktool result must be an object"))?;
    require_object(object, "client")?;
    require_object(object, "target")?;
    require_object(object, "metadata")?;
    require_nullable_string(object, "manifest")?;
    require_array(object, "strings")?;
    require_nullable_string(object, "locale")?;
    require_string_array(object, "locales")?;
    if let Some(string_tables) = object.get("string_tables") {
        if !string_tables.is_array() {
            return Err(invalid("string_tables must be an array"));
        }
    }
    require_non_negative_integer(object, "decoded_file_count")?;
    require_enum(object, "coverage", &["complete", "partial"])?;
    Ok(())
}

fn require_object(object: &Map<String, Value>, field: &str) -> Result<(), Failure> {
    if object.get(field).is_some_and(Value::is_object) {
        return Ok(());
    }
    Err(invalid(&format!("{field} must be an object")))
}

fn require_array(object: &Map<String, Value>, field: &str) -> Result<(), Failure> {
    if object.get(field).is_some_and(Value::is_array) {
        return Ok(());
    }
    Err(invalid(&format!("{field} must be an array")))
}

fn require_string_array(object: &Map<String, Value>, field: &str) -> Result<(), Failure> {
    let values = object
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(&format!("{field} must be an array")))?;
    if values
        .iter()
        .all(|value| value.as_str().is_some_and(|item| !item.is_empty()))
    {
        return Ok(());
    }
    Err(invalid(&format!("{field} must contain non-empty strings")))
}

fn require_nullable_string(object: &Map<String, Value>, field: &str) -> Result<(), Failure> {
    match object.get(field) {
        Some(Value::Null) => Ok(()),
        Some(Value::String(_)) => Ok(()),
        _ => Err(invalid(&format!("{field} must be a string or null"))),
    }
}

fn require_non_negative_integer(object: &Map<String, Value>, field: &str) -> Result<(), Failure> {
    if object.get(field).and_then(Value::as_u64).is_some() {
        return Ok(());
    }
    Err(invalid(&format!("{field} must be a non-negative integer")))
}

fn require_enum(object: &Map<String, Value>, field: &str, values: &[&str]) -> Result<(), Failure> {
    if object
        .get(field)
        .and_then(Value::as_str)
        .is_some_and(|value| values.contains(&value))
    {
        return Ok(());
    }
    Err(invalid(&format!("{field} has an unsupported value")))
}

fn invalid(message: &str) -> Failure {
    Failure::new_with_details(
        "invalid_request",
        "invalid_input",
        message.into(),
        false,
        "Provide one bounded captured Apktool resource report or Evidence envelope.".into(),
        BTreeMap::from([(String::from("operation"), Detail::Text(OPERATION.into()))]),
    )
}
