//! Read-only projection for the native `list_segments` operation.
//!
//! The Rust Ghidra worker reports object-file sections.  It does not report
//! the memory-block facts needed to claim read, write, or execute
//! permissions, so this boundary preserves that uncertainty in the public
//! segment shape instead of inferring permissions from section names or
//! worker fields.

use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub const OPERATION: &str = "list_segments";

const MAX_SEGMENTS: usize = 4_096;
const MAX_NAME_BYTES: usize = 4_096;
const MAX_COVERAGE_BYTES: usize = 4_096;
const UNKNOWN_PERMISSIONS_REASON: &str =
    "The Rust worker reports object-file sections without memory-protection facts.";

/// Validate and project a worker segment page or its item array.
pub fn project(value: &Value) -> Result<Value, Failure> {
    let items = segment_items(value)?;
    let mut projected = Vec::with_capacity(items.len());

    for (index, item) in items.iter().enumerate() {
        projected.push(project_item(item, index)?);
    }

    Ok(Value::Array(projected))
}

/// Validate a provider result before it is retained as Evidence.
pub fn validate_input(input: &Value) -> Result<(), Failure> {
    project(input).map(|_| ())
}

/// Accept the result envelope used by native adapters and return its segment
/// projection.  A bare worker page or item array is also accepted for direct
/// callers that already selected the provider result.
pub fn inspect(input: &Value) -> Result<Value, Failure> {
    let value = input
        .get("result")
        .or_else(|| input.get("normalized_result"))
        .or_else(|| input.get("observations"))
        .unwrap_or(input);

    project(value)
}

fn segment_items(value: &Value) -> Result<&[Value], Failure> {
    if let Some(items) = value.as_array() {
        return bounded_items(items);
    }

    let object = value
        .as_object()
        .ok_or_else(|| invalid("list-segments result must be an item array or worker page"))?;
    reject_unknown_page_fields(object)?;

    let items = object
        .get("items")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("list-segments worker page must contain an items array"))?;
    bounded_items(items)
}

fn bounded_items(items: &[Value]) -> Result<&[Value], Failure> {
    if items.len() > MAX_SEGMENTS {
        return Err(resource("list-segments result exceeds the segment limit"));
    }
    Ok(items)
}

fn project_item(item: &Value, index: usize) -> Result<Value, Failure> {
    let object = item
        .as_object()
        .ok_or_else(|| invalid(&format!("segments[{index}] must be an object")))?;
    reject_unknown_item_fields(object, index)?;

    let name = required_name(object, index)?;
    let start = required_address(object, "address", index)?;
    let end = required_address(object, "end", index)?;

    Ok(serde_json::json!({
        "name": name,
        "start": start,
        "end": end,
        "readable": null,
        "writable": null,
        "executable": null,
        "permissions": {
            "available": false,
            "reason": UNKNOWN_PERMISSIONS_REASON,
        },
        "provenance": "ghidra-rust-object-file-section",
        "sections": [],
    }))
}

fn reject_unknown_page_fields(object: &Map<String, Value>) -> Result<(), Failure> {
    for field in object.keys() {
        if field != "items" && field != "coverage" {
            return Err(invalid(&format!(
                "unknown list-segments page field `{field}`"
            )));
        }
    }
    let coverage = object
        .get("coverage")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("list-segments worker page must contain coverage"))?;
    if coverage.len() > MAX_COVERAGE_BYTES {
        return Err(resource("list-segments coverage exceeds the size limit"));
    }
    Ok(())
}

fn reject_unknown_item_fields(object: &Map<String, Value>, index: usize) -> Result<(), Failure> {
    for field in object.keys() {
        if !["name", "address", "end", "executable"].contains(&field.as_str()) {
            return Err(invalid(&format!(
                "unknown field `segments[{index}].{field}`"
            )));
        }
    }
    if object.get("executable").and_then(Value::as_bool).is_none() {
        return Err(invalid(&format!(
            "segments[{index}].executable must be a boolean"
        )));
    }
    Ok(())
}

fn required_name(object: &Map<String, Value>, index: usize) -> Result<String, Failure> {
    let name = object
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(&format!("segments[{index}].name must be a string")))?;
    if name.len() > MAX_NAME_BYTES {
        return Err(resource(
            "list-segments section name exceeds the size limit",
        ));
    }
    Ok(name.to_owned())
}

fn required_address(
    object: &Map<String, Value>,
    field: &str,
    index: usize,
) -> Result<String, Failure> {
    let value = object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| is_worker_address(value))
        .ok_or_else(|| {
            invalid(&format!(
                "segments[{index}].{field} must be a canonical worker address"
            ))
        })?;
    Ok(value.to_owned())
}

fn is_worker_address(value: &str) -> bool {
    let Some(digits) = value.strip_prefix("0x") else {
        return false;
    };
    !digits.is_empty()
        && digits.len() <= 16
        && digits.as_bytes().iter().all(u8::is_ascii_hexdigit)
        && (digits == "0" || !digits.starts_with('0'))
        && digits
            .chars()
            .all(|character| !character.is_ascii_uppercase())
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide a complete worker segment page and retry.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

fn resource(reason: &str) -> Failure {
    Failure::new(
        "resource_constraint",
        "resource_constraint",
        reason.to_owned(),
        false,
        "Select a segment inventory within the supported resource boundary.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
