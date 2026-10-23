//! Read-only projection of retained `list_bookmarks` Evidence.
//!
//! The provider owns the Hopper document and bookmark store.  This boundary
//! validates already retained bookmark rows and preserves their order and
//! null labels; it never opens a database or queries a live provider.

use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub const OPERATION: &str = "list_bookmarks";
pub const MAX_ROWS: usize = 200_000;
pub const MAX_RETAINED_BYTES: usize = 16 * 1024 * 1024;

const INPUT_FIELDS: &[&str] = &[
    "bookmarks",
    "document",
    "evidence",
    "inventory",
    "native_observation",
    "observations",
];
const ROW_FIELDS: &[&str] = &["address", "name"];

/// Validate a caller-owned bookmark inventory and every retained row.
pub fn validate_input(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("list_bookmarks input must be an object"))?;
    reject_unknown_fields(object)?;

    if let Some(document) = object.get("document") {
        require_non_empty_string(document, "document")?;
    }

    if let Some(bookmarks) = object.get("bookmarks").or_else(|| object.get("inventory")) {
        validate_rows(bookmarks, "bookmark inventory")?;
    }
    if let Some(evidence) = object
        .get("evidence")
        .or_else(|| object.get("native_observation"))
    {
        validate_evidence(evidence)?;
    }
    if let Some(observations) = object.get("observations") {
        let observations = observations
            .as_array()
            .ok_or_else(|| invalid("observations must be an array"))?;
        if observations.len() > MAX_ROWS {
            return Err(invalid("observations exceed the 200000 record limit"));
        }
        for observation in observations {
            validate_evidence(observation)?;
        }
    }

    if !has_inventory_source(object) {
        return Err(invalid(
            "list_bookmarks requires retained bookmark Evidence",
        ));
    }
    Ok(())
}

/// Return retained bookmark rows in provider order.
pub fn project(input: &Value) -> Result<Value, Failure> {
    validate_input(input)?;
    let object = input
        .as_object()
        .expect("validated list_bookmarks input object");
    let rows = resolve_rows(object)?;
    let result = Value::Array(rows);
    enforce_retained_size(&result)?;
    Ok(result)
}

/// Validate a provider result before the runtime wraps it in Evidence.
pub fn retain_result(input: &Value, result: Value) -> Result<Value, Failure> {
    validate_input(input)?;
    validate_rows(&result, "list_bookmarks result")?;
    enforce_retained_size(&result)?;
    Ok(result)
}

pub fn list(input: &Value) -> Result<Value, Failure> {
    project(input)
}

pub fn inspect(input: &Value) -> Result<Value, Failure> {
    project(input)
}

fn resolve_rows(object: &Map<String, Value>) -> Result<Vec<Value>, Failure> {
    let mut rows = Vec::new();
    if let Some(bookmarks) = object.get("bookmarks").or_else(|| object.get("inventory")) {
        append_rows(bookmarks, &mut rows, "bookmark inventory")?;
    }
    if let Some(evidence) = object
        .get("evidence")
        .or_else(|| object.get("native_observation"))
    {
        append_evidence_rows(evidence, &mut rows)?;
    }
    if let Some(observations) = object.get("observations").and_then(Value::as_array) {
        for observation in observations {
            append_evidence_rows(observation, &mut rows)?;
        }
    }
    if rows.is_empty() && !object.contains_key("bookmarks") && !object.contains_key("inventory") {
        return Err(invalid(
            "list_bookmarks requires retained bookmark Evidence",
        ));
    }
    Ok(rows)
}

fn append_evidence_rows(evidence: &Value, rows: &mut Vec<Value>) -> Result<(), Failure> {
    let result = result_value(evidence)?;
    let values = rows_from_value(result, "bookmark Evidence")?;
    append_values(values, rows, "bookmark Evidence")
}

fn append_rows(value: &Value, rows: &mut Vec<Value>, label: &str) -> Result<(), Failure> {
    let values = rows_from_value(value, label)?;
    append_values(values, rows, label)
}

fn append_values(values: Vec<Value>, rows: &mut Vec<Value>, label: &str) -> Result<(), Failure> {
    if rows.len().saturating_add(values.len()) > MAX_ROWS {
        return Err(invalid(&format!("{label} exceeds the 200000 record limit")));
    }
    rows.extend(values);
    Ok(())
}

fn rows_from_value(value: &Value, label: &str) -> Result<Vec<Value>, Failure> {
    if let Some(items) = value.get("items") {
        return rows_from_value(items, label);
    }
    if let Some(bookmarks) = value.get("bookmarks") {
        return rows_from_value(bookmarks, label);
    }
    if let Some(value) = value.get("value") {
        return rows_from_value(value, label);
    }
    validate_rows(value, label)?;
    Ok(value.as_array().expect("validated bookmark rows").clone())
}

fn validate_rows(value: &Value, label: &str) -> Result<(), Failure> {
    let rows = value
        .as_array()
        .ok_or_else(|| invalid(&format!("{label} must be an array")))?;
    if rows.len() > MAX_ROWS {
        return Err(invalid(&format!("{label} exceeds the 200000 record limit")));
    }
    for (index, row) in rows.iter().enumerate() {
        validate_row(row, &format!("{label}[{index}]"))?;
    }
    Ok(())
}

fn validate_row(value: &Value, label: &str) -> Result<(), Failure> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid(&format!("{label} must be an object")))?;
    if let Some(field) = object
        .keys()
        .find(|field| !ROW_FIELDS.contains(&field.as_str()))
    {
        return Err(invalid(&format!("{label} contains unknown field {field}")));
    }
    require_non_empty_string(
        object
            .get("address")
            .ok_or_else(|| invalid(&format!("{label}.address is required")))?,
        &format!("{label}.address"),
    )?;
    let name = object
        .get("name")
        .ok_or_else(|| invalid(&format!("{label}.name is required")))?;
    if !name.is_null() && name.as_str().is_none() {
        return Err(invalid(&format!("{label}.name must be a string or null")));
    }
    Ok(())
}

fn validate_evidence(evidence: &Value) -> Result<(), Failure> {
    let object = evidence
        .as_object()
        .ok_or_else(|| invalid("list_bookmarks Evidence must be an object"))?;
    if object
        .get("evidence_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .is_none()
    {
        return Err(invalid("list_bookmarks Evidence must include evidence_id"));
    }
    if let Some(operation) = object.get("operation").and_then(Value::as_str) {
        if operation != OPERATION {
            return Err(invalid("Evidence does not contain bookmark observations"));
        }
    }
    let _ = result_value(evidence)?;
    Ok(())
}

fn result_value(evidence: &Value) -> Result<&Value, Failure> {
    evidence
        .get("normalized_result")
        .or_else(|| evidence.get("result"))
        .or_else(|| evidence.get("value"))
        .ok_or_else(|| invalid("bookmark Evidence has no normalized result"))
}

fn enforce_retained_size(value: &Value) -> Result<(), Failure> {
    let bytes =
        serde_json::to_vec(value).map_err(|_| invalid("bookmark result is not serializable"))?;
    if bytes.len() > MAX_RETAINED_BYTES {
        return Err(Failure::new(
            "resource_constraint",
            "resource_constraint",
            "Retained bookmark inventory exceeds the configured size limit.".into(),
            false,
            "Provide a bounded bookmark inventory and retry.".into(),
            BTreeMap::from([
                ("operation", Detail::Text(OPERATION.into())),
                (
                    "max_retained_bytes",
                    Detail::Count(MAX_RETAINED_BYTES as u64),
                ),
            ]),
        ));
    }
    Ok(())
}

fn reject_unknown_fields(object: &Map<String, Value>) -> Result<(), Failure> {
    if let Some(field) = object
        .keys()
        .find(|field| !INPUT_FIELDS.contains(&field.as_str()))
    {
        return Err(invalid(&format!(
            "unknown list_bookmarks input field: {field}"
        )));
    }
    Ok(())
}

fn has_inventory_source(object: &Map<String, Value>) -> bool {
    object.contains_key("bookmarks")
        || object.contains_key("inventory")
        || object.contains_key("evidence")
        || object.contains_key("native_observation")
        || object.contains_key("observations")
}

fn require_non_empty_string(value: &Value, field: &str) -> Result<(), Failure> {
    if value.as_str().is_none_or(str::is_empty) {
        return Err(invalid(&format!("{field} must be a non-empty string")));
    }
    Ok(())
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide retained list_bookmarks Evidence or a bounded bookmark inventory.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
