//! Read-only projection of native annotation observations.
//!
//! The provider owns address resolution and document selection.  This module
//! validates retained results for `address_name`, `comment`, and
//! `inline_comment`; it does not open a database or perform annotation edits.
//! Address strings are deliberately treated as opaque so address-space names,
//! spelling, and leading zeroes remain available to callers.

use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub const OPERATIONS: &[&str] = &["address_name", "comment", "inline_comment"];

/// Validate a caller-selected retained annotation observation.
pub fn validate_input(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("native annotation input must be an object"))?;
    reject_unknown_fields(object)?;

    // The public retained-observation contract requires the canonical
    // `evidence` field.  Legacy adapter aliases remain readable below, but
    // they cannot satisfy the public boundary on their own.
    if !object.contains_key("evidence") {
        return Err(invalid("native annotation Evidence is required"));
    }

    let evidence = selected_evidence(object)?;
    validate_evidence(evidence, object.get("operation").and_then(Value::as_str))?;

    if let Some(document) = object.get("document") {
        validate_optional_text(document, "document")?;
    }
    if let Some(address) = object.get("address") {
        validate_optional_text(address, "address")?;
    }
    Ok(())
}

/// Return the exact nullable annotation text from retained Evidence.
pub fn project(input: &Value) -> Result<Value, Failure> {
    validate_input(input)?;
    let object = input
        .as_object()
        .ok_or_else(|| invalid("native annotation input must be an object"))?;
    let evidence = selected_evidence(object)?;
    annotation_value(evidence)
}

/// Alias used by operation-oriented application adapters.
pub fn inspect(input: &Value) -> Result<Value, Failure> {
    project(input)
}

/// Validate a provider result before the runtime wraps it in Evidence.
pub fn retain_result(input: &Value, result: Value) -> Result<Value, Failure> {
    validate_input(input)?;
    validate_annotation_result(&result)?;
    Ok(result)
}

fn selected_evidence<'a>(object: &'a Map<String, Value>) -> Result<&'a Value, Failure> {
    object
        .get("evidence")
        .or_else(|| object.get("native_observation"))
        .or_else(|| object.get("annotation"))
        .ok_or_else(|| invalid("native annotation Evidence is required"))
}

fn validate_evidence(evidence: &Value, requested_operation: Option<&str>) -> Result<(), Failure> {
    let object = evidence
        .as_object()
        .ok_or_else(|| invalid("native annotation Evidence must be an object"))?;
    let evidence_operation = object.get("operation").and_then(Value::as_str);
    if let (Some(evidence_operation), Some(requested_operation)) =
        (evidence_operation, requested_operation)
        && evidence_operation != requested_operation
    {
        return Err(invalid(
            "requested operation disagrees with Evidence operation",
        ));
    }
    let operation = evidence_operation
        .or(requested_operation)
        .ok_or_else(|| invalid("native annotation operation is required"))?;
    if !OPERATIONS.contains(&operation) {
        return Err(invalid(
            "Evidence operation is not a native annotation observation",
        ));
    }
    validate_evidence_identity(object, "evidence_id")?;
    if let Some(document) = object.get("document") {
        validate_optional_text(document, "Evidence.document")?;
    }
    if let Some(address) = object.get("address") {
        validate_optional_text(address, "Evidence.address")?;
    }
    validate_annotation_result(&annotation_value(evidence)?)
}

fn annotation_value(evidence: &Value) -> Result<Value, Failure> {
    let result = evidence
        .get("normalized_result")
        .or_else(|| evidence.get("result"))
        .or_else(|| evidence.get("value"))
        .unwrap_or(evidence);

    if result.is_null() || result.is_string() {
        return Ok(result.clone());
    }

    if let Some(value) = result.get("value") {
        if value.is_null() || value.is_string() {
            return Ok(value.clone());
        }
    }

    Err(invalid("native annotation result must be a string or null"))
}

fn validate_annotation_result(result: &Value) -> Result<(), Failure> {
    if result.is_null() {
        return Ok(());
    }
    if result.as_str().is_none() {
        return Err(invalid("native annotation result must be a string or null"));
    }
    Ok(())
}

fn validate_evidence_identity(object: &Map<String, Value>, field: &str) -> Result<(), Failure> {
    if object
        .get(field)
        .and_then(Value::as_str)
        .is_some_and(|value| !value.is_empty())
    {
        return Ok(());
    }
    if object.get(field).is_none() {
        return Ok(());
    }
    Err(invalid("Evidence identity must be a non-empty string"))
}

fn validate_optional_text(value: &Value, field: &str) -> Result<(), Failure> {
    if value.is_null() || value.as_str().is_some_and(|text| !text.is_empty()) {
        return Ok(());
    }
    Err(invalid(&format!(
        "{field} must be null or a non-empty string"
    )))
}

fn reject_unknown_fields(object: &Map<String, Value>) -> Result<(), Failure> {
    const FIELDS: &[&str] = &[
        "address",
        "annotation",
        "document",
        "evidence",
        "native_observation",
        "operation",
    ];
    if object.keys().any(|key| !FIELDS.contains(&key.as_str())) {
        return Err(invalid("native annotation input contains an unknown field"));
    }
    Ok(())
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide retained native annotation Evidence and retry.".into(),
        BTreeMap::from([("operation", Detail::Text("native_annotation".into()))]),
    )
}
