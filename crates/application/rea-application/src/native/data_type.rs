//! Read-only validation and projection for native analysis-database type facts.
//!
//! The analysis provider owns type recovery.  This boundary deliberately does
//! not infer layouts from bytes or attach to an analysis database; it validates
//! an authenticated provider result and carries its identities and unknowns
//! forward unchanged.

use rea_core::failure::{Detail, Failure};
use serde_json::Value;
use std::collections::BTreeMap;

pub const OPERATION: &str = "inspect_native_data_type";

const KINDS: &[&str] = &[
    "struct",
    "union",
    "enum",
    "pointer",
    "array",
    "typedef",
    "scalar",
    "unsupported",
    "unavailable",
];

/// Validate a request containing one retained native type Evidence record.
pub fn validate_input(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("native data-type input must be an object"))?;

    const ALLOWED_INPUT_FIELDS: &[&str] = &[
        "evidence",
        "native_observation",
        "native_data_type",
        "type",
        "address",
        "document",
    ];
    if object
        .keys()
        .any(|key| !ALLOWED_INPUT_FIELDS.contains(&key.as_str()))
    {
        return Err(invalid("native data-type input contains unknown fields"));
    }

    if object
        .get("document")
        .is_some_and(|value| !value.is_string())
    {
        return Err(invalid("native data-type document must be a string"));
    }

    let evidence = object
        .get("evidence")
        .or_else(|| object.get("native_observation"))
        .or_else(|| object.get("native_data_type"))
        .ok_or_else(|| invalid("native data-type Evidence is required"))?;
    validate_evidence(evidence)?;

    let has_type = object
        .get("type")
        .is_some_and(|value| value.as_str().is_some_and(|text| !text.is_empty()));
    let has_address = object
        .get("address")
        .is_some_and(|value| value.as_str().is_some_and(|text| !text.is_empty()));
    if has_type == has_address {
        return Err(invalid(
            "supply exactly one non-empty type or address selector",
        ));
    }
    if object.get("type").is_some_and(|value| !value.is_string())
        || object
            .get("address")
            .is_some_and(|value| !value.is_string())
    {
        return Err(invalid("type and address selectors must be strings"));
    }
    Ok(())
}

/// Retain a provider result after checking the complete native data-type shape.
pub fn retain_result(input: &Value, result: Value) -> Result<Value, Failure> {
    validate_input(input)?;
    validate_result(&result)?;
    Ok(result)
}

/// Project a selected native type from caller-supplied Evidence.
pub fn inspect(input: &Value) -> Result<Value, Failure> {
    validate_input(input)?;
    let object = input
        .as_object()
        .ok_or_else(|| invalid("native data-type input must be an object"))?;
    let evidence = object
        .get("evidence")
        .or_else(|| object.get("native_observation"))
        .or_else(|| object.get("native_data_type"))
        .ok_or_else(|| invalid("native data-type Evidence is required"))?;
    let result = result_value(evidence)?;
    validate_result(result)?;

    if let Some(expected_type) = object.get("type").and_then(Value::as_str) {
        let identity_matches = [result.get("id"), result.get("name")]
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .any(|candidate| candidate == expected_type);
        if !identity_matches && result.get("status").and_then(Value::as_str) == Some("available") {
            return Err(invalid("retained native type does not match type selector"));
        }
    }
    if let Some(expected_address) = object.get("address").and_then(Value::as_str)
        && result.get("address").and_then(Value::as_str) != Some(expected_address)
        && result.get("status").and_then(Value::as_str) == Some("available")
    {
        return Err(invalid(
            "retained native type does not match address selector",
        ));
    }

    Ok(result.clone())
}

fn validate_evidence(evidence: &Value) -> Result<(), Failure> {
    let object = evidence
        .as_object()
        .ok_or_else(|| invalid("native data-type Evidence must be an object"))?;
    if let Some(operation) = object.get("operation").and_then(Value::as_str)
        && operation != OPERATION
    {
        return Err(invalid(
            "Evidence operation is not inspect_native_data_type",
        ));
    }
    if object
        .get("evidence_id")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Err(invalid(
            "native data-type Evidence must include evidence_id",
        ));
    }
    validate_result(result_value(evidence)?)
}

fn result_value(evidence: &Value) -> Result<&Value, Failure> {
    let result = evidence
        .get("normalized_result")
        .or_else(|| evidence.get("result"))
        .or_else(|| evidence.get("value"))
        .unwrap_or(evidence);
    if !result.is_object() {
        return Err(invalid(
            "native data-type Evidence result must be an object",
        ));
    }
    Ok(result)
}

fn validate_result(result: &Value) -> Result<(), Failure> {
    let object = result
        .as_object()
        .ok_or_else(|| invalid("native data-type result must be an object"))?;
    const ALLOWED_FIELDS: &[&str] = &[
        "status",
        "reason",
        "id",
        "name",
        "kind",
        "source",
        "source_archive",
        "address",
        "size_bytes",
        "alignment_bytes",
        "packing_enabled",
        "referenced_type",
        "array_count",
        "array_stride_bytes",
        "fields",
        "members",
        "total_fields",
        "truncated",
        "limitations",
        "metadata_recovery",
    ];
    if object
        .keys()
        .any(|key| !ALLOWED_FIELDS.contains(&key.as_str()))
    {
        return Err(invalid("native data-type result contains unknown fields"));
    }
    for field in [
        "status",
        "reason",
        "id",
        "name",
        "kind",
        "source",
        "source_archive",
        "address",
        "size_bytes",
        "alignment_bytes",
        "packing_enabled",
        "referenced_type",
        "array_count",
        "array_stride_bytes",
        "fields",
        "members",
        "total_fields",
        "truncated",
        "limitations",
    ] {
        if !object.contains_key(field) {
            return Err(invalid(&format!("native data-type result lacks {field}")));
        }
    }
    if !matches!(
        object.get("status").and_then(Value::as_str),
        Some("available" | "unavailable")
    ) || !nullable_string(object.get("reason"))
        || !nullable_string(object.get("id"))
        || !nullable_string(object.get("name"))
        || !object
            .get("kind")
            .and_then(Value::as_str)
            .is_some_and(|kind| KINDS.contains(&kind))
        || object.get("source").and_then(Value::as_str) != Some("analysis-database")
        || !nullable_string(object.get("source_archive"))
        || !nullable_string(object.get("address"))
        || !nullable_string(object.get("referenced_type"))
    {
        return Err(invalid(
            "native data-type result has invalid identity fields",
        ));
    }
    for field in ["size_bytes", "array_count", "array_stride_bytes"] {
        if !nullable_nonnegative_integer(object.get(field)) {
            return Err(invalid(&format!("native data-type {field} is invalid")));
        }
    }
    if !nullable_positive_integer(object.get("alignment_bytes"))
        || !object
            .get("packing_enabled")
            .is_some_and(|v| v.is_boolean() || v.is_null())
        || object.get("fields").and_then(Value::as_array).is_none()
        || object.get("members").and_then(Value::as_array).is_none()
        || !nonnegative_integer(object.get("total_fields"))
        || !object.get("truncated").is_some_and(Value::is_boolean)
        || !string_array(object.get("limitations"))
    {
        return Err(invalid("native data-type result has invalid layout fields"));
    }

    let fields = object
        .get("fields")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("native data-type fields must be an array"))?;
    for field in fields {
        validate_field(field)?;
    }
    let members = object
        .get("members")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("native data-type members must be an array"))?;
    for member in members {
        let member = member
            .as_object()
            .ok_or_else(|| invalid("native data-type member must be an object"))?;
        if member.len() != 2
            || member.get("name").and_then(Value::as_str).is_none()
            || member.get("value").and_then(Value::as_str).is_none()
        {
            return Err(invalid("native data-type member has invalid shape"));
        }
    }
    if let Some(metadata) = object.get("metadata_recovery")
        && !metadata.is_object()
    {
        return Err(invalid("metadata_recovery must be an object when present"));
    }
    Ok(())
}

fn validate_field(field: &Value) -> Result<(), Failure> {
    let object = field
        .as_object()
        .ok_or_else(|| invalid("native data-type field must be an object"))?;
    for name in [
        "ordinal",
        "name",
        "offset_bytes",
        "size_bytes",
        "type_id",
        "bit_size",
        "bit_offset",
        "status",
        "flexible_tail",
    ] {
        if !object.contains_key(name) {
            return Err(invalid(&format!("native data-type field lacks {name}")));
        }
    }
    if !nonnegative_integer(object.get("ordinal"))
        || !nullable_string(object.get("name"))
        || !nonnegative_integer(object.get("offset_bytes"))
        || !nullable_nonnegative_integer(object.get("size_bytes"))
        || object.get("type_id").and_then(Value::as_str).is_none()
        || !nullable_nonnegative_integer(object.get("bit_size"))
        || !nullable_nonnegative_integer(object.get("bit_offset"))
        || !matches!(
            object.get("status").and_then(Value::as_str),
            Some("observed" | "unsupported")
        )
        || object.get("flexible_tail").and_then(Value::as_str) != Some("unknown")
    {
        return Err(invalid("native data-type field has invalid shape"));
    }
    Ok(())
}

fn nullable_string(value: Option<&Value>) -> bool {
    value.is_some_and(|value| value.is_null() || value.as_str().is_some())
}

fn nonnegative_integer(value: Option<&Value>) -> bool {
    value.is_some_and(|value| value.as_u64().is_some())
}

fn nullable_nonnegative_integer(value: Option<&Value>) -> bool {
    value.is_some_and(|value| value.is_null() || value.as_u64().is_some())
}

fn nullable_positive_integer(value: Option<&Value>) -> bool {
    value.is_some_and(|value| value.is_null() || value.as_u64().is_some_and(|n| n > 0))
}

fn string_array(value: Option<&Value>) -> bool {
    value.is_some_and(|value| {
        value
            .as_array()
            .is_some_and(|items| items.iter().all(|item| item.as_str().is_some()))
    })
}

fn invalid(reason: &str) -> Failure {
    Failure::new_with_details(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide authenticated inspect_native_data_type Evidence and preserve layout uncertainty."
            .into(),
        BTreeMap::from([(String::from("operation"), Detail::Text(OPERATION.into()))]),
    )
}
