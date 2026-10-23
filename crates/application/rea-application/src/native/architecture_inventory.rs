//! Read-only projection of native architecture inventory Evidence.
//!
//! Architecture discovery is owned by the native provider (normally `lipo`).
//! This module deliberately does not open binaries or run a provider.  It
//! validates the retained provider result and returns the stable application
//! shape while keeping nullable facts and source provenance intact.

use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub const OPERATION: &str = "list_architectures";
const MAX_ARCHITECTURES: usize = 200_000;

/// Validate a retained architecture result without accessing a target.
pub fn validate_input(input: &Value) -> Result<(), Failure> {
    let result = result_value(input)?;
    validate_result(result)
}

/// Project a provider result, preserving the provider's exact architecture
/// spelling, nullable metadata, provenance, and limitations.
pub fn project(input: &Value) -> Result<Value, Failure> {
    validate_input(input)?;
    Ok(result_value(input)?.clone())
}

/// Validate a result before the runtime wraps it in derived Evidence.
pub fn retain_result(input: &Value, result: Value) -> Result<Value, Failure> {
    let _ = input;
    validate_result(&result)?;
    Ok(result)
}

fn result_value(input: &Value) -> Result<&Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("architecture inventory must be an object"))?;

    // Retained Evidence commonly stores its normalized payload under one of
    // these fields.  A direct provider result is also accepted for adapters.
    Ok(object
        .get("normalized_result")
        .or_else(|| object.get("result"))
        .unwrap_or(input))
}

fn validate_result(value: &Value) -> Result<(), Failure> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid("architecture result must be an object"))?;
    reject_unknown_fields(object, &["architectures", "provenance", "limitations"])?;

    let coverage = object
        .get("architectures")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("architecture result requires architectures coverage"))?;
    reject_unknown_fields(coverage, &["items", "total", "exhaustive", "limitations"])?;

    let items = coverage
        .get("items")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("architectures.items must be an array"))?;
    if items.len() > MAX_ARCHITECTURES {
        return Err(invalid(
            "architecture inventory exceeds the 200000 record limit",
        ));
    }
    for (index, item) in items.iter().enumerate() {
        validate_architecture(item, index)?;
    }

    let total = coverage
        .get("total")
        .ok_or_else(|| invalid("architectures.total is required"))?;
    if !total.is_null() && !is_nonnegative_integer(total) {
        return Err(invalid(
            "architectures.total must be a non-negative integer or null",
        ));
    }
    if coverage
        .get("exhaustive")
        .and_then(Value::as_bool)
        .is_none()
    {
        return Err(invalid("architectures.exhaustive must be boolean"));
    }
    validate_string_array(
        coverage
            .get("limitations")
            .ok_or_else(|| invalid("architectures.limitations is required"))?,
        "architectures.limitations",
    )?;
    validate_provenance(
        object
            .get("provenance")
            .ok_or_else(|| invalid("architecture result provenance is required"))?,
    )?;
    validate_string_array(
        object
            .get("limitations")
            .ok_or_else(|| invalid("architecture result limitations are required"))?,
        "limitations",
    )?;

    Ok(())
}

fn validate_architecture(value: &Value, index: usize) -> Result<(), Failure> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid(&format!("architectures.items[{index}] must be an object")))?;
    reject_unknown_fields(
        object,
        &[
            "name",
            "cpu_type",
            "cpu_subtype",
            "cpu_type_code",
            "cpu_subtype_code",
            "cpu_subtype_base",
            "capabilities",
            "file_offset",
            "size",
            "alignment",
        ],
    )?;
    require_non_empty_string(
        object,
        "name",
        "architecture name must be a non-empty string",
    )?;
    validate_required_nullable_strings(object, &["cpu_type", "cpu_subtype"])?;
    validate_optional_nullable_integers(
        object,
        &["cpu_type_code", "cpu_subtype_code", "cpu_subtype_base"],
    )?;
    validate_required_nullable_string(object, "capabilities")?;
    validate_required_nullable_integers(object, &["file_offset", "size", "alignment"])?;

    Ok(())
}

fn validate_required_nullable_strings(
    object: &Map<String, Value>,
    fields: &[&str],
) -> Result<(), Failure> {
    for field in fields {
        if !object
            .get(*field)
            .is_some_and(|value| value.is_null() || value.is_string())
        {
            return Err(invalid(&format!(
                "architecture {field} must be a string or null"
            )));
        }
    }
    Ok(())
}

fn validate_required_nullable_string(
    object: &Map<String, Value>,
    field: &str,
) -> Result<(), Failure> {
    if !object
        .get(field)
        .is_some_and(|value| value.is_null() || value.is_string())
    {
        return Err(invalid(&format!(
            "architecture {field} must be a string or null"
        )));
    }

    Ok(())
}

fn validate_optional_nullable_integers(
    object: &Map<String, Value>,
    fields: &[&str],
) -> Result<(), Failure> {
    for field in fields {
        if let Some(value) = object.get(*field) {
            if !(value.is_null() || is_nonnegative_integer(value)) {
                return Err(invalid(&format!(
                    "architecture {field} must be a non-negative integer or null"
                )));
            }
        }
    }
    Ok(())
}

fn validate_required_nullable_integers(
    object: &Map<String, Value>,
    fields: &[&str],
) -> Result<(), Failure> {
    for field in fields {
        if !object
            .get(*field)
            .is_some_and(|value| value.is_null() || is_nonnegative_integer(value))
        {
            return Err(invalid(&format!(
                "architecture {field} must be a non-negative integer or null"
            )));
        }
    }
    Ok(())
}

fn reject_unknown_fields(object: &Map<String, Value>, allowed: &[&str]) -> Result<(), Failure> {
    if let Some(key) = object.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(invalid(&format!(
            "unknown architecture result field: {key}"
        )));
    }
    Ok(())
}

fn validate_string_array(value: &Value, field: &str) -> Result<(), Failure> {
    let values = value
        .as_array()
        .ok_or_else(|| invalid(&format!("{field} must be an array")))?;
    if values.iter().any(|value| value.as_str().is_none()) {
        return Err(invalid(&format!("{field} must contain only strings")));
    }
    Ok(())
}

fn validate_provenance(value: &Value) -> Result<(), Failure> {
    let entries = value
        .as_array()
        .ok_or_else(|| invalid("provenance must be an array"))?;

    for (index, entry) in entries.iter().enumerate() {
        let object = entry
            .as_object()
            .ok_or_else(|| invalid(&format!("provenance[{index}] must be an object")))?;
        reject_unknown_fields(
            object,
            &[
                "tool",
                "command",
                "tool_version",
                "version_reason",
                "executable_sha256",
                "exit",
                "stdout_bytes",
                "stderr_bytes",
            ],
        )?;

        require_non_empty_string(object, "tool", "provenance tool must be a non-empty string")?;
        let command = object
            .get("command")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("provenance command must be an array"))?;
        if command.iter().any(|argument| argument.as_str().is_none()) {
            return Err(invalid("provenance command must contain only strings"));
        }

        for field in ["tool_version", "version_reason"] {
            if !object
                .get(field)
                .is_some_and(|value| value.is_null() || value.is_string())
            {
                return Err(invalid(&format!(
                    "provenance {field} must be a string or null"
                )));
            }
        }

        let digest = object
            .get("executable_sha256")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("provenance executable_sha256 must be a string"))?;
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(invalid(
                "provenance executable_sha256 must be a lowercase SHA-256 digest",
            ));
        }

        let exit = object
            .get("exit")
            .and_then(Value::as_object)
            .ok_or_else(|| invalid("provenance exit must be an object"))?;
        reject_unknown_fields(exit, &["code", "signal"])?;
        if !exit
            .get("code")
            .is_some_and(|value| value.is_null() || is_integer(value))
        {
            return Err(invalid("provenance exit.code must be an integer or null"));
        }
        if !exit
            .get("signal")
            .is_some_and(|value| value.is_null() || value.is_string())
        {
            return Err(invalid("provenance exit.signal must be a string or null"));
        }

        for field in ["stdout_bytes", "stderr_bytes"] {
            let bytes = object
                .get(field)
                .ok_or_else(|| invalid(&format!("provenance {field} is required")))?;
            if !is_nonnegative_integer(bytes) {
                return Err(invalid(&format!(
                    "provenance {field} must be a non-negative integer"
                )));
            }
        }
    }

    Ok(())
}

fn require_non_empty_string(
    object: &Map<String, Value>,
    field: &str,
    message: &str,
) -> Result<(), Failure> {
    if object
        .get(field)
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Err(invalid(message));
    }
    Ok(())
}

fn is_integer(value: &Value) -> bool {
    value.as_i64().is_some() || value.as_u64().is_some()
}

fn is_nonnegative_integer(value: &Value) -> bool {
    value.as_u64().is_some() && value.as_f64().is_some_and(f64::is_finite)
}

fn invalid(reason: &str) -> Failure {
    Failure::new_with_details(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide retained list_architectures Evidence with validated coverage.".into(),
        BTreeMap::from([(String::from("operation"), Detail::Text(OPERATION.into()))]),
    )
}
