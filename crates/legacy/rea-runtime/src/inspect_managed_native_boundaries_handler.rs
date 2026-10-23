//! Captured-Evidence-only adapter for managed native-boundary inspection.
//!
//! The managed artifact reader owns PE/CLI decoding. This adapter authenticates
//! a retained boundary report and returns its declaration facts without
//! reopening the artifact or treating managed tokens as native addresses.

use rea_core::{
    evidence::record::EvidenceRecord,
    failure::{Detail, Failure},
};
use serde_json::Value;
use std::collections::BTreeMap;

pub const OPERATION: &str = "inspect_managed_native_boundaries";

/// Project one complete retained managed-boundary Evidence record.
pub fn handle(input: &Value) -> Result<Value, Failure> {
    let request = input
        .as_object()
        .ok_or_else(|| invalid("input must be an object"))?;
    if request.len() != 1 || !request.contains_key("evidence") {
        return Err(invalid("input must contain exactly the evidence field"));
    }

    let evidence = request
        .get("evidence")
        .ok_or_else(|| invalid("evidence is required"))?;
    let raw = serde_json::value::to_raw_value(evidence)
        .map_err(|error| invalid(&format!("evidence could not be encoded: {error}")))?;
    let record = EvidenceRecord::parse(&raw)
        .map_err(|error| invalid(&format!("evidence is invalid: {error}")))?;
    if !record.operation_matches(OPERATION) {
        return Err(invalid(
            "evidence operation must be inspect_managed_native_boundaries",
        ));
    }
    if record.predicate_type().get() != "\"rea.analysis\"" {
        return Err(invalid("evidence predicate_type must be rea.analysis"));
    }

    let result: Value = serde_json::from_str(record.normalized_result().get())
        .map_err(|error| invalid(&format!("managed boundary result is invalid JSON: {error}")))?;
    let object = result
        .as_object()
        .ok_or_else(|| invalid("managed boundary result must be an object"))?;
    require_text(object, "path")?;
    validate_sha256(object, "sha256")?;
    require_array(object, "module_refs")?;
    require_array(object, "pinvoke_imports")?;
    require_array(object, "native_implementations")?;
    require_object(object, "summary")?;
    require_object(object, "coverage")?;
    require_strings(object, "limitations")?;
    Ok(result)
}

fn require_text(object: &serde_json::Map<String, Value>, field: &str) -> Result<(), Failure> {
    if object
        .get(field)
        .and_then(Value::as_str)
        .is_some_and(|value| !value.is_empty())
    {
        Ok(())
    } else {
        Err(invalid(&format!(
            "managed boundary result requires {field}"
        )))
    }
}

fn validate_sha256(object: &serde_json::Map<String, Value>, field: &str) -> Result<(), Failure> {
    let value = object
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("managed boundary result requires artifact SHA-256"))?;
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        Ok(())
    } else {
        Err(invalid("managed boundary artifact SHA-256 is invalid"))
    }
}

fn require_array(object: &serde_json::Map<String, Value>, field: &str) -> Result<(), Failure> {
    if object.get(field).is_some_and(Value::is_array) {
        Ok(())
    } else {
        Err(invalid(&format!(
            "managed boundary result requires {field}"
        )))
    }
}

fn require_object(object: &serde_json::Map<String, Value>, field: &str) -> Result<(), Failure> {
    if object.get(field).is_some_and(Value::is_object) {
        Ok(())
    } else {
        Err(invalid(&format!(
            "managed boundary result requires {field}"
        )))
    }
}

fn require_strings(object: &serde_json::Map<String, Value>, field: &str) -> Result<(), Failure> {
    let values = object
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(&format!("managed boundary result requires {field}")))?;
    if values.iter().all(|value| value.as_str().is_some()) {
        Ok(())
    } else {
        Err(invalid(&format!(
            "managed boundary {field} must contain strings"
        )))
    }
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "Managed native-boundary Evidence input is invalid.".into(),
        false,
        "Provide retained inspect_managed_native_boundaries Evidence and retry.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("reason", Detail::Text(reason.into())),
            ("authority", Detail::Text("offline_capture_only".into())),
        ]),
    )
}
