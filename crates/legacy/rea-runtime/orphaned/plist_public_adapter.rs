//! Captured-only public boundary for inspect_plist.

use base64::Engine;
use rea_application::apple::plist;
use rea_core::{
    evidence::record::EvidenceRecord,
    failure::{Detail, Failure},
};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

pub const OPERATION: &str = "inspect_plist";

pub fn dispatch(input: Value) -> Result<Value, Failure> {
    let object = input_object(&input)?;

    if let Some(evidence) = object.get("evidence") {
        if object.len() != 1 || !evidence.is_object() {
            return Err(invalid("Evidence input must contain only a non-empty evidence object"));
        }
        return project_evidence(evidence);
    }

    validate_byte_input(object)?;
    let path = required_text(object, "path")?;
    let encoded = required_text(object, "bytes_base64")?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| invalid("bytes_base64 is malformed"))?;
    if bytes.len() > plist::MAX_INPUT_BYTES {
        return Err(invalid("property-list bytes exceed the admitted size"));
    }

    let parsed = plist::inspect(&json!({
        "path": path,
        "bytes_base64": encoded,
    }))?;
    let result = public_result(&parsed)?;

    Ok(json!({
        "result": result,
        "provenance": {
            "source": "caller-supplied-plist-bytes",
            "execution": "none",
        },
    }))
}

fn validate_byte_input(object: &Map<String, Value>) -> Result<(), Failure> {
    for key in object.keys() {
        if !matches!(key.as_str(), "path" | "bytes_base64") {
            return Err(invalid(&format!("input contains unknown field: {key}")));
        }
    }
    let path = required_text(object, "path")?;
    if path.contains('\0') {
        return Err(invalid("path must not contain NUL bytes"));
    }
    let encoded = required_text(object, "bytes_base64")?;
    if encoded.is_empty() {
        return Err(invalid("bytes_base64 must not be empty"));
    }
    Ok(())
}

fn project_evidence(value: &Value) -> Result<Value, Failure> {
    let raw = serde_json::value::to_raw_value(value)
        .map_err(|error| integrity(&error.to_string()))?;
    let record = EvidenceRecord::parse(&raw).map_err(|error| integrity(&error.to_string()))?;
    if !record.operation_matches(OPERATION) {
        return Err(integrity("captured Evidence operation does not match inspect_plist"));
    }
    let normalized: Value = serde_json::from_str(record.normalized_result().get())
        .map_err(|error| integrity(&error.to_string()))?;
    let result = public_result(&normalized)?;
    let subject: Value = serde_json::from_str(record.subject().get())
        .map_err(|error| integrity(&error.to_string()))?;

    Ok(json!({
        "evidence_id": record.evidence_id(),
        "subject": subject,
        "result": result,
        "provenance": {
            "source": "authenticated-captured-evidence",
            "execution": "unknown",
        },
    }))
}

fn public_result(value: &Value) -> Result<Value, Failure> {
    let object = value
        .as_object()
        .ok_or_else(|| integrity("property-list result must be an object"))?;
    let format = object
        .get("format")
        .and_then(Value::as_str)
        .filter(|value| matches!(*value, "xml" | "binary" | "json" | "unknown"))
        .ok_or_else(|| integrity("property-list result has an invalid format"))?;
    let bundle = object
        .get("bundle")
        .and_then(Value::as_object)
        .ok_or_else(|| integrity("property-list result has no bundle object"))?;
    for field in ["identifier", "executable", "name", "version", "short_version"] {
        if !bundle
            .get(field)
            .is_some_and(|value| value.is_null() || value.is_string())
        {
            return Err(integrity(&format!("property-list bundle field {field} is invalid")));
        }
    }
    let source_path = object
        .get("source_path")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && !value.contains('\0'))
        .ok_or_else(|| integrity("property-list result has an invalid source_path"))?;
    let provenance = object
        .get("provenance")
        .and_then(Value::as_array)
        .ok_or_else(|| integrity("property-list result has invalid provenance"))?;
    let limitations = object
        .get("limitations")
        .and_then(Value::as_array)
        .ok_or_else(|| integrity("property-list result has invalid limitations"))?;
    if limitations.iter().any(|value| !value.is_string()) {
        return Err(integrity("property-list limitations must contain strings"));
    }
    let result_value = object
        .get("value")
        .cloned()
        .ok_or_else(|| integrity("property-list result has no value"))?;

    Ok(json!({
        "format": format,
        "value": result_value,
        "bundle": bundle,
        "source_path": source_path,
        "provenance": provenance,
        "limitations": limitations,
    }))
}

fn input_object(input: &Value) -> Result<&Map<String, Value>, Failure> {
    input
        .as_object()
        .ok_or_else(|| invalid("input must be an object"))
}

fn required_text<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a str, Failure> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid(&format!("{field} must be non-empty text")))
}

fn invalid(message: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        message.into(),
        true,
        "Correct the inspect_plist input and retry.".into(),
        BTreeMap::from([("operation".into(), Detail::Text(OPERATION.into()))]),
    )
}

fn integrity(message: &str) -> Failure {
    Failure::new(
        "evidence_integrity_failed",
        "evidence_integrity",
        message.into(),
        false,
        "Supply authenticated inspect_plist Evidence and retry.".into(),
        BTreeMap::from([("operation".into(), Detail::Text(OPERATION.into()))]),
    )
}
