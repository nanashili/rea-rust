//! Captured-only boundary for `inspect_rust_binary`.
//!
//! The legacy inspection type owns stable-file reads and session Evidence.
//! This adapter accepts a bounded byte snapshot or authenticated retained
//! Evidence so the public operation can be used without target authority.

use base64::Engine;
use rea_core::{
    evidence::record::EvidenceRecord,
    failure::{Detail, Failure},
};
use rea_application::binary;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

pub const OPERATION: &str = "inspect_rust_binary";

pub fn dispatch(input: Value) -> Result<Value, Failure> {
    let object = input_object(&input)?;

    if let Some(evidence) = object.get("evidence") {
        if object.len() != 1 {
            return Err(invalid("Evidence input must contain only evidence"));
        }
        return replay_evidence(evidence);
    }

    if object.contains_key("result") || object.contains_key("normalized_result") {
        return replay_result(object);
    }

    let path = required_path(object)?;
    let encoded = object
        .get("bytes_base64")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("captured byte input requires bytes_base64"))?;
    if object.keys().any(|key| !["path", "bytes_base64", "sha256"].contains(&key.as_str())) {
        return Err(invalid("captured byte input contains an unknown field"));
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|error| invalid(&format!("bytes_base64 is invalid: {error}")))?;
    let result = binary::rust::inspect_captured(path, &bytes)?;

    if let Some(expected) = object.get("sha256").and_then(Value::as_str) {
        let actual = result
            .get("artifact")
            .and_then(Value::as_object)
            .and_then(|artifact| artifact.get("sha256"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        if expected != actual {
            return Err(integrity("captured artifact SHA-256 does not match sha256"));
        }
    }

    Ok(json!({
        "result": result,
        "provenance": {
            "operation": OPERATION,
            "source": "caller-supplied-artifact-bytes",
            "execution": "none"
        }
    }))
}

fn replay_evidence(evidence: &Value) -> Result<Value, Failure> {
    let raw = serde_json::value::to_raw_value(evidence)
        .map_err(|error| invalid(&format!("Evidence is not serializable: {error}")))?;
    let record = EvidenceRecord::parse(&raw)
        .map_err(|error| integrity(&format!("Evidence is invalid: {error}")))?;
    if !record.operation_matches(OPERATION) {
        return Err(integrity("Evidence operation does not match inspect_rust_binary"));
    }
    let result: Value = serde_json::from_str(record.normalized_result().get())
        .map_err(|error| integrity(&format!("Evidence result is invalid JSON: {error}")))?;
    Ok(json!({
        "result": result,
        "evidence_id": record.evidence_id(),
        "provenance": {
            "operation": OPERATION,
            "source": "authenticated-retained-evidence",
            "execution": "unknown"
        }
    }))
}

fn replay_result(object: &Map<String, Value>) -> Result<Value, Failure> {
    if object.keys().any(|key| {
        !["result", "normalized_result", "evidence_id"].contains(&key.as_str())
    }) {
        return Err(invalid("retained result input contains an unknown field"));
    }
    let result = object
        .get("normalized_result")
        .or_else(|| object.get("result"))
        .ok_or_else(|| invalid("retained result is required"))?;
    Ok(json!({
        "result": result,
        "evidence_id": object.get("evidence_id"),
        "provenance": {
            "operation": OPERATION,
            "source": "caller-supplied-retained-result",
            "execution": "unknown"
        }
    }))
}

fn input_object(input: &Value) -> Result<&Map<String, Value>, Failure> {
    input
        .as_object()
        .ok_or_else(|| invalid("inspect_rust_binary input must be an object"))
}

fn required_path(object: &Map<String, Value>) -> Result<&str, Failure> {
    object
        .get("path")
        .and_then(Value::as_str)
        .filter(|path| !path.is_empty() && !path.contains('\0'))
        .ok_or_else(|| invalid("path must be a non-empty NUL-free string"))
}

fn invalid(message: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        message.into(),
        false,
        "Provide a bounded Rust binary snapshot or authenticated retained Evidence.".into(),
        details(),
    )
}

fn integrity(message: &str) -> Failure {
    Failure::new(
        "integrity_error",
        "integrity_error",
        message.into(),
        false,
        "Provide intact retained Evidence for inspect_rust_binary.".into(),
        details(),
    )
}

fn details() -> BTreeMap<&'static str, Detail> {
    BTreeMap::from([( "operation", Detail::Text(OPERATION.into()) )])
}
