//! Captured-only boundary for `inspect_managed_artifact`.
//!
//! The normal managed inspection owns stable-file access. This adapter accepts
//! caller-supplied bytes or authenticated retained Evidence and never opens a
//! path, launches a provider, or executes managed code.

use base64::Engine;
use rea_application::managed;
use rea_core::{evidence::record::EvidenceRecord, failure::{Detail, Failure}};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

pub const OPERATION: &str = managed::artifact::OPERATION;

pub fn dispatch(input: Value) -> Result<Value, Failure> {
    let object = input.as_object().ok_or_else(|| invalid("input must be an object"))?;

    if let Some(evidence) = object.get("evidence") {
        if object.len() != 1 {
            return Err(invalid("Evidence input must contain only evidence"));
        }
        return replay_evidence(evidence);
    }

    if object.contains_key("result") || object.contains_key("normalized_result") {
        return replay_result(object);
    }

    let path = object
        .get("path")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && !value.contains('\0'))
        .ok_or_else(|| invalid("captured input requires a non-empty NUL-free path"))?;
    let encoded = object
        .get("bytes_base64")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("captured input requires bytes_base64"))?;
    if object.keys().any(|key| !["path", "bytes_base64", "sha256"].contains(&key.as_str())) {
        return Err(invalid("captured input contains an unknown field"));
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|error| invalid(&format!("bytes_base64 is invalid: {error}")))?;
    let result = managed::artifact::inspect_captured(path, &bytes)?;
    let actual = result["sha256"].as_str().unwrap_or_default();
    if let Some(expected) = object.get("sha256").and_then(Value::as_str) {
        if expected != actual {
            return Err(integrity("captured artifact SHA-256 does not match sha256"));
        }
    }
    Ok(json!({
        "result": result,
        "provenance": { "operation": OPERATION, "source": "caller-supplied-artifact-bytes", "execution": "none" }
    }))
}

fn replay_evidence(evidence: &Value) -> Result<Value, Failure> {
    let raw = serde_json::value::to_raw_value(evidence)
        .map_err(|error| invalid(&format!("Evidence is not serializable: {error}")))?;
    let record = EvidenceRecord::parse(&raw)
        .map_err(|error| integrity(&format!("Evidence is invalid: {error}")))?;
    if !record.operation_matches(OPERATION) {
        return Err(integrity("Evidence operation does not match inspect_managed_artifact"));
    }
    let result: Value = serde_json::from_str(record.normalized_result().get())
        .map_err(|error| integrity(&format!("Evidence result is invalid JSON: {error}")))?;
    validate_result(&result)?;
    Ok(json!({
        "result": result,
        "evidence_id": record.evidence_id(),
        "provenance": { "operation": OPERATION, "source": "authenticated-retained-evidence", "execution": "unknown" }
    }))
}

fn replay_result(object: &Map<String, Value>) -> Result<Value, Failure> {
    if object.keys().any(|key| !["result", "normalized_result", "evidence_id"].contains(&key.as_str())) {
        return Err(invalid("retained result input contains an unknown field"));
    }
    let result = object.get("normalized_result").or_else(|| object.get("result"))
        .ok_or_else(|| invalid("retained result is required"))?;
    validate_result(result)?;
    Ok(json!({
        "result": result,
        "evidence_id": object.get("evidence_id"),
        "provenance": { "operation": OPERATION, "source": "caller-supplied-retained-result", "execution": "unknown" }
    }))
}

fn validate_result(result: &Value) -> Result<(), Failure> {
    let object = result.as_object().ok_or_else(|| invalid("managed artifact result must be an object"))?;
    for field in ["artifact", "pe", "classification", "metadata", "coverage", "limitations"] {
        if !object.contains_key(field) { return Err(invalid(&format!("managed artifact result requires {field}"))); }
    }
    let artifact = object["artifact"].as_object().ok_or_else(|| invalid("artifact must be an object"))?;
    for field in ["path", "sha256", "byte_length", "format"] {
        if !artifact.contains_key(field) { return Err(invalid(&format!("artifact requires {field}"))); }
    }
    if artifact["format"] != "pe" { return Err(invalid("artifact format must be pe")); }
    let digest = artifact["sha256"].as_str().unwrap_or_default();
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()) {
        return Err(invalid("artifact SHA-256 is invalid"));
    }
    if !object["limitations"].is_array() || !object["coverage"].is_object() {
        return Err(invalid("managed artifact coverage and limitations are malformed"));
    }
    Ok(())
}

fn invalid(reason: &str) -> Failure {
    Failure::new("invalid_request", "invalid_input", "Managed artifact input is invalid.".into(), false,
        "Provide a bounded managed artifact snapshot or authenticated retained Evidence.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into())), ("reason", Detail::Text(reason.into())), ("authority", Detail::Text("offline_capture_only".into()))]))
}

fn integrity(reason: &str) -> Failure {
    Failure::new("integrity_error", "integrity_error", "Managed artifact Evidence is invalid.".into(), false,
        "Provide intact retained inspect_managed_artifact Evidence.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into())), ("reason", Detail::Text(reason.into()))]))
}

