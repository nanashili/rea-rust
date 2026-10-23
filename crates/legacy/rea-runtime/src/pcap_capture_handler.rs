//! Runtime adapter for the public `inspect_pcap_capture` contract.
//!
//! The application producer owns PCAP/PCAPNG framing and packet-fact
//! aggregation.  This boundary owns only request identity and provenance: it
//! never substitutes `inspect_packet_capture`, reinterprets decoded layers, or
//! claims completeness beyond the producer's explicit coverage value.

use rea_application::pcap;
use rea_core::{
    evidence::record::EvidenceRecord,
    failure::{Detail, Failure},
};
use serde_json::{Map, Value, json};
use std::{collections::BTreeMap, path::Path};

pub const OPERATION: &str = "inspect_pcap_capture";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputAuthority {
    Capture,
    Evidence,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Contract {
    pub operation: &'static str,
    pub authority: InputAuthority,
}

pub const CONTRACT: Contract = Contract {
    operation: OPERATION,
    authority: InputAuthority::Capture,
};

/// Inspect an already admitted capture representation.
pub fn dispatch(input: Value) -> Result<Value, Failure> {
    dispatch_ref(&input)
}

pub fn dispatch_ref(input: &Value) -> Result<Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("input must be an object"))?;
    reject_unknown_fields(object)?;

    if let Some(evidence) = object.get("evidence") {
        return project_evidence(evidence);
    }

    let request = required_request(object)?;
    let capture = object
        .get("capture")
        .filter(|value| value.is_object())
        .ok_or_else(|| invalid("capture must be an object"))?;
    let capture = capture_with_selected_path(request, capture)?;
    let result = pcap::capture::inspect(&capture)?;
    validate_result_identity(&result, request)?;

    Ok(json!({
        "result": result,
        "provenance": {
            "source": "caller-supplied-pcap-capture",
            "execution": "none",
            "source_path": request["path"],
            "coverage": result["coverage"],
        },
    }))
}

fn required_request<'a>(object: &'a Map<String, Value>) -> Result<&'a Map<String, Value>, Failure> {
    let request = object
        .get("request")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("request must be an object"))?;
    if request.len() != 1 || !request.contains_key("path") {
        return Err(invalid("request must contain only the selected path"));
    }
    let path = request
        .get("path")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && !value.contains('\0'))
        .ok_or_else(|| invalid("request.path must be a non-empty NUL-free string"))?;
    if !Path::new(path).is_absolute() {
        return Err(invalid("request.path must be an absolute local path"));
    }
    Ok(request)
}

fn capture_with_selected_path(
    request: &Map<String, Value>,
    capture: &Value,
) -> Result<Value, Failure> {
    let capture = capture
        .as_object()
        .ok_or_else(|| invalid("capture must be an object"))?;
    let allowed = ["bytes_base64", "records", "metadata"];
    if capture.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(invalid("capture contains an unsupported field"));
    }
    let has_bytes = capture.get("bytes_base64").is_some();
    let has_records = capture.get("records").is_some();
    if has_bytes == has_records {
        return Err(invalid(
            "capture must contain exactly one of bytes_base64 or records",
        ));
    }
    let mut selected = capture.clone();
    selected.insert("path".into(), request["path"].clone());
    Ok(Value::Object(selected))
}

fn validate_result_identity(result: &Value, request: &Map<String, Value>) -> Result<(), Failure> {
    let target = result
        .get("target")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("capture producer omitted target identity"))?;
    if target.get("path") != request.get("path") {
        return Err(integrity(
            "capture producer changed the selected source path",
        ));
    }
    match result.get("coverage").and_then(Value::as_str) {
        Some("complete") | Some("partial") => Ok(()),
        _ => Err(integrity(
            "capture producer omitted an explicit completeness value",
        )),
    }
}

fn project_evidence(value: &Value) -> Result<Value, Failure> {
    let raw = serde_json::value::to_raw_value(value)
        .map_err(|error| integrity(&format!("Evidence serialization failed: {error}")))?;
    let record = EvidenceRecord::parse(&raw)
        .map_err(|error| integrity(&format!("Evidence is malformed: {error}")))?;
    if !record.operation_matches(OPERATION) {
        return Err(integrity(
            "Evidence operation does not match inspect_pcap_capture",
        ));
    }
    let result: Value = serde_json::from_str(record.normalized_result().get())
        .map_err(|error| integrity(&format!("Evidence result is malformed: {error}")))?;
    validate_result_identity(
        &result,
        result
            .get("target")
            .and_then(Value::as_object)
            .ok_or_else(|| integrity("Evidence has no capture target"))?,
    )?;
    Ok(json!({
        "evidence_id": record.evidence_id(),
        "result": result,
        "provenance": {
            "source": "authenticated-captured-evidence",
            "execution": "unknown",
        },
    }))
}

fn reject_unknown_fields(object: &Map<String, Value>) -> Result<(), Failure> {
    if object
        .keys()
        .any(|key| !matches!(key.as_str(), "request" | "capture" | "evidence"))
    {
        return Err(invalid("input contains an unsupported field"));
    }
    if object.contains_key("evidence")
        && (object.contains_key("request") || object.contains_key("capture"))
    {
        return Err(invalid("supply either evidence or a capture request"));
    }
    Ok(())
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.into(),
        false,
        "Provide an absolute capture path and exactly one caller-supplied capture representation."
            .into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("authority", Detail::Text("offline_capture_only".into())),
        ]),
    )
}

fn integrity(reason: &str) -> Failure {
    Failure::new(
        "integrity_failure",
        "integrity_failure",
        reason.into(),
        false,
        "Provide an intact capture or authenticated Evidence for inspect_pcap_capture.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
