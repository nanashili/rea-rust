//! Isolated retained-report handler for `inspect_go_binary`.
//!
//! The normal static-format path owns stable file reads and parsing.  This
//! boundary is for callers that already possess the complete report: it
//! validates the identity and source ranges while preserving the producer's
//! uncertainty and raw metadata exactly.

use rea_core::failure::{Detail, Failure};
use base64::Engine;
use rea_application::binary;
use rea_core::evidence::record::EvidenceRecord;
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub const OPERATION: &str = "inspect_go_binary";

/// Validate and return a caller-supplied complete Go report.
pub fn handle(input: &Value) -> Result<Value, Failure> {
    let request = input.as_object().ok_or_else(|| invalid("request must be an object"))?;

    if let Some(evidence) = request.get("evidence") {
        if request.len() != 1 || !evidence.is_object() {
            return Err(invalid("Evidence input must contain only an evidence object"));
        }
        let raw = serde_json::value::to_raw_value(evidence)
            .map_err(|error| invalid(&format!("Evidence is not serializable: {error}")))?;
        let record = EvidenceRecord::parse(&raw)
            .map_err(|error| invalid(&format!("Evidence is not authenticated: {error}")))?;
        if !record.operation_matches(OPERATION) {
            return Err(invalid("Evidence operation must be inspect_go_binary"));
        }
        return Ok(evidence.clone());
    }

    if request.contains_key("bytes_base64") {
        const ALLOWED: &[&str] = &["path", "bytes_base64", "sha256"];
        if let Some(field) = request
            .keys()
            .find(|field| !ALLOWED.contains(&field.as_str()))
        {
            return Err(invalid(&format!("unexpected captured Go inspection field: {field}")));
        }
        let path = required_text(request, "path")?;
        let encoded = required_text(request, "bytes_base64")?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| invalid("bytes_base64 is malformed"))?;
        let digest = request.get("sha256").and_then(Value::as_str);
        return binary::go::inspect_bytes(path, bytes, digest);
    }

    let path = required_text(request, "path")?;
    let digest = required_digest(request.get("sha256"))?;
    let report = request.get("report").ok_or_else(|| invalid("report is required"))?;
    validate_report(report, path, digest)?;
    Ok(report.clone())
}

fn validate_report(report: &Value, path: &str, digest: &str) -> Result<(), Failure> {
    let object = report.as_object().ok_or_else(|| invalid("report must be an object"))?;
    let artifact = object.get("artifact").and_then(Value::as_object).ok_or_else(|| invalid("report.artifact is required"))?;
    if artifact.get("path").and_then(Value::as_str) != Some(path) || artifact.get("sha256").and_then(Value::as_str) != Some(digest) { return Err(invalid("report artifact identity does not match the selected artifact")); }
    match object.get("format").and_then(Value::as_str) { Some("elf" | "pe" | "macho") => {}, _ => return Err(invalid("report.format is unsupported")), }
    match object.get("bits").and_then(Value::as_u64) { Some(32 | 64) => {}, _ => return Err(invalid("report.bits must be 32 or 64")), }
    match object.get("byte_order").and_then(Value::as_str) { Some("little" | "big") => {}, _ => return Err(invalid("report.byte_order is invalid")), }
    let bytes = artifact.get("bytes").and_then(Value::as_u64).ok_or_else(|| invalid("report.artifact.bytes is required"))?;
    if let Some(info) = object.get("build_info") { if !info.is_null() { validate_build_info(info, bytes)?; } }
    Ok(())
}

fn validate_build_info(value: &Value, artifact_bytes: u64) -> Result<(), Failure> {
    let info = value.as_object().ok_or_else(|| invalid("build_info must be an object or null"))?;
    let header = info.get("header_offset").and_then(Value::as_u64).ok_or_else(|| invalid("build_info.header_offset is required"))?;
    if artifact_bytes < 32 || header > artifact_bytes - 32 { return Err(invalid("build_info.header_offset is outside the artifact")); }
    for field in ["version_location", "module_location"] {
        let range = info.get(field).and_then(Value::as_object).ok_or_else(|| invalid("build_info source range is required"))?;
        let offset = range.get("offset").and_then(Value::as_u64).ok_or_else(|| invalid("build_info range offset is required"))?;
        let length = range.get("bytes").and_then(Value::as_u64).ok_or_else(|| invalid("build_info range bytes is required"))?;
        if offset > artifact_bytes || length > artifact_bytes - offset { return Err(invalid("build_info source range is outside the artifact")); }
    }
    for field in ["go_version_bytes_base64", "module_bytes_base64"] { if !info.get(field).and_then(Value::as_str).map(valid_base64).unwrap_or(false) { return Err(invalid("build_info raw bytes are not valid base64")); } }
    Ok(())
}

fn valid_base64(value: &str) -> bool { value.len() % 4 == 0 && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=')) }
fn required_text<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a str, Failure> { object.get(field).and_then(Value::as_str).filter(|value| !value.is_empty() && !value.contains('\0')).ok_or_else(|| invalid(&format!("{field} must be a non-empty string without NUL bytes"))) }
fn required_digest<'a>(value: Option<&'a Value>) -> Result<&'a str, Failure> { let digest = value.and_then(Value::as_str).filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())).ok_or_else(|| invalid("sha256 must be a lowercase SHA-256 digest"))?; Ok(digest) }
fn invalid(reason: &str) -> Failure { Failure::new("invalid_request", "invalid_input", "Go binary report is invalid.".into(), false, "Provide a complete report bound to the selected artifact.".into(), BTreeMap::from([("operation", Detail::Text(OPERATION.into())), ("reason", Detail::Text(reason.into()))])) }
