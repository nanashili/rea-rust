//! Read-only normalization for Binwalk firmware signature reports.
//!
//! The provider owns process execution.  This module owns the boundary after
//! execution: it validates the selected artifact and the provider report,
//! checks every reported interval against the immutable input, and emits the
//! portable inspection result without treating a signature as decoded data.

use rea_core::{
    cancellation::Cancellation,
    evidence::is_sha256,
    failure::{Detail, Failure},
};
use rea_host::fs::stable_file;
#[cfg(unix)]
use rea_host::fs::unix_file::UnixFiles;
#[cfg(windows)]
use rea_host::fs::windows_file::WindowsFiles;
use serde_json::{json, Map, Value};
use std::{collections::BTreeMap, path::Path, sync::Arc};

pub const OPERATION: &str = "inspect_firmware_regions";
pub const MAX_INPUT_BYTES: usize = 128 * 1024 * 1024;
pub const MAX_REPORT_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_REGIONS: usize = 100_000;

/// Validate the strict public request before any filesystem access.
pub fn validate_input(input: &Value) -> Result<&str, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("input", "Expected an object"))?;
    if object.len() != 1 || !object.contains_key("path") {
        return Err(invalid("input", "Expected exactly one field: path"));
    }
    let path = object
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("path", "Expected an absolute local path"))?;
    if path.is_empty() || !Path::new(path).is_absolute() {
        return Err(invalid("path", "Expected an absolute local path"));
    }
    Ok(path)
}

/// Read a stable firmware snapshot and return its identity.  No provider is
/// launched here; callers pass the provider's report to `normalize_report`.
pub fn snapshot_input(
    input: &Value,
    cancellation: &Cancellation,
) -> Result<(String, usize, String), Failure> {
    let path = validate_input(input)?.to_owned();
    let snapshot = stable_file::read(
        Arc::new(platform_files()),
        Path::new(&path),
        MAX_INPUT_BYTES,
        cancellation,
    )
    .map_err(|_| invalid("path", "Unable to read a stable regular firmware file"))?;
    if snapshot.bytes.is_empty() {
        return Err(invalid("path", "Firmware input must be nonempty"));
    }
    Ok((path, snapshot.bytes.len(), snapshot.sha256))
}

#[cfg(unix)]
fn platform_files() -> UnixFiles {
    UnixFiles
}

#[cfg(windows)]
fn platform_files() -> WindowsFiles {
    WindowsFiles
}

/// Normalize one provider report into the exact inspection result shape.
/// `report` is intentionally supplied by the runtime adapter so this parser
/// remains deterministic and cannot silently execute a tool.
pub fn normalize_report(
    path: &str,
    input_size: usize,
    report: &Value,
    engine: &Value,
) -> Result<Box<serde_json::value::RawValue>, Failure> {
    let records = report
        .as_array()
        .ok_or_else(|| invalid("report", "Expected a report array"))?;
    if records.len() != 1 {
        return Err(output(
            "Expected one inspection report for the selected input",
        ));
    }
    let analysis = records[0]
        .get("Analysis")
        .and_then(Value::as_object)
        .ok_or_else(|| output("Report is missing Analysis"))?;
    if analysis.get("file_path").and_then(Value::as_str) != Some(path) {
        return Err(output("Report input path disagrees with selected input"));
    }
    if analysis
        .get("extractions")
        .and_then(Value::as_object)
        .map(|items| !items.is_empty())
        .unwrap_or(true)
    {
        return Err(output("Inspection report contains extraction output"));
    }
    let hits = analysis
        .get("file_map")
        .and_then(Value::as_array)
        .ok_or_else(|| output("Report is missing Analysis.file_map"))?;
    if hits.len() > MAX_REGIONS {
        return Err(resource(
            "Reported region count exceeds the inspection bound",
        ));
    }
    let mut regions = Vec::with_capacity(hits.len());
    for hit in hits {
        let object = hit
            .as_object()
            .ok_or_else(|| output("Malformed signature record"))?;
        let provider_id = required_non_empty_text(object, "id")?;
        let offset = bounded_u64(object, "offset")?;
        let size = bounded_u64(object, "size")?;
        let signature = required_text(object, "name")?;
        let description = required_text(object, "description")?;
        let confidence = bounded_u8(object, "confidence")?;
        if offset >= input_size as u64 || size > input_size as u64 - offset {
            return Err(output("Reported region lies outside the selected file"));
        }
        regions.push(json!({
            "provider_id": provider_id,
            "offset": offset,
            "reported_size": size,
            "signature": signature,
            "description": description,
            "reported_confidence": confidence,
            "size_basis": "provider_reported_validation_unknown",
        }));
    }
    let engine = validate_engine(engine)?;
    let result = json!({
        "engine": engine,
        "input_size": input_size,
        "regions": regions,
        "coverage": "signature_scan",
    });
    serde_json::value::to_raw_value(&result)
        .map_err(|error| output(&format!("Unable to encode normalized report: {error}")))
}

fn validate_engine(value: &Value) -> Result<Value, Failure> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid("engine", "Expected an engine object"))?;
    for key in ["name", "version", "executable_path", "executable_sha256"] {
        if !object.get(key).is_some_and(Value::is_string) {
            return Err(invalid("engine", "Engine identity is incomplete"));
        }
    }
    if !is_sha256(
        object
            .get("executable_sha256")
            .and_then(Value::as_str)
            .unwrap_or_default(),
    ) {
        return Err(invalid("engine", "Engine executable SHA-256 is invalid"));
    }
    if object.get("source_revision") != Some(&Value::Null)
        || object.get("worker_count").and_then(Value::as_u64) != Some(1)
        || object.len() != 6
    {
        return Err(invalid(
            "engine",
            "Engine identity does not match the contract",
        ));
    }
    Ok(value.clone())
}

fn required_text(object: &Map<String, Value>, key: &str) -> Result<String, Failure> {
    object
        .get(key)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| output(&format!("Signature field {key} is missing")))
}

fn required_non_empty_text(object: &Map<String, Value>, key: &str) -> Result<String, Failure> {
    object
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| output(&format!("Signature field {key} is missing")))
}

fn bounded_u64(object: &Map<String, Value>, key: &str) -> Result<u64, Failure> {
    object
        .get(key)
        .and_then(Value::as_u64)
        .filter(|value| *value <= 9_007_199_254_740_991)
        .ok_or_else(|| output(&format!("Signature field {key} is not a safe integer")))
}

fn bounded_u8(object: &Map<String, Value>, key: &str) -> Result<u8, Failure> {
    object
        .get(key)
        .and_then(Value::as_u64)
        .filter(|value| *value <= u8::MAX as u64)
        .map(|value| value as u8)
        .ok_or_else(|| output(&format!("Signature field {key} is outside 0..255")))
}

fn invalid(path: &str, message: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "Analysis input is invalid. Check the arguments and retry.".into(),
        false,
        "Correct the input and retry.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("path", Detail::Text(path.into())),
            ("reason", Detail::Text(message.into())),
        ]),
    )
}

fn output(message: &str) -> Failure {
    Failure::new(
        "provider_output_invalid",
        "provider_output_invalid",
        message.into(),
        true,
        "Review the provider report and retry with a stable input.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

fn resource(message: &str) -> Failure {
    Failure::new(
        "resource_constraint",
        "resource_constraint",
        message.into(),
        false,
        "Use a smaller firmware input or a narrower provider report.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
