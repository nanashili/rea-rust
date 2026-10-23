//! Runtime boundary for replaying a caller-selected environment tool.
//!
//! The application owner performs record selection and response projection.  This
//! adapter only admits the authenticated manifest/capture values and the
//! caller's tool arguments, then preserves those values while invoking replay.

use rea_application::environment;
use rea_core::{
    cancellation::Cancellation,
    failure::{Detail, Failure},
};
use serde_json::Value;
use std::collections::BTreeMap;

pub const OPERATION: &str = environment::replay::OPERATION;

const MAX_RECORDS: usize = 200_000;
const MAX_TOOL_NAME_BYTES: usize = 512;
const MAX_EVIDENCE_ID_BYTES: usize = 256;

/// Replay one manifest tool against its retained capture.
///
/// `manifest` and `capture` are expected to be the already-authenticated,
/// normalized values selected by the caller.  Authentication belongs to the
/// Evidence loading boundary; this adapter must not reinterpret raw files.
pub fn inspect(input: &Value, cancellation: &Cancellation) -> Result<Value, Failure> {
    check_cancelled(cancellation)?;

    let object = input
        .as_object()
        .ok_or_else(|| invalid_input("input must be an object"))?;
    reject_unknown_fields(object)?;

    let manifest = required_object(object, "manifest")?;
    let capture = required_object(object, "capture")?;
    let tool_name = required_text(object, "tool_name", MAX_TOOL_NAME_BYTES)?;
    let evidence_id = required_text(object, "evidence_id", MAX_EVIDENCE_ID_BYTES)?;
    let no_arguments = Value::Object(serde_json::Map::new());
    let arguments = object.get("arguments").unwrap_or(&no_arguments);
    if !arguments.is_object() {
        return Err(invalid_input("arguments must be an object"));
    }

    enforce_record_bound(manifest, "manifest")?;
    enforce_record_bound(capture, "capture")?;
    check_cancelled(cancellation)?;

    // The application owner already returns the typed selection failure.
    environment::replay::replay(manifest, capture, tool_name, arguments, evidence_id)
}

fn reject_unknown_fields(object: &serde_json::Map<String, Value>) -> Result<(), Failure> {
    if let Some(field) = object.keys().find(|field| {
        !matches!(
            field.as_str(),
            "manifest" | "capture" | "tool_name" | "arguments" | "evidence_id"
        )
    }) {
        return Err(invalid_input(&format!("unknown field: {field}")));
    }

    Ok(())
}

fn required_object<'a>(
    object: &'a serde_json::Map<String, Value>,
    field: &str,
) -> Result<&'a Value, Failure> {
    object
        .get(field)
        .filter(|value| value.is_object())
        .ok_or_else(|| invalid_input(&format!("{field} must be an object")))
}

fn required_text<'a>(
    object: &'a serde_json::Map<String, Value>,
    field: &str,
    max_bytes: usize,
) -> Result<&'a str, Failure> {
    let value = object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= max_bytes)
        .ok_or_else(|| invalid_input(&format!("{field} must be a non-empty bounded string")))?;

    if value.contains('\0') {
        return Err(invalid_input(&format!("{field} must not contain NUL")));
    }

    Ok(value)
}

fn enforce_record_bound(value: &Value, field: &str) -> Result<(), Failure> {
    let Some(records) = value.get("records").and_then(Value::as_array) else {
        return Ok(());
    };
    if records.len() > MAX_RECORDS {
        return Err(invalid_input(&format!(
            "{field}.records exceeds the {MAX_RECORDS}-record limit"
        )));
    }

    Ok(())
}

fn check_cancelled(cancellation: &Cancellation) -> Result<(), Failure> {
    if cancellation.reason().is_some() {
        return Err(Failure::new(
            "cancelled",
            "cancelled",
            "Environment replay was cancelled.".into(),
            true,
            "Retry the replay when the caller is ready.".into(),
            BTreeMap::from([("operation".into(), Detail::Text(OPERATION.into()))]),
        ));
    }

    Ok(())
}

fn invalid_input(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "Environment replay input is invalid.".into(),
        false,
        "Provide an authenticated manifest, retained capture, tool name, arguments, and evidence ID.".into(),
        BTreeMap::from([
            ("operation".into(), Detail::Text(OPERATION.into())),
            ("reason".into(), Detail::Text(reason.into())),
        ]),
    )
}
