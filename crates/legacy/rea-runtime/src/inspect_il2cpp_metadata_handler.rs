//! Captured-Evidence-only adapter for IL2CPP metadata inspection.
//!
//! Byte decoding belongs to the artifact-owning reader. This adapter accepts
//! only authenticated retained Evidence and never reopens its recorded path.

use rea_application::{
    artifacts::inspection::Completion,
    il2cpp,
    il2cpp::metadata::{self as il2cpp_metadata, Il2cppMetadataInspection},
};
use rea_core::{
    cancellation::Cancellation,
    failure::{Detail, Failure},
};
use rea_host::fs::stable_file::FileAccess;
use serde_json::Value;
use serde_json::value::RawValue;
use std::collections::BTreeMap;

pub const OPERATION: &str = il2cpp_metadata::OPERATION;

/// Inspect a caller-selected metadata file through the read-only application
/// reader. The reader owns stable-file acquisition, decoding, Evidence
/// creation, and cancellation checkpoints.
pub fn inspect<F: FileAccess>(
    inspection: &mut Il2cppMetadataInspection<F>,
    input: &Value,
    cancellation: &Cancellation,
    completion: Completion,
) -> Result<Box<RawValue>, Failure> {
    let detail = requested_detail(input)?;
    let provider_input = without_delivery_selection(input)?;
    let complete = inspection.inspect(&provider_input, cancellation, completion)?;

    select_delivery(&complete, detail)
}

pub fn handle(input: &Value) -> Result<Value, Failure> {
    let detail = requested_detail(input)?;
    let provider_input = without_delivery_selection(input)?;
    let complete =
        il2cpp_metadata::project_captured_evidence(&provider_input).map_err(tag_failure)?;

    if detail == "summary" {
        let evidence = provider_input
            .get("evidence")
            .ok_or_else(|| invalid_input("evidence", "Evidence is required"))?;
        let projected = il2cpp::metadata_view::project(
            evidence,
            &serde_json::json!({
                "kind": "summary"
            }),
        )
        .map_err(tag_failure)?;
        return serde_json::from_str(projected.get()).map_err(|error| {
            invalid_input(
                "evidence",
                &format!("Summary could not be encoded: {error}"),
            )
        });
    }

    Ok(complete)
}

fn select_delivery(complete: &RawValue, detail: &str) -> Result<Box<RawValue>, Failure> {
    if detail == "complete" {
        return RawValue::from_string(complete.get().to_owned())
            .map_err(|error| invalid_input("result", &error.to_string()));
    }

    let parent: Value = serde_json::from_str(complete.get())
        .map_err(|error| invalid_input("result", &error.to_string()))?;
    il2cpp::metadata_view::project(&parent, &serde_json::json!({"kind": "summary"}))
        .map_err(tag_failure)
}

fn requested_detail(input: &Value) -> Result<&str, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid_input("input", "Expected an object"))?;
    match object.get("detail") {
        // The public MCP contract defaults to compact delivery while the
        // complete decoded Evidence remains retained by the caller.
        None => Ok("summary"),
        Some(Value::String(detail)) if matches!(detail.as_str(), "complete" | "summary") => {
            Ok(detail)
        }
        Some(_) => Err(invalid_input("detail", "Expected complete or summary")),
    }
}

fn without_delivery_selection(input: &Value) -> Result<Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid_input("input", "Expected an object"))?;
    let mut provider_input = object.clone();
    provider_input.remove("detail");
    Ok(Value::Object(provider_input))
}

fn invalid_input(field: &str, reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "IL2CPP metadata input is invalid.".into(),
        false,
        "Correct the input and retry.".into(),
        BTreeMap::from([
            ("operation".into(), Detail::Text(OPERATION.into())),
            ("field".into(), Detail::Text(field.into())),
            ("reason".into(), Detail::Text(reason.into())),
        ]),
    )
}

fn tag_failure(mut failure: Failure) -> Failure {
    failure.detail("operation", Detail::Text(OPERATION.into()));
    failure.detail("authority", Detail::Text("offline_capture_only".into()));
    failure
}
